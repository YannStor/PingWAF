//! Anomalous-login detection for control-plane accounts.
//!
//! Every successful login is recorded in `login_history` with the resolved
//! client IP and — best effort — its geolocation. Password logins are then
//! compared against the countries of the account's most recent resolved
//! logins: a country outside that baseline raises an `auth.login_anomaly`
//! alert. Passkey logins are recorded but never judged (they already carry
//! a stronger factor). The whole lookup-and-judge step runs detached, so
//! the login response never waits on a geo API.

use std::net::IpAddr;
use std::sync::OnceLock;

use axum::http::HeaderMap;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{event_type, login_history, severity};
use crate::notify::{self, AlertEvent};

/// Key of the settings row in `instance_settings`.
pub const SETTINGS_KEY: &str = "login_security";

/// Settings for the login anomaly feature. Stored separately from the
/// notification settings: this governs *detection* (which logins are
/// recorded, where geo data comes from), while
/// `NotificationSettings.notify_auth_login_anomaly` governs *delivery*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSecuritySettings {
    /// Run the country-baseline check on password logins. History is
    /// recorded regardless.
    #[serde(default)]
    pub anomaly_enabled: bool,
    /// How many recent resolved logins form the baseline.
    #[serde(default = "default_baseline")]
    pub baseline_count: u32,
    /// Forwarding header to trust for the client IP (e.g.
    /// `x-forwarded-for`). `None` — the default — keeps using the TCP peer
    /// address, which a proxy would mask.
    #[serde(default)]
    pub trusted_header: Option<String>,
    /// With a trusted header carrying several hops, use the last entry
    /// (the one the closest proxy appended) instead of the first.
    #[serde(default)]
    pub trust_last_hop: bool,
    /// Online geo API; `{ip}` is replaced with the address. The response
    /// is read loosely: `countryCode` is required, region/city optional.
    #[serde(default = "default_geo_url")]
    pub online_geo_url: String,
    /// Use the uploaded mmdb (when present) before the online API.
    #[serde(default)]
    pub geoip_local_enabled: bool,
}

fn default_baseline() -> u32 {
    3
}

fn default_geo_url() -> String {
    "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city"
        .to_string()
}

impl Default for LoginSecuritySettings {
    fn default() -> Self {
        Self {
            anomaly_enabled: false,
            baseline_count: default_baseline(),
            trusted_header: None,
            trust_last_hop: false,
            online_geo_url: default_geo_url(),
            geoip_local_enabled: false,
        }
    }
}

impl LoginSecuritySettings {
    /// Loads the settings from `instance_settings`, falling back to the
    /// defaults when the row is missing or unparsable.
    pub async fn load(db: &DatabaseConnection) -> Self {
        use crate::models::instance_setting;

        let stored = instance_setting::Entity::find_by_id(SETTINGS_KEY)
            .one(db)
            .await
            .ok()
            .flatten();
        match stored {
            Some(row) => serde_json::from_str(&row.value).unwrap_or_default(),
            None => Self::default(),
        }
    }

    /// Persists the settings; called by the settings API.
    pub async fn store(
        &self,
        db: &DatabaseConnection,
    ) -> Result<(), sea_orm::DbErr> {
        use crate::models::instance_setting;

        let value = serde_json::to_string(self)
            .map_err(|err| sea_orm::DbErr::Custom(err.to_string()))?;
        let existing = instance_setting::Entity::find_by_id(SETTINGS_KEY)
            .one(db)
            .await?;
        match existing {
            Some(row) => {
                let mut active: instance_setting::ActiveModel = row.into();
                active.value = Set(value);
                active.updated_at = Set(Utc::now());
                active.update(db).await?;
            },
            None => {
                instance_setting::ActiveModel {
                    key: Set(SETTINGS_KEY.to_string()),
                    value: Set(value),
                    updated_at: Set(Utc::now()),
                }
                .insert(db)
                .await?;
            },
        }
        Ok(())
    }

    /// Validates operator-supplied values; returns a human-readable reason.
    pub fn validate(&self) -> Result<(), String> {
        if !self.online_geo_url.contains("{ip}") {
            return Err(
                "online_geo_url must contain the {ip} placeholder".to_string()
            );
        }
        if !(self.online_geo_url.starts_with("http://")
            || self.online_geo_url.starts_with("https://"))
        {
            return Err("online_geo_url must start with http:// or https://"
                .to_string());
        }
        // SSRF gate (D16): the control plane fetches this URL on every login,
        // so a stored private / metadata / loopback host turns the operator
        // surface into an internal network probe. Refused at save time —
        // before anything is persisted — and again on the request path.
        check_geo_url_host(&self.online_geo_url)?;
        if let Some(header) = &self.trusted_header {
            let name = header.trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(
                    "trusted_header must not be empty when set".to_string()
                );
            }
        }
        if self.baseline_count == 0 || self.baseline_count > 100 {
            return Err("baseline_count must be 1-100".to_string());
        }
        Ok(())
    }
}

/// Resolved geolocation of one IP address.
#[derive(Debug, Clone, Default)]
pub struct GeoInfo {
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    /// One of [`crate::models::geo_source::ALL`].
    pub source: &'static str,
}

/// The shared HTTP client for online geo lookups: short timeout, no
/// redirects, deliberately separate from the notification manager's client.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default()
    })
}

/// The mmdb file the upload endpoint maintains.
pub fn geoip_mmdb_path() -> std::path::PathBuf {
    std::env::var("PINGWAF_GEOIP_MMDB")
        .unwrap_or_else(|_| "/var/lib/pingwaf/geoip.mmdb".to_string())
        .into()
}

/// True for addresses a login geo lookup must never touch: loopback,
/// RFC 1918, CGNAT, link-local (cloud metadata), broadcast and the IPv6
/// unique-local / link-local ranges. Explicit `ipnet`-style octet matching
/// instead of `IpAddr::is_global`, whose availability varies by toolchain.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || a == 255
        },
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
        },
    }
}

/// Extracts the host of an absolute `http(s)://` URL without parsing it into
/// a full `Url` (the crate is not a dependency of this package). Handles an
/// optional userinfo, an IPv6 literal in brackets, an optional port and the
/// path/query tail. Returns `None` for anything that is not shaped like an
/// absolute URL with a non-empty authority — the caller treats that as a
/// rejection, never as a pass.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .or_else(|| url.strip_prefix("HTTP://"))
        .or_else(|| url.strip_prefix("HTTPS://"))?;
    // Authority ends at the first `/`, `?` or `#`.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    if authority.is_empty() {
        return None;
    }
    // Drop `user:pass@`; only the part after the last `@` is the host, so a
    // crafted `http://127.0.0.1@evil/` resolves to `evil` and a crafted
    // `http://evil@127.0.0.1/` resolves to `127.0.0.1` — both judged on the
    // host the client would actually connect to.
    let host_port = match authority.rsplit_once('@') {
        Some((_, host_port)) => host_port,
        None => authority,
    };
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally followed by `:port`.
        let (inside, tail) = stripped.split_once(']')?;
        (inside.to_string(), tail.strip_prefix(':').unwrap_or(""))
    } else {
        match host_port.rsplit_once(':') {
            // A lone colon can only be `host:port` here; a bare IPv6 literal
            // never has colons left unbracketed in an absolute URL.
            Some((host, port)) => (host.to_string(), port),
            None => (host_port.to_string(), ""),
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    // Reject a malformed / out-of-range port rather than ignoring it.
    if !port.is_empty()
        && (port.parse::<u16>().is_err() || port.starts_with('+'))
    {
        return None;
    }
    Some(host)
}

/// Hostname literals that resolve inside the deployment by definition. No DNS
/// lookup is performed — resolving here would itself be the SSRF the check is
/// meant to stop, and a rebinding record would defeat a one-shot lookup
/// anyway. Operator-configured internal suffixes are refused by name.
pub fn is_private_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || host.ends_with(".lan")
        || host.ends_with(".intranet")
    {
        return true;
    }
    // A single-label name (`geo`, `db`, `kubernetes`) is resolved through the
    // container/enterprise search domain: there is no public DNS meaning for
    // it, so it is an internal target.
    if !host.contains('.') && !host.contains(':') {
        return true;
    }
    false
}

/// Host-only form of a geo URL for log lines: the path and query may carry a
/// provider key, which must never reach the log.
fn redact_url(url: &str) -> String {
    match url_host(url) {
        Some(host) => format!("{host}/…"),
        None => "<unparsable>".to_string(),
    }
}

/// True when `url` is safe to fetch from the control plane: absolute
/// `http(s)`, a parseable authority, and a host that is neither a private /
/// loopback / link-local / metadata address literal nor an obviously internal
/// name. See [`check_geo_url_host`] for the error text.
pub fn is_public_geo_url(url: &str) -> bool {
    check_geo_url_host(url).is_ok()
}

/// Validates the host part of an operator-supplied geo lookup URL.
///
/// Rejected address literals: `0.0.0.0/8` (incl. `0.0.0.0`), `127/8`,
/// `10/8`, `172.16/12`, `192.168/16`, `169.254/16` (so the
/// `169.254.169.254` metadata endpoint), `100.64/10` CGNAT, `255.255.255.255`,
/// `::1`, `::`, `fc00::/7` and `fe80::/10` — plus anything already covered by
/// [`is_private`], including IPv4-mapped IPv6 forms.
pub fn check_geo_url_host(url: &str) -> Result<(), String> {
    let Some(host) = url_host(url) else {
        return Err(
            "online_geo_url must be an absolute http:// or https:// URL with a host"
                .to_string(),
        );
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private(ip) {
            return Err(
                "online_geo_url must not point at a private, loopback, \
                 link-local or metadata address"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if is_private_hostname(&host) {
        return Err("online_geo_url must not point at an internal host name \
             (localhost, *.local, *.internal or a single-label name)"
            .to_string());
    }
    Ok(())
}

/// Resolves the client IP for one login: a trusted forwarding header wins
/// when configured and present, otherwise the TCP peer address. With
/// several hops in the header, `trust_last_hop` picks the value appended by
/// the closest proxy rather than the client-controlled first entry.
pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    settings: &LoginSecuritySettings,
) -> Option<IpAddr> {
    if let Some(name) = &settings.trusted_header {
        if let Some(value) = headers
            .get(name.trim().to_ascii_lowercase())
            .and_then(|value| value.to_str().ok())
        {
            let mut hops = value
                .split(',')
                .map(str::trim)
                .filter(|hop| !hop.is_empty() && hop.parse::<IpAddr>().is_ok());
            if settings.trust_last_hop {
                if let Some(last) =
                    hops.next_back().and_then(|h| h.parse().ok())
                {
                    return Some(last);
                }
            } else if let Some(first) = hops.next().and_then(|h| h.parse().ok())
            {
                return Some(first);
            }
        }
    }
    peer
}

/// Looks up the geolocation of one address: the uploaded mmdb first (when
/// enabled), then the online API. Private addresses are never looked up;
/// failures return the `unknown` source with NULL geo fields.
pub async fn lookup_geo(
    ip: IpAddr,
    settings: &LoginSecuritySettings,
) -> GeoInfo {
    if is_private(ip) {
        return GeoInfo {
            source: crate::models::geo_source::PRIVATE,
            ..GeoInfo::default()
        };
    }
    if settings.geoip_local_enabled {
        if let Some(info) = lookup_mmdb(ip).await {
            return info;
        }
    }
    lookup_online(ip, settings).await
}

/// Reads the uploaded MaxMind-format database. Reopened per call — mmap
/// makes this cheap and an uploaded file is picked up without restarts.
async fn lookup_mmdb(ip: IpAddr) -> Option<GeoInfo> {
    let path = geoip_mmdb_path();
    let result = tokio::task::spawn_blocking(move || -> Option<GeoInfo> {
        let reader = maxminddb::Reader::open_readfile(&path).ok()?;
        // maxminddb 0.27: `lookup` returns a lazy `LookupResult` and
        // decoding happens separately through `decode`.
        let found: Option<maxminddb::geoip2::Country> =
            reader.lookup(ip).ok()?.decode().ok()?;
        let country = found?;
        Some(GeoInfo {
            // 0.27: `country` is a plain struct; `iso_code` is the
            // `Option<&str>`.
            country_code: country.country.iso_code.map(|code| code.to_string()),
            region: None,
            city: None,
            source: crate::models::geo_source::LOCAL,
        })
    })
    .await
    .ok()
    .flatten();
    result
}

/// The loose subset of the online API response we consume; unknown fields
/// are ignored by serde.
#[derive(Deserialize)]
struct OnlineGeo {
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
}

async fn lookup_online(
    ip: IpAddr,
    settings: &LoginSecuritySettings,
) -> GeoInfo {
    let url = settings.online_geo_url.replace("{ip}", &ip.to_string());
    // Belt and braces on the request path (D16): the stored value was checked
    // at save time, but a row written by an older build (or edited in the
    // database) must not turn one login into an internal probe. The client
    // already refuses redirects, so a public host cannot bounce us onto a
    // private one.
    if let Err(reason) = check_geo_url_host(&url) {
        tracing::warn!(
            url = %redact_url(&url),
            %reason,
            "skipping online geo lookup for a non-public URL"
        );
        return GeoInfo {
            source: crate::models::geo_source::UNKNOWN,
            ..GeoInfo::default()
        };
    }
    let parsed = match http_client().get(&url).send().await {
        Ok(response) => response.json::<OnlineGeo>().await.ok(),
        Err(_) => None,
    };
    match parsed {
        Some(geo) => match geo.country_code {
            Some(code) if !code.is_empty() => GeoInfo {
                country_code: Some(code),
                region: geo.region_name.filter(|r| !r.is_empty()),
                city: geo.city.filter(|c| !c.is_empty()),
                source: crate::models::geo_source::ONLINE,
            },
            _ => GeoInfo {
                source: crate::models::geo_source::UNKNOWN,
                ..GeoInfo::default()
            },
        },
        None => GeoInfo {
            source: crate::models::geo_source::UNKNOWN,
            ..GeoInfo::default()
        },
    }
}

/// The anomaly rule: with fewer than `baseline_count` resolved logins the
/// account has no baseline and nothing is flagged; otherwise a country the
/// baseline does not contain is anomalous.
pub fn is_anomalous(
    baseline: &[String],
    current: &str,
    baseline_count: u32,
) -> bool {
    if baseline.len() < usize::try_from(baseline_count).unwrap_or(3) {
        return false;
    }
    !baseline.iter().any(|country| country == current)
}

/// Recorded facts of one login: the resolved client IP and user agent.
pub struct LoginCapture {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

/// Resolves the IP and user agent for a login without touching the network
/// or the database — safe to run inline in the handler. Header trust is NOT
/// applied here (that needs the stored settings); the spawned task calls
/// `resolve_client_ip` again with the real settings before persisting.
pub fn capture_login(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> LoginCapture {
    LoginCapture {
        ip: peer,
        user_agent: headers
            .get(reqwest::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
    }
}

/// Records one login, looks up its geo and — when `judge` is set — compares
/// the country against the account's recent baseline, emitting an alert on
/// a mismatch. Runs detached; a failure only costs the history row.
#[allow(clippy::too_many_arguments)]
pub async fn record_login(
    db: &DatabaseConnection,
    user_id: Uuid,
    email: &str,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    judge: bool,
) {
    let settings = LoginSecuritySettings::load(db).await;
    let Some(ip) = resolve_client_ip(headers, peer, &settings) else {
        tracing::debug!(%email, "login recorded without an IP");
        return;
    };
    let user_agent = headers
        .get(reqwest::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    // Baseline first: the row about to be inserted must never count
    // towards its own comparison, or an attacker logging in repeatedly
    // would bleach the new country into the baseline.
    let mut baseline_countries = Vec::new();
    if judge && settings.anomaly_enabled {
        baseline_countries =
            recent_countries(db, user_id, settings.baseline_count).await;
    }

    let geo = lookup_geo(ip, &settings).await;
    let row = login_history::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        email: Set(email.to_string()),
        ip: Set(ip.to_string()),
        user_agent: Set(user_agent),
        country_code: Set(geo.country_code.clone()),
        region: Set(geo.region),
        city: Set(geo.city),
        geo_source: Set(geo.source.to_string()),
        created_at: Set(Utc::now()),
    };
    if let Err(err) = row.insert(db).await {
        tracing::warn!(error = %err, %email, "could not record login history");
        return;
    }

    if !judge || !settings.anomaly_enabled {
        return;
    }
    let Some(country) = geo.country_code else {
        return;
    };
    if !is_anomalous(&baseline_countries, &country, settings.baseline_count) {
        return;
    }
    notify::emit(AlertEvent {
        event_type: event_type::AUTH_LOGIN_ANOMALY.to_string(),
        severity: severity::WARNING,
        title: format!("Unusual login location for {email}"),
        message: format!(
            "'{email}' signed in from {country} ({ip}), which does not \
             appear in the last {} known login location(s): [{}]. Verify \
             this was the account owner.",
            settings.baseline_count,
            baseline_countries.join(", "),
        ),
        details: Some(serde_json::json!({
            "user_id": user_id.to_string(),
            "email": email,
            "ip": ip.to_string(),
            "country_code": country,
            "geo_source": geo.source,
            "baseline": baseline_countries,
        })),
        dedup_key: Some(format!("{user_id}:{country}")),
    })
    .await;
}

/// The most recent distinct-with-rows countries for one account: the last
/// `count` rows that carry a resolved country, oldest first.
async fn recent_countries(
    db: &DatabaseConnection,
    user_id: Uuid,
    count: u32,
) -> Vec<String> {
    let limit = u64::from(count);
    match login_history::Entity::find()
        .filter(login_history::Column::UserId.eq(user_id))
        .filter(login_history::Column::CountryCode.is_not_null())
        .order_by_desc(login_history::Column::CreatedAt)
        .limit(limit)
        .all(db)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|row| row.country_code)
            .collect(),
        Err(err) => {
            tracing::warn!(error = %err, "could not load login baseline");
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes())
                .expect("valid header name in tests"),
            value.parse().unwrap(),
        );
        headers
    }

    #[test]
    fn private_addresses_are_not_looked_up() {
        for address in [
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.0.5",
        ] {
            assert!(is_private(ip(address)), "{address}");
        }
        for address in ["8.8.8.8", "2606:4700::1111", "172.32.0.1"] {
            assert!(!is_private(ip(address)), "{address}");
        }
    }

    #[test]
    fn without_a_trusted_header_the_peer_wins() {
        let settings = LoginSecuritySettings::default();
        let headers = headers_with("x-forwarded-for", "1.2.3.4");
        let peer = Some(ip("203.0.113.9"));
        assert_eq!(resolve_client_ip(&headers, peer, &settings), peer);
        assert_eq!(resolve_client_ip(&headers, None, &settings), None);
    }

    #[test]
    fn a_trusted_header_replaces_the_peer() {
        let settings = LoginSecuritySettings {
            trusted_header: Some("x-forwarded-for".to_string()),
            ..LoginSecuritySettings::default()
        };
        let headers = headers_with("x-forwarded-for", "198.51.100.7, 10.0.0.1");
        assert_eq!(
            resolve_client_ip(&headers, Some(ip("203.0.113.9")), &settings),
            Some(ip("198.51.100.7"))
        );
        // Malformed hops are skipped, not trusted.
        let bad = headers_with("x-forwarded-for", "not-an-ip");
        assert_eq!(
            resolve_client_ip(&bad, Some(ip("203.0.113.9")), &settings),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn trust_last_hop_takes_the_closest_proxy_value() {
        let settings = LoginSecuritySettings {
            trusted_header: Some("x-forwarded-for".to_string()),
            trust_last_hop: true,
            ..LoginSecuritySettings::default()
        };
        let headers =
            headers_with("x-forwarded-for", "198.51.100.7, 203.0.113.5");
        assert_eq!(
            resolve_client_ip(&headers, Some(ip("10.0.0.1")), &settings),
            Some(ip("203.0.113.5"))
        );
    }

    #[test]
    fn anomaly_requires_a_full_baseline() {
        let baseline = vec!["CN".to_string(), "CN".to_string()];
        // Two known entries, baseline wants three: no judgement yet.
        assert!(!is_anomalous(&baseline, "US", 3));
        assert!(!is_anomalous(&[], "US", 3));
    }

    #[test]
    fn a_new_country_is_anomalous_once_the_baseline_is_full() {
        let baseline =
            vec!["CN".to_string(), "CN".to_string(), "JP".to_string()];
        assert!(is_anomalous(&baseline, "US", 3));
        assert!(!is_anomalous(&baseline, "JP", 3));
        assert!(!is_anomalous(&baseline, "CN", 3));
    }

    #[test]
    fn the_baseline_size_follows_the_setting() {
        let baseline = vec![
            "CN".to_string(),
            "JP".to_string(),
            "DE".to_string(),
            "FR".to_string(),
        ];
        // Baseline slice already truncated to n by the query; a shorter
        // slice than n disables the check.
        assert!(!is_anomalous(&baseline, "US", 5));
        assert!(is_anomalous(&baseline, "US", 4));
    }

    #[test]
    fn settings_defaults_and_validation() {
        let settings = LoginSecuritySettings::default();
        assert!(!settings.anomaly_enabled);
        assert_eq!(settings.baseline_count, 3);
        assert!(settings.trusted_header.is_none());
        assert!(settings.validate().is_ok());

        let bad = LoginSecuritySettings {
            online_geo_url: "https://geo.example/lookup".to_string(),
            ..LoginSecuritySettings::default()
        };
        assert!(bad.validate().is_err());

        let empty_header = LoginSecuritySettings {
            trusted_header: Some("  ".to_string()),
            ..LoginSecuritySettings::default()
        };
        assert!(empty_header.validate().is_err());
    }

    /// D16 regression: a stored geo URL pointing inside the deployment is
    /// refused on the request path too, so a row written by an older build
    /// cannot turn a login into an internal probe. `lookup_online` returns
    /// before any socket is opened, which is what makes this test offline.
    #[tokio::test]
    async fn a_private_geo_url_never_reaches_the_network() {
        for url in [
            "http://169.254.169.254/latest/meta-data/{ip}",
            "http://127.0.0.1:8080/{ip}",
            "http://localhost/{ip}",
            "http://10.1.2.3/{ip}",
            "http://[::1]/{ip}",
        ] {
            let settings = LoginSecuritySettings {
                online_geo_url: url.to_string(),
                ..LoginSecuritySettings::default()
            };
            // A public address, so `lookup_geo` reaches the online path.
            let geo = lookup_geo(ip("8.8.8.8"), &settings).await;
            assert_eq!(
                geo.source,
                crate::models::geo_source::UNKNOWN,
                "{url} produced {:?}",
                geo.source
            );
            assert!(geo.country_code.is_none(), "{url}");
        }
    }

    /// D16: log lines for a refused URL keep only the host — a provider key
    /// in the query string must not reach the log.
    #[test]
    fn refused_urls_are_logged_host_only() {
        assert_eq!(
            redact_url("https://geo.example.com/lookup?key=secret&ip=1.2.3.4"),
            "geo.example.com/…"
        );
        assert_eq!(redact_url("not a url"), "<unparsable>");
    }

    #[test]
    fn private_v4_mapped_v6_is_caught() {
        use std::net::Ipv6Addr;
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 168, 0, 1).to_ipv6_mapped());
        assert!(is_private(mapped));
        let _ = Ipv6Addr::LOCALHOST;
    }
}
