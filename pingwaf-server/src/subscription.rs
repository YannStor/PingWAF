//! Fetching and parsing IP group subscription sources.
//!
//! Two source styles are understood:
//! - Plain text: one IP or CIDR per line, `#` starts a comment.
//! - JSON: either Cloudflare's `/client/v4/ips` document
//!   (`result.ipv4_cidrs` / `result.ipv6_cidrs`, or the newer
//!   `result.items[].ip_prefix` list) or any JSON array of strings.
//!
//! Parsing never panics on foreign payloads: entries that do not parse as an
//! IP/CIDR are skipped, and an empty result is reported to the caller so a
//! broken upstream cannot wipe an existing group.
//!
//! The module also carries the compiled-in [`BUILTIN_SNAPSHOTS`]: vendor
//! range lists bundled with the binary so groups can track them without any
//! outbound fetch. Google and Yandex publish crawler networks; Cloudflare
//! publishes its edge network, which sites behind Cloudflare reference from
//! their trusted-proxy scope. DuckDuckGo is intentionally absent — it
//! publishes no official IP list, so its crawler is verified through the
//! bot-protection reverse-DNS check instead.

use serde_json::Value;
use uuid::Uuid;

/// Builds the HTTP client used for subscription fetches.
///
/// Redirects are disabled entirely: the SSRF guard (`ensure_host_is_public`)
/// only validates the source URL's host, so a public source answering with a
/// `302 -> http://169.254.169.254/` would bypass every IP check. A
/// subscription source that redirects has no legitimate use anyway — the
/// operator controls the source list, and a hostile source is exactly the
/// attacker model here.
pub fn subscription_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("PingWAF/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// Rejects source URLs the fetcher must never follow: only `http`/`https` to
/// a named host. This blocks `file:`, `data:` and other schemes whose fetch
/// could touch local resources or internal services.
pub fn validate_source_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|err| format!("invalid source URL: {err}"))?;
    match parsed.scheme() {
        "http" | "https" => {},
        other => {
            return Err(format!(
                "unsupported source URL scheme '{other}:', use http or https"
            ))
        },
    }
    if parsed.host_str().unwrap_or_default().is_empty() {
        return Err("source URL must include a host".to_string());
    }
    Ok(())
}

/// Returns `true` for addresses a subscription fetch must never touch:
/// loopback, RFC 1918 private ranges, link-local (including the cloud
/// metadata service 169.254.169.254), CGNAT `100.64.0.0/10`, IETF protocol
/// assignments `192.0.0.0/24`, benchmarking `198.18.0.0/15`, IPv6
/// link-local / unique-local, the NAT64 prefix `64:ff9b::/96`, IPv4-mapped
/// IPv6 (judged against the V4 blacklist), the unspecified and this-network
/// ranges, multicast and reserved space.
pub fn is_ip_blocked_for_fetch(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    use std::net::IpAddr::{V4, V6};
    match ip {
        V4(v4) => {
            // Shared CGNAT space.
            let cgnat = v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 0x40; // 100.64.0.0/10
                                                                                // IETF protocol assignments (e.g. port control protocol).
            let v4_reserved_by_ietf = v4.octets()[0] == 192
                && v4.octets()[1] == 0
                && v4.octets()[2] == 0; // 192.0.0.0/24
                                        // Benchmarking space, must never be a real peer.
            let benchmarking =
                v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 0x12; // 198.18.0.0/15
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || cgnat
                || v4_reserved_by_ietf
                || benchmarking
                || v4.octets()[0] == 0 // 0.0.0.0/8 ("this network")
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // Reserved: 240.0.0.0/4.
                || v4.octets()[0] & 0xf0 == 0xf0
        },
        V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) reaches V4 space over the
            // same wire as the plain literal — judge it by the V4 blacklist
            // instead of the V6 one, or `::ffff:169.254.169.254` sails by.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_ip_blocked_for_fetch(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.segments()[0] & 0xffc0 == 0xfe80 // fe80::/10 link-local
                // NAT64 prefix 64:ff9b::/96: a V6 address here embeds a V4
                // endpoint the V6 checks never see.
                || v6.segments()[0] == 0x64
                    && v6.segments()[1] == 0xff9b
                    && v6.segments()[2] == 0
                    && v6.segments()[3] == 0
                    && v6.segments()[4] == 0
                    && v6.segments()[5] == 0
        },
    }
}

/// Resolves the URL's host and rejects every fetch target inside the
/// non-routable ranges covered by [`is_ip_blocked_for_fetch`].
///
/// An IP-literal host is checked directly; a hostname is resolved and every
/// returned address must pass, so an A/AAAA record cannot smuggle an internal
/// endpoint behind a public-looking name.
pub async fn ensure_host_is_public(url: &str) -> Result<(), String> {
    validate_source_url(url)?;
    let parsed = reqwest::Url::parse(url)
        .map_err(|err| format!("invalid source URL: {err}"))?;
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "source URL must include a host".to_string())?;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_ip_blocked_for_fetch(ip) {
            return Err(format!(
                "source URL host {host} points into a private, loopback or \
                 otherwise non-public network and is not allowed"
            ));
        }
        return Ok(());
    }

    let port = parsed.port_or_known_default().unwrap_or(80);
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|err| format!("failed to resolve the source host: {err}"))?;
    for socket in resolved {
        if is_ip_blocked_for_fetch(socket.ip()) {
            return Err(format!(
                "source host {host} resolves to {}, which is inside a \
                 private, loopback or otherwise non-public network and is \
                 not allowed",
                socket.ip()
            ));
        }
    }
    Ok(())
}

/// Downloads a subscription source and returns its validated IP ranges.
pub async fn fetch_subscription_ranges(
    client: &reqwest::Client,
    url: &str,
) -> Result<Vec<String>, String> {
    // Re-checked here so every caller is covered, not just the API paths.
    validate_source_url(url)?;
    // Resolve-and-block the internal network ranges before any byte is sent:
    // scheme + host validation alone would let a URL reach loopback, RFC 1918
    // space or the cloud metadata service.
    ensure_host_is_public(url).await?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("source answered with HTTP {}", response.status()));
    }
    let body = response
        .text()
        .await
        .map_err(|err| format!("failed to read the response body: {err}"))?;
    parse_subscription(&body)
}

/// Parses a subscription body, auto-detecting JSON and plain-text layouts.
pub fn parse_subscription(body: &str) -> Result<Vec<String>, String> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        match serde_json::from_str::<Value>(trimmed) {
            Ok(json) => return json_ranges(&json),
            Err(_) => {
                return Err(
                    "source looks like JSON but does not parse".to_string()
                )
            },
        }
    }
    let ranges = text_ranges(body);
    if ranges.is_empty() {
        return Err("source returned no IP ranges".to_string());
    }
    Ok(ranges)
}

/// Extracts ranges from a JSON document.
fn json_ranges(json: &Value) -> Result<Vec<String>, String> {
    let mut raw: Vec<String> = Vec::new();

    // Plain JSON arrays of strings.
    if let Some(items) = json.as_array() {
        raw.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
    }

    // Cloudflare /client/v4/ips: `result.ipv4_cidrs` / `result.ipv6_cidrs`.
    let result = json.get("result").unwrap_or(json);
    if let Some(cidrs) = result.get("ipv4_cidrs").and_then(Value::as_array) {
        raw.extend(cidrs.iter().filter_map(Value::as_str).map(str::to_string));
    }
    if let Some(cidrs) = result.get("ipv6_cidrs").and_then(Value::as_array) {
        raw.extend(cidrs.iter().filter_map(Value::as_str).map(str::to_string));
    }
    // Newer Cloudflare layout: `result.items[].ip_prefix`.
    if let Some(items) = result.get("items").and_then(Value::as_array) {
        raw.extend(items.iter().filter_map(|item| {
            item.get("ip_prefix")
                .or_else(|| item.get("ip"))
                .and_then(Value::as_str)
                .map(str::to_string)
        }));
    }

    let ranges: Vec<String> = raw
        .into_iter()
        .filter_map(|entry| valid_range(&entry))
        .collect();
    if ranges.is_empty() {
        return Err("no IP ranges found in the JSON source".to_string());
    }
    Ok(ranges)
}

/// One IP or CIDR per line; blank lines and `#` comments are ignored.
fn text_ranges(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(valid_range)
        .collect()
}

/// Accepts a bare IP or a `pfx.len` CIDR (including IPv6 zone-free notation).
fn valid_range(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let base = trimmed.split('/').next().unwrap_or(trimmed);
    if base.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    Some(trimmed.to_string())
}

/// Fixed ids for the built-in subscription groups seeded at startup.
/// Constant ids keep the seeding idempotent across restarts and upgrades.
pub const BUILTIN_GOOGLE_GROUP_ID: Uuid =
    uuid::uuid!("9e770000-0000-4000-8000-000000000001");
pub const BUILTIN_YANDEX_GROUP_ID: Uuid =
    uuid::uuid!("9e770000-0000-4000-8000-000000000002");
pub const BUILTIN_CLOUDFLARE_GROUP_ID: Uuid =
    uuid::uuid!("9e770000-0000-4000-8000-000000000003");

/// A vendor IP range snapshot compiled into the binary.
pub struct BuiltinSnapshot {
    /// Stable key stored in `ip_groups.subscription_kind` is always
    /// `"builtin"`; the snapshot itself is resolved by the group's fixed id.
    pub group_id: Uuid,
    pub name: &'static str,
    pub description: &'static str,
    pub ranges: &'static [&'static str],
}

/// Compiled-in snapshots of vendor-published networks.
///
/// `GOOGLE_RANGES` mirrors `https://www.gstatic.com/ipranges/goog.json`
/// (fetched 2026-10-08) and covers all Google-owned networks, not only
/// Googlebot. `YANDEX_RANGES` mirrors the list published at
/// `https://yandex.com/ips` (fetched 2026-10-08). `CLOUDFLARE_RANGES`
/// mirrors `https://www.cloudflare.com/ips/` (fetched 2026-10-08) and
/// covers Cloudflare's edge networks — the direct peers of sites proxied
/// through Cloudflare. None of them change often; refreshes ship with new
/// releases.
pub static BUILTIN_SNAPSHOTS: &[BuiltinSnapshot] = &[
    BuiltinSnapshot {
        group_id: BUILTIN_GOOGLE_GROUP_ID,
        name: "Google",
        description: "Built-in snapshot of Google's published networks \
                      (gstatic.com/ipranges/goog.json). Covers all \
                      Google-owned networks, not just Googlebot.",
        ranges: GOOGLE_RANGES,
    },
    BuiltinSnapshot {
        group_id: BUILTIN_YANDEX_GROUP_ID,
        name: "Yandex",
        description: "Built-in snapshot of the crawler networks Yandex \
                      publishes at yandex.com/ips.",
        ranges: YANDEX_RANGES,
    },
    BuiltinSnapshot {
        group_id: BUILTIN_CLOUDFLARE_GROUP_ID,
        name: "Cloudflare",
        description: "Built-in snapshot of the edge networks Cloudflare \
                      publishes at cloudflare.com/ips. Reference this group \
                      in a site's trusted-proxy scope when the site sits \
                      behind Cloudflare.",
        ranges: CLOUDFLARE_RANGES,
    },
];

/// Resolves a built-in snapshot by the fixed group id.
pub fn builtin_snapshot(group_id: Uuid) -> Option<&'static BuiltinSnapshot> {
    BUILTIN_SNAPSHOTS
        .iter()
        .find(|snapshot| snapshot.group_id == group_id)
}

static GOOGLE_RANGES: &[&str] = &[
    "104.154.0.0/15",
    "104.196.0.0/14",
    "104.237.160.0/19",
    "107.167.160.0/19",
    "107.178.192.0/18",
    "108.170.192.0/18",
    "108.177.0.0/17",
    "108.59.80.0/20",
    "130.211.0.0/16",
    "136.107.0.0/16",
    "136.108.0.0/14",
    "136.112.0.0/13",
    "136.120.0.0/22",
    "136.121.8.0/21",
    "136.124.0.0/15",
    "136.22.160.0/20",
    "136.22.176.0/21",
    "136.22.184.0/23",
    "136.22.186.0/24",
    "136.22.2.0/23",
    "136.22.4.0/23",
    "136.22.8.0/22",
    "136.23.39.0/24",
    "136.23.48.0/20",
    "136.23.64.0/18",
    "136.64.0.0/11",
    "142.250.0.0/15",
    "146.148.0.0/17",
    "152.238.0.0/16",
    "152.239.128.0/17",
    "162.120.128.0/17",
    "162.216.148.0/22",
    "162.222.176.0/21",
    "172.110.32.0/21",
    "172.217.0.0/16",
    "172.253.0.0/16",
    "173.194.0.0/16",
    "173.255.112.0/20",
    "177.176.0.0/16",
    "177.178.0.0/15",
    "177.208.0.0/15",
    "179.193.128.0/17",
    "179.199.0.0/17",
    "179.67.0.0/17",
    "179.69.128.0/17",
    "186.242.0.0/17",
    "186.245.0.0/16",
    "187.126.128.0/17",
    "187.78.0.0/17",
    "187.79.0.0/17",
    "189.105.128.0/17",
    "189.106.0.0/15",
    "189.24.128.0/17",
    "189.48.0.0/16",
    "189.49.128.0/17",
    "189.70.0.0/15",
    "189.82.0.0/15",
    "191.0.128.0/17",
    "191.2.0.0/15",
    "191.212.0.0/15",
    "191.216.128.0/17",
    "191.218.0.0/17",
    "191.220.0.0/15",
    "191.40.128.0/17",
    "191.44.128.0/17",
    "191.45.128.0/17",
    "191.46.0.0/15",
    "192.104.160.0/23",
    "192.158.28.0/22",
    "192.178.0.0/15",
    "193.186.4.0/24",
    "199.192.112.0/22",
    "199.223.232.0/21",
    "199.36.154.0/23",
    "199.36.156.0/24",
    "200.226.0.0/16",
    "207.175.0.0/16",
    "207.223.160.0/20",
    "208.117.224.0/19",
    "208.65.152.0/22",
    "208.68.108.0/22",
    "208.81.188.0/22",
    "209.85.128.0/17",
    "216.239.32.0/19",
    "216.252.220.0/22",
    "216.58.192.0/19",
    "216.73.80.0/20",
    "23.236.48.0/20",
    "23.251.128.0/19",
    "34.0.0.0/15",
    "34.128.0.0/10",
    "34.16.0.0/12",
    "34.2.0.0/16",
    "34.3.0.0/23",
    "34.3.16.0/20",
    "34.3.3.0/24",
    "34.3.32.0/19",
    "34.3.4.0/24",
    "34.3.64.0/18",
    "34.3.8.0/21",
    "34.32.0.0/11",
    "34.4.0.0/14",
    "34.64.0.0/10",
    "34.8.0.0/13",
    "35.184.0.0/13",
    "35.192.0.0/14",
    "35.196.0.0/15",
    "35.198.0.0/16",
    "35.199.0.0/17",
    "35.199.128.0/18",
    "35.200.0.0/13",
    "35.208.0.0/12",
    "35.224.0.0/12",
    "35.240.0.0/13",
    "35.252.0.0/14",
    "64.15.112.0/20",
    "64.233.160.0/19",
    "66.102.0.0/20",
    "66.249.64.0/19",
    "70.32.128.0/19",
    "72.14.192.0/18",
    "74.114.24.0/21",
    "74.125.0.0/16",
    "8.228.0.0/14",
    "8.232.0.0/14",
    "8.236.0.0/15",
    "8.34.208.0/20",
    "8.35.192.0/20",
    "8.8.4.0/24",
    "8.8.8.0/24",
    "2001:4860::/32",
    "2404:6800::/32",
    "2404:f340::/32",
    "2600:1900::/29",
    "2605:ef80::/32",
    "2606:40::/32",
    "2606:73c0::/32",
    "2607:1c0:241:40::/60",
    "2607:1c0:300::/40",
    "2607:f8b0::/32",
    "2620:11a:a000::/40",
    "2620:120:e000::/40",
    "2800:3f0::/32",
    "2a00:1450::/32",
    "2c0f:fb50::/32",
];

static YANDEX_RANGES: &[&str] = &[
    "141.8.128.0/18",
    "178.154.128.0/18",
    "185.32.187.0/24",
    "213.180.192.0/19",
    "37.140.128.0/18",
    "37.9.64.0/18",
    "5.255.192.0/18",
    "5.45.192.0/18",
    "77.88.0.0/18",
    "84.252.160.0/19",
    "87.250.224.0/19",
    "90.156.176.0/20",
    "92.255.112.0/20",
    "93.158.128.0/18",
    "95.108.128.0/17",
    "2a02:6b8::/29",
];

static CLOUDFLARE_RANGES: &[&str] = &[
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32",
    "2405:8100::/32",
    "2405:b500::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_text_lists() {
        let body = "# comment\n173.245.48.0/20\n\n10.0.0.1\nnot-an-ip\n2400:cb00::/32\n";
        let ranges = parse_subscription(body).unwrap();
        assert_eq!(
            ranges,
            vec!["173.245.48.0/20", "10.0.0.1", "2400:cb00::/32"]
        );
    }

    #[test]
    fn parses_cloudflare_ips_document() {
        let body = r#"{
            "success": true,
            "result": {
                "etag": "abc",
                "ipv4_cidrs": ["173.245.48.0/20", "103.21.244.0/22"],
                "ipv6_cidrs": ["2400:cb00::/32"]
            }
        }"#;
        let ranges = parse_subscription(body).unwrap();
        assert_eq!(
            ranges,
            vec!["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"]
        );
    }

    #[test]
    fn parses_cloudflare_items_document() {
        let body = r#"{
            "result": { "items": [
                { "ip_prefix": "173.245.48.0/20" },
                { "ip_prefix": "2400:cb00::/32" }
            ]}
        }"#;
        let ranges = parse_subscription(body).unwrap();
        assert_eq!(ranges, vec!["173.245.48.0/20", "2400:cb00::/32"]);
    }

    #[test]
    fn parses_json_array_of_strings() {
        let ranges = parse_subscription(r#"["10.0.0.0/8", "junk"]"#).unwrap();
        assert_eq!(ranges, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn rejects_empty_and_broken_sources() {
        assert!(parse_subscription("").is_err());
        assert!(parse_subscription("# only comments\n").is_err());
        assert!(parse_subscription("{not json").is_err());
        assert!(parse_subscription(r#"{"result": {}}"#).is_err());
    }

    #[test]
    fn fetch_targets_in_private_networks_are_blocked() {
        use std::net::IpAddr;
        let parse = |s: &str| s.parse::<IpAddr>().unwrap();
        // Loopback.
        assert!(is_ip_blocked_for_fetch(parse("127.0.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("127.8.8.8")));
        assert!(is_ip_blocked_for_fetch(parse("::1")));
        // RFC 1918.
        assert!(is_ip_blocked_for_fetch(parse("10.1.2.3")));
        assert!(is_ip_blocked_for_fetch(parse("172.16.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("172.31.255.255")));
        assert!(is_ip_blocked_for_fetch(parse("192.168.0.5")));
        // 172.32.0.0+ is public again — the /12 bound must hold.
        assert!(!is_ip_blocked_for_fetch(parse("172.32.0.1")));
        // Link-local, including the cloud metadata service.
        assert!(is_ip_blocked_for_fetch(parse("169.254.169.254")));
        assert!(is_ip_blocked_for_fetch(parse("fe80::1")));
        // Unique-local.
        assert!(is_ip_blocked_for_fetch(parse("fc00::1")));
        assert!(is_ip_blocked_for_fetch(parse("fd12:3456::1")));
        // This-network, broadcast, multicast, reserved.
        assert!(is_ip_blocked_for_fetch(parse("0.0.0.0")));
        assert!(is_ip_blocked_for_fetch(parse("0.1.2.3")));
        assert!(is_ip_blocked_for_fetch(parse("255.255.255.255")));
        assert!(is_ip_blocked_for_fetch(parse("240.0.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("224.0.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("ff02::1")));
        // Public addresses stay allowed.
        assert!(!is_ip_blocked_for_fetch(parse("8.8.8.8")));
        assert!(!is_ip_blocked_for_fetch(parse("1.1.1.1")));
        assert!(!is_ip_blocked_for_fetch(parse("2606:4700::1111")));
    }

    #[test]
    fn mapped_ipv6_and_extended_v4_ranges_are_blocked() {
        use std::net::IpAddr;
        let parse = |s: &str| s.parse::<IpAddr>().unwrap();
        // IPv4-mapped IPv6 must be judged by the V4 blacklist.
        assert!(is_ip_blocked_for_fetch(parse("::ffff:169.254.169.254")));
        assert!(is_ip_blocked_for_fetch(parse("::ffff:10.0.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("::ffff:127.0.0.1")));
        // CGNAT 100.64.0.0/10, both bounds and beyond.
        assert!(is_ip_blocked_for_fetch(parse("100.64.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("100.127.255.254")));
        assert!(!is_ip_blocked_for_fetch(parse("100.128.0.1")));
        assert!(!is_ip_blocked_for_fetch(parse("100.63.255.254")));
        // IETF protocol assignments 192.0.0.0/24.
        assert!(is_ip_blocked_for_fetch(parse("192.0.0.9")));
        assert!(!is_ip_blocked_for_fetch(parse("192.0.1.1")));
        // Benchmarking 198.18.0.0/15.
        assert!(is_ip_blocked_for_fetch(parse("198.18.0.1")));
        assert!(is_ip_blocked_for_fetch(parse("198.19.255.1")));
        assert!(!is_ip_blocked_for_fetch(parse("198.20.0.1")));
        // NAT64 prefix 64:ff9b::/96 embedding a private V4 endpoint.
        assert!(is_ip_blocked_for_fetch(parse("64:ff9b::a00:1")));
        // The whole NAT64 prefix is refused, not only private embeds.
        assert!(is_ip_blocked_for_fetch(parse("64:ff9b::808:808")));
        // A public V6 address outside the NAT64 prefix stays allowed.
        assert!(!is_ip_blocked_for_fetch(parse("2606:4700::1111")));
    }

    #[tokio::test]
    async fn ip_literal_hosts_are_checked_directly() {
        assert!(ensure_host_is_public("http://169.254.169.254/latest")
            .await
            .is_err());
        assert!(ensure_host_is_public("http://10.0.0.1/list").await.is_err());
        assert!(ensure_host_is_public("http://[::1]/list").await.is_err());
        assert!(ensure_host_is_public("https://1.1.1.1/ips").await.is_ok());
    }

    #[test]
    fn source_urls_must_be_http_or_https() {
        assert!(
            validate_source_url("https://www.cloudflare.com/ips-v4").is_ok()
        );
        assert!(validate_source_url("http://internal.example/list").is_ok());

        // Schemes that could touch local resources or opaque payloads.
        assert!(validate_source_url("file:///etc/passwd").is_err());
        assert!(validate_source_url("data:text/plain,1.2.3.4").is_err());
        assert!(validate_source_url("ftp://mirror.example/list").is_err());
        // No scheme and no host are both rejected.
        assert!(validate_source_url("www.cloudflare.com/ips-v4").is_err());
        assert!(validate_source_url("http://").is_err());
    }

    #[test]
    fn builtin_snapshots_are_non_empty_and_valid() {
        for snapshot in BUILTIN_SNAPSHOTS {
            assert!(!snapshot.ranges.is_empty(), "{}", snapshot.name);
            for range in snapshot.ranges {
                let base = range.split('/').next().unwrap_or(range);
                assert!(
                    base.parse::<std::net::IpAddr>().is_ok(),
                    "{}: invalid range {range}",
                    snapshot.name
                );
            }
        }
        assert_eq!(BUILTIN_SNAPSHOTS.len(), 3);
    }

    #[test]
    fn builtin_snapshot_resolves_by_group_id() {
        let google = builtin_snapshot(BUILTIN_GOOGLE_GROUP_ID).unwrap();
        assert_eq!(google.name, "Google");
        let yandex = builtin_snapshot(BUILTIN_YANDEX_GROUP_ID).unwrap();
        assert_eq!(yandex.name, "Yandex");
        let cloudflare = builtin_snapshot(BUILTIN_CLOUDFLARE_GROUP_ID).unwrap();
        assert_eq!(cloudflare.name, "Cloudflare");
        assert!(builtin_snapshot(Uuid::new_v4()).is_none());
    }
}
