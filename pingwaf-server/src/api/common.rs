//! Helpers shared by the API route modules: pagination, identifier parsing and
//! the multi-tenancy checks that every handler performs before touching data.

use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Statement,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::auth::AuthUser;
use crate::models::{acme_challenge, site};

/// Default number of rows returned by a list endpoint.
pub const DEFAULT_PAGE_SIZE: u64 = 50;
/// Upper bound accepted from clients, to keep queries predictable.
pub const MAX_PAGE_SIZE: u64 = 200;

/// `?page=&page_size=` query parameters.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Pagination {
    #[serde(default = "default_page", deserialize_with = "deserialize_u64")]
    pub page: u64,
    #[serde(
        default = "default_page_size",
        deserialize_with = "deserialize_u64"
    )]
    pub page_size: u64,
}

/// Accepts an integer whether it arrives as a number or as a string.
///
/// The list handlers flatten [`Pagination`] into their own query struct, and
/// the query-string extractor hands the buffered flattened values over as
/// strings; the default `u64` visitor would reject `page_size=200` with
/// "invalid type: string \"200\", expected u64".
fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use std::fmt;

    use serde::de::{Error, Visitor};

    struct U64Visitor;

    impl<'de> Visitor<'de> for U64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an unsigned integer or a decimal string")
        }

        fn visit_u64<E: Error>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }

        fn visit_i64<E: Error>(self, value: i64) -> Result<u64, E> {
            u64::try_from(value)
                .map_err(|_| E::custom("expected a non-negative integer"))
        }

        fn visit_str<E: Error>(self, value: &str) -> Result<u64, E> {
            value
                .trim()
                .parse()
                .map_err(|_| E::custom(format!("invalid integer '{value}'")))
        }
    }

    deserializer.deserialize_any(U64Visitor)
}

fn default_page() -> u64 {
    1
}

fn default_page_size() -> u64 {
    DEFAULT_PAGE_SIZE
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl Pagination {
    /// Clamps user supplied values into the supported range.
    pub fn normalise(&self) -> Self {
        Self {
            page: self.page.max(1),
            page_size: self.page_size.clamp(1, MAX_PAGE_SIZE),
        }
    }

    /// Zero-based page index used by [`sea_orm::PaginatorTrait::fetch_page`].
    pub fn index(&self) -> u64 {
        self.normalise().page - 1
    }

    pub fn limit(&self) -> u64 {
        self.normalise().page_size
    }

    pub fn offset(&self) -> u64 {
        self.index() * self.limit()
    }
}

/// Envelope returned by every list endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: u64, pagination: Pagination) -> Self {
        let p = pagination.normalise();
        Self {
            items,
            total,
            page: p.page,
            page_size: p.page_size,
        }
    }

    pub fn empty(pagination: Pagination) -> Self {
        Self::new(Vec::new(), 0, pagination)
    }
}

/// Parses a path/query UUID with a 400 instead of a 500.
pub fn parse_uuid(value: &str, what: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value.trim()).map_err(|err| {
        ApiError::BadRequest(format!("invalid {what} '{value}': {err}"))
    })
}

/// Parses an RFC 3339 timestamp filter.
pub fn parse_datetime(
    value: &str,
    what: &str,
) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value.trim())
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| {
            ApiError::BadRequest(format!("invalid {what} '{value}': {err}"))
        })
}

/// Optional RFC 3339 filter that tolerates an empty string.
pub fn parse_optional_datetime(
    value: &Option<String>,
    what: &str,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    match value {
        None => Ok(None),
        Some(raw) if raw.trim().is_empty() => Ok(None),
        Some(raw) => parse_datetime(raw, what).map(Some),
    }
}

/// Guards against a non-admin role performing a mutation (`viewer` and
/// `auditor` are read-only).
///
/// Accounts flagged `must_change_password` are also refused: the console
/// walks them through the password change first.
pub fn require_write(user: &AuthUser) -> Result<(), ApiError> {
    if !user.is_admin() {
        return Err(ApiError::Forbidden(
            "this account cannot modify resources".to_string(),
        ));
    }
    if user.must_change_password {
        return Err(ApiError::Forbidden(
            "change your password before making changes".to_string(),
        ));
    }
    Ok(())
}

/// Loads a site and asserts that `user` may see (and optionally mutate) it.
///
/// Administrators see every site; other roles only see sites they own. A site
/// owned by somebody else is reported as `404` rather than `403` so that the API
/// does not leak which domains exist.
pub async fn load_site(
    db: &DatabaseConnection,
    site_id: Uuid,
    user: &AuthUser,
    write: bool,
) -> Result<site::Model, ApiError> {
    let model = site::Entity::find_by_id(site_id)
        .one(db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("site {site_id} not found"))
        })?;

    if !user.is_admin() {
        if model.user_id != user.id {
            return Err(ApiError::NotFound(format!(
                "site {site_id} not found"
            )));
        }
        if write {
            require_write(user)?;
        }
    }
    Ok(model)
}

/// Convenience wrapper around [`load_site`] for read-only handlers.
pub async fn load_site_read(
    db: &DatabaseConnection,
    site_id: Uuid,
    user: &AuthUser,
) -> Result<site::Model, ApiError> {
    load_site(db, site_id, user, false).await
}

/// Convenience wrapper around [`load_site`] for mutating handlers.
pub async fn load_site_write(
    db: &DatabaseConnection,
    site_id: Uuid,
    user: &AuthUser,
) -> Result<site::Model, ApiError> {
    load_site(db, site_id, user, true).await
}

/// Drops a `:port` suffix from a `Host` header value.
///
/// Used wherever the host has to become a name rather than an authority: a
/// WebAuthn relying party id and a certificate subject alternative name both
/// reject the port part.
pub fn host_without_port(host: &str) -> &str {
    // Brackets delimit an IPv6 literal, never a port.
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((address, _)) => address,
            None => rest,
        };
    }
    match host.rsplit_once(':') {
        Some((domain, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => {
            domain
        },
        _ => host,
    }
}

/// Restricts a site id filter to what `user` is allowed to query.
///
/// Returns `None` when the caller asked for "all sites" *and* is an admin; in
/// every other case handlers must filter by the returned id.
pub fn scope_site(
    requested: Option<Uuid>,
    user: &AuthUser,
) -> Result<Option<Uuid>, ApiError> {
    match requested {
        Some(id) => Ok(Some(id)),
        None if user.is_admin() => Ok(None),
        None => Err(ApiError::BadRequest(
            "site_id is required for non-admin accounts".to_string(),
        )),
    }
}

/// Trims an optional filter string, turning blanks into `None`.
pub fn non_empty(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

/// Runs a parameterised read-only statement.
pub async fn query_all(
    db: &DatabaseConnection,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> Result<Vec<sea_orm::QueryResult>, ApiError> {
    db.query_all(Statement::from_sql_and_values(
        sea_orm::DatabaseBackend::Postgres,
        sql,
        values,
    ))
    .await
    .map_err(ApiError::from)
}

/// Strips a trailing slash so that both `/api/v1/sites` and `/api/v1/sites/`
/// behave the same when building absolute URLs.
pub fn trim_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// Lower-cases and validates a hostname.
///
/// A wildcard is only accepted as the whole left-most label (`*.example.com`)
/// and its base needs at least two labels, so `*` and `*.com` are rejected:
/// pingap's host selector would otherwise swallow every name under a TLD.
pub fn normalise_domain(value: &str) -> Result<String, ApiError> {
    let domain = value.trim().trim_start_matches('.').to_lowercase();
    let domain = trim_trailing_slash(&domain)
        .trim_end_matches('.')
        .to_string();
    if domain.is_empty() || domain.len() > 253 {
        return Err(ApiError::BadRequest(format!(
            "invalid domain '{value}': must be 1-253 characters"
        )));
    }

    let labels: Vec<&str> = domain.split('.').collect();
    let wildcard = labels.first() == Some(&"*");
    if !wildcard && labels.iter().any(|label| label.contains('*')) {
        return Err(ApiError::BadRequest(format!(
            "invalid domain '{value}': a wildcard must be the leading label and look like '*.example.com'"
        )));
    }
    if wildcard && labels.len() < 3 {
        return Err(ApiError::BadRequest(format!(
            "invalid domain '{value}': a wildcard needs at least two labels after '*.'"
        )));
    }
    let rest = if wildcard { &labels[1..] } else { &labels[..] };
    if rest.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label.chars().all(is_domain_char)
    }) {
        return Err(ApiError::BadRequest(format!(
            "invalid domain '{value}': labels may only contain letters, digits, '-' and '_'"
        )));
    }
    Ok(domain)
}

fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Normalises the hostnames of one site and rejects duplicates inside it.
///
/// `primary` is the site's own domain; alternates come from the caller. The
/// first repeated hostname (against the primary or another alternate) is an
/// error rather than something to silently swallow.
pub fn normalise_domain_list(
    primary: &str,
    alternates: &[String],
) -> Result<Vec<String>, ApiError> {
    let mut seen = std::collections::HashSet::new();
    seen.insert(primary.to_string());
    let mut result = Vec::with_capacity(alternates.len());
    for raw in alternates {
        let domain = normalise_domain(raw)?;
        if !seen.insert(domain.clone()) {
            return Err(ApiError::BadRequest(format!(
                "domain '{domain}' appears twice: the primary domain and alternate_domains must be distinct"
            )));
        }
        result.push(domain);
    }
    Ok(result)
}

/// Rejects two sites whose hostname sets would make request routing ambiguous.
///
/// pingap routes a Host header by suffix match with a flat weight, so two sites
/// may not lay claim to overlapping names: identical hostnames, a wildcard of
/// one site covering a hostname of the other, or two nested wildcards all make
/// the winner depend on configuration order. An apex and its wildcard
/// (`example.com` plus `*.example.com`) are fine — a wildcard never matches the
/// apex itself.
pub fn ensure_no_domain_conflict(
    site_a: &[String],
    site_b: &[String],
) -> Result<(), ApiError> {
    for left in site_a {
        for right in site_b {
            if left == right {
                return Err(ApiError::BadRequest(format!(
                    "domain '{left}' is already served by another site"
                )));
            }
            for (wildcard, exact) in [(left, right), (right, left)] {
                if let Some(base) = wildcard.strip_prefix("*.") {
                    if exact.ends_with(&format!(".{base}")) {
                        return Err(ApiError::BadRequest(format!(
                            "domain '{exact}' falls under the wildcard '{wildcard}' of another site"
                        )));
                    }
                }
            }
            if let (Some(base_a), Some(base_b)) =
                (left.strip_prefix("*."), right.strip_prefix("*."))
            {
                let nested_in_a = base_a.ends_with(&format!(".{base_b}"));
                let nested_in_b = base_b.ends_with(&format!(".{base_a}"));
                if nested_in_a || nested_in_b {
                    return Err(ApiError::BadRequest(format!(
                        "wildcard '{left}' overlaps wildcard '{right}' of another site"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Refuses an ACME order a wildcard hostname can never satisfy.
///
/// `http-01` proves control of one hostname at a time, so a certificate for
/// `*.example.com` can only come from `dns-01`. Rejecting the combination at
/// the API keeps the agent from retrying an order that can never succeed;
/// the data plane keeps its own copy of this guard for rows written before
/// the check existed.
pub fn ensure_acme_wildcard_supported(
    site: &site::Model,
    extra_domains: &[String],
    challenge: Option<&str>,
) -> Result<(), ApiError> {
    let wildcard = site.domain.starts_with("*.")
        || site.alternate_domains.iter().any(|d| d.starts_with("*."))
        || extra_domains.iter().any(|d| d.starts_with("*."));
    if !wildcard {
        return Ok(());
    }
    if challenge.unwrap_or(acme_challenge::HTTP_01) != acme_challenge::DNS_01 {
        return Err(ApiError::BadRequest(
            "a wildcard domain requires the dns-01 ACME challenge — http-01 cannot validate '*.example.com'; switch the challenge type to dns-01 and configure a DNS provider"
                .to_string(),
        ));
    }
    Ok(())
}

/// Checks a site's hostname set against every other site in the database.
///
/// `exclude` is the site being edited, so that a site does not conflict with
/// itself. New sites pass `None`.
pub async fn ensure_domains_available(
    db: &DatabaseConnection,
    domains: &[String],
    exclude: Option<Uuid>,
) -> Result<(), ApiError> {
    let mut query = site::Entity::find();
    if let Some(id) = exclude {
        query = query.filter(site::Column::Id.ne(id));
    }
    let others = query.all(db).await?;
    for other in others {
        let mut existing = vec![other.domain.clone()];
        existing.extend(other.alternate_domains.clone());
        ensure_no_domain_conflict(domains, &existing)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_is_clamped() {
        assert_eq!(Pagination::default().limit(), DEFAULT_PAGE_SIZE);
        assert_eq!(Pagination::default().offset(), 0);

        let huge = Pagination {
            page: 0,
            page_size: 10_000,
        };
        assert_eq!(huge.normalise().page, 1);
        assert_eq!(huge.limit(), MAX_PAGE_SIZE);

        let third = Pagination {
            page: 3,
            page_size: 20,
        };
        assert_eq!(third.index(), 2);
        assert_eq!(third.offset(), 40);
    }

    #[test]
    fn pagination_accepts_flattened_strings() {
        #[derive(Debug, Deserialize)]
        struct ListQuery {
            #[serde(flatten)]
            pagination: Pagination,
            search: Option<String>,
        }

        // Flattened values reach the struct buffered as strings, exactly like
        // `?page_size=200` in a real query string.
        let query: ListQuery = serde_json::from_str(
            r#"{"page_size":"200","page":"2","search":"web"}"#,
        )
        .expect("string values are accepted");
        assert_eq!(query.pagination.page, 2);
        assert_eq!(query.pagination.page_size, 200);
        assert_eq!(query.search.as_deref(), Some("web"));

        // Numbers and absent keys still work.
        let query: ListQuery =
            serde_json::from_str(r#"{"page_size":20}"#).unwrap();
        assert_eq!(query.pagination.page, 1);
        assert_eq!(query.pagination.page_size, 20);

        let query: ListQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.pagination.page_size, DEFAULT_PAGE_SIZE);

        // Garbage is still a hard error.
        assert!(serde_json::from_str::<ListQuery>(r#"{"page":"abc"}"#).is_err());
    }

    #[test]
    fn domains_are_normalised_and_validated() {
        assert_eq!(normalise_domain(" Example.COM ").unwrap(), "example.com");
        assert_eq!(normalise_domain(".Example.com.").unwrap(), "example.com");
        assert_eq!(normalise_domain("*.Example.COM").unwrap(), "*.example.com");
        assert!(normalise_domain("").is_err());
        assert!(normalise_domain("bad domain.com").is_err());
        assert!(normalise_domain("a..b.com").is_err());
    }

    #[test]
    fn wildcards_need_a_real_base_domain() {
        // Legitimate wildcards: base is at least two labels.
        assert_eq!(normalise_domain("*.example.com").unwrap(), "*.example.com");
        assert_eq!(normalise_domain("*.co.uk").unwrap(), "*.co.uk");
        assert_eq!(
            normalise_domain("*.api.example.com").unwrap(),
            "*.api.example.com"
        );

        // `*` may only stand as the whole leading label.
        assert!(normalise_domain("*").is_err());
        assert!(normalise_domain("*.com").is_err());
        assert!(normalise_domain("foo*bar.com").is_err());
        assert!(normalise_domain("foo.*.com").is_err());
        assert!(normalise_domain("*.*.example.com").is_err());
        assert!(normalise_domain("**.example.com").is_err());
    }

    #[test]
    fn domain_lists_reject_duplicates() {
        let alternates = vec!["api.example.com".to_string()];
        assert_eq!(
            normalise_domain_list("example.com", &alternates).unwrap(),
            vec!["api.example.com".to_string()]
        );

        // A repeat of the primary domain or of another alternate is an error,
        // even when the spelling differs in case.
        assert!(
            normalise_domain_list("example.com", &["Example.com".into()])
                .is_err()
        );
        assert!(normalise_domain_list(
            "example.com",
            &["a.example.com".into(), "A.example.com".into()]
        )
        .is_err());
        // A wildcard inside the same site may coexist with its apex.
        assert!(normalise_domain_list(
            "example.com",
            &["*.example.com".into()]
        )
        .is_ok());
    }

    #[test]
    fn wildcard_acme_orders_need_dns01() {
        let timestamp = Utc::now();
        let mut site = site::Model {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "shop".to_string(),
            domain: "*.example.com".to_string(),
            alternate_domains: Vec::new(),
            status: "active".to_string(),
            plan: "free".to_string(),
            cache_quota_mb: 1024,
            cache_max_file_size_mb: None,
            cache_type_limits_mb: None,
            trust_proxy_headers: false,
            trusted_header: crate::models::trusted_header::DEFAULT.to_string(),
            trust_last_hop: true,
            failover_policy: "inherit".to_string(),
            trusted_proxy_ranges: Vec::new(),
            trusted_proxy_group_ids: Vec::new(),
            created_at: timestamp,
            updated_at: timestamp,
        };
        // The default challenge is http-01, which a wildcard cannot pass.
        assert!(ensure_acme_wildcard_supported(&site, &[], None).is_err());
        assert!(ensure_acme_wildcard_supported(&site, &[], Some("http-01"))
            .is_err());
        assert!(
            ensure_acme_wildcard_supported(&site, &[], Some("dns-01")).is_ok()
        );

        // A wildcard among the alternates (or in the certificate's own
        // hostname list) counts too.
        site.domain = "example.com".to_string();
        site.alternate_domains = vec!["*.shop.example.com".to_string()];
        assert!(ensure_acme_wildcard_supported(&site, &[], Some("http-01"))
            .is_err());
        site.alternate_domains.clear();
        assert!(ensure_acme_wildcard_supported(
            &site,
            &["*.other.com".to_string()],
            Some("http-01")
        )
        .is_err());

        // Plain hostnames are unaffected.
        assert!(
            ensure_acme_wildcard_supported(&site, &[], Some("http-01")).is_ok()
        );
    }

    #[test]
    fn cross_site_domains_must_not_overlap() {
        let set = |items: &[&str]| -> Vec<String> {
            items.iter().map(|item| item.to_string()).collect()
        };

        // Exact collisions are refused, in every position.
        assert!(ensure_no_domain_conflict(
            &set(&["example.com"]),
            &set(&["example.com"])
        )
        .is_err());
        assert!(ensure_no_domain_conflict(
            &set(&["example.com", "api.example.com"]),
            &set(&["api.example.com"])
        )
        .is_err());
        assert!(ensure_no_domain_conflict(
            &set(&["*.example.com"]),
            &set(&["*.example.com"])
        )
        .is_err());

        // A wildcard of one site must not cover a hostname of the other.
        assert!(ensure_no_domain_conflict(
            &set(&["*.example.com"]),
            &set(&["app.example.com"])
        )
        .is_err());
        assert!(ensure_no_domain_conflict(
            &set(&["app.example.com"]),
            &set(&["*.example.com"])
        )
        .is_err());
        assert!(ensure_no_domain_conflict(
            &set(&["*.example.com"]),
            &set(&["foo.bar.example.com"])
        )
        .is_err());

        // Nested wildcards are ambiguous too.
        assert!(ensure_no_domain_conflict(
            &set(&["*.example.com"]),
            &set(&["*.api.example.com"])
        )
        .is_err());

        // The apex and its own wildcard live together; a wildcard never
        // matches the bare apex.
        assert!(ensure_no_domain_conflict(
            &set(&["example.com"]),
            &set(&["*.example.com"])
        )
        .is_ok());
        assert!(ensure_no_domain_conflict(
            &set(&["example.com"]),
            &set(&["*.other.example.com"])
        )
        .is_ok());

        // Unrelated names never conflict.
        assert!(ensure_no_domain_conflict(
            &set(&["shop.example.com", "*.shop.example.com"]),
            &set(&["blog.example.net"])
        )
        .is_ok());
    }

    #[test]
    fn uuid_parsing_reports_bad_request() {
        assert!(parse_uuid("nope", "site id").is_err());
        assert!(parse_uuid(&Uuid::nil().to_string(), "site id").is_ok());
    }

    #[test]
    fn datetime_filters_tolerate_blanks() {
        assert_eq!(parse_optional_datetime(&None, "from").unwrap(), None);
        assert_eq!(
            parse_optional_datetime(&Some("".into()), "from").unwrap(),
            None
        );
        assert!(parse_optional_datetime(
            &Some("2024-01-01T00:00:00Z".into()),
            "from"
        )
        .unwrap()
        .is_some());
        assert!(
            parse_optional_datetime(&Some("yesterday".into()), "from").is_err()
        );
    }

    #[test]
    fn blank_filters_are_dropped() {
        assert_eq!(non_empty(&Some("   ".into())), None);
        assert_eq!(non_empty(&Some(" x ".into())).as_deref(), Some("x"));
        assert_eq!(non_empty(&None), None);
    }
}
