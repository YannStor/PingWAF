//! `site_oidc` — per-site OpenID Connect authentication.
//!
//! One row per site, like the basic-auth and challenge settings next to it.
//!
//! The identity provider itself lives in `oidc_providers` (several sites
//! usually share one), so this table carries only what differs per site: the
//! provider reference, the callback paths, the session cookie name and TTL,
//! the session key, the claim-to-header map, and the access rules.
//!
//! `scopes` moved to the provider with the credentials; `claims_to_headers`
//! stayed because which claim becomes which header is a property of the
//! *origin* behind the site, not of the provider.
//!
//! The JSON columns are arrays kept in insertion order:
//!
//! * `claims_to_headers` — `{claim, header}` objects.
//! * `access_rules` — `{claim, operator, value}` objects, matched against the
//!   session's ID-token claims by [`AccessMode`].

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// What a site does with a signed-in visitor who is not in `access_rules`.
///
/// Authenticating proves *who* someone is; it does not say whether they may
/// enter. The mode is stored as text and matched in one place
/// ([`AccessMode::from_str`]) so a value the API accepted cannot be read
/// differently by the data plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Every signed-in visitor is admitted. The default, and what the gate
    /// did before access rules existed.
    AllowAll,
    /// Admitted when **any** rule matches.
    RequireAny,
    /// Admitted only when **every** rule matches.
    RequireAll,
}

impl AccessMode {
    pub const ALLOW_ALL: &'static str = "allow_all";
    pub const REQUIRE_ANY: &'static str = "require_any";
    pub const REQUIRE_ALL: &'static str = "require_all";

    /// Every value the column may hold, for the API's validation and the
    /// dashboard's picker.
    pub const ALL: [&'static str; 3] =
        [Self::ALLOW_ALL, Self::REQUIRE_ANY, Self::REQUIRE_ALL];

    /// Parses the stored value. `None` for anything else, so a row an older
    /// build wrote cannot be read as a permission it never meant.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            Self::ALLOW_ALL => Some(Self::AllowAll),
            Self::REQUIRE_ANY => Some(Self::RequireAny),
            Self::REQUIRE_ALL => Some(Self::RequireAll),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowAll => Self::ALLOW_ALL,
            Self::RequireAny => Self::REQUIRE_ANY,
            Self::RequireAll => Self::REQUIRE_ALL,
        }
    }
}

/// How a protected site signs its visitors in.
///
/// The counterpart to [`AccessMode`]: that one decides who may enter once they
/// are signed in, this one decides how they sign in at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Only the provider's authorization-code flow. The default, and what the
    /// gate did before local accounts existed — so an upgrade changes nothing
    /// for a site that was already configured.
    Oidc,
    /// Only a local account on this deployment, with a proof-of-work
    /// challenge.
    Local,
    /// Both: the login page offers the local form and links to the provider.
    Both,
}

impl AuthMode {
    pub const OIDC: &'static str = "oidc";
    pub const LOCAL: &'static str = "local";
    pub const BOTH: &'static str = "both";

    /// Every value the column may hold, for the API's validation and the
    /// dashboard's picker.
    pub const ALL: [&'static str; 3] = [Self::OIDC, Self::LOCAL, Self::BOTH];

    /// Parses the stored value. `None` for anything else, so a row a newer
    /// build wrote is not read as a mode it never meant — the data plane
    /// treats that as a configuration error rather than guessing at one.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            Self::OIDC => Some(Self::Oidc),
            Self::LOCAL => Some(Self::Local),
            Self::BOTH => Some(Self::Both),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => Self::OIDC,
            Self::Local => Self::LOCAL,
            Self::Both => Self::BOTH,
        }
    }

    /// Whether the local login page is reachable at all.
    pub fn allows_local(self) -> bool {
        matches!(self, Self::Local | Self::Both)
    }

    /// Whether the provider's flow is reachable at all.
    pub fn allows_oidc(self) -> bool {
        matches!(self, Self::Oidc | Self::Both)
    }
}

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "site_oidc")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    pub enabled: bool,
    /// The provider this site authenticates against. `None` = not chosen yet,
    /// which is why the API refuses to enable the gate.
    pub provider_id: Option<Uuid>,
    /// Key the session cookie is encrypted with; at least 16 characters while
    /// enabled.
    pub cookie_secret: String,
    pub redirect_path: String,
    pub logout_path: String,
    pub redirect_url: String,
    pub cookie_name: String,
    pub session_ttl_seconds: i32,
    /// JSON array of `{claim, header}` objects.
    #[sea_orm(column_type = "JsonBinary")]
    pub claims_to_headers: Json,
    /// One of [`AuthMode::ALL`].
    pub auth_mode: String,
    /// One of [`AccessMode::ALL`].
    pub access_mode: String,
    /// JSON array of `{claim, operator, value}` objects.
    #[sea_orm(column_type = "JsonBinary")]
    pub access_rules: Json,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_modes_round_trip() {
        for value in AccessMode::ALL {
            let parsed =
                AccessMode::parse(value).expect("every listed value parses");
            assert_eq!(value, parsed.as_str());
        }
    }

    /// A value written by a newer build, or corrupted, must not be read as a
    /// permission: `None` makes the caller decide, and the data plane treats
    /// it as "do not enforce" while the API refuses to store it.
    #[test]
    fn an_unknown_access_mode_is_not_a_permission() {
        assert_eq!(None, AccessMode::parse("require_some"));
        assert_eq!(None, AccessMode::parse(""));
        assert_eq!(None, AccessMode::parse("ALLOW_ALL"));
    }

    #[test]
    fn auth_modes_round_trip() {
        for value in AuthMode::ALL {
            let parsed =
                AuthMode::parse(value).expect("every listed value parses");
            assert_eq!(value, parsed.as_str());
        }
    }

    /// An unknown mode is not read as one this build knows, for the same
    /// reason an unknown access mode is not: guessing would be guessing at a
    /// way in.
    #[test]
    fn an_unknown_auth_mode_is_not_a_mode() {
        assert_eq!(None, AuthMode::parse("saml"));
        assert_eq!(None, AuthMode::parse(""));
        assert_eq!(None, AuthMode::parse("OIDC"));
    }

    /// The two predicates the data plane branches on, spelled out so a new
    /// variant cannot silently become "neither".
    #[test]
    fn each_mode_names_the_flows_it_allows() {
        assert!(AuthMode::Oidc.allows_oidc() && !AuthMode::Oidc.allows_local());
        assert!(
            !AuthMode::Local.allows_oidc() && AuthMode::Local.allows_local()
        );
        assert!(AuthMode::Both.allows_oidc() && AuthMode::Both.allows_local());
    }
}
