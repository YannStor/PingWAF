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
}
