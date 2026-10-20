//! Per-pool upstream address family.
//!
//! A pool whose origin address is a domain is resolved by the agent's data
//! plane, and the resolver answers with A and AAAA records alike. On a host
//! with no IPv6 route (the normal case for a container on an IPv4-only
//! network) the AAAA backends can never pass a health check; when the
//! resolver answers with AAAA only, every backend is unreachable and the site
//! answers `503 No available upstream` while `curl` still reaches the origin
//! through its happy-eyeballs fallback. The data plane has no such fallback,
//! so the family has to be chosen before the backends are built.
//!
//! `auto` - the default - prefers IPv4 and keeps IPv6 only for a host that has
//! no A record, which fixes that 503 for every existing pool without an
//! operator having to touch it. `ipv4` and `ipv6` pin one family for an origin
//! that is only reachable over it.
//!
//! The default backfills existing rows, so no data migration is needed. The
//! CHECK constraint makes the three accepted values a database invariant: an
//! unknown value could otherwise only be caught by the API, and a value
//! written by any other path would reach the agent as an address family the
//! data plane has to guess at.
//!
//! PostgreSQL-only, like the rest of this migration set.

use sea_orm_migration::prelude::*;

/// The values `address_family` may hold; mirrors `AddressFamily` in
/// `pingap-upstream`.
const ADDRESS_FAMILY_CHECK_UP_SQL: &str = "ALTER TABLE site_upstream_pools \
     ADD CONSTRAINT ck_site_upstream_pools_address_family \
     CHECK (address_family IN ('auto', 'ipv4', 'ipv6'))";

const ADDRESS_FAMILY_CHECK_DOWN_SQL: &str = "ALTER TABLE site_upstream_pools \
     DROP CONSTRAINT IF EXISTS ck_site_upstream_pools_address_family";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreamPools::Table)
                    .add_column(
                        ColumnDef::new(SiteUpstreamPools::AddressFamily)
                            .text()
                            .not_null()
                            .default("auto"),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(ADDRESS_FAMILY_CHECK_UP_SQL)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(ADDRESS_FAMILY_CHECK_DOWN_SQL)
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreamPools::Table)
                    .drop_column(SiteUpstreamPools::AddressFamily)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteUpstreamPools {
    Table,
    AddressFamily,
}
