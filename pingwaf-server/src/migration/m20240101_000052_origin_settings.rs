//! Global origin (upstream) settings (`origin_settings`).
//!
//! One single-row table, following the `cache_settings` pattern. It holds the
//! deployment-wide default for verifying the TLS certificate of an origin
//! reached over HTTPS. The data plane reaches it as
//! `BasicConf::origin_verify_cert`: an origin pool that carries no
//! `verify_cert` of its own follows this value, a pool that states one keeps
//! it.
//!
//! The default is `false` — accept any origin certificate — because that is
//! what the control plane has always written per pool, and self-signed
//! origins are the common case. Flipping it to `true` is the safe setting but
//! is deliberately not the default: it would 502 every existing HTTPS origin
//! whose certificate is not in the system trust store.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OriginSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OriginSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OriginSettings::VerifyCert)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(OriginSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Seed the default row so the first read does not have to handle a
        // missing row (the API also creates it lazily, this keeps direct SQL
        // readers honest).
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT INTO origin_settings (id, verify_cert, updated_at) \
                 VALUES (1, false, now()) ON CONFLICT (id) DO NOTHING",
            )
            .await?;

        // Pools written before the global switch existed carry an explicit
        // `false` that the old API stamped on every create — the operator
        // never chose it. Left in place, those rows would shadow the new
        // default forever and turning verification on would appear to do
        // nothing, which is precisely the surprise this switch exists to
        // remove. Clearing them to NULL is behavior-preserving today (the
        // seeded default is also `false`) and makes the switch authoritative
        // from now on.
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE site_upstream_pools SET verify_cert = NULL \
                 WHERE verify_cert = false",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(OriginSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum OriginSettings {
    Table,
    Id,
    VerifyCert,
    UpdatedAt,
}
