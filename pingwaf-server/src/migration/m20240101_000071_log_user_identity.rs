//! Adds `user_identity` to the two log tables.
//!
//! An event or an access entry has always said *where* a request came from —
//! `client_ip`, `user_agent`, `country_code` — and never *who* made it. On a
//! site behind an OIDC gate that is the difference between "an address" and
//! "an account", and it is the account that answers the question an operator
//! actually has after an incident: which user did this, and what else did
//! they do.
//!
//! The value is the provider's `sub` — an identifier the IdP issued for the
//! account, stable across logins, and not a secret. It is deliberately *not*
//! the email or the name: those are personal data that change, and the `sub`
//! is what an operator can take back to the provider to resolve the rest.
//!
//! Nullable on both tables, and that is the honest shape: most traffic is
//! anonymous, and every row written before this migration has no identity to
//! report. An empty string would be a claim that the caller was identified
//! and turned out to be nobody.
//!
//! `security_events` is the table the alert stream writes; `access_logs` is
//! the per-request one. Both are added here because both are read during an
//! investigation, and a column that exists on only one of them would send the
//! reader to the other table for the answer.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in
            [LogUserIdentity::SecurityEvents, LogUserIdentity::AccessLogs]
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(table)
                        .add_column(
                            ColumnDef::new(LogUserIdentity::UserIdentity)
                                .string_len(255)
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // An investigation starts from "who is this", so the lookup is by
        // identity. Plain (not partial) indexes: `Index::create` has no
        // predicate in this SeaORM version, and the column being NULL for
        // most rows does not make the index useless — Postgres still stores
        // the null entries, just compactly.
        for (name, table) in [
            (
                "idx_security_events_user_identity",
                LogUserIdentity::SecurityEvents,
            ),
            ("idx_access_logs_user_identity", LogUserIdentity::AccessLogs),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(table)
                        .col(LogUserIdentity::UserIdentity)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in [
            "idx_security_events_user_identity",
            "idx_access_logs_user_identity",
        ] {
            manager
                .drop_index(Index::drop().name(name).to_owned())
                .await?;
        }
        for table in
            [LogUserIdentity::SecurityEvents, LogUserIdentity::AccessLogs]
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(table)
                        .drop_column(LogUserIdentity::UserIdentity)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

/// The column and the two tables it goes on.
///
/// One enum, because `Table::alter` and `Index::create` take a single `Iden`
/// type: two `DeriveIden` enums would be distinct types and could not share
/// the loops below. The variant names carry the table names, so the mapping
/// stays readable.
#[derive(DeriveIden)]
enum LogUserIdentity {
    UserIdentity,
    SecurityEvents,
    AccessLogs,
}
