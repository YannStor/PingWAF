//! Short-lived visitor authentication state (`visitor_auth_states`).
//!
//! This table is what makes the proof-of-work login work across more than one
//! data-plane instance. The WAF challenge keeps its pending nonces in a
//! process-local `DashMap`, which is fine for a challenge that is issued and
//! answered by whichever instance the load balancer happens to pick — but a
//! *login* is not: the instance that renders the form and the instance that
//! receives the POST are routinely different, and a process-local store would
//! make the answer unverifiable about half the time on a two-instance
//! deployment.
//!
//! So the nonce lives here, keyed by a random id the browser carries, with an
//! expiry. The data plane asks the control plane over gRPC to create and to
//! consume it; `kind` distinguishes the uses so one table can serve them
//! without the rows being confusable:
//!
//! * `login_challenge` — a proof-of-work nonce and its difficulty, waiting for
//!   an answer.
//! * `passkey_reg` / `passkey_login` — a WebAuthn ceremony state.
//!
//! Consumption is a delete, which is what makes an answer single-use: the row
//! is gone after the first successful read, so a replayed POST finds nothing.
//!
//! `payload` holds the JSON blob each kind needs; the columns the queries
//! filter on are the ones lifted out. Rows are swept by `expires_at`, by the
//! same monitor loop that already trims other short-lived tables.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VisitorAuthStates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(VisitorAuthStates::Id)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    // `login_challenge` / `passkey_reg` / `passkey_login`.
                    // Kept as text rather than an enum column so a newer build
                    // can add a kind without a migration on the old one.
                    .col(
                        ColumnDef::new(VisitorAuthStates::Kind)
                            .string_len(32)
                            .not_null(),
                    )
                    // The site the login was started from, so a challenge
                    // answered at another site is refused. Text because a site
                    // is identified by its host at the data plane, matching
                    // `ClearancePayload.site_id`.
                    .col(
                        ColumnDef::new(VisitorAuthStates::SiteId)
                            .string_len(255)
                            .not_null()
                            .default(""),
                    )
                    // Set only for the kinds that have an account in hand
                    // (a registration ceremony); null while it is still just a
                    // challenge.
                    .col(
                        ColumnDef::new(VisitorAuthStates::VisitorId)
                            .uuid()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(VisitorAuthStates::Payload)
                            .json_binary()
                            .not_null()
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .col(
                        ColumnDef::new(VisitorAuthStates::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorAuthStates::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Rows are read by primary key and swept by expiry, so expiry is the
        // only column worth an index.
        manager
            .create_index(
                Index::create()
                    .name("idx_visitor_auth_states_expires_at")
                    .table(VisitorAuthStates::Table)
                    .col(VisitorAuthStates::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(VisitorAuthStates::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum VisitorAuthStates {
    Table,
    Id,
    Kind,
    SiteId,
    VisitorId,
    Payload,
    ExpiresAt,
    CreatedAt,
}
