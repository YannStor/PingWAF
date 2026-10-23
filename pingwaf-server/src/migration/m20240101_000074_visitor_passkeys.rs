//! Visitor passkey credentials (`visitor_passkeys`) and their ceremony state
//! (`visitor_passkey_states`).
//!
//! A parallel pair to `passkey_credentials` / `passkey_states`, which belong to
//! console operators. The columns match deliberately — the same `passkey-server`
//! crate verifies both — but the owner does not: `user_id` there, `visitor_id`
//! here. Reusing one table with an owner-type discriminator was considered and
//! rejected: a credential whose owner column can point at two different tables
//! cannot carry a foreign key, and the cascade on account deletion is exactly
//! what keeps a removed visitor from leaving a usable credential behind.
//!
//! `cred_id` is unique here for the same reason it is unique there: it names
//! one authenticator globally, and it is the key the login assertion looks up.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VisitorPasskeys::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(VisitorPasskeys::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::VisitorId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::CredId)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::PublicKey)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::Name)
                            .string_len(100)
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::Counter)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeys::LastUsedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_visitor_passkeys_visitor_id")
                            .from(
                                VisitorPasskeys::Table,
                                VisitorPasskeys::VisitorId,
                            )
                            .to(SiteVisitors::Table, SiteVisitors::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_visitor_passkeys_visitor_id")
                    .table(VisitorPasskeys::Table)
                    .col(VisitorPasskeys::VisitorId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_visitor_passkeys_cred_id")
                    .table(VisitorPasskeys::Table)
                    .col(VisitorPasskeys::CredId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Ceremony state, keyed like the console's: `reg:<visitor>` for a
        // registration, `login:<challenge>` for an assertion. Rows are only
        // read by primary key and swept by expiry.
        manager
            .create_table(
                Table::create()
                    .table(VisitorPasskeyStates::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(VisitorPasskeyStates::Id)
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeyStates::StateJson)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(VisitorPasskeyStates::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_visitor_passkey_states_expires_at")
                    .table(VisitorPasskeyStates::Table)
                    .col(VisitorPasskeyStates::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(VisitorPasskeyStates::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(VisitorPasskeys::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum VisitorPasskeys {
    Table,
    Id,
    VisitorId,
    CredId,
    PublicKey,
    Name,
    Counter,
    CreatedAt,
    LastUsedAt,
}

#[derive(DeriveIden)]
enum VisitorPasskeyStates {
    Table,
    Id,
    StateJson,
    ExpiresAt,
}

#[derive(DeriveIden)]
enum SiteVisitors {
    Table,
    Id,
}
