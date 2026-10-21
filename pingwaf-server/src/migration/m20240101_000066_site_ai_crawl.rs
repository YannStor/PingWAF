//! Site-level AI crawler control.
//!
//! Cloudflare's AI Crawl Control gives a site two things: visibility into the
//! AI crawlers that fetch it, and a switch per crawler family. PingWAF keeps
//! that shape and adds the generated files the same feature needs:
//!
//! * `site_ai_crawl_settings` — one row per site: the default action, the
//!   robots.txt / llms.txt mode and body, and the Content Signals switches.
//! * `site_ai_bot_policies` — one row per family the operator overrides
//!   (`site_id`, `bot_id` unique). The family catalogue itself lives in the
//!   control plane (`api::ai_crawl::AI_BOTS`), so a new crawler is a code
//!   change, not a migration.
//!
//! The generated bodies are pushed to the data plane with the rule bundle and
//! served by the `mock` plugin on an exact-path location; nothing is rendered
//! on the request path.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteAiCrawlSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::SiteId)
                            .uuid()
                            .not_null()
                            .unique_key(),
                    )
                    // Deleting a site must take its AI crawler policy with it;
                    // every other site-scoped table cascades for the same
                    // reason (no orphan rows, no blocked unique key).
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_ai_crawl_settings_site_id")
                            .from(
                                SiteAiCrawlSettings::Table,
                                SiteAiCrawlSettings::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::Enabled)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::DefaultAction)
                            .string_len(16)
                            .not_null()
                            .default("monitor"),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::RobotsMode)
                            .string_len(16)
                            .not_null()
                            .default("off"),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::RobotsBody)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::LlmsMode)
                            .string_len(16)
                            .not_null()
                            .default("off"),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::LlmsBody)
                            .text()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::LlmsIncludeRoutes)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::CacheMaxAge)
                            .integer()
                            .not_null()
                            .default(3600),
                    )
                    .col(
                        ColumnDef::new(
                            SiteAiCrawlSettings::ContentSignalSearch,
                        )
                        .boolean()
                        .not_null()
                        .default(true),
                    )
                    .col(
                        ColumnDef::new(
                            SiteAiCrawlSettings::ContentSignalAiTrain,
                        )
                        .boolean()
                        .not_null()
                        .default(false),
                    )
                    .col(
                        ColumnDef::new(
                            SiteAiCrawlSettings::ContentSignalAiInput,
                        )
                        .boolean()
                        .not_null()
                        .default(false),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(SiteAiCrawlSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SiteAiBotPolicies::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteAiBotPolicies::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SiteAiBotPolicies::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_ai_bot_policies_site_id")
                            .from(
                                SiteAiBotPolicies::Table,
                                SiteAiBotPolicies::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(SiteAiBotPolicies::BotId)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteAiBotPolicies::Action)
                            .string_len(16)
                            .not_null()
                            .default("inherit"),
                    )
                    .col(
                        ColumnDef::new(SiteAiBotPolicies::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // One override per (site, family); the upsert path relies on it.
        manager
            .create_index(
                Index::create()
                    .name("uq_site_ai_bot_policies_site_bot")
                    .table(SiteAiBotPolicies::Table)
                    .col(SiteAiBotPolicies::SiteId)
                    .col(SiteAiBotPolicies::BotId)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop().table(SiteAiBotPolicies::Table).to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop().table(SiteAiCrawlSettings::Table).to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteAiCrawlSettings {
    Table,
    Id,
    SiteId,
    Enabled,
    DefaultAction,
    RobotsMode,
    RobotsBody,
    LlmsMode,
    LlmsBody,
    LlmsIncludeRoutes,
    CacheMaxAge,
    ContentSignalSearch,
    ContentSignalAiTrain,
    ContentSignalAiInput,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SiteAiBotPolicies {
    Table,
    Id,
    SiteId,
    BotId,
    Action,
    CreatedAt,
}

/// The referenced table for both foreign keys.
#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
