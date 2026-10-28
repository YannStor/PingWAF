//! Single-use refresh tokens, so a replay is refused across restarts and
//! across control-plane instances.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE TABLE IF NOT EXISTS refresh_tokens (
                jti text PRIMARY KEY,
                user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at timestamptz NOT NULL,
                used_at timestamptz NOT NULL DEFAULT now(),
                created_at timestamptz NOT NULL DEFAULT now()
            )",
        )
        .await?;
        // Pruning walks expired rows; the index keeps that cheap.
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at \
             ON refresh_tokens (expires_at)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS refresh_tokens")
            .await?;
        Ok(())
    }
}
