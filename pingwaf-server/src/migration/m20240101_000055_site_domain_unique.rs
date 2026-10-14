//! Enforces site-hostname uniqueness at the database level.
//!
//! `ensure_domains_available` checked hostnames with a read-then-write, so two
//! concurrent requests could both pass the check and then race their inserts.
//! This migration adds the final backstop the pre-check documented:
//!
//! - a unique index on `sites.domain` (the primary hostname);
//! - a `BEFORE INSERT/UPDATE` trigger covering the cross-site conflicts a
//!   plain index cannot express on the `alternate_domains` text array
//!   (primary ↔ another site's alternates and alternates ↔ alternates),
//!   mirroring the exact-match semantics of `ensure_no_domain_conflict`.
//!   Wildcard-overlap rules stay application-level.
//!
//! Existing duplicates abort the migration with a clear error instead of being
//! silently dropped or left to violate the new index.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Fails the migration when any hostname is already claimed by two sites.
const DUPLICATE_CHECK_SQL: &str = r#"
DO $$
DECLARE
    conflict text;
    conflict_id uuid;
BEGIN
    -- Two sites sharing a primary hostname.
    SELECT domain INTO conflict
    FROM sites GROUP BY domain HAVING count(*) > 1 LIMIT 1;
    IF conflict IS NOT NULL THEN
        RAISE EXCEPTION 'duplicate primary domain "%" — resolve the conflict before upgrading', conflict;
    END IF;

    -- A primary hostname that also appears in another site's alternates.
    SELECT s.domain INTO conflict
    FROM sites s
    JOIN sites other ON other.id <> s.id AND s.domain = ANY (other.alternate_domains)
    LIMIT 1;
    IF conflict IS NOT NULL THEN
        RAISE EXCEPTION 'domain "%" is used both as a primary and an alternate hostname — resolve the conflict before upgrading', conflict;
    END IF;

    -- The same alternate hostname on two sites.
    SELECT d INTO conflict
    FROM (
        SELECT DISTINCT unnest(alternate_domains) AS d, id FROM sites
    ) per_site
    GROUP BY d HAVING count(*) > 1 LIMIT 1;
    IF conflict IS NOT NULL THEN
        RAISE EXCEPTION 'alternate domain "%" is used by more than one site — resolve the conflict before upgrading', conflict;
    END IF;

    -- A site whose own primary hostname also appears in its own alternates
    -- (the trigger's first branch turns every later UPDATE into an error).
    SELECT id, domain INTO conflict_id, conflict
    FROM sites WHERE domain = ANY (alternate_domains) LIMIT 1;
    IF conflict IS NOT NULL THEN
        RAISE EXCEPTION 'site with id "%" keeps its own domain "%" in alternate_domains — remove it from alternate_domains before upgrading', conflict_id, conflict;
    END IF;
END
$$;
"#;

/// Unique index on the primary hostname.
const UNIQUE_INDEX_UP_SQL: &str =
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_sites_domain ON sites (domain)";
const UNIQUE_INDEX_DOWN_SQL: &str = "DROP INDEX IF EXISTS uq_sites_domain";

/// The non-unique index created by migration 000002 (`idx_sites_domain`)
/// is fully covered by `uq_sites_domain` and only slows writes — dropped in
/// `up`, restored to the 000002 definition in `down`.
const DROP_REDUNDANT_INDEX_SQL: &str = "DROP INDEX IF EXISTS idx_sites_domain";
const RESTORE_REDUNDANT_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_sites_domain ON sites (domain)";

/// Trigger covering alternates: exact-match conflicts against every other
/// site's primary and alternate hostnames.
const TRIGGER_UP_SQL: &str = r#"
CREATE OR REPLACE FUNCTION check_site_domain_conflicts() RETURNS trigger AS $$
BEGIN
    IF NEW.domain = ANY (NEW.alternate_domains) THEN
        RAISE EXCEPTION 'domain "%" is already in use by this site', NEW.domain;
    END IF;
    IF EXISTS (
        SELECT 1 FROM sites other
        WHERE other.id <> NEW.id
          AND (
              other.domain = ANY (NEW.alternate_domains)
              OR NEW.domain = ANY (other.alternate_domains)
              OR other.alternate_domains && NEW.alternate_domains
          )
    ) THEN
        RAISE EXCEPTION 'domain already in use by another site';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_site_domain_conflicts ON sites;
CREATE TRIGGER trg_site_domain_conflicts
    BEFORE INSERT OR UPDATE OF domain, alternate_domains ON sites
    FOR EACH ROW EXECUTE FUNCTION check_site_domain_conflicts();
"#;

const TRIGGER_DOWN_SQL: &str = r#"
DROP TRIGGER IF EXISTS trg_site_domain_conflicts ON sites;
DROP FUNCTION IF EXISTS check_site_domain_conflicts();
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(DUPLICATE_CHECK_SQL).await?;
        conn.execute_unprepared(DROP_REDUNDANT_INDEX_SQL).await?;
        conn.execute_unprepared(UNIQUE_INDEX_UP_SQL).await?;
        conn.execute_unprepared(TRIGGER_UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(TRIGGER_DOWN_SQL).await?;
        conn.execute_unprepared(UNIQUE_INDEX_DOWN_SQL).await?;
        conn.execute_unprepared(RESTORE_REDUNDANT_INDEX_SQL).await?;
        Ok(())
    }
}
