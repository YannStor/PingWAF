// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Maintenance commands of the `pingwaf` binary.
//!
//! [`run`] serves the `user`, `mode` and `security` subcommands. They talk
//! straight to PostgreSQL instead of the REST API, so they keep working when
//! the control plane is down, not yet seeded, or its IP allowlist has locked
//! the operator out — which is exactly when they are needed.
//!
//! A *running* control plane notices these writes on its own: the
//! self-protection refresher and the observation-mode watcher poll their
//! settings rows every 15 seconds. Passwords are hashed exactly like the API
//! does (bcrypt), and a password that is not given on the command line is
//! generated and printed once.

use anyhow::{Context, bail};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database,
    DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use pingwaf_server::api::defense;
use pingwaf_server::api::self_protection::{self, effective_allowlist};
use pingwaf_server::auth::password::{
    MAX_PASSWORD_BYTES, hash_password, validate_password,
};
use pingwaf_server::config_history::{self, VersionScope};
use pingwaf_server::models::{
    api_protection_setting, config_version, defense_settings, ip_groups, role,
    site, user,
};

use crate::cli::{
    AddAdminOpts, AllowlistOpts, ConfigCommand, ConfigHistoryOpts,
    ConfigRollbackOpts, ConfigShowOpts, DbOpts, ModeCommand, OnOff, PingWafCli,
    PingWafCommand, ResetPasswordOpts, SecurityCommand, UserSubcommand,
};

/// Runs a maintenance subcommand.
///
/// The caller checks `PingWafCommand` first; a run mode reaching this
/// function is a programming error, reported rather than panicked so the
/// message names the mistake.
pub async fn run(cli: PingWafCli) -> anyhow::Result<()> {
    match cli.command {
        PingWafCommand::User { command } => user_command(command).await,
        PingWafCommand::Mode { command } => mode_command(command).await,
        PingWafCommand::Security { command } => security_command(command).await,
        PingWafCommand::Config { command } => config_command(command).await,
        PingWafCommand::Server(_)
        | PingWafCommand::Agent(_)
        | PingWafCommand::AllInOne(_) => {
            bail!("this is not a maintenance command")
        },
    }
}

// ─────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────

/// Connects for a maintenance command. One statement runs at a time, so a
/// couple of connections is plenty.
async fn connect(db_url: &str) -> anyhow::Result<DatabaseConnection> {
    let mut options = ConnectOptions::new(db_url.to_string());
    options
        .max_connections(2)
        .min_connections(1)
        .sqlx_logging(false);
    Database::connect(options).await.context(
        "cannot connect to PostgreSQL (check --db-url or PINGWAF_DB_URL)",
    )
}

/// Lower-cases and structurally validates an e-mail address, the same way
/// the API layer does, so a CLI-created account logs in under the address
/// the operator typed.
fn normalise_email(raw: &str) -> anyhow::Result<String> {
    let email = raw.trim().to_lowercase();
    let (local, domain) =
        email.split_once('@').context("invalid e-mail address")?;
    if local.is_empty()
        || domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        bail!("invalid e-mail address");
    }
    Ok(email)
}

/// The password to store: the one given, or a generated one. `true` in the
/// second slot marks a generated password, which the caller must print —
/// nothing else will ever show it.
fn resolve_password(given: &Option<String>) -> anyhow::Result<(String, bool)> {
    let Some(password) = given else {
        return Ok((generate_password(), true));
    };
    validate_password(password).map_err(|err| anyhow::anyhow!("{err}"))?;
    if password.len() > MAX_PASSWORD_BYTES {
        eprintln!(
            "warning: bcrypt only uses the first {MAX_PASSWORD_BYTES} bytes of a password"
        );
    }
    Ok((password.clone(), false))
}

/// A random password: 128 bits from two UUIDv4 payloads, the same
/// construction the API key generator uses.
fn generate_password() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Prints a generated password exactly once.
fn print_generated(password: &str) {
    println!();
    println!("password: {password}");
    println!("Store it now; it is not shown again.");
}

// ─────────────────────────────────────────────────────────────
// user
// ─────────────────────────────────────────────────────────────

async fn user_command(command: UserSubcommand) -> anyhow::Result<()> {
    match command {
        UserSubcommand::List(db) => list_users(db).await,
        UserSubcommand::AddAdmin(opts) => add_admin(opts).await,
        UserSubcommand::ResetPassword(opts) => reset_password(opts).await,
    }
}

async fn list_users(db: DbOpts) -> anyhow::Result<()> {
    let db = connect(&db.db_url).await?;
    let users = user::Entity::find()
        .order_by_asc(user::Column::CreatedAt)
        .all(&db)
        .await
        .context(
            "cannot list users; has the control plane booted against this database?",
        )?;

    if users.is_empty() {
        println!("no users");
        return Ok(());
    }
    println!("{:<40} {:<8} {:<24} CREATED", "EMAIL", "ROLE", "NAME");
    for row in &users {
        println!(
            "{:<40} {:<8} {:<24} {}",
            row.email,
            row.role,
            row.name.as_deref().unwrap_or("-"),
            row.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }
    println!();
    println!("{} user(s)", users.len());
    Ok(())
}

async fn add_admin(opts: AddAdminOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let email = normalise_email(&opts.email)?;
    let (password, generated) = resolve_password(&opts.password)?;

    let existing = user::Entity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
        .await
        .context(
            "cannot read the users table; has the control plane booted against this database?",
        )?;
    if existing.is_some() {
        bail!(
            "a user with e-mail {email} already exists; run \
             `pingwaf user reset-password --email {email}` to set a new password"
        );
    }

    let password_hash = hash_password(&password)
        .map_err(|err| anyhow::anyhow!("cannot hash the password: {err}"))?;
    let now = Utc::now();
    let row = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email),
        password_hash: Set(password_hash),
        name: Set(Some(
            opts.name
                .clone()
                .unwrap_or_else(|| "Administrator".to_string()),
        )),
        role: Set(role::ADMIN.to_string()),
        disabled: Set(false),
        must_change_password: Set(true),
        token_version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&db)
    .await
    .context("cannot create the administrator")?;

    println!("administrator {} created (id {})", row.email, row.id);
    if generated {
        print_generated(&password);
    }
    Ok(())
}

async fn reset_password(opts: ResetPasswordOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let email = normalise_email(&opts.email)?;
    let (password, generated) = resolve_password(&opts.password)?;

    let Some(row) = user::Entity::find()
        .filter(user::Column::Email.eq(&email))
        .one(&db)
        .await
        .context(
            "cannot read the users table; has the control plane booted against this database?",
        )?
    else {
        bail!("no user with e-mail {email}");
    };

    let password_hash = hash_password(&password)
        .map_err(|err| anyhow::anyhow!("cannot hash the password: {err}"))?;
    // A reset is a credential change like any other: revoke every token the
    // account still holds, exactly as `PUT /auth/password` does. Skipping this
    // left a leaked session working until its own expiry, which defeats the
    // point of resetting a compromised password from the CLI.
    let next_token_version = row.token_version + 1;
    let mut active: user::ActiveModel = row.into();
    active.password_hash = Set(password_hash);
    active.token_version = Set(next_token_version);
    active.updated_at = Set(Utc::now());
    let row = active
        .update(&db)
        .await
        .context("cannot update the password")?;

    println!(
        "password updated for {} ({}); all existing sessions are now invalid",
        row.email, row.role
    );
    if generated {
        print_generated(&password);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// mode
// ─────────────────────────────────────────────────────────────

async fn mode_command(command: ModeCommand) -> anyhow::Result<()> {
    match command {
        ModeCommand::Observe(db) => set_observation_mode(db, true).await,
        ModeCommand::Enforce(db) => set_observation_mode(db, false).await,
        ModeCommand::Status(db) => {
            let db = connect(&db.db_url).await?;
            let row = defense::load(&db).await?;
            print_observation_mode(row.observation_mode);
            Ok(())
        },
    }
}

async fn set_observation_mode(db: DbOpts, enabled: bool) -> anyhow::Result<()> {
    let db = connect(&db.db_url).await?;
    let row = defense::load(&db).await?;
    if row.observation_mode != enabled {
        let mut active: defense_settings::ActiveModel = row.into();
        active.observation_mode = Set(enabled);
        active.updated_at = Set(Utc::now());
        active
            .update(&db)
            .await
            .context("cannot update the defense settings")?;
        println!(
            "a running control plane pushes this to the agents within 15 seconds"
        );
    }
    print_observation_mode(enabled);
    Ok(())
}

fn print_observation_mode(enabled: bool) {
    println!("observation mode: {}", if enabled { "on" } else { "off" });
    if enabled {
        println!(
            "every detection (WAF, IP/geo rules, bot protection, rate \
             limiting) runs but only records; nothing is blocked"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// security
// ─────────────────────────────────────────────────────────────

async fn security_command(command: SecurityCommand) -> anyhow::Result<()> {
    match command {
        SecurityCommand::Status(db) => {
            let db = connect(&db.db_url).await?;
            security_status(&db).await
        },
        SecurityCommand::Allowlist(opts) => set_allowlist(opts).await,
    }
}

async fn security_status(db: &DatabaseConnection) -> anyhow::Result<()> {
    let settings = self_protection::load_settings(db).await?;
    let allowlist = effective_allowlist(db, &settings).await?;

    println!("control plane (9080) protection");
    println!(
        "  access log:        {}",
        if settings.access_log_enabled {
            format!(
                "enabled, retention {} day(s)",
                settings.access_log_retention_days
            )
        } else {
            "disabled".to_string()
        }
    );
    println!(
        "  IP allowlist:      {}",
        if settings.ip_allowlist_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "    inline ranges:   {}",
        settings.ip_allowlist_ranges.len()
    );
    match settings.ip_allowlist_group_id {
        Some(group_id) => {
            let group = ip_groups::Entity::find_by_id(group_id).one(db).await?;
            match group {
                Some(group) => println!(
                    "    group:           {} ({group_id}, {} range(s){})",
                    group.name,
                    group.ip_ranges.len(),
                    if group.enabled {
                        ""
                    } else {
                        ", disabled and contributing nothing"
                    }
                ),
                None => println!("    group:           {group_id} (missing)"),
            }
        },
        None => println!("    group:           none"),
    }
    println!("    effective entries: {}", allowlist.len());
    println!(
        "  WAF:               {}",
        if settings.waf_enabled {
            format!("enabled ({})", settings.waf_mode)
        } else {
            "disabled".to_string()
        }
    );
    println!(
        "  updated at:        {}",
        settings.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    Ok(())
}

async fn set_allowlist(opts: AllowlistOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let enabled = opts.state == OnOff::On;

    let settings = self_protection::load_settings(&db).await?;
    let allowlist = effective_allowlist(&db, &settings).await?;
    if enabled && allowlist.is_empty() && !opts.force {
        bail!(
            "the allowlist is empty; enabling it would refuse every API \
             caller (health probes excepted). Add ranges in the console \
             first, or pass --force to enable it anyway"
        );
    }

    if settings.ip_allowlist_enabled != enabled {
        let mut active: api_protection_setting::ActiveModel = settings.into();
        active.ip_allowlist_enabled = Set(enabled);
        active.updated_at = Set(Utc::now());
        active
            .update(&db)
            .await
            .context("cannot update the API protection settings")?;
        println!("a running control plane applies this within 15 seconds");
    }
    println!(
        "IP allowlist: {} ({} effective entr{})",
        if enabled { "enabled" } else { "disabled" },
        allowlist.len(),
        if allowlist.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// config (version history)
// ─────────────────────────────────────────────────────────────

async fn config_command(command: ConfigCommand) -> anyhow::Result<()> {
    match command {
        ConfigCommand::History(opts) => config_history_cmd(opts).await,
        ConfigCommand::Show(opts) => config_show(opts).await,
        ConfigCommand::Rollback(opts) => config_rollback(opts).await,
    }
}

/// Resolves the `--site` filter to a scope: a site UUID, `global`, or
/// `None` for "every scope".
async fn resolve_scope(
    db: &DatabaseConnection,
    site_filter: Option<&str>,
) -> anyhow::Result<Option<VersionScope>> {
    let Some(raw) = site_filter else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("global") {
        return Ok(Some(VersionScope::Global));
    }
    let id = Uuid::parse_str(raw)
        .with_context(|| format!("'--site {raw}' is not a UUID or 'global'"))?;
    let exists = site::Entity::find_by_id(id).one(db).await?.is_some();
    if !exists {
        bail!("no site with id {id}");
    }
    Ok(Some(VersionScope::Site(id)))
}

async fn config_history_cmd(opts: ConfigHistoryOpts) -> anyhow::Result<()> {
    use sea_orm::{QueryFilter, QuerySelect};

    let db = connect(&opts.db.db_url).await?;
    let scope = resolve_scope(&db, opts.site.as_deref()).await?;

    let mut query = config_version::Entity::find()
        .order_by_desc(config_version::Column::Id)
        .limit(u64::from(opts.limit.clamp(1, 200)));
    query = match scope {
        None => query,
        Some(VersionScope::Global) => {
            query.filter(config_version::Column::SiteId.is_null())
        },
        Some(VersionScope::Site(id)) => {
            query.filter(config_version::Column::SiteId.eq(id))
        },
    };
    let rows = query
        .all(&db)
        .await
        .context("cannot read the config_versions table; has the control plane booted against this database?")?;

    if rows.is_empty() {
        println!("no configuration versions recorded yet");
        return Ok(());
    }

    let referenced: Vec<Uuid> =
        rows.iter().filter_map(|row| row.site_id).collect();
    let domains: std::collections::HashMap<Uuid, String> = site::Entity::find()
        .filter(site::Column::Id.is_in(referenced))
        .all(&db)
        .await?
        .into_iter()
        .map(|row| (row.id, row.domain))
        .collect();

    println!(
        "{:<6} {:<36} {:<18} {:<10} {:<24} CHANGES",
        "VERSION", "SCOPE", "CONFIG HASH", "SOURCE", "CREATED (UTC)"
    );
    for row in &rows {
        let scope_label = match row.site_id {
            Some(id) => {
                domains.get(&id).cloned().unwrap_or_else(|| id.to_string())
            },
            None => "global".to_string(),
        };
        let changes = row
            .summary
            .as_ref()
            .and_then(|summary| summary.as_object())
            .map(|entries| {
                let mut parts: Vec<String> = entries
                    .iter()
                    .map(|(table, count)| {
                        format!("{table}={}", count.as_u64().unwrap_or(0))
                    })
                    .collect();
                parts.sort();
                parts.join(",")
            })
            .unwrap_or_default();
        println!(
            "{:<6} {:<36} {:<18} {:<10} {:<24} {}",
            row.id,
            truncate_display(&scope_label, 36),
            truncate_display(&row.config_hash, 18),
            truncate_display(&row.source, 10),
            row.created_at.format("%Y-%m-%d %H:%M:%S"),
            changes
        );
    }
    println!();
    println!(
        "{} version(s); details: pingwaf config show <version>",
        rows.len()
    );
    Ok(())
}

async fn config_show(opts: ConfigShowOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let row = config_version::Entity::find_by_id(opts.version)
        .one(&db)
        .await
        .context("cannot read the config_versions table")?
        .with_context(|| {
            format!("no configuration version {}", opts.version)
        })?;

    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&row.snapshot)
                .context("cannot serialise the snapshot")?
        );
        return Ok(());
    }

    let scope_label = match row.site_id {
        Some(id) => format!("site {id}"),
        None => "global".to_string(),
    };
    println!("version:      {}", row.id);
    println!("scope:        {scope_label}");
    println!("config hash:  {}", row.config_hash);
    println!("source:       {}", row.source);
    println!("actor:        {}", row.actor.as_deref().unwrap_or("-"));
    println!(
        "created at:   {}",
        row.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(entries) =
        row.summary.as_ref().and_then(|summary| summary.as_object())
    {
        println!("snapshot summary:");
        for (table, count) in entries {
            println!("  {table:<32} {} row(s)", count.as_u64().unwrap_or(0));
        }
    }
    println!();
    println!("full snapshot: pingwaf config show {} --json", row.id);
    Ok(())
}

async fn config_rollback(opts: ConfigRollbackOpts) -> anyhow::Result<()> {
    let db = connect(&opts.db.db_url).await?;
    let row = config_version::Entity::find_by_id(opts.version)
        .one(&db)
        .await
        .context("cannot read the config_versions table")?
        .with_context(|| {
            format!("no configuration version {}", opts.version)
        })?;

    let scope_label = match row.site_id {
        Some(id) => format!("site {id}"),
        None => "the global settings".to_string(),
    };
    if !opts.yes {
        println!(
            "This restores configuration version {} ({scope_label}, \
             recorded {} from {}).",
            row.id,
            row.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            row.source
        );
        print!("Type 'yes' to continue: ");
        use std::io::Write as _;
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim();
        if !(answer.eq_ignore_ascii_case("yes")
            || answer.eq_ignore_ascii_case("y"))
        {
            bail!("aborted");
        }
    }

    let outcome = config_history::rollback(&db, opts.version, Some("cli"))
        .await
        .map_err(|err| {
            if matches!(err, sea_orm::DbErr::RecordNotFound(_)) {
                anyhow::anyhow!("no configuration version {}", opts.version)
            } else {
                anyhow::anyhow!("rollback failed: {err}")
            }
        })?;

    println!(
        "restored configuration version {} ({})",
        outcome.restored_version,
        outcome.scope.describe()
    );
    if let Some(new_version) = outcome.new_version {
        println!("recorded as new version {new_version}");
    }
    println!(
        "note: a running control plane is not pushed this change; agents \
         pick it up on their next full sync or restart. Use the console \
         rollback for an immediate push."
    );
    Ok(())
}

/// Shortens a label for fixed-width table columns without cutting a
/// multi-byte character.
fn truncate_display(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let cut: String = value.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_lowercased_and_validated() {
        assert_eq!(
            normalise_email("  Ops@Example.COM ").unwrap(),
            "ops@example.com"
        );
        assert!(normalise_email("no-at-sign").is_err());
        assert!(normalise_email("user@nodot").is_err());
        assert!(normalise_email("@example.com").is_err());
        assert!(normalise_email("user@.example.com").is_err());
        assert!(normalise_email("user@example.com.").is_err());
    }

    #[test]
    fn table_labels_are_truncated_on_char_boundaries() {
        assert_eq!(truncate_display("short", 36), "short");
        let long = "a-very-long-site-name-that-keeps-going.example.com";
        let cut = truncate_display(long, 20);
        assert!(cut.chars().count() <= 20);
        assert!(cut.ends_with('…'));
        let multi_byte = "站点名称".repeat(20);
        assert!(truncate_display(&multi_byte, 10).chars().count() <= 10);
    }

    #[test]
    fn passwords_are_taken_or_generated() {
        let (password, generated) =
            resolve_password(&Some("correct horse".to_string())).unwrap();
        assert_eq!(password, "correct horse");
        assert!(!generated);

        // Short secrets never make it into the database.
        assert!(resolve_password(&Some("short".to_string())).is_err());

        let (password, generated) = resolve_password(&None).unwrap();
        assert!(generated);
        // 128 bits of hex from two UUIDv4 payloads.
        assert_eq!(password.len(), 64);
        assert!(password.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
