//! Database schema migrations.
//!
//! The migrations are applied at startup by [`crate::start_server`] through
//! [`Migrator::up`]; `sea-orm-migration` records the applied versions in the
//! `seaql_migrations` table, so restarting the control plane is a no-op once the
//! schema is current.

pub mod m20240101_000001_create_users;
pub mod m20240101_000002_create_sites;
pub mod m20240101_000003_create_rules;
pub mod m20240101_000004_create_agents;
pub mod m20240101_000005_create_logs;
pub mod m20240101_000006_create_additional_tables;
pub mod m20240101_000007_site_settings;
pub mod m20240101_000008_agent_host_samples;
pub mod m20240101_000009_create_certificate_events;
pub mod m20240101_000010_create_ip_groups;
pub mod m20240101_000011_site_origin_pools;
pub mod m20240101_000012_acme_events_and_ip_rule_groups;
pub mod m20240101_000013_access_log_request_detail;
pub mod m20240101_000014_ip_group_sync_error;
pub mod m20240101_000015_create_agent_metrics;
pub mod m20240101_000016_access_log_response_detail;
pub mod m20240101_000017_site_routes_ip_group;
pub mod m20240101_000018_mtls_certificates;
pub mod m20240101_000019_passkey_credentials;
pub mod m20240101_000020_control_plane_tls;
pub mod m20240101_000021_site_alternate_domains;
pub mod m20240101_000022_log_retention_settings;
pub mod m20240101_000023_global_error_pages;
pub mod m20240101_000024_site_basic_auth;
pub mod m20240101_000025_defense_settings;
pub mod m20240101_000026_api_protection;
pub mod m20240101_000027_ai_agent;
pub mod m20240101_000028_access_log_search_indexes;
pub mod m20240101_000029_agent_blocked_ips;
pub mod m20240101_000030_waf_settings;
pub mod m20240101_000031_waf_settings_monitor_managed_rules;
pub mod m20240101_000032_security_events_event_type;
pub mod m20240101_000033_site_proxy_trust;
pub mod m20240101_000034_user_account_controls;
pub mod m20240101_000035_instance_settings;
pub mod m20240101_000036_users_token_version;
pub mod m20240101_000037_site_trusted_proxy_ranges;
pub mod m20240101_000038_bot_ip_dns_verification;
pub mod m20240101_000039_ip_group_subscriptions;
pub mod m20240101_000040_waf_engine_switch;
pub mod m20240101_000041_site_trusted_proxy_group_ids;
pub mod m20240101_000042_agent_sync_timestamps;
pub mod m20240101_000043_config_versions;
pub mod m20240101_000044_notifications;
pub mod m20240101_000045_site_failover;
pub mod m20240101_000046_login_history;
pub mod m20240101_000047_waf_settings_mode_and_paranoia;
pub mod m20240101_000048_pool_health_check;
pub mod m20240101_000049_certificate_failure_reason;
pub mod m20240101_000050_cache_settings;
pub mod m20240101_000051_cache_type_policy;
pub mod m20240101_000052_origin_settings;
pub mod m20240101_000053_site_origin_verify_cert;
pub mod m20240101_000054_drop_challenge_cookie_secret;
pub mod m20240101_000055_site_domain_unique;
pub mod m20240101_000056_log_search_trgm;
pub mod m20240101_000057_waf_body_stage_timeout;
pub mod m20240101_000058_site_route_path_rewrite;
pub mod m20240101_000059_site_route_upstream_host;
pub mod m20240101_000060_site_response_replace;
pub mod m20240101_000061_agent_metrics_desc_index;
pub mod m20240101_000062_site_upstream_pool_address_unique;
pub mod m20240101_000063_site_upstream_pool_address_family;
pub mod m20240101_000064_agent_memory_split;
pub mod m20240101_000065_site_ssl_protocols;
pub mod m20240101_000066_site_ai_crawl;
pub mod m20240101_000067_site_oidc;
pub mod m20240101_000068_control_plane_boots;
pub mod m20240101_000069_oidc_providers;
pub mod m20240101_000070_site_oidc_access;
pub mod m20240101_000071_log_user_identity;
pub mod m20240101_000072_visitor_accounts;
pub mod m20240101_000073_visitor_site_grants;
pub mod m20240101_000074_visitor_passkeys;
pub mod m20240101_000075_visitor_auth_states;
pub mod m20240101_000076_site_oidc_auth_mode;
mod m20240101_000077_control_plane_stops;

use sea_orm_migration::prelude::*;

/// Ordered list of every schema change the control plane knows about.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240101_000001_create_users::Migration),
            Box::new(m20240101_000002_create_sites::Migration),
            Box::new(m20240101_000003_create_rules::Migration),
            Box::new(m20240101_000004_create_agents::Migration),
            Box::new(m20240101_000005_create_logs::Migration),
            Box::new(m20240101_000006_create_additional_tables::Migration),
            Box::new(m20240101_000007_site_settings::Migration),
            Box::new(m20240101_000008_agent_host_samples::Migration),
            Box::new(m20240101_000009_create_certificate_events::Migration),
            Box::new(m20240101_000010_create_ip_groups::Migration),
            Box::new(m20240101_000011_site_origin_pools::Migration),
            Box::new(
                m20240101_000012_acme_events_and_ip_rule_groups::Migration,
            ),
            Box::new(m20240101_000013_access_log_request_detail::Migration),
            Box::new(m20240101_000014_ip_group_sync_error::Migration),
            Box::new(m20240101_000015_create_agent_metrics::Migration),
            Box::new(m20240101_000016_access_log_response_detail::Migration),
            Box::new(m20240101_000017_site_routes_ip_group::Migration),
            Box::new(m20240101_000018_mtls_certificates::Migration),
            Box::new(m20240101_000019_passkey_credentials::Migration),
            Box::new(m20240101_000020_control_plane_tls::Migration),
            Box::new(m20240101_000021_site_alternate_domains::Migration),
            Box::new(m20240101_000022_log_retention_settings::Migration),
            Box::new(m20240101_000023_global_error_pages::Migration),
            Box::new(m20240101_000024_site_basic_auth::Migration),
            Box::new(m20240101_000025_defense_settings::Migration),
            Box::new(m20240101_000026_api_protection::Migration),
            Box::new(m20240101_000027_ai_agent::Migration),
            Box::new(m20240101_000028_access_log_search_indexes::Migration),
            Box::new(m20240101_000029_agent_blocked_ips::Migration),
            Box::new(m20240101_000030_waf_settings::Migration),
            Box::new(
                m20240101_000031_waf_settings_monitor_managed_rules::Migration,
            ),
            Box::new(m20240101_000032_security_events_event_type::Migration),
            Box::new(m20240101_000033_site_proxy_trust::Migration),
            Box::new(m20240101_000034_user_account_controls::Migration),
            Box::new(m20240101_000035_instance_settings::Migration),
            Box::new(m20240101_000036_users_token_version::Migration),
            Box::new(m20240101_000037_site_trusted_proxy_ranges::Migration),
            Box::new(m20240101_000038_bot_ip_dns_verification::Migration),
            Box::new(m20240101_000039_ip_group_subscriptions::Migration),
            Box::new(m20240101_000040_waf_engine_switch::Migration),
            Box::new(m20240101_000041_site_trusted_proxy_group_ids::Migration),
            Box::new(m20240101_000042_agent_sync_timestamps::Migration),
            Box::new(m20240101_000043_config_versions::Migration),
            Box::new(m20240101_000044_notifications::Migration),
            Box::new(m20240101_000045_site_failover::Migration),
            Box::new(m20240101_000046_login_history::Migration),
            Box::new(
                m20240101_000047_waf_settings_mode_and_paranoia::Migration,
            ),
            Box::new(m20240101_000048_pool_health_check::Migration),
            Box::new(m20240101_000049_certificate_failure_reason::Migration),
            Box::new(m20240101_000050_cache_settings::Migration),
            Box::new(m20240101_000051_cache_type_policy::Migration),
            Box::new(m20240101_000052_origin_settings::Migration),
            Box::new(m20240101_000053_site_origin_verify_cert::Migration),
            Box::new(m20240101_000054_drop_challenge_cookie_secret::Migration),
            Box::new(m20240101_000055_site_domain_unique::Migration),
            Box::new(m20240101_000056_log_search_trgm::Migration),
            Box::new(m20240101_000057_waf_body_stage_timeout::Migration),
            Box::new(m20240101_000058_site_route_path_rewrite::Migration),
            Box::new(m20240101_000059_site_route_upstream_host::Migration),
            Box::new(m20240101_000060_site_response_replace::Migration),
            Box::new(m20240101_000061_agent_metrics_desc_index::Migration),
            Box::new(
                m20240101_000062_site_upstream_pool_address_unique::Migration,
            ),
            Box::new(
                m20240101_000063_site_upstream_pool_address_family::Migration,
            ),
            Box::new(m20240101_000064_agent_memory_split::Migration),
            Box::new(m20240101_000065_site_ssl_protocols::Migration),
            Box::new(m20240101_000066_site_ai_crawl::Migration),
            Box::new(m20240101_000067_site_oidc::Migration),
            Box::new(m20240101_000068_control_plane_boots::Migration),
            Box::new(m20240101_000069_oidc_providers::Migration),
            Box::new(m20240101_000070_site_oidc_access::Migration),
            Box::new(m20240101_000071_log_user_identity::Migration),
            Box::new(m20240101_000072_visitor_accounts::Migration),
            Box::new(m20240101_000073_visitor_site_grants::Migration),
            Box::new(m20240101_000074_visitor_passkeys::Migration),
            Box::new(m20240101_000075_visitor_auth_states::Migration),
            Box::new(m20240101_000076_site_oidc_auth_mode::Migration),
            Box::new(m20240101_000077_control_plane_stops::Migration),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_ordered_and_unique() {
        let migrations = Migrator::migrations();
        assert_eq!(migrations.len(), 77);
        let names: Vec<String> =
            migrations.iter().map(|m| m.name().to_owned()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "migrations must be listed in name order");
        let unique: std::collections::BTreeSet<&String> =
            names.iter().collect();
        assert_eq!(unique.len(), names.len(), "duplicate migration name");
    }
}
