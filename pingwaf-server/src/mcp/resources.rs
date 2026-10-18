//! MCP resources: the same control-plane data the tools expose, as
//! addressable read-only documents.
//!
//! Resources require no arguments, which makes them the convenient entry
//! point for an agent that wants "the current state" in one read. Everything
//! here goes through the tool registry, so permissions stay enforced in one
//! place.

use chrono::Utc;
use serde_json::{json, Value};

use crate::api::state::AppState;
use crate::mcp::tools::{self, ToolContext};

/// Metadata of one resource, mirroring MCP's `resources/list` shape.
pub struct ResourceSpec {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
}

pub const RESOURCES: [ResourceSpec; 5] = [
    ResourceSpec {
        uri: "pingwaf://overview",
        name: "overview",
        description:
            "Platform snapshot: sites, agents, certificates and 24h traffic",
    },
    ResourceSpec {
        uri: "pingwaf://sites",
        name: "sites",
        description: "Every proxy site with status and online agent count",
    },
    ResourceSpec {
        uri: "pingwaf://agents",
        name: "agents",
        description: "Every data-plane agent with status and last heartbeat",
    },
    ResourceSpec {
        uri: "pingwaf://defense",
        name: "defense",
        description:
            "Observation mode and the control plane's own protection settings",
    },
    ResourceSpec {
        uri: "pingwaf://ip-groups",
        name: "ip-groups",
        description: "Shared IP groups with size, action and sync state",
    },
];

/// True when `uri` names one of [`RESOURCES`].
pub fn is_known(uri: &str) -> bool {
    RESOURCES.iter().any(|resource| resource.uri == uri)
}

/// `resources/list` payload.
pub fn list() -> Value {
    let resources: Vec<Value> = RESOURCES
        .iter()
        .map(|resource| {
            json!({
                "uri": resource.uri,
                "name": resource.name,
                "description": resource.description,
                "mimeType": "application/json",
            })
        })
        .collect();
    json!({ "resources": resources })
}

/// `resources/read` payload for one URI.
pub async fn read(
    state: &AppState,
    actor: &str,
    subject: uuid::Uuid,
    is_admin: bool,
    uri: &str,
) -> Result<Value, String> {
    let ctx = ToolContext {
        state,
        actor,
        // Resources are read-only by construction.
        can_write: false,
        subject,
        is_admin,
    };
    let payload = match uri {
        "pingwaf://overview" => overview(&ctx).await?,
        "pingwaf://sites" => {
            tools::call(&ctx, "list_sites", &json!({ "limit": 200 })).await?
        },
        "pingwaf://agents" => {
            tools::call(&ctx, "list_agents", &json!({ "limit": 200 })).await?
        },
        "pingwaf://defense" => {
            tools::call(&ctx, "get_defense_status", &json!({})).await?
        },
        "pingwaf://ip-groups" => {
            tools::call(&ctx, "list_ip_groups", &json!({})).await?
        },
        other => return Err(format!("unknown resource '{other}'")),
    };

    let text = serde_json::to_string_pretty(&payload)
        .unwrap_or_else(|_| payload.to_string());
    Ok(json!({
        "contents": [ { "uri": uri, "mimeType": "application/json", "text": text } ]
    }))
}

/// Composes the overview document out of the read tools.
async fn overview(ctx: &ToolContext<'_>) -> Result<Value, String> {
    let sites =
        tools::call(ctx, "list_sites", &json!({ "limit": 200 })).await?;
    let agents =
        tools::call(ctx, "list_agents", &json!({ "limit": 200 })).await?;
    let certificates =
        tools::call(ctx, "certificate_summary", &json!({})).await?;
    let traffic =
        tools::call(ctx, "get_traffic_summary", &json!({ "hours": 24 }))
            .await?;

    Ok(json!({
        "generated_at": Utc::now(),
        "sites": sites,
        "agents": agents,
        "certificates": certificates,
        "traffic_24h": traffic,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_uris_are_unique_and_well_formed() {
        let mut uris: Vec<&str> = RESOURCES.iter().map(|r| r.uri).collect();
        uris.sort_unstable();
        let unique: std::collections::BTreeSet<&str> =
            uris.iter().copied().collect();
        assert_eq!(unique.len(), uris.len());
        for resource in &RESOURCES {
            assert!(resource.uri.starts_with("pingwaf://"));
            assert!(!resource.description.is_empty());
        }
        assert!(is_known("pingwaf://overview"));
        assert!(!is_known("pingwaf://nope"));
    }

    #[test]
    fn list_advertises_every_resource_as_json() {
        let value = list();
        let resources = value["resources"].as_array().unwrap();
        assert_eq!(resources.len(), RESOURCES.len());
        for entry in resources {
            assert_eq!(entry["mimeType"], "application/json");
        }
    }
}
