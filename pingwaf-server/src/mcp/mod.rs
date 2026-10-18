//! Hosted MCP (Model Context Protocol) endpoint on the control plane.
//!
//! The control plane speaks MCP over **Streamable HTTP** at `/mcp`: clients
//! `POST` JSON-RPC 2.0 messages and receive JSON responses (the spec's
//! alternative to SSE streams, which this server does not need). The
//! endpoint is stateless — no `Mcp-Session-Id` is issued, and `GET`/`DELETE`
//! answer `405` so probing clients fall back to POST immediately.
//!
//! Authentication reuses the console credentials: `Authorization: Bearer`
//! with either a `pwk_…` API key or a JWT (see [`auth`]). Because the route
//! hangs off the root router, the control plane's self-protection stack —
//! access log, IP allowlist, WAF — applies to `/mcp` exactly as it does to
//! the API.
//!
//! Supported methods: `initialize`, `ping`, `tools/list`, `tools/call`,
//! `resources/list`, `resources/read`, `resources/templates/list`,
//! `prompts/list`, `prompts/get`, `logging/setLevel` (accepted, no-op) and
//! JSON-RPC batches thereof. Notifications receive `202 Accepted`.

pub mod auth;
pub mod prompts;
pub mod protocol;
pub mod resources;
pub mod tools;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Json;
use axum::Router;
use serde_json::{json, Value};

use crate::api::state::AppState;
pub use auth::McpPrincipal;
use tools::ToolContext;

/// Maximum number of JSON-RPC messages accepted in one batch request.
pub const MAX_BATCH_SIZE: usize = 16;

/// Maximum accepted request body (`tools/call` arguments are small JSON
/// documents; the control plane never ships bulk data through MCP).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Routes contributed to the root router (outside `/api/v1`, so the path is
/// exactly `/mcp`).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/mcp",
            post(handle_post).get(handle_get).delete(handle_delete),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// An error that aborts a stateless method.
#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: protocol::INVALID_PARAMS,
            message: message.into(),
        }
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: protocol::INVALID_REQUEST,
            message: message.into(),
        }
    }
}

/// Validates a batch envelope before any message is dispatched: empty and
/// oversized batches are rejected with a single error, per the JSON-RPC
/// guidance for batches beyond the server's processing capacity.
fn validate_batch(items: &[Value]) -> Result<(), RpcError> {
    if items.is_empty() {
        return Err(RpcError::invalid_request("empty JSON-RPC batch"));
    }
    if items.len() > MAX_BATCH_SIZE {
        return Err(RpcError::invalid_request(format!(
            "JSON-RPC batch exceeds the limit of {} messages",
            MAX_BATCH_SIZE
        )));
    }
    Ok(())
}

/// Handles the methods that need no database access. `None` means the method
/// belongs to the stateful half of the dispatcher.
fn handle_stateless(
    method: &str,
    params: &Value,
    can_write: bool,
) -> Option<Result<Value, RpcError>> {
    match method {
        "initialize" => {
            let protocol_version = protocol::negotiate_version(
                params.get("protocolVersion").and_then(Value::as_str),
            );
            tracing::info!(
                client = ?params.get("clientInfo"),
                protocol = %protocol_version,
                "MCP client initialized"
            );
            Some(Ok(protocol::initialize_result(params)))
        },
        "ping" => Some(Ok(json!({}))),
        "tools/list" => Some(Ok(tools::mcp_list(can_write))),
        "resources/list" => Some(Ok(resources::list())),
        "resources/templates/list" => {
            Some(Ok(json!({ "resourceTemplates": [] })))
        },
        "prompts/list" => Some(Ok(prompts::list())),
        "prompts/get" => {
            Some(match params.get("name").and_then(Value::as_str) {
                Some(name) => prompts::get(
                    name,
                    params.get("arguments").unwrap_or(&json!({})),
                )
                .map_err(RpcError::invalid_params),
                None => Err(RpcError::invalid_params(
                    "prompts/get requires a prompt name",
                )),
            })
        },
        // Clients (and some SDKs) set a log level; this server always uses
        // the tracing pipeline, so acknowledging is the honest answer.
        "logging/setLevel" => Some(Ok(json!({}))),
        _ => None,
    }
}

/// Dispatches one JSON-RPC message; `None` means it was a notification and
/// nothing is sent back.
async fn handle_message(
    state: &AppState,
    principal: &McpPrincipal,
    message: &Value,
) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(protocol::error(
            &Value::Null,
            protocol::INVALID_REQUEST,
            "a JSON-RPC message must be an object",
        ));
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Some(protocol::error(
            id.as_ref().unwrap_or(&Value::Null),
            protocol::INVALID_REQUEST,
            "missing method",
        ));
    };
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));

    // Notifications carry no id; per JSON-RPC they get no reply at all.
    let Some(id) = id else {
        tracing::debug!(method, "MCP notification received");
        return None;
    };

    if let Some(outcome) =
        handle_stateless(method, &params, principal.can_write)
    {
        return Some(match outcome {
            Ok(result) => protocol::result(&id, result),
            Err(err) => protocol::error(&id, err.code, err.message),
        });
    }

    match method {
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(protocol::error(
                    &id,
                    protocol::INVALID_PARAMS,
                    "tools/call requires a tool name",
                ));
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let ctx = ToolContext {
                state,
                actor: &principal.label,
                can_write: principal.can_write,
                subject: principal.subject,
                is_admin: principal.is_admin,
            };
            tracing::info!(
                tool = name,
                actor = %principal.label,
                "MCP tool call"
            );
            let value = match tools::call(&ctx, name, &args).await {
                Ok(value) => tool_content(&value, false),
                Err(message) => {
                    tracing::warn!(tool = name, error = %message, "MCP tool call failed");
                    tool_content(&json!({ "error": message }), true)
                },
            };
            Some(protocol::result(&id, value))
        },
        "resources/read" => {
            let Some(uri) = params.get("uri").and_then(Value::as_str) else {
                return Some(protocol::error(
                    &id,
                    protocol::INVALID_PARAMS,
                    "resources/read requires a uri",
                ));
            };
            Some(
                match resources::read(
                    state,
                    &principal.label,
                    principal.subject,
                    principal.is_admin,
                    uri,
                )
                .await
                {
                    Ok(value) => protocol::result(&id, value),
                    Err(message) => {
                        protocol::error(&id, protocol::INVALID_PARAMS, message)
                    },
                },
            )
        },
        other => {
            // Unknown notifications were already answered above; reaching
            // here means the client awaits a reply it will not get otherwise.
            Some(protocol::error(
                &id,
                protocol::METHOD_NOT_FOUND,
                format!("method '{other}' is not supported"),
            ))
        },
    }
}

/// Wraps a tool result into MCP's content-block shape.
fn tool_content(value: &Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(value)
        .unwrap_or_else(|_| value.to_string());
    let mut result = json!({
        "content": [ { "type": "text", "text": text } ],
    });
    if is_error {
        result["isError"] = json!(true);
    }
    result
}

/// `POST /mcp` — the one endpoint that matters.
pub async fn handle_post(
    State(state): State<AppState>,
    principal: McpPrincipal,
    body: Bytes,
) -> Response {
    let message: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => {
            tracing::debug!(error = %err, "MCP request body is not JSON");
            // The spec: a body that is not valid JSON gets HTTP 400 with a
            // JSON-RPC parse error.
            return (
                StatusCode::BAD_REQUEST,
                Json(protocol::error(
                    &Value::Null,
                    protocol::PARSE_ERROR,
                    "request body is not valid JSON",
                )),
            )
                .into_response();
        },
    };

    let response = match message {
        Value::Array(items) => match validate_batch(&items) {
            Err(err) => {
                Some(protocol::error(&Value::Null, err.code, err.message))
            },
            Ok(()) => {
                let mut replies = Vec::with_capacity(items.len());
                for item in &items {
                    if let Some(reply) =
                        handle_message(&state, &principal, item).await
                    {
                        replies.push(reply);
                    }
                }
                (!replies.is_empty()).then_some(Value::Array(replies))
            },
        },
        single => handle_message(&state, &principal, &single).await,
    };

    match response {
        // A batch of nothing but notifications: 202 with an empty body.
        None => StatusCode::ACCEPTED.into_response(),
        Some(value) => (StatusCode::OK, Json(value)).into_response(),
    }
}

/// `GET /mcp` — no server-initiated SSE stream here, so `405` per the spec.
pub async fn handle_get() -> Response {
    method_not_allowed()
}

/// `DELETE /mcp` — the server keeps no sessions to terminate.
pub async fn handle_delete() -> Response {
    method_not_allowed()
}

fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(
            header::ALLOW,
            HeaderValue::from_static("POST"),
        )],
        Json(json!({
            "error": {
                "code": "method_not_allowed",
                "message": "this MCP endpoint answers POST only (stateless Streamable HTTP)",
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateless_methods_answer_without_a_database() {
        let init = handle_stateless(
            "initialize",
            &json!({ "protocolVersion": "2025-03-26" }),
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(init["protocolVersion"], "2025-03-26");

        let ping = handle_stateless("ping", &json!({}), false)
            .unwrap()
            .unwrap();
        assert_eq!(ping, json!({}));

        let tools = handle_stateless("tools/list", &json!({}), false)
            .unwrap()
            .unwrap();
        assert!(tools["tools"].as_array().unwrap().len() >= 8);
        assert!(
            handle_stateless("logging/setLevel", &json!({}), false).is_some()
        );

        // The stateful half is passed through.
        assert!(handle_stateless("tools/call", &json!({}), true).is_none());
        assert!(handle_stateless("resources/read", &json!({}), true).is_none());
    }

    #[test]
    fn prompt_errors_surface_as_invalid_params() {
        let missing = handle_stateless("prompts/get", &json!({}), false)
            .unwrap()
            .unwrap_err();
        assert_eq!(missing.code, protocol::INVALID_PARAMS);

        let unknown =
            handle_stateless("prompts/get", &json!({ "name": "nope" }), false)
                .unwrap()
                .unwrap_err();
        assert!(unknown.message.contains("unknown prompt"));
    }

    #[test]
    fn tool_results_are_content_blocks() {
        let ok = tool_content(&json!({ "count": 1 }), false);
        assert_eq!(ok["content"][0]["type"], "text");
        assert!(ok.get("isError").is_none());
        assert!(ok["content"][0]["text"].as_str().unwrap().contains("count"));

        let failed = tool_content(&json!({ "error": "boom" }), true);
        assert_eq!(failed["isError"], true);
    }

    #[test]
    fn batch_envelope_is_validated() {
        let one = [json!({ "method": "ping", "id": 1 })];
        assert!(validate_batch(&one).is_ok());

        let empty: Vec<Value> = Vec::new();
        assert_eq!(
            validate_batch(&empty).unwrap_err().code,
            protocol::INVALID_REQUEST
        );

        let oversized: Vec<Value> = (0..=MAX_BATCH_SIZE)
            .map(|i| json!({ "method": "ping", "id": i }))
            .collect();
        let err = validate_batch(&oversized).unwrap_err();
        assert_eq!(err.code, protocol::INVALID_REQUEST);
        assert!(err.message.contains(&MAX_BATCH_SIZE.to_string()));
    }
}
