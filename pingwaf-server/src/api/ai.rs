//! AI assistant endpoints: provider settings, conversations and the streaming
//! chat turn.
//!
//! Configuration (`/settings/ai*`) is administrator-only — the provider key
//! and the token spend are shared, and the tools the assistant may call
//! expose fleet-wide data. Conversations and the chat turn are open to every
//! signed-in user: each conversation is owned by its creator (foreign access
//! answers 404), write tools stay gated behind the admin role, and the chat
//! endpoints are rate limited per user. The chat endpoint answers with an
//! SSE stream by default (`Accept: text/event-stream`); without that header
//! it buffers the same events into one JSON object, which keeps `curl` and
//! tests simple.

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, Unchanged,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::ai::{self, ChatEvent, Provider, TurnRequest};
use crate::api::ai_rate_limit;
use crate::api::common::{parse_uuid, Page, Pagination};
use crate::api::error::ApiError;
use crate::api::site_basic_auth::SECRET_MASK;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::models::ai::MAX_TOOL_ROUNDS_LIMIT;
use crate::models::{ai_conversation, ai_message, ai_setting};
use crate::notify::secretbox;

/// Longest user message accepted by the chat endpoint.
const MAX_MESSAGE_CHARS: usize = 8_000;
/// Longest manual conversation title (the column is `varchar(200)`).
const TITLE_LIMIT: usize = 200;
/// Longest "current page" hint a client may attach to a chat message.
const MAX_PAGE_CONTEXT_CHARS: usize = 500;
/// Messages returned per conversation detail response.
const MAX_MESSAGES: u64 = 500;
/// Events buffered between the chat loop and the HTTP response.
const EVENT_BUFFER: usize = 64;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings/ai", get(show_settings).put(update_settings))
        .route("/settings/ai/test", post(test_settings))
        .route(
            "/ai/conversations",
            get(list_conversations).post(create_conversation),
        )
        .route(
            "/ai/conversations/{id}",
            get(show_conversation).delete(delete_conversation),
        )
        .route("/ai/conversations/{id}/messages", post(send_message))
}

// ─────────────────────────────────────────────────────────────
// Settings
// ─────────────────────────────────────────────────────────────

/// Settings as returned to the dashboard; the API key is masked.
#[derive(Debug, Serialize)]
pub struct AiSettingsView {
    pub enabled: bool,
    pub base_url: String,
    /// [`SECRET_MASK`] when a key is stored, empty when none is.
    pub api_key: String,
    pub model: String,
    /// The prompt in effect: the stored override, or the built-in default
    /// when no override is saved. Clearing the field in the console stores
    /// the empty override again, so the default keeps applying.
    pub system_prompt: String,
    pub temperature: f64,
    pub max_tool_rounds: i32,
    pub allow_write_tools: bool,
    pub updated_at: DateTime<Utc>,
}

fn view_of(row: &ai_setting::Model) -> AiSettingsView {
    AiSettingsView {
        enabled: row.enabled,
        base_url: row.base_url.clone(),
        api_key: if row.api_key.is_empty() {
            String::new()
        } else {
            SECRET_MASK.to_string()
        },
        model: row.model.clone(),
        system_prompt: ai::effective_system_prompt(row),
        temperature: row.temperature,
        max_tool_rounds: row.max_tool_rounds,
        allow_write_tools: row.allow_write_tools,
        updated_at: row.updated_at,
    }
}

/// Partial update of the settings row; absent fields keep their stored value.
#[derive(Debug, Deserialize, Default)]
pub struct AiSettingsUpdate {
    pub enabled: Option<bool>,
    pub base_url: Option<String>,
    /// Absent/null keeps the stored key, and so does the [`SECRET_MASK`] a
    /// form round-trip sends back; an empty string clears it.
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub system_prompt: Option<String>,
    pub temperature: Option<f64>,
    pub max_tool_rounds: Option<i32>,
    pub allow_write_tools: Option<bool>,
}

/// Merges a partial update onto the stored row and validates the result.
///
/// A disabled assistant may be stored incomplete (a draft); once it is meant
/// to run, the URL, key and model must all be present.
fn apply_update(
    stored: &ai_setting::Model,
    update: AiSettingsUpdate,
) -> Result<ai_setting::Model, ApiError> {
    let enabled = update.enabled.unwrap_or(stored.enabled);
    let base_url = update
        .base_url
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|| stored.base_url.clone());
    let api_key = match update.api_key {
        None => stored.api_key.clone(),
        Some(key) if key == SECRET_MASK => stored.api_key.clone(),
        Some(key) => key.trim().to_string(),
    };
    let model = update
        .model
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| stored.model.clone());
    let system_prompt = update
        .system_prompt
        .unwrap_or_else(|| stored.system_prompt.clone());
    let temperature = update.temperature.unwrap_or(stored.temperature);
    let max_tool_rounds =
        update.max_tool_rounds.unwrap_or(stored.max_tool_rounds);
    let allow_write_tools =
        update.allow_write_tools.unwrap_or(stored.allow_write_tools);

    if base_url.len() > 500 {
        return Err(ApiError::BadRequest(
            "base_url must be at most 500 characters".to_string(),
        ));
    }
    let url_ok = base_url.is_empty()
        || base_url.starts_with("http://")
        || base_url.starts_with("https://");
    if !url_ok {
        return Err(ApiError::BadRequest(
            "base_url must be an http(s) URL, e.g. https://api.openai.com/v1"
                .to_string(),
        ));
    }
    if model.chars().count() > 200 {
        return Err(ApiError::BadRequest(
            "model must be at most 200 characters".to_string(),
        ));
    }
    if !(0.0..=2.0).contains(&temperature) {
        return Err(ApiError::BadRequest(
            "temperature must be between 0 and 2".to_string(),
        ));
    }
    if !(1..=MAX_TOOL_ROUNDS_LIMIT).contains(&max_tool_rounds) {
        return Err(ApiError::BadRequest(format!(
            "max_tool_rounds must be between 1 and {MAX_TOOL_ROUNDS_LIMIT}"
        )));
    }
    if enabled && base_url.is_empty() {
        return Err(ApiError::BadRequest(
            "base_url is required when the assistant is enabled".to_string(),
        ));
    }
    if enabled && api_key.is_empty() {
        return Err(ApiError::BadRequest(
            "api_key is required when the assistant is enabled".to_string(),
        ));
    }
    if enabled && model.is_empty() {
        return Err(ApiError::BadRequest(
            "model is required when the assistant is enabled".to_string(),
        ));
    }

    Ok(ai_setting::Model {
        id: stored.id,
        enabled,
        base_url,
        api_key,
        model,
        system_prompt,
        temperature,
        max_tool_rounds,
        allow_write_tools,
        updated_at: Utc::now(),
    })
}

/// Converts a merged row into an [`ai_setting::ActiveModel`] that writes
/// every column.
///
/// The plain `ActiveModel::from(model)` conversion marks every field
/// `Unchanged`, and SeaORM silently skips an `UPDATE` that has no values to
/// write (`Updater::is_noop`): the call would answer `Ok` with the stored
/// row while persisting nothing. Marking each column [`Set`] keeps saves
/// honest; [`the_model_writer_marks_every_column_for_writing`] fails when a
/// future column is added without updating this function.
fn writable(row: ai_setting::Model) -> ai_setting::ActiveModel {
    ai_setting::ActiveModel {
        id: Unchanged(row.id),
        enabled: Set(row.enabled),
        base_url: Set(row.base_url),
        api_key: Set(row.api_key),
        model: Set(row.model),
        system_prompt: Set(row.system_prompt),
        temperature: Set(row.temperature),
        max_tool_rounds: Set(row.max_tool_rounds),
        allow_write_tools: Set(row.allow_write_tools),
        updated_at: Set(row.updated_at),
    }
}

/// `GET /api/v1/settings/ai` — administrators only.
async fn show_settings(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<AiSettingsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let row = ai::load_settings(&state.db).await?;
    Ok(Json(view_of(&row)))
}

/// `PUT /api/v1/settings/ai` — administrators only.
async fn update_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<AiSettingsUpdate>,
) -> Result<Json<AiSettingsView>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let stored = ai::load_settings(&state.db).await?;
    let mut merged = apply_update(&stored, payload)?;
    // Seal the API key before it reaches the database. `apply_update`
    // deliberately returns a plain-text merge (the test endpoint feeds the
    // same merge straight into the provider without persisting it).
    merged.api_key = secretbox::seal_string(&merged.api_key);
    tracing::info!(
        actor = %current.id,
        enabled = merged.enabled,
        model = %merged.model,
        allow_write_tools = merged.allow_write_tools,
        "AI assistant settings updated"
    );
    let updated = writable(merged).update(&state.db).await?;
    Ok(Json(view_of(&updated)))
}

/// Response of the connectivity probe.
#[derive(Debug, Serialize)]
pub struct AiTestResult {
    pub ok: bool,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `POST /api/v1/settings/ai/test` — administrators only.
///
/// With a body, probes the submitted configuration merged onto the stored one;
/// without one, probes what is stored. The `enabled` switch is ignored for the
/// probe so a draft can be tested before it goes live.
async fn test_settings(
    State(state): State<AppState>,
    current: AuthUser,
    body: Option<Json<AiSettingsUpdate>>,
) -> Result<Json<AiTestResult>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let stored = ai::load_settings(&state.db).await?;
    let mut candidate = match body {
        Some(Json(update)) => apply_update(&stored, update)?,
        None => stored.clone(),
    };
    candidate.enabled = true;
    // The stored key may be sealed (`enc:v1:`); the provider needs plain
    // text. Clear-text legacy rows pass through untouched.
    candidate.api_key =
        secretbox::open_string(&candidate.api_key).unwrap_or_default();

    let provider = Provider::new(&candidate)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    let probe = [
        json!({ "role": "user", "content": "Reply with the single word: ok" }),
    ];
    Ok(Json(match provider.complete(&probe, 0.0, Some(16)).await {
        Ok(completion) => AiTestResult {
            ok: true,
            model: provider.model().to_string(),
            reply: Some(completion.content.trim().to_string()),
            error: None,
        },
        Err(err) => AiTestResult {
            ok: false,
            model: provider.model().to_string(),
            reply: None,
            error: Some(err.to_string()),
        },
    }))
}

// ─────────────────────────────────────────────────────────────
// Conversations
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConversationSummary {
    pub id: Uuid,
    /// Empty until the first message names the conversation.
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn summary_of(row: &ai_conversation::Model) -> ConversationSummary {
    ConversationSummary {
        id: row.id,
        title: row.title.clone(),
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// One stored message, shaped the way the console renders it.
#[derive(Debug, Serialize)]
pub struct MessageView {
    pub id: Uuid,
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<ai_message::Model> for MessageView {
    fn from(row: ai_message::Model) -> Self {
        Self {
            id: row.id,
            role: row.role,
            content: row.content,
            tool_calls: row.tool_calls,
            tool_call_id: row.tool_call_id,
            tool_name: row.tool_name,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConversationDetail {
    pub id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub messages: Vec<MessageView>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CreateConversationRequest {
    #[serde(default)]
    pub title: Option<String>,
}

/// `GET /api/v1/ai/conversations` — the caller's own conversations.
async fn list_conversations(
    State(state): State<AppState>,
    current: AuthUser,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Page<ConversationSummary>>, ApiError> {
    let p = pagination.normalise();

    let query = ai_conversation::Entity::find()
        .filter(ai_conversation::Column::UserId.eq(current.id))
        .order_by_desc(ai_conversation::Column::UpdatedAt);
    let total = query.clone().count(&state.db).await?;
    let items = query
        .paginate(&state.db, p.page_size)
        .fetch_page(p.index())
        .await?
        .iter()
        .map(summary_of)
        .collect();
    Ok(Json(Page::new(items, total, p)))
}

/// `POST /api/v1/ai/conversations`
async fn create_conversation(
    State(state): State<AppState>,
    current: AuthUser,
    body: Option<Json<CreateConversationRequest>>,
) -> Result<(StatusCode, Json<ConversationSummary>), ApiError> {
    ai_rate_limit::check_user_limit("ai_create", current.id)?;

    let title = body
        .and_then(|Json(payload)| payload.title)
        .unwrap_or_default()
        .trim()
        .to_string();
    if title.chars().count() > TITLE_LIMIT {
        return Err(ApiError::BadRequest(format!(
            "title must be at most {TITLE_LIMIT} characters"
        )));
    }

    let now = Utc::now();
    let row = ai_conversation::ActiveModel {
        id: sea_orm::Set(Uuid::new_v4()),
        user_id: sea_orm::Set(current.id),
        title: sea_orm::Set(title),
        created_at: sea_orm::Set(now),
        updated_at: sea_orm::Set(now),
    };
    let created = ai_conversation::Entity::insert(row)
        .exec_with_returning(&state.db)
        .await?;
    Ok((StatusCode::CREATED, Json(summary_of(&created))))
}

/// `GET /api/v1/ai/conversations/{id}` — the conversation with its messages.
async fn show_conversation(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<ConversationDetail>, ApiError> {
    let conversation_id = parse_uuid(&id, "conversation id")?;
    let conversation =
        load_conversation(&state, &current, conversation_id).await?;

    let messages = ai_message::Entity::find()
        .filter(ai_message::Column::ConversationId.eq(conversation_id))
        .order_by_asc(ai_message::Column::CreatedAt)
        .limit(MAX_MESSAGES)
        .all(&state.db)
        .await?
        .into_iter()
        .map(MessageView::from)
        .collect();

    Ok(Json(ConversationDetail {
        id: conversation.id,
        title: conversation.title,
        created_at: conversation.created_at,
        updated_at: conversation.updated_at,
        messages,
    }))
}

/// `DELETE /api/v1/ai/conversations/{id}` — messages cascade with the row.
async fn delete_conversation(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let conversation_id = parse_uuid(&id, "conversation id")?;
    let conversation =
        load_conversation(&state, &current, conversation_id).await?;

    ai_conversation::Entity::delete_by_id(conversation.id)
        .exec(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Loads a conversation, hiding other users' rows behind a `404`.
async fn load_conversation(
    state: &AppState,
    current: &AuthUser,
    conversation_id: Uuid,
) -> Result<ai_conversation::Model, ApiError> {
    let row = ai_conversation::Entity::find_by_id(conversation_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "conversation {conversation_id} not found"
            ))
        })?;
    if row.user_id != current.id {
        return Err(ApiError::NotFound(format!(
            "conversation {conversation_id} not found"
        )));
    }
    Ok(row)
}

// ─────────────────────────────────────────────────────────────
// Chat
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
    /// Optional hint about which console page the user is looking at,
    /// injected into this turn's system prompt only (never persisted).
    /// Client-controlled and unprivileged: trimmed, length-capped, and not
    /// consulted for tool authorization.
    #[serde(default)]
    pub page_path: Option<String>,
}

/// `POST /api/v1/ai/conversations/{id}/messages`
///
/// Runs one chat turn. The turn is answered as a Server-Sent Event stream
/// (`Accept: text/event-stream`), where each `data:` line is a serialized
/// [`ChatEvent`]; any other `Accept` gets the buffered equivalent as JSON.
async fn send_message(
    State(state): State<AppState>,
    current: AuthUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Response, ApiError> {
    ai_rate_limit::check_user_limit("ai_chat", current.id)?;
    let conversation_id = parse_uuid(&id, "conversation id")?;
    load_conversation(&state, &current, conversation_id).await?;

    let content = payload.content.trim().to_string();
    if content.is_empty() {
        return Err(ApiError::BadRequest(
            "message must not be empty".to_string(),
        ));
    }
    if content.chars().count() > MAX_MESSAGE_CHARS {
        return Err(ApiError::BadRequest(format!(
            "message must be at most {MAX_MESSAGE_CHARS} characters"
        )));
    }
    let page_context = payload
        .page_path
        .as_deref()
        .map(str::trim)
        .filter(|hint| !hint.is_empty())
        .map(str::to_string);
    if let Some(hint) = &page_context {
        if hint.chars().count() > MAX_PAGE_CONTEXT_CHARS {
            return Err(ApiError::BadRequest(format!(
                "page_path must be at most {MAX_PAGE_CONTEXT_CHARS} \
                 characters"
            )));
        }
    }

    let settings = ai::load_settings(&state.db).await?;
    if !settings.enabled {
        return Err(ApiError::Conflict(
            "the AI assistant is disabled; enable it in the settings"
                .to_string(),
        ));
    }
    let can_write = settings.allow_write_tools && current.is_admin();
    // The stored key may be sealed; the provider needs plain text.
    let mut provider_settings = settings.clone();
    provider_settings.api_key =
        secretbox::open_string(&settings.api_key).unwrap_or_default();
    let provider =
        Provider::new(&provider_settings).map_err(|err| match err {
            ai::ProviderError::Config(message) => ApiError::Conflict(message),
            other => ApiError::Internal(other.to_string()),
        })?;

    tracing::info!(
        actor = %current.id,
        conversation = %conversation_id,
        "AI chat turn started"
    );

    let (tx, rx) = mpsc::channel(EVENT_BUFFER);
    tokio::spawn(ai::run_turn(
        state,
        provider,
        settings,
        TurnRequest {
            user_id: current.id,
            user_email: current.email.clone(),
            conversation_id,
            message: content,
            page_context,
            can_write,
            is_admin: current.is_admin(),
        },
        tx,
    ));

    let wants_sse = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"));
    if wants_sse {
        let stream = ReceiverStream::new(rx).map(|event| {
            let data = serde_json::to_string(&event)
                .unwrap_or_else(|_| "{}".to_string());
            Ok::<_, Infallible>(Event::default().data(data))
        });
        return Ok(Sse::new(stream)
            .keep_alive(KeepAlive::default())
            .into_response());
    }

    // Buffered variant: fold the events into one response object.
    let mut rx = rx;
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut final_content = String::new();
    let mut error: Option<String> = None;
    while let Some(event) = rx.recv().await {
        match event {
            ChatEvent::Conversation { .. } | ChatEvent::Delta { .. } => {},
            ChatEvent::ToolCall {
                id,
                name,
                arguments,
            } => tool_calls.push(json!({
                "id": id,
                "name": name,
                "arguments": arguments,
            })),
            ChatEvent::ToolResult {
                id,
                result,
                is_error,
                name: _,
            } => {
                if let Some(entry) = tool_calls
                    .iter_mut()
                    .find(|entry| entry["id"].as_str() == Some(id.as_str()))
                {
                    entry["result"] = result;
                    entry["is_error"] = json!(is_error);
                }
            },
            ChatEvent::Done { content } => final_content = content,
            ChatEvent::Error { message } => error = Some(message),
        }
    }

    if let Some(message) = error {
        return Err(ApiError::BadGateway(message));
    }
    Ok(Json(json!({
        "conversation_id": conversation_id,
        "content": final_content,
        "tool_calls": tool_calls,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> ai_setting::Model {
        ai_setting::Model {
            id: 1,
            enabled: true,
            base_url: "https://api.openai.com/v1".to_string(),
            api_key: "sk-secret".to_string(),
            model: "gpt-4o-mini".to_string(),
            system_prompt: String::new(),
            temperature: 0.2,
            max_tool_rounds: 5,
            allow_write_tools: false,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_secret_mask_keeps_the_stored_key() {
        let merged = apply_update(
            &stored(),
            AiSettingsUpdate {
                api_key: Some(SECRET_MASK.to_string()),
                ..AiSettingsUpdate::default()
            },
        )
        .unwrap();
        assert_eq!(merged.api_key, "sk-secret");

        // An explicit empty string clears it (allowed while disabled).
        let merged = apply_update(
            &stored(),
            AiSettingsUpdate {
                enabled: Some(false),
                api_key: Some(String::new()),
                ..AiSettingsUpdate::default()
            },
        )
        .unwrap();
        assert_eq!(merged.api_key, "");
    }

    #[test]
    fn absent_fields_keep_their_values() {
        let merged =
            apply_update(&stored(), AiSettingsUpdate::default()).unwrap();
        assert_eq!(merged.base_url, "https://api.openai.com/v1");
        assert_eq!(merged.model, "gpt-4o-mini");
        assert_eq!(merged.temperature, 0.2);
        assert!(merged.enabled);
    }

    #[test]
    fn updates_are_validated() {
        let bad_url = apply_update(
            &stored(),
            AiSettingsUpdate {
                base_url: Some("api.openai.com".to_string()),
                ..AiSettingsUpdate::default()
            },
        );
        assert!(bad_url.is_err());

        let bad_temp = apply_update(
            &stored(),
            AiSettingsUpdate {
                temperature: Some(3.0),
                ..AiSettingsUpdate::default()
            },
        );
        assert!(bad_temp.is_err());

        let bad_rounds = apply_update(
            &stored(),
            AiSettingsUpdate {
                max_tool_rounds: Some(0),
                ..AiSettingsUpdate::default()
            },
        );
        assert!(bad_rounds.is_err());

        // A disabled draft may drop the key; enabling without one does not.
        let draft = apply_update(
            &stored(),
            AiSettingsUpdate {
                enabled: Some(false),
                api_key: Some(String::new()),
                ..AiSettingsUpdate::default()
            },
        )
        .unwrap();
        let reenabled = apply_update(
            &draft,
            AiSettingsUpdate {
                enabled: Some(true),
                ..AiSettingsUpdate::default()
            },
        );
        assert!(reenabled.is_err());
    }

    #[test]
    fn trailing_slashes_are_trimmed_from_the_base_url() {
        let merged = apply_update(
            &stored(),
            AiSettingsUpdate {
                base_url: Some(" https://gateway.example.com/v1/ ".to_string()),
                ..AiSettingsUpdate::default()
            },
        )
        .unwrap();
        assert_eq!(merged.base_url, "https://gateway.example.com/v1");
    }

    #[test]
    fn the_view_masks_the_key() {
        let view = view_of(&stored());
        assert_eq!(view.api_key, SECRET_MASK);
        assert_eq!(view.base_url, "https://api.openai.com/v1");

        let mut empty = stored();
        empty.api_key = String::new();
        assert_eq!(view_of(&empty).api_key, "");
    }

    #[test]
    fn the_view_returns_the_prompt_in_effect() {
        // Without a stored override the console should receive the built-in
        // default to prefill, not an empty field.
        assert_eq!(view_of(&stored()).system_prompt, ai::DEFAULT_SYSTEM_PROMPT);

        let mut custom = stored();
        custom.system_prompt = "  custom prompt  ".to_string();
        assert_eq!(view_of(&custom).system_prompt, "custom prompt");
    }

    #[test]
    fn the_model_writer_marks_every_column_for_writing() {
        // Regression: `ActiveModel::from(model)` leaves every field
        // `Unchanged`, so `update()` hits SeaORM's `Updater::is_noop` short
        // circuit — the row is read back unchanged and the API reports a
        // successful save that never happened. Every non-PK column must be
        // `Set`; this test fails when a new column lands without being added
        // to `writable()`.
        use sea_orm::{ActiveValue, Iterable, PrimaryKeyToColumn};

        let active = writable(stored());
        for column in ai_setting::Column::iter() {
            if ai_setting::PrimaryKey::from_column(column).is_some() {
                continue;
            }
            let value = active.get(column);
            assert!(
                matches!(value, ActiveValue::Set(_)),
                "column {column:?} is {value:?}: writable() must Set it"
            );
        }
    }
}
