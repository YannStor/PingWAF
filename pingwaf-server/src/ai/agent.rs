//! The streaming chat loop behind the console's assistant page.
//!
//! One turn = persist the user message, then up to `max_tool_rounds` rounds of
//! (stream a completion → execute the requested tools) plus one final
//! tool-less round for the answer. Every message is persisted as it is
//! produced, so a reload rebuilds the conversation verbatim — including the
//! assistant tool-call rows and tool answers the provider context requires.

use std::collections::HashSet;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set,
};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::provider::Provider;
use super::{conversation_title, effective_system_prompt};
use crate::api::state::AppState;
use crate::mcp::tools::{self, ToolContext};
use crate::models::ai::MAX_TOOL_ROUNDS_LIMIT;
use crate::models::{ai_conversation, ai_message, ai_setting, message_role};

/// How many recent messages are replayed to the provider.
const CONTEXT_MESSAGES: u64 = 40;
/// Cap on one tool result, in chars, as persisted and replayed.
const TOOL_RESULT_CHARS: usize = 24_000;

/// One event of a streaming turn, serialized as the SSE payload; the JSON
/// fallback folds the same events into a single object.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatEvent {
    /// The conversation's title (derived from the first message) became known.
    Conversation { id: Uuid, title: String },
    /// Incremental assistant text.
    Delta { text: String },
    /// The model requested a tool call.
    ToolCall {
        id: String,
        name: String,
        arguments: Value,
    },
    /// The tool answered; `result` is the tool's raw JSON, or an object with
    /// an `error` field when `is_error` is set.
    ToolResult {
        id: String,
        name: String,
        result: Value,
        is_error: bool,
    },
    /// The turn finished; `content` is the final round's message.
    Done { content: String },
    /// The turn failed; the message is safe to display to the operator.
    Error { message: String },
}

/// Inputs of one chat turn.
pub struct TurnRequest {
    pub user_id: Uuid,
    pub user_email: String,
    pub conversation_id: Uuid,
    pub message: String,
    /// Optional hint about the console page the user is viewing, injected
    /// into this turn's system prompt only (never persisted or replayed).
    /// Client-supplied and unprivileged — informational context, not an
    /// authorization input.
    pub page_context: Option<String>,
    /// Whether write tools may be invoked (settings opt-in ∧ admin role).
    pub can_write: bool,
    /// Whether the caller is an administrator. Independent of `can_write`:
    /// the settings switch can disable writes for an admin, and read tools
    /// still need to know whether to scope results to the caller's sites.
    pub is_admin: bool,
}

/// Runs one chat turn to completion, reporting progress through `events`.
///
/// Failures are delivered as a [`ChatEvent::Error`] rather than returned, so
/// both the SSE stream and the JSON fallback end the same way. The caller must
/// keep draining `events` — the loop is the only reader of the provider stream
/// and would stall on a full channel otherwise.
pub async fn run_turn(
    state: AppState,
    provider: Provider,
    settings: ai_setting::Model,
    request: TurnRequest,
    events: mpsc::Sender<ChatEvent>,
) {
    if let Err(message) =
        execute(&state, &provider, &settings, &request, &events).await
    {
        tracing::warn!(
            conversation = %request.conversation_id,
            error = %message,
            "AI chat turn failed"
        );
        let _ = events.send(ChatEvent::Error { message }).await;
    }
}

async fn execute(
    state: &AppState,
    provider: &Provider,
    settings: &ai_setting::Model,
    request: &TurnRequest,
    events: &mpsc::Sender<ChatEvent>,
) -> Result<(), String> {
    let db = &state.db;

    // 1. Persist the user message; the first one names the conversation.
    let existing = ai_message::Entity::find()
        .filter(ai_message::Column::ConversationId.eq(request.conversation_id))
        .count(db)
        .await
        .map_err(db_error)?;
    let stored = ai_conversation::Entity::find_by_id(request.conversation_id)
        .one(db)
        .await
        .map_err(db_error)?
        .ok_or_else(|| "the conversation no longer exists".to_string())?;

    let now = Utc::now();
    insert_message(
        state,
        request.conversation_id,
        message_role::USER,
        &request.message,
        None,
        None,
        None,
    )
    .await?;

    let title = if existing == 0 || stored.title.trim().is_empty() {
        conversation_title(&request.message)
    } else {
        stored.title.clone()
    };
    let mut conversation: ai_conversation::ActiveModel = stored.into();
    conversation.title = Set(title.clone());
    conversation.updated_at = Set(now);
    let conversation = conversation.update(db).await.map_err(db_error)?;

    let _ = events
        .send(ChatEvent::Conversation {
            id: conversation.id,
            title,
        })
        .await;

    // 2. Rebuild the provider context from the recent history.
    let mut history = ai_message::Entity::find()
        .filter(ai_message::Column::ConversationId.eq(request.conversation_id))
        .order_by_desc(ai_message::Column::CreatedAt)
        .limit(CONTEXT_MESSAGES)
        .all(db)
        .await
        .map_err(db_error)?;
    history.reverse();
    // The window must open with a user message: an assistant tool-call row is
    // only valid for the provider when the tool answers that follow it are
    // present too, and truncating anywhere else could split that pair.
    match history
        .iter()
        .position(|row| row.role == message_role::USER)
    {
        Some(start) => {
            history.drain(..start);
        },
        None => history.clear(),
    }

    let mut messages = Vec::with_capacity(history.len() + 1);
    let mut system_prompt = effective_system_prompt(settings);
    if let Some(page) = request.page_context.as_deref() {
        // Informational only: tells the model where in the console the
        // question is coming from. Trimmed and length-capped by the API.
        system_prompt.push_str(&format!(
            "\n\nThe user is currently viewing the console page: {page}"
        ));
    }
    messages.push(json!({
        "role": "system",
        "content": system_prompt,
    }));
    messages.extend(wire_context(&history));

    // 3. Tool-calling rounds, then one final tool-less round.
    let max_rounds = settings.max_tool_rounds.clamp(1, MAX_TOOL_ROUNDS_LIMIT);
    let actor = format!("{} (AI assistant)", request.user_email);
    let tool_ctx = ToolContext {
        state,
        actor: &actor,
        can_write: request.can_write,
        subject: request.user_id,
        is_admin: request.is_admin,
    };
    let mut answer = String::new();

    for round in 0..=max_rounds {
        if events.is_closed() {
            // The console went away; stop working (and stop paying for tokens).
            return Ok(());
        }

        let allow_tools = round < max_rounds;
        let tools = if allow_tools {
            tools::openai_tools(request.can_write)
        } else {
            Vec::new()
        };

        // Text deltas are forwarded live while the completion is assembled;
        // without this task the bounded channel would stall the provider once
        // the console cannot keep up.
        let (delta_tx, mut delta_rx) = mpsc::channel::<String>(64);
        let forwarder = {
            let events = events.clone();
            tokio::spawn(async move {
                while let Some(text) = delta_rx.recv().await {
                    if events.send(ChatEvent::Delta { text }).await.is_err() {
                        break;
                    }
                }
            })
        };

        let completion = provider
            .chat_stream(
                &messages,
                &tools,
                settings.temperature,
                Some(&delta_tx),
            )
            .await;
        drop(delta_tx);
        let _ = forwarder.await;

        let completion = completion.map_err(|err| err.to_string())?;

        // In the final round no tools were offered, so any call the model
        // still emits is dropped rather than executed — and dropping it from
        // the persisted row keeps the stored context valid for later turns.
        let execute_calls = allow_tools && !completion.tool_calls.is_empty();
        let wire_calls = if execute_calls {
            Some(Value::Array(
                completion
                    .tool_calls
                    .iter()
                    .map(|call| call.to_wire())
                    .collect(),
            ))
        } else {
            None
        };
        insert_message(
            state,
            request.conversation_id,
            message_role::ASSISTANT,
            &completion.content,
            wire_calls.clone(),
            None,
            None,
        )
        .await?;

        let mut assistant =
            json!({ "role": "assistant", "content": completion.content });
        if let Some(calls) = &wire_calls {
            assistant["tool_calls"] = calls.clone();
        }
        messages.push(assistant);

        if !execute_calls {
            answer = completion.content;
            break;
        }

        for call in &completion.tool_calls {
            let arguments: Value =
                serde_json::from_str(&call.arguments).unwrap_or(Value::Null);
            let _ = events
                .send(ChatEvent::ToolCall {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: arguments.clone(),
                })
                .await;

            let (result, is_error) =
                match tools::call(&tool_ctx, &call.name, &arguments).await {
                    Ok(value) => (value, false),
                    Err(message) => (json!({ "error": message }), true),
                };
            let serialized = clip_result(&result);

            insert_message(
                state,
                request.conversation_id,
                message_role::TOOL,
                &serialized,
                None,
                Some(call.id.clone()),
                Some(call.name.clone()),
            )
            .await?;

            let _ = events
                .send(ChatEvent::ToolResult {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    result: result.clone(),
                    is_error,
                })
                .await;

            messages.push(json!({
                "role": "tool",
                "tool_call_id": call.id,
                "content": serialized,
            }));
        }
    }

    let _ = events.send(ChatEvent::Done { content: answer }).await;
    Ok(())
}

/// One insert into `ai_messages`.
async fn insert_message(
    state: &AppState,
    conversation_id: Uuid,
    role: &str,
    content: &str,
    tool_calls: Option<Value>,
    tool_call_id: Option<String>,
    tool_name: Option<String>,
) -> Result<(), String> {
    let row = ai_message::ActiveModel {
        id: Set(Uuid::new_v4()),
        conversation_id: Set(conversation_id),
        role: Set(role.to_string()),
        content: Set(content.to_string()),
        tool_calls: Set(tool_calls),
        tool_call_id: Set(tool_call_id),
        tool_name: Set(tool_name),
        created_at: Set(Utc::now()),
    };
    ai_message::Entity::insert(row)
        .exec(&state.db)
        .await
        .map_err(db_error)?;
    Ok(())
}

/// Converts stored history into provider messages.
///
/// Assistant rows carrying tool calls are only replayed when the immediately
/// following tool rows answer every call: a dangling pair (the process died
/// between the two inserts) would make the provider reject every later
/// request of this conversation, so it is downgraded instead. Orphan tool rows
/// are dropped for the same reason.
fn wire_context(history: &[ai_message::Model]) -> Vec<Value> {
    let mut messages: Vec<Value> = Vec::with_capacity(history.len());
    // Tool call ids of the assistant row that opened the current run.
    let mut open_calls: HashSet<&str> = HashSet::new();

    for (index, row) in history.iter().enumerate() {
        match row.role.as_str() {
            message_role::TOOL => {
                let id = row.tool_call_id.as_deref().unwrap_or_default();
                if open_calls.contains(id) {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": id,
                        "content": row.content,
                    }));
                }
            },
            message_role::ASSISTANT => {
                open_calls.clear();
                let calls: Vec<&str> = row
                    .tool_calls
                    .as_ref()
                    .and_then(Value::as_array)
                    .map(|calls| {
                        calls
                            .iter()
                            .filter_map(|call| {
                                call.get("id").and_then(Value::as_str)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if calls.is_empty() {
                    messages.push(
                        json!({ "role": "assistant", "content": row.content }),
                    );
                    continue;
                }

                let answered: HashSet<&str> = history[index + 1..]
                    .iter()
                    .take_while(|next| next.role == message_role::TOOL)
                    .filter_map(|next| next.tool_call_id.as_deref())
                    .collect();
                if calls.iter().all(|id| answered.contains(id)) {
                    open_calls.extend(calls);
                    messages.push(json!({
                        "role": "assistant",
                        "content": row.content,
                        "tool_calls": row.tool_calls,
                    }));
                } else if !row.content.is_empty() {
                    messages.push(
                        json!({ "role": "assistant", "content": row.content }),
                    );
                }
            },
            _ => {
                open_calls.clear();
                messages
                    .push(json!({ "role": "user", "content": row.content }));
            },
        }
    }
    messages
}

/// Serializes a tool result for persistence and replay, capped at
/// [`TOOL_RESULT_CHARS`] on a char boundary.
fn clip_result(value: &Value) -> String {
    let text =
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    if text.len() <= TOOL_RESULT_CHARS {
        return text;
    }
    let mut end = TOOL_RESULT_CHARS;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…(truncated)", &text[..end])
}

fn db_error(err: sea_orm::DbErr) -> String {
    tracing::error!(error = %err, "AI chat database operation failed");
    "the control plane database is unavailable".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(
        role: &str,
        content: &str,
        tool_calls: Option<Value>,
        tool_call_id: Option<&str>,
    ) -> ai_message::Model {
        ai_message::Model {
            id: Uuid::new_v4(),
            conversation_id: Uuid::nil(),
            role: role.to_string(),
            content: content.to_string(),
            tool_calls,
            tool_call_id: tool_call_id.map(str::to_string),
            tool_name: None,
            created_at: Utc::now(),
        }
    }

    fn call(id: &str) -> Value {
        json!({
            "id": id,
            "type": "function",
            "function": { "name": "list_sites", "arguments": "{}" },
        })
    }

    #[test]
    fn a_complete_tool_round_trips_verbatim() {
        let history = vec![
            message(message_role::USER, "what is down?", None, None),
            message(
                message_role::ASSISTANT,
                "",
                Some(json!([call("c1")])),
                None,
            ),
            message(message_role::TOOL, "{\"sites\":[]}", None, Some("c1")),
            message(message_role::ASSISTANT, "Nothing.", None, None),
        ];
        let wire = wire_context(&history);
        assert_eq!(wire.len(), 4);
        assert_eq!(wire[1]["tool_calls"][0]["id"], "c1");
        assert_eq!(wire[2]["role"], "tool");
        assert_eq!(wire[2]["tool_call_id"], "c1");
    }

    #[test]
    fn a_dangling_tool_call_is_downgraded() {
        // Crash between the assistant insert and its tool answers.
        let history = vec![
            message(message_role::USER, "hi", None, None),
            message(
                message_role::ASSISTANT,
                "Checking…",
                Some(json!([call("c1")])),
                None,
            ),
            message(message_role::USER, "still there?", None, None),
        ];
        let wire = wire_context(&history);
        assert_eq!(wire.len(), 3);
        assert!(wire[1].get("tool_calls").is_none());
        assert_eq!(wire[1]["content"], "Checking…");

        // An empty, undelivered assistant message is dropped entirely.
        let history = vec![
            message(message_role::USER, "hi", None, None),
            message(
                message_role::ASSISTANT,
                "",
                Some(json!([call("c1")])),
                None,
            ),
            message(message_role::USER, "hello?", None, None),
        ];
        let wire = wire_context(&history);
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[1]["role"], "user");
    }

    #[test]
    fn partially_answered_calls_and_orphan_tools_are_dropped() {
        let history = vec![
            message(message_role::USER, "hi", None, None),
            message(
                message_role::ASSISTANT,
                "",
                Some(json!([call("c1"), call("c2")])),
                None,
            ),
            message(message_role::TOOL, "{}", None, Some("c1")),
            message(message_role::USER, "next", None, None),
            message(message_role::TOOL, "{}", None, Some("c9")),
        ];
        let wire = wire_context(&history);
        // c1/c2 downgraded (c2 unanswered), the orphan c9 tool row and the
        // empty downgraded assistant row are all gone.
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[1]["content"], "next");
    }

    #[test]
    fn events_serialize_with_a_type_tag() {
        let delta = serde_json::to_value(ChatEvent::Delta {
            text: "hi".to_string(),
        })
        .unwrap();
        assert_eq!(delta["type"], "delta");
        assert_eq!(delta["text"], "hi");

        let done = serde_json::to_value(ChatEvent::Done {
            content: "ok".to_string(),
        })
        .unwrap();
        assert_eq!(done["type"], "done");

        let call = serde_json::to_value(ChatEvent::ToolCall {
            id: "c1".to_string(),
            name: "list_sites".to_string(),
            arguments: json!({"limit": 5}),
        })
        .unwrap();
        assert_eq!(call["type"], "tool_call");
        assert_eq!(call["arguments"]["limit"], 5);
    }

    #[test]
    fn oversized_tool_results_are_clipped_on_a_char_boundary() {
        let huge = json!({ "blob": "中".repeat(TOOL_RESULT_CHARS) });
        let clipped = clip_result(&huge);
        assert!(clipped.ends_with("…(truncated)"));
        assert!(clipped.len() <= TOOL_RESULT_CHARS + "(truncated)".len() + 4);

        let small = json!({ "ok": true });
        assert_eq!(clip_result(&small), "{\"ok\":true}");
    }
}
