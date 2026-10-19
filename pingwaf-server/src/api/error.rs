//! Uniform error type and JSON error envelope for the REST API.
//!
//! Every failure is rendered as
//! `{"error": {"code": "<machine_readable>", "message": "<human readable>"}}`
//! together with the matching HTTP status code, which keeps the frontend's
//! error handling down to a single shape.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sea_orm::DbErr;
use serde_json::json;

/// Builds the shared `{"error": {...}}` envelope.
pub fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response {
    let body = json!({ "error": { "code": code, "message": message } });
    (status, Json(body)).into_response()
}

/// Fixed text for an unexpected failure.
///
/// The detail stays in the log: a `DbErr` or an I-O error names tables, files
/// and connection strings, and this is what a caller who did nothing wrong
/// gets to read.
const INTERNAL_MESSAGE: &str = "internal server error";

/// Fixed text for a row the database reports as missing.
///
/// `DbErr::RecordNotFound` carries whatever text the lookup used, and a
/// generated `find_related` / `update` path puts the table name in it, so the
/// message is not safe to echo.
const NOT_FOUND_MESSAGE: &str = "not found";

/// Errors surfaced by API handlers.
#[derive(Debug)]
pub enum ApiError {
    /// Malformed input, invalid identifiers, out-of-range pagination.
    BadRequest(String),
    /// Missing or invalid credentials.
    Unauthorized(String),
    /// Authenticated but not allowed to perform the action.
    Forbidden(String),
    /// The resource does not exist (or is not visible to this user).
    NotFound(String),
    /// Uniqueness violation, e.g. a domain that is already registered.
    Conflict(String),
    /// A budget shared by all callers was exhausted.
    TooManyRequests(String),
    /// Semantically invalid payload (well-formed JSON, bad values).
    Unprocessable(String),
    /// The endpoint exists but cannot run on this deployment, e.g. CPU
    /// profiling on non-Linux platforms.
    NotImplemented(String),
    /// An upstream dependency (e.g. a subscription source) failed; the
    /// upstream's own error text is safe to show to the operator.
    BadGateway(String),
    /// The endpoint is disabled on this deployment, e.g. profiling captures
    /// turned off via the deployment switch.
    ServiceUnavailable(String),
    /// Unexpected failure; the message is logged in full and a generic text is
    /// returned to the client.
    Internal(String),
}

impl ApiError {
    /// Error code embedded in the response body.
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::TooManyRequests(_) => "too_many_requests",
            ApiError::Unprocessable(_) => "unprocessable_entity",
            ApiError::NotImplemented(_) => "not_implemented",
            ApiError::BadGateway(_) => "bad_gateway",
            ApiError::ServiceUnavailable(_) => "service_unavailable",
            ApiError::Internal(_) => "internal_error",
        }
    }

    /// HTTP status code for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            ApiError::BadGateway(_) => StatusCode::BAD_GATEWAY,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        ApiError::Internal(err.to_string())
    }

    /// An unexpected failure whose detail must not leave the process.
    ///
    /// The error is logged here — with its cause chain — and the reply carries
    /// [`INTERNAL_MESSAGE`] only. Prefer this over
    /// `ApiError::Internal(x.to_string())`: the variant keeps `x` in the enum,
    /// where `Display` would hand it to whoever formats the error next (the
    /// MCP endpoint, a log line, a future response), and only the log is
    /// allowed to see it.
    pub fn internal_generic(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "internal API error");
        ApiError::Internal(INTERNAL_MESSAGE.to_string())
    }

    pub fn bad_request(err: impl std::fmt::Display) -> Self {
        ApiError::BadRequest(err.to_string())
    }

    pub fn not_found(err: impl std::fmt::Display) -> Self {
        ApiError::NotFound(err.to_string())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadRequest(msg)
            | ApiError::Unauthorized(msg)
            | ApiError::Forbidden(msg)
            | ApiError::NotFound(msg)
            | ApiError::Conflict(msg)
            | ApiError::TooManyRequests(msg)
            | ApiError::Unprocessable(msg)
            | ApiError::NotImplemented(msg)
            | ApiError::BadGateway(msg)
            | ApiError::ServiceUnavailable(msg)
            | ApiError::Internal(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            // The cause was already logged where it was known
            // (`internal_generic`, the `DbErr` / `anyhow` conversions); this
            // line only records that a 500 went out.
            tracing::error!(error = %self, "internal API error");
            return error_response(status, code, INTERNAL_MESSAGE);
        }
        if status.is_server_error() {
            tracing::error!(error = %self, "API error");
        } else {
            tracing::debug!(error = %self, code, "API rejected request");
        }
        error_response(status, code, &self.to_string())
    }
}

impl From<DbErr> for ApiError {
    fn from(err: DbErr) -> Self {
        match &err {
            // The lookup text can name the table the row was searched in; the
            // 404 body says only that it is gone.
            DbErr::RecordNotFound(_) => {
                ApiError::NotFound(NOT_FOUND_MESSAGE.to_string())
            },
            DbErr::Exec(runtime_err) | DbErr::Query(runtime_err)
                if runtime_err.to_string().contains("duplicate key") =>
            {
                ApiError::Conflict("resource already exists".to_string())
            },
            other => ApiError::internal_generic(other),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        // `{:#}` flattens the context chain into the single log line; the
        // client never sees any of it.
        ApiError::internal_generic(format!("{err:#}"))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::BadRequest(format!("invalid JSON: {err}"))
    }
}

impl From<uuid::Error> for ApiError {
    fn from(err: uuid::Error) -> Self {
        ApiError::BadRequest(format!("invalid UUID: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// Renders the error the way Axum does, and returns the status plus the
    /// parsed envelope.
    async fn envelope(err: ApiError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    /// D11: `DbErr::RecordNotFound` carries the lookup text, which on a
    /// generated query names the table — a 404 must not echo it back.
    #[tokio::test]
    async fn record_not_found_is_reported_without_the_database_text() {
        let err = ApiError::from(DbErr::RecordNotFound(
            "sites: no row for id 7".to_string(),
        ));
        let (status, body) = envelope(err).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["message"], NOT_FOUND_MESSAGE);
    }

    /// A 404 the handler phrased itself (an id the operator typed) still says
    /// what was missing.
    #[tokio::test]
    async fn handler_not_found_keeps_its_message() {
        let (status, body) =
            envelope(ApiError::NotFound("site 42 not found".to_string())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["message"], "site 42 not found");
    }

    /// The generic constructor logs the cause and puts none of it in the body.
    #[tokio::test]
    async fn internal_generic_body_omits_the_cause() {
        let err = ApiError::from(DbErr::Query(sea_orm::RuntimeErr::Internal(
            "connection refused: pingwaf@10.0.0.2:5432".to_string(),
        )));
        let (status, body) = envelope(err).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal_error");
        assert_eq!(body["error"]["message"], INTERNAL_MESSAGE);
    }
}
