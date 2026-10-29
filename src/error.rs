use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Every failure route answers with the same JSON envelope:
/// `{"error": "<human-readable>", "code": "<machine-readable>"}` (plan.md §Error bodies).
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub code: &'static str,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
        ApiError { status, code, message: message.into() }
    }

    pub fn bad_json(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_json", msg)
    }
    pub fn bad_sig(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, "bad_sig", msg)
    }
    pub fn bad_collection() -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_collection", "collection must match ^[a-z0-9/_-]{1,32}$")
    }
    pub fn bad_label(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_label", msg)
    }
    pub fn bad_owner() -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_owner",
            "owner must be `ed25519:<64-hex pubkey>`",
        )
    }
    pub fn ttl_range(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "ttl_range", msg)
    }
    pub fn too_large(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", msg)
    }
    pub fn bad_extension() -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_extension", "upload filename must end in .blob or .bin")
    }
    pub fn bad_blob(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_blob", msg)
    }
    pub fn at_watermark() -> ApiError {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "at_watermark", "storage at watermark — upload aborted")
    }
    pub fn subscriber_cap() -> ApiError {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "subscriber_cap", "SSE subscriber cap reached")
    }
    pub fn not_found(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, "not_found", msg)
    }
    pub fn internal(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.message, "code": self.code });
        (self.status, axum::Json(body)).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("sqlite error: {e}");
        ApiError::internal("storage failure")
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}/{}]", self.message, self.status, self.code)
    }
}
