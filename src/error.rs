use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Every failure route answers with the same JSON envelope:
/// `{"error": "<human-readable>", "code": "<machine-readable>"}`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub code: &'static str,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
        ApiError {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_json(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_json", msg)
    }
    pub fn bad_sig(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, "bad_sig", msg)
    }
    pub fn bad_collection() -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_collection",
            "collection must match ^[a-z0-9/_-]{1,32}$",
        )
    }
    pub fn bad_label(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_label", msg)
    }
    pub fn bad_blobs(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_blobs", msg)
    }
    pub fn bad_owner() -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_owner",
            "owner must be `ed25519:<64-hex pubkey>`",
        )
    }
    pub fn unauthorized(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", msg)
    }
    pub fn battery_empty(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, "battery_empty", msg)
    }
    pub fn blob_not_encrypted() -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "blob_not_encrypted",
            "blob is not a RABTA1 client-encrypted container (magic RABTA1, version 1, salt 16B, ciphertext >=25B, tag 16B); the relay stores client-encrypted blobs only",
        )
    }
    pub fn replay(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::CONFLICT, "replay", msg)
    }
    pub fn ttl_range(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, "ttl_range", msg)
    }
    pub fn too_large(msg: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", msg)
    }
    pub fn empty_body() -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_body",
            "upload body is empty",
        )
    }
    pub fn at_watermark() -> ApiError {
        ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "at_watermark",
            "storage at watermark — write refused",
        )
    }
    pub fn busy() -> ApiError {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "busy",
            "too many concurrent uploads or temp storage is full — retry shortly",
        )
    }
    pub fn disk_full() -> ApiError {
        ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "disk_full",
            "free disk space is below the safety floor — upload aborted",
        )
    }
    pub fn timeout() -> ApiError {
        ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "timeout",
            "request body stalled — upload aborted",
        )
    }
    pub fn blobs_disabled() -> ApiError {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "blobs_disabled",
            "the blob plane is disabled; STORAGE is 0",
        )
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
        ApiError::internal(format!("storage failure: {e}"))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}/{}]", self.message, self.status, self.code)
    }
}
