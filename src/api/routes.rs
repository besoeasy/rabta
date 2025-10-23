//! Canonical public API paths.
//!
//! Every public route lives under [`PREFIX`] and is built from these
//! constants, so the router, the JSON index, and generated URLs cannot drift
//! apart.

/// Public API version. [`PREFIX`] must stay in sync with it.
pub const API_VERSION: &str = "v1";

/// Versioned prefix for every public API route.
pub const PREFIX: &str = "/api/v1";

/// JSON route index.
pub const INDEX: &str = "/api/v1";
/// Liveness probe.
pub const HEALTH: &str = "/health";
/// This node's identity, storage, and runtime snapshot.
pub const NODE: &str = "/node";
/// OpenAPI 3.1 description of the API.
pub const OPENAPI: &str = "/openapi.json";

/// Event collection: publish.
pub const EVENTS: &str = "/events";
/// Count live events via query parameters.
pub const EVENTS_COUNT: &str = "/events/count";
/// Server-to-server peer sync.
pub const SYNC: &str = "/sync";
/// One event by its 64-hex id.
pub const EVENT_BY_ID: &str = "/events/{id}";
/// Size metadata for one event.
pub const EVENT_SIZE: &str = "/events/{id}/size";

/// Blob collection: upload.
pub const BLOBS: &str = "/blobs";
/// One blob by its 64-hex SHA-256.
pub const BLOB_BY_HASH: &str = "/blobs/{hash}";

/// Fully qualified path for one blob, used in `Location` and JSON responses.
pub fn blob_url(hash: &str) -> String {
    format!("{PREFIX}{BLOBS}/{hash}")
}

/// Fully qualified path for a version-relative route.
pub fn api_url(path: &str) -> String {
    format!("{PREFIX}{path}")
}
