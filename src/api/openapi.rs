//! OpenAPI 3.1 description of the public API.
//!
//! Paths are built from [`routes`](super::routes), so renaming a route changes
//! both the router and this document. Schemas describe the exact wire shapes
//! produced by the handlers.

use serde_json::{Map, Value, json};

use super::routes;

fn json_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {"application/json": {"schema": schema}},
    })
}

fn error_response(description: &str) -> Value {
    json_response(description, schema_ref("Error"))
}

fn schema_ref(name: &str) -> Value {
    json!({"$ref": format!("#/components/schemas/{name}")})
}

fn parameter_ref(name: &str) -> Value {
    json!({"$ref": format!("#/components/parameters/{name}")})
}

/// `GET /api/v1/openapi.json` — the generated document.
pub async fn serve() -> axum::Json<Value> {
    axum::Json(spec())
}

/// Build the OpenAPI document from the canonical route constants.
pub fn spec() -> Value {
    let mut paths = Map::new();

    paths.insert(
        routes::HEALTH.to_string(),
        json!({
            "get": {
                "tags": ["ops"],
                "operationId": "getHealth",
                "summary": "Liveness probe",
                "description": "Returns 200 when the process and embedded SQLite are usable.",
                "responses": {
                    "200": json_response("The node is alive.", schema_ref("Health"))
                }
            }
        }),
    );

    paths.insert(
        routes::NODE.to_string(),
        json!({
            "get": {
                "tags": ["ops"],
                "operationId": "getNodeIdentity",
                "summary": "This node's identity",
                "description": "Ed25519 identity for identification and multi-node operations, generated fresh at boot. Identification only: it is not an authorization key, and events remain owner-signed. The same id appears in `GET /api/v1/`, `GET /api/v1/health`, and the `X-Rabta-Node-Id` response header.",
                "responses": {
                    "200": json_response("The node identity.", schema_ref("NodeIdentity"))
                }
            }
        }),
    );

    paths.insert(
        routes::OPENAPI.to_string(),
        json!({
            "get": {
                "tags": ["meta"],
                "operationId": "getOpenApi",
                "summary": "OpenAPI description of this API",
                "description": "This document. Paths are relative to the `/api/v1` server URL.",
                "responses": {
                    "200": json_response(
                        "The OpenAPI 3.1 document.",
                        json!({"type": "object", "description": "An OpenAPI 3.1 document."})
                    )
                }
            }
        }),
    );

    paths.insert(
        routes::EVENTS.to_string(),
        json!({
            "get": {
                "tags": ["events"],
                "operationId": "listEvents",
                "summary": "List live events with ETag caching",
                "description": "Returns live, unexpired envelopes matching query parameters. Supports conditional caching via ETag and If-None-Match.",
                "parameters": [
                    parameter_ref("IfNoneMatch"),
                    {
                        "name": "collection",
                        "in": "query",
                        "required": false,
                        "description": "Exact collection match.",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "collection_glob",
                        "in": "query",
                        "required": false,
                        "description": "Wildcard collection match (* = zero or more, ? = one char).",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "labels",
                        "in": "query",
                        "required": false,
                        "description": "Comma-separated labels. All supplied labels must be present (AND).",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "owner",
                        "in": "query",
                        "required": false,
                        "description": "ed25519:<64 hex> only.",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "required": false,
                        "description": "Page size, 1..100. Default 20.",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
                    },
                    {
                        "name": "cursor",
                        "in": "query",
                        "required": false,
                        "description": "Opaque cursor from next_cursor.",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "since",
                        "in": "query",
                        "required": false,
                        "description": "Inclusive lower bound on created_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    },
                    {
                        "name": "until",
                        "in": "query",
                        "required": false,
                        "description": "Exclusive upper bound on created_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    },
                    {
                        "name": "expires_since",
                        "in": "query",
                        "required": false,
                        "description": "Inclusive lower bound on expires_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    },
                    {
                        "name": "expires_until",
                        "in": "query",
                        "required": false,
                        "description": "Exclusive upper bound on expires_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    }
                ],
                "responses": {
                    "200": json_response("One page of matching envelopes.", schema_ref("EventList")),
                    "304": {
                        "description": "Not Modified. Cached response is still fresh."
                    },
                    "400": error_response("Invalid label, owner, cursor, or query parameters (`bad_label`, `bad_owner`, `bad_json`)."),
                    "500": error_response("Storage failure (`internal`).")
                }
            },
            "post": {
                "tags": ["events"],
                "operationId": "publishEvent",
                "summary": "Publish a signed envelope",
                "description": "Validates the canonical envelope, its SHA-256 id, and its Ed25519 signature, then stores it. Republishing the same id is idempotent and adds no bytes.",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {"schema": schema_ref("EventEnvelope")}
                    }
                },
                "responses": {
                    "201": json_response("Event stored.", schema_ref("PublishResponse")),
                    "200": json_response("Event already stored; no bytes added.", schema_ref("PublishResponse")),
                    "400": error_response("Malformed JSON or an invalid field (`bad_json`, `bad_collection`, `bad_label`, `bad_blobs`, `bad_owner`, `ttl_range`)."),
                    "401": error_response("The signature does not verify (`bad_sig`)."),
                    "413": error_response("The envelope exceeds 100,000 bytes (`too_large`)."),
                    "500": error_response("Storage failure (`internal`)."),
                    "507": error_response("Storage is at the admission watermark (`at_watermark`).")
                }
            }
        }),
    );

    paths.insert(
        routes::EVENTS_COUNT.to_string(),
        json!({
            "get": {
                "tags": ["events"],
                "operationId": "countEventsGet",
                "summary": "Count live events via query parameters",
                "description": "Counts live, unexpired envelopes matching query parameters. Returns an uncached fresh count.",
                "parameters": [
                    {
                        "name": "collection",
                        "in": "query",
                        "required": false,
                        "description": "Exact collection match.",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "collection_glob",
                        "in": "query",
                        "required": false,
                        "description": "Wildcard collection match (* = zero or more, ? = one char).",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "labels",
                        "in": "query",
                        "required": false,
                        "description": "Comma-separated labels. All supplied labels must be present (AND).",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "owner",
                        "in": "query",
                        "required": false,
                        "description": "ed25519:<64 hex> only.",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "since",
                        "in": "query",
                        "required": false,
                        "description": "Inclusive lower bound on created_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    },
                    {
                        "name": "until",
                        "in": "query",
                        "required": false,
                        "description": "Exclusive upper bound on created_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    },
                    {
                        "name": "expires_since",
                        "in": "query",
                        "required": false,
                        "description": "Inclusive lower bound on expires_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    },
                    {
                        "name": "expires_until",
                        "in": "query",
                        "required": false,
                        "description": "Exclusive upper bound on expires_at (unix seconds).",
                        "schema": {"type": "integer", "format": "int64"}
                    }
                ],
                "responses": {
                    "200": json_response("Number of matching live events.", schema_ref("EventCount")),
                    "400": error_response("Invalid label, owner, or query parameters (`bad_label`, `bad_owner`, `bad_json`)."),
                    "500": error_response("Storage failure (`internal`).")
                }
            }
        }),
    );

    paths.insert(
        routes::EVENT_BY_ID.to_string(),
        json!({
            "get": {
                "tags": ["events"],
                "operationId": "getEvent",
                "summary": "Fetch one stored envelope",
                "description": "Returns the exact stored canonical envelope. Invalid, unknown, and expired ids all return 404.",
                "parameters": [
                    parameter_ref("EventIdPath"),
                    parameter_ref("IfNoneMatch")
                ],
                "responses": {
                    "200": {
                        "description": "The stored canonical envelope.",
                        "headers": {
                            "ETag": {
                                "description": "Quoted event id.",
                                "schema": {"type": "string"}
                            },
                            "X-Content-Type-Options": {
                                "description": "Always `nosniff`.",
                                "schema": {"type": "string", "const": "nosniff"}
                            }
                        },
                        "content": {
                            "application/json": {"schema": schema_ref("EventEnvelope")}
                        }
                    },
                    "304": {
                        "description": "The client's ETag matches; no body.",
                        "headers": {
                            "ETag": {
                                "description": "Quoted event id.",
                                "schema": {"type": "string"}
                            }
                        }
                    },
                    "404": error_response("Invalid, unknown, or expired event id (`not_found`).")
                }
            }
        }),
    );

    paths.insert(
        routes::EVENT_SIZE.to_string(),
        json!({
            "get": {
                "tags": ["events"],
                "operationId": "getEventSize",
                "summary": "Event size metadata",
                "description": "The stored envelope size plus the sizes of the live blobs named in `blobs`. Dangling and repeated references add nothing.",
                "parameters": [parameter_ref("EventIdPath")],
                "responses": {
                    "200": json_response("Envelope and total attached size.", schema_ref("EventSize")),
                    "404": error_response("Invalid, unknown, or expired event id (`not_found`).")
                }
            }
        }),
    );

    paths.insert(
        routes::SYNC.to_string(),
        json!({
            "post": {
                "tags": ["sync"],
                "operationId": "peerSync",
                "summary": "Server-to-server peer synchronization",
                "description": "Authenticated push and pull of live events, missing blob hashes, and Merkle tree state. Authenticated via Ed25519 signature headers (`x-rabta-node`, `x-rabta-timestamp`, `x-rabta-nonce`, `x-rabta-signature`). Regulated by node battery accounting.",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {"schema": schema_ref("SyncRequest")}
                    }
                },
                "responses": {
                    "200": json_response("Sync batch result.", schema_ref("SyncResponse")),
                    "400": error_response("Malformed JSON (`bad_json`)."),
                    "401": error_response("Invalid Ed25519 node signature or stale timestamp (`unauthorized`)."),
                    "409": error_response("Replay nonce already seen (`replay`)."),
                    "413": error_response("Sync wire payload exceeds 2 MB (`too_large`)."),
                    "429": error_response("Node battery below the sync floor (or read-only); retry after the given wait (`battery_empty`)."),
                    "500": error_response("Storage failure (`internal`).")
                }
            }
        }),
    );

    paths.insert(
        routes::BLOBS.to_string(),
        json!({
            "put": {
                "tags": ["blobs"],
                "operationId": "uploadBlob",
                "summary": "Upload a client-encrypted blob container",
                "description": "Accepts only a `RABTA1` client-encrypted container (magic `RABTA1`, version 1, 16-byte salt, AEAD ciphertext of at least 25 bytes, 16-byte tag; minimum 64 bytes total). The relay validates shape — magic and version in the first bytes, minimum length, payload entropy — and never learns a key; the tag is verifiable only by recipients. The hash address is SHA-256 over the wrapped bytes. Re-uploading the same bytes is deduplicated.",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/octet-stream": {
                            "schema": {"type": "string", "format": "binary"}
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Blob stored.",
                        "headers": {
                            "Location": {
                                "description": "Versioned download path for this blob.",
                                "schema": {"type": "string"}
                            }
                        },
                        "content": {
                            "application/json": {"schema": schema_ref("BlobUpload")}
                        }
                    },
                    "200": {
                        "description": "The blob already existed; access metadata was refreshed.",
                        "content": {
                            "application/json": {"schema": schema_ref("BlobUpload")}
                        }
                    },
                    "400": error_response("Empty body, a failed body stream, or a body that is not a `RABTA1` client-encrypted container (`empty_body`, `bad_body`, `blob_not_encrypted`)."),
                    "404": error_response("The blob plane is disabled (`blobs_disabled`)."),
                    "408": error_response("The body stalled for 30 seconds (`timeout`)."),
                    "413": error_response("The blob exceeds 0.1% of `STORAGE` (`too_large`)."),
                    "429": error_response("No upload slot or temp-file budget is available (`busy`)."),
                    "500": error_response("Storage failure (`internal`)."),
                    "507": error_response("Storage is at the watermark or below the free-space floor (`at_watermark`, `disk_full`).")
                }
            }
        }),
    );

    paths.insert(
        routes::BLOB_BY_HASH.to_string(),
        json!({
            "get": {
                "tags": ["blobs"],
                "operationId": "downloadBlob",
                "summary": "Download a blob",
                "description": "Streams the blob with ETag, cache, and range support. A successful read records access but never extends the blob deadline.",
                "parameters": [
                    parameter_ref("BlobHashPath"),
                    parameter_ref("Range"),
                    parameter_ref("IfNoneMatch")
                ],
                "responses": {
                    "200": {
                        "description": "The full blob, or the full blob when a range is unsatisfiable.",
                        "headers": {
                            "Content-Type": {
                                "description": "Always `application/octet-stream`.",
                                "schema": {"type": "string", "const": "application/octet-stream"}
                            },
                            "ETag": {
                                "description": "Quoted blob hash.",
                                "schema": {"type": "string"}
                            },
                            "Cache-Control": {
                                "description": "Always `public, max-age=3600`.",
                                "schema": {"type": "string", "const": "public, max-age=3600"}
                            },
                            "Accept-Ranges": {
                                "description": "Always `bytes`.",
                                "schema": {"type": "string", "const": "bytes"}
                            },
                            "X-Content-Type-Options": {
                                "description": "Always `nosniff`.",
                                "schema": {"type": "string", "const": "nosniff"}
                            },
                            "Content-Length": {
                                "description": "Blob size in bytes.",
                                "schema": {"type": "integer", "format": "int64", "minimum": 0}
                            }
                        },
                        "content": {
                            "application/octet-stream": {
                                "schema": {"type": "string", "format": "binary"}
                            }
                        }
                    },
                    "206": {
                        "description": "The requested byte range.",
                        "headers": {
                            "Content-Range": {
                                "description": "The served byte range and full size.",
                                "schema": {"type": "string"}
                            },
                            "Content-Length": {
                                "description": "Range length in bytes.",
                                "schema": {"type": "integer", "format": "int64", "minimum": 0}
                            }
                        },
                        "content": {
                            "application/octet-stream": {
                                "schema": {"type": "string", "format": "binary"}
                            }
                        }
                    },
                    "304": {
                        "description": "The client's ETag matches; no body.",
                        "headers": {
                            "ETag": {
                                "description": "Quoted blob hash.",
                                "schema": {"type": "string"}
                            },
                            "Cache-Control": {
                                "description": "Always `public, max-age=3600`.",
                                "schema": {"type": "string", "const": "public, max-age=3600"}
                            }
                        }
                    },
                    "404": error_response("Unknown, expired, or malformed hash, or the blob plane is disabled (`not_found`, `blobs_disabled`)."),
                    "500": error_response("Storage failure (`internal`).")
                }
            },
            "head": {
                "tags": ["blobs"],
                "operationId": "headBlob",
                "summary": "Blob metadata",
                "description": "Same headers and miss behavior as GET, with no body. A hit records access.",
                "parameters": [
                    parameter_ref("BlobHashPath"),
                    parameter_ref("IfNoneMatch")
                ],
                "responses": {
                    "200": {
                        "description": "The blob exists; headers describe it.",
                        "headers": {
                            "Content-Type": {
                                "description": "Always `application/octet-stream`.",
                                "schema": {"type": "string", "const": "application/octet-stream"}
                            },
                            "ETag": {
                                "description": "Quoted blob hash.",
                                "schema": {"type": "string"}
                            },
                            "Cache-Control": {
                                "description": "Always `public, max-age=3600`.",
                                "schema": {"type": "string", "const": "public, max-age=3600"}
                            },
                            "Accept-Ranges": {
                                "description": "Always `bytes`.",
                                "schema": {"type": "string", "const": "bytes"}
                            },
                            "Content-Length": {
                                "description": "Blob size in bytes.",
                                "schema": {"type": "integer", "format": "int64", "minimum": 0}
                            }
                        }
                    },
                    "304": {
                        "description": "The client's ETag matches; no body.",
                        "headers": {
                            "ETag": {
                                "description": "Quoted blob hash.",
                                "schema": {"type": "string"}
                            },
                            "Cache-Control": {
                                "description": "Always `public, max-age=3600`.",
                                "schema": {"type": "string", "const": "public, max-age=3600"}
                            }
                        }
                    },
                    "404": error_response("Unknown, expired, or malformed hash, or the blob plane is disabled (`not_found`, `blobs_disabled`)."),
                    "500": error_response("Storage failure (`internal`).")
                }
            }
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Rabta API",
            "version": routes::API_VERSION,
            "description": "Signed-event relay with local content-addressed blobs. Clients canonicalize, hash, and sign envelopes; the node verifies signatures, stores opaque JSON, and expires data on a TTL. Every failure uses the Error schema."
        },
        "servers": [
            {
                "url": routes::PREFIX,
                "description": "This node."
            }
        ],
        "tags": [
            {"name": "ops", "description": "Liveness and monitoring."},
            {"name": "events", "description": "Signed event envelopes and queried listing."},
            {"name": "sync", "description": "Server-to-server peer synchronization."},
            {"name": "blobs", "description": "Raw content-addressed blob upload and download."},
            {"name": "meta", "description": "Machine-readable API description."}
        ],
        "security": [],
        "paths": Value::Object(paths),
        "components": {
            "parameters": {
                "EventIdPath": {
                    "name": "id",
                    "in": "path",
                    "required": true,
                    "description": "64-hex event id.",
                    "schema": schema_ref("EventId")
                },
                "BlobHashPath": {
                    "name": "hash",
                    "in": "path",
                    "required": true,
                    "description": "64-hex SHA-256 of the raw blob body.",
                    "schema": schema_ref("BlobHash")
                },
                "IfNoneMatch": {
                    "name": "If-None-Match",
                    "in": "header",
                    "required": false,
                    "description": "A quoted ETag, the bare value, or `*`. A match returns 304.",
                    "schema": {"type": "string"}
                },
                "Range": {
                    "name": "Range",
                    "in": "header",
                    "required": false,
                    "description": "One `bytes=from-to` range. Malformed or unsatisfiable ranges return the full blob.",
                    "schema": {"type": "string"},
                    "example": "bytes=0-1023"
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error", "code"],
                    "properties": {
                        "error": {
                            "type": "string",
                            "description": "Human-readable message."
                        },
                        "code": {
                            "type": "string",
                            "description": "Stable machine-readable code, such as `not_found` or `at_watermark`."
                        }
                    },
                    "additionalProperties": false
                },
                "Health": {
                    "type": "object",
                    "required": ["status", "node_id", "live_events", "live_blobs"],
                    "properties": {
                        "status": {"type": "string", "const": "ok"},
                        "node_id": schema_ref("NodeId"),
                        "live_events": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "live_blobs": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        }
                    },
                    "additionalProperties": false
                },
                "NodeId": {
                    "type": "string",
                    "description": "Lowercase hex SHA-256 of the node's raw Ed25519 public key.",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "NodeIdentity": {
                    "type": "object",
                    "required": [
                        "node_id",
                        "public_key",
                        "algorithm",
                        "source",
                        "sync",
                        "donate",
                        "started_at",
                        "uptime_s",
                        "version",
                        "api_version"
                    ],
                    "properties": {
                        "node_id": schema_ref("NodeId"),
                        "public_key": {
                            "type": "string",
                            "description": "The node's Ed25519 public key.",
                            "pattern": "^ed25519:[0-9a-f]{64}$"
                        },
                        "algorithm": {"type": "string", "const": "ed25519"},
                        "source": {
                            "type": "string",
                            "enum": ["generated"],
                            "description": "Always `generated` (ephemeral identity created at process boot)."
                        },
                        "sync": {
                            "type": "array",
                            "description": "Peer node base URLs configured in SYNC, in configured order.",
                            "maxItems": 4,
                            "items": {"type": "string", "format": "uri"}
                        },
                        "donate": {
                            "type": ["string", "null"],
                            "description": "The operator's optional on-chain donation address from `BITCOIN`; null when unset. Display-only: never part of events or signatures.",
                            "maxLength": 90
                        },
                        "started_at": {"type": "integer", "format": "int64"},
                        "uptime_s": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "version": {"type": "string"},
                        "api_version": {"type": "string"},
                        "events": schema_ref("StatsEvents"),
                        "blobs": schema_ref("StatsBlobs"),
                        "storage": schema_ref("StatsStorage"),
                        "reaper": schema_ref("StatsReaper"),
                        "eviction": schema_ref("StatsEviction"),
                        "upload": schema_ref("StatsUpload"),
                        "peers": schema_ref("StatsPeers")
                    },
                    "additionalProperties": false
                },
                "EventId": {
                    "type": "string",
                    "description": "Lowercase hex SHA-256 of the canonical envelope digest.",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "BlobHash": {
                    "type": "string",
                    "description": "Lowercase hex SHA-256 of the raw blob body.",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "Owner": {
                    "type": "string",
                    "description": "Ed25519 public key as `ed25519:<64 hex>`. The server stores it lowercase.",
                    "pattern": "^ed25519:[0-9a-fA-F]{64}$"
                },
                "CollectionGlob": {
                    "type": "string",
                    "description": "Wildcard collection match: `*` spans zero or more characters, `?` exactly one. Charset is the collection charset plus the metacharacters; `*` and `?` cannot appear in stored collections, so patterns never need escaping. Mutually exclusive with `collection`.",
                    "pattern": "^[a-z0-9/_\\-*?]{1,64}$"
                },
                "EventEnvelope": {
                    "type": "object",
                    "required": [
                        "collection",
                        "created_at",
                        "expires_at",
                        "owner",
                        "labels",
                        "blobs",
                        "data",
                        "id",
                        "sig"
                    ],
                    "properties": {
                        "collection": {
                            "type": "string",
                            "pattern": "^[a-z0-9/_-]{1,32}$"
                        },
                        "created_at": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Unix seconds. Must not be in the server's future."
                        },
                        "expires_at": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Unix seconds. Must be in the future and at most 400 days after `created_at`."
                        },
                        "owner": schema_ref("Owner"),
                        "labels": {
                            "type": "array",
                            "maxItems": 10,
                            "items": {
                                "type": "string",
                                "pattern": "^[A-Za-z0-9:_\\.\\-\\+/]{1,128}$"
                            }
                        },
                        "blobs": {
                            "type": "array",
                            "description": "Blob hashes this event claims; empty means none. References only; bytes never travel in the envelope.",
                            "maxItems": 8,
                            "uniqueItems": true,
                            "items": schema_ref("BlobHash")
                        },
                        "data": {
                            "type": "object",
                            "description": "Opaque JSON object owned by the client.",
                            "additionalProperties": true
                        },
                        "id": schema_ref("EventId"),
                        "sig": {
                            "type": "string",
                            "description": "Ed25519 signature over the 32-byte digest.",
                            "pattern": "^[0-9a-f]{128}$"
                        }
                    },
                    "additionalProperties": true,
                    "description": "Canonical signed envelope. On publish, unknown fields are accepted and discarded; `id` must match the digest and `sig` must verify."
                },
                "PublishResponse": {
                    "type": "object",
                    "required": ["status", "id"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["stored", "duplicate"]
                        },
                        "id": schema_ref("EventId")
                    },
                    "additionalProperties": false
                },
                "EventList": {
                    "type": "object",
                    "required": ["count", "events", "next_cursor"],
                    "properties": {
                        "count": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "events": {
                            "type": "array",
                            "items": schema_ref("EventEnvelope")
                        },
                        "next_cursor": {
                            "type": ["string", "null"],
                            "description": "Opaque cursor for the next page, or null when the page was not full."
                        }
                    },
                    "additionalProperties": false
                },
                "EventCount": {
                    "type": "object",
                    "required": ["count"],
                    "properties": {
                        "count": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Live, unexpired events matching the filters."
                        }
                    },
                    "additionalProperties": false
                },
                "EventSize": {
                    "type": "object",
                    "required": ["id", "envelope_size", "total_size"],
                    "properties": {
                        "id": schema_ref("EventId"),
                        "envelope_size": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "description": "Stored canonical envelope size in bytes."
                        },
                        "total_size": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "description": "Envelope size plus live attached blob bytes."
                        }
                    },
                    "additionalProperties": false
                },
                "BlobUpload": {
                    "type": "object",
                    "required": ["hash", "size", "url", "expires_at"],
                    "properties": {
                        "hash": schema_ref("BlobHash"),
                        "size": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "url": {
                            "type": "string",
                            "format": "uri-reference",
                            "description": "Versioned download path for this blob."
                        },
                        "expires_at": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Unix seconds when the blob expires unless a live event extends it."
                        }
                    },
                    "additionalProperties": false
                },
                "StatsEvents": {
                    "type": "object",
                    "required": ["live", "bytes"],
                    "properties": {
                        "live": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "description": "Charged live envelope bytes."
                        }
                    },
                    "additionalProperties": false
                },
                "StatsBlobs": {
                    "type": "object",
                    "required": [
                        "enabled",
                        "live",
                        "bytes",
                        "claimed_bytes",
                        "unclaimed",
                        "unclaimed_bytes",
                        "unclaimed_limit_bytes",
                        "unclaimed_max_blobs",
                        "max_single_bytes"
                    ],
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "live": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "claimed_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "unclaimed": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "unclaimed_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "unclaimed_limit_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "unclaimed_max_blobs": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 1,
                            "description": "Blob-count ceiling for the unclaimed plane."
                        },
                        "max_single_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        }
                    },
                    "additionalProperties": false
                },
                "StatsStorage": {
                    "type": "object",
                    "required": [
                        "budget_bytes",
                        "target_bytes",
                        "used_bytes",
                        "store_bytes",
                        "configured_bytes",
                        "clamped_to_free",
                        "free_bytes",
                        "data_dir",
                        "policy_rules",
                        "policy_event_bytes",
                        "policy_blob_bytes"
                    ],
                    "properties": {
                        "budget_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Admission line: the effective budget itself (STORAGE after any boot-time clamp)."
                        },
                        "target_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Eviction target: 85% of the effective budget."
                        },
                        "used_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Charged bytes: live envelopes plus claimed blobs."
                        },
                        "store_bytes": {
                            "type": "integer",
                            "format": "int64"
                        },
                        "configured_bytes": {
                            "type": "integer",
                            "format": "int64"
                        },
                        "clamped_to_free": {"type": "boolean"},
                        "free_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "data_dir": {"type": "string"},
                        "policy_rules": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "description": "Number of configured POLICY rules."
                        },
                        "policy_event_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "policy_blob_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        }
                    },
                    "additionalProperties": false
                },
                "StatsReaper": {
                    "type": "object",
                    "required": ["interval_s", "last_sweep_at", "last_sweep_age_s"],
                    "properties": {
                        "interval_s": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "last_sweep_at": {
                            "type": ["integer", "null"],
                            "description": "Unix seconds of the last completed sweep, or null before the first one."
                        },
                        "last_sweep_age_s": {
                            "type": ["integer", "null"],
                            "description": "Seconds since the last sweep, or null before the first one."
                        }
                    },
                    "additionalProperties": false
                },
                "StatsEviction": {
                    "type": "object",
                    "required": [
                        "events_evicted",
                        "blobs_evicted",
                        "bytes_reclaimed",
                        "unclaimed_blobs_evicted",
                        "unclaimed_bytes_reclaimed",
                        "candidates"
                    ],
                    "properties": {
                        "events_evicted": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "blobs_evicted": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "bytes_reclaimed": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "unclaimed_blobs_evicted": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "unclaimed_bytes_reclaimed": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "candidates": schema_ref("StatsEvictionCandidates")
                    },
                    "additionalProperties": false
                },
                "StatsEvictionCandidates": {
                    "type": "object",
                    "required": [
                        "events",
                        "envelope_bytes",
                        "blob_bytes",
                        "reclaimable_bytes",
                        "largest_bytes"
                    ],
                    "properties": {
                        "events": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "description": "Live events pressure eviction could delete now."
                        },
                        "envelope_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "blob_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0,
                            "description": "Blob bytes only the candidate events claim."
                        },
                        "reclaimable_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "largest_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        }
                    },
                    "additionalProperties": false
                },
                "StatsUpload": {
                    "type": "object",
                    "required": ["inflight_bytes", "max_single_bytes"],
                    "properties": {
                        "inflight_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        },
                        "max_single_bytes": {
                            "type": "integer",
                            "format": "int64",
                            "minimum": 0
                        }
                    },
                    "additionalProperties": false
                },
                "StatsPeers": {
                    "type": "object",
                    "required": ["battery", "items"],
                    "properties": {
                        "battery": {
                            "type": ["object", "null"],
                            "description": "The node's battery, lazily regenerated; null before the first sync. mode is the enforced tier: readwrite, sync_disabled (sync refused and outbound passes paused; local writes still work) or read_only (no writes at all).",
                            "required": ["remaining", "max", "regen_per_sec", "mode"],
                            "properties": {
                                "remaining": {"type": "number", "minimum": 0},
                                "max": {"type": "number", "minimum": 0},
                                "regen_per_sec": {"type": "number", "minimum": 0},
                                "mode": {"type": "string", "enum": ["readwrite", "sync_disabled", "read_only"]}
                            },
                            "additionalProperties": false
                        },
                        "items": {
                            "type": "array",
                            "items": schema_ref("StatsPeer")
                        }
                    },
                    "additionalProperties": false
                },
                "StatsPeer": {
                    "type": "object",
                    "description": "One row of persisted peer sync state, keyed by URL.",
                    "required": [
                        "url",
                        "last_success_at",
                        "last_error",
                        "last_error_at",
                        "next_poll_at",
                        "battery"
                    ],
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "last_success_at": {
                            "type": ["integer", "null"],
                            "description": "Unix seconds of the last clean sync, or null."
                        },
                        "last_error": {
                            "type": ["string", "null"],
                            "description": "Most recent transport or verification error, or null."
                        },
                        "last_error_at": {
                            "type": ["integer", "null"],
                            "description": "Unix seconds of the last error, or null."
                        },
                        "next_poll_at": {
                            "type": "integer",
                            "format": "int64",
                            "description": "Unix seconds when this peer is next eligible for a poll."
                        },
                        "battery": {
                            "type": ["object", "null"],
                            "description": "Battery reported by the peer's last sync response, or null before the first sync.",
                            "required": ["remaining", "max", "updated_at"],
                            "properties": {
                                "remaining": {"type": "number", "minimum": 0},
                                "max": {"type": "number", "minimum": 0},
                                "updated_at": {
                                    "type": "integer",
                                    "format": "int64",
                                    "description": "Unix seconds when this battery reading was stored."
                                }
                            },
                            "additionalProperties": false
                        }
                    },
                    "additionalProperties": false
                },
                "RangeSummary": {
                    "type": "object",
                    "required": ["start", "end", "count", "digest"],
                    "properties": {
                        "start": {"type": "integer", "format": "int64"},
                        "end": {"type": "integer", "format": "int64"},
                        "count": {"type": "integer", "format": "int64"},
                        "digest": {"type": "string"}
                    }
                },
                "SyncRequest": {
                    "type": "object",
                    "required": ["epoch", "root", "ranges", "push_events", "request_id"],
                    "properties": {
                        "epoch": {"type": "string", "description": "Local sync epoch hex."},
                        "root": {"$ref": "#/components/schemas/RangeSummary"},
                        "ranges": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/RangeSummary"}
                        },
                        "push_events": {
                            "type": "array",
                            "items": {"type": "object"}
                        },
                        "request_id": {"type": "string"}
                    }
                },
                "SyncResponse": {
                    "type": "object",
                    "required": [
                        "epoch", "accepted", "rejected", "pull_events",
                        "known_ids", "sub_ranges",
                        "missing_blobs", "battery", "peer"
                    ],
                    "properties": {
                        "epoch": {"type": "string"},
                        "accepted": {"type": "integer", "minimum": 0},
                        "rejected": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["id", "code"],
                                "properties": {
                                    "id": {"type": "string"},
                                    "code": {"type": "string"}
                                }
                            }
                        },
                        "pull_events": {
                            "type": "array",
                            "items": {"type": "object"}
                        },
                        "known_ids": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "sub_ranges": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/RangeSummary"}
                        },
                        "missing_blobs": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "battery": {
                            "type": "object",
                            "required": ["remaining", "max", "regen_per_sec", "cost", "retry_after_s"],
                            "properties": {
                                "remaining": {"type": "number"},
                                "max": {"type": "number"},
                                "regen_per_sec": {"type": "number"},
                                "cost": {"type": "number"},
                                "retry_after_s": {"type": "integer"}
                            }
                        },
                        "peer": {
                            "type": "object",
                            "required": ["next_poll_after_ms"],
                            "properties": {
                                "next_poll_after_ms": {"type": "integer"}
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_refs<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if key == "$ref"
                        && let Some(reference) = child.as_str()
                    {
                        out.push(reference);
                    }
                    collect_refs(child, out);
                }
            }
            Value::Array(items) => {
                for child in items {
                    collect_refs(child, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn spec_covers_every_public_route_and_resolves_refs() {
        let document = spec();
        assert_eq!(document["openapi"], "3.1.0");
        assert_eq!(routes::PREFIX, format!("/api/{}", routes::API_VERSION));
        assert_eq!(document["info"]["version"], routes::API_VERSION);
        assert_eq!(document["servers"][0]["url"], routes::PREFIX);

        let paths = document["paths"].as_object().expect("paths object");
        for route in [
            routes::HEALTH,
            routes::NODE,
            routes::EVENTS,
            routes::EVENTS_COUNT,
            routes::SYNC,
            routes::EVENT_BY_ID,
            routes::EVENT_SIZE,
            routes::BLOBS,
            routes::BLOB_BY_HASH,
            routes::OPENAPI,
        ] {
            let item = paths
                .get(route)
                .unwrap_or_else(|| panic!("missing path {route}"));
            assert!(
                item.as_object()
                    .is_some_and(|operations| !operations.is_empty()),
                "{route} has no operations"
            );
        }

        let mut refs = Vec::new();
        collect_refs(&document, &mut refs);
        assert!(!refs.is_empty());
        for reference in refs {
            let pointer = reference
                .strip_prefix("#/")
                .unwrap_or_else(|| panic!("non-local reference {reference}"));
            let mut node = &document;
            for part in pointer.split('/') {
                node = node
                    .get(part)
                    .unwrap_or_else(|| panic!("unresolved reference {reference}"));
            }
        }
    }
}
