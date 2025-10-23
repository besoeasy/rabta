# Rabta API reference

**Protocol version:** 1 · **API style:** HTTP + JSON · **Authentication:** none

This is the detailed wire reference for Rabta: every route, the event envelope format, the signing rules, and local blob storage.

New to Rabta? Start with the [README](README.md) for the one-container quick start. Open `GET /` in a browser for a self-contained status page, or call `GET /api/v1/` for a machine-readable route index.

## Contents

- [Relay model](#relay-model)
- [Conventions](#conventions)
- [Errors](#errors)
- [Cryptography and the event envelope](#cryptography-and-the-event-envelope)
- [Public routes](#public-routes)
  - [API routes showcase](#api-routes-showcase)
  - [System and observability](#system-and-observability)
    - [`GET /`](#get-)
    - [`GET /api/v1/`](#get-apiv1-)
    - [`GET /api/v1/openapi.json`](#get-apiv1openapijson)
    - [`GET /api/v1/health`](#get-apiv1health)
    - [`GET /api/v1/node`](#get-apiv1node)
  - [Events plane](#events-plane)
    - [`POST /api/v1/events`](#post-apiv1events)
    - [`GET /api/v1/events`](#get-apiv1events)
    - [`GET /api/v1/events/count`](#get-apiv1eventscount)
    - [`GET /api/v1/events/{id}`](#get-apiv1eventsid)
    - [`GET /api/v1/events/{id}/size`](#get-apiv1eventsidsize)
  - [Peer synchronization](#peer-synchronization)
    - [`POST /api/v1/sync`](#post-apiv1sync)
  - [Blob plane routes](#blob-plane-routes)
    - [`PUT /api/v1/blobs`](#put-apiv1blobs)
    - [`GET /api/v1/blobs/{hash}`](#get-apiv1blobshash)
    - [`HEAD /api/v1/blobs/{hash}`](#head-apiv1blobshash)
- [Blob plane](#blob-plane)
- [Battery](#battery)
- [Limits and runtime configuration](#limits-and-runtime-configuration)
- [Client examples](#client-examples)

## Relay model

Rabta is an event relay — signed events, a pubkey identity, and queried listing. Events are immutable with mandatory TTLs.

- **Transport:** HTTP + JSON.
- **Signatures:** Ed25519 over a canonical Rabta object.
- **Model:** opaque `data`, `collection` plus up to 10 `labels`, mandatory TTL (60 seconds to 400 days).
- **Deletion:** the owner key can hard-delete its events with a signed request.
- **Attachments:** raw uploads are stored content-addressed on the node's own disk. Lifecycle and retention: see [Blob plane](#blob-plane).

## Conventions

| Topic | Rule |
| --- | --- |
| Base URL | `http://<host>:3232` by default. All routes are on one port. |
| Request/response bodies | JSON, except raw blob uploads. |
| Timestamps | Unix seconds, integers. |
| Event IDs | 64 lowercase hex characters = SHA-256 of the canonical envelope fields. |
| Blob identity | 64 lowercase hex characters = SHA-256 of the raw body. |
| Node identity | 64 lowercase hex characters = SHA-256 of the node's raw Ed25519 public key. Sent as `X-Rabta-Node-Id` on every response. Identification only, not an authorization key. |
| Hex input | Accepted case-insensitively; responses and stored IDs are lowercase. |
| Authentication | None (no accounts). |
| CORS | Permissive (`Access-Control-Allow-Origin: *`, all methods/headers). |
| Versioning | All API routes live under `/api/v1`; `/` alone is the HTML status page. |

Because there are no accounts, anyone who can reach the node can publish events and upload blobs under a key they control. The `owner` field is a cryptographic identity, not a gate on who may write. Deleting an event is different: it requires a signature from that event's owner key. Put the node behind TLS and an authenticating reverse proxy if it is exposed to the internet.

## Errors

Every handled failure returns the same JSON shape:

```json
{
  "error": "human-readable message",
  "code": "machine_readable_code"
}
```

The HTTP status and `code` identify the class of failure:

| `code` | Status | Meaning |
| --- | --- | --- |
| `bad_json` | 400 | Malformed JSON, missing/invalid body shape, or a bad cursor. |
| `bad_sig` | 401 | Missing/invalid `id`, `sig`, or `owner`; digest mismatch; signature verification failed. |
| `bad_collection` | 400 | `collection` does not match `^[a-z0-9/_-]{1,32}$`. |
| `bad_label` | 400 | Invalid envelope label, or empty/duplicate label filter. |
| `bad_blobs` | 400 | `blobs` is missing or is not an array of 0–8 unique 64-char lowercase hex hashes. |
| `bad_owner` | 400 | `owner` is not `ed25519:<64 hex>`. |
| `ttl_range` | 400 | Timestamp or TTL outside the allowed window. |
| `too_large` | 413 | Event body exceeds 100,000 bytes, query body exceeds 8,192 bytes, or a blob exceeds 0.1% of `STORAGE`. |
| `empty_body` | 400 | Blob upload body is empty. |
| `blob_not_encrypted` | 400 | Body is not a `RABTA1` client-encrypted container (bad magic/version, too short, or low-entropy payload). Nothing was stored. |
| `bad_body` | 400 | The blob upload stream failed partway through the body. |
| `at_watermark` | 507 | Storage admission watermark reached, or an unclaimed blob cannot fit the unclaimed cap; write refused. |
| `disk_full` | 507 | Free space is below the safety floor. |
| `busy` | 429 | Upload slots or temp-file budget are exhausted; retry shortly. |
| `battery_empty` | 429 | The node's battery is below the floor for this write: read-only locally, or sync-disabled for peer traffic. `Retry-After` gives the regen wait. |
| `timeout` | 408 | Upload body stalled between chunks. |
| `not_found` | 404 | Unknown, expired, or malformed resource ID. |
| `internal` | 500 | Storage or filesystem failure. |

## Cryptography and the event envelope

### The short version

1. Clients own encryption and signing.
2. The node verifies **Ed25519** signatures and stores the envelope opaquely.
3. Event identity is a **SHA-256** hash; blob identity is the **SHA-256 of the raw bytes**.
4. The signed digest is computed over **canonical JSON** with sorted keys and compact separators.
5. Clients may encrypt `data` and blob bytes before upload. The server never needs plaintext.

> **Rabta event envelope.** The signature is Ed25519 over the canonical object below. See [Relay model](#relay-model).

### What the server can see

Rabta is zero-knowledge in the practical sense: it has no accounts, no application schema, and never decrypts payloads. It does see envelope metadata — public key, collection, labels, timestamps, sizes, blob-reference hashes, and access timing. It also stores blob bytes on its own disk, under a content hash. Encrypt client-side when that metadata matters.

The server does **not**:

- generate or hold user keys;
- encrypt or decrypt `data` or blobs;
- sign events on behalf of clients;
- restrict who may publish or read; deletion is the only operation checked against an existing owner.

Deletion is authorized by the owner key's signature over the target list. Authenticity comes from the client signature. Confidentiality, if you need it, comes from client-side encryption of `data` and blob bodies.

### Envelope fields

A complete example with a computed digest and signature is in the [Worked example](#worked-example).

| Field | Required | Type | Rules |
| --- | --- | --- | --- |
| `collection` | yes | string | `^[a-z0-9/_-]{1,32}$`. Lowercase only. |
| `created_at` | yes | integer | Unix seconds. Must not be in the server's future. |
| `expires_at` | yes | integer | Unix seconds. Must be in the future and no more than 400 days after `created_at`. |
| `owner` | yes | string | `ed25519:` + 64 hex chars (32-byte public key). |
| `labels` | yes | array of strings | At most 10. Each matches `^[A-Za-z0-9:_\.\-\+\/]{1,128}$`. Order is preserved. |
| `blobs` | yes | array of strings | 0–8 blob hashes, each exactly 64 lowercase hex chars. Empty means none. Duplicates rejected. Order is preserved. Reference only: see [Blob references](#blob-references). |
| `data` | yes | JSON object | Opaque to the server. Any JSON object. |
| `id` | yes | string | 64 hex chars. Must equal the computed digest. |
| `sig` | yes | string | 128 hex chars. Ed25519 signature over the 32-byte digest. |

Unknown fields are accepted, ignored, and not persisted.

The stored envelope is the canonical object containing the digest fields plus lowercase `id` and `sig`. Comments, whitespace, key order, and extra fields from the upload are not preserved.

### Canonical JSON

The digest input is exactly the object:

```text
{blobs, collection, created_at, data, expires_at, labels, owner}
```

`blobs` is always present; an empty array means none. `id` and `sig` are never part of the digest input. Blobs are a separate plane: an event never uploads or embeds blob bytes.

Canonicalization rules:

- object keys sorted lexicographically, recursively;
- compact separators: `,` and `:`, no spaces;
- UTF-8 bytes;
- arrays keep their order (including `labels` and `blobs`);
- numbers must be integers in the digest fields (`created_at`, `expires_at`).

A Rust-compatible canonical encoding: the `canonical()` in the [Node.js client example](#sign-and-publish-with-nodejs) is the reference implementation.

**Number warning:** avoid floating-point numbers in `data` if clients are written in different languages. JavaScript prints `1.0` as `1`, while Rust may print `1.0`, producing different canonical bytes and a different digest. Use integers and strings for values that must round-trip exactly.

### Identity and signature

```text
canonical_bytes = canonical_json({blobs, collection, created_at, data, expires_at, labels, owner})
digest          = SHA-256(canonical_bytes)          // 32 bytes
id              = lowercase_hex(digest)             // 64 chars
sig             = Ed25519_sign(owner_private_key, digest)  // 64 bytes
```

Important details:

- The signature is over the **32-byte SHA-256 digest**, not over the canonical JSON bytes directly.
- The public key is the raw 32-byte Ed25519 verifying key, hex-encoded after `ed25519:`.
- The owner string used in the digest is normalized to lowercase hex.
- `id` and `sig` are hex-encoded and stored lowercase.
- Ed25519 is deterministic: the same key and digest always produce the same signature.

Verification order inside the node: body cap → JSON shape → TTL window → canonical digest → `id` cross-check → signature verification → transactional insert.

### Blob references

`blobs` lets an event advertise the blobs it uses; `[]` means none. Each entry is a SHA-256 hash of a blob uploaded through `PUT /api/v1/blobs`. The server validates shape only — it never checks existence — and a dangling reference is valid. `blobs` is not indexed or filterable; the query endpoint has no blob filter (the server keeps an internal refs table only to calculate retention).

Retention, eviction, and the shared storage budget are covered in [Blob plane](#blob-plane). Upload the blob first, then put its hash in the event's `blobs` array.

### Worked example

Digest input, byte-for-byte:

```text
{"blobs":[],"collection":"docs/example","created_at":1793283000,"data":{"ciphertext":"base64-or-any-client-format","nonce":"..."},"expires_at":1824732600,"labels":["demo","docs"],"owner":"ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"}
```

SHA-256 of those bytes:

```text
6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5
```

Signature over that 32-byte digest with the example key:

```text
eb9d881af37ca78e3365006101c5aa06f9ce0e9390870e5ae9570262e93869c9dd38574e30f078e4156b2841f7371a2ee3fc2af4a39b06bd4fd7946e020bf904
```

Full envelope as POSTed (pretty-printed for readability; the node accepts any key order):

```json
{
  "blobs": [],
  "collection": "docs/example",
  "created_at": 1793283000,
  "expires_at": 1824732600,
  "owner": "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
  "labels": ["demo", "docs"],
  "data": {
    "ciphertext": "base64-or-any-client-format",
    "nonce": "..."
  },
  "id": "6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5",
  "sig": "eb9d881af37ca78e3365006101c5aa06f9ce0e9390870e5ae9570262e93869c9dd38574e30f078e4156b2841f7371a2ee3fc2af4a39b06bd4fd7946e020bf904"
}
```

`POST /api/v1/events` stores it with `201` (full response under the route). `GET /api/v1/events/{id}` returns the stored canonical envelope:

```text
{"blobs":[],"collection":"docs/example","created_at":1793283000,"data":{"ciphertext":"base64-or-any-client-format","nonce":"..."},"expires_at":1824732600,"id":"6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5","labels":["demo","docs"],"owner":"ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"eb9d881af37ca78e3365006101c5aa06f9ce0e9390870e5ae9570262e93869c9dd38574e30f078e4156b2841f7371a2ee3fc2af4a39b06bd4fd7946e020bf904"}
```

## Public routes

### API routes showcase

Rabta routes are organized into four functional **categories** and classified by operational **type**, data format, and caching behavior:

| Method | Endpoint | Category | Type | Request Payload | Caching & Freshness | Purpose |
|:---|:---|:---|:---|:---|:---|:---|
| `GET` | [`/`](#get-) | System & Observability | Dashboard UI | None | Uncached | Browser status dashboard (events, blobs, batteries, storage) |
| `GET` | [`/api/v1/`](#get-apiv1-) | System & Observability | Route Index | None | Dynamic JSON | Root endpoint index mapping route paths to purposes |
| `GET` | [`/api/v1/openapi.json`](#get-apiv1openapijson) | System & Observability | Specification | None | Static JSON | OpenAPI 3.1 schema specification of the public API |
| `GET` | [`/api/v1/health`](#get-apiv1health) | System & Observability | Liveness Probe | None | Uncached | Minimal health probe returning status and live entity counts |
| `GET` | [`/api/v1/node`](#get-apiv1node) | System & Observability | Unified Telemetry | None | Dynamic JSON | Unified node identity, runtime telemetry, storage budget, limits & peer sync |
| `POST` | [`/api/v1/events`](#post-apiv1events) | Events Plane | Mutation (Ingest) | `application/json` (Signed Envelope) | Uncached (State Version Bump) | Ingest and verify a cryptographically signed immutable event |
| `GET` | [`/api/v1/events`](#get-apiv1events) | Events Plane | Query (List) | Query parameters | ETag / `304 Not Modified` | Fast-path listing of live events with query filtering |
| `GET` | [`/api/v1/events/count`](#get-apiv1eventscount) | Events Plane | Aggregate (Count) | Query parameters | Strict Uncached (Fresh) | Real-time count of events matching query parameters |
| `GET` | [`/api/v1/events/{id}`](#get-apiv1eventsid) | Events Plane | Point Read | Path parameter (`{id}`) | ETag / `304 Not Modified` | Retrieve canonical signed envelope by 64-hex SHA-256 ID |
| `GET` | [`/api/v1/events/{id}/size`](#get-apiv1eventsidsize) | Events Plane | Metadata Read | Path parameter (`{id}`) | ETag / `304 Not Modified` | Envelope byte size and total footprint including claimed blobs |
| `POST` | [`/api/v1/sync`](#post-apiv1sync) | Peer Synchronization | Protocol Sync | `application/json` (Sync Request) | Uncached (Battery Policed) | Inter-relay range reconciliation and bidirectional event exchange |
| `PUT` | [`/api/v1/blobs`](#put-apiv1blobs) | Blob Plane | Mutation (Upload) | `application/octet-stream` (Container) | Uncached | Store client-encrypted binary blob container |
| `GET` | [`/api/v1/blobs/{hash}`](#get-apiv1blobshash) | Blob Plane | Point Read (Stream) | Path parameter (`{hash}`), `Range` | Strong Cache (Immutable) | Download binary blob bytes with HTTP Range support |
| `HEAD` | [`/api/v1/blobs/{hash}`](#head-apiv1blobshash) | Blob Plane | Metadata Read | Path parameter (`{hash}`) | Strong Cache (Immutable) | Inspect blob presence and content length without body transfer |

#### Route Categories

- **System & Observability**: Operational endpoints providing node identity, hardware storage usage, eviction metrics, peer health, and discovery schemas.
- **Events Plane**: Ingestion, point lookup, cached listing, flexible query search, and lightweight counting of signed events.
- **Blob Plane**: Content-addressed encrypted attachment storage with chunked streaming and HTTP Range caching.
- **Peer Synchronization**: Inter-relay synchronization protocol utilizing adaptive range reconciliation and battery hysteresis.

#### Operation Types

- **Mutation / Ingest**: Creates or alters data state. Increments the internal event state version counter, invalidating event ETag caches.
- **Query (List & Structured)**: Evaluates collection and label filters against SQLite indexes to return event envelopes.
- **Aggregate (Count)**: Computes matching record totals in SQLite without paging overhead or payload transfer.
- **Point Read**: O(1) single-item retrieval by hash or identifier with ETag caching.
- **Metadata / Specification**: Self-describing schema definitions or route directories.
- **Protocol Sync**: Bidirectional multi-operation sync cycle policed by battery budgets.

---

### System and observability

#### `GET /`

Serves only a self-contained HTML status page (no CDN, no fonts, no external assets) centred on the viewport. The page polls `/api/v1/node` every 5 seconds and shows live events, live blobs, per-node sync batteries, store usage, and version. The machine-readable route index is at `GET /api/v1/` (both `/api/v1` and `/api/v1/` work).

#### `GET /api/v1/`

JSON route index. Includes the service version, API version, base path, description, and a map of route → purpose.

```json
{
  "service": "rabta",
  "version": "0.0.1",
  "api_version": "v1",
  "base_path": "/api/v1",
  "description": "signed-event relay with local content-addressed blobs",
  "node_id": "<64 hex>",
  "public_key": "ed25519:<64 hex>",
  "routes": {
    "GET /api/v1/health": "liveness probe",
    "GET /api/v1/node": "node identity, runtime telemetry, storage, and peer health",
    "GET /api/v1/openapi.json": "OpenAPI 3.1 description of this API",
    "POST /api/v1/events": "publish a signed envelope (application/json)",
    "GET /api/v1/events": "list live events (query params, ETag / If-None-Match caching)",
    "GET /api/v1/events/count": "count live events matching query parameters",
    "POST /api/v1/sync": "server-to-server peer sync",
    "GET /api/v1/events/{id}": "fetch one (ETag / If-None-Match)",
    "GET /api/v1/events/{id}/size": "envelope size + attached blob bytes",
    "PUT /api/v1/blobs": "raw blob upload; identity is the sha256 of the body",
    "GET /api/v1/blobs/{hash}": "download a blob (Range / ETag)",
    "HEAD /api/v1/blobs/{hash}": "blob metadata"
  }
}
```

#### `GET /api/v1/openapi.json`

OpenAPI 3.1 document describing every public route, parameter, request body, and response schema. Paths are built from the same route constants as the router, so the document cannot drift from the served endpoints. The `servers` entry is `/api/v1`, and paths inside the document are relative to that prefix.

```bash
curl -s http://localhost:3232/api/v1/openapi.json | jq '.paths | keys'
```

#### `GET /api/v1/health`

Liveness probe.

```json
{"status":"ok","node_id":"<64 hex>","live_events":6,"live_blobs":3}
```

`live_events` and `live_blobs` count rows currently marked live. Expired rows disappear from reads immediately, but the counts include them until the next reaper sweep (every 5 minutes).

#### `GET /api/v1/node`

Unified endpoint for node identity, runtime telemetry, storage, and peer health. Combines identity parameters with real-time operational state so clients and dashboards can observe the entire node in a single request.

```json
{
  "node_id": "<64 hex>",
  "public_key": "ed25519:<64 hex>",
  "algorithm": "ed25519",
  "source": "generated",
  "sync": ["https://peer.example.com"],
  "donate": null,
  "started_at": 1794065600,
  "uptime_s": 42,
  "version": "0.0.1",
  "api_version": "v1",
  "events": {"live": 6, "bytes": 2185},
  "limits": {
    "min_ttl_s": 60,
    "max_ttl_s": 25920000,
    "battery": {
      "event_cost": 1,
      "blob_cost": 100,
      "push_multiplier": 10,
      "sync_floor": 75000,
      "read_only_floor": 100
    }
  },
  "blobs": {
    "enabled": true,
    "live": 3,
    "bytes": 4194304,
    "claimed_bytes": 1048576,
    "unclaimed": 2,
    "unclaimed_bytes": 3145728,
    "unclaimed_limit_bytes": 2147483648,
    "unclaimed_max_blobs": 100,
    "max_single_bytes": 21474836
  },
  "storage": {
    "budget_bytes": 21474836480,
    "target_bytes": 18253611008,
    "used_bytes": 1050761,
    "store_bytes": 21474836480,
    "configured_bytes": 21474836480,
    "clamped_to_free": false,
    "free_bytes": 457677926400,
    "data_dir": "/data",
    "policy_rules": 0,
    "policy_event_bytes": 0,
    "policy_blob_bytes": 0
  },
  "reaper": {
    "interval_s": 300,
    "last_sweep_at": 1793283600,
    "last_sweep_age_s": 12
  },
  "eviction": {
    "events_evicted": 0,
    "blobs_evicted": 0,
    "bytes_reclaimed": 0,
    "unclaimed_blobs_evicted": 0,
    "unclaimed_bytes_reclaimed": 0,
    "candidates": {
      "events": 6,
      "envelope_bytes": 2185,
      "blob_bytes": 1048576,
      "reclaimable_bytes": 1050761,
      "largest_bytes": 1048596
    }
  },
  "upload": {
    "inflight_bytes": 0,
    "max_single_bytes": 21474836
  },
  "peers": {
    "battery": {
      "remaining": 1000000.0,
      "max": 1000000.0,
      "regen_per_sec": 30.0,
      "mode": "readwrite"
    },
    "items": [
      {
        "url": "https://peer.example.com",
        "last_success_at": 1793283595,
        "last_error": null,
        "last_error_at": null,
        "next_poll_at": 1793283615,
        "battery": {
          "remaining": 980000.0,
          "max": 1000000.0,
          "updated_at": 1793283595
        }
      }
    ]
  }
}
```

- The node always generates a fresh ephemeral keypair at boot. `source` is always `generated`, and `node_id` changes on every restart.
- `donate` is the operator's optional on-chain donation address from `BITCOIN` (`null` when unset). Display-only: never part of events or signatures.
- `sync` lists configured peer node URLs in configured order.
- Telemetry blocks (`events`, `blobs`, `storage`, `reaper`, `eviction`, `upload`, `peers`) report live database and peer metrics.

The `storage` block is the one to read when a write is refused:

| Field | Meaning |
| --- | --- |
| `budget_bytes` | The effective budget itself: the admission line and the configured number are the same value. |
| `target_bytes` | Post-eviction target: 85% of the effective budget. |
| `used_bytes` | Charged bytes: live envelopes plus blobs claimed by a live event. |
| `store_bytes` | Effective budget after the boot-time free-disk clamp. |
| `configured_bytes` | Budget as configured, before the clamp. |
| `clamped_to_free` | Whether the boot-time clamp changed the budget. |
| `free_bytes` | Free space on the data volume at the time of the call. |
| `data_dir` | Data directory in use. |
| `policy_rules` | Number of configured `POLICY` rules. |
| `policy_event_bytes` | Charged bytes of live envelopes matching a policy rule. |
| `policy_blob_bytes` | Size of live blobs claimed by at least one policy-matching event, counted once. |

`eviction` counts cover the life of the process. `unclaimed_blobs_evicted` and `unclaimed_bytes_reclaimed` count only cap evictions, separate from TTL expiry and pressure eviction. `eviction.candidates` is a live snapshot: the events pressure eviction could delete right now (policy-exempt records excluded), the envelope plus sole-claimed blob bytes they hold, and the footprint of the single largest candidate. It is computed on each `/api/v1/node` call, not accumulated. `upload.inflight_bytes` is the temp-file reservation currently held by active uploads. `reaper.last_sweep_at` and `last_sweep_age_s` are `null` until the first sweep completes. The `limits` block reports the enforced event TTL window (`min_ttl_s`, `max_ttl_s`) and the battery price model — see [Battery](#battery); clients should read them instead of assuming bounds. `peers.battery.mode` is the enforced tier: `readwrite`, `sync_disabled`, or `read_only`. Each `peers.items[]` entry carries the battery that peer reported in its most recent sync response; `battery` is `null` until the first successful sync.

---

### Events plane

#### `POST /api/v1/events`

Publish one signed envelope.

```bash
curl -X POST http://localhost:3232/api/v1/events \
  -H 'content-type: application/json' \
  --data-binary @event.json
```

**Request**

- Body: one envelope JSON object, at most **100,000 bytes**.
- `Content-Type` is not enforced, but send `application/json`.

**Response**

- `201 Created` when the event is new:

  ```json
  {"status":"stored","id":"6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5"}
  ```

- `200 OK` when the same `id` is already stored:

  ```json
  {"status":"duplicate","id":"6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5"}
  ```

Duplicate deliveries are idempotent. Blobs are uploaded separately and referenced through `blobs` — see [Blob references](#blob-references).

Each newly stored event consumes 1 battery unit; a read-only node refuses with `429 battery_empty` (see [Battery](#battery)). Duplicates are free.

#### `GET /api/v1/events`

List live, unexpired events using standard URL query parameters, with full HTTP conditional caching (`ETag` and `If-None-Match`). Polling clients that send `If-None-Match` receive `304 Not Modified` without transferring duplicate data.

**Query Parameters**

| Parameter | Meaning |
| --- | --- |
| `collection` | Exact collection match. |
| `collection_glob` | Wildcard collection match (`*` zero or more chars, `?` one char). Mutually exclusive with `collection`. |
| `labels` | Comma-separated labels (e.g. `urgent,team`). All supplied labels must be present on the event (AND). |
| `owner` | `ed25519:<64 hex>` only. |
| `limit` | Page size, `1..100`. Default `20`. |
| `cursor` | Opaque pagination cursor from `next_cursor`. |
| `since` | Half-open lower bound on `created_at` in unix seconds (inclusive). |
| `until` | Half-open upper bound on `created_at` in unix seconds (exclusive). |
| `expires_since` | Half-open lower bound on `expires_at` in unix seconds (inclusive). |
| `expires_until` | Half-open upper bound on `expires_at` in unix seconds (exclusive). |

Unknown parameters are rejected with `400 bad_json` to avoid silent filter omissions.

**ETag and Conditional Caching (`304 Not Modified`)**

Every response includes:
- `ETag: "v<version>-<qhash>-<min_exp>-<chash>"`
- `Cache-Control: public, no-cache`

On subsequent polls, clients send `If-None-Match: <etag>`.
- **Fast Path:** If the node's monotonic version counter has not changed and no returned event has reached its `expires_at`, the server returns `304 Not Modified` with an empty body **immediately** — performing zero SQLite reads and zero memory allocations.
- **Normal Path:** If the version has bumped (e.g. events inserted or deleted elsewhere), the database query executes; if the query result and minimum expiry still match the client's cached content, `304 Not Modified` is returned.
- If data has changed, `200 OK` is returned with the new JSON page and updated `ETag`.

```bash
# List events with query parameters
curl -i "http://localhost:3232/api/v1/events?collection=chat/room-42&limit=20"

# Subsequent conditional poll (returns HTTP 304 if unchanged)
curl -i "http://localhost:3232/api/v1/events?collection=chat/room-42&limit=20" \
  -H 'If-None-Match: "v1-0000000000001234-000000006ae34800-000000000000abcd"'
```

**Response**

```json
{
  "count": 2,
  "events": [
    {
      "blobs": [],
      "collection": "chat/room-42",
      "created_at": 1793283000,
      "data": {"ciphertext": "..."},
      "expires_at": 1824732600,
      "id": "6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5",
      "labels": ["demo", "docs"],
      "owner": "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
      "sig": "eb9d881a..."
    }
  ],
  "next_cursor": "AAAAAGrjU7iHct-oZmR5c1u2Rf7wWDJ_YsEjeJkftl8wntHQkpuCSg"
}
```

- Results are ordered by `created_at DESC, id DESC`.
- `next_cursor` is `null` when fewer than `limit` rows were returned; otherwise it is a base64url-encoded opaque cursor for the next page.
- Expired events and events being evicted are never returned.
- Empty or duplicate `labels` filters return `400 bad_label`.
- A non-canonical `owner` returns `400 bad_owner`.
- `collection` and `collection_glob` together return `400 bad_json`.
- **Wildcards:** `collection_glob` allows the collection charset (`a-z 0-9 / _ -`) plus `*` (zero or more characters) and `?` (exactly one), at most 64 characters; empty patterns and `[...]` character classes are rejected with `400 bad_json`. Patterns anchored at the start (`chat/*`, `chat/room-4?`) are answered through an index range; patterns that open with a metacharacter (`*/status`) scan live rows.

#### `GET /api/v1/events/count`

Count live, unexpired events matching query parameters, without fetching full envelopes. Always executes a fresh database count with zero caching, returning `{"count": <number>}`. Ideal for status badges, dashboards, and monitoring probes.

**Query Parameters**

| Parameter | Meaning |
| --- | --- |
| `collection` | Exact collection match. |
| `collection_glob` | Wildcard collection match (`*` zero or more chars, `?` one char). Mutually exclusive with `collection`. |
| `labels` | Comma-separated labels (e.g. `urgent,team`). All supplied labels must be present on the event (AND). |
| `owner` | `ed25519:<64 hex>` only. |
| `since` | Half-open lower bound on `created_at` in unix seconds (inclusive). |
| `until` | Half-open upper bound on `created_at` in unix seconds (exclusive). |
| `expires_since` | Half-open lower bound on `expires_at` in unix seconds (inclusive). |
| `expires_until` | Half-open upper bound on `expires_at` in unix seconds (exclusive). |

Unknown parameters are rejected with `400 bad_json`.

```bash
# Count events in a collection
curl "http://localhost:3232/api/v1/events/count?collection=chat/room-42"

# Count a whole namespace subtree with a wildcard
curl "http://localhost:3232/api/v1/events/count?collection_glob=chat/*"

# Response:
# {"count": 42}
```

- Only live, unexpired events count — matching the same liveness rules as `/events`.
- Time ranges are half-open `[since, until)` and `[expires_since, expires_until)`.

#### `GET /api/v1/events/{id}`

Fetch one stored envelope by event ID.

```bash
curl -i http://localhost:3232/api/v1/events/6084fc0692f37f8d952b1012921f2d70d9960f5da20436742529c022647811e5
```

- `200` with `Content-Type: application/json`.
- `ETag: "<id>"`.
- `If-None-Match: "<id>"`, the bare ID, or `*` returns `304 Not Modified`.
- Invalid, unknown, or expired IDs return `404 not_found`.
- The body is the exact stored canonical envelope, not the original upload bytes.

#### `GET /api/v1/events/{id}/size`

Return the stored envelope size and the true size including its attached blobs.

```json
{
  "id": "2f134cda189a7ba816061f1c1bf3975ff6e5d7cbb3c86d2b5a60a7518904079f",
  "envelope_size": 398,
  "total_size": 12582952
}
```

- `envelope_size` is the stored canonical envelope in bytes.
- `total_size` is `envelope_size` plus the sizes of the live blob rows named in `blobs`.
- Dangling references, expired blobs, and repeated hashes add nothing.
- Missing/expired events return `404 not_found`.

---

### Peer synchronization

#### `POST /api/v1/sync`

Server-to-server peer sync. Authenticated with Ed25519 node signatures, carrying push and pull together in a single request-response cycle.

```bash
curl -X POST http://localhost:3232/api/v1/sync \
  -H 'X-Rabta-Node: ed25519:<public-key>' \
  -H 'X-Rabta-Timestamp: 1793283000' \
  -H 'X-Rabta-Nonce: <base64url>' \
  -H 'X-Rabta-Signature: <base64url>' \
  -H 'Content-Type: application/json' \
  -d @sync_request.json
```

- Enforces the node battery on peer traffic; a node below the sync floor refuses the whole request with `429 battery_empty` and a `Retry-After` — the pricing model and tiers are in [Battery](#battery).
- Includes in-memory ring-buffer duplicate filtering (64,000 entries) to protect the SQLite writer.
- Adaptive Range-Based Set Reconciliation: verifies root and time-range summaries to resolve diffs and repull missing/deleted events in a single round trip.

---

### Blob plane routes

#### `PUT /api/v1/blobs`

Upload one client-encrypted blob container. The relay never learns a key and cannot decrypt what it stores.

```bash
curl -X PUT http://localhost:3232/api/v1/blobs \
  --data-binary @blob.rabta1
```

**Wire format** — the only shape the relay accepts; anything else is `400 blob_not_encrypted`:

```
"RABTA1" | ver(1)=1 | salt(16) | ciphertext(min 25 B) | tag(16)      min total 64 B
```

- The client encrypts end-to-end with an AEAD under a key it distributes out-of-band; `salt` is the KDF input, `tag` the authentication tag. The relay validates shape (magic, version, minimum length, payload entropy) and cannot verify the tag — that is the recipient's job with the key.
- The hash address is SHA-256 over the wrapped bytes, so dedup, Range/ETag and expiry behave exactly as before.

**Request**

- Body: one container, at most **0.1% of `STORAGE`** (`413 too_large` if exceeded; a `Content-Length` already over the cap is rejected before reading).
- A plaintext body is cut off at the first bytes (magic check) rather than after the upload. The body is streamed to a temp file while SHA-256 is computed; nothing is buffered in memory.
- The admission checks around the upload — combined watermark, unclaimed cap, disk floor, battery — follow the rules in [Blob plane](#blob-plane) and [Battery](#battery); the possible codes are in [Errors](#errors).

**Response** — `201 Created` for new bytes (with `Location: /api/v1/blobs/{hash}`), `200 OK` when the hash already exists:

```json
{
  "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "size": 12,
  "url": "/api/v1/blobs/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "expires_at": 1824732600
}
```

Re-uploading existing bytes is idempotent: the hash already exists, no bytes are added, access metadata is refreshed, and the response is `200 OK`. It never changes a blob's deadline — see [Blob plane](#blob-plane).

#### `GET /api/v1/blobs/{hash}`

Download a blob. `hash` is 64 hex characters; a malformed hash returns `404 not_found`.

```bash
curl -o file.bin http://localhost:3232/api/v1/blobs/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

Response headers:

| Header | Value |
| --- | --- |
| `Content-Type` | `application/octet-stream` |
| `ETag` | `"<hash>"` |
| `Cache-Control` | `public, max-age=3600` |
| `Accept-Ranges` | `bytes` |
| `X-Content-Type-Options` | `nosniff` |

- Supports one `Range: bytes=from-to` range with `206 Partial Content` and `Content-Range`. An unsatisfiable range falls back to the full `200`.
- `If-None-Match` with the blob's ETag returns `304 Not Modified`.
- A successful `200`, `206`, or `304` records the access (write-throttled to at most once per hour per blob).

#### `HEAD /api/v1/blobs/{hash}`

Same headers and miss behavior as `GET`, with no body. A hit records the access.

## Blob plane

Blobs are client-encrypted containers — wire format in [PUT /api/v1/blobs](#put-apiv1blobs). Blobs are stored locally:

| Event | Effect |
| --- | --- |
| `PUT /api/v1/blobs` | Validates the container shape, streams the body to a temp file, hashes it, installs it at `/data/blobs/ab/<hash>`, and returns the hash. |
| Same bytes uploaded again | Deduplicated; no new bytes; access metadata refreshed; deadline unchanged. |
| Peer download | The sync worker fetches containers peers serve and runs the same shape gate; a peer serving plaintext or zero bytes fails the download, never the store. |
| Read | Serves bytes with Range/ETag and records the access (throttled). Deadline unchanged. |
| Event deleted | The event's labels and `blob_refs` rows are removed. A blob with no remaining live reference becomes unclaimed and expires 6 hours after its original upload — a deadline that may already have passed. |
| Disk pressure | Events leave first, largest total footprint first (envelope plus blobs only that event claims), which may unclaim their blobs; then claimed blobs, down to the 85% target. Unclaimed blobs are not pressure-evicted. |
| Unclaimed cap | Unclaimed blobs share a byte cap (default 10% of `STORAGE`) and a hard cap of 100 blobs. On breach the coldest unclaimed blobs are evicted first — least recently read, ties broken by read frequency then upload time — on upload and on every reaper sweep. |
| Policy claim | A blob referenced by any live event matching a `POLICY` rule is never a pressure victim, even if an unprotected event also references it. |
| Retention | Deadlines are derived — see below. Reclaimed by the reaper. |

Blob deadlines are derived, not stored as a sliding lease: an unclaimed blob expires 6 hours after its first upload; a blob named in one or more live events expires when the latest of those events expires, so multiple claimants resolve to the longest-lived one. Reads, HEADs, and re-uploads never change the deadline. The unclaimed window is short on purpose — upload and the claiming event normally happen in one online session.

`STORAGE` is a single byte budget: the admission line is the budget itself — the configured number is what the panel shows and where `507 at_watermark` begins — and the eviction target is 85% of it. It counts event envelopes plus blobs claimed by a live event; unclaimed blobs sit outside it, capped at 10% of the budget and at most 100 blobs.

Eviction removes events one at a time, largest total footprint first — the envelope plus any blobs only that event claims — until charged usage is at or below the 85% target. A blob shared with another live event counts for neither claimant, because deleting one of them frees no charged bytes. Ties go to the older event, then the lower id.

Policy rules change only the pressure path: policy-matching events and the blobs their live events claim are skipped by eviction, while the TTL sweep still deletes them at `expires_at`. If policy data alone exceeds the admission watermark, new writes are refused with `507 at_watermark`, and `/api/v1/node` shows the policy totals under `storage`.

## Battery

Every write — local or synced — is priced against one battery and admitted at the core submission point. The battery bounds ingest **rate**; `STORAGE` bounds **capacity**; TTL bounds **time**. The three axes are independent: evicted or expired data is never refunded, and a full disk refuses writes even at a full battery.

| Property | Value |
| --- | --- |
| Tank | 1,000,000 units, hardcoded |
| Regeneration | `REGEN` (random 20–40 per second if unset), lazy, capped at the tank |
| Event price | 1 unit — local submit and pull alike |
| Blob price | 100 units — local upload and pull download alike |
| Push surcharge | ×10 on pushed events, multiplied further by the sending peer's penalty |
| Duplicates | Free — bytes already stored charge nothing |

Prices are exposed in `GET /api/v1/node` under `limits.battery` so clients never hardcode them.

### Tiers

The battery has three tiers. Degrading is instant on crossing a floor; recovering waits until the battery climbs 1,000 units back above it, so a node at the boundary does not flap.

| Tier | When | Effect |
| --- | --- | --- |
| `readwrite` | battery ≥ 750,000 (three quarters of the tank) | Everything is admitted. |
| `sync_disabled` | battery < 750,000 | Sync is disabled in both directions: inbound requests are refused with `429 battery_empty` and the node stops polling peers — no push, no pull, no blob transfers. Local writes and local reads keep working. Peers back off and re-offer; nothing is lost. |
| `read_only` | battery < 100 | Every write is refused with `429 battery_empty` + `Retry-After`. Reads, the reaper, and regeneration continue. |

Below the sync floor, local writes win over replication by construction: only local submissions can drain the tank under 750,000, and they keep working down to the read-only floor. A bootstrapping node that pulls a large history therefore self-paces at its regeneration rate instead of exhausting itself on arrival.

## Limits and runtime configuration

### Hard limits

| Limit | Value |
| --- | --- |
| Event envelope | 100,000 bytes |
| Event TTL | > 60 seconds and ≤ 400 days |
| Labels per event | 10 |
| Public event list page | 1–100 (default 20) |
| Single blob | 0.1% of effective `STORAGE` |
| Unclaimed blobs | 10% of effective `STORAGE` and at most 100 blobs; coldest evicted first. |
| Concurrent blob uploads | 8 |
| Upload stall timeout | 30 seconds between chunks |
| Blob retention | Unclaimed: 6 hours from upload; claimed: latest referencing event expiry — see [Blob plane](#blob-plane). |
| Reaper interval | 300 seconds |
| Battery | Tank, prices, and tiers — see [Battery](#battery); regen is set by `REGEN` (per second). |
| Policy rules | Up to 16 in `POLICY` — see [Environment variables](#environment-variables); exempt from pressure eviction, still TTL-expired. |

### Environment variables

Set variables in the process environment or in `/data/config.env` as `KEY=VALUE` lines. The process environment wins. Invalid values refuse to boot rather than silently falling back.

The Dockerfile bakes `STORAGE=20GB` and `RUST_LOG=info` as image defaults; override them with `-e` or in `/data/config.env`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3232` | HTTP port. |
| `DATA` | `/data` | SQLite database and blob directory. |
| `STORAGE` | `20GB` | Hard byte ceiling on events plus claimed blobs, shown verbatim in the panel. Must be greater than 0; the unclaimed cap and eviction target are described in [Blob plane](#blob-plane). |
| `POLICY` | empty | Single-line JSON `{"rules":[...]}` (grammar below). Policy-matching records are exempt from pressure eviction — see [Blob plane](#blob-plane). |
| `SYNC` | empty | Comma-separated base URLs of up to 4 other Rabta nodes, exposed at `GET /api/v1/node`. |
| `REGEN` | Random `20`–`40` | Battery units regenerated per second (random 20–40 if unset); the tank is hardcoded at `1000000` — see [Battery](#battery). |
| `BITCOIN` | empty | Optional operator donation address, exposed at `GET /api/v1/node` and rendered on the status page. Validated at boot; malformed values refuse startup. |
| `RUST_LOG` | `info` | Log filter, for example `debug` or `rabta=debug`. |

`POLICY` value shape:

```json
{"rules": [
  {"owner": ["ed25519:..."], "collection": ["notes"], "labels": ["keep"]},
  {"collection": ["archive/*"]}
]}
```

Fields are optional; an omitted field (or a literal `*` entry) matches anything. Within a rule the listed fields are AND'ed, and the patterns inside a field OR'ed (a collection is matched by any pattern, an event matches policy when any of its labels matches any listed pattern). Rules themselves OR: matching one is enough. Patterns use one wildcard, `*`, matching any characters; `notes*` keeps every collection starting with `notes`. Matching is case-sensitive. Limits: at most 16 rules, 32 values per field, 256 bytes per pattern. The values must be single-line in every channel (env var and `config.env` alike). Invalid JSON, unknown fields, malformed keys, or exceeding a limit all refuse boot; the node never silently pins a partial list.

Sizes accept `20GB`, `512MiB`, `52428800`, and similar. Derived values — the 10% unclaimed cap and its 100-blob count cap, the 85% eviction target, eviction order, the per-blob cap (0.1% of the budget, always inside the unclaimed cap), and policy behavior — are described in [Blob plane](#blob-plane). If `STORAGE` exceeds 90% of free disk at boot, it is clamped to 90%. `STORAGE=0` refuses to boot.

## Client examples

### Sign and publish with Node.js

```js
import { createHash, generateKeyPairSync, sign } from 'node:crypto';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const owner = `ed25519:${rawPublicKey.toString('hex')}`;

const now = Math.floor(Date.now() / 1000);
const fields = {
  collection: 'chat/room-42',
  created_at: now,
  expires_at: now + 24 * 60 * 60,
  owner,
  labels: ['team'],
  data: { ciphertext: '<client-encrypted payload>' },
};

const digest = createHash('sha256').update(canonical(fields)).digest();
const envelope = {
  ...fields,
  id: digest.toString('hex'),
  sig: sign(null, digest, privateKey).toString('hex'),
};

const response = await fetch('http://localhost:3232/api/v1/events', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(envelope),
});
console.log(await response.json());
```

### Upload an encrypted blob with Python

The reference scheme below is AES-256-GCM with the key and nonce derived from one per-blob secret via HKDF-SHA256 — the wire format it must produce is defined in [PUT /api/v1/blobs](#put-apiv1blobs). Any AEAD works as long as the container shape is kept. Send `secret` to recipients out-of-band — it is not stored anywhere on the relay.

```python
import os, json, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

BASE = "http://localhost:3232"

def blob_key_material(secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
    km = HKDF(algorithm=hashes.SHA256(), length=44, salt=salt,
              info=b"rabta/blob/v1").derive(secret)
    return km[:32], km[32:]          # (key, nonce)

def seal(plaintext: bytes, secret: bytes) -> bytes:
    salt = os.urandom(16)
    key, nonce = blob_key_material(secret, salt)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)   # ciphertext || 16B tag
    return b"RABTA1" + bytes([1]) + salt + ct_tag

def open_container(container: bytes, secret: bytes) -> bytes:
    assert container[:7] == b"RABTA1\x01"
    salt = container[7:23]
    key, nonce = blob_key_material(secret, salt)
    return AESGCM(key).decrypt(nonce, container[23:], None)

secret = os.urandom(32)                              # distribute out-of-band
container = seal(b"an image or video, encrypted before upload", secret)

req = urllib.request.Request(f"{BASE}/api/v1/blobs", data=container,
                             method="PUT", headers={"content-type": "application/octet-stream"})
blob = json.load(urllib.request.urlopen(req))
print(blob)                                          # {"hash": "...", "url": "..."}

raw = urllib.request.urlopen(f"{BASE}{blob['url']}").read()
assert open_container(raw, secret).startswith(b"an image")
```

Uploading bytes without the container is refused: `400 blob_not_encrypted`.

```bash
curl -X PUT --data-binary @file.bin "http://localhost:3232/api/v1/blobs"
# {"code":"blob_not_encrypted","error":"...the relay stores client-encrypted blobs only"}
```

### Upload an encrypted blob with Node.js

Same scheme, same container:

```js
import { webcrypto as crypto } from 'node:crypto';

const BASE = 'http://localhost:3232';
const MAGIC = Buffer.from('RABTA1', 'ascii');

async function blobKeyMaterial(secret, salt) {
  // HKDF-SHA256(ikm=secret, salt=salt, info) -> 44 bytes: key(32) + nonce(12).
  const km = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: Buffer.from('rabta/blob/v1') }, km, 352);
  const b = Buffer.from(bits);
  return [b.subarray(0, 32), b.subarray(32)];
}

async function seal(plaintext, secret) {
  const salt = crypto.getRandomValues(Buffer.alloc(16));
  const [key, nonce] = await blobKeyMaterial(secret, salt);
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const ctTag = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, k, plaintext);
  return Buffer.concat([MAGIC, Buffer.from([1]), salt, Buffer.from(ctTag)]);
}

async function open(container, secret) {
  const [key, nonce] = await blobKeyMaterial(
    Buffer.from(secret), container.subarray(7, 23));
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, k,
    container.subarray(23));
}

const secret = crypto.getRandomValues(Buffer.alloc(32));  // distribute out-of-band
const container = await seal(Buffer.from('an image or video, encrypted before upload'), secret);

const res = await fetch(`${BASE}/api/v1/blobs`, { method: 'PUT', body: container });
const blob = await res.json();                        // { hash, url, ... }
console.log(blob);

const raw = Buffer.from(
  await fetch(`${BASE}${blob.url}`).then((r) => r.arrayBuffer()));
console.log(Buffer.from(await open(raw, secret)).toString().startsWith('an image')); // true
```

In a browser the same `seal` works with `window.crypto.subtle`; render after decrypting (the relay serves `application/octet-stream` with `nosniff`, so blobs download or render client-side — never inline).

### List and fetch

```bash
# List the newest 20 events in a collection.
curl "http://localhost:3232/api/v1/events?collection=chat/room-42&limit=20"

# Fetch one event by ID.
curl http://localhost:3232/api/v1/events/<64-hex-id>

# Check the stored envelope size.
curl http://localhost:3232/api/v1/events/<64-hex-id>/size
```

---

Rabta is under active development. The public API is intentionally small. If a wire detail here disagrees with the code, the code in `src/api/` is authoritative.
