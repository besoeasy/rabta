# Rabta API reference

**Protocol version:** 1 · **API style:** HTTP + JSON + SSE · **Authentication:** none

This is the detailed wire reference for Rabta: every route, the event envelope format, the signing rules, the blob model, and the peer sync protocol.

New to Rabta? Start with the [README](README.md) for the one-container quick start. For a machine-readable route index, call `GET /` on a running node.

## Contents

- [Conventions](#conventions)
- [Errors](#errors)
- [Cryptography and the event envelope](#cryptography-and-the-event-envelope)
- [Public routes](#public-routes)
  - [`GET /`](#get-)
  - [`GET /healthz`](#get-healthz)
  - [`GET /stats`](#get-stats)
  - [`POST /events`](#post-events)
  - [`GET /events`](#get-events)
  - [`GET /events/{id}`](#get-eventsid)
  - [`GET /events/{id}/size`](#get-eventsidsize)
  - [`GET /events/stream`](#get-eventsstream)
  - [`PUT /blobs/{name}.blob|bin`](#put-blobsnameblobbin)
  - [`GET /blobs/{hash}`](#get-blobshash)
  - [`HEAD /blobs/{hash}`](#head-blobshash)
- [Blob lifecycle](#blob-lifecycle)
- [Sync protocol v1](#sync-protocol-v1)
  - [Peer configuration and behavior](#peer-configuration-and-behavior)
  - [`POST /sync/reconcile`](#post-syncreconcile)
  - [`POST /sync/events`](#post-syncevents)
  - [`POST /sync/events/fetch`](#post-synceventsfetch)
  - [`GET /sync/events`](#get-syncevents)
  - [`GET /sync/events/{id}`](#get-synceventsid)
  - [`POST /sync/blobs`](#post-syncblobs)
  - [`GET /sync/blobs/{hash}`](#get-syncblobshash)
- [Limits and runtime configuration](#limits-and-runtime-configuration)
- [Client examples](#client-examples)

## Conventions

| Topic | Rule |
| --- | --- |
| Base URL | `http://<host>:3232` by default. All routes are on one port. |
| Request/response bodies | JSON, except raw blob upload/download and the SSE stream. |
| Timestamps | Unix seconds, integers. |
| Event IDs | 64 lowercase hex characters = SHA-256 of the canonical envelope fields. |
| Blob hashes | 64 lowercase hex characters = SHA-256 of the raw body bytes. |
| Hex input | Accepted case-insensitively; responses and stored IDs are lowercase. |
| Authentication | None. Every route is unauthenticated. |
| CORS | Permissive (`Access-Control-Allow-Origin: *`, all methods/headers). |
| Versioning | No URL version prefix. The peer sync protocol carries `"v": 1`. |
| HTML | None. A UI is a separate static app that calls the node. |

Because there is no authentication, anyone who can reach the node can publish events and upload blobs. The `owner` field is a cryptographic identity, not an access-control check. Put the node behind TLS and an authenticating reverse proxy if it is exposed to the internet, and keep sync traffic on a private network.

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
| `bad_json` | 400 | Malformed JSON, missing/invalid body shape, bad cursor, or a rejected sync request. |
| `bad_sig` | 401 | Missing/invalid `id`, `sig`, or `owner`; digest mismatch; signature verification failed. |
| `bad_collection` | 400 | `collection` does not match `^[a-z0-9/_-]{1,32}$`. |
| `bad_label` | 400 | Invalid envelope label, or empty/duplicate label filter. |
| `bad_owner` | 400 | `owner` filter is not `ed25519:<64 hex>`. |
| `ttl_range` | 400 | Timestamp or TTL outside the allowed window. |
| `too_large` | 413 | Body or batch exceeds a cap. |
| `bad_extension` | 400 | Public blob upload filename is not `*.blob` or `*.bin`. |
| `bad_blob` | 400 | Envelope `blob` is not exactly one 64-hex SHA-256. |
| `at_watermark` | 503 | Storage is at the admission watermark; upload refused. |
| `busy` | 503 | Too many concurrent uploads or the temp-file budget is exhausted; retry shortly. |
| `disk_full` | 507 | Free disk space is below the safety floor; upload refused. |
| `timeout` | 408 | Upload body stalled between chunks; upload aborted. |
| `subscriber_cap` | 503 | SSE subscriber limit reached. |
| `not_found` | 404 | Unknown, expired, or malformed resource ID. |
| `internal` | 500 | Storage or filesystem failure. |

Sync request validation failures (wrong version, bad kind, bad prefix, too many ranges, invalid leaf) are reported as `400` with code `bad_json`.

## Cryptography and the event envelope

### The short version

1. Clients own encryption and signing.
2. The node verifies **Ed25519** signatures and stores the envelope opaquely.
3. Event identity and blob identity are **SHA-256** hashes.
4. The signed digest is computed over **canonical JSON** with sorted keys and compact separators.
5. Clients may encrypt `data` and blob bytes before upload. The server never needs plaintext.

### What the server can see

Rabta is zero-knowledge in the practical sense: it has no accounts, no application schema, and never decrypts payloads. It does see envelope metadata — public key, collection, labels, timestamps, sizes, blob hashes, and access timing. Encrypt client-side when that metadata matters.

The server does **not**:

- generate or hold user keys;
- encrypt or decrypt `data` or blobs;
- sign events on behalf of clients;
- enforce per-owner read/write permissions.

Authenticity comes from the client signature. Confidentiality, if you need it, comes from client-side encryption of `data` and blob bodies.

### Envelope fields

```json
{
  "collection": "chat/room-42",
  "created_at": 1793283000,
  "expires_at": 1824732600,
  "owner": "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
  "labels": ["demo", "docs"],
  "data": {
    "ciphertext": "base64-or-any-client-format",
    "nonce": "..."
  },
  "blob": "e0e92d20fa00b30f538402ba10edea927d9d220fa8d5c08ccfabebca3e606127",
  "id": "8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a",
  "sig": "e5bc0571cf814a9c0bdafa595532e9c4793b0b1343e563ec9951b6be4d7a078a373c7f2728b47f32c03ee6d0235a20a315487777e17956314b0b3e415ed1f903"
}
```

| Field | Required | Type | Rules |
| --- | --- | --- | --- |
| `collection` | yes | string | `^[a-z0-9/_-]{1,32}$`. Lowercase only. |
| `created_at` | yes | integer | Unix seconds. Must not be in the server's future. |
| `expires_at` | yes | integer | Unix seconds. Must be in the future. |
| `owner` | yes | string | `ed25519:` + 64 hex chars (32-byte public key). |
| `labels` | yes | array of strings | At most 10. Each matches `^[A-Za-z0-9:_\.\-\+\/]{1,64}$`. Order is preserved. |
| `data` | yes | JSON object | Opaque to the server. Any JSON object. |
| `blob` | no | string | One 64-hex SHA-256. Omit or use `null` for no attachment. |
| `id` | yes | string | 64 hex chars. Must equal the computed digest. |
| `sig` | yes | string | 128 hex chars. Ed25519 signature over the 32-byte digest. |

Unknown fields are accepted, ignored, and not persisted.

The stored envelope is the canonical object containing the digest fields plus lowercase `id` and `sig`. Comments, whitespace, key order, and extra fields from the upload are not preserved.

### Canonical JSON

The digest input is exactly the object:

```text
{collection, created_at, data, expires_at, labels, owner}
```

plus `blob` when the optional attachment is present. `id` and `sig` are never part of the digest input.

Canonicalization rules:

- object keys sorted lexicographically, recursively;
- compact separators: `,` and `:`, no spaces;
- UTF-8 bytes;
- arrays keep their order (including `labels`);
- numbers must be integers in the digest fields (`created_at`, `expires_at`).

A Rust-compatible canonical encoding can be written as:

```js
function canonical(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
```

**Number warning:** avoid floating-point numbers in `data` if clients are written in different languages. JavaScript prints `1.0` as `1`, while Rust may print `1.0`, producing different canonical bytes and a different digest. Use integers and strings for values that must round-trip exactly.

### Identity and signature

```text
canonical_bytes = canonical_json({collection, created_at, data, expires_at, labels, owner [, blob]})
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

### Worked example

Digest input, byte-for-byte:

```text
{"collection":"docs/example","created_at":1793283000,"data":{"ciphertext":"base64-or-any-client-format","nonce":"..."},"expires_at":1824732600,"labels":["demo","docs"],"owner":"ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"}
```

SHA-256 of those bytes:

```text
8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a
```

Signature over that 32-byte digest with the example key:

```text
e5bc0571cf814a9c0bdafa595532e9c4793b0b1343e563ec9951b6be4d7a078a373c7f2728b47f32c03ee6d0235a20a315487777e17956314b0b3e415ed1f903
```

Full envelope as POSTed (pretty-printed for readability; the node accepts any key order):

```json
{
  "collection": "docs/example",
  "created_at": 1793283000,
  "expires_at": 1824732600,
  "owner": "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
  "labels": ["demo", "docs"],
  "data": {
    "ciphertext": "base64-or-any-client-format",
    "nonce": "..."
  },
  "id": "8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a",
  "sig": "e5bc0571cf814a9c0bdafa595532e9c4793b0b1343e563ec9951b6be4d7a078a373c7f2728b47f32c03ee6d0235a20a315487777e17956314b0b3e415ed1f903"
}
```

`POST /events` returns `201`:

```json
{"status":"stored","id":"8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a"}
```

`GET /events/{id}` returns the stored canonical envelope:

```text
{"collection":"docs/example","created_at":1793283000,"data":{"ciphertext":"base64-or-any-client-format","nonce":"..."},"expires_at":1824732600,"id":"8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a","labels":["demo","docs"],"owner":"ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c","sig":"e5bc0571cf814a9c0bdafa595532e9c4793b0b1343e563ec9951b6be4d7a078a373c7f2728b47f32c03ee6d0235a20a315487777e17956314b0b3e415ed1f903"}
```

## Public routes

### `GET /`

Minimal JSON route index. Includes the service version, description, and a map of route → purpose. Sync routes are listed only when `NODES` is configured, but they are always mounted and callable.

```json
{
  "service": "rabta",
  "version": "0.0.1-dev",
  "description": "rabta node — events + blobs on one port",
  "routes": {
    "GET /": "this index",
    "GET /healthz": "liveness probe",
    "GET /stats": "storage + eviction counters",
    "POST /events": "publish a signed envelope (application/json; `blob` references raw-PUT bytes)",
    "GET /events": "list (collection, label*, owner, limit, cursor)",
    "GET /events/{id}": "fetch one (ETag / If-None-Match)",
    "GET /events/{id}/size": "envelope + attachment sizes",
    "GET /events/stream": "SSE (Last-Event-ID resume)",
    "PUT /blobs/{name}.blob|bin": "raw blob upload (orphan clock)",
    "GET /blobs/{hash}": "fetch blob (Range / ETag)",
    "HEAD /blobs/{hash}": "probe blob"
  }
}
```

### `GET /healthz`

Liveness probe.

```json
{"status":"ok","live_events":6,"live_blobs":2}
```

Counts are rows currently marked live. Expired rows disappear from reads immediately, but the counters include them until the next reaper sweep (every 5 minutes).

### `GET /stats`

JSON monitoring snapshot. No dashboard.

```json
{
  "events": {"live": 6, "bytes": 2185},
  "blobs": {"live": 2, "bytes": 64},
  "storage": {
    "max_bytes": 21474836480,
    "configured_max_bytes": 21474836480,
    "clamped_to_free": false,
    "watermark_bytes": 19327352832,
    "eviction_target_bytes": 18253611008,
    "max_single_blob_bytes": 2147483648,
    "free_bytes": 457677926400,
    "data_dir": "/data"
  },
  "reaper": {
    "interval_s": 300,
    "last_sweep_at": 1793283600,
    "last_sweep_age_s": 12
  },
  "eviction": {
    "events_evicted": 0,
    "blobs_evicted": 0,
    "bytes_reclaimed": 0
  },
  "sse": {"subscribers": 1, "cap": 256},
  "sync": {
    "nodes": 1,
    "interval_s": 60,
    "accepting": true,
    "pulls": {
      "attempts": 0,
      "succeeded": 0,
      "failed": 0,
      "skipped_backoff": 0,
      "in_backoff": 0
    },
    "reconcile": {
      "probes": 6,
      "requests": 6,
      "events_pushed": 0,
      "events_pulled": 0,
      "blobs_pulled": 1,
      "skipped_pressure": 0,
      "skipped_peer_full": 0,
      "queue_overflow": 0,
      "queued_ranges": 0
    },
    "heals": {"attempts": 0, "succeeded": 0, "failed": 0}
  },
  "uptime_s": 3600,
  "version": "0.0.1-dev"
}
```

`sync.accepting` reflects the node's hysteresis-aware pause decision from the last reconcile tick. This is slightly different from the `accepting` value returned by `POST /sync/reconcile`, which compares live bytes directly against the watermark.

### `POST /events`

Publish one signed envelope.

```bash
curl -X POST http://localhost:3232/events \
  -H 'content-type: application/json' \
  --data-binary @event.json
```

**Request**

- Body: one envelope JSON object, at most **100,000 bytes**.
- `Content-Type` is not enforced, but send `application/json`.

**Response**

- `201 Created` when the event is new:

  ```json
  {"status":"stored","id":"8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a"}
  ```

- `200 OK` when the same `id` is already stored:

  ```json
  {"status":"duplicate","id":"8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a"}
  ```

- When the envelope has a `blob` field, both responses include the hash and a convenience URL:

  ```json
  {
    "status": "stored",
    "id": "2f134cda189a7ba816061f1c1bf3975ff6e5d7cbb3c86d2b5a60a7518904079f",
    "blob": "28a0a142baa93fdf578096bf507a457719a9dec6bc8174ab3907f274e9cdbea2",
    "blob_url": "/blobs/28a0a142baa93fdf578096bf507a457719a9dec6bc8174ab3907f274e9cdbea2"
  }
  ```

The `blob` hash does **not** have to exist when the event is published. The reference is recorded immediately; the bytes may arrive before or after, via the public blob door or a peer. Reads of that blob return `404` until the bytes exist.

New events are pushed immediately to every configured peer. Duplicate deliveries are idempotent.

### `GET /events`

List live, unexpired events with filters and cursor pagination.

| Query parameter | Meaning |
| --- | --- |
| `collection` | Exact collection match. |
| `label` | Repeatable. All supplied labels must be present (AND). |
| `owner` | `ed25519:<64 hex>` only. Bare hex is rejected. |
| `limit` | Page size, clamped to `1..100`. Default `20`. |
| `cursor` | Opaque cursor from `next_cursor`. |

```bash
curl 'http://localhost:3232/events?collection=chat/room-42&label=team&limit=20'
```

**Response**

```json
{
  "count": 2,
  "events": [
    {
      "collection": "chat/room-42",
      "created_at": 1793283000,
      "data": {"ciphertext": "..."},
      "expires_at": 1824732600,
      "id": "8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a",
      "labels": ["demo", "docs"],
      "owner": "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
      "sig": "e5bc0571..."
    }
  ],
  "next_cursor": "AAAAAGrjU7iHct-oZmR5c1u2Rf7wWDJ_YsEjeJkftl8wntHQkpuCSg"
}
```

- Results are ordered by `created_at DESC, id DESC`.
- `next_cursor` is `null` when fewer than `limit` rows were returned; otherwise it is a base64url-encoded opaque cursor for the next page.
- The cursor encodes the last row's `(created_at, id)`. Treat it as opaque.
- Expired events and events being evicted are never returned.
- Empty or duplicate `label` filters return `400 bad_label`.
- A non-canonical `owner` returns `400 bad_owner`.
- A malformed `cursor` returns `400 bad_json`.

### `GET /events/{id}`

Fetch one stored envelope by event ID.

```bash
curl -i http://localhost:3232/events/8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a
```

- `200` with `Content-Type: application/json`.
- `ETag: "<id>"`.
- `If-None-Match: "<id>"`, the bare ID, or `*` returns `304 Not Modified`.
- Invalid, unknown, or expired IDs return `404 not_found`.
- The body is the exact stored canonical envelope, not the original upload bytes.

### `GET /events/{id}/size`

Return envelope and attachment sizes without transferring the blob bodies.

```json
{
  "id": "2f134cda189a7ba816061f1c1bf3975ff6e5d7cbb3c86d2b5a60a7518904079f",
  "envelope_size": 398,
  "attachments": [
    {"hash": "28a0a142baa93fdf578096bf507a457719a9dec6bc8174ab3907f274e9cdbea2", "size": 43}
  ],
  "total_size": 441
}
```

- `attachments` lists every blob hash referenced by the envelope.
- `size` is `null` when the bytes are not present locally.
- `total_size` is `envelope_size` plus the sizes of attachments that are present.
- Missing/expired events return `404 not_found`.

### `GET /events/stream`

Server-Sent Events stream of newly stored events.

```bash
curl -N 'http://localhost:3232/events/stream?collection=chat/room-42&label=team'
```

**Query parameters**

Same filters as `GET /events`: `collection`, repeated `label` (AND), and canonical `owner`. `limit` and `cursor` are not used; all matching live events are streamed.

**Resume**

Send `Last-Event-ID: <seq>` to resume after a sequence number. Without the header, the stream starts at the current high-water mark and emits only events stored after the connection opens.

The `id:` field is an internal per-node event sequence number, **not** the event's SHA-256 ID. It is stable only on the same node/database and exists for resume.

**Wire format**

Each event is one frame:

```text
id: 42
event: message
data: {"collection":"chat/room-42","created_at":1793283000,"data":{"ciphertext":"..."},"expires_at":1824732600,"id":"8772dfa8...","labels":["team"],"owner":"ed25519:ea4a...","sig":"e5bc05..."}

```

- `data` is the compact canonical envelope on one line.
- The blank line terminates the frame.
- Every 15 seconds an idle stream receives a comment keepalive:

  ```text
  : keepalive

  ```

- On reconnect, the node replays matching rows after `Last-Event-ID` from SQLite, then switches to the live feed. Missed rows are not lost as long as they are still live and unexpired.
- The default subscriber cap is 256; when full, the request fails with `503 subscriber_cap` before the stream starts.
- Disconnects release the subscriber slot automatically.

### `PUT /blobs/{name}.blob|bin`

Upload raw bytes. The body is content-addressed; the URL filename is only an extension gate.

```bash
curl -X PUT --data-binary @file.bin \
  http://localhost:3232/blobs/file.bin
```

- The path must end in `.blob` or `.bin`; anything else returns `400 bad_extension`.
- The filename itself is not stored.
- Empty uploads return `400 bad_json`.
- Maximum body size is **10% of effective `STORAGE_MAX`** (default 20 GB → 2 GB).
- Uploads are refused with `503 at_watermark` when admitting them would cross the watermark.
- At most **8 uploads** run concurrently per process. In-flight temp bytes are reserved against half the watermark and against the free-space safety floor (5% of `STORAGE_MAX`, minimum 16 MiB). Exhaustion returns `503 busy` or `507 disk_full`.
- An upload that stalls for **30 seconds** between chunks is aborted with `408 timeout`; its temp file is removed.
- The SHA-256 is computed while streaming; nothing is committed until the body is complete.

**Response**

`201 Created` for a new blob, `200 OK` when the same bytes already exist:

```json
{
  "hash": "e0e92d20fa00b30f538402ba10edea927d9d220fa8d5c08ccfabebca3e606127",
  "size": 21,
  "url": "/blobs/e0e92d20fa00b30f538402ba10edea927d9d220fa8d5c08ccfabebca3e606127"
}
```

To attach the blob to an event, put the returned hash in the envelope's `"blob"` field. Upload before or after publishing the event; the hash is the join point.

### `GET /blobs/{hash}`

Download a blob by SHA-256.

```bash
curl -o file.bin http://localhost:3232/blobs/e0e92d20fa00b30f538402ba10edea927d9d220fa8d5c08ccfabebca3e606127
```

**Headers**

| Header | Value |
| --- | --- |
| `Content-Type` | `application/octet-stream` |
| `ETag` | `"<sha256>"` |
| `Cache-Control` | `public, max-age=31536000, immutable` |
| `Accept-Ranges` | `bytes` |
| `X-Content-Type-Options` | `nosniff` |

- `If-None-Match` with the quoted hash, bare hash, or `*` returns `304 Not Modified` with the ETag and cache headers.
- Invalid or unknown hashes return `404 not_found` (not `400`).
- Blobs are immutable by construction: the same hash always names the same bytes.
- If the blob is missing locally and peers are configured, the node attempts a read-time heal before returning `404`.

**Range requests**

Single ranges are supported:

```bash
curl -H 'Range: bytes=0-99' http://localhost:3232/blobs/<hash>
```

- Valid range → `206 Partial Content`, `Content-Range: bytes <from>-<to>/<size>`, and the sliced body.
- `bytes=<from>-` is supported and runs to the end.
- The end is clamped to the blob size.
- Malformed, multi-range, suffix (`bytes=-N`), or unsatisfiable ranges return **`200 OK` with the full body**, not `416`. This is a deliberate simplification of the contract.

### `HEAD /blobs/{hash}`

Same lookup and headers as `GET`, with no response body. Useful for existence checks, size probes, and `ETag` comparisons.

## Blob lifecycle

Blobs are independent of events until an envelope references their hash.

| State | Lifetime |
| --- | --- |
| Uploaded, never referenced | Deleted after 1 hour (orphan clock). |
| Referenced by one or more live events | Kept while any parent event is live. |
| Last parent expires or is evicted | Deleted on the next reaper/pressure pass. |
| Referenced but bytes never uploaded | Event remains valid; blob reads return `404` until bytes arrive. |

Only referenced blobs participate in peer sync: an unreferenced upload is neither advertised in the blob keyspace nor pulled from a peer.

The reaper runs every 300 seconds and also runs after eviction pressure. Expiry is enforced on reads immediately, so an expired event is invisible before the sweep removes its row.

Content addressing deduplicates bytes: uploading the same body twice returns the existing hash and does not consume additional storage.

## Sync protocol v1

Sync is bidirectional for events and pull-only for blob bodies. Nodes converge toward the union of live data, subject to TTL and eviction. It is **not** a consensus system: there are no quorum writes, no leader election, and no conflict resolution beyond content identity.

All sync routes are unauthenticated and share the public port. Treat peer URLs as trusted infrastructure.

### Peer configuration and behavior

Set `NODES` to a comma-separated list of peer base URLs, maximum 8, HTTP(S) only:

```bash
docker run -d --name rabta \
  -p 3232:3232 \
  -v rabta:/data \
  -e NODES=http://node-b:3232,http://node-c:3232 \
  ghcr.io/besoeasy/rabta:latest
```

- Every peer tick is 60 seconds, with exponential backoff on consecutive failures (×2, capped at 1 hour).
- On publish, the origin node immediately pushes the new event to every peer. Inbound sync events are **not** re-fanned, preventing loops.
- Each tick reconciles both `events` and `blobs` separately.
- Blob bodies are never pushed proactively. A node discovers missing blob hashes from event envelopes/refs, then pulls bodies.
- Blob reads heal lazily: a public `GET` or sync `GET` for a missing local blob asks trusted peers before answering `404`.
- A node reporting `accepting: false` stops receiving pushes from peers that honor the field.
- Event pushes batch up to 64 envelopes. Blob pulls run at most 4 at a time, 32 per tick.
- The built-in client limits each tick to 16 reconcile POSTs, 64 total HTTP calls, and 20 seconds of wall-clock work per peer/kind, with a bounded work queue of 4096 ranges.

### `POST /sync/reconcile`

Exact Merkle range exchange. One request may contain up to **128** range probes. The body cap is **2 MiB**.

**Request**

```json
{
  "v": 1,
  "kind": "events",
  "ranges": [
    {"prefix": "a", "count": 2, "fp": "T90Zfv3jclvlnTwMg42xhw"}
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `v` | yes | Must be `1`. |
| `kind` | yes | `"events"` or `"blobs"`. |
| `ranges` | yes | 1–128 probes. |
| `prefix` | yes | Hex nibble prefix, 0–64 chars. `""` is the whole keyspace; `"a"` covers `a0…` through `af…`. |
| `count` | no | Claimed item count. Defaults to `0`. |
| `fp` | no | Claimed fingerprint. The server computes its own and does not trust this. |
| `ids` | no | Optional leaf claim, at most 64 IDs. Each must be 64 hex and inside `prefix`. If present, its length must equal `count`. |
| `ids_only` | no | When `true`, return one ID page instead of a summary. Default `false`. |
| `after` | no | Page cursor for `ids_only`: exclusive 64-hex key. |
| `limit` | no | Page size for `ids_only`, clamped to `1..1000`. Default `1000`. |

**Response**

```json
{
  "v": 1,
  "kind": "events",
  "ranges": [
    {
      "prefix": "a",
      "count": 2,
      "fp": "T90Zfv3jclvlnTwMg42xhw",
      "ids": [
        "a100000000000000000000000000000000000000000000000000000000000000",
        "a200000000000000000000000000000000000000000000000000000000000000"
      ]
    }
  ],
  "accepting": true
}
```

Summary replies:

- `count` is the exact number of live keys in the prefix.
- `fp` is omitted when `count` is 0.
- `ids` is present when `count <= 64`, including `[]` for an empty range.
- If `count > 64`, `ids` is omitted.

ID-page replies (`ids_only: true`):

```json
{"prefix":"a","ids":["a1...", "a2..."],"next":"a2..."}
```

- `ids` is ordered ascending.
- `next` is the last returned key when more pages remain; pass it back as `after`. Omitted at the end.

`accepting` is always added by the handler. It is `true` when live event + blob bytes are at or below the admission watermark. Peers use it to stop pushing to a full node.

**Fingerprint algorithm**

The fingerprint identifies the exact set of keys in a range:

```text
fp = SHA-256(
  "rabta-range-v1"
  || kind                      // ASCII "events" or "blobs"
  || lowercase_hex_prefix      // ASCII
  || each 32-byte key, ascending
  || count as u64 little-endian
)[0..16]
```

The 16-byte truncation is encoded as base64 with the standard alphabet and no `=` padding.

Range contents:

- `events`: rows with `state='live'` and `expires_at > now`.
- `blobs`: rows with `state='live'` that at least one live, unexpired event references. Unreferenced uploads stay local and are never advertised for sync.

**Reconciliation algorithm (built-in client)**

1. Start at prefix `""` (the whole keyspace).
2. Probe up to 128 prefixes per POST and compare `count` + `fp`.
3. Equal count and fingerprint → range already matches; skip it.
4. Remote range empty → push local events underneath it (events only; blobs stay pull-only).
5. Local range empty → page the peer's IDs and pull each missing event/blob.
6. Remote range has ≤64 keys → compare exact ID sets; pull remote-only keys and push local-only events.
7. Local range has ≤64 keys but remote has more → push the local leaf's events, then page the remote IDs and pull the rest.
8. Otherwise split the prefix into its 16 hex children (`"a"` → `"a0"`…`"af"`) and enqueue them.
9. Repeat until the queue empties, the per-tick budget is exhausted, or time runs out. Unfinished work stays queued for the next tick.

Duplicate prefixes inside one request are validated per probe but scanned only once. Their replies are reused.

### `POST /sync/events`

Push a batch of signed envelopes. This is the sync-plane counterpart of `POST /events`.

**Request**

A JSON array of envelopes, at most **1000 events** and **32 MiB** of body:

```json
[
  { "collection": "chat/room-42", "created_at": 1793283000, "...": "..." },
  { "collection": "chat/room-42", "created_at": 1793283001, "...": "..." }
]
```

Each item goes through normal validation: shape, TTL, canonical digest, `id` claim, signature, and storage admission. Invalid items are counted and skipped; the batch does not fail because one envelope is bad.

**Response**

```json
{"stored": 63, "rejected": 1}
```

- `stored` counts newly written events.
- `rejected` counts invalid items **and duplicates**.
- Inbound sync events are not re-fanned to other peers.
- A non-array body returns `400 bad_json`; more than 1000 items returns `413 too_large`.

### `POST /sync/events/fetch`

Fetch full envelopes by exact ID. At most **1000 IDs** and **256 KiB** of body.

```json
{"ids":["8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a"]}
```

**Response**

```json
{
  "events": [
    {
      "collection": "docs/example",
      "created_at": 1793283000,
      "data": {"ciphertext": "..."},
      "expires_at": 1824732600,
      "id": "8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a",
      "labels": ["demo", "docs"],
      "owner": "ed25519:ea4a...",
      "sig": "e5bc05..."
    }
  ],
  "missing": ["0000..."]
}
```

- `events` preserves request order, skipping missing IDs.
- `missing` contains IDs that are absent, expired, or have corrupt stored JSON.
- A malformed ID returns `404 not_found`.

### `GET /sync/events`

Paged pull in local sequence order, for fresh joins and catch-up.

| Query parameter | Meaning |
| --- | --- |
| `cursor` | Exclusive sequence number. Default `0`. |
| `limit` | Rows per page, clamped to `1..1000`. Default `1000`. |

```json
{
  "count": 2,
  "events": [
    {"id": "...", "collection": "...", "...": "..."}
  ],
  "next_cursor": 42
}
```

- Ordered by ascending internal `seq`.
- `next_cursor` is `null` when fewer than `limit` rows were returned.
- Only rows marked `state='live'` are selected. This route does **not** apply an expiry predicate, so clients should honor each envelope's `expires_at`.
- The cursor is a plain integer, unlike the opaque cursor used by `GET /events`.

### `GET /sync/events/{id}`

Fetch one envelope by exact ID on the sync plane.

- `200` with `Content-Type: application/json` and the stored canonical envelope.
- No `ETag` handling.
- Invalid, unknown, or expired IDs return `404 not_found`.
- Missing events are **not** healed on this read. A node learns about new events through the reconcile loop, then pulls them with `POST /sync/events/fetch` or `GET /sync/events`.

### `POST /sync/blobs`

Push one raw blob body. This is the sync-plane counterpart of `PUT /blobs/...`.

- The body is raw bytes; there is no filename or extension gate.
- Content addressing, the single-blob cap, and the storage watermark still apply.
- Peer-origin admission never evicts local events to make room. Collectible orphan blobs may be reclaimed; if the body still does not fit, the result is `refused` with `at_watermark`.
- The SHA-256 is computed while streaming.

**Response**

The route returns `200 OK` with a wrapped result for storage outcomes:

```json
{
  "blobs": [
    {
      "hash": "28a0a142baa93fdf578096bf507a457719a9dec6bc8174ab3907f274e9cdbea2",
      "status": "stored",
      "size": 43,
      "url": "/blobs/28a0a142baa93fdf578096bf507a457719a9dec6bc8174ab3907f274e9cdbea2"
    }
  ]
}
```

- `status`: `"stored"`, `"duplicate"`, or `"refused"`.
- `stored` and `duplicate` include `size` and `url`.
- `refused` includes a `code` (for example `at_watermark` or `internal`) and no `size`/`url`.
- Body-level failures before install (too large, stream error, finalize failure) still use the normal error envelope with a non-200 status.
- Failures after staging, including install/storage errors, are reported inside the `refused` result.

The result is wrapped in a `blobs` array even though this route currently accepts one body.

### `GET /sync/blobs/{hash}`

Fetch one blob body for peer synchronization.

- `200` with `Content-Type: application/octet-stream`, `X-Content-Type-Options: nosniff`, and `Content-Length`.
- No `Range`, `ETag`, or immutable cache headers; this is a bulk sync read.
- Invalid or missing hashes return `404 not_found`.
- If peers are configured, a miss triggers a single-flight read heal before the `404`. Recursive heal fan-out is suppressed.

## Limits and runtime configuration

### Hard limits

| Limit | Value |
| --- | --- |
| Event envelope | 100,000 bytes |
| Event TTL | > 60 seconds and ≤ 365 days |
| Labels per event | 10 |
| Public event list page | 1–100 (default 20) |
| Sync event batch | 1000 items, 32 MiB body |
| Sync event fetch | 1000 IDs, 256 KiB body |
| Sync event pull page | 1–1000 (default 1000) |
| Reconcile request | 128 ranges, 2 MiB body |
| Reconcile ID page | 1–1000 (default 1000) |
| Reconcile leaf | 64 IDs |
| Single blob | 10% of effective `STORAGE_MAX` |
| Orphan blob lifetime | 1 hour |
| Peers | 8, HTTP(S) only |
| SSE subscribers | 256 by default |
| Reaper interval | 300 seconds |
| Peer tick interval | 60 seconds |

### Environment variables

Set variables in the process environment or in `/data/config.env` as `KEY=VALUE` lines. The process environment wins. Invalid values refuse to boot rather than silently falling back.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3232` | HTTP port. |
| `DATA_DIR` | `/data` | SQLite database and blob directory. |
| `STORAGE_MAX` | `20GB` | Storage ceiling, clamped to 90% of free disk at boot. Accepts sizes such as `20GB`, `512MiB`, `52428800`. |
| `SSE_SUBSCRIBER_CAP` | `256` | Maximum concurrent SSE clients. |
| `NODES` | empty | Comma-separated peer base URLs, maximum 8. |
| `RUST_LOG` | `info` | Log filter, for example `debug` or `rabta=debug`. |

Derived values:

- Admission watermark = 90% of effective `STORAGE_MAX`.
- Eviction target = 85% of effective `STORAGE_MAX`.
- Maximum single blob = 10% of effective `STORAGE_MAX`.

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

const response = await fetch('http://localhost:3232/events', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(envelope),
});
console.log(await response.json());
```

### Upload a blob, then attach it

```bash
HASH=$(sha256sum file.bin | cut -d' ' -f1)

curl -X PUT --data-binary @file.bin \
  "http://localhost:3232/blobs/file.bin"

# Put "$HASH" in the envelope's "blob" field, then POST /events.
```

### List, fetch, and stream

```bash
# List the newest 20 events in a collection.
curl 'http://localhost:3232/events?collection=chat/room-42&limit=20'

# Fetch one event by ID.
curl http://localhost:3232/events/<64-hex-id>

# Check envelope and attachment sizes.
curl http://localhost:3232/events/<64-hex-id>/size

# Stream live updates, resuming after sequence 42.
curl -N -H 'Last-Event-ID: 42' \
  'http://localhost:3232/events/stream?collection=chat/room-42'
```

### Pull and push peer data manually

```bash
# Pull events after sequence 0.
curl 'http://localhost:3232/sync/events?cursor=0&limit=100'

# Fetch specific envelopes.
curl -X POST http://localhost:3232/sync/events/fetch \
  -H 'content-type: application/json' \
  -d '{"ids":["8772dfa8666479735bb645fef058327f62c12378991fb65f309ed1d0929b824a"]}'

# Ask a peer for an exact range summary.
curl -X POST http://localhost:3232/sync/reconcile \
  -H 'content-type: application/json' \
  -d '{"v":1,"kind":"events","ranges":[{"prefix":"","count":0}]}'
```

---

Rabta is under active development. The public API is intentionally small, and the sync protocol is versioned at `1`. If a wire detail here disagrees with the code, the code in `src/api/` and `src/sync/ranges.rs` is authoritative.
