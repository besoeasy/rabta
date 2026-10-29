# Rabta

### Minimal zero-knowledge backend for everything.

One HTTP port for signed events and content-addressed blobs. No accounts, no app
schema, no UI, no database server. Run one container and use it as the backend
for apps, AI agents, Nostr clients, privacy chat, multiplayer games, and
anything else that needs sync.

The node does not need to understand your data. Clients encrypt and sign;
Rabta verifies signatures, stores opaque envelopes, and expires them.

## Use cases

- **Apps** — sync state, settings, and messages across devices without writing a backend.
- **AI agents** — shared memory, task queues, and event streams between agents.
- **Nostr** — store and relay signed events over plain HTTP.
- **Privacy chat** — end-to-end encrypted messages; the server only holds ciphertext.
- **Multiplayer games** — ephemeral rooms, player state, and assets that clean themselves up.
- **Everything else** — file drop, CRDT sync, feature flags, webhooks, telemetry, IoT, backups, activity feeds.

## What you get

- Ed25519-signed events, verified before storage
- Content-addressed blobs (SHA-256) with `Range` and `ETag`
- TTL on every event — automatic expiry and storage reclamation
- Live SSE stream with `Last-Event-ID` resume
- Peer replication via exact Merkle range reconciliation, up to 8 peers
- One SQLite file plus a blob directory on one volume
- Storage watermark and eviction, so the disk never fills up

## Deploy

The only supported deployment is the prebuilt GitHub Docker image. GitHub
Actions builds and publishes it to GHCR for `linux/amd64` and `linux/arm64`.

```bash
docker run -d \
  --name rabta \
  -p 3232:3232 \
  -v rabta:/data \
  --restart unless-stopped \
  ghcr.io/besoeasy/rabta:latest
```

Tags: `latest`, `X.X.X`, and `dev`.

Rabta serves no HTML. A UI is a static app hosted anywhere that points at the
node URL. The node itself always comes from the GitHub image above.

```bash
curl -s http://localhost:3232/healthz
# {"status":"ok","live_events":0,"live_blobs":0}
```

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Route index |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/stats` | Storage, eviction, SSE, and sync counters |
| `POST` | `/events` | Publish a signed envelope |
| `GET` | `/events` | List by `collection`, `label`, `owner`, `limit`, `cursor` |
| `GET` | `/events/{id}` | Fetch one event (`ETag` / `If-None-Match`) |
| `GET` | `/events/{id}/size` | Envelope and attachment sizes |
| `GET` | `/events/stream` | SSE stream with `Last-Event-ID` resume |
| `PUT` | `/blobs/{name}.blob\|bin` | Upload raw bytes |
| `GET` | `/blobs/{hash}` | Fetch a blob (`Range` / `ETag`) |
| `HEAD` | `/blobs/{hash}` | Probe a blob |

## Publish an event

```json
{
  "collection": "chat/room-42",
  "created_at": 1760000000,
  "expires_at": 1760086400,
  "owner": "ed25519:<64 hex public key>",
  "labels": ["team"],
  "data": { "ciphertext": "..." },
  "id": "<sha256 of the canonical fields>",
  "sig": "<ed25519 signature>"
}
```

`id` is the SHA-256 of the canonical JSON of `{collection, created_at, data,
expires_at, labels, owner}` plus `blob` when present — sorted keys, compact
separators. `sig` is the Ed25519 signature over that 32-byte digest.

```bash
curl -X POST http://localhost:3232/events \
  -H 'content-type: application/json' \
  --data-binary @event.json
```

## Attach a file

```bash
curl -X PUT --data-binary @file.bin http://localhost:3232/blobs/file.bin
# {"hash":"<sha256>","size":123,"url":"/blobs/<sha256>"}
```

Add the returned hash as `"blob"` in an event. Upload before or after; the hash
is the join point.

## Stream live

```bash
curl -N 'http://localhost:3232/events/stream?collection=chat/room-42'
```

## Replicate

```bash
docker run -d \
  --name rabta \
  -p 3232:3232 \
  -v rabta:/data \
  -e NODES=http://node-b:3232,http://node-c:3232 \
  ghcr.io/besoeasy/rabta:latest
```

New events push to peers immediately. Every 60 seconds nodes reconcile exact
sorted-key ranges: matching ranges are skipped by count + fingerprint, small
ranges exchange ids directly, and larger mismatches split by nibble. Event
bodies move in both directions; blob bodies are pull-only (also healed on read).
Sync endpoints are unauthenticated — keep them on a private network or behind a
proxy.

## Configuration

Set environment variables, or put `KEY=VALUE` lines in `/data/config.env`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3232` | HTTP port |
| `DATA_DIR` | `/data` | SQLite database and blob storage |
| `STORAGE_MAX` | `20GB` | Storage ceiling; clamped to 90% of free disk at boot |
| `SSE_SUBSCRIBER_CAP` | `256` | Maximum concurrent SSE clients |
| `NODES` | empty | Comma-separated peer URLs, max 8 |

## Guardrails

- Event envelope: 100 KB max
- Event TTL: greater than 60 seconds, up to 365 days
- Single blob: 10% of `STORAGE_MAX`
- Unattached blobs: deleted after 1 hour
- Admission watermark: 90% of `STORAGE_MAX`; pressure cleanup evicts to 85%
- Peers: 8 max, HTTP(S) only

## Privacy note

Rabta is zero-knowledge in the practical sense: it has no accounts, no app
logic, and never needs plaintext. It does see metadata — public key,
collection, labels, sizes, and timing. Encrypt payloads client-side when that
metadata matters.
