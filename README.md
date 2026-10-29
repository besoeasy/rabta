# Rabta

### The self-hosted, zero-knowledge backend for events, blobs, and realtime sync.

[![GitHub stars](https://img.shields.io/github/stars/besoeasy/rabta?style=flat&logo=github)](https://github.com/besoeasy/rabta/stargazers)
[![Rust](https://img.shields.io/badge/Rust-2024-000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-embedded-003B57?logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Docker](https://img.shields.io/badge/Docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)](https://github.com/besoeasy/rabta/pkgs/container/rabta)
[![Sync protocol](https://img.shields.io/badge/sync%20protocol-v1-6f42c1)](src/sync/ranges.rs)

Rabta is the backend you run when you want to **ship the product, not the infrastructure**. It stores signed events and content-addressed blobs, streams changes over SSE, expires data automatically, and replicates to peers — all from one Rust binary, one SQLite file, and one Docker container.

**No accounts. No app schema. No database server. No vendor lock-in.**

Clients encrypt and sign. Rabta verifies signatures, stores opaque envelopes, and never needs to understand your data.

## Why Rabta?

- **Zero-knowledge by design** — payloads are encrypted and signed by clients; the node only sees ciphertext and metadata.
- **One container, zero ops** — Rust + SQLite + a blob directory. No Postgres, Redis, Kafka, or cloud account required.
- **Events and blobs together** — JSON event envelopes plus content-addressed files with `Range` and `ETag` support.
- **Realtime without extra services** — built-in Server-Sent Events with `Last-Event-ID` resume.
- **Retention that runs itself** — every event has a TTL; expired rows and orphaned blobs are reclaimed automatically.
- **Exact peer replication** — Merkle range reconciliation syncs events bidirectionally and pulls missing blob bodies.
- **Safe by default** — Ed25519 verification, size limits, storage watermark, and eviction before the disk fills.
- **Browser-ready** — permissive CORS, plain HTTP, and no proprietary client SDK required.

## What you can build

| You're building | Rabta gives you |
| --- | --- |
| **AI agents** | Shared memory, task queues, and append-only event logs between agents |
| **Local-first / offline-first apps** | Sync-friendly event streams with encrypted payloads and file attachments |
| **Chat and collaboration** | Rooms, presence, messages, and live updates over SSE |
| **Nostr clients and relays** | Signed event storage and relay-style access over plain HTTP |
| **Multiplayer games** | Ephemeral rooms, player state, and assets that clean themselves up |
| **IoT and telemetry** | Signed time-series events with automatic retention |
| **Webhooks and integrations** | A durable event inbox/outbox without running a message broker |
| **File drop and media** | SHA-256 content-addressed storage with range reads |

## Quick start

```bash
docker run -d \
  --name rabta \
  -p 3232:3232 \
  -v rabta:/data \
  --restart unless-stopped \
  ghcr.io/besoeasy/rabta:latest

curl -s http://localhost:3232/healthz
# {"status":"ok","live_events":0,"live_blobs":0}
```

That's it. Your backend is live at `http://localhost:3232`. The root route returns a machine-readable index of every endpoint.

Images are published for **linux/amd64** and **linux/arm64**. Tags: `latest`, `X.X.X`, and `dev`.

Rabta serves no HTML. A UI is a static app hosted anywhere that points at the node URL.

## How it works

```mermaid
flowchart LR
    app["Your app / AI agent"] -->|"signed events + blobs"| node["Rabta node"]
    node -->|"SSE + range reads"| app
    node <-->|"exact range sync"| peer["Peer node"]
    node --> store[("SQLite + blob dir")]
```

1. **The client owns the data model.** It canonicalizes JSON, hashes it, signs with Ed25519, and optionally encrypts the payload.
2. **Rabta verifies and stores.** The node checks the signature and TTL, then writes an opaque envelope to SQLite.
3. **The event goes live.** Subscribers receive it over SSE; attached blobs are fetched by hash.
4. **Peers reconcile.** Nodes exchange exact range summaries and transfer only the keys and bodies they are missing.

The server never parses your application data, never runs your schema, and never needs a plaintext copy.

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

Sync-plane routes are unauthenticated by design. Keep them on a private network or behind a proxy.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/sync/reconcile` | Exact range reconciliation (protocol v1) |
| `POST` | `/sync/events` | Push an event batch |
| `POST` | `/sync/events/fetch` | Fetch event envelopes by ID |
| `GET` | `/sync/events` | Paged event pull |
| `GET` | `/sync/events/{id}` | Pull one event envelope |
| `POST` | `/sync/blobs` | Push one blob body |
| `GET` | `/sync/blobs/{hash}` | Pull one blob body |

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

`id` is the SHA-256 of the canonical JSON of `{collection, created_at, data, expires_at, labels, owner}` plus `blob` when present — sorted keys, compact separators. `sig` is the Ed25519 signature over that 32-byte digest.

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

Add the returned hash as `"blob"` in an event. Upload before or after; the hash is the join point.

## Stream live

```bash
curl -N 'http://localhost:3232/events/stream?collection=chat/room-42'
```

Reconnect with `Last-Event-ID` to resume from the last event you processed. The stream is backed by a shared in-process feed, so one subscriber burst does not multiply database reads.

## Replicate

```bash
docker run -d \
  --name rabta \
  -p 3232:3232 \
  -v rabta:/data \
  -e NODES=http://node-b:3232,http://node-c:3232 \
  ghcr.io/besoeasy/rabta:latest
```

New events push to peers immediately. Every 60 seconds each node reconciles exact sorted-key ranges: matching ranges are skipped by count plus fingerprint, small ranges exchange IDs directly, and larger mismatches split by nibble. Event bodies move in both directions; blob bodies are pull-only and are also healed on read.

Replication is designed for small, self-managed clusters of up to **8 peers**. It is not a consensus system: nodes converge toward the union of live data, subject to TTL and eviction.

## Configuration

Set environment variables, or put `KEY=VALUE` lines in `/data/config.env`. Process environment wins.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3232` | HTTP port |
| `DATA_DIR` | `/data` | SQLite database and blob storage |
| `STORAGE_MAX` | `20GB` | Storage ceiling; clamped to 90% of free disk at boot |
| `SSE_SUBSCRIBER_CAP` | `256` | Maximum concurrent SSE clients |
| `NODES` | empty | Comma-separated peer URLs, max 8 |
| `RUST_LOG` | `info` | Log filter, for example `debug` or `rabta=debug` |

## Guardrails

- Event envelope: 100 KB max
- Event TTL: greater than 60 seconds, up to 365 days
- Single blob: 10% of `STORAGE_MAX`
- Unattached blobs: deleted after 1 hour
- Admission watermark: 90% of `STORAGE_MAX`; pressure cleanup evicts to 85%
- Peers: 8 max, HTTP(S) only

## Privacy model

Rabta is zero-knowledge in the practical sense: it has no accounts, no application logic, and never needs plaintext. It does see metadata — public key, collection, labels, sizes, and timing. Encrypt payloads client-side when that metadata matters.

For a hardened deployment:

- Put the node behind TLS and an authenticated reverse proxy if it is reachable from the internet.
- Keep sync ports on a private network.
- Treat peer URLs as trusted infrastructure, not user input.

## Project status

Rabta is under active development (`0.0.1-dev`). The core API is deliberately small, and the sync protocol is versioned at v1. Issues and pull requests are welcome.

If Rabta saves you from building a backend, a ⭐ helps other builders discover it.

## Keywords

Self-hosted backend · Rust backend · SQLite backend · event store · blob storage · content-addressed storage · object storage · realtime API · Server-Sent Events · SSE · local-first sync · offline-first apps · peer-to-peer replication · distributed systems · Ed25519 · end-to-end encryption · zero-knowledge backend · privacy-first · AI agent memory · Nostr relay · Docker · Axum · backend as a service
