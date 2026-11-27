# Rabta

**Sync for local-first apps, without running a cloud.**

Rabta is a single-binary, self-healing sync relay for signed events and encrypted files. Build offline-capable sync with SQLite storage, Ed25519 verification, and peer-to-peer reconciliation - no database cluster, no message broker, no vendor lock-in.

**Best for:** local-first apps, edge devices, self-hosted products, peer meshes, and teams that want sync without backend ops.

[![API v1](https://img.shields.io/badge/API-v1-blue)](api.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green)](#license)
[![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-informational)](https://github.com/besoeasy/rabta/releases/latest)
[![Release](https://img.shields.io/github/v/release/besoeasy/rabta)](https://github.com/besoeasy/rabta/releases/latest)
[![Checks](https://github.com/besoeasy/rabta/actions/workflows/checks.yml/badge.svg)](https://github.com/besoeasy/rabta/actions/workflows/checks.yml)

[**Website**](https://rabta.space) · [**API Reference**](api.md) · [**Quick Start**](#quick-start) · [**Configuration**](#configuration) · [**Security Model**](#security-model)

---

## Why Rabta

- **One binary, zero dependencies** - SQLite, blob storage, and peer sync are embedded. Run it as a static binary or Docker container.
- **Cryptographic trust** - Every event is Ed25519-signed and verified. Relays and peers cannot forge or tamper with records.
- **Private by design** - Attached files are encrypted client-side (`RABTA1`) before upload. The relay stores content-addressed encrypted blobs without decryption keys.
- **Self-healing peer sync** - Connect nodes with `SYNC=...`. Peers exchange signed range summaries and transfer missing records with minimal bandwidth.
- **Predictable operations** - Storage budgets, watermarks, TTL expiry, and rate limiting keep nodes within hardware limits.

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  --name rabta \
  -p 127.0.0.1:3232:3232 \
  -v rabta-data:/data \
  --restart unless-stopped \
  -e STORAGE=20GB \
  ghcr.io/besoeasy/rabta:latest
```

### Native Linux

Prebuilt static musl binaries are available for `x86_64` (amd64) and `aarch64` (arm64) on the [Releases](https://github.com/besoeasy/rabta/releases/latest) page.

```bash
# x86_64 / amd64
curl -fsSL https://github.com/besoeasy/rabta/releases/latest/download/rabta-linux-amd64 -o rabta
chmod +x rabta

DATA=./data PORT=3232 ./rabta
```

For ARM64 devices (Raspberry Pi, AWS Graviton), download `rabta-linux-arm64`.

### Verify it’s running

```bash
curl -fsS http://localhost:3232/api/v1/health
curl -fsS http://localhost:3232/api/v1/node
```

Then open `http://localhost:3232/` for the built-in status dashboard.

**Next:** publish signed events and encrypted blobs through the [API Reference](api.md). Rabta verifies signatures, stores immutable records, and lets peers reconcile missing data automatically.

## Use Cases

| Use case | What Rabta gives you |
|---|---|
| **Local-first app** | Sync user data across devices without a managed cloud database. |
| **Edge / IoT fleet** | Collect signed events from intermittent nodes and let them catch up later. |
| **Self-hosted SaaS** | Deploy sync as a simple container with predictable storage and no external DB. |
| **Peer mesh / collaboration** | Run multiple relays that exchange missing records and recover after outages. |

## How It Works

1. **Publish Event** - Clients sign an envelope with an Ed25519 private key and submit it to `POST /api/v1/events`.
2. **Attach Blobs** - Large files are encrypted client-side and uploaded via `PUT /api/v1/blobs`. Events reference blobs by SHA-256 hash.
3. **Query** - Clients query events by collection, owner, labels, or time ranges with conditional caching (`ETag` / `If-None-Match`) via `GET /api/v1/events`.
4. **Reconcile** - Nodes periodically exchange signed `POST /api/v1/sync` requests containing XOR range summaries to pinpoint and transfer missing records with minimal bandwidth.

See the [**API Reference**](api.md) for wire format, signing rules, routes, and client examples.

## Configuration

Configure Rabta via environment variables or a `/data/config.env` file. Environment variables take precedence.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3232` | TCP port for the HTTP API and dashboard. |
| `DATA` | `/data` | Directory for SQLite database, blobs, and keys. |
| `STORAGE` | `20GB` | Maximum disk storage for events and blobs before pressure eviction triggers. |
| `POLICY` | *None* | JSON rules exempting matching events/blobs from pressure eviction (e.g. `{"rules":[{"owner":["ed25519:..."]}]}`). TTL expiry still applies. |
| `SYNC` | *None* | Comma-separated list of up to 4 peer relay URLs (e.g. `https://relay-a.space,https://relay-b.space`). |
| `REGEN` | `20`–`40` | Battery units regenerated per second (out of `1,000,000` capacity). Random by default. |
| `BITCOIN` | *None* | Optional on-chain Bitcoin donation address displayed on `GET /api/v1/node` and the web dashboard. |
| `RUST_LOG` | `info` | Logging verbosity (`error`, `warn`, `info`, `debug`). |

## Why Teams Pick Rabta

| Need | Rabta | Typical DIY sync stack | Managed sync backend |
|---|---|---|---|
| **Setup** | Single binary/container | Database + queue + API + workers | Vendor account + SDK integration |
| **Offline / edge** | Designed for intermittent nodes | Custom retry/reconcile logic | Varies by vendor |
| **Data integrity** | Ed25519-signed, verifiable events | Build your own signing/audit model | Vendor-defined trust model |
| **Blob privacy** | Client-side encrypted before upload | Build your own encryption/storage flow | Varies by vendor |
| **Operations** | Embedded SQLite + bounded storage | You operate multiple systems | Less infra, more vendor lock-in |

## Security Model

Rabta is designed to be trust-minimized, not magic.

- **Verifies:** Ed25519 signatures, event IDs, blob hashes, and canonical envelope rules.
- **Stores:** signed event envelopes, metadata visible in the envelope, and encrypted blob bytes on the node’s disk.
- **Does not do:** account management, server-side payload decryption, or key custody.
- **Your responsibility:** encrypt sensitive `data` and blobs client-side, protect private keys, and put public nodes behind TLS/reverse proxy controls when needed.

Read the full wire and threat-relevant details in the [API Reference](api.md).

## Get Started

- [Deploy with Docker](#quick-start)
- [Read the API Reference](api.md)
- [Visit rabta.space](https://rabta.space)
- [View releases](https://github.com/besoeasy/rabta/releases)
- [Report an issue](https://github.com/besoeasy/rabta/issues)

## License

Licensed under either MIT or Apache-2.0, at your option.