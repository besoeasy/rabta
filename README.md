# Rabta

**The self-healing sync relay for local-first apps and peer meshes.**

Rabta is an append-only, content-addressed sync relay for signed events and encrypted files. It runs as a single lightweight binary or Docker container with zero external dependencies, no database servers to manage, and no schema migrations.

![API v1](https://img.shields.io/badge/API-v1-blue)
![Platforms](https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-informational)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green)

[**API Reference**](api.md) · [**Quick Start**](#quick-start) · [**Configuration**](#configuration)

---

## What Problem Does It Solve?

Building sync for decentralized, local-first, or edge applications traditionally requires complex cloud backends:
- **Centralized Cloud Lock-in**: Heavy dependence on managed cloud platforms or proprietary services.
- **Operational Burden**: Managing and babysitting database clusters, replication topologies, migrations, and message brokers.
- **Trust Assumptions**: Servers have the power to view, modify, or forge user records.
- **Network Brittleness**: Systems break or fail when nodes operate offline, across intermittent links, or at the edge.

## Why Do You Need Rabta?

Rabta provides a self-contained, trust-minimized building block:
- **Zero Babysitting**: Single static binary or container. SQLite, blob storage, and peer sync are completely self-managed and embedded.
- **Cryptographic Trust**: Every event is Ed25519-signed and verified. Relays and peers cannot forge or tamper with records.
- **Zero-Knowledge Blob Storage**: Attached files must be encrypted client-side (`RABTA1` container). The relay stores content-addressed encrypted blobs without ever holding decryption keys.
- **Autonomous Peer-to-Peer Sync**: Connect nodes with a single environment variable (`SYNC`). Nodes exchange range summaries and self-heal missing records in 1 round trip.
- **Bounded Resources & Abuse Resistance**: Built-in work battery rate-limiting, storage watermarks, and automated TTL/storage-pressure eviction ensure nodes never exceed their hardware limits.

---

## Quick Start

### Docker

Run the official image with Docker:

```bash
docker run -d \
  --name rabta \
  -p 127.0.0.1:3232:3232 \
  -v rabta-data:/data \
  --restart unless-stopped \
  -e STORAGE=20GB \
  ghcr.io/besoeasy/rabta:latest
```

Verify your node is online:

```bash
curl -fsS http://localhost:3232/api/v1/health
curl -fsS http://localhost:3232/api/v1/node
```

Visit `http://localhost:3232/` in your browser to inspect the node's built-in status dashboard.

### Native Linux Install

Prebuilt static musl binaries are available for `x86_64` (amd64) and `aarch64` (arm64) on each [Release](https://github.com/besoeasy/rabta/releases/latest). No runtime dependencies or glibc required.

```bash
# Download the binary (for x86_64 / amd64)
curl -fsSL https://github.com/besoeasy/rabta/releases/latest/download/rabta-linux-amd64 -o rabta
chmod +x rabta

# Run directly
DATA=./data PORT=3232 ./rabta
```

*(For ARM64 devices such as Raspberry Pi or AWS Graviton, download `rabta-linux-arm64`.)*

---

## Configuration

Configure Rabta via environment variables or by placing a `/data/config.env` file. Environment variables take precedence.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3232` | TCP port for the HTTP API and dashboard. |
| `DATA` | `/data` | Path to the directory where SQLite database, blobs, and keys are stored. |
| `STORAGE` | `20GB` | Maximum disk storage for events and blobs before pressure eviction triggers. |
| `POLICY` | *None* | JSON rules exempting matching events/blobs from pressure eviction (e.g. `{"rules":[{"owner":["ed25519:..."]}]}`). TTL expiry still applies. |
| `SYNC` | *None* | Comma-separated list of up to 4 peer relay URLs (e.g. `https://relay-a.space,https://relay-b.space`). |
| `REGEN` | `20`–`40` | Battery units regenerated per second (out of `1,000,000` capacity). Random by default. |
| `BITCOIN` | *None* | Optional on-chain Bitcoin donation address displayed on `GET /api/v1/node` and the web dashboard. |
| `RUST_LOG` | `info` | Logging verbosity (`error`, `warn`, `info`, `debug`). |

---

## How It Works

1. **Publish Event**: Clients sign an envelope with their Ed25519 private key and submit it to `POST /api/v1/events`.
2. **Attach Blobs**: Large files are encrypted client-side and uploaded via `PUT /api/v1/blobs`. Events reference blobs by SHA-256 hash.
3. **Query**: Clients query events by collection, owner, tags, or time ranges with conditional caching (`ETag` / `If-None-Match`) via `GET /api/v1/events`.
4. **Reconcile**: Nodes periodically exchange signed `POST /api/v1/sync` requests containing XOR range summaries to pinpoint and transfer missing records with minimal bandwidth.

See [**api.md**](api.md) for the complete API reference and schema details.

---

## License

Licensed under either MIT or Apache-2.0, at your option.
