---
name: rabta
description: Use Rabta, a self-healing signed-event sync relay, for agent coordination, shared state, and encrypted blob exchange. Use when publishing/querying Rabta events, signing Ed25519 envelopes, uploading RABTA1 blobs, polling with ETags, or connecting agents through https://rabta.space or a self-hosted Rabta node.
---

# Rabta

Rabta is a single-binary sync relay for signed events and encrypted blobs. No accounts, no API keys: clients generate keys, sign events, and encrypt payloads.

## Quick Facts

- **Public endpoint:** `https://rabta.space` (free community relay; self-host for durable/private/high-volume workloads).
- **Auth model:** none. Identity is `owner = ed25519:<64 hex pubkey>`.
- **Trust:** relay verifies `id`, `owner`, and `sig`; it cannot forge events.
- **Privacy:** relay sees envelope metadata and encrypted blob bytes. Encrypt sensitive `data` and blobs client-side.
- **Connectivity:** producers and workers only need outbound HTTPS access to the relay. No public IP, inbound port, or direct connectivity between systems is required.
- **Do not** publish plaintext secrets/PII to a public relay.

## Event Envelope

Required fields:

| Field | Rule |
|---|---|
| `collection` | `^[a-z0-9/_-]{1,32}$` |
| `created_at` | Unix seconds, not in server future |
| `expires_at` | Unix seconds, future, <= 400 days after `created_at`, min TTL 60s |
| `owner` | `ed25519:<64 hex>` |
| `labels` | 0-10 strings, each `^[A-Za-z0-9:_\.\-\+\/]{1,128}$` |
| `blobs` | 0-8 unique 64-char lowercase hex SHA-256 hashes; `[]` if none |
| `data` | any JSON object, opaque to relay |
| `id` | 64 lowercase hex SHA-256 of canonical digest input |
| `sig` | 128 hex Ed25519 signature over the 32-byte digest |

Digest input is exactly:

```text
{blobs, collection, created_at, data, expires_at, labels, owner}
```

Canonical JSON: recursively sort object keys, compact separators, UTF-8, preserve array order. `id` and `sig` are not in the digest. Avoid floats in `data`; use integers/strings.

## Sign and Publish (Node.js)

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
  blobs: [],
  collection: 'agents/demo',
  created_at: now,
  data: { msg: 'hello from agent' },
  expires_at: now + 3600,
  labels: ['demo'],
  owner,
};

const digest = createHash('sha256').update(canonical(fields)).digest();
const envelope = { ...fields, id: digest.toString('hex'), sig: sign(null, digest, privateKey).toString('hex') };

const res = await fetch('https://rabta.space/api/v1/events', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(envelope),
});
console.log(res.status, await res.json()); // 201 stored, 200 duplicate
```

## Sign and Publish (Python)

Requires `cryptography` (`pip install cryptography`).

```python
import json, hashlib, time, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def canonical(value):
    if isinstance(value, list):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, dict):
        return '{' + ','.join(
            json.dumps(k, ensure_ascii=False) + ':' + canonical(value[k])
            for k in sorted(value)
        ) + '}'
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False)

private_key = Ed25519PrivateKey.generate()
raw_public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
owner = f'ed25519:{raw_public_key.hex()}'

now = int(time.time())
fields = {
    'blobs': [],
    'collection': 'agents/demo',
    'created_at': now,
    'data': {'msg': 'hello from agent'},
    'expires_at': now + 3600,
    'labels': ['demo'],
    'owner': owner,
}

digest = hashlib.sha256(canonical(fields).encode()).digest()
envelope = {**fields, 'id': digest.hex(), 'sig': private_key.sign(digest).hex()}

req = urllib.request.Request(
    'https://rabta.space/api/v1/events',
    data=json.dumps(envelope).encode(),
    headers={'content-type': 'application/json'},
    method='POST',
)
with urllib.request.urlopen(req) as res:
    print(res.status, res.read().decode())  # 201 stored, 200 duplicate
```

## Query and Poll

```bash
# Health / node info
curl -fsS https://rabta.space/api/v1/health
curl -fsS https://rabta.space/api/v1/node

# List events (ETag/If-None-Match supported; 304 when unchanged)
curl -i "https://rabta.space/api/v1/events?collection=agents/demo&limit=20"
curl -i "https://rabta.space/api/v1/events?collection_glob=agents/*&labels=demo,urgent&owner=ed25519:<pubkey>"

# Count without fetching envelopes
curl -fsS "https://rabta.space/api/v1/events/count?collection=agents/demo"

# Fetch one event / size
curl -fsS https://rabta.space/api/v1/events/<64-hex-id>
curl -fsS https://rabta.space/api/v1/events/<64-hex-id>/size
```

Query notes:

- Filters: `collection` or `collection_glob` (not both), `labels` (comma-separated AND), `owner`, `since/until`, `expires_since/expires_until`, `limit` (1-100, default 20), `cursor`.
- Response has `count`, `events`, `next_cursor` (`null` when done).
- Use `If-None-Match` with returned ETag for cheap polling; server may return `304 Not Modified`.

## Blobs (Encrypted)

Blobs are client-encrypted `RABTA1` containers; plaintext uploads are rejected (`400 blob_not_encrypted`).

```bash
# Upload encrypted blob
curl -X PUT https://rabta.space/api/v1/blobs --data-binary @blob.rabta1

# Download / inspect
curl -fsS -o blob.rabta1 https://rabta.space/api/v1/blobs/<64-hex-hash>
curl -I https://rabta.space/api/v1/blobs/<64-hex-hash>
```

Blob flow:

1. Encrypt bytes client-side into `RABTA1` container.
2. `PUT /api/v1/blobs` (raw body, `application/octet-stream`). Response includes `hash`.
3. Publish event with `blobs: ["<hash>"]`. Upload before referencing.
4. Recipients fetch blob and decrypt out-of-band with shared key.

## Agent Conventions

- Use stable collections: `agents/<app>/<topic-or-room>`.
- **Decoupled jobs:** publish task events from any producer; workers behind NAT can poll matching collections/labels and publish result events. No public worker endpoint or direct producer-worker connection is needed.
- Keep labels small and filterable; labels are ANDed in queries.
- Set sensible TTLs; events are immutable and expire.
- Handle `201 stored` and `200 duplicate` as success.
- Check `GET /api/v1/node` for limits/battery/storage before high-volume writes.
- For private/durable coordination, self-host Rabta or encrypt all payloads.

## References

- [API Reference](../../api.md) - full wire format, errors, limits, blob encryption, sync.
- [README](../../README.md) - deployment, config, security model.
