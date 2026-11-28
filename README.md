<img width="1082" height="980" alt="image" src="https://github.com/user-attachments/assets/4ac8328e-310c-4d66-930f-95b87cbb8e53" />


# Rabta

**A simple data layer for anything you can express as an event.**

Rabta is an open-source, self-hosted event database. Write signed JSON records, query them by collection, owner, label, and time, attach encrypted files, and sync between nodes.

Use it as an app database or shared data store, an append-only log, an AI-agent memory or coordination bus, a job queue, or a place for telemetry and audit events. **Your app defines the data; Rabta stores and syncs it.** No fixed domain schema, managed database, or message broker.

> Rabta is an immutable event store, not a SQL database for in-place row updates. Events expire by TTL and storage pressure can evict data, so self-host it when you need control over retention and durability.

## Run with Docker

Docker is the fastest way to start a node. The named volume keeps its database and blobs across container restarts.

```bash
docker run -d \
  --name rabta \
  --restart unless-stopped \
  -p 3232:3232 \
  -v rabta-data:/data \
  -e STORAGE=20GB \
  ghcr.io/besoeasy/rabta:latest
```

Check it, then open the dashboard:

```bash
curl -fsS http://localhost:3232/api/v1/health
```

Visit [http://localhost:3232](http://localhost:3232). For an internet-facing node, put it behind HTTPS and choose a storage limit appropriate for your disk.

## Add Rabta to an AI agent

Install the Rabta skill in a compatible agent:

```bash
npx skills add besoeasy/rabta
```

The skill teaches agents how to create identities, sign and publish events, query and poll for updates, and exchange client-encrypted blobs. Point it at the public node for demos or your own node for private and durable workloads.

## The basic model

1. **Publish** a signed event: a collection, timestamps, labels, and your JSON data.
2. **Query** events over HTTP, or poll efficiently with ETags.
3. **Sync** nodes to reconcile missing events; attach encrypted blobs when a record needs files.

Events are immutable and signed by their authors. Rabta verifies the signature but does not control your schema or hold your keys. Encrypt sensitive data on the client; blob uploads must use Rabta's client-side encrypted format.

## Links

- [Website and public node](https://rabta.space/)
- [AI agent skill](skills/rabta/SKILL.md)
- [API reference](api.md)
- [Docker releases](https://github.com/besoeasy/rabta/pkgs/container/rabta)
- [All releases](https://github.com/besoeasy/rabta/releases)
- [License](#license)

## License

Licensed under either MIT or Apache-2.0, at your option.
