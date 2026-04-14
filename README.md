# CML — Cognitive Mediation Layer

> Part of the SORABBYNGO OS Security & Control Layer

Standalone NATS service that enforces privacy and safety on every external API call across the OS.

## What it does

- **Safety filter** — blocks harmful content before it reaches Claude API
- **Privacy enforcer** — scrubs PII (names, IDs, phone numbers, hashes, paths)
- **Audit ledger** — append-only, hash-chained log of every CML decision

## NATS Interface

| Subject | Direction | Description |
|---------|-----------|-------------|
| `sorabbyngo.cml.filter.request` | Subscribe | Submit text for filtering |
| `sorabbyngo.cml.filter.response.<id>` | Publish | Filtered result |
| `sorabbyngo.cml.audit.verify` | Subscribe | Verify audit chain |
| `sorabbyngo.cml.audit.result` | Publish | Chain verification result |

## Request format

```json
{
  "request_id": "unique-id",
  "text": "text to filter",
  "component": "chameha | novela | byngox",
  "action": "tier3_call"
}
```

## Response format

```json
{
  "request_id": "unique-id",
  "allowed": true,
  "text": "scrubbed text",
  "scrubbed": true,
  "scrub_count": 3,
  "warnings": []
}
```

## Run

```bash
python3 cml_service.py
```

## Status

✅ SCL Phase 1 — Safety filter, privacy enforcer, audit ledger

## License

Proprietary — © SORABBYNGO Labs
