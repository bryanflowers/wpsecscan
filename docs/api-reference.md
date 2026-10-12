# WPSecScan daemon — full API reference

Round-64 #147 — narrative reference for the REST API. Pairs with the
formal OpenAPI spec at [openapi/wpsecscan-api.yaml](../openapi/wpsecscan-api.yaml).

## Embedded API server (`wpsecscan --api-server HOST:PORT`)

The stdlib HTTP server started with `--api-server` (token via `--api-token`
or `WPSECSCAN_API_TOKEN`; it refuses to start without one) exposes:

| Endpoint | Purpose |
|----------|---------|
| `GET /healthz` | `{"ok": true}` |
| `GET /history?url=<url>` | Past scans for a URL |
| `POST /scan` | Start a scan in the background |
| `GET /scan/<task_id>` | Status and, when done, the report |
| `GET /reports/<filename>` | A saved JSON snapshot |
| `GET /openapi.json` | Minimal OpenAPI 3 document |

`POST /scan` request body:

```json
{ "target": "https://example.com", "aggressive": false, "owned": false }
```

- `owned` (boolean): `true` marks the target as owned for this request.
  Aggressive checks run only when consent resolves, from `owned: true`, the
  `WPSECSCAN_OWNED_TARGETS` environment variable, or the owned-targets file
  (`wpsecscan owned add <host>`). Otherwise the scan is downgraded to passive.
- The `202` response is `{"task_id": "...", "status": "running", "consent": "..."}`
  where `consent` is `granted`, `downgraded` (aggressive was requested but
  no consent resolved, so the scan runs passive) or `n/a` (not aggressive).
- Target allowlist: when `WPSECSCAN_API_ALLOWED_TARGETS` is set (comma-separated
  hosts; `example.com` exact, `*.example.com` for subdomains, `*` for all),
  `POST /scan` for any other host returns `403` before a scan starts. When it
  is unset, any target is accepted.
- `429` when the concurrent-scan cap is reached.

The sections below describe the planned daemon / multi-tenant API (JWT
login, `/scans`, `/sites`, tenants). The embedded server above implements
only the endpoints in the table.

## Auth

All endpoints require a Bearer JWT in `Authorization: Bearer <token>`.
Obtain a token via:

```bash
wpsecscan daemon login --username admin
```

The token is OIDC-signed when SSO is configured (see
`wpsecscan/auth/sso_oidc.py`); otherwise HMAC-signed with a local
key.

## Endpoints

### POST /scans

Start a scan.

Request:
```json
{
  "target": "https://example.com",
  "aggressive": false,
  "authenticated": false
}
```

Response 202:
```json
{ "scan_id": "scan_abc123" }
```

### GET /scans/:id

Fetch scan status + summary.

Response:
```json
{
  "scan_id": "scan_abc123",
  "target": "https://example.com",
  "status": "complete",
  "summary": { "critical": 0, "high": 2, "medium": 5, "low": 12, "info": 8 },
  "risk_score": 42,
  "scanned_at": "2026-05-24T02:00:00Z"
}
```

Status is one of `running`, `complete`, `failed`.

### GET /scans/:id/findings

List findings. Optional `?severity=critical|high|medium|low|info`.

### POST /sites

Add a site.

Request:
```json
{
  "name": "example",
  "url": "https://example.com",
  "scan_interval_hours": 24,
  "notify_slack_webhook": "https://hooks.slack.com/..."
}
```

### Webhook v2

Outbound webhooks are signed with HMAC-SHA256 over
`<timestamp>.<nonce>.<body>`. See `wpsecscan/daemon/webhook_v2.py` for
verification code in Python; the SDKs include equivalent helpers.

Headers sent:
- `X-Wpsec-Timestamp` — unix seconds
- `X-Wpsec-Nonce` — random per-delivery
- `X-Wpsec-Signature` — HMAC hex
- `Content-Type: application/json`

Receiver MUST:
1. Reject deliveries where `|now - timestamp| > 300s`
2. Reject replayed nonces (cache last 4096)
3. Compute the HMAC + compare with `hmac.compare_digest`

## RBAC

| Role     | Can call |
|----------|----------|
| reader   | GET /scans/*, GET /sites |
| operator | + POST /scans, POST/DELETE /sites |
| admin    | + everything (users, settings, billing) |

See `wpsecscan/auth/rbac.py` for the full permission matrix.

## Rate limits

The daemon enforces per-token rate limits:
- 60 scan requests / hour (default; configurable per tenant)
- 600 read requests / minute

Quota counter resets at UTC midnight (see `wpsecscan/enterprise/quota.py`).

## Errors

All errors return a JSON object:
```json
{ "error": "scan_not_found", "message": "No scan with id ..." }
```

Common codes: `scan_not_found`, `quota_exceeded`, `permission_denied`,
`invalid_target`, `aggressive_requires_approval`.

## Multi-tenant

When the daemon runs with `--multi-tenant`, every endpoint is
namespaced under `/tenants/:tenant_id/`. The token must contain a
`tenant_id` claim matching the URL.

## Versioning

The API follows semantic versioning. Breaking changes only in major
versions. The `X-Wpsec-Api-Version` response header reports the
running version.
