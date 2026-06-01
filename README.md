# SafeNote — Community Safety Platform

Anonymous incident reporting + AI-ready heatmap for South African communities.

## Quick start (local)

```bash
pip install -r requirements.txt
uvicorn safenote_api:app --reload --port 8001
```

Open `safenote.html` in browser (or serve it from FastAPI static files).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SAFENOTE_DB` | `safenote.db` | SQLite path (use absolute path on Render) |
| `NHW_SECRET` | `nhw-secret-change-me` | **Change this** — not used for token auth (tokens are in DB) |
| `ADMIN_SECRET` | `admin-secret-change-me` | **Change this** — bearer token for admin routes |
| `ESKOM_API_KEY` | _(empty)_ | EskomSePush API key — get free at eskomsepush.co.za |
| `PUBLIC_DELAY_SECONDS` | `86400` | Delay before reports appear on public map (default 24h) |

## Deploy on Render (same as VigiNote)

1. Push to GitHub repo
2. New Web Service → connect repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn safenote_api:app --host 0.0.0.0 --port $PORT`
5. Add environment variables above
6. Add a Render Disk for persistent SQLite storage, mount at `/data`, set `SAFENOTE_DB=/data/safenote.db`

## NHW token management

Create tokens via admin API:
```bash
curl -X POST "https://yourdomain/api/admin/nhw-tokens?label=Kensington+NHW" \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET"
```

Returns: `{"token": "NHW-A3F9B2", "label": "Kensington NHW"}`

Give this token to the CPF coordinator. They share it with verified patrol members.
Revoke at any time: `DELETE /api/admin/nhw-tokens/NHW-A3F9B2`

## Data protection (POPIA compliance)

- No names, emails or phone numbers are ever stored
- Device tokens are random UUIDs with no link to identity
- GPS coordinates are rounded to 5 decimal places (~1m precision) on receipt
- CSV export rounds to 3 decimal places (~100m) for SAPS/funding sharing
- IP addresses are one-way hashed (SHA-256, first 16 chars) for rate limiting only — never logged raw
- All data stored in SQLite on your own server — nothing sent to third parties except optional EskomSePush API call

## API summary

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/reports` | None | Submit anonymous report |
| GET | `/api/reports/public` | None | 24h-delayed public feed |
| GET | `/api/reports/live` | NHW token | Real-time NHW feed |
| GET | `/api/reports/stats` | None | Summary counts |
| GET | `/api/reports/heatmap` | None | Aggregated grid heatmap |
| GET | `/api/eskom/status` | None | Load-shedding status |
| GET | `/api/admin/reports` | Admin | Full report export |
| GET | `/api/admin/export` | Admin | CSV download |
| POST | `/api/admin/nhw-tokens` | Admin | Create NHW token |
| DELETE | `/api/admin/nhw-tokens/{token}` | Admin | Revoke NHW token |
