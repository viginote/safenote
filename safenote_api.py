"""
SafeNote — Community Safety Platform
FastAPI backend

Routes:
  GET  /                       — serves safenote_sa.html (the app)
  POST /api/reports            — anonymous incident submission
  GET  /api/reports/public     — delayed public feed (24h lag)
  GET  /api/reports/live       — NHW real-time feed (NHW token required)
  GET  /api/reports/stats      — summary counts for the map UI
  GET  /api/reports/heatmap    — aggregated heatmap data
  GET  /api/eskom/status       — Eskom load-shedding status (via EskomSePush)
  GET  /api/admin/reports      — full admin export (admin session required)
  GET  /api/admin/export       — CSV export for funding reports
  GET  /api/admin/nhw-tokens   — list NHW access tokens
  POST /api/admin/nhw-tokens   — create new NHW token
  DELETE /api/admin/nhw-tokens/{token} — revoke NHW token
  GET  /api/health             — service health check

Data stored per report:
  id, token (random UUID, device-side), type, severity, lat, lng,
  note (optional, max 200 chars), ts (UTC unix), created_at

NO names, emails, phone numbers or any PII ever stored.
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator
from typing import Optional, List
import sqlite3, uuid, time, os, hashlib, json, io, csv
import httpx
from datetime import datetime, timezone

app = FastAPI(title="SafeNote API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── CONFIG ────────────────────────────────────────────────────────────────────
DB_PATH        = os.environ.get("SAFENOTE_DB", "safenote.db")
NHW_SECRET     = os.environ.get("NHW_SECRET", "nhw-secret-change-me")
ADMIN_SECRET   = os.environ.get("ADMIN_SECRET", "admin-secret-change-me")
ESKOM_API_KEY  = os.environ.get("ESKOM_API_KEY", "")   # EskomSePush API key
PUBLIC_DELAY_S = int(os.environ.get("PUBLIC_DELAY_SECONDS", 86400))  # 24h default

VALID_TYPES = {
    # Violent
    "murder","shooting","stabbing","attempted_murder",
    # Robbery
    "hijacking","armed_robbery","mugging","house_robbery",
    # Property
    "burglary","vehicle_theft","theft","vandalism",
    # GBV
    "gbv","domestic","sexual_assault","child_abuse",
    # Suspicious
    "suspicious_person","suspicious_vehicle","loitering","drone_surveillance",
    # Drugs / Gangs
    "drug_dealing","gang_activity","illegal_firearm","extortion",
    # Infrastructure
    "cable_theft","illegal_connection","manhole_theft","road_blockage",
    # Community
    "fire","missing_person","illegal_dumping","other",
}

VALID_SEVERITIES = {"low","medium","high","critical"}

SEV_WEIGHTS = {"low":1,"medium":2,"high":3,"critical":4}

# ── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
    finally:
        con.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS reports (
            id          TEXT PRIMARY KEY,
            token       TEXT NOT NULL,
            type        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            lat         REAL NOT NULL,
            lng         REAL NOT NULL,
            note        TEXT,
            ts          INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            ip_hash     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_reports_ts  ON reports(ts);
        CREATE INDEX IF NOT EXISTS idx_reports_geo ON reports(lat, lng);
        CREATE TABLE IF NOT EXISTS nhw_tokens (
            token       TEXT PRIMARY KEY,
            label       TEXT,
            created_at  INTEGER
        );
        -- Seed pilot tokens
        INSERT OR IGNORE INTO nhw_tokens(token,label,created_at) VALUES
            ('NHW-PILOT1','Pilot NHW Group 1',strftime('%s','now')),
            ('NHW-PILOT2','Pilot NHW Group 2',strftime('%s','now')),
            ('NHW-PILOT3','Pilot NHW Group 3',strftime('%s','now'));
    """)
    con.commit()
    con.close()

init_db()

# ── MODELS ────────────────────────────────────────────────────────────────────
class ReportIn(BaseModel):
    type:     str
    severity: str
    lat:      float = Field(..., ge=-90, le=90)
    lng:      float = Field(..., ge=-180, le=180)
    note:     Optional[str] = None
    token:    Optional[str] = None  # device-generated UUID

    @validator("type")
    def valid_type(cls, v):
        if v not in VALID_TYPES:
            raise ValueError("Invalid incident type")
        return v

    @validator("severity")
    def valid_severity(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError("Invalid severity")
        return v

    @validator("note")
    def clean_note(cls, v):
        if v is None: return None
        v = v.strip()[:200]
        return v if v else None

    @validator("lat","lng")
    def sa_bounds(cls, v, field):
        # Loose SA bounding box check
        if field.name == "lat" and not (-35.0 <= v <= -22.0):
            raise ValueError("Coordinates appear to be outside South Africa")
        if field.name == "lng" and not (16.0 <= v <= 33.0):
            raise ValueError("Coordinates appear to be outside South Africa")
        return round(v, 5)  # limit precision to ~1m

# ── HELPERS ───────────────────────────────────────────────────────────────────
def ip_hash(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256(ip.encode()).hexdigest()[:16]

def row_to_dict(row) -> dict:
    return dict(row)

def is_nhw(authorization: Optional[str] = Header(None)) -> bool:
    if not authorization: return False
    token = authorization.replace("Bearer ","").strip()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    result = cur.execute("SELECT 1 FROM nhw_tokens WHERE token=?", (token,)).fetchone()
    con.close()
    return result is not None

def require_nhw(authorization: Optional[str] = Header(None)):
    if not is_nhw(authorization):
        raise HTTPException(status_code=401, detail="NHW token required")

def require_admin(authorization: Optional[str] = Header(None)):
    if not authorization or authorization.replace("Bearer ","").strip() != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Admin token required")

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.post("/api/reports", status_code=201)
async def submit_report(report: ReportIn, request: Request, db=Depends(get_db)):
    """
    Anonymous incident submission. No PII stored.
    Rate-limit: crude check on ip_hash — max 10 reports per hour per IP.
    """
    now = int(time.time())
    h = ip_hash(request)

    # Crude rate limiting — max 10 per hour per IP hash
    hour_ago = now - 3600
    recent_count = db.execute(
        "SELECT COUNT(*) FROM reports WHERE ip_hash=? AND created_at>?",
        (h, hour_ago)
    ).fetchone()[0]
    if recent_count >= 10:
        raise HTTPException(status_code=429, detail="Too many reports. Please try again later.")

    report_id = str(uuid.uuid4())
    token = report.token or str(uuid.uuid4())  # accept device token or generate one

    db.execute(
        """INSERT INTO reports(id,token,type,severity,lat,lng,note,ts,created_at,ip_hash)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (report_id, token, report.type, report.severity,
         report.lat, report.lng, report.note, now, now, h)
    )
    db.commit()

    return {
        "id": report_id,
        "token": token,
        "message": "Report received. Thank you for keeping your community safer."
    }


@app.get("/api/reports/public")
async def public_feed(db=Depends(get_db)):
    """
    Delayed public feed — returns reports older than PUBLIC_DELAY_S (default 24h).
    This prevents criminals using real-time patrol/incident data.
    Returns last 500 delayed reports.
    """
    cutoff = int(time.time()) - PUBLIC_DELAY_S
    rows = db.execute(
        """SELECT type,severity,lat,lng,note,ts
           FROM reports
           WHERE ts <= ?
           ORDER BY ts DESC
           LIMIT 500""",
        (cutoff,)
    ).fetchall()
    return {"reports": [row_to_dict(r) for r in rows], "delayed_hours": PUBLIC_DELAY_S // 3600}


@app.get("/api/reports/live")
async def live_feed(_=Depends(require_nhw), db=Depends(get_db)):
    """
    Real-time feed for verified NHW/CPF members.
    Returns last 100 reports with no delay.
    """
    rows = db.execute(
        """SELECT type,severity,lat,lng,note,ts
           FROM reports
           ORDER BY ts DESC
           LIMIT 100"""
    ).fetchall()
    return {"reports": [row_to_dict(r) for r in rows], "live": True}


@app.get("/api/reports/stats")
async def report_stats(db=Depends(get_db)):
    """Summary stats for the map UI bottom sheet."""
    now = int(time.time())
    today_start = now - 86400
    week_start  = now - 604800

    today = db.execute("SELECT COUNT(*) FROM reports WHERE ts > ?", (today_start,)).fetchone()[0]
    week  = db.execute("SELECT COUNT(*) FROM reports WHERE ts > ?", (week_start,)).fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    # Distinct areas = clusters of reports (approx: round lat/lng to 2dp = ~1km grid)
    areas = db.execute(
        "SELECT COUNT(DISTINCT round(lat,2)||','||round(lng,2)) FROM reports WHERE ts > ?",
        (week_start,)
    ).fetchone()[0]

    return {"today": today, "week": week, "total": total, "areas": areas}


@app.get("/api/reports/heatmap")
async def heatmap_data(db=Depends(get_db)):
    """
    Aggregated heatmap data — returns grid-level counts, not individual points.
    Safe for fully public consumption.
    """
    rows = db.execute(
        """SELECT round(lat,2) as glat, round(lng,2) as glng,
                  COUNT(*) as count,
                  MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                       WHEN 'medium' THEN 2 ELSE 1 END) as max_sev
           FROM reports
           GROUP BY round(lat,2), round(lng,2)
           ORDER BY count DESC
           LIMIT 300"""
    ).fetchall()
    return {"cells": [row_to_dict(r) for r in rows]}


@app.get("/api/eskom/status")
async def eskom_status():
    """
    Proxy to EskomSePush API.
    Returns simplified status: active, stage, next_off.
    Falls back gracefully if API key not set.
    """
    if not ESKOM_API_KEY:
        return {"active": False, "stage": 0, "next_off": "No Eskom API key configured", "source": "mock"}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                "https://developer.sepush.co.za/business/2.0/status",
                headers={"Token": ESKOM_API_KEY}
            )
            d = r.json()
            status = d.get("status", {})
            eskom = status.get("eskom", {})
            stage = int(eskom.get("stage", "0").replace("Stage ","") or 0)
            next_stages = eskom.get("next_stages", [])
            next_off = next_stages[0].get("stage", "No further stages") if next_stages else "Clear"
            return {
                "active": stage > 0,
                "stage": stage,
                "next_off": next_off,
                "raw": eskom.get("stage_updated","")
            }
    except Exception as e:
        return {"active": False, "stage": 0, "next_off": "Status unavailable", "error": str(e)}


# ── ADMIN ROUTES ──────────────────────────────────────────────────────────────

@app.get("/api/admin/reports")
async def admin_all_reports(
    limit: int = 500,
    offset: int = 0,
    type_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    days: int = 30,
    _=Depends(require_admin),
    db=Depends(get_db)
):
    """Full report access for admin — for funding dashboards and SAPS exports."""
    since = int(time.time()) - (days * 86400)
    where = ["ts > ?"]
    params = [since]
    if type_filter:
        where.append("type=?"); params.append(type_filter)
    if severity_filter:
        where.append("severity=?"); params.append(severity_filter)
    sql = f"SELECT id,type,severity,lat,lng,note,ts FROM reports WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = db.execute(sql, params).fetchall()
    count = db.execute(f"SELECT COUNT(*) FROM reports WHERE {' AND '.join(where)}", params[:-2]).fetchone()[0]
    return {"reports": [row_to_dict(r) for r in rows], "total": count, "days": days}


@app.get("/api/admin/export")
async def admin_export_csv(_=Depends(require_admin), db=Depends(get_db)):
    """
    CSV export — anonymised, suitable for funding applications and SAPS data sharing.
    No IP hashes in export, no tokens.
    """
    rows = db.execute(
        "SELECT type,severity,round(lat,3) as lat,round(lng,3) as lng,note,ts FROM reports ORDER BY ts DESC"
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc","type","severity","latitude","longitude","note"])
    for r in rows:
        writer.writerow([
            datetime.fromtimestamp(r["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
            r["type"], r["severity"],
            r["lat"], r["lng"],
            r["note"] or ""
        ])
    output.seek(0)
    filename = f"safenote_export_{datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/admin/nhw-tokens")
async def list_nhw_tokens(_=Depends(require_admin), db=Depends(get_db)):
    rows = db.execute("SELECT token,label,created_at FROM nhw_tokens ORDER BY created_at DESC").fetchall()
    return {"tokens": [row_to_dict(r) for r in rows]}


@app.post("/api/admin/nhw-tokens")
async def create_nhw_token(
    label: str,
    _=Depends(require_admin),
    db=Depends(get_db)
):
    """Create a new NHW access token for a CPF group."""
    token = "NHW-" + uuid.uuid4().hex[:6].upper()
    db.execute(
        "INSERT INTO nhw_tokens(token,label,created_at) VALUES(?,?,?)",
        (token, label, int(time.time()))
    )
    db.commit()
    return {"token": token, "label": label}


@app.delete("/api/admin/nhw-tokens/{token}")
async def revoke_nhw_token(token: str, _=Depends(require_admin), db=Depends(get_db)):
    db.execute("DELETE FROM nhw_tokens WHERE token=?", (token,))
    db.commit()
    return {"revoked": token}


# ── HEALTH CHECK ──────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "SafeNote", "ts": int(time.time())}


# ── STATIC SERVING ────────────────────────────────────────────────────────────
# Serves safenote_sa.html at / — the full app
# All /api/* routes above take priority due to FastAPI route ordering

HTML_FILE = os.path.join(os.path.dirname(__file__), "safenote_sa.html")

@app.get("/", include_in_schema=False)
async def serve_app():
    if not os.path.exists(HTML_FILE):
        raise HTTPException(status_code=404, detail="App file not found. Ensure safenote_sa.html is in the same directory as safenote_api.py.")
    return FileResponse(HTML_FILE, media_type="text/html")
