"""
SafeNote — Community Safety Platform
FastAPI backend

Routes:
  GET  /                            — serves safenote_sa.html (the app)
  POST /api/reports                 — anonymous incident submission
  GET  /api/reports/public          — delayed public feed (24h lag)
  GET  /api/reports/live            — NHW real-time feed (NHW token required)
  GET  /api/reports/stats           — summary counts for the map UI
  GET  /api/reports/heatmap         — aggregated heatmap data
  GET  /api/power/status            — scraped Eskom national stage (no API key)
  GET  /api/power/outages           — crowd-sourced outage clusters from reports
  GET  /api/power/outages/area      — outage status for a specific lat/lng area
  GET  /api/admin/reports           — full admin export (admin session required)
  GET  /api/admin/export            — CSV export for funding reports
  GET  /api/admin/nhw-tokens        — list NHW access tokens
  POST /api/admin/nhw-tokens        — create new NHW token
  DELETE /api/admin/nhw-tokens/{t}  — revoke NHW token
  GET  /api/health                  — service health check

Power outage system:
  - Users report outages as incident types: power_loadshedding, power_fault,
    power_partial, power_restored
  - API clusters reports within 500m radius / 2hr window
  - 1 report = REPORTED, 2+ reports = CONFIRMED
  - power_restored closes the cluster for that area
  - National stage scraped from Eskom public page (no API key required)
  - Scrape result cached for 30 minutes to avoid hammering

Data stored per report:
  id, token, type, severity, lat, lng, note, ts, created_at, ip_hash

NO names, emails, phone numbers or any PII ever stored.
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator
from typing import Optional, List
import sqlite3, uuid, time, os, hashlib, io, csv, math, re, urllib.parse

import httpx
from datetime import datetime, timezone

app = FastAPI(title="SafeNote API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── CONFIG ────────────────────────────────────────────────────────────────────
DB_PATH        = os.environ.get("SAFENOTE_DB", "safenote.db")
ADMIN_SECRET   = os.environ.get("ADMIN_SECRET", "admin-secret-change-me")
PUBLIC_DELAY_S = int(os.environ.get("PUBLIC_DELAY_SECONDS", 86400))

# Outage clustering config
OUTAGE_RADIUS_M   = 500    # metres — reports within this radius form a cluster
OUTAGE_WINDOW_S   = 7200   # 2 hours — reports older than this don't count
OUTAGE_CONFIRM_N  = 2      # reports needed to confirm an outage

# Eskom scrape cache
_eskom_cache = {"ts": 0, "data": None}
ESKOM_CACHE_TTL = 1800  # 30 minutes

# ── VALID INCIDENT TYPES ──────────────────────────────────────────────────────
VALID_TYPES = {
    "murder","shooting","stabbing","attempted_murder",
    "hijacking","armed_robbery","mugging","house_robbery","atm_robbery",
    "burglary","vehicle_theft","theft","vandalism",
    "gbv","domestic","sexual_assault","child_abuse",
    "suspicious_person","suspicious_vehicle","loitering",
    "drone_surveillance","casing","following",
    "drug_dealing","gang_activity","illegal_firearm","extortion",
    "cable_theft","illegal_connection","manhole_theft","road_blockage","water_cut",
    "fire","missing_person","illegal_dumping","protest_violence",
    "farm_attack","mob_justice","xenophobia","other",
    "power_loadshedding","power_fault","power_partial","power_restored",
}

VALID_INTEL_TYPES = {
    "drug_house","drug_distribution","gang_house",
    "weapons_cache","stolen_goods","chop_shop",
}

POWER_TYPES = {
    "power_loadshedding", "power_fault", "power_partial", "power_restored"
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# ── DATABASE ──────────────────────────────────────────────────────────────────
def get_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA busy_timeout=5000')
    try:
        yield con
    finally:
        con.close()

def init_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.execute('PRAGMA busy_timeout=5000')
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
        CREATE INDEX IF NOT EXISTS idx_reports_ts   ON reports(ts);
        CREATE INDEX IF NOT EXISTS idx_reports_geo  ON reports(lat, lng);
        CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);

        CREATE TABLE IF NOT EXISTS nhw_tokens (
            token       TEXT PRIMARY KEY,
            label       TEXT,
            created_at  INTEGER
        );
        CREATE TABLE IF NOT EXISTS eskom_cache (
            id          INTEGER PRIMARY KEY CHECK (id=1),
            stage       INTEGER DEFAULT 0,
            active      INTEGER DEFAULT 0,
            note        TEXT,
            source      TEXT,
            scraped_at  INTEGER
        );
        CREATE TABLE IF NOT EXISTS intel_locations (
            id          TEXT PRIMARY KEY,
            type        TEXT NOT NULL,
            duration    TEXT,
            lat         REAL NOT NULL,
            lng         REAL NOT NULL,
            note        TEXT,
            ts          INTEGER NOT NULL,
            ip_hash     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_intel_geo ON intel_locations(lat, lng);
    """)
    con.commit()
    con.close()

init_db()

# ── MODELS ────────────────────────────────────────────────────────────────────
class ReportIn(BaseModel):
    type:     str
    severity: str
    lat:      float = Field(..., ge=-90,  le=90)
    lng:      float = Field(..., ge=-180, le=180)
    note:     Optional[str] = None
    token:    Optional[str] = None

    @validator("type")
    def valid_type(cls, v):
        if v not in VALID_TYPES:
            raise ValueError(f"Invalid incident type: {v}")
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

    @validator("lat")
    def check_lat(cls, v):
        if not (-35.0 <= v <= -22.0):
            raise ValueError("Latitude outside South Africa bounds")
        return round(v, 5)

    @validator("lng")
    def check_lng(cls, v):
        if not (16.0 <= v <= 33.0):
            raise ValueError("Longitude outside South Africa bounds")
        return round(v, 5)

# ── HELPERS ───────────────────────────────────────────────────────────────────
def ip_hash(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256(ip.encode()).hexdigest()[:16]

def row_to_dict(row) -> dict:
    return dict(row)

def require_nhw(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="NHW token required")
    token = authorization.replace("Bearer ", "").strip()
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    result = con.execute(
        "SELECT 1 FROM nhw_tokens WHERE token=?", (token,)
    ).fetchone()
    con.close()
    if not result:
        raise HTTPException(status_code=401, detail="Invalid NHW token")

def require_admin(authorization: Optional[str] = Header(None)):
    if not authorization or \
       authorization.replace("Bearer ", "").strip() != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Admin token required")

def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Distance in metres between two lat/lng points."""
    R = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi  = math.radians(lat2 - lat1)
    dlam  = math.radians(lng2 - lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

# ── ESKOM SCRAPER (no API key) ────────────────────────────────────────────────
async def scrape_eskom_stage() -> dict:
    """
    Scrapes the national load-shedding stage from Eskom's public status page.
    No API key required. Cached for ESKOM_CACHE_TTL seconds.
    Falls back to crowd-sourced stage estimate if scrape fails.
    """
    global _eskom_cache
    now = int(time.time())

    # Return cached result if fresh
    if _eskom_cache["data"] and (now - _eskom_cache["ts"]) < ESKOM_CACHE_TTL:
        return _eskom_cache["data"]

    result = {"active": False, "stage": 0, "note": "No load-shedding", "source": "scrape"}

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            # Primary: Eskom's own status endpoint (returns JSON, no key needed)
            r = await client.get(
                "https://loadshedding.eskom.co.za/LoadShedding/GetStatus",
                headers={"User-Agent": "SafeNote-Community-App/1.0"}
            )
            if r.status_code == 200:
                text = r.text.strip()
                # Returns a single integer: 1=no shedding, 2=stage1, 3=stage2 etc
                val = int(text)
                stage = max(0, val - 1)
                result = {
                    "active": stage > 0,
                    "stage": stage,
                    "note": f"Stage {stage}" if stage > 0 else "No load-shedding",
                    "source": "eskom_official"
                }
    except Exception:
        # Fallback: try poweroutage.co.za public page
        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                r = await client.get(
                    "https://poweroutage.co.za/",
                    headers={"User-Agent": "SafeNote-Community-App/1.0"}
                )
                if r.status_code == 200:
                    html = r.text
                    # Look for stage pattern in page
                    m = re.search(r'[Ss]tage\s+(\d)', html)
                    if m:
                        stage = int(m.group(1))
                        result = {
                            "active": stage > 0,
                            "stage": stage,
                            "note": f"Stage {stage} (via poweroutage.co.za)",
                            "source": "poweroutage_scrape"
                        }
        except Exception:
            result["note"] = "Status unavailable — showing community reports only"
            result["source"] = "unavailable"

    _eskom_cache = {"ts": now, "data": result}
    return result


def cluster_outage_reports(reports: list) -> list:
    """
    Groups power outage reports into geographic clusters.
    Each cluster within OUTAGE_RADIUS_M and OUTAGE_WINDOW_S
    is returned with status: CONFIRMED (2+ reports) or REPORTED (1 report).
    power_restored reports cancel any cluster at that location.
    """
    now = int(time.time())
    window_start = now - OUTAGE_WINDOW_S

    # Only recent, non-restoration reports
    active = [r for r in reports
              if r["ts"] >= window_start
              and r["type"] != "power_restored"]

    # Restoration reports — used to cancel clusters
    restorations = [r for r in reports
                    if r["ts"] >= window_start
                    and r["type"] == "power_restored"]

    clusters = []
    assigned = set()

    for i, anchor in enumerate(active):
        if i in assigned:
            continue
        group = [anchor]
        assigned.add(i)
        for j, other in enumerate(active):
            if j in assigned:
                continue
            dist = haversine_m(anchor["lat"], anchor["lng"],
                               other["lat"],  other["lng"])
            if dist <= OUTAGE_RADIUS_M:
                group.append(other)
                assigned.add(j)

        # Check if this cluster has been restored
        center_lat = sum(r["lat"] for r in group) / len(group)
        center_lng = sum(r["lng"] for r in group) / len(group)

        restored = any(
            haversine_m(center_lat, center_lng, r["lat"], r["lng"]) <= OUTAGE_RADIUS_M
            for r in restorations
        )
        if restored:
            continue

        # Determine dominant outage type
        types = [r["type"] for r in group]
        dominant = max(set(types), key=types.count)

        clusters.append({
            "lat":     round(center_lat, 4),
            "lng":     round(center_lng, 4),
            "count":   len(group),
            "status":  "CONFIRMED" if len(group) >= OUTAGE_CONFIRM_N else "REPORTED",
            "type":    dominant,
            "type_label": {
                "power_loadshedding": "Load-shedding",
                "power_fault":        "Power Fault",
                "power_partial":      "Partial Outage",
            }.get(dominant, "Outage"),
            "oldest_ts": min(r["ts"] for r in group),
            "newest_ts": max(r["ts"] for r in group),
        })

    return clusters


# ── REPORT ROUTES ─────────────────────────────────────────────────────────────

@app.post("/api/reports", status_code=201)
async def submit_report(report: ReportIn, request: Request, db=Depends(get_db)):
    """Anonymous incident submission. No PII stored. Max 10 reports/hour/IP."""
    now = int(time.time())
    h   = ip_hash(request)

    recent = db.execute(
        "SELECT COUNT(*) FROM reports WHERE ip_hash=? AND created_at>?",
        (h, now - 3600)
    ).fetchone()[0]
    if recent >= 10:
        raise HTTPException(status_code=429,
            detail="Too many reports. Please try again later.")

    report_id = str(uuid.uuid4())
    token     = report.token or str(uuid.uuid4())

    db.execute(
        """INSERT INTO reports(id,token,type,severity,lat,lng,note,ts,created_at,ip_hash)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (report_id, token, report.type, report.severity,
         report.lat, report.lng, report.note, now, now, h)
    )
    db.commit()

    # If this is a power report, return the updated cluster status for the area
    extra = {}
    if report.type in POWER_TYPES:
        rows = db.execute(
            """SELECT type,lat,lng,ts FROM reports
               WHERE type IN ('power_loadshedding','power_fault',
                              'power_partial','power_restored')
               AND ts > ?""",
            (now - OUTAGE_WINDOW_S,)
        ).fetchall()
        clusters = cluster_outage_reports([row_to_dict(r) for r in rows])
        extra["outage_clusters"] = clusters

    return {
        "id": report_id,
        "token": token,
        "message": "Report received. Thank you for keeping your community safer.",
        **extra
    }


@app.get("/api/reports/public")
async def public_feed(db=Depends(get_db)):
    """Delayed public feed — 24h lag to prevent criminal use of real-time data."""
    cutoff = int(time.time()) - PUBLIC_DELAY_S
    rows = db.execute(
        """SELECT type,severity,lat,lng,note,ts FROM reports
           WHERE ts <= ? AND type NOT IN
             ('power_loadshedding','power_fault','power_partial','power_restored')
           ORDER BY ts DESC LIMIT 500""",
        (cutoff,)
    ).fetchall()
    return {"reports": [row_to_dict(r) for r in rows],
            "delayed_hours": PUBLIC_DELAY_S // 3600}


@app.get("/api/reports/live")
async def live_feed(_=Depends(require_nhw), db=Depends(get_db)):
    """Real-time feed for verified NHW/CPF members — no delay, all types."""
    rows = db.execute(
        """SELECT type,severity,lat,lng,note,ts FROM reports
           ORDER BY ts DESC LIMIT 100"""
    ).fetchall()
    return {"reports": [row_to_dict(r) for r in rows], "live": True}


@app.get("/api/reports/stats")
async def report_stats(db=Depends(get_db)):
    """Summary counts for the map UI bottom sheet."""
    now        = int(time.time())
    today_s    = now - 86400
    week_s     = now - 604800

    today  = db.execute("SELECT COUNT(*) FROM reports WHERE ts>?", (today_s,)).fetchone()[0]
    week   = db.execute("SELECT COUNT(*) FROM reports WHERE ts>?", (week_s,)).fetchone()[0]
    total  = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    areas  = db.execute(
        "SELECT COUNT(DISTINCT round(lat,2)||','||round(lng,2)) FROM reports WHERE ts>?",
        (week_s,)
    ).fetchone()[0]
    outages = db.execute(
        "SELECT COUNT(*) FROM reports WHERE type LIKE 'power_%' AND ts>?",
        (today_s,)
    ).fetchone()[0]

    return {"today": today, "week": week, "total": total,
            "areas": areas, "outages_today": outages}


@app.get("/api/reports/heatmap")
async def heatmap_data(db=Depends(get_db)):
    """Aggregated grid heatmap — safe for public consumption."""
    rows = db.execute(
        """SELECT round(lat,2) as glat, round(lng,2) as glng,
                  COUNT(*) as count,
                  MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                      WHEN 'medium' THEN 2 ELSE 1 END) as max_sev
           FROM reports
           WHERE type NOT LIKE 'power_%'
           GROUP BY round(lat,2), round(lng,2)
           ORDER BY count DESC LIMIT 300"""
    ).fetchall()
    return {"cells": [row_to_dict(r) for r in rows]}


# ── POWER OUTAGE ROUTES ───────────────────────────────────────────────────────

@app.get("/api/power/status")
async def power_status(db=Depends(get_db)):
    """
    Combined power status:
    - National stage scraped from Eskom (no API key, cached 30 min)
    - Community-reported outage cluster count
    - Active confirmed outage areas
    """
    eskom   = await scrape_eskom_stage()
    now     = int(time.time())

    rows = db.execute(
        """SELECT type,lat,lng,ts FROM reports
           WHERE type IN ('power_loadshedding','power_fault',
                          'power_partial','power_restored')
           AND ts > ?""",
        (now - OUTAGE_WINDOW_S,)
    ).fetchall()

    clusters  = cluster_outage_reports([row_to_dict(r) for r in rows])
    confirmed = [c for c in clusters if c["status"] == "CONFIRMED"]
    reported  = [c for c in clusters if c["status"] == "REPORTED"]

    return {
        "national": eskom,
        "community": {
            "confirmed_outages": len(confirmed),
            "reported_outages":  len(reported),
            "clusters":          clusters,
        },
        "summary": (
            f"Stage {eskom['stage']} nationally · "
            f"{len(confirmed)} confirmed outage area{'s' if len(confirmed)!=1 else ''}"
            if eskom["active"] else
            f"No national load-shedding · "
            f"{len(confirmed)} confirmed fault{'s' if len(confirmed)!=1 else ''} reported"
        ) if clusters else (
            f"Stage {eskom['stage']} nationally — no community reports yet"
            if eskom["active"] else
            "No load-shedding and no community outage reports"
        ),
        "ts": now,
    }


@app.get("/api/power/outages")
async def power_outages(db=Depends(get_db)):
    """
    All active outage clusters from community reports.
    Public — used to draw the outage overlay on the map.
    No delay applied (outage info should be real-time).
    """
    now  = int(time.time())
    rows = db.execute(
        """SELECT type,lat,lng,ts FROM reports
           WHERE type IN ('power_loadshedding','power_fault',
                          'power_partial','power_restored')
           AND ts > ?""",
        (now - OUTAGE_WINDOW_S,)
    ).fetchall()

    clusters = cluster_outage_reports([row_to_dict(r) for r in rows])
    return {"clusters": clusters, "window_hours": OUTAGE_WINDOW_S // 3600}


@app.get("/api/power/outages/area")
async def power_outage_area(
    lat: float = Query(..., ge=-35.0, le=-22.0),
    lng: float = Query(..., ge=16.0,  le=33.0),
    db=Depends(get_db)
):
    """
    Is there an outage near a specific point?
    Returns the closest cluster within OUTAGE_RADIUS_M, if any.
    Used by the frontend to show a localised outage warning.
    """
    now  = int(time.time())
    rows = db.execute(
        """SELECT type,lat,lng,ts FROM reports
           WHERE type IN ('power_loadshedding','power_fault',
                          'power_partial','power_restored')
           AND ts > ?""",
        (now - OUTAGE_WINDOW_S,)
    ).fetchall()

    clusters = cluster_outage_reports([row_to_dict(r) for r in rows])

    nearby = []
    for c in clusters:
        dist = haversine_m(lat, lng, c["lat"], c["lng"])
        if dist <= OUTAGE_RADIUS_M * 2:  # slightly wider search radius
            nearby.append({**c, "distance_m": round(dist)})

    nearby.sort(key=lambda x: x["distance_m"])
    closest = nearby[0] if nearby else None

    return {
        "has_outage": closest is not None,
        "closest":    closest,
        "all_nearby": nearby[:5],
    }


# ── ADMIN ROUTES ──────────────────────────────────────────────────────────────

@app.get("/api/admin/reports")
async def admin_all_reports(
    limit:           int = 500,
    offset:          int = 0,
    type_filter:     Optional[str] = None,
    severity_filter: Optional[str] = None,
    days:            int = 30,
    _=Depends(require_admin),
    db=Depends(get_db)
):
    """Full report access for admin — for funding dashboards and SAPS exports."""
    since  = int(time.time()) - (days * 86400)
    where  = ["ts > ?"]
    params = [since]
    if type_filter:
        where.append("type=?");     params.append(type_filter)
    if severity_filter:
        where.append("severity=?"); params.append(severity_filter)

    sql   = (f"SELECT id,type,severity,lat,lng,note,ts FROM reports "
             f"WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT ? OFFSET ?")
    count_sql = f"SELECT COUNT(*) FROM reports WHERE {' AND '.join(where)}"
    rows  = db.execute(sql, params + [limit, offset]).fetchall()
    count = db.execute(count_sql, params).fetchone()[0]

    return {"reports": [row_to_dict(r) for r in rows],
            "total": count, "days": days}


@app.get("/api/admin/export")
async def admin_export_csv(_=Depends(require_admin), db=Depends(get_db)):
    """CSV export — anonymised, suitable for funding applications."""
    rows = db.execute(
        """SELECT type,severity,round(lat,3) as lat,round(lng,3) as lng,note,ts
           FROM reports ORDER BY ts DESC"""
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc","type","severity","latitude","longitude","note"])
    for r in rows:
        writer.writerow([
            datetime.fromtimestamp(r["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
            r["type"], r["severity"], r["lat"], r["lng"], r["note"] or ""
        ])
    output.seek(0)
    fname = f"safenote_export_{datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )


@app.get("/api/admin/nhw-tokens")
async def list_nhw_tokens(_=Depends(require_admin), db=Depends(get_db)):
    rows = db.execute(
        "SELECT token,label,created_at FROM nhw_tokens ORDER BY created_at DESC"
    ).fetchall()
    return {"tokens": [row_to_dict(r) for r in rows]}


@app.post("/api/admin/nhw-tokens")
async def create_nhw_token(label: str, _=Depends(require_admin), db=Depends(get_db)):
    """Create a new NHW access token for a CPF group."""
    token = "NHW-" + uuid.uuid4().hex[:10].upper()
    db.execute("INSERT INTO nhw_tokens(token,label,created_at) VALUES(?,?,?)",
               (token, label, int(time.time())))
    db.commit()
    return {"token": token, "label": label}


@app.delete("/api/admin/nhw-tokens/{token}")
async def revoke_nhw_token(token: str, _=Depends(require_admin), db=Depends(get_db)):
    db.execute("DELETE FROM nhw_tokens WHERE token=?", (token,))
    db.commit()
    return {"revoked": token}


# ── INTEL LOCATION MODEL ─────────────────────────────────────────────────────

class IntelIn(BaseModel):
    type:     str
    duration: Optional[str] = "unknown"
    lat:      float = Field(..., ge=-90, le=90)
    lng:      float = Field(..., ge=-180, le=180)
    note:     Optional[str] = None

    @validator("type")
    def valid_type(cls, v):
        if v not in VALID_INTEL_TYPES:
            raise ValueError(f"Invalid intel type: {v}")
        return v

    @validator("note")
    def clean_note(cls, v):
        if v is None: return None
        v = v.strip()[:300]
        return v if v else None

    @validator("lat")
    def check_lat(cls, v):
        if not (-35.5 <= v <= -31.0):
            raise ValueError("Outside Western Cape bounds")
        return round(v, 5)

    @validator("lng")
    def check_lng(cls, v):
        if not (17.8 <= v <= 22.0):
            raise ValueError("Outside Western Cape bounds")
        return round(v, 5)


# ── INTEL ROUTES ──────────────────────────────────────────────────────────────

@app.post("/api/intel/report", status_code=201)
async def submit_intel(report: IntelIn, request: Request, db=Depends(get_db)):
    """
    Anonymous intel report — drug houses, gang houses etc.
    Stored separately, never shown on public map.
    Rate-limit: 3 per hour per IP (stricter — these are serious reports).
    """
    now = int(time.time())
    h   = ip_hash(request)

    recent = db.execute(
        "SELECT COUNT(*) FROM intel_locations WHERE ip_hash=? AND ts>?",
        (h, now - 3600)
    ).fetchone()[0]
    if recent >= 3:
        raise HTTPException(status_code=429,
            detail="Too many intel reports. Please try again later.")

    report_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO intel_locations(id,type,duration,lat,lng,note,ts,ip_hash) VALUES(?,?,?,?,?,?,?,?)",
        (report_id, report.type, report.duration,
         report.lat, report.lng, report.note, now, h)
    )
    db.commit()
    return {"id": report_id, "message": "Intel report received. Stored securely."}


@app.get("/api/intel/locations")
async def get_intel_locations(_=Depends(require_nhw), db=Depends(get_db)):
    """
    NHW/CPF and admin only — never public.
    Returns all active intel location markers for the map.
    """
    rows = db.execute(
        "SELECT type,duration,lat,lng,note,ts FROM intel_locations ORDER BY ts DESC LIMIT 200"
    ).fetchall()
    return {"locations": [row_to_dict(r) for r in rows]}


@app.get("/api/admin/intel")
async def admin_intel(_=Depends(require_admin), db=Depends(get_db)):
    """Full intel export for SAPS packages — admin only."""
    rows = db.execute(
        "SELECT id,type,duration,round(lat,3) as lat,round(lng,3) as lng,note,ts FROM intel_locations ORDER BY ts DESC"
    ).fetchall()
    return {"locations": [row_to_dict(r) for r in rows], "total": len(rows)}



# ── SUBURB BOUNDARY PROXY ─────────────────────────────────────────────────────
# Calls Nominatim server-side — avoids browser CORS issues entirely.
# Results cached in memory for the life of the process.

_suburb_boundary_cache: dict = {}

@app.get("/api/suburb/boundary")
async def suburb_boundary(name: str = Query(..., min_length=2, max_length=80)):
    """
    Fetch suburb GeoJSON boundary from Nominatim, server-side.
    Cached in memory. Returns {geojson, lat, lng, bbox} or 404.
    """
    key = name.lower().strip()
    if key in _suburb_boundary_cache:
        return _suburb_boundary_cache[key]

    url = (
        "https://nominatim.openstreetmap.org/search"
        "?q=" + urllib.parse.quote(f"{name}, Western Cape, South Africa", safe="")
        + "&format=json&limit=5&polygon_geojson=1&addressdetails=1"
    )

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await client.get(url, headers={
                "User-Agent": "SafeNote-WC-CommunityApp/1.0 (community safety platform)",
                "Accept": "application/json",
                "Accept-Language": "en"
            })
            results = r.json()

        # Pick best match — must be in Western Cape
        best = None
        prefer = {"suburb","neighbourhood","quarter","residential","town","village"}
        for res in results:
            addr = res.get("address", {})
            state = addr.get("state", "").lower()
            if "western cape" not in state and "wes-kaap" not in state:
                continue
            if best is None:
                best = res
            if res.get("type") in prefer:
                best = res
                break

        if not best or not best.get("geojson"):
            raise HTTPException(status_code=404,
                detail=f"No boundary found for '{name}' in Western Cape")

        bounds = best.get("boundingbox")
        data = {
            "name":   name,
            "geojson": best["geojson"],
            "lat":    float(best["lat"]),
            "lng":    float(best["lon"]),
            "bbox": [
                [float(bounds[0]), float(bounds[2])],
                [float(bounds[1]), float(bounds[3])]
            ] if bounds else None,
            "type": best.get("type"),
            "display_name": best.get("display_name","")
        }
        _suburb_boundary_cache[key] = data
        return data

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503,
            detail=f"Boundary service unavailable: {str(e)}")

# ── NHW TOKEN VERIFY (public — used by frontend) ─────────────────────────────

class NhwVerifyIn(BaseModel):
    code: str

@app.post("/api/nhw/verify")
async def nhw_verify(body: NhwVerifyIn, db=Depends(get_db)):
    """
    Frontend calls this to verify an NHW access code without exposing
    the full token list. Returns {valid: true/false} only.
    """
    code = body.code.strip().upper()
    result = db.execute(
        "SELECT 1 FROM nhw_tokens WHERE token=?", (code,)
    ).fetchone()
    return {"valid": result is not None}


# ── HEALTH ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "SafeNote", "version": "1.1.0",
            "ts": int(time.time())}


# ── SERVE APP ─────────────────────────────────────────────────────────────────

HTML_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safenote_sa.html")

@app.get("/", include_in_schema=False)
async def serve_app():
    if not os.path.exists(HTML_FILE):
        raise HTTPException(status_code=404,
            detail="safenote_sa.html not found. "
                   "Ensure it is in the same directory as safenote_api.py.")
    return FileResponse(HTML_FILE, media_type="text/html")
