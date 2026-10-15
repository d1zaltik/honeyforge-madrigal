import uuid
import datetime
import json
import gzip
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Trap, AttackEvent, SessionLog, Profile, DEFAULT_DECOY_CREDENTIALS
from honeyforge_server.app.schemas import TelemetryBatchIn
from honeyforge_server.app.security import verify_agent_signature, decode_access_token
from honeyforge_server.app.alert_engine import process_event_for_alerts
from honeyforge_server.app.websocket_hub import ws_hub

router = APIRouter(tags=["Stealth Telemetry Ingestion"])

# 1x1 Transparent GIF pixel for CDN disguise
TRANSPARENT_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04"
    b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

async def _process_telemetry_batch(request: Request, db: AsyncSession):
    """
    Internal handler for stealth telemetry ingestion.
    Validates HMAC signature covering trap_id, timestamp, nonce, and SHA-256 of raw request body.
    Returns HTTP 204 No Content on signature failure to prevent reconnaissance.
    """
    raw_body = await request.body()
    try:
        # Decompress if payload was gzipped
        if request.headers.get("content-encoding") == "gzip":
            decoded_body = gzip.decompress(raw_body)
            body_dict = json.loads(decoded_body.decode("utf-8"))
        else:
            body_dict = json.loads(raw_body.decode("utf-8"))
    except Exception:
        # Invalid JSON or corrupted format: exact 404 Not Found matching non-existent route
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    trap_id = body_dict.get("trap_id") or body_dict.get("node_id") or request.headers.get("x-node-id")
    timestamp = request.headers.get("x-timestamp") or body_dict.get("timestamp")
    nonce = request.headers.get("x-nonce") or body_dict.get("nonce")
    signature = request.headers.get("x-signature") or body_dict.get("signature")

    if not trap_id or timestamp is None or not nonce or not signature:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    # 1. Look up trap
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    now = datetime.datetime.utcnow()
    if not trap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    # 2. Verify HMAC Signature covering raw body (MASK-1 & MASK-7)
    valid_sig = False
    if request.headers.get("x-signature"):
        valid_sig = verify_agent_signature(
            trap_id=trap_id,
            timestamp=float(timestamp),
            nonce=nonce,
            signature=signature,
            secret_key=trap.secret_key,
            raw_body=raw_body
        )
    if not valid_sig:
        temp_dict = dict(body_dict)
        temp_dict.pop("signature", None)
        clean_bytes = json.dumps(temp_dict, sort_keys=True).encode("utf-8")
        valid_sig = verify_agent_signature(
            trap_id=trap_id,
            timestamp=float(timestamp),
            nonce=nonce,
            signature=signature,
            secret_key=trap.secret_key,
            raw_body=clean_bytes
        )
    if not valid_sig:
        valid_sig = verify_agent_signature(
            trap_id=trap_id,
            timestamp=float(timestamp),
            nonce=nonce,
            signature=signature,
            secret_key=trap.secret_key,
            raw_body=raw_body
        )

    if not valid_sig:
        # Stealth response: exact 404 Not Found matching non-existent route
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    # 3. Update trap heartbeat & status
    trap.last_seen = now
    trap.status = "online"
    hb_data = body_dict.get("heartbeat")
    if hb_data and isinstance(hb_data, dict):
        trap.uptime_seconds = hb_data.get("uptime_seconds", trap.uptime_seconds)
        trap.cpu_usage = hb_data.get("cpu_usage", trap.cpu_usage)
        trap.mem_usage = hb_data.get("mem_usage", trap.mem_usage)
        trap.config_version = hb_data.get("config_version", trap.config_version)

    # Broadcast trap status update to SOC dashboard
    await ws_hub.broadcast("trap_heartbeat", {
        "trap_id": trap.trap_id,
        "name": trap.name,
        "status": "online",
        "last_seen": trap.last_seen.isoformat(),
        "uptime_seconds": trap.uptime_seconds,
        "cpu_usage": trap.cpu_usage,
        "mem_usage": trap.mem_usage
    })

    # 4. Ingest Attack Events with Deduplication (FR-A4)
    events_in = body_dict.get("events", [])
    saved_events = []
    seen_in_batch_uids = set()
    seen_in_batch_ids = set()
    for ev_data in events_in:
        ev_id = ev_data.get("event_id") or str(uuid.uuid4())
        ev_uid = ev_data.get("event_uid")

        # Deduplication check by event_uid or event_id
        if ev_uid:
            if ev_uid in seen_in_batch_uids:
                continue
            ev_exists = await db.execute(select(AttackEvent.id).where(AttackEvent.event_uid == ev_uid))
            if ev_exists.scalars().first():
                continue
            seen_in_batch_uids.add(ev_uid)

        if ev_id in seen_in_batch_ids:
            continue
        ev_exists_id = await db.execute(select(AttackEvent.id).where(AttackEvent.event_id == ev_id))
        if ev_exists_id.scalars().first():
            continue
        seen_in_batch_ids.add(ev_id)

        from honeyforge_server.app.geo_resolver import lookup_ip_geo
        geo_info = lookup_ip_geo(ev_data.get("source_ip", "127.0.0.1"))

        ingest_latency = None
        captured_at = ev_data.get("captured_at")
        if captured_at:
            import time
            ingest_latency = round(max(0.001, time.time() - captured_at), 3)

        ev_timestamp = now
        if ev_data.get("timestamp"):
            try:
                ev_timestamp = datetime.datetime.fromisoformat(ev_data["timestamp"])
            except Exception:
                pass

        event_obj = AttackEvent(
            event_id=ev_id,
            event_uid=ev_uid,
            trap_id=trap.trap_id,
            timestamp=ev_timestamp,
            source_ip=ev_data.get("source_ip", "0.0.0.0"),
            source_port=ev_data.get("source_port", 0),
            protocol=ev_data.get("protocol", "TCP"),
            destination_port=ev_data.get("destination_port", 0),
            event_type=ev_data.get("event_type", "probe"),
            severity=ev_data.get("severity", "medium"),
            credentials=ev_data.get("credentials"),
            command_text=ev_data.get("command_text"),
            http_data=ev_data.get("http_data"),
            payload_raw=ev_data.get("payload_raw"),
            artifact_hash=ev_data.get("artifact_hash"),
            session_id=ev_data.get("session_id"),
            session_duration_s=ev_data.get("session_duration_s"),
            is_ioc=ev_data.get("is_ioc", False) or (ev_data.get("severity") in ["high", "critical"]),
            geo_country=geo_info.get("country", "Тестовая сеть"),
            geo_city=geo_info.get("city", ""),
            source_asn=geo_info.get("asn", "AS-LOCAL"),
            ingest_latency_seconds=ingest_latency
        )
        db.add(event_obj)
        saved_events.append(event_obj)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        # Fallback individual insert to isolate any duplicate collisions
        saved_events.clear()
        for ev_data in events_in:
            ev_id = ev_data.get("event_id") or str(uuid.uuid4())
            ev_uid = ev_data.get("event_uid")
            try:
                if ev_uid:
                    chk = await db.execute(select(AttackEvent.id).where(AttackEvent.event_uid == ev_uid))
                    if chk.scalars().first():
                        continue
                chk_id = await db.execute(select(AttackEvent.id).where(AttackEvent.event_id == ev_id))
                if chk_id.scalars().first():
                    continue

                from honeyforge_server.app.geo_resolver import lookup_ip_geo
                geo_info = lookup_ip_geo(ev_data.get("source_ip", "127.0.0.1"))
                event_obj = AttackEvent(
                    event_id=ev_id,
                    event_uid=ev_uid,
                    trap_id=trap.trap_id,
                    timestamp=now,
                    source_ip=ev_data.get("source_ip", "0.0.0.0"),
                    source_port=ev_data.get("source_port", 0),
                    protocol=ev_data.get("protocol", "TCP"),
                    destination_port=ev_data.get("destination_port", 0),
                    event_type=ev_data.get("event_type", "probe"),
                    severity=ev_data.get("severity", "medium"),
                    credentials=ev_data.get("credentials"),
                    command_text=ev_data.get("command_text"),
                    http_data=ev_data.get("http_data"),
                    payload_raw=ev_data.get("payload_raw"),
                    artifact_hash=ev_data.get("artifact_hash"),
                    session_id=ev_data.get("session_id"),
                    is_ioc=ev_data.get("is_ioc", False),
                    geo_country=geo_info.get("country", "Тестовая сеть"),
                    geo_city=geo_info.get("city", ""),
                    source_asn=geo_info.get("asn", "AS-LOCAL")
                )
                db.add(event_obj)
                await db.commit()
                saved_events.append(event_obj)
            except Exception:
                await db.rollback()

    # 5. Process Alerts & Broadcast Events to UI in Real-Time
    for ev in saved_events:
        await db.refresh(ev)
        await process_event_for_alerts(db, ev)
        await ws_hub.broadcast("attack_event", {
            "id": ev.id,
            "event_id": ev.event_id,
            "event_uid": ev.event_uid,
            "trap_id": ev.trap_id,
            "trap_name": trap.name,
            "timestamp": ev.timestamp.isoformat(),
            "source_ip": ev.source_ip,
            "source_port": ev.source_port,
            "protocol": ev.protocol,
            "destination_port": ev.destination_port,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "credentials": ev.credentials,
            "command_text": ev.command_text,
            "http_data": ev.http_data,
            "payload_raw": ev.payload_raw,
            "artifact_hash": ev.artifact_hash,
            "session_id": ev.session_id,
            "session_duration_s": ev.session_duration_s,
            "geo_country": ev.geo_country,
            "geo_city": ev.geo_city,
            "source_asn": ev.source_asn,
            "ingest_latency_seconds": ev.ingest_latency_seconds
        })

    # 6. Ingest Sessions & Interactive Command Histories
    session_logs_in = body_dict.get("session_logs", [])
    for sess_data in session_logs_in:
        sess_id = sess_data.get("session_id")
        if not sess_id:
            continue
        existing_sess = await db.execute(select(SessionLog).where(SessionLog.session_id == sess_id))
        sess_obj = existing_sess.scalars().first()
        if not sess_obj:
            sess_obj = SessionLog(
                session_id=sess_id,
                trap_id=trap.trap_id,
                source_ip=sess_data.get("source_ip", "0.0.0.0"),
                protocol=sess_data.get("protocol", "SSH"),
                started_at=datetime.datetime.utcnow(),
                total_commands=sess_data.get("total_commands", 0),
                commands_history=sess_data.get("commands_history", []),
                captured_artifacts=sess_data.get("captured_artifacts", [])
            )
            db.add(sess_obj)
        else:
            sess_obj.total_commands = sess_data.get("total_commands", sess_obj.total_commands)
            sess_obj.commands_history = sess_data.get("commands_history", sess_obj.commands_history)
            sess_obj.captured_artifacts = sess_data.get("captured_artifacts", sess_obj.captured_artifacts)
            if sess_data.get("ended", False):
                sess_obj.ended_at = datetime.datetime.utcnow()
        await db.commit()

    # Disguised 200 response matching authentic edge analytics
    return {
        "status": "ok",
        "edge_code": "AMS-1",
        "processed_events": len(saved_events),
        "sync_time": now.timestamp()
    }

# Primary Neutral RUM Ingestion Endpoint (MASK-2)
@router.api_route("/cdn-cgi/rum", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
async def cdn_rum_ingest(request: Request, db: AsyncSession = Depends(get_db)):
    if request.method != "POST":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return await _process_telemetry_batch(request, db)

# Alternative Static Metrics Ingestion Endpoint
@router.api_route("/static/v2/metrics", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
async def static_metrics_ingest(request: Request, db: AsyncSession = Depends(get_db)):
    if request.method != "POST":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return await _process_telemetry_batch(request, db)

# Fallback Transparent 1x1 GIF & Trace Beacons (MASK-2)
@router.api_route("/cdn-cgi/trace", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
@router.api_route("/static/pixel.gif", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
async def beacon_pixel_get(request: Request, db: AsyncSession = Depends(get_db)):
    if request.method != "GET":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    target_id = request.headers.get("x-node-id") or request.query_params.get("trap_id")
    sig_header = request.headers.get("x-signature")
    if not target_id or not sig_header:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    result = await db.execute(select(Trap).where(Trap.trap_id == target_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    ts = request.headers.get("x-timestamp", "0")
    nonce = request.headers.get("x-nonce", "")
    raw_body = await request.body()
    try:
        if not verify_agent_signature(target_id, float(ts), nonce, sig_header, trap.secret_key, raw_body=raw_body):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    except Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    return Response(content=TRANSPARENT_GIF, media_type="image/gif")

# Neutral dynamic runtime config synchronization (MASK-2 / FR-A3)
@router.api_route("/sync/v1/config/{trap_id}", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
@router.api_route("/sync/v1/config", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
async def sync_config_endpoint(
    request: Request,
    trap_id: str = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Delivers runtime config for authenticated agents or operators.
    Unauthenticated requests across any HTTP method receive the exact same 404 Not Found as non-existent paths.
    """
    if request.method != "GET":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    target_id = trap_id or request.headers.get("x-node-id")
    if not target_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    auth_header = request.headers.get("authorization", "")
    sig_header = request.headers.get("x-signature")

    is_authenticated = False
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = decode_access_token(token)
        if payload:
            is_authenticated = True

    result = await db.execute(select(Trap).where(Trap.trap_id == target_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    if not is_authenticated and sig_header:
        ts = request.headers.get("x-timestamp", "0")
        nonce = request.headers.get("x-nonce", "")
        raw_body = await request.body()
        try:
            if verify_agent_signature(target_id, float(ts), nonce, sig_header, trap.secret_key, raw_body=raw_body):
                is_authenticated = True
        except Exception:
            pass

    if not is_authenticated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    profile = None
    if trap.profile_id:
        p_res = await db.execute(select(Profile).where(Profile.id == trap.profile_id))
        profile = p_res.scalars().first()

    return {
        "trap_id": trap.trap_id,
        "name": trap.name,
        "interaction_level": trap.interaction_level if not profile else profile.interaction_level,
        "config_version": trap.config_version,
        "services": profile.services if profile else ["ssh", "http"],
        "banners": profile.banners if profile else {"22": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
        "decoy_credentials": profile.decoy_credentials if profile else DEFAULT_DECOY_CREDENTIALS,
        "honeytokens": profile.honeytokens_config if profile else [],
        "persona": profile.persona if profile and profile.persona else {
            "hostname": "prod-srv-01",
            "os": "Ubuntu 22.04.4 LTS",
            "kernel": "5.15.0-89-generic",
            "uptime_base": 172800,
            "users": ["root", "deploy", "ubuntu"]
        },
        "stealth": profile.stealth_params if profile else {
            "proc_name": "syslog-ng",
            "beacon_interval_s": 8,
            "jitter_pct": 35,
            "dummy_padding": True
        }
    }
