import uuid
import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Trap, AttackEvent, SessionLog, Honeytoken
from honeyforge_server.app.schemas import TelemetryBatchIn
from honeyforge_server.app.security import verify_agent_signature
from honeyforge_server.app.alert_engine import process_event_for_alerts
from honeyforge_server.app.websocket_hub import ws_hub

router = APIRouter(tags=["Stealth Telemetry Ingestion"])

# 1x1 Transparent GIF pixel for CDN disguise
TRANSPARENT_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04"
    b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

@router.post("/v1/telemetry/collect")
async def collect_telemetry(payload: TelemetryBatchIn, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Stealth Ingestion Endpoint (MASK-2):
    Disguised as standard CDN/analytics event telemetry ingestion.
    Validates HMAC signature (MASK-7), updates trap health, logs attack events and sessions,
    and broadcasts to Web-UI SOC dashboard in real time.
    """
    # 1. Look up trap
    result = await db.execute(select(Trap).where(Trap.trap_id == payload.trap_id))
    trap = result.scalars().first()
    now = datetime.datetime.utcnow()
    if not trap:
        # Auto-provision trap on first beacon
        level = "medium" if "med" in payload.trap_id.lower() else "low"
        trap = Trap(
            trap_id=payload.trap_id,
            name=f"Trap-{payload.trap_id}",
            interaction_level=level,
            ip_address="192.168.1.10",
            mgmt_ip="10.200.0.10",
            status="online",
            secret_key="secret-key-med-01" if "med" in payload.trap_id else "secret-key-low-01",
            last_seen=now,
            created_at=now
        )
        db.add(trap)
        await db.commit()
        await db.refresh(trap)
        
    # 2. Verify HMAC Signature (MASK-1 & MASK-7)
    # Allows secret_key or master bypass for testing/simulators
    valid_sig = verify_agent_signature(
        trap_id=payload.trap_id,
        timestamp=payload.timestamp,
        nonce=payload.nonce,
        signature=payload.signature,
        secret_key=trap.secret_key
    )
    if not valid_sig:
        # Even on signature mismatch, return realistic CDN response to prevent reconnaissance
        return Response(
            content='{"status":"ok","code":200,"dispatched":false}',
            media_type="application/json"
        )

    # 3. Update trap heartbeat & status
    now = datetime.datetime.utcnow()
    trap.last_seen = now
    trap.status = "online"
    if payload.heartbeat:
        trap.uptime_seconds = payload.heartbeat.uptime_seconds
        trap.cpu_usage = payload.heartbeat.cpu_usage
        trap.mem_usage = payload.heartbeat.mem_usage
        trap.config_version = payload.heartbeat.config_version
    
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

    # 4. Ingest Attack Events
    saved_events = []
    for ev_in in payload.events:
        # Check idempotency
        ev_exists = await db.execute(select(AttackEvent).where(AttackEvent.event_id == ev_in.event_id))
        if ev_exists.scalars().first():
            continue
            
        event_obj = AttackEvent(
            event_id=ev_in.event_id or str(uuid.uuid4()),
            trap_id=payload.trap_id,
            timestamp=ev_in.timestamp or now,
            source_ip=ev_in.source_ip,
            source_port=ev_in.source_port,
            protocol=ev_in.protocol,
            destination_port=ev_in.destination_port,
            event_type=ev_in.event_type,
            severity=ev_in.severity,
            credentials=ev_in.credentials,
            command_text=ev_in.command_text,
            http_data=ev_in.http_data,
            payload_raw=ev_in.payload_raw,
            artifact_hash=ev_in.artifact_hash,
            session_id=ev_in.session_id,
            is_ioc=ev_in.is_ioc or (ev_in.severity in ["high", "critical"]),
            geo_country=ev_in.geo_country or "Unknown",
            geo_city=ev_in.geo_city or "Unknown"
        )
        db.add(event_obj)
        saved_events.append(event_obj)
        
    await db.commit()

    # 5. Process Alerts & Broadcast Events to UI in Real-Time
    for ev in saved_events:
        await db.refresh(ev)
        # Check alerts
        await process_event_for_alerts(db, ev)
        # WebSocket broadcast to SOC dashboard
        await ws_hub.broadcast("attack_event", {
            "id": ev.id,
            "event_id": ev.event_id,
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
            "geo_country": ev.geo_country,
            "geo_city": ev.geo_city
        })

    # 6. Ingest Sessions & Interactive Command Histories
    for sess_data in payload.session_logs:
        sess_id = sess_data.get("session_id")
        if not sess_id:
            continue
        existing_sess = await db.execute(select(SessionLog).where(SessionLog.session_id == sess_id))
        sess_obj = existing_sess.scalars().first()
        if not sess_obj:
            sess_obj = SessionLog(
                session_id=sess_id,
                trap_id=payload.trap_id,
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

    # 7. Disguised response matching legitimate CDN analytics
    return {
        "status": "ok",
        "edge_code": "AMS-1",
        "processed_events": len(saved_events),
        "sync_time": now.timestamp()
    }

@router.get("/cdn-cgi/telemetry/pixel.gif")
async def beacon_pixel_get():
    """Fallback transparent 1x1 GIF beacon for stealth web tracking (MASK-2)"""
    return Response(content=TRANSPARENT_GIF, media_type="image/gif")
