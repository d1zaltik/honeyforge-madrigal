import datetime
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from honeyforge_server.app.models import AlertRule, AlertEvent, AttackEvent
from honeyforge_server.app.websocket_hub import ws_hub

SUSPICIOUS_KEYWORDS = ["wget", "curl", "chmod", "sh", "bash", "nc", "ncat", "python", "/etc/shadow", "id_rsa", "miner", "xmrig"]

async def process_event_for_alerts(db: AsyncSession, event: AttackEvent):
    """Evaluates incoming event against alert rules and triggers real-time alerts (FR-C7)"""
    # 1. Immediate Honeytoken Alert
    if event.event_type == "honeytoken_triggered":
        alert = AlertEvent(
            rule_name="Honeytoken Breach Detected",
            trap_id=event.trap_id,
            source_ip=event.source_ip,
            message=f"CRITICAL: Canary honeytoken triggered by {event.source_ip}! Decoy asset compromised: {event.payload_raw or 'Canary Access'}",
            severity="critical",
            created_at=datetime.datetime.utcnow()
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        await ws_hub.broadcast("alert", {
            "id": alert.id,
            "rule_name": alert.rule_name,
            "trap_id": alert.trap_id,
            "source_ip": alert.source_ip,
            "message": alert.message,
            "severity": alert.severity,
            "created_at": alert.created_at.isoformat()
        })
        return

    # 2. Malicious Command or Payload Alert
    if event.command_text:
        cmd_lower = event.command_text.lower()
        if any(kw in cmd_lower for kw in SUSPICIOUS_KEYWORDS):
            alert = AlertEvent(
                rule_name="Suspicious Post-Exploitation Activity",
                trap_id=event.trap_id,
                source_ip=event.source_ip,
                message=f"Malicious command detected in session: '{event.command_text[:80]}'",
                severity="high",
                created_at=datetime.datetime.utcnow()
            )
            db.add(alert)
            await db.commit()
            await db.refresh(alert)
            await ws_hub.broadcast("alert", {
                "id": alert.id,
                "rule_name": alert.rule_name,
                "trap_id": alert.trap_id,
                "source_ip": alert.source_ip,
                "message": alert.message,
                "severity": alert.severity,
                "created_at": alert.created_at.isoformat()
            })

    # 3. Brute Force Detection: check auth attempts from this IP in the last 60 seconds
    if event.event_type == "auth_attempt":
        time_threshold = datetime.datetime.utcnow() - datetime.timedelta(seconds=60)
        query = select(func.count(AttackEvent.id)).where(
            AttackEvent.source_ip == event.source_ip,
            AttackEvent.event_type == "auth_attempt",
            AttackEvent.timestamp >= time_threshold
        )
        result = await db.execute(query)
        attempt_count = result.scalar() or 0
        
        if attempt_count >= 5:  # Default threshold: 5 auth attempts/min
            # Check if alert was recently generated to prevent alert fatigue
            recent_alert_q = select(AlertEvent).where(
                AlertEvent.source_ip == event.source_ip,
                AlertEvent.rule_name == "Credential Brute-Force Wave",
                AlertEvent.created_at >= time_threshold
            )
            recent_res = await db.execute(recent_alert_q)
            if not recent_res.scalars().first():
                alert = AlertEvent(
                    rule_name="Credential Brute-Force Wave",
                    trap_id=event.trap_id,
                    source_ip=event.source_ip,
                    message=f"Brute-force attack in progress! {attempt_count} authentication attempts detected within 60s from {event.source_ip}",
                    severity="high",
                    created_at=datetime.datetime.utcnow()
                )
                db.add(alert)
                await db.commit()
                await db.refresh(alert)
                await ws_hub.broadcast("alert", {
                    "id": alert.id,
                    "rule_name": alert.rule_name,
                    "trap_id": alert.trap_id,
                    "source_ip": alert.source_ip,
                    "message": alert.message,
                    "severity": alert.severity,
                    "created_at": alert.created_at.isoformat()
                })
