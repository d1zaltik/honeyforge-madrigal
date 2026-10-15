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
            rule_name="Компрометация токена-приманки (Honeytoken)",
            trap_id=event.trap_id,
            source_ip=event.source_ip,
            message=f"КРИТИЧЕСКИЙ: Зафиксирован несанкционированный доступ к приманке с IP {event.source_ip}. Скомпрометированный ресурс: {event.payload_raw or 'Canary Access'}",
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
                rule_name="Подозрительная активность в сессии",
                trap_id=event.trap_id,
                source_ip=event.source_ip,
                message=f"Обнаружена подозрительная команда в сессии: '{event.command_text[:80]}'",
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

    # 3. Brute Force Detection: check auth attempts against active brute_force AlertRule
    if event.event_type == "auth_attempt":
        # Check active rule for specific trap or global (trap_id is None)
        rule_q = select(AlertRule).where(
            AlertRule.rule_type == "brute_force",
            AlertRule.is_enabled == True,
            (AlertRule.trap_id == None) | (AlertRule.trap_id == event.trap_id)
        )
        rule_res = await db.execute(rule_q)
        rule = rule_res.scalars().first()
        if not rule:
            return

        window_s = rule.window_seconds or 60
        threshold = rule.threshold or 5
        time_threshold = datetime.datetime.utcnow() - datetime.timedelta(seconds=window_s)

        query = select(func.count(AttackEvent.id)).where(
            AttackEvent.source_ip == event.source_ip,
            AttackEvent.event_type == "auth_attempt",
            AttackEvent.timestamp >= time_threshold
        )
        result = await db.execute(query)
        attempt_count = result.scalar() or 0
        
        if attempt_count >= threshold:
            # Check if alert was recently generated (within 5s) to prevent storming on a single batch
            recent_alert_q = select(AlertEvent).where(
                AlertEvent.source_ip == event.source_ip,
                AlertEvent.rule_name == rule.name,
                AlertEvent.created_at >= (datetime.datetime.utcnow() - datetime.timedelta(seconds=5))
            )
            recent_res = await db.execute(recent_alert_q)
            if not recent_res.scalars().first():
                alert = AlertEvent(
                    rule_name=rule.name,
                    trap_id=event.trap_id,
                    source_ip=event.source_ip,
                    message=f"Зафиксирована серия попыток подбора учетных данных: {attempt_count} запросов за {window_s} секунд с IP-адреса {event.source_ip}",
                    severity=rule.severity or "high",
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
