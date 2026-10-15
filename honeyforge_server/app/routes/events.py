import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import AttackEvent, SessionLog, AlertEvent
from honeyforge_server.app.schemas import AttackEventOut, SessionLogOut, AlertEventOut
from honeyforge_server.app.ioc_exporter import export_iocs_csv, export_iocs_stix, export_suricata_rules
from honeyforge_server.app.security import get_current_user

router = APIRouter(prefix="/events", tags=["Attack Events & Analytics"])

@router.get("", response_model=List[AttackEventOut])
async def list_events(
    trap_id: Optional[str] = Query(None, description="Фильтр по ID ловушки"),
    event_type: Optional[str] = Query(None, description="Фильтр по типу события"),
    source_ip: Optional[str] = Query(None, description="Фильтр по IP источника"),
    severity: Optional[str] = Query(None, description="Фильтр по важности"),
    period: Optional[str] = Query(None, description="Период: 15m, 1h, 24h, all"),
    since: Optional[datetime.datetime] = Query(None),
    until: Optional[datetime.datetime] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Поиск и фильтрация телеметрии атак"""
    query = select(AttackEvent).order_by(desc(AttackEvent.timestamp))
    
    now = datetime.datetime.utcnow()
    if period == "15m":
        query = query.where(AttackEvent.timestamp >= now - datetime.timedelta(minutes=15))
    elif period == "1h":
        query = query.where(AttackEvent.timestamp >= now - datetime.timedelta(hours=1))
    elif period == "24h":
        query = query.where(AttackEvent.timestamp >= now - datetime.timedelta(hours=24))
    elif since:
        query = query.where(AttackEvent.timestamp >= since)
    if until:
        query = query.where(AttackEvent.timestamp <= until)
        
    if trap_id:
        query = query.where(AttackEvent.trap_id == trap_id)
    if event_type:
        query = query.where(AttackEvent.event_type == event_type)
    if source_ip:
        query = query.where(AttackEvent.source_ip == source_ip)
    if severity:
        query = query.where(AttackEvent.severity == severity)
        
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    events = result.scalars().all()
    return [AttackEventOut.model_validate(e) for e in events]

@router.get("/sessions", response_model=List[SessionLogOut])
async def list_sessions(
    trap_id: Optional[str] = None,
    limit: int = 50,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Список интерактивных honeypot-сессий (только Medium)"""
    query = select(SessionLog).order_by(desc(SessionLog.started_at))
    if trap_id:
        query = query.where(SessionLog.trap_id == trap_id)
    query = query.limit(limit)
    result = await db.execute(query)
    sessions = result.scalars().all()
    return [SessionLogOut.model_validate(s) for s in sessions]

@router.get("/sessions/{session_id}", response_model=SessionLogOut)
async def get_session_replay(
    session_id: str,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Данные интерактивной сессии и история команд"""
    result = await db.execute(select(SessionLog).where(SessionLog.session_id == session_id))
    session = result.scalars().first()
    if not session:
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    return SessionLogOut.model_validate(session)

@router.get("/alerts", response_model=List[AlertEventOut])
async def list_alerts(
    limit: int = 50,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Оповещения безопасности"""
    result = await db.execute(select(AlertEvent).order_by(desc(AlertEvent.created_at)).limit(limit))
    alerts = result.scalars().all()
    return [AlertEventOut.model_validate(a) for a in alerts]

@router.post("/alerts/{alert_id}/ack")
async def acknowledge_alert(
    alert_id: int,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Принятие / квитирование оповещения"""
    result = await db.execute(select(AlertEvent).where(AlertEvent.id == alert_id))
    alert = result.scalars().first()
    if alert:
        await db.delete(alert)
        await db.commit()
    return {"status": "ok", "acknowledged": alert_id}

@router.post("/alerts/ack-all")
async def acknowledge_all_alerts(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Принятие всех активных оповещений (очистка очереди инцидентов)"""
    from sqlalchemy import delete
    await db.execute(delete(AlertEvent))
    await db.commit()
    return {"status": "ok", "acknowledged_all": True}

@router.get("/ioc/summary")
async def get_ioc_summary(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Предпросмотр таблицы IoC-индикаторов"""
    # 1. IP IoCs
    query = select(
        AttackEvent.source_ip,
        AttackEvent.trap_id,
        func.min(AttackEvent.timestamp).label("first_seen"),
        func.max(AttackEvent.timestamp).label("last_seen"),
        func.count(AttackEvent.id).label("count")
    ).group_by(AttackEvent.source_ip, AttackEvent.trap_id).order_by(desc("count")).limit(50)
    res = await db.execute(query)
    summary = []
    for row in res.all():
        summary.append({
            "type": "IP (ipv4-addr)",
            "value": row[0],
            "trap_id": row[1],
            "first_seen": row[2].isoformat() if row[2] else "",
            "last_seen": row[3].isoformat() if row[3] else "",
            "count": row[4]
        })
    # 2. File Hashes
    h_query = select(
        AttackEvent.artifact_hash,
        AttackEvent.trap_id,
        func.min(AttackEvent.timestamp).label("first_seen"),
        func.max(AttackEvent.timestamp).label("last_seen"),
        func.count(AttackEvent.id).label("count")
    ).where(AttackEvent.artifact_hash.isnot(None)).group_by(AttackEvent.artifact_hash, AttackEvent.trap_id).limit(20)
    h_res = await db.execute(h_query)
    for row in h_res.all():
        summary.append({
            "type": "SHA-256 (file)",
            "value": row[0],
            "trap_id": row[1],
            "first_seen": row[2].isoformat() if row[2] else "",
            "last_seen": row[3].isoformat() if row[3] else "",
            "count": row[4]
        })
    return summary

@router.get("/export/ioc")
async def export_iocs(
    format: str = Query("stix", enum=["stix", "csv"]),
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Exports IoCs in STIX 2.1, CSV or Suricata rules (FR-C7 Bonus)"""
    result = await db.execute(select(AttackEvent).where(AttackEvent.is_ioc == True).order_by(desc(AttackEvent.timestamp)).limit(500))
    events = result.scalars().all()
    
    # If no flagged IoCs yet, take all distinct attacker events
    if not events:
        all_res = await db.execute(select(AttackEvent).order_by(desc(AttackEvent.timestamp)).limit(200))
        events = all_res.scalars().all()
        
    if format == "csv":
        csv_data = export_iocs_csv(events)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=honeyforge_ioc.csv"}
        )
    elif format == "suricata":
        rules = export_suricata_rules(events)
        return Response(
            content=rules,
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=honeyforge_rules.rules"}
        )
    else:
        stix_bundle = export_iocs_stix(events)
        return stix_bundle
