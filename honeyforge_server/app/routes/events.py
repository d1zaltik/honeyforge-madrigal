import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import AttackEvent, SessionLog, AlertEvent
from honeyforge_server.app.schemas import AttackEventOut, SessionLogOut, AlertEventOut
from honeyforge_server.app.ioc_exporter import export_iocs_csv, export_iocs_stix, export_suricata_rules

router = APIRouter(prefix="/events", tags=["Attack Events & Analytics"])

@router.get("", response_model=List[AttackEventOut])
async def list_events(
    trap_id: Optional[str] = Query(None, description="Filter by trap ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """Query and filter attack telemetry (FR-C4)"""
    query = select(AttackEvent).order_by(desc(AttackEvent.timestamp))
    
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
    db: AsyncSession = Depends(get_db)
):
    """Lists captured interactive honeypot sessions (SSH/Telnet)"""
    query = select(SessionLog).order_by(desc(SessionLog.started_at))
    if trap_id:
        query = query.where(SessionLog.trap_id == trap_id)
    query = query.limit(limit)
    result = await db.execute(query)
    sessions = result.scalars().all()
    return [SessionLogOut.model_validate(s) for s in sessions]

@router.get("/sessions/{session_id}", response_model=SessionLogOut)
async def get_session_replay(session_id: str, db: AsyncSession = Depends(get_db)):
    """Fetches command sequence and execution output for Asciinema-style session replay"""
    result = await db.execute(select(SessionLog).where(SessionLog.session_id == session_id))
    session = result.scalars().first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionLogOut.model_validate(session)

@router.get("/alerts", response_model=List[AlertEventOut])
async def list_alerts(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Retrieves correlated security alerts"""
    result = await db.execute(select(AlertEvent).order_by(desc(AlertEvent.created_at)).limit(limit))
    alerts = result.scalars().all()
    return [AlertEventOut.model_validate(a) for a in alerts]

@router.get("/export/ioc")
async def export_iocs(
    format: str = Query("stix", enum=["stix", "csv", "suricata"]),
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
