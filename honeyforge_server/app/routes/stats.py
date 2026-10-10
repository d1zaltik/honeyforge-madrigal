from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Trap, AttackEvent, Honeytoken, AuditLog
from honeyforge_server.app.schemas import OverviewStats

router = APIRouter(prefix="/stats", tags=["Dashboard Statistics"])

@router.get("/overview", response_model=OverviewStats)
async def get_overview_stats(db: AsyncSession = Depends(get_db)):
    # Total traps
    tot_traps_res = await db.execute(select(func.count(Trap.id)))
    total_traps = tot_traps_res.scalar() or 0
    
    online_traps_res = await db.execute(select(func.count(Trap.id)).where(Trap.status == "online"))
    online_traps = online_traps_res.scalar() or 0
    
    # Events
    tot_ev_res = await db.execute(select(func.count(AttackEvent.id)))
    total_events = tot_ev_res.scalar() or 0
    
    crit_ev_res = await db.execute(select(func.count(AttackEvent.id)).where(AttackEvent.severity.in_(["high", "critical"])))
    critical_events = crit_ev_res.scalar() or 0
    
    # Credentials & payloads
    creds_res = await db.execute(select(func.count(AttackEvent.id)).where(AttackEvent.credentials.isnot(None)))
    captured_credentials = creds_res.scalar() or 0
    
    payloads_res = await db.execute(select(func.count(AttackEvent.id)).where(AttackEvent.artifact_hash.isnot(None)))
    captured_payloads = payloads_res.scalar() or 0
    
    # Honeytokens
    ht_tot_res = await db.execute(select(func.count(Honeytoken.id)))
    honeytokens_count = ht_tot_res.scalar() or 0
    
    ht_trig_res = await db.execute(select(func.count(Honeytoken.id)).where(Honeytoken.is_triggered == True))
    honeytokens_triggered = ht_trig_res.scalar() or 0
    
    # Top attackers
    top_att_query = select(AttackEvent.source_ip, func.count(AttackEvent.id).label("count")).group_by(
        AttackEvent.source_ip
    ).order_by(desc("count")).limit(5)
    top_att_res = await db.execute(top_att_query)
    top_attackers = [{"ip": row[0], "count": row[1]} for row in top_att_res.all()]
    
    # Top ports
    top_port_query = select(AttackEvent.destination_port, AttackEvent.protocol, func.count(AttackEvent.id).label("count")).group_by(
        AttackEvent.destination_port, AttackEvent.protocol
    ).order_by(desc("count")).limit(5)
    top_port_res = await db.execute(top_port_query)
    top_ports = [{"port": row[0], "protocol": row[1], "count": row[2]} for row in top_port_res.all()]
    
    # Events per type
    ev_type_query = select(AttackEvent.event_type, func.count(AttackEvent.id).label("count")).group_by(
        AttackEvent.event_type
    )
    ev_type_res = await db.execute(ev_type_query)
    events_per_type = {row[0]: row[1] for row in ev_type_res.all()}
    
    return OverviewStats(
        total_traps=total_traps,
        online_traps=online_traps,
        total_events=total_events,
        critical_events=critical_events,
        captured_credentials=captured_credentials,
        captured_payloads=captured_payloads,
        honeytokens_count=honeytokens_count,
        honeytokens_triggered=honeytokens_triggered,
        top_attackers=top_attackers,
        top_ports=top_ports,
        events_per_type=events_per_type
    )

@router.get("/audit")
async def list_audit_logs(limit: int = 50, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit))
    logs = result.scalars().all()
    return logs
