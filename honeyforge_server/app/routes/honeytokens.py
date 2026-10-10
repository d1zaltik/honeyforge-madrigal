import uuid
import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Honeytoken, AttackEvent, AlertEvent
from honeyforge_server.app.schemas import HoneytokenCreate, HoneytokenOut
from honeyforge_server.app.websocket_hub import ws_hub

router = APIRouter(tags=["Honeytokens Subsystem"])

@router.get("/api/v1/honeytokens", response_model=List[HoneytokenOut])
async def list_honeytokens(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Honeytoken).order_by(Honeytoken.id.desc()))
    tokens = result.scalars().all()
    return [HoneytokenOut.model_validate(t) for t in tokens]

@router.post("/api/v1/honeytokens", response_model=HoneytokenOut)
async def create_honeytoken(token_in: HoneytokenCreate, db: AsyncSession = Depends(get_db)):
    token_id = f"ht-{uuid.uuid4().hex[:12]}"
    token = Honeytoken(
        token_id=token_id,
        token_type=token_in.token_type,
        token_value=token_in.token_value,
        canary_path=token_in.canary_path,
        trap_id=token_in.trap_id,
        description=token_in.description or f"Canary {token_in.token_type} decoy",
        is_triggered=False
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return HoneytokenOut.model_validate(token)

@router.get("/canary/{token_id}")
async def canary_trap_trigger(token_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Canary URL Trigger (FR-A6 Bonus):
    When an attacker opens or curls this decoy URL, an immediate CRITICAL alert is generated!
    """
    client_ip = request.client.host if request.client else "Unknown"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    result = await db.execute(select(Honeytoken).where(Honeytoken.token_id == token_id))
    token = result.scalars().first()
    
    now = datetime.datetime.utcnow()
    trap_id = token.trap_id if token else "canary-web"
    
    if token:
        token.is_triggered = True
        token.triggered_at = now
        token.triggered_by_ip = client_ip
    
    # Create attack event
    event = AttackEvent(
        event_id=str(uuid.uuid4()),
        trap_id=trap_id,
        timestamp=now,
        source_ip=client_ip,
        source_port=0,
        protocol="HTTP",
        destination_port=80,
        event_type="honeytoken_triggered",
        severity="critical",
        http_data={"method": "GET", "path": f"/canary/{token_id}", "user_agent": user_agent},
        payload_raw=f"Attacker opened Canary Token: {token.description if token else token_id}",
        is_ioc=True
    )
    db.add(event)
    
    # Create critical alert
    alert = AlertEvent(
        rule_name="Honeytoken Breach Detected",
        trap_id=trap_id,
        source_ip=client_ip,
        message=f"CRITICAL: Canary token '{token.description if token else token_id}' triggered by {client_ip}!",
        severity="critical",
        created_at=now
    )
    db.add(alert)
    await db.commit()
    
    # Broadcast to live dashboard
    await ws_hub.broadcast("alert", {
        "id": alert.id,
        "rule_name": alert.rule_name,
        "trap_id": trap_id,
        "source_ip": client_ip,
        "message": alert.message,
        "severity": "critical",
        "created_at": now.isoformat()
    })
    await ws_hub.broadcast("honeytoken_triggered", {
        "token_id": token_id,
        "source_ip": client_ip,
        "triggered_at": now.isoformat()
    })
    
    # Return innocent fake 403 Forbidden to not reveal that it's a canary trap
    return Response(
        content="<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1><p>Access denied by server policy.</p></center></body></html>",
        status_code=403,
        media_type="text/html"
    )
