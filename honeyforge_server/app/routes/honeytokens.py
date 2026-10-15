import uuid
import datetime
import random
import string
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Honeytoken, AttackEvent, AlertEvent, AuditLog, Trap
from honeyforge_server.app.schemas import HoneytokenCreate, HoneytokenOut
from honeyforge_server.app.security import get_current_user, require_admin
from honeyforge_server.app.websocket_hub import ws_hub

router = APIRouter(tags=["Honeytokens Subsystem"])

@router.get("/api/v1/honeytokens", response_model=List[HoneytokenOut])
async def list_honeytokens(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Honeytoken).order_by(Honeytoken.id.desc()))
    tokens = result.scalars().all()
    return [HoneytokenOut.model_validate(t) for t in tokens]

@router.post("/api/v1/honeytokens", response_model=HoneytokenOut)
async def create_honeytoken(
    token_in: HoneytokenCreate,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    token_id = f"ht-{uuid.uuid4().hex[:8]}"
    
    # Auto-generate realistic but non-functional decoy values
    val = token_in.token_value
    if not val:
        if token_in.token_type == "aws_key":
            rnd_secret = ''.join(random.choices(string.ascii_letters + string.digits + "+/", k=40))
            val = f"AKIA{uuid.uuid4().hex[:16].upper()}:{rnd_secret}"
        elif token_in.token_type == "ssh_key":
            val = f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC{uuid.uuid4().hex} decoy-dev@corp"
        elif token_in.token_type == "account":
            val = f"backup_operator:TempPass_{uuid.uuid4().hex[:6]}"
        elif token_in.token_type == "canary_url":
            val = f"/sync/{token_id}"
        else:
            val = f"decoy-token-{uuid.uuid4().hex[:12]}"

    valid_trap_id = token_in.trap_id
    if not valid_trap_id:
        t_res = await db.execute(select(Trap.trap_id).limit(1))
        valid_trap_id = t_res.scalars().first() or "n-7f3a"

    token = Honeytoken(
        token_id=token_id,
        token_type=token_in.token_type,
        token_value=val,
        canary_path=token_in.canary_path or ("/root/.aws/credentials" if token_in.token_type == "aws_key" else "/var/www/internal_api.env"),
        trap_id=valid_trap_id,
        description=token_in.description or f"Приманка {token_in.token_type}",
        is_triggered=False
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="create_honeytoken",
        target_type="honeytoken",
        target_id=token.token_id,
        details=f"Размещен Honeytoken [{token.token_type}] на ловушке {token.trap_id} ({token.canary_path})"
    )
    db.add(audit)
    await db.commit()

    return HoneytokenOut.model_validate(token)

@router.api_route("/sync/{token_id}", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
@router.api_route("/canary/{token_id}", methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"])
async def canary_trap_trigger(token_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Neutral Sync / Canary URL Trigger (FR-A6 Bonus):
    When an attacker curls or requests this disguised URL, an immediate CRITICAL alert is generated.
    """
    client_ip = request.client.host if request.client else "Unknown"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    result = await db.execute(
        select(Honeytoken).where(
            (Honeytoken.token_id == token_id) |
            (Honeytoken.canary_path == f"/sync/{token_id}") |
            (Honeytoken.canary_path == f"/canary/{token_id}") |
            (Honeytoken.canary_path == request.url.path)
        )
    )
    token = result.scalars().first()
    if not token:
        raise HTTPException(status_code=404, detail="Not Found")
    
    now = datetime.datetime.utcnow()
    t_res = await db.execute(select(Trap.trap_id).limit(1))
    fallback_trap_id = t_res.scalars().first() or "n-7f3a"

    trap_id = token.trap_id if token.trap_id else fallback_trap_id
    chk = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    if not chk.scalars().first():
        trap_id = fallback_trap_id
    
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
        http_data={"method": request.method, "path": request.url.path, "user_agent": user_agent},
        payload_raw=f"Attacker opened Canary Token: {token.description if token else token_id}",
        is_ioc=True
    )
    db.add(event)
    
    # Create critical alert
    alert = AlertEvent(
        rule_name="Компрометация токена-приманки (Honeytoken)",
        trap_id=trap_id,
        source_ip=client_ip,
        message=f"КРИТИЧЕСКИЙ: Зафиксировано срабатывание токена-приманки '{token.description if token else token_id}' с IP-адреса {client_ip}",
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
