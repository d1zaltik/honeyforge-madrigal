import uuid
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Trap, Profile, AuditLog, AttackEvent, DEFAULT_DECOY_CREDENTIALS
from honeyforge_server.app.schemas import TrapRegister, TrapOut
from honeyforge_server.app.security import get_current_user, require_admin, decode_access_token, verify_agent_signature
from honeyforge_server.app.orchestrator import (
    generate_docker_compose_artifact,
    generate_bash_deployment_script,
    generate_powershell_deployment_script
)

router = APIRouter(prefix="/traps", tags=["Traps Management"])

@router.get("", response_model=List[TrapOut])
async def list_traps(user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Trap).order_by(Trap.id.desc()))
    traps = result.scalars().all()
    out = []
    
    now = datetime.datetime.utcnow()
    day_ago = now - datetime.timedelta(hours=24)
    for t in traps:
        # Fix name mismatch if needed
        if t.trap_id == "trap-med-01" and "02" in t.name:
            t.name = "Internal-SSH-Trap-01"
            await db.commit()

        status = t.status
        if t.last_seen:
            diff = (now - t.last_seen).total_seconds()
            if diff > 45:
                status = "offline"
        else:
            status = "offline"
            
        p_name = None
        services = []
        if t.profile_id:
            pres = await db.execute(select(Profile).where(Profile.id == t.profile_id))
            p_obj = pres.scalars().first()
            if p_obj:
                p_name = p_obj.name
                services = p_obj.services or []
        if not services:
            services = ["ftp", "telnet", "redis"] if t.interaction_level == "low" else ["ssh", "http"]
            
        # Count events in last 24h
        ev_res = await db.execute(
            select(func.count(AttackEvent.id)).where(
                AttackEvent.trap_id == t.trap_id,
                AttackEvent.timestamp >= day_ago
            )
        )
        ev_24h = ev_res.scalar() or 0

        out.append(TrapOut(
            id=t.id,
            trap_id=t.trap_id,
            name=t.name,
            profile_id=t.profile_id,
            interaction_level=t.interaction_level,
            ip_address=t.ip_address,
            mgmt_ip=t.mgmt_ip,
            status=status,
            last_seen=t.last_seen,
            uptime_seconds=t.uptime_seconds,
            cpu_usage=t.cpu_usage,
            mem_usage=t.mem_usage,
            config_version=t.config_version,
            created_at=t.created_at,
            profile_name=p_name,
            services=services,
            events_24h=ev_24h
        ))
    return out

@router.post("", response_model=TrapOut)
async def register_trap(
    trap_in: TrapRegister,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    # Check if trap_id exists
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_in.trap_id))
    existing = result.scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Trap with this ID is already registered")
        
    secret_key = trap_in.secret_key or str(uuid.uuid4().hex)
    
    trap = Trap(
        trap_id=trap_in.trap_id,
        name=trap_in.name,
        profile_id=trap_in.profile_id,
        interaction_level=trap_in.interaction_level,
        ip_address=trap_in.ip_address,
        mgmt_ip=trap_in.mgmt_ip,
        status="offline",
        secret_key=secret_key,
        created_at=datetime.datetime.utcnow()
    )
    db.add(trap)
    await db.commit()
    await db.refresh(trap)
    
    audit = AuditLog(
        username=user.get("username", "admin"),
        action="register_trap",
        target_type="trap",
        target_id=trap.trap_id,
        details=f"Registered trap '{trap.name}' [{trap.trap_id}] level={trap.interaction_level}"
    )
    db.add(audit)
    await db.commit()
    
    return TrapOut(
        id=trap.id,
        trap_id=trap.trap_id,
        name=trap.name,
        profile_id=trap.profile_id,
        interaction_level=trap.interaction_level,
        ip_address=trap.ip_address,
        mgmt_ip=trap.mgmt_ip,
        status=trap.status,
        last_seen=trap.last_seen,
        uptime_seconds=trap.uptime_seconds,
        cpu_usage=trap.cpu_usage,
        mem_usage=trap.mem_usage,
        config_version=trap.config_version,
        created_at=trap.created_at,
        secret_key=trap.secret_key
    )

@router.get("/{trap_id}", response_model=TrapOut)
async def get_trap(
    trap_id: str,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")

    p_name = None
    services = []
    if trap.profile_id:
        pres = await db.execute(select(Profile).where(Profile.id == trap.profile_id))
        p_obj = pres.scalars().first()
        if p_obj:
            p_name = p_obj.name
            services = p_obj.services or []
    if not services:
        services = ["ftp", "telnet", "redis"] if trap.interaction_level == "low" else ["ssh", "http"]

    return TrapOut(
        id=trap.id,
        trap_id=trap.trap_id,
        name=trap.name,
        profile_id=trap.profile_id,
        interaction_level=trap.interaction_level,
        ip_address=trap.ip_address,
        mgmt_ip=trap.mgmt_ip,
        status=trap.status,
        last_seen=trap.last_seen,
        uptime_seconds=trap.uptime_seconds,
        cpu_usage=trap.cpu_usage,
        mem_usage=trap.mem_usage,
        config_version=trap.config_version,
        created_at=trap.created_at,
        profile_name=p_name,
        services=services
    )

@router.post("/{trap_id}/rotate-key")
async def rotate_trap_key(
    trap_id: str,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")

    new_key = str(uuid.uuid4().hex)
    trap.secret_key = new_key
    trap.config_version += 1
    audit = AuditLog(
        username=user.get("username", "admin"),
        action="trap_rotate_creds",
        target_type="trap",
        target_id=trap.trap_id,
        details=f"Выполнена ротация учетных данных ловушки {trap.trap_id}"
    )
    db.add(audit)
    await db.commit()
    return {"status": "success", "new_secret_key": new_key, "config_version": trap.config_version}

@router.get("/{trap_id}/config")
async def get_trap_config(
    trap_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Delivers runtime configuration for the trap based on its bound profile (FR-C3).
    Supports either operator JWT authentication or Agent HMAC signature.
    """
    # 1. Check authorization (Operator JWT or Agent HMAC signature)
    auth_header = request.headers.get("authorization", "")
    sig_header = request.headers.get("x-signature")
    
    is_authenticated = False
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = decode_access_token(token)
        if payload:
            is_authenticated = True
            
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    if not is_authenticated and sig_header:
        ts = request.headers.get("x-timestamp", "0")
        nonce = request.headers.get("x-nonce", "")
        raw_body = await request.body()
        try:
            if verify_agent_signature(trap_id, float(ts), nonce, sig_header, trap.secret_key, raw_body=raw_body):
                is_authenticated = True
        except Exception:
            pass

    if not is_authenticated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
        
    profile = None
    if trap.profile_id:
        p_res = await db.execute(select(Profile).where(Profile.id == trap.profile_id))
        profile = p_res.scalars().first()
        
    config = {
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
            "proc_name": "systemd-resolved",
            "beacon_interval_s": 10,
            "jitter_pct": 35,
            "dummy_padding": True
        }
    }
    return config

@router.post("/{trap_id}/confirm-rotation")
async def confirm_credential_rotation(
    trap_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Confirms that the agent has successfully applied rotated credentials (MASK-7 / FR-C3).
    """
    auth_header = request.headers.get("authorization", "")
    sig_header = request.headers.get("x-signature")
    is_authenticated = False
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = decode_access_token(token)
        if payload:
            is_authenticated = True

    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    if not is_authenticated and sig_header:
        ts = request.headers.get("x-timestamp", "0")
        nonce = request.headers.get("x-nonce", "")
        raw_body = await request.body()
        try:
            if verify_agent_signature(trap_id, float(ts), nonce, sig_header, trap.secret_key, raw_body=raw_body):
                is_authenticated = True
        except Exception:
            pass

    if not is_authenticated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    audit = AuditLog(
        username="agent",
        action="confirm_rotation",
        target_type="trap",
        target_id=trap.trap_id,
        details=f"Ловушка {trap.trap_id} подтвердила ротацию учетных данных и применение новой конфигурации"
    )
    db.add(audit)
    await db.commit()
    return {"status": "success", "confirmed": True, "trap_id": trap.trap_id}

@router.get("/{trap_id}/deploy-artifact")
async def get_deploy_artifact(
    trap_id: str,
    format: str = Query("docker-compose", enum=["docker-compose", "bash", "powershell"]),
    server_url: str = "https://honeyforge-nginx",
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generates 1-click deployment artifact (FR-C6)"""
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")
        
    profile = None
    if trap.profile_id:
        p_res = await db.execute(select(Profile).where(Profile.id == trap.profile_id))
        profile = p_res.scalars().first()
    if not profile:
        profile = Profile(name="Default", interaction_level=trap.interaction_level, services=["ssh", "http"])
        
    if format == "docker-compose":
        content = generate_docker_compose_artifact(trap, profile, server_url)
        return Response(content=content, media_type="text/yaml")
    elif format == "bash":
        content = generate_bash_deployment_script(trap, profile, server_url)
        return Response(content=content, media_type="text/x-shellscript")
    else:
        content = generate_powershell_deployment_script(trap, profile, server_url)
        return Response(content=content, media_type="text/plain")

@router.post("/{trap_id}/action")
async def execute_trap_action(
    trap_id: str,
    action_data: dict,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Выполнение действия над ловушкой (остановить, обновить конфигурацию, ротировать креды, сменить профиль)"""
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Ловушка не найдена")

    action = action_data.get("action")
    details = f"Действие '{action}' для ловушки {trap.trap_id}"

    if action == "stop":
        trap.status = "offline"
        details = f"Остановлена ловушка {trap.trap_id}"
    elif action == "start":
        trap.status = "online"
        trap.last_seen = datetime.datetime.utcnow()
        details = f"Ловушка {trap.trap_id} активирована и переведена в режим онлайн"
    elif action == "update_config":
        trap.config_version += 1
        details = f"Конфигурация ловушки {trap.trap_id} обновлена до v{trap.config_version}"
    elif action == "rotate_creds":
        trap.secret_key = str(uuid.uuid4().hex)
        trap.config_version += 1
        details = f"Выполнена ротация учетных данных ловушки {trap.trap_id}"
    elif action == "change_profile":
        new_prof_id = action_data.get("profile_id")
        if new_prof_id:
            trap.profile_id = int(new_prof_id)
            trap.config_version += 1
            details = f"Сменен профиль ловушки {trap.trap_id} на #{new_prof_id}"

    audit = AuditLog(
        username=user.get("username", "admin"),
        action=f"trap_{action}",
        target_type="trap",
        target_id=trap.trap_id,
        details=details
    )
    db.add(audit)
    await db.commit()
    res = {"status": "success", "message": details, "config_version": trap.config_version}
    if action == "rotate_creds":
        res["new_secret_key"] = trap.secret_key
    return res

@router.delete("/{trap_id}")
async def delete_trap(
    trap_id: str,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")
        
    audit = AuditLog(
        username=user.get("username", "admin"),
        action="delete_trap",
        target_type="trap",
        target_id=trap.trap_id,
        details=f"Удалена ловушка '{trap.name}' [{trap.trap_id}]"
    )
    db.add(audit)
    await db.delete(trap)
    await db.commit()
    return {"status": "success", "message": f"Trap {trap_id} deregistered"}
