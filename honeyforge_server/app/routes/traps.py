import uuid
import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Trap, Profile, AuditLog
from honeyforge_server.app.schemas import TrapRegister, TrapOut
from honeyforge_server.app.orchestrator import (
    generate_docker_compose_artifact,
    generate_bash_deployment_script,
    generate_powershell_deployment_script
)

router = APIRouter(prefix="/traps", tags=["Traps Management"])

@router.get("", response_model=List[TrapOut])
async def list_traps(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Trap).order_by(Trap.id.desc()))
    traps = result.scalars().all()
    out = []
    
    # Check offline status based on last_seen (offline if no beacon in > 45s)
    now = datetime.datetime.utcnow()
    for t in traps:
        status = t.status
        if t.last_seen:
            diff = (now - t.last_seen).total_seconds()
            if diff > 45:
                status = "offline"
        else:
            status = "offline"
            
        p_name = None
        if t.profile_id:
            pres = await db.execute(select(Profile.name).where(Profile.id == t.profile_id))
            p_name = pres.scalar_one_or_none()
            
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
            profile_name=p_name
        ))
    return out

@router.post("", response_model=TrapOut)
async def register_trap(trap_in: TrapRegister, db: AsyncSession = Depends(get_db)):
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
        username="admin",
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
        created_at=trap.created_at
    )

@router.get("/{trap_id}/config")
async def get_trap_config(trap_id: str, db: AsyncSession = Depends(get_db)):
    """Delivers runtime configuration for the trap based on its bound profile (FR-C3)"""
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")
        
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
        "decoy_credentials": profile.decoy_credentials if profile else [{"user": "root", "pass": "admin123"}, {"user": "admin", "pass": "admin"}],
        "honeytokens": profile.honeytokens_config if profile else [],
        "stealth": profile.stealth_params if profile else {
            "proc_name": "systemd-resolved",
            "beacon_interval_s": 10,
            "jitter_pct": 35,
            "dummy_padding": True
        }
    }
    return config

@router.get("/{trap_id}/deploy-artifact")
async def get_deploy_artifact(
    trap_id: str,
    format: str = Query("docker-compose", enum=["docker-compose", "bash", "powershell"]),
    server_url: str = "http://127.0.0.1:8000",
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

@router.delete("/{trap_id}")
async def delete_trap(trap_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Trap).where(Trap.trap_id == trap_id))
    trap = result.scalars().first()
    if not trap:
        raise HTTPException(status_code=404, detail="Trap not found")
        
    await db.delete(trap)
    await db.commit()
    return {"status": "success", "message": f"Trap {trap_id} deregistered"}
