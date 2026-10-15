import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Profile, Trap, AuditLog
from honeyforge_server.app.schemas import ProfileCreate, ProfileUpdate, ProfileOut
from honeyforge_server.app.security import get_current_user, require_admin

router = APIRouter(prefix="/profiles", tags=["Trap Profiles"])

@router.get("", response_model=List[ProfileOut])
async def list_profiles(user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).order_by(Profile.id.desc()))
    profiles = result.scalars().all()
    out = []
    for p in profiles:
        tc_res = await db.execute(select(func.count(Trap.id)).where(Trap.profile_id == p.id))
        count = tc_res.scalar() or 0
        p_data = ProfileOut.model_validate(p)
        p_data.traps_count = count
        out.append(p_data)
    return out

@router.post("", response_model=ProfileOut)
async def create_profile(
    profile_in: ProfileCreate,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    # Check duplicate name
    existing = await db.execute(select(Profile).where(Profile.name == profile_in.name))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="Профиль с таким именем уже существует")
        
    profile = Profile(
        name=profile_in.name,
        description=profile_in.description or "",
        interaction_level=profile_in.interaction_level,
        services=profile_in.services,
        banners=profile_in.banners,
        decoy_credentials=profile_in.decoy_credentials,
        honeytokens_config=profile_in.honeytokens_config,
        logging_params=profile_in.logging_params,
        stealth_params=profile_in.stealth_params,
        persona=profile_in.persona.model_dump() if hasattr(profile_in.persona, "model_dump") else (profile_in.persona or {
            "hostname": "prod-srv-01",
            "os": "Ubuntu 22.04.4 LTS",
            "kernel": "5.15.0-89-generic",
            "uptime_base": 172800,
            "users": ["root", "deploy", "ubuntu"]
        }),
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    
    audit = AuditLog(
        username=user.get("username", "admin"),
        action="create_profile",
        target_type="profile",
        target_id=str(profile.id),
        details=f"Создан профиль '{profile.name}' (уровень: {profile.interaction_level})"
    )
    db.add(audit)
    await db.commit()
    
    p_data = ProfileOut.model_validate(profile)
    p_data.traps_count = 0
    return p_data

@router.post("/{profile_id}/copy", response_model=ProfileOut)
async def copy_profile(
    profile_id: int,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    orig = result.scalars().first()
    if not orig:
        raise HTTPException(status_code=404, detail="Профиль не найден")
        
    new_name = f"{orig.name} (Копия)"
    # Avoid duplicate
    dup_chk = await db.execute(select(Profile).where(Profile.name == new_name))
    if dup_chk.scalars().first():
        new_name = f"{orig.name} (Копия {datetime.datetime.utcnow().strftime('%H%M%S')})"

    new_prof = Profile(
        name=new_name,
        description=orig.description,
        interaction_level=orig.interaction_level,
        services=orig.services,
        banners=orig.banners,
        decoy_credentials=orig.decoy_credentials,
        honeytokens_config=orig.honeytokens_config,
        logging_params=orig.logging_params,
        stealth_params=orig.stealth_params,
        persona=orig.persona or {},
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.add(new_prof)
    await db.commit()
    await db.refresh(new_prof)

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="copy_profile",
        target_type="profile",
        target_id=str(new_prof.id),
        details=f"Скопирован профиль #{orig.id} -> #{new_prof.id} '{new_prof.name}'"
    )
    db.add(audit)
    await db.commit()

    p_data = ProfileOut.model_validate(new_prof)
    p_data.traps_count = 0
    return p_data

@router.get("/{profile_id}", response_model=ProfileOut)
async def get_profile(
    profile_id: int,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalars().first()
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    tc_res = await db.execute(select(func.count(Trap.id)).where(Trap.profile_id == profile.id))
    p_data = ProfileOut.model_validate(profile)
    p_data.traps_count = tc_res.scalar() or 0
    return p_data

@router.put("/{profile_id}", response_model=ProfileOut)
async def update_profile(
    profile_id: int,
    profile_in: ProfileUpdate,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalars().first()
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
        
    for field, val in profile_in.model_dump(exclude_unset=True).items():
        setattr(profile, field, val)
    profile.updated_at = datetime.datetime.utcnow()
    
    await db.commit()
    await db.refresh(profile)

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="update_profile",
        target_type="profile",
        target_id=str(profile.id),
        details=f"Обновлен профиль '{profile.name}'"
    )
    db.add(audit)
    await db.commit()

    tc_res = await db.execute(select(func.count(Trap.id)).where(Trap.profile_id == profile.id))
    p_data = ProfileOut.model_validate(profile)
    p_data.traps_count = tc_res.scalar() or 0
    return p_data

@router.delete("/{profile_id}")
async def delete_profile(
    profile_id: int,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalars().first()
    if not profile:
        raise HTTPException(status_code=404, detail="Профиль не найден")
        
    # Check if any traps are bound to this profile
    bound_traps = await db.execute(select(Trap).where(Trap.profile_id == profile_id))
    if bound_traps.scalars().first():
        raise HTTPException(status_code=400, detail="Удаление запрещено: к профилю привязаны активные ловушки")

    prof_name = profile.name
    await db.delete(profile)
    await db.commit()

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="delete_profile",
        target_type="profile",
        target_id=str(profile_id),
        details=f"Удален профиль '{prof_name}'"
    )
    db.add(audit)
    await db.commit()

    return {"status": "success", "message": f"Профиль {profile_id} удален"}
