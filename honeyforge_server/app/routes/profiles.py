import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Profile, AuditLog
from honeyforge_server.app.schemas import ProfileCreate, ProfileUpdate, ProfileOut

router = APIRouter(prefix="/profiles", tags=["Trap Profiles"])

@router.get("", response_model=List[ProfileOut])
async def list_profiles(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).order_by(Profile.id.desc()))
    profiles = result.scalars().all()
    return [ProfileOut.model_validate(p) for p in profiles]

@router.post("", response_model=ProfileOut)
async def create_profile(profile_in: ProfileCreate, db: AsyncSession = Depends(get_db)):
    # Check duplicate name
    existing = await db.execute(select(Profile).where(Profile.name == profile_in.name))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="Profile with this name already exists")
        
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
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    
    audit = AuditLog(
        username="admin",
        action="create_profile",
        target_type="profile",
        target_id=str(profile.id),
        details=f"Created profile '{profile.name}' with level '{profile.interaction_level}'"
    )
    db.add(audit)
    await db.commit()
    
    return ProfileOut.model_validate(profile)

@router.get("/{profile_id}", response_model=ProfileOut)
async def get_profile(profile_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalars().first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileOut.model_validate(profile)

@router.put("/{profile_id}", response_model=ProfileOut)
async def update_profile(profile_id: int, profile_in: ProfileUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalars().first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    for field, val in profile_in.model_dump(exclude_unset=True).items():
        setattr(profile, field, val)
    profile.updated_at = datetime.datetime.utcnow()
    
    await db.commit()
    await db.refresh(profile)
    return ProfileOut.model_validate(profile)

@router.delete("/{profile_id}")
async def delete_profile(profile_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalars().first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    await db.delete(profile)
    await db.commit()
    return {"status": "success", "message": f"Profile {profile_id} deleted"}
