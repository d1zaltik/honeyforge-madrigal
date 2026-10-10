from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import User, AuditLog
from honeyforge_server.app.schemas import UserLogin, TokenResponse, UserOut
from honeyforge_server.app.security import verify_password, create_access_token, hash_password

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == credentials.username))
    user = result.scalars().first()
    
    # If initial admin doesn't exist, auto-seed default credentials
    if not user and credentials.username == "admin" and credentials.password == "admin123":
        user = User(
            username="admin",
            password_hash=hash_password("admin123"),
            role="admin",
            is_active=True
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    elif not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
        
    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    
    # Write audit log
    audit = AuditLog(
        username=user.username,
        action="operator_login",
        target_type="auth",
        target_id=str(user.id),
        details="Operator logged in to Cyber SOC console"
    )
    db.add(audit)
    await db.commit()
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserOut.model_validate(user)
    )

@router.get("/me", response_model=UserOut)
async def get_me(username: str = "admin", db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut.model_validate(user)
