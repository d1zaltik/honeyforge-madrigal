from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import AuditLog
from honeyforge_server.app.schemas import AuditLogOut
from honeyforge_server.app.security import get_current_user

router = APIRouter(prefix="/audit", tags=["Audit Log"])

@router.get("", response_model=List[AuditLogOut])
async def list_audit_logs(
    username: Optional[str] = Query(None, description="Фильтр по оператору"),
    action: Optional[str] = Query(None, description="Фильтр по действию"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Журнал аудита действий операторов (только чтение)"""
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))
    if username:
        query = query.where(AuditLog.username == username)
    if action:
        query = query.where(AuditLog.action == action)
    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    logs = result.scalars().all()
    return [AuditLogOut.model_validate(log) for log in logs]
