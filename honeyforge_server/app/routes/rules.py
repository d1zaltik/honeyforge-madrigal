from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import AlertRule, AuditLog
from honeyforge_server.app.schemas import AlertRuleCreate, AlertRuleOut
from honeyforge_server.app.security import get_current_user, require_admin

router = APIRouter(prefix="/rules", tags=["Alert Rules"])

@router.get("", response_model=List[AlertRuleOut])
async def list_alert_rules(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(AlertRule).order_by(desc(AlertRule.id)))
    rules = result.scalars().all()
    return [AlertRuleOut.model_validate(r) for r in rules]

@router.post("", response_model=AlertRuleOut)
async def create_alert_rule(
    rule_in: AlertRuleCreate,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    rule = AlertRule(
        name=rule_in.name,
        rule_type=rule_in.rule_type,
        threshold=rule_in.threshold,
        window_seconds=rule_in.window_seconds,
        trap_id=rule_in.trap_id,
        severity=rule_in.severity,
        is_enabled=rule_in.is_enabled
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="create_rule",
        target_type="rule",
        target_id=str(rule.id),
        details=f"Добавлено правило оповещения '{rule.name}' (порог: {rule.threshold}, окно: {rule.window_seconds}с)"
    )
    db.add(audit)
    await db.commit()

    return AlertRuleOut.model_validate(rule)

@router.put("/{rule_id}/toggle", response_model=AlertRuleOut)
async def toggle_alert_rule(
    rule_id: int,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    rule.is_enabled = not rule.is_enabled
    await db.commit()
    await db.refresh(rule)

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="toggle_rule",
        target_type="rule",
        target_id=str(rule.id),
        details=f"Правило #{rule.id} '{rule.name}' {'включено' if rule.is_enabled else 'отключено'}"
    )
    db.add(audit)
    await db.commit()

    return AlertRuleOut.model_validate(rule)

@router.delete("/{rule_id}")
async def delete_alert_rule(
    rule_id: int,
    user: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(AlertRule).where(AlertRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Правило не найдено")

    audit = AuditLog(
        username=user.get("username", "admin"),
        action="delete_rule",
        target_type="rule",
        target_id=str(rule.id),
        details=f"Удалено правило #{rule.id} '{rule.name}'"
    )
    db.add(audit)
    await db.delete(rule)
    await db.commit()
    return {"status": "success", "message": f"Правило {rule_id} удалено"}
