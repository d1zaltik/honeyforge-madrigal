import time
import os
import json
import hashlib
import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import User, AuditLog, Trap
from honeyforge_server.app.schemas import (
    UserLogin, TokenResponse, UserOut, UserCreate,
    UserRoleUpdate, UserStatusUpdate, UserPasswordReset,
    KeyStoreExportRequest, KeyStoreInspectRequest
)
from honeyforge_server.app.security import (
    verify_password_and_needs_rehash,
    create_access_token,
    decode_access_token,
    hash_password,
    get_current_user,
    revoke_token,
    create_ws_ticket,
    check_login_lockout,
    record_login_failure,
    reset_login_failures,
    security_bearer
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    """
    FR-C5: Аутентификация оператора SOC.
    Защита от перебора (brute-force): блокировка на 5 минут после 5 неудачных попыток.
    Бесшовная миграция старых хэшей паролей на безопасный PBKDF2-HMAC-SHA256 (600,000 итераций).
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    lockout_key = f"{credentials.username}:{client_ip}"

    # 1. Проверка блокировки
    is_locked, remaining_seconds = check_login_lockout(lockout_key)
    if is_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Слишком много неудачных попыток входа. Попробуйте снова через {remaining_seconds} сек."
        )

    # 2. Поиск пользователя в БД
    result = await db.execute(select(User).where(User.username == credentials.username))
    user = result.scalars().first()

    if not user or not user.is_active:
        fail_count, is_now_locked, lock_sec = record_login_failure(lockout_key)
        audit_fail = AuditLog(
            username=credentials.username,
            action="failed_login",
            target_type="auth",
            target_id="0",
            details=f"Неудачная попытка входа: несуществующий или отключенный пользователь (попытка #{fail_count})",
            ip_address=client_ip
        )
        db.add(audit_fail)
        await db.commit()
        if is_now_locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Превышено допустимое число попыток входа. Учетная запись заблокирована на {lock_sec} сек."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )

    # 3. Верификация пароля
    is_valid, needs_rehash = verify_password_and_needs_rehash(credentials.password, user.password_hash)
    if not is_valid:
        fail_count, is_now_locked, lock_sec = record_login_failure(lockout_key)
        audit_fail = AuditLog(
            username=user.username,
            action="failed_login",
            target_type="auth",
            target_id=str(user.id),
            details=f"Неудачная попытка входа: неверный пароль (попытка #{fail_count})",
            ip_address=client_ip
        )
        db.add(audit_fail)
        await db.commit()
        if is_now_locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Превышено допустимое число попыток входа. Доступ заблокирован на {lock_sec} сек."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверное имя пользователя или пароль"
        )

    # Сброс счетчика неудач при успешном входе
    reset_login_failures(lockout_key)

    # Автоматическое перехеширование в PBKDF2 при необходимости
    if needs_rehash:
        user.password_hash = hash_password(credentials.password)
        await db.commit()

    token = create_access_token({"sub": user.username, "username": user.username, "role": user.role, "id": user.id})

    # Журналирование успешного входа
    audit = AuditLog(
        username=user.username,
        action="operator_login",
        target_type="auth",
        target_id=str(user.id),
        details=f"Вход оператора SOC ({user.role}) в панель управления",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserOut.model_validate(user)
    )

@router.post("/logout")
async def logout(
    request: Request,
    user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer),
    db: AsyncSession = Depends(get_db)
):
    """
    FR-C5: Завершение сессии (Logout).
    Добавляет JTI токена в denylist отозванных токенов для исключения повторного использования.
    """
    if not credentials or not credentials.credentials:
        return {"status": "ok", "message": "Сессия завершена"}

    token = credentials.credentials
    payload = decode_access_token(token)
    username = "unknown"
    if payload:
        jti = payload.get("jti")
        exp = payload.get("exp", time.time() + 3600)
        username = payload.get("username", "unknown")
        if jti:
            revoke_token(jti, exp)

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        username=username,
        action="operator_logout",
        target_type="auth",
        target_id=username,
        details="Оператор завершил сеанс (токен отозван)",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()

    return {"status": "ok", "message": "Сессия успешно завершена"}

@router.post("/ws-ticket")
async def get_websocket_ticket(user: dict = Depends(get_current_user)):
    """
    Одноразовый билет для защищенного подключения к WebSocket (/ws/attacks).
    Действителен в течение 30 секунд. Предотвращает утечку долговременных JWT в query-параметрах и логах Nginx.
    """
    ticket = create_ws_ticket(user, ttl_seconds=30)
    return {"ticket": ticket, "expires_in": 30}

@router.get("/me", response_model=UserOut)
async def get_me(user_token: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    username = user_token.get("username") or user_token.get("sub")
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return UserOut.model_validate(user)

# =====================================================================
# 6. User Management Endpoints (RBAC)
# =====================================================================
VALID_ROLES = ["admin", "soc_lead", "analyst_l2", "analyst_l1", "auditor", "analyst"]

def require_role(user: dict, allowed_roles: List[str]):
    role = user.get("role", "")
    if role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Недостаточно прав. Требуется одна из ролей: {', '.join(allowed_roles)}"
        )

@router.get("/users", response_model=List[UserOut])
async def list_users(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Список зарегистрированных операторов SOC платформы."""
    require_role(user, ["admin", "soc_lead", "auditor"])
    result = await db.execute(select(User).order_by(User.id.asc()))
    users = result.scalars().all()
    return [UserOut.model_validate(u) for u in users]

@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    new_user: UserCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Создание нового оператора SOC (доступно только роли admin)."""
    require_role(current_user, ["admin"])

    if new_user.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Недопустимая роль. Доступные роли: {', '.join(VALID_ROLES)}"
        )

    # Check if username exists
    existing = await db.execute(select(User).where(User.username == new_user.username))
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Пользователь с именем '{new_user.username}' уже существует"
        )

    if len(new_user.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен содержать не менее 6 символов"
        )

    user_obj = User(
        username=new_user.username,
        password_hash=hash_password(new_user.password),
        role=new_user.role,
        is_active=True
    )
    db.add(user_obj)
    await db.flush()

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        username=current_user.get("username", "admin"),
        action="user_created",
        target_type="auth",
        target_id=str(user_obj.id),
        details=f"Создан новый оператор SOC '{user_obj.username}' с ролью '{user_obj.role}'",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()
    await db.refresh(user_obj)

    return UserOut.model_validate(user_obj)

@router.patch("/users/{user_id}/status", response_model=UserOut)
async def update_user_status(
    user_id: int,
    status_update: UserStatusUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Включение / отключение учетной записи оператора."""
    require_role(current_user, ["admin"])

    if user_id == current_user.get("id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Запрещено блокировать собственную учетную запись"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    target_user.is_active = status_update.is_active
    client_ip = request.client.host if request.client else "127.0.0.1"
    action_str = "активирован" if status_update.is_active else "заблокирован"
    audit = AuditLog(
        username=current_user.get("username", "admin"),
        action="user_status_changed",
        target_type="auth",
        target_id=str(target_user.id),
        details=f"Оператор '{target_user.username}' {action_str}",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()
    await db.refresh(target_user)
    return UserOut.model_validate(target_user)

@router.patch("/users/{user_id}/role", response_model=UserOut)
async def update_user_role(
    user_id: int,
    role_update: UserRoleUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Изменение роли оператора в SOC."""
    require_role(current_user, ["admin"])

    if role_update.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Недопустимая роль. Доступные роли: {', '.join(VALID_ROLES)}"
        )

    if user_id == current_user.get("id") and role_update.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Нельзя понизить права собственного аккаунта администратора"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    old_role = target_user.role
    target_user.role = role_update.role
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        username=current_user.get("username", "admin"),
        action="user_role_changed",
        target_type="auth",
        target_id=str(target_user.id),
        details=f"Роль оператора '{target_user.username}' изменена с '{old_role}' на '{target_user.role}'",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()
    await db.refresh(target_user)
    return UserOut.model_validate(target_user)

@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    pwd_reset: UserPasswordReset,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Сброс пароля оператора SOC."""
    require_role(current_user, ["admin"])

    if len(pwd_reset.new_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Новый пароль должен содержать не менее 6 символов"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    target_user.password_hash = hash_password(pwd_reset.new_password)
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        username=current_user.get("username", "admin"),
        action="user_password_reset",
        target_type="auth",
        target_id=str(target_user.id),
        details=f"Пароль оператора '{target_user.username}' сброшен администратором",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()
    return {"status": "ok", "message": f"Пароль оператора '{target_user.username}' успешно обновлен"}

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Удаление оператора из системы."""
    require_role(current_user, ["admin"])

    if user_id == current_user.get("id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Запрещено удалять собственный аккаунт"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalars().first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    deleted_username = target_user.username
    await db.delete(target_user)

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        username=current_user.get("username", "admin"),
        action="user_deleted",
        target_type="auth",
        target_id=str(user_id),
        details=f"Оператор '{deleted_username}' удален из системы",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()
    return {"status": "ok", "message": f"Оператор '{deleted_username}' успешно удален"}

# =====================================================================
# 7. Password-Protected KeyStore (AES-256-GCM + PBKDF2-HMAC-SHA256)
# =====================================================================
@router.post("/keystore/export")
async def export_keystore(
    req: KeyStoreExportRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Экспорт зашифрованного хранилища ключей KeyStore.
    Защита: Мастер-пароль -> PBKDF2-HMAC-SHA256 (100,000 итераций) -> AES-256-GCM (12-байтный nonce).
    Содержит криптографические ключи узлов ловушек, секреты подписи телеметрии и токены.
    """
    require_role(current_user, ["admin", "soc_lead"])

    if not req.master_password or len(req.master_password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Мастер-пароль KeyStore должен содержать не менее 6 символов"
        )

    # Сбор секретов ловушек
    traps_res = await db.execute(select(Trap).order_by(Trap.id.asc()))
    traps = traps_res.scalars().all()

    traps_data = []
    for t in traps:
        traps_data.append({
            "trap_id": t.trap_id,
            "name": t.name,
            "interaction_level": t.interaction_level,
            "ip_address": t.ip_address,
            "mgmt_ip": t.mgmt_ip,
            "status": t.status,
            "secret_key": t.secret_key,
            "config_version": t.config_version,
            "last_seen": t.last_seen.isoformat() if t.last_seen else None
        })

    payload_dict = {
        "format": "HFKS",
        "version": 1,
        "description": req.description or "HoneyForge SOC Production KeyStore",
        "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
        "exported_by": current_user.get("username", "admin"),
        "platform_id": "honeyforge-c2-main",
        "crypto_specs": {
            "node_auth": "HMAC-SHA256",
            "channel_encryption": "TLS 1.3",
            "keystore_cipher": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256"
        },
        "node_keys": traps_data,
        "summary": {
            "total_nodes": len(traps_data),
            "online_nodes": sum(1 for t in traps_data if t["status"] == "online")
        }
    }

    payload_json = json.dumps(payload_dict, ensure_ascii=False, indent=2).encode("utf-8")

    # Шифрование
    salt = os.urandom(16)
    kdf_key = hashlib.pbkdf2_hmac("sha256", req.master_password.encode("utf-8"), salt, 100000, 32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(kdf_key)
    ciphertext = aesgcm.encrypt(nonce, payload_json, None)

    keystore_envelope = {
        "format": "HFKS",
        "version": 1,
        "description": req.description,
        "kdf": {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": 100000,
            "salt": salt.hex()
        },
        "cipher": {
            "algorithm": "AES-256-GCM",
            "nonce": nonce.hex()
        },
        "ciphertext": ciphertext.hex(),
        "metadata": {
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "exported_by": current_user.get("username", "admin"),
            "node_count": len(traps_data),
            "fingerprint": hashlib.sha256(ciphertext).hexdigest()[:16]
        }
    }

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        username=current_user.get("username", "admin"),
        action="keystore_exported",
        target_type="keystore",
        target_id=keystore_envelope["metadata"]["fingerprint"],
        details=f"Экспорт зашифрованного KeyStore ({len(traps_data)} узлов) с мастер-паролем",
        ip_address=client_ip
    )
    db.add(audit)
    await db.commit()

    return keystore_envelope

@router.post("/keystore/inspect")
async def inspect_keystore(
    req: KeyStoreInspectRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Проверка и расшифровка KeyStore с использованием мастер-пароля.
    При неверном пароле или повреждении данных возвращает ошибку тега AES-GCM (InvalidTag).
    """
    require_role(current_user, ["admin", "soc_lead", "analyst_l2", "auditor"])

    try:
        if isinstance(req.keystore_data, str):
            raw = req.keystore_data.strip()
            data = json.loads(raw)
        else:
            data = req.keystore_data

        if not isinstance(data, dict) or "ciphertext" not in data or "kdf" not in data or "cipher" not in data:
            raise ValueError("Некорректный формат пакета KeyStore")

        salt = bytes.fromhex(data["kdf"]["salt"])
        iterations = int(data["kdf"].get("iterations", 100000))
        nonce = bytes.fromhex(data["cipher"]["nonce"])
        ciphertext = bytes.fromhex(data["ciphertext"])

        kdf_key = hashlib.pbkdf2_hmac("sha256", req.master_password.encode("utf-8"), salt, iterations, 32)
        aesgcm = AESGCM(kdf_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        decrypted_dict = json.loads(decrypted_bytes.decode("utf-8"))

        client_ip = request.client.host if request.client else "127.0.0.1"
        audit = AuditLog(
            username=current_user.get("username", "admin"),
            action="keystore_inspected",
            target_type="keystore",
            target_id=data.get("metadata", {}).get("fingerprint", "unknown"),
            details="Успешная аутентификация и расшифровка KeyStore",
            ip_address=client_ip
        )
        db.add(audit)
        await db.commit()

        return {
            "status": "ok",
            "verified": True,
            "algorithm": "AES-256-GCM",
            "metadata": data.get("metadata", {}),
            "payload": decrypted_dict
        }

    except InvalidTag:
        client_ip = request.client.host if request.client else "127.0.0.1"
        audit = AuditLog(
            username=current_user.get("username", "admin"),
            action="keystore_failed_inspection",
            target_type="keystore",
            target_id="0",
            details="Попытка расшифровки KeyStore с неверным мастер-паролем (InvalidTag)",
            ip_address=client_ip
        )
        db.add(audit)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный мастер-пароль или файл KeyStore поврежден (ошибка проверки аутентификационного тега AES-GCM)"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ошибка обработки пакета KeyStore: {str(e)}"
        )

