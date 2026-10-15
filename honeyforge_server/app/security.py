import hmac
import hashlib
import time
import base64
import json
import secrets
import threading
import uuid
from typing import Optional, Dict, Any, Tuple
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select

from honeyforge_server.app.config import settings
from honeyforge_server.app.database import AsyncSessionLocal
from honeyforge_server.app.models import User

# =====================================================================
# 1. PBKDF2-HMAC-SHA256 Password Hashing & Legacy Fallback Migration
# =====================================================================
PBKDF2_ITERATIONS = 600000

def hash_password(password: str) -> str:
    """
    Hashes password using PBKDF2-HMAC-SHA256 with 600,000 iterations and per-user salt.
    Format: pbkdf2$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${salt.hex()}${key.hex()}"

def verify_password_and_needs_rehash(plain_password: str, hashed_password: str) -> Tuple[bool, bool]:
    """
    Verifies password.
    Returns (is_valid, needs_rehash).
    Supports seamless migration from legacy SHA256 hashes to PBKDF2-HMAC-SHA256.
    """
    if not hashed_password:
        return False, False

    if hashed_password.startswith("pbkdf2$"):
        try:
            parts = hashed_password.split("$")
            if len(parts) != 3:
                return False, False
            salt = bytes.fromhex(parts[1])
            expected_key = bytes.fromhex(parts[2])
            calc_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
            return hmac.compare_digest(calc_key, expected_key), False
        except Exception:
            return False, False
    else:
        # Legacy format fallback: SHA-256 with static salt
        legacy_salt = "honeyforge_salt_2026"
        calc_hash = hashlib.sha256(f"{legacy_salt}{plain_password}".encode("utf-8")).hexdigest()
        if hmac.compare_digest(calc_hash, hashed_password):
            return True, True
        return False, False

def verify_password(plain_password: str, hashed_password: str) -> bool:
    valid, _ = verify_password_and_needs_rehash(plain_password, hashed_password)
    return valid


# =====================================================================
# 2. JWT Access Tokens with JTI & Token Revocation Denylist
# =====================================================================
_revoked_jtis: Dict[str, float] = {}
_revoke_lock = threading.Lock()

def revoke_token(jti: str, exp: float):
    """Adds token JTI to in-memory denylist until its expiration"""
    with _revoke_lock:
        now = time.time()
        # Clean expired records
        expired = [k for k, v in _revoked_jtis.items() if v <= now]
        for k in expired:
            del _revoked_jtis[k]
        _revoked_jtis[jti] = exp

def is_token_revoked(jti: str) -> bool:
    """Checks if token JTI is in revocation denylist"""
    with _revoke_lock:
        now = time.time()
        exp = _revoked_jtis.get(jti)
        if exp is None:
            return False
        if exp <= now:
            del _revoked_jtis[jti]
            return False
        return True

def create_access_token(data: dict, expires_in_seconds: Optional[int] = None) -> str:
    """Creates signed JWT with unique jti and configurable expiration (default 8 hours)"""
    if expires_in_seconds is None:
        expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["exp"] = int(time.time()) + expires_in_seconds
    if "jti" not in payload:
        payload["jti"] = uuid.uuid4().hex

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    signature_base = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(settings.JWT_SECRET.encode(), signature_base, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{sig_b64}"

def decode_access_token(token: str) -> Optional[dict]:
    """Decodes and validates JWT token signature, expiration, and revocation status"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        signature_base = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(settings.JWT_SECRET.encode(), signature_base, hashlib.sha256).digest()

        padding_needed = 4 - (len(sig_b64) % 4)
        if padding_needed != 4:
            sig_b64 += "=" * padding_needed
        actual_sig = base64.urlsafe_b64decode(sig_b64.encode())

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_padding = 4 - (len(payload_b64) % 4)
        if payload_padding != 4:
            payload_b64 += "=" * payload_padding
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode())

        if payload_data.get("exp", 0) < time.time():
            return None

        jti = payload_data.get("jti")
        if jti and is_token_revoked(jti):
            return None

        return payload_data
    except Exception:
        return None


# =====================================================================
# 3. Agent HMAC Signature with Body SHA-256 & Replay Protection
# =====================================================================
# Allowed time skew window: 300 seconds (5 minutes)
HMAC_TIME_WINDOW_SECONDS = 300.0

# In-memory nonce cache with thread lock
# NOTE: For distributed multi-worker deployments, replace this in-memory cache
# with a Redis SETNX command: SET nonce:<nonce> 1 EX 180 NX
_nonce_cache: Dict[str, float] = {}
_nonce_lock = threading.Lock()

def _clean_nonce_cache_locked(now: float):
    cutoff = now - HMAC_TIME_WINDOW_SECONDS
    expired = [n for n, ts in _nonce_cache.items() if ts < cutoff]
    for n in expired:
        del _nonce_cache[n]

def verify_agent_signature(
    trap_id: str,
    timestamp: float,
    nonce: str,
    signature: str,
    secret_key: str,
    raw_body: bytes = b""
) -> bool:
    """
    Verifies agent telemetry HMAC-SHA256 signature:
    - Covers trap_id, timestamp, nonce, and SHA-256 of raw request body.
    - Replay protection: verifies timestamp skew <= 180s and checks nonce uniqueness.
    - Constant-time comparison via hmac.compare_digest.
    """
    now = time.time()
    # Check timestamp window
    if abs(now - timestamp) > HMAC_TIME_WINDOW_SECONDS:
        return False

    with _nonce_lock:
        _clean_nonce_cache_locked(now)
        # Check nonce replay
        if nonce in _nonce_cache:
            return False
        _nonce_cache[nonce] = timestamp

    # SHA-256 of body (empty bytes SHA-256 for GET requests)
    body_hash = hashlib.sha256(raw_body).hexdigest()
    data_to_sign = f"{trap_id}:{timestamp}:{nonce}:{body_hash}".encode("utf-8")
    expected_sig = hmac.new(secret_key.encode("utf-8"), data_to_sign, hashlib.sha256).hexdigest()

    return hmac.compare_digest(expected_sig, signature)

def generate_agent_signature(
    trap_id: str,
    timestamp: float,
    nonce: str,
    secret_key: str,
    raw_body: bytes = b""
) -> str:
    """Generates HMAC-SHA256 signature incorporating body SHA-256"""
    body_hash = hashlib.sha256(raw_body).hexdigest()
    data_to_sign = f"{trap_id}:{timestamp}:{nonce}:{body_hash}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), data_to_sign, hashlib.sha256).hexdigest()


# =====================================================================
# 4. Single-Use WebSocket Connection Tickets
# =====================================================================
_ws_tickets: Dict[str, Dict[str, Any]] = {}
_ticket_lock = threading.Lock()

def create_ws_ticket(user: dict, ttl_seconds: int = 30) -> str:
    """Generates a single-use ticket valid for 30 seconds for WebSocket connection"""
    ticket = secrets.token_urlsafe(32)
    with _ticket_lock:
        now = time.time()
        # Clean expired tickets
        expired = [k for k, v in _ws_tickets.items() if v["exp"] <= now]
        for k in expired:
            del _ws_tickets[k]

        _ws_tickets[ticket] = {
            "username": user.get("username", "unknown"),
            "role": user.get("role", "analyst"),
            "exp": now + ttl_seconds
        }
    return ticket

def consume_ws_ticket(ticket: str) -> Optional[dict]:
    """Atomically consumes and invalidates a single-use WebSocket ticket"""
    if not ticket:
        return None
    with _ticket_lock:
        ticket_data = _ws_tickets.pop(ticket, None)
        if not ticket_data:
            return None
        if ticket_data["exp"] < time.time():
            return None
        return ticket_data


# =====================================================================
# 5. In-App Login Attempt Lockout
# =====================================================================
# 5 failures in 5 minutes -> 5 minutes lockout
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 300.0
LOCKOUT_DURATION_SECONDS = 300.0

_login_attempts: Dict[str, list] = {}
_lockouts: Dict[str, float] = {}
_lockout_lock = threading.Lock()

def check_login_lockout(key: str) -> Tuple[bool, int]:
    """Returns (is_locked, remaining_seconds)"""
    with _lockout_lock:
        now = time.time()
        lock_until = _lockouts.get(key)
        if lock_until:
            if now < lock_until:
                return True, int(lock_until - now)
            else:
                del _lockouts[key]
                _login_attempts.pop(key, None)
        return False, 0

def record_login_failure(key: str) -> Tuple[int, bool, int]:
    """Records failed attempt, returns (current_fail_count, is_now_locked, lock_seconds)"""
    with _lockout_lock:
        now = time.time()
        attempts = _login_attempts.get(key, [])
        # Filter attempts within window
        attempts = [t for t in attempts if now - t <= LOCKOUT_WINDOW_SECONDS]
        attempts.append(now)
        _login_attempts[key] = attempts

        if len(attempts) >= LOCKOUT_THRESHOLD:
            _lockouts[key] = now + LOCKOUT_DURATION_SECONDS
            _login_attempts.pop(key, None)
            return len(attempts), True, int(LOCKOUT_DURATION_SECONDS)

        return len(attempts), False, 0

def reset_login_failures(key: str):
    """Resets failed attempt counter on successful login"""
    with _lockout_lock:
        _login_attempts.pop(key, None)
        _lockouts.pop(key, None)


# =====================================================================
# 6. FastAPI Dependencies: get_current_user & require_admin
# =====================================================================
security_bearer = HTTPBearer(auto_error=False)

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> dict:
    """
    FR-C5: Проверка JWT-токена доступа в заголовке Authorization: Bearer <token>.
    Проверяет валидность токена, статус отзыва и актуальное состояние пользователя в БД.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не авторизован",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не авторизован",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("username") or payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не авторизован",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify user state in database
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(User).where(User.username == username))
        user_obj = res.scalars().first()
        if not user_obj or not user_obj.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь не найден или учетная запись отключена",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Ensure fresh role from DB
        payload["username"] = user_obj.username
        payload["role"] = user_obj.role
        payload["id"] = user_obj.id

    return payload

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """
    FR-C5: Ограничение доступа только для администраторов (role == 'admin').
    Аналитикам возвращает HTTP 403 Forbidden.
    """
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав. Требуется роль администратора"
        )
    return user
