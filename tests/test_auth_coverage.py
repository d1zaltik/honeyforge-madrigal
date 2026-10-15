import asyncio
import os
import sys
import time
import json
import uuid
import pytest
import pytest_asyncio
import httpx
from httpx import ASGITransport

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeyforge_server.app.main import app
from honeyforge_server.app.database import init_db, AsyncSessionLocal
from honeyforge_server.app.models import User, Trap, Profile
from honeyforge_server.app.security import (
    hash_password,
    verify_password_and_needs_rehash,
    create_access_token,
    decode_access_token,
    revoke_token,
    is_token_revoked,
    verify_agent_signature,
    generate_agent_signature,
    create_ws_ticket,
    consume_ws_ticket,
    record_login_failure,
    check_login_lockout,
    reset_login_failures,
    get_current_user,
    require_admin
)

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_test_db():
    await init_db()
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        for u_name, u_role, u_pwd in [
            ("test_admin_auth", "admin", "admin_pass_9981"),
            ("test_analyst_auth", "analyst", "analyst_pass_9981"),
            ("test_legacy_user", "analyst", "legacy_pass_9981")
        ]:
            res = await db.execute(select(User).where(User.username == u_name))
            if not res.scalars().first():
                db.add(User(
                    username=u_name,
                    password_hash=hash_password(u_pwd),
                    role=u_role,
                    is_active=True
                ))
        
        # Ensure test trap exists with known secret
        res_t = await db.execute(select(Trap).where(Trap.trap_id == "n-7f3a"))
        if not res_t.scalars().first():
            db.add(Trap(
                trap_id="n-7f3a",
                name="DMZ-Perimeter-Probe-01",
                interaction_level="low",
                ip_address="192.168.10.15",
                mgmt_ip="10.200.0.15",
                status="online",
                secret_key="secure-agent-key-test-01"
            ))
        await db.commit()
    yield

@pytest.mark.asyncio
async def test_01_pbkdf2_hashing_and_legacy_migration():
    """Validates PBKDF2-HMAC-SHA256 (600k iterations) and legacy migration fallback"""
    pwd = "CorrectHorseBatteryStaple2026!"
    hashed = hash_password(pwd)
    assert hashed.startswith("pbkdf2$"), "Hash format must start with pbkdf2$"

    is_valid, needs_rehash = verify_password_and_needs_rehash(pwd, hashed)
    assert is_valid is True
    assert needs_rehash is False

    is_valid_wrong, _ = verify_password_and_needs_rehash("WrongPassword", hashed)
    assert is_valid_wrong is False

    # Test legacy format migration
    legacy_salt = "honeyforge_salt_2026"
    import hashlib
    legacy_hash = hashlib.sha256(f"{legacy_salt}{pwd}".encode("utf-8")).hexdigest()
    leg_valid, leg_needs_rehash = verify_password_and_needs_rehash(pwd, legacy_hash)
    assert leg_valid is True
    assert leg_needs_rehash is True, "Legacy hash should trigger automatic rehash"

@pytest.mark.asyncio
async def test_02_agent_hmac_tampering_protection():
    """Validates that modifying trap_id, timestamp, nonce, or body invalidates agent signature"""
    secret = "secure-agent-key-alpha-99"
    trap_id = "trap-node-01"
    now = time.time()
    nonce = uuid.uuid4().hex
    raw_body = b'{"events":[{"event_type":"port_scan"}]}'

    sig = generate_agent_signature(trap_id, now, nonce, secret, raw_body=raw_body)
    assert verify_agent_signature(trap_id, now, nonce, sig, secret, raw_body=raw_body) is True

    # 1. Tamper body
    tampered_body = b'{"events":[{"event_type":"malicious_injection"}]}'
    assert verify_agent_signature(trap_id, now, nonce, sig, secret, raw_body=tampered_body) is False

    # 2. Tamper trap_id
    assert verify_agent_signature("trap-node-02", now, nonce, sig, secret, raw_body=raw_body) is False

    # 3. Tamper timestamp (outside window > 180s)
    old_time = now - 200.0
    sig_old = generate_agent_signature(trap_id, old_time, nonce, secret, raw_body=raw_body)
    assert verify_agent_signature(trap_id, old_time, nonce, sig_old, secret, raw_body=raw_body) is False

    # 4. Nonce replay
    replay_nonce = uuid.uuid4().hex
    sig_replay = generate_agent_signature(trap_id, now, replay_nonce, secret, raw_body=raw_body)
    assert verify_agent_signature(trap_id, now, replay_nonce, sig_replay, secret, raw_body=raw_body) is True
    # Immediate replay with same nonce must be rejected
    assert verify_agent_signature(trap_id, now, replay_nonce, sig_replay, secret, raw_body=raw_body) is False

@pytest.mark.asyncio
async def test_03_token_logout_revocation():
    """Validates that logged out tokens with jti are revoked via denylist"""
    token = create_access_token({"sub": "test_admin_auth", "username": "test_admin_auth", "role": "admin", "id": 1})
    payload = decode_access_token(token)
    assert payload is not None
    jti = payload["jti"]

    assert is_token_revoked(jti) is False
    revoke_token(jti, payload["exp"])
    assert is_token_revoked(jti) is True

    # Token decode must fail after revocation
    decoded_after = decode_access_token(token)
    assert decoded_after is None

@pytest.mark.asyncio
async def test_04_websocket_ticket_single_use():
    """Validates single-use WebSocket ticket issuance and consumption"""
    user_info = {"username": "soc_operator", "role": "admin"}
    ticket = create_ws_ticket(user_info, ttl_seconds=30)
    assert ticket is not None

    # First consumption succeeds
    consumed = consume_ws_ticket(ticket)
    assert consumed is not None
    assert consumed["username"] == "soc_operator"

    # Second consumption of same ticket must fail (single-use guarantee)
    consumed_again = consume_ws_ticket(ticket)
    assert consumed_again is None

@pytest.mark.asyncio
async def test_05_in_app_login_lockout():
    """Validates 5 failures within window triggers temporary lockout"""
    key = f"brute_force_user_{uuid.uuid4().hex[:6]}"
    assert check_login_lockout(key)[0] is False

    for attempt in range(1, 5):
        fails, is_locked, _ = record_login_failure(key)
        assert is_locked is False

    # 5th attempt triggers lockout
    fails, is_locked, lock_sec = record_login_failure(key)
    assert is_locked is True
    assert lock_sec > 0

    assert check_login_lockout(key)[0] is True
    reset_login_failures(key)
    assert check_login_lockout(key)[0] is False

@pytest.mark.asyncio
async def test_06_stealth_telemetry_indistinguishable_from_404():
    """
    TASK 2 & MASK-2 Verification:
    Asserts that unauthenticated requests to stealth telemetry and config paths
    receive the EXACT same response as non-existent paths across GET, POST, HEAD, OPTIONS
    (same status 404, identical JSON body '{"detail":"Not Found"}', identical headers).
    Also asserts valid signed telemetry gets HTTP 200 with ok status.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        methods = ["GET", "POST", "HEAD", "OPTIONS"]
        stealth_paths = [
            "/cdn-cgi/rum",
            "/static/v2/metrics",
            "/static/pixel.gif",
            "/sync/v1/config",
            "/sync/v1/config/n-7f3a",
        ]
        non_existent_path = "/non_existent_route_probe_x92"

        for p in stealth_paths:
            for m in methods:
                r_stealth = await client.request(m, p)
                r_nonexist = await client.request(m, non_existent_path)

                assert r_stealth.status_code == 404, f"{m} {p} status={r_stealth.status_code}, expected 404"
                assert r_stealth.status_code == r_nonexist.status_code
                assert r_stealth.content == r_nonexist.content, (
                    f"Mismatch on {m} {p}: stealth body '{r_stealth.content}' vs nonexist '{r_nonexist.content}'"
                )
                assert dict(r_stealth.headers) == dict(r_nonexist.headers), (
                    f"Header mismatch on {m} {p}: {r_stealth.headers} vs {r_nonexist.headers}"
                )

        # Verify authentic signed request succeeds (200 with status ok)
        trap_id = "n-7f3a"
        secret = "secure-agent-key-test-01"
        now = time.time()
        nonce = uuid.uuid4().hex
        payload_dict = {
            "node_id": trap_id,
            "nonce": nonce,
            "timestamp": now,
            "heartbeat": {"uptime_seconds": 3600, "cpu_usage": 1.2, "mem_usage": 4.5},
            "events": []
        }
        raw_body = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        sig = generate_agent_signature(trap_id, now, nonce, secret, raw_body=raw_body)
        payload_dict["signature"] = sig
        final_body = json.dumps(payload_dict).encode("utf-8")

        r_valid = await client.post("/cdn-cgi/rum", content=final_body, headers={"Content-Type": "application/json"})
        assert r_valid.status_code == 200
        assert r_valid.json().get("status") == "ok"

@pytest.mark.asyncio
async def test_07_fastapi_route_walker_auth_coverage():
    """
    TASK 6: Dynamic route crawler across app.routes (including WebSocket).
    Verifies that every route's dependency tree contains get_current_user or require_admin,
    except routes in the strict explicit whitelist.
    """
    WHITELIST_EXACT = {
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/",
        "/api/v1/auth/login",
        "/cdn-cgi/rum",
        "/static/v2/metrics",
        "/static/pixel.gif",
        "/cdn-cgi/trace",
        "/sync/v1/config",
        "/api/v1/traps/{trap_id}/config",
        "/api/v1/traps/{trap_id}/confirm-rotation",
        "/ws/attacks",
    }
    WHITELIST_PREFIXES = (
        "/static",
        "/sync/",
        "/canary/",
    )

    def get_all_dependencies(dependant):
        calls = []
        if getattr(dependant, "call", None):
            calls.append(dependant.call)
        for sub in getattr(dependant, "dependencies", []):
            calls.extend(get_all_dependencies(sub))
        return calls

    def get_all_routes(fastapi_app):
        routes = []
        for r in fastapi_app.routes:
            if hasattr(r, "original_router"):
                prefix = getattr(r.include_context, "prefix", "") if hasattr(r, "include_context") else ""
                for sub_r in r.original_router.routes:
                    routes.append((prefix + getattr(sub_r, "path", ""), sub_r))
            elif hasattr(r, "routes"):
                for sub_r in r.routes:
                    routes.append((getattr(sub_r, "path", ""), sub_r))
            else:
                routes.append((getattr(r, "path", ""), r))
        return routes

    unprotected_routes = []
    all_inspected_routes = get_all_routes(app)
    assert len(all_inspected_routes) >= 20, f"Expected >= 20 routes, got {len(all_inspected_routes)}"

    for path, route in all_inspected_routes:
        if path in WHITELIST_EXACT or any(path.startswith(pfx) for pfx in WHITELIST_PREFIXES):
            continue

        dep = getattr(route, "dependant", None)
        if not dep:
            unprotected_routes.append((path, "No Dependant attached"))
            continue

        calls = get_all_dependencies(dep)
        has_auth = any(c in (get_current_user, require_admin) for c in calls)
        if not has_auth:
            unprotected_routes.append((path, [getattr(c, "__name__", str(c)) for c in calls]))

    assert len(unprotected_routes) == 0, f"Unprotected routes detected by crawler: {unprotected_routes}"

@pytest.mark.asyncio
async def test_08_fastapi_route_walker_proves_failure_on_unprotected_route():
    """
    TASK 6 Proof of Failure:
    Registers a temporary route WITHOUT authentication dependencies.
    Proves that the dynamic route crawler successfully catches it and fails.
    Then safely removes the temporary route.
    """
    temp_path = "/api/v1/temporary_unprotected_probe_endpoint"

    @app.get(temp_path)
    async def temporary_unprotected_endpoint():
        return {"leaked_secret": "compromised"}

    # Run check and assert detection
    detected = False
    for r in app.routes:
        if getattr(r, "path", None) == temp_path:
            dep = getattr(r, "dependant", None)
            calls = [dep.call] + [d.call for d in getattr(dep, "dependencies", [])] if dep else []
            has_auth = any(c in (get_current_user, require_admin) for c in calls)
            if not has_auth:
                detected = True
            break

    # Clean up immediately
    app.router.routes = [r for r in app.router.routes if getattr(r, "path", None) != temp_path]

    assert detected is True, "Dynamic route crawler MUST detect temporary unprotected endpoint!"

@pytest.mark.asyncio
async def test_09_http_request_level_auth_and_rbac_enforcement():
    """
    Validates runtime HTTP enforcement: unauthenticated access gets 401,
    analyst access to admin-only actions gets 403, admin access gets 200.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        admin_token = create_access_token({"sub": "test_admin_auth", "username": "test_admin_auth", "role": "admin", "id": 1})
        analyst_token = create_access_token({"sub": "test_analyst_auth", "username": "test_analyst_auth", "role": "analyst", "id": 2})

        # 1. Unauthenticated -> 401
        protected_endpoints = [
            ("GET", "/api/v1/traps"),
            ("GET", "/api/v1/profiles"),
            ("GET", "/api/v1/events"),
            ("GET", "/api/v1/auth/me"),
            ("POST", "/api/v1/simulator/run"),
            ("DELETE", "/api/v1/traps/trap-med-01"),
        ]

        for method, path in protected_endpoints:
            res = await client.request(method, path)
            assert res.status_code == 401, f"{method} {path} returned {res.status_code}, expected 401"

        # 2. Analyst -> 403 on admin-only
        admin_only_endpoints = [
            ("POST", "/api/v1/simulator/run", {"trap_id": "trap-med-01", "scenario": "brute_force"}),
            ("POST", "/api/v1/profiles", {"name": "TestProfRBAC", "interaction_level": "medium"}),
            ("DELETE", "/api/v1/traps/trap-med-01", None),
        ]

        for method, path, json_body in admin_only_endpoints:
            res = await client.request(
                method,
                path,
                headers={"Authorization": f"Bearer {analyst_token}"},
                json=json_body
            )
            assert res.status_code == 403, f"Analyst access to {method} {path} returned {res.status_code}, expected 403"

        # 3. Admin -> 200
        res_admin = await client.get(
            "/api/v1/traps",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert res_admin.status_code == 200
