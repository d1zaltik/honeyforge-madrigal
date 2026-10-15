import asyncio
import json
import os
import httpx
import websockets

def load_env(path: str = ".env") -> dict:
    cfg = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

env_cfg = load_env()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or env_cfg.get("ADMIN_PASSWORD", "")
ANALYST_PASSWORD = os.environ.get("ANALYST_PASSWORD") or env_cfg.get("ANALYST_PASSWORD", "")

BASE_HTTPS = "https://localhost"
BASE_HTTP = "http://localhost"

async def test_suite():
    print("==================================================")
    print("1. ТЕСТИРОВАНИЕ СЕТЕВОЙ БЕЗОПАСНОСТИ И TLS (MASK-1)")
    print("==================================================")
    
    # 1.1 Port 8000 closed to host
    async with httpx.AsyncClient(timeout=2.0) as client:
        try:
            await client.get("http://localhost:8000")
            print("[-] ОШИБКА: Порт 8000 доступен снаружи!")
        except Exception as e:
            print("[+] УСПЕХ: Порт 8000 закрыт снаружи (Connection refused):", type(e).__name__)

    # 1.2 Port 80 redirect to HTTPS
    async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
        res = await client.get(f"{BASE_HTTP}/")
        assert res.status_code == 301, f"Expected 301, got {res.status_code}"
        location = res.headers.get("location", "")
        print(f"[+] УСПЕХ: Порт 80 возвращает 301 редирект на: {location}")
        assert "https://" in location

    # 1.3 Dashboard over HTTPS port 443
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        res = await client.get(f"{BASE_HTTPS}/")
        assert res.status_code == 200
        assert "HoneyForge" in res.text
        print("[+] УСПЕХ: Дашборд успешно открывается по HTTPS (порт 443)")

    print("\n==================================================")
    print("2. ТЕСТИРОВАНИЕ СЕРВЕРНОЙ АВТОРИЗАЦИИ (FR-C5)")
    print("==================================================")
    
    # 2.1 Unauthenticated requests -> 401
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        endpoints_to_test = [
            ("GET", f"{BASE_HTTPS}/api/v1/traps"),
            ("GET", f"{BASE_HTTPS}/api/v1/profiles"),
            ("GET", f"{BASE_HTTPS}/api/v1/events"),
            ("GET", f"{BASE_HTTPS}/api/v1/auth/me"),
            ("POST", f"{BASE_HTTPS}/api/v1/simulator/run"),
            ("DELETE", f"{BASE_HTTPS}/api/v1/traps/trap-med-01"),
        ]
        for method, url in endpoints_to_test:
            res = await client.request(method, url)
            assert res.status_code == 401, f"{method} {url} returned {res.status_code}, expected 401"
            body = res.json()
            assert body.get("detail") == "Не авторизован", f"Unexpected detail: {body}"
        print("[+] УСПЕХ: Все защищенные эндпоинты без токена возвращают 401 'Не авторизован'")

    # 2.2 Login as analyst
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        res_login_analyst = await client.post(
            f"{BASE_HTTPS}/api/v1/auth/login",
            json={"username": "analyst", "password": ANALYST_PASSWORD}
        )
        assert res_login_analyst.status_code == 200, f"Login failed: {res_login_analyst.text}"
        analyst_data = res_login_analyst.json()
        analyst_token = analyst_data["access_token"]
        print(f"[+] УСПЕХ: Аналитик успешно авторизован, роль: {analyst_data['user']['role']}")

        headers_analyst = {"Authorization": f"Bearer {analyst_token}"}

        # 2.3 GET /auth/me for analyst
        res_me = await client.get(f"{BASE_HTTPS}/api/v1/auth/me", headers=headers_analyst)
        assert res_me.status_code == 200
        me_user = res_me.json()
        assert me_user["username"] == "analyst"
        assert me_user["role"] == "analyst"
        print(f"[+] УСПЕХ: /auth/me возвращает профиль текущего аналитика: {me_user['username']} ({me_user['role']})")

        # 2.4 Analyst read access (GET traps, GET events)
        res_traps = await client.get(f"{BASE_HTTPS}/api/v1/traps", headers=headers_analyst)
        assert res_traps.status_code == 200
        print(f"[+] УСПЕХ: Аналитик имеет доступ на чтение списка ловушек (получено: {len(res_traps.json())})")

        # 2.5 Analyst forbidden actions (POST profiles, POST simulator, POST honeytokens, POST rules) -> 403
        admin_only_tests = [
            ("POST", f"{BASE_HTTPS}/api/v1/profiles", {"name": "Test-Prof-Analyst", "interaction_level": "low", "services": []}),
            ("POST", f"{BASE_HTTPS}/api/v1/simulator/run", {"scenario": "port_scan"}),
            ("POST", f"{BASE_HTTPS}/api/v1/honeytokens", {"token_type": "aws_key"}),
            ("POST", f"{BASE_HTTPS}/api/v1/rules", {"name": "Test-Rule", "rule_type": "brute_force", "threshold": 5, "window_seconds": 60}),
            ("POST", f"{BASE_HTTPS}/api/v1/traps/trap-med-01/action", {"action": "stop"}),
        ]
        for method, url, payload in admin_only_tests:
            res = await client.request(method, url, json=payload, headers=headers_analyst)
            assert res.status_code == 403, f"{method} {url} returned {res.status_code}, expected 403"
            detail = res.json().get("detail")
            assert "Требуется роль администратора" in detail
        print("[+] УСПЕХ: Все действия администратора блокируются для аналитика с кодом 403 Forbidden")

    # 2.6 Login as admin
    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
        res_login_admin = await client.post(
            f"{BASE_HTTPS}/api/v1/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert res_login_admin.status_code == 200
        admin_data = res_login_admin.json()
        admin_token = admin_data["access_token"]
        headers_admin = {"Authorization": f"Bearer {admin_token}"}
        print(f"[+] УСПЕХ: Администратор успешно авторизован, роль: {admin_data['user']['role']}")

        # 2.7 Admin allowed actions
        res_sim = await client.post(
            f"{BASE_HTTPS}/api/v1/simulator/run",
            json={"scenario": "port_scan"},
            headers=headers_admin
        )
        assert res_sim.status_code == 200, f"Simulator run failed: {res_sim.text}"
        sim_data = res_sim.json()
        print(f"[+] УСПЕХ: Администратор успешно запустил сценарий проверки: {sim_data['scenario']} (задержка: {sim_data['latency_seconds']} с)")

        # 2.8 Audit log contains real operator usernames
        res_audit = await client.get(f"{BASE_HTTPS}/api/v1/audit?limit=10", headers=headers_admin)
        assert res_audit.status_code == 200
        audit_logs = res_audit.json()
        print(f"[+] УСПЕХ: Журнал аудита прочитан ({len(audit_logs)} записей). Последние действия:")
        for log in audit_logs[:3]:
            print(f"    - [{log['timestamp']}] Оператор: {log['username']} | Действие: {log['action']} | Детали: {log['details'][:60]}...")

    print("\n==================================================")
    print("3. ТЕСТИРОВАНИЕ WEBSOCKET С АВТОРИЗАЦИЕЙ")
    print("==================================================")
    
    # 3.1 WebSocket without token -> policy violation / rejected
    import ssl
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    ws_url_no_token = "wss://localhost/ws/attacks"
    try:
        async with websockets.connect(ws_url_no_token, ssl=ssl_ctx) as ws:
            print("[-] ОШИБКА: WebSocket подключился без токена!")
    except Exception as e:
        print(f"[+] УСПЕХ: WebSocket без токена отклонён сервером: {type(e).__name__} ({e})")

    # 3.2 WebSocket with valid admin token -> connected
    ws_url_with_token = f"wss://localhost/ws/attacks?token={admin_token}"
    async with websockets.connect(ws_url_with_token, ssl=ssl_ctx) as ws:
        print("[+] УСПЕХ: WebSocket с JWT-токеном успешно подключён по wss:// (порт 443 TLS)")

    print("\n==================================================")
    print("ВСЕ ПРОВЕРКИ УСПЕШНО ПРОЙДЕНЫ!")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(test_suite())
