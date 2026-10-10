import os
import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy import select

from honeyforge_server.app.config import settings
from honeyforge_server.app.database import init_db, AsyncSessionLocal
from honeyforge_server.app.models import Profile, Trap, Honeytoken, AlertRule, User
from honeyforge_server.app.security import hash_password
from honeyforge_server.app.websocket_hub import ws_hub

# Routers
from honeyforge_server.app.routes import auth, profiles, traps, telemetry, events, honeytokens, stats, simulator

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Cyber SOC Honeypot C2 & Telemetry Collection Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
app.include_router(stats.router, prefix=settings.API_V1_STR)
app.include_router(simulator.router, prefix=settings.API_V1_STR)

# Ingestion Stealth Route (MASK-2)
app.include_router(telemetry.router)

# WebSocket Endpoint for Live SOC Dashboard
@app.websocket("/ws/attacks")
async def websocket_attacks_endpoint(websocket: WebSocket):
    await ws_hub.connect(websocket)
    try:
        while True:
            # Keepalive listening for ping
            data = await websocket.receive_text()
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

@app.on_event("startup")
async def on_startup():
    await init_db()
    # Seed initial profiles and traps for immediate out-of-the-box readiness
    async with AsyncSessionLocal() as db:
        # Check profiles
        pres = await db.execute(select(Profile))
        if not pres.scalars().first():
            # 1. Low-Interaction Profile
            low_p = Profile(
                name="DMZ-Perimeter-Low",
                description="Low interaction perimeter trap emulating open network ports with authentic service banners",
                interaction_level="low",
                services=["ftp", "telnet", "redis"],
                banners={
                    "21": "220 ProFTPD 1.3.5 Server (Ubuntu) [10.0.1.5]",
                    "23": "Ubuntu 22.04 LTS \nlogin: ",
                    "6379": "-ERR operation not permitted\r\n"
                },
                decoy_credentials=[],
                honeytokens_config=[],
                logging_params={"level": "INFO", "capture_payload": True},
                stealth_params={
                    "proc_name": "systemd-resolved",
                    "beacon_interval_s": 10,
                    "jitter_pct": 30,
                    "dummy_padding": True
                }
            )
            db.add(low_p)

            # 2. Medium-Interaction Profile
            med_p = Profile(
                name="Enterprise-Linux-Medium",
                description="Medium interaction trap: Authentic Fake-SSH daemon, fake bash shell, fake web admin, and honeytokens",
                interaction_level="medium",
                services=["ssh", "http"],
                banners={
                    "22": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                    "80": "Apache/2.4.52 (Ubuntu)"
                },
                decoy_credentials=[
                    {"user": "root", "pass": "admin123"},
                    {"user": "admin", "pass": "password"},
                    {"user": "deploy", "pass": "deploy2026"}
                ],
                honeytokens_config=[
                    {"type": "aws_key", "path": "/root/.aws/credentials"},
                    {"type": "shadow_hash", "path": "/etc/shadow"}
                ],
                logging_params={"level": "DEBUG", "capture_payload": True, "record_commands": True},
                stealth_params={
                    "proc_name": "rsyslogd",
                    "beacon_interval_s": 8,
                    "jitter_pct": 40,
                    "dummy_padding": True
                }
            )
            db.add(med_p)

            # 3. High-Interaction Sandbox Profile
            high_p = Profile(
                name="Isolated-Sandbox-High",
                description="High interaction sandbox environment with full command tracking and snapshot isolation",
                interaction_level="high",
                services=["ssh", "http", "mysql"],
                banners={
                    "22": "SSH-2.0-OpenSSH_9.0p1 Debian-1+deb12u1",
                    "3306": "8.0.32-0ubuntu0.22.04.2"
                },
                decoy_credentials=[{"user": "root", "pass": "toor"}],
                honeytokens_config=[{"type": "database_dump", "path": "/var/backups/production_dump.sql"}],
                logging_params={"level": "DEBUG", "full_tty_capture": True},
                stealth_params={
                    "proc_name": "kworker/0:1",
                    "beacon_interval_s": 12,
                    "jitter_pct": 45,
                    "dummy_padding": True
                }
            )
            db.add(high_p)
            await db.commit()

        # Check Traps
        tres = await db.execute(select(Trap))
        if not tres.scalars().first():
            pres = await db.execute(select(Profile))
            all_profs = pres.scalars().all()
            low_id = all_profs[0].id if all_profs else None
            med_id = all_profs[1].id if len(all_profs) > 1 else low_id

            t1 = Trap(
                trap_id="trap-low-01",
                name="DMZ-Perimeter-Trap-01",
                profile_id=low_id,
                interaction_level="low",
                ip_address="192.168.10.15",
                mgmt_ip="10.200.0.15",
                status="online",
                last_seen=datetime.datetime.utcnow(),
                uptime_seconds=3600,
                cpu_usage=1.2,
                mem_usage=4.5,
                secret_key="secret-key-low-01"
            )
            t2 = Trap(
                trap_id="trap-med-01",
                name="Internal-SSH-Trap-02",
                profile_id=med_id,
                interaction_level="medium",
                ip_address="192.168.20.44",
                mgmt_ip="10.200.0.44",
                status="online",
                last_seen=datetime.datetime.utcnow(),
                uptime_seconds=7200,
                cpu_usage=3.8,
                mem_usage=9.1,
                secret_key="secret-key-med-01"
            )
            db.add(t1)
            db.add(t2)
            await db.commit()

        # Check Honeytoken
        ht_res = await db.execute(select(Honeytoken))
        if not ht_res.scalars().first():
            token1 = Honeytoken(
                token_id="ht-prod-aws-8821",
                token_type="aws_key",
                token_value="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                canary_path="/root/.aws/credentials",
                trap_id="trap-med-01",
                description="Production AWS Deployer Credentials",
                is_triggered=False
            )
            db.add(token1)
            await db.commit()

        # Check User
        u_res = await db.execute(select(User))
        if not u_res.scalars().first():
            admin_user = User(
                username="admin",
                password_hash=hash_password("admin123"),
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            await db.commit()
