import asyncio
import os
import sys
import unittest
import uuid
import datetime
import time
import json

# Ensure project in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeyforge_server.app.database import init_db, AsyncSessionLocal
from honeyforge_server.app.models import Profile, Trap, AttackEvent, Honeytoken, AlertEvent, SessionLog
from honeyforge_server.app.security import hash_password, verify_password, create_access_token, decode_access_token, verify_agent_signature
from honeyforge_agent.stealth import sign_telemetry_payload
from honeyforge_server.app.alert_engine import process_event_for_alerts
from honeyforge_server.app.ioc_exporter import export_iocs_csv, export_iocs_stix, export_suricata_rules
from honeyforge_server.app.orchestrator import generate_docker_compose_artifact, generate_bash_deployment_script
from honeyforge_agent.buffer import LocalEventBuffer
from honeyforge_agent.stealth import calculate_jittered_interval, generate_dummy_padding

class TestHoneyForgeE2E(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        await init_db()

    async def test_01_security_and_auth(self):
        """Test password hashing, JWT and HMAC agent signature"""
        pwd = "SecretAdminPassword2026"
        hashed = hash_password(pwd)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("wrong", hashed))

        # JWT
        token = create_access_token({"sub": "admin", "role": "admin"})
        payload = decode_access_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "admin")

        # HMAC Signature (MASK-7)
        now = time.time()
        nonce = "nonce-1234"
        secret = "secret-test-key"
        sig = sign_telemetry_payload("trap-01", now, nonce, secret)
        self.assertTrue(verify_agent_signature("trap-01", now, nonce, sig, secret))
        self.assertFalse(verify_agent_signature("trap-01", now, nonce, "invalid-sig", secret))

    async def test_02_database_and_profiles_crud(self):
        """FR-C1: CRUD Profiles"""
        async with AsyncSessionLocal() as db:
            p = Profile(
                name=f"Test-Profile-{uuid.uuid4().hex[:6]}",
                interaction_level="medium",
                services=["ssh", "http"],
                banners={"22": "SSH-2.0-OpenSSH_8.9p1"},
                stealth_params={"proc_name": "systemd-resolved", "jitter_pct": 35}
            )
            db.add(p)
            await db.commit()
            await db.refresh(p)
            self.assertIsNotNone(p.id)
            self.assertEqual(p.interaction_level, "medium")

    async def test_03_local_buffer_store_and_forward(self):
        """FR-A4: Local buffer persistence during network disruptions"""
        test_db = f".test_buf_{uuid.uuid4().hex[:6]}.db"
        try:
            buf = LocalEventBuffer(test_db)
            self.assertEqual(buf.count_pending(), 0)

            ev1 = {"event_id": "ev-1", "trap_id": "t1", "payload": "SYN Probe"}
            ev2 = {"event_id": "ev-2", "trap_id": "t1", "payload": "GET /login"}
            buf.push_event(ev1)
            buf.push_event(ev2)

            self.assertEqual(buf.count_pending(), 2)

            batch = buf.peek_pending(limit=10)
            self.assertEqual(len(batch), 2)
            self.assertEqual(batch[0]["event_id"], "ev-1")

            buf.mark_delivered(["ev-1"])
            self.assertEqual(buf.count_pending(), 1)
            buf.mark_delivered(["ev-2"])
            self.assertEqual(buf.count_pending(), 0)
        finally:
            if os.path.exists(test_db):
                os.remove(test_db)

    async def test_04_stealth_jitter_and_padding(self):
        """MASK-5: Jitter interval and random dummy padding verification"""
        base = 10.0
        jitter = 40.0
        for _ in range(10):
            interval = calculate_jittered_interval(base, jitter)
            self.assertTrue(6.0 <= interval <= 14.0)

        padding = generate_dummy_padding(32, 64)
        self.assertTrue(32 <= len(padding) <= 64)

    async def test_05_alert_engine_correlation(self):
        """FR-C7: Brute force & Honeytoken correlation detection"""
        async with AsyncSessionLocal() as db:
            # Honeytoken event -> critical alert
            ht_ev = AttackEvent(
                event_id=str(uuid.uuid4()),
                trap_id="trap-test",
                timestamp=datetime.datetime.utcnow(),
                source_ip="203.0.113.5",
                destination_port=80,
                event_type="honeytoken_triggered",
                severity="critical",
                payload_raw="Canary breached"
            )
            db.add(ht_ev)
            await db.commit()
            await db.refresh(ht_ev)

            await process_event_for_alerts(db, ht_ev)

    async def test_06_ioc_export(self):
        """FR-C7: STIX 2.1, CSV and Suricata export"""
        events = [
            AttackEvent(
                event_id="ev-100",
                trap_id="trap-1",
                timestamp=datetime.datetime.utcnow(),
                source_ip="198.51.100.99",
                destination_port=2222,
                protocol="SSH",
                event_type="auth_attempt",
                severity="high",
                credentials={"username": "root", "password": "123"},
                artifact_hash="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
                is_ioc=True
            )
        ]
        csv_out = export_iocs_csv(events)
        self.assertIn("198.51.100.99", csv_out)
        self.assertIn("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", csv_out)

        stix_out = export_iocs_stix(events)
        self.assertEqual(stix_out["type"], "bundle")
        self.assertTrue(len(stix_out["objects"]) >= 2)

        suricata_out = export_suricata_rules(events)
        self.assertIn("198.51.100.99", suricata_out)

    async def test_07_orchestrator_deployment_artifacts(self):
        """FR-C6: 1-Click deployment script generation"""
        trap = Trap(trap_id="test-trap", name="Test Trap", secret_key="k1", ip_address="192.168.1.5", mgmt_ip="10.0.0.5")
        prof = Profile(name="P1", interaction_level="medium", services=["ssh", "http"])
        
        compose = generate_docker_compose_artifact(trap, prof, "http://localhost:8000")
        self.assertIn("systemd-resolved-test-trap", compose)
        self.assertIn("honeynet_public", compose)
        self.assertIn("honeyforge_mgmt", compose)

        bash = generate_bash_deployment_script(trap, prof, "http://localhost:8000")
        self.assertIn("#!/usr/bin/env bash", bash)
        self.assertIn("test-trap", bash)

if __name__ == "__main__":
    unittest.main()
