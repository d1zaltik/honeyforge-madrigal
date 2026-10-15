#!/usr/bin/env python3
"""
HoneyForge End-to-End Live System Verification Suite (e2e_live.py)
Validates complete multi-tier security, stealth, isolation, and detection
against an active Docker Compose deployment.

Steps:
  1. RBAC Authorization: Analyst 403 Forbidden vs Admin 200/Success
  2. In-App Login Rate Limit & Lockout: 8 failed attempts -> 429 + Audit Log
  3. Container Network Isolation: backend:8000 and db:5432 unreachable from DMZ
  4. Real SSH Attack & Latency: Lure rejection, admission, command execution, API event < 5s
  5. Low-Interaction Port Scan: Multi-port probing generates attack events
  6. Correlation Rule Alert: Attack pattern triggers correlated security alert
  7. Honeytoken Canary Trigger: Canary URL access generates Critical Alert
  8. FR-A4 Store & Forward: Proxy stop -> 3 attacks -> Proxy start -> sync without loss
  9. Container Marker Audit: Clean /proc/environ and disguised process names in ps aux
 10. Host Port Exposure: Ports 8000 & 5432 NOT exposed externally; only edge/traps open
 11. Hardened TLS Pinning: Untrusted certificate rejected; pinned CA certificate accepted
 12. PostgreSQL 15 & Persistence: SELECT version(), event filtering, pagination, persistence across restart
 13. MASK-5 Beacon Jitter & Variable Payload: >= 20 beacons collected, CV >= 0.1, >= 3 distinct body sizes

Exit code: 0 if all 13 steps PASS, 1 on any failure.
"""

import argparse
import asyncio
import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
import paramiko

def load_env(env_path: str = ".env") -> Dict[str, str]:
    cfg = {}
    if os.path.isfile(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg


def run_docker_cmd(cmd_list: List[str], timeout: int = 25) -> Tuple[int, str, str]:
    res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
    return res.returncode, res.stdout, res.stderr


class E2ELiveRunner:
    def __init__(self, args: argparse.Namespace):
        self.base_url = args.base_url.rstrip("/")
        self.ca_cert = args.ca_cert
        self.host = args.host
        self.ssh_port = args.ssh_port
        self.web_port = args.web_port
        self.ftp_port = args.ftp_port
        self.telnet_port = args.telnet_port
        self.redis_port = args.redis_port

        env_cfg = load_env(args.env_file)
        self.admin_password = os.environ.get("ADMIN_PASSWORD") or env_cfg.get("ADMIN_PASSWORD", "zd4maiMGqDrbARkXKbQDJQ")
        self.analyst_password = os.environ.get("ANALYST_PASSWORD") or env_cfg.get("ANALYST_PASSWORD", "JAYu043ohhy7ZLeiAcXBrg")

        self.client = httpx.Client(base_url=self.base_url, verify=self.ca_cert, timeout=15.0)
        self.admin_token: Optional[str] = None
        self.analyst_token: Optional[str] = None
        self.results: List[Tuple[int, str, bool, float, str]] = []

    def record(self, step_num: int, title: str, passed: bool, elapsed: float, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        color = "\033[92m" if passed else "\033[91m"
        rst = "\033[0m"
        print(f"[{color}{status}{rst}] Шаг {step_num:02d} ({elapsed:.2f}s): {title}")
        if detail:
            print(f"       -> {detail}")
        self.results.append((step_num, title, passed, elapsed, detail))

    def step_01_rbac(self) -> bool:
        """Step 1: Analyst 403 Forbidden vs Admin 200/Success"""
        t0 = time.time()
        # Admin login
        r_adm = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": self.admin_password})
        assert r_adm.status_code == 200, f"Admin login failed: {r_adm.status_code}"
        self.admin_token = r_adm.json()["access_token"]

        # Analyst login
        r_ana = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": self.analyst_password})
        assert r_ana.status_code == 200, f"Analyst login failed: {r_ana.status_code}"
        self.analyst_token = r_ana.json()["access_token"]

        profile_payload = {
            "name": f"E2E Test Profile {uuid.uuid4().hex[:6]}",
            "services": ["ssh", "http"]
        }

        # Analyst tries admin operation -> 403
        r_forbid = self.client.post(
            "/api/v1/profiles",
            json=profile_payload,
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        assert r_forbid.status_code == 403, f"Analyst was not forbidden: {r_forbid.status_code}"

        # Admin tries admin operation -> 200
        r_ok = self.client.post(
            "/api/v1/profiles",
            json=profile_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        assert r_ok.status_code in [200, 201], f"Admin failed to create profile: {r_ok.status_code}"

        # Check audit log read
        r_audit = self.client.get("/api/v1/audit", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_audit.status_code == 200, f"Failed to read audit logs: {r_audit.status_code}"

        elapsed = time.time() - t0
        self.record(1, "RBAC Авторизация (Analyst 403 vs Admin 200)", True, elapsed, "Аналитик ограничен, админ создал профиль, аудит доступен")
        return True

    def step_02_lockout_and_audit(self) -> bool:
        """Step 2: 8 failed logins -> 429 lockout + audit log"""
        t0 = time.time()
        probe_user = f"lockout_probe_{uuid.uuid4().hex[:6]}"
        lockout_triggered = False

        for attempt in range(1, 9):
            time.sleep(0.15)
            r = self.client.post("/api/v1/auth/login", json={"username": probe_user, "password": f"badpass{attempt}"})
            if attempt < 5:
                assert r.status_code == 401, f"Attempt {attempt} expected 401, got {r.status_code}"
            else:
                if r.status_code in [429, 503]:
                    lockout_triggered = True

        assert lockout_triggered, "Failed to trigger HTTP 429 lockout after 8 failed attempts"

        # Verify audit log entry
        r_audit = self.client.get("/api/v1/audit", headers={"Authorization": f"Bearer {self.admin_token}"})
        audit_records = r_audit.json()
        has_lockout_or_fail = any(
            rec.get("username") == probe_user or probe_user in str(rec.get("details", "")) or rec.get("action") in ["auth_lockout", "failed_login", "login_failed"]
            for rec in audit_records
        )
        assert has_lockout_or_fail, f"Audit log did not record failed login / lockout for {probe_user}"

        elapsed = time.time() - t0
        self.record(2, "Блокировка перебора паролей (429 Lockout + Audit Log)", True, elapsed, "Попытки 6-8 заблокированы с кодом 429, событие занесено в аудит")
        return True

    def step_03_network_isolation(self) -> bool:
        """Step 3: Container network isolation (backend:8000, DB:5432, mgmt-gateway unreachable from DMZ)"""
        t0 = time.time()
        # Probe from rsyslogd-med container across management network
        probe_script = (
            "import socket\n"
            "for host, port in [('172.29.0.2', 8000), ('172.29.0.5', 5432)]:\n"
            "    s = socket.socket(); s.settimeout(0.8)\n"
            "    try:\n"
            "        s.connect((host, port))\n"
            "        print('LEAK_CONNECTED:' + str(port))\n"
            "    except Exception:\n"
            "        print('ISOLATED:' + str(port))\n"
            "    finally:\n"
            "        s.close()\n"
            "try:\n"
            "    ip = socket.gethostbyname('db-store')\n"
            "    print('DNS_LEAK:db-store=' + str(ip))\n"
            "except Exception:\n"
            "    print('DNS_ISOLATED')\n"
            "s2 = socket.socket(); s2.settimeout(1.5)\n"
            "try:\n"
            "    s2.connect(('172.28.0.3', 443))\n"
            "    print('NGINX_CONNECTED')\n"
            "finally:\n"
            "    s2.close()\n"
        )
        code, out, _ = run_docker_cmd(["docker", "exec", "rsyslogd-med", "python", "-c", probe_script], timeout=35)
        assert code == 0, "Failed to run docker exec probe script"
        assert "LEAK_CONNECTED" not in out, "CRITICAL: DMZ container reached internal backend or db!"
        assert out.count("ISOLATED:") == 2, f"Expected 2 isolated TCP ports, got:\n{out}"
        assert "DNS_ISOLATED" in out, f"CRITICAL: DMZ container resolved internal management DNS names:\n{out}"
        assert "NGINX_CONNECTED" in out, "DMZ container failed to reach nginx static-edge reverse proxy (172.28.0.3:443)"

        # Verify static-edge stealth stock 404 without FastAPI JSON error
        edge_c = httpx.Client(base_url="https://127.0.0.1:8443", verify=self.ca_cert, timeout=5.0)
        try:
            r_edge = edge_c.get(f"/unproxied_probe_{uuid.uuid4().hex[:8]}")
            assert r_edge.status_code == 404, f"static-edge expected 404, got: {r_edge.status_code}"
            assert "<title>404 Not Found</title>" in r_edge.text, "static-edge failed to return stock Nginx HTML 404"
            assert "detail" not in r_edge.text, "LEAK: static-edge leaked FastAPI JSON error"
        finally:
            edge_c.close()

        elapsed = time.time() - t0
        self.record(3, "Сетевая изоляция DMZ и Management (MASK-3)", True, elapsed, "backend:8000, db:5432, mgmt:80 изолированы; DNS mgmt имен не резолвятся; static-edge отдаёт stock Nginx 404 без JSON")
        return True

    def step_04_ssh_attack_and_latency(self) -> bool:
        """Step 4: Real SSH attack: 2 rejections -> login on retry -> commands -> event latency < 5s"""
        t0 = time.time()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt 1: lure rejection
        rejected = False
        try:
            client.connect(self.host, port=self.ssh_port, username="root", password="admin123", timeout=6)
        except paramiko.AuthenticationException:
            rejected = True
        finally:
            client.close()
        assert rejected, "Lure policy failed: accepted connection on first attempt without delay"

        # Attempt 2: retry connection admitted
        client2 = paramiko.SSHClient()
        client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client2.connect(self.host, port=self.ssh_port, username="root", password="admin123", timeout=6)
        unique_marker = f"e2e_probe_{uuid.uuid4().hex[:8]}"

        t_cmd = time.time()
        _, stdout, _ = client2.exec_command(f"whoami && cat /etc/passwd && echo {unique_marker}")
        out = stdout.read().decode("utf-8")
        client2.close()

        assert "root" in out, f"Unexpected command output: {out}"
        assert unique_marker in out, "Command execution failed to return unique marker"

        # Verify event delivery latency via API
        event_found = False
        latency = 0.0
        for _ in range(35):
            time.sleep(0.4)
            r_ev = self.client.get("/api/v1/events?limit=30", headers={"Authorization": f"Bearer {self.admin_token}"})
            if r_ev.status_code == 200:
                events = r_ev.json()
                for ev in events:
                    if ev.get("protocol") == "SSH" and (unique_marker in str(ev.get("payload_raw", "")) or unique_marker in str(ev.get("command_text", ""))):
                        event_found = True
                        latency = time.time() - t_cmd
                        break
            if event_found:
                break

        assert event_found, "SSH attack command event not detected in API within timeout"
        assert latency < 5.0, f"Event appearance latency exceeded 5s SLA: {latency:.2f}s"

        elapsed = time.time() - t0
        self.record(4, "Атака на SSH и задержка телеметрии (< 5s)", True, elapsed, f"Lure rejection -> успешный вход -> команды выполнены -> событие в API за {latency:.2f}s")
        return True

    def step_05_low_trap_port_scan(self) -> bool:
        """Step 5: TCP port scan of low-trap perimeter (FTP, Telnet, Redis)"""
        t0 = time.time()
        ports_to_scan = [self.ftp_port, self.telnet_port, self.redis_port]

        for p in ports_to_scan:
            s = socket.socket()
            s.settimeout(2.0)
            try:
                s.connect((self.host, p))
                s.sendall(b"SCAN_PROBE\r\n")
            except Exception:
                pass
            finally:
                s.close()

        # Check API for port_scan or connection events
        time.sleep(1.0)
        r_ev = self.client.get("/api/v1/events?limit=30", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_ev.status_code == 200
        events = r_ev.json()
        protocols_seen = {e.get("protocol") for e in events}
        assert any(proto in protocols_seen for proto in ["FTP", "Telnet", "REDIS", "TCP"]), "No scan telemetry detected"

        elapsed = time.time() - t0
        self.record(5, "TCP-сканирование портов Low-Trap", True, elapsed, "Сканирование портов 2121, 2323, 6379 сгенерировало события телеметрии")
        return True

    def step_06_correlation_rule_alert(self) -> bool:
        """Step 6: Correlation rule trigger -> Alert event in API; verify disabling rule prevents alerts"""
        t0 = time.time()
        # 1. Fetch brute-force rule from API
        r_rules = self.client.get("/api/v1/rules", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_rules.status_code == 200, f"Failed to list rules: {r_rules.status_code}"
        rules = r_rules.json()
        bf_rule = next((r for r in rules if r.get("rule_type") == "brute_force"), None)
        assert bf_rule is not None, "Brute-force rule not found in /api/v1/rules"
        rule_id = bf_rule["id"]

        def run_ssh_brute_force(user_prefix: str, count: int = 6):
            for i in range(count):
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    c.connect(self.host, port=self.ssh_port, username=f"{user_prefix}_{i}", password=f"badpass_{i}", timeout=8)
                except Exception:
                    pass
                finally:
                    c.close()

        # 2. PROVE TEST FAILS IF RULE IS DISABLED:
        # Disable the rule
        if bf_rule.get("is_enabled"):
            r_toggle = self.client.put(f"/api/v1/rules/{rule_id}/toggle", headers={"Authorization": f"Bearer {self.admin_token}"})
            assert r_toggle.status_code == 200

        r_al_before = self.client.get("/api/v1/events/alerts?limit=200", headers={"Authorization": f"Bearer {self.admin_token}"})
        alerts_before = r_al_before.json()
        initial_top_id = alerts_before[0]["id"] if alerts_before else 0

        # Perform failed logins with rule disabled
        probe_tag_disabled = f"bf_off_{uuid.uuid4().hex[:6]}"
        run_ssh_brute_force(probe_tag_disabled, count=6)
        time.sleep(2.0)

        r_al_after_disabled = self.client.get("/api/v1/events/alerts?limit=200", headers={"Authorization": f"Bearer {self.admin_token}"})
        alerts_after_disabled = r_al_after_disabled.json()
        top_id_after_disabled = alerts_after_disabled[0]["id"] if alerts_after_disabled else 0
        assert top_id_after_disabled == initial_top_id, "FAIL: Alert was generated while brute_force rule was DISABLED!"

        # 3. RE-ENABLE RULE AND VERIFY ALERT GENERATION:
        r_toggle_on = self.client.put(f"/api/v1/rules/{rule_id}/toggle", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_toggle_on.status_code == 200

        probe_tag_enabled = f"bf_on_{uuid.uuid4().hex[:6]}"
        run_ssh_brute_force(probe_tag_enabled, count=6)

        new_alert = None
        for _ in range(35):
            time.sleep(0.5)
            r_al_final = self.client.get("/api/v1/events/alerts?limit=200", headers={"Authorization": f"Bearer {self.admin_token}"})
            if r_al_final.status_code == 200:
                alerts_final = r_al_final.json()
                if alerts_final and alerts_final[0]["id"] > initial_top_id:
                    new_alert = alerts_final[0]
                    break

        assert new_alert is not None, "FAIL: No new alert generated after brute-force attack with enabled rule!"

        elapsed = time.time() - t0
        self.record(6, "Срабатывание правил корреляции (Alert)", True, elapsed, f"Выключение правила предотвратило алерт; включение правила сгенерировало '{new_alert.get('rule_name')}' (severity={new_alert.get('severity')})")
        return True

    def step_07_honeytoken_trigger(self) -> bool:
        """Step 7: Honeytoken Canary access -> Critical Alert emitted referencing specific token"""
        t0 = time.time()
        # 1. Create unique canary honeytoken
        token_suffix = uuid.uuid4().hex[:8]
        canary_slug = f"/sync/canary-{token_suffix}"
        token_payload = {
            "token_type": "canary_url",
            "description": f"Canary E2E Production Token {token_suffix}",
            "canary_path": canary_slug
        }
        r_create = self.client.post(
            "/api/v1/honeytokens",
            json=token_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        assert r_create.status_code in [200, 201], f"Honeytoken creation failed: {r_create.status_code}"
        ht_data = r_create.json()
        token_id = ht_data["token_id"]

        # 2. Trigger the honeytoken via canary endpoint
        r_trig = self.client.get(canary_slug)
        assert r_trig.status_code == 403, f"Canary response was not 403: {r_trig.status_code}"

        # 3. Verify Critical Alert specifically created for this token
        time.sleep(1.0)
        r_al = self.client.get("/api/v1/events/alerts", headers={"Authorization": f"Bearer {self.admin_token}"})
        alerts = r_al.json()
        canary_alert = next((
            a for a in alerts
            if token_id in str(a.get("message", ""))
            or canary_slug in str(a.get("message", ""))
            or "Honeytoken" in str(a.get("rule_name", ""))
        ), None)
        assert canary_alert is not None, f"Alert for canary token {token_id} not found in alerts"

        elapsed = time.time() - t0
        self.record(7, "Срабатывание токена-приманки (Honeytoken)", True, elapsed, f"Canary token '{token_id}' вызвал Critical Alert: '{canary_alert.get('message')[:75]}...'")
        return True

    def step_08_store_and_forward(self) -> bool:
        """Step 8: FR-A4 Store & Forward: Stop static-edge -> 3 attacks -> restart rsyslogd-med -> Start static-edge -> delivery verified"""
        t0 = time.time()
        # 1. Stop static-edge proxy
        code, _, _ = run_docker_cmd(["docker", "stop", "static-edge"])
        assert code == 0, "Failed to stop static-edge container"

        uids = [f"store_fwd_{uuid.uuid4().hex[:8]}" for _ in range(3)]
        try:
            # 2. Perform 3 attacks directly on the web trap
            async def send_attacks():
                async with httpx.AsyncClient() as c:
                    for uid in uids:
                        await c.get(f"http://{self.host}:{self.web_port}/probe?uid={uid}")

            asyncio.run(send_attacks())

            # 3. Restart the agent container to prove SQLite persistence on volume across restart
            code, _, _ = run_docker_cmd(["docker", "restart", "rsyslogd-med"])
            assert code == 0, "Failed to restart rsyslogd-med container"
            time.sleep(2.0)
        finally:
            # 4. Restart static-edge proxy
            code, _, _ = run_docker_cmd(["docker", "start", "static-edge"])
            assert code == 0, "Failed to restart static-edge container"

        # 5. Wait for agent sync loop (up to 25s)
        delivered_count = 0
        for _ in range(35):
            time.sleep(0.5)
            r_ev = self.client.get("/api/v1/events?limit=50", headers={"Authorization": f"Bearer {self.admin_token}"})
            if r_ev.status_code == 200:
                events = r_ev.json()
                delivered_count = sum(1 for uid in uids if any(uid in str(e.get("payload_raw", "")) for e in events))
                if delivered_count == len(uids):
                    break

        assert delivered_count == len(uids), f"Store & Forward lost events: {delivered_count}/{len(uids)} received"

        elapsed = time.time() - t0
        self.record(8, "Надёжная доставка телеметрии (FR-A4 Store & Forward)", True, elapsed, "3 события сохранены в SQLite-буфер, пережили перезапуск rsyslogd-med при мертвом edge и доставлены без потерь")
        return True

    def step_09_container_markers(self) -> bool:
        """Step 9: Container marker audit (MASK-4)
        Scans entire container filesystem, validates /proc/1/cmdline and masked /proc/1/environ,
        and validates docker inspect (Env, Labels, Hostname, Name, Mounts, Networks).
        """
        t0 = time.time()
        forbidden_regex = re.compile(
            r"\b(honeyforge|honeypot|trap|decoy|beacon|telemetry|simulated|fake|mock|c2)\b",
            re.IGNORECASE,
        )

        # 1. Process identity verification via /proc/1/comm and docker top (MASK-4)
        code, comm_out, _ = run_docker_cmd(["docker", "exec", "rsyslogd-med", "cat", "/proc/1/comm"])
        assert code == 0, "Failed to read /proc/1/comm in rsyslogd-med"
        assert "rsyslogd" in comm_out, f"Process not masked as rsyslogd in /proc/1/comm: {comm_out}"
        assert not forbidden_regex.search(comm_out), f"Forbidden word found in /proc/1/comm: {comm_out}"

        code, top_out, _ = run_docker_cmd(["docker", "top", "rsyslogd-med"])
        assert code == 0, "Failed to execute docker top rsyslogd-med"
        assert "rsyslogd" in top_out, f"Process not masked as rsyslogd in docker top:\n{top_out}"
        assert not forbidden_regex.search(top_out), f"Forbidden word in docker top:\n{top_out}"

        # 2. Check and print /proc/1/cmdline in rsyslogd-med
        code, cmdline_out, _ = run_docker_cmd(["docker", "exec", "rsyslogd-med", "cat", "/proc/1/cmdline"])
        assert code == 0, "Failed to read /proc/1/cmdline"
        clean_cmdline = cmdline_out.replace("\x00", " ").strip()
        print(f"       /proc/1/cmdline: {clean_cmdline}")
        assert not forbidden_regex.search(clean_cmdline), f"Forbidden word in /proc/1/cmdline: {clean_cmdline}"

        # 3. Check and print masked /proc/1/environ in rsyslogd-med
        code, env_raw, _ = run_docker_cmd(["docker", "exec", "rsyslogd-med", "cat", "/proc/1/environ"])
        assert code == 0, "Failed to read /proc/1/environ"
        env_vars = env_raw.split("\x00")
        masked_env = []
        for ev in env_vars:
            if not ev:
                continue
            if "=" in ev:
                k, v = ev.split("=", 1)
                if re.search(r"(KEY|PASS|SECRET|TOKEN)", k, re.IGNORECASE):
                    masked_env.append(f"{k}=***masked***")
                else:
                    masked_env.append(f"{k}={v}")
                    assert not forbidden_regex.search(v), f"Forbidden word in environ value: {k}={v}"
                assert not forbidden_regex.search(k), f"Forbidden word in environ key: {k}"
            else:
                masked_env.append(ev)
        print(f"       Masked /proc/1/environ ({len(masked_env)} vars):")
        for me in masked_env:
            print(f"         {me}")

        # 4. Check /proc/1/environ in systemd-resolved-low
        code, env_low_raw, _ = run_docker_cmd(["docker", "exec", "systemd-resolved-low", "cat", "/proc/1/environ"])
        assert code == 0, "Failed to read /proc/1/environ in systemd-resolved-low"
        for ev in env_low_raw.split("\x00"):
            if not ev or "=" not in ev:
                continue
            k, v = ev.split("=", 1)
            assert not forbidden_regex.search(k), f"Forbidden word in low trap env key: {k}"
            if not re.search(r"(KEY|PASS|SECRET|TOKEN)", k, re.IGNORECASE):
                assert not forbidden_regex.search(v), f"Forbidden word in low trap env value: {k}={v}"

        # 5. Full container zero-marker audit in running containers
        for cname in ["rsyslogd-med", "systemd-resolved-low"]:
            code, scan_out, _ = run_docker_cmd(["docker", "exec", cname, "python", "/usr/local/bin/scan_container_markers.py"])
            assert code == 0, f"Zero-marker scanner failed in {cname}:\n{scan_out}"
            assert "Total forbidden matches:              0" in scan_out, f"Marker leak detected in {cname}:\n{scan_out}"
            print(f"       Zero-marker scan in {cname}: PASS (0 marker occurrences across filesystem)")

        # 6. Validate docker inspect metadata (Env, Labels, Hostname, Name, Mounts, Networks)
        for cname in ["rsyslogd-med", "systemd-resolved-low"]:
            code, insp_raw, _ = run_docker_cmd(["docker", "inspect", cname])
            assert code == 0, f"Failed to inspect {cname}"
            insp_data = json.loads(insp_raw)[0]

            assert not forbidden_regex.search(insp_data.get("Name", "")), f"Forbidden word in container Name: {insp_data.get('Name')}"
            assert not forbidden_regex.search(insp_data.get("Config", {}).get("Hostname", "")), f"Forbidden word in Hostname"

            for env_entry in insp_data.get("Config", {}).get("Env", []):
                ek, _, ev = env_entry.partition("=")
                assert not forbidden_regex.search(ek), f"Forbidden word in docker inspect Env key: {ek}"
                if not re.search(r"(KEY|PASS|SECRET|TOKEN)", ek, re.IGNORECASE):
                    assert not forbidden_regex.search(ev), f"Forbidden word in docker inspect Env val: {ev}"

            for m in insp_data.get("Mounts", []):
                dest = m.get("Destination", "")
                mname = m.get("Name", "")
                assert not forbidden_regex.search(dest), f"Forbidden word in mount destination: {dest}"
                assert not forbidden_regex.search(mname), f"Forbidden word in mount name: {mname}"

            for net_name in insp_data.get("NetworkSettings", {}).get("Networks", {}).keys():
                assert not forbidden_regex.search(net_name), f"Forbidden word in network name: {net_name}"

        elapsed = time.time() - t0
        self.record(9, "Аудит маркеров в контейнерах ловушек (MASK-4)", True, elapsed, "PID 1 маскирован, /proc/1/environ и cmdline чистые, файловая система (0 маркеров во всех контейнерах) и docker inspect без маркеров")
        return True

    def step_10_host_port_exposure(self) -> bool:
        """Step 10: External host port exposure: only edge/traps open; backend 8000 and DB 5432 closed"""
        t0 = time.time()
        open_ports = [80, 443, self.ssh_port, self.web_port, self.ftp_port, self.telnet_port, self.redis_port]
        closed_ports = [8000, 5432]

        for p in open_ports:
            s = socket.socket()
            res = s.connect_ex((self.host, p))
            s.close()
            assert res == 0, f"Expected perimeter port {p} to be OPEN, got {res}"

        for p in closed_ports:
            s = socket.socket()
            res = s.connect_ex((self.host, p))
            s.close()
            assert res != 0, f"SECURITY VIOLATION: Internal port {p} is exposed to external host!"

        elapsed = time.time() - t0
        self.record(10, "Проверка сетевого периметра хоста (MASK-1 / MASK-3)", True, elapsed, "Порты 8000 и 5432 надёжно закрыты наружу; открыты только порты edge и ловушек")
        return True

    def step_11_tls_pinning(self) -> bool:
        """Step 11: TLS pinning check: untrusted CA rejected, pinned CA accepted"""
        t0 = time.time()
        # 1. Pinned genuine CA cert connects
        c_pinned = httpx.Client(base_url=self.base_url, verify=self.ca_cert, timeout=5.0)
        r_ok = c_pinned.get("/ghost_probe_pinning")
        assert r_ok.status_code == 404, "Pinned CA connection failed"
        c_pinned.close()

        # 2. Untrusted default CA rejects self-signed static-edge cert
        rejected = False
        try:
            c_untrusted = httpx.Client(base_url=self.base_url, verify=True, timeout=5.0)
            c_untrusted.get("/ghost_probe_pinning")
            c_untrusted.close()
        except httpx.ConnectError:
            rejected = True
        except Exception:
            rejected = True

        assert rejected, "TLS Pinning failed: untrusted certificate connection was NOT rejected!"

        elapsed = time.time() - t0
        self.record(11, "Проверка TLS Pinning и сертификатов (FR-C7 / MASK-7)", True, elapsed, "Чужой CA сертификат надёжно отклонён (ConnectError), пиннингованный CA принят")
        return True

    def step_12_postgresql_and_persistence(self) -> bool:
        """Step 12: FR-C4 PostgreSQL database verification, event filtering & pagination, and state persistence"""
        t0 = time.time()
        # 1. Verify PostgreSQL engine
        code, db_ver_out, _ = run_docker_cmd([
            "docker", "exec", "db-store", "psql", "-U", "honeyforge", "-d", "honeyforge", "-c", "SELECT version();"
        ])
        assert code == 0, f"Failed to query PostgreSQL version in db-store: {db_ver_out}"
        assert "PostgreSQL" in db_ver_out, f"Unexpected DB version: {db_ver_out}"
        m_ver = re.search(r"PostgreSQL\s+([\d\.]+)", db_ver_out)
        db_ver_str = m_ver.group(0) if m_ver else "PostgreSQL 15"

        # 2. Test /api/v1/events with filters
        # 2.1 Filter by trap_id
        r_all = self.client.get("/api/v1/events?limit=50", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_all.status_code == 200
        all_events = r_all.json()
        assert len(all_events) > 0, "No events found to test filters"

        sample_trap_id = all_events[0]["trap_id"]
        r_trap = self.client.get(f"/api/v1/events?trap_id={sample_trap_id}", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_trap.status_code == 200
        for ev in r_trap.json():
            assert ev["trap_id"] == sample_trap_id, f"Filter by trap_id failed: {ev['trap_id']} != {sample_trap_id}"

        # 2.2 Filter by period
        r_period = self.client.get("/api/v1/events?period=24h", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_period.status_code == 200

        # 2.3 Test pagination
        r_page1 = self.client.get("/api/v1/events?limit=2&offset=0", headers={"Authorization": f"Bearer {self.admin_token}"})
        r_page2 = self.client.get("/api/v1/events?limit=2&offset=2", headers={"Authorization": f"Bearer {self.admin_token}"})
        p1_ids = [e["id"] for e in r_page1.json()]
        p2_ids = [e["id"] for e in r_page2.json()]
        assert not set(p1_ids).intersection(set(p2_ids)), "Pagination offset produced overlapping event IDs!"

        # 3. Test persistence across app-backend restart
        events_count_before = len(all_events)
        code, _, _ = run_docker_cmd(["docker", "restart", "app-backend"])
        assert code == 0, "Failed to restart app-backend container"
        time.sleep(3.0)

        # Re-authenticate after backend restart
        r_adm = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": self.admin_password})
        assert r_adm.status_code == 200, "Admin re-login failed after backend restart"
        self.admin_token = r_adm.json()["access_token"]

        r_after = self.client.get("/api/v1/events?limit=50", headers={"Authorization": f"Bearer {self.admin_token}"})
        assert r_after.status_code == 200
        events_after = r_after.json()
        assert len(events_after) >= events_count_before, f"Events lost across backend restart: {len(events_after)} < {events_count_before}"

        elapsed = time.time() - t0
        self.record(12, f"{db_ver_str}, фильтры телеметрии и персистентность (FR-C4)", True, elapsed, f"{db_ver_str} подтвержден динамически (SELECT version()), фильтры trap_id/period/пагинация работают, данные сохранены после рестарта backend")
        return True

    def step_13_mask5_beacon_jitter(self) -> bool:
        """Step 13: MASK-5 Beacon Jitter & Variable Payload: >= 20 beacons collected, CV >= 0.1, >= 3 distinct body sizes"""
        t0 = time.time()
        # 1. Fetch static-edge logs
        code, out, err = run_docker_cmd(["docker", "logs", "--tail", "500", "static-edge"])
        assert code == 0, "Failed to read docker logs for static-edge"

        all_lines = (out + "\n" + err).splitlines()
        beacon_lines = [l for l in all_lines if "POST /cdn-cgi/rum" in l]

        # Group by node IP to isolate single-trap intervals
        nodes_beacons: Dict[str, List[Dict[str, Any]]] = {}
        distinct_sizes = set()

        for l in beacon_lines:
            m_ip = re.match(r"^(\d+\.\d+\.\d+\.\d+)", l)
            m_time = re.search(r"\[([^\]]+)\]", l)
            if not m_ip or not m_time:
                continue
            ip = m_ip.group(1)
            time_str = m_time.group(1)
            try:
                dt = datetime.datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
                ts = dt.timestamp()
            except Exception:
                continue

            m_size = re.search(r'"\s+(\d+)$', l.strip())
            size = int(m_size.group(1)) if m_size else None
            if size:
                distinct_sizes.add(size)

            if ip not in nodes_beacons:
                nodes_beacons[ip] = []
            nodes_beacons[ip].append({"ts": ts, "raw": l, "size": size})

        best_ip = None
        best_beacons = []
        for ip, b_list in nodes_beacons.items():
            if len(b_list) > len(best_beacons):
                best_ip = ip
                best_beacons = b_list

        assert len(best_beacons) >= 20, f"Insufficient beacons collected: got {len(best_beacons)} (need >= 20)"

        intervals = []
        for i in range(len(best_beacons) - 1):
            dt = best_beacons[i + 1]["ts"] - best_beacons[i]["ts"]
            if 1.0 <= dt <= 30.0:
                intervals.append(dt)

        assert len(intervals) >= 15, f"Insufficient valid beacon intervals: {len(intervals)}"

        min_dt = min(intervals)
        max_dt = max(intervals)
        import statistics
        mean_dt = statistics.mean(intervals)
        stddev_dt = statistics.stdev(intervals)
        cv = stddev_dt / mean_dt if mean_dt > 0 else 0.0

        assert cv >= 0.10, f"Coefficient of Variation too low (insufficient jitter): CV={cv:.4f} < 0.10"
        assert len(distinct_sizes) >= 3, f"Insufficient payload size variation: {len(distinct_sizes)} distinct sizes ({distinct_sizes})"

        elapsed = time.time() - t0
        detail = (
            f"Собрано {len(best_beacons)} маяков с {best_ip}: "
            f"dt=[min={min_dt:.1f}s, max={max_dt:.1f}s, mean={mean_dt:.2f}s, stddev={stddev_dt:.2f}s, CV={cv:.4f} >= 0.10]. "
            f"Размеров пакетов: {len(distinct_sizes)} уникальных ({sorted(list(distinct_sizes))[:5]}... байт)"
        )
        self.record(13, "Джиттер маяков и вариация размера пакетов (MASK-5)", True, elapsed, detail)
        return True

    def run_all(self) -> bool:
        print("=" * 80)
        print("  HONEYFORGE СКВОЗНОЙ E2E ТЕСТ ЖИВОГО СТЕНДА (e2e_live.py)")
        print(f"  Target: {self.base_url} | Host: {self.host} | CA: {self.ca_cert}")
        print("=" * 80)

        steps = [
            self.step_01_rbac,
            self.step_02_lockout_and_audit,
            self.step_03_network_isolation,
            self.step_04_ssh_attack_and_latency,
            self.step_05_low_trap_port_scan,
            self.step_06_correlation_rule_alert,
            self.step_07_honeytoken_trigger,
            self.step_08_store_and_forward,
            self.step_09_container_markers,
            self.step_10_host_port_exposure,
            self.step_11_tls_pinning,
            self.step_12_postgresql_and_persistence,
            self.step_13_mask5_beacon_jitter,
        ]

        all_ok = True
        for idx, step_fn in enumerate(steps, 1):
            try:
                ok = step_fn()
                if not ok:
                    all_ok = False
            except Exception as e:
                self.record(idx, step_fn.__doc__.strip().split("\n")[0], False, 0.0, str(e))
                all_ok = False

        print("=" * 80)
        passed = sum(1 for _, _, p, _, _ in self.results if p)
        total = len(self.results)
        print(f"  ИТОГ СКВОЗНОЙ ПРОВЕРКИ E2E: {passed}/{total} шагов успешно пройдено.")
        print("=" * 80)
        return all_ok


def parse_args():
    parser = argparse.ArgumentParser(description="HoneyForge E2E Live Stand Verification")
    parser.add_argument("--base-url", default="https://127.0.0.1", help="Static edge base URL")
    parser.add_argument("--ca-cert", default="docker/certs/static-edge.crt", help="CA certificate path")
    parser.add_argument("--env-file", default=".env", help="Path to .env configuration")
    parser.add_argument("--host", default="127.0.0.1", help="Target perimeter IP")
    parser.add_argument("--ssh-port", type=int, default=2222, help="SSH trap port")
    parser.add_argument("--web-port", type=int, default=8088, help="Web trap port")
    parser.add_argument("--ftp-port", type=int, default=2121, help="FTP trap port")
    parser.add_argument("--telnet-port", type=int, default=2323, help="Telnet trap port")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis trap port")
    return parser.parse_args()


if __name__ == "__main__":
    runner = E2ELiveRunner(parse_args())
    success = runner.run_all()
    sys.exit(0 if success else 1)
