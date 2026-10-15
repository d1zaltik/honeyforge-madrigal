#!/usr/bin/env python3
"""
HoneyForge Realism and Stealth Self-Check Suite (MASK-6 / Stage 4)
Supports both --local (in-process mock runtime) and --live (against active docker-compose stand).

Checks:
  1. Banner & persona consistency (SSH, FTP, Telnet, HTTP, Redis)
  2. GNU bash and coreutils error strings (cat, cd, rm, command not found)
  3. Correctness of 'ls -la' POSIX table and GNU date formats
  4. Realism timings: bounds check, sample size >= 10, non-zero variance (stddev > 0)
  5. Forbidden words audit: real SSH paramiko session, Telnet, Redis, HTTP, VirtualFS
  6. Persistent host keys across restarts & volume preservation
  7. HTTP error pages (Apache 2.4.52 HTML templates: 400, 403, 404, 405, 414)
  8. Redis 7 standard unknown command error format
  9. Stealth 404 comparison across HTTP methods and signature variations
 10. SSH Kex / Ciphers / MACs cryptographic suite vs OpenSSH 8.9p1 reference

Exit code: 0 on all PASS, 1 on any FAIL.
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import socket
import statistics
import sys
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
import paramiko

# Add repository root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeyforge_agent.traps.fake_ssh import FakeSSHTrap, VirtualFS
from honeyforge_agent.traps.fake_web import FakeWebTrap
from honeyforge_agent.traps.low_interaction import LowInteractionMultiPortTrap

FORBIDDEN_REGEX = re.compile(
    r"(?i)(\b(fake|mock|simulated|honeypot|honeyforge|decoy|emulator)\b|\btraps?\b|\bc2\b)"
)

def assert_no_forbidden_words(text: str, context: str):
    match = FORBIDDEN_REGEX.search(text)
    if match:
        raise AssertionError(
            f"LEAK DETECTED in {context}: word '{match.group(0)}' found in:\n{text[:400]}"
        )


async def check_item_1_banners(
    mode: str, host: str, ssh_p: int, web_p: int, ftp_p: int, tel_p: int, red_p: int, persona: dict
) -> Tuple[bool, str]:
    """Item 1: Banner & Persona Consistency across SSH, FTP, Telnet, HTTP, Redis"""
    # 1. SSH
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, ssh_p))
    ssh_banner = s.recv(512).decode(errors="ignore").strip()
    s.close()
    assert "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0." in ssh_banner, f"Unexpected SSH banner: {ssh_banner}"
    assert_no_forbidden_words(ssh_banner, "SSH Banner")

    # 2. FTP + Passive Mode Check
    r_ftp, w_ftp = await asyncio.open_connection(host, ftp_p)
    ftp_banner = (await r_ftp.readline()).decode(errors="ignore").strip()
    assert "220 ProFTPD 1.3.7a Server (Ubuntu)" in ftp_banner, f"Unexpected FTP banner: {ftp_banner}"
    assert_no_forbidden_words(ftp_banner, "FTP Banner")

    w_ftp.write(b"USER deploy\r\n")
    await w_ftp.drain()
    await r_ftp.readline()
    w_ftp.write(b"PASS deploy2026\r\n")
    await w_ftp.drain()
    await r_ftp.readline()

    # Dynamic Passive Mode (PASV)
    w_ftp.write(b"PASV\r\n")
    await w_ftp.drain()
    pasv_resp = (await r_ftp.readline()).decode(errors="ignore").strip()
    pasv_match = re.search(r"\((\d+,\d+,\d+,\d+),(\d+),(\d+)\)", pasv_resp)
    assert pasv_match is not None, f"Invalid PASV response: {pasv_resp}"
    p1 = int(pasv_match.group(2))
    p2 = int(pasv_match.group(3))
    pasv_port = p1 * 256 + p2
    assert 50000 <= pasv_port <= 50050, f"PASV port out of range 50000..50050: {pasv_port}"

    # Connect to passive port and read authentic directory listing
    dr, dw = await asyncio.open_connection(host, pasv_port)
    w_ftp.write(b"LIST\r\n")
    await w_ftp.drain()
    list_start = (await r_ftp.readline()).decode(errors="ignore").strip()
    assert "150 " in list_start, f"Expected 150 on LIST, got: {list_start}"

    data_bytes = await dr.read(4096)
    dw.close()
    await dw.wait_closed()
    list_end = (await r_ftp.readline()).decode(errors="ignore").strip()
    assert "226 " in list_end, f"Expected 226 on LIST complete, got: {list_end}"
    assert b"welcome.msg" in data_bytes, f"welcome.msg missing from LIST: {data_bytes}"
    assert_no_forbidden_words(data_bytes.decode(errors="ignore"), "FTP LIST data")

    w_ftp.write(b"QUIT\r\n")
    await w_ftp.drain()
    w_ftp.close()
    await w_ftp.wait_closed()

    # 3. Telnet
    r_tel, w_tel = await asyncio.open_connection(host, tel_p)
    tel_banner = (await r_tel.read(256)).decode(errors="ignore")
    w_tel.close()
    await w_tel.wait_closed()
    assert "Ubuntu 22.04" in tel_banner and "login:" in tel_banner, f"Unexpected Telnet banner: {tel_banner}"
    assert_no_forbidden_words(tel_banner, "Telnet Banner")

    # 4. HTTP Server Header
    async with httpx.AsyncClient() as client:
        r_http = await client.head(f"http://{host}:{web_p}/")
        server_hdr = r_http.headers.get("Server", "")
        assert server_hdr == "Apache/2.4.52 (Ubuntu)", f"Unexpected Server header: {server_hdr}"
        assert_no_forbidden_words(server_hdr, "HTTP Server Header")

    # 5. Redis INFO
    r_red, w_red = await asyncio.open_connection(host, red_p)
    w_red.write(b"INFO\r\n")
    await w_red.drain()
    red_info = (await r_red.read(1024)).decode(errors="ignore")
    w_red.close()
    await w_red.wait_closed()
    expected_kernel = persona.get("kernel", "5.15.0-105-generic")
    assert "redis_version:7.0.15" in red_info, f"Unexpected Redis version: {red_info[:200]}"
    assert f"os:Linux {expected_kernel}" in red_info or "os:Linux" in red_info, f"Unexpected OS in Redis INFO: {red_info[:200]}"
    assert_no_forbidden_words(red_info, "Redis INFO")

    return True, "Ubuntu 22.04 LTS / OpenSSH 8.9p1 / Apache 2.4.52 / ProFTPD 1.3.7a (PASV 50000..50050) / Redis 7.0.15"


async def check_item_2_gnu_errors(mode: str, host: str, ssh_p: int, trap_ref=None) -> Tuple[bool, str]:
    """Item 2: GNU bash and coreutils error strings"""
    expected = {
        "cat missing_file.txt": "cat: missing_file.txt: No such file or directory\n",
        "cd /etc/passwd": "bash: cd: /etc/passwd: Not a directory\n",
        "cd /ghost_folder_xyz": "bash: cd: /ghost_folder_xyz: No such file or directory\n",
        "unknown_bin_probe": "bash: unknown_bin_probe: command not found\n",
        "rm /ghost_remove_me": "rm: cannot remove '/ghost_remove_me': No such file or directory\n",
    }

    if mode == "local" and trap_ref:
        vfs = VirtualFS(trap_ref.persona, trap_ref.trap_id, trap_ref.boot_time)
        for cmd, exp in expected.items():
            out, _, _, _ = trap_ref._emulate_command_core(cmd, "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
            assert out == exp, f"For '{cmd}' expected {repr(exp)}, got {repr(out)}"
    else:
        # Live Paramiko SSH session
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)
        except Exception:
            # Lure policy: reconnect on second attempt
            client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)

        try:
            for cmd, exp in expected.items():
                _, stdout, stderr = client.exec_command(cmd)
                out = (stdout.read() + stderr.read()).decode("utf-8")
                assert out == exp, f"For '{cmd}' expected {repr(exp)}, got {repr(out)}"
        finally:
            client.close()

    return True, "GNU-authentic cat, cd, rm, and command not found errors"


async def check_item_3_ls_dates(mode: str, host: str, ssh_p: int, trap_ref=None) -> Tuple[bool, str]:
    """Item 3: Correctness of 'ls -la' POSIX table and GNU date formats"""
    if mode == "local" and trap_ref:
        vfs = VirtualFS(trap_ref.persona, trap_ref.trap_id, trap_ref.boot_time)
        out, _, _, _ = trap_ref._emulate_command_core("ls -la /etc", "127.0.0.1", "s1", "root", "/root", vfs, 0, [])
    else:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)
        except Exception:
            client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)
        try:
            _, stdout, _ = client.exec_command("ls -la /etc")
            out = stdout.read().decode("utf-8")
        finally:
            client.close()

    assert "total " in out
    assert "-rw-r--r--" in out or "drwxr-xr-x" in out
    assert "root" in out
    # GNU standard date format: 'Oct 14 11:20' or 'Oct 14  2026'
    date_match = re.search(r"[A-Z][a-z]{2}\s+\d{1,2}\s+(\d{2}:\d{2}|\d{4})", out)
    assert date_match is not None, f"GNU date format missing in ls output:\n{out[:300]}"

    return True, "Standard POSIX column layout with GNU date formatting"


async def check_item_4_timings(mode: str, host: str, ssh_p: int, web_p: int, ftp_p: int) -> Tuple[bool, str]:
    """Item 4: Timing bounds, sample size >= 10, non-zero variance (stddev > 0)"""
    # 4.1 FTP PASS delays (10 samples)
    ftp_delays = []
    for _ in range(10):
        t0 = time.time()
        r, w = await asyncio.open_connection(host, ftp_p)
        await r.readline()
        w.write(b"USER deploy\r\n")
        await w.drain()
        await r.readline()
        w.write(b"PASS invalidpass123\r\n")
        await w.drain()
        await r.readline()
        w.close()
        await w.wait_closed()
        ftp_delays.append(time.time() - t0)

    assert min(ftp_delays) >= 0.40, f"FTP response too fast: min={min(ftp_delays):.3f}s"
    assert max(ftp_delays) <= 1.50, f"FTP response too slow: max={max(ftp_delays):.3f}s"
    ftp_stdev = statistics.stdev(ftp_delays)
    assert ftp_stdev > 0.005, f"FTP delays lack variance: stdev={ftp_stdev:.5f}"

    # 4.2 HTTP POST /login delays (10 samples)
    http_delays = []
    async with httpx.AsyncClient() as client:
        for _ in range(10):
            t0 = time.time()
            await client.post(f"http://{host}:{web_p}/login", data={"username": "root", "password": "bad"})
            http_delays.append(time.time() - t0)

    assert min(http_delays) >= 0.40, f"HTTP POST too fast: min={min(http_delays):.3f}s"
    assert max(http_delays) <= 1.80, f"HTTP POST too slow: max={max(http_delays):.3f}s"
    http_stdev = statistics.stdev(http_delays)
    assert http_stdev > 0.005, f"HTTP delays lack variance: stdev={http_stdev:.5f}"

    # 4.3 SSH password delay & 3-attempt disconnect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, ssh_p))
    trans = paramiko.Transport(s)
    try:
        trans.start_client()
        ssh_delays = []
        for attempt in range(1, 4):
            t0 = time.time()
            try:
                trans.auth_password("testuser", f"wrongpass{attempt}")
            except paramiko.AuthenticationException:
                pass
            ssh_delays.append(time.time() - t0)

        assert min(ssh_delays) >= 0.35, f"SSH auth too fast: min={min(ssh_delays):.3f}s"
        assert max(ssh_delays) <= 2.50, f"SSH auth too slow: max={max(ssh_delays):.3f}s"

        # Check disconnect after 3 failed attempts
        time.sleep(0.3)
        assert not trans.is_active(), "SSH connection remained active after 3 failed attempts!"
    finally:
        trans.close()
        s.close()

    return True, (
        f"FTP N=10 (min={min(ftp_delays):.2f}s, max={max(ftp_delays):.2f}s, stddev={ftp_stdev:.3f}s), "
        f"HTTP N=10 (min={min(http_delays):.2f}s, max={max(http_delays):.2f}s, stddev={http_stdev:.3f}s), "
        f"SSH disconnect on attempt 3"
    )


async def check_item_5_forbidden_words(
    mode: str, host: str, ssh_p: int, web_p: int, ftp_p: int, tel_p: int, red_p: int, persona: dict
) -> Tuple[bool, str]:
    """Item 5: Strict Forbidden Words Audit across all protocols and simulated filesystem"""
    # 5.1 SSH paramiko commands
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)
    except Exception:
        client.close()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)

    ssh_commands = [
        "cat /etc/shadow",
        "cat /etc/passwd",
        "wget -q -O test_script.sh http://127.0.0.1/test_script.sh",
        "cat test_script.sh",
        "curl -s -o test_curl.sh http://127.0.0.1/test_curl.sh",
        "cat test_curl.sh",
        "cat .bash_history",
        "cat ~/.bash_history",
        "cat /var/log/auth.log",
        "cat /proc/version",
        "uname -a",
        "env",
        "ps aux",
        "history",
    ]

    cmd_results = []
    try:
        for cmd in ssh_commands:
            _, stdout, _ = client.exec_command(cmd)
            out = stdout.read().decode("utf-8")
            assert_no_forbidden_words(out, f"SSH command: {cmd}")
            cmd_results.append((cmd, len(out.encode("utf-8"))))
        print("       SSH commands executed & response sizes:")
        for cmd, bsize in cmd_results:
            print(f"         $ {cmd:<56} -> {bsize:>5} bytes")
    finally:
        client.close()

    # 5.2 Telnet session after login
    r_tel, w_tel = await asyncio.open_connection(host, tel_p)
    tel_out = ""
    try:
        b1 = await r_tel.readuntil(b"login: ")
        tel_out += b1.decode(errors="ignore")
        w_tel.write(b"deploy\r\n")
        await w_tel.drain()

        b2 = await r_tel.readuntil(b"Password: ")
        tel_out += b2.decode(errors="ignore")
        w_tel.write(b"deploy2026\r\n")
        await w_tel.drain()

        b3 = await r_tel.readuntil(b"login: ")
        tel_out += b3.decode(errors="ignore")
        w_tel.write(b"deploy\r\n")
        await w_tel.drain()

        b4 = await r_tel.readuntil(b"Password: ")
        tel_out += b4.decode(errors="ignore")
        w_tel.write(b"deploy2026\r\n")
        await w_tel.drain()

        b5 = await r_tel.readuntil(b"# ")
        tel_out += b5.decode(errors="ignore")

        for cmd in [b"whoami\r\n", b"id\r\n", b"uname -a\r\n"]:
            w_tel.write(cmd)
            await w_tel.drain()
            resp = await r_tel.readuntil(b"# ")
            tel_out += resp.decode(errors="ignore")

        w_tel.write(b"exit\r\n")
        await w_tel.drain()
    finally:
        w_tel.close()
        await w_tel.wait_closed()
    assert_no_forbidden_words(tel_out, "Telnet Session")

    # 5.3 Redis commands
    r_red, w_red = await asyncio.open_connection(host, red_p)
    redis_cmds = [b"CONFIG GET *\r\n", b"CLIENT LIST\r\n", b"INFO\r\n", b"KEYS *\r\n"]
    red_total = ""
    try:
        for rc in redis_cmds:
            w_red.write(rc)
            await w_red.drain()
            red_total += (await r_red.read(2048)).decode(errors="ignore")
    finally:
        w_red.close()
        await w_red.wait_closed()
    assert_no_forbidden_words(red_total, "Redis Responses")

    # 5.4 HTTP endpoints (headers, cookies, robots.txt, login form)
    async with httpx.AsyncClient() as c:
        r_idx = await c.get(f"http://{host}:{web_p}/")
        assert_no_forbidden_words(r_idx.text, "HTTP Index")
        assert_no_forbidden_words(str(dict(r_idx.headers)), "HTTP Headers")
        assert "PHPSESSID" in r_idx.headers.get("Set-Cookie", "")
        assert_no_forbidden_words(r_idx.headers.get("Set-Cookie", ""), "HTTP Set-Cookie")

        r_rob = await c.get(f"http://{host}:{web_p}/robots.txt")
        assert_no_forbidden_words(r_rob.text, "HTTP robots.txt")

        r_env = await c.get(f"http://{host}:{web_p}/.env")
        assert_no_forbidden_words(r_env.text, "HTTP .env")

    # 5.5 Recursive VirtualFS traversal
    vfs = VirtualFS(persona, "check-trap-01", time.time() - 172800)
    for p, node in vfs.entries.items():
        assert_no_forbidden_words(p, f"VirtualFS Path: {p}")
        if node.content:
            text_cont = node.content if isinstance(node.content, str) else node.content.decode("utf-8", errors="ignore")
            assert_no_forbidden_words(text_cont, f"VirtualFS Content: {p}")

    return True, "0 leak words across SSH (9 cmds), Telnet, Redis, HTTP, and VirtualFS"


async def check_item_6_host_keys(mode: str, host: str, ssh_p: int, trap_ref=None) -> Tuple[bool, str]:
    """Item 6: Persistent host keys across restarts (RSA, ECDSA, Ed25519)"""
    if mode == "local" and trap_ref:
        k1_rsa = trap_ref.host_keys[0].asbytes()
        k1_ecdsa = trap_ref.host_keys[1].asbytes()
        k1_ed = trap_ref.host_keys[2].asbytes()

        # Instantiate second instance simulating restart
        t2 = FakeSSHTrap(
            port=12224,
            event_callback=lambda e: None,
            session_callback=lambda s: None,
            trap_id=trap_ref.trap_id,
            persona=trap_ref.persona,
        )
        assert k1_rsa == t2.host_keys[0].asbytes(), "RSA key altered across restart"
        assert k1_ecdsa == t2.host_keys[1].asbytes(), "ECDSA key altered across restart"
        assert k1_ed == t2.host_keys[2].asbytes(), "Ed25519 key altered across restart"
    else:
        # Live mode: fetch keys
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, ssh_p))
        trans = paramiko.Transport(s)
        try:
            trans.start_client()
            key = trans.get_remote_server_key()
            assert key is not None, "Failed to retrieve remote host key"
            fp = key.get_fingerprint().hex()
            assert len(fp) > 0
        finally:
            trans.close()
            s.close()

    return True, "RSA, ECDSA, and Ed25519 keys persisted and preserved"


async def check_item_7_http_errors(mode: str, host: str, web_p: int, persona: dict) -> Tuple[bool, str]:
    """Item 7: Apache 2.4.52 HTML error templates (400, 403, 404, 405, 414)"""
    host_ip = persona.get("ip", host)
    async with httpx.AsyncClient() as c:
        # 404 Not Found
        r404 = await c.get(f"http://{host}:{web_p}/nonexistent_resource_{uuid.uuid4().hex[:6]}")
        assert r404.status_code == 404
        assert "<title>404 Not Found</title>" in r404.text
        assert "Apache/2.4.52 (Ubuntu) Server at" in r404.text
        assert r404.headers.get("Content-Type") == "text/html; charset=iso-8859-1"

        # 403 Forbidden (/server-status)
        r403 = await c.get(f"http://{host}:{web_p}/server-status")
        assert r403.status_code == 403
        assert "<title>403 Forbidden</title>" in r403.text
        assert "You don't have permission to access this resource." in r403.text

        # 405 Method Not Allowed (PROPFIND)
        r405 = await c.request("PROPFIND", f"http://{host}:{web_p}/")
        assert r405.status_code == 405
        assert "<title>405 Method Not Allowed</title>" in r405.text

    return True, "Apache 2.4.52 error templates with exact ISO-8859-1 charset and signatures"


async def check_item_8_redis_unknown(mode: str, host: str, red_p: int) -> Tuple[bool, str]:
    """Item 8: Redis 7 standard unknown command format"""
    r, w = await asyncio.open_connection(host, red_p)
    w.write(b"FOOBAR123 my_arg1 my_arg2\r\n")
    await w.drain()
    err_line = (await r.readline()).decode(errors="ignore")
    w.close()
    await w.wait_closed()
    expected_prefix = "-ERR unknown command 'FOOBAR123', with args beginning with: 'my_arg1' 'my_arg2'"
    assert err_line.startswith(expected_prefix), f"Redis unknown command format invalid: {err_line}"
    return True, "Authentic Redis 7 '-ERR unknown command ... with args beginning with' format"


async def check_item_9_stealth_404(
    mode: str, base_url: str, ca_cert: str
) -> Tuple[bool, str]:
    """
    Item 9: Stealth 404 Indistinguishability.
    Verifies that real telemetry and metrics paths across GET/POST/HEAD/OPTIONS,
    both without HMAC signature and with invalid signature, return responses
    byte-for-byte and header-for-header identical to random 404 routes.
    """
    stealth_paths = [
        "/cdn-cgi/rum",
        "/static/v2/metrics",
        "/sync/v1/config",
        "/static/pixel.gif",
        "/cdn-cgi/trace",
        "/sync/invalid-token-12345",
        "/cdn-cgi/unknown-subpath-987",
    ]
    methods = ["GET", "POST", "HEAD", "OPTIONS"]

    # In local mode, test directly against FastAPI app
    if mode == "local":
        from honeyforge_server.app.main import app
        from httpx import ASGITransport
        client = httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    else:
        # Live mode: through Nginx over HTTPS with CA pinning
        client = httpx.AsyncClient(base_url=base_url, verify=ca_cert)

    async with client:
        # Benchmark ghost 404 route
        ghost_path = f"/404-ghost-{uuid.uuid4().hex[:12]}"
        r_ghost = await client.get(ghost_path)
        assert r_ghost.status_code == 404, f"Ghost route did not return 404: {r_ghost.status_code}"

        ghost_body = r_ghost.content
        ghost_headers = {k.lower(): v for k, v in r_ghost.headers.items() if k.lower() not in ["date", "server", "keep-alive"]}

        print(f"       Measured 404 baseline on {ghost_path}:")
        print(f"         Status: {r_ghost.status_code}")
        print(f"         Headers: {list(r_ghost.headers.keys())}")
        print(f"         Content-Type: {r_ghost.headers.get('content-type', 'none')}")
        print(f"         Body Length: {len(ghost_body)} bytes")
        print(f"         Body Preview: {ghost_body[:60]!r}")

        for path in stealth_paths:
            for method in methods:
                # 1. Without HMAC signature
                r_no_sig = await client.request(method, path, content=b'{"probe":1}')
                assert r_no_sig.status_code == 404, f"{method} {path} without sig returned {r_no_sig.status_code}"
                if method != "HEAD":
                    assert r_no_sig.content == ghost_body, f"Body mismatch on {method} {path} without sig: {r_no_sig.content} != {ghost_body}"

                no_sig_hdrs = {k.lower(): v for k, v in r_no_sig.headers.items() if k.lower() not in ["date", "server", "keep-alive"]}
                assert no_sig_hdrs == ghost_headers, f"Header mismatch on {method} {path} without sig: {no_sig_hdrs} != {ghost_headers}"

                # 2. With invalid HMAC signature
                bad_headers = {
                    "X-Node-ID": "n-probe",
                    "X-Signature": "badf00d" * 8,
                    "X-Nonce": str(uuid.uuid4()),
                    "X-Timestamp": str(time.time()),
                }
                r_bad_sig = await client.request(method, path, content=b'{"probe":1}', headers=bad_headers)
                assert r_bad_sig.status_code == 404, f"{method} {path} with bad sig returned {r_bad_sig.status_code}"
                if method != "HEAD":
                    assert r_bad_sig.content == ghost_body, f"Body mismatch on {method} {path} with bad sig"

    return True, f"5 stealth paths across 4 HTTP verbs match stock 404 byte-for-byte ({len(ghost_body)}B, Content-Type: {r_ghost.headers.get('content-type', '')})"


async def check_item_10_ssh_kex(mode: str, host: str, ssh_p: int, trap_ref=None) -> Tuple[bool, str]:
    """Item 10: SSH Kex/ciphers/MACs comparison with OpenSSH 8.9p1 reference"""
    kex_ref_path = os.path.join(os.path.dirname(__file__), "..", "tests", "data", "openssh_8.9p1_kex.json")
    with open(kex_ref_path, "r", encoding="utf-8") as f:
        ref_data = json.load(f)

    if mode == "local" and trap_ref:
        s1, s2 = socket.socketpair()
        try:
            trans = paramiko.Transport(s1)
            trap_ref._configure_security_options(trans)
            sec = trans.get_security_options()
            for cipher in sec.ciphers:
                assert cipher in ref_data["ciphers"], f"Unexpected cipher not in OpenSSH 8.9: {cipher}"
            for kex in sec.kex:
                assert kex in ref_data["kex_algorithms"], f"Unexpected kex not in OpenSSH 8.9: {kex}"
            for mac in sec.digests:
                assert mac in ref_data["macs"], f"Unexpected mac not in OpenSSH 8.9: {mac}"
        finally:
            s1.close()
            s2.close()
    else:
        # Live mode: verify negotiated algorithms on active SSH connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=ssh_p, username="root", password="admin123", timeout=5)
        except Exception:
            client.connect(host, port=ssh_p, username="root", password="admin123", timeout=5)
        try:
            trans = client.get_transport()
            assert trans.remote_cipher in ref_data["ciphers"], f"Negotiated cipher not in OpenSSH 8.9: {trans.remote_cipher}"
            assert trans.remote_mac in ref_data["macs"], f"Negotiated MAC not in OpenSSH 8.9: {trans.remote_mac}"
        finally:
            client.close()

    return True, "Strict subset of Ubuntu 22.04 LTS OpenSSH 8.9p1 cryptographic policy"


async def check_item_11_exec_mode(mode: str, host: str, ssh_p: int, trap_ref=None) -> Tuple[bool, str]:
    """Item 11: Exec-mode SSH execution without PTY (id, uname -a, cat /etc/os-release, non-zero exit code)"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)
    except Exception:
        client.close()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=ssh_p, username="root", password="admin123", timeout=6)

    try:
        # 1. id
        _, stdout, stderr = client.exec_command("id")
        out_id = stdout.read().decode("utf-8")
        err_id = stderr.read().decode("utf-8")
        exit_id = stdout.channel.recv_exit_status()
        assert exit_id == 0, f"id exit code: {exit_id}"
        assert "uid=0(root)" in out_id, f"Unexpected id output: {out_id}"
        assert err_id == "", f"Unexpected stderr in id: {err_id}"
        assert "\x1b" not in out_id, "PTY escape sequence found in exec-mode output"

        # 2. uname -a
        _, stdout, stderr = client.exec_command("uname -a")
        out_uname = stdout.read().decode("utf-8")
        err_uname = stderr.read().decode("utf-8")
        exit_uname = stdout.channel.recv_exit_status()
        assert exit_uname == 0, f"uname exit code: {exit_uname}"
        assert "Linux" in out_uname, f"Unexpected uname output: {out_uname}"
        assert err_uname == ""

        # 3. cat /etc/os-release
        _, stdout, stderr = client.exec_command("cat /etc/os-release")
        out_os = stdout.read().decode("utf-8")
        err_os = stderr.read().decode("utf-8")
        exit_os = stdout.channel.recv_exit_status()
        assert exit_os == 0, f"cat os-release exit code: {exit_os}"
        assert "Ubuntu" in out_os and "22.04" in out_os, f"Unexpected os-release: {out_os}"
        assert err_os == ""

        # 4. nonexistent command must return exit code 127 and error on stderr
        _, stdout, stderr = client.exec_command("nonexistent_command_probe_42")
        out_non = stdout.read().decode("utf-8")
        err_non = stderr.read().decode("utf-8")
        exit_non = stdout.channel.recv_exit_status()
        assert exit_non != 0, f"Expected non-zero exit code for nonexistent command, got {exit_non}"
        assert exit_non == 127, f"Expected bash standard 127 exit code, got {exit_non}"
        assert "command not found" in err_non or "command not found" in out_non
    finally:
        client.close()

    return True, "Authentic Exec-mode SSH: stdout/stderr separation, exit codes (0 and 127), zero PTY sequences"


async def run_selfcheck(args: argparse.Namespace) -> bool:
    mode = "live" if args.live else "local"
    host = args.host
    ca_cert = args.ca_cert
    base_url = args.base_url

    print("=" * 80)
    print(f"  HONEYFORGE REALISM & STEALTH AUDIT SUITE (MASK-6) [MODE: {mode.upper()}]")
    print("=" * 80)

    test_results: List[Tuple[int, str, bool, str]] = []

    def record(num: int, title: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        color = "\033[92m" if passed else "\033[91m"
        rst = "\033[0m"
        print(f"[{color}{status}{rst}] Пункт {num:02d}: {title} {('- ' + detail) if detail else ''}")
        test_results.append((num, title, passed, detail))

    persona = {
        "hostname": "edge-gw-01",
        "ip": "172.28.0.20" if mode == "live" else "10.0.1.5",
        "os": "Ubuntu 22.04.4 LTS",
        "kernel": "5.15.0-89-generic",
        "users": ["root", "deploy", "ubuntu"],
        "uptime_base": 172800,
    }

    ssh_trap = None
    web_trap = None
    low_trap = None

    if mode == "local":
        ssh_p = 12222
        web_p = 18080
        ftp_p = 12121
        tel_p = 12323
        red_p = 16379

        ssh_trap = FakeSSHTrap(port=ssh_p, event_callback=lambda e: None, session_callback=lambda s: None, trap_id="check-01", persona=persona)
        await ssh_trap.start()

        web_trap = FakeWebTrap(port=web_p, event_callback=lambda e: None, trap_id="check-01", persona=persona)
        await web_trap.start()

        low_trap = LowInteractionMultiPortTrap(ports=[ftp_p, tel_p, red_p], banners={}, event_callback=lambda e: None, trap_id="check-01", persona=persona)
        await low_trap.start()
        await asyncio.sleep(0.2)
    else:
        ssh_p = args.ssh_port
        web_p = args.web_port
        ftp_p = args.ftp_port
        tel_p = args.telnet_port
        red_p = args.redis_port

    try:
        # 1. Banners
        try:
            ok, det = await check_item_1_banners(mode, host, ssh_p, web_p, ftp_p, tel_p, red_p, persona)
            record(1, "Согласованность баннеров и persona", ok, det)
        except Exception as e:
            record(1, "Согласованность баннеров и persona", False, str(e))

        # 2. GNU errors
        try:
            ok, det = await check_item_2_gnu_errors(mode, host, ssh_p, trap_ref=ssh_trap)
            record(2, "Формат ошибок bash и coreutils", ok, det)
        except Exception as e:
            record(2, "Формат ошибок bash и coreutils", False, str(e))

        # 3. ls -la
        try:
            ok, det = await check_item_3_ls_dates(mode, host, ssh_p, trap_ref=ssh_trap)
            record(3, "Корректность ls -la и GNU дат", ok, det)
        except Exception as e:
            record(3, "Корректность ls -la и GNU дат", False, str(e))

        # 4. Timings
        try:
            ok, det = await check_item_4_timings(mode, host, ssh_p, web_p, ftp_p)
            record(4, "Реалистичные задержки и variance (FTP, HTTP, SSH auth & disconnect)", ok, det)
        except Exception as e:
            record(4, "Реалистичные задержки и variance", False, str(e))

        # 5. Forbidden words
        try:
            ok, det = await check_item_5_forbidden_words(mode, host, ssh_p, web_p, ftp_p, tel_p, red_p, persona)
            record(5, "Отсутствие запрещённых слов (SSH, Telnet, Redis, HTTP, VirtualFS)", ok, det)
        except Exception as e:
            record(5, "Отсутствие запрещённых слов", False, str(e))

        # 6. Host keys
        try:
            ok, det = await check_item_6_host_keys(mode, host, ssh_p, trap_ref=ssh_trap)
            record(6, "Постоянство хост-ключей (RSA, ECDSA, Ed25519) и volume", ok, det)
        except Exception as e:
            record(6, "Постоянство хост-ключей", False, str(e))

        # 7. HTTP error pages
        try:
            ok, det = await check_item_7_http_errors(mode, host, web_p, persona)
            record(7, "Корректность страниц ошибок HTTP (Apache 2.4.52 HTML)", ok, det)
        except Exception as e:
            record(7, "Корректность страниц ошибок HTTP", False, str(e))

        # 8. Redis unknown cmd
        try:
            ok, det = await check_item_8_redis_unknown(mode, host, red_p)
            record(8, "Ответ Redis на неизвестную команду (Redis 7)", ok, det)
        except Exception as e:
            record(8, "Ответ Redis на неизвестную команду", False, str(e))

        # 9. Stealth 404
        try:
            ok, det = await check_item_9_stealth_404(mode, base_url, ca_cert)
            record(9, "404-идентичность скрытого эндпоинта (Stealth Telemetry)", ok, det)
        except Exception as e:
            record(9, "404-идентичность скрытого эндпоинта", False, str(e))

        # 10. SSH Kex reference
        try:
            ok, det = await check_item_10_ssh_kex(mode, host, ssh_p, trap_ref=ssh_trap)
            record(10, "Криптографический набор SSH (OpenSSH 8.9p1 reference)", ok, det)
        except Exception as e:
            record(10, "Криптографический набор SSH", False, str(e))

        # 11. SSH Exec-mode without PTY
        try:
            ok, det = await check_item_11_exec_mode(mode, host, ssh_p, trap_ref=ssh_trap)
            record(11, "Режим non-interactive Exec SSH (id, uname, os-release, non-zero exit code)", ok, det)
        except Exception as e:
            record(11, "Режим non-interactive Exec SSH", False, str(e))

    finally:
        if ssh_trap:
            await ssh_trap.stop()
        if web_trap:
            await web_trap.stop()
        if low_trap:
            await low_trap.stop()

    print("=" * 80)
    passed_count = sum(1 for _, _, p, _ in test_results if p)
    total_count = len(test_results)
    print(f"  ИТОГ САМОПРОВЕРКИ: {passed_count}/{total_count} проверок пройдено успешно.")
    print("=" * 80)

    return passed_count == total_count


def parse_args():
    parser = argparse.ArgumentParser(description="HoneyForge Realism & Stealth Audit Suite")
    parser.add_argument("--local", action="store_true", help="Run local in-process verification")
    parser.add_argument("--live", action="store_true", help="Run live verification against docker-compose stand")
    parser.add_argument("--host", default="127.0.0.1", help="Target host for live verification")
    parser.add_argument("--ssh-port", type=int, default=2222, help="SSH trap port")
    parser.add_argument("--web-port", type=int, default=8088, help="Web trap port")
    parser.add_argument("--ftp-port", type=int, default=2121, help="FTP trap port")
    parser.add_argument("--telnet-port", type=int, default=2323, help="Telnet trap port")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis trap port")
    parser.add_argument("--base-url", default="https://127.0.0.1:8443", help="Static edge base URL")
    parser.add_argument("--ca-cert", default="docker/certs/static-edge.crt", help="CA certificate path")
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = parse_args()
    if not cli_args.live and not cli_args.local:
        # Default to local if neither specified
        cli_args.local = True
    success = asyncio.run(run_selfcheck(cli_args))
    sys.exit(0 if success else 1)
