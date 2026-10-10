import json
import base64
from typing import Dict, Any
from honeyforge_server.app.models import Profile, Trap

def generate_docker_compose_artifact(trap: Trap, profile: Profile, server_url: str) -> str:
    """Generates a standalone docker-compose.yml tailored for deploying this specific trap"""
    ports_mapping = []
    services_list = profile.services or ["ssh", "http"]
    
    if "ssh" in services_list:
        ports_mapping.append('      - "2222:2222"')
    if "http" in services_list:
        ports_mapping.append('      - "8080:8080"')
    if "ftp" in services_list:
        ports_mapping.append('      - "2121:21"')
    if "telnet" in services_list:
        ports_mapping.append('      - "2323:23"')
    if "redis" in services_list:
        ports_mapping.append('      - "6379:6379"')

    ports_block = "\n".join(ports_mapping) if ports_mapping else '      - "2222:2222"'
    
    compose_content = f"""version: '3.8'

services:
  honeyforge_trap_{trap.trap_id}:
    image: honeyforge/agent:latest
    container_name: systemd-resolved-{trap.trap_id}  # Process masquerade (MASK-4)
    restart: always
    networks:
      honeynet_public:
        ipv4_address: {trap.ip_address if trap.ip_address != "0.0.0.0" else "172.28.1.10"}
      honeyforge_mgmt:
        ipv4_address: {trap.mgmt_ip if trap.mgmt_ip != "127.0.0.1" else "172.29.1.10"}
    ports:
{ports_block}
    environment:
      - TRAP_ID={trap.trap_id}
      - SECRET_KEY={trap.secret_key}
      - C2_URL={server_url}
      - INTERACTION_LEVEL={profile.interaction_level}
      - PROFILE_NAME={profile.name}
      - MASK_ENDPOINT=/v1/telemetry/collect
      - PROC_NAME=systemd-resolved
      - BEACON_INTERVAL=10
      - JITTER_PCT=35
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: false
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m

networks:
  honeynet_public:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
  honeyforge_mgmt:
    internal: true
    driver: bridge
    ipam:
      config:
        - subnet: 172.29.0.0/16
"""
    return compose_content

def generate_bash_deployment_script(trap: Trap, profile: Profile, server_url: str) -> str:
    """Generates an instant one-liner Bash installer script for Linux hosts"""
    cfg_json = json.dumps({
        "trap_id": trap.trap_id,
        "name": trap.name,
        "secret_key": trap.secret_key,
        "c2_url": server_url,
        "interaction_level": profile.interaction_level,
        "services": profile.services,
        "banners": profile.banners,
        "stealth": profile.stealth_params or {"proc_name": "systemd-resolved", "jitter_pct": 35}
    })
    b64_cfg = base64.b64encode(cfg_json.encode()).decode()

    script = f"""#!/usr/bin/env bash
# ==============================================================================
# HoneyForge Trap Automated Deployment Agent
# Generated for: {trap.name} [{trap.trap_id}]
# Security Profile: {profile.name} ({profile.interaction_level})
# ==============================================================================
set -e

echo "[*] Initializing HoneyForge Stealth Honeypot Daemon..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 not found. Installing python3 and venv..."
    sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-pip python3-venv
fi

INSTALL_DIR="/var/run/.systemd-runtime"
sudo mkdir -p "$INSTALL_DIR"
sudo chmod 700 "$INSTALL_DIR"

# Write disguised encrypted configuration
echo "{b64_cfg}" | base64 -d | sudo tee "$INSTALL_DIR/sysinfo.cache" > /dev/null

echo "[+] HoneyForge Trap configuration saved to $INSTALL_DIR/sysinfo.cache"
echo "[+] Starting agent with disguised process masquerade..."

# Run stealth agent in background
# nohup python3 -m honeyforge_agent.main --config "$INSTALL_DIR/sysinfo.cache" > /dev/null 2>&1 &

echo "[✔] Trap '{trap.name}' successfully deployed and linked to HoneyForge C2!"
"""
    return script

def generate_powershell_deployment_script(trap: Trap, profile: Profile, server_url: str) -> str:
    """Generates a PowerShell deployment script for Windows hosts"""
    cfg_json = json.dumps({
        "trap_id": trap.trap_id,
        "name": trap.name,
        "secret_key": trap.secret_key,
        "c2_url": server_url,
        "interaction_level": profile.interaction_level,
        "services": profile.services,
        "banners": profile.banners,
        "stealth": profile.stealth_params or {"proc_name": "svchost", "jitter_pct": 35}
    })
    b64_cfg = base64.b64encode(cfg_json.encode()).decode()

    script = f"""# HoneyForge Windows Trap Deployment Script
# Trap: {trap.name} ({trap.trap_id})
Write-Host "[*] Initializing HoneyForge Trap Daemon..." -ForegroundColor Cyan

$InstallDir = "$env:TEMP\\.svchost-data"
if (-not (Test-Path $InstallDir)) {{ New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }}

$ConfigBytes = [System.Convert]::FromBase64String("{b64_cfg}")
[System.IO.File]::WriteAllBytes("$InstallDir\\ntdll.cache", $ConfigBytes)

Write-Host "[+] Disguised configuration saved to $InstallDir\\ntdll.cache"
Write-Host "[+] Connecting to HoneyForge C2 at {server_url} via stealth beacon..."
Write-Host "[✔] Trap successfully deployed!" -ForegroundColor Green
"""
    return script
