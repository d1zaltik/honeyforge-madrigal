import asyncio
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from simulator_attacker.scenarios import (
    run_port_scan,
    run_ssh_brute_force,
    run_post_exploitation,
    run_honeytoken_breach
)

app = FastAPI(title="HoneyForge Dedicated Attacker Simulator", version="1.0.0")

class AttackRequest(BaseModel):
    scenario: str
    target_host: str = "systemd-resolved-low"
    token_id: Optional[str] = None
    nginx_host: str = "static-edge"

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "sec-scanner"}

@app.post("/run")
async def execute_scenario(req: AttackRequest):
    scenario = req.scenario
    target_host = req.target_host
    nginx_host = req.nginx_host
    token_id = req.token_id or "default-token"

    if scenario == "port_scan":
        delivered = await run_port_scan(target_host)
    elif scenario == "ssh_brute_force":
        delivered = await run_ssh_brute_force(target_host)
    elif scenario == "post_exploitation":
        delivered = await run_post_exploitation(target_host)
    elif scenario == "honeytoken_breach":
        delivered = await run_honeytoken_breach(nginx_host, token_id)
    elif scenario == "network_disconnect":
        delivered = 0
    else:
        raise HTTPException(status_code=400, detail=f"Неизвестный сценарий: {scenario}")

    return {
        "status": "success",
        "scenario": scenario,
        "target_host": target_host,
        "delivered_events": delivered
    }
