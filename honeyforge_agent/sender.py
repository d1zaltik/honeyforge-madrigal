import uuid
import time
import httpx
from typing import List, Dict, Any, Optional
from honeyforge_agent.config import agent_config
from honeyforge_agent.stealth import (
    get_disguised_headers,
    sign_telemetry_payload,
    generate_dummy_padding
)

class TelemetrySender:
    """
    MASK-1, MASK-2, MASK-7, FR-A3:
    Transmits encrypted and disguised telemetry batches to HoneyForge C2.
    """
    def __init__(self, c2_url: str = agent_config.C2_URL, secret_key: str = agent_config.SECRET_KEY, trap_id: str = None):
        self.c2_url = c2_url.rstrip("/")
        self.secret_key = secret_key
        self.trap_id = trap_id or agent_config.TRAP_ID
        self.endpoint = f"{self.c2_url}{agent_config.MASK_ENDPOINT}"

    async def send_batch(
        self,
        events: List[Dict[str, Any]],
        session_logs: List[Dict[str, Any]],
        heartbeat_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Sends batch of events through disguised endpoint with signature validation"""
        timestamp = time.time()
        nonce = uuid.uuid4().hex
        signature = sign_telemetry_payload(
            trap_id=self.trap_id,
            timestamp=timestamp,
            nonce=nonce,
            secret_key=self.secret_key
        )

        payload = {
            "trap_id": self.trap_id,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature,
            "heartbeat": heartbeat_data,
            "events": events,
            "session_logs": session_logs
        }
        
        # MASK-5: add dummy padding if configured
        if agent_config.DUMMY_PADDING:
            payload["_pad"] = generate_dummy_padding(32, 96)

        headers = get_disguised_headers()

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.post(self.endpoint, json=payload, headers=headers)
                if response.status_code == 200:
                    return True
                return False
        except Exception:
            # Network failure or C2 unreachable: keep in local buffer
            return False

    async def fetch_config(self) -> Optional[Dict[str, Any]]:
        """Pulls runtime updates from C2 (FR-A3)"""
        cfg_url = f"{self.c2_url}/api/v1/traps/{agent_config.TRAP_ID}/config"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(cfg_url)
                if res.status_code == 200:
                    return res.json()
        except Exception:
            pass
        return None
