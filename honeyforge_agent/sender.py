import os
import uuid
import time
import json
import asyncio
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
    Transmits encrypted and disguised telemetry batches to HoneyForge C2 / Static-Edge proxy.
    Performs cryptographic body hashing (HMAC-SHA256) and TLS certificate pinning.
    """
    def __init__(self, c2_url: str = agent_config.C2_URL, secret_key: str = agent_config.SECRET_KEY, trap_id: str = None):
        self.c2_url = c2_url.rstrip("/")
        self.secret_key = secret_key
        self.trap_id = trap_id or agent_config.TRAP_ID
        self.endpoint = f"{self.c2_url}{agent_config.MASK_ENDPOINT}"

        # MASK-7: Certificate Pinning
        self.failure_count = 0

    def _resolve_ssl_verification(self) -> Optional[str]:
        """Resolves pinned TLS CA certificate path. Returns valid path or None. Never returns False."""
        candidate_paths = [
            agent_config.SSL_CERT_PATH,
            "/etc/ssl/certs/static-edge.crt",
            "/etc/nginx/certs/static-edge.crt",
            "./docker/certs/static-edge.crt",
            "docker/certs/static-edge.crt"
        ]
        for p in candidate_paths:
            if p and os.path.isfile(p):
                return p
        return None

    async def send_batch(
        self,
        events: List[Dict[str, Any]],
        session_logs: List[Dict[str, Any]],
        heartbeat_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Sends batch of events through disguised endpoint with body-hashed signature validation"""
        timestamp = time.time()
        nonce = uuid.uuid4().hex

        # Construct payload
        payload = {
            "trap_id": self.trap_id,
            "nonce": nonce,
            "timestamp": timestamp,
            "heartbeat": heartbeat_data,
            "events": events,
            "session_logs": session_logs
        }
        
        # MASK-5: Add variable dummy padding to disrupt packet size analysis
        if agent_config.DUMMY_PADDING:
            payload["_pad"] = generate_dummy_padding(32, 96)

        # 1. Compute clean body signature
        clean_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        clean_sig = sign_telemetry_payload(
            trap_id=self.trap_id,
            timestamp=timestamp,
            nonce=nonce,
            secret_key=self.secret_key,
            raw_body=clean_bytes
        )
        payload["signature"] = clean_sig

        # 2. Serialize final wire bytes and compute wire signature
        final_wire_bytes = json.dumps(payload).encode("utf-8")
        wire_sig = sign_telemetry_payload(
            trap_id=self.trap_id,
            timestamp=timestamp,
            nonce=nonce,
            secret_key=self.secret_key,
            raw_body=final_wire_bytes
        )

        headers = get_disguised_headers()
        headers["X-Signature"] = wire_sig
        headers["X-Timestamp"] = str(timestamp)
        headers["X-Nonce"] = nonce
        headers["X-Node-ID"] = self.trap_id

        verify_target = self._get_client_verify()
        if verify_target is None:
            # TLS certificate not yet available: backoff and retry, NEVER fall back to insecure mode
            await asyncio.sleep(min(10.0, 1.5 ** min(self.failure_count, 4)))
            self.failure_count += 1
            return False

        try:
            async with httpx.AsyncClient(timeout=8.0, verify=verify_target) as client:
                response = await client.post(
                    self.endpoint,
                    content=final_wire_bytes,
                    headers=headers
                )
                if response.status_code in [200, 204]:
                    self.failure_count = 0
                    return True
                self.failure_count += 1
                return False
        except Exception:
            # Network failure or C2 unreachable: keep in local store-and-forward buffer
            self.failure_count += 1
            return False

    def _get_client_verify(self) -> Optional[Any]:
        if not self.c2_url.startswith("https://"):
            return True
        cert_path = self._resolve_ssl_verification()
        if cert_path:
            return cert_path
        return None

    async def fetch_config(self) -> Optional[Dict[str, Any]]:
        """Pulls runtime updates from C2 using signed GET request (FR-A3)"""
        verify_target = self._get_client_verify()
        if verify_target is None:
            await asyncio.sleep(min(10.0, 1.5 ** min(self.failure_count, 4)))
            self.failure_count += 1
            return None

        timestamp = time.time()
        nonce = uuid.uuid4().hex
        empty_body = b""
        sig = sign_telemetry_payload(
            trap_id=self.trap_id,
            timestamp=timestamp,
            nonce=nonce,
            secret_key=self.secret_key,
            raw_body=empty_body
        )

        headers = get_disguised_headers()
        headers["X-Signature"] = sig
        headers["X-Timestamp"] = str(timestamp)
        headers["X-Nonce"] = nonce
        headers["X-Node-ID"] = self.trap_id

        cfg_urls = [
            f"{self.c2_url}/api/v1/traps/{self.trap_id}/config",
            f"{self.c2_url}/sync/v1/config/{self.trap_id}"
        ]

        for url in cfg_urls:
            try:
                async with httpx.AsyncClient(timeout=5.0, verify=verify_target) as client:
                    res = await client.get(url, headers=headers)
                    if res.status_code == 200:
                        self.failure_count = 0
                        return res.json()
            except Exception:
                continue
        self.failure_count += 1
        return None

    async def confirm_credential_rotation(self) -> bool:
        """Confirms to C2 that rotated credentials have been adopted (MASK-7)"""
        verify_target = self._get_client_verify()
        if verify_target is None:
            return False

        timestamp = time.time()
        nonce = uuid.uuid4().hex
        sig = sign_telemetry_payload(self.trap_id, timestamp, nonce, self.secret_key, raw_body=b"")
        headers = get_disguised_headers()
        headers["X-Signature"] = sig
        headers["X-Timestamp"] = str(timestamp)
        headers["X-Nonce"] = nonce
        url = f"{self.c2_url}/api/v1/traps/{self.trap_id}/confirm-rotation"
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=verify_target) as client:
                res = await client.post(url, headers=headers)
                return res.status_code == 200
        except Exception:
            return False
