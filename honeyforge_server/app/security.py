import hmac
import hashlib
import time
import base64
import json
from typing import Optional, Dict, Any
from honeyforge_server.app.config import settings

def hash_password(password: str) -> str:
    salt = "honeyforge_salt_2026"
    return hashlib.sha256(f"{salt}{password}".encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict, expires_in_seconds: int = 86400) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = data.copy()
    payload["exp"] = int(time.time()) + expires_in_seconds
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    
    signature_base = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(settings.JWT_SECRET.encode(), signature_base, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def decode_access_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        
        # Verify signature
        signature_base = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(settings.JWT_SECRET.encode(), signature_base, hashlib.sha256).digest()
        
        # Add padding back to base64 if needed
        padding_needed = 4 - (len(sig_b64) % 4)
        if padding_needed != 4:
            sig_b64 += "=" * padding_needed
        actual_sig = base64.urlsafe_b64decode(sig_b64.encode())
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
            
        payload_padding = 4 - (len(payload_b64) % 4)
        if payload_padding != 4:
            payload_b64 += "=" * payload_padding
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64.encode()).decode())
        
        if payload_data.get("exp", 0) < time.time():
            return None
            
        return payload_data
    except Exception:
        return None

def verify_agent_signature(trap_id: str, timestamp: float, nonce: str, signature: str, secret_key: str) -> bool:
    """Verifies HMAC signature of agent telemetry to prevent tampering or unauthorized beacons"""
    # Max skew 10 minutes to allow for time differences
    if abs(time.time() - timestamp) > 600:
        return False
    data_to_sign = f"{trap_id}:{timestamp}:{nonce}".encode()
    expected_sig = hmac.new(secret_key.encode(), data_to_sign, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, signature)

def generate_agent_signature(trap_id: str, timestamp: float, nonce: str, secret_key: str) -> str:
    data_to_sign = f"{trap_id}:{timestamp}:{nonce}".encode()
    return hmac.new(secret_key.encode(), data_to_sign, hashlib.sha256).hexdigest()
