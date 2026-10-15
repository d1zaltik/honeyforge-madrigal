import os

def _resolve_secret_key() -> str:
    key_file = os.getenv("NODE_KEY_FILE", "/run/secrets/node_key")
    if os.path.isfile(key_file):
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass
    return os.getenv("NODE_KEY") or os.getenv("SECRET_KEY", "node-auth-default-k91")

class AgentConfig:
    # Neutral Node Identity & Upstream Channel (MASK-1 & MASK-3)
    NODE_ID: str = os.getenv("NODE_ID") or os.getenv("TRAP_ID", "n-7f3a")
    SECRET_KEY: str = _resolve_secret_key()
    C2_URL: str = os.getenv("UPSTREAM_URL") or os.getenv("C2_URL", "https://static-edge")
    
    # Backward compatibility alias
    TRAP_ID: str = NODE_ID
    TRAP_NAME: str = NODE_ID

    # Interaction level
    INTERACTION_LEVEL: str = os.getenv("INTERACTION_LEVEL", "medium")
    
    # Stealth parameters (MASK-1, MASK-2, MASK-4, MASK-5)
    MASK_ENDPOINT: str = os.getenv("MASK_ENDPOINT", "/cdn-cgi/rum")
    CONFIG_ENDPOINT: str = os.getenv("CONFIG_ENDPOINT", "/sync/v1/config")
    PROC_NAME: str = os.getenv("PROC_NAME", "syslog-ng")
    BEACON_INTERVAL_S: float = float(os.getenv("SYNC_INTERVAL") or os.getenv("BEACON_INTERVAL", "8.0"))
    JITTER_PCT: float = float(os.getenv("JITTER_PCT", "35.0"))
    DUMMY_PADDING: bool = os.getenv("DUMMY_PADDING", "true").lower() == "true"
    
    # TLS Certificate Pinning (MASK-7)
    SSL_CERT_PATH: str = os.getenv("SSL_CERT_PATH", "/etc/ssl/certs/static-edge.crt")
    
    # Local store-and-forward buffer DB path in neutral cache directory (FR-A4)
    BUFFER_DB_PATH: str = os.getenv("BUFFER_DB_PATH", "/var/tmp/.cache/syslog.store.db")
    
    # Bound ports for service probes
    SSH_PORT: int = int(os.getenv("SSH_PORT", "2222"))
    WEB_PORT: int = int(os.getenv("WEB_PORT", "8088"))
    LOW_PORTS: list = [2121, 2323, 6379]

DEFAULT_DECOY_CREDENTIALS = [
    {"user": "root", "pass": "admin123"},
    {"user": "admin", "pass": "password"},
    {"user": "deploy", "pass": "deploy2026"}
]

agent_config = AgentConfig()
