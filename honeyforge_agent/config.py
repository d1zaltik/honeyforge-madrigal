import os

class AgentConfig:
    TRAP_ID: str = os.getenv("TRAP_ID", "trap-med-01")
    TRAP_NAME: str = os.getenv("TRAP_NAME", "Internal-SSH-Trap-02")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "secret-key-med-01")
    C2_URL: str = os.getenv("C2_URL", "http://127.0.0.1:8000")
    
    # Interaction level
    INTERACTION_LEVEL: str = os.getenv("INTERACTION_LEVEL", "medium")
    
    # Stealth parameters (MASK-1, MASK-2, MASK-4, MASK-5)
    MASK_ENDPOINT: str = os.getenv("MASK_ENDPOINT", "/v1/telemetry/collect")
    PROC_NAME: str = os.getenv("PROC_NAME", "systemd-resolved")
    BEACON_INTERVAL_S: float = float(os.getenv("BEACON_INTERVAL", "10.0"))
    JITTER_PCT: float = float(os.getenv("JITTER_PCT", "35.0"))
    DUMMY_PADDING: bool = os.getenv("DUMMY_PADDING", "true").lower() == "true"
    
    # Local store-and-forward buffer DB path (FR-A4)
    BUFFER_DB_PATH: str = os.getenv("BUFFER_DB_PATH", ".sysinfo.store.db")
    
    # Bound ports for trap services
    SSH_PORT: int = int(os.getenv("SSH_PORT", "2222"))
    WEB_PORT: int = int(os.getenv("WEB_PORT", "8088"))
    LOW_PORTS: list = [2121, 2323, 6379]  # FTP, Telnet, Redis low interaction
    
agent_config = AgentConfig()
