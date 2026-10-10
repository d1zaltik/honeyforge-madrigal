import os

class Settings:
    PROJECT_NAME: str = "HoneyForge C2 Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Server network bindings
    HOST: str = os.getenv("HONEYFORGE_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("HONEYFORGE_PORT", "8000"))
    
    # Database URL: default SQLite with aiosqlite for zero-dependency standalone execution
    # or PostgreSQL in production docker: postgresql+asyncpg://honeyforge:secret@db:5432/honeyforge
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./honeyforge.db")
    
    # Security
    JWT_SECRET: str = os.getenv("JWT_SECRET", "honeyforge-soc-super-secret-key-2026")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    
    # Stealth Telemetry Settings (MASK-1 & MASK-2)
    # The ingestion endpoint is disguised as a legitimate CDN/analytics telemetry beacon
    MASK_TELEMETRY_ENDPOINT: str = "/v1/telemetry/collect"
    MASK_BEACON_GIF_ENDPOINT: str = "/cdn-cgi/telemetry/pixel.gif"
    MASK_CONFIG_ENDPOINT: str = "/v1/static/runtime.cfg"
    
    # Pre-shared Master Key for Agent HMAC Auth (MASK-7)
    MASTER_AGENT_KEY: str = os.getenv("MASTER_AGENT_KEY", "honeyforge-stealth-agent-secret-4f7b2")

settings = Settings()
