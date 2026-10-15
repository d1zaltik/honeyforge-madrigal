import os
import secrets
import logging

logger = logging.getLogger("honeyforge_server.config")

class Settings:
    PROJECT_NAME: str = "HoneyForge C2 Platform"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Server network bindings
    HOST: str = os.getenv("HONEYFORGE_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("HONEYFORGE_PORT", "8000"))
    
    # Database URL: default SQLite with aiosqlite for zero-dependency standalone execution
    # or PostgreSQL in production docker: postgresql+asyncpg://honeyforge:postgres_secure_pass_2026@db-store:5432/honeyforge
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./honeyforge.db"
    )
    
    # Security: Ephemeral or configured JWT Secret
    # If unset in environment, generate random secure 32-byte secret with warning
    _env_jwt = os.getenv("JWT_SECRET")
    if not _env_jwt:
        JWT_SECRET: str = secrets.token_urlsafe(32)
        logger.warning("WARNING: JWT_SECRET environment variable is not set! Generated ephemeral random secret.")
    else:
        JWT_SECRET: str = _env_jwt
    JWT_ALGORITHM: str = "HS256"
    
    # 8 hours token lifetime (28800s)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
    
    # Dynamic Operator Credentials (if empty in env, generated at startup and printed to stdout)
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "")
    ANALYST_PASSWORD: str = os.getenv("ANALYST_PASSWORD", "")
    
    # Stealth Telemetry Settings (MASK-1 & MASK-2)
    # Primary neutral RUM / metrics ingestion routes
    MASK_TELEMETRY_ENDPOINT: str = "/cdn-cgi/rum"
    MASK_METRICS_ENDPOINT: str = "/static/v2/metrics"
    MASK_BEACON_GIF_ENDPOINT: str = "/static/pixel.gif"
    MASK_CONFIG_ENDPOINT: str = "/sync/v1/config"
    
    # Pre-shared Master Key for Agent HMAC Auth (MASK-7) from environment
    MASTER_AGENT_KEY: str = os.getenv("MASTER_AGENT_KEY", "")

settings = Settings()
