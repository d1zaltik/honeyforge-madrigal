from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from honeyforge_server.app.config import settings

db_url = settings.DATABASE_URL
if "postgresql" in db_url:
    try:
        import asyncpg
    except ImportError:
        db_url = "sqlite+aiosqlite:///./honeyforge.db"

engine = create_async_engine(
    db_url,
    echo=False,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    import honeyforge_server.app.models  # Ensure all SQLAlchemy models are registered on Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Legacy SQLite migrations for schema upgrades
    if "sqlite" in str(engine.url):
        from sqlalchemy import text
        for stmt in [
            "ALTER TABLE alert_rules ADD COLUMN trap_id VARCHAR(64);",
            "ALTER TABLE attack_events ADD COLUMN source_asn VARCHAR(64) DEFAULT 'AS-LOCAL';",
            "ALTER TABLE attack_events ADD COLUMN ingest_latency_seconds FLOAT;",
            "ALTER TABLE profiles ADD COLUMN persona JSON;",
            "ALTER TABLE attack_events ADD COLUMN event_uid VARCHAR(64);",
            "ALTER TABLE attack_events ADD COLUMN session_duration_s FLOAT;"
        ]:
            try:
                async with engine.begin() as conn:
                    await conn.execute(text(stmt))
            except Exception:
                pass
