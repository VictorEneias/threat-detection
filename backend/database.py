import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import text

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://usuario:senha@localhost/dbname",
)

engine = create_async_engine(DATABASE_URL, future=True, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("ALTER TABLE reports ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP"))
        await conn.execute(text("ALTER TABLE reports ADD COLUMN IF NOT EXISTS usuario VARCHAR"))
