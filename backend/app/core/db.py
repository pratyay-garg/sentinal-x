"""
Async SQLAlchemy engine + session factory. One engine per process (API and
worker each create their own on startup).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings

engine = create_async_engine(settings.database_url, pool_pre_ping=True, pool_size=10)
SessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


async def get_session_dep() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency form of get_session."""
    async with SessionLocal() as session:
        yield session
