"""Synchronous SQLAlchemy session helpers for Celery tasks.

Celery workers run in a synchronous context, so we cannot use the async
SQLAlchemy engine configured for FastAPI.  This module creates a separate
sync engine (psycopg2) that is safe to use inside tasks.
"""
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import settings


def _sync_db_url() -> str:
    """Convert the async asyncpg URL to a sync psycopg2 URL.

    Raises ``ValueError`` if the URL cannot be converted (e.g. a non-asyncpg
    driver is already in use and no safe substitution is possible).
    """
    url = settings.database_url
    if "+asyncpg" in url:
        return url.replace("+asyncpg", "+psycopg2")
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        # Bare postgresql:// URL — inject the psycopg2 driver explicitly.
        return url.replace("postgresql://", "postgresql+psycopg2://", 1).replace(
            "postgres://", "postgresql+psycopg2://", 1
        )
    if "+psycopg2" in url:
        # Already a psycopg2 URL — use as-is.
        return url
    raise ValueError(
        f"Cannot derive a synchronous psycopg2 database URL from: {url!r}. "
        "Set DATABASE_URL to a postgresql+asyncpg:// or postgresql:// URL."
    )


# Module-level engine — created once per worker process.
_engine = create_engine(
    _sync_db_url(),
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)
_SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


@contextmanager
def get_sync_session() -> Generator[Session, None, None]:
    """Yield a synchronous SQLAlchemy session with automatic commit/rollback."""
    session: Session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
