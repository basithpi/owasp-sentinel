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
    """Convert the async asyncpg URL to a sync psycopg2 URL."""
    url = settings.database_url
    return url.replace("+asyncpg", "+psycopg2")


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
