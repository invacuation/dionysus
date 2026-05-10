"""Database engine and session helpers."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def normalize_database_url(database_url: str) -> str:
    """Return a SQLAlchemy URL with the expected secure driver selected.

    Plain PostgreSQL URLs are upgraded to use the psycopg driver; all other
    database URLs are returned unchanged so callers keep their configured
    connection target.

    Args:
        database_url: The configured SQLAlchemy database URL.

    Returns:
        The normalized database URL.
    """

    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)

    return database_url


def create_engine_from_url(database_url: str) -> Engine:
    """Build a SQLAlchemy engine from a configured database URL.

    Args:
        database_url: The configured SQLAlchemy database URL.

    Returns:
        A SQLAlchemy engine with pre-ping enabled and SQLite thread checks
        disabled for local application use.
    """

    database_url = normalize_database_url(database_url)

    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to the given engine.

    Args:
        engine: The SQLAlchemy engine used for new sessions.

    Returns:
        A sessionmaker configured without autoflush and with non-expiring
        committed instances.
    """

    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """Provide a transactional session that commits or rolls back as a unit.

    Args:
        engine: The SQLAlchemy engine used to create the session.

    Yields:
        A SQLAlchemy session inside a transaction boundary.

    Raises:
        Exception: Re-raises any exception from the managed block after rolling
            back the transaction.
    """

    session_factory = create_session_factory(engine)
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
