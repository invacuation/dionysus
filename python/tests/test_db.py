import contextlib
import importlib.util
import sys
import types
from pathlib import Path

import pytest
from alembic import context as alembic_context
from sqlalchemy import text

from dionysus.db import create_engine_from_url, normalize_database_url, session_scope


def test_normalize_plain_postgresql_url_uses_psycopg_driver() -> None:
    database_url = normalize_database_url("postgresql://user:pass@example.test:5432/dionysus")

    assert database_url == "postgresql+psycopg://user:pass@example.test:5432/dionysus"


def test_normalize_psycopg_postgresql_url_keeps_driver() -> None:
    database_url = normalize_database_url(
        "postgresql+psycopg://user:pass@example.test:5432/dionysus"
    )

    assert database_url == "postgresql+psycopg://user:pass@example.test:5432/dionysus"


def test_alembic_get_database_url_normalizes_plain_postgresql_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DIONYSUS_DATABASE_URL",
        "postgresql://user:pass@example.test:5432/dionysus",
    )

    config = types.SimpleNamespace(config_file_name=None)
    monkeypatch.setattr(alembic_context, "config", config, raising=False)
    monkeypatch.setattr(alembic_context, "is_offline_mode", lambda: True, raising=False)
    monkeypatch.setattr(alembic_context, "configure", lambda **_kwargs: None, raising=False)
    monkeypatch.setattr(alembic_context, "begin_transaction", contextlib.nullcontext, raising=False)
    monkeypatch.setattr(alembic_context, "run_migrations", lambda: None, raising=False)
    module_path = Path(__file__).parents[1] / "migrations" / "env.py"
    spec = importlib.util.spec_from_file_location("test_migrations_env", module_path)
    assert spec is not None
    assert spec.loader is not None

    migration_env = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "test_migrations_env", migration_env)
    spec.loader.exec_module(migration_env)

    assert (
        migration_env.get_database_url()
        == "postgresql+psycopg://user:pass@example.test:5432/dionysus"
    )


def test_create_engine_from_sqlite_url_connects() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")

    with engine.connect() as connection:
        result = connection.execute(text("select 1")).scalar_one()

    assert result == 1


def test_create_engine_from_plain_postgresql_url_uses_psycopg_driver() -> None:
    engine = create_engine_from_url("postgresql://user:pass@example.test:5432/dionysus")

    assert engine.url.drivername == "postgresql+psycopg"


def test_create_engine_from_psycopg_postgresql_url_keeps_driver() -> None:
    engine = create_engine_from_url("postgresql+psycopg://user:pass@example.test:5432/dionysus")

    assert engine.url.drivername == "postgresql+psycopg"


def test_session_scope_commits() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")

    with engine.begin() as connection:
        connection.execute(text("create table items (id integer primary key)"))

    with session_scope(engine) as session:
        session.execute(text("insert into items (id) values (1)"))

    with engine.connect() as connection:
        result = connection.execute(text("select count(*) from items")).scalar_one()

    assert result == 1


def test_session_scope_rolls_back_on_exception() -> None:
    engine = create_engine_from_url("sqlite:///:memory:")

    with engine.begin() as connection:
        connection.execute(text("create table items (id integer primary key)"))

    with pytest.raises(RuntimeError, match="rollback"), session_scope(engine) as session:
        session.execute(text("insert into items (id) values (1)"))
        raise RuntimeError("rollback")

    with engine.connect() as connection:
        result = connection.execute(text("select count(*) from items")).scalar_one()

    assert result == 0
