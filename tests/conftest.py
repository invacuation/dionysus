from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from fastapi import FastAPI
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.db import create_engine_from_url
from dionysus.models import Base

BOOTSTRAP_PASSWORD = "change-me-now-please"  # noqa: S105 - test fixture password


def make_prepared_app_settings(
    tmp_path: Path,
    *,
    database_name: str = "app.db",
    **overrides: Any,
) -> AppSettings:
    database_url = f"sqlite:///{tmp_path / database_name}"
    engine = create_engine_from_url(database_url)
    Base.metadata.create_all(engine)
    engine.dispose()

    settings: dict[str, Any] = {
        "environment": Environment.TEST,
        "database_url": database_url,
        "bootstrap_admin_username": "admin",
        "bootstrap_admin_password": BOOTSTRAP_PASSWORD,
    }
    settings.update(overrides)
    return AppSettings(**settings)


def create_prepared_test_app(**overrides: Any) -> FastAPI:
    tmp_dir = TemporaryDirectory()
    app = create_app(make_prepared_app_settings(Path(tmp_dir.name), **overrides))
    app.state.bootstrap_database_tmp_dir = tmp_dir
    return app


@pytest.fixture
def prepared_app_settings(tmp_path: Path) -> AppSettings:
    return make_prepared_app_settings(tmp_path)


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
