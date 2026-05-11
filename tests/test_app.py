from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.bootstrap import BootstrapAdminError
from dionysus.identity.users import authenticate_user
from dionysus.imports.persistence import import_trivy_report
from dionysus.models import Base
from dionysus.models.inventory import AssetNode, AssetNodeType, Project
from dionysus.overview import get_estate_overview

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"
BOOTSTRAP_PASSWORD = "change-me-now-please"  # noqa: S105 - test fixture password


def _client_with_frontend_dist(tmp_path: Path, settings: AppSettings) -> TestClient:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text('<div id="root"></div>', encoding="utf-8")
    app = create_app(settings)
    app.state.frontend_dist = frontend_dist
    return TestClient(app)


def test_health_endpoint_returns_ok(prepared_app_settings: AppSettings) -> None:
    client = TestClient(create_app(prepared_app_settings))

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_app_bootstraps_admin_from_settings(prepared_app_settings: AppSettings) -> None:
    app = create_app(prepared_app_settings)

    with app.state.session_factory() as session:
        user = authenticate_user(session, "admin", BOOTSTRAP_PASSWORD)

    assert user is not None
    assert user.username == "admin"


def test_create_app_requires_bootstrap_username_and_password(
    prepared_app_settings: AppSettings,
) -> None:
    settings = prepared_app_settings.model_copy(
        update={"bootstrap_admin_username": None, "bootstrap_admin_password": None}
    )

    with pytest.raises(BootstrapAdminError) as exc_info:
        create_app(settings)

    assert "username and password are required" in str(exc_info.value)


def test_create_app_reports_schema_not_ready_when_bootstrap_schema_is_missing() -> None:
    settings = AppSettings(
        environment=Environment.TEST,
        database_url="sqlite:///:memory:",
        bootstrap_admin_username="admin",
        bootstrap_admin_password=BOOTSTRAP_PASSWORD,
    )

    with pytest.raises(BootstrapAdminError) as exc_info:
        create_app(settings)

    assert str(exc_info.value) == (
        "startup bootstrap failed: database schema is not up to date; "
        "run migrations and retry"
    )


def test_estate_overview_excludes_sla_reporting_opt_out_from_sla_counts(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)
        with session_factory() as session:
            project = Project(
                slug="opted-out",
                name="Opted Out",
                sla_reporting_enabled=False,
                grace_period_enabled=True,
                grace_period_percent=100,
                critical_sla_days=1,
                medium_sla_days=1,
            )
            target = AssetNode(
                project=project,
                node_type=AssetNodeType.SCAN_TARGET,
                name="api",
                path="images/api",
                target_ref="registry.example.test/opted-out/api:2026.05",
            )
            session.add_all([project, target])
            session.flush()
            import_trivy_report(
                session,
                project=project,
                scan_target=target,
                payload=FIXTURE.read_bytes(),
                now=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            )
            session.commit()

            overview = get_estate_overview(
                session,
                now=datetime(2026, 5, 7, 10, 0, tzinfo=UTC),
            )

    assert overview.open_findings == 2
    assert overview.overdue_sla == 0
    assert overview.grace_period_risk == 0
    assert overview.highest_risk_projects[0].project_name == "Opted Out"
    assert overview.highest_risk_projects[0].open_count == 2
    assert overview.highest_risk_projects[0].overdue_count == 0


def test_imports_route_serves_react_frontend(
    tmp_path: Path,
    prepared_app_settings: AppSettings,
) -> None:
    client = _client_with_frontend_dist(tmp_path, prepared_app_settings)

    response = client.get("/imports")

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text


def test_admin_route_serves_react_frontend(
    tmp_path: Path,
    prepared_app_settings: AppSettings,
) -> None:
    client = _client_with_frontend_dist(tmp_path, prepared_app_settings)

    response = client.get("/admin")

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text
