from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from dionysus.app import create_app
from dionysus.imports.persistence import import_trivy_report
from dionysus.models import Base
from dionysus.models.inventory import AssetNode, AssetNodeType, Project
from dionysus.overview import get_estate_overview

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def _client_with_frontend_dist(tmp_path: Path) -> TestClient:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text('<div id="root"></div>', encoding="utf-8")
    app = create_app()
    app.state.frontend_dist = frontend_dist
    return TestClient(app)


def test_health_endpoint_returns_ok() -> None:
    client = TestClient(create_app())

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


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


def test_imports_route_serves_react_frontend(tmp_path: Path) -> None:
    client = _client_with_frontend_dist(tmp_path)

    response = client.get("/imports")

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text


def test_admin_route_serves_react_frontend(tmp_path: Path) -> None:
    client = _client_with_frontend_dist(tmp_path)

    response = client.get("/admin")

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text
