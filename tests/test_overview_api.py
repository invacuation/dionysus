from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from conftest import create_prepared_test_app
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.imports.persistence import import_trivy_report
from dionysus.models import Base
from dionysus.models.identity import PermissionEffect, PrincipalType
from dionysus.models.inventory import AssetNode, AssetNodeType, Project

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_prepared_test_app()
    app.state.session_factory = session_factory
    return TestClient(app)


def _login_user(client: TestClient, session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        session.commit()
        user_id = user.id

    response = client.post(
        "/api/auth/session",
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return user_id


def _grant_permission(
    session_factory: sessionmaker[Session],
    *,
    user_id: str,
    permission: str,
) -> None:
    with session_factory() as session:
        assign_permission(
            session,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission=permission,
            effect=PermissionEffect.ALLOW,
            scope_type=None,
            scope_id=None,
        )
        session.commit()


def test_overview_openapi_uses_stable_response_schema() -> None:
    app = create_prepared_test_app()
    client = TestClient(app)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    openapi = response.json()
    overview_response_schema = openapi["paths"]["/api/overview"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    assert overview_response_schema == {"$ref": "#/components/schemas/OverviewResponse"}

    schemas = openapi["components"]["schemas"]
    overview_schema = schemas["OverviewResponse"]
    overview_properties = overview_schema["properties"]
    assert set(overview_properties) == {
        "open_findings",
        "overdue_sla",
        "grace_period_risk",
        "severity_counts",
        "highest_risk_projects",
    }
    assert overview_schema["required"] == [
        "open_findings",
        "overdue_sla",
        "grace_period_risk",
        "severity_counts",
        "highest_risk_projects",
    ]
    assert overview_properties["severity_counts"]["items"] == {
        "$ref": "#/components/schemas/SeverityCount"
    }
    assert overview_properties["highest_risk_projects"]["items"] == {
        "$ref": "#/components/schemas/ProjectRiskSummary"
    }
    assert set(schemas["SeverityCount"]["properties"]) == {"severity", "count"}
    assert set(schemas["ProjectRiskSummary"]["properties"]) == {
        "project_id",
        "project_name",
        "open_count",
        "overdue_count",
    }


def test_overview_api_returns_estate_summary(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = Project(slug="alpha", name="Alpha")
            target = AssetNode(
                project=project,
                node_type=AssetNodeType.SCAN_TARGET,
                name="api",
                path="images/api",
                target_ref="registry.example.test/alpha/api:2026.05",
            )
            session.add_all([project, target])
            session.flush()
            import_trivy_report(
                session,
                project=project,
                scan_target=target,
                payload=FIXTURE.read_bytes(),
                now=datetime(2026, 5, 7, 10, 0, tzinfo=UTC),
            )
            session.commit()

        app = create_prepared_test_app()
        app.state.session_factory = session_factory
        client = TestClient(app)
        user_id = _login_user(client, session_factory)
        _grant_permission(session_factory, user_id=user_id, permission="report:view")

        response = client.get("/api/overview")

    assert response.status_code == 200
    assert response.json() == {
        "open_findings": 2,
        "overdue_sla": 0,
        "grace_period_risk": 0,
        "severity_counts": [
            {"severity": "Critical", "count": 1},
            {"severity": "Medium", "count": 1},
        ],
        "highest_risk_projects": [
            {
                "project_id": response.json()["highest_risk_projects"][0]["project_id"],
                "project_name": "Alpha",
                "open_count": 2,
                "overdue_count": 0,
            }
        ],
    }


def test_overview_api_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        client = _client_with_session_factory(_session_factory_for_connection(connection))

        response = client.get("/api/overview")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_overview_api_requires_report_view_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get("/api/overview")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
