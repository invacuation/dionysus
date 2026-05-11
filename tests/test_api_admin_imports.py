import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.models import (
    AssetNode,
    AssetNodeType,
    Base,
    ImportAttempt,
    ImportStatus,
    PermissionEffect,
    PrincipalType,
    Project,
)

ADMIN_IMPORTS_URL = "/api/admin/imports"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(
        AppSettings(
            environment=Environment.TEST,
            database_url="sqlite:///:memory:",
        )
    )
    app.state.session_factory = session_factory
    return TestClient(app)


def _create_user(
    session_factory: sessionmaker[Session],
    *,
    username: str = "alice",
    permission: str | None = "import:history:view",
) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username=username,
            display_name=username.title(),
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        if permission is not None:
            assign_permission(
                session,
                principal_type=PrincipalType.USER,
                principal_id=user.id,
                permission=permission,
                effect=PermissionEffect.ALLOW,
                scope_type=None,
                scope_id=None,
            )
        session.commit()
        return user.id


def _login(client: TestClient, *, username: str = "alice") -> None:
    response = client.post(
        "/api/auth/session",
        json={"username": username, "password": "correct horse battery staple"},
    )
    assert response.status_code == 200


def _project_target_and_attempts(session: Session, *, uploader_user_id: str) -> tuple[str, str]:
    project = Project(slug="alpha", name="Alpha")
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name="API Image",
        path="images/api",
        target_ref="registry.example.test/dionysus/api:2026.05",
    )
    session.add_all([project, target])
    session.flush()
    older = datetime(2026, 5, 7, 12, 0, tzinfo=UTC)
    session.add_all(
        [
            ImportAttempt(
                project=project,
                asset_node=target,
                uploader_principal_type="user",
                uploader_principal_id=uploader_user_id,
                status=ImportStatus.SUCCESS,
                parser_name="trivy-image-json",
                sanitized_message="import completed",
                correlation_id="corr-success",
                metadata_json={
                    "raw_report_retained": False,
                    "scanner": "trivy",
                    "finding_count": 2,
                },
                created_at=older,
                updated_at=older,
            ),
            ImportAttempt(
                project=project,
                asset_node=target,
                uploader_principal_type="user",
                uploader_principal_id=uploader_user_id,
                status=ImportStatus.FAILED,
                parser_name="trivy-image-json",
                sanitized_message="Invalid JSON report",
                correlation_id="corr-failed",
                metadata_json={
                    "failure_category": "parser_error",
                    "raw_report_retained": False,
                    "raw_payload": '{"secret":"must-not-leak"}',
                    "report_file": "not-retained.json",
                },
                created_at=older + timedelta(minutes=5),
                updated_at=older + timedelta(minutes=5),
            ),
        ]
    )
    session.commit()
    return project.id, target.id


def test_admin_import_history_requires_import_history_permission_or_admin_wildcard(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        _create_user(session_factory, username="alice", permission=None)
        _create_user(session_factory, username="viewer", permission="import:history:view")
        _create_user(session_factory, username="admin", permission="admin:*")
        anonymous_client = _client_with_session_factory(session_factory)
        forbidden_client = _client_with_session_factory(session_factory)
        _login(forbidden_client)
        viewer_client = _client_with_session_factory(session_factory)
        _login(viewer_client, username="viewer")
        admin_client = _client_with_session_factory(session_factory)
        _login(admin_client, username="admin")

        anonymous_response = anonymous_client.get(ADMIN_IMPORTS_URL)
        forbidden_response = forbidden_client.get(ADMIN_IMPORTS_URL)
        viewer_response = viewer_client.get(ADMIN_IMPORTS_URL)
        admin_response = admin_client.get(ADMIN_IMPORTS_URL)

    assert anonymous_response.status_code == 401
    assert forbidden_response.status_code == 403
    assert viewer_response.status_code == 200
    assert admin_response.status_code == 200


def test_admin_import_history_returns_sanitized_newest_first_attempts(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id = _project_target_and_attempts(
                session,
                uploader_user_id=user_id,
            )
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = client.get(f"{ADMIN_IMPORTS_URL}?limit=500")

    assert response.status_code == 200
    body = response.json()
    assert list(body) == ["attempts"]
    assert [attempt["status"] for attempt in body["attempts"]] == ["failed", "success"]
    failed, success = body["attempts"]
    assert failed == {
        "id": failed["id"],
        "project_id": project_id,
        "project_name": "Alpha",
        "asset_id": target_id,
        "asset_name": "API Image",
        "asset_path": "images/api",
        "uploader_principal_type": "user",
        "uploader_principal_id": user_id,
        "uploader_display": "Alice",
        "status": "failed",
        "parser_name": "trivy-image-json",
        "sanitized_message": "Invalid JSON report",
        "correlation_id": "corr-failed",
        "metadata": {
            "failure_category": "parser_error",
            "raw_report_retained": False,
        },
        "created_at": failed["created_at"],
        "updated_at": failed["updated_at"],
    }
    assert success["metadata"] == {
        "raw_report_retained": False,
        "scanner": "trivy",
        "finding_count": 2,
    }
    serialized = json.dumps(body)
    assert "secret" not in serialized
    assert "raw_payload" not in serialized
    assert "report_file" not in serialized
    assert "must-not-leak" not in serialized
