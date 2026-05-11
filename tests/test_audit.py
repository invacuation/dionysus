import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.audit import record_audit_event
from dionysus.config import AppSettings, Environment
from dionysus.identity.permissions import assign_permission
from dionysus.identity.sessions import create_session
from dionysus.identity.users import create_user
from dionysus.models import Base
from dionysus.models.identity import PermissionEffect, PrincipalType

SESSION_COOKIE = "dionysus_session"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_app(AppSettings(environment=Environment.TEST, database_url="sqlite:///:memory:"))
    app.state.session_factory = session_factory
    return TestClient(app)


def _create_user_and_session_cookie(session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        assign_permission(
            session,
            principal_type=PrincipalType.USER,
            principal_id=user.id,
            permission="admin:*",
            effect=PermissionEffect.ALLOW,
            scope_type=None,
            scope_id=None,
        )
        raw_token, _session_record = create_session(
            session,
            user=user,
            now=datetime.now(UTC),
            idle_timeout_minutes=30,
            absolute_timeout_minutes=480,
            user_agent=None,
            ip_address=None,
        )
        session.commit()
        return raw_token


def _create_user_with_permission_and_session_cookie(
    session_factory: sessionmaker[Session],
    *,
    permission: str | None,
) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
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
        raw_token, _session_record = create_session(
            session,
            user=user,
            now=datetime.now(UTC),
            idle_timeout_minutes=30,
            absolute_timeout_minutes=480,
            user_agent=None,
            ip_address=None,
        )
        session.commit()
        return raw_token


def test_audit_model_table_has_expected_columns_and_indexes(engine: Engine) -> None:
    Base.metadata.create_all(engine)

    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("audit_log_events")}
    indexes = {
        index["name"]: tuple(index["column_names"])
        for index in inspector.get_indexes("audit_log_events")
    }

    assert columns == {
        "id",
        "event_type",
        "actor_principal_type",
        "actor_principal_id",
        "actor_display",
        "target_type",
        "target_id",
        "project_id",
        "ip_address",
        "user_agent",
        "metadata_json",
        "created_at",
    }
    assert indexes["ix_audit_log_events_event_type"] == ("event_type",)
    assert indexes["ix_audit_log_events_actor"] == (
        "actor_principal_type",
        "actor_principal_id",
    )
    assert indexes["ix_audit_log_events_target"] == ("target_type", "target_id")
    assert indexes["ix_audit_log_events_project_id"] == ("project_id",)
    assert indexes["ix_audit_log_events_created_at"] == ("created_at",)


def test_audit_migration_chains_after_finding_workflow() -> None:
    migration_path = Path(__file__).parents[1] / "migrations" / "versions" / "0008_audit_log.py"
    spec = importlib.util.spec_from_file_location("test_migration_0008_audit_log", migration_path)
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0008_audit_log"
    assert migration.down_revision == "0007_finding_workflow"


def test_peer_review_settings_migration_chains_after_audit_log() -> None:
    migration_path = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0009_peer_review_settings.py"
    )
    spec = importlib.util.spec_from_file_location(
        "test_migration_0009_peer_review_settings",
        migration_path,
    )
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0009_peer_review_settings"
    assert migration.down_revision == "0008_audit_log"


def test_import_attempt_asset_cascade_migration_chains_after_peer_review() -> None:
    migration_path = (
        Path(__file__).parents[1]
        / "migrations"
        / "versions"
        / "0010_import_attempt_asset_cascade.py"
    )
    spec = importlib.util.spec_from_file_location(
        "test_migration_0010_import_attempt_asset_cascade",
        migration_path,
    )
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0010_import_attempt_asset_cascade"
    assert migration.down_revision == "0009_peer_review_settings"


def test_session_timeout_settings_migration_chains_after_asset_cascade() -> None:
    migration_path = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0011_session_timeout_settings.py"
    )
    spec = importlib.util.spec_from_file_location(
        "test_migration_0011_session_timeout_settings",
        migration_path,
    )
    assert spec is not None
    assert spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration.revision == "0011_session_timeout_settings"
    assert migration.down_revision == "0010_import_attempt_asset_cascade"


def test_record_audit_event_redacts_sensitive_metadata(db_session: Session) -> None:
    event = record_audit_event(
        db_session,
        event_type="auth.login.failure",
        actor_principal_type="user",
        actor_principal_id="principal-id",
        metadata={
            "username": "alice",
            "password": "not-stored",
            "nested": {"access_token": "also-not-stored", "safe": "kept"},
            "items": [{"client_secret": "hidden"}, {"detail": "ok"}],
            "stack_trace": "Traceback with implementation detail",
            "raw_report": {"ArtifactName": "private-image"},
        },
    )
    db_session.commit()

    assert event.metadata_json == {
        "username": "alice",
        "password": "[REDACTED]",
        "nested": {"access_token": "[REDACTED]", "safe": "kept"},
        "items": [{"client_secret": "[REDACTED]"}, {"detail": "ok"}],
        "stack_trace": "[REDACTED]",
        "raw_report": "[REDACTED]",
    }


def test_record_audit_event_rejects_blank_event_type(db_session: Session) -> None:
    with pytest.raises(ValueError, match="event_type is required"):
        record_audit_event(db_session, event_type="  ")


def test_audit_api_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        client = _client_with_session_factory(_session_factory_for_connection(connection))

        response = client.get("/api/audit-log")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_audit_api_requires_audit_log_view_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_with_permission_and_session_cookie(
            session_factory,
            permission=None,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get("/api/audit-log")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_audit_api_allows_admin_wildcard_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_with_permission_and_session_cookie(
            session_factory,
            permission="admin:*",
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get("/api/audit-log")

    assert response.status_code == 200


def test_audit_api_allows_direct_audit_log_view_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_with_permission_and_session_cookie(
            session_factory,
            permission="audit_log:view",
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get("/api/audit-log")

    assert response.status_code == 200


def test_audit_api_returns_newest_first_filters_and_clamps_limit(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_and_session_cookie(session_factory)
        base_time = datetime(2026, 5, 8, 12, 0, tzinfo=UTC)
        with session_factory() as session:
            for index in range(205):
                project_id = "project-a" if index % 2 == 0 else "project-b"
                target_type = "finding" if index % 3 == 0 else "import"
                event_type = "finding.status.changed" if index % 5 == 0 else "import.trivy.success"
                record_audit_event(
                    session,
                    event_type=event_type,
                    actor_principal_type="user",
                    actor_principal_id="alice-id",
                    actor_display="Alice",
                    target_type=target_type,
                    target_id=f"target-{index % 4}",
                    project_id=project_id,
                    metadata={"index": index},
                ).created_at = base_time + timedelta(minutes=index)
            session.commit()
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get(
            "/api/audit-log",
            params={
                "event_type": "finding.status.changed",
                "project_id": "project-a",
                "target_type": "finding",
                "target_id": "target-0",
                "limit": 999,
            },
        )

    assert response.status_code == 200
    events = response.json()["events"]
    assert len(events) <= 200
    assert [event["created_at"] for event in events] == sorted(
        [event["created_at"] for event in events],
        reverse=True,
    )
    assert events
    assert all(event["event_type"] == "finding.status.changed" for event in events)
    assert all(event["project_id"] == "project-a" for event in events)
    assert all(event["target_type"] == "finding" for event in events)
    assert all(event["target_id"] == "target-0" for event in events)
    assert events[0]["metadata"]["index"] == 180


def test_audit_api_filters_by_created_time_range_inclusively(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_and_session_cookie(session_factory)
        base_time = datetime(2026, 5, 8, 12, 0, tzinfo=UTC)
        with session_factory() as session:
            for index in range(5):
                record_audit_event(
                    session,
                    event_type="finding.status.changed",
                    actor_principal_type="user",
                    actor_principal_id="alice-id",
                    metadata={"index": index},
                ).created_at = base_time + timedelta(hours=index)
            session.commit()
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get(
            "/api/audit-log",
            params={
                "created_from": "2026-05-08T13:00:00Z",
                "created_to": "2026-05-08T15:00:00",
            },
        )

    assert response.status_code == 200
    events = response.json()["events"]
    assert [event["metadata"]["index"] for event in events] == [3, 2, 1]


@pytest.mark.parametrize(
    ("params", "expected_detail"),
    [
        ({"created_from": "not-a-date"}, "created_from must be a valid ISO datetime."),
        ({"created_to": "2026-99-99T00:00:00Z"}, "created_to must be a valid ISO datetime."),
        (
            {"created_from": "2026-05-09T00:00:00Z", "created_to": "2026-05-08T00:00:00Z"},
            "created_from must be at or before created_to.",
        ),
    ],
)
def test_audit_api_rejects_invalid_created_time_range(
    engine: Engine,
    params: dict[str, str],
    expected_detail: str,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_and_session_cookie(session_factory)
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get("/api/audit-log", params=params)

    assert response.status_code == 400
    assert response.json()["detail"] == expected_detail


def test_audit_api_returns_all_distinct_event_types_and_enriched_id_metadata(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        cookie = _create_user_and_session_cookie(session_factory)
        with session_factory() as session:
            record_audit_event(
                session,
                event_type="import.trivy.success",
                actor_principal_type="machine",
                actor_principal_id="machine-id",
                target_type="import",
                target_id="import-id",
                project_id="project-z",
                metadata={"actor_principal_id": "already-present", "detail": "kept"},
            )
            record_audit_event(
                session,
                event_type="finding.status.changed",
                actor_principal_type="user",
                actor_principal_id="alice-id",
                target_type="finding",
                target_id="finding-id",
                project_id="project-a",
                metadata={},
            )
            record_audit_event(
                session,
                event_type="auth.login.success",
                actor_principal_type="user",
                actor_principal_id="alice-id",
                metadata={},
            )
            session.commit()
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, cookie)

        response = client.get(
            "/api/audit-log",
            params={"event_type": "finding.status.changed"},
        )
        all_events_response = client.get("/api/audit-log")

    assert response.status_code == 200
    assert all_events_response.status_code == 200
    body = response.json()
    assert body["event_types"] == [
        "auth.login.success",
        "finding.status.changed",
        "import.trivy.success",
    ]
    assert len(body["events"]) == 1
    event = body["events"][0]
    assert event["event_type"] == "finding.status.changed"
    assert event["actor_principal_id"] == "alice-id"
    assert event["target_id"] == "finding-id"
    assert event["project_id"] == "project-a"
    assert event["metadata"]["actor_principal_id"] == "alice-id"
    assert event["metadata"]["target_id"] == "finding-id"
    assert event["metadata"]["project_id"] == "project-a"

    all_events = all_events_response.json()["events"]
    import_event = next(
        event for event in all_events if event["event_type"] == "import.trivy.success"
    )
    assert import_event["metadata"]["actor_principal_id"] == "already-present"
    assert import_event["metadata"]["target_id"] == "import-id"
    assert import_event["metadata"]["project_id"] == "project-z"
    assert import_event["metadata"]["detail"] == "kept"
