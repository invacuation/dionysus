from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment
from dionysus.identity.bootstrap import ADMIN_PERMISSION
from dionysus.identity.machines import create_machine_credential, exchange_machine_client_secret
from dionysus.identity.permissions import assign_permission
from dionysus.identity.sessions import create_session
from dionysus.identity.users import create_user
from dionysus.inventory.assets import create_scan_target
from dionysus.inventory.projects import create_project
from dionysus.models import AuditLogEvent, Base, User
from dionysus.models.findings import ImportAttempt, ImportStatus, RawFindingInstance, Scan
from dionysus.models.identity import PermissionEffect, PrincipalType
from dionysus.models.inventory import AssetNode, AssetNodeType

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"
SESSION_COOKIE = "dionysus_session"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(
    session_factory: sessionmaker[Session],
    *,
    settings: AppSettings | None = None,
    raise_server_exceptions: bool = True,
) -> TestClient:
    app = create_app(
        settings or AppSettings(environment=Environment.TEST, database_url="sqlite:///:memory:")
    )
    app.state.session_factory = session_factory
    return TestClient(app, raise_server_exceptions=raise_server_exceptions)


def _project_inventory(session: Session) -> tuple[str, str, str]:
    project = create_project(session, slug="alpha", name="Alpha")
    target = create_scan_target(
        session,
        project=project,
        folder_path="images/releases",
        name="Production Image",
        target_ref="registry.example.test/app:2026.05",
    )
    folder = AssetNode(
        project=project,
        node_type=AssetNodeType.FOLDER,
        name="manual",
        path="manual",
    )
    session.add(folder)
    session.flush()
    return project.id, target.id, folder.id


def _create_user(session_factory: sessionmaker[Session]) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username="alice",
            display_name="Alice",
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        session.commit()
        return user.id


def _create_session_cookie(session_factory: sessionmaker[Session], user_id: str) -> str:
    with session_factory() as session:
        raw_token, _session_record = create_session(
            session,
            user=session.get_one(User, user_id),
            now=datetime.now(UTC),
            idle_timeout_minutes=30,
            absolute_timeout_minutes=480,
            user_agent=None,
            ip_address=None,
        )
        session.commit()
        return raw_token


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _create_machine_access_token(session_factory: sessionmaker[Session]) -> tuple[str, str]:
    with session_factory() as session:
        raw_secret, credential = create_machine_credential(session, name="trivy-uploader")
        token_pair = exchange_machine_client_secret(
            session,
            client_id=credential.client_id,
            client_secret=raw_secret,
            now=credential.created_at,
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        assert token_pair is not None
        session.commit()
        return credential.id, token_pair.access_token


def _grant_permission(
    session_factory: sessionmaker[Session],
    *,
    principal_type: PrincipalType,
    principal_id: str,
    permission: str,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    scope_type: str | None = None,
    scope_id: str | None = None,
) -> None:
    with session_factory() as session:
        assign_permission(
            session,
            principal_type=principal_type,
            principal_id=principal_id,
            permission=permission,
            effect=effect,
            scope_type=scope_type,
            scope_id=scope_id,
        )
        session.commit()


def _login(client: TestClient) -> None:
    response = client.post(
        "/api/auth/session",
        json={"username": "alice", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200


def _post_trivy_import(
    client: TestClient,
    *,
    project_id: str,
    target_id: str,
    payload: bytes | None = None,
    scan_started_at: str | None = "2026-05-07T09:30:00+00:00",
    headers: dict[str, str] | None = None,
):
    data = {
        "project_id": project_id,
        "scan_target_id": target_id,
    }
    if scan_started_at is not None:
        data["scan_started_at"] = scan_started_at
    return client.post(
        "/api/imports/trivy",
        data=data,
        files={
            "report_file": (
                "trivy-image.json",
                payload if payload is not None else FIXTURE.read_bytes(),
                "application/json",
            )
        },
        headers=headers,
    )


def _post_trivy_import_to_folder(
    client: TestClient,
    *,
    project_id: str,
    folder_id: str | None = None,
    folder_path: str | None = None,
    asset_name: str | None = "Production Image",
    target_ref: str | None = "registry.example.test/dionysus/api:2026.05.07",
    payload: bytes | None = None,
    headers: dict[str, str] | None = None,
):
    data = {
        "project_id": project_id,
        "scan_started_at": "2026-05-07T09:30:00+00:00",
    }
    if folder_id is not None:
        data["folder_id"] = folder_id
    if folder_path is not None:
        data["folder_path"] = folder_path
    if asset_name is not None:
        data["asset_name"] = asset_name
    if target_ref is not None:
        data["target_ref"] = target_ref
    return client.post(
        "/api/imports/trivy",
        data=data,
        files={
            "report_file": (
                "trivy-image.json",
                payload if payload is not None else FIXTURE.read_bytes(),
                "application/json",
            )
        },
        headers=headers,
    )


def _post_trivy_preview(
    client: TestClient,
    *,
    project_id: str,
    payload: bytes | None = None,
    headers: dict[str, str] | None = None,
):
    return client.post(
        "/api/imports/trivy/preview",
        data={"project_id": project_id},
        files={
            "report_file": (
                "trivy-image.json",
                payload if payload is not None else FIXTURE.read_bytes(),
                "application/json",
            )
        },
        headers=headers,
    )


def test_api_trivy_import_accepts_session_authenticated_upload(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory)
        _login(client)

        response = _post_trivy_import(client, project_id=project_id, target_id=target_id)

        assert response.status_code == 200
        body = response.json()
        assert body == {
            "import_attempt_id": body["import_attempt_id"],
            "scan_id": body["scan_id"],
            "project_id": project_id,
            "scan_target_id": target_id,
            "scanner": "trivy",
            "report_kind": "trivy-image-json",
            "finding_count": 2,
            "group_count": 2,
        }
        with session_factory() as session:
            attempt = session.scalars(select(ImportAttempt)).one()
            scan = session.scalars(select(Scan)).one()
            findings = session.scalars(select(RawFindingInstance)).all()
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "import.trivy.success")
            ).one()
            assert attempt.status == ImportStatus.SUCCESS
            assert attempt.uploader_principal_type == "user"
            assert attempt.uploader_principal_id == user_id
            assert scan.scan_target_id == target_id
            assert scan.scan_started_at is not None
            assert _as_utc(scan.scan_started_at) == datetime(2026, 5, 7, 9, 30, tzinfo=UTC)
            assert len(findings) == 2
            assert event.actor_principal_type == "user"
            assert event.actor_principal_id == user_id
            assert event.project_id == project_id
            assert event.target_type == "scan_target"
            assert event.target_id == target_id
            assert event.metadata_json == {
                "scan_target_id": target_id,
                "finding_count": 2,
                "group_count": 2,
            }


def test_api_trivy_preview_returns_detected_metadata_without_persistence(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_preview(client, project_id=project_id)

        assert response.status_code == 200
        assert response.json() == {
            "scanner": "trivy",
            "report_kind": "trivy-image-json",
            "tool_label": "Trivy (Image)",
            "detected_asset_name": "registry.example.test/dionysus/api:2026.05.07",
            "detected_target_ref": "registry.example.test/dionysus/api:2026.05.07",
            "scan_started_at": "2026-05-07T12:34:56Z",
            "finding_count": 2,
            "group_count": 2,
        }
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []
            assert session.scalars(select(AuditLogEvent)).all() == []


def test_api_trivy_import_uses_report_created_at_when_form_timestamp_absent(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import(
            client,
            project_id=project_id,
            target_id=target_id,
            scan_started_at=None,
        )

        assert response.status_code == 200
        with session_factory() as session:
            scan = session.scalars(select(Scan)).one()
            assert scan.scan_started_at is not None
            assert _as_utc(scan.scan_started_at) == datetime(
                2026,
                5,
                7,
                12,
                34,
                56,
                tzinfo=UTC,
            )


def test_api_trivy_preview_invalid_json_returns_safe_400_without_persistence(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory, raise_server_exceptions=False)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_preview(
            client,
            project_id=project_id,
            payload=b'{"ArtifactName":"secret-registry.example.test/private:latest",',
        )

        assert response.status_code == 400
        assert response.json() == {"detail": "invalid JSON: unable to parse Trivy report"}
        assert "secret-registry" not in response.text
        assert "private:latest" not in response.text
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []
            assert session.scalars(select(AuditLogEvent)).all() == []


def test_api_trivy_preview_oversized_upload_returns_413_without_persistence(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(
            session_factory,
            settings=AppSettings(
                environment=Environment.TEST,
                database_url="sqlite:///:memory:",
                max_report_upload_bytes=8,
            ),
            raise_server_exceptions=False,
        )
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_preview(
            client,
            project_id=project_id,
            payload=b"sensitive-report-payload",
        )

        assert response.status_code == 413
        assert response.text == "Request body too large"
        assert "sensitive-report-payload" not in response.text
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []
            assert session.scalars(select(AuditLogEvent)).all() == []


def test_api_trivy_preview_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project_id, _target_id, _folder_id = _project_inventory(session)
            session.commit()
        client = _client_with_session_factory(session_factory)

        response = _post_trivy_preview(client, project_id=project_id)

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_api_trivy_preview_requires_project_upload_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, _folder_id = _project_inventory(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_preview(client, project_id=project_id)

        assert response.status_code == 403
        assert response.json() == {"detail": "Forbidden"}
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []
            assert session.scalars(select(AuditLogEvent)).all() == []


def test_api_trivy_import_accepts_folder_asset_details_and_reuses_asset(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        first_response = _post_trivy_import_to_folder(
            client,
            project_id=project_id,
            folder_id=folder_id,
            target_ref=None,
        )
        second_response = _post_trivy_import_to_folder(
            client,
            project_id=project_id,
            folder_id=folder_id,
            asset_name="Detected Image Rename Should Not Duplicate",
            target_ref=None,
        )

        assert first_response.status_code == 200
        assert second_response.status_code == 200
        first_body = first_response.json()
        second_body = second_response.json()
        assert second_body["scan_target_id"] == first_body["scan_target_id"]
        with session_factory() as session:
            created_target = session.get_one(AssetNode, first_body["scan_target_id"])
            scans = session.scalars(select(Scan).order_by(Scan.created_at)).all()
            attempts = session.scalars(
                select(ImportAttempt).order_by(ImportAttempt.created_at)
            ).all()
            assert created_target.project_id == project_id
            assert created_target.parent_id == folder_id
            assert created_target.node_type == AssetNodeType.SCAN_TARGET
            assert created_target.name == "Production Image"
            assert created_target.path == "manual/Production Image"
            assert created_target.target_ref == "registry.example.test/dionysus/api:2026.05.07"
            assert [scan.scan_target_id for scan in scans] == [
                created_target.id,
                created_target.id,
            ]
            assert [attempt.asset_node_id for attempt in attempts] == [
                created_target.id,
                created_target.id,
            ]


def test_api_trivy_import_accepts_folder_path_and_creates_missing_folders(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import_to_folder(
            client,
            project_id=project_id,
            folder_path="releases/1.0.0/images",
            asset_name="Ubuntu image",
            target_ref=None,
        )

        assert response.status_code == 200
        with session_factory() as session:
            created_target = session.get_one(AssetNode, response.json()["scan_target_id"])
            created_folder = session.get_one(AssetNode, created_target.parent_id)
            assert created_folder.path == "releases/1.0.0/images"
            assert created_folder.node_type == AssetNodeType.FOLDER
            assert created_target.name == "Ubuntu image"
            assert created_target.path == "releases/1.0.0/images/Ubuntu image"
            assert created_target.target_ref == "registry.example.test/dionysus/api:2026.05.07"


def test_api_trivy_import_accepts_bearer_authenticated_upload(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        machine_id, access_token = _create_machine_access_token(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.MACHINE,
            principal_id=machine_id,
            permission=ADMIN_PERMISSION,
        )
        client = _client_with_session_factory(session_factory)

        response = _post_trivy_import(
            client,
            project_id=project_id,
            target_id=target_id,
            headers={"authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        assert response.json()["finding_count"] == 2
        with session_factory() as session:
            attempt = session.scalars(select(ImportAttempt)).one()
            assert attempt.status == ImportStatus.SUCCESS
            assert attempt.uploader_principal_type == "machine"
            assert attempt.uploader_principal_id == machine_id


def test_api_trivy_import_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        client = _client_with_session_factory(session_factory)

        response = _post_trivy_import(client, project_id=project_id, target_id=target_id)

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_api_trivy_import_invalid_json_returns_safe_400_and_failed_attempt(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory, raise_server_exceptions=False)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import(
            client,
            project_id=project_id,
            target_id=target_id,
            payload=b'{"ArtifactName":"secret-registry.example.test/private:latest",',
        )

        assert response.status_code == 400
        assert response.json() == {"detail": "invalid JSON: unable to parse Trivy report"}
        assert "secret-registry" not in response.text
        assert "private:latest" not in response.text
        with session_factory() as session:
            attempt = session.scalars(select(ImportAttempt)).one()
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "import.trivy.failure")
            ).one()
            assert attempt.status == ImportStatus.FAILED
            assert attempt.asset_node_id == target_id
            assert attempt.metadata_json["failure_category"] == "parser_error"
            assert event.project_id == project_id
            assert event.target_type == "scan_target"
            assert event.target_id == target_id
            assert event.metadata_json == {
                "scan_target_id": target_id,
                "failure_category": "parser_error",
                "detail": "invalid JSON: unable to parse Trivy report",
            }
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []


def test_api_trivy_import_oversized_upload_returns_413_without_attempt(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(
            session_factory,
            settings=AppSettings(
                environment=Environment.TEST,
                database_url="sqlite:///:memory:",
                max_report_upload_bytes=8,
            ),
            raise_server_exceptions=False,
        )
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import(
            client,
            project_id=project_id,
            target_id=target_id,
            payload=b"sensitive-report-payload",
        )

        assert response.status_code == 413
        assert response.text == "Request body too large"
        assert "sensitive-report-payload" not in response.text
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []


def test_api_trivy_import_unknown_project_and_target_return_404(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, _target_id, folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory, raise_server_exceptions=False)
        _login(client)

        unknown_project_response = _post_trivy_import(
            client,
            project_id="00000000-0000-0000-0000-000000000000",
            target_id=folder_id,
        )
        unknown_target_response = _post_trivy_import(
            client,
            project_id=project_id,
            target_id="00000000-0000-0000-0000-000000000000",
        )
        folder_target_response = _post_trivy_import(
            client,
            project_id=project_id,
            target_id=folder_id,
        )

    assert unknown_project_response.status_code == 404
    assert unknown_target_response.status_code == 404
    assert folder_target_response.status_code == 404


def test_api_trivy_import_requires_project_upload_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import(client, project_id=project_id, target_id=target_id)

        assert response.status_code == 403
        assert response.json() == {"detail": "Forbidden"}
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
            assert session.scalars(select(Scan)).all() == []
            assert session.scalars(select(RawFindingInstance)).all() == []


def test_api_trivy_import_admin_wildcard_allows_upload(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission=ADMIN_PERMISSION,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import(client, project_id=project_id, target_id=target_id)

        assert response.status_code == 200
        assert response.json()["finding_count"] == 2


def test_api_trivy_import_explicit_deny_overrides_admin_wildcard(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        user_id = _create_user(session_factory)
        with session_factory() as session:
            project_id, target_id, _folder_id = _project_inventory(session)
            session.commit()
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission=ADMIN_PERMISSION,
        )
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="import:upload",
            effect=PermissionEffect.DENY,
            scope_type="project",
            scope_id=project_id,
        )
        client = _client_with_session_factory(session_factory)
        client.cookies.set(SESSION_COOKIE, _create_session_cookie(session_factory, user_id))

        response = _post_trivy_import(client, project_id=project_id, target_id=target_id)

        assert response.status_code == 403
        assert response.json() == {"detail": "Forbidden"}
        with session_factory() as session:
            assert session.scalars(select(ImportAttempt)).all() == []
