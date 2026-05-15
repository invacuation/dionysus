from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import Connection, Engine, select
from sqlalchemy.orm import Session, sessionmaker

from conftest import create_prepared_test_app
from dionysus.identity.bootstrap import ADMIN_PERMISSION
from dionysus.identity.machines import create_machine_credential, exchange_machine_client_secret
from dionysus.identity.permissions import assign_permission
from dionysus.identity.users import create_user
from dionysus.imports.persistence import import_trivy_report
from dionysus.models import AuditLogEvent, Base
from dionysus.models.findings import (
    FindingStatus,
    FindingStatusChangeRequest,
    FindingStatusChangeState,
    RawFindingInstance,
)
from dionysus.models.identity import PermissionEffect, PrincipalType
from dionysus.models.inventory import AssetNode, AssetNodeType, Project
from dionysus.security.settings import get_security_settings

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-image.json"


def _session_factory_for_connection(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)


def _client_with_session_factory(session_factory: sessionmaker[Session]) -> TestClient:
    app = create_prepared_test_app()
    app.state.session_factory = session_factory
    return TestClient(app)


def _login_user(
    client: TestClient,
    session_factory: sessionmaker[Session],
    *,
    username: str = "alice",
    display_name: str = "Alice",
    grant_admin: bool = True,
) -> str:
    with session_factory() as session:
        user = create_user(
            session,
            username=username,
            display_name=display_name,
            password="correct horse battery staple",  # noqa: S106 - test fixture password
        )
        if grant_admin:
            assign_permission(
                session,
                principal_type=PrincipalType.USER,
                principal_id=user.id,
                permission=ADMIN_PERMISSION,
                effect=PermissionEffect.ALLOW,
                scope_type=None,
                scope_id=None,
            )
        session.commit()
        user_id = user.id

    response = client.post(
        "/api/auth/session",
        json={"username": username, "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return user_id


def _create_machine_access_token(session_factory: sessionmaker[Session]) -> str:
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
        return token_pair.access_token


def _project_and_target(
    session: Session,
    *,
    slug: str,
    target_name: str,
) -> tuple[Project, AssetNode]:
    project = Project(
        slug=slug,
        name=slug.title(),
        grace_period_enabled=True,
        grace_period_percent=50,
    )
    target = AssetNode(
        project=project,
        node_type=AssetNodeType.SCAN_TARGET,
        name=target_name,
        path=f"images/{target_name}",
        target_ref=f"registry.example.test/dionysus/{target_name}:2026.05.07",
    )
    session.add_all([project, target])
    session.flush()
    return project, target


def _import_two_projects(session: Session) -> tuple[Project, AssetNode, Project, AssetNode]:
    alpha, alpha_target = _project_and_target(session, slug="alpha", target_name="api")
    beta, beta_target = _project_and_target(session, slug="beta", target_name="worker")
    import_trivy_report(
        session,
        project=alpha,
        scan_target=alpha_target,
        payload=FIXTURE.read_bytes(),
        now=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
    )
    import_trivy_report(
        session,
        project=beta,
        scan_target=beta_target,
        payload=FIXTURE.read_bytes(),
        now=datetime(2026, 5, 3, 10, 0, tzinfo=UTC),
    )
    fixed = session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == beta.id,
            RawFindingInstance.package_name == "requests",
        )
    ).one()
    fixed.status = FindingStatus.FIXED
    absent = session.scalars(
        select(RawFindingInstance).where(
            RawFindingInstance.project_id == alpha.id,
            RawFindingInstance.package_name == "requests",
        )
    ).one()
    absent.present_in_latest_scan = False
    session.flush()
    return alpha, alpha_target, beta, beta_target


def _prepared_client(
    connection: Connection,
) -> tuple[TestClient, sessionmaker[Session], Project, AssetNode, Project, AssetNode]:
    Base.metadata.create_all(connection)
    session_factory = _session_factory_for_connection(connection)
    with session_factory() as session:
        alpha, alpha_target, beta, beta_target = _import_two_projects(session)
        session.commit()
    client = _client_with_session_factory(session_factory)
    _login_user(client, session_factory)
    return (
        client,
        session_factory,
        alpha,
        alpha_target,
        beta,
        beta_target,
    )


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


def _alpha_openssl_finding_id(session_factory: sessionmaker[Session], project_id: str) -> str:
    with session_factory() as session:
        return session.scalars(
            select(RawFindingInstance.id).where(
                RawFindingInstance.project_id == project_id,
                RawFindingInstance.package_name == "openssl",
            )
        ).one()


def test_findings_api_list_empty_returns_rows_array(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        access_token = _create_machine_access_token(session_factory)

        response = client.get(
            "/api/findings",
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 200
    assert response.json() == {"rows": []}


def test_findings_api_list_returns_imported_trivy_rows(engine: Engine) -> None:
    with engine.connect() as connection:
        client, _session_factory, alpha, alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )

        response = client.get(f"/api/findings?project_id={alpha.id}&sort=package&direction=asc")

    assert response.status_code == 200
    rows = response.json()["rows"]
    assert len(rows) == 2
    row = rows[0]
    assert row["project_id"] == alpha.id
    assert row["project_name"] == "Alpha"
    assert row["scan_target_id"] == alpha_target.id
    assert row["scan_target_name"] == "api"
    assert row["scan_target_path"] == "images/api"
    assert row["scan_target_ref"] == "registry.example.test/dionysus/api:2026.05.07"
    assert row["scanner"] == "trivy"
    assert row["primary_identifier"] == "CVE-2026-1001"
    assert row["additional_identifiers"] == ["CWE-787", "DSA-2026-001", "CWE-120"]
    assert row["package_name"] == "openssl"
    assert row["installed_version"] == "3.0.11-1"
    assert row["fixed_version"] == "3.0.13-1"
    assert row["severity"] == "CRITICAL"
    assert row["cvss"]["nvd"]["v3"]["score"] == 9.1
    assert row["status"] == "open"
    assert row["first_detected_at"] == "2026-05-01T10:00:00Z"
    assert row["last_seen_at"] == "2026-05-01T10:00:00Z"
    assert row["present_in_latest_scan"] is True
    assert isinstance(row["sla_remaining_days"], int)
    assert isinstance(row["grace_remaining_days"], int)
    assert row["sla_status"] == "active"
    assert row["sla_active"] is True


def test_findings_api_list_filters_inaccessible_project_rows(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory, grant_admin=False)
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="finding:view",
            scope_type="project",
            scope_id=alpha.id,
        )

        response = client.get("/api/findings")

    assert response.status_code == 200
    rows = response.json()["rows"]
    assert len(rows) == 2
    assert {row["project_id"] for row in rows} == {alpha.id}


def test_findings_api_list_filters_and_sorts(engine: Engine) -> None:
    with engine.connect() as connection:
        client, _session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )

        response = client.get(
            "/api/findings"
            f"?project_id={alpha.id}"
            "&identifier=CWE-601"
            "&present_in_latest_scan=false"
            "&sort=identifier"
            "&direction=asc"
        )

    assert response.status_code == 200
    rows = response.json()["rows"]
    assert [row["primary_identifier"] for row in rows] == ["CVE-2026-2002"]
    assert rows[0]["package_name"] == "requests"
    assert rows[0]["present_in_latest_scan"] is False


def test_findings_api_list_filters_by_folder_asset(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            project = Project(slug="alpha", name="Alpha")
            folder = AssetNode(
                project=project,
                node_type=AssetNodeType.FOLDER,
                name="Images",
                path="images",
            )
            api_target = AssetNode(
                project=project,
                parent=folder,
                node_type=AssetNodeType.SCAN_TARGET,
                name="api",
                path="images/api",
                target_ref="registry.example.test/dionysus/api:2026.05.07",
            )
            worker_target = AssetNode(
                project=project,
                parent=folder,
                node_type=AssetNodeType.SCAN_TARGET,
                name="worker",
                path="images/worker",
                target_ref="registry.example.test/dionysus/worker:2026.05.07",
            )
            sibling_target = AssetNode(
                project=project,
                node_type=AssetNodeType.SCAN_TARGET,
                name="docs",
                path="docs",
                target_ref="registry.example.test/dionysus/docs:2026.05.07",
            )
            session.add(project)
            session.flush()
            for target in [api_target, worker_target, sibling_target]:
                import_trivy_report(
                    session,
                    project=project,
                    scan_target=target,
                    payload=FIXTURE.read_bytes(),
                    now=datetime(2026, 5, 1, 10, 0, tzinfo=UTC),
                )
            session.commit()
            folder_id = folder.id
            expected_target_ids = {api_target.id, worker_target.id}
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get(f"/api/findings?asset_id={folder_id}&sort=package&direction=asc")

    assert response.status_code == 200
    rows = response.json()["rows"]
    assert len(rows) == 4
    assert {row["scan_target_id"] for row in rows} == expected_target_ids


def test_findings_api_list_supports_table_column_sorts(engine: Engine) -> None:
    with engine.connect() as connection:
        client, _session_factory, _alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )

        installed = client.get("/api/findings?sort=installed_version&direction=asc")
        fixed = client.get("/api/findings?sort=fixed_version&direction=asc")
        project = client.get("/api/findings?sort=project&direction=desc")
        status = client.get("/api/findings?sort=status&direction=asc")
        grace = client.get("/api/findings?sort=grace_remaining&direction=asc")

    assert installed.status_code == 200
    assert installed.json()["rows"]

    assert fixed.status_code == 200
    assert fixed.json()["rows"][0]["fixed_version"] is not None

    assert project.status_code == 200
    assert project.json()["rows"][0]["project_name"] == "Beta"

    assert status.status_code == 200
    assert status.json()["rows"][0]["status"] == "fixed"

    assert grace.status_code == 200
    assert grace.json()["rows"]


def test_findings_api_list_filters_by_fix_availability(engine: Engine) -> None:
    with engine.connect() as connection:
        client, _session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )

        fix_available = client.get(f"/api/findings?project_id={alpha.id}&fix_available=true")
        no_fix_available = client.get(f"/api/findings?project_id={alpha.id}&fix_available=false")

    assert fix_available.status_code == 200
    assert fix_available.json()["rows"]
    assert all(row["fixed_version"] for row in fix_available.json()["rows"])

    assert no_fix_available.status_code == 200
    assert all(row["fixed_version"] is None for row in no_fix_available.json()["rows"])


def test_findings_api_list_rejects_invalid_status(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get("/api/findings?status=triaged")

    assert response.status_code == 400
    assert response.json() == {"detail": "Unsupported finding status"}


def test_findings_api_list_rejects_invalid_sort_and_direction(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        invalid_sort = client.get("/api/findings?sort=created_at")
        invalid_direction = client.get("/api/findings?direction=sideways")

    assert invalid_sort.status_code == 400
    assert invalid_sort.json() == {"detail": "Unsupported finding sort"}
    assert invalid_direction.status_code == 400
    assert invalid_direction.json() == {"detail": "Unsupported finding sort direction"}


def test_findings_api_list_rejects_invalid_fix_available_filter(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get("/api/findings?fix_available=maybe")

    assert response.status_code == 400
    assert response.json() == {"detail": "fix_available must be true or false"}


def test_findings_api_detail_returns_joined_evidence(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        response = client.get(f"/api/findings/{finding_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == finding_id
    assert body["project_name"] == "Alpha"
    assert body["scan_target_path"] == "images/api"
    assert body["primary_identifier"] == "CVE-2026-1001"
    assert body["additional_identifiers"] == ["CWE-787", "DSA-2026-001", "CWE-120"]
    assert body["scanner_finding_id"] == "CVE-2026-1001:openssl:3.0.11-1"
    assert body["dedupe_key"].endswith("|CVE-2026-1001")
    assert body["identifiers"] == ["CVE-2026-1001", "CWE-787", "DSA-2026-001", "CWE-120"]
    assert body["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
        "https://security-tracker.debian.org/tracker/CVE-2026-1001",
        "https://example.test/advisories/CVE-2026-1001",
    ]
    assert body["description"] == "A representative OpenSSL vulnerability."
    assert body["source_evidence"]["result_class"] == "os-pkgs"
    assert body["cvss"]["nvd"]["v3"]["score"] == 9.1
    assert body["project_group"] == {
        "id": body["project_group"]["id"],
        "primary_identifier": "CVE-2026-1001",
        "additional_identifiers": ["CWE-787", "DSA-2026-001", "CWE-120"],
        "status": "open",
        "first_detected_at": "2026-05-01T10:00:00Z",
    }
    assert body["comments"] == []
    assert body["status_change_requests"] == []


def test_findings_api_detail_requires_project_view_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory, grant_admin=False)

        response = client.get(f"/api/findings/{finding_id}")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_findings_api_add_comment_appears_in_detail(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        create_response = client.post(
            f"/api/findings/{finding_id}/comments",
            json={"body": "  Needs owner validation.  "},
        )
        detail_response = client.get(f"/api/findings/{finding_id}")
        with session_factory() as session:
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "finding.comment.created")
            ).one()

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["body"] == "Needs owner validation."
    assert created["author_principal_type"] == "user"
    assert created["author_display"] == "Alice"
    assert created["is_system"] is False
    assert created["status_from"] is None
    assert created["status_to"] is None

    assert detail_response.status_code == 200
    comments = detail_response.json()["comments"]
    assert len(comments) == 1
    assert comments[0]["id"] == created["id"]
    assert comments[0]["body"] == "Needs owner validation."
    assert comments[0]["author_display"] == "Alice"
    assert event.project_id == alpha.id
    assert event.target_type == "finding"
    assert event.target_id == finding_id
    assert event.metadata_json == {"comment_id": created["id"]}


def test_findings_api_add_comment_requires_project_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory, grant_admin=False)
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)

        response = client.post(
            f"/api/findings/{finding_id}/comments",
            json={"body": "Needs owner validation."},
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_findings_api_add_comment_allows_project_scoped_grant(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory, grant_admin=False)
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="finding:comment",
            scope_type="project",
            scope_id=alpha.id,
        )
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)

        response = client.post(
            f"/api/findings/{finding_id}/comments",
            json={"body": "Needs owner validation."},
        )

    assert response.status_code == 201
    assert response.json()["body"] == "Needs owner validation."


def test_findings_api_add_blank_comment_returns_400(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        response = client.post(f"/api/findings/{finding_id}/comments", json={"body": "  "})

    assert response.status_code == 400
    assert response.json() == {"detail": "Comment body is required"}


def test_findings_api_change_status_requires_comment_for_non_open(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={"status": "fixed", "comment": ""},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Status change comment is required"}


def test_findings_api_change_status_updates_detail_and_activity(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={"status": "fixed", "comment": "Patched in image 2026.05.08."},
        )
        with session_factory() as session:
            finding = session.get(RawFindingInstance, finding_id)
            assert finding is not None
            assert finding.status == FindingStatus.FIXED
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "finding.status.changed")
            ).one()

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fixed"
    assert body["project_group"]["status"] == "fixed"
    assert body["comments"][0]["body"] == "Patched in image 2026.05.08."
    assert body["comments"][0]["author_display"] == "Alice"
    assert body["comments"][0]["status_from"] == "open"
    assert body["comments"][0]["status_to"] == "fixed"
    assert body["status_change_requests"][0]["state"] == "approved"
    assert body["status_change_requests"][0]["requester_display"] == "Alice"
    assert body["status_change_requests"][0]["reviewer_display"] is None
    assert event.project_id == alpha.id
    assert event.target_type == "finding"
    assert event.target_id == finding_id
    assert event.metadata_json == {
        "request_id": body["status_change_requests"][0]["id"],
        "comment_id": body["comments"][0]["id"],
        "from_status": "open",
        "to_status": "fixed",
    }


def test_findings_api_change_status_requires_project_permission(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory, grant_admin=False)
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={"status": "fixed", "comment": "Patched in image 2026.05.08."},
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_findings_api_change_status_allows_project_scoped_grant(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        user_id = _login_user(client, session_factory, grant_admin=False)
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            permission="finding:status_change:request",
            scope_type="project",
            scope_id=alpha.id,
        )
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={"status": "fixed", "comment": "Patched in image 2026.05.08."},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "fixed"


def test_findings_api_peer_review_status_request_does_not_update_status(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        with session_factory() as session:
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "finding.status.requested")
            ).one()

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "open"
    assert body["project_group"]["status"] == "open"
    assert body["comments"][0]["status_from"] == "open"
    assert body["comments"][0]["status_to"] == "fixed"
    assert body["comments"][0]["author_display"] == "Alice"
    assert body["status_change_requests"][0]["state"] == "pending"
    assert body["status_change_requests"][0]["requester_display"] == "Alice"
    assert body["status_change_requests"][0]["reviewer_display"] is None
    assert event.project_id == alpha.id
    assert event.target_type == "finding"
    assert event.target_id == finding_id
    assert event.metadata_json == {
        "request_id": body["status_change_requests"][0]["id"],
        "comment_id": body["comments"][0]["id"],
        "from_status": "open",
        "to_status": "fixed",
    }


def test_findings_api_global_peer_review_setting_forces_status_request(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            settings = get_security_settings(session)
            settings.force_peer_review_for_status_changes = True
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()
            session.commit()

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Global policy requires review.",
                "require_peer_review": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "open"
    assert body["project_group"]["status"] == "open"
    assert body["status_change_requests"][0]["state"] == "pending"


def test_findings_api_project_peer_review_setting_forces_status_request(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            project = session.get(Project, alpha.id)
            assert project is not None
            project.require_peer_review_for_status_changes = True
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()
            session.commit()

        response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Project policy requires review.",
                "require_peer_review": False,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "open"
    assert body["project_group"]["status"] == "open"
    assert body["status_change_requests"][0]["state"] == "pending"


def test_findings_api_approve_status_request_updates_detail_and_audit(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        create_response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]
        client.post("/api/auth/logout")
        _login_user(client, session_factory, username="bob", display_name="Bob")

        response = client.post(
            f"/api/findings/{finding_id}/status-requests/{request_id}/approve",
            json={"comment": "Looks good."},
        )
        with session_factory() as session:
            finding = session.get(RawFindingInstance, finding_id)
            assert finding is not None
            assert finding.status == FindingStatus.FIXED
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "finding.status.approved")
            ).one()

    assert response.status_code == 200
    body = response.json()
    status_request = body["status_change_requests"][0]
    assert body["status"] == "fixed"
    assert body["project_group"]["status"] == "fixed"
    assert status_request["state"] == "approved"
    assert status_request["requester_display"] == "Alice"
    assert status_request["reviewer_display"] == "Bob"
    assert status_request["decision_comment"] == "Looks good."
    assert status_request["decided_at"] is not None
    assert event.project_id == alpha.id
    assert event.target_type == "finding"
    assert event.target_id == finding_id
    assert event.metadata_json == {
        "request_id": request_id,
        "from_status": "open",
        "to_status": "fixed",
    }


def test_findings_api_approve_status_request_requires_project_permission(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        requester_id = _login_user(client, session_factory, grant_admin=False)
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=requester_id,
            permission="finding:status_change:request",
            scope_type="project",
            scope_id=alpha.id,
        )
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)
        create_response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]
        client.post("/api/auth/logout")
        _login_user(client, session_factory, username="bob", display_name="Bob", grant_admin=False)

        response = client.post(
            f"/api/findings/{finding_id}/status-requests/{request_id}/approve",
            json={"comment": "Looks good."},
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_findings_api_approve_status_request_allows_project_scoped_grant(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        requester_id = _login_user(client, session_factory, grant_admin=False)
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=requester_id,
            permission="finding:status_change:request",
            scope_type="project",
            scope_id=alpha.id,
        )
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)
        create_response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]
        client.post("/api/auth/logout")
        reviewer_id = _login_user(
            client,
            session_factory,
            username="bob",
            display_name="Bob",
            grant_admin=False,
        )
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=reviewer_id,
            permission="finding:status_change:approve",
            scope_type="project",
            scope_id=alpha.id,
        )

        response = client.post(
            f"/api/findings/{finding_id}/status-requests/{request_id}/approve",
            json={"comment": "Looks good."},
        )

    assert response.status_code == 200
    assert response.json()["status_change_requests"][0]["state"] == "approved"


def test_findings_api_reject_status_request_leaves_status_and_audits(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        create_response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]
        client.post("/api/auth/logout")
        _login_user(client, session_factory, username="bob", display_name="Bob")

        response = client.post(
            f"/api/findings/{finding_id}/status-requests/{request_id}/reject",
            json={"comment": "Patch evidence is incomplete."},
        )
        with session_factory() as session:
            finding = session.get(RawFindingInstance, finding_id)
            assert finding is not None
            assert finding.status == FindingStatus.OPEN
            event = session.scalars(
                select(AuditLogEvent).where(AuditLogEvent.event_type == "finding.status.rejected")
            ).one()

    assert response.status_code == 200
    body = response.json()
    status_request = body["status_change_requests"][0]
    assert body["status"] == "open"
    assert body["project_group"]["status"] == "open"
    assert status_request["state"] == "rejected"
    assert status_request["requester_display"] == "Alice"
    assert status_request["reviewer_display"] == "Bob"
    assert status_request["decision_comment"] == "Patch evidence is incomplete."
    assert event.project_id == alpha.id
    assert event.target_type == "finding"
    assert event.target_id == finding_id
    assert event.metadata_json == {
        "request_id": request_id,
        "from_status": "open",
        "to_status": "fixed",
    }


def test_findings_api_reject_status_request_allows_project_scoped_grant(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        with session_factory() as session:
            alpha, _alpha_target, _beta, _beta_target = _import_two_projects(session)
            session.commit()
        client = _client_with_session_factory(session_factory)
        requester_id = _login_user(client, session_factory, grant_admin=False)
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=requester_id,
            permission="finding:status_change:request",
            scope_type="project",
            scope_id=alpha.id,
        )
        finding_id = _alpha_openssl_finding_id(session_factory, alpha.id)
        create_response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]
        client.post("/api/auth/logout")
        reviewer_id = _login_user(
            client,
            session_factory,
            username="bob",
            display_name="Bob",
            grant_admin=False,
        )
        _grant_permission(
            session_factory,
            principal_type=PrincipalType.USER,
            principal_id=reviewer_id,
            permission="finding:status_change:approve",
            scope_type="project",
            scope_id=alpha.id,
        )

        response = client.post(
            f"/api/findings/{finding_id}/status-requests/{request_id}/reject",
            json={"comment": "Patch evidence is incomplete."},
        )

    assert response.status_code == 200
    status_request = response.json()["status_change_requests"][0]
    assert response.json()["status"] == "open"
    assert status_request["state"] == "rejected"
    assert status_request["reviewer_display"] == "Bob"


def test_findings_api_status_request_self_review_returns_400(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        create_response = client.post(
            f"/api/findings/{finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]

        response = client.post(
            f"/api/findings/{finding_id}/status-requests/{request_id}/approve",
            json={"comment": None},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Requester cannot review their own status change"}


def test_findings_api_status_request_missing_returns_404(engine: Engine) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            alpha_finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()
            beta_finding_id = session.scalars(
                select(RawFindingInstance.id).where(
                    RawFindingInstance.project_id == beta.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()

        create_response = client.post(
            f"/api/findings/{alpha_finding_id}/status",
            json={
                "status": "fixed",
                "comment": "Please review the patch evidence.",
                "require_peer_review": True,
            },
        )
        request_id = create_response.json()["status_change_requests"][0]["id"]
        client.post("/api/auth/logout")
        _login_user(client, session_factory, username="bob", display_name="Bob")

        response = client.post(
            f"/api/findings/{beta_finding_id}/status-requests/{request_id}/approve",
            json={},
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "Status change request not found"}


def test_findings_api_detail_resolves_activity_display_names_for_users_and_machines(
    engine: Engine,
) -> None:
    with engine.connect() as connection:
        client, session_factory, alpha, _alpha_target, _beta, _beta_target = _prepared_client(
            connection
        )
        with session_factory() as session:
            finding = session.scalars(
                select(RawFindingInstance).where(
                    RawFindingInstance.project_id == alpha.id,
                    RawFindingInstance.package_name == "openssl",
                )
            ).one()
            bob = create_user(
                session,
                username="bob",
                display_name="bob",
                password="correct horse battery staple",  # noqa: S106 - test fixture password
            )
            _raw_secret, credential = create_machine_credential(session, name="review-bot")
            request = FindingStatusChangeRequest(
                finding=finding,
                project_id=finding.project_id,
                requester_principal_type="user",
                requester_principal_id=bob.id,
                reviewer_principal_type="machine",
                reviewer_principal_id=credential.id,
                from_status=FindingStatus.OPEN,
                to_status=FindingStatus.FIXED,
                state=FindingStatusChangeState.APPROVED,
                comment="Patch has evidence.",
                decision_comment="Approved by automation.",
                decided_at=datetime(2026, 5, 8, 12, 0, tzinfo=UTC),
            )
            session.add(request)
            session.commit()
            finding_id = finding.id

        response = client.get(f"/api/findings/{finding_id}")

    assert response.status_code == 200
    status_request = response.json()["status_change_requests"][0]
    assert status_request["requester_principal_id"] == bob.id
    assert status_request["requester_display"] == "bob"
    assert status_request["reviewer_principal_id"] == credential.id
    assert status_request["reviewer_display"] == "review-bot"


def test_findings_api_detail_returns_404_for_unknown_id(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        session_factory = _session_factory_for_connection(connection)
        client = _client_with_session_factory(session_factory)
        _login_user(client, session_factory)

        response = client.get("/api/findings/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json() == {"detail": "Finding not found"}


def test_findings_api_list_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        client = _client_with_session_factory(_session_factory_for_connection(connection))

        response = client.get("/api/findings")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_findings_api_detail_requires_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        client = _client_with_session_factory(_session_factory_for_connection(connection))

        response = client.get("/api/findings/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_findings_api_comment_and_status_require_authentication(engine: Engine) -> None:
    with engine.connect() as connection:
        Base.metadata.create_all(connection)
        client = _client_with_session_factory(_session_factory_for_connection(connection))

        comment_response = client.post(
            "/api/findings/00000000-0000-0000-0000-000000000000/comments",
            json={"body": "No auth."},
        )
        status_response = client.post(
            "/api/findings/00000000-0000-0000-0000-000000000000/status",
            json={"status": "fixed", "comment": "No auth."},
        )

    assert comment_response.status_code == 401
    assert comment_response.json() == {"detail": "Not authenticated"}
    assert status_response.status_code == 401
    assert status_response.json() == {"detail": "Not authenticated"}
