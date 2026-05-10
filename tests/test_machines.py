from datetime import UTC, datetime

from sqlalchemy.orm import Session

import dionysus.identity.machines as machines
from dionysus.identity.machines import (
    create_machine_credential,
    exchange_machine_client_secret,
    refresh_machine_token,
    regenerate_machine_client_secret,
    revoke_machine_access_token,
    revoke_machine_credential,
    revoke_machine_refresh_token,
    verify_machine_access_token,
    verify_machine_client_secret,
)


def test_create_machine_credential_returns_secret_once(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    db_session.commit()

    assert raw_secret
    assert credential.client_secret_digest != raw_secret
    assert verify_machine_client_secret(credential, raw_secret)


def test_machine_auth_public_api_excludes_direct_token_issuance() -> None:
    removed_api_names = {
        "issue_machine" + "_token",
        "issue_machine" + "_refresh_token",
        "verify_machine" + "_token",
    }

    assert removed_api_names.isdisjoint(vars(machines))


def test_verify_machine_access_token_rejects_expired_exchange_token(
    db_session: Session,
) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=30,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None
    db_session.commit()

    assert (
        verify_machine_access_token(
            db_session,
            token_pair.access_token,
            now=datetime(2026, 5, 7, 0, 31, tzinfo=UTC),
        )
        is None
    )


def test_exchange_machine_client_secret_issues_token_pair(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    db_session.commit()

    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )

    assert token_pair is not None
    assert token_pair.access_token
    assert token_pair.refresh_token
    assert token_pair.access_token != token_pair.refresh_token
    verified = verify_machine_access_token(
        db_session,
        token_pair.access_token,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
    )
    assert verified is not None
    assert verified.id == token_pair.access_token_record.id
    assert token_pair.refresh_token_record.machine_credential_id == credential.id


def test_regenerate_machine_client_secret_returns_new_secret_once(
    db_session: Session,
) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    db_session.commit()

    new_raw_secret = regenerate_machine_client_secret(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
    )
    db_session.commit()

    assert new_raw_secret
    assert new_raw_secret != raw_secret
    assert credential.client_secret_digest != new_raw_secret
    assert not verify_machine_client_secret(credential, raw_secret)
    assert verify_machine_client_secret(credential, new_raw_secret)
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=raw_secret,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=new_raw_secret,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is not None
    )


def test_regenerate_machine_client_secret_does_not_reactivate_inactive_credential(
    db_session: Session,
) -> None:
    _raw_secret, credential = create_machine_credential(
        db_session,
        name="inactive-uploader",
    )
    credential.is_active = False
    db_session.commit()

    new_raw_secret = regenerate_machine_client_secret(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
    )
    db_session.commit()

    assert credential.is_active is False
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=new_raw_secret,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_regenerate_machine_client_secret_does_not_reactivate_revoked_credential(
    db_session: Session,
) -> None:
    _raw_secret, credential = create_machine_credential(
        db_session,
        name="revoked-uploader",
    )
    revoked_at = datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    revoke_machine_credential(db_session, credential, now=revoked_at)
    db_session.commit()

    new_raw_secret = regenerate_machine_client_secret(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 10, tzinfo=UTC),
    )
    db_session.commit()

    assert credential.revoked_at == revoked_at
    assert credential.is_active is False
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=new_raw_secret,
            now=datetime(2026, 5, 7, 0, 11, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_regenerate_machine_client_secret_with_tokens_revokes_existing_tokens(
    db_session: Session,
) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None

    regenerate_machine_client_secret(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
        revoke_tokens=True,
    )

    assert token_pair.access_token_record.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert token_pair.refresh_token_record.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert (
        verify_machine_access_token(
            db_session,
            token_pair.access_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
        )
        is None
    )
    assert (
        refresh_machine_token(
            db_session,
            token_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_regenerate_machine_client_secret_without_tokens_leaves_existing_tokens_usable(
    db_session: Session,
) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None

    regenerate_machine_client_secret(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
        revoke_tokens=False,
    )

    assert token_pair.access_token_record.revoked_at is None
    assert token_pair.refresh_token_record.revoked_at is None
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=raw_secret,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )
    assert (
        verify_machine_access_token(
            db_session,
            token_pair.access_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
        )
        is not None
    )
    assert (
        refresh_machine_token(
            db_session,
            token_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is not None
    )


def test_exchange_machine_client_secret_rejects_wrong_secret(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    db_session.commit()

    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=f"{raw_secret}-mismatch",
            now=datetime(2026, 5, 7, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_refresh_machine_token_rotates_refresh_token(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    first_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert first_pair is not None
    db_session.commit()

    second_pair = refresh_machine_token(
        db_session,
        first_pair.refresh_token,
        now=datetime(2026, 5, 7, 0, 10, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )

    assert second_pair is not None
    assert second_pair.refresh_token != first_pair.refresh_token
    assert first_pair.refresh_token_record.revoked_at == datetime(2026, 5, 7, 0, 10, tzinfo=UTC)
    assert (
        refresh_machine_token(
            db_session,
            first_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 11, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )
    verified = verify_machine_access_token(
        db_session,
        second_pair.access_token,
        now=datetime(2026, 5, 7, 0, 20, tzinfo=UTC),
    )
    assert verified is not None
    assert verified.id == second_pair.access_token_record.id


def test_revoke_machine_access_token_prevents_verification(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None

    revoke_machine_access_token(
        db_session,
        token_pair.access_token_record,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
    )

    assert token_pair.access_token_record.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert (
        verify_machine_access_token(
            db_session,
            token_pair.access_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
        )
        is None
    )


def test_revoke_machine_refresh_token_prevents_refresh(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None

    revoke_machine_refresh_token(
        db_session,
        token_pair.refresh_token_record,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
    )

    assert token_pair.refresh_token_record.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert (
        refresh_machine_token(
            db_session,
            token_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_revoke_machine_credential_with_tokens_disables_auth_and_revokes_rows(
    db_session: Session,
) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None

    revoke_machine_credential(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
        revoke_tokens=True,
    )

    assert credential.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert credential.is_active is False
    assert token_pair.access_token_record.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert token_pair.refresh_token_record.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=raw_secret,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )
    assert (
        verify_machine_access_token(
            db_session,
            token_pair.access_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
        )
        is None
    )
    assert (
        refresh_machine_token(
            db_session,
            token_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_revoke_machine_credential_without_tokens_keeps_row_revocation_audit_distinction(
    db_session: Session,
) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    token_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert token_pair is not None

    revoke_machine_credential(
        db_session,
        credential,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
        revoke_tokens=False,
    )

    assert credential.revoked_at == datetime(2026, 5, 7, 0, 5, tzinfo=UTC)
    assert credential.is_active is False
    assert token_pair.access_token_record.revoked_at is None
    assert token_pair.refresh_token_record.revoked_at is None
    assert (
        exchange_machine_client_secret(
            db_session,
            client_id=credential.client_id,
            client_secret=raw_secret,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )
    assert (
        verify_machine_access_token(
            db_session,
            token_pair.access_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
        )
        is None
    )
    assert (
        refresh_machine_token(
            db_session,
            token_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 6, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_revoked_or_inactive_credential_prevents_exchange_and_refresh(
    db_session: Session,
) -> None:
    active_secret, active_credential = create_machine_credential(
        db_session,
        name="trivy-uploader",
    )
    active_pair = exchange_machine_client_secret(
        db_session,
        client_id=active_credential.client_id,
        client_secret=active_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert active_pair is not None

    inactive_secret, inactive_credential = create_machine_credential(
        db_session,
        name="inactive-uploader",
    )
    inactive_credential.is_active = False
    revoked_secret, revoked_credential = create_machine_credential(
        db_session,
        name="revoked-uploader",
    )
    revoked_credential.revoked_at = datetime(2026, 5, 7, tzinfo=UTC)
    db_session.commit()

    for credential, raw_secret in (
        (inactive_credential, inactive_secret),
        (revoked_credential, revoked_secret),
    ):
        assert (
            exchange_machine_client_secret(
                db_session,
                client_id=credential.client_id,
                client_secret=raw_secret,
                now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
                access_expires_in_minutes=15,
                refresh_expires_in_minutes=60,
            )
            is None
        )

    active_credential.is_active = False
    db_session.commit()

    assert (
        refresh_machine_token(
            db_session,
            active_pair.refresh_token,
            now=datetime(2026, 5, 7, 0, 10, tzinfo=UTC),
            access_expires_in_minutes=15,
            refresh_expires_in_minutes=60,
        )
        is None
    )


def test_sqlite_reloaded_machine_token_timestamps_verify(db_session: Session) -> None:
    raw_secret, credential = create_machine_credential(db_session, name="trivy-uploader")
    first_pair = exchange_machine_client_secret(
        db_session,
        client_id=credential.client_id,
        client_secret=raw_secret,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )
    assert first_pair is not None
    db_session.commit()
    db_session.expire_all()

    verified = verify_machine_access_token(
        db_session,
        first_pair.access_token,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
    )
    refreshed = refresh_machine_token(
        db_session,
        first_pair.refresh_token,
        now=datetime(2026, 5, 7, 0, 5, tzinfo=UTC),
        access_expires_in_minutes=15,
        refresh_expires_in_minutes=60,
    )

    assert verified is not None
    assert refreshed is not None
