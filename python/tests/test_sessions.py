from datetime import UTC, datetime

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from dionysus.identity.sessions import create_session, get_active_session, revoke_session
from dionysus.identity.users import create_user

TEST_PASSWORD = "correct horse battery staple"  # noqa: S105


def test_create_session_returns_raw_token_once(db_session: Session) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password=TEST_PASSWORD)
    token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent="pytest",
        ip_address="127.0.0.1",
    )
    db_session.commit()

    assert token
    assert session_record.token_digest != token
    assert session_record.user_agent == "pytest"
    assert session_record.ip_address == "127.0.0.1"


def test_get_active_session_touches_idle_expiry(db_session: Session) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password=TEST_PASSWORD)
    token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()

    active = get_active_session(
        db_session,
        token,
        now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert active is not None
    assert active.id == session_record.id
    assert active.idle_expires_at == datetime(2026, 5, 7, 12, 15, tzinfo=UTC)


def test_get_active_session_rejects_revoked_session(db_session: Session) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password=TEST_PASSWORD)
    token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    revoke_session(db_session, session_record, now=datetime(2026, 5, 7, 0, 1, tzinfo=UTC))
    db_session.commit()

    assert (
        get_active_session(
            db_session,
            token,
            now=datetime(2026, 5, 7, 0, 2, tzinfo=UTC),
            idle_timeout_minutes=10,
        )
        is None
    )


def test_get_active_session_rejects_idle_timeout(db_session: Session) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password=TEST_PASSWORD)
    token, _ = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()

    assert (
        get_active_session(
            db_session,
            token,
            now=datetime(2026, 5, 7, 12, 11, tzinfo=UTC),
            idle_timeout_minutes=10,
        )
        is None
    )


def test_get_active_session_accepts_sqlite_reloaded_naive_timestamps(
    engine: Engine, db_session: Session
) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password=TEST_PASSWORD)
    token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=10,
        absolute_timeout_minutes=60,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()
    db_session.close()

    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with session_factory() as fresh_session:
        active = get_active_session(
            fresh_session,
            token,
            now=datetime(2026, 5, 7, 12, 5, tzinfo=UTC),
            idle_timeout_minutes=10,
        )

        assert active is not None
        assert active.id == session_record.id


def test_get_active_session_clamps_idle_expiry_to_absolute_expiry(db_session: Session) -> None:
    user = create_user(db_session, username="alice", display_name="Alice", password=TEST_PASSWORD)
    token, session_record = create_session(
        db_session,
        user=user,
        now=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
        idle_timeout_minutes=20,
        absolute_timeout_minutes=15,
        user_agent=None,
        ip_address=None,
    )
    db_session.commit()

    active = get_active_session(
        db_session,
        token,
        now=datetime(2026, 5, 7, 12, 10, tzinfo=UTC),
        idle_timeout_minutes=10,
    )

    assert active is not None
    assert active.idle_expires_at == session_record.expires_at
