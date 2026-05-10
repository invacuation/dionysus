from sqlalchemy.orm import Session

from dionysus.identity.users import authenticate_user, create_user
from dionysus.models.identity import User


def test_create_user_stores_hashed_password(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )

    db_session.commit()

    stored_user = db_session.get(User, user.id)
    assert stored_user is not None
    assert stored_user.password_credential is not None
    assert stored_user.password_credential.password_hash != "correct horse battery staple"  # noqa: S105


def test_authenticate_user_accepts_valid_password(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )
    db_session.commit()

    authenticated = authenticate_user(db_session, "alice", "correct horse battery staple")

    assert authenticated is not None
    assert authenticated.id == user.id


def test_authenticate_user_rejects_wrong_password(db_session: Session) -> None:
    create_user(
        db_session,
        username="alice",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )
    db_session.commit()

    assert authenticate_user(db_session, "alice", "wrong password") is None
