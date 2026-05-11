import pytest
from sqlalchemy.orm import Session

from dionysus.identity.users import (
    authenticate_user,
    canonicalize_username,
    create_user,
    get_user_by_username,
)
from dionysus.models.identity import User


def test_create_user_stores_hashed_password(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice@example.com",
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
        username="alice@example.com",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )
    db_session.commit()

    authenticated = authenticate_user(
        db_session,
        "alice@example.com",
        "correct horse battery staple",
    )

    assert authenticated is not None
    assert authenticated.id == user.id


def test_authenticate_user_rejects_wrong_password(db_session: Session) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )
    db_session.commit()

    assert authenticate_user(db_session, "alice@example.com", "wrong password 12345") is None


def test_canonicalize_username_accepts_unicode_email_domain(db_session: Session) -> None:
    user = create_user(
        db_session,
        username=" Alice@bücher.example ",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )

    assert user.username == "Alice@xn--bcher-kva.example"
    assert get_user_by_username(db_session, "Alice@bücher.example") == user


def test_canonicalize_username_accepts_plain_identifier() -> None:
    assert canonicalize_username("admin") == "admin"


def test_canonicalize_username_trims_surrounding_whitespace() -> None:
    assert canonicalize_username("  alice@example.com\n") == "alice@example.com"


@pytest.mark.parametrize(
    "username",
    [
        "",
        "alice@",
        "@example.com",
        "alice@@example.com",
        "alice example@example.com",
        "alice@example.com\nadmin",
        "alice\tadmin",
    ],
)
def test_create_user_rejects_malformed_usernames(db_session: Session, username: str) -> None:
    with pytest.raises(ValueError, match="username"):
        create_user(
            db_session,
            username=username,
            display_name="Alice Example",
            password="correct horse battery staple",  # noqa: S106
        )


def test_authenticate_user_returns_none_for_malformed_username(db_session: Session) -> None:
    create_user(
        db_session,
        username="alice@example.com",
        display_name="Alice Example",
        password="correct horse battery staple",  # noqa: S106
    )
    db_session.commit()

    assert (
        authenticate_user(db_session, "alice@@example.com", "correct horse battery staple")
        is None
    )


def test_create_user_rejects_overlong_canonical_username(db_session: Session) -> None:
    username = f"{'a' * 140}@example.com"

    with pytest.raises(ValueError, match="username"):
        create_user(
            db_session,
            username=username,
            display_name="Alice Example",
            password="correct horse battery staple",  # noqa: S106
        )


def test_display_name_trims_and_accepts_script_like_text(db_session: Session) -> None:
    user = create_user(
        db_session,
        username="alice@example.com",
        display_name=" <script>alert('Alice')</script> ",
        password="correct horse battery staple",  # noqa: S106
    )

    assert user.display_name == "<script>alert('Alice')</script>"


@pytest.mark.parametrize("display_name", ["", "   ", "a" * 201])
def test_create_user_rejects_invalid_display_names(db_session: Session, display_name: str) -> None:
    with pytest.raises(ValueError, match="display name"):
        create_user(
            db_session,
            username="alice@example.com",
            display_name=display_name,
            password="correct horse battery staple",  # noqa: S106
        )


@pytest.mark.parametrize(
    "password",
    [
        "a" * 15,
        "correct horse battery staple",
        "🔒" * 15,
    ],
)
def test_create_user_accepts_valid_passwords(db_session: Session, password: str) -> None:
    user = create_user(
        db_session,
        username=f"{len(password)}@example.com",
        display_name="Alice Example",
        password=password,
    )

    assert user.password_credential is not None
    assert user.password_credential.password_hash != password


@pytest.mark.parametrize("password", ["", "short", " " * 15, "a" * 257])
def test_create_user_rejects_invalid_passwords(db_session: Session, password: str) -> None:
    with pytest.raises(ValueError, match="password"):
        create_user(
            db_session,
            username="alice@example.com",
            display_name="Alice Example",
            password=password,
        )
