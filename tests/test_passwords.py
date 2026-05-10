from dionysus.security.passwords import hash_password, verify_password


def test_password_hash_does_not_store_plaintext() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert password_hash != "correct horse battery staple"  # noqa: S105
    assert verify_password("correct horse battery staple", password_hash)


def test_password_verify_rejects_wrong_password() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert not verify_password("wrong password", password_hash)


def test_password_verify_rejects_malformed_hash() -> None:
    assert not verify_password("password", "not-an-argon2-hash")
