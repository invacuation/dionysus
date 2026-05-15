from pathlib import Path

DOCKERFILE = Path(__file__).parents[2] / "Dockerfile"


def test_runtime_image_upgrades_os_packages_and_pip() -> None:
    dockerfile = DOCKERFILE.read_text()
    runtime_stage = dockerfile.split("FROM python:3.13-alpine AS runtime", maxsplit=1)[1]

    assert "apk upgrade --no-cache" in runtime_stage
    assert 'python -m pip install --no-cache-dir --upgrade "pip>=26.1"' in runtime_stage


def test_runtime_image_sets_app_var_database_default() -> None:
    dockerfile = DOCKERFILE.read_text()
    runtime_stage = dockerfile.split("FROM python:3.13-alpine AS runtime", maxsplit=1)[1]

    assert "DIONYSUS_DATABASE_URL=sqlite:////app/var/dionysus.db" in runtime_stage
