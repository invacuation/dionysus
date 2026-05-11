import os
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pytest import MonkeyPatch
from sqlalchemy import Engine

from conftest import make_prepared_app_settings
from dionysus.app import create_app
from dionysus.config import AppSettings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ROOT = PROJECT_ROOT / "frontend"


def _node_version_tuple(node_bin: Path) -> tuple[int, int, int] | None:
    try:
        result = subprocess.run(  # noqa: S603
            [str(node_bin), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    version = result.stdout.strip().removeprefix("v").split(".")
    if len(version) < 3:
        return None
    try:
        major, minor, patch = version[:3]
        return int(major), int(minor), int(patch)
    except ValueError:
        return None


def _vite_compatible_node_bin() -> Path:
    candidates = [Path(node) for node in [shutil.which("node")] if node]
    candidates.extend(sorted(Path.home().glob(".nvm/versions/node/v*/bin/node"), reverse=True))

    for node_bin in candidates:
        version = _node_version_tuple(node_bin)
        if version and version >= (22, 12, 0):
            return node_bin

    pytest.skip("frontend build requires Node >=22.12")


def _bun_bin() -> Path:
    bun = shutil.which("bun")
    candidates = [Path(bun)] if bun else []
    candidates.append(Path.home() / ".bun/bin/bun")

    for bun_bin in candidates:
        if bun_bin.exists():
            return bun_bin

    pytest.skip("frontend build requires Bun")


def _test_settings(tmp_path: Path) -> AppSettings:
    return make_prepared_app_settings(tmp_path)


def test_react_frontend_serves_index_at_root_when_build_exists(tmp_path: Path) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text(
        '<div id="root"></div><script type="module" src="/assets/app.js"></script>',
        encoding="utf-8",
    )

    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = frontend_dist
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text


def test_react_frontend_falls_back_to_index_for_frontend_routes(tmp_path: Path) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text(
        '<div id="root"></div><script type="module" src="/assets/app.js"></script>',
        encoding="utf-8",
    )

    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = frontend_dist
    client = TestClient(app)

    response = client.get("/findings")

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text


@pytest.mark.parametrize("path", ["/admin", "/findings", "/imports", "/inventory", "/login"])
def test_react_frontend_serves_index_for_known_frontend_routes(
    path: str,
    tmp_path: Path,
) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text(
        '<div id="root"></div><script type="module" src="/assets/app.js"></script>',
        encoding="utf-8",
    )

    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = frontend_dist
    client = TestClient(app)

    response = client.get(path)

    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text
    assert "csrf_token" not in response.text


def test_app_route_returns_404(tmp_path: Path) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text('<div id="root"></div>', encoding="utf-8")

    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = frontend_dist
    client = TestClient(app, follow_redirects=False)

    response = client.get("/app")

    assert response.status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/app//evil.example/path",
        "/app/%2F%2Fevil.example/path",
    ],
)
def test_app_route_nested_paths_return_404(
    path: str,
    tmp_path: Path,
) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text('<div id="root"></div>', encoding="utf-8")

    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = frontend_dist
    client = TestClient(app, follow_redirects=False)

    response = client.get(path)

    assert response.status_code == 404


def test_react_frontend_missing_build_returns_404(tmp_path: Path) -> None:
    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = tmp_path / "missing"
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "React frontend build not found. Run `cd frontend && bun run build`."
    }


def test_built_frontend_assets_are_mounted_when_build_exists(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    frontend_dist = tmp_path / "dist"
    assets_dir = frontend_dist / "assets"
    assets_dir.mkdir(parents=True)
    (frontend_dist / "index.html").write_text("<div id='root'></div>", encoding="utf-8")
    (assets_dir / "app.js").write_text("console.log('dionysus')", encoding="utf-8")
    monkeypatch.setattr("dionysus.app.default_frontend_dist", lambda: frontend_dist, raising=False)

    client = TestClient(create_app(_test_settings(tmp_path)))

    response = client.get("/assets/app.js")

    assert response.status_code == 200
    assert "console.log('dionysus')" in response.text


def test_vite_build_has_html_entrypoint_for_fastapi_app_route() -> None:
    index_html = FRONTEND_ROOT / "index.html"

    assert index_html.exists()

    html = index_html.read_text(encoding="utf-8")
    assert '<div id="root"></div>' in html
    assert 'type="module"' in html
    assert "/src/main.tsx" in html


def test_vite_build_outputs_index_html_contract(tmp_path: Path) -> None:
    out_dir = tmp_path / "dist"
    node_bin = _vite_compatible_node_bin()
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(node_bin.parent), env.get("PATH", "")])

    result = subprocess.run(  # noqa: S603
        [
            str(_bun_bin()),
            "run",
            "vite",
            "build",
            "--outDir",
            str(out_dir),
            "--emptyOutDir",
        ],
        cwd=FRONTEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0, result.stderr
    built_index = out_dir / "index.html"
    assert built_index.exists()

    html = built_index.read_text(encoding="utf-8")
    assert '<div id="root"></div>' in html
    assert 'type="module"' in html
    assert "/assets/" in html


@pytest.mark.parametrize(
    "path",
    [
        "/legacy",
        "/legacy/admin",
        "/legacy/findings",
        "/legacy/imports",
        "/projects",
        "/projects/not-a-real",
    ],
)
def test_legacy_jinja_routes_are_not_registered(
    path: str,
    engine: Engine,
    tmp_path: Path,
) -> None:
    with engine.connect():
        client = TestClient(create_app(_test_settings(tmp_path)))
        response = client.get(path)

    assert response.status_code == 404


def test_frontend_fallback_does_not_swallow_backend_prefixes(tmp_path: Path) -> None:
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text('<div id="root"></div>', encoding="utf-8")

    app = create_app(_test_settings(tmp_path))
    app.state.frontend_dist = frontend_dist
    client = TestClient(app)

    assert client.get("/api/not-a-real-route").status_code == 404
    assert client.get("/assets/not-a-real-asset.js").status_code == 404
    assert client.get("/healthz/not-a-real-route").status_code == 404
    assert client.get("/projects/not-a-real/extra").status_code == 404
    assert client.get("/login/extra").status_code == 404
