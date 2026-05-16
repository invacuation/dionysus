from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from dionysus.app import create_app
from dionysus.config import AppSettings, Environment

ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIR = ROOT / "python"
BACKEND_DIR = ROOT / "backend"
BOOTSTRAP_PASSWORD = "change-me-now-please"  # noqa: S105 - parity fixture password.


@dataclass(frozen=True)
class ContractResponse:
    status: int
    body: Any


class PythonBackend:
    def __init__(self, database_url: str) -> None:
        app = create_app(
            AppSettings(
                environment=Environment.TEST,
                database_url=database_url,
                bootstrap_admin_username="admin",
                bootstrap_admin_password=BOOTSTRAP_PASSWORD,
                bootstrap_admin_display_name="Local Admin",
            )
        )
        self.client = TestClient(app)

    def request(self, method: str, path: str, json_body: Any | None = None) -> ContractResponse:
        response = self.client.request(method, path, json=json_body)
        return ContractResponse(response.status_code, response_body(response.content))


class GoBackend:
    def __init__(self, addr: str, process: subprocess.Popen[str]) -> None:
        self.base_url = f"http://{addr}"
        self.process = process
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def request(self, method: str, path: str, json_body: Any | None = None) -> ContractResponse:
        data = None
        headers = {"Accept": "application/json"}
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(  # noqa: S310 - base URL is fixed to local test server.
            urllib.parse.urljoin(self.base_url, path),
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                return ContractResponse(response.status, response_body(response.read()))
        except urllib.error.HTTPError as error:
            return ContractResponse(error.code, response_body(error.read()))


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        python_db = tmp_path / "python.db"
        go_db = tmp_path / "go.db"
        migrate_database(python_db)
        migrate_database(go_db)

        python_backend = PythonBackend(sqlite_url(python_db))
        go_process = start_go_backend(go_db, tmp_path)
        try:
            go_backend = GoBackend("127.0.0.1:18080", go_process)
            wait_for_go(go_backend, go_process)
            run_contracts(python_backend, go_backend)
        finally:
            go_process.terminate()
            try:
                go_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                go_process.kill()
                go_process.wait(timeout=5)
    return 0


def migrate_database(path: Path) -> None:
    env = os.environ.copy()
    env["DIONYSUS_DATABASE_URL"] = sqlite_url(path)
    uv = find_executable("uv")
    subprocess.run(  # noqa: S603 - command is fixed and runs local Alembic migrations.
        [uv, "run", "alembic", "upgrade", "head"],
        cwd=PYTHON_DIR,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def start_go_backend(database_path: Path, tmp_path: Path) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "DIONYSUS_DATABASE_URL": sqlite_url(database_path),
            "DIONYSUS_HTTP_ADDR": "127.0.0.1:18080",
            "DIONYSUS_FRONTEND_DIST": str(tmp_path / "missing-frontend"),
            "DIONYSUS_BOOTSTRAP_ADMIN_USERNAME": "admin",
            "DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD": BOOTSTRAP_PASSWORD,
            "DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME": "Local Admin",
        }
    )
    go = find_go()
    return subprocess.Popen(  # noqa: S603 - command is fixed and runs the local Go backend.
        [go, "run", "./cmd/dionysus"],
        cwd=BACKEND_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def wait_for_go(backend: GoBackend, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"go backend exited early:\n{output}")
        try:
            response = backend.request("GET", "/healthz")
            if response.status == 200:
                return
        except OSError:
            pass
        time.sleep(0.25)
    output = process.stdout.read() if process.stdout else ""
    raise TimeoutError(f"go backend did not become healthy:\n{output}")


def run_contracts(python_backend: PythonBackend, go_backend: GoBackend) -> None:
    compare("unauthenticated overview", python_backend, go_backend, "GET", "/api/overview")
    compare(
        "login",
        python_backend,
        go_backend,
        "POST",
        "/api/auth/session",
        {"username": "admin", "password": BOOTSTRAP_PASSWORD},
    )
    compare("current actor", python_backend, go_backend, "GET", "/api/auth/me")
    compare("empty overview", python_backend, go_backend, "GET", "/api/overview")
    compare("security settings", python_backend, go_backend, "GET", "/api/admin/security-settings")
    compare(
        "update security settings",
        python_backend,
        go_backend,
        "PATCH",
        "/api/admin/security-settings",
        {
            "force_peer_review_for_status_changes": True,
            "session_idle_timeout_minutes": 12,
            "session_absolute_timeout_minutes": 240,
        },
    )
    compare(
        "create project",
        python_backend,
        go_backend,
        "POST",
        "/api/projects",
        {
            "slug": "alpha",
            "name": "Alpha",
            "description": "Primary inventory",
            "sla_tracking_enabled": False,
            "sla_reporting_enabled": False,
            "require_peer_review_for_status_changes": True,
            "grace_period_enabled": True,
            "grace_period_percent": 50,
        },
    )
    compare("list projects", python_backend, go_backend, "GET", "/api/projects")
    project_id_python = python_backend.request("GET", "/api/projects").body["projects"][0]["id"]
    project_id_go = go_backend.request("GET", "/api/projects").body["projects"][0]["id"]
    compare_pair(
        "update project",
        python_backend.request(
            "PATCH",
            f"/api/projects/{project_id_python}",
            {"slug": "alpha-renamed", "name": "Alpha Renamed", "grace_period_percent": 75},
        ),
        go_backend.request(
            "PATCH",
            f"/api/projects/{project_id_go}",
            {"slug": "alpha-renamed", "name": "Alpha Renamed", "grace_period_percent": 75},
        ),
    )
    compare_pair(
        "create folder",
        python_backend.request(
            "POST",
            f"/api/projects/{project_id_python}/folders",
            {"path": "images/releases"},
        ),
        go_backend.request(
            "POST",
            f"/api/projects/{project_id_go}/folders",
            {"path": "images/releases"},
        ),
    )
    compare_pair(
        "list assets",
        python_backend.request("GET", f"/api/projects/{project_id_python}/assets"),
        go_backend.request("GET", f"/api/projects/{project_id_go}/assets"),
    )


def compare(
    name: str,
    python_backend: PythonBackend,
    go_backend: GoBackend,
    method: str,
    path: str,
    json_body: Any | None = None,
) -> None:
    compare_pair(
        name,
        python_backend.request(method, path, json_body),
        go_backend.request(method, path, json_body),
    )


def compare_pair(
    name: str,
    python_response: ContractResponse,
    go_response: ContractResponse,
) -> None:
    python_normalized = normalize_response(python_response)
    go_normalized = normalize_response(go_response)
    if python_normalized != go_normalized:
        raise AssertionError(
            f"{name} parity mismatch\n"
            f"python: {json.dumps(python_normalized, indent=2, sort_keys=True)}\n"
            f"go:     {json.dumps(go_normalized, indent=2, sort_keys=True)}"
        )


def normalize_response(response: ContractResponse) -> dict[str, Any]:
    return {"status": response.status, "body": normalize_value(response.body)}


def normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize_field(key, field_value) for key, field_value in sorted(value.items())
        }
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    return value


def normalize_field(key: str, value: Any) -> Any:
    if value is None:
        return None
    if key == "id" or key.endswith("_id"):
        return "<id>"
    datetime_keys = {
        "created_at",
        "updated_at",
        "last_seen_at",
        "first_detected_at",
        "idle_expires_at",
        "expires_at",
    }
    if key in datetime_keys:
        return "<datetime>"
    return normalize_value(value)


def response_body(payload: bytes) -> Any:
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload.decode()


def sqlite_url(path: Path) -> str:
    return f"sqlite:///{path}"


def find_go() -> str:
    if go := find_executable("go", required=False):
        return str(go)
    fallback = Path.home() / ".cache" / "codex-go" / "go" / "bin" / "go"
    if fallback.exists():
        return str(fallback)
    raise FileNotFoundError("go")


def find_executable(name: str, *, required: bool = True) -> str | None:
    if path := shutil.which(name):
        return path
    if required:
        raise FileNotFoundError(name)
    return None


if __name__ == "__main__":
    raise SystemExit(main())
