# Dionysus

Security scan triage web application.

## Local Development

Use Go for the default backend, Python 3.13 with `uv` for the legacy backend and
Alembic migrations, and Node 22.12.0 from `.nvmrc` / `.node-version` with Bun for
frontend package scripts.

Releases are managed by release-please. Regular feature PRs should not edit version files;
release-please opens dedicated release PRs with the package metadata and changelog updates.

Install Python dependencies for migrations, parity checks, and the legacy backend:

```bash
cd python
uv sync
```

Install frontend dependencies:

```bash
cd frontend
bun install
```

Run the Go backend only:

```bash
cd backend
go run ./cmd/dionysus
```

Run the Python backend only:

```bash
cd python
uv run uvicorn dionysus.app:create_app --factory --reload
```

Run the React frontend in another shell:

```bash
cd frontend
bun run dev
```

Vite proxies `/api` requests to the backend at `http://127.0.0.1:8000`.

For a production/static-style local build:

```bash
cd frontend
bun run build
```

After the build, the backend serves the React app at `/`.

Install Playwright's Chromium browser before running e2e tests on a new machine:

```bash
cd frontend
bunx playwright install chromium
```

Run frontend e2e smoke tests:

```bash
cd frontend
bun run e2e
```

For visible browser debugging:

```bash
cd frontend
bun run e2e:headed
```


## Docker

The compose setup supports two database options:

1. **SQLite (default)** — no external SQL service required, stores data in `./var` on
   your local filesystem.
2. **PostgreSQL** — either the bundled `db` service or a pre-existing PostgreSQL
   instance via `DIONYSUS_DATABASE_URL`.

Run with SQLite using the default Go backend:

```bash
docker compose up --build
```

Run the Python backend image instead:

```bash
DIONYSUS_BACKEND_TARGET=python-runtime docker compose up --build
```

The Go runtime still runs Alembic from the Python environment before starting the
Go binary. Keep the `python/` directory available until migrations move to a Go
owned path or Alembic is intentionally retired.

On first startup with no existing users, Dionysus bootstraps the initial admin
from environment variables. `DIONYSUS_BOOTSTRAP_ADMIN_USERNAME` must be a login
identifier, `DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD` must be at least 15 characters, and
`DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME` is optional. Docker Compose provides
local-only defaults:

```bash
DIONYSUS_BOOTSTRAP_ADMIN_USERNAME=admin
DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD=change-me-now-please
DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME="Local Admin"
```

Real deployments must override those values before the first startup. After the
first user exists, remove the bootstrap variables from the runtime environment;
the app will warn when they remain configured, but it will not fail startup.

Run with bundled PostgreSQL:

```bash
DIONYSUS_DATABASE_URL=postgresql+psycopg://dionysus:dionysus@db:5432/dionysus \
  docker compose --profile postgres up --build
```

Run with an existing PostgreSQL database:

```bash
DIONYSUS_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME \
  docker compose up --build
```

The app is available at `http://127.0.0.1:8000`.

## Manual Parity Verification

Before deleting or disabling the Python backend, manually smoke both Docker
targets against a fresh database:

```bash
docker compose down --volumes --remove-orphans
docker compose up --build
```

Then repeat with the Python target:

```bash
docker compose down --volumes --remove-orphans
DIONYSUS_BACKEND_TARGET=python-runtime docker compose up --build
```

For each target, sign in with the configured bootstrap admin, create a project,
import `python/tests/fixtures/trivy-image.json`, review the findings list, and
check the admin security pages. The CI parity contract is the automated gate; this
manual pass is the final review before removing Python runtime support.

## Quality Gate

Run this before committing code changes:

```bash
cd python
uv run ruff check .
uv run ruff format --check .
uv run ty check src tests migrations
uv run pytest
cd ..
cd backend
go test ./...
cd ..
cd python
uv run python ../scripts/parity_contract.py
cd ..
cd frontend
bun run typecheck
bun run e2e
bun run build
```

Create a migration after model changes:

```bash
cd python
uv run alembic revision --autogenerate -m "describe change"
```

Apply migrations:

```bash
cd python
uv run alembic upgrade head
```
