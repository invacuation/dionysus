# Dionysus

Security scan triage web application.

## Local Development

Use Go 1.26 for the backend and Node 22.12.0 from `.nvmrc` / `.node-version`
with Bun for frontend package scripts.

The application defaults to using SQLite, storing the db at `./var/dionysus.db`.

Releases are managed by release-please. Regular feature PRs should not edit
version files; release-please opens dedicated release PRs with package metadata
and changelog updates

Install frontend dependencies:

```bash
cd frontend
bun install
```

Run the backend:

```bash
cd backend
go run ./cmd/dionysus
```

If you haven't set up the DB uo yet, you'll have to run this instead:
```bash
cd backend

DIONYSUS_BOOTSTRAP_ADMIN_USERNAME=<admin_username> \
DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD=<admin_password> \
DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME=<admin_display_name> \
go run ./cmd/dionysus
```

The backend applies the initial Go-owned schema automatically when the database
is empty. During the unreleased phase, reset local development data after schema
changes:

```bash
docker compose down --volumes --remove-orphans
rm -f var/dionysus.db
```

Run the React frontend in another shell:

```bash
cd frontend
bun run dev
```

Browse to `http://127.0.0.1:5173` to use Dionysus.
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

1. **SQLite (default)**: no external SQL service required, stores data in `./var`
   on your local filesystem.
2. **PostgreSQL**: either the bundled `db` service or a pre-existing PostgreSQL
   instance via `DIONYSUS_DATABASE_URL`.

Run with SQLite:

```bash
docker compose up --build
```

On first startup with no existing users, Dionysus bootstraps the initial admin
from environment variables. `DIONYSUS_BOOTSTRAP_ADMIN_USERNAME` must be a login
identifier, `DIONYSUS_BOOTSTRAP_ADMIN_PASSWORD` must be at least 15 characters,
and `DIONYSUS_BOOTSTRAP_ADMIN_DISPLAY_NAME` is optional. Docker Compose provides
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
DIONYSUS_DATABASE_URL=postgresql://dionysus:dionysus@db:5432/dionysus \
  docker compose --profile postgres up --build
```

Run with an existing PostgreSQL database:

```bash
DIONYSUS_DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DBNAME \
  docker compose up --build
```

The app is available at `http://127.0.0.1:8000`.

## Manual Verification

Before review, smoke the Docker image against a fresh database:

```bash
docker compose down --volumes --remove-orphans
rm -f var/dionysus.db
docker compose up --build
```

Sign in with the configured bootstrap admin, create a project, import
`backend/testdata/trivy-image.json`, review the findings list, and check the
admin security pages.

## Quality Gate

Run this before committing code changes:

```bash
cd backend
go test ./...
cd ..
cd frontend
bun run typecheck
bun run e2e
bun run build
```
