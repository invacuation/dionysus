# Dionysus

Security scan triage web application.

## Local Development

Use Python 3.13 with `uv`. Use Node 22.12.0 from `.nvmrc` / `.node-version`, and run
frontend package scripts with Bun.

Install Python dependencies:

```bash
uv sync
```

Install frontend dependencies:

```bash
cd frontend
bun install
```

Run the backend only:

```bash
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

Run with SQLite (default):

```bash
docker compose up --build
```

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

## Quality Gate

Run this before committing code changes:

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check src tests migrations
uv run pytest
cd frontend
bun run typecheck
bun run e2e
bun run build
```

Create a migration after model changes:

```bash
uv run alembic revision --autogenerate -m "describe change"
```

Apply migrations:

```bash
uv run alembic upgrade head
```
