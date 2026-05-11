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

Build and run the full stack (API + React frontend + PostgreSQL):

```bash
docker compose up --build
```

The app is available at `http://127.0.0.1:8000`.

Set `DIONYSUS_DATABASE_URL` on the `app` service in `docker-compose.yml` if you
want to point to a managed cloud database instead of the bundled PostgreSQL
container.

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
