# syntax=docker/dockerfile:1.7

FROM oven/bun:1.2.23-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

FROM ghcr.io/astral-sh/uv:python3.13-alpine AS backend-build
WORKDIR /app
RUN apk add --no-cache build-base libpq-dev
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ ./src/
RUN uv sync --frozen --no-dev

FROM python:3.13-alpine AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"
WORKDIR /app
RUN apk upgrade --no-cache \
    && apk add --no-cache libpq \
    && python -m pip install --no-cache-dir --upgrade "pip>=26.1"

COPY --from=backend-build /app/.venv /app/.venv
COPY pyproject.toml ./
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini ./
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn dionysus.app:create_app --factory --host 0.0.0.0 --port 8000"]
