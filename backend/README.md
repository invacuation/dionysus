# Dionysus Go Backend

This directory contains the default backend runtime for the migration period.
The Python backend under `../python` is still kept in the repository for manual
parity verification and for Alembic migrations.

Run tests:

```bash
go test ./...
```

Run the backend:

```bash
go run ./cmd/dionysus
```

The server exposes the same `/api` surface as the Python backend and serves the
React build from `../frontend/dist` by default. During the dual-backend phase,
run `cd ../python && uv run python ../scripts/parity_contract.py` before relying
on behavior changes.
