# Dionysus Go Backend

This directory contains the backend runtime.

Run tests:

```bash
go test ./...
```

Run the backend:

```bash
go run ./cmd/dionysus
```

The server exposes `/api`, serves the React build from `../frontend/dist` by
default, and applies the initial Go-owned schema automatically for empty SQLite
or PostgreSQL databases.
