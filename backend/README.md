# Dionysus Go Backend

This directory contains the in-progress Go backend rewrite.

The Python backend under `../python` remains the current production backend until the Go backend reaches parity.

Run tests:

```bash
go test ./...
```

Run the skeleton server:

```bash
go run ./cmd/dionysus
```

The skeleton currently exposes `/healthz`.
