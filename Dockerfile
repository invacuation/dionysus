# syntax=docker/dockerfile:1.7

FROM oven/bun:1.2.23-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

FROM golang:1.26-alpine AS backend-build
WORKDIR /app/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/dionysus ./cmd/dionysus

FROM alpine:3.23 AS runtime
ENV DIONYSUS_DATABASE_URL=sqlite:////app/var/dionysus.db \
    DIONYSUS_FRONTEND_DIST=/app/frontend/dist
WORKDIR /app/backend
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates

COPY --from=backend-build /out/dionysus /app/backend/dionysus
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

EXPOSE 8000
CMD ["/app/backend/dionysus"]
