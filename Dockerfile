# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy module files first for layer caching
COPY go.mod ./
RUN go mod download

# Copy source
COPY . .

# Build static binary (no CGO, no libc dependency)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath -o /llm-security-monitor ./cmd/proxy

# ── Stage 2: Run ──────────────────────────────────────────────────────────────
# gcr.io/distroless/static has no shell, no package manager — minimal attack surface
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /llm-security-monitor /llm-security-monitor

# Run as non-root (distroless nonroot = uid 65532)
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/llm-security-monitor"]
