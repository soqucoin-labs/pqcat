# PQCAT Scanner — Open Source Edition
# Minimal container for running PQCAT scans in CI/CD pipelines.
#
# Build:
#   docker build -t pqcat .
#
# Usage:
#   docker run --rm pqcat scan tls your-server.gov
#   docker run --rm -v $(pwd):/data pqcat scan code /data/src/ --html /data/report.html
#   docker run --rm pqcat scan tls 10.0.0.0/24 --framework fisma --workers 50
#
# Soqucoin Labs Inc.

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w \
      -X main.Version=$(cat VERSION 2>/dev/null || echo dev) \
      -X main.Edition=Scanner \
      -X main.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /pqcat ./cmd/pqcat/

# Runtime — scratch for minimal attack surface
FROM scratch

COPY --from=builder /pqcat /pqcat
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/pqcat"]
