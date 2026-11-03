# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/tamamo ./cmd/tamamo \
 && mkdir -p /out/data

# ---- run ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tamamo /usr/local/bin/tamamo
COPY --from=build --chown=65532:65532 /out/data /data

ENV TAMAMO_DATA=/data \
    TAMAMO_LISTEN=:8923 \
    TAMAMO_ADMIN_LISTEN=:8081

# /data holds tamamo.yaml (all settings), tamamo.db (statistics), secret.key and uploads/.
# Mount a host folder there (compose: ./data:/data) to edit the files directly.
# The folder must be writable by uid 65532 (nonroot).
VOLUME ["/data"]
EXPOSE 8923 8081
USER nonroot:nonroot

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/tamamo", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/tamamo"]
