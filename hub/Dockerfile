# SwiftProof Hub: the web application, with the CLI it runs.
#
# Build context is the repository root, because the image needs both modules:
#   docker build -f hub/Dockerfile -t swiftproof-hub .
#
# The CLI is shipped inside the image on purpose. The hub never analyzes a
# change itself: it prepares a disposable checkout and executes this trusted
# binary, so the report a user reads is the one the CLI produced.

FROM golang:1.26-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.work ./
COPY app/ app/
COPY hub/ hub/
ARG VERSION=dev
RUN go build -ldflags "-s -w" -o /out/swiftproof ./app/cmd/swiftproof \
 && go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/swiftproof-hub ./hub/cmd/swiftproof-hub
# The binaries must run in the final image, which has no Go toolchain.
RUN go vet ./hub/... && /out/swiftproof-hub version

FROM debian:bookworm-slim
# git fetches the analyzed commits; ca-certificates lets the hub reach the
# forge over TLS. Nothing else is needed: the UI is embedded in the binary.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The service runs unprivileged and owns only its data directory.
RUN useradd --system --create-home --home-dir /var/lib/swiftproof-hub --uid 10001 swiftproof

COPY --from=build /out/swiftproof /usr/local/bin/swiftproof
COPY --from=build /out/swiftproof-hub /usr/local/bin/swiftproof-hub

ENV SWIFTPROOF_HUB_ADDR=:8080 \
    SWIFTPROOF_HUB_DATA_DIR=/var/lib/swiftproof-hub \
    SWIFTPROOF_HUB_BINARY=/usr/local/bin/swiftproof \
    SWIFTPROOF_HUB_MODE=lint

USER swiftproof
WORKDIR /var/lib/swiftproof-hub
VOLUME ["/var/lib/swiftproof-hub"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/swiftproof-hub", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/swiftproof-hub"]
