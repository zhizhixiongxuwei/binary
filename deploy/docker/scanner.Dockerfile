ARG GO_BUILD_IMAGE=golang:1.25.0-bookworm
ARG TRIVY_RUNTIME_DB_IMAGE=binaryscan/trivy-runtime-db:0.72.0-offline20260822
ARG SCANNER_RUNTIME_IMAGE=alpine:3.22.5

FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src/app/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download
COPY app/backend/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-scanner ./cmd/scanner

FROM ${TRIVY_RUNTIME_DB_IMAGE} AS trivy
FROM ${SCANNER_RUNTIME_IMAGE}
ARG BINARY_VERSION=0.1.0-dev
USER root
COPY --from=build --chmod=0555 /out/binary-scanner /usr/local/bin/binary-scanner
COPY --from=trivy --chmod=0555 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trivy --chown=10001:10001 /opt/trivy-cache /opt/trivy-cache
ENV HOME=/tmp TMPDIR=/tmp \
    TRIVY_DISABLE_TELEMETRY=true \
    TRIVY_OFFLINE_SCAN=true \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true \
    TRIVY_SKIP_VERSION_CHECK=true
LABEL org.opencontainers.image.title="BinaryScan scanner" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.runtime-role="scanner"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/binary-scanner"]
