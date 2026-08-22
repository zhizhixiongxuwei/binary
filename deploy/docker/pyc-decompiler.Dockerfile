ARG GO_BUILD_IMAGE=golang:1.26.7-bookworm
ARG PYCDC_TOOLS_IMAGE=binaryscan/pycdc-tools:git-b428976

FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src/app/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download
COPY app/backend/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-pyc-decompiler ./cmd/pyc-decompiler

FROM ${PYCDC_TOOLS_IMAGE}
ARG BINARY_VERSION=0.1.0-dev
USER root
COPY --from=build --chmod=0555 /out/binary-pyc-decompiler /usr/local/bin/binary-pyc-decompiler
ENV HOME=/tmp TMPDIR=/tmp
LABEL org.opencontainers.image.title="BinaryScan PYC decompiler" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.runtime-role="pyc-decompiler"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/binary-pyc-decompiler"]
