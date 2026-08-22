# syntax=docker/dockerfile:1.7
ARG GO_BUILD_IMAGE=golang:1.25.0-bookworm
ARG JVM_TOOLS_IMAGE=binaryscan/java-runtime:21-tools20260807

FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src/app/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download
COPY app/backend/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-jvm-decompiler ./cmd/jvm-decompiler

FROM ${JVM_TOOLS_IMAGE}
ARG BINARY_VERSION=0.1.0-dev
USER root
COPY --from=build --chmod=0555 /out/binary-jvm-decompiler /usr/local/bin/binary-jvm-decompiler
ENV HOME=/tmp TMPDIR=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8
LABEL org.opencontainers.image.title="BinaryScan JVM decompiler" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.runtime-role="jvm-decompiler"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/binary-jvm-decompiler"]
