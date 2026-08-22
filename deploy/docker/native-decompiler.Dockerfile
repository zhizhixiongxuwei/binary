ARG GO_BUILD_IMAGE=golang:1.25.0-bookworm
ARG GHIDRA_RUNTIME_IMAGE=binaryscan/ghidra-runtime:12.1.2-jdk21

FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src/app/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download
COPY app/backend/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-native-decompiler ./cmd/native-decompiler

FROM ${GHIDRA_RUNTIME_IMAGE}
ARG BINARY_VERSION=0.1.0-dev
USER root
COPY --from=build --chmod=0555 /out/binary-native-decompiler /usr/local/bin/binary-native-decompiler
RUN install -d -m 0555 /opt/binaryscan/ghidra
COPY --chmod=0444 app/backend/tools/ghidra/ExportPseudoC.java /opt/binaryscan/ghidra/ExportPseudoC.java
ENV HOME=/tmp TMPDIR=/tmp
LABEL org.opencontainers.image.title="BinaryScan native decompiler" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.runtime-role="native-decompiler"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/binary-native-decompiler"]
