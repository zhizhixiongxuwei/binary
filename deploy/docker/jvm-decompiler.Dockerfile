ARG GO_BUILD_IMAGE=golang:1.26.7-bookworm
ARG JVM_TOOLS_IMAGE=binaryscan/java-runtime:21-vf1.12.0-cfr0.152-jadx1.5.6
ARG JAVA_BUILD_IMAGE=public.ecr.aws/docker/library/maven:3.9.11-eclipse-temurin-21

FROM ${JVM_TOOLS_IMAGE} AS jvm-tools

FROM ${JAVA_BUILD_IMAGE} AS mapping-build
WORKDIR /src
COPY --from=jvm-tools /opt/bytecode-tools/vineflower/vineflower.jar ./vineflower.jar
COPY app/backend/tools/vineflower/ExportVineflowerSource.java ./
RUN mkdir classes && javac --release 21 -cp vineflower.jar -d classes ExportVineflowerSource.java \
    && jar --create --file binaryscan-mapping.jar -C classes .

FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src/app/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download
COPY app/backend/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-jvm-decompiler ./cmd/jvm-decompiler

FROM jvm-tools
ARG BINARY_VERSION=0.1.0-dev
USER root
COPY --from=build --chmod=0555 /out/binary-jvm-decompiler /usr/local/bin/binary-jvm-decompiler
COPY --from=mapping-build --chmod=0444 /src/binaryscan-mapping.jar /opt/bytecode-tools/vineflower/binaryscan-mapping.jar
ENV HOME=/tmp TMPDIR=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8
LABEL org.opencontainers.image.title="BinaryScan JVM decompiler" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.runtime-role="jvm-decompiler"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/binary-jvm-decompiler"]
