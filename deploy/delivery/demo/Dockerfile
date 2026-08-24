ARG APP_BUILD_DEPS_IMAGE=binaryscan/app-build-deps:0.1.0-dev
ARG NODE_BUILD_IMAGE=public.ecr.aws/docker/library/node:22.19.0-bookworm-slim
ARG GO_BUILD_IMAGE=public.ecr.aws/docker/library/golang:1.26.7-bookworm
ARG APP_RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${APP_BUILD_DEPS_IMAGE} AS app-build-deps

FROM ${NODE_BUILD_IMAGE} AS frontend-build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
COPY --from=app-build-deps /opt/frontend/node_modules ./node_modules
COPY frontend/ ./
RUN npm run build

FROM ${GO_BUILD_IMAGE} AS backend-build
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
COPY --from=app-build-deps /go/pkg/mod /go/pkg/mod
ENV GOPROXY=off GOSUMDB=off
COPY backend/ ./
RUN rm -rf internal/webui/dist && mkdir -p internal/webui/dist
COPY --from=frontend-build /src/frontend/dist/ ./internal/webui/dist/
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-app ./cmd/app

FROM ${APP_RUNTIME_IMAGE}
ARG BINARY_VERSION=0.1.0-dev
ARG SOURCE_SHA256=unknown
ARG DEPENDENCY_LOCK_SHA256=unknown
LABEL org.opencontainers.image.title="BinaryScan app" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="app" \
      com.binaryscan.source-sha256="${SOURCE_SHA256}" \
      com.binaryscan.dependency-lock-sha256="${DEPENDENCY_LOCK_SHA256}"
COPY --from=backend-build --chmod=0555 /out/binary-app /usr/local/bin/binary-app
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/binary-app"]
