ARG NODE_BUILD_IMAGE=public.ecr.aws/docker/library/node:22.19.0-bookworm-slim
ARG GO_BUILD_IMAGE=public.ecr.aws/docker/library/golang:1.26.7-bookworm

FROM ${NODE_BUILD_IMAGE} AS frontend-deps
WORKDIR /src/frontend
COPY app/frontend/package.json app/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund && npm cache clean --force

FROM ${GO_BUILD_IMAGE} AS backend-deps
WORKDIR /src/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download

FROM scratch
ARG DEPENDENCY_LOCK_SHA256
LABEL org.opencontainers.image.title="BinaryScan app offline build dependencies" \
      com.binaryscan.dependency-role="app-build" \
      com.binaryscan.dependency-lock-sha256="${DEPENDENCY_LOCK_SHA256}"
COPY --from=frontend-deps /src/frontend/node_modules /opt/frontend/node_modules
COPY --from=backend-deps /go/pkg/mod /go/pkg/mod
