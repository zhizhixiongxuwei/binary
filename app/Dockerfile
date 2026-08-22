# syntax=docker/dockerfile:1.7

ARG NODE_BUILD_IMAGE=node:22.19.0-bookworm-slim
ARG GO_BUILD_IMAGE=golang:1.25.0-bookworm
ARG APP_RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${NODE_BUILD_IMAGE} AS frontend-build
WORKDIR /src/app/frontend
COPY app/frontend/package.json app/frontend/package-lock.json ./
RUN npm ci
COPY app/frontend/ ./
RUN npm run build

FROM ${GO_BUILD_IMAGE} AS backend-build
WORKDIR /src/app/backend
COPY app/backend/go.mod app/backend/go.sum ./
RUN go mod download
COPY app/backend/ ./
RUN rm -rf internal/webui/dist && mkdir -p internal/webui/dist
COPY --from=frontend-build /src/app/frontend/dist/ ./internal/webui/dist/
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/binary-app ./cmd/app

FROM ${APP_RUNTIME_IMAGE}
ARG BINARY_VERSION=0.1.0-dev
LABEL org.opencontainers.image.title="BinaryScan app" \
      org.opencontainers.image.version="${BINARY_VERSION}" \
      com.binaryscan.product="binaryscan" \
      com.binaryscan.runtime-role="app"
COPY --from=backend-build --chmod=0555 /out/binary-app /usr/local/bin/binary-app
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/binary-app"]
