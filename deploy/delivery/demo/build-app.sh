#!/bin/sh
set -eu

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
app_root="$bundle_root/app"
env_file="$bundle_root/.env"
evidence_root="$bundle_root/build-output"

die() {
  echo "error: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    die "sha256sum or shasum is required"
  fi
}

tree_digest() {
  tree=$1
  output=$2
  (
    cd "$tree"
    find . -type f | LC_ALL=C sort | while IFS= read -r file; do
      sha256_file "$file"
    done
  ) > "$output"
  sha256_file "$output" | awk '{print $1}'
}

[ -f "$env_file" ] || die "missing $env_file"
[ -f "$app_root/Dockerfile" ] || die "missing app/Dockerfile"
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

APP_BUILD_DEPS_IMAGE=${APP_BUILD_DEPS_IMAGE:-binaryscan/app-build-deps:0.1.0-dev}
GO_BUILD_IMAGE=${GO_BUILD_IMAGE:-public.ecr.aws/docker/library/golang:1.26.7-bookworm}
NODE_BUILD_IMAGE=${NODE_BUILD_IMAGE:-public.ecr.aws/docker/library/node:22.19.0-bookworm-slim}
APP_RUNTIME_IMAGE=${APP_RUNTIME_IMAGE:-gcr.io/distroless/static-debian12:nonroot}

mkdir -p "$evidence_root"
timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
source_manifest="$evidence_root/source-$timestamp.sha256"
source_sha=$(tree_digest "$app_root" "$source_manifest")

dependency_manifest="$evidence_root/dependencies-$timestamp.sha256"
(
  cd "$app_root"
  for file in backend/go.mod backend/go.sum frontend/package.json frontend/package-lock.json; do
    sha256_file "$file"
  done
) > "$dependency_manifest"
dependency_sha=$(sha256_file "$dependency_manifest" | awk '{print $1}')

for image in "$APP_BUILD_DEPS_IMAGE" "$GO_BUILD_IMAGE" "$NODE_BUILD_IMAGE" "$APP_RUNTIME_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 ||
    die "offline build image is not loaded: $image (run ./load-images.sh)"
done

cached_dependency_sha=$(docker image inspect \
  --format '{{index .Config.Labels "com.binaryscan.dependency-lock-sha256"}}' \
  "$APP_BUILD_DEPS_IMAGE")
[ "$cached_dependency_sha" = "$dependency_sha" ] ||
  die "dependency lock files changed; the sealed offline dependency image no longer matches"

echo "building $APP_IMAGE from source digest $source_sha with networking disabled"
docker build \
  --platform "$BINARY_PLATFORM" \
  --network=none \
  --pull=false \
  --provenance=false \
  --progress=plain \
  -f "$app_root/Dockerfile" \
  -t "$APP_IMAGE" \
  --build-arg "APP_BUILD_DEPS_IMAGE=$APP_BUILD_DEPS_IMAGE" \
  --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
  --build-arg "NODE_BUILD_IMAGE=$NODE_BUILD_IMAGE" \
  --build-arg "APP_RUNTIME_IMAGE=$APP_RUNTIME_IMAGE" \
  --build-arg "BINARY_VERSION=$BINARY_VERSION" \
  --build-arg "SOURCE_SHA256=$source_sha" \
  --build-arg "DEPENDENCY_LOCK_SHA256=$dependency_sha" \
  "$app_root"

image_id=$(docker image inspect --format '{{.Id}}' "$APP_IMAGE")
platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$APP_IMAGE")
evidence="$evidence_root/app-build-$timestamp.txt"
{
  printf 'built_at_utc=%s\n' "$timestamp"
  printf 'app_image=%s\n' "$APP_IMAGE"
  printf 'image_id=%s\n' "$image_id"
  printf 'platform=%s\n' "$platform"
  printf 'source_sha256=%s\n' "$source_sha"
  printf 'dependency_lock_sha256=%s\n' "$dependency_sha"
  printf 'network=none\n'
  printf 'dockerfile=app/Dockerfile\n'
} > "$evidence"

echo "built image: $APP_IMAGE"
echo "evidence: $evidence"
echo "apply it with: ./manage.sh restart-app"
