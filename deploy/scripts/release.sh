#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
env_file="$repo_dir/.env"
image_lock="$repo_dir/deploy/docker/images.lock.env"

[ -f "$env_file" ] || { echo "missing $env_file" >&2; exit 1; }
[ -f "$image_lock" ] || { echo "missing $image_lock" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$env_file"
# shellcheck disable=SC1090
. "$image_lock"
set +a

checksum_create() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" > "$1.sha256"
  else
    shasum -a 256 "$1" > "$1.sha256"
  fi
}

checksum_verify() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1.sha256"
  else
    shasum -a 256 -c "$1.sha256"
  fi
}

case "${1:-}" in
  build)
    docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/app/Dockerfile" -t "$APP_IMAGE" \
      --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
      --build-arg "NODE_BUILD_IMAGE=$NODE_BUILD_IMAGE" \
      --build-arg "APP_RUNTIME_IMAGE=$APP_RUNTIME_IMAGE" \
      --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
    docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/scanner.Dockerfile" -t "$SCANNER_IMAGE" \
      --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
      --build-arg "TRIVY_RUNTIME_DB_IMAGE=$TRIVY_RUNTIME_DB_IMAGE" \
      --build-arg "ARCHIVE_TOOLS_IMAGE=$ARCHIVE_TOOLS_IMAGE" \
      --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
    docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/native-decompiler.Dockerfile" -t "$NATIVE_DECOMPILER_IMAGE" \
      --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
      --build-arg "GHIDRA_RUNTIME_IMAGE=$GHIDRA_RUNTIME_IMAGE" \
      --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
    docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/jvm-decompiler.Dockerfile" -t "$JVM_DECOMPILER_IMAGE" \
      --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
      --build-arg "JVM_TOOLS_IMAGE=$JVM_TOOLS_IMAGE" \
      --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
    docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/pyc-decompiler.Dockerfile" -t "$PYC_DECOMPILER_IMAGE" \
      --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
      --build-arg "PYCDC_TOOLS_IMAGE=$PYCDC_TOOLS_IMAGE" \
      --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
    docker build --platform "$BINARY_PLATFORM" -t "$C_CHECKER_IMAGE" \
      --build-arg "JAVA_BUILD_IMAGE=$JAVA_BUILD_IMAGE" \
      --build-arg "JAVA_RUNTIME_IMAGE=$JAVA_RUNTIME_IMAGE" "$repo_dir/checkers/c"
    docker build --platform "$BINARY_PLATFORM" -t "$JAVA_CHECKER_IMAGE" \
      --build-arg "JAVA_BUILD_IMAGE=$JAVA_BUILD_IMAGE" \
      --build-arg "JAVA_RUNTIME_IMAGE=$JAVA_RUNTIME_IMAGE" "$repo_dir/checkers/java"
    docker build --platform "$BINARY_PLATFORM" -t "$PYTHON_CHECKER_IMAGE" \
      --build-arg "PYTHON_RUNTIME_IMAGE=$PYTHON_RUNTIME_IMAGE" "$repo_dir/checkers/python"
    ;;
  package)
    output=${2:-"$repo_dir/binary-runtime-${BINARY_VERSION}-${BINARY_PLATFORM##*/}.tar"}
    docker image inspect "$MYSQL_IMAGE" >/dev/null
    docker save -o "$output" \
      "$MYSQL_IMAGE" "$APP_IMAGE" "$SCANNER_IMAGE" \
      "$NATIVE_DECOMPILER_IMAGE" "$JVM_DECOMPILER_IMAGE" "$PYC_DECOMPILER_IMAGE" \
      "$C_CHECKER_IMAGE" "$JAVA_CHECKER_IMAGE" "$PYTHON_CHECKER_IMAGE"
    checksum_create "$output"
    echo "created $output"
    ;;
  load)
    archive=${2:?usage: release.sh load ARCHIVE.tar}
    checksum_verify "$archive"
    docker load -i "$archive"
    ;;
  *)
    echo "usage: $0 {build|package [FILE]|load FILE}" >&2
    exit 2
    ;;
esac
