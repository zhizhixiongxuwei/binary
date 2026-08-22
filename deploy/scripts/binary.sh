#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
env_file="$repo_dir/.env"

die() {
  echo "error: $*" >&2
  exit 1
}

load_env() {
  [ -f "$env_file" ] || die "missing $env_file"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
}

validate_data_root() {
  case "${BINARY_DATA_ROOT:-}" in
    ""|/|"$repo_dir"|"$repo_dir"/*|*".."*) die "unsafe BINARY_DATA_ROOT: ${BINARY_DATA_ROOT:-empty}" ;;
  esac
  [ ! -L "$BINARY_DATA_ROOT" ] || die "data root must not be a symlink"
}

init_data() {
  load_env
  validate_data_root
  : "${PRODUCT_UID:?PRODUCT_UID is required}"
  : "${PRODUCT_GID:?PRODUCT_GID is required}"

  if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" -ne 0 ]; then
    die "Linux data initialization must run as root: sudo deploy/scripts/binary.sh init"
  fi

  umask 077
  mkdir -p \
    "$BINARY_DATA_ROOT/mysql" \
    "$BINARY_DATA_ROOT/storage/uploads" \
    "$BINARY_DATA_ROOT/storage/blobs" \
    "$BINARY_DATA_ROOT/storage/artifacts" \
    "$BINARY_DATA_ROOT/storage/projects/native" \
    "$BINARY_DATA_ROOT/storage/projects/jvm" \
    "$BINARY_DATA_ROOT/storage/projects/pyc" \
    "$BINARY_DATA_ROOT/storage/reports" \
    "$BINARY_DATA_ROOT/work/scanner" \
    "$BINARY_DATA_ROOT/work/native-decompiler" \
    "$BINARY_DATA_ROOT/work/jvm-decompiler" \
    "$BINARY_DATA_ROOT/work/pyc-decompiler" \
    "$BINARY_DATA_ROOT/tls"

  if [ "$(id -u)" -eq 0 ]; then
    chown "$PRODUCT_UID:$PRODUCT_GID" "$BINARY_DATA_ROOT"
    chown -R "$PRODUCT_UID:$PRODUCT_GID" \
      "$BINARY_DATA_ROOT/storage" \
      "$BINARY_DATA_ROOT/work" \
      "$BINARY_DATA_ROOT/tls"
  fi
  chmod 0750 "$BINARY_DATA_ROOT" \
    "$BINARY_DATA_ROOT/storage" \
    "$BINARY_DATA_ROOT/work" \
    "$BINARY_DATA_ROOT/tls"
  chmod 0600 "$env_file"
  echo "initialized $BINARY_DATA_ROOT"
}

doctor() {
  load_env
  validate_data_root
  [ -d "$BINARY_DATA_ROOT" ] || die "run: deploy/scripts/binary.sh init"
  docker compose --project-directory "$repo_dir" --env-file "$env_file" config --quiet
  echo "configuration is valid"
}

compose() {
  load_env
  docker compose --project-directory "$repo_dir" --env-file "$env_file" "$@"
}

case "${1:-}" in
  init) init_data ;;
  doctor) doctor ;;
  up) shift; compose up --pull never --wait "$@" ;;
  down) shift; compose down "$@" ;;
  status) shift; compose ps "$@" ;;
  logs) shift; compose logs "$@" ;;
  *)
    echo "usage: $0 {init|doctor|up|down|status|logs}" >&2
    exit 2
    ;;
esac
