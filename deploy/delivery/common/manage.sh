#!/bin/sh
set -eu

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
env_file="$bundle_root/.env"
compose_file="$bundle_root/docker-compose.yml"
data_root="$bundle_root/data"
sentinel="$data_root/.binaryscan-data-root"

die() {
  echo "error: $*" >&2
  exit 1
}

load_env() {
  [ -f "$env_file" ] || die "missing $env_file"
  [ ! -L "$env_file" ] || die "$env_file must not be a symlink"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
  [ "${BINARY_DATA_ROOT:-}" = "./data" ] ||
    die "BINARY_DATA_ROOT must remain ./data in this sealed delivery"
  BINARY_DATA_ROOT=$data_root
  export BINARY_DATA_ROOT
}

compose() {
  docker compose --project-directory "$bundle_root" --env-file "$env_file" \
    -f "$compose_file" "$@"
}

require_linux_root() {
  if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" -ne 0 ]; then
    die "this initialization operation needs root on Linux; rerun with sudo"
  fi
}

validate_data_target() {
  [ "$data_root" != "/" ] || die "refusing root directory as data target"
  [ "$data_root" = "$bundle_root/data" ] || die "unexpected data target: $data_root"
  [ ! -L "$data_root" ] || die "data directory must not be a symlink"
  if [ -e "$data_root" ]; then
    [ -d "$data_root" ] || die "data target is not a directory: $data_root"
  fi
}

validate_sentinel() {
  [ -f "$sentinel" ] || die "data sentinel is missing; refusing destructive operation"
  [ ! -L "$sentinel" ] || die "data sentinel must not be a symlink"
  expected="binaryscan-data:${COMPOSE_PROJECT_NAME}"
  actual=$(sed -n '1p' "$sentinel")
  [ "$actual" = "$expected" ] || die "data sentinel does not match this delivery"
}

init_data() {
  load_env
  validate_data_target
  require_linux_root
  : "${PRODUCT_UID:?PRODUCT_UID is required}"
  : "${PRODUCT_GID:?PRODUCT_GID is required}"
  : "${COMPOSE_PROJECT_NAME:?COMPOSE_PROJECT_NAME is required}"

  if [ -d "$data_root" ] && [ ! -f "$sentinel" ] &&
     [ -n "$(find "$data_root" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    die "$data_root is non-empty and has no delivery sentinel"
  fi

  umask 077
  mkdir -p \
    "$data_root/mysql" \
    "$data_root/storage/uploads" \
    "$data_root/storage/blobs" \
    "$data_root/storage/artifacts" \
    "$data_root/storage/projects/native" \
    "$data_root/storage/projects/jvm" \
    "$data_root/storage/projects/pyc" \
    "$data_root/storage/reports" \
    "$data_root/work/scanner" \
    "$data_root/work/native-decompiler" \
    "$data_root/work/jvm-decompiler" \
    "$data_root/work/pyc-decompiler"
  printf 'binaryscan-data:%s\n' "$COMPOSE_PROJECT_NAME" > "$sentinel"

  if [ "$(id -u)" -eq 0 ]; then
    chown "$PRODUCT_UID:$PRODUCT_GID" "$data_root"
    chown -R "$PRODUCT_UID:$PRODUCT_GID" "$data_root/storage" "$data_root/work"
  fi
  chmod 0750 "$data_root" "$data_root/storage" "$data_root/work"
  chmod 0600 "$env_file"
  echo "initialized mutable data at $data_root"
}

validate_images() {
  expected_os=${BINARY_PLATFORM%%/*}
  expected_arch=${BINARY_PLATFORM#*/}
  expected_arch=${expected_arch%%/*}
  [ -n "$expected_os" ] && [ -n "$expected_arch" ] || die "invalid BINARY_PLATFORM"

  for image in \
    "$MYSQL_IMAGE" \
    "$APP_IMAGE" \
    "$SCANNER_IMAGE" \
    "$NATIVE_DECOMPILER_IMAGE" \
    "$JVM_DECOMPILER_IMAGE" \
    "$PYC_DECOMPILER_IMAGE" \
    "$C_CHECKER_IMAGE" \
    "$JAVA_CHECKER_IMAGE" \
    "$PYTHON_CHECKER_IMAGE"; do
    actual=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image" 2>/dev/null) ||
      die "required image is not loaded: $image (run ./load-images.sh)"
    [ "$actual" = "$expected_os/$expected_arch" ] ||
      die "platform mismatch for $image: expected $expected_os/$expected_arch, got $actual"
  done
}

doctor() {
  load_env
  validate_data_target
  validate_sentinel
  [ -d "$data_root/mysql" ] || die "data is not initialized; run ./manage.sh init"
  docker version >/dev/null
  docker compose version >/dev/null
  docker compose --project-directory "$bundle_root" --env-file "$env_file" \
    -f "$compose_file" config --quiet
  validate_images
  echo "configuration, data layout, and nine runtime images are valid"
}

start() {
  load_env
  if [ ! -f "$sentinel" ]; then
    init_data
  fi
  doctor
  compose up -d --pull never --remove-orphans --wait
}

reset_and_start() {
  [ "${1:-}" = "--yes" ] && [ "$#" -eq 1 ] ||
    die "reset permanently deletes all mounted data; run: ./manage.sh reset --yes"
  load_env
  validate_data_target
  validate_sentinel
  require_linux_root
  compose down --remove-orphans
  find "$data_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  init_data
  doctor
  compose up -d --pull never --remove-orphans --wait
}

case "${1:-}" in
  init)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh init"
    init_data
    ;;
  doctor)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh doctor"
    doctor
    ;;
  start)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh start"
    start
    ;;
  stop)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh stop"
    load_env
    compose stop
    ;;
  restart)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh restart"
    doctor
    compose up -d --pull never --remove-orphans --force-recreate --wait
    ;;
  restart-app)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh restart-app"
    doctor
    compose up -d --pull never --no-deps --force-recreate --wait app
    ;;
  down)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh down"
    load_env
    compose down --remove-orphans
    ;;
  reset)
    shift
    reset_and_start "$@"
    ;;
  status)
    [ "$#" -eq 1 ] || die "usage: ./manage.sh status"
    load_env
    compose ps
    ;;
  logs)
    shift
    load_env
    compose logs "$@"
    ;;
  *)
    echo "usage: ./manage.sh {init|doctor|start|stop|restart|restart-app|down|reset --yes|status|logs}" >&2
    exit 2
    ;;
esac
