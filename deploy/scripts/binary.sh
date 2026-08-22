#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
env_file="$repo_dir/.env"

die() {
  echo "error: $*" >&2
  exit 1
}

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

file_owner() {
  if stat -f '%u:%g' "$1" >/dev/null 2>&1; then
    stat -f '%u:%g' "$1"
  else
    stat -c '%u:%g' "$1"
  fi
}

permission_digit() {
  permission_path=$1
  mode=$(file_mode "$permission_path")
  mode=$(printf '%s\n' "$mode" | sed 's/.*\(...\)$/\1/')
  owner=$(file_owner "$permission_path")
  owner_uid=${owner%%:*}
  owner_gid=${owner#*:}
  if [ "$owner_uid" = "$PRODUCT_UID" ]; then
    printf '%s\n' "$mode" | cut -c 1
  elif [ "$owner_gid" = "$PRODUCT_GID" ]; then
    printf '%s\n' "$mode" | cut -c 2
  else
    printf '%s\n' "$mode" | cut -c 3
  fi
}

require_product_access() {
  access_path=$1
  required=$2
  description=$3
  if [ "$(uname -s)" = "Darwin" ]; then
    case "$required" in
      4) [ -r "$access_path" ] ;;
      5) [ -r "$access_path" ] && [ -x "$access_path" ] ;;
      7) [ -r "$access_path" ] && [ -w "$access_path" ] && [ -x "$access_path" ] ;;
      *) die "unsupported access check for $description" ;;
    esac || die "$description is not accessible"
    return
  fi
  digit=$(permission_digit "$access_path")
  case "$digit" in
    [0-7]) ;;
    *) die "cannot determine permissions for $description" ;;
  esac
  [ $((digit & required)) -eq "$required" ] ||
    die "$description is not accessible to PRODUCT_UID:PRODUCT_GID"
}

reject_placeholder() {
  name=$1
  value=$2
  normalized=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')
  case "$normalized" in
    *example*|*placeholder*|*changeme*|*your-domain*|*.invalid*)
      die "$name still contains a deployment placeholder"
      ;;
  esac
}

tls_host_path() {
  container_path=$1
  case "$container_path" in
    /run/binary/tls/*)
      relative=${container_path#/run/binary/tls/}
      case "$relative" in
        ""|.|..|*/*) die "TLS files must be direct children of /run/binary/tls" ;;
      esac
      printf '%s/tls/%s\n' "$BINARY_DATA_ROOT" "$relative"
      ;;
    *) die "TLS files must be below /run/binary/tls" ;;
  esac
}

validate_env_permissions() {
  [ ! -L "$env_file" ] || die "$env_file must not be a symlink"
  mode=$(file_mode "$env_file")
  mode=$(printf '%s\n' "$mode" | sed 's/.*\(...\)$/\1/')
  case "$mode" in
    [0-7]00) ;;
    *) die "$env_file must not be accessible by group or other users" ;;
  esac
}

validate_data_layout() {
  for directory in \
    "$BINARY_DATA_ROOT/storage" \
    "$BINARY_DATA_ROOT/mysql" \
    "$BINARY_DATA_ROOT/storage/uploads" \
    "$BINARY_DATA_ROOT/storage/blobs" \
    "$BINARY_DATA_ROOT/storage/artifacts" \
    "$BINARY_DATA_ROOT/storage/projects" \
    "$BINARY_DATA_ROOT/storage/projects/native" \
    "$BINARY_DATA_ROOT/storage/projects/jvm" \
    "$BINARY_DATA_ROOT/storage/projects/pyc" \
    "$BINARY_DATA_ROOT/storage/reports" \
    "$BINARY_DATA_ROOT/work" \
    "$BINARY_DATA_ROOT/work/scanner" \
    "$BINARY_DATA_ROOT/work/native-decompiler" \
    "$BINARY_DATA_ROOT/work/jvm-decompiler" \
    "$BINARY_DATA_ROOT/work/pyc-decompiler" \
    "$BINARY_DATA_ROOT/tls"; do
    [ -d "$directory" ] || die "required data directory is missing: $directory"
    [ ! -L "$directory" ] || die "data directory must not be a symlink: $directory"
  done

  require_product_access "$BINARY_DATA_ROOT" 5 "data root $BINARY_DATA_ROOT"
  require_product_access "$BINARY_DATA_ROOT/storage" 7 "storage root"
  require_product_access "$BINARY_DATA_ROOT/storage/projects" 7 "project storage root"
  require_product_access "$BINARY_DATA_ROOT/work" 7 "work root"
  require_product_access "$BINARY_DATA_ROOT/tls" 5 "TLS directory"

  for directory in \
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
    "$BINARY_DATA_ROOT/work/pyc-decompiler"; do
    require_product_access "$directory" 7 "data directory $directory"
  done
}

validate_tls() {
  case "$APP_TLS_MODE" in
    direct)
      case "$PUBLIC_BASE_URL" in
        https://*) ;;
        *) die "direct TLS requires an https PUBLIC_BASE_URL" ;;
      esac
      cert_file=$(tls_host_path "$APP_TLS_CERT_FILE")
      key_file=$(tls_host_path "$APP_TLS_KEY_FILE")
      [ -f "$cert_file" ] && [ ! -L "$cert_file" ] || die "direct TLS certificate is missing or unsafe"
      [ -f "$key_file" ] && [ ! -L "$key_file" ] || die "direct TLS private key is missing or unsafe"
      require_product_access "$cert_file" 4 "direct TLS certificate"
      require_product_access "$key_file" 4 "direct TLS private key"
      key_mode=$(file_mode "$key_file")
      key_mode=$(printf '%s\n' "$key_mode" | sed 's/.*\(...\)$/\1/')
      key_group=$(printf '%s\n' "$key_mode" | cut -c 2)
      key_other=$(printf '%s\n' "$key_mode" | cut -c 3)
      case "$key_group:$key_other" in
        0:0|4:0)
          if [ "$key_group" = 4 ]; then
            key_owner=$(file_owner "$key_file")
            [ "${key_owner#*:}" = "$PRODUCT_GID" ] ||
              die "group-readable TLS private key must use PRODUCT_GID"
          fi
          ;;
        *) die "TLS private key must not be writable/executable by group or accessible by other users" ;;
      esac
      ;;
    proxy)
      case "$PUBLIC_BASE_URL" in
        https://*) ;;
        *) die "proxy TLS mode requires an https PUBLIC_BASE_URL" ;;
      esac
      [ -n "${APP_TRUSTED_PROXY_CIDRS:-}" ] || die "proxy TLS mode requires APP_TRUSTED_PROXY_CIDRS"
      trusted_proxy_cidrs=$(printf '%s' "$APP_TRUSTED_PROXY_CIDRS" | tr -d '[:space:]')
      case ",${trusted_proxy_cidrs}," in
        *,0.0.0.0/0,*|*,::/0,*) die "trusted proxy CIDRs must not trust every address" ;;
      esac
      ;;
    http) die "production doctor requires direct or proxy TLS mode" ;;
    *) die "unsupported APP_TLS_MODE" ;;
  esac
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
      die "required production image is not loaded: $image"
    [ "$actual" = "$expected_os/$expected_arch" ] ||
      die "image platform mismatch for $image: expected $expected_os/$expected_arch, found $actual"
  done
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
    /*) ;;
    *) die "BINARY_DATA_ROOT must be an absolute path" ;;
  esac
  case "$BINARY_DATA_ROOT" in
    /|*".."*) die "unsafe BINARY_DATA_ROOT: $BINARY_DATA_ROOT" ;;
  esac
  [ ! -L "$BINARY_DATA_ROOT" ] || die "data root must not be a symlink"
  data_parent=$(dirname -- "$BINARY_DATA_ROOT")
  data_name=$(basename -- "$BINARY_DATA_ROOT")
  [ -d "$data_parent" ] || die "data root parent does not exist: $data_parent"
  data_parent=$(CDPATH= cd -- "$data_parent" && pwd -P)
  BINARY_DATA_ROOT=$data_parent/$data_name
  export BINARY_DATA_ROOT
  case "$BINARY_DATA_ROOT" in
    "$repo_dir"|"$repo_dir"/*) die "data root must not be inside the Git repository" ;;
  esac
  case "$repo_dir" in
    "$BINARY_DATA_ROOT"/*) die "data root must not contain the Git repository" ;;
  esac
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
  validate_env_permissions
  reject_placeholder PUBLIC_BASE_URL "$PUBLIC_BASE_URL"
  reject_placeholder APP_ALLOWED_ORIGINS "$APP_ALLOWED_ORIGINS"
  validate_data_layout
  validate_tls
  docker compose --project-directory "$repo_dir" --env-file "$env_file" config --quiet
  validate_images
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
