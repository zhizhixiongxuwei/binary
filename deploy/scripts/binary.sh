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
    "$BINARY_DATA_ROOT/work/pyc-decompiler"; do
    [ -d "$directory" ] || die "required data directory is missing: $directory"
    [ ! -L "$directory" ] || die "data directory must not be a symlink: $directory"
  done

  require_product_access "$BINARY_DATA_ROOT" 5 "data root $BINARY_DATA_ROOT"
  require_product_access "$BINARY_DATA_ROOT/storage" 7 "storage root"
  require_product_access "$BINARY_DATA_ROOT/storage/projects" 7 "project storage root"
  require_product_access "$BINARY_DATA_ROOT/work" 7 "work root"

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

validate_http() {
  case "$PUBLIC_BASE_URL" in
    http://*) ;;
    *) die "PUBLIC_BASE_URL must use http" ;;
  esac
  public_authority=${PUBLIC_BASE_URL#http://}
  case "$public_authority" in
    ""|*@*|*/*|*'?'*|*'#'*) die "PUBLIC_BASE_URL must contain only host and optional port" ;;
  esac
  printf '%s' "$APP_ALLOWED_ORIGINS" | tr ',' '\n' | grep -Fqx "$PUBLIC_BASE_URL" ||
    die "APP_ALLOWED_ORIGINS must include PUBLIC_BASE_URL exactly"
  case "$APP_PORT" in
    ""|*[!0-9]*) die "APP_PORT must be numeric" ;;
  esac
  [ "$APP_PORT" -ge 1 ] && [ "$APP_PORT" -le 65535 ] || die "APP_PORT must be between 1 and 65535"
  [ "$APP_LISTEN_ADDR" = ":8080" ] || die "APP_LISTEN_ADDR must remain :8080"
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
    "$BINARY_DATA_ROOT/work/pyc-decompiler"

  if [ "$(id -u)" -eq 0 ]; then
    chown "$PRODUCT_UID:$PRODUCT_GID" "$BINARY_DATA_ROOT"
    chown -R "$PRODUCT_UID:$PRODUCT_GID" \
      "$BINARY_DATA_ROOT/storage" \
      "$BINARY_DATA_ROOT/work"
  fi
  chmod 0750 "$BINARY_DATA_ROOT" \
    "$BINARY_DATA_ROOT/storage" \
    "$BINARY_DATA_ROOT/work"
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
  validate_http
  docker compose --project-directory "$repo_dir" --env-file "$env_file" \
    -f "$repo_dir/docker-compose.yml" config --quiet
  validate_images
  echo "configuration is valid"
}

compose() {
  load_env
  docker compose --project-directory "$repo_dir" --env-file "$env_file" \
    -f "$repo_dir/docker-compose.yml" "$@"
}

case "${1:-}" in
  init) init_data ;;
  doctor) doctor ;;
  up)
    shift
    [ "$#" -eq 0 ] || die "up does not accept service names or Compose options"
    doctor
    compose up --pull never --remove-orphans --wait
    ;;
  down) shift; compose down "$@" ;;
  status) shift; compose ps "$@" ;;
  logs) shift; compose logs "$@" ;;
  *)
    echo "usage: $0 {init|doctor|up|down|status|logs}" >&2
    exit 2
    ;;
esac
