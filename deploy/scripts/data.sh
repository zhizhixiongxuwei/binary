#!/bin/sh
set -eu
umask 077

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
env_file="$repo_dir/.env"
marker_name=.binaryscan-data-root
marker_value=binaryscan-data-root-v1
bundle_format=binaryscan-data-backup-v1
writer_services="app scanner native-decompiler jvm-decompiler pyc-decompiler"

operation_temp=
operation_lock=
resume_writer_services=
drill_active=0
drill_target=
drill_project=
drill_port=
target_existed=0

die() {
  echo "error: $*" >&2
  exit 1
}

compose() {
  docker compose --project-directory "$repo_dir" --env-file "$env_file" \
    -f "$repo_dir/docker-compose.yml" "$@"
}

drill_compose() {
  (
    export BINARY_DATA_ROOT="$drill_target"
    export COMPOSE_PROJECT_NAME="$drill_project"
    export APP_BIND_IP=127.0.0.1
    export APP_HTTPS_PORT="$drill_port"
    export APP_LISTEN_ADDR=:8443
    export APP_TLS_MODE=http
    export PUBLIC_BASE_URL="http://127.0.0.1:$drill_port"
    export APP_ALLOWED_ORIGINS="http://127.0.0.1:$drill_port"
    docker compose --project-directory "$repo_dir" --env-file "$env_file" \
      -f "$repo_dir/docker-compose.yml" "$@"
  )
}

cleanup() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM

  if [ "$drill_active" -eq 1 ]; then
    if ! drill_compose down --remove-orphans; then
      echo "warning: failed to stop restore-drill project $drill_project" >&2
      cleanup_status=1
    fi
    drill_active=0
  fi

  if [ -n "$resume_writer_services" ]; then
    # The values come only from the fixed writer_services list above.
    # shellcheck disable=SC2086
    if ! compose start $resume_writer_services; then
      echo "warning: failed to resume one or more services: $resume_writer_services" >&2
      cleanup_status=1
    fi
    resume_writer_services=
  fi

  if [ -n "$operation_temp" ] && [ -d "$operation_temp" ]; then
    rm -f \
      "$operation_temp/database.sql" \
      "$operation_temp/database.sql.stderr" \
      "$operation_temp/storage.tar" \
      "$operation_temp/manifest" \
      "$operation_temp/live-counts" \
      "$operation_temp/references.tsv"
    rmdir "$operation_temp" 2>/dev/null || true
    operation_temp=
  fi

  if [ -n "$operation_lock" ] && [ -d "$operation_lock" ]; then
    rmdir "$operation_lock" 2>/dev/null || true
    operation_lock=
  fi

  exit "$cleanup_status"
}

signal_exit() {
  exit 130
}

trap cleanup EXIT
trap signal_exit HUP INT TERM

load_env() {
  [ -f "$env_file" ] || die "missing $env_file"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a

  : "${BINARY_DATA_ROOT:?BINARY_DATA_ROOT is required}"
  : "${BINARY_VERSION:?BINARY_VERSION is required}"
  : "${MYSQL_IMAGE:?MYSQL_IMAGE is required}"
  : "${MYSQL_DATABASE:?MYSQL_DATABASE is required}"
  : "${PRODUCT_UID:?PRODUCT_UID is required}"
  : "${PRODUCT_GID:?PRODUCT_GID is required}"
  case "$MYSQL_DATABASE" in
    *[!A-Za-z0-9_]*) die "MYSQL_DATABASE must be a simple SQL identifier" ;;
  esac
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_runtime() {
  for command_name in docker tar awk grep find mktemp wc tr date sed; do
    require_command "$command_name"
  done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
  if [ "$(uname -s)" = Linux ] && [ "$(id -u)" -ne 0 ]; then
    die "Linux data operations must run as root: sudo deploy/scripts/data.sh ..."
  fi
}

canonical_existing_dir() {
  [ -d "$1" ] || return 1
  (CDPATH= cd -- "$1" && pwd -P)
}

candidate_path() {
  candidate_input=$1
  case "$candidate_input" in
    ""|*"
"*) return 1 ;;
    /*) candidate_absolute=$candidate_input ;;
    *) candidate_absolute=$PWD/$candidate_input ;;
  esac
  candidate_parent=$(dirname -- "$candidate_absolute")
  candidate_base=$(basename -- "$candidate_absolute")
  case "$candidate_base" in
    ""|.|..) return 1 ;;
  esac
  candidate_parent=$(canonical_existing_dir "$candidate_parent") || return 1
  if [ "$candidate_parent" = / ]; then
    printf '/%s\n' "$candidate_base"
  else
    printf '%s/%s\n' "$candidate_parent" "$candidate_base"
  fi
}

path_is_within() {
  path_parent=$1
  path_child=$2
  case "$path_child" in
    "$path_parent"|"$path_parent"/*) return 0 ;;
  esac
  return 1
}

paths_overlap() {
  path_is_within "$1" "$2" || path_is_within "$2" "$1"
}

validate_source_root() {
  case "$BINARY_DATA_ROOT" in
    /*) ;;
    *) die "BINARY_DATA_ROOT must be absolute" ;;
  esac
  [ ! -L "$BINARY_DATA_ROOT" ] || die "BINARY_DATA_ROOT must not be a symlink"
  source_root=$(canonical_existing_dir "$BINARY_DATA_ROOT") || die "data root does not exist: $BINARY_DATA_ROOT"
  [ "$source_root" != / ] || die "data root must not be /"
  paths_overlap "$source_root" "$repo_dir" && die "data root must not overlap the Git repository"
  [ -d "$source_root/mysql" ] && [ ! -L "$source_root/mysql" ] || die "data root mysql directory is missing or unsafe"
  [ -d "$source_root/storage" ] && [ ! -L "$source_root/storage" ] || die "data root storage directory is missing or unsafe"
  BINARY_DATA_ROOT=$source_root
  export BINARY_DATA_ROOT
}

validate_configured_root_reference() {
  case "$BINARY_DATA_ROOT" in
    /*) ;;
    *) die "BINARY_DATA_ROOT must be absolute" ;;
  esac
  [ ! -L "$BINARY_DATA_ROOT" ] || die "BINARY_DATA_ROOT must not be a symlink"
  if [ -d "$BINARY_DATA_ROOT" ]; then
    configured_root=$(canonical_existing_dir "$BINARY_DATA_ROOT") || die "cannot resolve configured data root"
  else
    [ ! -e "$BINARY_DATA_ROOT" ] || die "configured data root must be a directory"
    configured_root=$(candidate_path "$BINARY_DATA_ROOT") || die "configured data root must have an existing parent directory"
  fi
  [ "$configured_root" != / ] || die "configured data root must not be /"
  paths_overlap "$configured_root" "$repo_dir" && die "configured data root must not overlap the Git repository"
  BINARY_DATA_ROOT=$configured_root
  export BINARY_DATA_ROOT
}

ensure_source_marker() {
  marker_path="$BINARY_DATA_ROOT/$marker_name"
  if [ -e "$marker_path" ] || [ -L "$marker_path" ]; then
    [ -f "$marker_path" ] && [ ! -L "$marker_path" ] || die "invalid data-root marker: $marker_path"
    marker_contents=$(sed -n '1p' "$marker_path")
    [ "$marker_contents" = "$marker_value" ] || die "unexpected data-root marker contents"
    return
  fi
  (umask 077; printf '%s\n' "$marker_value" > "$marker_path")
}

acquire_operation_lock() {
  operation_lock="$BINARY_DATA_ROOT/.binaryscan-data-operation"
  if ! mkdir "$operation_lock" 2>/dev/null; then
    operation_lock=
    die "another data operation may be active; inspect $BINARY_DATA_ROOT/.binaryscan-data-operation"
  fi
}

validate_output_path() {
  output_path=$(candidate_path "$1") || die "backup output must have an existing parent directory"
  [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || die "backup output already exists: $output_path"
  path_is_within "$BINARY_DATA_ROOT" "$output_path" && die "backup output must be outside BINARY_DATA_ROOT"
  path_is_within "$repo_dir" "$output_path" && die "backup output must be outside the Git repository"
  return 0
}

validate_restore_target() {
  restore_input=$1
  target_existed=0
  [ ! -L "$restore_input" ] || die "restore target must not be a symlink"
  if [ -d "$restore_input" ]; then
    target_existed=1
    target_path=$(canonical_existing_dir "$restore_input") || die "cannot resolve restore target"
    first_entry=$(find "$target_path" -mindepth 1 -print -quit)
    [ -z "$first_entry" ] || die "restore target must be empty: $target_path"
  else
    [ ! -e "$restore_input" ] || die "restore target must be a directory"
    target_path=$(candidate_path "$restore_input") || die "restore target must have an existing parent directory"
  fi
  [ "$target_path" != / ] || die "restore target must not be /"
  paths_overlap "$target_path" "$repo_dir" && die "restore target must not overlap the Git repository"
  paths_overlap "$target_path" "$BINARY_DATA_ROOT" && die "restore target must not overlap the active data root"
  return 0
}

acquire_restore_target() {
  if [ "$target_existed" -eq 0 ]; then
    mkdir "$target_path" || die "restore target was created concurrently: $target_path"
  fi
  operation_lock="$target_path/.binaryscan-data-operation"
  if ! mkdir "$operation_lock" 2>/dev/null; then
    operation_lock=
    die "restore target is already in use: $target_path"
  fi
}

current_db_query() {
  current_query=$1
  compose exec -T mysql sh -eu -c '
    export MYSQL_PWD="$MYSQL_PASSWORD"
    exec mysql --protocol=TCP --host=127.0.0.1 --user="$MYSQL_USER" \
      --batch --raw --skip-column-names "$MYSQL_DATABASE" --execute="$1"
  ' binaryscan-data "$current_query"
}

drill_db_query() {
  drill_query=$1
  drill_compose exec -T mysql sh -eu -c '
    export MYSQL_PWD="$MYSQL_PASSWORD"
    exec mysql --protocol=TCP --host=127.0.0.1 --user="$MYSQL_USER" \
      --batch --raw --skip-column-names "$MYSQL_DATABASE" --execute="$1"
  ' binaryscan-data "$drill_query"
}

database_counts_sql="
SELECT CONCAT('schema_version=', COALESCE(MAX(version), 0)) FROM schema_migrations
UNION ALL SELECT CONCAT('users=', COUNT(*)) FROM users
UNION ALL SELECT CONCAT('tasks=', COUNT(*)) FROM tasks
UNION ALL SELECT CONCAT('blobs=', COUNT(*)) FROM blobs
UNION ALL SELECT CONCAT('runs=', COUNT(*)) FROM runs
UNION ALL SELECT CONCAT('jobs=', COUNT(*)) FROM jobs
UNION ALL SELECT CONCAT('source_projects=', COUNT(*)) FROM source_projects
UNION ALL SELECT CONCAT('findings=', COUNT(*)) FROM findings
UNION ALL SELECT CONCAT('run_artifacts=', COUNT(*)) FROM run_artifacts
UNION ALL SELECT CONCAT('reports=', COUNT(*)) FROM reports
UNION ALL SELECT CONCAT('audit_logs=', COUNT(*)) FROM audit_logs;
"

running_service_list() {
  compose ps --services --status running
}

enter_maintenance() {
  running_now=$(running_service_list)
  resume_writer_services=
  for service_name in $writer_services; do
    if printf '%s\n' "$running_now" | grep -qx "$service_name"; then
      resume_writer_services="$resume_writer_services $service_name"
    fi
  done
  # Stop every writer even if it was not in the running snapshot; this also
  # closes a race with containers that were still transitioning to running.
  # shellcheck disable=SC2086
  compose stop $writer_services
}

dump_database() {
  dump_path=$1
  dump_stderr=$dump_path.stderr
  if ! compose exec -T mysql sh -eu -c '
    export MYSQL_PWD="$MYSQL_PASSWORD"
    exec mysqldump --protocol=TCP --host=127.0.0.1 --user="$MYSQL_USER" \
      --single-transaction --quick --hex-blob --no-tablespaces \
      --set-gtid-purged=OFF --skip-comments \
      --skip-masking-policies --skip-add-drop-masking-policy "$MYSQL_DATABASE"
  ' > "$dump_path" 2> "$dump_stderr"; then
    [ ! -s "$dump_stderr" ] || sed 's/^/mysqldump: /' "$dump_stderr" >&2
    die "mysqldump failed"
  fi
  if grep -Fq 'mysqldump: Error:' "$dump_stderr"; then
    sed 's/^/mysqldump: /' "$dump_stderr" >&2
    die "mysqldump reported an error"
  fi
  [ ! -s "$dump_stderr" ] || sed 's/^/mysqldump: /' "$dump_stderr" >&2
  rm -f "$dump_stderr"
  [ -s "$dump_path" ] || die "mysqldump produced an empty file"
  grep -Fq 'CREATE TABLE `schema_migrations`' "$dump_path" || die "database dump does not contain schema_migrations"
}

archive_storage() {
  archive_path=$1
  symlink_entry=$(find "$BINARY_DATA_ROOT/storage" -type l -print -quit)
  [ -z "$symlink_entry" ] || die "storage contains an unsupported symbolic link: $symlink_entry"
  tar -C "$BINARY_DATA_ROOT" -cf "$archive_path" storage
  [ -s "$archive_path" ] || die "storage archive is empty"
}

manifest_value() {
  manifest_file=$1
  manifest_key=$2
  awk -v wanted="$manifest_key" '
    index($0, wanted "=") == 1 { print substr($0, length(wanted) + 2); found++ }
    END { if (found != 1) exit 1 }
  ' "$manifest_file"
}

verify_numeric_manifest_value() {
  numeric_value=$(manifest_value "$1" "$2") || die "manifest key is missing or duplicated: $2"
  case "$numeric_value" in
    ""|*[!0-9]*) die "manifest key is not numeric: $2" ;;
  esac
}

verify_bundle() {
  bundle_dir=$(canonical_existing_dir "$1") || die "backup bundle is not a directory: $1"
  [ ! -L "$1" ] || die "backup bundle must not be a symlink"
  for bundle_file in manifest database.sql storage.tar; do
    [ -f "$bundle_dir/$bundle_file" ] && [ ! -L "$bundle_dir/$bundle_file" ] || \
      die "backup bundle file is missing or unsafe: $bundle_file"
  done

  bundle_format_value=$(manifest_value "$bundle_dir/manifest" format) || die "backup manifest has no unique format"
  [ "$bundle_format_value" = "$bundle_format" ] || die "unsupported backup format: $bundle_format_value"
  for manifest_key in created_at binary_version mysql_image mysql_database; do
    manifest_value "$bundle_dir/manifest" "$manifest_key" >/dev/null || die "manifest key is missing or duplicated: $manifest_key"
  done
  for manifest_key in schema_version users tasks blobs runs jobs source_projects findings run_artifacts reports audit_logs database_bytes storage_archive_bytes; do
    verify_numeric_manifest_value "$bundle_dir/manifest" "$manifest_key"
  done

  expected_database_bytes=$(manifest_value "$bundle_dir/manifest" database_bytes)
  actual_database_bytes=$(wc -c < "$bundle_dir/database.sql" | tr -d '[:space:]')
  [ "$actual_database_bytes" = "$expected_database_bytes" ] || die "database.sql size does not match manifest"
  expected_storage_bytes=$(manifest_value "$bundle_dir/manifest" storage_archive_bytes)
  actual_storage_bytes=$(wc -c < "$bundle_dir/storage.tar" | tr -d '[:space:]')
  [ "$actual_storage_bytes" = "$expected_storage_bytes" ] || die "storage.tar size does not match manifest"
  grep -Fq 'CREATE TABLE `schema_migrations`' "$bundle_dir/database.sql" || die "database.sql is not a BinaryScan schema dump"
  tar -tf "$bundle_dir/storage.tar" >/dev/null
  tar -tf "$bundle_dir/storage.tar" | awk '
    BEGIN { entries = 0; bad = 0 }
    {
      entries++
      if ($0 != "storage" && $0 != "storage/" && index($0, "storage/") != 1) bad = 1
      if ($0 ~ /^\// || $0 ~ /(^|\/)\.\.(\/|$)/) bad = 1
    }
    END { if (entries == 0 || bad != 0) exit 1 }
  ' || die "storage.tar contains an unsafe member path"
  tar -tvf "$bundle_dir/storage.tar" | awk '
    { type = substr($0, 1, 1); if (type != "-" && type != "d") bad = 1 }
    END { if (bad != 0) exit 1 }
  ' || die "storage.tar contains links or unsupported member types"

  verified_bundle_dir=$bundle_dir
}

write_manifest() {
  manifest_path=$1
  dump_path=$2
  archive_path=$3
  {
    printf 'format=%s\n' "$bundle_format"
    printf 'created_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'binary_version=%s\n' "$BINARY_VERSION"
    printf 'mysql_image=%s\n' "$MYSQL_IMAGE"
    printf 'mysql_database=%s\n' "$MYSQL_DATABASE"
    current_db_query "$database_counts_sql"
    printf 'database_bytes=%s\n' "$(wc -c < "$dump_path" | tr -d '[:space:]')"
    printf 'storage_archive_bytes=%s\n' "$(wc -c < "$archive_path" | tr -d '[:space:]')"
  } > "$manifest_path"
}

backup_data() {
  backup_output=${1:?usage: data.sh backup OUTPUT_DIR}
  validate_source_root
  ensure_source_marker
  validate_output_path "$backup_output"
  acquire_operation_lock

  running_services=$(running_service_list)
  printf '%s\n' "$running_services" | grep -qx mysql || die "mysql must be running before backup"
  current_db_query 'SELECT 1;' >/dev/null

  output_parent=$(dirname -- "$output_path")
  output_base=$(basename -- "$output_path")
  operation_temp=$(mktemp -d "$output_parent/.${output_base}.tmp.XXXXXX")
  chmod 0700 "$operation_temp"

  echo "entering maintenance: stopping BinaryScan writers"
  enter_maintenance
  dump_database "$operation_temp/database.sql"
  archive_storage "$operation_temp/storage.tar"
  write_manifest "$operation_temp/manifest" "$operation_temp/database.sql" "$operation_temp/storage.tar"
  chmod 0600 "$operation_temp/database.sql" "$operation_temp/storage.tar" "$operation_temp/manifest"
  verify_bundle "$operation_temp"

  mv "$operation_temp" "$output_path"
  operation_temp=
  echo "backup created and verified: $output_path"
}

prepare_restore_target() {
  mkdir -p \
    "$target_path/mysql" \
    "$target_path/work/scanner" \
    "$target_path/work/native-decompiler" \
    "$target_path/work/jvm-decompiler" \
    "$target_path/work/pyc-decompiler" \
    "$target_path/tls"
  (umask 077; printf '%s\n' "$marker_value" > "$target_path/$marker_name")
  tar -C "$target_path" -xpf "$verified_bundle_dir/storage.tar"
  mkdir -p \
    "$target_path/storage/uploads" \
    "$target_path/storage/blobs" \
    "$target_path/storage/artifacts" \
    "$target_path/storage/projects/native" \
    "$target_path/storage/projects/jvm" \
    "$target_path/storage/projects/pyc" \
    "$target_path/storage/reports"

  if [ "$(uname -s)" = Linux ]; then
    chown "$PRODUCT_UID:$PRODUCT_GID" "$target_path"
    chown -R "$PRODUCT_UID:$PRODUCT_GID" \
      "$target_path/storage" "$target_path/work" "$target_path/tls"
  fi
  chmod 0750 "$target_path" "$target_path/storage" "$target_path/work" "$target_path/tls"
}

compare_restored_counts() {
  drill_db_query "$database_counts_sql" > "$operation_temp/live-counts"
  while IFS='=' read -r count_key actual_count; do
    expected_count=$(manifest_value "$verified_bundle_dir/manifest" "$count_key") || die "backup manifest is missing count: $count_key"
    [ "$actual_count" = "$expected_count" ] || die "restored $count_key count differs: expected $expected_count, got $actual_count"
  done < "$operation_temp/live-counts"
}

safe_relative_path() {
  relative_value=$1
  case "$relative_value" in
    ""|/*|*\\*) return 1 ;;
  esac
  case "/$relative_value/" in
    *"/../"*|*"/./"*) return 1 ;;
  esac
  return 0
}

verify_restored_references() {
  references_sql="
SELECT 'blob', CONCAT('storage/blobs/', storage_key), CAST(size_bytes AS CHAR)
  FROM blobs WHERE state = 'ready' AND deleted_at IS NULL
UNION ALL
SELECT 'artifact', CONCAT('storage/artifacts/', storage_key), CAST(size_bytes AS CHAR)
  FROM run_artifacts
UNION ALL
SELECT 'report', CONCAT('storage/', storage_key), ''
  FROM reports WHERE status = 'ready' AND deleted_at IS NULL
UNION ALL
SELECT 'project', CONCAT('storage/projects/', source_kind, '/', root_storage_key), CAST(file_count AS CHAR)
  FROM source_projects WHERE state = 'ready' AND deleted_at IS NULL;
"
  drill_db_query "$references_sql" > "$operation_temp/references.tsv"
  reference_count=0
  tab_character=$(printf '\t')
  while IFS="$tab_character" read -r reference_kind relative_path expected_size; do
    [ -n "$reference_kind" ] || continue
    safe_relative_path "$relative_path" || die "database contains unsafe storage path: $relative_path"
    absolute_path="$target_path/$relative_path"
    case "$reference_kind" in
      blob|artifact)
        [ -f "$absolute_path" ] && [ ! -L "$absolute_path" ] || die "restored file is missing: $relative_path"
        actual_size=$(wc -c < "$absolute_path" | tr -d '[:space:]')
        [ "$actual_size" = "$expected_size" ] || die "restored file size differs: $relative_path"
        ;;
      report)
        [ -f "$absolute_path" ] && [ ! -L "$absolute_path" ] || die "restored report is missing: $relative_path"
        ;;
      project)
        [ -d "$absolute_path" ] && [ ! -L "$absolute_path" ] || die "restored source project is missing: $relative_path"
        [ -f "$absolute_path/project.json" ] && [ ! -L "$absolute_path/project.json" ] || die "restored source project manifest is missing: $relative_path/project.json"
        actual_project_files=$(find "$absolute_path" -type f ! -name project.json | wc -l | tr -d '[:space:]')
        [ "$actual_project_files" = "$expected_size" ] || die "restored source project file count differs: $relative_path"
        ;;
      *) die "unexpected reference type: $reference_kind" ;;
    esac
    reference_count=$((reference_count + 1))
  done < "$operation_temp/references.tsv"
  echo "verified $reference_count database-to-storage references"
}

restore_drill() {
  backup_bundle=${1:?usage: data.sh restore-drill BACKUP_DIR TARGET_DATA_ROOT [HOST_PORT]}
  restore_input=${2:?usage: data.sh restore-drill BACKUP_DIR TARGET_DATA_ROOT [HOST_PORT]}
  requested_port=${3:-18443}
  case "$requested_port" in
    ""|*[!0-9]*) die "restore-drill port must be numeric" ;;
  esac
  [ "$requested_port" -ge 1024 ] && [ "$requested_port" -le 65535 ] || die "restore-drill port must be between 1024 and 65535"

  validate_configured_root_reference
  verify_bundle "$backup_bundle"
  validate_restore_target "$restore_input"
  paths_overlap "$target_path" "$verified_bundle_dir" && die "restore target must not overlap the backup bundle"

  [ "$(manifest_value "$verified_bundle_dir/manifest" binary_version)" = "$BINARY_VERSION" ] || die "backup BINARY_VERSION differs from current .env"
  [ "$(manifest_value "$verified_bundle_dir/manifest" mysql_image)" = "$MYSQL_IMAGE" ] || die "backup MYSQL_IMAGE differs from current .env"
  [ "$(manifest_value "$verified_bundle_dir/manifest" mysql_database)" = "$MYSQL_DATABASE" ] || die "backup MYSQL_DATABASE differs from current .env"

  acquire_restore_target
  prepare_restore_target
  drill_target=$target_path
  drill_project="binary-restore-$$"
  drill_port=$requested_port
  drill_active=1
  operation_temp=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-restore.XXXXXX")

  echo "starting isolated restore-drill MySQL project: $drill_project"
  drill_compose up -d --pull never --wait --wait-timeout 180 mysql
  target_table_count=$(drill_db_query "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '$MYSQL_DATABASE';")
  [ "$target_table_count" = 0 ] || die "restore target database is not empty"

  drill_compose exec -T mysql sh -eu -c '
    export MYSQL_PWD="$MYSQL_PASSWORD"
    exec mysql --protocol=TCP --host=127.0.0.1 --user="$MYSQL_USER" "$MYSQL_DATABASE"
  ' < "$verified_bundle_dir/database.sql"
  compare_restored_counts
  verify_restored_references

  echo "starting all nine services without pulling images"
  drill_compose up -d --pull never --wait --wait-timeout 300
  running_count=$(drill_compose ps --services --status running | wc -l | tr -d '[:space:]')
  [ "$running_count" = 9 ] || die "restore drill started $running_count services instead of 9"
  drill_db_query 'SELECT 1;' >/dev/null

  echo "restore drill passed; restored data remains at $target_path"
  echo "the isolated Compose project will now be stopped; work and tls were not restored"
}

usage() {
  echo "usage:" >&2
  echo "  $0 backup OUTPUT_DIR" >&2
  echo "  $0 verify BACKUP_DIR" >&2
  echo "  $0 restore-drill BACKUP_DIR TARGET_DATA_ROOT [HOST_PORT]" >&2
  exit 2
}

load_env
require_runtime

case "${1:-}" in
  backup)
    [ "$#" -eq 2 ] || usage
    backup_data "$2"
    ;;
  verify)
    [ "$#" -eq 2 ] || usage
    verify_bundle "$2"
    echo "backup bundle is structurally valid: $verified_bundle_dir"
    ;;
  restore-drill)
    [ "$#" -eq 3 ] || [ "$#" -eq 4 ] || usage
    restore_drill "$2" "$3" "${4:-18443}"
    ;;
  *) usage ;;
esac
