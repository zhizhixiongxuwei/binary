#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
lock_file="$repo_dir/deploy/docker/images.lock.env"
env_file="$repo_dir/.env"
active_temporary=
active_segments=

cleanup() {
  [ -z "$active_temporary" ] || rm -f "$active_temporary"
  [ -z "$active_segments" ] || rm -rf "$active_segments"
}

trap cleanup EXIT HUP INT TERM

die() {
  echo "error: $*" >&2
  exit 1
}

note() {
  echo "==> $*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

absolute_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$repo_dir/$1" ;;
  esac
}

download() {
  url=$1
  destination=$2
  expected_size=${3:-0}
  if [ -s "$destination" ]; then
    note "using cached $(basename "$destination")"
    return
  fi
  mkdir -p "$(dirname "$destination")"
  temporary=$(mktemp "$(dirname "$destination")/.download.XXXXXX")
  active_temporary=$temporary
  remote_size=$expected_size
  if [ "$remote_size" -eq 0 ]; then
    remote_size=$(curl --fail --location --silent --show-error --retry 3 --retry-delay 2 --head "$url" |
      awk 'BEGIN { IGNORECASE=1 } /^content-length:/ { value=$2 } END { gsub("\r", "", value); print value }')
  fi
  case "$remote_size" in
    ''|*[!0-9]*) remote_size=0 ;;
  esac
  if [ "$remote_size" -ge 16777216 ]; then
    segment_root=$(mktemp -d "$(dirname "$destination")/.segments.XXXXXX")
    active_segments=$segment_root
    segment_count=16
    segment_size=$(( (remote_size + segment_count - 1) / segment_count ))
    pids=
    index=0
    while [ "$index" -lt "$segment_count" ]; do
      start=$((index * segment_size))
      end=$((start + segment_size - 1))
      [ "$end" -lt "$remote_size" ] || end=$((remote_size - 1))
      if [ "$start" -lt "$remote_size" ]; then
        curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
          --range "$start-$end" --output "$segment_root/$index" "$url" &
        pids="$pids $!"
      fi
      index=$((index + 1))
    done
    failed=0
    for pid in $pids; do
      wait "$pid" || failed=1
    done
    [ "$failed" -eq 0 ] || die "segmented download failed: $url"
    : > "$temporary"
    index=0
    while [ "$index" -lt "$segment_count" ]; do
      [ ! -f "$segment_root/$index" ] || cat "$segment_root/$index" >> "$temporary"
      index=$((index + 1))
    done
    actual_size=$(wc -c < "$temporary" | tr -d ' ')
    [ "$actual_size" -eq "$remote_size" ] || die "download size mismatch for $url"
    rm -rf "$segment_root"
    active_segments=
  elif ! curl --fail --location --silent --show-error --retry 3 --retry-delay 2 --output "$temporary" "$url"; then
    die "download failed: $url"
  fi
  chmod 0444 "$temporary"
  mv "$temporary" "$destination"
  active_temporary=
}

ensure_image() {
  image=$1
  if docker image inspect "$image" >/dev/null 2>&1; then
    note "using loaded image $image"
    return
  fi
  note "pulling $image for $BINARY_PLATFORM"
  docker pull --platform "$BINARY_PLATFORM" "$image"
}

download_tools() {
  cache_root=$1
  mkdir -p "$cache_root/jvm" "$cache_root/ghidra" "$cache_root/pycdc"

  download "$VINEFLOWER_URL" "$cache_root/jvm/vineflower.jar"
  download "$CFR_URL" "$cache_root/jvm/cfr.jar"
  download "$JADX_URL" "$cache_root/jvm/jadx.zip" "$JADX_ASSET_SIZE"
  download "$GHIDRA_URL" "$cache_root/ghidra/ghidra.zip" "$GHIDRA_ASSET_SIZE"
  download "$PYCDC_URL" "$cache_root/pycdc/source.tar.gz"

  [ "$(wc -c < "$cache_root/jvm/jadx.zip" | tr -d ' ')" -eq "$JADX_ASSET_SIZE" ] ||
    die "cached JADX archive size does not match images.lock.env"
  [ "$(wc -c < "$cache_root/ghidra/ghidra.zip" | tr -d ' ')" -eq "$GHIDRA_ASSET_SIZE" ] ||
    die "cached Ghidra archive size does not match images.lock.env"

  jar tf "$cache_root/jvm/vineflower.jar" >/dev/null
  jar tf "$cache_root/jvm/cfr.jar" >/dev/null
  unzip -tq "$cache_root/jvm/jadx.zip" >/dev/null
  unzip -tq "$cache_root/ghidra/ghidra.zip" >/dev/null
  tar -tzf "$cache_root/pycdc/source.tar.gz" >/dev/null

  if [ ! -s "$cache_root/ghidra/executable-files.txt" ]; then
    temporary=$(mktemp "$cache_root/ghidra/.executable-files.XXXXXX")
    active_temporary=$temporary
    zipinfo -l "$cache_root/ghidra/ghidra.zip" |
      awk '$1 ~ /^-/ && substr($1, 4, 1) == "x" { print $NF }' |
      sed 's|^[^/]*/||' > "$temporary"
    chmod 0444 "$temporary"
    mv "$temporary" "$cache_root/ghidra/executable-files.txt"
    active_temporary=
  fi
  [ -s "$cache_root/ghidra/executable-files.txt" ] || die "Ghidra executable manifest is empty"

  if [ ! -s "$cache_root/jvm/jadx-all.jar" ]; then
    extract_root=$(mktemp -d "$cache_root/.jadx.XXXXXX")
    unzip -q "$cache_root/jvm/jadx.zip" -d "$extract_root"
    jadx_jar=$(find "$extract_root" -type f -name 'jadx-*-all.jar' -print)
    [ -n "$jadx_jar" ] || {
      rm -rf "$extract_root"
      die "jadx all-in-one jar is missing from the release archive"
    }
    [ "$(printf '%s\n' "$jadx_jar" | wc -l | tr -d ' ')" -eq 1 ] || {
      rm -rf "$extract_root"
      die "jadx release contains multiple all-in-one jars"
    }
    cp "$jadx_jar" "$cache_root/jvm/jadx-all.jar"
    chmod 0444 "$cache_root/jvm/jadx-all.jar"
    rm -rf "$extract_root"
  fi
  jar tf "$cache_root/jvm/jadx-all.jar" >/dev/null
  note "official tool assets are ready in $cache_root"
}

download_trivy_databases() {
  cache_root=$1
  trivy_cache="$cache_root/trivy"
  if [ -s "$trivy_cache/db/trivy.db" ] && [ -s "$trivy_cache/db/metadata.json" ] &&
     [ -s "$trivy_cache/java-db/trivy-java.db" ] && [ -s "$trivy_cache/java-db/metadata.json" ]; then
    note "using cached Trivy databases"
    return
  fi
  ensure_image "$TRIVY_SOURCE_IMAGE"
  mkdir -p "$trivy_cache"
  note "downloading Trivy vulnerability database"
  docker run --rm --platform "$BINARY_PLATFORM" \
    --volume "$trivy_cache:/cache" \
    --entrypoint /usr/local/bin/trivy \
    "$TRIVY_SOURCE_IMAGE" --cache-dir /cache image --download-db-only --no-progress
  note "downloading Trivy Java database"
  docker run --rm --platform "$BINARY_PLATFORM" \
    --volume "$trivy_cache:/cache" \
    --entrypoint /usr/local/bin/trivy \
    "$TRIVY_SOURCE_IMAGE" --cache-dir /cache image --download-java-db-only --no-progress
  [ -s "$trivy_cache/db/trivy.db" ] || die "Trivy database download did not produce trivy.db"
  [ -s "$trivy_cache/db/metadata.json" ] || die "Trivy database metadata is missing"
  [ -s "$trivy_cache/java-db/trivy-java.db" ] || die "Trivy Java database download did not produce trivy-java.db"
  [ -s "$trivy_cache/java-db/metadata.json" ] || die "Trivy Java database metadata is missing"
}

build_tools() {
  cache_root=$1
  download_tools "$cache_root"
  download_trivy_databases "$cache_root"
  ensure_image "$JAVA_RUNTIME_IMAGE"
  ensure_image "$GHIDRA_JDK_IMAGE"
  ensure_image "$PYCDC_BUILD_IMAGE"

  note "building $JVM_TOOLS_IMAGE"
  docker build --pull=false --platform "$BINARY_PLATFORM" \
    --file "$repo_dir/deploy/tools/jvm-runtime.Dockerfile" \
    --tag "$JVM_TOOLS_IMAGE" \
    --build-arg "JAVA_RUNTIME_IMAGE=$JAVA_RUNTIME_IMAGE" \
    "$cache_root"

  note "building $GHIDRA_RUNTIME_IMAGE"
  docker build --pull=false --platform "$BINARY_PLATFORM" \
    --file "$repo_dir/deploy/tools/ghidra-runtime.Dockerfile" \
    --tag "$GHIDRA_RUNTIME_IMAGE" \
    --build-arg "GHIDRA_JDK_IMAGE=$GHIDRA_JDK_IMAGE" \
    "$cache_root"

  note "building $PYCDC_TOOLS_IMAGE"
  docker build --pull=false --platform "$BINARY_PLATFORM" \
    --file "$repo_dir/deploy/tools/pycdc-runtime.Dockerfile" \
    --tag "$PYCDC_TOOLS_IMAGE" \
    --build-arg "PYCDC_BUILD_IMAGE=$PYCDC_BUILD_IMAGE" \
    --build-arg "PYCDC_RUNTIME_IMAGE=$PYCDC_RUNTIME_IMAGE" \
    "$cache_root"

  note "building $TRIVY_RUNTIME_DB_IMAGE"
  docker build --pull=false --platform "$BINARY_PLATFORM" \
    --file "$repo_dir/deploy/tools/trivy-runtime-db.Dockerfile" \
    --tag "$TRIVY_RUNTIME_DB_IMAGE" \
    --build-arg "TRIVY_SOURCE_IMAGE=$TRIVY_SOURCE_IMAGE" \
    "$cache_root"
}

verify_tools() {
  for image in "$JVM_TOOLS_IMAGE" "$GHIDRA_RUNTIME_IMAGE" "$PYCDC_TOOLS_IMAGE" "$TRIVY_RUNTIME_DB_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 || die "tool image is not loaded: $image"
  done
  docker run --rm --platform "$BINARY_PLATFORM" "$JVM_TOOLS_IMAGE" \
    /opt/java/openjdk/bin/java -jar /opt/bytecode-tools/vineflower/vineflower.jar --help >/dev/null
  docker run --rm --platform "$BINARY_PLATFORM" "$JVM_TOOLS_IMAGE" \
    /opt/java/openjdk/bin/java -jar /opt/bytecode-tools/cfr/cfr.jar --version >/dev/null
  docker run --rm --platform "$BINARY_PLATFORM" "$JVM_TOOLS_IMAGE" \
    /opt/java/openjdk/bin/java -cp /opt/bytecode-tools/jadx/lib/jadx-all.jar jadx.cli.JadxCLI --version >/dev/null
  docker run --rm --platform "$BINARY_PLATFORM" "$GHIDRA_RUNTIME_IMAGE" \
    /bin/bash -ec "grep -F 'application.version=$GHIDRA_VERSION' /opt/ghidra/Ghidra/application.properties >/dev/null"
  docker run --rm --platform "$BINARY_PLATFORM" "$PYCDC_TOOLS_IMAGE" \
    /opt/bytecode-tools/pycdc/pycdc --help >/dev/null 2>&1
  docker run --rm --platform "$BINARY_PLATFORM" "$TRIVY_RUNTIME_DB_IMAGE" \
    version --format json >/dev/null
  note "four tool images passed version and layout checks"
}

usage() {
  echo "usage: $0 {download|build|verify|all} CACHE_DIR" >&2
  exit 2
}

[ -f "$lock_file" ] || die "missing $lock_file"
[ -f "$env_file" ] || die "missing $env_file"
set -a
# shellcheck disable=SC1090
. "$env_file"
# shellcheck disable=SC1090
. "$lock_file"
set +a

require_command docker
require_command curl
require_command jar
require_command unzip
require_command zipinfo
require_command tar

[ "$#" -eq 2 ] || usage
cache_root=$(absolute_path "$2")
[ "$cache_root" != "$repo_dir" ] || die "CACHE_DIR must not be the repository root"
mkdir -p "$cache_root"

case "$1" in
  download) download_tools "$cache_root" ;;
  build) build_tools "$cache_root" ;;
  verify) verify_tools ;;
  all) build_tools "$cache_root"; verify_tools ;;
  *) usage ;;
esac
