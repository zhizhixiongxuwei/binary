#!/bin/sh
set -eu

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
images_root="$bundle_root/images"

[ -d "$images_root" ] || { echo "missing $images_root" >&2; exit 1; }

verify_archive() {
  archive=$1
  checksum_file="$archive.sha256"
  archive_dir=$(dirname -- "$archive")
  checksum_name=$(basename -- "$checksum_file")
  [ -f "$checksum_file" ] || { echo "missing $checksum_file" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$archive_dir" && sha256sum -c "$checksum_name")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$archive_dir" && shasum -a 256 -c "$checksum_name")
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
}

archives=$(find "$images_root" -type f -name '*.tar' | LC_ALL=C sort)
[ -n "$archives" ] || { echo "no Docker image archives found under $images_root" >&2; exit 1; }

printf '%s\n' "$archives" | while IFS= read -r archive; do
  verify_archive "$archive"
  echo "loading $(basename -- "$archive")"
  docker load -i "$archive"
done

echo "all delivery images are loaded"
