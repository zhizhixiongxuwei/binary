#!/bin/sh
set -eu

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
[ "$#" -eq 0 ] || { echo "usage: sh install.sh" >&2; exit 2; }
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" -ne 0 ]; then
  echo "Run sudo sh install.sh on Linux to initialize data ownership." >&2
  exit 1
fi
docker info >/dev/null
docker compose version >/dev/null
# Verify the entire immutable payload before importing any image or starting services.
sh "$bundle_root/verify.sh" package
sh "$bundle_root/load-images.sh"
sh "$bundle_root/manage.sh" start
