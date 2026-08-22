#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
set -a
# shellcheck disable=SC1090
. "$repo_dir/.env"
set +a

services=$(docker compose --project-directory "$repo_dir" config --services | sort | tr '\n' ' ')
expected="app c-checker java-checker jvm-decompiler mysql native-decompiler pyc-decompiler python-checker scanner "
[ "$services" = "$expected" ] || {
  echo "unexpected service set: $services" >&2
  exit 1
}

echo "compose service topology is correct"
