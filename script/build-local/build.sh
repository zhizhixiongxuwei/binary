#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for python in python3 python; do
  if command -v "$python" >/dev/null 2>&1 && "$python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
    exec "$python" "$script_dir/../lib/build.py" local "$@"
  fi
done
echo 'error: Python 3.10 or newer is required on the build host' >&2
exit 1
