#!/bin/sh
set -eu

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

verify_manifest() {
  manifest=$1
  [ -f "$bundle_root/$manifest" ] || { echo "missing $manifest" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$bundle_root" && sha256sum -c "$manifest")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$bundle_root" && shasum -a 256 -c "$manifest")
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
}

case "${1:-package}" in
  package) verify_manifest manifests/package.sha256 ;;
  source) verify_manifest manifests/source.sha256 ;;
  all)
    verify_manifest manifests/package.sha256
    if [ -f "$bundle_root/manifests/source.sha256" ]; then
      verify_manifest manifests/source.sha256
    fi
    ;;
  *)
    echo "usage: ./verify.sh {package|source|all}" >&2
    exit 2
    ;;
esac
