#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
requested_fixture_root=${BINARY_FIXTURE_REPO:-/Users/chenzhe/Documents/binary-repo}
fixture_root=
output_dir=
archive_dir=
build_dir=

die() {
  echo "error: $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$build_dir" ] && [ -d "$build_dir" ]; then
    rm -rf -- "$build_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

for command in clang javac jar python3 zip shasum file; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done

case "$requested_fixture_root" in
  "" | / | //) die "refusing unsafe fixture root: $requested_fixture_root" ;;
esac
[ -d "$requested_fixture_root" ] ||
  die "fixture repository does not exist: $requested_fixture_root"
fixture_root=$(CDPATH= cd -- "$requested_fixture_root" && pwd -P)
[ "$(basename -- "$fixture_root")" = "binary-repo" ] ||
  die "refusing to rebuild unexpected directory: $fixture_root"
[ -f "$fixture_root/generate.sh" ] || die "missing fixture repository generator"
[ -f "$fixture_root/README.md" ] || die "missing fixture repository README"
output_dir="$fixture_root/01-binary"
archive_dir="$fixture_root/02-archive"
[ "$output_dir" = "$fixture_root/01-binary" ] || die "invalid binary output path"
[ "$archive_dir" = "$fixture_root/02-archive" ] || die "invalid archive output path"

python_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
[ "$python_version" = "3.9" ] ||
  die "Python 3.9 is required for pycdc-compatible PYC fixtures (found $python_version)"

# This repository is intentionally a result-producing corpus, not a broad
# format corpus. Rebuild the two generated directories from scratch so retired
# zero-finding fixtures cannot survive a later regeneration.
rm -rf -- "$output_dir" "$archive_dir" "$fixture_root/03-container"
rm -f -- "$fixture_root/generate.go" "$fixture_root/manifest.json" \
  "$fixture_root/SHA256SUMS"
find "$fixture_root" -name .DS_Store -type f -delete
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-vulnerable-fixtures.XXXXXX")
mkdir -p "$output_dir" "$archive_dir" "$build_dir/java"

clang -O0 -fno-inline -Wl,-no_uuid -o "$build_dir/vulnerable-macho" \
  "$repo_root/test-fixtures/vulnerable/native.c"
cp "$build_dir/vulnerable-macho" "$output_dir/vulnerable-macho"

javac --release 8 -g -encoding UTF-8 -d "$build_dir/java" \
  "$repo_root/test-fixtures/vulnerable/VulnerableFixture.java"
cp "$build_dir/java/VulnerableFixture.class" "$output_dir/VulnerableFixture.class"
jar --create --file "$output_dir/vulnerable.jar" \
  --date=2000-01-01T00:00:00Z -C "$build_dir/java" .

python3 -c "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], dfile='unsafe.py', doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)" \
  "$repo_root/test-fixtures/vulnerable/unsafe.py" "$output_dir/vulnerable.pyc"

cp "$repo_root/test-fixtures/vulnerable/OUTPUT_README.md" "$output_dir/README.md"
cp "$repo_root/test-fixtures/vulnerable/expected-findings.json" "$output_dir/expected-findings.json"
TZ=UTC touch -t 200001010000 "$output_dir/vulnerable-macho" \
  "$output_dir/VulnerableFixture.class" "$output_dir/vulnerable.jar" \
  "$output_dir/vulnerable.pyc" "$output_dir/README.md" \
  "$output_dir/expected-findings.json"
rm -f "$archive_dir/vulnerable-binaries.zip"
(
  cd "$output_dir"
  TZ=UTC zip -X -q "$archive_dir/vulnerable-binaries.zip" \
    vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.pyc
)
(
  cd "$output_dir"
  shasum -a 256 vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.pyc \
    README.md expected-findings.json > SHA256SUMS
)
TZ=UTC touch -t 200001010000 "$output_dir/SHA256SUMS" \
  "$archive_dir/vulnerable-binaries.zip"

file "$output_dir/vulnerable-macho" "$output_dir/VulnerableFixture.class" \
  "$output_dir/vulnerable.jar" "$output_dir/vulnerable.pyc" \
  "$archive_dir/vulnerable-binaries.zip"
echo "generated vulnerable fixtures in $output_dir"
