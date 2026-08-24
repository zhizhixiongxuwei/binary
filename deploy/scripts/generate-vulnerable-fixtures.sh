#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
fixture_root=${BINARY_FIXTURE_REPO:-/Users/chenzhe/Documents/binary-repo}
output_dir="$fixture_root/01-binary/vulnerable"
archive_dir="$fixture_root/02-archive"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-vulnerable-fixtures.XXXXXX")

cleanup() {
  rm -rf "$build_dir"
}
trap cleanup EXIT HUP INT TERM

for command in clang javac jar python3 zip shasum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required command: $command" >&2
    exit 1
  }
done

mkdir -p "$output_dir" "$archive_dir" "$build_dir/java"
rm -rf "$output_dir/vulnerable-macho.dSYM"

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
    vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.pyc \
    README.md expected-findings.json
)
(
  cd "$output_dir"
  shasum -a 256 vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.pyc \
    README.md expected-findings.json > SHA256SUMS
)

file "$output_dir/vulnerable-macho" "$output_dir/VulnerableFixture.class" \
  "$output_dir/vulnerable.jar" "$output_dir/vulnerable.pyc" \
  "$archive_dir/vulnerable-binaries.zip"
echo "generated vulnerable fixtures in $output_dir"
