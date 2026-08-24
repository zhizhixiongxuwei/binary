#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
requested_fixture_root=${BINARY_FIXTURE_REPO:-/Users/chenzhe/Documents/binary-repo}
fixture_root=
output_dir=
archive_dir=
container_dir=
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

for command in clang javac jar python3 zip shasum file hdiutil; do
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
container_dir="$fixture_root/03-container"
[ "$output_dir" = "$fixture_root/01-binary" ] || die "invalid binary output path"
[ "$archive_dir" = "$fixture_root/02-archive" ] || die "invalid archive output path"
[ "$container_dir" = "$fixture_root/03-container" ] || die "invalid container output path"

python_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
[ "$python_version" = "3.9" ] ||
  die "Python 3.9 is required for pycdc-compatible PYC fixtures (found $python_version)"

# This repository is intentionally a result-producing corpus, not a broad
# format corpus. Rebuild the three generated directories from scratch so retired
# zero-finding fixtures cannot survive a later regeneration.
rm -rf -- "$output_dir" "$archive_dir" "$container_dir"
rm -f -- "$fixture_root/generate.go" "$fixture_root/manifest.json" \
  "$fixture_root/SHA256SUMS"
find "$fixture_root" -name .DS_Store -type f -delete
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-vulnerable-fixtures.XXXXXX")
mkdir -p "$output_dir" "$archive_dir" "$container_dir" \
  "$build_dir/java" "$build_dir/iso"

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
cp "$repo_root/test-fixtures/vulnerable/ARCHIVE_README.md" "$archive_dir/README.md"
cp "$repo_root/test-fixtures/vulnerable/CONTAINER_README.md" "$container_dir/README.md"
cp "$repo_root/test-fixtures/vulnerable/expected-trivy.json" \
  "$container_dir/expected-trivy.json"
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

cp "$output_dir/vulnerable-macho" "$build_dir/iso/vulnerable-macho"
cp "$output_dir/VulnerableFixture.class" "$build_dir/iso/VulnerableFixture.class"
cp "$output_dir/vulnerable.jar" "$build_dir/iso/vulnerable.jar"
cp "$output_dir/vulnerable.pyc" "$build_dir/iso/vulnerable.pyc"
find "$build_dir/iso" -exec touch -t 200001010000 {} +
hdiutil makehybrid -quiet -iso -joliet -default-volume-name BINARYSCAN \
  -o "$archive_dir/vulnerable-binaries.iso" "$build_dir/iso"
python3 - "$archive_dir/vulnerable-binaries.iso" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
image = bytearray(path.read_bytes())
timestamp = b"2000010100000000\x00"
recording_timestamp = bytes((100, 1, 1, 0, 0, 0, 0))
seen_directories = set()


def normalize_system_use(record_offset, record_length):
    identifier_length = image[record_offset + 32]
    cursor = record_offset + 33 + identifier_length
    if identifier_length % 2 == 0:
        cursor += 1
    end = record_offset + record_length
    while cursor + 4 <= end:
        entry_length = image[cursor + 2]
        if entry_length < 4 or cursor + entry_length > end:
            break
        if image[cursor : cursor + 2] == b"TF" and entry_length >= 5:
            flags = image[cursor + 4]
            value_length = 17 if flags & 0x80 else 7
            value = timestamp if value_length == 17 else recording_timestamp
            value_offset = cursor + 5
            for bit in range(7):
                if flags & (1 << bit):
                    if value_offset + value_length > cursor + entry_length:
                        raise SystemExit("invalid ISO 9660 Rock Ridge timestamp")
                    image[value_offset : value_offset + value_length] = value
                    value_offset += value_length
        cursor += entry_length


def normalize_directory(extent, size):
    key = (extent, size)
    if key in seen_directories:
        return
    seen_directories.add(key)
    cursor = extent * 2048
    end = cursor + size
    while cursor < end and cursor < len(image):
        record_length = image[cursor]
        if record_length == 0:
            cursor = ((cursor // 2048) + 1) * 2048
            continue
        if record_length < 34 or cursor + record_length > len(image):
            raise SystemExit("invalid ISO 9660 directory record")
        image[cursor + 18 : cursor + 25] = recording_timestamp
        normalize_system_use(cursor, record_length)
        identifier_length = image[cursor + 32]
        identifier = bytes(image[cursor + 33 : cursor + 33 + identifier_length])
        if image[cursor + 25] & 2 and identifier not in (b"\x00", b"\x01"):
            child_extent = int.from_bytes(image[cursor + 2 : cursor + 6], "little")
            child_size = int.from_bytes(image[cursor + 10 : cursor + 14], "little")
            normalize_directory(child_extent, child_size)
        cursor += record_length


for sector in range(16, 32):
    offset = sector * 2048
    if len(image) < offset + 881 or image[offset + 1 : offset + 6] != b"CD001":
        break
    if image[offset] in (1, 2):
        for field_offset in (813, 830, 847, 864):
            image[offset + field_offset : offset + field_offset + 17] = timestamp
        root_record = offset + 156
        image[root_record + 18 : root_record + 25] = recording_timestamp
        normalize_system_use(root_record, image[root_record])
        root_extent = int.from_bytes(image[root_record + 2 : root_record + 6], "little")
        root_size = int.from_bytes(image[root_record + 10 : root_record + 14], "little")
        normalize_directory(root_extent, root_size)
path.write_bytes(image)
PY
cp "$archive_dir/vulnerable-binaries.iso" "$archive_dir/vulnerable-binaries.img"

python3 "$repo_root/deploy/scripts/build-image-fixtures.py" \
  --binary-dir "$output_dir" --output-dir "$container_dir"

(
  cd "$output_dir"
  shasum -a 256 vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.pyc \
    README.md expected-findings.json > SHA256SUMS
)
(
  cd "$archive_dir"
  shasum -a 256 vulnerable-binaries.zip vulnerable-binaries.iso \
    vulnerable-binaries.img README.md > SHA256SUMS
)
(
  cd "$container_dir"
  shasum -a 256 docker-save.tar oci-layout.tar README.md \
    expected-trivy.json > SHA256SUMS
)
TZ=UTC touch -t 200001010000 "$output_dir/SHA256SUMS" \
  "$archive_dir/vulnerable-binaries.zip" \
  "$archive_dir/vulnerable-binaries.iso" \
  "$archive_dir/vulnerable-binaries.img" \
  "$archive_dir/README.md" "$archive_dir/SHA256SUMS" \
  "$container_dir/docker-save.tar" "$container_dir/oci-layout.tar" \
  "$container_dir/README.md" "$container_dir/expected-trivy.json" \
  "$container_dir/SHA256SUMS"

file "$output_dir/vulnerable-macho" "$output_dir/VulnerableFixture.class" \
  "$output_dir/vulnerable.jar" "$output_dir/vulnerable.pyc" \
  "$archive_dir/vulnerable-binaries.zip" \
  "$archive_dir/vulnerable-binaries.iso" \
  "$archive_dir/vulnerable-binaries.img" \
  "$container_dir/docker-save.tar" "$container_dir/oci-layout.tar"
echo "generated vulnerable fixtures in $output_dir"
