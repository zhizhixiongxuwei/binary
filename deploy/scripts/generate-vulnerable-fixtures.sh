#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
requested_fixture_root=${BINARY_FIXTURE_REPO:-/Users/chenzhe/Documents/binary-repo}
fixture_builder_image=${FIXTURE_BUILDER_IMAGE:-binaryscan/fixture-builder:1.0.0}
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

for command in clang javac jar python3 zip shasum file hdiutil docker go; do
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

# shellcheck disable=SC1091
. "$repo_root/.env"
docker image inspect "$fixture_builder_image" >/dev/null 2>&1 ||
  docker build --pull=false -t "$fixture_builder_image" \
    -f "$repo_root/deploy/tools/fixture-builder.Dockerfile" "$repo_root"

# Rebuild only the three validated result directories. This corpus intentionally
# excludes zero-finding and ambiguous placeholder files.
rm -rf -- "$output_dir" "$archive_dir" "$container_dir"
find "$fixture_root" -name .DS_Store -type f -delete
build_dir=$(mktemp -d "$repo_root/.fixture-build.XXXXXX")
mkdir -p "$output_dir" "$archive_dir" "$container_dir" \
  "$build_dir/native" "$build_dir/java" "$build_dir/apk" "$build_dir/iso" \
  "$build_dir/rpmbuild/BUILD" "$build_dir/rpmbuild/BUILDROOT" \
  "$build_dir/rpmbuild/RPMS" "$build_dir/rpmbuild/SOURCES" \
  "$build_dir/rpmbuild/SPECS" "$build_dir/rpmbuild/SRPMS"

# Native inputs: real Mach-O on the macOS host, plus Linux ELF and Windows
# PE32+ EXE/DLL/SYS in the reproducible Linux builder.
clang -O0 -fno-inline -Wl,-no_uuid -o "$output_dir/vulnerable-macho" \
  "$repo_root/test-fixtures/vulnerable/native.c"
docker run --rm --pull never --platform "$BINARY_PLATFORM" \
  -v "$repo_root/test-fixtures/vulnerable:/src:ro" \
  -v "$build_dir/native:/out" "$fixture_builder_image" sh -ec '
    gcc -O0 -fno-inline -fno-builtin -o /out/vulnerable-elf /src/native_portable.c
    x86_64-w64-mingw32-gcc -O0 -fno-inline -fno-builtin \
      -o /out/vulnerable.exe /src/native_portable.c
    x86_64-w64-mingw32-gcc -O0 -fno-inline -fno-builtin -shared \
      -Wl,--export-all-symbols -o /out/vulnerable.dll /src/native_portable.c
    cp /out/vulnerable.exe /out/vulnerable.sys
    python3 - /out/vulnerable.sys <<"PY"
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
body = bytearray(path.read_bytes())
pe_offset = struct.unpack_from("<I", body, 0x3C)[0]
if struct.unpack_from("<H", body, pe_offset + 24)[0] != 0x20B:
    raise SystemExit("expected PE32+ optional header")
struct.pack_into("<H", body, pe_offset + 24 + 68, 1)
path.write_bytes(body)
PY
  '
cp "$build_dir/native/vulnerable-elf" "$output_dir/vulnerable-elf"
cp "$build_dir/native/vulnerable.exe" "$output_dir/vulnerable.exe"
cp "$build_dir/native/vulnerable.dll" "$output_dir/vulnerable.dll"
cp "$build_dir/native/vulnerable.sys" "$output_dir/vulnerable.sys"

# JVM/Dalvik/Python inputs. CLASS and JAR use Vineflower; DEX and APK use JADX.
javac --release 8 -g -encoding UTF-8 -d "$build_dir/java" \
  "$repo_root/test-fixtures/vulnerable/VulnerableFixture.java"
cp "$build_dir/java/VulnerableFixture.class" "$output_dir/VulnerableFixture.class"
jar --create --file "$output_dir/vulnerable.jar" \
  --date=2000-01-01T00:00:00Z -C "$build_dir/java" .
docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/java/openjdk/bin/java \
  -v "$repo_root/test-fixtures/vulnerable:/input:ro" -v "$output_dir:/output" \
  "$JVM_DECOMPILER_IMAGE" -cp /opt/bytecode-tools/jadx/lib/jadx-all.jar \
  com.android.tools.smali.smali.Main assemble /input/VulnerableDex.smali \
  -o /output/vulnerable.dex
cp "$repo_root/test-fixtures/vulnerable/AndroidManifest.xml" "$build_dir/apk/AndroidManifest.xml"
cp "$output_dir/vulnerable.dex" "$build_dir/apk/classes.dex"
find "$build_dir/apk" -exec touch -t 200001010000 {} +
(
  cd "$build_dir/apk"
  TZ=UTC zip -X -9 -q "$output_dir/vulnerable.apk" AndroidManifest.xml classes.dex
)
python3 -c "import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], dfile='unsafe.py', doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)" \
  "$repo_root/test-fixtures/vulnerable/unsafe.py" "$output_dir/vulnerable.pyc"

cp "$repo_root/test-fixtures/vulnerable/OUTPUT_README.md" "$output_dir/README.md"
cp "$repo_root/test-fixtures/vulnerable/expected-findings.json" "$output_dir/expected-findings.json"
cp "$repo_root/test-fixtures/vulnerable/ARCHIVE_README.md" "$archive_dir/README.md"
cp "$repo_root/test-fixtures/vulnerable/CONTAINER_README.md" "$container_dir/README.md"
cp "$repo_root/test-fixtures/vulnerable/expected-trivy.json" "$container_dir/expected-trivy.json"
find "$output_dir" -mindepth 1 -maxdepth 1 -type f -exec touch -t 200001010000 {} +

# One-layer archive fixtures. ZIP/TAR/7Z/RAR/ISO/EXT4 contain direct ELF and
# PE members; stream/package formats contain an ELF; JAR/APK expose CLASS/DEX.
python3 "$repo_root/deploy/scripts/build-archive-fixtures.py" \
  --binary-dir "$output_dir" --output-dir "$archive_dir"
docker run --rm --pull never --platform "$BINARY_PLATFORM" \
  -v "$output_dir:/binary:ro" -v "$archive_dir:/archive" \
  "$fixture_builder_image" sh -ec '
    cd /binary
    7z a -bd -y -t7z -mx=9 -mtc=off -mtm=off -mta=off \
      /archive/vulnerable-binaries.7z vulnerable-elf vulnerable.exe >/dev/null
  '
python3 "$repo_root/deploy/scripts/build-rar-fixture.py" \
  "$archive_dir/vulnerable-binaries.rar" \
  vulnerable-elf "$output_dir/vulnerable-elf" \
  vulnerable.exe "$output_dir/vulnerable.exe"

cp "$output_dir/vulnerable-elf" "$build_dir/rpmbuild/SOURCES/vulnerable-elf"
cp "$repo_root/test-fixtures/vulnerable/vulnerable-binaries.spec" \
  "$build_dir/rpmbuild/SPECS/vulnerable-binaries.spec"
docker run --rm --pull never --platform "$BINARY_PLATFORM" \
  -v "$build_dir/rpmbuild:/root/rpmbuild" -v "$archive_dir:/archive" \
  "$fixture_builder_image" sh -ec '
    rpmbuild -bb --define "_topdir /root/rpmbuild" \
      /root/rpmbuild/SPECS/vulnerable-binaries.spec >/dev/null
    cp /root/rpmbuild/RPMS/x86_64/binaryscan-vulnerable-binaries-1.0-1.x86_64.rpm \
      /archive/vulnerable-binaries.rpm
  '

cp "$output_dir/vulnerable-elf" "$build_dir/iso/vulnerable-elf"
cp "$output_dir/vulnerable.exe" "$build_dir/iso/vulnerable.exe"
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
(
  cd "$repo_root/app/backend"
  go run ../../deploy/scripts/build-ext4-fixture.go \
    "$archive_dir/vulnerable-binaries.ext4" \
    "$output_dir/vulnerable-elf" "$output_dir/vulnerable.exe"
)

# Real Docker-save and OCI-layout archives. The IMG is intentionally the exact
# Docker-save byte stream with a different suffix, proving content-first routing.
python3 "$repo_root/deploy/scripts/build-image-fixtures.py" \
  --binary-dir "$output_dir" --output-dir "$container_dir"
cp "$container_dir/docker-save.tar" "$container_dir/docker-save.img"

(
  cd "$output_dir"
  shasum -a 256 vulnerable.exe vulnerable.dll vulnerable.sys vulnerable-elf \
    vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.dex \
    vulnerable.apk vulnerable.pyc README.md expected-findings.json > SHA256SUMS
)
(
  cd "$archive_dir"
  shasum -a 256 vulnerable-binaries.zip vulnerable-binaries.7z \
    vulnerable-binaries.rar vulnerable-binaries.tar vulnerable-elf.gz \
    vulnerable-elf.xz vulnerable-binaries.deb vulnerable-binaries.rpm \
    vulnerable-binaries.iso vulnerable-binaries.ext4 vulnerable-binaries.jar \
    vulnerable-binaries.apk README.md > SHA256SUMS
)
(
  cd "$container_dir"
  shasum -a 256 docker-save.tar oci-layout.tar docker-save.img README.md \
    expected-trivy.json > SHA256SUMS
)
find "$output_dir" "$archive_dir" "$container_dir" -mindepth 1 -maxdepth 1 \
  -type f -exec touch -t 200001010000 {} +

file "$output_dir"/vulnerable.exe "$output_dir"/vulnerable.dll \
  "$output_dir"/vulnerable.sys "$output_dir"/vulnerable-elf \
  "$output_dir"/vulnerable-macho "$output_dir"/VulnerableFixture.class \
  "$output_dir"/vulnerable.jar "$output_dir"/vulnerable.dex \
  "$output_dir"/vulnerable.apk "$output_dir"/vulnerable.pyc \
  "$archive_dir"/vulnerable-binaries.iso \
  "$archive_dir"/vulnerable-binaries.ext4 \
  "$container_dir"/docker-save.tar "$container_dir"/docker-save.img \
  "$container_dir"/oci-layout.tar
echo "generated result-producing fixture corpus in $fixture_root"
