#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
fixture_root=${BINARY_FIXTURE_REPO:?set BINARY_FIXTURE_REPO to the external binary-repo fixture directory}
binary_dir="$fixture_root/01-binary"
work_dir=$(mktemp -d "$repo_dir/.decompiler-checker.XXXXXX")

cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

cd "$repo_dir"
# shellcheck disable=SC1091
. ./.env

checker_network=$(docker network ls \
  --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
  --filter "label=com.docker.compose.network=checker-net" \
  --format '{{.Name}}')
[ -n "$checker_network" ] || {
  echo "checker network is not running" >&2
  exit 1
}

expectations="$binary_dir/expected-findings.json"
for name in vulnerable.exe vulnerable.dll vulnerable.sys vulnerable-elf \
  vulnerable-macho VulnerableFixture.class vulnerable.jar vulnerable.dex \
  vulnerable.apk vulnerable.pyc expected-findings.json; do
  [ -f "$binary_dir/$name" ] || {
    echo "missing fixture: $binary_dir/$name" >&2
    exit 1
  }
done

for name in vulnerable-macho vulnerable-elf vulnerable.exe vulnerable.dll vulnerable.sys; do
  mkdir -p "$work_dir/native/$name/project" "$work_dir/native/$name/source"
  if ! docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
      --entrypoint /opt/ghidra/support/analyzeHeadless \
      -v "$binary_dir:/fixtures:ro" -v "$work_dir/native/$name:/work" \
      "$NATIVE_DECOMPILER_IMAGE" \
      /work/project binaryscan -import "/fixtures/$name" \
      -scriptPath /opt/binaryscan/ghidra \
      -postScript ExportPseudoC.java /work/source 1000 134217728 -deleteProject \
      >"$work_dir/native/$name.log" 2>&1; then
    sed -n '1,260p' "$work_dir/native/$name.log" >&2
    exit 1
  fi
done

mkdir -p "$work_dir/jvm/class" "$work_dir/jvm/jar" \
  "$work_dir/dalvik/dex" "$work_dir/dalvik/apk" "$work_dir/python"
docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/java/openjdk/bin/java \
  -v "$binary_dir:/fixtures:ro" -v "$work_dir/jvm/class:/output" \
  "$JVM_DECOMPILER_IMAGE" -Xms128m -Xmx3g -XX:+ExitOnOutOfMemoryError \
  -jar /opt/bytecode-tools/vineflower/vineflower.jar \
  --silent --folder /fixtures/VulnerableFixture.class /output
docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/java/openjdk/bin/java \
  -v "$binary_dir:/fixtures:ro" -v "$work_dir/jvm/jar:/output" \
  "$JVM_DECOMPILER_IMAGE" -Xms128m -Xmx3g -XX:+ExitOnOutOfMemoryError \
  -jar /opt/bytecode-tools/vineflower/vineflower.jar \
  --silent --folder /fixtures/vulnerable.jar /output
for name in dex apk; do
  docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
    --entrypoint /opt/java/openjdk/bin/java \
    -v "$binary_dir:/fixtures:ro" -v "$work_dir/dalvik/$name:/output" \
    "$JVM_DECOMPILER_IMAGE" -Xms128m -Xmx3g -XX:+ExitOnOutOfMemoryError \
    -cp /opt/bytecode-tools/jadx/lib/jadx-all.jar jadx.cli.JadxCLI \
    --no-res -d /output "/fixtures/vulnerable.$name"
done
docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/bytecode-tools/pycdc/pycdc \
  -v "$binary_dir:/fixtures:ro" "$PYC_DECOMPILER_IMAGE" \
  /fixtures/vulnerable.pyc >"$work_dir/python/decompiled.py"

docker run --rm --pull never --platform "$BINARY_PLATFORM" \
  --network "$checker_network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$work_dir:/decompiled:ro" \
  -v "$expectations:/fixtures/expected-findings.json:ro" \
  --entrypoint python3 "$PYTHON_CHECKER_IMAGE" -c '
import glob
import json
import os
import urllib.request

with open("/fixtures/expected-findings.json", encoding="utf-8") as source:
    manifest = json.load(source)

cases = [
    ("native-macho", "native-macho-ghidra", "c-checker", "/decompiled/native/vulnerable-macho/source/*.c"),
    ("native-elf", "native-elf-ghidra", "c-checker", "/decompiled/native/vulnerable-elf/source/*.c"),
    ("native-exe", "native-exe-ghidra", "c-checker", "/decompiled/native/vulnerable.exe/source/*.c"),
    ("native-dll", "native-dll-ghidra", "c-checker", "/decompiled/native/vulnerable.dll/source/*.c"),
    ("native-sys", "native-sys-ghidra", "c-checker", "/decompiled/native/vulnerable.sys/source/*.c"),
    ("jvm-class", "jvm-vineflower", "java-checker", "/decompiled/jvm/class/**/*.java"),
    ("jvm-jar", "jvm-vineflower", "java-checker", "/decompiled/jvm/jar/**/*.java"),
    ("dalvik-dex", "dalvik-jadx", "java-checker", "/decompiled/dalvik/dex/**/*.java"),
    ("dalvik-apk", "dalvik-jadx", "java-checker", "/decompiled/dalvik/apk/**/*.java"),
    ("python-pyc", "python-pycdc", "python-checker", "/decompiled/python/*.py"),
]

for case_name, target_name, service, pattern in cases:
    target = manifest["targets"][target_name]
    expected = set(target["expectedRuleIds"])
    files = []
    for source_path in sorted(glob.glob(pattern, recursive=True)):
        with open(source_path, encoding="utf-8") as source:
            files.append({
                "path": os.path.relpath(source_path, "/decompiled"),
                "content": source.read(),
            })
    if not files:
        raise SystemExit(case_name + " produced no source files")
    body = json.dumps({
        "version": "checker-v1",
        "projectId": "decompiler-regression-" + case_name,
        "language": target["language"],
        "files": files,
    }).encode("utf-8")
    request = urllib.request.Request(
        "http://" + service + ":8080/v1/check",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    actual = {finding["ruleId"] for finding in result["findings"]}
    missing = expected - actual
    unexpected = actual - expected
    if result.get("status") != "complete" or missing or unexpected:
        raise SystemExit(
            case_name + " failed; missing=" + repr(sorted(missing))
            + " unexpected=" + repr(sorted(unexpected))
            + " diagnostics=" + repr(result.get("diagnostics"))
        )
    print(case_name + ": " + str(len(actual)) + " expected rule families observed")
'
