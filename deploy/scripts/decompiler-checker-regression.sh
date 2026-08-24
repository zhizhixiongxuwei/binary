#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
fixture_root=${BINARY_FIXTURE_REPO:-/Users/chenzhe/Documents/binary-repo}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-decompiler-checker.XXXXXX")

cleanup() {
  rm -rf "$work_dir"
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

native_input="$fixture_root/01-binary/vulnerable-macho"
jvm_class_input="$fixture_root/01-binary/VulnerableFixture.class"
jvm_jar_input="$fixture_root/01-binary/vulnerable.jar"
pyc_input="$fixture_root/01-binary/vulnerable.pyc"
expectations="$fixture_root/01-binary/expected-findings.json"
for input in "$native_input" "$jvm_class_input" "$jvm_jar_input" "$pyc_input" "$expectations"; do
  [ -f "$input" ] || {
    echo "missing fixture: $input" >&2
    exit 1
  }
done

mkdir -p "$work_dir/ghidra/project" "$work_dir/ghidra/source" \
  "$work_dir/vineflower-class" "$work_dir/vineflower-jar" "$work_dir/pycdc"

if ! docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
    --entrypoint /opt/ghidra/support/analyzeHeadless \
    -v "$native_input:/input/vulnerable-macho:ro" \
    -v "$work_dir/ghidra:/work" \
    "$NATIVE_DECOMPILER_IMAGE" \
    /work/project binaryscan -import /input/vulnerable-macho \
    -scriptPath /opt/binaryscan/ghidra \
    -postScript ExportPseudoC.java /work/source 1000 134217728 -deleteProject \
    >"$work_dir/ghidra.log" 2>&1; then
  sed -n '1,260p' "$work_dir/ghidra.log" >&2
  exit 1
fi

docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/java/openjdk/bin/java \
  -v "$jvm_class_input:/input/VulnerableFixture.class:ro" \
  -v "$work_dir/vineflower-class:/output" \
  "$JVM_DECOMPILER_IMAGE" \
  -Xms128m -Xmx3g -XX:+ExitOnOutOfMemoryError \
  -jar /opt/bytecode-tools/vineflower/vineflower.jar \
  --silent --folder /input/VulnerableFixture.class /output

docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/java/openjdk/bin/java \
  -v "$jvm_jar_input:/input/vulnerable.jar:ro" \
  -v "$work_dir/vineflower-jar:/output" \
  "$JVM_DECOMPILER_IMAGE" \
  -Xms128m -Xmx3g -XX:+ExitOnOutOfMemoryError \
  -jar /opt/bytecode-tools/vineflower/vineflower.jar \
  --silent --folder /input/vulnerable.jar /output

docker run --rm --pull never --platform "$BINARY_PLATFORM" --user root \
  --entrypoint /opt/bytecode-tools/pycdc/pycdc \
  -v "$pyc_input:/input/vulnerable.pyc:ro" \
  "$PYC_DECOMPILER_IMAGE" /input/vulnerable.pyc \
  >"$work_dir/pycdc/decompiled.py"

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
    ("native-ghidra", "native-ghidra", "c-checker", "/decompiled/ghidra/source/*.c"),
    ("jvm-class-vineflower", "jvm-vineflower", "java-checker", "/decompiled/vineflower-class/**/*.java"),
    ("jvm-jar-vineflower", "jvm-vineflower", "java-checker", "/decompiled/vineflower-jar/**/*.java"),
    ("python-pycdc", "python-pycdc", "python-checker", "/decompiled/pycdc/*.py"),
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
    with urllib.request.urlopen(request, timeout=30) as response:
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
