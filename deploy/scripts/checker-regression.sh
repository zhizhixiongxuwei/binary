#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
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

docker run --rm --pull never --platform "$BINARY_PLATFORM" \
  --network "$checker_network" --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$repo_dir/test-fixtures/vulnerable:/fixtures:ro" \
  --entrypoint python3 "$PYTHON_CHECKER_IMAGE" -c '
import json
import urllib.request

with open("/fixtures/expected-findings.json", encoding="utf-8") as source:
    expected_manifest = json.load(source)
if expected_manifest.get("schema") != "binaryscan-checker-fixtures-v1":
    raise SystemExit("unsupported checker fixture manifest")
targets = expected_manifest["targets"]

cases = [
    (
        "native-ghidra", "c-checker", "native.c", "/fixtures/native.c",
    ),
    (
        "jvm-vineflower", "java-checker", "VulnerableFixture.java",
        "/fixtures/VulnerableFixture.java",
    ),
    (
        "python-pycdc", "python-checker", "unsafe.py", "/fixtures/unsafe.pycdc.py",
    ),
]

for target_name, service, path, source_path in cases:
    target = targets[target_name]
    language = target["language"]
    expected = set(target["expectedRuleIds"])
    with open(source_path, encoding="utf-8") as source:
        content = source.read()
    body = json.dumps({
        "version": "checker-v1",
        "projectId": "regression-" + language,
        "language": language,
        "files": [{"path": path, "content": content}],
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
            service + " regression failed; missing=" + repr(sorted(missing))
            + " unexpected=" + repr(sorted(unexpected))
            + " diagnostics=" + repr(result.get("diagnostics"))
        )
    print(service + ": " + str(len(actual)) + " rule families observed")
'
