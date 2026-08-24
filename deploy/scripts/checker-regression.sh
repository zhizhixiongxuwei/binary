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

cases = [
    (
        "c-checker", "c", "native.c", "/fixtures/native.c",
        {"cwe-120-bounds", "cwe-78-command", "cwe-732-permissions"},
    ),
    (
        "java-checker", "java", "VulnerableFixture.java", "/fixtures/VulnerableFixture.java",
        {
            "java-weak-message-digest", "java-weak-cipher", "java-legacy-tls",
            "java-hardcoded-crypto-key", "java-trust-all-hostname-verifier",
            "java-trust-all-x509-manager", "java-xxe-enabled",
            "java-unsafe-deserialization", "java-sql-injection",
            "java-command-injection", "java-dynamic-code-execution",
            "java-overly-permissive-file", "java-insecure-cookie",
        },
    ),
    (
        "python-checker", "python", "unsafe.py", "/fixtures/unsafe.pycdc.py",
        {
            "python-dynamic-code-execution", "python-command-injection",
            "python-unsafe-deserialization", "python-weak-message-digest",
            "python-insecure-request",
        },
    ),
]

for service, language, path, source_path, expected in cases:
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
    if result.get("status") != "complete" or missing:
        raise SystemExit(
            service + " regression failed; missing=" + repr(sorted(missing))
            + " diagnostics=" + repr(result.get("diagnostics"))
        )
    print(service + ": " + str(len(actual)) + " rule families observed")
'
