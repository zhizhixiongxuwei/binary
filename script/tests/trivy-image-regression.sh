#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
fixture_root=${BINARY_FIXTURE_REPO:?set BINARY_FIXTURE_REPO to the external binary-repo fixture directory}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-trivy-image.XXXXXX")

cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

cd "$repo_dir"
# shellcheck disable=SC1091
. ./.env

docker_input="$fixture_root/03-container/docker-save.tar"
docker_img_input="$fixture_root/03-container/docker-save.img"
oci_input="$fixture_root/03-container/oci-layout.tar"
expectations="$fixture_root/03-container/expected-trivy.json"
for input in "$docker_input" "$docker_img_input" "$oci_input" "$expectations"; do
  [ -f "$input" ] || {
    echo "missing fixture: $input" >&2
    exit 1
  }
done

mkdir -p "$work_dir/docker" "$work_dir/docker-img" "$work_dir/oci" "$work_dir/oci-layout"
tar -xf "$oci_input" -C "$work_dir/oci-layout"

run_trivy() {
  name=$1
  input=$2
  input_target=$3
  output_dir="$work_dir/$name"
  docker run --rm --pull never --platform "$BINARY_PLATFORM" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    -v "$input:$input_target:ro" -v "$output_dir:/work" \
    --entrypoint sh "$SCANNER_IMAGE" -c '
      mkdir -p /work/cache
      ln -s /opt/trivy-cache/db /work/cache/db
      ln -s /opt/trivy-cache/java-db /work/cache/java-db
      exec trivy image --input "$1" --scanners vuln --format json \
        --output /work/report.json --cache-dir /work/cache \
        --skip-db-update --skip-java-db-update --offline-scan
    ' sh "$input_target"
}

run_trivy docker "$docker_input" /input/image.tar
run_trivy docker-img "$docker_img_input" /input/image.img
run_trivy oci "$work_dir/oci-layout" /input/oci-layout

python3 - "$expectations" "$work_dir/docker/report.json" \
  "$work_dir/docker-img/report.json" "$work_dir/oci/report.json" <<'PY'
import json
import pathlib
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    expectations = json.load(source)
if expectations.get("schema") != "binaryscan-trivy-image-fixtures-v1":
    raise SystemExit("unsupported Trivy fixture manifest")

required = set(expectations["requiredVulnerabilityIds"])
minimum = expectations["minimumFindings"]
package = expectations["package"]
for target_name, report_name in zip(("docker-save", "docker-img", "oci-layout"), sys.argv[2:]):
    report = json.loads(pathlib.Path(report_name).read_text(encoding="utf-8"))
    findings = [
        finding
        for result in report.get("Results", [])
        for finding in (result.get("Vulnerabilities") or [])
        if finding.get("PkgName") == package["name"]
        and finding.get("InstalledVersion") == package["version"]
    ]
    actual = {finding.get("VulnerabilityID") for finding in findings}
    missing = required - actual
    if len(findings) < minimum or missing:
        raise SystemExit(
            target_name
            + " Trivy regression failed; findings="
            + str(len(findings))
            + " missing="
            + repr(sorted(missing))
        )
    print(
        target_name
        + ": "
        + str(len(findings))
        + " Log4j 2.14.1 vulnerabilities observed"
    )
PY
