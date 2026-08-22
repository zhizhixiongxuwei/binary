#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
set -a
# shellcheck disable=SC1090
. "$repo_dir/.env"
set +a

die() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

topology_smoke() {
  require_command docker
  require_command jq
  docker compose --project-directory "$repo_dir" --env-file "$repo_dir/.env" \
    -f "$repo_dir/docker-compose.yml" config --format json |
    jq -e '
      (.services | keys | sort) ==
        (["app", "c-checker", "java-checker", "jvm-decompiler", "mysql",
          "native-decompiler", "pyc-decompiler", "python-checker", "scanner"] | sort)
      and (.networks | keys | sort) == (["checker-net", "database-net", "edge-net"] | sort)
      and .networks["checker-net"].internal == true
      and .networks["database-net"].internal == true
      and (.networks["edge-net"].internal // false) == false
      and (((.secrets // {}) | length) == 0)
      and (((.configs // {}) | length) == 0)
      and ([.services[] | select(.build != null)] | length) == 0
      and ([.services[] | select(.image == null or .image == "" or .pull_policy != "never")] | length) == 0
      and ([.services[] | select(((.profiles // []) | length) > 0 or ((.deploy.replicas // 1) != 1))] | length) == 0
      and ([.services | to_entries[] | select(((.value.ports // []) | length) > 0) | .key] == ["app"])
      and ((.services.app.ports | length) == 1 and .services.app.ports[0].target == 8443)
      and ((.services.app.networks | keys | sort) == (["database-net", "edge-net"] | sort))
      and ((.services.mysql.networks | keys) == ["database-net"])
      and ((.services.scanner.networks | keys | sort) == (["checker-net", "database-net"] | sort))
      and ((.services["native-decompiler"].networks | keys) == ["database-net"])
      and ((.services["jvm-decompiler"].networks | keys) == ["database-net"])
      and ((.services["pyc-decompiler"].networks | keys) == ["database-net"])
      and ([.services["c-checker"], .services["java-checker"], .services["python-checker"]] |
        all(
          ((.volumes // []) | length) == 0
          and ((.ports // []) | length) == 0
          and ((.networks | keys) == ["checker-net"])
        ))
      and ((.services["c-checker"].environment | keys | sort) == (["JAVA_TOOL_OPTIONS", "SERVER_PORT"] | sort))
      and ((.services["java-checker"].environment | keys | sort) == (["JAVA_TOOL_OPTIONS", "SERVER_PORT"] | sort))
      and ((.services["python-checker"].environment | keys) == ["SERVER_PORT"])
    ' >/dev/null || die "production Compose boundaries are invalid"
  echo "production Compose boundaries are correct"
}

checker_contract_smoke() {
  require_command docker
  smoke_project=${BINARY_SMOKE_PROJECT:-$COMPOSE_PROJECT_NAME}
  checker_networks=$(docker network ls \
    --filter "label=com.docker.compose.project=$smoke_project" \
    --filter "label=com.docker.compose.network=checker-net" \
    --format '{{.Name}}')
  [ -n "$checker_networks" ] || die "checker network is not running for project $smoke_project"
  [ "$(printf '%s\n' "$checker_networks" | wc -l | tr -d ' ')" = 1 ] ||
    die "multiple checker networks found for project $smoke_project"

  docker run --rm --pull never --platform "$BINARY_PLATFORM" \
    --network "$checker_networks" --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --entrypoint python3 "$PYTHON_CHECKER_IMAGE" -c '
import json
import urllib.request

cases = [
    ("c-checker", "c", "unsafe.c", "int main(void) { char value[8]; gets(value); }", "C001"),
    ("java-checker", "java", "Unsafe.java", "class Unsafe { void run() throws Exception { Runtime.getRuntime().exec(\"id\"); } }", "JAVA001"),
    ("python-checker", "python", "unsafe.py", "eval(\"40 + 2\")", "PY001"),
]
for service, language, path, content, expected_rule in cases:
    project_id = "smoke-" + language
    body = json.dumps({
        "version": "checker-v1",
        "projectId": project_id,
        "language": language,
        "files": [{"path": path, "content": content}],
    }).encode("utf-8")
    request = urllib.request.Request(
        "http://" + service + ":8080/v1/check",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.headers.get_content_type() != "application/json":
            raise SystemExit(service + " returned a non-JSON content type")
        result = json.load(response)
    required_response = {"version", "projectId", "status", "findings", "diagnostics"}
    if not isinstance(result, dict) or set(result) != required_response:
        raise SystemExit(service + " omitted checker-v1 response fields")
    if not isinstance(result["findings"], list) or not isinstance(result["diagnostics"], list):
        raise SystemExit(service + " returned invalid checker-v1 collections")
    if len(result["findings"]) > 10000 or len(result["diagnostics"]) > 1000:
        raise SystemExit(service + " exceeded checker-v1 collection limits")
    if not all(isinstance(item, str) for item in result["diagnostics"]):
        raise SystemExit(service + " returned invalid diagnostics")
    required_finding = {"ruleId", "severity", "path", "line", "title", "message"}
    optional_finding = {"cwe", "column", "evidence"}
    for finding in result["findings"]:
        if (not isinstance(finding, dict) or not required_finding.issubset(finding)
                or not set(finding).issubset(required_finding | optional_finding)):
            raise SystemExit(service + " omitted checker-v1 finding fields")
        if not all(isinstance(finding[key], str) for key in ("ruleId", "path", "title", "message")):
            raise SystemExit(service + " returned invalid finding text")
        if finding["severity"] not in {"critical", "high", "medium", "low", "info"}:
            raise SystemExit(service + " returned an invalid finding severity")
        if (not isinstance(finding["line"], int) or isinstance(finding["line"], bool)
                or finding["line"] < 1):
            raise SystemExit(service + " returned an invalid finding line")
        if "cwe" in finding and not isinstance(finding["cwe"], str):
            raise SystemExit(service + " returned an invalid finding CWE")
        if ("column" in finding and (not isinstance(finding["column"], int)
                or isinstance(finding["column"], bool) or finding["column"] < 1)):
            raise SystemExit(service + " returned an invalid finding column")
        if "evidence" in finding and not isinstance(finding["evidence"], dict):
            raise SystemExit(service + " returned invalid finding evidence")
    rules = {finding["ruleId"] for finding in result["findings"]}
    if result.get("version") != "checker-v1" or result.get("projectId") != project_id:
        raise SystemExit(service + " returned an invalid checker-v1 identity")
    if result.get("status") != "complete" or expected_rule not in rules:
        raise SystemExit(service + " did not return expected rule " + expected_rule)
print("three checker-v1 contracts are correct")
'
}

smoke_curl() {
  if [ -n "${BINARY_SMOKE_RESOLVE:-}" ]; then
    set -- --resolve "$BINARY_SMOKE_RESOLVE" "$@"
  fi
  if [ -n "${BINARY_SMOKE_CA_CERT:-}" ]; then
    set -- --cacert "$BINARY_SMOKE_CA_CERT" "$@"
  fi
  curl --disable --noproxy '*' --silent --show-error --connect-timeout 10 --max-time 60 "$@"
}

decode_pyc_fixture() {
  fixture='YQ0NCgAAAADqyYlqSAAAAOMAAAAAAAAAAAAAAAAAAAAAAwAAAEAAAABzGAAAAGQAZAGEAFoAZQFlAGQCgwGDAQEAZANTACkEYwEAAAAAAAAAAAAAAAEAAAACAAAAQwAAAHMIAAAAdAB8AIMBUwApAU4pAdoEZXZhbCkB2gV2YWx1ZakAcgMAAAD6Li90bXAvYmluYXJ5c2Nhbi1waGFzZTQtdW5zYWZlL3Vuc2FmZS1weXRob24ucHnaCGV2YWx1YXRlAQAAAHMCAAAAAAFyBQAAAHoGNDAgKyAyTikCcgUAAADaBXByaW50cgMAAAByAwAAAHIDAAAAcgQAAADaCDxtb2R1bGU+AQAAAHMCAAAACAQ='
  if printf '%s' "$fixture" | base64 --decode > "$smoke_tmp/binaryscan-smoke-unsafe.pyc" 2>/dev/null; then
    return
  fi
  if printf '%s' "$fixture" | base64 -D > "$smoke_tmp/binaryscan-smoke-unsafe.pyc" 2>/dev/null; then
    return
  fi
  die "base64 cannot decode the embedded PYC fixture"
}

cleanup_live_smoke() {
  if [ -n "${smoke_csrf:-}" ] && [ -s "${smoke_cookie_file:-/nonexistent}" ]; then
    if ! logout_live_smoke; then
      echo "warning: smoke logout failed; the session will remain until server expiry" >&2
    fi
  fi
  if [ -n "${smoke_tmp:-}" ] && [ -d "$smoke_tmp" ]; then
    rm -rf "$smoke_tmp"
  fi
}

logout_live_smoke() {
  smoke_logout_code=$(smoke_curl --max-time 5 --output /dev/null --write-out '%{http_code}' \
    --cookie "$smoke_cookie_file" -H "X-CSRF-Token: $smoke_csrf" -X POST \
    "$smoke_base_url/api/v1/auth/logout") || return 1
  [ "$smoke_logout_code" = 204 ] || return 1
  smoke_csrf=
}

read_task() {
  smoke_curl --fail --output "$smoke_tmp/task.json" --cookie "$smoke_cookie_file" \
    "$smoke_base_url/api/v1/tasks/$smoke_task_id"
}

wait_for_automatic_runs() {
  smoke_deadline=$(( $(date +%s) + BINARY_SMOKE_TIMEOUT_SECONDS ))
  while [ "$(date +%s)" -lt "$smoke_deadline" ]; do
    read_task
    if jq -e '.runs | any(.kind == "scan" and (.status == "failed" or .status == "cancelled")) or any(.kind == "trivy_scan" and (.status == "failed" or .status == "cancelled"))' "$smoke_tmp/task.json" >/dev/null; then
      die "automatic scan failed for task $smoke_task_id"
    fi
    if jq -e '.runs | length == 2 and all(.kind == "scan" or .kind == "trivy_scan") and any(.kind == "scan" and .status == "complete") and any(.kind == "trivy_scan" and .status == "complete")' "$smoke_tmp/task.json" >/dev/null; then
      return
    fi
    sleep 2
  done
  die "automatic scan timed out for task $smoke_task_id"
}

wait_for_run() {
  smoke_wait_run_id=$1
  smoke_wait_kind=$2
  smoke_deadline=$(( $(date +%s) + BINARY_SMOKE_TIMEOUT_SECONDS ))
  while [ "$(date +%s)" -lt "$smoke_deadline" ]; do
    read_task
    smoke_wait_status=$(jq -r --arg id "$smoke_wait_run_id" '.runs[] | select(.id == $id) | .status' "$smoke_tmp/task.json")
    case "$smoke_wait_status" in
      complete) return ;;
      failed|cancelled|unsupported|partial) die "$smoke_wait_kind ended with status $smoke_wait_status" ;;
    esac
    sleep 2
  done
  die "$smoke_wait_kind timed out for task $smoke_task_id"
}

live_workflow_smoke() {
  require_command base64
  require_command curl
  require_command date
  require_command jq
  require_command mktemp

  : "${BINARY_SMOKE_USERNAME:?set BINARY_SMOKE_USERNAME to an operator or administrator account}"
  : "${BINARY_SMOKE_PASSWORD:?set BINARY_SMOKE_PASSWORD without placing it on the command line}"
  BINARY_SMOKE_TIMEOUT_SECONDS=${BINARY_SMOKE_TIMEOUT_SECONDS:-600}
  case "$BINARY_SMOKE_TIMEOUT_SECONDS" in
    ''|*[!0-9]*) die "BINARY_SMOKE_TIMEOUT_SECONDS must be a positive integer" ;;
  esac
  [ "$BINARY_SMOKE_TIMEOUT_SECONDS" -gt 0 ] || die "BINARY_SMOKE_TIMEOUT_SECONDS must be positive"
  smoke_base_url=${BINARY_SMOKE_BASE_URL:-$PUBLIC_BASE_URL}
  smoke_base_url=${smoke_base_url%/}
  case "$smoke_base_url" in
    https://*)
      smoke_https_authority=${smoke_base_url#https://}
      case "$smoke_https_authority" in
        ''|*@*|*/*|*'?'*|*'#'*) die "HTTPS smoke URL must contain only host and optional port" ;;
      esac
      ;;
    http://*)
      [ -z "${BINARY_SMOKE_RESOLVE:-}" ] || die "BINARY_SMOKE_RESOLVE is not allowed with loopback HTTP"
      smoke_http_authority=${smoke_base_url#http://}
      case "$smoke_http_authority" in
        *@*|*/*|*'?'*|*'#'*) die "loopback HTTP smoke URL must contain only host and optional port" ;;
      esac
      case "$smoke_http_authority" in
        127.0.0.1|localhost|"[::1]") ;;
        127.0.0.1:*|localhost:*|"[::1]":*)
          smoke_http_port=${smoke_http_authority##*:}
          case "$smoke_http_port" in
            ''|*[!0-9]*) die "loopback HTTP smoke port must be numeric" ;;
          esac
          if ! [ "$smoke_http_port" -ge 1 ] 2>/dev/null || ! [ "$smoke_http_port" -le 65535 ] 2>/dev/null; then
            die "loopback HTTP smoke port is outside 1-65535"
          fi
          ;;
        *) die "HTTP smoke is restricted to a loopback address" ;;
      esac
      ;;
    *) die "BINARY_SMOKE_BASE_URL must use https or loopback http" ;;
  esac
  if [ -n "${BINARY_SMOKE_CA_CERT:-}" ]; then
    [ -r "$BINARY_SMOKE_CA_CERT" ] || die "BINARY_SMOKE_CA_CERT is not readable"
  fi

  smoke_tmp=$(mktemp -d "${TMPDIR:-/tmp}/binaryscan-smoke.XXXXXX")
  smoke_cookie_file="$smoke_tmp/cookies"
  smoke_csrf=
  trap cleanup_live_smoke EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  decode_pyc_fixture

  smoke_curl --fail --output /dev/null "$smoke_base_url/healthz"
  smoke_curl --fail --output /dev/null "$smoke_base_url/readyz"
  smoke_login_body=$(jq -n '{username:env.BINARY_SMOKE_USERNAME,password:env.BINARY_SMOKE_PASSWORD}')
  unset BINARY_SMOKE_PASSWORD
  smoke_code=$(printf '%s' "$smoke_login_body" | smoke_curl \
    --output "$smoke_tmp/login.json" --write-out '%{http_code}' \
    --cookie-jar "$smoke_cookie_file" -H 'Content-Type: application/json' \
    --data-binary @- "$smoke_base_url/api/v1/auth/login")
  smoke_login_body=
  [ "$smoke_code" = 200 ] || die "login failed with HTTP $smoke_code"
  smoke_csrf=$(jq -r '.user.csrfToken // empty' "$smoke_tmp/login.json")
  [ -n "$smoke_csrf" ] || die "login response omitted the CSRF token"
  jq -e '.user.mustChangePassword == false and (.user.role == "operator" or .user.role == "administrator")' \
    "$smoke_tmp/login.json" >/dev/null || die "smoke account must complete its password change and have operator access"

  smoke_code=$(smoke_curl --output "$smoke_tmp/upload.json" --write-out '%{http_code}' \
    --cookie "$smoke_cookie_file" -H "X-CSRF-Token: $smoke_csrf" \
    -F "file=@$smoke_tmp/binaryscan-smoke-unsafe.pyc;type=application/octet-stream" \
    "$smoke_base_url/api/v1/tasks")
  [ "$smoke_code" = 201 ] || die "upload failed with HTTP $smoke_code"
  smoke_task_id=$(jq -r '.task.id // empty' "$smoke_tmp/upload.json")
  [ -n "$smoke_task_id" ] || die "upload response omitted the task ID"
  wait_for_automatic_runs

  smoke_scan_run_id=$(jq -r '.runs[] | select(.kind == "scan") | .id' "$smoke_tmp/task.json")
  smoke_trivy_run_id=$(jq -r '.runs[] | select(.kind == "trivy_scan") | .id' "$smoke_tmp/task.json")
  smoke_file_id=$(jq -r '.files[] | select(.detectedFormat == "pyc") | .id' "$smoke_tmp/task.json" | head -1)
  [ -n "$smoke_file_id" ] || die "scanner did not identify the PYC fixture"

  smoke_code=$(smoke_curl --output "$smoke_tmp/decompile.json" --write-out '%{http_code}' \
    --cookie "$smoke_cookie_file" -H "X-CSRF-Token: $smoke_csrf" \
    -H "Idempotency-Key: smoke-pyc-decompile-$smoke_task_id" -X POST \
    "$smoke_base_url/api/v1/tasks/$smoke_task_id/files/$smoke_file_id/decompile")
  [ "$smoke_code" = 201 ] || die "PYC decompile queue failed with HTTP $smoke_code"
  smoke_decompile_run_id=$(jq -r '.run.id // empty' "$smoke_tmp/decompile.json")
  [ -n "$smoke_decompile_run_id" ] || die "decompile response omitted the run ID"
  wait_for_run "$smoke_decompile_run_id" pyc_decompile
  smoke_project_id=$(jq -r --arg run "$smoke_decompile_run_id" '.projects[] | select(.runId == $run and .language == "python" and .resultQuality != "bytecode_only") | .id' "$smoke_tmp/task.json" | head -1)
  [ -n "$smoke_project_id" ] || die "PYC decompile did not publish Python source"

  smoke_code=$(smoke_curl --output "$smoke_tmp/check.json" --write-out '%{http_code}' \
    --cookie "$smoke_cookie_file" -H "X-CSRF-Token: $smoke_csrf" \
    -H "Idempotency-Key: smoke-python-check-$smoke_task_id" -X POST \
    "$smoke_base_url/api/v1/tasks/$smoke_task_id/projects/$smoke_project_id/check")
  [ "$smoke_code" = 201 ] || die "Python check queue failed with HTTP $smoke_code"
  smoke_check_run_id=$(jq -r '.run.id // empty' "$smoke_tmp/check.json")
  [ -n "$smoke_check_run_id" ] || die "check response omitted the run ID"
  wait_for_run "$smoke_check_run_id" python_check
  smoke_curl --fail --output "$smoke_tmp/findings.json" --cookie "$smoke_cookie_file" \
    "$smoke_base_url/api/v1/tasks/$smoke_task_id/findings?runId=$smoke_check_run_id"
  jq -e '.findings | any(.ruleId == "PY001")' "$smoke_tmp/findings.json" >/dev/null ||
    die "Python checker did not return PY001"

  jq -n --arg scan "$smoke_scan_run_id" --arg trivy "$smoke_trivy_run_id" \
    --arg decompile "$smoke_decompile_run_id" --arg check "$smoke_check_run_id" \
    '{format:"json",runIds:[$scan,$trivy,$decompile,$check]}' > "$smoke_tmp/report-request.json"
  smoke_code=$(smoke_curl --output "$smoke_tmp/report.json" --write-out '%{http_code}' \
    --cookie "$smoke_cookie_file" -H "X-CSRF-Token: $smoke_csrf" \
    -H 'Content-Type: application/json' --data-binary "@$smoke_tmp/report-request.json" \
    "$smoke_base_url/api/v1/tasks/$smoke_task_id/reports")
  [ "$smoke_code" = 201 ] || die "report creation failed with HTTP $smoke_code"
  smoke_report_id=$(jq -r '.report.id // empty' "$smoke_tmp/report.json")
  [ -n "$smoke_report_id" ] || die "report response omitted the report ID"
  smoke_curl --fail --output "$smoke_tmp/report-content.json" --cookie "$smoke_cookie_file" \
    "$smoke_base_url/api/v1/reports/$smoke_report_id/content"
  jq -e --arg task "$smoke_task_id" --arg scan "$smoke_scan_run_id" \
    --arg trivy "$smoke_trivy_run_id" --arg decompile "$smoke_decompile_run_id" \
    --arg check "$smoke_check_run_id" '
      .schema == "binaryscan-report-v1"
      and .task.id == $task
      and (([.runs[].id] | sort) == ([$scan, $trivy, $decompile, $check] | sort))
      and any(.findings[]; .ruleId == "PY001" and .runId == $check)
    ' \
    "$smoke_tmp/report-content.json" >/dev/null || die "downloaded report does not match the smoke workflow"

  logout_live_smoke || die "workflow completed but logout failed"
  echo "live workflow smoke passed: task=$smoke_task_id report=$smoke_report_id"
}

case "${1:-topology}" in
  topology) topology_smoke ;;
  contracts) checker_contract_smoke ;;
  live) live_workflow_smoke ;;
  all)
    topology_smoke
    checker_contract_smoke
    live_workflow_smoke
    ;;
  *)
    echo "usage: $0 {topology|contracts|live|all}" >&2
    exit 2
    ;;
esac
