"""Exercise the actual offline install scripts without contacting Docker.

Each test has an isolated package in a path containing spaces. The Docker CLI is
replaced by a recorder; checksums, environment parsing, initialization and the
installer's error propagation execute normally. Shell tests simulate macOS UID
handling so they do not need root or change ownership on the test host.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("binary_build_delivery_test", ROOT / "script/lib/build.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
if os.name == "nt":
    SHELL = next((str(path) for path in (Path("C:/Program Files/Git/bin/bash.exe"), Path("C:/Program Files/Git/usr/bin/sh.exe")) if path.is_file()), None)
else:
    SHELL = shutil.which("sh")


PS_HARNESS = r'''
param([string]$Bundle)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function global:docker {
    $call = @($args | ForEach-Object { [string]$_ })
    [System.IO.File]::AppendAllText($env:FAKE_DOCKER_LOG, (ConvertTo-Json -InputObject $call -Compress) + [char]10)
    $global:LASTEXITCODE = 0
    switch ($call[0]) {
        "info" { "linux/x86_64" }
        "version" { "27.3.1" }
        "image" { "linux/amd64" }
        "load" { if ($env:FAKE_DOCKER_FAIL_LOAD -eq "1") { $global:LASTEXITCODE = 9 } }
        "compose" { if ($call[1] -eq "version") { "2.30.3" } }
        default { throw "unexpected Docker call: $($call -join ' ')" }
    }
}
try {
    & (Join-Path $Bundle "install.ps1")
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
'''

SH_DOCKER = '''#!/bin/sh
printf '%s\\t' "$@" >> "$FAKE_DOCKER_LOG"
printf '\\n' >> "$FAKE_DOCKER_LOG"
case "$1" in
  info) printf 'linux/x86_64\\n' ;;
  version) printf '27.3.1\\n' ;;
  image) printf 'linux/amd64\\n' ;;
  load) [ "${FAKE_DOCKER_FAIL_LOAD:-0}" != 1 ] || exit 9 ;;
  compose) [ "$2" != version ] || printf '2.30.3\\n' ;;
  *) echo "unexpected Docker command: $*" >&2; exit 99 ;;
esac
'''

SH_HARNESS = '''#!/bin/sh
set -eu
fake_bin=$1
bundle=$2
if command -v cygpath >/dev/null 2>&1; then
  fake_bin=$(cygpath -u "$fake_bin")
  bundle=$(cygpath -u "$bundle")
  FAKE_DOCKER_LOG=$(cygpath -u "$FAKE_DOCKER_LOG")
  export FAKE_DOCKER_LOG
fi
PATH="$fake_bin:$PATH"
export PATH
exec sh "$bundle/install.sh"
'''


class DeliveryInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="Binary delivery tests ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "customer package with spaces"
        self.bundle.mkdir()
        self.log = self.root / "fake docker calls.log"
        self.archive = self.bundle / "images/runtime-images.tar"
        BUILD.write_text(self.archive, "fake offline Docker archive for installer tests\n")
        BUILD.write_text(self.archive.with_suffix(".tar.sha256"), f"{BUILD.checksum(self.archive)}  {self.archive.name}\n")
        for name in BUILD.TEMPLATES:
            shutil.copyfile(ROOT / "deploy/delivery/common" / name, self.bundle / name)
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8-sig")
        BUILD.write_text(self.bundle / "docker-compose.yml", compose)
        keys = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}", compose))
        config = BUILD.runtime_config(BUILD.load_env(ROOT / ".env"), keys, "release")
        BUILD.write_text(self.bundle / ".env", "".join(f"{key}='{value}'\n" for key, value in config.items()))
        BUILD.write_manifest(self.bundle)

    def run_install(self, kind, fail_load=False):
        environment = os.environ.copy()
        environment.update(FAKE_DOCKER_LOG=str(self.log), FAKE_DOCKER_FAIL_LOAD="1" if fail_load else "0")
        if kind == "powershell":
            if not POWERSHELL:
                self.skipTest("PowerShell is not available")
            harness = self.root / "fake Docker harness.ps1"
            BUILD.write_text(harness, PS_HARNESS)
            command = [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness), str(self.bundle)]
        else:
            if not SHELL:
                self.skipTest("POSIX shell / Git Bash is not available")
            fake_bin = self.root / "fake Docker bin"
            fake_bin.mkdir()
            for name, script in {"docker": SH_DOCKER, "uname": "#!/bin/sh\nprintf 'Darwin\\n'\n", "id": "#!/bin/sh\nprintf '1000\\n'\n"}.items():
                path = fake_bin / name
                BUILD.write_text(path, script)
                path.chmod(0o755)
            harness = self.root / "fake Docker harness.sh"
            BUILD.write_text(harness, SH_HARNESS)
            command = [SHELL, str(harness), str(fake_bin), str(self.bundle)]
        result = subprocess.run(command, cwd=self.root, env=environment, text=True,
                                encoding="utf-8", errors="replace", capture_output=True, timeout=45)
        calls = []
        if self.log.exists():
            for line in self.log.read_text(encoding="utf-8-sig").splitlines():
                calls.append(json.loads(line) if kind == "powershell" else line.rstrip("\t").split("\t"))
        return result, calls

    def assert_installs(self, kind):
        result, calls = self.run_install(kind)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        loads = [call for call in calls if call[0] == "load"]
        self.assertEqual(len(loads), 1, calls)
        self.assertIn("runtime-images.tar", " ".join(loads[0]))
        starts = [call for call in calls if call[0] == "compose" and "up" in call]
        self.assertEqual(len(starts), 1, calls)
        self.assertLess(calls.index(loads[0]), calls.index(starts[0]))
        self.assertIn("--no-build", starts[0])
        self.assertEqual(starts[0][starts[0].index("--pull") + 1], "never")
        self.assertIn("--wait", starts[0])
        self.assertFalse(any(call[0] in ("build", "pull") for call in calls))
        sentinel = self.bundle / "data/.binaryscan-data-root"
        self.assertEqual(sentinel.read_text().strip(), "binaryscan-data:binary-release")
        for directory in BUILD.DATA_DIRS:
            self.assertTrue((self.bundle / "data" / directory).is_dir(), directory)

    def assert_tamper_blocks(self, kind, file):
        target = self.bundle / file
        with target.open("a", encoding="utf-8") as stream:
            stream.write("\n# modified after packaging\n")
        result, calls = self.run_install(kind)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(call[0] == "load" or "up" in call for call in calls), calls)
        self.assertFalse((self.bundle / "data").exists())

    def assert_failed_load_blocks(self, kind):
        result, calls = self.run_install(kind, fail_load=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len([call for call in calls if call[0] == "load"]), 1)
        self.assertFalse(any("up" in call for call in calls), calls)
        self.assertFalse((self.bundle / "data").exists())

    def test_powershell_installs_offline_in_path_with_spaces(self):
        self.assert_installs("powershell")

    def test_powershell_rejects_tampered_archive_before_load(self):
        self.assert_tamper_blocks("powershell", "images/runtime-images.tar")

    def test_powershell_rejects_tampered_script_before_load(self):
        self.assert_tamper_blocks("powershell", "manage.ps1")

    def test_powershell_does_not_start_after_load_failure(self):
        self.assert_failed_load_blocks("powershell")

    def test_shell_installs_offline_in_path_with_spaces(self):
        self.assert_installs("shell")

    def test_shell_rejects_tampered_archive_before_load(self):
        self.assert_tamper_blocks("shell", "images/runtime-images.tar")

    def test_shell_rejects_tampered_script_before_load(self):
        self.assert_tamper_blocks("shell", "manage.sh")

    def test_shell_does_not_start_after_load_failure(self):
        self.assert_failed_load_blocks("shell")


if __name__ == "__main__":
    unittest.main()
