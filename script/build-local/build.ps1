Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$BuildScript = Join-Path $PSScriptRoot "../lib/build.py"
foreach ($candidate in @("python3", "python", "py")) {
    $command = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($null -eq $command) { continue }
    $prefix = @()
    if ($candidate -eq "py") { $prefix = @("-3") }
    & $command.Source @prefix -c "import sys; sys.exit(sys.version_info < (3, 10))" 2>$null
    if ($LASTEXITCODE -ne 0) { continue }
    & $command.Source @prefix $BuildScript local @args
    exit $LASTEXITCODE
}
throw "Python 3.10 or newer is required on the build host"
