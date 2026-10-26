Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($args.Count -ne 0) { throw "usage: .\install.ps1" }
& docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker is not running; start Docker Desktop with Linux containers." }
& docker compose version
if ($LASTEXITCODE -ne 0) { throw "Docker Compose v2 is required." }

# Stop on any checksum/import error. Customer machines need no Python or build tools.
& (Join-Path $PSScriptRoot "verify.ps1") package
& (Join-Path $PSScriptRoot "load-images.ps1")
& (Join-Path $PSScriptRoot "manage.ps1") start
