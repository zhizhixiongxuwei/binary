Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BundleRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$ImagesRoot = Join-Path $BundleRoot "images"

function Stop-WithError {
    param([string]$Message)
    throw "error: $Message"
}

if (-not (Test-Path -LiteralPath $ImagesRoot -PathType Container)) {
    Stop-WithError "missing $ImagesRoot"
}

$archives = @(
    Get-ChildItem -LiteralPath $ImagesRoot -Recurse -File -Filter "*.tar" |
        Sort-Object -Property FullName
)
if ($archives.Count -eq 0) {
    Stop-WithError "no Docker image archives found under $ImagesRoot"
}

foreach ($archive in $archives) {
    $checksumPath = $archive.FullName + ".sha256"
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        Stop-WithError "missing $checksumPath"
    }

    $checksumLine = [System.IO.File]::ReadAllText($checksumPath).Trim()
    if ($checksumLine -notmatch "^([0-9A-Fa-f]{64})[ \t]+") {
        Stop-WithError "invalid checksum file: $checksumPath"
    }

    $expected = $Matches[1].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Stop-WithError "SHA-256 mismatch: $($archive.FullName)"
    }

    Write-Host ("{0}: OK" -f $archive.Name)
    Write-Host ("loading {0}" -f $archive.Name)
    & docker load --input $archive.FullName
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "docker load failed for $($archive.FullName)"
    }
}

Write-Host "all delivery images are loaded"
