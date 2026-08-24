param(
    [Parameter(Position = 0)]
    [ValidateSet("package", "source", "all")]
    [string]$Mode = "package"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BundleRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Stop-WithError {
    param([string]$Message)
    throw "error: $Message"
}

function Resolve-SealedPath {
    param([string]$RelativePath)

    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        Stop-WithError "manifest contains an absolute path: $RelativePath"
    }

    $normalized = $RelativePath.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $parts = $normalized.Split([System.IO.Path]::DirectorySeparatorChar)
    if ($parts -contains "..") {
        Stop-WithError "manifest path escapes the delivery root: $RelativePath"
    }

    $resolved = [System.IO.Path]::GetFullPath((Join-Path $BundleRoot $normalized))
    $rootPrefix = $BundleRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-WithError "manifest path escapes the delivery root: $RelativePath"
    }
    return $resolved
}

function Test-SealedManifest {
    param([string]$ManifestRelativePath)

    $manifestPath = Resolve-SealedPath $ManifestRelativePath
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Stop-WithError "missing $ManifestRelativePath"
    }

    foreach ($line in [System.IO.File]::ReadAllLines($manifestPath, $Utf8NoBom)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -notmatch "^([0-9A-Fa-f]{64})[ \t]+\*?(.+)$") {
            Stop-WithError "invalid SHA-256 manifest line in $ManifestRelativePath"
        }

        $expected = $Matches[1].ToLowerInvariant()
        $relativePath = $Matches[2]
        $filePath = Resolve-SealedPath $relativePath
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            Stop-WithError "missing sealed file: $relativePath"
        }

        $actual = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            Stop-WithError "SHA-256 mismatch: $relativePath"
        }
        Write-Host ("{0}: OK" -f $relativePath)
    }
}

switch ($Mode) {
    "package" {
        Test-SealedManifest "manifests/package.sha256"
    }
    "source" {
        Test-SealedManifest "manifests/source.sha256"
    }
    "all" {
        Test-SealedManifest "manifests/package.sha256"
        $sourceManifest = Join-Path $BundleRoot "manifests/source.sha256"
        if (Test-Path -LiteralPath $sourceManifest -PathType Leaf) {
            Test-SealedManifest "manifests/source.sha256"
        }
    }
}
