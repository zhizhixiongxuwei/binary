Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BundleRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$AppRoot = Join-Path $BundleRoot "app"
$EnvFile = Join-Path $BundleRoot ".env"
$EvidenceRoot = Join-Path $BundleRoot "build-output"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Stop-WithError {
    param([string]$Message)
    throw "error: $Message"
}

function Import-DeliveryEnvironment {
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        Stop-WithError "missing $EnvFile"
    }

    foreach ($rawLine in [System.IO.File]::ReadAllLines($EnvFile)) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
            continue
        }

        $separator = $line.IndexOf("=")
        if ($separator -le 0) {
            Stop-WithError "invalid .env line: $rawLine"
        }

        $name = $line.Substring(0, $separator).Trim()
        $value = $line.Substring($separator + 1)
        if ($name -notmatch "^[A-Za-z_][A-Za-z0-9_]*$") {
            Stop-WithError "invalid .env variable name: $name"
        }
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

function Get-RequiredEnvironment {
    param([string]$Name)
    $value = [System.Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) {
        Stop-WithError "$Name is required in .env"
    }
    return $value
}

function Get-EnvironmentOrDefault {
    param(
        [string]$Name,
        [string]$DefaultValue
    )
    $value = [System.Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }
    return $value
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-LfLines {
    param(
        [string]$Path,
        [string[]]$Lines
    )
    $lineFeed = [string][char]10
    $fileContent = ($Lines -join $lineFeed) + $lineFeed
    [System.IO.File]::WriteAllText($Path, $fileContent, $Utf8NoBom)
}

function New-TreeManifest {
    param(
        [string]$TreeRoot,
        [string]$OutputPath
    )

    $root = [System.IO.Path]::GetFullPath($TreeRoot).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $relativePaths = @(
        Get-ChildItem -LiteralPath $root -Recurse -File -Force | ForEach-Object {
            $relative = $_.FullName.Substring($root.Length)
            $relative = $relative.TrimStart([char[]]@([char]92, [char]47))
            $relative = $relative.Replace([char]92, [char]47)
            "./$relative"
        }
    )
    [System.Array]::Sort($relativePaths, [System.StringComparer]::Ordinal)

    $lines = @()
    foreach ($relativePath in $relativePaths) {
        $nativeRelative = $relativePath.Substring(2).Replace(
            [char]47,
            [System.IO.Path]::DirectorySeparatorChar
        )
        $filePath = Join-Path $root $nativeRelative
        $lines += ("{0}  {1}" -f (Get-Sha256 $filePath), $relativePath)
    }
    Write-LfLines $OutputPath $lines
    return Get-Sha256 $OutputPath
}

function New-DependencyManifest {
    param([string]$OutputPath)

    $relativePaths = @(
        "backend/go.mod",
        "backend/go.sum",
        "frontend/package.json",
        "frontend/package-lock.json"
    )
    $lines = @()
    foreach ($relativePath in $relativePaths) {
        $nativeRelative = $relativePath.Replace(
            [char]47,
            [System.IO.Path]::DirectorySeparatorChar
        )
        $filePath = Join-Path $AppRoot $nativeRelative
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            Stop-WithError "missing dependency lock file: $relativePath"
        }
        $lines += ("{0}  {1}" -f (Get-Sha256 $filePath), $relativePath)
    }
    Write-LfLines $OutputPath $lines
    return Get-Sha256 $OutputPath
}

function Assert-Image {
    param([string]$Image)
    & docker image inspect $Image *> $null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "offline build image is not loaded: $Image (run .\load-images.ps1)"
    }
}

Import-DeliveryEnvironment

if (-not (Test-Path -LiteralPath (Join-Path $AppRoot "Dockerfile") -PathType Leaf)) {
    Stop-WithError "missing app\Dockerfile"
}
if ($null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-WithError "docker is not installed or is not on PATH"
}

$AppImage = Get-RequiredEnvironment "APP_IMAGE"
$BinaryVersion = Get-RequiredEnvironment "BINARY_VERSION"
$BinaryPlatform = Get-RequiredEnvironment "BINARY_PLATFORM"
$AppBuildDepsImage = Get-EnvironmentOrDefault "APP_BUILD_DEPS_IMAGE" "binaryscan/app-build-deps:0.1.0-dev"
$GoBuildImage = Get-EnvironmentOrDefault "GO_BUILD_IMAGE" "public.ecr.aws/docker/library/golang:1.26.7-bookworm"
$NodeBuildImage = Get-EnvironmentOrDefault "NODE_BUILD_IMAGE" "public.ecr.aws/docker/library/node:22.19.0-bookworm-slim"
$AppRuntimeImage = Get-EnvironmentOrDefault "APP_RUNTIME_IMAGE" "gcr.io/distroless/static-debian12:nonroot"

$null = New-Item -ItemType Directory -Path $EvidenceRoot -Force
$timestamp = [System.DateTime]::UtcNow.ToString(
    "yyyyMMddTHHmmssZ",
    [System.Globalization.CultureInfo]::InvariantCulture
)
$sourceManifest = Join-Path $EvidenceRoot "source-$timestamp.sha256"
$dependencyManifest = Join-Path $EvidenceRoot "dependencies-$timestamp.sha256"
$sourceSha = New-TreeManifest $AppRoot $sourceManifest
$dependencySha = New-DependencyManifest $dependencyManifest

foreach ($image in @($AppBuildDepsImage, $GoBuildImage, $NodeBuildImage, $AppRuntimeImage)) {
    Assert-Image $image
}

$cachedDependencySha = & docker image inspect --format '{{index .Config.Labels "com.binaryscan.dependency-lock-sha256"}}' $AppBuildDepsImage
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "cannot inspect dependency label on $AppBuildDepsImage"
}
if ($cachedDependencySha.Trim() -ne $dependencySha) {
    Stop-WithError "dependency lock files changed; the sealed offline dependency image no longer matches"
}

Write-Host "building $AppImage from source digest $sourceSha with networking disabled"
$buildArguments = @(
    "build",
    "--platform", $BinaryPlatform,
    "--network=none",
    "--pull=false",
    "--provenance=false",
    "--progress=plain",
    "-f", (Join-Path $AppRoot "Dockerfile"),
    "-t", $AppImage,
    "--build-arg", "APP_BUILD_DEPS_IMAGE=$AppBuildDepsImage",
    "--build-arg", "GO_BUILD_IMAGE=$GoBuildImage",
    "--build-arg", "NODE_BUILD_IMAGE=$NodeBuildImage",
    "--build-arg", "APP_RUNTIME_IMAGE=$AppRuntimeImage",
    "--build-arg", "BINARY_VERSION=$BinaryVersion",
    "--build-arg", "SOURCE_SHA256=$sourceSha",
    "--build-arg", "DEPENDENCY_LOCK_SHA256=$dependencySha",
    $AppRoot
)
& docker @buildArguments
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "offline App build failed"
}

$imageId = (& docker image inspect --format "{{.Id}}" $AppImage).Trim()
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "cannot inspect built image $AppImage"
}
$platform = (& docker image inspect --format "{{.Os}}/{{.Architecture}}" $AppImage).Trim()
if ($platform -ne $BinaryPlatform) {
    Stop-WithError "built image platform mismatch: expected $BinaryPlatform, got $platform"
}

$evidencePath = Join-Path $EvidenceRoot "app-build-$timestamp.txt"
$evidenceLines = @(
    "built_at_utc=$timestamp",
    "app_image=$AppImage",
    "image_id=$imageId",
    "platform=$platform",
    "source_sha256=$sourceSha",
    "dependency_lock_sha256=$dependencySha",
    "network=none",
    "dockerfile=app/Dockerfile",
    "host_shell=PowerShell"
)
Write-LfLines $evidencePath $evidenceLines

Write-Host "built image: $AppImage"
Write-Host "evidence: $evidencePath"
Write-Host "apply it with: .\manage.ps1 restart-app"
