param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "init", "doctor", "start", "stop", "restart", "restart-app", "down", "reset", "status", "logs")]
    [string]$Command = "help",

    [switch]$Yes,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BundleRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$EnvFile = Join-Path $BundleRoot ".env"
$ComposeFile = Join-Path $BundleRoot "docker-compose.yml"
$DataRoot = [System.IO.Path]::GetFullPath((Join-Path $BundleRoot "data"))
$Sentinel = Join-Path $DataRoot ".binaryscan-data-root"

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
        $value = $line.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and
            (($value.StartsWith("'") -and $value.EndsWith("'")) -or
             ($value.StartsWith('"') -and $value.EndsWith('"')))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($name -notmatch "^[A-Za-z_][A-Za-z0-9_]*$") {
            Stop-WithError "invalid .env variable name: $name"
        }
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }

    if ($env:BINARY_DATA_ROOT -ne "./data") {
        Stop-WithError "BINARY_DATA_ROOT must remain ./data in this sealed delivery"
    }
    $env:BINARY_DATA_ROOT = $DataRoot
}

function Get-RequiredEnvironment {
    param([string]$Name)
    $value = [System.Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($value)) {
        Stop-WithError "$Name is required in .env"
    }
    return $value
}

function Invoke-Docker {
    param([string[]]$DockerArguments)
    & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError ("docker command failed: docker {0}" -f ($DockerArguments -join " "))
    }
}

function Invoke-Compose {
    param([string[]]$Arguments)
    $dockerArguments = @(
        "compose",
        "--project-directory", $BundleRoot,
        "--env-file", $EnvFile,
        "-f", $ComposeFile
    ) + $Arguments
    Invoke-Docker $dockerArguments
}

function Test-ReparsePoint {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Stop-WithError "path must not be a symlink or junction: $Path"
        }
    }
}

function Test-DataTarget {
    $expected = [System.IO.Path]::GetFullPath((Join-Path $BundleRoot "data"))
    if (-not $DataRoot.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-WithError "unexpected data target: $DataRoot"
    }
    Test-ReparsePoint $DataRoot
    if ((Test-Path -LiteralPath $DataRoot) -and
        -not (Test-Path -LiteralPath $DataRoot -PathType Container)) {
        Stop-WithError "data target is not a directory: $DataRoot"
    }
}

function Test-Sentinel {
    if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
        Stop-WithError "data sentinel is missing; refusing destructive operation"
    }
    Test-ReparsePoint $Sentinel

    $projectName = Get-RequiredEnvironment "COMPOSE_PROJECT_NAME"
    $expected = "binaryscan-data:$projectName"
    $actual = [System.IO.File]::ReadAllText($Sentinel).Trim()
    if ($actual -ne $expected) {
        Stop-WithError "data sentinel does not match this delivery"
    }
}

function Initialize-Data {
    Test-DataTarget
    $productUid = Get-RequiredEnvironment "PRODUCT_UID"
    $productGid = Get-RequiredEnvironment "PRODUCT_GID"
    $projectName = Get-RequiredEnvironment "COMPOSE_PROJECT_NAME"
    $null = $productUid
    $null = $productGid

    if ((Test-Path -LiteralPath $DataRoot -PathType Container) -and
        -not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
        $firstEntry = Get-ChildItem -LiteralPath $DataRoot -Force | Select-Object -First 1
        if ($null -ne $firstEntry) {
            Stop-WithError "$DataRoot is non-empty and has no delivery sentinel"
        }
    }

    $directories = @(
        "mysql",
        "storage/uploads",
        "storage/blobs",
        "storage/artifacts",
        "storage/projects/native",
        "storage/projects/jvm",
        "storage/projects/pyc",
        "storage/reports",
        "work/scanner",
        "work/native-decompiler",
        "work/jvm-decompiler",
        "work/pyc-decompiler"
    )
    foreach ($relativePath in $directories) {
        $nativePath = $relativePath.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
        $null = New-Item -ItemType Directory -Path (Join-Path $DataRoot $nativePath) -Force
    }

    [System.IO.File]::WriteAllText(
        $Sentinel,
        ("binaryscan-data:$projectName" + [char]10),
        [System.Text.Encoding]::ASCII
    )
    Write-Host "initialized mutable data at $DataRoot"
}

function Test-RuntimeImages {
    $expectedPlatform = Get-RequiredEnvironment "BINARY_PLATFORM"
    $imageVariables = @(
        "MYSQL_IMAGE",
        "APP_IMAGE",
        "SCANNER_IMAGE",
        "NATIVE_DECOMPILER_IMAGE",
        "JVM_DECOMPILER_IMAGE",
        "PYC_DECOMPILER_IMAGE",
        "C_CHECKER_IMAGE",
        "JAVA_CHECKER_IMAGE",
        "PYTHON_CHECKER_IMAGE"
    )

    foreach ($variableName in $imageVariables) {
        $image = Get-RequiredEnvironment $variableName
        $actual = & docker image inspect --format "{{.Os}}/{{.Architecture}}" $image 2>$null
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "required image is not loaded: $image (run .\load-images.ps1)"
        }
        if ($actual.Trim() -ne $expectedPlatform) {
            Stop-WithError ("platform mismatch for {0}: expected {1}, got {2}" -f $image, $expectedPlatform, $actual)
        }
    }
}

function Test-Delivery {
    Test-DataTarget
    Test-Sentinel
    if (-not (Test-Path -LiteralPath (Join-Path $DataRoot "mysql") -PathType Container)) {
        Stop-WithError "data is not initialized; run .\manage.ps1 init"
    }

    if ($null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError "docker is not installed or is not on PATH"
    }

    $dockerHost = & docker info --format "{{.OSType}}/{{.Architecture}}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "Docker Desktop is not running"
    }
    if (-not $dockerHost.Trim().StartsWith("linux/")) {
        Stop-WithError "Docker Desktop must use Linux containers (WSL2), not Windows containers"
    }

    Invoke-Docker @("compose", "version")
    Invoke-Compose @("config", "--quiet")
    Test-RuntimeImages
    Write-Host "configuration, data layout, and nine runtime images are valid"
}

function Start-Delivery {
    if (-not (Test-Path -LiteralPath $Sentinel -PathType Leaf)) {
        Initialize-Data
    }
    Test-Delivery
    Invoke-Compose @("up", "-d", "--no-build", "--pull", "never", "--remove-orphans", "--wait")
}

function Reset-AndStart {
    if (-not $Yes.IsPresent) {
        Stop-WithError "reset permanently deletes all mounted data; run: .\manage.ps1 reset -Yes"
    }

    Test-DataTarget
    Test-Sentinel
    Invoke-Compose @("down", "--remove-orphans")

    Get-ChildItem -LiteralPath $DataRoot -Force | Remove-Item -Recurse -Force
    Initialize-Data
    Test-Delivery
    Invoke-Compose @("up", "-d", "--no-build", "--pull", "never", "--remove-orphans", "--wait")
}

Import-DeliveryEnvironment

switch ($Command) {
    "help" {
        Write-Host "usage: .\manage.ps1 {init|doctor|start|stop|restart|restart-app|down|reset -Yes|status|logs [service]}"
    }
    "init" {
        Initialize-Data
    }
    "doctor" {
        Test-Delivery
    }
    "start" {
        Start-Delivery
    }
    "stop" {
        Invoke-Compose @("stop")
    }
    "restart" {
        Test-Delivery
        Invoke-Compose @("up", "-d", "--no-build", "--pull", "never", "--remove-orphans", "--force-recreate", "--wait")
    }
    "restart-app" {
        Test-Delivery
        Invoke-Compose @("up", "-d", "--no-build", "--pull", "never", "--no-deps", "--force-recreate", "--wait", "app")
    }
    "down" {
        Invoke-Compose @("down", "--remove-orphans")
    }
    "reset" {
        Reset-AndStart
    }
    "status" {
        Invoke-Compose @("ps")
    }
    "logs" {
        Invoke-Compose (@("logs") + $ComposeArguments)
    }
}
