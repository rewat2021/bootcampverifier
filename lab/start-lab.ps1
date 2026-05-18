# start-lab.ps1 - Windows PowerShell
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Detect architecture via env var (works on all PowerShell versions)
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $Tag = "arm64" } else { $Tag = "amd64" }

Write-Host "=== Lab Setup ===" -ForegroundColor Cyan
Write-Host "Architecture: $Tag"
Write-Host ""

# Check Docker is ready
Write-Host "[0/4] Checking Docker..." -ForegroundColor Yellow
$MaxWait = 60
$Waited  = 0
while ($true) {
    $null = & docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Docker is ready." -ForegroundColor Green
        break
    }
    if ($Waited -ge $MaxWait) {
        Write-Host ""
        Write-Host "ERROR: Docker is not responding after ${MaxWait}s." -ForegroundColor Red
        Write-Host ""
        Write-Host "How to fix:" -ForegroundColor Yellow
        Write-Host "  1. Open Docker Desktop and wait until the icon in System Tray stops spinning"
        Write-Host "  2. If Docker Desktop is already open, right-click icon -> Restart"
        Write-Host "  3. Close and reopen Docker Desktop, wait 30s, then run this script again"
        exit 1
    }
    Write-Host "  Docker not ready yet, waiting... (${Waited}s)" -ForegroundColor Gray
    Start-Sleep -Seconds 5
    $Waited += 5
}
Write-Host ""

# Create shared Docker network
Write-Host "[1/4] Creating shared network 'lab-network'..." -ForegroundColor Yellow
$null = & docker network create lab-network 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Created." -ForegroundColor Green
} else {
    Write-Host "  Already exists, skipping." -ForegroundColor Gray
}
Write-Host ""

# Load images
Write-Host "[2/4] Loading Docker images..." -ForegroundColor Yellow
$ImagesDir = Join-Path $ScriptDir "images"

$AllImages = @(
    "verifier-api",
    "issuer-api",
    "waltid-wallet-api",
    "waltid-issuer-api",
    "waltid-verifier-api",
    "waltid-verifier-api2",
    "waltid-portal",
    "waltid-demo-wallet",
    "waltid-dev-wallet"
)

foreach ($Image in $AllImages) {
    $File = Join-Path $ImagesDir "${Image}-linux-${Tag}.tar.gz"
    if (-not (Test-Path $File)) {
        Write-Host "  ERROR: $File not found." -ForegroundColor Red
        Write-Host "         Download from GitHub Releases and place in the images\ folder." -ForegroundColor Red
        exit 1
    }

    Write-Host "  Loading $Image..."

    # Capture output to parse "Loaded image: repo:tag" lines
    $LoadOutput = & docker load --input $File 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: Failed to load ${Image}:" -ForegroundColor Red
        $LoadOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        exit 1
    }

    # Retag loaded image to :latest
    foreach ($Line in $LoadOutput) {
        Write-Host "    $Line" -ForegroundColor DarkGray
        if ($Line -match 'Loaded image:\s+(.+)') {
            $LoadedTag = $Matches[1].Trim()
            if ($LoadedTag -notmatch ':latest$') {
                $Base = $LoadedTag -replace ':[^:]+$', ''
                $null = & docker tag $LoadedTag "${Base}:latest" 2>&1
                Write-Host "    Tagged: ${Base}:latest" -ForegroundColor DarkGray
            }
        }
    }
}

# Start services
Write-Host ""
Write-Host "[3/4] Starting services..." -ForegroundColor Yellow

Write-Host "  Starting VerifierAPI + MySQL..."
& docker compose -f "$ScriptDir\verifier\docker-compose.yml" up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to start VerifierAPI." -ForegroundColor Red
    exit 1
}

Write-Host "  Starting IssuerAPI + MySQL..."
& docker compose -f "$ScriptDir\issuer\docker-compose.yml" up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to start IssuerAPI." -ForegroundColor Red
    exit 1
}

Write-Host "  Starting waltid services (may take 1-5 min on first run to pull caddy/postgres)..."
& docker compose -f "$ScriptDir\waltid\docker-compose.yaml" --profile identity up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to start waltid services." -ForegroundColor Red
    exit 1
}

# Connect waltid containers to lab-network
Write-Host "  Connecting waltid services to lab-network..."
$WaltidContainers = & docker compose -f "$ScriptDir\waltid\docker-compose.yaml" --profile identity ps -q 2>&1
foreach ($CID in $WaltidContainers) {
    if (-not [string]::IsNullOrWhiteSpace($CID)) {
        $null = & docker network connect lab-network $CID 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    Connected container $CID" -ForegroundColor DarkGray
        } else {
            Write-Host "    Already connected: $CID" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "[4/4] All services started." -ForegroundColor Green
Write-Host ""
Write-Host "  VerifierAPI    : http://localhost:5001/swagger" -ForegroundColor Cyan
Write-Host "  IssuerAPI      : http://localhost:5002/swagger" -ForegroundColor Cyan
Write-Host "  waltid wallet  : http://localhost:7101" -ForegroundColor Cyan
Write-Host "  waltid portal  : http://localhost:7102" -ForegroundColor Cyan
Write-Host "  waltid issuer  : http://localhost:7002" -ForegroundColor Cyan
Write-Host "  waltid verifier: http://localhost:7003" -ForegroundColor Cyan
Write-Host ""
Write-Host "To stop all services, run: .\stop-lab.ps1"
