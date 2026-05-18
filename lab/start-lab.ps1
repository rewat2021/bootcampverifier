# start-lab.ps1 - Windows PowerShell
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Detect architecture
$Arch = (Get-WmiObject Win32_Processor).Architecture
if ($Arch -eq 12) { $Tag = "arm64" } else { $Tag = "amd64" }

Write-Host "=== Lab Setup ===" -ForegroundColor Cyan
Write-Host "Architecture: $Tag"
Write-Host ""

# Check Docker is ready
Write-Host "[0/4] Checking Docker..." -ForegroundColor Yellow
$MaxWait = 60
$Waited  = 0
while ($true) {
    $Result = & docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Docker is ready." -ForegroundColor Green
        break
    }
    if ($Waited -ge $MaxWait) {
        Write-Host "" -ForegroundColor Red
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
try {
    $null = & docker network create lab-network 2>&1
    Write-Host "  Created." -ForegroundColor Green
} catch {
    Write-Host "  Already exists, skipping." -ForegroundColor Gray
}

# Load images
Write-Host ""
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
    if (Test-Path $File) {
        Write-Host "  Loading $Image..."

        # Snapshot images before load
        $Before = @(& docker images --format "{{.Repository}}:{{.Tag}}" 2>$null)

        # docker load streams progress directly to console
        & docker load --input $File

        # Find newly added images and retag to :latest
        $After = @(& docker images --format "{{.Repository}}:{{.Tag}}" 2>$null)
        $NewImages = $After | Where-Object {
            ($Before -notcontains $_) -and
            ($_ -notmatch ':latest$') -and
            ($_ -notmatch '<none>')
        }
        foreach ($Loaded in $NewImages) {
            $Base = $Loaded -replace ':[^:]+$', ''
            & docker tag $Loaded "${Base}:latest" 2>$null
            Write-Host "    Tagged: ${Base}:latest" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  ERROR: $File not found." -ForegroundColor Red
        Write-Host "         Download from GitHub Releases and place in the images\ folder." -ForegroundColor Red
        exit 1
    }
}

# Start services
Write-Host ""
Write-Host "[3/4] Starting services..." -ForegroundColor Yellow

Write-Host "  Starting VerifierAPI + MySQL..."
docker compose -f "$ScriptDir\verifier\docker-compose.yml" up -d

Write-Host "  Starting IssuerAPI + MySQL..."
docker compose -f "$ScriptDir\issuer\docker-compose.yml" up -d

Write-Host "  Starting waltid services (may take 1-5 min on first run to pull caddy/postgres)..."
docker compose -f "$ScriptDir\waltid\docker-compose.yaml" --profile identity up -d

# Connect waltid containers to lab-network (ignore if already connected)
Write-Host "  Connecting waltid services to lab-network..."
$WaltidContainers = & docker compose -f "$ScriptDir\waltid\docker-compose.yaml" --profile identity ps -q 2>$null
foreach ($CID in $WaltidContainers) {
    if ($CID) {
        try {
            $null = & docker network connect lab-network $CID 2>&1
            Write-Host "    Connected container $CID" -ForegroundColor DarkGray
        } catch {
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
