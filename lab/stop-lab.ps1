# stop-lab.ps1 - Windows PowerShell
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Stopping Lab Services ===" -ForegroundColor Yellow
Write-Host ""

Write-Host "  Stopping VerifierAPI + MySQL..."
& docker compose -f "$ScriptDir\verifier\docker-compose.yml" down -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: VerifierAPI may not have stopped cleanly." -ForegroundColor Yellow
}

Write-Host "  Stopping IssuerAPI + MySQL..."
& docker compose -f "$ScriptDir\issuer\docker-compose.yml" down -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: IssuerAPI may not have stopped cleanly." -ForegroundColor Yellow
}

Write-Host "  Stopping waltid services..."
& docker compose -f "$ScriptDir\waltid\docker-compose.yaml" --profile identity down -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: waltid services may not have stopped cleanly." -ForegroundColor Yellow
}

Write-Host "  Removing shared network 'lab-network'..."
$null = & docker network rm lab-network 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  Removed." -ForegroundColor DarkGray
} else {
    Write-Host "  Network not found or already removed, skipping." -ForegroundColor Gray
}

Write-Host ""
Write-Host "All services stopped." -ForegroundColor Green
