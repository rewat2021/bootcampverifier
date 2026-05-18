# stop-lab.ps1 — Windows PowerShell
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Stopping Lab Services ===" -ForegroundColor Yellow

docker compose -f "$ScriptDir\verifier\docker-compose.yml" down
docker compose -f "$ScriptDir\issuer\docker-compose.yml" down
docker compose -f "$ScriptDir\waltid\docker-compose.yaml" --profile identity down

Write-Host "All services stopped." -ForegroundColor Green
