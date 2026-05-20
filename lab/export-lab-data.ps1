# export-lab-data.ps1 — Export MySQL data from running lab containers
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DbPass    = if ($env:MYSQL_ROOT_PASSWORD) { $env:MYSQL_ROOT_PASSWORD } else { "P@ssw0rd@1234" }
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportDir = Join-Path $ScriptDir "lab-data-export"
$OutFile   = Join-Path $ScriptDir "lab-data-${Timestamp}.zip"

Write-Host "=== Export Lab Data ===" -ForegroundColor Cyan
Write-Host ""

New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

# Export Verifier DB
Write-Host "[1/2] Exporting Verifier database..." -ForegroundColor Yellow
$null = & docker exec verifier-mysql mysqladmin ping -uroot -p"$DbPass" --silent 2>$null
if ($LASTEXITCODE -eq 0) {
    & docker exec verifier-mysql mysqldump -uroot -p"$DbPass" verifier 2>$null `
        | Out-File -Encoding utf8 -FilePath (Join-Path $ExportDir "verifier.sql")
    $Rows = (Select-String -Path (Join-Path $ExportDir "verifier.sql") -Pattern "^INSERT INTO").Count
    Write-Host "  Done — $Rows INSERT statements" -ForegroundColor Green
} else {
    Write-Host "  ERROR: verifier-mysql is not running" -ForegroundColor Red
    exit 1
}

# Export Issuer DB
Write-Host "[2/2] Exporting Issuer database..." -ForegroundColor Yellow
$null = & docker exec issuer-mysql mysqladmin ping -uroot -p"$DbPass" --silent 2>$null
if ($LASTEXITCODE -eq 0) {
    & docker exec issuer-mysql mysqldump -uroot -p"$DbPass" issuer 2>$null `
        | Out-File -Encoding utf8 -FilePath (Join-Path $ExportDir "issuer.sql")
    $Rows = (Select-String -Path (Join-Path $ExportDir "issuer.sql") -Pattern "^INSERT INTO").Count
    Write-Host "  Done — $Rows INSERT statements" -ForegroundColor Green
} else {
    Write-Host "  WARNING: issuer-mysql is not running, skipping" -ForegroundColor Yellow
}

# Package to zip
Write-Host ""
Write-Host "Packaging..." -ForegroundColor Yellow
Compress-Archive -Path $ExportDir -DestinationPath $OutFile -Force
Remove-Item -Recurse -Force $ExportDir

Write-Host ""
Write-Host "Export complete!" -ForegroundColor Green
Write-Host "  File: $OutFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "Copy this file to machine B, then run:"
Write-Host "  .\import-lab-data.ps1 lab-data-${Timestamp}.zip"
