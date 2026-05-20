# import-lab-data.ps1 — Import MySQL data into running lab containers
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DbPass    = if ($env:MYSQL_ROOT_PASSWORD) { $env:MYSQL_ROOT_PASSWORD } else { "P@ssw0rd@1234" }

Write-Host "=== Import Lab Data ===" -ForegroundColor Cyan
Write-Host ""

if (-not $args[0]) {
    Write-Host "Usage: .\import-lab-data.ps1 <lab-data-YYYYMMDD_HHMMSS.zip>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Available export files:"
    $Files = Get-ChildItem -Path $ScriptDir -Filter "lab-data-*.zip" 2>$null
    if ($Files) { $Files | ForEach-Object { Write-Host "  $($_.Name)" } }
    else { Write-Host "  (none found)" -ForegroundColor Gray }
    exit 1
}

$ZipFile = $args[0]
if (-not (Test-Path $ZipFile)) { $ZipFile = Join-Path $ScriptDir $args[0] }
if (-not (Test-Path $ZipFile)) {
    Write-Host "ERROR: File not found: $($args[0])" -ForegroundColor Red
    exit 1
}

$ImportDir = Join-Path $ScriptDir "lab-data-import-tmp"
if (Test-Path $ImportDir) { Remove-Item -Recurse -Force $ImportDir }
New-Item -ItemType Directory -Path $ImportDir -Force | Out-Null

Write-Host "Extracting $ZipFile..."
Expand-Archive -Path $ZipFile -DestinationPath $ImportDir -Force

$VerifierSql = Get-ChildItem -Path $ImportDir -Recurse -Filter "verifier.sql" | Select-Object -First 1
$IssuerSql   = Get-ChildItem -Path $ImportDir -Recurse -Filter "issuer.sql"   | Select-Object -First 1

# Import Verifier DB
if ($VerifierSql) {
    Write-Host ""
    Write-Host "[1/2] Importing Verifier database..." -ForegroundColor Yellow
    $null = & docker exec verifier-mysql mysqladmin ping -uroot -p"$DbPass" --silent 2>$null
    if ($LASTEXITCODE -eq 0) {
        Get-Content $VerifierSql.FullName | & docker exec -i verifier-mysql mysql -uroot -p"$DbPass" verifier 2>$null
        Write-Host "  Done" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: verifier-mysql is not running. Start the lab first." -ForegroundColor Red
        Remove-Item -Recurse -Force $ImportDir
        exit 1
    }
} else {
    Write-Host "[1/2] verifier.sql not found in zip, skipping" -ForegroundColor Gray
}

# Import Issuer DB
if ($IssuerSql) {
    Write-Host "[2/2] Importing Issuer database..." -ForegroundColor Yellow
    $null = & docker exec issuer-mysql mysqladmin ping -uroot -p"$DbPass" --silent 2>$null
    if ($LASTEXITCODE -eq 0) {
        Get-Content $IssuerSql.FullName | & docker exec -i issuer-mysql mysql -uroot -p"$DbPass" issuer 2>$null
        Write-Host "  Done" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: issuer-mysql is not running, skipping" -ForegroundColor Yellow
    }
} else {
    Write-Host "[2/2] issuer.sql not found in zip, skipping" -ForegroundColor Gray
}

Remove-Item -Recurse -Force $ImportDir

Write-Host ""
Write-Host "Import complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Verify:" -ForegroundColor Yellow
Write-Host "  docker exec -it verifier-mysql mysql -uroot -p${DbPass} verifier -e `"SELECT COUNT(*) FROM dbverifiersession; SELECT COUNT(*) FROM dbverifierresponse;`""
