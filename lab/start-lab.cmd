@echo off
:: start-lab.cmd — double-click หรือรันใน Command Prompt / PowerShell ได้เลย
:: ไม่ต้องแก้ Execution Policy

echo === Lab Setup ===
echo.

:: Unblock ps1 scripts ก่อนรัน (ลบ Zone.Identifier flag ที่ Windows ติดไว้ตอน download)
powershell -Command "Get-ChildItem '%~dp0*.ps1' | Unblock-File" >nul 2>&1

:: รัน start-lab.ps1 ด้วย Bypass policy
powershell -ExecutionPolicy Bypass -File "%~dp0start-lab.ps1"

if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: start-lab.ps1 failed. See messages above.
    pause
    exit /b %ERRORLEVEL%
)
