@echo off
:: stop-lab.cmd — double-click หรือรันใน Command Prompt / PowerShell ได้เลย

echo === Stop Lab ===
echo.

powershell -Command "Get-ChildItem '%~dp0*.ps1' | Unblock-File" >nul 2>&1
powershell -ExecutionPolicy Bypass -File "%~dp0stop-lab.ps1"

if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: stop-lab.ps1 failed.
    pause
    exit /b %ERRORLEVEL%
)
