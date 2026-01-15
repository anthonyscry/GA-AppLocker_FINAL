@echo off
REM =====================================================
REM GA-AppLocker Portable Launcher
REM Runs the WPF GUI without compilation
REM =====================================================

title GA-AppLocker Toolkit v1.2.4
color 0B

REM Change to script directory
cd /d "%~dp0"

echo.
echo  ======================================
echo   GA-AppLocker Toolkit v1.2.4
echo  ======================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [WARNING] Not running as Administrator
    echo  Some features may not work properly.
    echo  Right-click and select "Run as administrator"
    echo.
    echo  Press any key to continue anyway...
    pause >nul
)

echo  Starting GA-AppLocker GUI...
echo.

REM Try PowerShell 7 (pwsh) first, fall back to Windows PowerShell
where pwsh >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  Using PowerShell 7...
    pwsh -NoProfile -ExecutionPolicy Bypass -File "GA-AppLocker-Portable.ps1"
) else (
    echo  Using Windows PowerShell...
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "GA-AppLocker-Portable.ps1"
)

REM Check for errors
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERROR] GA-AppLocker exited with error code %ERRORLEVEL%
    echo.
    pause
)
