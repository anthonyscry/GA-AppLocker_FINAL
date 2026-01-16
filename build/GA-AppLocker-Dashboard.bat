@echo off
REM =====================================================
REM GA-AppLocker Dashboard Launcher (Build Version)
REM Runs the WPF GUI from the build folder
REM =====================================================

title GA-AppLocker Dashboard
color 0B

REM Change to script directory
cd /d "%~dp0"

echo.
echo  ======================================
echo   GA-AppLocker Dashboard
echo  ======================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [WARNING] Not running as Administrator
    echo  Some features require admin privileges.
    echo.
)

REM Check which GUI script exists
if exist "GA-AppLocker-GUI-WPF.ps1" (
    set "GUISCRIPT=GA-AppLocker-GUI-WPF.ps1"
) else if exist "GA-AppLocker-GUI-Full.ps1" (
    set "GUISCRIPT=GA-AppLocker-GUI-Full.ps1"
) else (
    echo  [ERROR] No GUI script found in build folder!
    echo  Please run Build-Only.ps1 or Build-EXE.ps1 first.
    pause
    exit /b 1
)

echo  Starting %GUISCRIPT%...
echo.

REM Try PowerShell 7 first, fall back to Windows PowerShell
where pwsh >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%GUISCRIPT%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%GUISCRIPT%"
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERROR] Application exited with error code %ERRORLEVEL%
    pause
)
