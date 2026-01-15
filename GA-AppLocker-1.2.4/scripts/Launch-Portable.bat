@echo off
REM =====================================================
REM GA-AppLocker Portable Launcher (Scripts Folder)
REM Redirects to the main GUI launcher
REM =====================================================

title GA-AppLocker Toolkit v1.2.4
cd /d "%~dp0"

REM Go up to parent and launch from GUI folder
if exist "..\src\GUI\Launch-Portable.bat" (
    call "..\src\GUI\Launch-Portable.bat"
) else if exist "..\src\GUI\GA-AppLocker-Portable.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "..\src\GUI\GA-AppLocker-Portable.ps1"
) else (
    echo [ERROR] Could not find GA-AppLocker GUI!
    pause
)
