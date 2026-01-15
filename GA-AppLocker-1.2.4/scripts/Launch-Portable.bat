@echo off
REM GA-AppLocker Portable Launcher
REM Runs the portable GUI without compilation

title GA-AppLocker Toolkit
cd /d "%~dp0"

REM Check for PowerShell
where pwsh >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "GA-AppLocker-Portable.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "GA-AppLocker-Portable.ps1"
)
