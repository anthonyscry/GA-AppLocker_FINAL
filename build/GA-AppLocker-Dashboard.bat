@echo off
REM GA-AppLocker Dashboard Launcher
REM Runs the WPF GUI with proper execution policy

PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0GA-AppLocker-GUI-WPF.ps1"

if %ERRORLEVEL% NEQ 0 (
    pause
)
