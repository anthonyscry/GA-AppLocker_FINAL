@echo off
REM =====================================================
REM GA-AppLocker Toolkit - Main Launcher
REM Double-click this file to run GA-AppLocker
REM =====================================================

title GA-AppLocker Toolkit v1.2.4
color 0B

REM Change to script directory
cd /d "%~dp0"

echo.
echo  =============================================
echo      GA-AppLocker Toolkit v1.2.4
echo      AppLocker Policy Management Dashboard
echo  =============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [!] WARNING: Not running as Administrator
    echo      Some features require elevated privileges:
    echo      - Reading AppLocker events
    echo      - Deploying GPO policies
    echo      - Remote computer scanning
    echo.
    echo      Right-click this file and select
    echo      "Run as administrator" for full functionality.
    echo.
    echo  Press any key to continue anyway...
    pause >nul
    echo.
)

REM Find the best GUI script to run
set "GUISCRIPT="

REM Priority 1: Production portable version
if exist "GA-AppLocker-1.2.4\src\GUI\GA-AppLocker-Portable.ps1" (
    set "GUISCRIPT=GA-AppLocker-1.2.4\src\GUI\GA-AppLocker-Portable.ps1"
    goto :launch
)

REM Priority 2: Build folder WPF version
if exist "build\GA-AppLocker-GUI-WPF.ps1" (
    set "GUISCRIPT=build\GA-AppLocker-GUI-WPF.ps1"
    goto :launch
)

REM Priority 3: Build folder Full version
if exist "build\GA-AppLocker-GUI-Full.ps1" (
    set "GUISCRIPT=build\GA-AppLocker-GUI-Full.ps1"
    goto :launch
)

REM Priority 4: Output folder (after build)
if exist "output\GA-AppLocker-GUI.ps1" (
    set "GUISCRIPT=output\GA-AppLocker-GUI.ps1"
    goto :launch
)

REM No GUI found
echo  [ERROR] Could not find GA-AppLocker GUI script!
echo.
echo  Expected locations:
echo    - GA-AppLocker-1.2.4\src\GUI\GA-AppLocker-Portable.ps1
echo    - build\GA-AppLocker-GUI-WPF.ps1
echo    - output\GA-AppLocker-GUI.ps1
echo.
pause
exit /b 1

:launch
echo  Launching: %GUISCRIPT%
echo.

REM Ensure AaronLocker is available
if exist "AaronLocker-main\AaronLocker" (
    echo  [OK] AaronLocker found in local directory
    REM Copy to C:\GA-AppLocker if running from source and it doesn't exist there
    if not exist "C:\GA-AppLocker\AaronLocker-main" (
        echo  [*] Copying AaronLocker to C:\GA-AppLocker...
        if not exist "C:\GA-AppLocker" mkdir "C:\GA-AppLocker"
        xcopy /E /I /Y "AaronLocker-main" "C:\GA-AppLocker\AaronLocker-main" >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            echo  [OK] AaronLocker copied successfully
        ) else (
            echo  [!] Could not copy AaronLocker - run as admin to enable AaronLocker Tools
        )
    )
) else if exist "C:\GA-AppLocker\AaronLocker-main\AaronLocker" (
    echo  [OK] AaronLocker found at C:\GA-AppLocker
) else (
    echo  [!] WARNING: AaronLocker not found
    echo      AaronLocker Tools page will not work until you copy
    echo      the AaronLocker-main folder to C:\GA-AppLocker\
)
echo.

REM Try PowerShell 7 (pwsh) first for better performance
where pwsh >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  [Using PowerShell 7]
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%GUISCRIPT%"
) else (
    echo  [Using Windows PowerShell]
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%GUISCRIPT%"
)

REM Check exit code
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo  =============================================
    echo  [ERROR] GA-AppLocker exited with code %ERRORLEVEL%
    echo  =============================================
    echo.
    echo  Common issues:
    echo    - Missing .NET Framework 4.7.2+
    echo    - PowerShell execution policy restrictions
    echo    - Missing WPF assemblies
    echo.
    pause
)
