@echo off
REM =============================================================================
REM GA-AppLocker GUI Test Runner
REM =============================================================================
REM Usage:
REM   Run-GUITests.bat           - Run full test suite
REM   Run-GUITests.bat quick     - Run quick smoke test
REM   Run-GUITests.bat verbose   - Run with verbose output
REM =============================================================================

setlocal enabledelayedexpansion

REM Find AutoIt installation
set "AUTOIT_PATH="
if exist "C:\Program Files (x86)\AutoIt3\AutoIt3.exe" (
    set "AUTOIT_PATH=C:\Program Files (x86)\AutoIt3\AutoIt3.exe"
) else if exist "C:\Program Files\AutoIt3\AutoIt3.exe" (
    set "AUTOIT_PATH=C:\Program Files\AutoIt3\AutoIt3.exe"
) else if exist "%ProgramFiles(x86)%\AutoIt3\AutoIt3.exe" (
    set "AUTOIT_PATH=%ProgramFiles(x86)%\AutoIt3\AutoIt3.exe"
)

if "%AUTOIT_PATH%"=="" (
    echo ERROR: AutoIt3 not found. Please install from https://www.autoitscript.com/
    echo.
    echo Installation steps:
    echo   1. Download AutoIt from https://www.autoitscript.com/site/autoit/downloads/
    echo   2. Run the installer
    echo   3. Re-run this script
    exit /b 1
)

echo =============================================================================
echo GA-AppLocker GUI Automated Test Suite
echo =============================================================================
echo.
echo AutoIt: %AUTOIT_PATH%
echo.

REM Parse arguments
set "ARGS="
:parse_args
if "%~1"=="" goto run_tests
if /i "%~1"=="quick" set "ARGS=%ARGS% /quick"
if /i "%~1"=="full" set "ARGS=%ARGS% /full"
if /i "%~1"=="verbose" set "ARGS=%ARGS% /verbose"
if /i "%~1"=="-v" set "ARGS=%ARGS% /verbose"
shift
goto parse_args

:run_tests
echo Running tests...
echo.

REM Run the AutoIt script
"%AUTOIT_PATH%" "%~dp0GA-AppLocker-GUI-Test.au3" %ARGS%

set "EXIT_CODE=%ERRORLEVEL%"

echo.
echo =============================================================================
if %EXIT_CODE%==0 (
    echo TEST RESULT: PASSED
) else (
    echo TEST RESULT: FAILED
)
echo =============================================================================
echo.
echo Log files are in: %~dp0
echo.

exit /b %EXIT_CODE%
