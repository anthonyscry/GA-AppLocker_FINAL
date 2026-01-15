# GA-AppLocker GUI Automated Tests

Automated GUI testing suite for GA-AppLocker using AutoIt v3.

## Prerequisites

1. **AutoIt v3** - Download and install from https://www.autoitscript.com/site/autoit/downloads/
2. **GA-AppLocker.exe** - Build the executable first using `.\build\Build-GUI.ps1`

## Running Tests

### Quick Start

```batch
# Run from Tests\GUI directory
Run-GUITests.bat
```

### Options

| Command | Description |
|---------|-------------|
| `Run-GUITests.bat` | Run full test suite |
| `Run-GUITests.bat quick` | Quick smoke test (shorter timeouts) |
| `Run-GUITests.bat verbose` | Verbose output to console |
| `Run-GUITests.bat full` | Thorough testing (longer timeouts) |

### Running Directly with AutoIt

```batch
# Basic run
"C:\Program Files (x86)\AutoIt3\AutoIt3.exe" GA-AppLocker-GUI-Test.au3

# With options
"C:\Program Files (x86)\AutoIt3\AutoIt3.exe" GA-AppLocker-GUI-Test.au3 /quick /verbose
```

## Test Suites

| Suite | Description |
|-------|-------------|
| Navigation | Tests all sidebar navigation buttons |
| Keyboard Shortcuts | Tests Ctrl+1 through Ctrl+8, F1, Ctrl+R, Ctrl+Q |
| Scan Page | Tests Scan page controls and inputs |
| Generate Page | Tests policy generation options |
| Merge Page | Tests policy merge functionality |
| Validate Page | Tests policy validation |
| Events Page | Tests event collection options |
| Settings Page | Tests settings/configuration |
| Help Page | Tests help system |
| About Page | Tests version and author info |
| Quick Workflow | Tests workflow dialogs |
| Log Panel | Tests log output panel |

## Test Output

### Log Files
- Located in `Tests\GUI\` directory
- Named: `test-results-YYYYMMDD-HHMMSS.log`

### Screenshots
- Captured on test failures (if enabled)
- Located in `Tests\GUI\screenshots\`

### Exit Codes
- `0` - All tests passed
- `1` - One or more tests failed

## Configuration

Edit the `$Config` section in `GA-AppLocker-GUI-Test.au3`:

```autoit
$Config.Add("Timeout", 10000)          ; Control wait timeout (ms)
$Config.Add("StartupWait", 3000)       ; App initialization wait (ms)
$Config.Add("ActionDelay", 500)        ; Delay between actions (ms)
$Config.Add("Verbose", True)           ; Console output
$Config.Add("StopOnError", False)      ; Stop on first failure
$Config.Add("ScreenshotOnFail", True)  ; Capture screenshots on failure
```

## Extending Tests

### Adding a New Test

```autoit
Func TestSuite_MyNewFeature($hWnd)
    LogMessage("=== My New Feature Test Suite ===", "INFO")

    ; Navigate to relevant page
    Send("^1")  ; Ctrl+1 for Scan
    ActionDelay()

    ; Test 1
    StartTest("My Test Name")
    ; ... perform actions ...
    If $success Then
        PassTest("Optional success message")
    Else
        FailTest("What went wrong")
    EndIf
EndFunc
```

### Adding to Main Suite

Add your test suite call in the `Main()` function:

```autoit
TestSuite_MyNewFeature($appHandle)
```

## Troubleshooting

### "AutoIt3 not found"
Install AutoIt from https://www.autoitscript.com/site/autoit/downloads/

### "Application not found"
Build the executable first:
```powershell
.\build\Build-GUI.ps1
```

### Tests failing unexpectedly
1. Run with `/verbose` to see detailed output
2. Check screenshots in `Tests\GUI\screenshots\`
3. Review log file for error messages
4. Increase timeouts with `/full` option

### WPF Control Detection Issues
WPF controls can be harder to detect than standard Win32 controls. The test suite uses:
- Named controls (`[NAME:ControlName]`)
- Text matching (`[TEXT:ButtonText]`)
- Keyboard shortcuts as primary navigation

## CI/CD Integration

### Azure DevOps / GitHub Actions

```yaml
- name: Run GUI Tests
  shell: cmd
  run: |
    cd Tests\GUI
    Run-GUITests.bat quick
  continue-on-error: false
```

### Exit code checking
```batch
Run-GUITests.bat
if %ERRORLEVEL% neq 0 (
    echo GUI tests failed!
    exit /b 1
)
```
