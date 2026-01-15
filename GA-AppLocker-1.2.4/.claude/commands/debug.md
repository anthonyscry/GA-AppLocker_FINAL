# Add Verbose Logging to Function

Add comprehensive debug/verbose logging to a specified function to help troubleshoot issues.

## Instructions

When the user specifies a function name, add verbose logging following this pattern:

1. **Add CmdletBinding with verbose support** (if not present):
```powershell
function FunctionName {
    [CmdletBinding()]
    param(
        # existing parameters
    )
```

2. **Add entry logging** at the start of the function:
```powershell
Write-Verbose "[$($MyInvocation.MyCommand.Name)] START"
Write-Verbose "[$($MyInvocation.MyCommand.Name)] Parameters: $($PSBoundParameters | ConvertTo-Json -Compress)"
```

3. **Add logging before key operations**:
```powershell
Write-Verbose "[$($MyInvocation.MyCommand.Name)] Connecting to $ComputerName..."
Write-Verbose "[$($MyInvocation.MyCommand.Name)] Processing $($items.Count) items..."
```

4. **Add logging in catch blocks**:
```powershell
catch {
    Write-Verbose "[$($MyInvocation.MyCommand.Name)] ERROR: $($_.Exception.Message)"
    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Stack: $($_.ScriptStackTrace)"
    throw
}
```

5. **Add exit logging** at the end:
```powershell
Write-Verbose "[$($MyInvocation.MyCommand.Name)] END - Duration: $($stopwatch.Elapsed)"
```

## For GUI Functions

For WPF GUI functions, also add logging to the log panel:

```powershell
function SomeGuiOperation {
    Write-Log "Starting operation..." -Level Info
    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Detailed: $variableValue"

    try {
        # operation
        Write-Log "Operation completed." -Level Success
    }
    catch {
        Write-Log "Operation failed: $_" -Level Error
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Full error: $($_ | Format-List -Force | Out-String)"
    }
}
```

## Debug Switch Pattern

If the function needs a -Debug switch for even more output:

```powershell
function FunctionName {
    [CmdletBinding()]
    param(
        [switch]$EnableDebug
    )

    if ($EnableDebug -or $DebugPreference -ne 'SilentlyContinue') {
        Write-Debug "[$($MyInvocation.MyCommand.Name)] Debug mode enabled"
        Write-Debug "[$($MyInvocation.MyCommand.Name)] Variable states:"
        Write-Debug ($variableToInspect | Format-List | Out-String)
    }
}
```

## Logging to File

For persistent debugging, add file logging:

```powershell
$Script:DebugLogPath = Join-Path $env:TEMP "GA-AppLocker-Debug-$(Get-Date -Format 'yyyyMMdd').log"

function Write-DebugLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    "$timestamp | $Message" | Add-Content -Path $Script:DebugLogPath
    Write-Verbose $Message
}
```

## Usage

Tell me which function you want to add logging to, and I will:
1. Read the function's current implementation
2. Add appropriate verbose/debug logging
3. Preserve existing functionality
4. Show you how to run with verbose output:

```powershell
# Enable verbose output
$VerbosePreference = 'Continue'
FunctionName -Verbose

# Or for a script
.\Script.ps1 -Verbose
```
