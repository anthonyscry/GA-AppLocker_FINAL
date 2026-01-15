# CLAUDE.md - GA-AppLocker GUI Development

## Project Overview

This is the WPF GUI component of the GA-AppLocker toolkit. It provides a modern graphical interface for all toolkit workflows using Windows Presentation Foundation (WPF) with XAML.

**Technology Stack:**
- PowerShell 5.1+ / PowerShell 7+ (pwsh)
- WPF/XAML for UI
- Runspace pools for async operations

## Project Structure

```
GUI/
├── GA-AppLocker-Portable.ps1  # Main WPF application with embedded XAML
├── AsyncHelpers.psm1          # Async execution module (runspace pool)
├── Build-Portable.ps1         # Build script for portable EXE
├── Scripts/                   # Setup and validation scripts
├── Tests/                     # Pester tests
└── CLAUDE.md                  # This file
```

## Development Commands

### Linting with PSScriptAnalyzer

```powershell
# Lint all PowerShell files in GUI folder
Invoke-ScriptAnalyzer -Path ./GUI -Recurse -Severity Warning

# Lint a specific file
Invoke-ScriptAnalyzer -Path ./GUI/GA-AppLocker-Portable.ps1 -Severity Warning

# Lint with all rules including informational
Invoke-ScriptAnalyzer -Path ./GUI -Recurse -Severity Information

# Lint and output as JSON (for CI/automation)
Invoke-ScriptAnalyzer -Path ./GUI -Recurse -Severity Warning | ConvertTo-Json
```

### Testing with Pester

```powershell
# Run all tests
Invoke-Pester -Path ./GUI/Tests -Output Detailed

# Run tests with code coverage
Invoke-Pester -Path ./GUI/Tests -Output Detailed -CodeCoverage ./GUI/*.ps1

# Run specific test file
Invoke-Pester -Path ./GUI/Tests/AsyncHelpers.Tests.ps1 -Output Detailed
```

### Install Development Dependencies

```powershell
# Install PSScriptAnalyzer (linter)
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser

# Install Pester (testing framework)
Install-Module -Name Pester -Force -Scope CurrentUser -MinimumVersion 5.0

# Verify installations
Get-Module -ListAvailable PSScriptAnalyzer, Pester
```

### Running the GUI

```powershell
# From project root
.\Start-GUI.ps1

# Or directly
.\GUI\GA-AppLocker-Portable.ps1
```

## Code Conventions

### PowerShell Style

- Use approved verbs for function names (Get-, Set-, New-, Invoke-, etc.)
- Use PascalCase for function names and parameters
- Use `$Script:` scope for module-level variables
- Always use `[CmdletBinding()]` for advanced functions
- Include comment-based help for public functions

### WPF/XAML Patterns

- XAML is embedded as a here-string in `GA-AppLocker-Portable.ps1`
- Controls are accessed via the `$controls` hashtable after XAML parsing
- Use `Dispatcher.Invoke()` for cross-thread UI updates
- Long operations should use the async helpers module

### Event Handlers

```powershell
# Pattern for button click handlers
$controls['ButtonName'].Add_Click({
    # Validate inputs
    if ([string]::IsNullOrWhiteSpace($controls['TextBox'].Text)) {
        Write-Log "Error message" -Level Error
        return
    }

    # Execute operation
    Set-Status -State 'Running'
    # ... do work ...
    Set-Status -State 'Success'
    Write-Log "Operation completed." -Level Success
})
```

### Logging

Use the `Write-Log` function for all user-visible output:
```powershell
Write-Log "Message" -Level Info      # [*] prefix
Write-Log "Message" -Level Success   # [+] prefix
Write-Log "Message" -Level Warning   # [!] prefix
Write-Log "Message" -Level Error     # [-] prefix
```

## PSScriptAnalyzer Rules

The following rules are particularly important for this project:

- **PSAvoidUsingWriteHost** - Suppressed for GUI (Write-Host is appropriate for console fallback)
- **PSUseShouldProcessForStateChangingFunctions** - Required for functions that modify state
- **PSAvoidUsingPlainTextForPassword** - Must use SecureString for credentials
- **PSUseDeclaredVarsMoreThanAssignments** - Avoid unused variables

### Suppressing Rules (when necessary)

```powershell
# Suppress for a specific line
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]

# Suppress for entire function
function Example {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('RuleName', '')]
    [CmdletBinding()]
    param()
}
```

## Testing Guidelines

### Test File Naming

- Test files should be named `*.Tests.ps1`
- Place tests in `GUI/Tests/` directory
- Name tests after the module/script they test (e.g., `AsyncHelpers.Tests.ps1`)

### Test Structure

```powershell
Describe "Function-Name" {
    BeforeAll {
        # Setup code
    }

    Context "When condition" {
        It "Should expected behavior" {
            # Arrange
            # Act
            # Assert
            $result | Should -Be $expected
        }
    }

    AfterAll {
        # Cleanup code
    }
}
```

## Common Issues

### WPF Not Loading

WPF requires Windows. These scripts will not work on Linux/macOS.

```powershell
# Check if WPF assemblies are available
Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
```

### Runspace Pool Issues

If async operations hang, check:
1. Runspace pool is initialized (`Initialize-AsyncPool`)
2. Pool is closed on window exit (`Close-AsyncPool`)
3. No deadlocks from UI thread blocking

### XAML Parsing Errors

Common causes:
- Invalid XML syntax
- Missing xmlns declarations
- Typos in x:Name attributes
