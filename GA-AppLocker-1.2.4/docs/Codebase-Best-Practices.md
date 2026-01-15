# Codebase Best Practices

This document covers the coding standards, security practices, and patterns used throughout the GA-AppLocker codebase.

---

## PowerShell Best Practices

### Script Structure

All scripts follow a consistent structure:

```powershell
<#
.SYNOPSIS
    Brief description
.DESCRIPTION
    Detailed description
.PARAMETER ParameterName
    Parameter description
.EXAMPLE
    Usage example
.NOTES
    Requirements and version info
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$RequiredParam
)

# Import modules
Import-Module .\utilities\Common.psm1 -Force

# Script logic...
```

### Parameter Validation

All parameters use appropriate validation attributes:

| Attribute | Usage |
|-----------|-------|
| `[ValidateNotNullOrEmpty()]` | Required string parameters |
| `[ValidateScript({})]` | Custom validation logic (file exists, format check) |
| `[ValidateSet()]` | Enumerated values |
| `[ValidateRange()]` | Numeric bounds |
| `[ValidatePattern()]` | Regex patterns |

**Example from `Invoke-RemoteScan.ps1`:**

```powershell
[ValidateScript({
    if (-not (Test-Path $_ -PathType Leaf)) {
        throw "Computer list file not found: $_"
    }
    $ext = [System.IO.Path]::GetExtension($_).ToLower()
    if ($ext -notin '.txt', '.csv') {
        throw "Computer list must be a .txt or .csv file"
    }
    $true
})]
[string]$ComputerListPath
```

### CmdletBinding and ShouldProcess

Scripts that modify state support `-WhatIf` and `-Confirm`:

```powershell
[CmdletBinding(SupportsShouldProcess=$true)]
param(...)

if ($PSCmdlet.ShouldProcess($policyPath, "Create AppLocker policy file")) {
    $policyXml | Out-File -FilePath $policyPath -Encoding UTF8
}
```

---

## Error Handling

### ErrorHandling.psm1 Functions

The `ErrorHandling.psm1` module provides standardized error handling:

#### Invoke-SafeOperation

Wraps code blocks with consistent error handling:

```powershell
Invoke-SafeOperation -ScriptBlock {
    Get-Content $file
} -ErrorMessage "Failed to read file" -ContinueOnError
```

- `ContinueOnError`: Log warning and continue instead of throwing
- `Silent`: Suppress warning output

#### Write-ErrorMessage

Standardized error output:

```powershell
Write-ErrorMessage -Message "Operation failed" -Exception $_.Exception -Throw
```

### Error Handling Patterns

**Pattern 1: Try-Catch with Logging**

```powershell
try {
    $session = New-PSSession -ComputerName $Computer -Credential $Credential
}
catch {
    $result.Message = $_.Exception.Message
    if ($null -ne $session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}
```

**Pattern 2: Validation Before Action**

```powershell
$validPath = Test-ValidPath -Path $Path -Type Directory -MustExist
if (-not $validPath) {
    return $null
}
```

---

## Input Validation

### Validation Functions

`ErrorHandling.psm1` provides comprehensive validation:

| Function | Purpose |
|----------|---------|
| `Test-ValidPath` | Validates file/directory paths, optionally creates missing directories |
| `Test-ValidXml` | Validates XML structure and root element |
| `Test-ValidAppLockerPolicy` | Validates AppLocker policy XML format |
| `Test-ValidComputerList` | Validates computer list file content |
| `Test-ValidSid` | Validates SID format (S-1-x-x pattern) |
| `Test-ValidGuid` | Validates GUID format |
| `Test-ValidComputerName` | Validates NetBIOS name rules |
| `Test-ValidDomainName` | Validates domain name format |
| `Test-ValidEnforcementMode` | Validates AppLocker enforcement modes |
| `Test-ValidFileHash` | Validates SHA256/SHA1/MD5 hash format |

### Example: Path Validation

```powershell
function Test-ValidPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet('File', 'Directory', 'Any')]
        [string]$Type = 'Any',

        [switch]$MustExist,
        [switch]$CreateIfMissing
    )

    # Handle empty/null
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Warning "Path cannot be empty"
        return $null
    }

    # Resolve relative paths
    $resolvedPath = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path (Get-Location) $Path
    }

    # Validate existence and type...
}
```

### Example: XML Validation

```powershell
function Test-ValidAppLockerPolicy {
    param([Parameter(Mandatory)][string]$Path)

    $xml = Test-ValidXml -Path $Path -RootElement 'AppLockerPolicy'
    if (-not $xml) { return $null }

    # Check for rule collections
    $collections = $xml.AppLockerPolicy.RuleCollection
    if (-not $collections -or $collections.Count -eq 0) {
        Write-Warning "Policy contains no rule collections"
        return $null
    }

    return $xml
}
```

---

## Security Practices

### Credential Handling

**SecureString for Passwords:**

```powershell
# Credentials stored as SecureString
$credPassword = $Credential.Password  # SecureString, not plaintext

# Reconstruct inside job
$Credential = New-Object System.Management.Automation.PSCredential(
    $UserName, $SecurePass
)
```

**Never log credentials:**

```powershell
# Good: Log username only
Write-Log "Credentials provided for user: $($Credential.UserName)" -Level Info

# Bad: Never do this
# Write-Log "Password: $($Credential.GetNetworkCredential().Password)"
```

### Session Cleanup

Always clean up remote sessions:

```powershell
try {
    $session = New-PSSession -ComputerName $Computer -Credential $Credential
    # ... work ...
}
finally {
    if ($null -ne $session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}
```

### XML Escaping

Prevent XML injection in generated policies:

```powershell
$pubXml = [System.Security.SecurityElement]::Escape($rule.Publisher)
$prodXml = [System.Security.SecurityElement]::Escape($rule.Product)
$ruleNameXml = [System.Security.SecurityElement]::Escape($ruleName)
```

### Default to Audit Mode

All policy generation defaults to `AuditOnly`:

```powershell
[ValidateSet("AuditOnly", "Enabled")]
[string]$EnforcementMode = "AuditOnly"
```

### Principal Scoping

Build Guide mode enforces proper principal scoping:

```powershell
# GOOD: Specific principals for Microsoft publisher
foreach ($principal in @(
    @{ Name = "SYSTEM"; Sid = $sids.SYSTEM },
    @{ Name = "LOCAL SERVICE"; Sid = $sids.LocalService },
    @{ Name = "NETWORK SERVICE"; Sid = $sids.NetworkService },
    @{ Name = "BUILTIN\Administrators"; Sid = $sids.BuiltinAdmins }
)) {
    # Create rule for specific principal
}

# BAD: Don't use Everyone for publisher rules
# $sids.Everyone  <- Avoided for publisher rules
```

---

## Code Organization

### Module Structure

```
src/
├── Core/                    # Main workflow scripts
│   ├── Start-AppLockerWorkflow.ps1
│   ├── Invoke-RemoteScan.ps1
│   ├── Invoke-RemoteEventCollection.ps1
│   └── New-AppLockerPolicyFromGuide.ps1
├── GUI/                     # WPF GUI application
│   └── GA-AppLocker-Portable.ps1
└── Utilities/               # Shared modules and helpers
    ├── Common.psm1          # Core functions (SID resolution, XML helpers)
    ├── ErrorHandling.psm1   # Error handling and validation
    ├── Config.psd1          # Centralized configuration
    └── *.ps1                # Feature-specific utilities
```

### Configuration Centralization

All configurable values in `Config.psd1`:

```powershell
@{
    WellKnownSids = @{
        Everyone = 'S-1-1-0'
        Administrators = 'S-1-5-32-544'
        Users = 'S-1-5-32-545'
        # ...
    }

    LOLBins = @(
        @{ Name = 'mshta.exe'; Description = 'HTML Application Host' }
        @{ Name = 'wscript.exe'; Description = 'Windows Script Host' }
        # ...
    )

    DefaultDenyPaths = @(
        @{ Path = '%USERPROFILE%\Downloads\*'; Description = 'User Downloads' }
        @{ Path = '%TEMP%\*'; Description = 'Temp folder' }
        # ...
    )
}
```

### Function Naming

Follow PowerShell verb-noun convention:

| Verb | Usage |
|------|-------|
| `Get-` | Retrieve data |
| `Set-` | Modify existing |
| `New-` | Create new objects |
| `Test-` | Validation/checks |
| `Invoke-` | Execute actions |
| `Start-` | Begin processes |
| `Write-` | Output/logging |

---

## Logging

### Logging Functions (Common.psm1)

```powershell
# Start logging session
Start-Logging -LogName "RemoteScan"

# Log messages at different levels
Write-Log "Operation started" -Level Info
Write-Log "Detailed debug info" -Level Debug
Write-Log "Completed successfully" -Level Success
Write-Log "Potential issue" -Level Warning
Write-Log "Operation failed" -Level Error

# Log structured sections
Write-LogSection "Target Computers"
Write-LogResults -Results $results

# End logging and get log file path
$logFile = Stop-Logging -Summary "Scan complete"
```

### Conditional Logging

Check if logging is enabled before expensive operations:

```powershell
if (Test-LoggingEnabled) {
    Write-Log "Loaded $($computers.Count) computers from list" -Level Info
    Write-LogSection "Target Computers"
    foreach ($comp in $computers) {
        Write-Log "  - $comp" -Level Debug
    }
}
```

---

## Testing

### Pester Tests

Tests are located in `Tests/` directory:

```powershell
# Run all tests
Invoke-Pester -Path .\Tests

# Run specific test file
Invoke-Pester -Path .\Tests\Common.Tests.ps1

# Run with coverage
Invoke-Pester -Path .\Tests -CodeCoverage .\src\Utilities\*.psm1
```

### Test Structure

```powershell
Describe 'Test-ValidPath' {
    Context 'When path exists' {
        It 'Returns resolved path for valid directory' {
            $result = Test-ValidPath -Path $TestDrive -Type Directory
            $result | Should -Be $TestDrive
        }
    }

    Context 'When path does not exist' {
        It 'Returns null with MustExist' {
            $result = Test-ValidPath -Path 'C:\NonExistent' -MustExist
            $result | Should -BeNullOrEmpty
        }
    }
}
```

---

## Performance Considerations

### Job Throttling

Limit concurrent remote connections:

```powershell
[ValidateRange(1, 100)]
[int]$ThrottleLimit = 10

# Throttle check in loop
while (($runningJobs | Where-Object { $_.State -eq 'Running' }).Count -ge $ThrottleLimit) {
    Start-Sleep -Seconds 2
}
```

### Scan Limits

Prevent timeouts on large directories:

```powershell
# Limit files per path
$maxFilesPerPath = 5000
$files = Get-ChildItem -Path $basePath -Filter $ext -Recurse |
    Select-Object -First $maxFilesPerPath

# Limit directories per path
$maxDirectoriesPerPath = 2000
$dirs = Get-ChildItem -Path $basePath -Directory -Recurse |
    Select-Object -First $maxDirectoriesPerPath
```

### Deduplication

Use hashtables for efficient deduplication:

```powershell
$publisherRules = @{}

foreach ($exe in $signedExes) {
    $key = "$($exe.Publisher)|$($exe.Product)|$($exe.Binary)"
    if (-not $publisherRules.ContainsKey($key)) {
        $publisherRules[$key] = @{
            Publisher = $exe.Publisher
            Product = $exe.Product
            Binary = $exe.Binary
        }
    }
}
```

---

## Security Audit Checklist

When reviewing code changes, verify:

- [ ] No credentials logged or written to files
- [ ] SecureString used for password handling
- [ ] Remote sessions cleaned up in finally blocks
- [ ] User input validated before use
- [ ] XML content escaped to prevent injection
- [ ] Default to AuditOnly enforcement mode
- [ ] Proper principal scoping (not Everyone for publishers)
- [ ] File paths validated before access
- [ ] Error messages don't expose sensitive information
