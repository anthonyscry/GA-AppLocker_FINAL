# GA-AppLocker Code Review

## Executive Summary

This document provides a comprehensive code review of the GA-AppLocker PowerShell toolkit. The review covers code quality, maintainability, security, and identifies areas for improvement.

**Overall Assessment**: The codebase is well-structured with good separation of concerns. There are opportunities to reduce duplication, improve error handling, and enhance testability.

---

## Issues Identified by File

### 1. New-AppLockerPolicyFromGuide.ps1

#### Duplicate Logic (HIGH)

**Problem**: The publisher rule building logic is duplicated twice (lines 360-398 and 400-443). The same switch statement for `$RuleGranularity` appears in both blocks.

**Before** (repeated in two places):
```powershell
switch ($RuleGranularity) {
    "Publisher" {
        $key = $publisher
        $productName = "*"
        $binaryName = "*"
    }
    "PublisherProduct" {
        $key = "$publisher|$product"
        $productName = $product
        $binaryName = "*"
    }
    "PublisherProductBinary" {
        $key = "$publisher|$product|$binary"
        $productName = $product
        $binaryName = $binary
    }
}
```

**Recommendation**: Extract to a helper function:
```powershell
function Get-PublisherRuleKey {
    param(
        [string]$Publisher,
        [string]$Product,
        [string]$Binary,
        [string]$Granularity
    )

    switch ($Granularity) {
        "Publisher" {
            return @{ Key = $Publisher; Product = "*"; Binary = "*" }
        }
        "PublisherProduct" {
            return @{ Key = "$Publisher|$Product"; Product = $Product; Binary = "*" }
        }
        "PublisherProductBinary" {
            return @{ Key = "$Publisher|$Product|$Binary"; Product = $Product; Binary = $Binary }
        }
    }
}
```

#### Large Inline XML Strings (MEDIUM)

**Problem**: XML is built using string interpolation (lines 539-672, 1226-1330). This is error-prone and hard to maintain.

**Recommendation**: Use helper functions from Common.psm1 more consistently:
```powershell
# Instead of inline XML strings, use:
$xml = New-PolicyHeaderXml -TargetType $TargetType -Phase $Phase
$xml += New-RuleCollectionXml -Type "Exe" -EnforcementMode $exeMode -Rules $exeRules
```

#### Missing Parameter Validation (MEDIUM)

**Problem**: Simplified mode requires one of `-ScanPath`, `-SoftwareListPath`, or `-EventPath`, but this is validated at runtime (lines 228-236).

**Recommendation**: Add `[ValidateScript()]` to enforce this at parameter binding:
```powershell
[ValidateScript({
    if ($Simplified -and -not ($ScanPath -or $SoftwareListPath -or $EventPath)) {
        throw "Simplified mode requires -ScanPath, -SoftwareListPath, or -EventPath"
    }
    $true
})]
```

#### EXE Compatibility Issue (LOW)

**Problem**: Using `$(New-Guid)` inside here-strings may cause issues when compiled to EXE with PS2EXE.

**Recommendation**: Generate GUIDs before string interpolation:
```powershell
$adminRuleId = [Guid]::NewGuid().ToString()
$simplifiedXml = @"
<FilePathRule Id="$adminRuleId" ...
"@
```

---

### 2. Invoke-RemoteScan.ps1

#### Complex Job Script Block (HIGH)

**Problem**: The job script block (lines 293-600) is 300+ lines. This is difficult to test, debug, and maintain.

**Recommendation**: Split into separate functions that can be tested independently:
```powershell
function Get-RemoteAppLockerPolicy { ... }
function Get-RemoteInstalledSoftware { ... }
function Get-RemoteExecutables { ... }
function Get-RemoteWritableDirectories { ... }
function Get-RemoteSystemInfo { ... }
```

Then compose in the job:
```powershell
Start-Job -ScriptBlock {
    $session = New-PSSession ...
    $results = @{
        Policy = Invoke-Command -Session $session -ScriptBlock ${function:Get-RemoteAppLockerPolicy}
        Software = Invoke-Command -Session $session -ScriptBlock ${function:Get-RemoteInstalledSoftware}
        # ...
    }
}
```

#### Credential Handling (MEDIUM)

**Problem**: Passing credentials via `$credUsername, $credPassword` arguments (lines 272-274) works but is complex.

**Recommendation**: Consider using `[PSCredential]` with `-Credential` parameter which handles serialization:
```powershell
# Jobs can receive PSCredential directly if passed properly
$jobParams = @{
    Credential = $Credential
    # ...
}
```

#### Magic Numbers (LOW)

**Problem**: Hardcoded limits like `5000` for files (line 400) and `2000` for directories (line 487).

**Recommendation**: Move to Config.psd1:
```powershell
$config = Get-AppLockerConfig
$maxFilesPerPath = $config.ScanLimits.MaxFilesPerPath  # 5000
$maxDirectoriesPerPath = $config.ScanLimits.MaxDirectoriesPerPath  # 2000
```

---

### 3. Start-AppLockerWorkflow.ps1

#### Function Extraction Needed (MEDIUM)

**Problem**: Many workflow functions (Invoke-ScanWorkflow, Invoke-GenerateWorkflow, etc.) are defined inline in the script. This makes testing difficult.

**Recommendation**: Move workflow functions to a separate module:
```
utilities/
  WorkflowFunctions.psm1  # Contains Invoke-ScanWorkflow, etc.
```

#### Inconsistent Error Handling (MEDIUM)

**Problem**: Some functions use try/catch, others return `$null` on error. Inconsistent patterns.

**Recommendation**: Use ErrorHandling.psm1 consistently:
```powershell
function Invoke-ScanWorkflow {
    Invoke-SafeOperation -ScriptBlock {
        # workflow code
    } -ErrorMessage "Scan workflow failed" -ContinueOnError:$ContinueOnError
}
```

---

### 4. ErrorHandling.psm1

#### Missing Validation Functions (LOW)

**Problem**: No validation for common types like email addresses, IP addresses, or domain names.

**Recommendation**: Add for future use:
```powershell
function Test-ValidIPAddress {
    param([string]$Address)
    try {
        [ipaddress]::Parse($Address)
        return $true
    } catch { return $false }
}

function Test-ValidDomainName {
    param([string]$Name)
    return $Name -match '^[a-zA-Z][a-zA-Z0-9-]*$'
}
```

---

### 5. PolicyVersionControl.psm1

#### Script-Scoped State (MEDIUM)

**Problem**: Uses `$Script:RepositoryPath` for state. This can cause issues in long-running sessions or when working with multiple repositories.

**Recommendation**: Return repository context objects:
```powershell
function New-PolicyRepositoryContext {
    param([string]$Path)
    return [PSCustomObject]@{
        Path = $Path
        CurrentBranch = 'main'
    }
}

function Save-PolicyVersion {
    param(
        [PSCustomObject]$Repository,  # Pass context explicitly
        [string]$PolicyPath,
        [string]$Message
    )
}
```

---

### 6. Test-RuleHealth.ps1

#### Missing Try/Catch in Main (LOW)

**Problem**: Main region (lines 450-604) lacks comprehensive error handling.

**Recommendation**: Wrap in Invoke-SafeOperation:
```powershell
$allIssues = Invoke-SafeOperation -ScriptBlock {
    $issues = @()
    $issues += Test-PathRuleHealth -PolicyXml $policyXml
    $issues += Test-PublisherRuleHealth -PolicyXml $policyXml
    # ...
    return $issues
} -ErrorMessage "Health check failed"
```

---

## Dead Code Identified

| File | Lines | Description |
|------|-------|-------------|
| New-AppLockerPolicyFromGuide.ps1 | 840-842 | Empty region comment for SID Resolution Function (logic moved to Common.psm1) |
| New-AppLockerPolicyFromGuide.ps1 | 937-939 | Empty region comment for helper function aliases |

---

## Security Considerations

1. **Credential Handling**: The toolkit properly uses `PSCredential` and `SecureString`. No plaintext passwords found.

2. **Path Validation**: Good use of `ValidateScript` for path parameters in Invoke-RemoteScan.ps1.

3. **XML Escaping**: Uses `[System.Security.SecurityElement]::Escape()` for XML content - good practice.

4. **LOLBins Deny Rules**: Properly implements deny rules for known living-off-the-land binaries.

---

## Recommendations Summary

### High Priority
1. Extract duplicate publisher rule logic in New-AppLockerPolicyFromGuide.ps1
2. Break up the 300-line job script block in Invoke-RemoteScan.ps1
3. Add more unit tests for core functions

### Medium Priority
4. Use ErrorHandling.psm1 consistently across all scripts
5. Move workflow functions to a testable module
6. Add parameter validation for combined parameter requirements

### Low Priority
7. Move magic numbers to configuration
8. Clean up empty region comments
9. Consider repository context objects instead of script-scoped state

---

## EXE Compilation Notes

The following patterns may cause issues when compiling to EXE with PS2EXE:

1. **Here-string with expressions**: `$(New-Guid)` inside here-strings should be pre-computed
2. **Dynamic module imports**: `Join-Path $PSScriptRoot` may not resolve correctly
3. **Get-Command checks**: Commands like `Get-Command Write-Banner -ErrorAction SilentlyContinue` may behave differently

**Recommendation**: Test EXE compilation after each major change using:
```powershell
.\build\Build-Executable.ps1 -Verbose
```
