# PowerShell Script Usage

This guide covers using GA-AppLocker via PowerShell scripts instead of the GUI.

## First-Time Setup

```powershell
# Set execution policy (allows local scripts)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Unblock downloaded files
Get-ChildItem -Path "C:\GA-AppLocker" -Recurse -Include *.ps1,*.psm1 | Unblock-File
```

## Interactive Mode

```powershell
.\src\Core\Start-AppLockerWorkflow.ps1
```

## Direct Parameter Mode

### Scanning

```powershell
# Scan remote computers
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList .\ADManagement\computers.csv

# Full workflow (Scan + Generate)
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Full -ComputerList .\ADManagement\computers.csv
```

### Policy Generation

```powershell
# Generate simplified policy
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -Simplified

# Generate Build Guide policy (enterprise)
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans\Scan-20260109 `
    -TargetType Workstation -DomainName CONTOSO -Phase 1

# Validate a policy file
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Validate -PolicyPath .\policy.xml
```

### Event Collection

```powershell
# Collect blocked events from last 14 days
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv

# Collect events from last 30 days
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv -DaysBack 30

# Include allowed events
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv -IncludeAllowedEvents

# Incremental collection - only get events since last run
.\src\Core\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\ADManagement\computers.csv -OutputPath .\Events -SinceLastRun
```

### Policy Merging

```powershell
# Merge policies in a folder
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Merge -PolicyPath .\policies\

# Merge with default rules removed
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ -RemoveDefaultRules

# Merge with SID replacement
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ `
    -TargetGroup "DOMAIN\AppLocker-Users" -ReplaceMode Everyone
```

## Utility Scripts

### Software Inventory Comparison

```powershell
# Compare two inventories
.\src\Utilities\Compare-SoftwareInventory.ps1 -ReferencePath .\baseline.csv -ComparePath .\target.csv

# Compare with HTML output
.\src\Utilities\Compare-SoftwareInventory.ps1 -ReferencePath .\baseline.csv -ComparePath .\target.csv -OutputFormat HTML
```

### Diagnostics

```powershell
# Test connectivity
.\src\Utilities\Test-AppLockerDiagnostic.ps1 -ComputerName TARGET-PC

# Test with job execution
.\src\Utilities\Test-AppLockerDiagnostic.ps1 -ComputerName TARGET-PC -TestType JobFull
```

### WinRM Setup

```powershell
# Deploy WinRM via GPO
.\src\Utilities\Enable-WinRM-Domain.ps1

# Remove WinRM GPO
.\src\Utilities\Enable-WinRM-Domain.ps1 -Action Remove
```

### Compliance Reporting

```powershell
# Generate HTML compliance report
.\src\Utilities\New-ComplianceReport.ps1

# Generate with evidence listings
.\src\Utilities\New-ComplianceReport.ps1 -Format Markdown -IncludeEvidence

# Generate for specific policy
.\src\Utilities\New-ComplianceReport.ps1 -PolicyPath .\policy.xml
```

### Rule Health Checking

```powershell
# Basic health check
.\src\Utilities\Test-RuleHealth.ps1 -PolicyPath .\policy.xml

# With scan data analysis
.\src\Utilities\Test-RuleHealth.ps1 -PolicyPath .\policy.xml -ScanPath .\Scans

# Full check with certificates
.\src\Utilities\Test-RuleHealth.ps1 -PolicyPath .\policy.xml -CheckCertificates
```

### Impact Analysis

```powershell
# Pre-deployment impact analysis
.\src\Utilities\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml -ScanPath .\Scans

# Compare with current policy
.\src\Utilities\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml `
    -CurrentPolicyPath .\current.xml -Detailed
```

### Continuous Monitoring

```powershell
# Start monitoring
.\src\Utilities\Start-AppLockerMonitor.ps1 -ComputerListPath .\ADManagement\computers.csv

# Background monitoring with alerts
.\src\Utilities\Start-AppLockerMonitor.ps1 -ComputerListPath .\ADManagement\computers.csv -AsJob `
    -AlertWebhook "https://teams.webhook.url" -AlertThreshold 5
```

### GPO Export

```powershell
# Export for GPO deployment
.\src\Utilities\Export-AppLockerGPO.ps1 -PolicyPath .\policy.xml -OutputPath .\GPO-Export

# Export for Intune
.\src\Utilities\Export-AppLockerGPO.ps1 -PolicyPath .\policy.xml -Format Intune
```

### Industry Templates

```powershell
# List available templates
.\src\Utilities\New-PolicyFromTemplate.ps1 -ListTemplates

# Get template info
.\src\Utilities\New-PolicyFromTemplate.ps1 -TemplateInfo Healthcare

# Generate from template
.\src\Utilities\New-PolicyFromTemplate.ps1 -Template FinancialServices -Phase 1
```

### Phase Advancement

```powershell
# Check if ready for next phase
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events

# Auto-advance if ready
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events -AutoAdvance
```

## Parameters Reference

| Parameter | Description |
|-----------|-------------|
| `-Phase 1-4` | Build Guide deployment phases (1=EXE only, 4=All+DLL) |
| `-TargetType` | Workstation, Server, or DomainController |
| `-Simplified` | Quick deployment mode |
| `-IncludeDenyRules` | Add LOLBins deny rules |
| `-IncludeVendorPublishers` | Trust vendor publishers from scan |
| `-ScanUserProfiles` | Include user profile scanning |
| `-ThrottleLimit` | Concurrent remote connections (default: 10) |
| `-SoftwareListPath` | Path to software list JSON for policy generation |
| `-OutputPath` | Output folder (defaults to `.\Outputs`) |
| `-DaysBack` | Days of events to collect (default: 14, 0=all) |
| `-BlockedOnly` | Only collect "would have been blocked" events |
| `-IncludeAllowedEvents` | Also collect "would have been allowed" events |
| `-SinceLastRun` | Incremental collection - only get events since last run |
| `-RemoveDefaultRules` | Filter out default AppLocker rules during merge |
| `-TargetGroup` | Replace Everyone SID with specific group |
| `-ReplaceMode` | SID replacement mode: Everyone, All, or None |

## Module Usage

You can also import GA-AppLocker as a PowerShell module:

```powershell
# Import the module
Import-Module .\GA-AppLocker.psd1

# Use the shorthand alias
gaapp

# Call functions directly
Start-AppLockerWorkflow -Mode Scan -ComputerList .\computers.csv
Invoke-RemoteScan -ComputerList .\computers.csv -OutputPath .\Scans
New-AppLockerPolicyFromGuide -ScanPath .\Scans -Simplified
```

## Exported Functions

The module exports 46 functions:

**Main Workflow:**
- `Start-AppLockerWorkflow`

**Scanning:**
- `Invoke-RemoteScan`
- `Invoke-RemoteEventCollection`

**Policy:**
- `New-AppLockerPolicyFromGuide`
- `Merge-AppLockerPolicies`
- `Test-AppLockerPolicy`
- `Compare-AppLockerPolicies`

**SID Resolution:**
- `Resolve-AccountToSid`
- `Resolve-AccountsToSids`
- `Get-StandardPrincipalSids`
- `Clear-SidCache`
- `Get-SidCacheStats`

**Configuration:**
- `Get-AppLockerConfig`

**Logging:**
- `Start-Logging`
- `Write-Log`
- `Stop-Logging`

**Utilities:**
- `Get-ComputerList`
- `Confirm-Directory`

**Error Handling:**
- `Invoke-SafeOperation`
- `Test-ValidPath`
- `Test-ValidXml`
- `Test-ValidAppLockerPolicy`
- `Test-ValidComputerList`
- `Test-CredentialValidity`
- `Write-SectionHeader`
- `Write-StepProgress`
- `Write-SuccessMessage`
- `Write-ErrorMessage`
- `Write-ResultSummary`
- `Initialize-GAAppLockerScript`
