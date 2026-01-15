# Advanced Features

## GUI Improvements (v1.2.0+)

### Embedded Help System (v1.2.4)

Press **F1** or click **Help** in the navigation to access comprehensive in-app documentation:

- **Getting Started** - Quick start guide, prerequisites, workflow overview
- **Scanning** - Remote computer scanning via WinRM
- **Policy Generation** - Build Guide vs Simplified mode, deployment phases
- **Merging Policies** - Combining and deduplicating policies
- **Event Collection** - AppLocker audit events (8003/8004)
- **Software Lists** - Managing curated allowlists
- **Deployment** - Enterprise deployment strategy
- **Troubleshooting** - Common issues and solutions
- **FAQ** - Frequently asked questions

### Keyboard Shortcuts (v1.2.4)

| Shortcut | Action |
|----------|--------|
| Ctrl+1 | Scan Page |
| Ctrl+2 | Events Page |
| Ctrl+3 | Compare Page |
| Ctrl+4 | Validate Page |
| Ctrl+5 | Generate Page |
| Ctrl+6 | Merge Page |
| Ctrl+7 | Software Lists |
| Ctrl+8 | CORA Evidence |
| Ctrl+, | Settings |
| Ctrl+Q | Quick Workflow |
| Ctrl+R | Refresh Detection |
| F1 | Help (shows shortcuts dialog) |

Keyboard shortcut hints are displayed as tooltips on navigation buttons. Shortcuts follow the sidebar navigation order.

### Operation Cancellation

Long-running operations can be cancelled using the Cancel button that appears in the status bar. Cancellation occurs at the next output line.

### Button State Management

Operation buttons are automatically disabled during long-running tasks to prevent conflicts. They re-enable when the operation completes.

### Progress Indicators

- XML validation progress during merge operations
- File processing counts during scans
- Policy rule processing progress

---

## Credential Validation

Validate WinRM credentials before running operations:

```powershell
# Import ErrorHandling module
Import-Module .\src\Utilities\ErrorHandling.psm1

# Test credentials against a target computer
$cred = Get-Credential
$isValid = Test-CredentialValidity -Credential $cred -ComputerName 'TARGET-PC' -TimeoutSeconds 30
if ($isValid) {
    Write-Host "Credentials validated successfully"
}
```

---

## Monitoring (v1.1.0)

### Continuous Monitoring with Alerts

```powershell
# Basic monitoring
.\src\Utilities\Start-AppLockerMonitor.ps1 -ComputerListPath .\computers.txt -IntervalMinutes 30

# Background monitoring with webhook alerts
.\src\Utilities\Start-AppLockerMonitor.ps1 -ComputerListPath .\computers.txt -AsJob `
    -AlertWebhook "https://teams.webhook.url" -AlertThreshold 5
```

### GPO Export Formats

```powershell
# Export for GPO deployment
.\src\Utilities\Export-AppLockerGPO.ps1 -PolicyPath .\policy.xml -OutputPath .\GPO-Export

# Export for specific deployment method
.\src\Utilities\Export-AppLockerGPO.ps1 -PolicyPath .\policy.xml -Format Intune
```

Supported formats: GPOBackup, PowerShell, Registry, SCCM, Intune

### Impact Analysis

```powershell
# Pre-deployment impact analysis
.\src\Utilities\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml -ScanPath .\Scans

# Detailed impact with current policy comparison
.\src\Utilities\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml -ScanPath .\Scans `
    -CurrentPolicyPath .\current.xml -Detailed
```

---

## Policy Lifecycle (v1.2.0)

### Version Control

```powershell
Import-Module .\src\Utilities\PolicyVersionControl.psm1

# Initialize repository
Initialize-PolicyRepository -Path .\PolicyRepo

# Save a policy version
Save-PolicyVersion -PolicyPath .\policy.xml -Message "Added Chrome rules"

# View history
Show-PolicyLog -Last 10

# Compare versions
Compare-PolicyVersions -Version1 "v1" -Version2 "v2"

# Restore previous version
Restore-PolicyVersion -Version "v3"

# Branch management
New-PolicyBranch -Name "test-dlls"
Switch-PolicyBranch -Name "main"
```

### Industry Templates

```powershell
# List available templates
.\src\Utilities\New-PolicyFromTemplate.ps1 -ListTemplates

# Get detailed template info
.\src\Utilities\New-PolicyFromTemplate.ps1 -TemplateInfo Healthcare

# Generate policy from template
.\src\Utilities\New-PolicyFromTemplate.ps1 -Template FinancialServices -Phase 1

# With custom publishers
.\src\Utilities\New-PolicyFromTemplate.ps1 -Template Government -Phase 2 `
    -CustomPublishers @('O=MY COMPANY*')
```

**Available Templates:**
- **FinancialServices**: SOX/PCI-DSS compliance
- **Healthcare**: HIPAA/HITECH compliance
- **Government**: NIST/CMMC compliance
- **Manufacturing**: ICS/OT integration
- **Education**: FERPA/COPPA compliance
- **Retail**: PCI-DSS for POS systems
- **SmallBusiness**: Balanced productivity/security

### Phase Advancement

```powershell
# Check if ready for next phase
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events

# With custom thresholds
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 2 -EventPath .\Events `
    -Thresholds @{ MaxBlockedPerDay = 5; MinAuditDays = 14 }

# Auto-advance if ready
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events -AutoAdvance
```

### Rule Health Checking

```powershell
# Basic health check
.\src\Utilities\Test-RuleHealth.ps1 -PolicyPath .\policy.xml

# With scan data for usage analysis
.\src\Utilities\Test-RuleHealth.ps1 -PolicyPath .\policy.xml -ScanPath .\Scans

# Full check with certificate validation
.\src\Utilities\Test-RuleHealth.ps1 -PolicyPath .\policy.xml -CheckCertificates `
    -EventPath .\Events -OutputPath .\Reports
```

**Health Checks:**
- Path validation (broken paths, environment variables)
- Publisher validation (wildcards, certificate expiry)
- Hash validation (matching files exist)
- Rule conflicts (overlapping allow/deny)
- SID validation (resolvable principals)
- Usage analysis (never-matched rules)

### Self-Service Whitelist Requests

```powershell
Import-Module .\src\Utilities\WhitelistRequestManager.psm1

# Initialize request system
Initialize-WhitelistSystem -RequestsPath .\Requests -ApproversGroup "AppLocker-Approvers"

# Submit a whitelist request
New-WhitelistRequest -ApplicationPath "C:\Apps\MyApp.exe" `
    -Justification "Required for daily operations" `
    -Requester "john.doe@company.com"

# List pending requests
Get-WhitelistRequests -Status Pending

# Approve request
Approve-WhitelistRequest -RequestId "REQ-001" -Approver "admin@company.com"

# Reject request
Deny-WhitelistRequest -RequestId "REQ-002" -Reason "Security concern"
```

### CORA Evidence Generator (v1.2.1)

Generate comprehensive audit evidence packages for compliance reviews:

```powershell
# Generate CORA evidence package
.\src\Utilities\New-CORAEvidence.ps1 -OutputPath .\CORA-Evidence

# Include raw data files
.\src\Utilities\New-CORAEvidence.ps1 -OutputPath .\CORA-Evidence -IncludeRawData

# For a specific policy
.\src\Utilities\New-CORAEvidence.ps1 -OutputPath .\CORA-Evidence -PolicyPath .\policy.xml
```

**Via GUI:** Navigate to **CORA Evidence** (Ctrl+8), set output path, and click Generate.

**CORA Package Contents:**
- `CORA-Executive-Summary.md` - High-level overview for leadership
- `CORA-Policy-Inventory.md` - Detailed policy listing
- `CORA-Rule-Analysis.md` - Rule breakdown by type and collection
- `CORA-Compliance-Assessment.md` - NIST/CIS/CMMC mapping
- `CORA-System-Configuration.md` - AppLocker service status
- `RawData/` folder (when `-IncludeRawData` is specified)

**Supported Compliance Frameworks:**
- NIST 800-53 (CM-7, CM-11, SI-7)
- CIS Controls (2.5, 2.6, 2.7)
- CMMC (CM.L2-3.4.8)

### Incremental Event Collection (v1.2.1)

Efficiently collect only new events since the last collection:

```powershell
# First run - collects all events within DaysBack range
.\src\Core\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\computers.txt -OutputPath .\Events

# Subsequent runs - only collects new events since last run
.\src\Core\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\computers.txt -OutputPath .\Events -SinceLastRun

# Custom state file location
.\src\Core\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\computers.txt -OutputPath .\Events `
    -SinceLastRun -StateFilePath .\Events\collection-state.json
```

**Via main workflow:**
```powershell
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\computers.csv -SinceLastRun
```

The state file (`.lastrun`) tracks:
- Last successful run timestamp
- Computers processed
- Total events collected
- Output path used

---

## Policy Merge Enhancements

Advanced merge options for policy consolidation:

```powershell
# Merge policies and remove default rules
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ -RemoveDefaultRules

# Replace Everyone SID with specific group
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ `
    -TargetGroup "DOMAIN\AppLocker-Users" -ReplaceMode Everyone

# Merge all policies in folder
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ -OutputPath .\merged.xml
```

**ReplaceMode Options:**
- `Everyone` - Replace only S-1-1-0 (Everyone) SID
- `All` - Replace all user SIDs
- `None` - Keep original SIDs

---

## GUI Automated Testing (v1.2.4)

An AutoIt-based GUI test suite is included for automated testing:

```batch
# Run from Tests\GUI directory
Run-GUITests.bat              # Full test suite
Run-GUITests.bat quick        # Quick smoke test
Run-GUITests.bat verbose      # Verbose output
```

**Test Coverage (21 tests):**
- Window basics (exists, title, size, activation)
- Navigation (Ctrl+1 through Ctrl+8)
- Keyboard shortcuts (F1, Ctrl+R, Ctrl+Q, Ctrl+,)
- Page elements (Scan, Generate, Events, Settings, Help)

**Requirements:** AutoIt v3 from https://www.autoitscript.com/

**Output:**
- Log files: `Tests/GUI/test-results-YYYYMMDD-HHMMSS.log`
- Exit code 0 = all tests passed, 1 = failures

---

## Building the EXE

To rebuild the standalone executable:

```powershell
# Full build with validation, tests, and packaging
.\build\Build-AppLocker.ps1

# Build just the GUI executable
.\build\Build-GUI.ps1

# Build the CLI executable
.\build\Build-Executable.ps1

# Run validation only (lint + tests)
.\build\Invoke-LocalValidation.ps1
```

---

## PowerShell Gallery

```powershell
# Publish to PowerShell Gallery
.\build\Publish-ToGallery.ps1 -ApiKey "your-api-key"

# Preview what would be published
.\build\Publish-ToGallery.ps1 -WhatIf
```
