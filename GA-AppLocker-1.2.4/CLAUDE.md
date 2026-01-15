# CLAUDE.md - GA-AppLocker Project Reference

## Project Overview

**GA-AppLocker** is a simplified AppLocker deployment toolkit for Windows security administrators. Created by Tony Tran (ISSO, GA-ASI), it automates creating and managing Windows AppLocker policies.

**Purpose:**
- Collect application inventory data from Windows machines remotely via WinRM
- Collect AppLocker audit events (8003/8004) to identify blocked applications
- Generate enterprise-ready AppLocker policies based on real environment data
- Support phased deployment (low-risk to high-risk enforcement)
- Merge and validate AppLocker policies across organizations
- Compare software inventories to identify drift between systems

**Target Platforms:** Windows 11, Windows Server 2019+

## Technology Stack

- **Pure PowerShell** (5.1+) - no external dependencies
- **WinRM** for remote scanning
- **Active Directory** (optional) for group management
- **AppLocker Policy XML** (native Windows security format)
- **Authenticode signatures** for publisher-based rules

## Project Structure

```
GA-AppLocker/
├── GA-AppLocker.exe                 # Standalone portable executable (main entry)
├── GA-AppLocker.psd1                # PowerShell module manifest
├── GA-AppLocker.psm1                # Root module with wrapper functions
├── README.md                        # Full documentation
├── LICENSE
├── ADManagement/                    # AD-related files (created automatically)
│   └── computers.csv.example
├── build/
│   ├── Build-AppLocker.ps1          # Full build orchestrator
│   ├── Build-Executable.ps1         # CLI executable compilation
│   ├── Build-GUI.ps1                # GUI executable compilation
│   ├── Invoke-LocalValidation.ps1   # Pre-commit validation
│   └── Publish-ToGallery.ps1        # PowerShell Gallery publishing
├── src/
│   ├── Core/                        # Core workflow scripts
│   │   ├── Start-AppLockerWorkflow.ps1   # Main entry point
│   │   ├── Start-GUI.ps1                 # GUI launcher
│   │   ├── Invoke-RemoteScan.ps1         # WinRM-based scanning
│   │   ├── Invoke-RemoteEventCollection.ps1  # Audit event collection
│   │   ├── New-AppLockerPolicyFromGuide.ps1  # Policy generation
│   │   └── Merge-AppLockerPolicies.ps1   # Policy merging
│   ├── GUI/
│   │   ├── GA-AppLocker-Portable.ps1     # WPF GUI application
│   │   ├── AsyncHelpers.psm1             # Async execution module
│   │   ├── Scripts/                      # Setup scripts
│   │   └── Tests/                        # GUI-specific tests
│   └── Utilities/
│       ├── Common.psm1                   # Shared functions
│       ├── Config.psd1                   # Centralized configuration
│       ├── ErrorHandling.psm1            # Standardized error handling
│       ├── CredentialManager.psm1        # Secure credential storage
│       ├── Manage-SoftwareLists.ps1      # Software whitelist management
│       ├── PolicyVersionControl.psm1     # Git-like policy versioning
│       ├── PolicyTemplates.psd1          # Industry-specific templates
│       ├── WhitelistRequestManager.psm1  # Self-service whitelist workflows
│       ├── Start-AppLockerMonitor.ps1    # Continuous monitoring
│       ├── Export-AppLockerGPO.ps1       # GPO/SCCM/Intune export
│       ├── Get-RuleImpactAnalysis.ps1    # Pre-deployment analysis
│       ├── Invoke-PhaseAdvancement.ps1   # Automatic phase progression
│       ├── New-PolicyFromTemplate.ps1    # Template-based generation
│       ├── Test-RuleHealth.ps1           # Rule health checking
│       ├── New-ComplianceReport.ps1      # Compliance audit reporting
│       ├── Enable-WinRM-Domain.ps1       # WinRM deployment
│       ├── Manage-ADResources.ps1        # AD management
│       ├── Compare-SoftwareInventory.ps1 # Inventory comparison
│       └── Test-AppLockerDiagnostic.ps1  # Diagnostics
├── Tests/                           # Pester test files
│   └── GUI/                         # AutoIt GUI tests (v1.2.4)
│       ├── GA-AppLocker-GUI-Test.au3    # AutoIt test script
│       ├── Run-GUITests.bat             # Test runner
│       └── README.md                    # Test documentation
├── assets/                          # Icons and images
└── docs/                            # Additional documentation
```

## Key Patterns and Conventions

### Entry Point Pattern
- `Start-AppLockerWorkflow.ps1` is the unified hub for all functionality
- Supports interactive menu mode (default) and direct parameter mode
- Always start here rather than individual scripts

### Configuration Centralization
- `utilities/Config.psd1` contains all settings (SIDs, LOLBins, paths, defaults)
- Modify this file to customize for specific environments

### Two Policy Generation Modes

**Build Guide Mode** (Enterprise):
- Target-specific: Workstation, Server, Domain Controller
- Custom AD group scoping
- Phased deployment (Phase 1-4)
- Proper principal scoping (SYSTEM, LOCAL SERVICE, etc.)

**Simplified Mode** (Quick Deployment):
- Single target user/group
- Good for labs, testing, or standalone machines

### Data Formats
- **Policies:** AppLocker XML format
- **Software Lists:** JSON format
- **Scan Results:** CSV files (per-computer subdirectories)
- **Computer Lists:** CSV format with `ComputerName` column (TXT also supported for backwards compatibility)

### Output Organization
- Scans: `./Scans/Scan-YYYYMMDD-HHMMSS/[COMPUTERNAME]/`
- Events: `./Events/Events-YYYYMMDD-HHMMSS/[COMPUTERNAME]/`
- Policies: `./Outputs/AppLockerPolicy-[Mode].xml`
- Software Lists: `./SoftwareLists/[ListName].json`
- Comparisons: `./SoftwareLists/Comparisons/`
- AD Files: `./ADManagement/` (computers.csv, users.csv, groups.csv)
- Reports: `./Reports/` (compliance reports)

### Interactive UI Features
- **Folder Browser**: Numbered selection for navigating scan folders
- **Output Defaults**: Validate/Merge workflows default to `./Outputs` folder
- **Auto-selection**: Compare workflow auto-selects InstalledSoftware.csv

### GUI Features
- **Button State Management**: Buttons disabled during long operations to prevent conflicts
- **Operation Cancellation**: Cancel button appears during long operations (cancels at next output line)
- **Keyboard Shortcuts** (v1.2.4 - matches sidebar order):
  - Ctrl+1: Scan, Ctrl+2: Events, Ctrl+3: Compare, Ctrl+4: Validate
  - Ctrl+5: Generate, Ctrl+6: Merge, Ctrl+7: Software, Ctrl+8: CORA
  - Ctrl+Q: Quick Workflow, Ctrl+R: Refresh, Ctrl+,: Settings, F1: Help
- **Progress Indicators**: Visual feedback during XML validation and file processing
- **Version Display**: Window title and About page show version dynamically ($Script:AppVersion)

### Software List Management
The toolkit includes advanced software list features for curated allowlists:

**Import Methods:**
- **Scan Data**: Import from remote scan CSV files
- **Common Publishers**: Pre-defined trusted publishers (Microsoft, Adobe, Google, Security vendors, etc.)
- **AppLocker Policy**: Extract rules from existing policy XML
- **Folder Scan**: Scan local folders for executables

**Publisher Categories:**
- Microsoft, Productivity, Browser/Cloud, Development, Security, Communication, Remote Access

## Common Commands

### Recommended: Use the EXE
```powershell
# Double-click GA-AppLocker.exe in the root folder
# Or run from command line:
.\GA-AppLocker.exe
```

### Interactive Mode (PowerShell)
```powershell
.\src\Core\Start-AppLockerWorkflow.ps1
```

### Direct Parameter Mode
```powershell
# Quick scan
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList .\ADManagement\computers.csv

# Generate simplified policy
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -Simplified

# Generate Build Guide policy
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans\Scan-20260109 `
    -TargetType Workstation -DomainName CONTOSO -Phase 1

# Validate policy
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Validate -PolicyPath .\policy.xml

# Full workflow (Scan + Generate)
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Full -ComputerList .\ADManagement\computers.csv

# Collect AppLocker audit events (blocked apps from last 14 days)
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv

# Collect events from last 30 days
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv -DaysBack 30

# Collect all audit events (blocked + allowed)
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv -IncludeAllowedEvents
```

### Utility Scripts
```powershell
# Software list management (use interactive menu [S] from main workflow)
.\src\Core\Start-AppLockerWorkflow.ps1
# Select [S] Software → [4] Publishers to import trusted publishers

# Compare inventories
.\src\Utilities\Compare-SoftwareInventory.ps1 -ReferencePath .\baseline.csv -ComparePath .\target.csv

# Diagnostics
.\src\Utilities\Test-AppLockerDiagnostic.ps1 -ComputerName TARGET-PC

# WinRM setup
.\src\Utilities\Enable-WinRM-Domain.ps1
```

### Advanced Features (v1.1.0)
```powershell
# Continuous monitoring with alerts
.\src\Utilities\Start-AppLockerMonitor.ps1 -ComputerListPath .\computers.txt -IntervalMinutes 30

# Background monitoring with webhook alerts
.\src\Utilities\Start-AppLockerMonitor.ps1 -ComputerListPath .\computers.txt -AsJob `
    -AlertWebhook "https://teams.webhook.url" -AlertThreshold 5

# Export policy for GPO deployment
.\src\Utilities\Export-AppLockerGPO.ps1 -PolicyPath .\policy.xml -OutputPath .\GPO-Export

# Export for specific deployment method (GPOBackup, PowerShell, Registry, SCCM, Intune)
.\src\Utilities\Export-AppLockerGPO.ps1 -PolicyPath .\policy.xml -Format Intune

# Pre-deployment impact analysis
.\src\Utilities\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml -ScanPath .\Scans

# Detailed impact with current policy comparison
.\src\Utilities\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml -ScanPath .\Scans `
    -CurrentPolicyPath .\current.xml -Detailed

# Publish to PowerShell Gallery
.\build\Publish-ToGallery.ps1 -ApiKey "your-api-key"

# Preview what would be published
.\build\Publish-ToGallery.ps1 -WhatIf
```

### Policy Lifecycle Features (v1.2.0)
```powershell
# Initialize policy version control repository
Import-Module .\src\Utilities\PolicyVersionControl.psm1
Initialize-PolicyRepository -Path .\PolicyRepo

# Save a policy version with message
Save-PolicyVersion -PolicyPath .\policy.xml -Message "Added Chrome rules"

# View policy history
Show-PolicyLog -Last 10

# Compare policy versions
Compare-PolicyVersions -Version1 "v1" -Version2 "v2"

# Restore previous version
Restore-PolicyVersion -Version "v3"

# Branch management for testing
New-PolicyBranch -Name "test-dlls"
Switch-PolicyBranch -Name "main"
```

### Industry Templates (v1.2.0)
```powershell
# List available templates
.\src\Utilities\New-PolicyFromTemplate.ps1 -ListTemplates

# Get detailed template info
.\src\Utilities\New-PolicyFromTemplate.ps1 -TemplateInfo Healthcare

# Generate policy from template
.\src\Utilities\New-PolicyFromTemplate.ps1 -Template FinancialServices -Phase 1

# Generate with custom publishers
.\src\Utilities\New-PolicyFromTemplate.ps1 -Template Government -Phase 2 `
    -CustomPublishers @('O=MY COMPANY*')
```

**Available Templates:**
- **FinancialServices**: SOX/PCI-DSS compliance (Banking, Insurance)
- **Healthcare**: HIPAA/HITECH compliance (Hospitals, Clinics)
- **Government**: NIST/CMMC compliance (Federal, State, Defense)
- **Manufacturing**: ICS/OT integration (Automotive, Aerospace)
- **Education**: FERPA/COPPA compliance (K-12, Higher Ed)
- **Retail**: PCI-DSS for POS systems
- **SmallBusiness**: Balanced productivity/security

### Phase Advancement (v1.2.0)
```powershell
# Check if ready for next phase
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events

# With custom thresholds
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 2 -EventPath .\Events `
    -Thresholds @{ MaxBlockedPerDay = 5; MinAuditDays = 14 }

# Auto-advance if ready
.\src\Utilities\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events -AutoAdvance
```

### Rule Health Checking (v1.2.0)
```powershell
# Run health check on policy
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

### Self-Service Whitelist Requests (v1.2.0)
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

# Approve request (creates policy rule automatically)
Approve-WhitelistRequest -RequestId "REQ-001" -Approver "admin@company.com"

# Reject request
Deny-WhitelistRequest -RequestId "REQ-002" -Reason "Security concern"
```

### Compliance Reporting (v1.2.0)
```powershell
# Generate HTML compliance report
.\src\Utilities\New-ComplianceReport.ps1

# Generate Markdown report with evidence listings
.\src\Utilities\New-ComplianceReport.ps1 -Format Markdown -IncludeEvidence

# Generate report for specific policy
.\src\Utilities\New-ComplianceReport.ps1 -PolicyPath .\policy.xml -Format HTML
```

**Compliance Standards Supported:**
- NIST 800-53 (CM-7, CM-11, SI-7)
- CIS Controls (2.5, 2.6)
- CMMC (CM.L2-3.4.8)

### CORA Evidence Package (v1.2.1)
```powershell
# Generate complete CORA audit evidence package (use menu [R] or script directly)
.\src\Utilities\New-CORAEvidence.ps1

# Include raw data files (larger but complete)
.\src\Utilities\New-CORAEvidence.ps1 -IncludeRawData

# Analyze specific production policy
.\src\Utilities\New-CORAEvidence.ps1 -PolicyPath .\production-policy.xml -IncludeRawData
```

**Evidence Package Contents:**
- Executive Summary (HTML) with compliance score
- Software inventory scans with timestamps
- AppLocker event collections
- Policy files with rule counts
- Control mapping (NIST, CIS, CMMC)
- Deployment timeline
- Health check results
- Machine-readable manifest (JSON)

### Policy Merge Enhancements
```powershell
# Merge policies and remove default rules
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Merge -RemoveDefaultRules

# Replace Everyone SID with specific group during merge
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ `
    -TargetGroup "DOMAIN\AppLocker-Users" -ReplaceMode Everyone

# Merge with deduplication modes
.\src\Core\Merge-AppLockerPolicies.ps1 -PolicyPaths .\policies\ -OutputPath .\merged.xml
```

## Important Parameters

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
| `-TargetGroup` | Replace Everyone SID with specific group in merged policies |
| `-ReplaceMode` | SID replacement mode: Everyone, All, or None |

## Security Principles

The toolkit follows these security principles:
- "Allow who may run trusted code, deny where code can never run"
- Explicit deny rules for user-writable paths (%TEMP%, Downloads, AppData)
- LOLBins (mshta.exe, wscript.exe, powershell.exe, etc.) explicitly denied when enabled
- Publisher-based rules use correct principal scoping (not Everyone)

## Development Notes

### When Modifying Scripts
- Import `Common.psm1` for shared functions
- Import `ErrorHandling.psm1` for standardized error handling
- Reference `Config.psd1` for configurable values
- Follow existing parameter patterns for consistency
- Use `Write-Host` with color for user feedback
- Support both interactive and parameter-driven modes

### ErrorHandling.psm1 Functions
```powershell
# Standardized error handling
Invoke-SafeOperation -ScriptBlock { ... } -ErrorMessage "Operation failed" -ContinueOnError

# Input validation
Test-ValidPath -Path $path -Type Directory -MustExist -CreateIfMissing
Test-ValidXml -Path $file -RootElement "AppLockerPolicy"
Test-ValidAppLockerPolicy -Path $policyFile
Test-ValidComputerList -Path $computers
Test-RequiredKeys -Hashtable $config -RequiredKeys @('Key1', 'Key2')

# Credential validation (tests WinRM connectivity)
Test-CredentialValidity -Credential $cred -ComputerName 'TARGET-PC' -TimeoutSeconds 30

# Standardized output
Write-SectionHeader -Title "Processing..."
Write-StepProgress -Step 1 -Total 5 -Message "Loading data"
Write-SuccessMessage -Message "Completed successfully"
Write-ErrorMessage -Message "Failed to process" -Throw
Write-ResultSummary -Title "Results" -Results $results

# Script initialization
Initialize-GAAppLockerScript -RequireAdmin -RequireModules @('ActiveDirectory')
```

### Config.psd1 Key Sections
- `WellKnownSids` - Windows security identifiers (26 entries)
- `LOLBins` - High-risk executables for deny rules (18 executables)
- `DefaultDenyPaths` - User-writable locations
- `DefaultAllowPaths` - Protected system paths
- `MicrosoftPublishers` - Microsoft certificate subjects
- `DefaultScanPaths` - Paths to scan for executables
- `FileExtensions` - Grouped by type (Exe, Dll, Script, Installer)
- `CommonPublishers` - Pre-defined trusted publishers (19 vendors)
- `SoftwareCategories` - Software categorization (13 categories)
- `HealthCheck` - Rule health checking thresholds

### Manage-SoftwareLists.ps1 Key Features
- `$Script:CommonPublishers` - Pre-defined trusted publishers by category
- Categories: Microsoft, Productivity, Browser/Cloud, Development, Security, Communication, Remote Access
- Functions: `New-SoftwareList`, `Import-ScanDataToSoftwareList`, `Import-CommonPublishersToSoftwareList`

### Testing Changes
```powershell
# Test connectivity
Test-WSMan -ComputerName "TARGET-PC"

# Local policy test
Set-AppLockerPolicy -XmlPolicy .\Outputs\AppLockerPolicy.xml

# Diagnostic mode
.\utilities\Test-AppLockerDiagnostic.ps1 -ComputerName TARGET-PC
```

## Workflow for Enterprise Deployment

1. **Setup WinRM** organization-wide
2. **Scan** 14+ machines to collect inventory
3. **Generate Phase 1** policies (EXE only - lowest risk)
4. **Deploy via GPO** in Audit mode for 14+ days
5. **Collect audit events** using `[E] Events` menu (collects 8003/8004)
6. **Review blocked apps** in `UniqueBlockedApps.csv` output
7. **Create rules** for legitimate blocked software via Software Lists
8. **Advance through phases** progressively

### Event Collection Details
AppLocker audit events provide critical feedback during the deployment process:
- **Event 8003**: Would have been allowed (EXE/DLL)
- **Event 8004**: Would have been blocked (EXE/DLL) - most useful
- **Event 8005/8006**: MSI and Script events
- **Event 8007/8008**: Packaged app events

The `Invoke-RemoteEventCollection.ps1` script collects these events and produces:
- `UniqueBlockedApps.csv`: Deduplicated list with occurrence counts, affected computers
- `AllBlockedEvents.csv`: Consolidated view for analysis
- Per-computer CSV files with detailed event data

## File Naming Conventions

- Scripts: PascalCase with Verb-Noun pattern (e.g., `Start-AppLockerWorkflow.ps1`)
- Modules: PascalCase (e.g., `Common.psm1`)
- Data files: PascalCase (e.g., `Config.psd1`)
- Output files: Descriptive with timestamps when applicable
