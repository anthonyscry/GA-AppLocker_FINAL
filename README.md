# GA-AppLocker Dashboard

**Enterprise AppLocker Policy Management Tool**

A comprehensive PowerShell WPF application for enterprise AppLocker deployment, aligned with Microsoft AaronLocker best practices.

![Version](https://img.shields.io/badge/version-1.3.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgray)

## Table of Contents

- [Overview](#overview)
- [What's New](#whats-new-in-v130)
- [Features](#features)
- [Installation](#installation)
- [Quick Start Guide](#quick-start-guide)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Overview

GA-AppLocker Dashboard provides complete AppLocker lifecycle management with an intuitive graphical interface:

```
Setup -> Discovery -> Scanning -> Rules -> Deployment -> Monitoring -> Compliance
```

### Core Capabilities

| Phase | Description | Panel |
|-------|-------------|-------|
| **Setup** | Initialize AD structure, create groups | AppLocker Setup |
| **Discovery** | Find and test domain computers | AD Discovery |
| **Scanning** | Collect software artifacts | Artifacts |
| **Rules** | Generate Publisher/Hash/Path rules | Rule Generator |
| **Deployment** | Create GPOs, apply policies | Deployment |
| **Monitoring** | View events, track health | Events, Dashboard |
| **Compliance** | Generate evidence packages | Compliance |

## What's New in v1.3.0

### UI/UX Improvements
- **Cleaner Rule Generator** - Reorganized into 5 clear sections with better spacing
- **Improved Help System** - Comprehensive documentation with visual separators
- **Standardized Button Sizes** - Consistent 30-36px heights across all panels
- **Better Visual Hierarchy** - Clear section headers with descriptive labels
- **Fixed Event Monitor Filters** - Button layout corrected for proper text display

### Bug Fixes
- **Fixed Chart Elements** - Added missing FindName initializations for all chart controls
- **Removed Duplicate Content** - Cleaned up ~470 lines of duplicate XAML
- **Removed Emojis** - Replaced with ASCII text indicators for PS 5.1 compatibility
- **Fixed Text Encoding** - Corrected corrupted bullet point characters in help content

### Security Enhancements
- **Remote Scanning Removed** - Artifact panel now focuses on local scanning only
- **AD Discovery Integration** - Remote scanning capabilities moved to AD Discovery panel
- **Simplified Permissions** - Clearer separation between local and remote operations

## Features

### Setup (AppLocker Setup Panel)
Initialize your Active Directory structure for AppLocker deployment:
- Create AppLocker OU with security groups
- Configure group membership via CSV import/export
- Set up Domain Admins as owner for deletion access
- Remove OU protection option available

### Discovery (AD Discovery Panel)
Find target computers for AppLocker deployment:
- Scan Active Directory for all computers
- Separate computers into Online/Offline lists
- Test connectivity to each computer
- Export computer inventory to CSV

### Scanning (Artifacts Panel)
Collect executable inventory from your environment:
- **Quick Load**: Pull artifacts from Event Monitor
- **Import File**: Load CSV exports manually
- **Import Folder**: Batch load multiple CSVs
- **Deduplicate**: Remove duplicates by Publisher/Hash/Path
- **Export List**: Save filtered artifact list

### Rule Generator (Rules Panel)
Create AppLocker rules with enhanced workflow:

**Configuration Section:**
- Rule type selection (Auto/Publisher/Hash/Path)
- Action selection (Allow/Deny)
- Target AD group assignment

**Import Artifacts Section:**
- Quick load from other panels
- File and folder import options
- Deduplication tools
- Export capabilities

**Generate Rules Section:**
- Generate rules from artifacts
- Default Deny Rules (block bypass locations)
- Browser Deny Rules (admin protection)

**Rules List Section:**
- Filter by Type, Action, Group
- Search functionality
- Delete selected rules
- DataGrid with sorting

**Output Log Section:**
- Real-time generation feedback
- Success/error messages

### Deployment (Deployment Panel)
Deploy policies via Group Policy:
- Create AppLocker GPOs
- One-click Audit/Enforce toggle
- Export rules to XML
- Import existing policies
- Assign GPOs to OUs (DCs/Servers/Workstations)

### Monitoring (Dashboard & Events Panels)
Track policy effectiveness:
- **Dashboard**: Policy health score, event statistics, machine counts
- **Events**: Filter by type (Allowed/Audit/Blocked), quick date presets, export to CSV
- **Charts**: Visual representation of data (pie charts, gauge, bar charts)

### Compliance (Compliance Panel)
Generate audit evidence packages:
- Timestamped evidence folders
- Policy snapshots
- Event log exports
- HTML compliance reports

## Quick Start Guide

Follow these steps to deploy AppLocker in your environment:

### Step 1: Prepare (5 minutes)
1. Run the application as Administrator
2. Go to **AppLocker Setup** panel
3. Click **Create AppLocker Structure**
4. Go to **AD Discovery** panel
5. Click **Discover Computers** to find targets

### Step 2: Collect Artifacts (15-30 minutes)
1. Go to **Artifacts** panel
2. Click **Scan Local System** for quick local scan
3. Or select online computers and click **Scan Selected**
4. Artifacts saved to `C:\GA-AppLocker\Scans\`

### Step 3: Generate Rules (10 minutes)
1. Go to **Rule Generator** panel
2. Click **Load Artifacts** to pull from scan
3. Configure: Type=Auto, Action=Allow, Group=AppLocker-StandardUsers
4. Click **Generate Rules**
5. Click **Default Deny Rules** for security
6. Click **Export List** to save

### Step 4: Deploy in Audit Mode (5 minutes)
1. Go to **Deployment** panel
2. Click **Create GPO** (Audit mode)
3. Click **Export Rules** to save policy
4. Run `gpupdate /force` on test computer
5. Wait 7-14 days, monitor events

### Step 5: Monitor (7-14 days)
1. Go to **Events** panel
2. Review Audit events (Event ID 8003)
3. Add rules for legitimate software
4. Document exceptions

### Step 6: Enforce (5 minutes)
1. Go to **Deployment** panel
2. Click **[!] AUDIT MODE** to switch to Enforce
3. Confirm the change
4. Run `gpupdate /force` on target computers

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Run as Administrator

### Domain Mode (Full Features)
- Active Directory domain membership
- RSAT tools installed:
  ```powershell
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
  ```

### Workgroup Mode (Limited)
- Local scanning only
- No AD discovery or GPO features

## Installation

1. Extract to `C:\GA-AppLocker\`
2. Run as Administrator:
   ```powershell
   .\build\GA-AppLocker-GUI-WPF.ps1
   ```

## Directory Structure

```
C:\GA-AppLocker\
├── build/                  # Main application GUIs
│   ├── GA-AppLocker-GUI-WPF.ps1      # Primary WPF GUI (recommended)
│   ├── GA-AppLocker-GUI-Full.ps1     # Windows Forms alternative
│   └── GA-AppLocker-GUI-Standalone.ps1
├── src/
│   ├── modules/            # PowerShell modules (7 modules)
│   ├── lib/                # Shared library functions
│   ├── GA-AppLocker.psm1   # Main module wrapper
│   └── Config.psm1         # Configuration
├── Scans/                  # Artifact scan output
├── Events/                 # Exported event files
├── Rules/                  # Generated AppLocker rules
├── Logs/                   # Application logs
└── Compliance/             # Evidence packages
```

## Module Architecture

The application is built on 7 specialized PowerShell modules:

### Module 1: Dashboard (`Module1-Dashboard.psm1`)
Provides overview statistics for the AppLocker environment:
- **Get-AppLockerEventStats** - Counts events by type (Allowed/Audit/Blocked)
- **Get-ADMachineCount** - Counts computers in AD by type
- **Get-PolicyHealthScore** - Calculates policy coverage score (0-100)
- **Get-DashboardSummary** - Aggregates all dashboard metrics

### Module 2: Remote Scan (`Module2-RemoteScan.psm1`)
Discovers machines and scans for software artifacts:
- **Get-DirectorySafetyClassification** - AaronLocker-style path classification
- **Get-AllADComputers** / **Get-ComputersByOU** - AD computer discovery
- **Test-ComputerOnline** - Network connectivity testing
- **Get-ExecutableArtifacts** - Comprehensive local scanning
- **Get-RemoteArtifacts** - Remote scanning via WinRM
- **Export-ScanResults** / **Import-ScanResults** - CSV operations

### Module 3: Rule Generator (`Module3-RuleGenerator.psm1`)
Creates AppLocker rules from artifacts:
- **New-PublisherRule** / **New-PathRule** / **New-HashRule** - Rule creation
- **New-RulesFromArtifacts** - Bulk rule generation with deny list filtering
- **Compare-SoftwareBaseline** - Gap analysis
- **Export-RulesToXml** / **Import-RulesFromXml** - Policy XML operations
- **Protect-XmlAttributeValue** - XML injection prevention

### Module 4: Policy Lab (`Module4-PolicyLab.psm1`)
Manages GPO creation and policy deployment:
- **New-AppLockerGPO** - Creates AppLocker GPOs
- **Add-GPOLink** - Links GPOs to OUs
- **Set-GPOAppLockerPolicy** - Applies XML policy to GPO
- **Set-LatestAppLockerPolicy** - Finds and applies most recent policy
- **Save-PolicyToFile** - UTF-16 policy export

### Module 5: Event Monitor (`Module5-EventMonitor.psm1`)
Monitors and backs up AppLocker events:
- **Get-AppLockerEvents** - Event retrieval with FQBN parsing
- **Filter-EventsByEventId** / **Filter-EventsByDateRange** - Event filtering
- **Backup-RemoteAppLockerEvents** - Single computer backup
- **Backup-AllAppLockerEvents** - Batch backup

### Module 6: AD Manager (`Module6-ADManager.psm1`)
Active Directory and WinRM management:
- **Protect-LDAPFilterValue** - LDAP injection protection
- **Get-AllADUsers** / **Search-ADUsers** - User queries
- **New-AppLockerGroups** - Creates standard security groups
- **Add-UserToAppLockerGroup** / **Remove-UserFromAppLockerGroup** - Membership
- **New-WinRMGPO** - WinRM configuration GPO

### Module 7: Compliance (`Module7-Compliance.psm1`)
Compliance evidence collection:
- **New-EvidenceFolder** - Creates evidence directory structure
- **Export-CurrentPolicy** - Exports AppLocker policy
- **Export-SystemInventory** - Collects software and process inventory
- **Get-ComplianceSummary** - Generates compliance metrics
- **New-ComplianceReport** - Creates HTML compliance report
- **Export-AllEvidence** - Orchestrates all evidence collection

### Common Library (`Common.psm1`)
Shared utility functions:
- **Write-Log** - Logging with rotation
- **Save-XmlDocAsUnicode** - UTF-16 XML saving
- **IsWin32Executable** - PE header detection
- **ConvertTo-AppLockerGenericPath** - Path variable conversion
- **ConvertFrom-SidCached** - SID translation with caching
- **Test-AppLockerPath** / **Test-PublisherName** - Input validation

## Quick Start

### Phase 1: Setup
1. **AppLocker Setup** - Create AD structure
2. **Group Management** - Populate AppLocker groups
3. **AD Discovery** - Find target computers

### Phase 2: Scanning
4. **Artifact Collection** - Scan computers
5. Or **Comprehensive Scan** for full inventory

### Phase 3: Rules
6. **Rule Generator** - Import artifacts
7. Select type (Publisher preferred), action, group
8. **Generate Rules** - Export

### Phase 4: Deploy
9. **Deployment** - Create GPO (Audit mode)
10. **Event Monitor** - Review 7-14 days
11. **Deployment** - Switch to Enforce

## AppLocker Groups

| Group | Purpose |
|-------|---------|
| AppLocker-Admins | Domain/Server admins |
| AppLocker-PowerUsers | Advanced execution permissions |
| AppLocker-StandardUsers | Regular end users (most restrictive) |
| AppLocker-RestrictedUsers | Limited essential tools |
| AppLocker-Installers | Software deployment staff |
| AppLocker-Developers | Development environment |

## AppLocker Event IDs

| Event ID | Type | Description |
|----------|------|-------------|
| 8002 | EXE/DLL | Execution Allowed |
| 8003 | EXE/DLL | Execution Audit (would be blocked) |
| 8004 | EXE/DLL | Execution Blocked |
| 8005 | MSI/Script | Allowed |
| 8006 | MSI/Script | Audit |
| 8007 | MSI/Script | Blocked |

## Rule Type Priority

1. **Publisher Rules** - Preferred, resilient to updates
2. **Hash Rules** - Fallback for unsigned files
3. **Path Rules** - Use sparingly, easily bypassed

## Best Practices

- Always start in **Audit mode**
- Use **Publisher rules** first
- Create **Deny rules** for user-writable paths:
  - `%USERPROFILE%\Downloads\*`
  - `%APPDATA%\*`
  - `%LOCALAPPDATA%\Temp\*`
- Never allow **Everyone** to run Microsoft-signed code
- Test with actual user accounts

## Policy Guide (Key Principles)

### Execution Decision Order
1. Explicit Deny (always wins)
2. Explicit Allow
3. Implicit Deny

### Mandatory Allow Principals
- NT AUTHORITY\SYSTEM
- NT AUTHORITY\LOCAL SERVICE
- NT AUTHORITY\NETWORK SERVICE
- BUILTIN\Administrators

### Required Deny Rules
Create Deny-Path rules for Everyone:
- `%USERPROFILE%\Downloads\*`
- `%APPDATA%\*`
- `%LOCALAPPDATA%\Temp\*`
- `%TEMP%\*`

## Troubleshooting

### Events not appearing
- Verify Application Identity service running
- Run `gpresult /r` to check policy
- Run `gpupdate /force` on target

### WinRM failures
- Check WinRM GPO applied
- Firewall TCP 5985/5986 open
- Run `winrm quickconfig` on target

### Rule generation errors
- Verify scan completed
- Check CSV format (UTF-8)
- Use Hash rules for unsigned files

### AD Discovery issues
- Verify RSAT tools installed
- Check domain connectivity
- Run as domain admin

## Logs

Daily logs in `C:\GA-AppLocker\Logs\GA-AppLocker-YYYY-MM-DD.log`

## Development

See `claude.md` for detailed technical documentation including:
- Module architecture
- Function reference
- Return value patterns
- Known issues and technical debt

## Version History

- **v1.2.4** - Custom scan credentials, dashboard filters, improved event parsing
- **v1.2.3** - Policy Guide, Gap Analysis improvements
- **v1.2.0** - WPF GUI, comprehensive scanning
- **v1.0.0** - Initial release

## License

Internal use - GA-ASI

## References

- [AaronLocker](https://github.com/microsoft/AaronLocker)
- [Microsoft AppLocker Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
