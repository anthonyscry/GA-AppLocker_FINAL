# GA-AppLocker Dashboard

**AaronLocker-Aligned AppLocker Policy Management Tool**

A PowerShell WPF application for enterprise AppLocker deployment, aligned with Microsoft AaronLocker best practices.

![Version](https://img.shields.io/badge/version-1.2.5-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgray)

## Overview

GA-AppLocker Dashboard provides a complete AppLocker lifecycle management solution with quality-of-life enhancements for enterprise deployments:

1. **Setup** - Initialize AD structure (OU, groups, starter policy)
2. **Discovery** - Find and ping-check domain computers
3. **Scanning** - Collect software artifacts (local or remote)
4. **Rule Generation** - Create Publisher/Hash/Path rules with validation
5. **Deployment** - Export rules, create GPOs
6. **Monitoring** - View events, track policy health
7. **Compliance** - Generate evidence packages

## What's New in v1.2.5

### Quality-of-Life Features
- **Search/Filter** - Filter artifacts and rules by publisher, path, filename
- **Audit Toggle** - One-click switch between Audit and Enforce modes
- **Rule Preview** - Preview XML rules before generation
- **Mini Status Bar** - Real-time domain, artifact count, and sync status
- **Bulk Confirmation** - Confirmation dialogs before destructive operations
- **Quick Date Presets** - Last Hour, Today, Last 7 Days, Last 30 Days event filtering

### Bug Fixes
- **UTF-16 Encoding** - Fixed XML export to use proper UTF-16 encoding (required for AppLocker)
- **Regex Patterns** - Improved directory safety classification with robust regex escaping
- **System.Web Assembly** - Added assembly loading for HTML encoding security
- **Emoji Removal** - Replaced emoji characters with ASCII for PowerShell compatibility

### Architecture Improvements
- **Standardized Artifact Model** - Common artifact data structure across all modules
- **Artifact Conversion** - Automatic property name mapping between different formats
- **Rule Validation** - Pre-export validation ensures all required properties exist
- **Unit Tests** - 20 new artifact interoperability tests (all passing)

## Features

### Setup
| Feature | Description |
|---------|-------------|
| AppLocker Setup | Create AD OU, security groups, and starter policy |
| Group Management | Export/import group membership via CSV |
| AD Discovery | Find computers with online/offline status |

### Scanning
| Feature | Description |
|---------|-------------|
| Artifact Collection | Scan for executables, DLLs, scripts, MSIs |
| Comprehensive Scan | AaronLocker-style full inventory |
| Remote Scanning | Scan multiple computers via WinRM |

### Rule Generation
| Feature | Description |
|---------|-------------|
| Publisher Rules | Create rules from code signing certificates |
| Hash Rules | Create rules from file hashes (unsigned files) |
| Path Rules | Create rules from file paths |
| From Events | Generate rules from AppLocker event logs |

### Deployment
| Feature | Description |
|---------|-------------|
| Rule Export | Export to AppLocker XML format |
| GPO Management | Create/link AppLocker GPOs |
| WinRM Setup | Configure remote management via GPO |
| Browser Deny | Generate admin browser deny rules |

### Monitoring
| Feature | Description |
|---------|-------------|
| Dashboard | Policy health score, event statistics |
| Event Monitor | View Allowed/Blocked/Audit events |
| Gap Analysis | Compare software between systems |
| Compliance | Generate audit evidence packages |

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
