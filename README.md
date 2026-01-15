# GA-AppLocker Dashboard

**AaronLocker-Aligned AppLocker Policy Management Tool**

A PowerShell WPF application for enterprise AppLocker deployment, aligned with AaronLocker best practices.

![Version](https://img.shields.io/badge/version-1.2.4-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgray)

## Overview

GA-AppLocker Dashboard provides a complete AppLocker lifecycle management solution:

1. **Setup** - Initialize AD structure (OU, groups, starter policy)
2. **Discovery** - Find and ping-check domain computers
3. **Scanning** - Collect software artifacts (local or remote)
4. **Rule Generation** - Create Publisher/Hash/Path rules
5. **Deployment** - Export rules, create GPOs
6. **Monitoring** - View events, track policy health
7. **Compliance** - Generate evidence packages

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
├── build\              # Main application
├── src\modules\        # PowerShell modules
├── Scans\              # Artifact scan output
├── Events\             # Exported event files
├── Rules\              # Generated AppLocker rules
├── Logs\               # Application logs
└── Compliance\         # Evidence packages
```

## Quick Start

### Phase 1: Setup
1. **AppLocker Setup** → Create AD structure
2. **Group Management** → Populate AppLocker groups
3. **AD Discovery** → Find target computers

### Phase 2: Scanning
4. **Artifact Collection** → Scan computers
5. Or **Comprehensive Scan** for full inventory

### Phase 3: Rules
6. **Rule Generator** → Import artifacts
7. Select type (Publisher preferred), action, group
8. **Generate Rules** → Export

### Phase 4: Deploy
9. **Deployment** → Create GPO (Audit mode)
10. **Event Monitor** → Review 7-14 days
11. **Deployment** → Switch to Enforce

## AppLocker Groups

| Group | Purpose |
|-------|---------|
| AppLocker-Admins | Domain/Server admins |
| AppLocker-StandardUsers | Regular end users (most restrictive) |
| AppLocker-Service-Accounts | Service accounts |
| AppLocker-Installers | Software deployment staff |

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

## Logs

Daily logs in `C:\GA-AppLocker\Logs\GA-AppLocker-YYYY-MM-DD.log`

## Version History

- **v1.2.4** - Dashboard filters, improved event parsing, UI fixes
- **v1.2.3** - Policy Guide, Gap Analysis improvements
- **v1.2.0** - WPF GUI, comprehensive scanning
- **v1.0.0** - Initial release

## License

Internal use - GA-ASI

## References

- [AaronLocker](https://github.com/microsoft/AaronLocker)
- [Microsoft AppLocker Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
