# GA-AppLocker Dashboard

A comprehensive PowerShell-based dashboard for managing Microsoft AppLocker policies across an Active Directory environment.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgray)

## Overview

GA-AppLocker Dashboard implements the complete AppLocker lifecycle:

1. **Discovery** - Scan Active Directory for target computers
2. **Scan** - Collect software artifacts from machines
3. **Ingest** - Import scan results seamlessly
4. **Generate** - Automatically create AppLocker rules based on best practices
5. **Merge** - Combine rules by machine type (Workstation/Server/DC)
6. **Deploy** - Apply policies to OUs in Audit mode
7. **Monitor** - Watch for blocked/audited events
8. **Enforce** - Move from Audit to Enforced mode

## Features

| Module | Features |
|--------|----------|
| **Dashboard** | Event statistics, machine counts, policy health score |
| **Remote Scan** | AD discovery, online status checking, artifact collection |
| **Rule Generator** | Publisher, path, and hash rule generation from scan data |
| **Policy Lab** | GPO creation, policy linking, OU management |
| **Event Monitor** | Event viewing, filtering, remote backup |
| **AD Manager** | User/group management, WinRM configuration |
| **Compliance** | Evidence collection, reporting, deployment readiness |

## Quick Start

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Active Directory PowerShell module (RSAT)
- Group Policy PowerShell module
- Domain Administrator privileges

### Installation

```powershell
# Clone the repository
git clone https://github.com/anthonyscry/GA-AppLocker_FINAL.git
cd GA-AppLocker_FINAL

# Copy to Program Files
Copy-Item -Path ".\src" -Destination "C:\Program Files\GA-AppLocker" -Recurse

# Create output directories
New-Item -Path "C:\AppLocker\output" -ItemType Directory -Force
New-Item -Path "C:\AppLocker\logs" -ItemType Directory -Force
```

### Basic Usage

```powershell
# Import the main module
Import-Module "C:\Program Files\GA-AppLocker\GA-AppLocker.psm1"

# Get dashboard summary
Get-DashboardSummary

# Scan local computer for executables
Scan-LocalComputer -TargetPath "C:\Program Files"

# Get all computers from AD
Get-AllComputers

# Generate rules from artifacts
$artifacts = Scan-LocalComputer
$rules = Generate-Rules -Artifacts $artifacts.data -RuleType Publisher

# Export policy to XML
Export-Policy -Rules $rules.data -OutputPath "C:\AppLocker\output\policy.xml" -EnforcementMode AuditOnly

# Create and link GPO
Create-GPO -GpoName "AppLocker-Workstation-Policy"
Link-GPO -GpoName "AppLocker-Workstation-Policy" -TargetOU "OU=Workstations,DC=corp,DC=com"
```

## Project Structure

```
GA-AppLocker_FINAL/
├── src/
│   ├── modules/
│   │   ├── Module1-Dashboard.psm1       # Event stats, health scores
│   │   ├── Module2-RemoteScan.psm1      # AD discovery, artifact scanning
│   │   ├── Module3-RuleGenerator.psm1   # Rule creation (Publisher/Path/Hash)
│   │   ├── Module4-PolicyLab.psm1       # GPO management
│   │   ├── Module5-EventMonitor.psm1    # Event viewing and backup
│   │   ├── Module6-ADManager.psm1       # User/group management
│   │   └── Module7-Compliance.psm1      # Evidence collection, reporting
│   ├── lib/
│   │   └── Common.psm1                  # Shared utilities
│   └── GA-AppLocker.psm1                # Main controller module
├── output/                              # Generated policies and scans
├── logs/                                # Application logs
├── P2S-Frontend-Spec.md                 # Frontend specification
└── README.md
```

## Module Reference

### Module 1: Dashboard

```powershell
# Get AppLocker event statistics
Get-AppLockerEventStats

# Get AD machine count
Get-ADMachineCount

# Get policy health score
Get-PolicyHealthScore

# Get complete dashboard summary
Get-DashboardSummary
```

### Module 2: Remote Scan

```powershell
# Get all computers from AD
Get-AllComputers -MaxResults 500

# Get computers by specific OU
Get-ComputersByOU -OUPath "OU=Workstations,DC=corp,DC=com"

# Test if computer is online
Test-ComputerOnline -ComputerName "PC001"

# Scan local path for executables
Get-ExecutableArtifacts -TargetPath "C:\Program Files" -MaxFiles 500

# Scan remote computer via WinRM
Get-RemoteArtifacts -ComputerName "PC001"

# Export scan results
Export-ScanResults -Artifacts $artifacts -OutputPath "C:\AppLocker\output\scan.csv"

# Import scan results
Import-ScanResults -CsvPath "C:\AppLocker\output\scan.csv"
```

### Module 3: Rule Generator

```powershell
# Get trusted publishers
Get-TrustedPublishers

# Generate publisher rule
New-PublisherRule -PublisherName "Microsoft Corporation" -Action Allow

# Generate path rule
New-PathRule -Path "C:\Program Files\*\*.exe" -Action Allow

# Generate hash rule
New-HashRule -FilePath "C:\Program Files\app.exe" -Action Allow

# Generate rules from artifacts
New-RulesFromArtifacts -Artifacts $artifacts -RuleType Publisher -Action Allow

# Export rules to XML
Export-RulesToXml -Rules $rules -OutputPath "C:\AppLocker\output\policy.xml" -EnforcementMode AuditOnly

# Import rules from XML
Import-RulesFromXml -XmlPath "C:\AppLocker\output\policy.xml"
```

### Module 4: Policy Lab

```powershell
# Create new GPO
New-AppLockerGPO -GpoName "AppLocker-Workstation-Policy"

# Link GPO to OU
Add-GPOLink -GpoName "AppLocker-Workstation-Policy" -TargetOU "OU=Workstations,DC=corp,DC=com"

# Get all OUs with computer counts
Get-OUsWithComputerCounts

# Set AppLocker policy in GPO
Set-GPOAppLockerPolicy -GpoName "AppLocker-Workstation-Policy" -PolicyXmlPath "C:\AppLocker\output\policy.xml"
```

### Module 5: Event Monitor

```powershell
# Get AppLocker events
Get-AppLockerEvents -MaxEvents 100 -FilterType All

# Filter events by date
Filter-EventsByDateRange -Events $events -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Backup events from remote computer
Backup-RemoteAppLockerEvents -ComputerName "PC001" -OutputPath "C:\AppLocker\output\events\PC001.xml"

# Backup events from all systems
Backup-AllAppLockerEvents -ComputerNames $computers -OutputFolder "C:\AppLocker\output\events"
```

### Module 6: AD Manager

```powershell
# Get all AD users
Get-AllADUsers -MaxResults 500

# Search for users
Search-ADUsers -SearchQuery "john"

# Create AppLocker security groups
New-AppLockerGroups -TargetOU "OU=Groups,DC=corp,DC=com"

# Add user to group
Add-UserToAppLockerGroup -SamAccountName "jdoe" -GroupName "AppLocker-PowerUsers"

# Remove user from group
Remove-UserFromAppLockerGroup -SamAccountName "jdoe" -GroupName "AppLocker-PowerUsers"

# Get group members
Get-AppLockerGroupMembers -GroupName "AppLocker-PowerUsers"

# Create WinRM GPO
New-WinRMGPO -GpoName "Enable-WinRM"
```

### Module 7: Compliance

```powershell
# Create evidence folder structure
New-EvidenceFolders -BasePath "C:\AppLocker\Evidence"

# Export current policy
Export-CurrentPolicy -OutputPath "C:\AppLocker\Evidence\Policies\CurrentPolicy.xml"

# Export system inventory
Export-SystemInventory -OutputPath "C:\AppLocker\Evidence\Inventory\Inventory.json"

# Get compliance summary
Get-ComplianceSummary

# Generate HTML compliance report
New-ComplianceReport -OutputPath "C:\AppLocker\Evidence\Reports\ComplianceReport.html"

# Export all evidence
Export-AllEvidence -BasePath "C:\AppLocker\Evidence"
```

## Building the P2S EXE

See [P2S-Frontend-Spec.md](P2S-Frontend-Spec.md) for complete frontend specification.

```powershell
# Install PS2EXE
Install-Module -Name ps2exe -Force

# Build the EXE
Invoke-PS2EXE -InputFile ".\src\GA-AppLocker.psm1" `
             -OutputFile ".\GA-AppLocker-Dashboard.exe" `
             -Title "GA-AppLocker Dashboard" `
             -RequireAdmin
```

## Security Considerations

1. **Run as Domain Administrator** - Most operations require elevated privileges
2. **Use Audit Mode First** - Always test in AuditOnly mode before enforcing
3. **Review Events** - Check blocked/audited events before enforcing
4. **Backup Policies** - Export existing policies before making changes
5. **Test GPOs** - Link GPOs to test OUs before production

## Troubleshooting

### WinRM Connection Issues

```powershell
# Enable WinRM on target computers
Invoke-Command -ComputerName PC001 -ScriptBlock { Enable-PSRemoting -Force }

# Or deploy via GPO
New-WinRMGPO
```

### Module Import Errors

```powershell
# Check module path
Get-Module -ListAvailable

# Import with full path
Import-Module "C:\Program Files\GA-AppLocker\GA-AppLocker.psm1" -Force
```

### Event Log Access Denied

```powershell
# Run as Administrator
# Add account to Event Log Readers local group
```

## Roadmap

- [ ] Web-based frontend (ASP.NET Core)
- [ ] Scheduled scanning and reporting
- [ ] Policy versioning and rollback
- [ ] Integration with Microsoft Sentinel
- [ ] Automated rule recommendations

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is provided as-is for educational and administrative purposes.

## Credits

Developed as part of the GA-ASI AppLocker Toolkit.

## Support

For issues and questions, please open a GitHub issue.
