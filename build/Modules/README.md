# GA-AppLocker Modules

Modular PowerShell modules for AppLocker policy management.

## Structure

```
Modules/
├── GA-AppLocker.psm1         # Main module (imports all sub-modules)
├── GA-AppLocker.Common.psm1  # Common utilities
├── GA-AppLocker.Scan.psm1    # Scanning functions
├── GA-AppLocker.Policy.psm1  # Policy generation/merge
├── GA-AppLocker.AD.psm1      # Active Directory integration
└── README.md                 # This file
```

## Quick Start

```powershell
# Import the module
Import-Module .\Modules\GA-AppLocker.psm1

# One-command scan and policy creation
Invoke-AppLockerScan

# Scan multiple computers
Invoke-AppLockerScan -ComputerName "PC1","PC2","PC3"

# Scan from AD and apply policy
Get-ADComputerList | Invoke-AppLockerScan -ApplyPolicy -MergePolicy
```

## Module Functions

### GA-AppLocker.Common
| Function | Description |
|----------|-------------|
| `Get-Timestamp` | Get formatted timestamp |
| `Get-ScanFolderPath` | Create scan output folder |
| `Find-AaronLockerRoot` | Find AaronLocker installation |
| `Write-Status` | Write colored status message |
| `Test-RemoteAccess` | Test if computer is accessible |
| `Export-ToCsv` | Export to CSV with standard settings |
| `Save-XmlPolicy` | Save XML with UTF-16 encoding |

### GA-AppLocker.Scan
| Function | Description |
|----------|-------------|
| `Get-InstalledSoftware` | Get installed software from registry |
| `Get-Executables` | Scan for executables in common paths |
| `Get-AppLockerEvents` | Get AppLocker events from event log |
| `Invoke-ComprehensiveScan` | Run full scan on computer |

### GA-AppLocker.Policy
| Function | Description |
|----------|-------------|
| `New-AppLockerPolicy` | Create AppLocker policy XML |
| `Merge-AppLockerPolicy` | Merge two policy files |
| `Save-AppLockerPolicy` | Save policy with correct encoding |
| `Import-AppLockerPolicy` | Apply policy to local GPO |

### GA-AppLocker.AD
| Function | Description |
|----------|-------------|
| `Test-ADModule` | Check if AD module is available |
| `Get-ADComputerList` | Get computer names from AD |
| `Get-ADComputerInfo` | Get detailed AD computer info |

### Main Module (GA-AppLocker.psm1)
| Function | Description |
|----------|-------------|
| `Invoke-AppLockerScan` | One-command scan and policy creation |

## Examples

### Basic Scan
```powershell
Import-Module .\Modules\GA-AppLocker.psm1
Invoke-AppLockerScan
```

### Scan with Events
```powershell
Invoke-AppLockerScan -IncludeEvents
```

### Scan Remote Computers
```powershell
Invoke-AppLockerScan -ComputerName "SERVER01","SERVER02"
```

### Scan AD Computers and Apply Policy
```powershell
$computers = Get-ADComputerList -OperatingSystem "*Windows 10*"
Invoke-AppLockerScan -ComputerName $computers -ApplyPolicy -MergePolicy
```

### Create Enforce Policy
```powershell
Invoke-AppLockerScan -PolicyMode Enforce
```

### Merge Multiple Scans
```powershell
# First scan
$result1 = Invoke-ComprehensiveScan -ComputerName "PC1"

# Create policy from first scan
$policy = New-AppLockerPolicy -Publishers $result1.Publishers
Save-AppLockerPolicy -PolicyXml $policy -Path "C:\policy.xml"

# Second scan
$result2 = Invoke-ComprehensiveScan -ComputerName "PC2"
$policy2 = New-AppLockerPolicy -Publishers $result2.Publishers
Save-AppLockerPolicy -PolicyXml $policy2 -Path "C:\policy2.xml"

# Merge
Merge-AppLockerPolicy -BasePolicyPath "C:\policy.xml" -NewPolicyPath "C:\policy2.xml"
```

## Output

Scan results are saved to: `C:\GA-AppLocker\Scans\HOSTNAME_TIMESTAMP\`

Files created:
- `InstalledSoftware.csv` - Installed programs
- `Executables.csv` - Found executables
- `Publishers.csv` - Unique publishers
- `AppLockerEvents.csv` - AppLocker events (if -IncludeEvents)

Policy saved to: `C:\GA-AppLocker\Scans\AppLocker-Policy-MODE-TIMESTAMP.xml`

## Importing Policy

```powershell
# Merge with existing rules
Set-AppLockerPolicy -XmlPolicy "C:\GA-AppLocker\Scans\AppLocker-Policy-Audit-*.xml" -Merge

# Replace existing rules
Set-AppLockerPolicy -XmlPolicy "C:\GA-AppLocker\Scans\AppLocker-Policy-Audit-*.xml"
```

Or use Group Policy Editor:
1. Open `gpedit.msc`
2. Navigate to: Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker
3. Right-click AppLocker > Import Policy
4. Select the XML file
