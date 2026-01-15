# GA-AppLocker Dashboard - P2S Frontend Specification

## Overview

This specification describes the visual frontend design for the GA-AppLocker Dashboard using **P2S (PowerShell to Studio/EXE)**. The frontend provides a graphical interface to all PowerShell backend modules.

## P2S Project Setup

```
Project Name: GA-AppLocker-Dashboard
Output Type: Windows Forms Application
PowerShell Version: 5.1 or higher
```

---

## Main Window Layout

### Window Properties
```
Name: frmMain
Text: GA-AppLocker Dashboard
Width: 1200
Height: 800
StartPosition: CenterScreen
Font: Segoe UI, 10pt
BackColor: #F5F5F5
```

### Layout Structure
```
┌────────────────────────────────────────────────────────────────┐
│  [Logo]  GA-AppLocker Dashboard           [User: DOMAIN\admin] │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  NAVIGATION PANEL (Left Sidebar)                      │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │  [Dashboard]   [Remote Scan]   [Rule Gen]      │   │   │
│  │  │  [Policy Lab]   [Events]       [AD Manager]    │   │   │
│  │  │  [Compliance]                                 │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │                                                         │   │
│  │              CONTENT PANEL (Dynamic)                    │   │
│  │             Changes based on navigation                 │   │
│  │                                                         │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  STATUS BAR                                             │   │
│  │  Ready | Connected: CORP-DC01 | Last Update: 2:30 PM   │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

---

## Page 1: Dashboard

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  DASHBOARD                                                     │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐     │
│  │               │  │               │  │               │     │
│  │  MACHINES     │  │  EVENTS       │  │  HEALTH       │     │
│  │               │  │               │  │               │     │
│  │     523       │  │   Allowed:    │  │   Score:      │     │
│  │   Total       │  │     12,453    │  │     75        │     │
│  │               │  │               │  │               │     │
│  └───────────────┘  └───────────────┘  └───────────────┘     │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Policy Health Progress Bar                           │   │
│  │  ████████████░░░░░░░░░░░  75%                         │   │
│  │                                                       │   │
│  │  Categories:                                          │   │
│  │  [✓] EXE    [✓] MSI    [✓] Script    [ ] DLL        │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Recent Events (Last 24 Hours)                        │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │  Time        |  Action    |  File               │ │   │
│  │  ├──────────────────────────────────────────────────┤ │   │
│  │  │  14:32:15   │  Allowed   │  chrome.exe         │ │   │
│  │  │  14:30:22   │  Audit     │  unknown.exe        │ │   │
│  │  │  14:28:05   │  Allowed   │  outlook.exe        │ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│            [Refresh Data]  [View Full Events]                 │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Load Dashboard Data
$script = {
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Get-DashboardSummary | ConvertTo-Json
}
```

---

## Page 2: Remote Scan

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  REMOTE SCAN                                                   │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Discovery                                             │   │
│  │                                                        │   │
│  │  Target: [All Computers ▼]                            │   │
│  │  OU Filter: [OU=Workstations,DC=corp,DC=com...] [Browse]│   │
│  │                                                        │   │
│  │  [Discover Computers]  [Test Connection]              │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Discovered Computers (523)                           │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │ [x] │ Hostname    │ OS           │ Status  │     │ │   │
│  │  ├──────────────────────────────────────────────────┤ │   │
│  │  │ [x] │ PC001       │ Windows 11   │ Online  │     │ │   │
│  │  │ [ ] │ PC002       │ Windows 10   │ Offline │     │ │   │
│  │  │ [x] │ SRV001      │ Server 2019  │ Online  │     │ │   │
│  │  │ [x] │ DC01        │ Server 2022  │ Online  │     │ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  │                                                        │   │
│  │  [Select All Online]  [Clear Selection]              │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Scan Options                                         │   │
│  │                                                        │   │
│  │  Paths to Scan:                                      │   │
│  │  [x] C:\Program Files                                │   │
│  │  [x] C:\Program Files (x86)                          │   │
│  │  [ ] C:\Custom Path...                               │   │
│  │                                                        │   │
│  │  Max Files per Computer: [500 ▼]                     │   │
│  │                                                        │   │
│  │          [Start Scan]  [Export Results]               │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  Progress: [████████████░░░░░░░░] 60% (3/5 computers)        │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Discover Computers
$scriptDiscover = {
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Get-AllComputers | ConvertTo-Json
}

# Start Scan
$scriptScan = {
    param($computerNames)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    $results = @()
    foreach ($computer in $computerNames) {
        $results += Get-RemoteArtifacts -ComputerName $computer
    }
    $results | ConvertTo-Json
}
```

---

## Page 3: Rule Generator

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  RULE GENERATOR                                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Load Artifacts                                       │   │
│  │                                                        │   │
│  │  Source: [Previous Scan ▼]                            │   │
│  │  File: [C:\AppLocker\scans\scan-results.csv] [Browse]│   │
│  │                                                        │   │
│  │  [Load Artifacts]  [View Details]                     │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Artifacts Found: 1,247 files                         │   │
│  │                                                        │   │
│  │  Rule Type: [Publisher ▼]                             │   │
│  │  Action: [Allow ▼]                                    │   │
│  │                                                        │   │
│  │  Options:                                             │   │
│  │  [x] Deduplicate by publisher                         │   │
│  │  [ ] Include unsigned files                           │   │
│  │  [x] Auto-generate description                        │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Publishers to Create Rules For                       │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │ [x] │ Publisher              │ File Count │     │ │   │
│  │  ├──────────────────────────────────────────────────┤ │   │
│  │  │ [x] │ Microsoft Corporation   │ 245        │     │ │   │
│  │  │ [x] │ Google LLC              │ 12         │     │ │   │
│  │  │ [x] │ VMware, Inc.            │ 8          │     │ │   │
│  │  │ [ ] │ Unknown Publisher        │ 156        │     │ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│              [Generate Rules]  [Preview XML]                   │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Load Artifacts
$scriptLoadArtifacts = {
    param($csvPath)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Import-Module "C:\AppLocker\src\modules\Module2-RemoteScan.psm1"
    Import-ScanResults -CsvPath $csvPath | ConvertTo-Json
}

# Generate Rules
$scriptGenerateRules = {
    param($artifacts, $ruleType, $action)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Generate-Rules -Artifacts $artifacts -RuleType $ruleType -Action $action | ConvertTo-Json
}
```

---

## Page 4: Policy Lab

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  POLICY LAB                                                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Rules Management                                     │   │
│  │                                                        │   │
│  │  Policy Name: [AppLocker-Workstation-Policy]          │   │
│  │                                                        │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │ Rules: 45 total                                  │ │   │
│  │  │                                                  │ │   │
│  │  │ Publisher: 35  |  Path: 8  |  Hash: 2          │ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  │                                                        │   │
│  │  Enforcement Mode: [Audit Only ▼]                    │   │
│  │                                                        │   │
│  │  [Import Rules] [Export Rules] [Validate Policy]     │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  GPO Deployment                                        │   │
│  │                                                        │   │
│  │  GPO Name: [AppLocker-Workstation-Policy]             │   │
│  │                                                        │   │
│  │  Target OU: [OU=Workstations,DC=corp,DC=com ▼]       │   │
│  │                                                        │   │
│  │  [Create GPO]  [Link to OU]  [Unlink]  [Delete]       │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Deployment Status                                     │   │
│  │                                                        │   │
│  │  GPO: [✓] Created                                     │   │
│  │  Link: [✓] Linked to Workstations OU                 │   │
│  │  Policy: [✓] Applied                                  │   │
│  │                                                        │   │
│  │  Affected Computers: 347                              │   │
│  │                                                        │   │
│  │  [Force GPUpdate]  [Check Deployment Status]          │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Create GPO
$scriptCreateGPO = {
    param($gpoName)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Create-GPO -GpoName $gpoName | ConvertTo-Json
}

# Link GPO
$scriptLinkGPO = {
    param($gpoName, $targetOU)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Link-GPO -GpoName $gpoName -TargetOU $targetOU | ConvertTo-Json
}

# Get OUs
$scriptGetOUs = {
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Get-AllOUs | ConvertTo-Json
}
```

---

## Page 5: Event Monitor

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  EVENT MONITOR                                                 │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Filters                                               │   │
│  │                                                        │   │
│  │  Event Type: [All ▼]                                  │   │
│  │  Date Range: [Last 24 Hours ▼]                        │   │
│  │  Computer: [All Computers ▼]                          │   │
│  │                                                        │   │
│  │  [Apply Filters]  [Clear Filters]                     │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Event Statistics                                     │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐           │   │
│  │  │  Allowed  │ │   Audit   │ │  Blocked  │           │   │
│  │  │   12,453  │ │     23    │ │      0    │           │   │
│  │  └───────────┘ └───────────┘ └───────────┘           │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Recent Events                                        │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │ Time │ Action │ File │ User │ Computer │ Details│ │   │
│  │  ├──────────────────────────────────────────────────┤ │   │
│  │  │14:32 │ Allowed│ chrome│ jdoe│ PC001   │ [View] │ │   │
│  │  │14:30 │ Audit  │ bad.exe│ jsmith│ PC002 │ [View] │ │   │
│  │  │14:28 │ Allowed│ outlook│ asmith│ PC003 │ [View] │ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  │                                                        │   │
│  │              [Export Events]  [Backup All]            │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Get Events
$scriptGetEvents = {
    param($maxEvents, $filterType)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Get-Events -MaxEvents $maxEvents -FilterType $filterType | ConvertTo-Json
}
```

---

## Page 6: AD Manager

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  AD MANAGER                                                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Security Groups                                      │   │
│  │                                                        │   │
│  │  [Create AppLocker Groups]  [Add User]  [Remove User]│   │
│  │                                                        │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │ Group                    │ Members │ Actions    │ │   │
│  │  ├──────────────────────────────────────────────────┤ │   │
│  │  │ AppLocker-Admins         │ 12      │ [View] [..]│ │   │
│  │  │ AppLocker-PowerUsers     │ 45      │ [View] [..]│ │   │
│  │  │ AppLocker-StandardUsers  │ 234     │ [View] [..]│ │   │
│  │  │ AppLocker-RestrictedUsers│ 8       │ [View] [..]│ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Add User to Group                                    │   │
│  │                                                        │   │
│  │  User: [jdoe ▼ or search...]                          │   │
│  │  Group: [AppLocker-PowerUsers ▼]                      │   │
│  │                                                        │   │
│  │                   [Add to Group]                       │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  WinRM Configuration                                  │   │
│  │                                                        │   │
│  │  Status: [✓] WinRM GPO deployed                      │   │
│  │                                                        │   │
│  │  [Create WinRM GPO]  [Remove WinRM GPO]               │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Get Users
$scriptGetUsers = {
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Get-Users | ConvertTo-Json
}

# Create Groups
$scriptCreateGroups = {
    param($targetOU)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Create-AppLockerGroups -TargetOU $targetOU | ConvertTo-Json
}

# Add User to Group
$scriptAddUser = {
    param($samAccountName, $groupName)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Add-UserToGroup -SamAccountName $samAccountName -GroupName $groupName | ConvertTo-Json
}
```

---

## Page 7: Compliance

### Controls
```
┌────────────────────────────────────────────────────────────────┐
│  COMPLIANCE                                                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Compliance Score                                     │   │
│  │                                                        │   │
│  │      ┌─────────┐                                      │   │
│  │      │         │                                      │   │
│  │      │    75   │                                      │   │
│  │      │         │                                      │   │
│  │      └─────────┘                                      │   │
│  │                                                        │   │
│  │  Assessment: Good - Some categories need rules        │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Rule Coverage                                        │   │
│  │  ┌──────────────────────────────────────────────────┐ │   │
│  │  │ EXE     [████████████████████░░] 100%            │ │   │
│  │  │ MSI     [███████████████████░░░]  75%            │ │   │
│  │  │ Script  [███████████████████░░░]  75%            │ │   │
│  │  │ DLL     [████████░░░░░░░░░░░░░░]  25%            │ │   │
│  │  └──────────────────────────────────────────────────┘ │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Evidence Collection                                   │   │
│  │                                                        │   │
│  │  [Collect Evidence]  [Generate Report]  [View Reports]│   │
│  │                                                        │   │
│  │  Last Collection: 2024-01-15 14:30:00                │   │
│  │                                                        │   │
│  │  Evidence Folder: C:\AppLocker\Evidence               │   │
│  │              [Open Folder]                            │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Enforcement Readiness                                 │   │
│  │                                                        │   │
│  │  [✓] Policy configured                               │   │
│  │  [✓] Rules created                                  │   │
│  │  [✓] Low audit events (23)                          │   │
│  │  [✓] No blocked events                              │   │
│  │                                                        │   │
│  │  Status: READY TO ENFORCE                             │   │
│  │            [Switch to Enforced Mode]                  │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### PowerShell Bindings
```powershell
# Get Compliance
$scriptGetCompliance = {
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    Get-Compliance | ConvertTo-Json
}

# Generate Report
$scriptGenerateReport = {
    param($outputPath)
    Import-Module "C:\AppLocker\src\GA-AppLocker.psm1"
    New-Report -OutputPath $outputPath | ConvertTo-Json
}
```

---

## Common Controls

### Button Styles
```
Primary Button:
  - BackColor: #0078D4 (Windows Blue)
  - ForeColor: White
  - FlatStyle: Flat
  - Font: Segoe UI, 9pt, Bold

Secondary Button:
  - BackColor: #F0F0F0
  - ForeColor: #333333
  - FlatStyle: Flat

Danger Button:
  - BackColor: #D13438
  - ForeColor: White
  - FlatStyle: Flat
```

### DataGrid Styles
```
Grid:
  - BackColor: White
  - AlternatingRowsBackColor: #F5F5F5
  - GridColor: #E0E0E0
  - HeaderBackColor: #0078D4
  - HeaderForeColor: White
  - SelectionBackColor: #0078D4
  - SelectionForeColor: White
```

### Progress Bar
```
ProgressBar:
  - ForeColor: #107C10 (Green for success)
  - Style: Continuous
```

---

## P2S Configuration File

Save as `GA-AppLocker.p2sconfig`:

```json
{
  "ProjectName": "GA-AppLocker-Dashboard",
  "OutputType": "WinForms",
  "PowerShellVersion": "5.1",
  "ModulesPath": "src\\modules",
  "MainModule": "src\\GA-AppLocker.psm1",
  "IconPath": "assets\\icon.ico",
  "Manifest": {
    "CompanyName": "GA-ASI",
    "ProductName": "GA-AppLocker Dashboard",
    "FileDescription": "AppLocker Policy Management Dashboard",
    "Version": "1.0.0.0"
  },
  "Pages": [
    {
      "Name": "Dashboard",
      "Script": "Get-DashboardSummary",
      "RefreshInterval": 30
    },
    {
      "Name": "RemoteScan",
      "Script": "Get-AllComputers",
      "Async": true
    },
    {
      "Name": "RuleGenerator",
      "Script": "Generate-Rules",
      "RequiresInput": true
    },
    {
      "Name": "PolicyLab",
      "Script": "Get-AllOUs",
      "Async": true
    },
    {
      "Name": "EventMonitor",
      "Script": "Get-Events",
      "RefreshInterval": 60
    },
    {
      "Name": "ADManager",
      "Script": "Get-Users",
      "Async": true
    },
    {
      "Name": "Compliance",
      "Script": "Get-Compliance",
      "RefreshInterval": 300
    }
  ]
}
```

---

## Building with P2S

### Method 1: PowerShell to EXE (PS2EXE)
```powershell
# Install PS2EXE
Install-Module -Name ps2exe

# Build EXE
Invoke-PS2EXE -InputFile ".\src\GA-AppLocker.psm1" `
             -OutputFile ".\output\GA-AppLocker-Dashboard.exe" `
             -IconFile ".\assets\icon.ico" `
             -Title "GA-AppLocker Dashboard" `
             -RequireAdmin
```

### Method 2: P2S (PowerShell Studio)
1. Open PowerShell Studio
2. Create new WinForms project
3. Import the specification file
4. Add PowerShell module references
5. Build EXE

### Method 3: Convert-WindowsImage (P2EXE)
```powershell
# Using P2EXE converter
.\p2exe.exe --input ".\src\GA-AppLocker.psm1" `
            --output ".\output\GA-AppLocker-Dashboard.exe" `
            --config ".\GA-AppLocker.p2sconfig"
```

---

## Notes

1. All PowerShell scripts return JSON for easy parsing in the frontend
2. Use `Invoke-Command` with `-AsJob` for long-running operations
3. Implement progress reporting using `Write-Progress`
4. Store configuration in `C:\ProgramData\GA-AppLocker\config.json`
5. Logs go to `C:\ProgramData\GA-AppLocker\logs\`
