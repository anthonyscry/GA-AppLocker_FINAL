# GA-AppLocker Dashboard - Claude Code Reference

This document provides comprehensive technical documentation for Claude Code to assist with development and maintenance of the GA-AppLocker Dashboard project.

## Project Overview

**GA-AppLocker Dashboard** is a PowerShell WPF application for enterprise AppLocker policy management, aligned with Microsoft AaronLocker best practices.

### Key Technologies
- PowerShell 5.1+
- WPF (Windows Presentation Foundation) for GUI
- Active Directory PowerShell Module
- Group Policy Management PowerShell Module
- Windows Event Log API

### Directory Structure

```
GA-AppLocker_FINAL/
├── build/                          # Main application executables
│   ├── GA-AppLocker-GUI-WPF.ps1    # Primary WPF GUI (recommended)
│   ├── GA-AppLocker-GUI-Full.ps1   # Windows Forms alternative
│   ├── GA-AppLocker-GUI-Standalone.ps1
│   └── GA-AppLocker-GUI.ps1
├── src/
│   ├── modules/                    # Core PowerShell modules
│   │   ├── Module1-Dashboard.psm1
│   │   ├── Module2-RemoteScan.psm1
│   │   ├── Module3-RuleGenerator.psm1
│   │   ├── Module4-PolicyLab.psm1
│   │   ├── Module5-EventMonitor.psm1
│   │   ├── Module6-ADManager.psm1
│   │   └── Module7-Compliance.psm1
│   ├── lib/
│   │   └── Common.psm1             # Shared utility functions
│   ├── GA-AppLocker.psm1           # Main module wrapper
│   └── Config.psm1                 # Configuration settings
├── ExampleGUI/                     # Reference implementations
├── AaronLocker-main/               # Microsoft AaronLocker reference
└── GA-AppLocker-1.2.4/             # Legacy version (do not modify)
```

## Module Architecture

### Module 1: Dashboard (`Module1-Dashboard.psm1`)

**Purpose:** Provides dashboard statistics and overview metrics.

**Key Functions:**
- `Get-AppLockerEventStats` - Retrieves event counts by type (Allowed/Audit/Blocked)
- `Get-ADMachineCount` - Counts AD computers by type (workstation/server/DC)
- `Get-PolicyHealthScore` - Calculates policy coverage score (0-100)
- `Get-DashboardSummary` - Aggregates all dashboard metrics

**Known Issues:**
- ActiveDirectory module imported per-function (performance impact)
- DC detection uses DN pattern matching (fragile)
- Policy health score doesn't differentiate AUDIT vs ENFORCE modes

---

### Module 2: Remote Scan (`Module2-RemoteScan.psm1`)

**Purpose:** Discovers AD computers and scans for software artifacts and AppLocker event logs.

**Key Functions:**
- `Get-DirectorySafetyClassification` - Classifies paths as Safe/Unsafe/Unknown
- `Get-DirectoryFilesSafe` - Scans directories with junction handling
- `Get-AllADComputers` - Retrieves all computers from AD
- `Get-ComputersByOU` - Retrieves computers from specific OU
- `Test-ComputerOnline` - Ping test with configurable timeout
- `Get-ExecutableArtifacts` - Comprehensive local EXE scanning
- `Get-RemoteArtifacts` - Remote scanning via WinRM
- `Get-RemoteAppLockerEvents` - **NEW** Comprehensive remote AppLocker event log collection
- `Get-RemoteAppLockerEventsMultiple` - **NEW** Multi-computer event log scanning
- `ConvertTo-RuleGeneratorArtifacts` - **NEW** Convert events to rule generator format

**Remote Event Log Scanning (Audit-Compliant):**

The new event log scanning functions provide comprehensive remote AppLocker data collection:

```powershell
# Single computer scan
$result = Get-RemoteAppLockerEvents -ComputerName "WORKSTATION01" -DaysBack 7

# Access collected data
$result.PolicyMode        # Enforcement modes (Exe, Dll, Msi, Script, Appx)
$result.RuleCounts        # Rule counts per collection
$result.Events            # Raw event data with parsed details
$result.artifacts         # Pre-formatted for rule generator

# Multi-computer scan
$computers = @("WS01", "WS02", "SERVER01")
$multi = Get-RemoteAppLockerEventsMultiple -ComputerNames $computers -DaysBack 14
$multi.uniqueArtifacts    # Deduplicated artifacts across all computers
$multi.publisherSummary   # Publisher breakdown across environment

# Generate rules from audit/block events
$artifacts = ConvertTo-RuleGeneratorArtifacts -Events $result.events -IncludeEventTypes @('Audit', 'Blocked')
$rules = New-RulesFromArtifacts -Artifacts $artifacts -RuleType Publisher -Action Allow
```

**What Gets Collected:**
- System info (OS, Build, Architecture)
- AppIDSvc status (required for enforcement)
- Effective policy modes and rule counts
- Full policy XML (optional, via -IncludePolicyXml)
- Events from all 4 AppLocker log channels (last N days)
- Parsed event data (FilePath, Publisher, Hash, UserSid)
- Pre-formatted artifacts for rule generation

**Audit Compliance:**
- Uses WinRM only (Invoke-Command)
- No local execution on targets
- No registry scraping
- Pulls effective state via Get-AppLockerPolicy -Effective
- Works under least privilege (Remote Management Users)

**Known Issues:**
- Remote artifact scanning collects fewer data points than local scanning
- `Get-AllADComputers` has silent pagination limit (500)
- No PE verification in remote scanning

---

### Module 3: Rule Generator (`Module3-RuleGenerator.psm1`)

**Purpose:** Creates AppLocker rules from scanned artifacts.

**Key Functions:**
- `Get-DenyList` / `Test-DeniedPublisher` / `Test-DeniedPath` - Deny list management
- `Protect-XmlAttributeValue` - XML injection prevention
- `New-PublisherRule` / `New-PathRule` / `New-HashRule` - Rule creation
- `New-RulesFromArtifacts` - Bulk rule generation with deduplication
- `Compare-SoftwareBaseline` - Gap analysis
- `Export-RulesToXml` / `Import-RulesFromXml` - Policy XML operations

**Known Issues:**
- Publisher matching may have false positives with substring matching
- File system operations in generator module (should be separate)

---

### Module 4: Policy Lab (`Module4-PolicyLab.psm1`)

**Purpose:** Manages AppLocker GPO creation and deployment.

**Key Functions:**
- `New-AppLockerGPO` - Creates/retrieves AppLocker GPO
- `Add-GPOLink` - Links GPO to OU
- `Get-OUsWithComputerCounts` - Enumerates OUs with computer counts
- `Set-GPOAppLockerPolicy` - Applies XML policy to GPO
- `Set-LatestAppLockerPolicy` - Finds and applies most recent policy
- `Save-PolicyToFile` - Saves policy with UTF-16 encoding

**CRITICAL BUG:**
- Line 259: Namespace typo `System.Directoryservices` should be `System.DirectoryServices`

---

### Module 5: Event Monitor (`Module5-EventMonitor.psm1`)

**Purpose:** Monitors and backs up AppLocker events.

**Key Functions:**
- `Get-AppLockerEvents` - Main event retrieval with filtering
- `Filter-EventsByEventId` - Filter by event ID
- `Filter-EventsByDateRange` - Filter by date range
- `Backup-RemoteAppLockerEvents` - Backup from remote computer
- `Backup-AllAppLockerEvents` - Batch backup from multiple computers

**Known Issues:**
- `Filter-EventsByDateRange` requires EndDate but doesn't enforce it
- Remote backup captures less data than local retrieval

---

### Module 6: AD Manager (`Module6-ADManager.psm1`)

**Purpose:** Active Directory user/group management and WinRM configuration.

**Key Functions:**
- `Protect-LDAPFilterValue` - LDAP injection protection
- `Get-AllADUsers` / `Search-ADUsers` - User queries
- `New-AppLockerGroups` - Creates standard AppLocker groups
- `Add-UserToAppLockerGroup` / `Remove-UserFromAppLockerGroup` - Group membership
- `Get-AppLockerGroupMembers` - Retrieves group members
- `New-WinRMGPO` - Creates WinRM configuration GPO

**Known Issues:**
- `New-WinRMGPO` returns `success = $true` even when linking fails
- `Get-AppLockerGroupMembers` missing input validation

---

### Module 7: Compliance (`Module7-Compliance.psm1`)

**Purpose:** Compliance evidence collection and reporting.

**Key Functions:**
- `ConvertTo-HtmlEncoded` - XSS prevention for HTML output
- `New-EvidenceFolder` - Creates evidence directory structure
- `Export-CurrentPolicy` - Exports AppLocker policy XML
- `Export-SystemInventory` - Collects installed software and processes
- `Get-ComplianceSummary` - Generates compliance metrics
- `New-ComplianceReport` - Creates HTML compliance report
- `Export-AllEvidence` - Orchestrates all evidence collection

**CRITICAL BUG:**
- Line 219: Imports wrong module (Module5 instead of Module1)

---

### Common Library (`Common.psm1`)

**Purpose:** Shared utility functions used across all modules.

**Key Functions:**
- `Write-Log` - Logging with rotation
- `ConvertTo-JsonResponse` - JSON conversion for API responses
- `Save-XmlDocAsUnicode` - UTF-16 XML saving (required for AppLocker)
- `Get-AppLockerFileInfo` - File information for rule creation
- `ConvertFrom-SidCached` - SID to username with caching
- `ConvertTo-AppLockerGenericPath` - Path variable conversion
- `IsWin32Executable` - PE header detection
- `Test-AppLockerPath` / `Test-PublisherName` - Input validation

**Artifact Data Model Functions (v1.2.5):**
- `New-AppLockerArtifact` - Creates standardized artifact hashtable with properties: name, path, publisher, hash, version, size, modifiedDate, fileType
- `Convert-AppLockerArtifact` - Converts artifacts between different property naming conventions (Module2 lowercase, GUI PascalCase, CSV import)
- `Test-AppLockerArtifact` - Validates artifact has required properties for specific rule types (Publisher, Path, Hash)

**Key Constants:**
- `$UnsafeDir`, `$SafeDir`, `$UnknownDir` - Directory classification
- `$GetAlfiDefaultExts` - Default file extensions for scanning
- `$NeverExecutableExts` - Extensions to skip during scanning

---

## GUI Files

### Primary GUI: `build/GA-AppLocker-GUI-WPF.ps1`

Modern WPF-based dashboard with GitHub-style dark theme.

**Navigation Panels:**
- Dashboard - Policy health and event statistics
- Artifacts - Local/remote scanning
- Rule Generator - Create rules from artifacts or events
- Deployment - GPO creation and management
- Events - Event monitoring and remote collection
- AD Discovery - Computer discovery and connectivity testing
- WinRM Setup - Configure remote management
- Group Management - AD group membership
- AppLocker Setup - Initial AD structure creation
- Compliance - Evidence collection
- Policy Guide - Best practices reference
- About - Application information
- Help - Context-sensitive help documentation

**Key Script Variables:**
- `$script:CollectedArtifacts` - Scanned artifact data
- `$script:DiscoveredComputers` - AD computer list
- `$script:GeneratedRules` - Generated rule objects
- `$script:BaselineSoftware` / `$script:TargetSoftware` - Gap analysis data

**Quality-of-Life Features (v1.2.5):**
- **Search/Filter** - Filter artifacts and rules by publisher, path, filename (Rule Generator panel)
- **Audit Toggle** - One-click switch between Audit and Enforce modes (Deployment panel)
- **Rule Preview** - Preview XML rules before generation (Rule Generator panel)
- **Mini Status Bar** - Real-time domain, artifact count, and sync status (top bar)
- **Bulk Confirmation** - Confirmation dialogs before destructive operations (clear rules, delete GPOs)
- **Quick Date Presets** - Last Hour, Today, Last 7 Days, Last 30 Days event filtering (Events panel)

**Rule Validation (v1.2.5):**
- `Test-AppLockerRules` - Pre-export validation ensures all required properties exist
- Validates Publisher rules have: type, action, publisher, userSid
- Validates Path rules have: type, action, path, userSid
- Validates Hash rules have: type, action, hash, userSid
- Returns success, validRules, errors, warnings

---

## Common Patterns

### Return Value Structure

All module functions return hashtables with standardized structure:

```powershell
@{
    success = $true|$false      # Operation status
    data = @(...)               # Result data (if success)
    count = 0                   # Item count (optional)
    error = "message"           # Error message (if !success)
    message = "info"            # Informational message (optional)
}
```

### Error Handling Pattern

```powershell
try {
    Import-Module ModuleName -ErrorAction Stop
    # ... operations
    return @{ success = $true; data = $result }
}
catch {
    return @{ success = $false; error = $_.Exception.Message }
}
```

### LDAP Injection Protection

Always use `Protect-LDAPFilterValue` for user input in AD queries:

```powershell
$escapedQuery = Protect-LDAPFilterValue -Value $UserInput
$users = Get-ADUser -LDAPFilter "(name=*$escapedQuery*)"
```

### XML Security

Always use `Protect-XmlAttributeValue` for user data in XML:

```powershell
$safeName = Protect-XmlAttributeValue -Value $UnsafeInput
$xml = "<Rule Name=`"$safeName`" />"
```

---

## AppLocker Event IDs

| Event ID | Type | Description |
|----------|------|-------------|
| 8002 | EXE/DLL | Execution Allowed |
| 8003 | EXE/DLL | Execution Audit (would be blocked) |
| 8004 | EXE/DLL | Execution Blocked |
| 8005 | MSI/Script | Allowed |
| 8006 | MSI/Script | Audit |
| 8007 | MSI/Script | Blocked |
| 8020 | Packaged App | Allowed |
| 8021 | Packaged App | Audit |
| 8022 | Packaged App | Blocked |

---

## AppLocker Security Groups

Standard groups created by `New-AppLockerGroups`:

| Group Name | Purpose |
|------------|---------|
| AppLocker-Admins | Full policy control |
| AppLocker-PowerUsers | Advanced execution permissions |
| AppLocker-StandardUsers | Normal business applications |
| AppLocker-RestrictedUsers | Limited essential tools |
| AppLocker-Installers | Software deployment |
| AppLocker-Developers | Development environment |

---

## Testing

### Local Testing
```powershell
# Run WPF GUI
.\build\GA-AppLocker-GUI-WPF.ps1

# Test individual module
Import-Module .\src\modules\Module1-Dashboard.psm1
Get-DashboardSummary
```

### Domain Requirements
- Active Directory module: `Import-Module ActiveDirectory`
- Group Policy module: `Import-Module GroupPolicy`
- Run as Administrator for GPO operations

---

## Known Technical Debt

### Critical Issues to Fix
1. `Module4-PolicyLab.psm1:259` - Namespace typo
2. `Module7-Compliance.psm1:219` - Wrong module import
3. `Module6-ADManager.psm1:528` - Return value logic error

### Performance Issues
1. ActiveDirectory module imported per-function call
2. No caching for expensive AD queries
3. Sequential execution where parallel is possible

### Security Improvements Needed
1. Complete HTML encoding in compliance reports
2. Parameter validation in several functions
3. OU validation before GPO linking

---

## Development Guidelines

### Adding New Features
1. Add function to appropriate module
2. Follow return value structure pattern
3. Include parameter validation
4. Add LDAP/XML escaping for user input
5. Update Export-ModuleMember
6. Add inline comments explaining logic

### Code Style
- Use `[CmdletBinding()]` for advanced functions
- Return hashtables with `success` key
- Use `-ErrorAction Stop` in try blocks
- Log operations with `Write-Log` from Common.psm1

### GUI Development
- Use XAML for WPF layout
- Follow existing panel/navigation pattern
- Update both XAML and event handlers
- Test in both domain and workgroup modes

---

## Session Context Management

### Purpose
This section documents how Claude Code maintains continuity across sessions. All sessions should log their activities to enable context recovery and continuous development.

### Context File Location
```
GA-AppLocker_FINAL/
└── .context/
    ├── sessions/           # Individual session logs
    │   └── YYYY-MM-DD_session-id.md
    ├── CURRENT_CONTEXT.md  # Active development context
    └── CHANGELOG.md        # Summary of all changes
```

### Session Logging Requirements

**At Session Start:**
1. Read `.context/CURRENT_CONTEXT.md` for active context
2. Check recent session logs for continuity
3. Verify git branch and status

**During Session:**
1. Log significant operations (commits, major changes)
2. Track any issues encountered
3. Note decisions made and rationale

**At Session End:**
1. Update `.context/CURRENT_CONTEXT.md` with:
   - Current branch and last commit
   - Work in progress items
   - Known issues encountered
   - Next steps recommended
2. Create session log in `.context/sessions/`

### CURRENT_CONTEXT.md Format

```markdown
# GA-AppLocker Current Development Context

## Last Updated
[Date and session ID]

## Active Branch
[Branch name]

## Recent Commits
[Last 3-5 commits with descriptions]

## Work In Progress
- [ ] Task 1 description
- [ ] Task 2 description

## Known Issues
- Issue 1: Description and status
- Issue 2: Description and status

## Next Steps
1. Priority 1 task
2. Priority 2 task

## Session Notes
[Important decisions, blockers, or context for next session]
```

### Session Log Format

```markdown
# Session Log: [Date] - [Session ID]

## Session Summary
Brief description of what was accomplished

## Changes Made
- File: description of change
- File: description of change

## Commits
- [hash] Commit message

## Issues Encountered
- Issue description and resolution

## Decisions Made
- Decision and rationale

## Handoff Notes
Notes for next session
```

### Context Recovery

If starting a new session without context:
1. Run `git log --oneline -10` to see recent commits
2. Check `.context/CURRENT_CONTEXT.md` for state
3. Read most recent session log for continuity
4. Ask user for clarification if needed

---

## Test Coverage Requirements

### Current Test State
- **Framework:** Pester 5.0
- **Location:** `/tests/`
- **Coverage:** ~8% (artifact data model only)
- **Critical Gap:** 67+ core functions untested

### Priority Test Areas

**Priority 1 (Critical):**
- Module3-RuleGenerator: Rule creation (Publisher, Path, Hash)
- Module2-RemoteScan: Local/remote artifact scanning
- Common.psm1: Helper functions

**Priority 2 (High):**
- Integration tests: Scan → Rule generation → Export
- Module4-PolicyLab: GPO operations
- Module5-EventMonitor: Event collection

**Priority 3 (Medium):**
- E2E tests: Complete workflows
- Error handling tests
- Performance tests

### Test File Naming Convention
```
tests/
├── GA-AppLocker.Tests.ps1              # Structure tests
├── GA-AppLocker.Artifact.Tests.ps1     # Data model tests
├── GA-AppLocker.RuleGenerator.Tests.ps1 # Rule generation
├── GA-AppLocker.RemoteScan.Tests.ps1   # Scanning
├── GA-AppLocker.Integration.Tests.ps1  # Integration
└── GA-AppLocker.E2E.Tests.ps1          # End-to-end
```

---

## Recent Fixes (January 2026)

### Critical Bug Fixes Applied
1. **New-PathRule missing** - Added function for Path rule generation
2. **GPO import parameter mismatch** - Fixed `-PolicyXml` to `-PolicyXmlPath`
3. **Convert-RulesToAppLockerXml placeholder** - Implemented proper XML conversion
4. **Property name mismatches** - Fixed `publisherName`/`publisher`, `FileHash`/`hash`
5. **Admin elevation check** - Added to WinRM GPO creation
6. **Null safety** - Added checks to Show-Panel, Update-StatusBar

### Code Quality Improvements
- Consolidated duplicate scan buttons in Artifact Collection
- Enhanced local scanning with Get-AuthenticodeSignature
- Fixed corrupted emoji characters in comments
- Removed orphaned button references
