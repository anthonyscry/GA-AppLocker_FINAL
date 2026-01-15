# Changelog

All notable changes to GA-AppLocker are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No unreleased changes_

## [1.2.4] - 2026-01-11

### Added
- **AutoIt GUI Test Suite** (`Tests/GUI/`)
  - Automated GUI testing with 21 test cases
  - Tests window basics, navigation, keyboard shortcuts, page elements
  - Command line options: `/quick`, `/verbose`, `/full`
  - Timestamped log files for test results
  - Batch runner script (`Run-GUITests.bat`)

### Fixed
- **Version consistency**: All version references now unified at 1.2.4
  - Build-GUI.ps1 version updated from 1.2.1.0 to 1.2.4.0
  - About page version updated from 1.0.0 to 1.2.4
  - Added `$Script:AppVersion` constant for centralized version management
  - Window title now shows version dynamically

- **Keyboard shortcuts**: Fixed mismatch between shortcuts and sidebar order
  - Ctrl+1: Scan (was correct)
  - Ctrl+2: Events (was Generate)
  - Ctrl+3: Compare (was Merge)
  - Ctrl+4: Validate (was correct)
  - Ctrl+5: Generate (was Events)
  - Ctrl+6: Merge (was Compare)
  - Ctrl+7: Software (was correct)
  - Ctrl+8: CORA (was correct)
  - Updated F1 help text to match actual shortcuts

### Changed
- Startup log now shows version number
- Help dialog (F1) now includes note about tooltips showing shortcuts

## [1.2.2] - 2026-01-11

### Fixed
- **AsyncHelpers.Tests.ps1**: Fixed `Join-Path` compatibility with PowerShell 5.1 (nested calls required)
- **ErrorHandling.Tests.ps1**: Added PSScriptAnalyzer suppressions for test-specific rules
- **Build-AppLocker.ps1**: Fixed array handling for `Count` property access on potentially null objects
- **Build-Executable.ps1**: Updated path references for new `src/` directory structure

### Changed
- All 211 tests now pass (4 intentionally skipped)
- Build scripts now work correctly with restructured project layout
- Improved error handling in build process

### Added
- Download section in README with placeholder for bundle package link

## [1.2.1] - 2026-01-10

### Added
- **CORA Evidence Generator** (`New-CORAEvidence.ps1`)
  - Single-command audit evidence package generation
  - Executive Summary HTML with compliance score
  - Control mapping for NIST 800-53, CIS Controls, CMMC
  - Deployment timeline with audit trail
  - Evidence manifest (JSON) for machine-readable processing
  - New menu option `[R] CORA` in main workflow
- `RemoveDefaultRules` switch to filter out default AppLocker rules during merge
- `ReplaceMode` parameter for flexible SID replacement modes (Everyone, All, None)
- `TargetGroup` parameter to replace Everyone SID in merged policies
- `users.csv` export with semicolon-separated usernames per group
- Simple two-column CSV format for user imports (Group, Users)
- New trusted publishers: WinZip, MATLAB, Splunk, Trellix, Cisco, Forescout

### Changed
- Improved user import workflow with better log file handling
- Changed simple import format to group-centric (Group, Users columns)
- Default event collection to ADManagement\computers.csv and Events folder

## [1.2.0] - 2025-01-08

### Added
- **Policy Version Control** (`PolicyVersionControl.psm1`)
  - Git-like versioning with save, restore, and rollback
  - Branch management for testing policy variations
  - Commit messages and history tracking
  - Compare policy versions with diff visualization

- **Automatic Phase Advancement** (`Invoke-PhaseAdvancement.ps1`)
  - Event trend analysis to determine readiness
  - Coverage metrics calculation
  - Safety assessment before advancing
  - Auto-generate next phase policy with `-AutoAdvance`
  - Custom thresholds support

- **Self-Service Whitelist Requests** (`WhitelistRequestManager.psm1`)
  - User request submission workflow
  - Admin approval/rejection process
  - Automatic rule generation from approved requests
  - Email/webhook notifications
  - Request state tracking (Pending → Approved/Rejected → Implemented)

- **Industry Templates** (`New-PolicyFromTemplate.ps1`, `PolicyTemplates.psd1`)
  - 7 pre-built compliance templates:
    - FinancialServices (SOX/PCI-DSS)
    - Healthcare (HIPAA/HITECH)
    - Government (NIST/CMMC)
    - Manufacturing (ICS/OT)
    - Education (FERPA/COPPA)
    - Retail (PCI-DSS/POS)
    - SmallBusiness (balanced)
  - Custom publisher extension support

- **Rule Health Checking** (`Test-RuleHealth.ps1`)
  - Broken path detection
  - Publisher certificate validation
  - Hash rule file existence check
  - Duplicate and conflicting rule detection
  - Unused rule identification
  - Health score reporting

- **Compliance Reporting** (`New-ComplianceReport.ps1`)
  - Executive summary with compliance score
  - Evidence inventory (scans, events, policies, logs)
  - Compliance checklist verification
  - Support for NIST 800-53, CIS Controls, CMMC
  - HTML, Markdown, and Text output formats

- **Remote Event Collection** (`Invoke-RemoteEventCollection.ps1`)
  - Collect AppLocker audit events (8003/8004) from remote computers
  - `UniqueBlockedApps.csv` output with occurrence counts
  - `-DaysBack`, `-BlockedOnly`, `-IncludeAllowedEvents` parameters
  - Per-computer detailed event logs

### Changed
- GUI keyboard shortcuts now show in tooltips
- Improved button state management during operations
- Enhanced progress indicators during file processing

## [1.1.0] - 2024-12-15

### Added
- **PowerShell Gallery Support** (`Publish-ToGallery.ps1`)
  - Automated module publication
  - WhatIf preview mode

- **Continuous Monitoring** (`Start-AppLockerMonitor.ps1`)
  - Scheduled event collection intervals
  - Background job support with `-AsJob`
  - Email/webhook alert notifications
  - Configurable alert thresholds
  - Rolling log retention

- **Multi-Format GPO Export** (`Export-AppLockerGPO.ps1`)
  - GPOBackup (importable via GPMC)
  - PowerShell script (Set-AppLockerPolicy)
  - Registry export (.reg files)
  - SCCM configuration baselines
  - Intune JSON format

- **Rule Impact Analysis** (`Get-RuleImpactAnalysis.ps1`)
  - Compare proposed vs. current policy
  - Analyze against scan data
  - Risk assessment and recommendations
  - Detailed per-application impact reports

- **Credential Management** (`CredentialManager.psm1`)
  - DPAPI encryption for credentials
  - Windows Credential Manager integration
  - Session-based caching

- **GUI Improvements**
  - Keyboard shortcuts (Ctrl+1-6 for navigation, F1 for help)
  - Operation cancellation support
  - Auto-detection of folders on startup

## [1.0.0] - 2024-11-01

### Added
- Initial public release
- **Remote Scanning** (`Invoke-RemoteScan.ps1`)
  - WinRM-based data collection
  - Parallel job execution with throttle control
  - Collect: installed software, executables, publishers, writable directories

- **Policy Generation** (`New-AppLockerPolicyFromGuide.ps1`)
  - Build Guide mode (enterprise, phased deployment)
  - Simplified mode (quick deployment)
  - Publisher, path, and hash rules
  - LOLBins deny rules

- **Policy Management**
  - Merge with deduplication (`Merge-AppLockerPolicies.ps1`)
  - Validation and comparison
  - Interactive and parameter-driven modes

- **Software List Management** (`Manage-SoftwareLists.ps1`)
  - Create and manage curated allowlists
  - Import from scans, policies, folders
  - Pre-defined publisher categories

- **AD Integration** (`Manage-ADResources.ps1`)
  - OU and security group creation
  - User/group membership export/import

- **WinRM Deployment** (`Enable-WinRM-Domain.ps1`)
  - Domain-wide GPO deployment
  - Firewall configuration

- **Diagnostics** (`Test-AppLockerDiagnostic.ps1`)
  - Connectivity testing
  - Job execution verification
  - Scan logic isolation

- **Interactive CLI and Portable GUI**
  - Unified workflow hub
  - WPF-based graphical interface

---

For full documentation, see [README.md](README.md).
