<#
.SYNOPSIS
    Help system content and documentation

.DESCRIPTION
    Provides comprehensive help documentation for GA-AppLocker Dashboard.
    Contains help topics covering workflow, rules, troubleshooting, what's new, and policy guides.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Get-HelpContent {
    <#
    .SYNOPSIS
        Returns help content for the specified topic

    .DESCRIPTION
        Retrieves detailed help documentation for various GA-AppLocker topics.

    .PARAMETER Topic
        The help topic to retrieve. Valid values:
        - Workflow: AppLocker deployment workflow guide
        - Rules: Rule best practices and recommendations
        - Troubleshooting: Common issues and solutions
        - WhatsNew: Latest features and changes
        - PolicyGuide: Policy build guide and mental model

    .EXAMPLE
        Get-HelpContent -Topic "Workflow"
        Returns the complete workflow guide for AppLocker deployment

    .EXAMPLE
        Get-HelpContent -Topic "Rules"
        Returns best practices for creating AppLocker rules
    #>
    param(
        [ValidateSet("Workflow", "Rules", "Troubleshooting", "WhatsNew", "PolicyGuide")]
        [string]$Topic = "Workflow"
    )

    switch ($Topic) {
        "Workflow" {
            return @"

=============================================================================
                    APPLOCKER DEPLOYMENT WORKFLOW
=============================================================================

This guide walks you through the complete AppLocker deployment process.


PHASE 1: SETUP (Prepare Your Environment)
---------------------------------------------------------------------------

1. AppLocker Setup (AppLocker Setup Panel)

   Purpose: Creates the Active Directory structure for AppLocker

   What it does:
   - Creates AppLocker OU with security groups
   - Sets up: AppLocker-Admins, AppLocker-StandardUsers
   - Sets up: AppLocker-Service-Accounts, AppLocker-Installers
   - Configures Domain Admins as owner (for deletion access)

   Required: Domain Administrator privileges

   Tip: Click 'Remove OU Protection' if you need to delete the OU later


2. Group Management (Group Management Panel)

   Purpose: Configure who belongs to each AppLocker group

   What it does:
   - Export current group membership to CSV file
   - Edit the CSV to add or remove members
   - Import changes back to Active Directory
   - Preview changes before applying

   Tip: Always use the preview feature before importing!


3. AD Discovery (AD Discovery Panel)

   Purpose: Find target computers for AppLocker deployment

   What it does:
   - Scans Active Directory for all computers
   - Separates computers into Online/Offline lists
   - Tests connectivity to each computer

   Tip: Select only online hosts for artifact scanning


PHASE 2: SCANNING (Collect Software Inventory)
---------------------------------------------------------------------------

4A. AD Discovery Panel (Remote Scanning)

   Purpose: Find target computers and collect artifacts remotely

   Workflow:
   - Discover Computers: Scans Active Directory for all computers
   - Test Connectivity: Pings computers to check online/offline status
   - Select Online: Choose computers from the Online list
   - Scan Selected: Collects artifacts from remote computers via WinRM

   Requirements:
   - WinRM must be enabled (use WinRM panel first)
   - Domain Administrator privileges
   - Target computers must be online

4B. Artifacts Panel (Local Scanning)

   Purpose: Collect artifacts from the local system

   Scan Options:
   - Scan Local System: Quick scan of the local computer
   - Load Artifacts: Pull from AD Discovery panel results
   - Import File: Load a CSV file manually
   - Import Folder: Load all CSVs from a folder

   Output: C:\GA-AppLocker\Scans\


5. Rule Generator (Rules Panel)

   Purpose: Create AppLocker rules from collected artifacts

   Import Options:
   - Load Artifacts: Pull from Artifact Collection panel
   - Load Events: Pull from Event Monitor panel
   - Import File: Load a CSV file manually
   - Import Folder: Load all CSVs from a folder

   Configure:
   - Type: Auto (recommended), Publisher, Hash, or Path
   - Action: Allow or Deny
   - Group: Which AD group receives this rule

   Rule Types:
   - Auto: Publisher for signed, Hash for unsigned (BEST)
   - Publisher: Uses code signing certificate
   - Hash: SHA256 hash (breaks on software updates)
   - Path: File path (least secure, use sparingly)

   Actions:
   - Generate Rules: Create rules from artifacts
   - Default Deny Rules: Block TEMP, Downloads, AppData
   - Browser Deny Rules: Block browsers for admin accounts


PHASE 3: DEPLOYMENT (Push Policies to Computers)
---------------------------------------------------------------------------

6. Deployment (Deployment Panel)

   Purpose: Deploy AppLocker policies via Group Policy

   Actions:
   - Create GPO: Creates new AppLocker GPO
   - Toggle Audit/Enforce: Switch mode for all rules at once
   - Export Rules: Save rules to C:\GA-AppLocker\Rules\
   - Import Rules: Load existing AppLocker XML file

   GPO Assignment:
   - DCs: Domain Controllers GPO
   - Servers: Member servers GPO
   - Workstations: Workstations GPO


7. WinRM Setup (WinRM Panel)

   Purpose: Enable remote management for scanning

   What it creates:
   - WinRM GPO with service auto-configuration
   - Basic authentication enabled
   - TrustedHosts configured
   - Firewall rules for ports 5985/5986

   Actions:
   - Create WinRM GPO: Creates the GPO
   - Force GPUpdate: Push policy to all computers
   - Enable/Disable: Turn WinRM GPO link on or off

   Required For: Remote artifact scanning and remote event collection


PHASE 4: MONITORING (Track Effectiveness)
---------------------------------------------------------------------------

8. Event Monitor (Events Panel)

   Purpose: Monitor AppLocker policy effectiveness

   Actions:
   - Scan Local: Collect AppLocker events from local system
   - Scan Selected: Collect events from remote computers via WinRM
   - Quick Date Filters: Last Hour, Today, 7 Days, 30 Days
   - Filter by Type: Allowed (8002), Audit (8003), Blocked (8004)
   - Export to CSV: Analyze events externally
   - Import to Rules: Create rules from events

   Event IDs:
   - 8002: Allowed (policy allows execution)
   - 8003: Audit (would be blocked in Enforce mode)
   - 8004: Blocked (policy denies execution)


9. Dashboard (Dashboard Panel)

   Purpose: At-a-glance overview of your AppLocker environment

   Shows:
   - Mini Status Bar: Domain status, artifact count
   - Policy Health Score: 0-100 based on configured rules
   - Event Counts: From C:\GA-AppLocker\Events\
   - Filters: By time range (7/30 days) and computer
   - Charts: Visual representation of data


10. Compliance (Compliance Panel)

    Purpose: Generate audit evidence packages

    Creates:
    - Timestamped folder with all policies
    - Event logs for specified time period
    - Ready-to-export documentation


BEST PRACTICES (Key Recommendations)
---------------------------------------------------------------------------

1. Always start in Audit mode (Event ID 8003)
   - Monitor for 7-14 days before switching to Enforce
   - Review Audit events to identify legitimate software

2. Use Auto rule type (Publisher for signed, Hash for unsigned)
   - Most resilient to software updates
   - Reduces rule maintenance overhead

3. Add Default Deny Rules for bypass locations
   - Block TEMP, Downloads, AppData, user-writable paths
   - Prevents living-off-the-land attacks

4. Maintain break-glass admin access
   - Keep a local admin account for emergencies
   - Document all exceptions and justifications

5. Use Search/Filter for large artifact lists
   - Quickly find specific applications
   - Reduce noise before generating rules

6. Test with actual user accounts
   - Verify rules work as expected
   - Check for business process interruptions


QUICK REFERENCE (Common Commands)
---------------------------------------------------------------------------

PowerShell Commands:
- Get-AppLockerPolicy -Effective        (View current policy)
- Get-WinEvent -LogName 'AppLocker/EXE and DLL'  (View events)
- Test-AppLockerPolicy                   (Test policy against file)
- gpupdate /force                         (Refresh Group Policy)
- gpresult /r /scope computer             (Check applied GPOs)


NEED MORE HELP?
---------------------------------------------------------------------------

- Check Application Logs: C:\GA-AppLocker\Logs\
- Review Microsoft AppLocker documentation
- Contact your security team
- Open a support ticket

"@
        }
        "Rules" {
            return @"

=============================================================================
                    APPLOCKER RULE BEST PRACTICES
=============================================================================

This guide explains how to create effective and secure AppLocker rules.


RULE TYPE PRIORITY (Use in this order)
---------------------------------------------------------------------------

1. PUBLISHER RULES (Preferred - Use First)

   Best For: Signed commercial software

   Advantages:
   - Most resilient to software updates
   - Covers all versions from a publisher
   - Automatic version updates

   Example: Microsoft Corporation, Adobe Inc.

   When to Use:
   - All signed software from trusted vendors
   - Microsoft Office, Adobe products, etc.


2. HASH RULES (Fallback for Unsigned Software)

   Best For: Unsigned executables only

   Advantages:
   - Most specific - exact file match
   - Cannot be bypassed by file renaming

   Disadvantages:
   - Fragile - breaks on every file update
   - High maintenance overhead

   When to Use:
   - Unsigned internal tools
   - Legacy applications without signatures
   - Temporary exceptions


3. PATH RULES (Exceptions Only - Use with Caution)

   Best For: Specific exception cases only

   Disadvantages:
   - Too permissive - easily bypassed
   - Moving files bypasses rules
   - Symbolic links can bypass rules

   When to Use (Rarely):
   - Denying specific user-writable paths (TEMP, Downloads)
   - Allowing specific admin tools from fixed paths
   - Temporary exceptions during testing

   Example: %OSDRIVE%\Users\*\Downloads\*\*


SECURITY PRINCIPLES (Core Concepts)
---------------------------------------------------------------------------

DENY-FIRST MODEL (Default Stance)
  - Default deny: Block all executables by default
  - Explicit allow: Only allow approved software
  - Deny bypass locations: Block user-writable paths

  This approach provides the strongest security posture.


LEAST PRIVILEGE (User Groups)
  - AppLocker-Admin: Full system access
  - AppLocker-Installers: Software installation rights
  - AppLocker-StandardUsers: Restricted workstation users
  - AppLocker-Service-Accounts: Service account access
  - AppLocker-Dev: Developer tools access

  Different rules for different user groups reduces risk.


AUDIT BEFORE ENFORCE (Deployment Process)
  1. Deploy in Audit mode first
  2. Monitor for 7-14 days minimum
  3. Review and categorize events:
     - Legitimate software: Add allow rules
     - Unapproved software: Leave blocked
     - False positives: Create exceptions
  4. Switch to Enforce only after validation

  Never skip the audit phase!


RULE COLLECTIONS TO CONFIGURE
---------------------------------------------------------------------------

Required:
- Executable (.exe, .com)           - Most important
- Script (.ps1, .bat, .cmd, .vbs)   - PowerShell critical
- Windows Installer (.msi, .msp)    - Software deployment

Optional (Advanced):
- DLL (.dll, .ocx)                  - High maintenance
- Packaged Apps/MSIX                - Windows 10+ store apps


COMMON MISTAKES TO AVOID
---------------------------------------------------------------------------

1. Using wildcards in path rules
   - Bad: C:\Program Files\*\*
   - Good: Specific publisher rules

2. Forgetting to update hash rules after updates
   - Set reminder to review hash rules monthly

3. Not testing with actual user accounts
   - Test with standard user, not admin

4. Skipping the audit phase
   - Always audit first, enforce later

5. Forgetting service accounts
   - Service accounts need special rules

6. Not documenting exceptions
   - Document why each exception exists


GROUP STRATEGY RECOMMENDATIONS
---------------------------------------------------------------------------

AppLocker-Admin
  - Purpose: Full system administration
  - Access: Allow most executables
  - Exceptions: May deny browsers, P2P software

AppLocker-Installers
  - Purpose: Software installation rights
  - Access: Allow installers, updaters
  - Scope: Limited to installation tasks

AppLocker-StandardUsers
  - Purpose: General workforce
  - Access: Highly restricted
  - Scope: Business applications only

AppLocker-Service-Accounts
  - Purpose: Running services
  - Access: Specific service executables
  - Scope: Minimal required access

AppLocker-Dev
  - Purpose: Software development
  - Access: Development tools, compilers
  - Scope: Development workstations only


ADMIN ACCOUNT SECURITY
---------------------------------------------------------------------------

Recommendations:
- Consider denying web browsers for admin accounts
- Admins should use separate workstations for admin tasks
- Maintain break-glass local admin for emergencies
- Document all exceptions with justifications
- Review admin exceptions quarterly


RULE MAINTENANCE
---------------------------------------------------------------------------

Monthly:
- Review hash rules for stale entries
- Check for new software versions
- Verify all exceptions are still needed

Quarterly:
- Full policy review and cleanup
- Remove unused rules
- Update documentation

Annually:
- Complete audit of all AppLocker policies
- Compliance review and reporting

"@
        }
        "Troubleshooting" {
            return @"
=== APPLOCKER TROUBLESHOOTING ===

ISSUE: Events not appearing in Event Monitor
SOLUTIONS:
- Verify AppLocker ID 8001 (Policy Applied) appears first
- Check Application Identity service is running
- Verify policy is actually enforced (gpresult /r)
- Restart Application Identity service if needed

ISSUE: All executables being blocked
SOLUTIONS:
- Check if policy is in Enforce mode (should start as Audit)
- Verify rule collection is enabled
- Check for conflicting deny rules
- Review event logs for specific blocked files

ISSUE: False positives - legitimate apps blocked
SOLUTIONS:
- Add specific Publisher rule for the application
- Check if app needs to run from user-writable location
- Consider creating exception path rule
- Review hash rule if app version changed

ISSUE: Policy not applying to computers
SOLUTIONS:
- Run: gpresult /r /scope computer
- Check GPO is linked to correct OU
- Verify GPO security filtering
- Force GP update: gpupdate /force
- Check DNS resolution for domain controllers

ISSUE: Cannot create GPO (access denied)
SOLUTIONS:
- Must be Domain Admin or have GPO creation rights
- Check Group Policy Management console permissions
- Verify RSAT is installed if running from workstation
- Run PowerShell as Administrator

ISSUE: WinRM connection failures
SOLUTIONS:
- Verify WinRM GPO has applied (gpupdate /force)
- Check firewall allows port 5985/5986
- Test with: Test-WsMan -ComputerName <target>
- Ensure target computer has WinRM enabled

ISSUE: Rule generation errors
SOLUTIONS:
- Verify artifact scan completed successfully
- Check CSV format is correct (UTF-8 encoding)
- Ensure Publisher info exists in file version
- Use Hash rules for unsigned executables

ISSUE: Group import fails
SOLUTIONS:
- Verify CSV format: GroupName,Members (semicolon-separated)
- Check member accounts exist in AD
- Ensure you have rights to modify group membership
- Use dry-run first to preview changes

ISSUE: High CPU/memory during scan
SOLUTIONS:
- Reduce MaxFiles setting
- Scan specific directories instead of full drives
- Run during off-peak hours
- Use AD discovery to target specific computers

USEFUL PowerShell COMMANDS:
- Get-AppLockerPolicy -Effective
- Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'
- Test-AppLockerPolicy
- Set-AppLockerPolicy
- gpupdate /force
- gpresult /r /scope computer

LOG LOCATIONS:
- AppLocker Events: Event Viewer -> Applications and Services -> Microsoft -> Windows -> AppLocker
- Group Policy: Event Viewer -> Windows Logs -> System
- Application ID: Services.msc -> Application Identity
- Application Logs: C:\GA-AppLocker\Logs\

ESCALATION PATH:
1. Review this help documentation
2. Check Application Logs in C:\GA-AppLocker\Logs\
3. Consult internal security team
4. Review Microsoft AppLocker documentation
5. Contact GA-ASI security team for advanced issues
"@
        }
        "WhatsNew" {
            return @"
=== WHAT'S NEW IN v1.2.5 ===

QUALITY-OF-LIFE FEATURES:

[1] Search/Filter (Rule Generator Panel)
   - Filter artifacts by publisher, path, or filename
   - Filter generated rules by any property
   - Real-time filtering as you type
   - Location: Top of Rule Generator panel

[2] One-Click Audit Toggle (Deployment Panel)
   - Instantly switch between Audit and Enforce modes
   - Updates all rule collections at once
   - Confirmation dialog before mode change
   - Location: Deployment panel, "Toggle Audit/Enforce" button

[3] Rule Preview Panel (Rule Generator Panel)
   - Preview XML rules before generation
   - Shows exact XML that will be exported
   - Helps verify rule structure
   - Location: Rule Generator panel, "Preview Rules" button

[4] Mini Status Bar (Top Navigation Bar)
   - Real-time domain status (joined/workgroup)
   - Artifact count indicator
   - Sync status for data refresh
   - Location: Top bar, right side

[5] Bulk Action Confirmation
   - Confirmation dialogs before destructive operations
   - Prevents accidental rule clear
   - Prevents accidental GPO deletion
   - Shows count of affected items

[6] Quick Date Presets (Events Panel)
   - Last Hour: Events from the last 60 minutes
   - Today: Events from today
   - Last 7 Days: Events from past week
   - Last 30 Days: Events from past month
   - Location: Events panel, quick date buttons

BUG FIXES:

[1] UTF-16 Encoding Fix
   - AppLocker XML policies now use proper UTF-16 encoding
   - Previous UTF-8 encoding caused import failures
   - All exported policies now compatible with AppLocker

[2] Regex Pattern Improvements
   - Directory safety classification now uses robust regex escaping
   - Prevents false positives in path matching
   - More reliable unsafe path detection

[3] System.Web Assembly Loading
   - Added assembly loading for HTML encoding security
   - Prevents encoding errors in compliance reports

[4] Emoji Character Removal
   - Removed emoji characters for PowerShell compatibility
   - Replaced with ASCII equivalents
   - Prevents syntax errors in script parsing

ARCHITECTURE IMPROVEMENTS:

[1] Standardized Artifact Data Model
   - Common artifact structure across all modules
   - Properties: name, path, publisher, hash, version, size, modifiedDate, fileType
   - Automatic property name mapping between formats

[2] Artifact Conversion Functions
   - Convert-AppLockerArtifact: Maps between naming conventions
   - Handles Module2 (lowercase), GUI (PascalCase), CSV import formats
   - Ensures interoperability between modules

[3] Rule Validation Before Export
   - Test-AppLockerRules: Validates all required properties exist
   - Pre-export validation catches missing data
   - Returns success, errors, warnings

[4] Unit Tests for Artifact Interoperability
   - 22 new tests in GA-AppLocker.Artifact.Tests.ps1
   - Tests artifact creation, conversion, validation
   - Tests property name mappings
   - 20 passing, 2 skipped

DOCUMENTATION UPDATES:

[1] ARTIFACT-DATA-MODEL.md
   - Complete documentation of artifact data structure
   - Property name mapping tables
   - Usage examples and best practices

[2] Updated README.md
   - v1.2.5 release notes
   - New features and bug fixes documented

[3] Updated CLAUDE.md
   - Technical documentation for new functions
   - GUI feature descriptions

HOW TO USE NEW FEATURES:

Search/Filter:
   1. Go to Rule Generator panel
   2. Type in the Search box to filter artifacts or rules
   3. Results update in real-time

Audit Toggle:
   1. Go to Deployment panel
   2. Click "Toggle Audit/Enforce"
   3. Confirm the mode change

Rule Preview:
   1. Generate rules in Rule Generator panel
   2. Click "Preview Rules" button
   3. Review XML before export

Quick Date Presets:
   1. Go to Events panel
   2. Click quick date button (Today, 7 Days, etc.)
   3. Events automatically filter by selected range

For detailed technical documentation, see:
   - docs/ARTIFACT-DATA-MODEL.md - Artifact and rule data structures
   - claude.md - Developer reference
   - README.md - Project overview
"@
        }
        "PolicyGuide" {
            return @"
=== APPLOCKER POLICY BUILD GUIDE ===

OBJECTIVE:
Allow who may execute trusted code, deny where code can never run,
validate in Audit, then enforce - without breaking services or failing audit.

--- CORE MENTAL MODEL ---
* AppLocker evaluates security principal + rule match
* Explicit Deny always wins
* Publisher rules apply everywhere unless denied
* Each rule collection is independent
* "Must exist" does NOT mean "allowed everything"

--- EXECUTION DECISION ORDER ---
1. Explicit Deny
2. Explicit Allow
3. Implicit Deny (only if nothing matches)

If you allow broadly, you must deny explicitly.

=== MANDATORY ALLOW PRINCIPALS ===
(Referenced in every rule collection: EXE, Script, MSI, DLL)

[ ] NT AUTHORITY\SYSTEM
[ ] NT AUTHORITY\LOCAL SERVICE
[ ] NT AUTHORITY\NETWORK SERVICE
[ ] BUILTIN\Administrators

IMPORTANT: These principals are NOT allowed everything.
They are allowed only what your rules explicitly permit.
They are still subject to Explicit Deny rules.

=== CUSTOM APPLOCKER GROUPS ===

[ ] DOMAIN\AppLocker-Admins
[ ] DOMAIN\AppLocker-StandardUsers
[ ] DOMAIN\AppLocker-Service-Accounts
[ ] DOMAIN\AppLocker-Installers (optional but recommended)

Rules of use:
* Service accounts -> only in AppLocker-Service-Accounts
* No service accounts in Administrators
* Deny interactive logon for service accounts via GPO

=== GROUP MEMBERSHIP + MINIMUM PERMISSIONS ===

1. AppLocker-Admins
   Who: Domain/Server/Platform admins, Security administrators
   Minimum permissions:
   * EXE -> Microsoft + approved vendor publishers
   * Script -> Microsoft-signed scripts
   * MSI -> Microsoft + vendor installers
   * DLL -> Microsoft-signed DLLs
   Still blocked by Deny paths!
   Purpose: admin survivability without blanket trust

2. AppLocker-StandardUsers
   Who: Regular end users
   Minimum permissions:
   * EXE -> Explicitly approved vendor apps only
   * Script -> None
   * MSI -> None
   * DLL -> Only via allowed EXEs
   Denied: installers, scripts, user-writable paths
   Purpose: least-privilege execution

3. AppLocker-Service-Accounts
   Who: Domain service accounts (svc_sql, svc_backup, SCCM, monitoring)
   Minimum permissions:
   * EXE -> Vendor-signed binaries
   * Script -> Vendor-signed scripts (if required)
   * MSI -> Only if service self-updates
   * DLL -> Vendor-signed DLLs
   Mandatory controls:
   * No admin rights
   * No interactive logon
   * No path-based allows
   Purpose: prevent outages without privilege creep

4. AppLocker-Installers (Optional)
   Who: Desktop Support (Tier 2+), Imaging/deployment, SCCM/Intune
   Minimum permissions:
   * MSI -> Vendor + Microsoft installers
   * EXE -> Vendor installer bootstrap EXEs only
   * Script -> None unless explicitly required
   * DLL -> None directly
   Purpose: controlled software introduction

=== MICROSOFT / WINDOWS SIGNED CODE ===

NEVER do this:
  Microsoft Publisher -> Everyone

CORRECT pattern:
  Microsoft Publisher ->
  [ ] SYSTEM
  [ ] LOCAL SERVICE
  [ ] NETWORK SERVICE
  [ ] BUILTIN\Administrators

This allows OS & services but does NOT give users blanket execution.

=== SERVICE ACCOUNTS ===

Built-in services:
* Run as SYSTEM / NT SERVICE*
* Covered by Microsoft publisher rules
* No path allows required

Domain service accounts:
[ ] Members of DOMAIN\AppLocker-Service-Accounts
[ ] Allowed via publisher rules only
[ ] No admin rights
[ ] No local logon

=== EXPLICIT DENY RULES (REQUIRED) ===

Create Deny-Path rules for Everyone:
[ ] %USERPROFILE%\Downloads\*
[ ] %APPDATA%\*
[ ] %LOCALAPPDATA%\Temp\*
[ ] %TEMP%\*

Why:
* Prevent signed binary abuse
* Close living-off-the-land execution paths
* Override all Allows (including SYSTEM)

=== MINIMUM RULE ASSIGNMENTS BY COLLECTION ===

EXECUTABLES (EXE):
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Admins -> Microsoft + Vendor Publisher
[ ] Service Accounts -> Vendor Publisher
[ ] Users -> Explicitly approved apps only
[ ] Installers -> Vendor installer EXEs only
Deny:
[ ] User-writable paths (above)

SCRIPTS (PS1, BAT, CMD, VBS) - Highest Risk:
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Admins -> Microsoft Publisher
[ ] Service Accounts -> Vendor Publisher
Do NOT allow:
[ ] Standard users
[ ] Everyone

MSI / INSTALLERS:
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Installers Group -> Vendor Publisher
[ ] Admins -> Vendor Publisher
Deny:
[ ] Everyone else

DLL (Enable LAST):
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Admins -> Microsoft Publisher
[ ] Service Accounts -> Vendor Publisher
ALWAYS Audit first!

=== AUDIT MODE VALIDATION (REQUIRED) ===

[ ] EXE audit clean
[ ] Script audit clean
[ ] MSI audit clean
[ ] DLL audited 7-14 days
[ ] Event ID 8004 reviewed
[ ] Services start normally
[ ] Scheduled tasks run
[ ] Patch & agent updates succeed

If it runs in Audit, it will run in Enforce.

=== RULE CREATION ORDER (Follow Exactly) ===

Phase 0 - Prep:
[ ] Identify service accounts
[ ] Create AppLocker AD groups

Phase 1 - EXE:
[ ] Microsoft publisher rules
[ ] Vendor publisher rules
[ ] Explicit Deny paths
[ ] Enable Audit

Phase 2 - Scripts:
[ ] Microsoft scripts -> SYSTEM/Admins
[ ] Vendor scripts -> Service Accounts
[ ] Audit and review

Phase 3 - MSI:
[ ] Microsoft MSIs -> SYSTEM
[ ] Vendor MSIs -> Installers/Admins
[ ] Audit patch cycles

Phase 4 - DLL (LAST):
[ ] Enable Audit
[ ] Review 7-14 days
[ ] Add vendor DLL publishers as needed

Phase 5 - Enforce:
[ ] EXE -> Enforce
[ ] Scripts -> Enforce
[ ] MSI -> Enforce
[ ] DLL -> Enforce (last)

=== COMMON BLIND SPOTS ===

[ ] Scheduled Tasks (often SYSTEM)
[ ] Self-updating agents (AV, monitoring, backup)
[ ] ProgramData execution (audit before denying)
[ ] DLL rules enabled too early

=== ENFORCEMENT GATE (ALL must be true) ===

[ ] SYSTEM not blocked
[ ] No service failures
[ ] No Everyone allows
[ ] Explicit Deny rules exist
[ ] Audit evidence retained

=== AUDITOR-APPROVED SUMMARY ===

"Application execution is controlled using publisher-based AppLocker
rules scoped to defined administrative, installer, service, and user
security groups. User-writable directories are explicitly denied to
prevent abuse of signed binaries. All policies were validated in
audit mode prior to enforcement."

=== FINAL ONE-LINE MODEL ===

Allow who may run trusted code, deny where code can never run,
and never enforce what you didn't audit.
"@
        }
    }
}

Export-ModuleMember -Function Get-HelpContent
