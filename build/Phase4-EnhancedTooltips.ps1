# ============================================================
# PHASE 4: ENHANCED TOOLTIPS AND CONTEXT HELP
# GA-AppLocker GUI Enhancement
# ============================================================
# This script contains all the enhanced tooltips and context help
# functionality for Phase 4 implementation.
#
# INSTRUCTIONS:
# 1. Insert this entire content before the "Get-HelpContent" function
#    (around line 5789 in GA-AppLocker-GUI-WPF.ps1)
# 2. Add the initialization call in the main window setup section
# 3. Add context help calls in navigation button click handlers
# ============================================================

function Show-ContextHelp {
    <#
    .SYNOPSIS
        Update context help panel based on current tab
    .DESCRIPTION
        Displays contextual help information in the Help panel
        based on the currently active tab/panel.
    .PARAMETER Panel
        Current panel name (e.g., "Dashboard", "Artifacts", "Rules")
    .EXAMPLE
        Show-ContextHelp -Panel "Dashboard"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Panel
    )

    $helpText = Get-ContextHelpText -Panel $Panel
    $helpTitle = Get-ContextHelpTitle -Panel $Panel

    $HelpText = $window.FindName("HelpText")
    $HelpTitleCtrl = $window.FindName("HelpTitle")

    if ($HelpText) {
        $HelpText.Text = $helpText
    }
    if ($HelpTitleCtrl) {
        $HelpTitleCtrl.Text = $helpTitle
    }

    Write-Log -Level VERBOSE -Message "Context help updated for panel: $Panel"
}

function Get-ContextHelpTitle {
    <#
    .SYNOPSIS
        Get the title for context help based on panel
    #>
    param([string]$Panel)

    switch ($Panel) {
        "Dashboard"      { return "Dashboard Help" }
        "Artifacts"      { return "Artifact Collection Help" }
        "Rules"          { return "Rule Generator Help" }
        "Events"         { return "Events Monitoring Help" }
        "Deployment"     { return "Deployment Help" }
        "AppLockerSetup" { return "AppLocker Setup Help" }
        "Discovery"      { return "AD Discovery Help" }
        "Compliance"     { return "Compliance Help" }
        "WinRM"          { return "WinRM Setup Help" }
        "GroupMgmt"      { return "Group Management Help" }
        "GapAnalysis"    { return "Gap Analysis Help" }
        default          { return "Context Help" }
    }
}

function Get-ContextHelpText {
    <#
    .SYNOPSIS
        Get contextual help text for each panel
    .DESCRIPTION
        Returns detailed help text for each panel including
        key features, workflows, and tips.
    #>
    param([string]$Panel)

    switch ($Panel) {
        "Dashboard" {
            return @"
The Dashboard provides an at-a-glance overview of your AppLocker deployment health and activity.

KEY METRICS:
• Policy Health Score - Overall policy status (0-100)
• Total Events - All AppLocker events in the timeframe
• Allowed (8002) - Successfully allowed executions
• Audited (8003) - Would be blocked in Enforce mode
• Blocked (8004) - Actually blocked executions

FILTERS:
• Time Range - Select Last 7 Days or Last 30 Days
• System - Filter by specific computer name

QUICK ACTIONS:
• Click Refresh to update all metrics
• Use Filters to drill down into specific systems or timeframes

TIP: High Audited events indicate policies need tuning before enforcing.
"@
        }
        "Artifacts" {
            return @"
Artifact Collection builds your software inventory for rule generation.

LOCAL SCANNING:
• Scan Local - Quick scan of localhost for executable artifacts
• Generates: Executables.csv, Publishers.csv, RunningProcesses.csv

REMOTE SCANNING:
• Select computers from the list (Ctrl+click for multiple)
• Scan Selected - Collect artifacts from remote systems
• Requires WinRM enabled on target systems

DIRECTORY SCANNING:
• Specify custom directory paths (one per line)
• Set Max Files limit to prevent excessive scans
• Useful for network shares or specific application folders

OUTPUT LOCATION:
C:\GA-AppLocker\Scans\<ComputerName>\

TIP: Always scan representative systems, not just administrators' computers.
"@
        }
        "Rules" {
            return @"
The Rule Generator converts collected artifacts into AppLocker rules.

RULE TYPES (Priority Order):
• Auto (Recommended) - Publisher for signed, Hash for unsigned
• Publisher - Uses code signing certificate (most resilient)
• Hash - SHA256 hash (breaks on updates)
• Path - File path (easiest to bypass)

ACTIONS:
• Allow - Permit execution
• Deny - Block execution

TARGET GROUPS:
• AppLocker-Admins - Administrator applications
• AppLocker-StandardUsers - Standard user applications
• AppLocker-Service-Accounts - Service account applications
• AppLocker-Installers - Installer applications

WORKFLOW:
1. Load Artifacts or Load Events
2. Select items from the list
3. Choose rule type, action, and target group
4. Click Generate Rules
5. Preview and Export

FEATURES:
• Deduplicate - Remove duplicates by Publisher/Hash/Path
• Search/Filter - Find specific artifacts quickly
• Audit Mode Toggle - Switch all rules to audit only

TIP: Use Auto rule type for optimal security and manageability.
"@
        }
        "Events" {
            return @"
Events monitoring shows what AppLocker is blocking or allowing on your systems.

EVENT TYPES:
• Allowed (8002) - Successfully allowed executions
• Audited (8003) - Would be blocked in Enforce mode
• Blocked (8004) - Actually blocked executions

QUICK DATE FILTERS:
• Last Hour - Recent activity only
• Today - All events from today
• Last 7 Days - Week view
• Last 30 Days - Month view

SCANNING:
• Scan Local - Check localhost AppLocker events
• Scan Selected - Scan remote computers (requires WinRM)

FILTER BUTTONS:
• All - Show all event types
• Allowed - Show only successful executions
• Blocked - Show only blocked executions
• Audit - Show only audit events

EXPORT:
• Export to CSV for analysis or documentation

TIP: High blocked events in Audit mode? Add missing rules before enforcing!
"@
        }
        "Deployment" {
            return @"
Deployment manages GPO creation and policy distribution.

GPO MANAGEMENT:
• Create GPO - Create and link new AppLocker GPO
• Disable AppLocker GPO - Unlink and disable the GPO

RULE MANAGEMENT:
• Export Rules - Save rules to C:\GA-AppLocker\Rules\
• Import Rules to GPO - Load rules into Group Policy

AUDIT MODE TOGGLE:
• [!] AUDIT MODE - Click to switch all rules to Audit
• [!] ENFORCE MODE - Click to switch all rules to Enforce
• Use this to quickly change enforcement mode

IMPORT MODE:
• Replace - Clear existing rules, add new ones
• Append - Add new rules to existing rules

TIP: Always test in Audit mode for 7-14 days before enforcing!
"@
        }
        "AppLockerSetup" {
            return @"
AppLocker Setup initializes your Active Directory structure for AppLocker management.

INITIALIZATION:
• Creates AppLocker OU in Active Directory
• Creates AppLocker security groups:
  - AppLocker-Admins
  - AppLocker-StandardUsers
  - AppLocker-Service-Accounts
  - AppLocker-Installers

OPTIONS:
• OU Name - Customize OU name (default: AppLocker)
• Auto-Populate Admins - Add Domain Admins to groups

GPO CREATION:
• Create 3 GPOs (DC, Servers, Workstations)
• Configure Phase (1-4) and Mode (Audit/Enforce)
• Link GPOs to appropriate OUs

PREREQUISITES:
• Domain Admin rights
• Domain-joined computer

TIP: Click "Remove OU Protection" if you need to delete/recreate the structure.
"@
        }
        "Discovery" {
            return @"
AD Discovery finds and tests connectivity to target computers.

DISCOVERY:
• Search Filter - Use * for all, or specify criteria (e.g., "WIN-*")
• Click Discover to find computers in AD
• Online/Offline shown in separate lists

CONNECTIVITY:
• Test Connectivity - Check WinRM access to selected systems
• Required for remote artifact and event scanning

SELECTION:
• Select All - Select all online computers
• Clear All - Deselect all computers
• Ctrl+click - Select multiple specific computers

SCANNING:
• Scan Selected - Initiate scan on selected systems

TIP: Only scan online systems with confirmed WinRM connectivity.
"@
        }
        "Compliance" {
            return @"
Compliance generates evidence packages for audit documentation.

SCANNING:
• Scan Local - Check localhost compliance
• Scan Selected - Scan remote computers

EVIDENCE PACKAGE:
• Generate Evidence Package - Creates timestamped folder with:
  - Current AppLocker policies
  - Event logs
  - Compliance status reports

OUTPUT LOCATION:
C:\GA-AppLocker\Compliance\<Timestamp>\

USE CASES:
• Audit preparation
• Policy review documentation
• Incident response evidence

TIP: Generate evidence packages regularly for audit trail.
"@
        }
        "WinRM" {
            return @"
WinRM Setup enables remote management for AppLocker operations.

WINRM GPO CREATION:
• Creates WinRM GPO with required settings:
  - WinRM Service auto-start
  - Basic authentication
  - TrustedHosts = *
  - Firewall rules for ports 5985/5986

GPO LINK MANAGEMENT:
• Enable GPO Link - Activate WinRM GPO
• Disable GPO Link - Deactivate WinRM GPO
• Force GPUpdate - Push policy to all computers

PREREQUISITES:
• WinRM required for remote scanning
• Requires Domain Admin rights

TIP: Test WinRM connectivity in AD Discovery after enabling.
"@
        }
        "GroupMgmt" {
            return @"
Group Management manages AppLocker security group memberships.

EXPORT:
• Export Groups - Save current membership to CSV
• Output: C:\GA-AppLocker\Groups\Export_<Timestamp>.csv

IMPORT:
• Import Changes - Load and apply group changes
• Dry Run (Preview) - Preview changes without applying
• Allow Removals - Enable removing users from groups
• Include Tier-0 - Include protected accounts (caution!)

EDITING WORKFLOW:
1. Export Groups to CSV
2. Edit CSV in Excel/text editor
3. Import Changes
4. Review preview
5. Uncheck Dry Run to apply

TIP: Always use Dry Run first to preview changes!
"@
        }
        "GapAnalysis" {
            return @"
Gap Analysis compares software inventory between baseline and target systems.

IMPORT:
• Import Baseline CSV - Reference system software
• Import Target CSV - Target system software
• Use software inventory from Artifact scans

COMPARISON:
• Compare Lists - Identify software differences
• Shows: Missing, Additional, Version mismatches

EXPORT:
• Export Comparison - Save results to CSV

USE CASES:
• Identify missing applications on target systems
• Find unauthorized software installations
• Plan software deployments

TIP: Use for planning application deployments before enforcing policies.
"@
        }
        default {
            return "Select a panel to view context-sensitive help and tips."
        }
    }
}

function Initialize-Tooltips {
    <#
    .SYNOPSIS
        Initialize enhanced tooltips for all controls
    .DESCRIPTION
        Sets tooltips for all major controls in the GUI including
        navigation buttons, action buttons, and input controls.
        Tooltips explain what controls do, when to use them,
        prerequisites, and keyboard shortcuts.
    .EXAMPLE
        Initialize-Tooltips
    #>
    [CmdletBinding()]
    param()

    Write-Log -Level INFO -Message "Initializing enhanced tooltips for all controls"

    # ============================================================
    # NAVIGATION BUTTONS
    # ============================================================
    Set-ControlToolTip -ControlName "NavDashboard" -ToolTip "View policy health and event statistics (Ctrl+D)"
    Set-ControlToolTip -ControlName "NavAppLockerSetup" -ToolTip "Initialize AD structure and create GPOs (Ctrl+Shift+S)"
    Set-ControlToolTip -ControlName "NavGroupMgmt" -ToolTip "Manage AppLocker security group memberships"
    Set-ControlToolTip -ControlName "NavDiscovery" -ToolTip "Discover computers and test connectivity"
    Set-ControlToolTip -ControlName "NavArtifacts" -ToolTip "Collect executable inventory from systems (Ctrl+A)"
    Set-ControlToolTip -ControlName "NavGapAnalysis" -ToolTip "Compare software between systems"
    Set-ControlToolTip -ControlName "NavRules" -ToolTip "Generate AppLocker rules from artifacts (Ctrl+R)"
    Set-ControlToolTip -ControlName "NavDeployment" -ToolTip "Deploy policies via GPO (Ctrl+Shift+D)"
    Set-ControlToolTip -ControlName "NavWinRM" -ToolTip "Enable WinRM for remote management"
    Set-ControlToolTip -ControlName "NavEvents" -ToolTip "Monitor AppLocker events (Ctrl+E)"
    Set-ControlToolTip -ControlName "NavCompliance" -ToolTip "Generate audit evidence packages"
    Set-ControlToolTip -ControlName "NavHelp" -ToolTip "View workflow and best practices guide (F1)"
    Set-ControlToolTip -ControlName "NavAbout" -ToolTip "Version and license information"

    # ============================================================
    # DASHBOARD CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "DashboardTimeFilter" -ToolTip "Filter events by time range (7/30 days)"
    Set-ControlToolTip -ControlName "DashboardSystemFilter" -ToolTip "Filter by specific computer name"
    Set-ControlToolTip -ControlName "RefreshDashboardBtn" -ToolTip "Refresh all dashboard metrics (F5)"

    # ============================================================
    # ARTIFACTS CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "ScanLocalArtifactsBtn" -ToolTip "Scan localhost for executable artifacts (Quick scan)"
    Set-ControlToolTip -ControlName "ScanRemoteArtifactsBtn" -ToolTip "Scan selected remote computers for artifacts"
    Set-ControlToolTip -ControlName "RefreshArtifactComputersBtn" -ToolTip "Refresh the computer list from AD"
    Set-ControlToolTip -ControlName "MaxFilesText" -ToolTip "Maximum number of files to scan (prevents excessive scans)"
    Set-ControlToolTip -ControlName "ScanDirectoriesBtn" -ToolTip "Scan specified directory paths for artifacts"

    # ============================================================
    # GAP ANALYSIS CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "ImportBaselineBtn" -ToolTip "Import baseline software inventory CSV"
    Set-ControlToolTip -ControlName "ImportTargetBtn" -ToolTip "Import target software inventory CSV"
    Set-ControlToolTip -ControlName "CompareSoftwareBtn" -ToolTip "Compare software lists and identify gaps"
    Set-ControlToolTip -ControlName "ExportGapAnalysisBtn" -ToolTip "Export comparison results to CSV"

    # ============================================================
    # RULES CONTROLS
    # ============================================================
    # Rule Type Radio Buttons
    Set-ControlToolTip -ControlName "RuleTypeAuto" -ToolTip "Auto: Publisher for signed, Hash for unsigned (Recommended)"
    Set-ControlToolTip -ControlName "RuleTypePublisher" -ToolTip "Publisher: Uses code signing certificate (most resilient)"
    Set-ControlToolTip -ControlName "RuleTypeHash" -ToolTip "Hash: SHA256 hash (breaks on updates)"
    Set-ControlToolTip -ControlName "RuleTypePath" -ToolTip "Path: File path (least secure, easily bypassed)"

    # Rule Action Radio Buttons
    Set-ControlToolTip -ControlName "RuleActionAllow" -ToolTip "Allow: Permit execution of this application"
    Set-ControlToolTip -ControlName "RuleActionDeny" -ToolTip "Deny: Block execution of this application"

    # Rule Generation Controls
    Set-ControlToolTip -ControlName "RuleGroupCombo" -ToolTip "Select target AppLocker group for this rule"
    Set-ControlToolTip -ControlName "CustomSidText" -ToolTip "Enter custom SID or group name"
    Set-ControlToolTip -ControlName "LoadCollectedArtifactsBtn" -ToolTip "Load artifacts from previous scans"
    Set-ControlToolTip -ControlName "LoadCollectedEventsBtn" -ToolTip "Load events to create rules from actual usage"
    Set-ControlToolTip -ControlName "DedupeTypeCombo" -ToolTip "Deduplicate by Publisher, Hash, or Path"
    Set-ControlToolTip -ControlName "DedupeBtn" -ToolTip "Remove duplicate entries from the list"
    Set-ControlToolTip -ControlName "ExportArtifactsListBtn" -ToolTip "Export current artifact list to CSV"
    Set-ControlToolTip -ControlName "ImportArtifactsBtn" -ToolTip "Import artifacts from CSV file"
    Set-ControlToolTip -ControlName "ImportFolderBtn" -ToolTip "Import all CSV files from a folder"
    Set-ControlToolTip -ControlName "MergeRulesBtn" -ToolTip "Merge new rules with existing rules"
    Set-ControlToolTip -ControlName "GenerateRulesBtn" -ToolTip "Generate AppLocker rules from selected artifacts (Enter)"
    Set-ControlToolTip -ControlName "AuditToggleBtn" -ToolTip "Toggle all rules between Audit and Enforce mode"
    Set-ControlToolTip -ControlName "RulesSearchBox" -ToolTip "Search artifacts by name, publisher, or path (Ctrl+F)"
    Set-ControlToolTip -ControlName "ClearFilterBtn" -ToolTip "Clear search filter"
    Set-ControlToolTip -ControlName "DefaultDenyRulesBtn" -ToolTip "Add default deny rules for bypass locations (TEMP, Downloads, etc.)"
    Set-ControlToolTip -ControlName "CreateBrowserDenyBtn" -ToolTip "Add rules to deny browsers in admin sessions"

    # Rule Preview Panel Controls
    Set-ControlToolTip -ControlName "ClosePreviewBtn" -ToolTip "Close rule preview panel"
    Set-ControlToolTip -ControlName "ChangeGroupBtn" -ToolTip "Change target group for selected rules"
    Set-ControlToolTip -ControlName "DuplicateRulesBtn" -ToolTip "Duplicate rules to another group"
    Set-ControlToolTip -ControlName "DeleteRulesBtn" -ToolTip "Delete selected rules (Del)"

    # ============================================================
    # EVENTS CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "ScanLocalEventsBtn" -ToolTip "Scan localhost for AppLocker events"
    Set-ControlToolTip -ControlName "ScanRemoteEventsBtn" -ToolTip "Scan selected remote computers for events"
    Set-ControlToolTip -ControlName "RefreshComputersBtn" -ToolTip "Refresh the computer list from AD"
    Set-ControlToolTip -ControlName "ExportEventsBtn" -ToolTip "Export events to CSV for analysis"
    Set-ControlToolTip -ControlName "FilterAllBtn" -ToolTip "Show all event types"
    Set-ControlToolTip -ControlName "FilterAllowedBtn" -ToolTip "Show only allowed events (ID 8002)"
    Set-ControlToolTip -ControlName "FilterBlockedBtn" -ToolTip "Show only blocked events (ID 8004)"
    Set-ControlToolTip -ControlName "FilterAuditBtn" -ToolTip "Show only audit events (ID 8003)"
    Set-ControlToolTip -ControlName "RefreshEventsBtn" -ToolTip "Refresh events view with current filters"

    # ============================================================
    # DEPLOYMENT CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "CreateGP0Btn" -ToolTip "Create and link new AppLocker GPO"
    Set-ControlToolTip -ControlName "DisableGpoBtn" -ToolTip "Unlink and disable AppLocker GPO"
    Set-ControlToolTip -ControlName "ExportRulesBtn" -ToolTip "Export rules to C:\GA-AppLocker\Rules\"
    Set-ControlToolTip -ControlName "ImportRulesBtn" -ToolTip "Import rules into Group Policy"
    Set-ControlToolTip -ControlName "TargetGpoCombo" -ToolTip "Select target GPO for import"
    Set-ControlToolTip -ControlName "ImportModeCombo" -ToolTip "Replace existing rules or Append to them"

    # ============================================================
    # COMPLIANCE CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "ScanLocalComplianceBtn" -ToolTip "Scan localhost for compliance status"
    Set-ControlToolTip -ControlName "ScanSelectedComplianceBtn" -ToolTip "Scan selected computers for compliance"
    Set-ControlToolTip -ControlName "RefreshComplianceListBtn" -ToolTip "Refresh the computer list from AD"
    Set-ControlToolTip -ControlName "GenerateEvidenceBtn" -ToolTip "Generate audit evidence package"

    # ============================================================
    # WINRM CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "CreateWinRMGpoBtn" -ToolTip "Create or update WinRM GPO with required settings"
    Set-ControlToolTip -ControlName "ForceGPUpdateBtn" -ToolTip "Force GPUpdate on all computers (may take time)"
    Set-ControlToolTip -ControlName "EnableWinRMGpoBtn" -ToolTip "Enable WinRM GPO link"
    Set-ControlToolTip -ControlName "DisableWinRMGpoBtn" -ToolTip "Disable WinRM GPO link"

    # ============================================================
    # AD DISCOVERY CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "ADSearchFilter" -ToolTip "AD search filter (* for all, or criteria like WIN-*)"
    Set-ControlToolTip -ControlName "DiscoverComputersBtn" -ToolTip "Discover computers in Active Directory"
    Set-ControlToolTip -ControlName "TestConnectivityBtn" -ToolTip "Test WinRM connectivity to selected systems"
    Set-ControlToolTip -ControlName "SelectAllComputersBtn" -ToolTip "Select all online computers"
    Set-ControlToolTip -ControlName "ScanSelectedBtn" -ToolTip "Scan selected computers"

    # ============================================================
    # GROUP MANAGEMENT CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "ExportGroupsBtn" -ToolTip "Export current group memberships to CSV"
    Set-ControlToolTip -ControlName "DryRunCheck" -ToolTip "Preview changes without applying (Recommended)"
    Set-ControlToolTip -ControlName "AllowRemovalsCheck" -ToolTip "Allow removing users from groups"
    Set-ControlToolTip -ControlName "IncludeProtectedCheck" -ToolTip "Include Tier-0 protected accounts (Caution!)"
    Set-ControlToolTip -ControlName "ImportGroupsBtn" -ToolTip "Import group membership changes from CSV"

    # ============================================================
    # APPLOCKER SETUP CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "OUNameText" -ToolTip "Name for the AppLocker OU (default: AppLocker)"
    Set-ControlToolTip -ControlName "AutoPopulateCheck" -ToolTip "Automatically add Domain Admins to AppLocker groups"
    Set-ControlToolTip -ControlName "BootstrapAppLockerBtn" -ToolTip "Initialize AppLocker OU and groups in AD"
    Set-ControlToolTip -ControlName "RemoveOUProtectionBtn" -ToolTip "Remove OU protection to allow deletion (Requires Domain Admin)"

    # ============================================================
    # GPO QUICK ASSIGNMENT CONTROLS
    # ============================================================
    Set-ControlToolTip -ControlName "DCGPOPhase" -ToolTip "Deployment phase for Domain Controllers (1-4)"
    Set-ControlToolTip -ControlName "DCGPOMode" -ToolTip "Enforcement mode for Domain Controllers"
    Set-ControlToolTip -ControlName "ServersGPOPhase" -ToolTip "Deployment phase for Servers (1-4)"
    Set-ControlToolTip -ControlName "ServersGPOMode" -ToolTip "Enforcement mode for Servers"
    Set-ControlToolTip -ControlName "WorkstationsGPOPhase" -ToolTip "Deployment phase for Workstations (1-4)"
    Set-ControlToolTip -ControlName "WorkstationsGPOMode" -ToolTip "Enforcement mode for Workstations"
    Set-ControlToolTip -ControlName "CreateGPOsBtn" -ToolTip "Create 3 GPOs (DC, Servers, Workstations)"
    Set-ControlToolTip -ControlName "ApplyGPOSettingsBtn" -ToolTip "Apply phase and mode settings to GPOs"
    Set-ControlToolTip -ControlName "LinkGPOsBtn" -ToolTip "Link GPOs to appropriate OUs"

    # ============================================================
    # HELP BUTTONS
    # ============================================================
    Set-ControlToolTip -ControlName "HelpBtnWorkflow" -ToolTip "View complete deployment workflow guide"
    Set-ControlToolTip -ControlName "HelpBtnWhatsNew" -ToolTip "View new features and changes in v1.2.5"
    Set-ControlToolTip -ControlName "HelpBtnPolicyGuide" -ToolTip "View AppLocker policy configuration guide"
    Set-ControlToolTip -ControlName "HelpBtnRules" -ToolTip "View rule creation best practices"
    Set-ControlToolTip -ControlName "HelpBtnTroubleshooting" -ToolTip "View common issues and solutions"

    Write-Log -Level INFO -Message "Enhanced tooltips initialized successfully"
}

function Set-ControlToolTip {
    <#
    .SYNOPSIS
        Set tooltip for a control by name
    .DESCRIPTION
        Creates and assigns a tooltip to a WPF control with
        enhanced display properties (15 second duration, 0.5s delay).
    .PARAMETER ControlName
        Name of the control as defined in XAML
    .PARAMETER ToolTip
        Tooltip text to display
    .EXAMPLE
        Set-ControlToolTip -ControlName "NavDashboard" -ToolTip "View dashboard (Ctrl+D)"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlName,

        [Parameter(Mandatory = $true)]
        [string]$ToolTip
    )

    try {
        $control = $window.FindName($ControlName)
        if ($control) {
            # Create new tooltip
            $newToolTip = [System.Windows.Controls.ToolTip]::new()
            $newToolTip.Content = $ToolTip

            # Set tooltip property
            $control.ToolTip = $newToolTip

            # Set tooltip service properties for better display
            [System.Windows.Controls.ToolTipService]::SetShowDuration($control, 15000)  # 15 seconds
            [System.Windows.Controls.ToolTipService]::SetInitialShowDelay($control, 500)  # 0.5 second delay

            Write-Log -Level VERBOSE -Message "Tooltip set for control: $ControlName"
        }
        else {
            Write-Log -Level WARNING -Message "Control not found for tooltip: $ControlName"
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to set tooltip for $ControlName`: $($_.Exception.Message)"
    }
}

# ============================================================
# ADDITIONAL INTEGRATION INSTRUCTIONS
# ============================================================
#
# After inserting the functions above, you need to add these
# integration points in the main script:
#
# 1. In the main window initialization (after $window is created),
#    add this call:
#    Initialize-Tooltips
#
# 2. In each navigation button click handler, add context help:
#    For example, in NavDashboard.Add_Click:
#    Show-ContextHelp -Panel "Dashboard"
#
# 3. Example for all navigation buttons:
#    $NavDashboard.Add_Click({
#        Show-Panel -Name "Dashboard"
#        Show-ContextHelp -Panel "Dashboard"
#    })
#    $NavArtifacts.Add_Click({
#        Show-Panel -Name "Artifacts"
#        Show-ContextHelp -Panel "Artifacts"
#    })
#    $NavRules.Add_Click({
#        Show-Panel -Name "Rules"
#        Show-ContextHelp -Panel "Rules"
#    })
#    ... and so on for all navigation buttons
#
# ============================================================
