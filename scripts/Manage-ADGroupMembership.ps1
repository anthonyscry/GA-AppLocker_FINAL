<#
.SYNOPSIS
    End-to-end AD Group Membership Management Workflow

.DESCRIPTION
    Export AD groups to editable CSV format, then import changes back into AD.
    Features dry-run mode, Tier-0 protection, and optional removals.

    CSV Format:
    GroupName,Members
    Domain Admins,user1;user2;user3
    Backup Operators,svc_backup;SERVER01$

.PARAMETER Action
    "Export" - Export current AD state to CSV
    "Import" - Apply desired state from CSV to AD

.PARAMETER CsvPath
    Path to CSV file (export destination or import source)

.PARAMETER DryRun
    Import only: Preview changes without applying (default: true)

.PARAMETER AllowRemovals
    Import only: Remove members not in CSV (default: false)

.PARAMETER IncludeProtected
    Import only: Allow changes to Tier-0 groups (default: false)

.EXAMPLE
    # Export current state
    .\Manage-ADGroupMembership.ps1 -Action Export -CsvPath .\AD_GroupMembership_Export.csv

.EXAMPLE
    # Import with dry-run (safe preview)
    .\Manage-ADGroupMembership.ps1 -Action Import -CsvPath .\AD_GroupMembership_Desired.csv

.EXAMPLE
    # Apply changes for real (after review)
    .\Manage-ADGroupMembership.ps1 -Action Import -CsvPath .\AD_GroupMembership_Desired.csv -DryRun:$false

.EXAMPLE
    # Apply with removals enabled
    .\Manage-ADGroupMembership.ps1 -Action Import -CsvPath .\AD_GroupMembership_Desired.csv -DryRun:$false -AllowRemovals

.NOTES
    Tier-0 Protected Groups (removals blocked by default):
    - Domain Admins
    - Enterprise Admins
    - Schema Admins
    - Administrators (built-in)
    - Account Operators
    - Backup Operators
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Export", "Import")]
    [string]$Action,

    [string]$CsvPath = ".\AD_GroupMembership.csv",

    [bool]$DryRun = $true,

    [bool]$AllowRemovals = $false,

    [bool]$IncludeProtected = $false
)

#Requires -Modules ActiveDirectory

# ---- TIER-0 PROTECTED GROUPS ----
$ProtectedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Group Policy Creator Owners"
)

# ---- LOGGING FUNCTION ----
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
}

# ---- EXPORT FUNCTION ----
function Export-ADGroupMembership {
    param([string]$Path)

    Write-Log "Starting AD group membership export..." "INFO"

    try {
        $groupCount = 0
        $results = Get-ADGroup -Filter * |
            ForEach-Object {
                $group = $_
                $groupCount++

                Write-Progress -Activity "Exporting AD Groups" -Status "Processing $($group.Name)" -PercentComplete (($groupCount / (Get-ADGroup -Filter * | Measure-Object).Count) * 100)

                $Members = Get-ADGroupMember $group -Recursive:$false -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty SamAccountName

                [PSCustomObject]@{
                    GroupName = $group.Name
                    Members   = ($Members -join ';')
                }
            }

        $results | Export-Csv $Path -NoTypeInformation -Encoding UTF8

        $actualCount = (Import-Csv $Path).Count
        Write-Log "Export complete: $Path" "SUCCESS"
        Write-Log "Exported $actualCount groups" "INFO"
        Write-Log "Full path: $((Get-Item $Path).FullName)" "INFO"

        # Create template for desired state
        $desiredPath = $Path -replace '_Export\.csv$', '_Desired.csv'
        if ($desiredPath -eq $Path) {
            $desiredPath = $Path -replace '\.csv$', '_Desired.csv'
        }

        Copy-Item $Path $desiredPath -Force
        Write-Log "Template created for editing: $desiredPath" "INFO"
        Write-Log "Edit the Desired file, then run Import action" "WARNING"

    }
    catch {
        Write-Log "Export failed: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}

# ---- IMPORT FUNCTION ----
function Import-ADGroupMembership {
    param(
        [string]$Path,
        [bool]$Preview,
        [bool]$Removals,
        [bool]$IncludeProtected
    )

    Write-Log "Starting AD group membership import..." "INFO"
    Write-Log "Configuration:" "INFO"
    Write-Log "  Dry Run: $Preview" "INFO"
    Write-Log "  Allow Removals: $Removals" "INFO"
    Write-Log "  Include Protected Groups: $IncludeProtected" "INFO"

    if (-not (Test-Path $Path)) {
        Write-Log "CSV file not found: $Path" "ERROR"
        exit 1
    }

    $DesiredGroups = Import-Csv $Path

    if (-not $DesiredGroups) {
        Write-Log "No data found in CSV file" "ERROR"
        exit 1
    }

    # Track statistics
    $stats = @{
        TotalGroups    = 0
        GroupsProcessed = 0
        Adds           = 0
        Removals       = 0
        Errors         = 0
        Skipped        = 0
    }
    $stats.TotalGroups = $DesiredGroups.Count

    Write-Log "Processing $($stats.TotalGroups) groups from CSV..." "INFO"

    foreach ($Row in $DesiredGroups) {

        $GroupName = $Row.GroupName
        $DesiredMembers = $Row.Members -split ';' | Where-Object { $_ -ne "" }

        Write-Host "`n========================================" -ForegroundColor DarkGray
        Write-Log "GROUP: $GroupName" "INFO"
        Write-Host "========================================" -ForegroundColor DarkGray

        # Check if protected
        if (($ProtectedGroups -contains $GroupName) -and -not $IncludeProtected) {
            Write-Log "Protected group detected - skipping changes" "WARNING"
            Write-Log "Use -IncludeProtected to modify Tier-0 groups" "WARNING"
            $stats.Skipped++
            continue
        }

        try {
            $Group = Get-ADGroup $GroupName -ErrorAction Stop
        }
        catch {
            Write-Log "Group not found in AD: $GroupName" "ERROR"
            $stats.Errors++
            continue
        }

        $stats.GroupsProcessed++

        $CurrentMembers = Get-ADGroupMember $Group -Recursive:$false -ErrorAction SilentlyContinue
        $CurrentSam = @($CurrentMembers | ForEach-Object { $_.SamAccountName })

        # ---- ADD MISSING MEMBERS ----
        foreach ($Member in $DesiredMembers) {
            if ($CurrentSam -notcontains $Member) {

                # Verify member exists
                try {
                    $null = Get-ADObject -LDAPFilter "(sAMAccountName=$Member)" -ErrorAction Stop
                }
                catch {
                    Write-Log "Member not found in AD: $Member" "ERROR"
                    continue
                }

                Write-Log "[ADD] $Member -> $GroupName" "SUCCESS"

                if (-not $Preview) {
                    try {
                        Add-ADGroupMember -Identity $GroupName -Members $Member -ErrorAction Stop
                        $stats.Adds++
                    }
                    catch {
                        Write-Log "Failed to add $Member`: $($_.Exception.Message)" "ERROR"
                        $stats.Errors++
                    }
                }
                else {
                    $stats.Adds++
                }
            }
        }

        # ---- REMOVE EXTRA MEMBERS (OPTIONAL) ----
        if ($Removals) {
            foreach ($Existing in $CurrentMembers) {
                if ($DesiredMembers -notcontains $Existing.SamAccountName) {

                    Write-Log "[REMOVE] $($Existing.SamAccountName) <- $GroupName" "WARNING"

                    if (-not $Preview) {
                        try {
                            Remove-ADGroupMember `
                                -Identity $GroupName `
                                -Members $Existing.SamAccountName `
                                -Confirm:$false `
                                -ErrorAction Stop
                            $stats.Removals++
                        }
                        catch {
                            Write-Log "Failed to remove $($Existing.SamAccountName): $($_.Exception.Message)" "ERROR"
                            $stats.Errors++
                        }
                    }
                    else {
                        $stats.Removals++
                    }
                }
            }
        }
    }

    # ---- SUMMARY ----
    Write-Host "`n========================================" -ForegroundColor DarkGray
    Write-Log "IMPORT SUMMARY" "INFO"
    Write-Host "========================================" -ForegroundColor DarkGray
    Write-Log "Total Groups in CSV: $($stats.TotalGroups)" "INFO"
    Write-Log "Groups Processed: $($stats.GroupsProcessed)" "INFO"
    Write-Log "Skipped (Protected): $($stats.Skipped)" "INFO"
    Write-Log "Adds: $($stats.Adds)" "SUCCESS"
    Write-Log "Removals: $($stats.Removals)" "WARNING"
    Write-Log "Errors: $($stats.Errors)" "ERROR"
    Write-Host "========================================" -ForegroundColor DarkGray

    if ($Preview) {
        Write-Log "DRY RUN COMPLETE - No changes were applied" "WARNING"
        Write-Log "Re-run with -DryRun:`$false to apply changes" "INFO"
    }
    else {
        Write-Log "CHANGES APPLIED TO ACTIVE DIRECTORY" "SUCCESS"
    }

    # Safety reminder
    if ($stats.Errors -gt 0) {
        Write-Log "Review errors above before re-running" "WARNING"
    }
}

# ---- MAIN EXECUTION ----
switch ($Action) {
    "Export" {
        Export-ADGroupMembership -Path $CsvPath
    }
    "Import" {
        Import-ADGroupMembership -Path $CsvPath -Preview $DryRun -Removals $AllowRemovals -IncludeProtected $IncludeProtected
    }
}
