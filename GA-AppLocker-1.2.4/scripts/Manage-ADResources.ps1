<#
.SYNOPSIS
    Consolidated Active Directory management for AppLocker deployments.

.DESCRIPTION
    This script combines AD resource management functions into a single tool:

    - CreateStructure: Creates AppLocker OUs and security groups in AD
    - ExportUsers: Exports AD users and their group memberships to CSV
    - ImportUsers: Applies group membership changes from CSV to AD
    - ExportComputers: Exports computer names from AD to a text file for scanning

    This consolidation simplifies AD management for AppLocker deployments by
    providing a single entry point for all AD operations.

.PARAMETER Action
    The action to perform:
    - CreateStructure: Create AppLocker AD OUs and security groups
    - ExportUsers: Export user group memberships to CSV for editing
    - ImportUsers: Import group membership changes from CSV
    - ExportComputers: Export computer names to text file for scanning

.PARAMETER DomainName
    NetBIOS domain name for CreateStructure action.

.PARAMETER ParentOU
    Parent OU distinguished name for CreateStructure action.

.PARAMETER OUName
    Name for the AppLocker OU (default: "AppLocker").

.PARAMETER GroupPrefix
    Prefix for security group names (default: "AppLocker").

.PARAMETER GroupScope
    Security group scope: DomainLocal, Global, or Universal (default: Global).

.PARAMETER SearchBase
    OU to search for ExportUsers action.

.PARAMETER InputPath
    CSV file path for ImportUsers action. Supports two formats:
    - Simple format: Two columns (Group, Users) - one row per group with list of users
    - Full format: Export format with SamAccountName, AddToGroups, RemoveFromGroups columns

.PARAMETER OutputPath
    Output file path for ExportUsers action.

.PARAMETER IncludeDisabled
    Include disabled user accounts in ExportUsers.

.PARAMETER Filter
    LDAP filter for ExportUsers action.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    # Create AppLocker AD structure
    .\Manage-ADResources.ps1 -Action CreateStructure -DomainName "CONTOSO"

.EXAMPLE
    # Export users for editing
    .\Manage-ADResources.ps1 -Action ExportUsers -OutputPath ".\Users.csv"

.EXAMPLE
    # Preview group changes
    .\Manage-ADResources.ps1 -Action ImportUsers -InputPath ".\Users.csv" -WhatIf

.EXAMPLE
    # Apply group changes
    .\Manage-ADResources.ps1 -Action ImportUsers -InputPath ".\Users.csv"

.EXAMPLE
    # Import using simple two-column format (Group,Users)
    # CSV contents:
    #   Group,Users
    #   AppLocker-StandardUsers,jsmith;jdoe;asmith
    #   AppLocker-Admins,admin1;admin2
    #   AppLocker-Installers,helpdesk1 helpdesk2
    .\Manage-ADResources.ps1 -Action ImportUsers -InputPath ".\GroupMembers.csv"

.NOTES
    Part of GA-AppLocker toolkit.
    Requires: ActiveDirectory PowerShell module
    Requires: Domain Admin or delegated permissions
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CreateStructure", "ExportUsers", "ImportUsers", "ExportComputers", "ExportGroupsWithMembers", "ExportCategorizedUsers", "UpdateGroupMembership")]
    [string]$Action,

    # CreateStructure parameters
    [string]$DomainName,
    [string]$ParentOU,
    [string]$OUName = "AppLocker",
    [string]$GroupPrefix = "AppLocker",
    [ValidateSet("DomainLocal", "Global", "Universal")]
    [string]$GroupScope = "Global",
    [switch]$CreatePoliciesOU = $true,

    # ExportUsers parameters
    [string]$SearchBase,
    [switch]$IncludeDisabled,
    [string]$Filter,

    # ImportUsers parameters
    [string]$InputPath,
    [switch]$SkipValidation,

    # ExportComputers parameters
    [ValidateSet("All", "Workstations", "Servers", "DomainControllers")]
    [string]$ComputerType = "All",
    [switch]$EnabledOnly = $true,
    [switch]$WindowsOnly = $true,

    # ExportGroupsWithMembers parameters
    [string]$GroupFilter,  # Optional filter like "AppLocker*" or "Domain*"

    # UpdateGroupMembership parameters
    [string]$GroupName,
    [string[]]$AddMembers,
    [string[]]$RemoveMembers,

    # Common parameters
    [string]$OutputPath,
    [string]$LogPath,
    [switch]$Force
)

#Requires -Version 5.1

#region Module Check
Write-Host "Checking prerequisites..." -ForegroundColor Cyan

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  [OK] ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Error "ActiveDirectory PowerShell module is required but not installed."
    Write-Host ""
    Write-Host "To install, run one of the following:" -ForegroundColor Yellow
    Write-Host "  Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    Write-Host "  Windows Server: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
#endregion

#region CreateStructure Function
function Invoke-CreateStructure {
    param(
        [string]$Domain,
        [string]$Parent,
        [string]$OU,
        [string]$Prefix,
        [string]$Scope,
        [switch]$Policies,
        [switch]$NoConfirm
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        $Domain = Read-Host "Enter domain name (e.g., CONTOSO)"
    }

    # Determine Domain DN
    try {
        $domainObj = Get-ADDomain -ErrorAction Stop
        $domainDN = $domainObj.DistinguishedName
        $domainDNS = $domainObj.DNSRoot
        Write-Host "Connected to domain: $domainDNS ($domainDN)" -ForegroundColor Cyan
    }
    catch {
        throw "Failed to connect to Active Directory: $_"
    }

    # Determine parent OU
    if ($Parent) {
        try {
            Get-ADOrganizationalUnit -Identity $Parent -ErrorAction Stop | Out-Null
            $targetParentDN = $Parent
            Write-Host "Parent OU: $Parent" -ForegroundColor Cyan
        }
        catch {
            throw "Parent OU not found: $Parent"
        }
    }
    else {
        $targetParentDN = $domainDN
        Write-Host "Parent: Domain root ($domainDN)" -ForegroundColor Yellow
        Write-Host "  TIP: Use -ParentOU to place under an existing IT/Security OU" -ForegroundColor Gray
    }

    # Define structure
    $appLockerOUDN = "OU=$OU,$targetParentDN"
    $groupsOUDN = "OU=Groups,$appLockerOUDN"
    $policiesOUDN = "OU=Policies,$appLockerOUDN"

    $groups = @(
        @{
            Name        = "$Prefix-Admins"
            Description = "Members bypass all AppLocker restrictions. Add IT administrators and deployment accounts."
            Notes       = "Use sparingly - members can run ANY executable"
        },
        @{
            Name        = "$Prefix-StandardUsers"
            Description = "Standard users subject to AppLocker policy. Add domain users who need standard restrictions."
            Notes       = "Default group for most users"
        },
        @{
            Name        = "$Prefix-ServiceAccounts"
            Description = "Service accounts requiring specific application access beyond standard policy."
            Notes       = "Add accounts running scheduled tasks or services"
        },
        @{
            Name        = "$Prefix-Installers"
            Description = "Users authorized to install software via MSI. More permissive MSI rules apply."
            Notes       = "Software deployment accounts and helpdesk staff"
        }
    )

    # Display plan
    Write-Host ""
    Write-Host "The following will be created:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Organizational Units:" -ForegroundColor White
    Write-Host "    [OU] $appLockerOUDN" -ForegroundColor Gray
    Write-Host "    [OU] $groupsOUDN" -ForegroundColor Gray
    if ($Policies) {
        Write-Host "    [OU] $policiesOUDN" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  Security Groups (in Groups OU):" -ForegroundColor White
    foreach ($group in $groups) {
        Write-Host "    [Group] $Domain\$($group.Name)" -ForegroundColor Gray
    }
    Write-Host ""

    # Confirmation
    if (-not $NoConfirm -and -not $WhatIfPreference) {
        $confirm = Read-Host "Create this structure? (Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return
        }
    }

    # Create OUs
    $created = @{ OUs = @(); Groups = @(); Skipped = @() }

    # Main OU
    try {
        $existingOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$appLockerOUDN'" -ErrorAction SilentlyContinue
        if ($existingOU) {
            Write-Host "[SKIP] OU already exists: $appLockerOUDN" -ForegroundColor Yellow
            $created.Skipped += $appLockerOUDN
        }
        else {
            if ($PSCmdlet.ShouldProcess($appLockerOUDN, "Create Organizational Unit")) {
                New-ADOrganizationalUnit -Name $OU -Path $targetParentDN -Description "AppLocker management structure" -ProtectedFromAccidentalDeletion $true
                Write-Host "[CREATED] OU: $appLockerOUDN" -ForegroundColor Green
                $created.OUs += $appLockerOUDN
            }
        }
    }
    catch {
        Write-Warning "Failed to create OU $appLockerOUDN : $_"
    }

    # Groups OU
    try {
        $existingGroupsOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$groupsOUDN'" -ErrorAction SilentlyContinue
        if ($existingGroupsOU) {
            Write-Host "[SKIP] OU already exists: $groupsOUDN" -ForegroundColor Yellow
            $created.Skipped += $groupsOUDN
        }
        else {
            if ($PSCmdlet.ShouldProcess($groupsOUDN, "Create Organizational Unit")) {
                New-ADOrganizationalUnit -Name "Groups" -Path $appLockerOUDN -Description "AppLocker security groups" -ProtectedFromAccidentalDeletion $true
                Write-Host "[CREATED] OU: $groupsOUDN" -ForegroundColor Green
                $created.OUs += $groupsOUDN
            }
        }
    }
    catch {
        Write-Warning "Failed to create Groups OU: $_"
    }

    # Policies OU
    if ($Policies) {
        try {
            $existingPoliciesOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$policiesOUDN'" -ErrorAction SilentlyContinue
            if ($existingPoliciesOU) {
                Write-Host "[SKIP] OU already exists: $policiesOUDN" -ForegroundColor Yellow
                $created.Skipped += $policiesOUDN
            }
            else {
                if ($PSCmdlet.ShouldProcess($policiesOUDN, "Create Organizational Unit")) {
                    New-ADOrganizationalUnit -Name "Policies" -Path $appLockerOUDN -Description "Computer accounts receiving AppLocker GPOs" -ProtectedFromAccidentalDeletion $true
                    Write-Host "[CREATED] OU: $policiesOUDN" -ForegroundColor Green
                    $created.OUs += $policiesOUDN
                }
            }
        }
        catch {
            Write-Warning "Failed to create Policies OU: $_"
        }
    }

    # Create Groups
    Write-Host ""
    foreach ($group in $groups) {
        $groupName = $group.Name
        try {
            $existingGroup = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            if ($existingGroup) {
                Write-Host "[SKIP] Group already exists: $groupName" -ForegroundColor Yellow
                $created.Skipped += $groupName
            }
            else {
                if ($PSCmdlet.ShouldProcess("$Domain\$groupName", "Create Security Group")) {
                    New-ADGroup -Name $groupName `
                        -SamAccountName $groupName `
                        -GroupCategory Security `
                        -GroupScope $Scope `
                        -DisplayName $groupName `
                        -Path $groupsOUDN `
                        -Description $group.Description

                    Set-ADGroup -Identity $groupName -Replace @{info = $group.Notes }

                    Write-Host "[CREATED] Group: $Domain\$groupName" -ForegroundColor Green
                    $created.Groups += $groupName
                }
            }
        }
        catch {
            Write-Warning "Failed to create group $groupName : $_"
        }
    }

    # Summary
    Write-Host ""
    Write-Host "=== SETUP COMPLETE ===" -ForegroundColor Cyan
    Write-Host "Created: $($created.OUs.Count) OUs, $($created.Groups.Count) Groups" -ForegroundColor White
    if ($created.Skipped.Count -gt 0) {
        Write-Host "Skipped (already existed): $($created.Skipped.Count)" -ForegroundColor Yellow
    }

    return @{
        AppLockerOU     = $appLockerOUDN
        GroupsOU        = $groupsOUDN
        PoliciesOU      = $policiesOUDN
        Groups          = @{
            Admins          = "$Domain\$Prefix-Admins"
            StandardUsers   = "$Domain\$Prefix-StandardUsers"
            ServiceAccounts = "$Domain\$Prefix-ServiceAccounts"
            Installers      = "$Domain\$Prefix-Installers"
        }
    }
}
#endregion

#region ExportUsers Function
function Invoke-ExportUsers {
    param(
        [string]$Search,
        [string]$Output,
        [switch]$Disabled,
        [string]$UserFilter
    )

    if ([string]::IsNullOrWhiteSpace($Output)) {
        $Output = ".\ADUserGroups-Export.csv"
    }

    Write-Host @"

================================================================================
                    AD User Group Membership Export Tool
================================================================================
"@ -ForegroundColor Cyan

    # Build LDAP filter
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)"
    if (-not $Disabled) {
        $ldapFilter += "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        Write-Host "Filter: Enabled accounts only" -ForegroundColor Gray
    }
    else {
        Write-Host "Filter: Including disabled accounts" -ForegroundColor Gray
    }

    if ($UserFilter) {
        $ldapFilter += $UserFilter
        Write-Host "Custom filter: $UserFilter" -ForegroundColor Gray
    }
    $ldapFilter += ")"

    # Query AD
    Write-Host ""
    Write-Host "Querying Active Directory..." -ForegroundColor Yellow

    $adParams = @{
        LDAPFilter = $ldapFilter
        Properties = @("DisplayName", "EmailAddress", "Enabled", "Department", "Title", "MemberOf", "Description")
    }

    if ($Search) {
        $adParams.SearchBase = $Search
        Write-Host "  Search scope: $Search" -ForegroundColor Gray
    }
    else {
        Write-Host "  Search scope: Entire domain" -ForegroundColor Gray
    }

    try {
        $users = Get-ADUser @adParams
        Write-Host "  Found $($users.Count) users" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to query Active Directory: $_"
        return
    }

    if ($users.Count -eq 0) {
        Write-Warning "No users found matching the specified criteria."
        return
    }

    # Process users
    Write-Host ""
    Write-Host "Processing user group memberships..." -ForegroundColor Yellow

    $results = @()
    $counter = 0
    $total = $users.Count

    foreach ($user in $users) {
        $counter++
        $percentComplete = [math]::Round(($counter / $total) * 100)
        Write-Progress -Activity "Processing Users" -Status "$counter of $total - $($user.SamAccountName)" -PercentComplete $percentComplete

        $groupNames = @()
        if ($user.MemberOf) {
            foreach ($groupDN in $user.MemberOf) {
                try {
                    $groupName = ($groupDN -split ',')[0] -replace '^CN=', ''
                    $groupNames += $groupName
                }
                catch {
                    $groupNames += $groupDN
                }
            }
        }
        $groupNames = $groupNames | Sort-Object

        $results += [PSCustomObject]@{
            SamAccountName    = $user.SamAccountName
            DisplayName       = $user.DisplayName
            EmailAddress      = $user.EmailAddress
            Enabled           = $user.Enabled
            Department        = $user.Department
            Title             = $user.Title
            Description       = $user.Description
            DistinguishedName = $user.DistinguishedName
            CurrentGroups     = ($groupNames -join "; ")
            AddToGroups       = ""
            RemoveFromGroups  = ""
        }
    }

    Write-Progress -Activity "Processing Users" -Completed

    # Export full format
    Write-Host ""
    Write-Host "Exporting to CSV..." -ForegroundColor Yellow

    try {
        $results | Export-Csv -Path $Output -NoTypeInformation -Encoding UTF8
        $fullPath = (Resolve-Path $Output).Path

        Write-Host ""
        Write-Host "=== EXPORT COMPLETE ===" -ForegroundColor Green
        Write-Host "  Full export: $fullPath" -ForegroundColor Cyan
        Write-Host "  Users exported: $($results.Count)" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Failed to export CSV: $_"
        return
    }

    # Also create groups.csv (Group, Users format for easy import)
    Write-Host ""
    Write-Host "Creating groups.csv (simple import format)..." -ForegroundColor Yellow

    try {
        # Build group -> users mapping
        $groupMembers = @{}
        foreach ($user in $users) {
            $username = $user.SamAccountName
            if ($user.MemberOf) {
                foreach ($groupDN in $user.MemberOf) {
                    $groupName = ($groupDN -split ',')[0] -replace '^CN=', ''
                    if (-not $groupMembers.ContainsKey($groupName)) {
                        $groupMembers[$groupName] = @()
                    }
                    $groupMembers[$groupName] += $username
                }
            }
        }

        # Create group-centric output with sorted usernames
        $groupExport = @()
        foreach ($groupName in ($groupMembers.Keys | Sort-Object)) {
            $sortedUsers = $groupMembers[$groupName] | Sort-Object
            $groupExport += [PSCustomObject]@{
                Group = $groupName
                Users = ($sortedUsers -join ";")
            }
        }

        $groupsPath = Join-Path (Split-Path $Output -Parent) "groups.csv"
        $groupExport | Export-Csv -Path $groupsPath -NoTypeInformation -Encoding UTF8
        $fullGroupsPath = (Resolve-Path $groupsPath).Path

        Write-Host "  Groups export: $fullGroupsPath" -ForegroundColor Cyan
        Write-Host "  Groups found: $($groupExport.Count)" -ForegroundColor Cyan

        # Create users.csv with all usernames separated by semicolons
        $allUsernames = ($users | ForEach-Object { $_.SamAccountName } | Sort-Object -Unique) -join ";"
        $usersPath = Join-Path (Split-Path $Output -Parent) "users.csv"
        [PSCustomObject]@{ Username = $allUsernames } | Export-Csv -Path $usersPath -NoTypeInformation -Encoding UTF8
        $fullUsersPath = (Resolve-Path $usersPath).Path
        Write-Host "  Users export: $fullUsersPath" -ForegroundColor Cyan

        Write-Host ""
        Write-Host "To import group changes:" -ForegroundColor Yellow
        Write-Host "  .\Manage-ADResources.ps1 -Action ImportUsers -InputPath `"$fullGroupsPath`"" -ForegroundColor Cyan
        Write-Host "  Or use the default: .\ADManagement\groups.csv" -ForegroundColor DarkGray

        return $fullPath
    }
    catch {
        Write-Warning "Failed to create groups.csv: $_"
        return $fullPath
    }
}
#endregion

#region ImportUsers Function
function Invoke-ImportUsers {
    param(
        [string]$InputFile,
        [string]$Log,
        [switch]$NoValidation
    )

    if ([string]::IsNullOrWhiteSpace($Log)) {
        $Log = ".\ADUserGroups-ChangeLog.csv"
    }

    $previewMode = $WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')

    Write-Host @"

================================================================================
                    AD User Group Membership Import Tool
================================================================================
"@ -ForegroundColor Cyan

    if ($previewMode) {
        Write-Host "                         *** PREVIEW MODE (WhatIf) ***" -ForegroundColor Yellow
        Write-Host "                    No changes will be made to Active Directory" -ForegroundColor Yellow
    }

    # Load CSV
    Write-Host ""
    Write-Host "Loading CSV file..." -ForegroundColor Yellow
    Write-Host "  Input: $InputFile" -ForegroundColor Gray

    try {
        $csvData = Import-Csv -Path $InputFile -Encoding UTF8

        if ($csvData.Count -eq 0) {
            Write-Error "CSV file is empty."
            return
        }

        $csvColumns = $csvData[0].PSObject.Properties.Name

        # Detect format: Group-based (Group, Users) or Full (SamAccountName, AddToGroups, RemoveFromGroups)
        $simpleFormat = $false
        $groupColumn = $null
        $usersColumn = $null

        # Check for simple group-based format - look for Group and Users columns
        foreach ($col in $csvColumns) {
            if ($col -match '^(Group|GroupName|AppLockerGroup)$') {
                $groupColumn = $col
            }
            if ($col -match '^(Users|User|Usernames|Username|Members)$') {
                $usersColumn = $col
            }
        }

        if ($groupColumn -and $usersColumn) {
            $simpleFormat = $true
            Write-Host "  [OK] Detected simple format (Group, Users)" -ForegroundColor Green
            Write-Host "  [OK] CSV loaded - $($csvData.Count) rows" -ForegroundColor Green
        }
        else {
            # Check for full format
            $requiredColumns = @('SamAccountName', 'AddToGroups', 'RemoveFromGroups')
            foreach ($col in $requiredColumns) {
                if ($col -notin $csvColumns) {
                    Write-Host ""
                    Write-Host "CSV format not recognized. Supported formats:" -ForegroundColor Red
                    Write-Host ""
                    Write-Host "  Simple format (Group, Users):" -ForegroundColor Yellow
                    Write-Host "    Group,Users" -ForegroundColor Gray
                    Write-Host "    AppLocker-StandardUsers,jsmith;jdoe;asmith" -ForegroundColor Gray
                    Write-Host "    AppLocker-Admins,admin1" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  Full format (from ExportUsers):" -ForegroundColor Yellow
                    Write-Host "    SamAccountName,AddToGroups,RemoveFromGroups,..." -ForegroundColor Gray
                    Write-Host ""
                    Write-Error "Required column '$col' not found in CSV file."
                    return
                }
            }
            Write-Host "  [OK] Detected full export format" -ForegroundColor Green
            Write-Host "  [OK] CSV loaded - $($csvData.Count) rows" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to load CSV: $_"
        return
    }

    # Handle simple format - convert to standard processing format
    if ($simpleFormat) {
        Write-Host ""
        Write-Host "Processing simple format import..." -ForegroundColor Yellow

        # Parse group-based format and convert to user-based format
        $userGroups = @{}
        foreach ($row in $csvData) {
            # Sanitize group name - remove quotes and trim
            $group = $row.$groupColumn.Trim().Trim('"').Trim("'").Trim()
            $usersRaw = $row.$usersColumn

            if ([string]::IsNullOrWhiteSpace($group) -or [string]::IsNullOrWhiteSpace($usersRaw)) {
                continue
            }

            # Split users by semicolon, comma, or space and sanitize
            $users = $usersRaw -split '[;,\s]+' | ForEach-Object {
                # Remove any surrounding quotes and trim whitespace
                $_.Trim().Trim('"').Trim("'").Trim()
            } | Where-Object { $_ -ne "" }

            foreach ($username in $users) {
                if (-not $userGroups.ContainsKey($username)) {
                    $userGroups[$username] = @()
                }
                $userGroups[$username] += $group
            }
        }

        # Convert to standard format for processing
        $csvData = @()
        foreach ($username in $userGroups.Keys) {
            $csvData += [PSCustomObject]@{
                SamAccountName   = $username
                AddToGroups      = ($userGroups[$username] -join "; ")
                RemoveFromGroups = ""
            }
        }

        Write-Host "  Found $($userGroups.Count) unique users across $($csvData.Count) group assignments" -ForegroundColor Cyan

        # Check for potential group names in user list (common data entry error)
        $suspiciousUsernames = $userGroups.Keys | Where-Object {
            $_ -match '^(AppLocker-|AD-|Domain |Security-|GRP-|GRP_|Group-)' -or
            $_ -match '(Admins|Users|ServiceAccounts|Installers|Operators)$'
        }
        if ($suspiciousUsernames.Count -gt 0) {
            Write-Host ""
            Write-Host "  [WARNING] The following entries in the Users column look like group names:" -ForegroundColor Yellow
            foreach ($suspect in $suspiciousUsernames) {
                Write-Host "    - $suspect" -ForegroundColor Yellow
            }
            Write-Host "  If these are AD groups, move them to the Group column instead." -ForegroundColor Yellow
            Write-Host ""
        }
    }

    # Find rows with changes
    Write-Host ""
    Write-Host "Analyzing changes..." -ForegroundColor Yellow

    $rowsWithChanges = $csvData | Where-Object {
        ($_.AddToGroups -and $_.AddToGroups.Trim() -ne "") -or
        ($_.RemoveFromGroups -and $_.RemoveFromGroups.Trim() -ne "")
    }

    if ($rowsWithChanges.Count -eq 0) {
        Write-Host "  No changes detected in CSV file." -ForegroundColor Yellow
        return
    }

    Write-Host "  Found $($rowsWithChanges.Count) users with pending changes" -ForegroundColor Cyan

    # Collect unique groups (with sanitization to remove quotes)
    $allGroupNames = @()
    foreach ($row in $rowsWithChanges) {
        if ($row.AddToGroups -and $row.AddToGroups.Trim() -ne "") {
            $groups = $row.AddToGroups -split ';' | ForEach-Object { $_.Trim().Trim('"').Trim("'").Trim() } | Where-Object { $_ -ne "" }
            $allGroupNames += $groups
        }
        if ($row.RemoveFromGroups -and $row.RemoveFromGroups.Trim() -ne "") {
            $groups = $row.RemoveFromGroups -split ';' | ForEach-Object { $_.Trim().Trim('"').Trim("'").Trim() } | Where-Object { $_ -ne "" }
            $allGroupNames += $groups
        }
    }
    $uniqueGroups = $allGroupNames | Select-Object -Unique
    Write-Host "  Unique groups referenced: $($uniqueGroups.Count)" -ForegroundColor Gray

    # Validate groups
    if (-not $NoValidation) {
        Write-Host ""
        Write-Host "Validating groups in Active Directory..." -ForegroundColor Yellow

        $validGroups = @{}
        $invalidGroups = @()

        foreach ($groupName in $uniqueGroups) {
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                if ($group) {
                    $validGroups[$groupName] = $group.DistinguishedName
                    Write-Host "  [OK] $groupName" -ForegroundColor Green
                }
                else {
                    $invalidGroups += $groupName
                    Write-Host "  [NOT FOUND] $groupName" -ForegroundColor Red
                }
            }
            catch {
                $invalidGroups += $groupName
                Write-Host "  [ERROR] $groupName - $_" -ForegroundColor Red
            }
        }

        if ($invalidGroups.Count -gt 0) {
            Write-Error "The following groups were not found in Active Directory:"
            $invalidGroups | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            Write-Host ""
            Write-Host "Use -SkipValidation to bypass this check (not recommended)." -ForegroundColor Gray
            return
        }
    }

    # Process changes
    Write-Host ""
    Write-Host "Processing group membership changes..." -ForegroundColor Yellow
    Write-Host ""

    $changeLog = @()
    $addSuccess = 0
    $addFailed = 0
    $removeSuccess = 0
    $removeFailed = 0

    foreach ($row in $rowsWithChanges) {
        # Sanitize username - remove any quotes that may have been in the CSV
        $username = $row.SamAccountName.Trim().Trim('"').Trim("'").Trim()
        Write-Host "Processing: $username" -ForegroundColor Cyan

        try {
            $user = Get-ADUser -Identity $username -ErrorAction Stop
        }
        catch {
            Write-Host "  [ERROR] User not found: $username" -ForegroundColor Red
            $changeLog += [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                User      = $username
                Action    = "ERROR"
                Group     = "N/A"
                Result    = "User not found in AD"
            }
            continue
        }

        # Process additions
        if ($row.AddToGroups -and $row.AddToGroups.Trim() -ne "") {
            $groupsToAdd = $row.AddToGroups -split ';' | ForEach-Object { $_.Trim().Trim('"').Trim("'").Trim() } | Where-Object { $_ -ne "" }

            foreach ($groupName in $groupsToAdd) {
                $logEntry = [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    User      = $username
                    Action    = "ADD"
                    Group     = $groupName
                    Result    = ""
                }

                if ($previewMode) {
                    Write-Host "  [WOULD ADD] $username -> $groupName" -ForegroundColor Yellow
                    $logEntry.Result = "PREVIEW - Would add"
                }
                else {
                    try {
                        Add-ADGroupMember -Identity $groupName -Members $user -ErrorAction Stop
                        Write-Host "  [ADDED] $username -> $groupName" -ForegroundColor Green
                        $logEntry.Result = "SUCCESS"
                        $addSuccess++
                    }
                    catch {
                        if ($_ -match "already a member") {
                            Write-Host "  [SKIP] $username already member of $groupName" -ForegroundColor Gray
                            $logEntry.Result = "SKIPPED - Already member"
                        }
                        else {
                            Write-Host "  [FAILED] Add $username to $groupName - $_" -ForegroundColor Red
                            $logEntry.Result = "FAILED - $_"
                            $addFailed++
                        }
                    }
                }
                $changeLog += $logEntry
            }
        }

        # Process removals
        if ($row.RemoveFromGroups -and $row.RemoveFromGroups.Trim() -ne "") {
            $groupsToRemove = $row.RemoveFromGroups -split ';' | ForEach-Object { $_.Trim().Trim('"').Trim("'").Trim() } | Where-Object { $_ -ne "" }

            foreach ($groupName in $groupsToRemove) {
                $logEntry = [PSCustomObject]@{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    User      = $username
                    Action    = "REMOVE"
                    Group     = $groupName
                    Result    = ""
                }

                if ($previewMode) {
                    Write-Host "  [WOULD REMOVE] $username <- $groupName" -ForegroundColor Yellow
                    $logEntry.Result = "PREVIEW - Would remove"
                }
                else {
                    try {
                        Remove-ADGroupMember -Identity $groupName -Members $user -Confirm:$false -ErrorAction Stop
                        Write-Host "  [REMOVED] $username <- $groupName" -ForegroundColor Green
                        $logEntry.Result = "SUCCESS"
                        $removeSuccess++
                    }
                    catch {
                        if ($_ -match "not a member") {
                            Write-Host "  [SKIP] $username not a member of $groupName" -ForegroundColor Gray
                            $logEntry.Result = "SKIPPED - Not a member"
                        }
                        else {
                            Write-Host "  [FAILED] Remove $username from $groupName - $_" -ForegroundColor Red
                            $logEntry.Result = "FAILED - $_"
                            $removeFailed++
                        }
                    }
                }
                $changeLog += $logEntry
            }
        }
        Write-Host ""
    }

    # Export log
    if ($changeLog.Count -gt 0) {
        try {
            $changeLog | Export-Csv -Path $Log -NoTypeInformation -Encoding UTF8
            $fullLogPath = (Resolve-Path $Log).Path
            Write-Host "Change log saved: $fullLogPath" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Failed to save change log: $_"
        }
    }

    # Summary
    Write-Host ""
    Write-Host "=== IMPORT COMPLETE ===" -ForegroundColor Green

    if ($previewMode) {
        $wouldAdd = ($changeLog | Where-Object { $_.Action -eq "ADD" }).Count
        $wouldRemove = ($changeLog | Where-Object { $_.Action -eq "REMOVE" }).Count
        Write-Host "  Would add to groups:      $wouldAdd" -ForegroundColor Yellow
        Write-Host "  Would remove from groups: $wouldRemove" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To apply these changes, run without -WhatIf" -ForegroundColor Cyan
    }
    else {
        Write-Host "  Successful additions:     $addSuccess" -ForegroundColor Green
        Write-Host "  Failed additions:         $addFailed" -ForegroundColor $(if ($addFailed -gt 0) { "Red" } else { "Gray" })
        Write-Host "  Successful removals:      $removeSuccess" -ForegroundColor Green
        Write-Host "  Failed removals:          $removeFailed" -ForegroundColor $(if ($removeFailed -gt 0) { "Red" } else { "Gray" })
    }
}
#endregion

#region ExportComputers Function
function Invoke-ExportComputers {
    <#
    .SYNOPSIS
    Exports computer names from Active Directory to a text file for scanning.
    #>
    param(
        [string]$Output,
        [string]$Type = "All",
        [string]$Search,
        [switch]$EnabledOnly = $true,
        [switch]$WindowsOnly = $true
    )

    Write-Host "`n=== Export AD Computers ===" -ForegroundColor Cyan

    # Build filter based on computer type
    $ldapFilter = switch ($Type) {
        "Workstations" {
            # Workstations - NOT servers, NOT domain controllers
            "(&(objectCategory=computer)(!(operatingSystem=*Server*))(!(primaryGroupID=516)))"
        }
        "Servers" {
            # Servers - Server OS but NOT domain controllers
            "(&(objectCategory=computer)(operatingSystem=*Server*)(!(primaryGroupID=516)))"
        }
        "DomainControllers" {
            # Domain Controllers only
            "(&(objectCategory=computer)(primaryGroupID=516))"
        }
        default {
            # All computers
            "(objectCategory=computer)"
        }
    }

    # Add enabled filter if requested
    if ($EnabledOnly) {
        $ldapFilter = "(&$ldapFilter(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    }

    # Add Windows OS filter if requested
    if ($WindowsOnly) {
        $ldapFilter = "(&$ldapFilter(operatingSystem=*Windows*))"
    }

    Write-Host "  Computer type: $Type" -ForegroundColor Gray
    Write-Host "  Enabled only: $EnabledOnly" -ForegroundColor Gray
    Write-Host "  Windows only: $WindowsOnly" -ForegroundColor Gray
    Write-Host "  LDAP Filter: $ldapFilter" -ForegroundColor DarkGray

    try {
        # Get computers from AD
        $getParams = @{
            LDAPFilter = $ldapFilter
            Properties = @("Name", "DNSHostName", "OperatingSystem", "Enabled", "LastLogonDate")
        }
        if (-not [string]::IsNullOrWhiteSpace($Search)) {
            $getParams.SearchBase = $Search
        }

        $computers = Get-ADComputer @getParams | Sort-Object Name

        if ($computers.Count -eq 0) {
            Write-Host "  [-] No computers found matching criteria" -ForegroundColor Yellow
            return
        }

        Write-Host "  [+] Found $($computers.Count) computers" -ForegroundColor Green

        # Export to CSV with ComputerName column
        $computers | Select-Object @{N='ComputerName';E={$_.Name}}, OperatingSystem, Enabled, LastLogonDate |
            Export-Csv -Path $Output -NoTypeInformation -Encoding UTF8

        Write-Host "  [+] Exported to: $Output" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Preview (first 10):" -ForegroundColor Yellow
        $computers | Select-Object -First 10 | ForEach-Object {
            Write-Host "    $($_.Name)" -ForegroundColor White
        }
        if ($computers.Count -gt 10) {
            Write-Host "    ... and $($computers.Count - 10) more" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  [-] Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

#region ExportGroupsWithMembers Function
function Invoke-ExportGroupsWithMembers {
    <#
    .SYNOPSIS
    Exports all AD groups with their current members to JSON for GUI consumption
    #>
    param(
        [string]$Output,
        [string]$Filter,
        [string]$Search
    )

    Write-Host "`n=== Export AD Groups with Members ===" -ForegroundColor Cyan

    try {
        # Build filter
        $ldapFilter = "(objectCategory=group)"
        if ($Filter) {
            $ldapFilter = "(&(objectCategory=group)(name=$Filter))"
            Write-Host "  Filter: $Filter" -ForegroundColor Gray
        }

        $getParams = @{
            LDAPFilter = $ldapFilter
            Properties = @("Name", "Description", "GroupCategory", "GroupScope", "Members", "ManagedBy", "DistinguishedName")
        }
        if ($Search) {
            $getParams.SearchBase = $Search
        }

        Write-Host "  Querying groups..." -ForegroundColor Yellow
        $groups = Get-ADGroup @getParams | Sort-Object Name

        if ($groups.Count -eq 0) {
            Write-Host "  [-] No groups found" -ForegroundColor Yellow
            return
        }

        Write-Host "  [+] Found $($groups.Count) groups" -ForegroundColor Green

        # Process each group
        $groupData = @()
        $counter = 0
        foreach ($group in $groups) {
            $counter++
            Write-Progress -Activity "Processing Groups" -Status "$counter of $($groups.Count) - $($group.Name)" -PercentComplete (($counter / $groups.Count) * 100)

            $members = @()
            if ($group.Members) {
                foreach ($memberDN in $group.Members) {
                    try {
                        $member = Get-ADObject -Identity $memberDN -Properties SamAccountName, ObjectClass -ErrorAction SilentlyContinue
                        if ($member) {
                            $members += @{
                                SamAccountName = $member.SamAccountName
                                ObjectClass = $member.ObjectClass
                                DistinguishedName = $memberDN
                            }
                        }
                    }
                    catch {
                        # Skip if can't resolve
                    }
                }
            }

            $groupData += @{
                Name = $group.Name
                Description = $group.Description
                Category = $group.GroupCategory.ToString()
                Scope = $group.GroupScope.ToString()
                MemberCount = $members.Count
                Members = $members
                DistinguishedName = $group.DistinguishedName
            }
        }
        Write-Progress -Activity "Processing Groups" -Completed

        # Export to JSON
        $groupData | ConvertTo-Json -Depth 4 | Out-File -FilePath $Output -Encoding UTF8
        Write-Host "  [+] Exported to: $Output" -ForegroundColor Green
        Write-Host "  [+] Groups: $($groupData.Count)" -ForegroundColor Cyan

        return $groupData
    }
    catch {
        Write-Host "  [-] Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

#region ExportCategorizedUsers Function
function Invoke-ExportCategorizedUsers {
    <#
    .SYNOPSIS
    Exports AD users categorized by type (Standard, Service, Privileged) to JSON
    #>
    param(
        [string]$Output,
        [string]$Search
    )

    Write-Host "`n=== Export Categorized AD Users ===" -ForegroundColor Cyan

    try {
        # Get all enabled users
        $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        $getParams = @{
            LDAPFilter = $ldapFilter
            Properties = @("SamAccountName", "DisplayName", "Description", "Department", "Title",
                          "MemberOf", "ServicePrincipalName", "UserAccountControl", "AdminCount",
                          "PasswordNeverExpires", "DistinguishedName", "Mail", "Enabled")
        }
        if ($Search) {
            $getParams.SearchBase = $Search
        }

        Write-Host "  Querying users..." -ForegroundColor Yellow
        $users = Get-ADUser @getParams

        if ($users.Count -eq 0) {
            Write-Host "  [-] No users found" -ForegroundColor Yellow
            return
        }

        Write-Host "  [+] Found $($users.Count) users" -ForegroundColor Green

        # Get privileged group memberships for categorization
        $privilegedGroups = @(
            "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
            "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
            "DnsAdmins", "Group Policy Creator Owners"
        )

        # Categorize users
        $standardUsers = @()
        $serviceAccounts = @()
        $privilegedAccounts = @()

        $counter = 0
        foreach ($user in $users) {
            $counter++
            Write-Progress -Activity "Categorizing Users" -Status "$counter of $($users.Count)" -PercentComplete (($counter / $users.Count) * 100)

            $userGroups = @()
            if ($user.MemberOf) {
                $userGroups = $user.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }
            }

            $userData = @{
                SamAccountName = $user.SamAccountName
                DisplayName = $user.DisplayName
                Description = $user.Description
                Department = $user.Department
                Title = $user.Title
                Email = $user.Mail
                Groups = $userGroups
                DistinguishedName = $user.DistinguishedName
            }

            # Determine category
            $isPrivileged = $false
            $isService = $false

            # Check for privileged access
            if ($user.AdminCount -eq 1) { $isPrivileged = $true }
            foreach ($pg in $privilegedGroups) {
                if ($userGroups -contains $pg) { $isPrivileged = $true; break }
            }

            # Check for service account indicators
            if ($user.ServicePrincipalName) { $isService = $true }
            if ($user.SamAccountName -match '^(svc|srv|service|sql|app|task|batch|sys)[-_]' -or
                $user.SamAccountName -match '[-_](svc|srv|service)$' -or
                $user.Description -match 'service account|automated|scheduled task') {
                $isService = $true
            }
            if ($user.PasswordNeverExpires -and -not $isPrivileged) { $isService = $true }

            # Categorize
            if ($isPrivileged) {
                $userData.Category = "Privileged"
                $privilegedAccounts += $userData
            }
            elseif ($isService) {
                $userData.Category = "Service"
                $serviceAccounts += $userData
            }
            else {
                $userData.Category = "Standard"
                $standardUsers += $userData
            }
        }
        Write-Progress -Activity "Categorizing Users" -Completed

        # Build output
        $result = @{
            ExportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            TotalUsers = $users.Count
            Categories = @{
                Standard = @{
                    Count = $standardUsers.Count
                    Users = $standardUsers | Sort-Object { $_.SamAccountName }
                }
                Service = @{
                    Count = $serviceAccounts.Count
                    Users = $serviceAccounts | Sort-Object { $_.SamAccountName }
                }
                Privileged = @{
                    Count = $privilegedAccounts.Count
                    Users = $privilegedAccounts | Sort-Object { $_.SamAccountName }
                }
            }
        }

        # Export to JSON
        $result | ConvertTo-Json -Depth 5 | Out-File -FilePath $Output -Encoding UTF8
        Write-Host "  [+] Exported to: $Output" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Summary:" -ForegroundColor Yellow
        Write-Host "    Standard Users:     $($standardUsers.Count)" -ForegroundColor White
        Write-Host "    Service Accounts:   $($serviceAccounts.Count)" -ForegroundColor Cyan
        Write-Host "    Privileged Accounts: $($privilegedAccounts.Count)" -ForegroundColor Magenta

        return $result
    }
    catch {
        Write-Host "  [-] Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

#region UpdateGroupMembership Function
function Invoke-UpdateGroupMembership {
    <#
    .SYNOPSIS
    Updates group membership by adding/removing specified users
    #>
    param(
        [string]$Group,
        [string[]]$Add,
        [string[]]$Remove,
        [switch]$NoConfirm
    )

    Write-Host "`n=== Update Group Membership ===" -ForegroundColor Cyan
    Write-Host "  Group: $Group" -ForegroundColor White

    $previewMode = $WhatIfPreference

    # Validate group exists
    try {
        $adGroup = Get-ADGroup -Identity $Group -ErrorAction Stop
        Write-Host "  [+] Group found: $($adGroup.Name)" -ForegroundColor Green
    }
    catch {
        Write-Host "  [-] Group not found: $Group" -ForegroundColor Red
        return @{ Success = $false; Error = "Group not found" }
    }

    $results = @{
        Group = $Group
        Added = @()
        Removed = @()
        Failed = @()
    }

    # Process additions
    if ($Add -and $Add.Count -gt 0) {
        Write-Host ""
        Write-Host "  Adding members:" -ForegroundColor Yellow
        foreach ($username in $Add) {
            if ([string]::IsNullOrWhiteSpace($username)) { continue }
            $username = $username.Trim()

            try {
                $user = Get-ADUser -Identity $username -ErrorAction Stop

                if ($previewMode) {
                    Write-Host "    [WOULD ADD] $username" -ForegroundColor Yellow
                    $results.Added += $username
                }
                else {
                    Add-ADGroupMember -Identity $Group -Members $user -ErrorAction Stop
                    Write-Host "    [ADDED] $username" -ForegroundColor Green
                    $results.Added += $username
                }
            }
            catch {
                if ($_ -match "already a member") {
                    Write-Host "    [SKIP] $username (already member)" -ForegroundColor Gray
                }
                else {
                    Write-Host "    [FAILED] $username - $_" -ForegroundColor Red
                    $results.Failed += @{ User = $username; Error = $_.ToString(); Action = "Add" }
                }
            }
        }
    }

    # Process removals
    if ($Remove -and $Remove.Count -gt 0) {
        Write-Host ""
        Write-Host "  Removing members:" -ForegroundColor Yellow
        foreach ($username in $Remove) {
            if ([string]::IsNullOrWhiteSpace($username)) { continue }
            $username = $username.Trim()

            try {
                $user = Get-ADUser -Identity $username -ErrorAction Stop

                if ($previewMode) {
                    Write-Host "    [WOULD REMOVE] $username" -ForegroundColor Yellow
                    $results.Removed += $username
                }
                else {
                    Remove-ADGroupMember -Identity $Group -Members $user -Confirm:$false -ErrorAction Stop
                    Write-Host "    [REMOVED] $username" -ForegroundColor Green
                    $results.Removed += $username
                }
            }
            catch {
                if ($_ -match "not a member") {
                    Write-Host "    [SKIP] $username (not a member)" -ForegroundColor Gray
                }
                else {
                    Write-Host "    [FAILED] $username - $_" -ForegroundColor Red
                    $results.Failed += @{ User = $username; Error = $_.ToString(); Action = "Remove" }
                }
            }
        }
    }

    # Summary
    Write-Host ""
    Write-Host "  === Summary ===" -ForegroundColor Cyan
    if ($previewMode) {
        Write-Host "  (Preview mode - no changes made)" -ForegroundColor Yellow
    }
    Write-Host "  Added: $($results.Added.Count)" -ForegroundColor Green
    Write-Host "  Removed: $($results.Removed.Count)" -ForegroundColor Green
    Write-Host "  Failed: $($results.Failed.Count)" -ForegroundColor $(if ($results.Failed.Count -gt 0) { "Red" } else { "Gray" })

    $results.Success = $true
    return $results
}
#endregion

#region Main Execution

switch ($Action) {
    "CreateStructure" {
        Invoke-CreateStructure -Domain $DomainName -Parent $ParentOU -OU $OUName -Prefix $GroupPrefix -Scope $GroupScope -Policies:$CreatePoliciesOU -NoConfirm:$Force
    }
    "ExportUsers" {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = ".\ADUserGroups-Export.csv"
        }
        Invoke-ExportUsers -Search $SearchBase -Output $OutputPath -Disabled:$IncludeDisabled -UserFilter $Filter
    }
    "ImportUsers" {
        if ([string]::IsNullOrWhiteSpace($InputPath)) {
            # Default to groups.csv
            if (Test-Path ".\groups.csv" -PathType Leaf) {
                $InputPath = ".\groups.csv"
                Write-Host "Using default input file: .\groups.csv" -ForegroundColor Cyan
            }
            else {
                $InputPath = Read-Host "Enter path to CSV file with group changes (default: .\groups.csv)"
                if ([string]::IsNullOrWhiteSpace($InputPath)) {
                    $InputPath = ".\groups.csv"
                }
            }
        }
        if (-not (Test-Path $InputPath -PathType Leaf)) {
            Write-Error "Input file not found: $InputPath"
            exit 1
        }
        if ([string]::IsNullOrWhiteSpace($LogPath)) {
            # Use Logs folder, ensure it exists
            $logsFolder = ".\Logs"
            if (-not (Test-Path $logsFolder -PathType Container)) {
                New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null
            }
            $LogPath = "$logsFolder\ADUserGroups-ChangeLog.csv"
        }
        Invoke-ImportUsers -InputFile $InputPath -Log $LogPath -NoValidation:$SkipValidation
    }
    "ExportComputers" {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = ".\ADManagement\computers.csv"
        }
        # Ensure output directory exists
        $outputDir = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        Invoke-ExportComputers -Output $OutputPath -Type $ComputerType -Search $SearchBase -EnabledOnly:$EnabledOnly -WindowsOnly:$WindowsOnly
    }
    "ExportGroupsWithMembers" {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = ".\ADManagement\groups-with-members.json"
        }
        $outputDir = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        Invoke-ExportGroupsWithMembers -Output $OutputPath -Filter $GroupFilter -Search $SearchBase
    }
    "ExportCategorizedUsers" {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = ".\ADManagement\users-categorized.json"
        }
        $outputDir = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        Invoke-ExportCategorizedUsers -Output $OutputPath -Search $SearchBase
    }
    "UpdateGroupMembership" {
        if ([string]::IsNullOrWhiteSpace($GroupName)) {
            Write-Error "GroupName is required for UpdateGroupMembership action"
            exit 1
        }
        Invoke-UpdateGroupMembership -Group $GroupName -Add $AddMembers -Remove $RemoveMembers -NoConfirm:$Force
    }
}

#endregion
