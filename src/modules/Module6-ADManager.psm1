# Module6-ADManager.psm1
# AD Manager module for GA-AppLocker
# Manages users, groups, and WinRM configuration

<#
.SYNOPSIS
    Get All AD Users
.DESCRIPTION
    Retrieves all users from Active Directory
#>
function Get-AllADUsers {
    [CmdletBinding()]
    param(
        [int]$MaxResults = 500
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $properties = @('DisplayName', 'Department', 'MemberOf', 'Enabled', 'DistinguishedName')
        $users = Get-ADUser -Filter * -Properties $properties | Select-Object -First $MaxResults

        $results = @()
        foreach ($user in $users) {
            $samAccountName = $user.SamAccountName
            $displayName = if ($user.DisplayName) { $user.DisplayName } else { $samAccountName }

            $groups = @()
            foreach ($groupDN in $user.MemberOf) {
                $groupName = ($groupDN -split ',')[0] -replace 'CN=', ''
                $groups += $groupName
            }

            $dn = $user.DistinguishedName
            $ou = ($dn -split ',', 2)[1]

            $results += @{
                samAccountName = $samAccountName
                displayName = $displayName
                department = $user.Department
                ou = $ou
                groups = $groups
                enabled = $user.Enabled
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Search AD Users
.DESCRIPTION
    Searches for users by name
#>
function Search-ADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchQuery
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $users = Get-ADUser -Filter "Name -like '*$SearchQuery*'" -Properties DisplayName, Department, Enabled

        $results = @()
        foreach ($user in $users) {
            $results += @{
                samAccountName = $user.SamAccountName
                displayName = $user.DisplayName
                department = $user.Department
                enabled = $user.Enabled
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Create AppLocker Security Groups
.DESCRIPTION
    Creates the standard AppLocker security groups
#>
function New-AppLockerGroups {
    [CmdletBinding()]
    param(
        [string]$TargetOU
    )

    $groupNames = @(
        'AppLocker-Admins',
        'AppLocker-PowerUsers',
        'AppLocker-StandardUsers',
        'AppLocker-RestrictedUsers',
        'AppLocker-Installers',
        'AppLocker-Developers'
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
        }
    }

    $results = @()
    foreach ($groupName in $groupNames) {
        $existing = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue

        if ($existing) {
            $results += @{
                name = $groupName
                created = $false
                existed = $true
            }
            continue
        }

        try {
            $params = @{
                Name = $groupName
                GroupScope = 'Global'
                GroupCategory = 'Security'
                Description = "AppLocker security group for policy assignment"
            }

            if ($TargetOU) {
                $params['Path'] = $TargetOU
            }

            New-ADGroup @params -ErrorAction Stop | Out-Null

            $results += @{
                name = $groupName
                created = $true
                existed = $false
            }
        }
        catch {
            $results += @{
                name = $groupName
                created = $false
                existed = $false
                error = $_.Exception.Message
            }
        }
    }

    return @{
        success = $true
        groups = $results
        created = ($results | Where-Object { $_.created }).Count
        existing = ($results | Where-Object { $_.existed }).Count
    }
}

<#
.SYNOPSIS
    Add User to AppLocker Group
.DESCRIPTION
    Adds a user to an AppLocker security group
#>
function Add-UserToAppLockerGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    # Validate parameters
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
        return @{ success = $false; error = 'SamAccountName is required' }
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return @{ success = $false; error = 'GroupName is required' }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{ success = $false; error = 'ActiveDirectory module not available' }
    }

    try {
        $user = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
        if (-not $user) {
            return @{ success = $false; error = "User not found: $SamAccountName" }
        }

        $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
        if (-not $group) {
            return @{ success = $false; error = "Group not found: $GroupName" }
        }

        $members = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue
        $alreadyMember = $members | Where-Object { $_.SamAccountName -eq $SamAccountName }

        if ($alreadyMember) {
            return @{
                success = $true
                alreadyMember = $true
                message = 'User is already a member of this group'
            }
        }

        Add-ADGroupMember -Identity $GroupName -Members $SamAccountName -ErrorAction Stop

        return @{
            success = $true
            alreadyMember = $false
            message = "User '$SamAccountName' added to group '$GroupName'"
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Remove User from AppLocker Group
.DESCRIPTION
    Removes a user from an AppLocker security group
#>
function Remove-UserFromAppLockerGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    # Validate parameters
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
        return @{ success = $false; error = 'SamAccountName is required' }
    }

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return @{ success = $false; error = 'GroupName is required' }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{ success = $false; error = 'ActiveDirectory module not available' }
    }

    try {
        $user = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
        if (-not $user) {
            return @{ success = $false; error = "User not found: $SamAccountName" }
        }

        $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
        if (-not $group) {
            return @{ success = $false; error = "Group not found: $GroupName" }
        }

        Remove-ADGroupMember -Identity $GroupName -Members $SamAccountName -Confirm:$false -ErrorAction Stop

        return @{
            success = $true
            message = "User '$SamAccountName' removed from group '$GroupName'"
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Get Group Members
.DESCRIPTION
    Retrieves members of an AppLocker group
#>
function Get-AppLockerGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $members = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop

        $results = @()
        foreach ($member in $members) {
            $results += @{
                name = $member.Name
                samAccountName = $member.SamAccountName
                type = $member.ObjectClass
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Create WinRM GPO
.DESCRIPTION
    Creates a GPO to enable WinRM for remote management
#>
function New-WinRMGPO {
    [CmdletBinding()]
    param(
        [string]$GpoName = 'Enable-WinRM'
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'Required modules not available'
        }
    }

    try {
        $existing = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if ($existing) {
            return @{
                success = $true
                existed = $true
                gpoName = $GpoName
                message = 'WinRM GPO already exists'
            }
        }

        $gpo = New-GPO -Name $GpoName -Comment 'Enables WinRM for remote management'

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                -ValueName 'AllowAutoConfig' `
                -Type DWord `
                -Value 1
        }
        catch { }

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                -ValueName 'IPv4Filter' `
                -Type String `
                -Value '*'
        }
        catch { }

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                -ValueName 'IPv6Filter' `
                -Type String `
                -Value '*'
        }
        catch { }

        $domainDN = (Get-ADDomain).DistinguishedName

        try {
            New-GPLink -Name $GpoName -Target $domainDN -LinkEnabled Yes -ErrorAction Stop
        }
        catch {
            return @{
                success = $true
                existed = $false
                gpoName = $GpoName
                linked = $false
                message = "GPO created but failed to link: $($_.Exception.Message)"
            }
        }

        return @{
            success = $true
            existed = $false
            gpoName = $GpoName
            linked = $true
            linkedTo = $domainDN
            message = 'WinRM GPO created and linked to domain'
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Export functions
Export-ModuleMember -Function Get-AllADUsers, Search-ADUsers, New-AppLockerGroups,
                              Add-UserToAppLockerGroup, Remove-UserFromAppLockerGroup,
                              Get-AppLockerGroupMembers, New-WinRMGPO
