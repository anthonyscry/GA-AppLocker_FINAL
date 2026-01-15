# Module6-ADManager.psm1
# AD Manager module for GA-AppLocker
# Manages users, groups, and WinRM configuration
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

<#
.SYNOPSIS
    Escape LDAP Special Characters
.DESCRIPTION
    Escapes special characters in LDAP filter values to prevent injection attacks
.PARAMETER Value
    The value to escape
#>
function Protect-LDAPFilterValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # Escape special LDAP characters: \ * ( ) NUL / and wildcard *
    # From RFC 4515 and Microsoft best practices
    $escaped = $Value -replace '\\', '\\5c'
    $escaped = $escaped -replace '\*', '\\2a'
    $escaped = $escaped -replace '\(', '\\28'
    $escaped = $escaped -replace '\)', '\\29'
    $escaped = $escaped -replace '\x00', '\\00'
    $escaped = $escaped -replace '/', '\\2f'

    return $escaped
}

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
    Searches for users by name with LDAP injection protection
.PARAMETER SearchQuery
    The search query (will be properly escaped)
#>
function Search-ADUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchQuery
    )

    if ([string]::IsNullOrWhiteSpace($SearchQuery)) {
        return @{
            success = $false
            error = 'Search query is required'
            data = @()
        }
    }

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
        # Protect against LDAP injection by escaping special characters
        $escapedQuery = Protect-LDAPFilterValue -Value $SearchQuery

        # Use LDAPFilter for safer querying (from AaronLocker pattern)
        # (name=*escapedValue*) searches for the query anywhere in the name
        $users = Get-ADUser -LDAPFilter "(name=*$escapedQuery*)" -Properties DisplayName, Department, Enabled

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
        # Use LDAPFilter for safer group lookup
        $existing = Get-ADGroup -LDAPFilter "(name=$groupName)" -ErrorAction SilentlyContinue

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
    Adds a user to an AppLocker security group with LDAP injection protection
.PARAMETER SamAccountName
    The SAM account name of the user (will be properly escaped)
.PARAMETER GroupName
    The name of the group (will be properly escaped)
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
        # Protect against LDAP injection
        $escapedUser = Protect-LDAPFilterValue -Value $SamAccountName
        $escapedGroup = Protect-LDAPFilterValue -Value $GroupName

        # Use LDAPFilter for safer querying
        $user = Get-ADUser -LDAPFilter "(sAMAccountName=$escapedUser)" -ErrorAction SilentlyContinue
        if (-not $user) {
            return @{ success = $false; error = "User not found: $SamAccountName" }
        }

        $group = Get-ADGroup -LDAPFilter "(name=$escapedGroup)" -ErrorAction SilentlyContinue
        if (-not $group) {
            return @{ success = $false; error = "Group not found: $GroupName" }
        }

        $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
        $alreadyMember = $members | Where-Object { $_.SamAccountName -eq $SamAccountName }

        if ($alreadyMember) {
            return @{
                success = $true
                alreadyMember = $true
                message = 'User is already a member of this group'
            }
        }

        Add-ADGroupMember -Identity $group.DistinguishedName -Members $user.DistinguishedName -ErrorAction Stop

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
    Removes a user from an AppLocker security group with LDAP injection protection
.PARAMETER SamAccountName
    The SAM account name of the user (will be properly escaped)
.PARAMETER GroupName
    The name of the group (will be properly escaped)
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
        # Protect against LDAP injection
        $escapedUser = Protect-LDAPFilterValue -Value $SamAccountName
        $escapedGroup = Protect-LDAPFilterValue -Value $GroupName

        # Use LDAPFilter for safer querying
        $user = Get-ADUser -LDAPFilter "(sAMAccountName=$escapedUser)" -ErrorAction SilentlyContinue
        if (-not $user) {
            return @{ success = $false; error = "User not found: $SamAccountName" }
        }

        $group = Get-ADGroup -LDAPFilter "(name=$escapedGroup)" -ErrorAction SilentlyContinue
        if (-not $group) {
            return @{ success = $false; error = "Group not found: $GroupName" }
        }

        Remove-ADGroupMember -Identity $group.DistinguishedName -Members $user.DistinguishedName -Confirm:$false -ErrorAction Stop

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

        # Configure WinRM service settings
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                -ValueName 'AllowAutoConfig' `
                -Type DWord `
                -Value 1 `
                -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to set AllowAutoConfig registry value: $($_.Exception.Message)"
        }

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                -ValueName 'IPv4Filter' `
                -Type String `
                -Value '*' `
                -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to set IPv4Filter registry value: $($_.Exception.Message)"
        }

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
                -ValueName 'IPv6Filter' `
                -Type String `
                -Value '*' `
                -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to set IPv6Filter registry value: $($_.Exception.Message)"
        }

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
Export-ModuleMember -Function Protect-LDAPFilterValue, Get-AllADUsers, Search-ADUsers, New-AppLockerGroups,
                              Add-UserToAppLockerGroup, Remove-UserFromAppLockerGroup,
                              Get-AppLockerGroupMembers, New-WinRMGPO
