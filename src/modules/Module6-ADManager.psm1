# Module6-ADManager.psm1
# AD Manager module for GA-AppLocker
# Manages users, groups, and WinRM configuration
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

# Import Config for path configuration
Import-Module (Join-Path $PSScriptRoot '..\Config.psm1') -ErrorAction SilentlyContinue

# Import required modules at module level for performance
# These imports are done once at module load instead of per function call
Import-Module ActiveDirectory -ErrorAction SilentlyContinue -Verbose:$false
Import-Module GroupPolicy -ErrorAction SilentlyContinue -Verbose:$false

<#
.SYNOPSIS
    Get helpful error message for AD module unavailability
.DESCRIPTION
    Returns a user-friendly error message with remediation steps
#>
function Get-ADModuleUnavailableMessage {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # Check if system is in workgroup mode
    try {
        $isWorkgroup = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain -eq $false
    }
    catch {
        # If we can't determine domain status, provide generic message
        return @'
The Active Directory PowerShell module is not available.

RECOMMENDATION:
- Install Remote Server Administration Tools (RSAT)
- Run as Administrator and execute: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
- Or download RSAT from Microsoft: https://aka.ms/rsat

For Windows 10/11:
  Settings -> Apps -> Optional Features -> Add Feature -> RSAT: Active Directory Lightweight Services
'@
    }

    if ($isWorkgroup) {
        return @'
This Active Directory feature is not available in WORKGROUP mode.

RECOMMENDATION:
- This feature requires a Domain Controller or domain-joined computer
- Your system is currently in WORKGROUP mode
- To use this feature, either:
  1. Join this computer to a domain, OR
  2. Run GA-AppLocker on a domain-joined computer or Domain Controller

Alternative: Use local policy management instead of AD-based features.
'@
    }
    else {
        return @'
The Active Directory PowerShell module is not available.

RECOMMENDATION:
- Install Remote Server Administration Tools (RSAT)
- Run as Administrator and execute: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
- Or download RSAT from Microsoft: https://aka.ms/rsat

For Windows 10/11:
  Settings -> Apps -> Optional Features -> Add Feature -> RSAT: Active Directory Lightweight Services
'@
    }
}

Export-ModuleMember -Function Get-ADModuleUnavailableMessage

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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = Get-ADModuleUnavailableMessage
            data = @()
        }
    }

    try {
        # Validate MaxResults parameter to prevent LDAP injection
        if ($MaxResults -lt 1 -or $MaxResults -gt 10000) {
            return @{
                success = $false
                error = 'MaxResults must be between 1 and 10000'
                data = @()
            }
        }

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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = Get-ADModuleUnavailableMessage
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

    # Validate TargetOU if provided
    if ($TargetOU) {
        if ($TargetOU -notmatch '^OU=|CN=|DC=') {
            return @{
                success = $false
                error = 'Invalid TargetOU format. Must be a valid LDAP path (e.g., "OU=Workstations,DC=contoso,DC=com")'
            }
        }
    }

    $groupNames = @(
        'AppLocker-Admins',
        'AppLocker-PowerUsers',
        'AppLocker-StandardUsers',
        'AppLocker-RestrictedUsers',
        'AppLocker-Installers',
        'AppLocker-Developers'
    )

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = Get-ADModuleUnavailableMessage
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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = Get-ADModuleUnavailableMessage
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
    Create Enterprise WinRM GPO for Remote AppLocker Artifact Collection
.DESCRIPTION
    Creates a GPO to enable WinRM for remote management following enterprise/DoD standards.

    This function creates a GPO-backed WinRM configuration suitable for:
    - Running Invoke-Command from a Domain Controller
    - Running Get-AppLockerPolicy -Effective -ComputerName
    - Pulling AppLocker event logs remotely
    - Querying CIM/WMI over WinRM

    CRITICAL: This function does NOT use:
    - Enable-PSRemoting (cmdlet - not GPO-backed)
    - winrm quickconfig (local configuration - not GPO-backed)
    - Local firewall rules (uses GPO firewall policies instead)

    All settings are registry-backed via Group Policy and will:
    - Survive reboot
    - Appear correctly in RSOP/GPRESULT
    - Be acceptable in RMF/audit/inspection scenarios

.PARAMETER GpoName
    Name of the GPO to create. Default: 'GA-AppLocker-WinRM'

.PARAMETER TargetOU
    Optional. Distinguished Name of the OU to link the GPO to.
    If not specified, links to domain root.

.PARAMETER IPv4Filter
    IP addresses/ranges allowed for WinRM. Default: '*' (all)
    Can be restricted to specific subnets for security.

.PARAMETER IPv6Filter
    IPv6 addresses/ranges allowed for WinRM. Default: '*' (all)

.PARAMETER DisableUnencryptedTraffic
    If $true (default), disables unencrypted WinRM traffic.
    Required for DoD/enterprise security compliance.

.EXAMPLE
    New-WinRMGPO -GpoName 'AppLocker-WinRM-Policy'

.EXAMPLE
    New-WinRMGPO -GpoName 'AppLocker-WinRM' -TargetOU 'OU=Workstations,DC=contoso,DC=com'

.NOTES
    Security Context:
    - Scanning account does NOT need to be Domain Admin
    - Access is granted via membership in:
      * Remote Management Users (local group on target)
      * Event Log Readers (for AppLocker event access)

    Validation Commands (run from Domain Controller after GPO applies):
      Test-WsMan targetMachine
      Invoke-Command -ComputerName targetMachine { hostname }
      Get-AppLockerPolicy -Effective -ComputerName targetMachine
      Get-WinEvent -ComputerName targetMachine -LogName "Microsoft-Windows-AppLocker/EXE and DLL"
#>
function New-WinRMGPO {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$GpoName = 'GA-AppLocker-WinRM',

        [string]$TargetOU,

        [string]$IPv4Filter = '*',

        [string]$IPv6Filter = '*',

        [bool]$DisableUnencryptedTraffic = $true
    )

    # =========================================================================
    # PREREQUISITE CHECK - Required PowerShell Modules
    # =========================================================================
    # Check if required modules are available (imported at module level)
    if (-not (Get-Module GroupPolicy)) {
        return @{
            success = $false
            error = 'GroupPolicy module not available. Install RSAT: GroupPolicy'
        }
    }

    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. Install RSAT: ActiveDirectory'
        }
    }

    # Track configuration results for detailed reporting
    $configResults = @{
        service = @{}
        client = @{}
        firewall = @{}
    }
    $warnings = @()

    try {
        # =====================================================================
        # CHECK FOR EXISTING GPO
        # =====================================================================
        $existing = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if ($existing) {
            return @{
                success = $true
                existed = $true
                gpoName = $GpoName
                gpoId = $existing.Id.ToString()
                message = 'WinRM GPO already exists. Delete it first to recreate with new settings.'
            }
        }

        # =====================================================================
        # CREATE NEW GPO
        # =====================================================================
        if ($PSCmdlet.ShouldProcess($GpoName, "Create WinRM Group Policy Object")) {
            $gpo = New-GPO -Name $GpoName -Comment @"
GA-AppLocker WinRM Configuration GPO
Purpose: Enable WinRM for remote AppLocker artifact collection
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Settings: Service auto-config, Client config, Firewall rules (Domain/Private)
Security: Unencrypted traffic disabled, requires Remote Management Users membership
"@
        }
        else {
            return @{ success = $false; error = 'Operation cancelled by user' }
        }

        # =====================================================================
        # SECTION 1: WINRM SERVICE CONFIGURATION
        # Registry Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service
        # These settings control the WinRM service on target computers
        # =====================================================================
        $serviceKeyPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

        # 1.1 Enable WinRM Service Auto-Configuration
        # This is the master switch that enables WinRM via Group Policy
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $serviceKeyPath `
                -ValueName 'AllowAutoConfig' `
                -Type DWord `
                -Value 1 `
                -ErrorAction Stop | Out-Null
            $configResults.service['AllowAutoConfig'] = 'Set to 1 (Enabled)'
        }
        catch {
            $warnings += "Failed to set Service\AllowAutoConfig: $($_.Exception.Message)"
            $configResults.service['AllowAutoConfig'] = "FAILED: $($_.Exception.Message)"
        }

        # 1.2 IPv4 Filter - Which IP addresses can connect
        # '*' allows all; can be restricted to specific subnets (e.g., '10.0.0.0/8')
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $serviceKeyPath `
                -ValueName 'IPv4Filter' `
                -Type String `
                -Value $IPv4Filter `
                -ErrorAction Stop | Out-Null
            $configResults.service['IPv4Filter'] = "Set to '$IPv4Filter'"
        }
        catch {
            $warnings += "Failed to set Service\IPv4Filter: $($_.Exception.Message)"
            $configResults.service['IPv4Filter'] = "FAILED: $($_.Exception.Message)"
        }

        # 1.3 IPv6 Filter - Which IPv6 addresses can connect
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $serviceKeyPath `
                -ValueName 'IPv6Filter' `
                -Type String `
                -Value $IPv6Filter `
                -ErrorAction Stop | Out-Null
            $configResults.service['IPv6Filter'] = "Set to '$IPv6Filter'"
        }
        catch {
            $warnings += "Failed to set Service\IPv6Filter: $($_.Exception.Message)"
            $configResults.service['IPv6Filter'] = "FAILED: $($_.Exception.Message)"
        }

        # 1.4 Allow Basic Authentication (Service)
        # Required for some remote management scenarios
        # Note: Traffic is still encrypted via HTTPS or Kerberos
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $serviceKeyPath `
                -ValueName 'AllowBasic' `
                -Type DWord `
                -Value 1 `
                -ErrorAction Stop | Out-Null
            $configResults.service['AllowBasic'] = 'Set to 1 (Enabled)'
        }
        catch {
            $warnings += "Failed to set Service\AllowBasic: $($_.Exception.Message)"
            $configResults.service['AllowBasic'] = "FAILED: $($_.Exception.Message)"
        }

        # 1.5 Disable Unencrypted Traffic (Security Requirement)
        # CRITICAL: Always disable unencrypted traffic in enterprise environments
        $unencryptedValue = if ($DisableUnencryptedTraffic) { 0 } else { 1 }
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $serviceKeyPath `
                -ValueName 'AllowUnencryptedTraffic' `
                -Type DWord `
                -Value $unencryptedValue `
                -ErrorAction Stop | Out-Null
            $configResults.service['AllowUnencryptedTraffic'] = "Set to $unencryptedValue ($(if ($DisableUnencryptedTraffic) { 'Disabled - Secure' } else { 'Enabled - WARNING' }))"
        }
        catch {
            $warnings += "Failed to set Service\AllowUnencryptedTraffic: $($_.Exception.Message)"
            $configResults.service['AllowUnencryptedTraffic'] = "FAILED: $($_.Exception.Message)"
        }

        # =====================================================================
        # SECTION 2: WINRM CLIENT CONFIGURATION
        # Registry Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client
        # These settings control WinRM client behavior when connecting TO other systems
        # =====================================================================
        $clientKeyPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'

        # 2.1 Allow Basic Authentication (Client)
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $clientKeyPath `
                -ValueName 'AllowBasic' `
                -Type DWord `
                -Value 1 `
                -ErrorAction Stop | Out-Null
            $configResults.client['AllowBasic'] = 'Set to 1 (Enabled)'
        }
        catch {
            $warnings += "Failed to set Client\AllowBasic: $($_.Exception.Message)"
            $configResults.client['AllowBasic'] = "FAILED: $($_.Exception.Message)"
        }

        # 2.2 Disable Unencrypted Traffic (Client)
        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $clientKeyPath `
                -ValueName 'AllowUnencryptedTraffic' `
                -Type DWord `
                -Value $unencryptedValue `
                -ErrorAction Stop | Out-Null
            $configResults.client['AllowUnencryptedTraffic'] = "Set to $unencryptedValue ($(if ($DisableUnencryptedTraffic) { 'Disabled - Secure' } else { 'Enabled - WARNING' }))"
        }
        catch {
            $warnings += "Failed to set Client\AllowUnencryptedTraffic: $($_.Exception.Message)"
            $configResults.client['AllowUnencryptedTraffic'] = "FAILED: $($_.Exception.Message)"
        }

        # =====================================================================
        # SECTION 3: WINDOWS FIREWALL CONFIGURATION VIA GPO
        # Registry Path: HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall
        # CRITICAL: These are GPO-based firewall rules, NOT local firewall rules
        # This ensures settings survive reboot and appear in RSOP/GPRESULT
        # =====================================================================

        # 3.1 Enable predefined WinRM firewall rules for Domain profile
        # Registry path for Windows Firewall with Advanced Security GPO settings
        $firewallDomainPath = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings'

        try {
            # Enable Windows Remote Management (HTTP-In) for Domain profile
            Set-GPRegistryValue -Name $GpoName `
                -Key $firewallDomainPath `
                -ValueName 'Enabled' `
                -Type DWord `
                -Value 1 `
                -ErrorAction Stop | Out-Null
            $configResults.firewall['DomainProfile_RemoteAdmin'] = 'Enabled'
        }
        catch {
            $warnings += "Failed to set Domain firewall settings: $($_.Exception.Message)"
            $configResults.firewall['DomainProfile_RemoteAdmin'] = "FAILED: $($_.Exception.Message)"
        }

        # 3.2 Enable for Private profile
        $firewallPrivatePath = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings'

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $firewallPrivatePath `
                -ValueName 'Enabled' `
                -Type DWord `
                -Value 1 `
                -ErrorAction Stop | Out-Null
            $configResults.firewall['PrivateProfile_RemoteAdmin'] = 'Enabled'
        }
        catch {
            $warnings += "Failed to set Private firewall settings: $($_.Exception.Message)"
            $configResults.firewall['PrivateProfile_RemoteAdmin'] = "FAILED: $($_.Exception.Message)"
        }

        # 3.3 Configure WinRM HTTP Inbound Rule (Port 5985)
        # Uses Windows Firewall GPO extension for proper rule definition
        $firewallRulesPath = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules'

        # WinRM HTTP Rule (Domain and Private profiles)
        $winrmHttpRule = 'v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|' +
                         'Profile=Domain|Profile=Private|' +
                         'Name=Windows Remote Management (HTTP-In)|' +
                         'Desc=Inbound rule for Windows Remote Management via WS-Management (HTTP port 5985)|' +
                         'EmbedCtxt=Windows Remote Management|'

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $firewallRulesPath `
                -ValueName 'WinRM-HTTP-In-TCP' `
                -Type String `
                -Value $winrmHttpRule `
                -ErrorAction Stop | Out-Null
            $configResults.firewall['WinRM_HTTP_5985'] = 'Rule created for Domain and Private profiles'
        }
        catch {
            $warnings += "Failed to create WinRM HTTP firewall rule: $($_.Exception.Message)"
            $configResults.firewall['WinRM_HTTP_5985'] = "FAILED: $($_.Exception.Message)"
        }

        # WinRM HTTPS Rule (Port 5986) - Domain and Private profiles
        $winrmHttpsRule = 'v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5986|' +
                          'Profile=Domain|Profile=Private|' +
                          'Name=Windows Remote Management (HTTPS-In)|' +
                          'Desc=Inbound rule for Windows Remote Management via WS-Management (HTTPS port 5986)|' +
                          'EmbedCtxt=Windows Remote Management|'

        try {
            Set-GPRegistryValue -Name $GpoName `
                -Key $firewallRulesPath `
                -ValueName 'WinRM-HTTPS-In-TCP' `
                -Type String `
                -Value $winrmHttpsRule `
                -ErrorAction Stop | Out-Null
            $configResults.firewall['WinRM_HTTPS_5986'] = 'Rule created for Domain and Private profiles'
        }
        catch {
            $warnings += "Failed to create WinRM HTTPS firewall rule: $($_.Exception.Message)"
            $configResults.firewall['WinRM_HTTPS_5986'] = "FAILED: $($_.Exception.Message)"
        }

        # =====================================================================
        # SECTION 4: LINK GPO TO TARGET
        # =====================================================================
        $linkTarget = if ($TargetOU) { $TargetOU } else { (Get-ADDomain).DistinguishedName }

        try {
            New-GPLink -Name $GpoName -Target $linkTarget -LinkEnabled Yes -ErrorAction Stop | Out-Null
            $linkedSuccessfully = $true
        }
        catch {
            $linkedSuccessfully = $false
            $warnings += "Failed to link GPO to '$linkTarget': $($_.Exception.Message)"
        }

        # =====================================================================
        # RETURN COMPREHENSIVE RESULTS
        # =====================================================================
        $overallSuccess = ($warnings.Count -eq 0) -and $linkedSuccessfully

        return @{
            success = $overallSuccess
            partialSuccess = (-not $overallSuccess -and $gpo)
            existed = $false
            gpoName = $GpoName
            gpoId = $gpo.Id.ToString()
            linked = $linkedSuccessfully
            linkedTo = $linkTarget
            configuration = @{
                service = $configResults.service
                client = $configResults.client
                firewall = $configResults.firewall
            }
            warnings = $warnings
            message = if ($overallSuccess) {
                'WinRM GPO created and configured successfully. Run gpupdate /force on target computers.'
            } else {
                "WinRM GPO created with $($warnings.Count) warning(s). Review warnings for details."
            }
            validationCommands = @(
                'Test-WsMan <targetMachine>',
                'Invoke-Command -ComputerName <targetMachine> { hostname }',
                'Get-AppLockerPolicy -Effective -ComputerName <targetMachine>',
                'Get-WinEvent -ComputerName <targetMachine> -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 10'
            )
            securityNotes = @(
                'Scanning account should be member of "Remote Management Users" on target',
                'For event log access, add to "Event Log Readers" group on target',
                'Unencrypted traffic is disabled (secure configuration)',
                'Basic authentication enabled for compatibility (traffic still encrypted)'
            )
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to create WinRM GPO: $($_.Exception.Message)"
        }
    }
}

# Export functions
Export-ModuleMember -Function Protect-LDAPFilterValue, Get-AllADUsers, Search-ADUsers, New-AppLockerGroups,
                              Add-UserToAppLockerGroup, Remove-UserFromAppLockerGroup,
                              Get-AppLockerGroupMembers, New-WinRMGPO
