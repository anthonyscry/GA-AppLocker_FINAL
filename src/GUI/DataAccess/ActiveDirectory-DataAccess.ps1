<#
.SYNOPSIS
    Active Directory data access layer

.DESCRIPTION
    Provides read-only access to Active Directory for querying domain information,
    group membership, computer objects, and organizational units.
    All functions return data objects only - no modifications, no UI updates.

.NOTES
    Version: 1.0.0
    Layer: Data Access (Read-Only)
    Requires: ActiveDirectory module for full functionality
#>

function Get-DomainInfo {
    <#
    .SYNOPSIS
        Retrieves domain information for the current computer

    .DESCRIPTION
        Queries domain membership status, RSAT availability, and domain details.
        Returns comprehensive domain information including workgroup detection.
        Read-only operation.

    .EXAMPLE
        Get-DomainInfo

    .OUTPUTS
        Hashtable with domain information including:
        - success: Boolean indicating success
        - isWorkgroup: Boolean indicating if computer is in workgroup
        - hasRSAT: Boolean indicating if RSAT is installed
        - dnsRoot: DNS root domain name
        - netBIOSName: NetBIOS domain name
        - message: Human-readable status message
    #>
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose "Querying domain information"
    }

    process {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

            # Check if actually part of a domain (PartOfDomain is a boolean)
            $isWorkgroup = -not $computerSystem -or -not $computerSystem.PartOfDomain

            if ($isWorkgroup) {
                Write-Verbose "Computer is in WORKGROUP mode"
                return @{
                    success = $true
                    isWorkgroup = $true
                    hasRSAT = $false
                    dnsRoot = "WORKGROUP"
                    netBIOSName = $env:COMPUTERNAME
                    message = "WORKGROUP - AD/GPO disabled"
                }
            }

            # We're domain-joined, check for RSAT (AD and GroupPolicy modules)
            $hasADModule = $false
            $hasGPModule = $false

            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $hasADModule = $true
                Write-Verbose "ActiveDirectory module is available"
            } catch {
                Write-Verbose "ActiveDirectory module is not available"
            }

            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $hasGPModule = $true
                Write-Verbose "GroupPolicy module is available"
            } catch {
                Write-Verbose "GroupPolicy module is not available"
            }

            $hasRSAT = $hasADModule -and $hasGPModule

            # Try to get domain info
            try {
                if ($hasADModule) {
                    $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
                    $domainName = $domain.DNSRoot
                    $netbios = $domain.NetBIOSName
                    Write-Verbose "Domain: $domainName ($netbios)"
                } else {
                    $domainName = $env:USERDNSDOMAIN
                    if ([string]::IsNullOrEmpty($domainName)) {
                        $domainName = $computerSystem.Domain
                    }
                    $netbios = $env:USERDOMAIN
                    Write-Verbose "Domain (without RSAT): $domainName ($netbios)"
                }

                if ($hasRSAT) {
                    return @{
                        success = $true
                        isWorkgroup = $false
                        hasRSAT = $true
                        dnsRoot = $domainName
                        netBIOSName = $netbios
                        message = "Domain: $domainName (Full features)"
                    }
                } else {
                    return @{
                        success = $true
                        isWorkgroup = $false
                        hasRSAT = $false
                        dnsRoot = $domainName
                        netBIOSName = $netbios
                        message = "Domain: $domainName (RSAT not installed - GPO features disabled)"
                    }
                }
            } catch {
                Write-Verbose "Failed to get domain details: $($_.Exception.Message)"
                return @{
                    success = $true
                    isWorkgroup = $true
                    hasRSAT = $false
                    dnsRoot = "WORKGROUP"
                    netBIOSName = $env:COMPUTERNAME
                    message = "WORKGROUP - AD/GPO disabled"
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve domain information: $($_.Exception.Message)"
            return @{
                success = $false
                isWorkgroup = $true
                hasRSAT = $false
                dnsRoot = "WORKGROUP"
                netBIOSName = $env:COMPUTERNAME
                message = "Error: $($_.Exception.Message)"
                error = $_.Exception.Message
            }
        }
    }
}

function Test-DomainJoined {
    <#
    .SYNOPSIS
        Checks if the computer is joined to a domain

    .DESCRIPTION
        Simple boolean check for domain membership.
        Read-only operation.

    .EXAMPLE
        Test-DomainJoined

    .OUTPUTS
        Boolean - $true if domain-joined, $false if workgroup
    #>
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose "Checking domain join status"
    }

    process {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            $isDomainJoined = $computerSystem -and $computerSystem.PartOfDomain

            Write-Verbose "Domain joined: $isDomainJoined"
            return $isDomainJoined
        }
        catch {
            Write-Verbose "Failed to check domain status: $($_.Exception.Message)"
            return $false
        }
    }
}

function Get-ADGroupMembers {
    <#
    .SYNOPSIS
        Retrieves members of an Active Directory group

    .DESCRIPTION
        Queries AD group membership and returns member details.
        Read-only operation.

    .PARAMETER GroupName
        Name of the AD group to query

    .PARAMETER Recursive
        Include nested group members

    .EXAMPLE
        Get-ADGroupMembers -GroupName "Domain Admins"

    .EXAMPLE
        Get-ADGroupMembers -GroupName "IT Staff" -Recursive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,

        [Parameter()]
        [switch]$Recursive
    )

    begin {
        Write-Verbose "Querying members of AD group: $GroupName (Recursive: $Recursive)"
    }

    process {
        try {
            # Verify AD module is available
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Write-Warning "ActiveDirectory module is not available"
                return @()
            }

            Import-Module ActiveDirectory -ErrorAction Stop

            # Get the group
            $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

            if (-not $group) {
                Write-Warning "Group not found: $GroupName"
                return @()
            }

            # Get members
            $members = Get-ADGroupMember -Identity $group -Recursive:$Recursive -ErrorAction Stop

            Write-Verbose "Retrieved $($members.Count) members from group: $GroupName"

            return $members
        }
        catch {
            Write-Warning "Failed to retrieve group members for '$GroupName': $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-ADGroupMembershipData {
    <#
    .SYNOPSIS
        Retrieves all AD groups and their memberships

    .DESCRIPTION
        Exports all AD groups with member lists for reporting or backup.
        Read-only operation - does not modify AD or create files.

    .PARAMETER Filter
        AD group filter (default: all groups)

    .EXAMPLE
        Get-ADGroupMembershipData

    .EXAMPLE
        Get-ADGroupMembershipData -Filter "Name -like 'AppLocker*'"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Filter = "*"
    )

    begin {
        Write-Verbose "Retrieving AD group membership data"
    }

    process {
        try {
            # Verify AD module
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Write-Warning "ActiveDirectory module is not available"
                return @()
            }

            Import-Module ActiveDirectory -ErrorAction Stop

            $groupData = @()
            $groups = Get-ADGroup -Filter $Filter -ErrorAction Stop

            Write-Verbose "Processing $($groups.Count) groups"

            foreach ($group in $groups) {
                try {
                    $members = Get-ADGroupMember -Identity $group -Recursive:$false -ErrorAction SilentlyContinue

                    $memberNames = if ($members) {
                        $members | Select-Object -ExpandProperty SamAccountName
                    } else {
                        @()
                    }

                    $groupData += [PSCustomObject]@{
                        GroupName = $group.Name
                        GroupDN = $group.DistinguishedName
                        GroupSID = $group.SID.Value
                        MemberCount = $memberNames.Count
                        Members = ($memberNames -join ';')
                    }
                }
                catch {
                    Write-Verbose "Failed to process group '$($group.Name)': $($_.Exception.Message)"
                }
            }

            Write-Verbose "Successfully retrieved data for $($groupData.Count) groups"
            return $groupData
        }
        catch {
            Write-Error "Failed to retrieve AD group membership data: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-ADComputersInOU {
    <#
    .SYNOPSIS
        Retrieves computers in a specified Organizational Unit

    .DESCRIPTION
        Queries AD for computer objects within an OU.
        Read-only operation.

    .PARAMETER OU
        Distinguished name of the OU to query

    .PARAMETER Recurse
        Include computers in child OUs

    .PARAMETER Filter
        Additional AD filter for computer objects

    .EXAMPLE
        Get-ADComputersInOU -OU "OU=Workstations,DC=contoso,DC=com"

    .EXAMPLE
        Get-ADComputersInOU -OU "OU=Servers,DC=contoso,DC=com" -Recurse -Filter "OperatingSystem -like '*Server*'"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OU,

        [Parameter()]
        [switch]$Recurse,

        [Parameter()]
        [string]$Filter = "*"
    )

    begin {
        Write-Verbose "Querying computers in OU: $OU (Recurse: $Recurse)"
    }

    process {
        try {
            # Verify AD module
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Write-Warning "ActiveDirectory module is not available"
                return @()
            }

            Import-Module ActiveDirectory -ErrorAction Stop

            # Build search parameters
            $searchParams = @{
                Filter = $Filter
                SearchBase = $OU
                ErrorAction = 'Stop'
            }

            if ($Recurse) {
                $searchParams['SearchScope'] = 'Subtree'
            } else {
                $searchParams['SearchScope'] = 'OneLevel'
            }

            # Query computers
            $computers = Get-ADComputer @searchParams -Properties Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled

            Write-Verbose "Found $($computers.Count) computers in OU"

            return $computers
        }
        catch {
            Write-Error "Failed to retrieve computers in OU: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-OUStructure {
    <#
    .SYNOPSIS
        Enumerates the OU hierarchy in Active Directory

    .DESCRIPTION
        Retrieves the organizational unit structure from AD.
        Read-only operation.

    .PARAMETER SearchBase
        Starting point for OU enumeration (default: domain root)

    .PARAMETER MaxDepth
        Maximum depth to traverse (default: unlimited)

    .EXAMPLE
        Get-OUStructure

    .EXAMPLE
        Get-OUStructure -SearchBase "OU=Corporate,DC=contoso,DC=com" -MaxDepth 3
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxDepth = 10
    )

    begin {
        Write-Verbose "Enumerating OU structure"
    }

    process {
        try {
            # Verify AD module
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Write-Warning "ActiveDirectory module is not available"
                return @()
            }

            Import-Module ActiveDirectory -ErrorAction Stop

            # Get domain root if SearchBase not specified
            if (-not $SearchBase) {
                $domain = Get-ADDomain -ErrorAction Stop
                $SearchBase = $domain.DistinguishedName
                Write-Verbose "Using domain root: $SearchBase"
            }

            # Query OUs
            $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -SearchScope Subtree -Properties CanonicalName, Description -ErrorAction Stop

            Write-Verbose "Found $($ous.Count) organizational units"

            $ouData = $ous | ForEach-Object {
                # Calculate depth based on DN components
                $depth = ($_.DistinguishedName -split ',OU=').Count - 1

                if ($depth -le $MaxDepth) {
                    [PSCustomObject]@{
                        Name = $_.Name
                        DistinguishedName = $_.DistinguishedName
                        CanonicalName = $_.CanonicalName
                        Description = $_.Description
                        Depth = $depth
                    }
                }
            }

            return $ouData | Sort-Object Depth, CanonicalName
        }
        catch {
            Write-Error "Failed to enumerate OU structure: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-ADDomainControllers {
    <#
    .SYNOPSIS
        Retrieves domain controller information

    .DESCRIPTION
        Queries Active Directory for domain controller details.
        Read-only operation.

    .EXAMPLE
        Get-ADDomainControllers
    #>
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose "Retrieving domain controller information"
    }

    process {
        try {
            # Verify AD module
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Write-Warning "ActiveDirectory module is not available"
                return @()
            }

            Import-Module ActiveDirectory -ErrorAction Stop

            $dcs = Get-ADDomainController -Filter * -ErrorAction Stop

            Write-Verbose "Found $($dcs.Count) domain controllers"

            return $dcs
        }
        catch {
            Write-Error "Failed to retrieve domain controllers: $($_.Exception.Message)"
            return @()
        }
    }
}

function Test-ADGroupExists {
    <#
    .SYNOPSIS
        Checks if an AD group exists

    .DESCRIPTION
        Verifies existence of an Active Directory group.
        Read-only operation.

    .PARAMETER GroupName
        Name or SamAccountName of the group

    .EXAMPLE
        Test-ADGroupExists -GroupName "Domain Admins"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName
    )

    begin {
        Write-Verbose "Checking if AD group exists: $GroupName"
    }

    process {
        try {
            # Verify AD module
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                Write-Verbose "ActiveDirectory module is not available"
                return $false
            }

            Import-Module ActiveDirectory -ErrorAction Stop

            $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop

            if ($group) {
                Write-Verbose "Group exists: $GroupName"
                return $true
            }

            return $false
        }
        catch {
            Write-Verbose "Group does not exist or is not accessible: $GroupName"
            return $false
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-DomainInfo',
    'Test-DomainJoined',
    'Get-ADGroupMembers',
    'Get-ADGroupMembershipData',
    'Get-ADComputersInOU',
    'Get-OUStructure',
    'Get-ADDomainControllers',
    'Test-ADGroupExists'
)
