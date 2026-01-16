<#
.SYNOPSIS
    Active Directory computer discovery ViewModel

.DESCRIPTION
    Manages discovered computers from Active Directory, including computer status,
    connectivity, and selection for compliance scanning or rule generation.

.NOTES
    Module Name: DiscoveryViewModel
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: BusinessLogic/ActiveDirectory-DataAccess

.EXAMPLE
    Import-Module .\DiscoveryViewModel.ps1

    # Initialize and add discovered computers
    Initialize-Discovery
    Add-DiscoveredComputer -ComputerName "PC01" -OU "OU=Workstations,DC=contoso,DC=com"
    $computers = Get-DiscoveredComputers

.EXAMPLE
    # Update computer connectivity status
    Update-ComputerStatus -ComputerName "PC01" -IsOnline $true -ResponseTime 15

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# SCRIPT-SCOPE STATE
# ============================================================

$script:DiscoveredComputers = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$script:DiscoveryFilters = [hashtable]::Synchronized(@{
    OU = "All"
    OnlineStatus = "All"      # All, Online, Offline
    OperatingSystem = "All"
    SearchText = ""
    ShowDisabledComputers = $false
})

$script:DiscoveryStatistics = [hashtable]::Synchronized(@{
    TotalComputers = 0
    OnlineComputers = 0
    OfflineComputers = 0
    UnknownStatus = 0
    WindowsServers = 0
    WindowsWorkstations = 0
    LastDiscoveryDate = $null
    DiscoveryDuration = 0
})

$script:SelectedComputers = [hashtable]::Synchronized(@{})

# ============================================================
# PUBLIC FUNCTIONS - INITIALIZATION & DATA RETRIEVAL
# ============================================================

function Initialize-Discovery {
    <#
    .SYNOPSIS
        Initializes the discovery collection

    .DESCRIPTION
        Clears existing discovered computers and resets state

    .EXAMPLE
        Initialize-Discovery
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Initializing discovery collection..."

        $script:DiscoveredComputers.Clear()
        $script:SelectedComputers.Clear()

        # Reset filters
        $script:DiscoveryFilters.OU = "All"
        $script:DiscoveryFilters.OnlineStatus = "All"
        $script:DiscoveryFilters.OperatingSystem = "All"
        $script:DiscoveryFilters.SearchText = ""
        $script:DiscoveryFilters.ShowDisabledComputers = $false

        # Reset statistics
        Update-DiscoveryStatistics

        Write-Verbose "Discovery collection initialized"
        return @{ success = $true; message = "Discovery initialized" }
    }
    catch {
        Write-Warning "Failed to initialize discovery: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-DiscoveredComputers {
    <#
    .SYNOPSIS
        Gets the list of discovered computers

    .PARAMETER ApplyFilters
        Whether to apply current filters (default: $true)

    .PARAMETER IncludeDetails
        Whether to include full computer details (default: $true)

    .OUTPUTS
        Array of discovered computer objects

    .EXAMPLE
        $computers = Get-DiscoveredComputers
        $dataGrid.ItemsSource = $computers
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$ApplyFilters = $true,

        [Parameter()]
        [bool]$IncludeDetails = $true
    )

    try {
        Write-Verbose "Getting discovered computers (ApplyFilters: $ApplyFilters)..."

        # Get base collection
        $computers = if ($ApplyFilters) {
            Get-FilteredComputers
        } else {
            $script:DiscoveredComputers.ToArray()
        }

        # Format for display
        if ($IncludeDetails) {
            $displayItems = $computers | ForEach-Object {
                [PSCustomObject]@{
                    ComputerName = $_.ComputerName
                    DNSHostName = $_.DNSHostName
                    OperatingSystem = $_.OperatingSystem
                    OperatingSystemVersion = $_.OperatingSystemVersion
                    OU = $_.OU
                    Description = $_.Description
                    IsOnline = $_.IsOnline
                    OnlineStatus = if ($_.IsOnline -eq $true) { "Online" }
                                  elseif ($_.IsOnline -eq $false) { "Offline" }
                                  else { "Unknown" }
                    ResponseTime = $_.ResponseTime
                    LastLogon = $_.LastLogon
                    IsEnabled = $_.IsEnabled
                    IsSelected = $script:SelectedComputers.ContainsKey($_.ComputerName)
                    IPv4Address = $_.IPv4Address
                    CreatedDate = $_.CreatedDate
                    ModifiedDate = $_.ModifiedDate
                    _RawData = $_
                }
            }
            return $displayItems
        } else {
            return $computers | Select-Object ComputerName, OnlineStatus, OperatingSystem
        }
    }
    catch {
        Write-Warning "Failed to get discovered computers: $($_.Exception.Message)"
        return @()
    }
}

function Get-ComputerByName {
    <#
    .SYNOPSIS
        Gets a specific computer by name

    .PARAMETER ComputerName
        Name of the computer to retrieve

    .OUTPUTS
        Computer object or $null if not found

    .EXAMPLE
        $computer = Get-ComputerByName -ComputerName "PC01"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    try {
        $computer = $script:DiscoveredComputers | Where-Object { $_.ComputerName -eq $ComputerName } | Select-Object -First 1
        return $computer
    }
    catch {
        Write-Warning "Failed to get computer by name: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PUBLIC FUNCTIONS - COMPUTER MANAGEMENT
# ============================================================

function Add-DiscoveredComputer {
    <#
    .SYNOPSIS
        Adds a discovered computer to the collection

    .PARAMETER ComputerName
        Name of the computer

    .PARAMETER DNSHostName
        DNS hostname

    .PARAMETER OperatingSystem
        Operating system name

    .PARAMETER OU
        Organizational Unit DN

    .PARAMETER Description
        Computer description

    .PARAMETER IsEnabled
        Whether the computer account is enabled

    .PARAMETER LastLogon
        Last logon timestamp

    .PARAMETER IPv4Address
        IPv4 address

    .EXAMPLE
        Add-DiscoveredComputer -ComputerName "PC01" -OperatingSystem "Windows 10" -OU "OU=Workstations,DC=contoso,DC=com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [string]$DNSHostName = "",

        [Parameter()]
        [string]$OperatingSystem = "Unknown",

        [Parameter()]
        [string]$OperatingSystemVersion = "",

        [Parameter()]
        [string]$OU = "",

        [Parameter()]
        [string]$Description = "",

        [Parameter()]
        [bool]$IsEnabled = $true,

        [Parameter()]
        [datetime]$LastLogon,

        [Parameter()]
        [string]$IPv4Address = "",

        [Parameter()]
        [datetime]$CreatedDate,

        [Parameter()]
        [datetime]$ModifiedDate
    )

    try {
        Write-Verbose "Adding discovered computer: $ComputerName..."

        # Check if already exists
        $existing = $script:DiscoveredComputers | Where-Object { $_.ComputerName -eq $ComputerName } | Select-Object -First 1
        if ($existing) {
            Write-Verbose "Computer already exists, updating: $ComputerName"
            return Update-DiscoveredComputer -ComputerName $ComputerName -OperatingSystem $OperatingSystem -OU $OU -Description $Description -IsEnabled $IsEnabled
        }

        # Create computer object
        $computer = [PSCustomObject]@{
            ComputerName = $ComputerName
            DNSHostName = if ($DNSHostName) { $DNSHostName } else { $ComputerName }
            OperatingSystem = $OperatingSystem
            OperatingSystemVersion = $OperatingSystemVersion
            OU = $OU
            Description = $Description
            IsOnline = $null  # null = unknown, true = online, false = offline
            ResponseTime = 0
            LastLogon = $LastLogon
            IsEnabled = $IsEnabled
            IPv4Address = $IPv4Address
            CreatedDate = $CreatedDate
            ModifiedDate = $ModifiedDate
            DiscoveredDate = Get-Date
            LastStatusCheck = $null
        }

        [void]$script:DiscoveredComputers.Add($computer)

        # Update statistics
        Update-DiscoveryStatistics

        Write-Verbose "Computer added: $ComputerName"
        return @{ success = $true; message = "Computer added"; computer = $computer }
    }
    catch {
        Write-Warning "Failed to add discovered computer: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Add-DiscoveredComputers {
    <#
    .SYNOPSIS
        Adds multiple discovered computers to the collection

    .PARAMETER Computers
        Array of computer objects or hashtables

    .EXAMPLE
        Add-DiscoveredComputers -Computers $computerArray
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Computers
    )

    try {
        Write-Verbose "Adding $($Computers.Count) discovered computers..."

        $addedCount = 0
        $updatedCount = 0

        foreach ($comp in $Computers) {
            $params = @{
                ComputerName = $comp.ComputerName
            }

            if ($comp.DNSHostName) { $params.DNSHostName = $comp.DNSHostName }
            if ($comp.OperatingSystem) { $params.OperatingSystem = $comp.OperatingSystem }
            if ($comp.OperatingSystemVersion) { $params.OperatingSystemVersion = $comp.OperatingSystemVersion }
            if ($comp.OU) { $params.OU = $comp.OU }
            if ($comp.Description) { $params.Description = $comp.Description }
            if ($null -ne $comp.IsEnabled) { $params.IsEnabled = $comp.IsEnabled }
            if ($comp.LastLogon) { $params.LastLogon = $comp.LastLogon }
            if ($comp.IPv4Address) { $params.IPv4Address = $comp.IPv4Address }
            if ($comp.CreatedDate) { $params.CreatedDate = $comp.CreatedDate }
            if ($comp.ModifiedDate) { $params.ModifiedDate = $comp.ModifiedDate }

            $result = Add-DiscoveredComputer @params
            if ($result.success) {
                if ($result.message -match "updated") {
                    $updatedCount++
                } else {
                    $addedCount++
                }
            }
        }

        Write-Verbose "Added $addedCount computers, updated $updatedCount computers"
        return @{
            success = $true
            message = "Added $addedCount, updated $updatedCount computers"
            addedCount = $addedCount
            updatedCount = $updatedCount
        }
    }
    catch {
        Write-Warning "Failed to add discovered computers: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-DiscoveredComputer {
    <#
    .SYNOPSIS
        Updates a discovered computer's information

    .PARAMETER ComputerName
        Name of the computer to update

    .PARAMETER OperatingSystem
        Updated operating system

    .PARAMETER OU
        Updated OU

    .PARAMETER Description
        Updated description

    .PARAMETER IsEnabled
        Updated enabled status

    .EXAMPLE
        Update-DiscoveredComputer -ComputerName "PC01" -Description "Finance Department PC"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [string]$OperatingSystem,

        [Parameter()]
        [string]$OU,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [bool]$IsEnabled
    )

    try {
        Write-Verbose "Updating discovered computer: $ComputerName..."

        $computer = Get-ComputerByName -ComputerName $ComputerName

        if (-not $computer) {
            throw "Computer not found: $ComputerName"
        }

        # Update fields
        if ($OperatingSystem) { $computer.OperatingSystem = $OperatingSystem }
        if ($OU) { $computer.OU = $OU }
        if ($Description) { $computer.Description = $Description }
        if ($null -ne $IsEnabled) { $computer.IsEnabled = $IsEnabled }

        $computer.ModifiedDate = Get-Date

        Write-Verbose "Computer updated: $ComputerName"
        return @{ success = $true; message = "Computer updated"; computer = $computer }
    }
    catch {
        Write-Warning "Failed to update discovered computer: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-ComputerStatus {
    <#
    .SYNOPSIS
        Updates computer connectivity status

    .PARAMETER ComputerName
        Name of the computer

    .PARAMETER IsOnline
        Whether the computer is online

    .PARAMETER ResponseTime
        Ping response time in milliseconds

    .EXAMPLE
        Update-ComputerStatus -ComputerName "PC01" -IsOnline $true -ResponseTime 15
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [bool]$IsOnline,

        [Parameter()]
        [int]$ResponseTime = 0
    )

    try {
        Write-Verbose "Updating status for computer: $ComputerName (Online: $IsOnline)..."

        $computer = Get-ComputerByName -ComputerName $ComputerName

        if (-not $computer) {
            throw "Computer not found: $ComputerName"
        }

        $computer.IsOnline = $IsOnline
        $computer.ResponseTime = $ResponseTime
        $computer.LastStatusCheck = Get-Date

        # Update statistics
        Update-DiscoveryStatistics

        Write-Verbose "Status updated for: $ComputerName"
        return @{ success = $true; message = "Status updated"; isOnline = $IsOnline }
    }
    catch {
        Write-Warning "Failed to update computer status: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Clear-Discovery {
    <#
    .SYNOPSIS
        Clears all discovered computers

    .EXAMPLE
        Clear-Discovery
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Clearing discovery collection..."

        $count = $script:DiscoveredComputers.Count
        $script:DiscoveredComputers.Clear()
        $script:SelectedComputers.Clear()

        Update-DiscoveryStatistics

        Write-Verbose "Cleared $count computers"
        return @{ success = $true; message = "Cleared $count computers"; count = $count }
    }
    catch {
        Write-Warning "Failed to clear discovery: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - SELECTION MANAGEMENT
# ============================================================

function Select-Computer {
    <#
    .SYNOPSIS
        Marks a computer as selected

    .PARAMETER ComputerName
        Name of the computer to select

    .EXAMPLE
        Select-Computer -ComputerName "PC01"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    try {
        $script:SelectedComputers[$ComputerName] = $true
        return @{ success = $true; message = "Computer selected" }
    }
    catch {
        Write-Warning "Failed to select computer: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Deselect-Computer {
    <#
    .SYNOPSIS
        Deselects a computer

    .PARAMETER ComputerName
        Name of the computer to deselect

    .EXAMPLE
        Deselect-Computer -ComputerName "PC01"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    try {
        if ($script:SelectedComputers.ContainsKey($ComputerName)) {
            $script:SelectedComputers.Remove($ComputerName)
        }
        return @{ success = $true; message = "Computer deselected" }
    }
    catch {
        Write-Warning "Failed to deselect computer: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-SelectedComputers {
    <#
    .SYNOPSIS
        Gets the list of selected computer names

    .OUTPUTS
        Array of selected computer names

    .EXAMPLE
        $selected = Get-SelectedComputers
    #>
    [CmdletBinding()]
    param()

    try {
        return $script:SelectedComputers.Keys | ForEach-Object { $_ }
    }
    catch {
        Write-Warning "Failed to get selected computers: $($_.Exception.Message)"
        return @()
    }
}

function Clear-Selection {
    <#
    .SYNOPSIS
        Clears all computer selections

    .EXAMPLE
        Clear-Selection
    #>
    [CmdletBinding()]
    param()

    try {
        $script:SelectedComputers.Clear()
        return @{ success = $true; message = "Selection cleared" }
    }
    catch {
        Write-Warning "Failed to clear selection: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - FILTERING & STATISTICS
# ============================================================

function Apply-DiscoveryFilters {
    <#
    .SYNOPSIS
        Applies filters to the discovery collection

    .PARAMETER OU
        Filter by OU

    .PARAMETER OnlineStatus
        Filter by online status: All, Online, Offline

    .PARAMETER OperatingSystem
        Filter by operating system

    .PARAMETER SearchText
        Filter by search text

    .PARAMETER ShowDisabledComputers
        Whether to show disabled computer accounts

    .EXAMPLE
        Apply-DiscoveryFilters -OnlineStatus "Online" -OperatingSystem "Windows 10"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OU,

        [Parameter()]
        [ValidateSet("All", "Online", "Offline")]
        [string]$OnlineStatus,

        [Parameter()]
        [string]$OperatingSystem,

        [Parameter()]
        [string]$SearchText,

        [Parameter()]
        [bool]$ShowDisabledComputers
    )

    try {
        Write-Verbose "Applying discovery filters..."

        if ($OU) { $script:DiscoveryFilters.OU = $OU }
        if ($OnlineStatus) { $script:DiscoveryFilters.OnlineStatus = $OnlineStatus }
        if ($OperatingSystem) { $script:DiscoveryFilters.OperatingSystem = $OperatingSystem }
        if ($null -ne $SearchText) { $script:DiscoveryFilters.SearchText = $SearchText }
        if ($null -ne $ShowDisabledComputers) { $script:DiscoveryFilters.ShowDisabledComputers = $ShowDisabledComputers }

        Write-Verbose "Filters applied"
        return @{ success = $true; message = "Filters applied" }
    }
    catch {
        Write-Warning "Failed to apply discovery filters: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-DiscoveryStatistics {
    <#
    .SYNOPSIS
        Gets discovery statistics

    .OUTPUTS
        Hashtable containing statistics

    .EXAMPLE
        $stats = Get-DiscoveryStatistics
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            TotalComputers = $script:DiscoveryStatistics.TotalComputers
            OnlineComputers = $script:DiscoveryStatistics.OnlineComputers
            OfflineComputers = $script:DiscoveryStatistics.OfflineComputers
            UnknownStatus = $script:DiscoveryStatistics.UnknownStatus
            WindowsServers = $script:DiscoveryStatistics.WindowsServers
            WindowsWorkstations = $script:DiscoveryStatistics.WindowsWorkstations
            LastDiscoveryDate = $script:DiscoveryStatistics.LastDiscoveryDate
            DiscoveryDuration = $script:DiscoveryStatistics.DiscoveryDuration
            SelectedCount = $script:SelectedComputers.Count
        }
    }
    catch {
        Write-Warning "Failed to get discovery statistics: $($_.Exception.Message)"
        return @{ TotalComputers = 0 }
    }
}

# ============================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================

function Get-FilteredComputers {
    [CmdletBinding()]
    param()

    $filtered = $script:DiscoveredComputers.ToArray()

    # Apply OU filter
    if ($script:DiscoveryFilters.OU -ne "All") {
        $filtered = $filtered | Where-Object { $_.OU -eq $script:DiscoveryFilters.OU }
    }

    # Apply OnlineStatus filter
    if ($script:DiscoveryFilters.OnlineStatus -ne "All") {
        $isOnline = ($script:DiscoveryFilters.OnlineStatus -eq "Online")
        $filtered = $filtered | Where-Object { $_.IsOnline -eq $isOnline }
    }

    # Apply OperatingSystem filter
    if ($script:DiscoveryFilters.OperatingSystem -ne "All") {
        $filtered = $filtered | Where-Object { $_.OperatingSystem -like "*$($script:DiscoveryFilters.OperatingSystem)*" }
    }

    # Apply disabled computers filter
    if (-not $script:DiscoveryFilters.ShowDisabledComputers) {
        $filtered = $filtered | Where-Object { $_.IsEnabled -eq $true }
    }

    # Apply search text filter
    if ($script:DiscoveryFilters.SearchText) {
        $searchText = $script:DiscoveryFilters.SearchText.ToLower()
        $filtered = $filtered | Where-Object {
            $_.ComputerName.ToLower().Contains($searchText) -or
            ($_.Description -and $_.Description.ToLower().Contains($searchText)) -or
            ($_.OU -and $_.OU.ToLower().Contains($searchText))
        }
    }

    return $filtered
}

function Update-DiscoveryStatistics {
    [CmdletBinding()]
    param()

    try {
        $computers = $script:DiscoveredComputers.ToArray()

        $script:DiscoveryStatistics.TotalComputers = $computers.Count
        $script:DiscoveryStatistics.OnlineComputers = ($computers | Where-Object { $_.IsOnline -eq $true }).Count
        $script:DiscoveryStatistics.OfflineComputers = ($computers | Where-Object { $_.IsOnline -eq $false }).Count
        $script:DiscoveryStatistics.UnknownStatus = ($computers | Where-Object { $null -eq $_.IsOnline }).Count

        $script:DiscoveryStatistics.WindowsServers = ($computers | Where-Object { $_.OperatingSystem -like "*Server*" }).Count
        $script:DiscoveryStatistics.WindowsWorkstations = ($computers | Where-Object { $_.OperatingSystem -notlike "*Server*" }).Count

        if ($computers.Count -gt 0) {
            $script:DiscoveryStatistics.LastDiscoveryDate = Get-Date
        }
    }
    catch {
        Write-Verbose "Failed to update discovery statistics: $($_.Exception.Message)"
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Initialize-Discovery',
    'Get-DiscoveredComputers',
    'Get-ComputerByName',
    'Add-DiscoveredComputer',
    'Add-DiscoveredComputers',
    'Update-DiscoveredComputer',
    'Update-ComputerStatus',
    'Clear-Discovery',
    'Select-Computer',
    'Deselect-Computer',
    'Get-SelectedComputers',
    'Clear-Selection',
    'Apply-DiscoveryFilters',
    'Get-DiscoveryStatistics'
)
