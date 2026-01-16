#Requires -Version 5.1
<#
.SYNOPSIS
    GA-AppLocker Active Directory Module
.DESCRIPTION
    Functions for retrieving computers from Active Directory.
#>

# ============================================================
# AD FUNCTIONS
# ============================================================

function Test-ADModule {
    <#
    .SYNOPSIS
        Check if AD PowerShell module is available.
    .OUTPUTS
        Boolean.
    #>
    return $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)
}

function Get-ADComputerList {
    <#
    .SYNOPSIS
        Get Windows computers from Active Directory.
    .PARAMETER SearchBase
        OU to search in.
    .PARAMETER OperatingSystem
        Filter by OS name pattern.
    .PARAMETER MaxCount
        Maximum computers to return.
    .OUTPUTS
        Array of computer names.
    #>
    param(
        [string]$SearchBase,
        [string]$OperatingSystem,
        [int]$MaxCount = 100
    )

    # Check for AD module
    if (-not (Test-ADModule)) {
        Write-Warning "Active Directory module not available. Returning local computer."
        return @($env:COMPUTERNAME)
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Warning "Failed to import AD module: $_"
        return @($env:COMPUTERNAME)
    }

    try {
        # Build search parameters
        $params = @{
            Filter     = "Enabled -eq `$true"
            Properties = "Name", "OperatingSystem", "LastLogonDate"
        }

        if ($SearchBase) {
            $params["SearchBase"] = $SearchBase
        }

        # Get computers
        $computers = Get-ADComputer @params -ErrorAction Stop

        # Filter by OS if specified
        if ($OperatingSystem) {
            $computers = $computers | Where-Object { $_.OperatingSystem -like $OperatingSystem }
        }

        # Filter to Windows only
        $computers = $computers | Where-Object { $_.OperatingSystem -like "*Windows*" }

        # Sort by last logon and limit
        $computers = $computers |
            Sort-Object LastLogonDate -Descending |
            Select-Object -First $MaxCount

        return $computers | ForEach-Object { $_.Name }

    } catch {
        Write-Warning "AD query failed: $_"
        return @($env:COMPUTERNAME)
    }
}

function Get-ADComputerInfo {
    <#
    .SYNOPSIS
        Get detailed info about AD computers.
    .PARAMETER SearchBase
        OU to search in.
    .PARAMETER OperatingSystem
        Filter by OS name pattern.
    .PARAMETER MaxCount
        Maximum computers to return.
    .OUTPUTS
        Array of computer info objects.
    #>
    param(
        [string]$SearchBase,
        [string]$OperatingSystem,
        [int]$MaxCount = 100
    )

    if (-not (Test-ADModule)) {
        return @([PSCustomObject]@{
            Name            = $env:COMPUTERNAME
            OperatingSystem = (Get-CimInstance Win32_OperatingSystem).Caption
            LastLogonDate   = Get-Date
        })
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $params = @{
            Filter     = "Enabled -eq `$true"
            Properties = "Name", "OperatingSystem", "LastLogonDate", "DistinguishedName"
        }

        if ($SearchBase) { $params["SearchBase"] = $SearchBase }

        $computers = Get-ADComputer @params -ErrorAction Stop

        if ($OperatingSystem) {
            $computers = $computers | Where-Object { $_.OperatingSystem -like $OperatingSystem }
        }

        $computers = $computers | Where-Object { $_.OperatingSystem -like "*Windows*" }

        return $computers |
            Sort-Object LastLogonDate -Descending |
            Select-Object -First $MaxCount |
            ForEach-Object {
                [PSCustomObject]@{
                    Name            = $_.Name
                    OperatingSystem = $_.OperatingSystem
                    LastLogonDate   = $_.LastLogonDate
                    OU              = ($_.DistinguishedName -split ',', 2)[1]
                }
            }

    } catch {
        Write-Warning "AD query failed: $_"
        return @()
    }
}

# ============================================================
# EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Test-ADModule',
    'Get-ADComputerList',
    'Get-ADComputerInfo'
)
