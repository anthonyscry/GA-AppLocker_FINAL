#Requires -Version 5.1

<#
.SYNOPSIS
    Get computers from Active Directory for AppLocker scanning.

.DESCRIPTION
    Retrieves computer names from AD that can be piped to Scan-And-CreateAppLockerPolicy.ps1.
    Filters for enabled Windows computers.

.PARAMETER SearchBase
    The AD OU to search. If not specified, searches entire domain.

.PARAMETER Filter
    LDAP filter for computers. Defaults to all enabled Windows computers.

.PARAMETER OperatingSystem
    Filter by OS name (e.g., "*Windows 10*", "*Server 2019*")

.PARAMETER MaxCount
    Maximum number of computers to return. Defaults to 100.

.PARAMETER OutputFile
    Optional: Save computer list to a file.

.EXAMPLE
    .\Get-ADComputersForScan.ps1
    Gets all enabled Windows computers from AD.

.EXAMPLE
    .\Get-ADComputersForScan.ps1 -OperatingSystem "*Windows 10*" -MaxCount 50
    Gets up to 50 Windows 10 computers.

.EXAMPLE
    .\Get-ADComputersForScan.ps1 | .\Scan-And-CreateAppLockerPolicy.ps1 -CreatePolicy
    Gets computers from AD and scans them.

.EXAMPLE
    .\Get-ADComputersForScan.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com"
    Gets computers from a specific OU.
#>

[CmdletBinding()]
param(
    [string]$SearchBase,

    [string]$Filter = "(&(objectCategory=computer)(operatingSystem=*Windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",

    [string]$OperatingSystem,

    [int]$MaxCount = 100,

    [string]$OutputFile
)

# Check if AD module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ERROR: Active Directory PowerShell module not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "To install on Windows 10/11:" -ForegroundColor Yellow
    Write-Host "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Or install RSAT from Settings > Apps > Optional Features" -ForegroundColor Yellow
    Write-Host ""

    # Fall back to listing local computer
    Write-Host "Returning local computer only..." -ForegroundColor Yellow
    return $env:COMPUTERNAME
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "ERROR: Failed to import Active Directory module: $($_.Exception.Message)" -ForegroundColor Red
    return $env:COMPUTERNAME
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Get AD Computers for AppLocker Scan" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    # Build search parameters
    $searchParams = @{
        Filter = "Enabled -eq `$true"
        Properties = "Name", "OperatingSystem", "LastLogonDate", "DistinguishedName"
    }

    if ($SearchBase) {
        $searchParams["SearchBase"] = $SearchBase
        Write-Host "Search Base: $SearchBase" -ForegroundColor White
    } else {
        Write-Host "Search Base: Entire Domain" -ForegroundColor White
    }

    # Get computers
    $computers = Get-ADComputer @searchParams -ErrorAction Stop

    # Filter by OS if specified
    if ($OperatingSystem) {
        $computers = $computers | Where-Object { $_.OperatingSystem -like $OperatingSystem }
        Write-Host "OS Filter: $OperatingSystem" -ForegroundColor White
    }

    # Filter to Windows only
    $computers = $computers | Where-Object { $_.OperatingSystem -like "*Windows*" }

    # Sort by last logon (most recent first) and limit
    $computers = $computers |
        Sort-Object LastLogonDate -Descending |
        Select-Object -First $MaxCount

    Write-Host ""
    Write-Host "Found $($computers.Count) computers:" -ForegroundColor Green
    Write-Host ""

    # Display summary
    $computers | ForEach-Object {
        $lastLogon = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
        Write-Host "  $($_.Name.PadRight(20)) | $($_.OperatingSystem.PadRight(30)) | Last: $lastLogon" -ForegroundColor Gray
    }

    Write-Host ""

    # Save to file if requested
    if ($OutputFile) {
        $computers | Select-Object Name | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Saved to: $OutputFile" -ForegroundColor Yellow
        Write-Host ""
    }

    # Output just the computer names (for piping)
    $computerNames = $computers | ForEach-Object { $_.Name }

    Write-Host "Usage Examples:" -ForegroundColor Cyan
    Write-Host "  # Scan all these computers:" -ForegroundColor Gray
    Write-Host "  .\Get-ADComputersForScan.ps1 | .\Scan-And-CreateAppLockerPolicy.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Save list and scan:" -ForegroundColor Gray
    Write-Host "  .\Get-ADComputersForScan.ps1 -OutputFile computers.csv" -ForegroundColor Gray
    Write-Host "  Import-Csv computers.csv | .\Scan-And-CreateAppLockerPolicy.ps1 -CreatePolicy" -ForegroundColor Gray
    Write-Host ""

    return $computerNames

} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red

    # Common error handling
    if ($_.Exception.Message -like "*Unable to find*" -or $_.Exception.Message -like "*server is not operational*") {
        Write-Host ""
        Write-Host "Cannot connect to Active Directory. Possible reasons:" -ForegroundColor Yellow
        Write-Host "  - Not connected to domain network" -ForegroundColor Gray
        Write-Host "  - Domain controller not reachable" -ForegroundColor Gray
        Write-Host "  - Insufficient permissions" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Returning local computer only..." -ForegroundColor Yellow
    }

    return $env:COMPUTERNAME
}
