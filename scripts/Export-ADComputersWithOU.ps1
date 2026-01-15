<#
.SYNOPSIS
    Export AD computers with OU and OS information to CSV

.DESCRIPTION
    Exports all Active Directory computers with:
    - Computer name
    - Operating System
    - Operating System Version
    - Full OU path (DistinguishedName parsed)

.EXAMPLE
    .\Export-ADComputersWithOU.ps1

.NOTES
    Requires ActiveDirectory module
    Run from a machine with RSAT or on a Domain Controller
    CSV is Excel-ready with UTF8 encoding
#>

param(
    [string]$OutputPath = ".\AD_Computers_With_OU.csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Exporting AD computers to: $OutputPath" -ForegroundColor Cyan

try {
    Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,DistinguishedName |
    Select-Object `
        Name,
        OperatingSystem,
        OperatingSystemVersion,
        @{Name="OU";Expression={($_.DistinguishedName -split ',OU=',2)[1]}} |
    Export-Csv $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "SUCCESS: Exported $(Import-Csv $OutputPath | Measure-Object).Count computers" -ForegroundColor Green
    Write-Host "Output: $((Get-Item $OutputPath).FullName)" -ForegroundColor White
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
