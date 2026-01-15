<#
.SYNOPSIS
    Export AD groups with members to CSV

.DESCRIPTION
    Exports all Active Directory groups with their members.
    Creates one row per group member (audit-friendly format).

    Columns:
    - GroupName: AD group name
    - MemberName: User/Computer name
    - MemberType: user/computer/group
    - SamAccountName: Login name

.EXAMPLE
    .\Export-ADGroupsWithMembers.ps1

.NOTES
    Requires ActiveDirectory module
    Uses Get-ADGroupMember -Recursive to resolve nested groups
    Large domains: run from a DC or RSAT box
#>

param(
    [string]$OutputPath = ".\AD_Groups_With_Members.csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Exporting AD groups with members to: $OutputPath" -ForegroundColor Cyan
Write-Host "This may take a while for large domains..." -ForegroundColor Yellow

try {
    $totalMembers = 0
    $groupCount = 0

    Get-ADGroup -Filter * |
    ForEach-Object {
        $group = $_
        $groupCount++
        Write-ProgressHelper "Processing groups" $groupCount 100

        Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                GroupName = $group.Name
                MemberName = $_.Name
                MemberType = $_.ObjectClass
                SamAccountName = $_.SamAccountName
            }
            $totalMembers++
        }
    } |
    Export-Csv $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "SUCCESS: Exported $groupCount groups with $totalMembers member records" -ForegroundColor Green
    Write-Host "Output: $((Get-Item $OutputPath).FullName)" -ForegroundColor White
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
