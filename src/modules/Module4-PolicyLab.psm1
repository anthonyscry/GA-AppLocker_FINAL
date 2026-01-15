# Module4-PolicyLab.psm1
# Policy Lab module for GA-AppLocker
# Manages GPO creation, linking, and policy deployment

<#
.SYNOPSIS
    Create AppLocker GPO
.DESCRIPTION
    Creates a new Group Policy Object for AppLocker
#>
function New-AppLockerGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,
        [string]$Comment = 'AppLocker policy managed by GA-AppLocker Dashboard'
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'GroupPolicy module not available'
        }
    }

    if ([string]::IsNullOrWhiteSpace($GpoName)) {
        return @{
            success = $false
            error = 'GPO name is required'
        }
    }

    try {
        $existing = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if ($existing) {
            return @{
                success = $true
                gpo = $existing
                gpoName = $GpoName
                gpoId = $existing.Id.ToString()
                existed = $true
                message = 'GPO already exists'
            }
        }

        $gpo = New-GPO -Name $GpoName -Comment $Comment

        return @{
            success = $true
            gpo = $gpo
            gpoName = $GpoName
            gpoId = $gpo.Id.ToString()
            existed = $false
            message = 'GPO created successfully'
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
    Link GPO to OU
.DESCRIPTION
    Links a GPO to an Organizational Unit
#>
function Add-GPOLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
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
        $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            return @{
                success = $false
                error = "GPO not found: $GpoName"
            }
        }

        $inheritance = Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue
        if ($inheritance) {
            $existingLink = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
            if ($existingLink) {
                return @{
                    success = $true
                    existed = $true
                    message = 'GPO is already linked to this target'
                }
            }
        }

        New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes -ErrorAction Stop

        return @{
            success = $true
            existed = $false
            gpoName = $GpoName
            target = $TargetOU
            message = 'GPO linked successfully'
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
    Get All OUs with Computer Counts
.DESCRIPTION
    Lists all OUs and their computer counts
#>
function Get-OUsWithComputerCounts {
    [CmdletBinding()]
    param()

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
        $ous = Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName

        $results = @()
        foreach ($ou in $ous) {
            $computers = Get-ADComputer -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue
            $count = if ($computers) { @($computers).Count } else { 0 }

            $results += @{
                name = $ou.Name
                path = $ou.DistinguishedName
                computerCount = $count
            }
        }

        $results = $results | Sort-Object -Property computerCount -Descending

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
    Set AppLocker Policy in GPO
.DESCRIPTION
    Applies an AppLocker XML policy to a GPO
#>
function Set-GPOAppLockerPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,
        [Parameter(Mandatory = $true)]
        [string]$PolicyXmlPath
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'GroupPolicy module not available'
        }
    }

    try {
        $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            return @{
                success = $false
                error = "GPO not found: $GpoName"
            }
        }

        if (-not (Test-Path $PolicyXmlPath)) {
            return @{
                success = $false
                error = "XML file not found: $PolicyXmlPath"
            }
        }

        $xmlContent = Get-Content -Path $PolicyXmlPath -Raw
        $domain = (Get-ADDomain).DNSRoot
        $ldapPath = "LDAP://CN={$($gpo.Id)},CN=Policies,CN=System,DC=$($domain -replace '\.',',DC=')"

        Set-AppLockerPolicy -XMLPolicy $xmlContent -LDAP $ldapPath -ErrorAction Stop

        return @{
            success = $true
            gpoName = $GpoName
            policyPath = $PolicyXmlPath
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
    Save Policy to File
.DESCRIPTION
    Saves an AppLocker policy XML to a file
#>
function Save-PolicyToFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyXml,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $PolicyXml | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        return @{
            success = $true
            path = $OutputPath
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
Export-ModuleMember -Function New-AppLockerGPO, Add-GPOLink, Get-OUsWithComputerCounts,
                              Set-GPOAppLockerPolicy, Save-PolicyToFile
