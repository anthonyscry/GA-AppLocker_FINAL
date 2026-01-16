# Module4-PolicyLab.psm1
# Policy Lab module for GA-AppLocker
# Manages GPO creation, linking, and policy deployment
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

# Import Config for path configuration
Import-Module (Join-Path $PSScriptRoot '..\Config.psm1') -ErrorAction SilentlyContinue

# Import required modules at module level for performance
# These imports are done once at module load instead of per function call
Import-Module GroupPolicy -ErrorAction SilentlyContinue -Verbose:$false
Import-Module ActiveDirectory -ErrorAction SilentlyContinue -Verbose:$false

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

    # Check if GroupPolicy module is available (imported at module level)
    if (-not (Get-Module GroupPolicy)) {
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

    # Additional validation for empty strings
    if ([string]::IsNullOrWhiteSpace($GpoName)) {
        return @{
            success = $false
            error = 'GPO name is required'
        }
    }

    if ([string]::IsNullOrWhiteSpace($TargetOU)) {
        return @{
            success = $false
            error = 'Target OU is required'
        }
    }

    # Check if required modules are available (imported at module level)
    if (-not (Get-Module GroupPolicy)) {
        return @{
            success = $false
            error = 'GroupPolicy module not available'
        }
    }

    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. This feature requires a Domain Controller or domain-joined computer with RSAT installed.'
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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. This feature requires a Domain Controller or domain-joined computer with RSAT installed.'
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
    Applies an AppLocker XML policy to a GPO using improved LDAP path construction (from AaronLocker)
#>
function Set-GPOAppLockerPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,
        [Parameter(Mandatory = $true)]
        [string]$PolicyXmlPath,
        [switch]$Enforce
    )

    # Validate XML path for directory traversal attacks
    if ($PolicyXmlPath -match '\.\.\\|\.\./|:|\x00') {
        return @{
            success = $false
            error = 'Invalid XML path: path traversal patterns detected'
        }
    }

    # Ensure path is absolute
    if (-not [System.IO.Path]::IsPathRooted($PolicyXmlPath)) {
        return @{
            success = $false
            error = 'Invalid XML path: must be an absolute path'
        }
    }

    # Check if required modules are available (imported at module level)
    if (-not (Get-Module GroupPolicy)) {
        return @{
            success = $false
            error = 'GroupPolicy module not available'
        }
    }

    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. This feature requires a Domain Controller or domain-joined computer with RSAT installed.'
        }
    }

    if (-not (Test-Path $PolicyXmlPath)) {
        return @{
            success = $false
            error = "XML file not found: $PolicyXmlPath"
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

        # Load and potentially modify enforcement mode (from AaronLocker pattern)
        $xmlContent = Get-Content -Path $PolicyXmlPath -Raw
        $policy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::FromXml($xmlContent)

        if ($Enforce) {
            foreach ($ruleCollection in $policy.RuleCollections) {
                $ruleCollection.EnforcementMode = "Enabled"
            }
        }

        # Better LDAP path construction (from AaronLocker)
        # Note: Correct namespace capitalization is critical - DirectoryServices.ActiveDirectory
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $ldapPath = "LDAP://{0}" -f $gpo.Path.Replace("LDAP://", "")

        Write-Verbose "Applying policy to GPO '$GpoName' in domain '$($domain.Name)'"
        Set-AppLockerPolicy -AppLockerPolicy $policy -LDAP $ldapPath -ErrorAction Stop

        return @{
            success = $true
            gpoName = $GpoName
            gpoId = $gpo.Id.ToString()
            policyPath = $PolicyXmlPath
            domain = $domain.Name
            enforced = $Enforce
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
    Apply Latest Policy to GPO
.DESCRIPTION
    Applies the most recently generated policy to a GPO (from AaronLocker pattern)
.PARAMETER GpoName
    Name of the group policy object
.PARAMETER GpoGuid
    GUID of the group policy object
.PARAMETER Enforce
    If set, applies enforcing rules. Otherwise, applies auditing rules.
.PARAMETER PolicyDirectory
    Directory containing policy XML files
#>
function Set-LatestAppLockerPolicy {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'GpoName')]
        [string]$GpoName,

        [Parameter(Mandatory = $true, ParameterSetName = 'GpoGUID')]
        [guid]$GpoGuid,

        [switch]$Enforce = $false,

        [string]$PolicyDirectory = $script:outputsDir
    )

    # Validate PolicyDirectory parameter
    if (-not (Test-Path $PolicyDirectory)) {
        return @{
            success = $false
            error = "Policy directory not found: $PolicyDirectory"
        }
    }

    # Check if required modules are available (imported at module level)
    if (-not (Get-Module GroupPolicy)) {
        return @{
            success = $false
            error = 'GroupPolicy module not available'
        }
    }

    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. This feature requires a Domain Controller or domain-joined computer with RSAT installed.'
        }
    }

    # Find latest policy file
    $pattern = if ($Enforce) { "*-Enforce.xml" } else { "*-Audit.xml" }
    $latestPolicy = Get-ChildItem -Path $PolicyDirectory -Filter $pattern |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $latestPolicy) {
        return @{
            success = $false
            error = "No policy file found matching pattern: $pattern"
        }
    }

    if ($GpoGuid) {
        $gpo = Get-GPO -Guid $GpoGuid -ErrorAction Stop
    }
    else {
        $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    }

    # Note: Correct namespace capitalization is critical - DirectoryServices.ActiveDirectory
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()

    if ($PSCmdlet.ShouldProcess($gpo.DisplayName, "Set AppLocker policy using $($latestPolicy.Name)")) {
        $policy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::Load($latestPolicy.FullName)
        $ldapPath = "LDAP://{0}" -f $gpo.Path.Replace("LDAP://", "")

        Set-AppLockerPolicy -AppLockerPolicy $policy -LDAP $ldapPath -ErrorAction Stop

        return @{
            success = $true
            gpoName = $gpo.DisplayName
            gpoId = $gpo.Id.ToString()
            policyFile = $latestPolicy.FullName
            domain = $domain.Name
            enforced = $Enforce
        }
    }

    return @{
        success = $false
        error = "Operation cancelled by user"
    }
}

<#
.SYNOPSIS
    Save Policy to File
.DESCRIPTION
    Saves an AppLocker policy XML to a file with proper UTF-16 encoding (from AaronLocker)
.PARAMETER PolicyXml
    The AppLocker policy XML string
.PARAMETER OutputPath
    The output file path
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

        # Convert string to XmlDocument and save with UTF-16 encoding (from AaronLocker)
        # AppLocker policies MUST be UTF-16 encoded
        $xmlDoc = [xml]$PolicyXml
        Save-XmlDocAsUnicode -xmlDoc $xmlDoc -xmlFilename $OutputPath

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
                              Set-GPOAppLockerPolicy, Save-PolicyToFile,
                              Set-LatestAppLockerPolicy
