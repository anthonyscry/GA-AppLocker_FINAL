# Common.psm1
# Shared library functions for GA-AppLocker Dashboard
# Based on patterns from Microsoft AaronLocker

# Ensure the AppLocker assembly is loaded
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

function Write-Log {
    <#
    .SYNOPSIS
        Write a log message to file and console
    #>
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',
        [string]$LogPath = 'C:\AppLocker\logs\app.log'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    # Console output with colors
    switch ($Level) {
        'INFO'    { Write-Host $logMessage -ForegroundColor Cyan }
        'WARN'    { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
    }

    # File output
    try {
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore logging errors
    }
}

function ConvertTo-JsonResponse {
    <#
    .SYNOPSIS
        Convert result to JSON for p2s frontend consumption
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Data
    )

    if ($Data -is [hashtable]) {
        return $Data | ConvertTo-Json -Depth 10
    }
    elseif ($Data -is [array]) {
        return $Data | ConvertTo-Json -Depth 10
    }
    else {
        return @{ success = $true; data = $Data } | ConvertTo-Json -Depth 10
    }
}

Export-ModuleMember -Function Write-Log, ConvertTo-JsonResponse

####################################################################################################
# XML and Policy Management Functions (from AaronLocker patterns)
####################################################################################################

<#
.SYNOPSIS
    Save XML document as Unicode (UTF-16) encoding
.DESCRIPTION
    Saves an XmlDocument with proper Unicode encoding, required for AppLocker policies
.PARAMETER xmlDoc
    The XmlDocument to save
.PARAMETER xmlFilename
    The output file path
#>
function Save-XmlDocAsUnicode {
    param(
        [System.Xml.XmlDocument]$xmlDoc,
        [string]$xmlFilename
    )

    $xws = [System.Xml.XmlWriterSettings]::new()
    $xws.Encoding = [System.Text.Encoding]::Unicode
    $xws.Indent = $true
    $xw = [System.Xml.XmlWriter]::Create($xmlFilename, $xws)
    $xmlDoc.Save($xw)
    $xw.Close()
}

<#
.SYNOPSIS
    Save AppLocker Policy as Unicode XML
.DESCRIPTION
    Converts AppLockerPolicy object to XML and saves with proper encoding
.PARAMETER ALPolicy
    The AppLockerPolicy object
.PARAMETER xmlFilename
    The output file path
#>
function Save-AppLockerPolicyAsUnicodeXml {
    param(
        [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]$ALPolicy,
        [string]$xmlFilename
    )

    Save-XmlDocAsUnicode -xmlDoc ([xml]($ALPolicy.ToXml())) -xmlFilename $xmlFilename
}

<#
.SYNOPSIS
    Get file information for AppLocker rule creation
.DESCRIPTION
    Retrieves publisher and hash information from a file for creating AppLocker rules
.PARAMETER FilePath
    Path to the file to analyze
.EXAMPLE
    Get-AppLockerFileInfo -FilePath "C:\Windows\System32\cmd.exe"
#>
function Get-AppLockerFileInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        return @{ success = $false; error = "File not found: $FilePath" }
    }

    try {
        $alfi = Get-AppLockerFileInformation -FilePath $FilePath

        if ($null -eq $alfi) {
            return @{ success = $false; error = "Unable to get file information" }
        }

        $result = @{
            success = $true
            filePath = $FilePath
        }

        # Publisher information
        if ($alfi.Publisher -and $alfi.Publisher.HasPublisherName) {
            result.publisher = @{
                publisherName = $alfi.Publisher.PublisherName
                productName   = if ($alfi.Publisher.HasProductName) { $alfi.Publisher.ProductName } else { "" }
                binaryName    = if ($alfi.Publisher.HasBinaryName) { $alfi.Publisher.BinaryName } else { "" }
                version       = if ($alfi.Publisher.HasVersion) { $alfi.Publisher.Version } else { "" }
            }
            result.isSigned = $true
        }
        else {
            result.publisher = $null
            result.isSigned = $false
        }

        # Hash information
        if ($alfi.FileHash) {
            result.hash = $alfi.FileHash
        }

        return $result
    }
    catch {
        return @{ success = $false; error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Translate SID to username with caching
.DESCRIPTION
    Converts security identifier (SID) to account name with result caching
.PARAMETER Sid
    The SID to translate
#>
function ConvertFrom-SidCached {
    param([string]$Sid)

    # Static cache for SID-to-name lookups
    if (-not $script:SidToNameCache) {
        $script:SidToNameCache = @{}
    }

    if ($script:SidToNameCache.ContainsKey($Sid)) {
        return $script:SidToNameCache[$Sid]
    }

    try {
        $oSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $oUser = $oSID.Translate([System.Security.Principal.NTAccount])
        $name = $oUser.Value
    }
    catch {
        if ($Sid.EndsWith("-500")) {
            $name = "[[built-in admin]]"
        }
        else {
            $name = "[[Not translated]]"
        }
    }

    $script:SidToNameCache[$Sid] = $name
    return $name
}

<#
.SYNOPSIS
    Convert file path to generic AppLocker variable
.DESCRIPTION
    Replaces user-specific paths with AppLocker environment variables
.PARAMETER FilePath
    The file path to convert
.EXAMPLE
    ConvertTo-AppLockerGenericPath -FilePath "C:\Users\John\AppData\Local\Temp\app.exe"
    # Returns: %LOCALAPPDATA%\Temp\app.exe
#>
function ConvertTo-AppLockerGenericPath {
    param([string]$FilePath)

    if ([string]::IsNullOrEmpty($FilePath)) {
        return ""
    }

    # Define replacement patterns (order matters!)
    $patterns = @(
        @{ Pattern = "^(%OSDRIVE%|C:)\\ProgramData\\";      Replace = "%PROGRAMDATA%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Users\\Public\\";    Replace = "%PUBLIC%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]+\\AppData\\Local\\";  Replace = "%LOCALAPPDATA%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]+\\AppData\\Roaming\\"; Replace = "%APPDATA%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Users\\[^\\]+\\";    Replace = "%USERPROFILE%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Program Files[^\\]*\\"; Replace = "%PROGRAMFILES%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Windows\\";          Replace = "%WINDIR%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)";                     Replace = "%OSDRIVE%" }
    )

    $path = $FilePath
    foreach ($p in $patterns) {
        if ($path -match $p.Pattern) {
            $path = $path -replace $p.Pattern, $p.Replace
            break
        }
    }

    return $path
}

<#
.SYNOPSIS
    Create a valid GUID for AppLocker rules
.DESCRIPTION
    Generates a new GUID for use in AppLocker rule IDs
#>
function New-AppLockerGuid {
    return [string]([GUID]::NewGuid().Guid)
}

<#
.SYNOPSIS
    Get standard SIDs for common groups
.DESCRIPTION
    Returns well-known SID strings for use in AppLocker rules
#>
function Get-StandardSids {
    return @{
        Everyone       = "S-1-1-0"
        Administrators = "S-1-5-32-544"
        System         = "S-1-5-18"
        AuthenticatedUsers = "S-1-5-11"
        LocalService   = "S-1-5-19"
        NetworkService = "S-1-5-20"
    }
}

Export-ModuleMember -Function Save-XmlDocAsUnicode, Save-AppLockerPolicyAsUnicodeXml,
                              Get-AppLockerFileInfo, ConvertFrom-SidCached,
                              ConvertTo-AppLockerGenericPath, New-AppLockerGuid,
                              Get-StandardSids
