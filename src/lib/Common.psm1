# Common.psm1
# Shared library functions for GA-AppLocker Dashboard
# Based on patterns from Microsoft AaronLocker

# ======================================================================
# ARTIFACT DATA MODEL - Always load (before pragma once check)
# ======================================================================

# Only define artifact functions if they don't exist yet
if (-not (Test-Path "function:\New-AppLockerArtifact")) {

<#
.SYNOPSIS
    Creates a standardized AppLocker artifact hashtable
.DESCRIPTION
    Returns a hashtable with all standard artifact properties initialized.
    This ensures consistency across all modules (RemoteScan, RuleGenerator, GUI).
.PARAMETER Name
    File name (e.g., "notepad.exe")
.PARAMETER Path
    Full file path (e.g., "C:\Windows\System32\notepad.exe")
.PARAMETER Publisher
    Publisher name from digital signature (e.g., "Microsoft Corporation")
.PARAMETER Hash
    SHA256 hash of the file (optional)
.PARAMETER Version
    File version (optional)
.PARAMETER Size
    File size in bytes (optional)
.PARAMETER ModifiedDate
    Last modified date (optional)
.PARAMETER FileType
    File type: EXE, DLL, MSI, Script, etc. (optional)
.OUTPUTS
    System.Collections.Hashtable with standardized artifact properties
#>
function New-AppLockerArtifact {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name = "",

        [Parameter(Mandatory = $false)]
        [string]$Path = "",

        [Parameter(Mandatory = $false)]
        [string]$Publisher = "",

        [Parameter(Mandatory = $false)]
        [string]$Hash = "",

        [Parameter(Mandatory = $false)]
        [string]$Version = "",

        [Parameter(Mandatory = $false)]
        [long]$Size = 0,

        [Parameter(Mandatory = $false)]
        [DateTime]$ModifiedDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [ValidateSet('EXE', 'DLL', 'MSI', 'Script', 'Unknown')]
        [string]$FileType = "Unknown"
    )

    return @{
        # Core properties (required for rule generation)
        name      = $Name
        path      = $Path
        publisher = if ($Publisher) { $Publisher } else { "Unknown" }

        # Additional properties (optional)
        hash         = $Hash
        version      = $Version
        size         = $Size
        modifiedDate = $ModifiedDate
        fileType     = $FileType

        # Metadata
        source = "New-AppLockerArtifact"
        created = Get-Date
    }
}

<#
.SYNOPSIS
    Converts an artifact from one format to another
.DESCRIPTION
    Handles conversion between different artifact property naming conventions.
    Supports: Module2 format, CSV import format, GUI format.
.PARAMETER Artifact
    Input artifact (hashtable or PSCustomObject)
.PARAMETER TargetFormat
    Target format: Standard, Module2, CSV, GUI
.OUTPUTS
    System.Collections.Hashtable with standardized properties
#>
function Convert-AppLockerArtifact {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Artifact,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Standard', 'Module2', 'CSV', 'GUI')]
        [string]$TargetFormat = 'Standard'
    )

    $result = New-AppLockerArtifact

    # Map path property
    $result.path = $Artifact.FullPath
    if (-not $result.path) { $result.path = $Artifact.Path }
    if (-not $result.path) { $result.path = $Artifact.FilePath }
    if (-not $result.path) { $result.path = $Artifact.path }

    # Map name property
    $result.name = $Artifact.FileName
    if (-not $result.name) { $result.name = $Artifact.Name }
    if (-not $result.name) { $result.name = $Artifact.name }

    # Derive name from path if not set
    if (-not $result.name -and $result.path) {
        $result.name = [System.IO.Path]::GetFileName($result.path)
    }

    # Map publisher property (check multiple naming conventions)
    $result.publisher = $Artifact.Publisher
    if (-not $result.publisher) { $result.publisher = $Artifact.Vendor }
    if (-not $result.publisher) { $result.publisher = $Artifact.Company }
    if (-not $result.publisher) { $result.publisher = $Artifact.Signer }
    if (-not $result.publisher) { $result.publisher = $Artifact.publisher }

    # Default to Unknown if no publisher found
    if (-not $result.publisher) { $result.publisher = "Unknown" }

    # Map hash property
    $result.hash = $Artifact.Hash
    if (-not $result.hash) { $result.hash = $Artifact.SHA256 }
    if (-not $result.hash) { $result.hash = $Artifact.hash }

    # Map optional properties
    $result.version = $Artifact.Version
    if (-not $result.version) { $result.version = $Artifact.FileVersion }
    if (-not $result.version) { $result.version = $Artifact.version }

    $result.size = $Artifact.Size
    if (-not $result.size) { $result.size = $Artifact.Length }
    if (-not $result.size) { $result.size = $Artifact.size }

    $result.modifiedDate = $Artifact.ModifiedDate
    if (-not $result.modifiedDate) { $result.modifiedDate = $Artifact.LastWriteTime }
    if (-not $result.modifiedDate) { $result.modifiedDate = $Artifact.modifiedDate }

    $result.fileType = $Artifact.FileType
    if (-not $result.fileType) { $result.fileType = $Artifact.fileType }

    return $result
}

<#
.SYNOPSIS
    Validates an artifact has required properties
.DESCRIPTION
    Checks if an artifact has the minimum required properties for rule generation.
.PARAMETER Artifact
    Artifact to validate
.PARAMETER RuleType
    Type of rule to validate for: Publisher, Path, Hash, Auto
.OUTPUTS
    System.Collections.Hashtable with success and validation results
#>
function Test-AppLockerArtifact {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Artifact,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Publisher', 'Path', 'Hash', 'Auto')]
        [string]$RuleType = 'Auto'
    )

    $errors = @()
    $warnings = @()

    # Check for path (required for all rule types)
    $hasPath = $false
    if ($Artifact.path) { $hasPath = $true }
    elseif ($Artifact.Path) { $hasPath = $true }
    elseif ($Artifact.FullPath) { $hasPath = $true }
    elseif ($Artifact.FilePath) { $hasPath = $true }

    if (-not $hasPath) {
        $errors += "Missing required property: path"
    }

    # Check for publisher (required for Publisher rules)
    $hasPublisher = $false
    if ($Artifact.publisher -and $Artifact.publisher -ne "Unknown") { $hasPublisher = $true }
    elseif ($Artifact.Publisher -and $Artifact.Publisher -ne "Unknown") { $hasPublisher = $true }

    if ($RuleType -eq 'Publisher' -and -not $hasPublisher) {
        $errors += "Missing required property for Publisher rule: publisher"
    }

    # Check for hash (required for Hash rules)
    if ($RuleType -eq 'Hash') {
        $hasHash = $false
        if ($Artifact.hash) { $hasHash = $true }
        elseif ($Artifact.Hash) { $hasHash = $true }
        elseif ($Artifact.SHA256) { $hasHash = $true }

        if (-not $hasHash) {
            $warnings += "Hash not provided - will be calculated from file"
        }
    }

    # Check for name (recommended)
    $hasName = $false
    if ($Artifact.name) { $hasName = $true }
    elseif ($Artifact.Name) { $hasName = $true }
    elseif ($Artifact.FileName) { $hasName = $true }

    if (-not $hasName -and $hasPath) {
        # Name can be derived from path, so just a warning
        $warnings += "Name not provided - will be derived from path"
    }

    return @{
        success  = ($errors.Count -eq 0)
        valid    = ($errors.Count -eq 0)
        errors   = $errors
        warnings = $warnings
        canCreatePublisherRule = $hasPublisher
        canCreatePathRule     = $hasPath
        canCreateHashRule     = $hasPath
    }
}

} # End of artifact functions wrapper

# ======================================================================
# PRAGMA ONCE - Prevent duplicate module loading for other functions
# ======================================================================
if (Test-Path "function:\SaveXmlDocAsUnicode") {
    return
}

# ======================================================================
# AARONLOCKER CONSTANTS
# ======================================================================

# File extensions for Get-AppLockerFileInformation -Directory
Set-Variable -Option Constant -Name GetAlfiDefaultExts -Value @(
    ".com", ".exe", ".dll", ".ocx", ".msi", ".msp", ".mst",
    ".bat", ".cmd", ".js", ".ps1", ".vbs", ".appx"
)

# Extensions that are never executables - skip during scanning
Set-Variable -Option Constant -Name NeverExecutableExts -Value @(
    ".admx", ".adml", ".opax", ".opal",
    ".etl", ".evtx", ".msc", ".pdb", ".chm", ".hlp",
    ".gif", ".jpg", ".jpeg", ".png", ".bmp", ".svg", ".ico",
    ".html", ".htm", ".hta", ".css", ".json",
    ".txt", ".log", ".xml", ".xsl", ".ini", ".csv", ".reg",
    ".pdf", ".tif", ".tiff", ".xps", ".rtf",
    ".lnk", ".url", ".inf", ".mui"
)

# Special publisher names
Set-Variable -Option Constant -Name sNoPublisher -Value "-"
Set-Variable -Option Constant -Name sUnsigned -Value "[not signed]"
Set-Variable -Option Constant -Name sFiltered -Value "FILTERED"

# Safety classification constants
Set-Variable -Option Constant -Name UnsafeDir -Value "UnsafeDir"
Set-Variable -Option Constant -Name SafeDir -Value "SafeDir"
Set-Variable -Option Constant -Name UnknownDir -Value "UnknownDir"

# ======================================================================
# ARTIFACT DATA MODEL - Standardized Properties
# ======================================================================

<#
.SYNOPSIS
    Creates a standardized AppLocker artifact hashtable
.DESCRIPTION
    Returns a hashtable with all standard artifact properties initialized.
    This ensures consistency across all modules (RemoteScan, RuleGenerator, GUI).
.PARAMETER Name
    File name (e.g., "notepad.exe")
.PARAMETER Path
    Full file path (e.g., "C:\Windows\System32\notepad.exe")
.PARAMETER Publisher
    Publisher name from digital signature (e.g., "Microsoft Corporation")
.PARAMETER Hash
    SHA256 hash of the file (optional)
.PARAMETER Version
    File version (optional)
.PARAMETER Size
    File size in bytes (optional)
.PARAMETER ModifiedDate
    Last modified date (optional)
.PARAMETER FileType
    File type: EXE, DLL, MSI, Script, etc. (optional)
.OUTPUTS
    System.Collections.Hashtable with standardized artifact properties
#>
function New-AppLockerArtifact {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Name = "",

        [Parameter(Mandatory = $false)]
        [string]$Path = "",

        [Parameter(Mandatory = $false)]
        [string]$Publisher = "",

        [Parameter(Mandatory = $false)]
        [string]$Hash = "",

        [Parameter(Mandatory = $false)]
        [string]$Version = "",

        [Parameter(Mandatory = $false)]
        [long]$Size = 0,

        [Parameter(Mandatory = $false)]
        [DateTime]$ModifiedDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [ValidateSet('EXE', 'DLL', 'MSI', 'Script', 'Unknown')]
        [string]$FileType = "Unknown"
    )

    return @{
        # Core properties (required for rule generation)
        name      = $Name
        path      = $Path
        publisher = if ($Publisher) { $Publisher } else { "Unknown" }

        # Additional properties (optional)
        hash         = $Hash
        version      = $Version
        size         = $Size
        modifiedDate = $ModifiedDate
        fileType     = $FileType

        # Metadata
        source = "New-AppLockerArtifact"
        created = Get-Date
    }
}

<#
.SYNOPSIS
    Converts an artifact from one format to another
.DESCRIPTION
    Handles conversion between different artifact property naming conventions.
    Supports: Module2 format, CSV import format, GUI format.
.PARAMETER Artifact
    Input artifact (hashtable or PSCustomObject)
.PARAMETER TargetFormat
    Target format: Standard, Module2, CSV, GUI
.OUTPUTS
    System.Collections.Hashtable with standardized properties
#>
function Convert-AppLockerArtifact {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Artifact,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Standard', 'Module2', 'CSV', 'GUI')]
        [string]$TargetFormat = 'Standard'
    )

    $result = New-AppLockerArtifact

    # Map path property
    $result.path = $Artifact.FullPath
    if (-not $result.path) { $result.path = $Artifact.Path }
    if (-not $result.path) { $result.path = $Artifact.FilePath }
    if (-not $result.path) { $result.path = $Artifact.path }

    # Map name property
    $result.name = $Artifact.FileName
    if (-not $result.name) { $result.name = $Artifact.Name }
    if (-not $result.name) { $result.name = $Artifact.name }

    # Derive name from path if not set
    if (-not $result.name -and $result.path) {
        $result.name = [System.IO.Path]::GetFileName($result.path)
    }

    # Map publisher property (check multiple naming conventions)
    $result.publisher = $Artifact.Publisher
    if (-not $result.publisher) { $result.publisher = $Artifact.Vendor }
    if (-not $result.publisher) { $result.publisher = $Artifact.Company }
    if (-not $result.publisher) { $result.publisher = $Artifact.Signer }
    if (-not $result.publisher) { $result.publisher = $Artifact.publisher }

    # Default to Unknown if no publisher found
    if (-not $result.publisher) { $result.publisher = "Unknown" }

    # Map hash property
    $result.hash = $Artifact.Hash
    if (-not $result.hash) { $result.hash = $Artifact.SHA256 }
    if (-not $result.hash) { $result.hash = $Artifact.hash }

    # Map optional properties
    $result.version = $Artifact.Version
    if (-not $result.version) { $result.version = $Artifact.FileVersion }
    if (-not $result.version) { $result.version = $Artifact.version }

    $result.size = $Artifact.Size
    if (-not $result.size) { $result.size = $Artifact.Length }
    if (-not $result.size) { $result.size = $Artifact.size }

    $result.modifiedDate = $Artifact.ModifiedDate
    if (-not $result.modifiedDate) { $result.modifiedDate = $Artifact.LastWriteTime }
    if (-not $result.modifiedDate) { $result.modifiedDate = $Artifact.modifiedDate }

    $result.fileType = $Artifact.FileType
    if (-not $result.fileType) { $result.fileType = $Artifact.fileType }

    return $result
}

<#
.SYNOPSIS
    Validates an artifact has required properties
.DESCRIPTION
    Checks if an artifact has the minimum required properties for rule generation.
.PARAMETER Artifact
    Artifact to validate
.PARAMETER RuleType
    Type of rule to validate for: Publisher, Path, Hash, Auto
.OUTPUTS
    System.Collections.Hashtable with success and validation results
#>
function Test-AppLockerArtifact {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Artifact,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Publisher', 'Path', 'Hash', 'Auto')]
        [string]$RuleType = 'Auto'
    )

    $errors = @()
    $warnings = @()

    # Check for path (required for all rule types)
    $hasPath = $false
    if ($Artifact.path) { $hasPath = $true }
    elseif ($Artifact.Path) { $hasPath = $true }
    elseif ($Artifact.FullPath) { $hasPath = $true }
    elseif ($Artifact.FilePath) { $hasPath = $true }

    if (-not $hasPath) {
        $errors += "Missing required property: path"
    }

    # Check for publisher (required for Publisher rules)
    $hasPublisher = $false
    if ($Artifact.publisher -and $Artifact.publisher -ne "Unknown") { $hasPublisher = $true }
    elseif ($Artifact.Publisher -and $Artifact.Publisher -ne "Unknown") { $hasPublisher = $true }

    if ($RuleType -eq 'Publisher' -and -not $hasPublisher) {
        $errors += "Missing required property for Publisher rule: publisher"
    }

    # Check for hash (required for Hash rules)
    if ($RuleType -eq 'Hash') {
        $hasHash = $false
        if ($Artifact.hash) { $hasHash = $true }
        elseif ($Artifact.Hash) { $hasHash = $true }
        elseif ($Artifact.SHA256) { $hasHash = $true }

        if (-not $hasHash) {
            $warnings += "Hash not provided - will be calculated from file"
        }
    }

    # Check for name (recommended)
    $hasName = $false
    if ($Artifact.name) { $hasName = $true }
    elseif ($Artifact.Name) { $hasName = $true }
    elseif ($Artifact.FileName) { $hasName = $true }

    if (-not $hasName -and $hasPath) {
        # Name can be derived from path, so just a warning
        $warnings += "Name not provided - will be derived from path"
    }

    return @{
        success  = ($errors.Count -eq 0)
        valid    = ($errors.Count -eq 0)
        errors   = $errors
        warnings = $warnings
        canCreatePublisherRule = $hasPublisher
        canCreatePathRule     = $hasPath
        canCreateHashRule     = $hasPath
    }
}

# ======================================================================
# ASSEMBLY LOADING
# ======================================================================

# Ensure the AppLocker assembly is loaded
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

# ======================================================================
# LOGGING FUNCTIONS
# ======================================================================

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

    # Sanitize message - remove newlines and control characters
    $sanitizedMessage = $Message -replace "[\r\n]+", " " -replace "[\x00-\x1F\x7F]", ""

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $sanitizedMessage"

    # Console output with colors
    switch ($Level) {
        'INFO'    { Write-Host $logMessage -ForegroundColor Cyan }
        'WARN'    { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
    }

    # File output with rotation
    try {
        $logDir = Split-Path -Parent $LogPath
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }

        # Check log size - rotate if > 10MB
        if (Test-Path $LogPath) {
            $logFile = Get-Item $LogPath
            if ($logFile.Length -gt 10MB) {
                $archivePath = $LogPath -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $LogPath -Destination $archivePath -Force
            }
        }

        Add-Content -Path $LogPath -Value $logMessage
    }
    catch {
        # Fail silently for logging errors
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

    if ($null -eq $Data) {
        return @{ success = $false; error = "Null data" } | ConvertTo-Json -Depth 10
    }

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

function Save-XmlDocAsUnicode {
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

function Save-AppLockerPolicyAsUnicodeXml {
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
    param(
        [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]$ALPolicy,
        [string]$xmlFilename
    )

    Save-XmlDocAsUnicode -xmlDoc ([xml]($ALPolicy.ToXml())) -xmlFilename $xmlFilename
}

function Get-AppLockerFileInfo {
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
            $result.publisher = @{
                publisherName = $alfi.Publisher.PublisherName
                productName   = if ($alfi.Publisher.HasProductName) { $alfi.Publisher.ProductName } else { "" }
                binaryName    = if ($alfi.Publisher.HasBinaryName) { $alfi.Publisher.BinaryName } else { "" }
                version       = if ($alfi.Publisher.HasVersion) { $alfi.Publisher.Version } else { "" }
            }
            $result.isSigned = $true
        }
        else {
            $result.publisher = $null
            $result.isSigned = $false
        }

        # Hash information
        if ($alfi.FileHash) {
            $result.hash = $alfi.FileHash
        }

        return $result
    }
    catch {
        return @{ success = $false; error = $_.Exception.Message }
    }
}

function ConvertFrom-SidCached {
    <#
    .SYNOPSIS
        Translate SID to username with bounded caching
    .DESCRIPTION
        Converts security identifier (SID) to account name with result caching
    .PARAMETER Sid
        The SID to translate
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Sid
    )

    # Static cache for SID-to-name lookups with size limit
    if (-not $script:SidToNameCache) {
        $script:SidToNameCache = @{}
        $script:SidCacheMaxSize = 1000
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

    # Evict oldest if cache is too large
    if ($script:SidToNameCache.Count -ge $script:SidCacheMaxSize) {
        $script:SidToNameCache.Remove(($script:SidToNameCache.Keys | Select-Object -First 1))
    }

    $script:SidToNameCache[$Sid] = $name
    return $name
}

function ConvertTo-AppLockerGenericPath {
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
    param(
        [string]$FilePath
    )

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
        @{ Pattern = "^(%OSDRIVE%|C:)\\Program Files \(x86\)\\"; Replace = "%PROGRAMFILES(X86)%\" },
        @{ Pattern = "^(%OSDRIVE%|C:)\\Program Files\\"; Replace = "%PROGRAMFILES%\" },
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

function New-AppLockerGuid {
    <#
    .SYNOPSIS
        Create a valid GUID for AppLocker rules
    .DESCRIPTION
        Generates a new GUID for use in AppLocker rule IDs
    #>
    return [string]([GUID]::NewGuid().Guid)
}

function Get-StandardSids {
    <#
    .SYNOPSIS
        Get standard SIDs for common groups
    .DESCRIPTION
        Returns well-known SID strings for use in AppLocker rules
    #>
    return @{
        Everyone       = "S-1-1-0"
        Administrators = "S-1-5-32-544"
        System         = "S-1-5-18"
        AuthenticatedUsers = "S-1-5-11"
        LocalService   = "S-1-5-19"
        NetworkService = "S-1-5-20"
    }
}

####################################################################################################
# AARONLOCKER PE DETECTION (IsWin32Executable)
# From AaronLocker SupportFunctions.ps1
####################################################################################################

function IsWin32Executable {
    <#
    .SYNOPSIS
        Determine whether a file is a Win32 EXE, DLL, or neither
    .DESCRIPTION
        Reads PE headers to identify portable executables regardless of extension.
        Compatible with PowerShell 5.1 and PowerShell 7+.
    .PARAMETER filename
        Path to the file to analyze
    .RETURNS
        "EXE", "DLL", or $null
    #>
    param([string]$filename)

    if (-not (Test-Path -LiteralPath $filename -PathType Leaf)) {
        return $null
    }

    # PE header constants
    $sizeofImageDosHeader = 64
    $sizeofImageNtHeaders64 = 264
    $offset_e_lfanew = 60
    $offset_FileHeader = 4
    $offset_FileHeader_Characteristics = 18
    $offset_OptionalHeader = 24
    $offset_OptionalHeader_Subsystem = 68
    $IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    $IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    $IMAGE_FILE_DLL = 0x2000

    try {
        # Use .NET FileStream for reliable binary reading (works in PS 5.1 and 7+)
        $stream = [System.IO.File]::OpenRead($filename)
        try {
            # Read first 64 bytes (IMAGE_DOS_HEADER)
            $bytesImageDosHeader = [byte[]]::new($sizeofImageDosHeader)
            $bytesRead = $stream.Read($bytesImageDosHeader, 0, $sizeofImageDosHeader)
            if ($bytesRead -lt $sizeofImageDosHeader) {
                return $null
            }

            # Verify "MZ" signature
            if ($bytesImageDosHeader[0] -ne 0x4D -or $bytesImageDosHeader[1] -ne 0x5A) {
                return $null
            }

            # Get offset to IMAGE_NT_HEADERS (little-endian DWORD at offset 60)
            $offsetImageNtHeaders = [BitConverter]::ToInt32($bytesImageDosHeader, $offset_e_lfanew)

            # Seek to NT headers and read
            $totalToRead = $offsetImageNtHeaders + $sizeofImageNtHeaders64
            if ($totalToRead -gt $stream.Length) {
                return $null
            }

            $stream.Position = 0
            $bytesImageNtHeaders = [byte[]]::new($totalToRead)
            $bytesRead = $stream.Read($bytesImageNtHeaders, 0, $totalToRead)
            if ($bytesRead -lt $totalToRead) {
                return $null
            }

            # Verify "PE" signature
            if ($bytesImageNtHeaders[$offsetImageNtHeaders] -ne 0x50 -or $bytesImageNtHeaders[$offsetImageNtHeaders + 1] -ne 0x45) {
                return $null
            }

            # Get Characteristics (little-endian WORD)
            $offsChar = $offsetImageNtHeaders + $offset_FileHeader + $offset_FileHeader_Characteristics
            $characteristics = [BitConverter]::ToUInt16($bytesImageNtHeaders, $offsChar)

            # Get Subsystem (little-endian WORD)
            $offsSubsystem = $offsetImageNtHeaders + $offset_OptionalHeader + $offset_OptionalHeader_Subsystem
            $subsystem = [BitConverter]::ToUInt16($bytesImageNtHeaders, $offsSubsystem)

            # Verify subsystem (GUI or Console)
            if ($subsystem -ne $IMAGE_SUBSYSTEM_WINDOWS_GUI -and $subsystem -ne $IMAGE_SUBSYSTEM_WINDOWS_CUI) {
                return $null
            }

            # Return DLL or EXE
            if ($characteristics -band $IMAGE_FILE_DLL) {
                return "DLL"
            }
            else {
                return "EXE"
            }
        }
        finally {
            $stream.Close()
            $stream.Dispose()
        }
    }
    catch {
        return $null
    }
}

####################################################################################################
# INPUT VALIDATION FRAMEWORK
####################################################################################################

function Test-AppLockerPath {
    <#
    .SYNOPSIS
        Validate and normalize an AppLocker path
    .PARAMETER Path
        The path to validate
    .PARAMETER AllowWildcards
        Allow wildcards in path
    .PARAMETER AllowVariables
        Allow environment variables in path
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$AllowWildcards,
        [switch]$AllowVariables
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{ valid = $false; error = "Path is empty" }
    }

    # Block UNC paths unless explicitly allowed
    if ($Path -match '^\\\\' -and -not $AllowVariables) {
        return @{ valid = $false; error = "UNC paths not supported" }
    }

    # Block device paths
    if ($Path -match '^\\\\\.\\') {
        return @{ valid = $false; error = "Device paths not supported" }
    }

    # Check for path traversal if not a wildcards/variables
    if (-not $AllowWildcards -and -not $AllowVariables) {
        if ($Path -match '\.\.') {
            return @{ valid = $false; error = "Path traversal not allowed" }
        }

        # Resolve and validate
        try {
            $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
            if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
                return @{ valid = $false; error = "Path must be a file, not a directory" }
            }
            return @{ valid = $true; path = $resolvedPath }
        }
        catch {
            return @{ valid = $false; error = "Path not found: $Path" }
        }
    }

    return @{ valid = $true; path = $Path }
}

function Test-PublisherName {
    <#
    .SYNOPSIS
        Validate a publisher name
    .PARAMETER PublisherName
        The publisher name to validate
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublisherName
    )

    if ([string]::IsNullOrWhiteSpace($PublisherName)) {
        return @{ valid = $false; error = "Publisher name is empty" }
    }

    # Max length for publisher name in AppLocker
    if ($PublisherName.Length -gt 256) {
        return @{ valid = $false; error = "Publisher name too long (max 256 chars)" }
    }

    # Block characters that could cause issues
    if ($PublisherName -match '[<>"]') {
        return @{ valid = $false; error = "Publisher name contains invalid characters" }
    }

    return @{ valid = $true; name = $PublisherName.Trim() }
}

# ======================================================================
# SECURITY FUNCTIONS - Phase 1 Critical Fixes
# ======================================================================

function ConvertTo-SafeString {
    <#
    .SYNOPSIS
        Sanitize user input for display to prevent XSS and injection attacks
    .DESCRIPTION
        Removes or escapes potentially dangerous characters from user input
    .PARAMETER InputString
        The string to sanitize
    .PARAMETER MaxLength
        Maximum allowed length (default: 1000)
    .OUTPUTS
        Sanitized string safe for display
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$InputString,

        [Parameter(Mandatory = $false)]
        [int]$MaxLength = 1000
    )

    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }

    # Truncate to max length
    if ($InputString.Length -gt $MaxLength) {
        $InputString = $InputString.Substring(0, $MaxLength)
    }

    # Remove null bytes and control characters (except newline, tab, carriage return)
    $sanitized = $InputString -replace '[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', ''

    # Escape HTML entities (for display in web/html contexts)
    $sanitized = $sanitized -replace '&', '&amp;'
    $sanitized = $sanitized -replace '<', '&lt;'
    $sanitized = $sanitized -replace '>', '&gt;'
    $sanitized = $sanitized -replace '"', '&quot;'
    $sanitized = $sanitized -replace '''', '&apos;'

    # Remove potential script injection patterns
    $sanitized = $sanitized -replace 'javascript:', ''
    $sanitized = $sanitized -replace 'vbscript:', ''
    $sanitized = $sanitized -replace 'on\w+\s*=', ''  # Remove onerror=, onload=, etc.

    return $sanitized
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Write security audit log entries
    .DESCRIPTION
        Logs security-relevant operations for compliance and forensic analysis
    .PARAMETER Action
        The action performed (e.g., 'GPO_CREATED', 'GPO_LINKED', 'POLICY_APPLIED')
    .PARAMETER Target
        The target object (e.g., GPO name, OU path)
    .PARAMETER Result
        Operation result: 'SUCCESS' or 'FAILURE'
    .PARAMETER Details
        Additional details about the operation
    .PARAMETER UserName
        User who performed the action (defaults to current user)
    .PARAMETER ComputerName
        Computer where action was performed (defaults to local computer)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [string]$Target = '',

        [Parameter(Mandatory = $false)]
        [ValidateSet('SUCCESS', 'FAILURE', 'ATTEMPT', 'CANCELLED')]
        [string]$Result = 'SUCCESS',

        [Parameter(Mandatory = $false)]
        [string]$Details = '',

        [Parameter(Mandatory = $false)]
        [string]$UserName = '',

        [Parameter(Mandatory = $false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    # Get current user if not specified
    if ([string]::IsNullOrEmpty($UserName)) {
        $UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    # Sanitize inputs for log
    $Action = ConvertTo-SafeString -InputString $Action -MaxLength 100
    $Target = ConvertTo-SafeString -InputString $Target -MaxLength 500
    $Details = ConvertTo-SafeString -InputString $Details -MaxLength 2000

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Result] [$Action] Target=$Target User=$UserName Computer=$ComputerName Details=$Details"

    # Write to audit log file
    try {
        $auditLogPath = 'C:\GA-AppLocker\logs\audit.log'
        $auditLogDir = Split-Path -Parent $auditLogPath

        if (-not (Test-Path $auditLogDir)) {
            New-Item -ItemType Directory -Path $auditLogDir -Force | Out-Null
        }

        # Check log size - rotate if > 50MB (audit logs are important)
        if (Test-Path $auditLogPath) {
            $logFile = Get-Item $auditLogPath
            if ($logFile.Length -gt 50MB) {
                $archivePath = $auditLogPath -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $auditLogPath -Destination $archivePath -Force
            }
        }

        # Append to audit log
        Add-Content -Path $auditLogPath -Value $logEntry

        # Also write to Windows Event Log if available
        try {
            $eventSource = "GA-AppLocker"
            $logName = "Security"

            # Check if event source exists, create if not (requires admin)
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                try {
                    [System.Diagnostics.EventLog]::CreateEventSource($eventSource, $logName)
                } catch {
                    # Silently fail if not admin
                }
            }

            $eventID = switch ($Result) {
                'SUCCESS'  { 1000 }
                'FAILURE'  { 1001 }
                'ATTEMPT'  { 1002 }
                'CANCELLED' { 1003 }
                default    { 1000 }
            }

            $eventEntryType = switch ($Result) {
                'FAILURE'  { [System.Diagnostics.EventLogEntryType]::Warning }
                'CANCELLED' { [System.Diagnostics.EventLogEntryType]::Warning }
                default    { [System.Diagnostics.EventLogEntryType]::Information }
            }

            [System.Diagnostics.EventLog]::WriteEntry($eventSource, $logEntry, $eventID, $eventEntryType)
        }
        catch {
            # Silently fail if event log writing fails
        }
    }
    catch {
        # Fail silently for audit logging errors to avoid breaking operations
    }
}

function Show-ConfirmationDialog {
    <#
    .SYNOPSIS
        Display confirmation dialog for destructive operations
    .DESCRIPTION
        Shows a standardized confirmation dialog using GitHub dark theme colors
    .PARAMETER Title
        Dialog title
    .PARAMETER Message
        Confirmation message
    .PARAMETER TargetObject
        The object being acted upon (e.g., GPO name)
    .PARAMETER ActionType
        Type of action (e.g., 'CREATE', 'DELETE', 'LINK', 'MODIFY')
    .PARAMETER RequireTyping
        If true, requires user to type "CONFIRM" to proceed
    .OUTPUTS
        Boolean: true if user confirmed, false otherwise
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$TargetObject = '',

        [Parameter(Mandatory = $false)]
        [ValidateSet('CREATE', 'DELETE', 'LINK', 'MODIFY', 'ENFORCE', 'DISABLE')]
        [string]$ActionType = 'MODIFY',

        [Parameter(Mandatory = $false)]
        [switch]$RequireTyping
    )

    # Build full message
    $fullMessage = $Message

    if (-not [string]::IsNullOrEmpty($TargetObject)) {
        $fullMessage = "$fullMessage`n`nTarget: $TargetObject"
    }

    # Add warning based on action type
    $warningText = switch ($ActionType) {
        'DELETE'   { "This action cannot be easily undone." }
        'ENFORCE'  { "Enforce mode will BLOCK applications that don't match rules." }
        'CREATE'   { "This will create a new Group Policy Object." }
        'LINK'     { "This will apply the policy to the target OU immediately." }
        'DISABLE'  { "This will disable the policy link." }
        default    { "Please confirm you want to proceed." }
    }

    $fullMessage = "$fullMessage`n`n$warningText"

    if ($RequireTyping) {
        $fullMessage = "$fullMessage`n`nType 'CONFIRM' to proceed or press Cancel to abort."
    }

    # Show dialog
    $result = [System.Windows.MessageBox]::Show(
        $fullMessage,
        $Title,
        if ($RequireTyping) {
            [System.Windows.MessageBoxButton]::OKCancel
        } else {
            [System.Windows.MessageBoxButton]::YesNo
        },
        [System.Windows.MessageBoxImage]::Warning
    )

    # Log the confirmation attempt
    if ($result -eq [System.Windows.MessageBoxResult]::Yes -or
        $result -eq [System.Windows.MessageBoxResult]::OK) {
        Write-AuditLog -Action "CONFIRMATION_$ActionType" -Target $TargetObject -Result 'SUCCESS' -Details "User confirmed operation"
        return $true
    }
    else {
        Write-AuditLog -Action "CONFIRMATION_$ActionType" -Target $TargetObject -Result 'CANCELLED' -Details "User cancelled operation"
        return $false
    }
}

function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        HTML encode a string for safe display
    .DESCRIPTION
        Escapes HTML special characters to prevent XSS
    .PARAMETER Value
        The string to encode
    .OUTPUTS
        HTML-encoded string
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return ''
    }

    # Use System.Web if available (most complete)
    try {
        Add-Type -AssemblyName System.Web -ErrorAction Stop
        return [System.Web.HttpUtility]::HtmlEncode($Value)
    }
    catch {
        # Fallback to manual encoding
        $encoded = $Value -replace '&', '&amp;'
        $encoded = $encoded -replace '<', '&lt;'
        $encoded = $encoded -replace '>', '&gt;'
        $encoded = $encoded -replace '"', '&quot;'
        $encoded = $encoded -replace '''', '&apos;'
        return $encoded
    }
}

# ======================================================================
# EXPORTS
# ======================================================================

Export-ModuleMember -Function Save-XmlDocAsUnicode, Save-AppLockerPolicyAsUnicodeXml,
                              Get-AppLockerFileInfo, ConvertFrom-SidCached,
                              ConvertTo-AppLockerGenericPath, New-AppLockerGuid,
                              Get-StandardSids, IsWin32Executable,
                              Test-AppLockerPath, Test-PublisherName,
                              ConvertTo-SafeString, Write-AuditLog, Show-ConfirmationDialog,
                              ConvertTo-HtmlEncoded

Export-ModuleMember -Variable GetAlfiDefaultExts, NeverExecutableExts,
                              sNoPublisher, sUnsigned, sFiltered,
                              UnsafeDir, SafeDir, UnknownDir
