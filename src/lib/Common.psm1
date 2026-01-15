# Common.psm1
# Shared library functions for GA-AppLocker Dashboard
# Based on patterns from Microsoft AaronLocker

# ======================================================================
# PRAGMA ONCE - Prevent duplicate module loading
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
        Reads PE headers to identify portable executables regardless of extension
    .PARAMETER filename
        Path to the file to analyze
    .RETURNS
        "EXE", "DLL", or $null
    #>
    param([string]$filename)

    # PE header constants
    Set-Variable sizeofImageDosHeader -Option Constant -Value 64
    Set-Variable sizeofImageNtHeaders64 -Option Constant -Value 264
    Set-Variable offset_e_lfanew -Option Constant -Value 60
    Set-Variable offset_FileHeader -Option Constant -Value 4
    Set-Variable offset_FileHeader_Characteristics -Option Constant -Value 18
    Set-Variable offset_OptionalHeader -Option Constant -Value 24
    Set-Variable offset_OptionalHeader_Subsystem -Option Constant -Value 68
    Set-Variable IMAGE_SUBSYSTEM_WINDOWS_GUI -Option Constant -Value 2
    Set-Variable IMAGE_SUBSYSTEM_WINDOWS_CUI -Option Constant -Value 3
    Set-Variable IMAGE_FILE_DLL -Option Constant -Value 0x2000

    # Read first 64 bytes (IMAGE_DOS_HEADER)
    $bytesImageDosHeader = @(Get-Content -Encoding Byte -TotalCount $sizeofImageDosHeader $filename -ErrorAction SilentlyContinue)
    if ($null -eq $bytesImageDosHeader -or $bytesImageDosHeader.Length -lt $sizeofImageDosHeader) {
        return $null
    }

    # Verify "MZ" signature
    $dosSig = "" + [char]($bytesImageDosHeader[0]) + [char]($bytesImageDosHeader[1])
    if ($dosSig -ne "MZ") {
        return $null
    }

    # Get offset to IMAGE_NT_HEADERS
    $offsetImageNtHeaders = [Int32]('0x{0}' -f (( $bytesImageDosHeader[($offset_e_lfanew + 3)..$offset_e_lfanew] | ForEach-Object { $_.ToString('X2') }) -join ''))

    # Read NT headers
    $totalToRead = $offsetImageNtHeaders + $sizeofImageNtHeaders64
    $bytesImageNtHeaders = Get-Content -Encoding Byte -TotalCount $totalToRead $filename -ErrorAction SilentlyContinue
    if ($bytesImageNtHeaders.Length -lt $totalToRead) {
        return $null
    }

    # Verify "PE" signature
    $peSig = "" + [char]($bytesImageNtHeaders[$offsetImageNtHeaders]) + [char]($bytesImageNtHeaders[$offsetImageNtHeaders + 1])
    if ($peSig -ne "PE") {
        return $null
    }

    # Get Characteristics
    $offsChar = $offsetImageNtHeaders + $offset_FileHeader + $offset_FileHeader_Characteristics
    $characteristics = [UInt16]('0x{0}' -f (( $bytesImageNtHeaders[($offsChar + 1)..$offsChar] | ForEach-Object { $_.ToString('X2') }) -join ''))

    # Get Subsystem
    $offsSubsystem = $offsetImageNtHeaders + $offset_OptionalHeader + $offset_OptionalHeader_Subsystem
    $subsystem = [UInt16]('0x{0}' -f (( $bytesImageNtHeaders[($offsSubsystem + 1)..$offsSubsystem] | ForEach-Object { $_.ToString('X2') }) -join ''))

    # Verify subsystem
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
# EXPORTS
# ======================================================================

Export-ModuleMember -Function Save-XmlDocAsUnicode, Save-AppLockerPolicyAsUnicodeXml,
                              Get-AppLockerFileInfo, ConvertFrom-SidCached,
                              ConvertTo-AppLockerGenericPath, New-AppLockerGuid,
                              Get-StandardSids, IsWin32Executable,
                              Test-AppLockerPath, Test-PublisherName

Export-ModuleMember -Variable GetAlfiDefaultExts, NeverExecutableExts,
                              sNoPublisher, sUnsigned, sFiltered,
                              UnsafeDir, SafeDir, UnknownDir
