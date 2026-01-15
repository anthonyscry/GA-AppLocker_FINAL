<#
.SYNOPSIS
    Common utility functions for GA-AppLocker scripts.

.DESCRIPTION
    This module provides shared functions used across all AppLocker scripts:
    - SID resolution
    - XML generation helpers
    - File and path utilities
    - Logging functions

.NOTES
    Import this module in scripts using:
    Import-Module "$PSScriptRoot\utilities\Common.psm1" -Force
#>

#region SID Resolution Functions

# Script-level SID cache for performance optimization
$script:SidCache = @{}

<#
.SYNOPSIS
    Resolves a user/group name to its Security Identifier (SID).

.DESCRIPTION
    Resolves account names to SIDs with built-in caching for performance.
    The cache persists for the module lifetime, significantly improving
    performance when the same accounts are resolved multiple times.

.PARAMETER Name
    The name to resolve (e.g., "Everyone", "BUILTIN\Administrators", "DOMAIN\Group")

.PARAMETER NoCache
    Bypass the cache and force a fresh resolution.

.OUTPUTS
    String containing the SID value
#>
function Resolve-AccountToSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$NoCache
    )

    # If already a SID, return as-is (no need to cache)
    if ($Name -match "^S-1-") {
        return $Name
    }

    # Check cache first (unless NoCache specified)
    if (-not $NoCache -and $script:SidCache.ContainsKey($Name)) {
        Write-Verbose "SID cache hit for: $Name"
        return $script:SidCache[$Name]
    }

    # Check well-known SIDs (faster than AD translation)
    $config = Get-AppLockerConfig
    if ($config.WellKnownSids.ContainsKey($Name)) {
        $sid = $config.WellKnownSids[$Name]
        $script:SidCache[$Name] = $sid
        return $sid
    }

    # Try to translate via .NET
    try {
        $account = New-Object System.Security.Principal.NTAccount($Name)
        $sid = $account.Translate([System.Security.Principal.SecurityIdentifier])
        $sidValue = $sid.Value

        # Cache the result
        $script:SidCache[$Name] = $sidValue
        Write-Verbose "Resolved and cached SID for: $Name -> $sidValue"

        return $sidValue
    }
    catch {
        Write-Warning "Could not resolve '$Name' to SID - using placeholder. Verify group exists in AD."
        return "S-1-5-21-YOURDOMAINSID-YOURGROUP"
    }
}

<#
.SYNOPSIS
    Clears the SID resolution cache.

.DESCRIPTION
    Use this to force fresh SID resolution if AD group memberships have changed.
#>
function Clear-SidCache {
    [CmdletBinding()]
    param()

    $count = $script:SidCache.Count
    $script:SidCache = @{}
    Write-Verbose "Cleared $count entries from SID cache"
}

<#
.SYNOPSIS
    Gets current SID cache statistics.

.OUTPUTS
    PSCustomObject with cache statistics
#>
function Get-SidCacheStats {
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{
        EntryCount = $script:SidCache.Count
        Entries = $script:SidCache.Clone()
    }
}

<#
.SYNOPSIS
    Resolves multiple account names to SIDs.

.PARAMETER Names
    Array of names to resolve

.OUTPUTS
    Hashtable with Name as key and SID as value
#>
function Resolve-AccountsToSids {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    $result = @{}
    foreach ($name in $Names) {
        $result[$name] = Resolve-AccountToSid -Name $name
    }
    return $result
}

<#
.SYNOPSIS
    Gets standard principal SIDs used in AppLocker policies.

.PARAMETER DomainName
    Optional domain name for custom group resolution

.OUTPUTS
    Hashtable of principal names to SIDs
#>
function Get-StandardPrincipalSids {
    [CmdletBinding()]
    param(
        [string]$DomainName,
        [string]$AdminsGroup,
        [string]$StandardUsersGroup,
        [string]$ServiceAccountsGroup,
        [string]$InstallersGroup
    )

    # Set defaults if not provided
    if ($DomainName) {
        if (-not $AdminsGroup) { $AdminsGroup = "$DomainName\AppLocker-Admins" }
        if (-not $StandardUsersGroup) { $StandardUsersGroup = "$DomainName\AppLocker-StandardUsers" }
        if (-not $ServiceAccountsGroup) { $ServiceAccountsGroup = "$DomainName\AppLocker-ServiceAccounts" }
        if (-not $InstallersGroup) { $InstallersGroup = "$DomainName\AppLocker-Installers" }
    }

    $sids = @{
        # Mandatory Allow Principals
        SYSTEM         = Resolve-AccountToSid "NT AUTHORITY\SYSTEM"
        LocalService   = Resolve-AccountToSid "NT AUTHORITY\LOCAL SERVICE"
        NetworkService = Resolve-AccountToSid "NT AUTHORITY\NETWORK SERVICE"
        BuiltinAdmins  = Resolve-AccountToSid "BUILTIN\Administrators"
        Everyone       = Resolve-AccountToSid "Everyone"
    }

    # Add custom groups if domain specified
    if ($DomainName) {
        $sids.Admins = Resolve-AccountToSid $AdminsGroup
        $sids.StandardUsers = Resolve-AccountToSid $StandardUsersGroup
        $sids.ServiceAccounts = Resolve-AccountToSid $ServiceAccountsGroup
        $sids.Installers = Resolve-AccountToSid $InstallersGroup
    }

    return $sids
}

#endregion

#region XML Generation Helpers

<#
.SYNOPSIS
    Creates an AppLocker rule XML element.

.PARAMETER Type
    Rule type: FilePathRule, FilePublisherRule, FileHashRule

.PARAMETER Name
    Display name for the rule

.PARAMETER Description
    Rule description

.PARAMETER Sid
    Security identifier for the user/group

.PARAMETER Action
    Allow or Deny

.PARAMETER Condition
    Inner XML for the rule condition
#>
function New-AppLockerRuleXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("FilePathRule", "FilePublisherRule", "FileHashRule")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Description = "",

        [Parameter(Mandatory = $true)]
        [string]$Sid,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Allow", "Deny")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Condition
    )

    $id = [guid]::NewGuid().ToString()
    $escapedName = [System.Security.SecurityElement]::Escape($Name)
    $escapedDesc = [System.Security.SecurityElement]::Escape($Description)

    return @"
    <$Type Id="$id" Name="$escapedName" Description="$escapedDesc" UserOrGroupSid="$Sid" Action="$Action">
      <Conditions>
        $Condition
      </Conditions>
    </$Type>
"@
}

<#
.SYNOPSIS
    Creates a FilePathCondition XML element.
#>
function New-PathConditionXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return "<FilePathCondition Path=`"$Path`"/>"
}

<#
.SYNOPSIS
    Creates a FilePublisherCondition XML element.
#>
function New-PublisherConditionXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Publisher,

        [string]$Product = "*",
        [string]$Binary = "*",
        [string]$LowVersion = "*",
        [string]$HighVersion = "*"
    )

    $escapedPublisher = [System.Security.SecurityElement]::Escape($Publisher)

    return @"
<FilePublisherCondition PublisherName="$escapedPublisher" ProductName="$Product" BinaryName="$Binary">
          <BinaryVersionRange LowSection="$LowVersion" HighSection="$HighVersion"/>
        </FilePublisherCondition>
"@
}

<#
.SYNOPSIS
    Creates a FileHashCondition XML element.
#>
function New-HashConditionXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [long]$FileSize,

        [string]$HashType = "SHA256"
    )

    return @"
<FileHashCondition>
          <FileHash Type="$HashType" Data="0x$Hash" SourceFileName="$FileName" SourceFileLength="$FileSize"/>
        </FileHashCondition>
"@
}

<#
.SYNOPSIS
    Creates the XML header for an AppLocker policy.
#>
function New-PolicyHeaderXml {
    [CmdletBinding()]
    param(
        [string]$Comment = "",
        [string]$TargetType = "",
        [string]$Phase = "",
        [string]$Mode = "Generated"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    return @"
<?xml version="1.0" encoding="utf-8"?>
<!--
  AppLocker Policy - $Mode
  Generated: $timestamp
  Target: $TargetType
  Phase: $Phase
  $Comment
-->
<AppLockerPolicy Version="1">
"@
}

<#
.SYNOPSIS
    Creates a RuleCollection XML element.
#>
function New-RuleCollectionXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Exe", "Msi", "Script", "Dll", "Appx")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [ValidateSet("AuditOnly", "Enabled", "NotConfigured")]
        [string]$EnforcementMode,

        [string]$Rules = ""
    )

    return @"
  <RuleCollection Type="$Type" EnforcementMode="$EnforcementMode">
$Rules  </RuleCollection>
"@
}

#endregion

#region Configuration Functions

<#
.SYNOPSIS
    Loads the AppLocker configuration from Config.psd1
#>
function Get-AppLockerConfig {
    [CmdletBinding()]
    param()

    $configPath = Join-Path $PSScriptRoot "Config.psd1"

    if (Test-Path $configPath) {
        return Import-PowerShellDataFile -Path $configPath
    }
    else {
        Write-Warning "Config file not found at $configPath - using defaults"
        return Get-DefaultConfig
    }
}

<#
.SYNOPSIS
    Returns default configuration if Config.psd1 is missing.
#>
function Get-DefaultConfig {
    return @{
        WellKnownSids = @{
            "NT AUTHORITY\SYSTEM"              = "S-1-5-18"
            "NT AUTHORITY\LOCAL SERVICE"       = "S-1-5-19"
            "NT AUTHORITY\NETWORK SERVICE"     = "S-1-5-20"
            "BUILTIN\Administrators"           = "S-1-5-32-544"
            "BUILTIN\Users"                    = "S-1-5-32-545"
            "Everyone"                         = "S-1-1-0"
            "NT AUTHORITY\Authenticated Users" = "S-1-5-11"
        }
        LOLBins = @(
            @{ Name = "mshta.exe"; Description = "HTML Application Host" }
            @{ Name = "cscript.exe"; Description = "Console Script Host" }
            @{ Name = "wscript.exe"; Description = "Windows Script Host" }
        )
        DefaultDenyPaths = @(
            @{ Path = "%USERPROFILE%\Downloads\*"; Description = "User Downloads folder" }
            @{ Path = "%APPDATA%\*"; Description = "Roaming AppData" }
            @{ Path = "%TEMP%\*"; Description = "System Temp folder" }
        )
    }
}

#endregion

#region File Logging Functions

# Script-level variable for current log file path
$script:CurrentLogFile = $null
$script:LoggingEnabled = $false

<#
.SYNOPSIS
    Initializes file logging for the current session.

.DESCRIPTION
    Creates a timestamped log file in the Logs folder and sets up the logging context.
    All subsequent Write-Log calls will write to this file until Stop-Logging is called.

.PARAMETER LogName
    Base name for the log file (e.g., "Scan", "Generate", "Merge").
    The actual filename will be: {LogName}-{timestamp}.log

.PARAMETER LogPath
    Optional custom path for the Logs folder. Defaults to .\Logs relative to the script root.

.PARAMETER PassThru
    If specified, returns the log file path.

.OUTPUTS
    String (log file path) if -PassThru is specified.

.EXAMPLE
    Start-Logging -LogName "RemoteScan"
    # Creates: .\Logs\RemoteScan-20260109-143000.log
#>
function Start-Logging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [string]$LogPath,

        [switch]$PassThru
    )

    # Determine log folder path
    if (-not $LogPath) {
        # Default to Logs folder in the GA-AppLocker root
        $scriptRoot = if ($PSScriptRoot) {
            Split-Path $PSScriptRoot -Parent
        } else {
            $PWD.Path
        }
        $LogPath = Join-Path $scriptRoot "Logs"
    }

    # Create Logs folder if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    # Generate timestamped log filename
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logFileName = "$LogName-$timestamp.log"
    $script:CurrentLogFile = Join-Path $LogPath $logFileName
    $script:LoggingEnabled = $true

    # Write log header
    $header = @"
================================================================================
  GA-AppLocker Log File
  Operation: $LogName
  Started: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Computer: $env:COMPUTERNAME
  User: $env:USERNAME
================================================================================

"@
    $header | Out-File -FilePath $script:CurrentLogFile -Encoding UTF8

    Write-Verbose "Logging initialized: $($script:CurrentLogFile)"

    if ($PassThru) {
        return $script:CurrentLogFile
    }
}

<#
.SYNOPSIS
    Writes a log entry to the current log file.

.DESCRIPTION
    Writes a timestamped, leveled log entry to the active log file.
    Optionally also writes to the console with appropriate coloring.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    Log level: Info, Warning, Error, Debug, Success. Defaults to Info.

.PARAMETER NoConsole
    If specified, only writes to the log file (no console output).

.PARAMETER Console
    If specified, also writes to the console with color formatting.

.EXAMPLE
    Write-Log "Starting remote scan of 10 computers" -Level Info

.EXAMPLE
    Write-Log "Failed to connect to SERVER01" -Level Error -Console
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Success")]
        [string]$Level = "Info",

        [switch]$NoConsole,

        [switch]$Console
    )

    # Skip if logging not initialized
    if (-not $script:LoggingEnabled -or -not $script:CurrentLogFile) {
        # Still write to console if requested
        if ($Console -and -not $NoConsole) {
            Write-LogToConsole -Message $Message -Level $Level
        }
        return
    }

    # Format the log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $levelTag = $Level.ToUpper().PadRight(7)
    $logEntry = "[$timestamp] [$levelTag] $Message"

    # Write to log file
    try {
        $logEntry | Out-File -FilePath $script:CurrentLogFile -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }

    # Write to console if requested
    if ($Console -and -not $NoConsole) {
        Write-LogToConsole -Message $Message -Level $Level
    }
}

<#
.SYNOPSIS
    Internal function to write log message to console with color.
#>
function Write-LogToConsole {
    [CmdletBinding()]
    param(
        [string]$Message,
        [string]$Level
    )

    $colors = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Debug   = "DarkGray"
    }

    $prefix = @{
        Info    = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error   = "[-]"
        Debug   = "[.]"
    }

    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

<#
.SYNOPSIS
    Writes a section separator to the log file.

.PARAMETER Title
    Title for the section.
#>
function Write-LogSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    if (-not $script:LoggingEnabled) { return }

    $separator = @"

--------------------------------------------------------------------------------
  $Title
--------------------------------------------------------------------------------
"@
    $separator | Out-File -FilePath $script:CurrentLogFile -Append -Encoding UTF8
}

<#
.SYNOPSIS
    Logs the results of a remote operation (scan, event collection, etc.).

.PARAMETER Results
    Array of result objects with Computer, Status, and Message properties.
#>
function Write-LogResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )

    if (-not $script:LoggingEnabled) { return }

    Write-LogSection "Operation Results"

    $successCount = ($Results | Where-Object { $_.Status -eq "Success" }).Count
    $failCount = ($Results | Where-Object { $_.Status -eq "Failed" }).Count

    Write-Log "Total: $($Results.Count) | Success: $successCount | Failed: $failCount" -Level Info

    # Log failures with details
    $failures = $Results | Where-Object { $_.Status -eq "Failed" }
    if ($failures.Count -gt 0) {
        Write-Log "Failed operations:" -Level Warning
        foreach ($failure in $failures) {
            Write-Log "  - $($failure.Computer): $($failure.Message)" -Level Error
        }
    }
}

<#
.SYNOPSIS
    Stops logging and writes the log footer.

.DESCRIPTION
    Finalizes the log file with a footer containing end time and duration.
    Clears the logging context.

.PARAMETER Summary
    Optional summary message to include in the footer.
#>
function Stop-Logging {
    [CmdletBinding()]
    param(
        [string]$Summary = ""
    )

    if (-not $script:LoggingEnabled -or -not $script:CurrentLogFile) {
        return
    }

    # Write log footer
    $footer = @"

================================================================================
  Operation Completed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  $(if ($Summary) { "Summary: $Summary" } else { "" })
================================================================================
"@
    $footer | Out-File -FilePath $script:CurrentLogFile -Append -Encoding UTF8

    $logPath = $script:CurrentLogFile
    $script:CurrentLogFile = $null
    $script:LoggingEnabled = $false

    Write-Verbose "Logging stopped. Log file: $logPath"

    return $logPath
}

<#
.SYNOPSIS
    Gets the path to the current log file.

.OUTPUTS
    String path to the current log file, or $null if logging is not active.
#>
function Get-CurrentLogFile {
    [CmdletBinding()]
    param()

    return $script:CurrentLogFile
}

<#
.SYNOPSIS
    Checks if logging is currently active.

.OUTPUTS
    Boolean indicating whether logging is enabled.
#>
function Test-LoggingEnabled {
    [CmdletBinding()]
    param()

    return $script:LoggingEnabled
}

<#
.SYNOPSIS
    Gets a list of existing log files.

.PARAMETER LogPath
    Path to the Logs folder. Defaults to .\Logs.

.PARAMETER Days
    Only return logs from the last N days. Default is all logs.

.OUTPUTS
    Array of FileInfo objects for log files.
#>
function Get-LogFiles {
    [CmdletBinding()]
    param(
        [string]$LogPath,

        [int]$Days = 0
    )

    if (-not $LogPath) {
        $scriptRoot = if ($PSScriptRoot) {
            Split-Path $PSScriptRoot -Parent
        } else {
            $PWD.Path
        }
        $LogPath = Join-Path $scriptRoot "Logs"
    }

    if (-not (Test-Path $LogPath)) {
        return @()
    }

    $logs = Get-ChildItem -Path $LogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending

    if ($Days -gt 0) {
        $cutoff = (Get-Date).AddDays(-$Days)
        $logs = $logs | Where-Object { $_.LastWriteTime -ge $cutoff }
    }

    return $logs
}

<#
.SYNOPSIS
    Cleans up old log files.

.PARAMETER LogPath
    Path to the Logs folder. Defaults to .\Logs.

.PARAMETER RetentionDays
    Delete logs older than this many days. Default is 30.

.PARAMETER WhatIf
    Shows what would be deleted without actually deleting.

.OUTPUTS
    Count of deleted files.
#>
function Clear-OldLogs {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$LogPath,

        [int]$RetentionDays = 30
    )

    if (-not $LogPath) {
        $scriptRoot = if ($PSScriptRoot) {
            Split-Path $PSScriptRoot -Parent
        } else {
            $PWD.Path
        }
        $LogPath = Join-Path $scriptRoot "Logs"
    }

    if (-not (Test-Path $LogPath)) {
        return 0
    }

    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $oldLogs = Get-ChildItem -Path $LogPath -Filter "*.log" |
        Where-Object { $_.LastWriteTime -lt $cutoff }

    $deletedCount = 0
    foreach ($log in $oldLogs) {
        if ($PSCmdlet.ShouldProcess($log.Name, "Delete old log file")) {
            Remove-Item -Path $log.FullName -Force
            $deletedCount++
        }
    }

    return $deletedCount
}

#endregion

#region Remote Operation Helpers

<#
.SYNOPSIS
    Creates a timestamped output folder for scan or event collection operations.

.DESCRIPTION
    Creates a subfolder with a standardized timestamp format and returns
    the resolved absolute path. Useful for job-based operations where
    relative paths may not work.

.PARAMETER BasePath
    The parent directory where the timestamped folder will be created.

.PARAMETER Prefix
    Prefix for the folder name (e.g., "Scan", "Events").

.OUTPUTS
    String containing the absolute path to the created folder.

.EXAMPLE
    $outputRoot = New-TimestampedOutputFolder -BasePath ".\Scans" -Prefix "Scan"
    # Creates: .\Scans\Scan-20260110-143000 and returns absolute path
#>
function New-TimestampedOutputFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $folderName = "$Prefix-$timestamp"
    $outputPath = Join-Path $BasePath $folderName

    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

    # Return absolute path for use in jobs
    return (Resolve-Path $outputPath).Path
}

<#
.SYNOPSIS
    Parses AppLocker event data from XML format.

.DESCRIPTION
    Extracts structured data from an AppLocker event's XML representation,
    including file path, hash, publisher info, and FQBN parsing.

.PARAMETER EventXml
    The XML representation of the event (from $event.ToXml()).

.PARAMETER EventType
    The type of event: "Blocked" or "Allowed".

.OUTPUTS
    PSCustomObject with parsed event data.

.EXAMPLE
    $xml = [xml]$event.ToXml()
    $parsed = ConvertFrom-AppLockerEventXml -EventXml $xml -EventId $event.Id -EventType "Blocked"
#>
function ConvertFrom-AppLockerEventXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [xml]$EventXml,

        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [datetime]$TimeCreated,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Blocked", "Allowed")]
        [string]$EventType,

        [string]$LogName = ""
    )

    $eventData = $EventXml.Event.EventData.Data

    # Extract fields from event data
    $filePath = ($eventData | Where-Object { $_.Name -eq 'FilePath' }).'#text'
    $fileHash = ($eventData | Where-Object { $_.Name -eq 'FileHash' }).'#text'
    $fqbn = ($eventData | Where-Object { $_.Name -eq 'Fqbn' }).'#text'
    $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUser' }).'#text'
    $policyName = ($eventData | Where-Object { $_.Name -eq 'PolicyName' }).'#text'

    # Parse publisher info from FQBN (format: O=Publisher, L=..., S=..., C=...\ProductName\Version\FileName)
    $publisher = ""
    $productName = ""
    $fileVersion = ""
    if ($fqbn -and $fqbn -ne "-") {
        if ($fqbn -match "^O=([^\\,]+)") {
            $publisher = $matches[1].Trim('"')
        }
        $parts = $fqbn -split '\\'
        if ($parts.Count -ge 3) {
            $productName = $parts[-3]
            $fileVersion = $parts[-2]
        }
    }

    return [PSCustomObject]@{
        TimeCreated = $TimeCreated
        EventId     = $EventId
        EventType   = $EventType
        FilePath    = $filePath
        FileName    = if ($filePath) { Split-Path $filePath -Leaf } else { "" }
        FileHash    = $fileHash
        Publisher   = $publisher
        ProductName = $productName
        FileVersion = $fileVersion
        FQBN        = $fqbn
        TargetUser  = $targetUser
        PolicyName  = $policyName
        LogName     = $LogName
    }
}

#endregion

#region Console Output Functions

<#
.SYNOPSIS
    Writes a formatted status message.
#>
function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("Info", "Success", "Warning", "Error", "Header")]
        [string]$Type = "Info"
    )

    $colors = @{
        Info    = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Header  = "Magenta"
    }

    $prefix = @{
        Info    = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error   = "[-]"
        Header  = "==="
    }

    Write-Host "$($prefix[$Type]) $Message" -ForegroundColor $colors[$Type]
}

<#
.SYNOPSIS
    Writes a banner/header for script output.
#>
function Write-Banner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [string]$Subtitle = ""
    )

    $width = 78
    $line = "=" * $width

    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  " + $Title.PadRight($width - 4)) -ForegroundColor Cyan
    if ($Subtitle) {
        Write-Host ("  " + $Subtitle.PadRight($width - 4)) -ForegroundColor Gray
    }
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

#endregion

#region File Utilities

<#
.SYNOPSIS
    Ensures a directory exists, creating it if necessary.
#>
function Confirm-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Verbose "Created directory: $Path"
    }
    return $Path
}

<#
.SYNOPSIS
    Generates a timestamped filename.
#>
function Get-TimestampedFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseName,

        [string]$Extension = "xml"
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    return "$BaseName-$timestamp.$Extension"
}

<#
.SYNOPSIS
    Reads a computer list from either TXT or CSV format.

.DESCRIPTION
    Supports two formats:
    - TXT: One computer name per line (lines starting with # are comments)
    - CSV: Must have a 'ComputerName' column header

.PARAMETER Path
    Path to the computer list file (.txt or .csv)

.OUTPUTS
    Array of computer names
#>
function Get-ComputerList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLower()

    if ($extension -eq ".csv") {
        # CSV format - expect ComputerName column
        $csv = Import-Csv -Path $Path
        if (-not ($csv | Get-Member -Name "ComputerName" -MemberType NoteProperty)) {
            throw "CSV file must have a 'ComputerName' column header"
        }
        $computers = @($csv |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.ComputerName) } |
            ForEach-Object { $_.ComputerName.Trim() })
    }
    else {
        # TXT format - one computer per line, # for comments
        $computers = @(Get-Content -Path $Path |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith("#") } |
            ForEach-Object { $_.Trim() })
    }

    return $computers
}

#endregion

#region Validation Functions

<#
.SYNOPSIS
    Validates an AppLocker policy XML file.

.PARAMETER PolicyPath
    Path to the policy XML file.

.OUTPUTS
    PSCustomObject with validation results.
#>
function Test-AppLockerPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath
    )

    $result = [PSCustomObject]@{
        Path          = $PolicyPath
        IsValid       = $false
        XmlValid      = $false
        HasRules      = $false
        RuleCount     = 0
        Collections   = @()
        Warnings      = [System.Collections.Generic.List[string]]::new()
        Errors        = [System.Collections.Generic.List[string]]::new()
    }

    # Check file exists
    if (-not (Test-Path $PolicyPath)) {
        $result.Errors.Add("File not found: $PolicyPath")
        return $result
    }

    # Validate XML structure
    try {
        [xml]$policy = Get-Content -Path $PolicyPath -Raw -ErrorAction Stop
        $result.XmlValid = $true
    }
    catch {
        $result.Errors.Add("Invalid XML: $($_.Exception.Message)")
        return $result
    }

    # Check for AppLockerPolicy root element
    if ($null -eq $policy.AppLockerPolicy) {
        $result.Errors.Add("Missing <AppLockerPolicy> root element")
        return $result
    }

    # Analyze rule collections
    $totalRules = 0
    foreach ($collection in $policy.AppLockerPolicy.RuleCollection) {
        $collectionType = $collection.Type
        $enforcementMode = $collection.EnforcementMode

        $ruleCount = 0
        $ruleCount += ($collection.FilePublisherRule | Measure-Object).Count
        $ruleCount += ($collection.FilePathRule | Measure-Object).Count
        $ruleCount += ($collection.FileHashRule | Measure-Object).Count

        $result.Collections += [PSCustomObject]@{
            Type            = $collectionType
            EnforcementMode = $enforcementMode
            RuleCount       = $ruleCount
        }

        $totalRules += $ruleCount

        # Check for empty enforced collections (warning)
        if ($enforcementMode -eq "Enabled" -and $ruleCount -eq 0) {
            $result.Warnings.Add("$collectionType collection is enforced but has no rules - will block everything!")
        }

        # Check for DLL rules in enforce mode (warning)
        if ($collectionType -eq "Dll" -and $enforcementMode -eq "Enabled") {
            $result.Warnings.Add("DLL rules are in Enforce mode - ensure thorough testing was done")
        }
    }

    $result.RuleCount = $totalRules
    $result.HasRules = $totalRules -gt 0

    # Additional security checks
    $securityIssues = Test-PolicySecurity -Policy $policy
    foreach ($issue in $securityIssues) {
        $result.Warnings.Add($issue)
    }

    # Determine overall validity
    $result.IsValid = $result.XmlValid -and $result.HasRules -and ($result.Errors.Count -eq 0)

    return $result
}

<#
.SYNOPSIS
    Checks a policy for common security issues.

.PARAMETER Policy
    The XML policy object.

.OUTPUTS
    Array of warning messages.
#>
function Test-PolicySecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Policy
    )

    $warnings = @()

    foreach ($collection in $Policy.AppLockerPolicy.RuleCollection) {
        # Check for overly permissive path rules
        foreach ($rule in $collection.FilePathRule) {
            $path = $rule.Conditions.FilePathCondition.Path
            $action = $rule.Action
            $sid = $rule.UserOrGroupSid

            # Warning: Allow * for Everyone
            if ($path -eq "*" -and $action -eq "Allow" -and $sid -eq "S-1-1-0") {
                $warnings += "[$($collection.Type)] Rule '$($rule.Name)' allows EVERYTHING for Everyone"
            }

            # Warning: Allow from user-writable paths
            $userWritablePaths = @("%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%", "Downloads")
            foreach ($uwp in $userWritablePaths) {
                if ($path -like "*$uwp*" -and $action -eq "Allow") {
                    $warnings += "[$($collection.Type)] Rule '$($rule.Name)' allows execution from user-writable path: $path"
                }
            }
        }

        # Check for wildcard publisher rules to Everyone
        foreach ($rule in $collection.FilePublisherRule) {
            $publisher = $rule.Conditions.FilePublisherCondition.PublisherName
            $sid = $rule.UserOrGroupSid

            # Warning: Overly broad publisher to Everyone
            if ($publisher -eq "*" -and $sid -eq "S-1-1-0") {
                $warnings += "[$($collection.Type)] Rule '$($rule.Name)' allows ANY publisher for Everyone"
            }
        }
    }

    return $warnings
}

<#
.SYNOPSIS
    Compares two AppLocker policies and reports differences.

.PARAMETER ReferencePath
    Path to the reference (baseline) policy.

.PARAMETER DifferencePath
    Path to the policy to compare.

.OUTPUTS
    PSCustomObject with comparison results.
#>
function Compare-AppLockerPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReferencePath,

        [Parameter(Mandatory = $true)]
        [string]$DifferencePath
    )

    $result = [PSCustomObject]@{
        ReferencePath  = $ReferencePath
        DifferencePath = $DifferencePath
        AreIdentical   = $false
        RulesOnlyInRef = @()
        RulesOnlyInDiff = @()
        ModeDifferences = @()
    }

    # Load both policies
    try {
        [xml]$refPolicy = Get-Content -Path $ReferencePath -Raw
        [xml]$diffPolicy = Get-Content -Path $DifferencePath -Raw
    }
    catch {
        Write-Error "Failed to load policies: $_"
        return $result
    }

    # Compare enforcement modes
    foreach ($refColl in $refPolicy.AppLockerPolicy.RuleCollection) {
        $diffColl = $diffPolicy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $refColl.Type }

        if ($refColl.EnforcementMode -ne $diffColl.EnforcementMode) {
            $result.ModeDifferences += [PSCustomObject]@{
                Collection    = $refColl.Type
                ReferenceMode = $refColl.EnforcementMode
                DifferenceMode = $diffColl.EnforcementMode
            }
        }
    }

    # Extract rule identifiers for comparison
    $refRules = Get-PolicyRuleIdentifiers -Policy $refPolicy
    $diffRules = Get-PolicyRuleIdentifiers -Policy $diffPolicy

    $result.RulesOnlyInRef = $refRules | Where-Object { $_ -notin $diffRules }
    $result.RulesOnlyInDiff = $diffRules | Where-Object { $_ -notin $refRules }

    $result.AreIdentical = ($result.RulesOnlyInRef.Count -eq 0) -and
                           ($result.RulesOnlyInDiff.Count -eq 0) -and
                           ($result.ModeDifferences.Count -eq 0)

    return $result
}

<#
.SYNOPSIS
    Extracts unique rule identifiers from a policy for comparison.
#>
function Get-PolicyRuleIdentifiers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Policy
    )

    $identifiers = @()

    foreach ($collection in $Policy.AppLockerPolicy.RuleCollection) {
        $type = $collection.Type

        foreach ($rule in $collection.FilePublisherRule) {
            $pub = $rule.Conditions.FilePublisherCondition
            $identifiers += "$type|Publisher|$($pub.PublisherName)|$($pub.ProductName)|$($pub.BinaryName)"
        }

        foreach ($rule in $collection.FilePathRule) {
            $path = $rule.Conditions.FilePathCondition.Path
            $identifiers += "$type|Path|$($rule.Action)|$path"
        }

        foreach ($rule in $collection.FileHashRule) {
            $hash = $rule.Conditions.FileHashCondition.FileHash.Data
            $identifiers += "$type|Hash|$hash"
        }
    }

    return $identifiers
}

<#
.SYNOPSIS
    Displays a visual comparison between two AppLocker policies.

.DESCRIPTION
    Shows a formatted diff-style output comparing two policies, highlighting:
    - Rules only in the first policy (removed)
    - Rules only in the second policy (added)
    - Enforcement mode differences
    - Summary statistics

.PARAMETER ReferencePath
    Path to the reference (baseline) policy.

.PARAMETER DifferencePath
    Path to the policy to compare.

.PARAMETER PassThru
    If specified, returns the comparison result object in addition to displaying.

.EXAMPLE
    Show-PolicyDiff -ReferencePath .\baseline.xml -DifferencePath .\new-policy.xml
#>
function Show-PolicyDiff {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReferencePath,

        [Parameter(Mandatory = $true)]
        [string]$DifferencePath,

        [switch]$PassThru
    )

    # Get the comparison result
    $diff = Compare-AppLockerPolicies -ReferencePath $ReferencePath -DifferencePath $DifferencePath

    # Display header
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "                    AppLocker Policy Comparison                        " -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Reference: " -NoNewline -ForegroundColor Gray
    Write-Host (Split-Path $ReferencePath -Leaf) -ForegroundColor White
    Write-Host "Compare:   " -NoNewline -ForegroundColor Gray
    Write-Host (Split-Path $DifferencePath -Leaf) -ForegroundColor White
    Write-Host ""

    # Overall status
    if ($diff.AreIdentical) {
        Write-Host "=== RESULT: Policies are IDENTICAL ===" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "=== RESULT: Policies are DIFFERENT ===" -ForegroundColor Yellow
        Write-Host ""

        # Show enforcement mode differences
        if ($diff.ModeDifferences.Count -gt 0) {
            Write-Host "Enforcement Mode Changes:" -ForegroundColor Yellow
            foreach ($modeDiff in $diff.ModeDifferences) {
                Write-Host "  $($modeDiff.Collection): " -NoNewline -ForegroundColor Gray
                Write-Host "$($modeDiff.ReferenceMode)" -NoNewline -ForegroundColor Red
                Write-Host " -> " -NoNewline -ForegroundColor Gray
                Write-Host "$($modeDiff.DifferenceMode)" -ForegroundColor Green
            }
            Write-Host ""
        }

        # Show rules only in reference (removed in new policy)
        if ($diff.RulesOnlyInRef.Count -gt 0) {
            Write-Host "Rules REMOVED (only in reference):" -ForegroundColor Red
            $diff.RulesOnlyInRef | Select-Object -First 20 | ForEach-Object {
                $parts = $_ -split '\|'
                $ruleType = $parts[0]
                $conditionType = $parts[1]

                switch ($conditionType) {
                    'Publisher' {
                        Write-Host "  - [$ruleType] Publisher: $($parts[2])" -ForegroundColor Red
                        if ($parts[3] -ne '*') { Write-Host "           Product: $($parts[3])" -ForegroundColor DarkRed }
                    }
                    'Path' {
                        Write-Host "  - [$ruleType] Path ($($parts[2])): $($parts[3])" -ForegroundColor Red
                    }
                    'Hash' {
                        $hashPreview = if ($parts[2].Length -gt 20) { $parts[2].Substring(0, 20) + "..." } else { $parts[2] }
                        Write-Host "  - [$ruleType] Hash: $hashPreview" -ForegroundColor Red
                    }
                }
            }
            if ($diff.RulesOnlyInRef.Count -gt 20) {
                Write-Host "  ... and $($diff.RulesOnlyInRef.Count - 20) more" -ForegroundColor DarkRed
            }
            Write-Host ""
        }

        # Show rules only in difference (added in new policy)
        if ($diff.RulesOnlyInDiff.Count -gt 0) {
            Write-Host "Rules ADDED (only in compared policy):" -ForegroundColor Green
            $diff.RulesOnlyInDiff | Select-Object -First 20 | ForEach-Object {
                $parts = $_ -split '\|'
                $ruleType = $parts[0]
                $conditionType = $parts[1]

                switch ($conditionType) {
                    'Publisher' {
                        Write-Host "  + [$ruleType] Publisher: $($parts[2])" -ForegroundColor Green
                        if ($parts[3] -ne '*') { Write-Host "           Product: $($parts[3])" -ForegroundColor DarkGreen }
                    }
                    'Path' {
                        Write-Host "  + [$ruleType] Path ($($parts[2])): $($parts[3])" -ForegroundColor Green
                    }
                    'Hash' {
                        $hashPreview = if ($parts[2].Length -gt 20) { $parts[2].Substring(0, 20) + "..." } else { $parts[2] }
                        Write-Host "  + [$ruleType] Hash: $hashPreview" -ForegroundColor Green
                    }
                }
            }
            if ($diff.RulesOnlyInDiff.Count -gt 20) {
                Write-Host "  ... and $($diff.RulesOnlyInDiff.Count - 20) more" -ForegroundColor DarkGreen
            }
            Write-Host ""
        }
    }

    # Summary statistics
    Write-Host "=== Summary ===" -ForegroundColor Cyan
    $removedColor = if ($diff.RulesOnlyInRef.Count -gt 0) { 'Red' } else { 'Gray' }
    $addedColor = if ($diff.RulesOnlyInDiff.Count -gt 0) { 'Green' } else { 'Gray' }
    $modeColor = if ($diff.ModeDifferences.Count -gt 0) { 'Yellow' } else { 'Gray' }

    Write-Host "  Rules removed: $($diff.RulesOnlyInRef.Count)" -ForegroundColor $removedColor
    Write-Host "  Rules added:   $($diff.RulesOnlyInDiff.Count)" -ForegroundColor $addedColor
    Write-Host "  Mode changes:  $($diff.ModeDifferences.Count)" -ForegroundColor $modeColor
    Write-Host ""

    if ($PassThru) {
        return $diff
    }
}

<#
.SYNOPSIS
    Validates scan data directory structure and content.

.PARAMETER ScanPath
    Path to the scan results directory.

.OUTPUTS
    PSCustomObject with validation results.
#>
function Test-ScanData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScanPath
    )

    $result = [PSCustomObject]@{
        Path           = $ScanPath
        IsValid        = $false
        ComputerCount  = 0
        HasExecutables = $false
        HasPublishers  = $false
        HasWritable    = $false
        Computers      = @()
        Warnings       = [System.Collections.Generic.List[string]]::new()
        Errors         = [System.Collections.Generic.List[string]]::new()
    }

    # Check path exists
    if (-not (Test-Path $ScanPath)) {
        $result.Errors.Add("Scan path not found: $ScanPath")
        return $result
    }

    # Find computer folders (folders containing CSV files)
    $computerFolders = Get-ChildItem -Path $ScanPath -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName "*.csv") }

    if ($computerFolders.Count -eq 0) {
        $result.Errors.Add("No computer scan data found in $ScanPath")
        return $result
    }

    $result.ComputerCount = $computerFolders.Count

    foreach ($folder in $computerFolders) {
        $computerData = [PSCustomObject]@{
            Name           = $folder.Name
            ExecutableCount = 0
            SignedCount    = 0
            PublisherCount = 0
            WritableCount  = 0
        }

        # Check for Executables.csv
        $exePath = Join-Path $folder.FullName "Executables.csv"
        if (Test-Path $exePath) {
            $exes = Import-Csv -Path $exePath
            $computerData.ExecutableCount = $exes.Count
            $computerData.SignedCount = ($exes | Where-Object { $_.IsSigned -eq "True" }).Count
            $result.HasExecutables = $true
        }

        # Check for Publishers.csv
        $pubPath = Join-Path $folder.FullName "Publishers.csv"
        if (Test-Path $pubPath) {
            $pubs = Import-Csv -Path $pubPath
            $computerData.PublisherCount = $pubs.Count
            $result.HasPublishers = $true
        }

        # Check for WritableDirectories.csv
        $writablePath = Join-Path $folder.FullName "WritableDirectories.csv"
        if (Test-Path $writablePath) {
            $writable = Import-Csv -Path $writablePath
            $computerData.WritableCount = $writable.Count
            $result.HasWritable = $true
        }

        $result.Computers += $computerData
    }

    # Add warnings for missing data
    if (-not $result.HasExecutables) {
        $result.Warnings.Add("No executable data found - publisher rules cannot be generated")
    }

    if (-not $result.HasWritable) {
        $result.Warnings.Add("No writable directory data - security analysis incomplete")
    }

    $result.IsValid = $result.HasExecutables -and ($result.Errors.Count -eq 0)

    return $result
}

<#
.SYNOPSIS
    Displays validation results in a formatted manner.

.PARAMETER ValidationResult
    The result object from Test-AppLockerPolicy or Test-ScanData.
#>
function Show-ValidationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ValidationResult
    )

    $statusColor = if ($ValidationResult.IsValid) { "Green" } else { "Red" }
    $statusText = if ($ValidationResult.IsValid) { "VALID" } else { "INVALID" }

    Write-Host "`n=== Validation Result: $statusText ===" -ForegroundColor $statusColor
    Write-Host "Path: $($ValidationResult.Path)" -ForegroundColor Cyan

    if ($ValidationResult.RuleCount) {
        Write-Host "Total Rules: $($ValidationResult.RuleCount)" -ForegroundColor Gray
    }

    if ($ValidationResult.Collections) {
        Write-Host "`nRule Collections:" -ForegroundColor Yellow
        foreach ($coll in $ValidationResult.Collections) {
            Write-Host "  $($coll.Type): $($coll.RuleCount) rules ($($coll.EnforcementMode))" -ForegroundColor Gray
        }
    }

    if ($ValidationResult.ComputerCount) {
        Write-Host "Computers: $($ValidationResult.ComputerCount)" -ForegroundColor Gray
    }

    if ($ValidationResult.Warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($warning in $ValidationResult.Warnings) {
            Write-Host "  [!] $warning" -ForegroundColor Yellow
        }
    }

    if ($ValidationResult.Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($err in $ValidationResult.Errors) {
            Write-Host "  [-] $err" -ForegroundColor Red
        }
    }

    Write-Host ""
}

#endregion

#region Parameter and Input Helpers

<#
.SYNOPSIS
    Prompts for and validates a path with proper error handling.

.PARAMETER Prompt
    The prompt message to display.

.PARAMETER DefaultValue
    Optional default value if user provides no input.

.PARAMETER MustExist
    If true, validates that the path exists.

.PARAMETER MustBeFile
    If true, validates that the path is a file (not directory).

.PARAMETER MustBeDirectory
    If true, validates that the path is a directory (not file).

.OUTPUTS
    String path, or $null if validation fails.
#>
function Get-ValidatedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [string]$DefaultValue = "",
        [string]$Example = "",
        [switch]$MustExist,
        [switch]$MustBeFile,
        [switch]$MustBeDirectory
    )

    # Show example if provided
    if ($Example) {
        Write-Host "  Example: $Example" -ForegroundColor DarkGray
    }

    # Prompt with default
    if ($DefaultValue) {
        $userInput = Read-Host "$Prompt (default: $DefaultValue)"
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            $userInput = $DefaultValue
        }
    }
    else {
        $userInput = Read-Host $Prompt
    }

    # Check if empty
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        Write-Host "  [-] Path is required" -ForegroundColor Red
        return $null
    }

    # Check existence if required
    if ($MustExist -and -not (Test-Path $userInput)) {
        Write-Host "  [-] Path not found: $userInput" -ForegroundColor Red
        return $null
    }

    # Validate file type
    if ($MustExist) {
        $item = Get-Item $userInput -ErrorAction SilentlyContinue
        if ($item) {
            if ($MustBeFile -and $item.PSIsContainer) {
                Write-Host "  [-] Path is a directory, not a file: $userInput" -ForegroundColor Red
                Write-Host "      Please provide a file path" -ForegroundColor Yellow
                return $null
            }
            if ($MustBeDirectory -and -not $item.PSIsContainer) {
                Write-Host "  [-] Path is a file, not a directory: $userInput" -ForegroundColor Red
                Write-Host "      Please provide a directory path" -ForegroundColor Yellow
                return $null
            }
        }
    }

    return $userInput
}

<#
.SYNOPSIS
    Adds parameters to a hashtable only if they have non-empty values.

.PARAMETER Hashtable
    The hashtable to add parameters to.

.PARAMETER Parameters
    Hashtable of parameter names and values to conditionally add.

.EXAMPLE
    $params = @{}
    Add-NonEmptyParameters -Hashtable $params -Parameters @{
        Path = $Path
        Name = $Name
        Force = $Force
    }
#>
function Add-NonEmptyParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Hashtable,

        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    foreach ($key in $Parameters.Keys) {
        $value = $Parameters[$key]

        # Add if: not null, not empty string, or is a switch/bool
        if ($null -ne $value) {
            if ($value -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    $Hashtable[$key] = $value
                }
            }
            elseif ($value -is [bool] -or $value -is [switch]) {
                if ($value) {
                    $Hashtable[$key] = $value
                }
            }
            else {
                $Hashtable[$key] = $value
            }
        }
    }
}

#endregion

#region Publisher Rule Helpers

<#
.SYNOPSIS
    Generates a publisher rule key based on granularity settings.

.DESCRIPTION
    Creates a unique key for publisher rules based on the specified granularity level.
    This function consolidates duplicate logic for building publisher rule keys from
    scan data or event data.

.PARAMETER Publisher
    The publisher/signer name (e.g., "Microsoft Corporation")

.PARAMETER Product
    The product name (optional, defaults to "*")

.PARAMETER Binary
    The binary name (optional, defaults to "*")

.PARAMETER Granularity
    Rule granularity level: Publisher, PublisherProduct, or PublisherProductBinary

.OUTPUTS
    Hashtable with Key, Publisher, Product, and Binary properties
#>
function Get-PublisherRuleKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Publisher,

        [string]$Product = "*",

        [string]$Binary = "*",

        [Parameter(Mandatory)]
        [ValidateSet("Publisher", "PublisherProduct", "PublisherProductBinary")]
        [string]$Granularity
    )

    switch ($Granularity) {
        "Publisher" {
            return @{
                Key       = $Publisher
                Publisher = $Publisher
                Product   = "*"
                Binary    = "*"
            }
        }
        "PublisherProduct" {
            return @{
                Key       = "$Publisher|$Product"
                Publisher = $Publisher
                Product   = $Product
                Binary    = "*"
            }
        }
        "PublisherProductBinary" {
            return @{
                Key       = "$Publisher|$Product|$Binary"
                Publisher = $Publisher
                Product   = $Product
                Binary    = $Binary
            }
        }
    }
}

<#
.SYNOPSIS
    Adds a publisher rule to a hashtable if not already present.

.DESCRIPTION
    Helper function that adds publisher rules to a collection with deduplication.
    Returns whether the rule was added (true) or already existed (false).

.PARAMETER Rules
    Hashtable to add the rule to (passed by reference)

.PARAMETER Publisher
    Publisher name

.PARAMETER Product
    Product name (optional)

.PARAMETER Binary
    Binary name (optional)

.PARAMETER Granularity
    Rule granularity level

.PARAMETER Source
    Optional source identifier (e.g., "ScanData", "BlockedEvent")

.OUTPUTS
    Boolean indicating if the rule was added
#>
function Add-PublisherRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Rules,

        [Parameter(Mandatory)]
        [string]$Publisher,

        [string]$Product = "*",

        [string]$Binary = "*",

        [Parameter(Mandatory)]
        [ValidateSet("Publisher", "PublisherProduct", "PublisherProductBinary")]
        [string]$Granularity,

        [string]$Source
    )

    $keyInfo = Get-PublisherRuleKey -Publisher $Publisher -Product $Product -Binary $Binary -Granularity $Granularity

    if (-not $Rules.ContainsKey($keyInfo.Key)) {
        $rule = @{
            Publisher = $keyInfo.Publisher
            Product   = $keyInfo.Product
            Binary    = $keyInfo.Binary
        }
        if ($Source) {
            $rule.Source = $Source
        }
        $Rules[$keyInfo.Key] = $rule
        return $true
    }

    return $false
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    # SID Resolution
    'Resolve-AccountToSid',
    'Resolve-AccountsToSids',
    'Get-StandardPrincipalSids',
    'Clear-SidCache',
    'Get-SidCacheStats',

    # XML Generation
    'New-AppLockerRuleXml',
    'New-PathConditionXml',
    'New-PublisherConditionXml',
    'New-HashConditionXml',
    'New-PolicyHeaderXml',
    'New-RuleCollectionXml',

    # Configuration
    'Get-AppLockerConfig',
    'Get-DefaultConfig',

    # File Logging
    'Start-Logging',
    'Write-Log',
    'Write-LogSection',
    'Write-LogResults',
    'Stop-Logging',
    'Get-CurrentLogFile',
    'Test-LoggingEnabled',
    'Get-LogFiles',
    'Clear-OldLogs',

    # Console Output
    'Write-Status',
    'Write-Banner',

    # Remote Operation Helpers
    'New-TimestampedOutputFolder',
    'ConvertFrom-AppLockerEventXml',

    # File Utilities
    'Confirm-Directory',
    'Get-TimestampedFileName',
    'Get-ComputerList',

    # Validation
    'Test-AppLockerPolicy',
    'Test-PolicySecurity',
    'Compare-AppLockerPolicies',
    'Get-PolicyRuleIdentifiers',
    'Show-PolicyDiff',
    'Test-ScanData',
    'Show-ValidationResult',

    # Parameter and Input Helpers
    'Get-ValidatedPath',
    'Add-NonEmptyParameters',

    # Publisher Rule Helpers
    'Get-PublisherRuleKey',
    'Add-PublisherRule'
)
