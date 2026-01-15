<#
.SYNOPSIS
    Standardized error handling and validation for GA-AppLocker.

.DESCRIPTION
    Provides consistent error handling, input validation, and logging
    patterns across all GA-AppLocker scripts and modules.

.NOTES
    Import this module at the start of any script for consistent behavior.
#>

#Requires -Version 5.1

#region Error Handling

<#
.SYNOPSIS
    Invokes a script block with standardized error handling.

.PARAMETER ScriptBlock
    The code to execute.

.PARAMETER ErrorMessage
    Custom error message prefix.

.PARAMETER ContinueOnError
    If true, continues execution after error (logs warning instead).

.EXAMPLE
    Invoke-SafeOperation { Get-Content $file } -ErrorMessage "Failed to read file"
#>
function Invoke-SafeOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [string]$ErrorMessage = "Operation failed",

        [switch]$ContinueOnError,

        [switch]$Silent
    )

    try {
        return & $ScriptBlock
    }
    catch {
        $fullMessage = "$ErrorMessage`: $($_.Exception.Message)"

        if ($ContinueOnError) {
            if (-not $Silent) {
                Write-Warning $fullMessage
            }
            return $null
        }
        else {
            throw $fullMessage
        }
    }
}

<#
.SYNOPSIS
    Writes a standardized error message and optionally throws.

.PARAMETER Message
    The error message.

.PARAMETER Exception
    Optional exception object for details.

.PARAMETER Throw
    If true, throws an exception after logging.
#>
function Write-ErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [System.Exception]$Exception,

        [switch]$Throw
    )

    $fullMessage = if ($Exception) {
        "$Message`: $($Exception.Message)"
    } else {
        $Message
    }

    Write-Host "ERROR: $fullMessage" -ForegroundColor Red

    if ($Throw) {
        throw $fullMessage
    }
}

#endregion

#region Input Validation

<#
.SYNOPSIS
    Validates that a path exists and is of the expected type.

.PARAMETER Path
    The path to validate.

.PARAMETER Type
    Expected type: File, Directory, or Any.

.PARAMETER MustExist
    If true, path must exist.

.PARAMETER CreateIfMissing
    If true and path doesn't exist, creates it (directories only).

.OUTPUTS
    Validated and resolved path, or $null if invalid.
#>
function Test-ValidPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet('File', 'Directory', 'Any')]
        [string]$Type = 'Any',

        [switch]$MustExist,

        [switch]$CreateIfMissing
    )

    # Handle empty/null
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Warning "Path cannot be empty"
        return $null
    }

    # Resolve relative paths
    $resolvedPath = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path (Get-Location) $Path
    }

    $exists = Test-Path $resolvedPath

    if (-not $exists) {
        if ($MustExist) {
            Write-Warning "Path does not exist: $resolvedPath"
            return $null
        }

        if ($CreateIfMissing -and $Type -eq 'Directory') {
            try {
                New-Item -ItemType Directory -Path $resolvedPath -Force | Out-Null
                Write-Verbose "Created directory: $resolvedPath"
            }
            catch {
                Write-Warning "Failed to create directory: $resolvedPath"
                return $null
            }
        }

        return $resolvedPath
    }

    # Validate type
    $item = Get-Item $resolvedPath
    $isDirectory = $item.PSIsContainer

    if ($Type -eq 'File' -and $isDirectory) {
        Write-Warning "Expected file but found directory: $resolvedPath"
        return $null
    }

    if ($Type -eq 'Directory' -and -not $isDirectory) {
        Write-Warning "Expected directory but found file: $resolvedPath"
        return $null
    }

    return $resolvedPath
}

<#
.SYNOPSIS
    Validates XML file structure.

.PARAMETER Path
    Path to the XML file.

.PARAMETER RootElement
    Expected root element name (optional).

.OUTPUTS
    XML document object if valid, $null otherwise.
#>
function Test-ValidXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$RootElement
    )

    $validPath = Test-ValidPath -Path $Path -Type File -MustExist
    if (-not $validPath) {
        return $null
    }

    try {
        [xml]$xml = Get-Content $validPath -Raw -ErrorAction Stop

        if ($RootElement -and $xml.DocumentElement.Name -ne $RootElement) {
            Write-Warning "Expected root element '$RootElement' but found '$($xml.DocumentElement.Name)'"
            return $null
        }

        return $xml
    }
    catch {
        Write-Warning "Invalid XML file: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Validates an AppLocker policy XML file.

.PARAMETER Path
    Path to the policy file.

.OUTPUTS
    Validated XML document or $null.
#>
function Test-ValidAppLockerPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $xml = Test-ValidXml -Path $Path -RootElement 'AppLockerPolicy'
    if (-not $xml) {
        return $null
    }

    # Check for rule collections
    $collections = $xml.AppLockerPolicy.RuleCollection
    if (-not $collections -or $collections.Count -eq 0) {
        Write-Warning "Policy contains no rule collections"
        return $null
    }

    return $xml
}

<#
.SYNOPSIS
    Validates a computer list file.

.PARAMETER Path
    Path to the computer list file.

.OUTPUTS
    Array of computer names, or empty array if invalid.
#>
function Test-ValidComputerList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $validPath = Test-ValidPath -Path $Path -Type File -MustExist
    if (-not $validPath) {
        return @()
    }

    try {
        $computers = Get-Content $validPath -ErrorAction Stop |
            Where-Object { $_ -and $_ -notmatch '^\s*#' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }

        if ($computers.Count -eq 0) {
            Write-Warning "Computer list is empty: $validPath"
        }

        return $computers
    }
    catch {
        Write-Warning "Failed to read computer list: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Validates a hashtable has required keys.

.PARAMETER Hashtable
    The hashtable to validate.

.PARAMETER RequiredKeys
    Array of required key names.

.OUTPUTS
    $true if valid, $false otherwise.
#>
function Test-RequiredKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Hashtable,

        [Parameter(Mandatory)]
        [string[]]$RequiredKeys
    )

    $missing = @()
    foreach ($key in $RequiredKeys) {
        if (-not $Hashtable.ContainsKey($key)) {
            $missing += $key
        }
    }

    if ($missing.Count -gt 0) {
        Write-Warning "Missing required keys: $($missing -join ', ')"
        return $false
    }

    return $true
}

#endregion

#region Standardized Output

<#
.SYNOPSIS
    Writes a section header for console output.

.PARAMETER Title
    The section title.

.PARAMETER Width
    Character width for the header line.
#>
function Write-SectionHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [int]$Width = 50
    )

    $line = '=' * $Width
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

<#
.SYNOPSIS
    Writes a step indicator for multi-step operations.

.PARAMETER Step
    Current step number.

.PARAMETER Total
    Total number of steps.

.PARAMETER Message
    Step description.
#>
function Write-StepProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Step,

        [Parameter(Mandatory)]
        [int]$Total,

        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[$Step/$Total] $Message..." -ForegroundColor Yellow
}

<#
.SYNOPSIS
    Writes a success message.

.PARAMETER Message
    The success message.
#>
function Write-SuccessMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[OK] $Message" -ForegroundColor Green
}

<#
.SYNOPSIS
    Writes a result summary with pass/fail items.

.PARAMETER Title
    Summary title.

.PARAMETER Results
    Array of result objects with Status and Message properties.
#>
function Write-ResultSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [array]$Results
    )

    Write-Host ""
    Write-Host "$Title`:" -ForegroundColor Cyan

    foreach ($result in $Results) {
        $icon = if ($result.Status -eq 'Pass') { '[PASS]' } else { '[FAIL]' }
        $color = if ($result.Status -eq 'Pass') { 'Green' } else { 'Red' }

        Write-Host "  $icon $($result.Message)" -ForegroundColor $color
    }

    $passCount = ($Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = ($Results | Where-Object { $_.Status -ne 'Pass' }).Count

    Write-Host ""
    Write-Host "  Passed: $passCount, Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Yellow' })
}

#endregion

#region Module Initialization Helper

<#
.SYNOPSIS
    Standard initialization for GA-AppLocker scripts.

.DESCRIPTION
    Sets up common error handling, imports required modules,
    and validates the execution environment.

.PARAMETER RequireAdmin
    If true, checks for administrator privileges.

.PARAMETER RequireModules
    Array of required PowerShell modules.

.OUTPUTS
    $true if initialization succeeded, $false otherwise.
#>
function Initialize-GAAppLockerScript {
    [CmdletBinding()]
    param(
        [switch]$RequireAdmin,

        [string[]]$RequireModules = @()
    )

    # Check admin if required
    if ($RequireAdmin) {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-ErrorMessage "This script requires administrator privileges" -Throw
            return $false
        }
    }

    # Check required modules
    foreach ($module in $RequireModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Warning "Required module not found: $module"
            return $false
        }
    }

    # Import Common module
    $commonPath = Join-Path $PSScriptRoot 'Common.psm1'
    if (Test-Path $commonPath) {
        Import-Module $commonPath -Force -ErrorAction SilentlyContinue
    }

    return $true
}

#endregion

#region Additional Validation Functions

<#
.SYNOPSIS
    Validates a Security Identifier (SID) string format.

.PARAMETER Sid
    The SID string to validate.

.OUTPUTS
    $true if valid SID format, $false otherwise.
#>
function Test-ValidSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Sid
    )

    # SID format: S-1-{authority}-{sub-authorities}
    if ($Sid -notmatch '^S-1-\d+(-\d+)*$') {
        return $false
    }

    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $true
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Validates a GUID string format.

.PARAMETER Guid
    The GUID string to validate.

.OUTPUTS
    $true if valid GUID, $false otherwise.
#>
function Test-ValidGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Guid
    )

    try {
        [System.Guid]::Parse($Guid) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Validates a computer name format.

.PARAMETER ComputerName
    The computer name to validate.

.OUTPUTS
    $true if valid computer name, $false otherwise.
#>
function Test-ValidComputerName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    # NetBIOS name rules: 1-15 chars, alphanumeric and hyphens, no leading/trailing hyphen
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return $false
    }

    if ($ComputerName.Length -gt 15) {
        return $false
    }

    if ($ComputerName -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$') {
        return $false
    }

    return $true
}

<#
.SYNOPSIS
    Validates a domain name format.

.PARAMETER DomainName
    The domain name to validate.

.OUTPUTS
    $true if valid domain name, $false otherwise.
#>
function Test-ValidDomainName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        return $false
    }

    # Simple NetBIOS domain name validation (not FQDN)
    if ($DomainName -match '^[a-zA-Z][a-zA-Z0-9-]{0,14}$') {
        return $true
    }

    # FQDN validation
    if ($DomainName -match '^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
        return $true
    }

    return $false
}

<#
.SYNOPSIS
    Validates an AppLocker enforcement mode value.

.PARAMETER Mode
    The enforcement mode to validate.

.OUTPUTS
    $true if valid mode, $false otherwise.
#>
function Test-ValidEnforcementMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Mode
    )

    return $Mode -in @('AuditOnly', 'Enabled', 'NotConfigured')
}

<#
.SYNOPSIS
    Validates a file hash format (SHA256).

.PARAMETER Hash
    The hash string to validate.

.PARAMETER Algorithm
    The expected hash algorithm (default: SHA256).

.OUTPUTS
    $true if valid hash format, $false otherwise.
#>
function Test-ValidFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hash,

        [ValidateSet('SHA256', 'SHA1', 'MD5')]
        [string]$Algorithm = 'SHA256'
    )

    # Remove 0x prefix if present
    $cleanHash = $Hash -replace '^0x', ''

    $expectedLength = switch ($Algorithm) {
        'SHA256' { 64 }
        'SHA1' { 40 }
        'MD5' { 32 }
    }

    return $cleanHash -match "^[a-fA-F0-9]{$expectedLength}$"
}

#endregion

#region Credential Validation

<#
.SYNOPSIS
    Tests if credentials are valid for remote connectivity.

.DESCRIPTION
    Attempts to establish a WinRM connection to validate credentials
    before batch operations, preventing wasted time on failed auth.

.PARAMETER Credential
    The PSCredential object to validate.

.PARAMETER ComputerName
    The computer to test against.

.PARAMETER TimeoutSeconds
    Connection timeout in seconds (default: 30).

.OUTPUTS
    $true if credentials work, $false otherwise.

.EXAMPLE
    $cred = Get-Credential
    if (Test-CredentialValidity -Credential $cred -ComputerName "SERVER01") {
        # Proceed with batch operations
    }
#>
function Test-CredentialValidity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [int]$TimeoutSeconds = 30
    )

    try {
        # Test WinRM connectivity with provided credentials
        $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000)
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential `
            -SessionOption $sessionOption -ErrorAction Stop

        # Quick test command to verify session works
        $null = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop

        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Write-Verbose "Credential validation failed: $($_.Exception.Message)"
        return $false
    }
}

#endregion

# Export all functions
Export-ModuleMember -Function @(
    # Error handling
    'Invoke-SafeOperation',
    'Write-ErrorMessage',

    # Input validation
    'Test-ValidPath',
    'Test-ValidXml',
    'Test-ValidAppLockerPolicy',
    'Test-ValidComputerList',
    'Test-RequiredKeys',

    # Additional validation
    'Test-ValidSid',
    'Test-ValidGuid',
    'Test-ValidComputerName',
    'Test-ValidDomainName',
    'Test-ValidEnforcementMode',
    'Test-ValidFileHash',

    # Output formatting
    'Write-SectionHeader',
    'Write-StepProgress',
    'Write-SuccessMessage',
    'Write-ResultSummary',

    # Initialization
    'Initialize-GAAppLockerScript',

    # Credential validation
    'Test-CredentialValidity'
)
