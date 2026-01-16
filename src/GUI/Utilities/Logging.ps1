<#
.SYNOPSIS
    Logging utilities for GA-AppLocker GUI

.DESCRIPTION
    Provides logging, audit trail, and output logging functions with
    automatic log rotation and security features.

.NOTES
    Version:        2.0
    Author:         General Atomics - ASI
    Creation Date:  2026-01-16
    Module:         Utilities\Logging
#>

function Write-Log {
    <#
    .SYNOPSIS
        Write a log entry to the application log file

    .DESCRIPTION
        Creates timestamped log entries with severity levels.
        Automatically creates log directory and handles rotation.

    .PARAMETER Message
        The log message to write

    .PARAMETER Level
        Log level: INFO, WARN, ERROR, DEBUG

    .PARAMETER Path
        Optional custom log file path. Defaults to standard location.

    .EXAMPLE
        Write-Log "Application started" -Level "INFO"

    .EXAMPLE
        Write-Log "Failed to load policy" -Level "ERROR"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    # Determine log directory and file
    if (-not $Path) {
        $logDir = "C:\GA-AppLocker\Logs"
        if (-not (Test-Path $logDir)) {
            try {
                New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
            }
            catch {
                # Fallback to temp directory if C: is not writable
                $logDir = "$env:TEMP\GA-AppLocker\Logs"
                New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }

        $logFile = Join-Path $logDir "GA-AppLocker-$(Get-Date -Format 'yyyy-MM-dd').log"
    }
    else {
        $logFile = $Path
        $logDir = Split-Path -Parent $logFile
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # Create log entry
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to log file
    try {
        # Check if log rotation is needed (> 50MB)
        if (Test-Path $logFile) {
            $logFileInfo = Get-Item $logFile
            if ($logFileInfo.Length -gt 50MB) {
                $archivePath = $logFile -replace '\.log$', "_archive_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $logFile -Destination $archivePath -Force -ErrorAction SilentlyContinue
                Write-Verbose "Log file rotated to: $archivePath"
            }
        }

        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop

        # Also write to verbose stream if enabled
        Write-Verbose $logEntry

        # Write to appropriate PowerShell stream based on level
        switch ($Level) {
            'ERROR' { Write-Error $Message -ErrorAction SilentlyContinue }
            'WARN'  { Write-Warning $Message -WarningAction SilentlyContinue }
            'DEBUG' { Write-Debug $Message -Debug:$DebugPreference }
        }
    }
    catch {
        # Silently fail if logging fails - don't disrupt application
        Write-Verbose "Failed to write log entry: $($_.Exception.Message)"
    }
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Write security audit log entries

    .DESCRIPTION
        Logs security-relevant operations for compliance and forensic analysis.
        Includes automatic log rotation, Windows Event Log integration, and
        sanitized input for security.

    .PARAMETER Action
        The action performed (e.g., 'GPO_CREATED', 'GPO_LINKED', 'POLICY_APPLIED')

    .PARAMETER Target
        The target object (e.g., GPO name, OU path)

    .PARAMETER Result
        Operation result: SUCCESS, FAILURE, ATTEMPT, or CANCELLED

    .PARAMETER Details
        Additional details about the operation

    .PARAMETER Path
        Optional custom audit log path

    .EXAMPLE
        Write-AuditLog -Action "GPO_CREATED" -Target "AppLocker-Baseline" -Result "SUCCESS"

    .EXAMPLE
        Write-AuditLog -Action "POLICY_MODIFIED" -Target "Domain Controllers" -Result "FAILURE" `
                       -Details "Access denied - insufficient permissions"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [string]$Target = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet('SUCCESS', 'FAILURE', 'ATTEMPT', 'CANCELLED')]
        [string]$Result = 'SUCCESS',

        [Parameter(Mandatory = $false)]
        [string]$Details = "",

        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    # Get current user information
    try {
        $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        $userName = "$env:USERDOMAIN\$env:USERNAME"
    }

    # Sanitize inputs for security (prevent log injection)
    $Action = ConvertTo-SafeLogString -InputString $Action -MaxLength 100
    $Target = ConvertTo-SafeLogString -InputString $Target -MaxLength 500
    $Details = ConvertTo-SafeLogString -InputString $Details -MaxLength 2000

    # Create audit log entry
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Result] [$Action] Target=$Target User=$userName Computer=$env:COMPUTERNAME Details=$Details"

    # Determine audit log path
    if (-not $Path) {
        $auditLogPath = 'C:\GA-AppLocker\logs\audit.log'
    }
    else {
        $auditLogPath = $Path
    }

    $auditLogDir = Split-Path -Parent $auditLogPath

    # Create directory if needed
    if (-not (Test-Path $auditLogDir)) {
        try {
            New-Item -ItemType Directory -Path $auditLogDir -Force -ErrorAction Stop | Out-Null
        }
        catch {
            # Fallback to temp directory
            $auditLogPath = "$env:TEMP\GA-AppLocker\logs\audit.log"
            $auditLogDir = Split-Path -Parent $auditLogPath
            New-Item -ItemType Directory -Path $auditLogDir -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # Write to audit log file
    try {
        # Check log size - rotate if > 50MB
        if (Test-Path $auditLogPath) {
            $logFile = Get-Item $auditLogPath
            if ($logFile.Length -gt 50MB) {
                $archivePath = $auditLogPath -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $auditLogPath -Destination $archivePath -Force
                Write-Verbose "Audit log rotated to: $archivePath"
            }
        }

        Add-Content -Path $auditLogPath -Value $logEntry -ErrorAction Stop

        # Also write to Windows Event Log if available
        try {
            $eventSource = "GA-AppLocker"

            # Create event source if it doesn't exist
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                # Requires admin rights - skip if not available
                New-EventLog -LogName Application -Source $eventSource -ErrorAction SilentlyContinue
            }

            # Determine event type based on result
            $eventType = switch ($Result) {
                'SUCCESS' { 'Information' }
                'FAILURE' { 'Error' }
                'ATTEMPT' { 'Warning' }
                'CANCELLED' { 'Warning' }
                default { 'Information' }
            }

            # Write to event log
            $eventMessage = "Action: $Action`nTarget: $Target`nUser: $userName`nDetails: $Details"
            Write-EventLog -LogName Application -Source $eventSource -EventId 1000 `
                          -EntryType $eventType -Message $eventMessage -ErrorAction SilentlyContinue
        }
        catch {
            # Event log write is optional - don't fail if unavailable
            Write-Verbose "Could not write to Windows Event Log: $($_.Exception.Message)"
        }
    }
    catch {
        # Log failure - try to write to standard log instead
        Write-Log "AUDIT LOG WRITE FAILED: $logEntry" -Level "ERROR"
    }
}

function Write-OutputLog {
    <#
    .SYNOPSIS
        Log output text from UI sections

    .DESCRIPTION
        Logs output from GUI text boxes and panels to a separate output log file

    .PARAMETER Section
        The UI section generating the output (e.g., "Dashboard", "EventMonitor")

    .PARAMETER Output
        The output text to log

    .PARAMETER Path
        Optional custom output log path

    .EXAMPLE
        Write-OutputLog -Section "EventMonitor" -Output $outputTextBox.Text
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Section,

        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    if (-not $Path) {
        $logDir = "C:\GA-AppLocker\Logs\Output"
        if (-not (Test-Path $logDir)) {
            try {
                New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
            }
            catch {
                $logDir = "$env:TEMP\GA-AppLocker\Logs\Output"
                New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }

        $logFile = Join-Path $logDir "Output-$(Get-Date -Format 'yyyy-MM-dd').log"
    }
    else {
        $logFile = $Path
        $logDir = Split-Path -Parent $logFile
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $separator = "=" * 80
    $logEntry = @"
$separator
[$timestamp] Section: $Section
$separator
$Output
$separator

"@

    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
        Write-Verbose "Output logged to: $logFile"
    }
    catch {
        Write-Verbose "Failed to write output log: $($_.Exception.Message)"
    }
}

function ConvertTo-SafeLogString {
    <#
    .SYNOPSIS
        Sanitize string for safe logging

    .DESCRIPTION
        Removes or escapes characters that could be used for log injection attacks

    .PARAMETER InputString
        The string to sanitize

    .PARAMETER MaxLength
        Maximum allowed length

    .OUTPUTS
        Sanitized string

    .EXAMPLE
        $safe = ConvertTo-SafeLogString -InputString $userInput -MaxLength 500
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InputString = "",

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

    # Remove null bytes and most control characters (keep newline, tab, carriage return)
    $sanitized = $InputString -replace '[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', ''

    # Replace multiple spaces with single space
    $sanitized = $sanitized -replace '\s+', ' '

    # Trim whitespace
    $sanitized = $sanitized.Trim()

    return $sanitized
}

function Get-LogFiles {
    <#
    .SYNOPSIS
        Get list of log files

    .DESCRIPTION
        Returns information about application log files

    .PARAMETER LogType
        Type of logs to retrieve: Application, Audit, Output, or All

    .OUTPUTS
        Array of log file information

    .EXAMPLE
        $logs = Get-LogFiles -LogType "Audit"
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Application', 'Audit', 'Output', 'All')]
        [string]$LogType = 'All'
    )

    $logFiles = @()
    $baseLogDir = "C:\GA-AppLocker\Logs"

    if (-not (Test-Path $baseLogDir)) {
        $baseLogDir = "$env:TEMP\GA-AppLocker\Logs"
    }

    if (-not (Test-Path $baseLogDir)) {
        return $logFiles
    }

    # Get application logs
    if ($LogType -in @('Application', 'All')) {
        $appLogs = Get-ChildItem -Path $baseLogDir -Filter "GA-AppLocker-*.log" -ErrorAction SilentlyContinue
        foreach ($log in $appLogs) {
            $logFiles += @{
                Type = 'Application'
                Path = $log.FullName
                Size = $log.Length
                LastModified = $log.LastWriteTime
            }
        }
    }

    # Get audit logs
    if ($LogType -in @('Audit', 'All')) {
        $auditLog = Join-Path $baseLogDir "audit.log"
        if (Test-Path $auditLog) {
            $log = Get-Item $auditLog
            $logFiles += @{
                Type = 'Audit'
                Path = $log.FullName
                Size = $log.Length
                LastModified = $log.LastWriteTime
            }
        }

        # Get archived audit logs
        $archivedAudit = Get-ChildItem -Path $baseLogDir -Filter "audit_*.log" -ErrorAction SilentlyContinue
        foreach ($log in $archivedAudit) {
            $logFiles += @{
                Type = 'Audit (Archived)'
                Path = $log.FullName
                Size = $log.Length
                LastModified = $log.LastWriteTime
            }
        }
    }

    # Get output logs
    if ($LogType -in @('Output', 'All')) {
        $outputLogDir = Join-Path $baseLogDir "Output"
        if (Test-Path $outputLogDir) {
            $outputLogs = Get-ChildItem -Path $outputLogDir -Filter "Output-*.log" -ErrorAction SilentlyContinue
            foreach ($log in $outputLogs) {
                $logFiles += @{
                    Type = 'Output'
                    Path = $log.FullName
                    Size = $log.Length
                    LastModified = $log.LastWriteTime
                }
            }
        }
    }

    return $logFiles
}

# Export module members
Export-ModuleMember -Function Write-Log, Write-AuditLog, Write-OutputLog, `
                              ConvertTo-SafeLogString, Get-LogFiles
