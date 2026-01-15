# Common.psm1
# Shared library functions for GA-AppLocker Dashboard

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
