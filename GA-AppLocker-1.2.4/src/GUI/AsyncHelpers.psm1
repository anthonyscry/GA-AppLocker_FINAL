<#
.SYNOPSIS
    Async helper functions for GA-AppLocker GUI
.DESCRIPTION
    Provides runspace-based async execution for long-running operations,
    allowing the GUI to remain responsive during scans, event collection, etc.
#>

# Script-level runspace pool for async operations
$Script:RunspacePool = $null
$Script:ActiveJobs = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()

function Initialize-AsyncPool {
    <#
    .SYNOPSIS
        Initialize the runspace pool for async operations
    #>
    param(
        [int]$MaxThreads = 5
    )

    if ($null -eq $Script:RunspacePool) {
        $Script:RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
        $Script:RunspacePool.ApartmentState = "STA"
        $Script:RunspacePool.Open()
    }
}

function Close-AsyncPool {
    <#
    .SYNOPSIS
        Close and dispose of the runspace pool
    #>
    # Clear active jobs first
    $Script:ActiveJobs.Clear()

    if ($null -ne $Script:RunspacePool) {
        $Script:RunspacePool.Close()
        $Script:RunspacePool.Dispose()
        $Script:RunspacePool = $null
    }
}

function Start-AsyncOperation {
    <#
    .SYNOPSIS
        Start an async operation in the runspace pool
    .PARAMETER ScriptBlock
        The script block to execute
    .PARAMETER Parameters
        Hashtable of parameters to pass to the script
    .PARAMETER OnComplete
        Script block to execute when operation completes
    .PARAMETER OnProgress
        Script block to execute for progress updates
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [hashtable]$Parameters = @{},

        [scriptblock]$OnComplete,

        [scriptblock]$OnProgress,

        [string]$OperationName = "Operation"
    )

    if ($null -eq $Script:RunspacePool) {
        Initialize-AsyncPool
    }

    $jobId = [guid]::NewGuid().ToString()

    $powershell = [powershell]::Create()
    $powershell.RunspacePool = $Script:RunspacePool

    # Wrap script to capture output and errors
    $wrapperScript = {
        param($ScriptToRun, $Params, $AppRoot)

        $ErrorActionPreference = 'Continue'
        $results = @{
            Output = @()
            Errors = @()
            Success = $true
        }

        try {
            Set-Location $AppRoot
            $output = & $ScriptToRun @Params 2>&1
            foreach ($item in $output) {
                if ($item -is [System.Management.Automation.ErrorRecord]) {
                    $results.Errors += $item.ToString()
                } else {
                    $results.Output += $item.ToString()
                }
            }
        }
        catch {
            $results.Errors += $_.Exception.Message
            $results.Success = $false
        }

        return $results
    }

    $powershell.AddScript($wrapperScript) | Out-Null
    $powershell.AddParameter('ScriptToRun', $ScriptBlock) | Out-Null
    $powershell.AddParameter('Params', $Parameters) | Out-Null
    $powershell.AddParameter('AppRoot', $Script:AppRoot) | Out-Null

    $handle = $powershell.BeginInvoke()

    $jobInfo = @{
        Id = $jobId
        PowerShell = $powershell
        Handle = $handle
        OperationName = $OperationName
        OnComplete = $OnComplete
        OnProgress = $OnProgress
        StartTime = Get-Date
    }

    $Script:ActiveJobs[$jobId] = $jobInfo

    return $jobId
}

function Get-AsyncOperationStatus {
    <#
    .SYNOPSIS
        Check the status of an async operation
    #>
    param(
        [Parameter(Mandatory)]
        [string]$JobId
    )

    if (-not $Script:ActiveJobs.ContainsKey($JobId)) {
        return @{ Status = 'NotFound' }
    }

    $job = $Script:ActiveJobs[$JobId]

    if ($job.Handle.IsCompleted) {
        return @{
            Status = 'Completed'
            Duration = (Get-Date) - $job.StartTime
        }
    }

    return @{
        Status = 'Running'
        Duration = (Get-Date) - $job.StartTime
    }
}

function Wait-AsyncOperation {
    <#
    .SYNOPSIS
        Wait for an async operation to complete and get results
    #>
    param(
        [Parameter(Mandatory)]
        [string]$JobId,

        [int]$TimeoutSeconds = 3600
    )

    if (-not $Script:ActiveJobs.ContainsKey($JobId)) {
        return @{
            Success = $false
            Error = "Job not found: $JobId"
        }
    }

    $job = $Script:ActiveJobs[$JobId]
    $startWait = Get-Date

    while (-not $job.Handle.IsCompleted) {
        if (((Get-Date) - $startWait).TotalSeconds -gt $TimeoutSeconds) {
            $job.PowerShell.Stop()
            return @{
                Success = $false
                Error = "Operation timed out after $TimeoutSeconds seconds"
            }
        }
        Start-Sleep -Milliseconds 100
    }

    try {
        $result = $job.PowerShell.EndInvoke($job.Handle)

        # Execute completion callback if provided
        if ($job.OnComplete) {
            & $job.OnComplete -Result $result
        }

        return $result
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
    finally {
        $job.PowerShell.Dispose()
        $Script:ActiveJobs.TryRemove($JobId, [ref]$null) | Out-Null
    }
}

function Stop-AsyncOperation {
    <#
    .SYNOPSIS
        Stop a running async operation
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$JobId
    )

    if (-not $Script:ActiveJobs.ContainsKey($JobId)) {
        return $false
    }

    $job = $Script:ActiveJobs[$JobId]

    try {
        $job.PowerShell.Stop()
        $job.PowerShell.Dispose()
        $Script:ActiveJobs.TryRemove($JobId, [ref]$null) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-AllAsyncOperations {
    <#
    .SYNOPSIS
        Get all active async operations
    #>
    # Return empty array if no jobs exist
    if ($null -eq $Script:ActiveJobs -or $Script:ActiveJobs.Count -eq 0) {
        return @()
    }

    # Use ToArray() to get a proper snapshot and avoid "Stack empty" error during enumeration
    # This is safer than iterating .Keys on a ConcurrentDictionary during concurrent modifications
    $results = @()
    try {
        $snapshot = $Script:ActiveJobs.ToArray()
        foreach ($kvp in $snapshot) {
            $job = $kvp.Value
            if ($null -ne $job) {
                $results += [PSCustomObject]@{
                    Id = $kvp.Key
                    OperationName = $job.OperationName
                    StartTime = $job.StartTime
                    IsCompleted = $job.Handle.IsCompleted
                    Duration = (Get-Date) - $job.StartTime
                }
            }
        }
    }
    catch {
        # If enumeration fails, return what we have so far
        Write-Verbose "Error enumerating async operations: $_"
    }

    return $results
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-AsyncPool',
    'Close-AsyncPool',
    'Start-AsyncOperation',
    'Get-AsyncOperationStatus',
    'Wait-AsyncOperation',
    'Stop-AsyncOperation',
    'Get-AllAsyncOperations'
)
