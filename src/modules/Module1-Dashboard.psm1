# Module1-Dashboard.psm1
# Dashboard module for GA-AppLocker
# Shows overview statistics about AppLocker environment

using module ..\lib\Common.psm1

<#
.SYNOPSIS
    Get AppLocker Event Statistics
.DESCRIPTION
    Counts events by type (Allowed, Audit, Blocked)
    Event ID 8002 = Allowed
    Event ID 8003 = Audit (would be blocked in enforce mode)
    Event ID 8004 = Blocked
#>
function Get-AppLockerEventStats {
    [CmdletBinding()]
    param()

    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'

    # Check if log exists
    $logExists = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if (-not $logExists) {
        return @{
            success = $true
            allowed = 0
            audit = 0
            blocked = 0
            message = 'AppLocker log not found'
        }
    }

    # Query events
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue

        $allowed = ($events | Where-Object { $_.Id -eq 8002 }).Count
        $audit = ($events | Where-Object { $_.Id -eq 8003 }).Count
        $blocked = ($events | Where-Object { $_.Id -eq 8004 }).Count

        return @{
            success = $true
            allowed = $allowed
            audit = $audit
            blocked = $blocked
            total = $events.Count
        }
    }
    catch {
        return @{
            success = $true
            allowed = 0
            audit = 0
            blocked = 0
            message = 'No events found'
        }
    }
}

<#
.SYNOPSIS
    Get Machine Count from Active Directory
.DESCRIPTION
    Counts total computers, workstations, servers, and domain controllers
#>
function Get-ADMachineCount {
    [CmdletBinding()]
    param()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            total = 0
        }
    }

    try {
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem

        $total = @($computers).Count
        $workstations = @($computers | Where-Object {
            $_.OperatingSystem -match 'Windows 1[0-1]' -or
            $_.OperatingSystem -match 'Windows 7' -or
            $_.OperatingSystem -match 'Windows 8'
        }).Count

        $servers = @($computers | Where-Object {
            $_.OperatingSystem -match 'Server'
        }).Count

        $domainControllers = @($computers | Where-Object {
            $_.DistinguishedName -match 'Domain Controllers'
        }).Count

        return @{
            success = $true
            total = $total
            workstations = $workstations
            servers = $servers
            domainControllers = $domainControllers
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            total = 0
        }
    }
}

<#
.SYNOPSIS
    Get Policy Health Score
.DESCRIPTION
    Calculates a score (0-100) based on configured rule categories
    Each category (Exe, Msi, Script, Dll) is worth 25 points
#>
function Get-PolicyHealthScore {
    [CmdletBinding()]
    param()

    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    }
    catch {
        return @{
            success = $true
            score = 0
            hasPolicy = $false
            message = 'No AppLocker policy'
        }
    }

    if ($null -eq $policy) {
        return @{
            success = $true
            score = 0
            hasPolicy = $false
            hasExe = $false
            hasMsi = $false
            hasScript = $false
            hasDll = $false
        }
    }

    $hasExe = $false
    $hasMsi = $false
    $hasScript = $false
    $hasDll = $false

    foreach ($collection in $policy.RuleCollections) {
        switch ($collection.RuleCollectionType) {
            'Exe'     { if ($collection.Count -gt 0) { $hasExe = $true } }
            'Msi'     { if ($collection.Count -gt 0) { $hasMsi = $true } }
            'Script'  { if ($collection.Count -gt 0) { $hasScript = $true } }
            'Dll'     { if ($collection.Count -gt 0) { $hasDll = $true } }
        }
    }

    $score = 0
    if ($hasExe)     { $score += 25 }
    if ($hasMsi)     { $score += 25 }
    if ($hasScript)  { $score += 25 }
    if ($hasDll)     { $score += 25 }

    return @{
        success = $true
        score = $score
        hasPolicy = $true
        hasExe = $hasExe
        hasMsi = $hasMsi
        hasScript = $hasScript
        hasDll = $hasDll
    }
}

<#
.SYNOPSIS
    Get complete Dashboard summary
.DESCRIPTION
    Combines all dashboard statistics into one call
#>
function Get-DashboardSummary {
    [CmdletBinding()]
    param()

    $events = Get-AppLockerEventStats
    $machines = Get-ADMachineCount
    $health = Get-PolicyHealthScore

    return @{
        success = $true
        timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        events = $events
        machines = $machines
        policyHealth = $health
    }
}

# Export functions
Export-ModuleMember -Function Get-AppLockerEventStats, Get-ADMachineCount, Get-PolicyHealthScore, Get-DashboardSummary
