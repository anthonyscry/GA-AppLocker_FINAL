<#
.SYNOPSIS
    Automates AppLocker deployment phase advancement based on event analysis.

.DESCRIPTION
    Analyzes AppLocker audit events and scan data to determine if it's safe
    to advance to the next deployment phase. Provides:
    - Event trend analysis (blocked apps decreasing?)
    - Coverage metrics (% of installed apps with rules)
    - Risk assessment for phase advancement
    - Automatic policy generation for next phase
    - Rollback recommendations if issues detected

.PARAMETER CurrentPhase
    Current deployment phase (1-4).

.PARAMETER EventPath
    Path to event collection data.

.PARAMETER ScanPath
    Path to scan data.

.PARAMETER PolicyPath
    Path to current policy.

.PARAMETER DaysToAnalyze
    Number of days of event data to analyze (default: 14).

.PARAMETER AutoAdvance
    Automatically generate and save the next phase policy if safe.

.PARAMETER Thresholds
    Custom thresholds for advancement criteria.

.EXAMPLE
    .\Invoke-PhaseAdvancement.ps1 -CurrentPhase 1 -EventPath .\Events -ScanPath .\Scans

.EXAMPLE
    .\Invoke-PhaseAdvancement.ps1 -CurrentPhase 2 -EventPath .\Events -AutoAdvance

.NOTES
    Phase descriptions:
    - Phase 1: Executable rules only (lowest risk)
    - Phase 2: Executables + Scripts
    - Phase 3: Executables + Scripts + MSI
    - Phase 4: All rule types including DLL (highest security)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateRange(1, 4)]
    [int]$CurrentPhase,

    [string]$EventPath,

    [string]$ScanPath,

    [string]$PolicyPath,

    [int]$DaysToAnalyze = 14,

    [switch]$AutoAdvance,

    [string]$OutputPath = '.\Outputs',

    [hashtable]$Thresholds = @{
        MaxNewBlockedPerDay = 5
        MinDaysStable = 7
        MaxCriticalBlocked = 0
        MinCoveragePercent = 80
        TrendImprovement = 0.1  # 10% improvement required
    }
)

$ErrorActionPreference = 'Stop'

# Get module root
$scriptRoot = Split-Path $PSScriptRoot -Parent

# Import common functions and error handling
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ErrorHandling.psm1') -Force

#region Phase Definitions

$PhaseDefinitions = @{
    1 = @{
        Name = 'Executable Rules Only'
        Collections = @('Exe')
        RiskLevel = 'Low'
        Description = 'Only executable (.exe, .com) rules are enforced'
        NextPhasePrereqs = 'Stable executable blocking with minimal business impact'
    }
    2 = @{
        Name = 'Executables + Scripts'
        Collections = @('Exe', 'Script')
        RiskLevel = 'Medium-Low'
        Description = 'Script rules (.ps1, .bat, .cmd, .vbs, .js) added'
        NextPhasePrereqs = 'Script blocking stable, no critical script failures'
    }
    3 = @{
        Name = 'Executables + Scripts + MSI'
        Collections = @('Exe', 'Script', 'Msi')
        RiskLevel = 'Medium'
        Description = 'Installer rules (.msi, .msp, .mst) added'
        NextPhasePrereqs = 'All software installation methods covered'
    }
    4 = @{
        Name = 'Full Enforcement (All + DLL)'
        Collections = @('Exe', 'Script', 'Msi', 'Dll')
        RiskLevel = 'High'
        Description = 'DLL rules added - maximum security, highest impact'
        NextPhasePrereqs = 'N/A - Final phase'
    }
}

#endregion

#region Analysis Functions

function Get-EventTrend {
    param(
        [string]$EventPath,
        [int]$Days
    )

    $events = @()
    $cutoffDate = (Get-Date).AddDays(-$Days)

    # Find and load event files
    if (Test-Path $EventPath) {
        Get-ChildItem $EventPath -Filter '*.csv' -Recurse | ForEach-Object {
            try {
                $fileEvents = Import-Csv $_.FullName -ErrorAction SilentlyContinue
                $events += $fileEvents | Where-Object {
                    $eventDate = $null
                    if ([datetime]::TryParse($_.TimeCreated, [ref]$eventDate)) {
                        $eventDate -gt $cutoffDate
                    }
                }
            } catch { }
        }
    }

    if ($events.Count -eq 0) {
        return @{
            TotalEvents = 0
            DailyAverage = 0
            Trend = 'Unknown'
            TrendPercent = 0
            ByDay = @{}
        }
    }

    # Group by day
    $byDay = $events | Group-Object {
        $date = $null
        if ([datetime]::TryParse($_.TimeCreated, [ref]$date)) {
            $date.ToString('yyyy-MM-dd')
        } else {
            'Unknown'
        }
    } | Where-Object { $_.Name -ne 'Unknown' }

    $dailyCounts = @{}
    foreach ($day in $byDay) {
        $dailyCounts[$day.Name] = $day.Count
    }

    # Calculate trend (first half vs second half)
    $sortedDays = $dailyCounts.Keys | Sort-Object
    $midPoint = [math]::Floor($sortedDays.Count / 2)

    if ($midPoint -gt 0) {
        $firstHalf = $sortedDays[0..($midPoint-1)] | ForEach-Object { $dailyCounts[$_] } | Measure-Object -Average
        $secondHalf = $sortedDays[$midPoint..($sortedDays.Count-1)] | ForEach-Object { $dailyCounts[$_] } | Measure-Object -Average

        $trend = if ($secondHalf.Average -lt $firstHalf.Average) {
            'Improving'
        } elseif ($secondHalf.Average -gt $firstHalf.Average) {
            'Worsening'
        } else {
            'Stable'
        }

        $trendPercent = if ($firstHalf.Average -gt 0) {
            (($firstHalf.Average - $secondHalf.Average) / $firstHalf.Average) * 100
        } else { 0 }
    } else {
        $trend = 'Insufficient Data'
        $trendPercent = 0
    }

    return @{
        TotalEvents = $events.Count
        DailyAverage = [math]::Round($events.Count / $Days, 1)
        Trend = $trend
        TrendPercent = [math]::Round($trendPercent, 1)
        ByDay = $dailyCounts
        UniqueApps = ($events | Select-Object -ExpandProperty Path -Unique).Count
    }
}

function Get-CoverageMetrics {
    param(
        [string]$ScanPath,
        [string]$PolicyPath
    )

    $metrics = @{
        TotalApps = 0
        CoveredApps = 0
        CoveragePercent = 0
        UncoveredApps = @()
    }

    if (-not $ScanPath -or -not (Test-Path $ScanPath)) {
        return $metrics
    }

    # Get all installed software from scans
    $allApps = @()
    Get-ChildItem $ScanPath -Filter 'InstalledSoftware.csv' -Recurse | ForEach-Object {
        $apps = Import-Csv $_.FullName -ErrorAction SilentlyContinue
        $allApps += $apps
    }

    $uniqueApps = $allApps | Select-Object -Property Path, Publisher -Unique
    $metrics.TotalApps = $uniqueApps.Count

    if ($PolicyPath -and (Test-Path $PolicyPath)) {
        # Load policy and check coverage
        [xml]$policy = Get-Content $PolicyPath -Raw

        $coveredCount = 0
        $uncovered = @()

        foreach ($app in $uniqueApps) {
            $isCovered = $false

            foreach ($collection in $policy.AppLockerPolicy.RuleCollection) {
                foreach ($rule in $collection.ChildNodes) {
                    if ($rule.NodeType -ne 'Element') { continue }
                    if ($rule.Action -ne 'Allow') { continue }

                    # Check publisher match
                    if ($rule.Conditions.FilePublisherCondition) {
                        $pubCondition = $rule.Conditions.FilePublisherCondition
                        if ($app.Publisher -and $app.Publisher -like "*$($pubCondition.PublisherName)*") {
                            $isCovered = $true
                            break
                        }
                    }

                    # Check path match
                    if ($rule.Conditions.FilePathCondition) {
                        $pathPattern = $rule.Conditions.FilePathCondition.Path -replace '\*', '.*'
                        if ($app.Path -match $pathPattern) {
                            $isCovered = $true
                            break
                        }
                    }
                }
                if ($isCovered) { break }
            }

            if ($isCovered) {
                $coveredCount++
            } else {
                $uncovered += $app
            }
        }

        $metrics.CoveredApps = $coveredCount
        $metrics.CoveragePercent = if ($metrics.TotalApps -gt 0) {
            [math]::Round(($coveredCount / $metrics.TotalApps) * 100, 1)
        } else { 0 }
        $metrics.UncoveredApps = $uncovered | Select-Object -First 50
    }

    return $metrics
}

function Get-CriticalBlockedApps {
    param([string]$EventPath)

    $criticalPatterns = @(
        '*Microsoft*Office*',
        '*Microsoft*Teams*',
        '*Microsoft*Outlook*',
        '*Windows Defender*',
        '*System32*',
        '*SysWOW64*',
        '*Program Files*Microsoft*',
        '*OneDrive*',
        '*Azure*'
    )

    $criticalBlocked = @()

    if (Test-Path $EventPath) {
        Get-ChildItem $EventPath -Filter '*Blocked*.csv' -Recurse | ForEach-Object {
            $events = Import-Csv $_.FullName -ErrorAction SilentlyContinue
            foreach ($event in $events) {
                foreach ($pattern in $criticalPatterns) {
                    if ($event.Path -like $pattern) {
                        $criticalBlocked += $event
                        break
                    }
                }
            }
        }
    }

    return $criticalBlocked | Select-Object -Property Path, Publisher -Unique
}

function Test-PhaseAdvancementReady {
    param(
        [int]$CurrentPhase,
        [hashtable]$EventTrend,
        [hashtable]$Coverage,
        [array]$CriticalBlocked,
        [hashtable]$Thresholds
    )

    $checks = @()

    # Check 1: Event trend is improving or stable
    $trendCheck = @{
        Name = 'Event Trend'
        Passed = $EventTrend.Trend -in @('Improving', 'Stable', 'Insufficient Data')
        Value = "$($EventTrend.Trend) ($($EventTrend.TrendPercent)%)"
        Threshold = 'Improving or Stable'
    }
    $checks += $trendCheck

    # Check 2: Daily blocked apps below threshold
    $dailyCheck = @{
        Name = 'Daily Blocked Apps'
        Passed = $EventTrend.DailyAverage -le $Thresholds.MaxNewBlockedPerDay
        Value = "$($EventTrend.DailyAverage) per day"
        Threshold = "Max $($Thresholds.MaxNewBlockedPerDay) per day"
    }
    $checks += $dailyCheck

    # Check 3: No critical apps blocked
    $criticalCheck = @{
        Name = 'Critical Apps Blocked'
        Passed = $CriticalBlocked.Count -le $Thresholds.MaxCriticalBlocked
        Value = "$($CriticalBlocked.Count) critical apps"
        Threshold = "Max $($Thresholds.MaxCriticalBlocked)"
    }
    $checks += $criticalCheck

    # Check 4: Coverage threshold met
    $coverageCheck = @{
        Name = 'Policy Coverage'
        Passed = $Coverage.CoveragePercent -ge $Thresholds.MinCoveragePercent
        Value = "$($Coverage.CoveragePercent)%"
        Threshold = "Min $($Thresholds.MinCoveragePercent)%"
    }
    $checks += $coverageCheck

    # Check 5: Not already at max phase
    $phaseCheck = @{
        Name = 'Phase Advancement Available'
        Passed = $CurrentPhase -lt 4
        Value = "Current Phase $CurrentPhase"
        Threshold = 'Phase < 4'
    }
    $checks += $phaseCheck

    $allPassed = ($checks | Where-Object { -not $_.Passed }).Count -eq 0

    return @{
        Ready = $allPassed
        Checks = $checks
        FailedChecks = $checks | Where-Object { -not $_.Passed }
    }
}

#endregion

#region Main

Write-SectionHeader -Title "AppLocker Phase Advancement Analysis"

# Display current phase
$currentPhaseDef = $PhaseDefinitions[$CurrentPhase]
Write-Host "Current Phase: $CurrentPhase - $($currentPhaseDef.Name)" -ForegroundColor Yellow
Write-Host "  Risk Level: $($currentPhaseDef.RiskLevel)" -ForegroundColor Gray
Write-Host "  Collections: $($currentPhaseDef.Collections -join ', ')" -ForegroundColor Gray
Write-Host ""

# Analyze events
Write-Host "Analyzing event data..." -ForegroundColor Yellow
$eventTrend = Get-EventTrend -EventPath $EventPath -Days $DaysToAnalyze

Write-Host "  Total events: $($eventTrend.TotalEvents)" -ForegroundColor Gray
Write-Host "  Daily average: $($eventTrend.DailyAverage)" -ForegroundColor Gray
Write-Host "  Trend: $($eventTrend.Trend) ($($eventTrend.TrendPercent)%)" -ForegroundColor $(
    if ($eventTrend.Trend -eq 'Improving') { 'Green' }
    elseif ($eventTrend.Trend -eq 'Worsening') { 'Red' }
    else { 'Yellow' }
)
Write-Host ""

# Check coverage
Write-Host "Analyzing policy coverage..." -ForegroundColor Yellow
$coverage = Get-CoverageMetrics -ScanPath $ScanPath -PolicyPath $PolicyPath

Write-Host "  Total apps scanned: $($coverage.TotalApps)" -ForegroundColor Gray
Write-Host "  Apps with rules: $($coverage.CoveredApps)" -ForegroundColor Gray
Write-Host "  Coverage: $($coverage.CoveragePercent)%" -ForegroundColor $(
    if ($coverage.CoveragePercent -ge 80) { 'Green' }
    elseif ($coverage.CoveragePercent -ge 60) { 'Yellow' }
    else { 'Red' }
)
Write-Host ""

# Check critical apps
Write-Host "Checking for critical blocked apps..." -ForegroundColor Yellow
$criticalBlocked = Get-CriticalBlockedApps -EventPath $EventPath

if ($criticalBlocked.Count -gt 0) {
    Write-Host "  WARNING: $($criticalBlocked.Count) critical apps blocked!" -ForegroundColor Red
    $criticalBlocked | Select-Object -First 5 | ForEach-Object {
        Write-Host "    - $($_.Path)" -ForegroundColor DarkRed
    }
} else {
    Write-Host "  No critical apps blocked" -ForegroundColor Green
}
Write-Host ""

# Run advancement checks
Write-Host "Running advancement readiness checks..." -ForegroundColor Yellow
$readiness = Test-PhaseAdvancementReady -CurrentPhase $CurrentPhase `
    -EventTrend $eventTrend -Coverage $coverage `
    -CriticalBlocked $criticalBlocked -Thresholds $Thresholds

Write-Host ""
Write-Host "Advancement Checklist:" -ForegroundColor Cyan
foreach ($check in $readiness.Checks) {
    $status = if ($check.Passed) { '[PASS]' } else { '[FAIL]' }
    $color = if ($check.Passed) { 'Green' } else { 'Red' }

    Write-Host "  $status " -NoNewline -ForegroundColor $color
    Write-Host "$($check.Name): " -NoNewline -ForegroundColor White
    Write-Host "$($check.Value) " -NoNewline -ForegroundColor Gray
    Write-Host "(threshold: $($check.Threshold))" -ForegroundColor DarkGray
}
Write-Host ""

# Recommendation
Write-Host "======================================" -ForegroundColor Cyan
if ($readiness.Ready) {
    Write-Host "RECOMMENDATION: Ready to advance to Phase $($CurrentPhase + 1)" -ForegroundColor Green

    $nextPhaseDef = $PhaseDefinitions[$CurrentPhase + 1]
    Write-Host ""
    Write-Host "Next Phase: $($CurrentPhase + 1) - $($nextPhaseDef.Name)" -ForegroundColor Yellow
    Write-Host "  Risk Level: $($nextPhaseDef.RiskLevel)" -ForegroundColor Gray
    Write-Host "  New Collections: $($nextPhaseDef.Collections -join ', ')" -ForegroundColor Gray
    Write-Host "  Description: $($nextPhaseDef.Description)" -ForegroundColor Gray

    if ($AutoAdvance) {
        Write-Host ""
        Write-Host "Auto-advancing to Phase $($CurrentPhase + 1)..." -ForegroundColor Yellow

        # Generate next phase policy
        $genScript = Join-Path $scriptRoot 'New-AppLockerPolicyFromGuide.ps1'

        $genParams = @{
            Phase = $CurrentPhase + 1
            OutputPath = $OutputPath
        }

        if ($ScanPath) { $genParams.ScanPath = $ScanPath }

        & $genScript @genParams

        Write-Host ""
        Write-Host "Phase $($CurrentPhase + 1) policy generated in: $OutputPath" -ForegroundColor Green
        Write-Host "Deploy in AUDIT mode first and monitor for at least $($Thresholds.MinDaysStable) days." -ForegroundColor Yellow
    }
} else {
    Write-Host "RECOMMENDATION: NOT ready for phase advancement" -ForegroundColor Red
    Write-Host ""
    Write-Host "Issues to resolve:" -ForegroundColor Yellow
    foreach ($failed in $readiness.FailedChecks) {
        Write-Host "  - $($failed.Name): $($failed.Value) (need: $($failed.Threshold))" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Suggestions:" -ForegroundColor Yellow

    if ($eventTrend.Trend -eq 'Worsening') {
        Write-Host "  - Investigate newly blocked apps and add appropriate rules" -ForegroundColor Gray
    }
    if ($criticalBlocked.Count -gt 0) {
        Write-Host "  - Create allow rules for critical blocked applications" -ForegroundColor Gray
    }
    if ($coverage.CoveragePercent -lt $Thresholds.MinCoveragePercent) {
        Write-Host "  - Run additional scans and expand policy coverage" -ForegroundColor Gray
    }
}
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Return analysis results
return [PSCustomObject]@{
    CurrentPhase = $CurrentPhase
    ReadyToAdvance = $readiness.Ready
    EventTrend = $eventTrend
    Coverage = $coverage
    CriticalBlocked = $criticalBlocked
    Checks = $readiness.Checks
    NextPhase = if ($readiness.Ready) { $CurrentPhase + 1 } else { $null }
    Recommendations = if ($readiness.Ready) {
        @("Advance to Phase $($CurrentPhase + 1)", "Deploy in audit mode", "Monitor for $($Thresholds.MinDaysStable) days")
    } else {
        $readiness.FailedChecks | ForEach-Object { "Fix: $($_.Name)" }
    }
}

#endregion
