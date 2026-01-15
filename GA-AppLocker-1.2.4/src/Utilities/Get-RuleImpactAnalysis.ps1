<#
.SYNOPSIS
    Analyzes the impact of AppLocker policy changes before deployment.

.DESCRIPTION
    Performs comprehensive impact analysis by comparing a proposed policy against:
    - Scan data (what's installed on machines)
    - Event data (what's been blocked/allowed)
    - Current policy (if any)

    Provides detailed reports on:
    - Applications that would be blocked
    - Applications that would be allowed
    - Changes from current policy
    - Risk assessment and recommendations

.PARAMETER PolicyPath
    Path to the proposed AppLocker policy XML.

.PARAMETER ScanPath
    Path to scan data directory for installed application analysis.

.PARAMETER EventPath
    Path to event collection data for historical analysis.

.PARAMETER CurrentPolicyPath
    Path to the current policy for comparison (optional).

.PARAMETER ComputerName
    Specific computer(s) to analyze (optional - analyzes all if not specified).

.PARAMETER OutputPath
    Directory for impact analysis reports.

.PARAMETER Detailed
    Generate detailed per-application impact report.

.EXAMPLE
    .\Get-RuleImpactAnalysis.ps1 -PolicyPath .\new-policy.xml -ScanPath .\Scans

.EXAMPLE
    .\Get-RuleImpactAnalysis.ps1 -PolicyPath .\policy.xml -ScanPath .\Scans -EventPath .\Events -Detailed

.NOTES
    This analysis helps prevent accidental lockouts during AppLocker deployment.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$PolicyPath,

    [string]$ScanPath,

    [string]$EventPath,

    [string]$CurrentPolicyPath,

    [string[]]$ComputerName,

    [string]$OutputPath = '.\ImpactAnalysis',

    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

# Get module root
$scriptRoot = Split-Path $PSScriptRoot -Parent

# Import common functions and error handling
Import-Module (Join-Path $PSScriptRoot 'Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ErrorHandling.psm1') -Force

#region Helper Functions

function Get-PolicyRules {
    param([xml]$PolicyXml)

    $rules = @()

    foreach ($collection in $PolicyXml.AppLockerPolicy.RuleCollection) {
        $collectionType = $collection.Type
        $enforcementMode = $collection.EnforcementMode

        foreach ($rule in $collection.ChildNodes) {
            if ($rule.NodeType -ne 'Element') { continue }

            $ruleInfo = @{
                Id = $rule.Id
                Name = $rule.Name
                Description = $rule.Description
                UserOrGroupSid = $rule.UserOrGroupSid
                Action = $rule.Action
                Collection = $collectionType
                EnforcementMode = $enforcementMode
                Type = $rule.LocalName
                Conditions = @()
            }

            # Parse conditions
            if ($rule.Conditions) {
                foreach ($condition in $rule.Conditions.ChildNodes) {
                    if ($condition.NodeType -ne 'Element') { continue }

                    switch ($condition.LocalName) {
                        'FilePublisherCondition' {
                            $ruleInfo.Conditions += @{
                                Type = 'Publisher'
                                Publisher = $condition.PublisherName
                                Product = $condition.ProductName
                                BinaryName = $condition.BinaryName
                                LowVersion = $condition.BinaryVersionRange.LowSection
                                HighVersion = $condition.BinaryVersionRange.HighSection
                            }
                        }
                        'FilePathCondition' {
                            $ruleInfo.Conditions += @{
                                Type = 'Path'
                                Path = $condition.Path
                            }
                        }
                        'FileHashCondition' {
                            foreach ($hash in $condition.FileHash) {
                                $ruleInfo.Conditions += @{
                                    Type = 'Hash'
                                    Algorithm = $hash.Type
                                    Hash = $hash.Data
                                    FileName = $hash.SourceFileName
                                    FileLength = $hash.SourceFileLength
                                }
                            }
                        }
                    }
                }
            }

            $rules += [PSCustomObject]$ruleInfo
        }
    }

    return $rules
}

function Test-ApplicationAgainstRules {
    param(
        [object]$Application,
        [array]$Rules,
        [string]$Collection = 'Exe'
    )

    $matchedRules = @()
    $collectionRules = $Rules | Where-Object { $_.Collection -eq $Collection }

    foreach ($rule in $collectionRules) {
        $matches = $false

        foreach ($condition in $rule.Conditions) {
            switch ($condition.Type) {
                'Publisher' {
                    if ($Application.Publisher -and $condition.Publisher -ne '*') {
                        # Check publisher match
                        if ($Application.Publisher -like "*$($condition.Publisher)*") {
                            # Check product match if specified
                            if ($condition.Product -eq '*' -or $Application.ProductName -like "*$($condition.Product)*") {
                                $matches = $true
                            }
                        }
                    } elseif ($condition.Publisher -eq '*') {
                        $matches = $true
                    }
                }
                'Path' {
                    $pathPattern = $condition.Path -replace '\*', '.*' -replace '\?', '.'
                    if ($Application.Path -match $pathPattern) {
                        $matches = $true
                    }
                }
                'Hash' {
                    if ($Application.Hash -eq $condition.Hash) {
                        $matches = $true
                    }
                }
            }
        }

        if ($matches) {
            $matchedRules += $rule
        }
    }

    # Determine final action (Deny takes precedence over Allow)
    $finalAction = 'NoMatch'
    $effectiveRule = $null

    foreach ($rule in $matchedRules) {
        if ($rule.Action -eq 'Deny') {
            $finalAction = 'Deny'
            $effectiveRule = $rule
            break
        } elseif ($rule.Action -eq 'Allow' -and $finalAction -ne 'Deny') {
            $finalAction = 'Allow'
            $effectiveRule = $rule
        }
    }

    # If no match and enforcement is enabled, default deny
    if ($finalAction -eq 'NoMatch') {
        $enforcedCollections = $Rules | Where-Object {
            $_.Collection -eq $Collection -and $_.EnforcementMode -eq 'Enabled'
        }
        if ($enforcedCollections) {
            $finalAction = 'ImplicitDeny'
        }
    }

    return @{
        FinalAction = $finalAction
        MatchedRules = $matchedRules
        EffectiveRule = $effectiveRule
    }
}

function Get-RiskLevel {
    param(
        [int]$BlockedCount,
        [int]$TotalCount,
        [array]$CriticalApps
    )

    $percentage = if ($TotalCount -gt 0) { ($BlockedCount / $TotalCount) * 100 } else { 0 }

    if ($CriticalApps.Count -gt 0 -or $percentage -gt 20) {
        return @{ Level = 'Critical'; Color = 'Red'; Message = 'High risk of user impact' }
    } elseif ($percentage -gt 10) {
        return @{ Level = 'High'; Color = 'DarkYellow'; Message = 'Significant applications may be blocked' }
    } elseif ($percentage -gt 5) {
        return @{ Level = 'Medium'; Color = 'Yellow'; Message = 'Some applications may be affected' }
    } elseif ($percentage -gt 0) {
        return @{ Level = 'Low'; Color = 'Green'; Message = 'Minor impact expected' }
    } else {
        return @{ Level = 'None'; Color = 'Cyan'; Message = 'No impact detected' }
    }
}

function Get-CriticalApplications {
    # List of applications that if blocked could cause significant issues
    @(
        '*Microsoft*Office*',
        '*Microsoft*Teams*',
        '*Microsoft*Outlook*',
        '*Microsoft*Edge*',
        '*Google*Chrome*',
        '*Firefox*',
        '*Zoom*',
        '*Webex*',
        '*Slack*',
        '*OneDrive*',
        '*Adobe*Acrobat*',
        '*Visual Studio*',
        '*PowerShell*',
        '*Windows Terminal*',
        '*Remote Desktop*',
        '*VPN*',
        '*Antivirus*',
        '*Security*'
    )
}

#endregion

#region Main Analysis

Write-SectionHeader -Title "AppLocker Rule Impact Analysis"

# Validate and load policy using standardized validation
Write-Host "Loading policy..." -ForegroundColor Yellow
$policyXml = Test-ValidAppLockerPolicy -Path $PolicyPath
if (-not $policyXml) {
    Write-ErrorMessage -Message "Failed to load policy: $PolicyPath" -Throw
}

$rules = Get-PolicyRules -PolicyXml $policyXml
Write-Host "  Loaded $($rules.Count) rules from policy" -ForegroundColor Gray

# Summary by collection
$rulesByCollection = $rules | Group-Object Collection
foreach ($group in $rulesByCollection) {
    $allowCount = ($group.Group | Where-Object { $_.Action -eq 'Allow' }).Count
    $denyCount = ($group.Group | Where-Object { $_.Action -eq 'Deny' }).Count
    Write-Host "    $($group.Name): $allowCount allow, $denyCount deny" -ForegroundColor Gray
}

# Create output directory using standardized validation
$validOutputPath = Test-ValidPath -Path $OutputPath -Type Directory -CreateIfMissing
if (-not $validOutputPath) {
    Write-ErrorMessage -Message "Failed to create output directory: $OutputPath" -Throw
}

$analysisResults = @{
    PolicyPath = $PolicyPath
    AnalysisDate = Get-Date -Format 'o'
    RuleCount = $rules.Count
    Applications = @{
        Total = 0
        Allowed = @()
        Blocked = @()
        ImplicitDeny = @()
    }
    ByComputer = @{}
    CriticalImpact = @()
    Recommendations = @()
}

# Analyze against scan data
if ($ScanPath -and (Test-Path $ScanPath)) {
    Write-Host "`nAnalyzing scan data..." -ForegroundColor Yellow

    # Find all scan data
    $scanFolders = if ($ComputerName) {
        $ComputerName | ForEach-Object {
            Get-ChildItem $ScanPath -Directory -Recurse | Where-Object { $_.Name -eq $_ }
        }
    } else {
        Get-ChildItem $ScanPath -Directory -Recurse | Where-Object {
            Test-Path (Join-Path $_.FullName 'InstalledSoftware.csv')
        }
    }

    $criticalPatterns = Get-CriticalApplications
    $allApplications = @()

    foreach ($folder in $scanFolders) {
        $computerName = $folder.Name
        $softwarePath = Join-Path $folder.FullName 'InstalledSoftware.csv'

        if (-not (Test-Path $softwarePath)) { continue }

        Write-Host "  Processing: $computerName" -ForegroundColor Gray

        $software = Import-Csv $softwarePath
        $computerResults = @{
            ComputerName = $computerName
            Total = $software.Count
            Allowed = 0
            Blocked = 0
            ImplicitDeny = 0
            Details = @()
        }

        foreach ($app in $software) {
            $appInfo = @{
                Path = $app.Path
                Publisher = $app.Publisher
                ProductName = $app.ProductName
                Hash = $app.Hash
                ComputerName = $computerName
            }

            $result = Test-ApplicationAgainstRules -Application $appInfo -Rules $rules

            $appResult = [PSCustomObject]@{
                Path = $app.Path
                Publisher = $app.Publisher
                ProductName = $app.ProductName
                ComputerName = $computerName
                Action = $result.FinalAction
                MatchedRule = if ($result.EffectiveRule) { $result.EffectiveRule.Name } else { 'None' }
            }

            $allApplications += $appResult

            switch ($result.FinalAction) {
                'Allow' {
                    $computerResults.Allowed++
                    $analysisResults.Applications.Allowed += $appResult
                }
                'Deny' {
                    $computerResults.Blocked++
                    $analysisResults.Applications.Blocked += $appResult

                    # Check if critical
                    foreach ($pattern in $criticalPatterns) {
                        if ($app.Path -like $pattern -or $app.Publisher -like $pattern) {
                            $analysisResults.CriticalImpact += $appResult
                            break
                        }
                    }
                }
                'ImplicitDeny' {
                    $computerResults.ImplicitDeny++
                    $analysisResults.Applications.ImplicitDeny += $appResult
                }
            }

            if ($Detailed) {
                $computerResults.Details += $appResult
            }
        }

        $analysisResults.ByComputer[$computerName] = $computerResults
        $analysisResults.Applications.Total += $computerResults.Total
    }

    Write-Host "  Analyzed $($analysisResults.Applications.Total) applications across $($scanFolders.Count) computers" -ForegroundColor Gray
}

# Analyze against event data
if ($EventPath -and (Test-Path $EventPath)) {
    Write-Host "`nAnalyzing event history..." -ForegroundColor Yellow

    $eventFiles = Get-ChildItem $EventPath -Filter '*.csv' -Recurse

    $historicalBlocked = @()

    foreach ($file in $eventFiles) {
        if ($file.Name -match 'Blocked') {
            $events = Import-Csv $file.FullName -ErrorAction SilentlyContinue
            foreach ($event in $events) {
                $appInfo = @{
                    Path = $event.Path
                    Publisher = $event.Publisher
                }

                $result = Test-ApplicationAgainstRules -Application $appInfo -Rules $rules

                if ($result.FinalAction -in @('Allow')) {
                    # Previously blocked, now would be allowed
                    $historicalBlocked += [PSCustomObject]@{
                        Path = $event.Path
                        Publisher = $event.Publisher
                        PreviouslyBlocked = $true
                        NewAction = 'Allow'
                        Recommendation = 'This previously blocked application will now be allowed'
                    }
                }
            }
        }
    }

    if ($historicalBlocked.Count -gt 0) {
        Write-Host "  Found $($historicalBlocked.Count) previously blocked apps that would now be allowed" -ForegroundColor Green
        $analysisResults.HistoricalChanges = $historicalBlocked
    }
}

# Compare with current policy
if ($CurrentPolicyPath -and (Test-Path $CurrentPolicyPath)) {
    Write-Host "`nComparing with current policy..." -ForegroundColor Yellow

    $diff = Compare-AppLockerPolicies -ReferencePath $CurrentPolicyPath -DifferencePath $PolicyPath

    $analysisResults.PolicyChanges = @{
        RulesAdded = $diff.RulesOnlyInDiff.Count
        RulesRemoved = $diff.RulesOnlyInRef.Count
        ModeChanges = $diff.ModeDifferences.Count
        AreIdentical = $diff.AreIdentical
    }

    if (-not $diff.AreIdentical) {
        Write-Host "  Rules added: $($diff.RulesOnlyInDiff.Count)" -ForegroundColor Gray
        Write-Host "  Rules removed: $($diff.RulesOnlyInRef.Count)" -ForegroundColor Gray
    }
}

#endregion

#region Generate Report

Write-SectionHeader -Title "Impact Analysis Results"

# Calculate risk level
$riskLevel = Get-RiskLevel `
    -BlockedCount ($analysisResults.Applications.Blocked.Count + $analysisResults.Applications.ImplicitDeny.Count) `
    -TotalCount $analysisResults.Applications.Total `
    -CriticalApps $analysisResults.CriticalImpact

Write-Host "Overall Risk Level: " -NoNewline
Write-Host $riskLevel.Level -ForegroundColor $riskLevel.Color
Write-Host "  $($riskLevel.Message)" -ForegroundColor Gray
Write-Host ""

# Summary statistics
Write-Host "Application Impact Summary:" -ForegroundColor Yellow
Write-Host "  Total Applications Analyzed:  $($analysisResults.Applications.Total)" -ForegroundColor Gray
Write-Host "  Would be ALLOWED:             $($analysisResults.Applications.Allowed.Count)" -ForegroundColor Green
Write-Host "  Would be BLOCKED (explicit):  $($analysisResults.Applications.Blocked.Count)" -ForegroundColor Red
Write-Host "  Would be BLOCKED (implicit):  $($analysisResults.Applications.ImplicitDeny.Count)" -ForegroundColor DarkYellow
Write-Host ""

# Critical applications
if ($analysisResults.CriticalImpact.Count -gt 0) {
    Write-Host "CRITICAL APPLICATIONS AFFECTED:" -ForegroundColor Red
    $analysisResults.CriticalImpact | Select-Object -First 10 | ForEach-Object {
        Write-Host "  ! $($_.Path)" -ForegroundColor Red
        Write-Host "    Publisher: $($_.Publisher)" -ForegroundColor DarkRed
    }
    if ($analysisResults.CriticalImpact.Count -gt 10) {
        Write-Host "  ... and $($analysisResults.CriticalImpact.Count - 10) more" -ForegroundColor DarkRed
    }
    Write-Host ""
}

# Top blocked applications
if ($analysisResults.Applications.Blocked.Count -gt 0) {
    Write-Host "Top Blocked Applications:" -ForegroundColor Yellow
    $analysisResults.Applications.Blocked | Group-Object Path |
        Sort-Object Count -Descending |
        Select-Object -First 10 | ForEach-Object {
            Write-Host "  - $($_.Name) (on $($_.Count) computer(s))" -ForegroundColor Gray
        }
    Write-Host ""
}

# Generate recommendations
$recommendations = @()

if ($analysisResults.CriticalImpact.Count -gt 0) {
    $recommendations += "CRITICAL: Review and create allow rules for $($analysisResults.CriticalImpact.Count) critical applications before deployment"
}

if ($analysisResults.Applications.ImplicitDeny.Count -gt 50) {
    $recommendations += "WARNING: High number of applications ($($analysisResults.Applications.ImplicitDeny.Count)) would be implicitly blocked. Consider adding more allow rules."
}

if ($riskLevel.Level -in @('Critical', 'High')) {
    $recommendations += "Deploy policy in Audit mode first and monitor for at least 2 weeks"
    $recommendations += "Collect AppLocker events (8003/8004) to identify additional applications needing rules"
}

$recommendations += "Test policy on a pilot group before organization-wide deployment"

Write-Host "Recommendations:" -ForegroundColor Yellow
foreach ($rec in $recommendations) {
    Write-Host "  * $rec" -ForegroundColor Gray
}
Write-Host ""

$analysisResults.Recommendations = $recommendations
$analysisResults.RiskLevel = $riskLevel

#endregion

#region Export Reports

# Export JSON report
$jsonPath = Join-Path $validOutputPath 'impact-analysis.json'
Invoke-SafeOperation -ScriptBlock {
    $analysisResults | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
} -ErrorMessage "Failed to save JSON report" -ContinueOnError
Write-SuccessMessage -Message "JSON report: $jsonPath"

# Export CSV of blocked applications
if ($analysisResults.Applications.Blocked.Count -gt 0) {
    $blockedCsvPath = Join-Path $validOutputPath 'blocked-applications.csv'
    Invoke-SafeOperation -ScriptBlock {
        $analysisResults.Applications.Blocked | Export-Csv $blockedCsvPath -NoTypeInformation
    } -ErrorMessage "Failed to save blocked apps CSV" -ContinueOnError
    Write-SuccessMessage -Message "Blocked apps: $blockedCsvPath"
}

# Export HTML report
$htmlPath = Join-Path $validOutputPath 'impact-report.html'
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>AppLocker Impact Analysis Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .risk-critical { background: #dc3545; color: white; padding: 10px 20px; border-radius: 4px; display: inline-block; }
        .risk-high { background: #fd7e14; color: white; padding: 10px 20px; border-radius: 4px; display: inline-block; }
        .risk-medium { background: #ffc107; color: black; padding: 10px 20px; border-radius: 4px; display: inline-block; }
        .risk-low { background: #28a745; color: white; padding: 10px 20px; border-radius: 4px; display: inline-block; }
        .risk-none { background: #17a2b8; color: white; padding: 10px 20px; border-radius: 4px; display: inline-block; }
        .stat-box { display: inline-block; padding: 20px; margin: 10px; background: #f8f9fa; border-radius: 8px; text-align: center; min-width: 150px; }
        .stat-number { font-size: 36px; font-weight: bold; color: #333; }
        .stat-label { color: #666; margin-top: 5px; }
        .allowed { color: #28a745; }
        .blocked { color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .recommendation { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px 15px; margin: 10px 0; }
        .critical-app { background: #f8d7da; border-left: 4px solid #dc3545; padding: 10px 15px; margin: 5px 0; }
        .meta { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AppLocker Policy Impact Analysis</h1>
        <p class="meta">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>Policy: $(Split-Path $PolicyPath -Leaf)</p>

        <h2>Risk Assessment</h2>
        <span class="risk-$($riskLevel.Level.ToLower())">$($riskLevel.Level) Risk</span>
        <p>$($riskLevel.Message)</p>

        <h2>Impact Summary</h2>
        <div>
            <div class="stat-box">
                <div class="stat-number">$($analysisResults.Applications.Total)</div>
                <div class="stat-label">Total Apps Analyzed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number allowed">$($analysisResults.Applications.Allowed.Count)</div>
                <div class="stat-label">Would be Allowed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number blocked">$($analysisResults.Applications.Blocked.Count)</div>
                <div class="stat-label">Would be Blocked</div>
            </div>
            <div class="stat-box">
                <div class="stat-number blocked">$($analysisResults.Applications.ImplicitDeny.Count)</div>
                <div class="stat-label">Implicit Deny</div>
            </div>
        </div>

        $(if ($analysisResults.CriticalImpact.Count -gt 0) {
            "<h2>Critical Applications Affected</h2>"
            foreach ($app in ($analysisResults.CriticalImpact | Select-Object -First 20)) {
                "<div class='critical-app'><strong>$($app.Path)</strong><br>Publisher: $($app.Publisher)<br>Computer: $($app.ComputerName)</div>"
            }
        })

        <h2>Recommendations</h2>
        $(foreach ($rec in $recommendations) {
            "<div class='recommendation'>$rec</div>"
        })

        $(if ($analysisResults.Applications.Blocked.Count -gt 0) {
            "<h2>Blocked Applications (Top 50)</h2><table><tr><th>Application</th><th>Publisher</th><th>Computer</th><th>Matched Rule</th></tr>"
            foreach ($app in ($analysisResults.Applications.Blocked | Select-Object -First 50)) {
                "<tr><td>$(Split-Path $app.Path -Leaf)</td><td>$($app.Publisher)</td><td>$($app.ComputerName)</td><td>$($app.MatchedRule)</td></tr>"
            }
            "</table>"
        })

        <h2>Per-Computer Summary</h2>
        <table>
            <tr><th>Computer</th><th>Total Apps</th><th>Allowed</th><th>Blocked</th><th>Implicit Deny</th></tr>
            $(foreach ($computer in $analysisResults.ByComputer.GetEnumerator()) {
                "<tr><td>$($computer.Key)</td><td>$($computer.Value.Total)</td><td class='allowed'>$($computer.Value.Allowed)</td><td class='blocked'>$($computer.Value.Blocked)</td><td class='blocked'>$($computer.Value.ImplicitDeny)</td></tr>"
            })
        </table>

        <p class="meta" style="margin-top: 40px;">Generated by GA-AppLocker Impact Analysis Tool</p>
    </div>
</body>
</html>
"@

Invoke-SafeOperation -ScriptBlock {
    $htmlContent | Out-File $htmlPath -Encoding UTF8
} -ErrorMessage "Failed to save HTML report" -ContinueOnError
Write-SuccessMessage -Message "HTML report: $htmlPath"

#endregion

Write-SectionHeader -Title "Analysis Complete"

return $analysisResults
