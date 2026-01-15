<#
.SYNOPSIS
    Generates comprehensive CORA audit evidence package.

.DESCRIPTION
    Creates a complete evidence package for Cybersecurity Operational Readiness
    Assessment (CORA) audits. Collects all AppLocker artifacts, generates reports,
    and creates an audit-ready evidence folder with manifest.

    Evidence collected:
    - Software inventory scans with timestamps
    - AppLocker audit events (8003/8004)
    - Generated policies with metadata
    - Compliance reports
    - Health check results
    - Deployment timeline
    - Rule-to-control mapping

.PARAMETER OutputPath
    Path for the evidence package. Defaults to .\CORAEvidence-YYYYMMDD

.PARAMETER IncludeRawData
    Include raw CSV/XML files in evidence package (larger but complete)

.PARAMETER PolicyPath
    Path to current production AppLocker policy for analysis

.PARAMETER DomainName
    Domain name for AD group resolution

.EXAMPLE
    .\New-CORAEvidence.ps1
    # Generates evidence package in .\CORAEvidence-20260110

.EXAMPLE
    .\New-CORAEvidence.ps1 -IncludeRawData -PolicyPath .\production-policy.xml
    # Generates complete evidence package with raw data

.NOTES
    Author: GA-AppLocker Toolkit
    Version: 1.0

    CORA Framework Mappings:
    - NIST 800-53: CM-7 (Least Functionality), CM-11 (User-Installed Software), SI-7 (Software Integrity)
    - CIS Controls: 2.5 (Allowlist Authorized Software), 2.6 (Allowlist Authorized Libraries)
    - CMMC: CM.L2-3.4.8 (Application Execution Policy)
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$IncludeRawData,
    [string]$PolicyPath,
    [string]$DomainName
)

#Requires -Version 5.1

$scriptRoot = Split-Path $PSScriptRoot -Parent
$projectRoot = Split-Path $scriptRoot -Parent

# Set default output path with timestamp
if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $projectRoot "CORAEvidence-$timestamp"
}

# Create output structure
$folders = @(
    $OutputPath,
    (Join-Path $OutputPath "1-Inventory"),
    (Join-Path $OutputPath "2-Events"),
    (Join-Path $OutputPath "3-Policies"),
    (Join-Path $OutputPath "4-Reports"),
    (Join-Path $OutputPath "5-HealthChecks"),
    (Join-Path $OutputPath "6-Timeline")
)

foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  GA-AppLocker CORA Evidence Generator  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output: $OutputPath" -ForegroundColor Gray
Write-Host ""

# Initialize evidence manifest
$manifest = [ordered]@{
    GeneratedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    GeneratedBy = "$env:USERNAME@$env:COMPUTERNAME"
    ToolkitVersion = "GA-AppLocker 1.2.0"
    Evidence = [ordered]@{}
    ComplianceScore = 0
    Findings = @()
    Recommendations = @()
}

$totalSteps = 8
$currentStep = 0

#region Step 1: Collect Inventory Evidence
$currentStep++
Write-Host "[$currentStep/$totalSteps] Collecting software inventory evidence..." -ForegroundColor Yellow

$scansPath = Join-Path $projectRoot "Scans"
$inventoryEvidence = @()

if (Test-Path $scansPath) {
    $scanFolders = Get-ChildItem -Path $scansPath -Directory | Sort-Object LastWriteTime -Descending

    foreach ($scan in $scanFolders) {
        $computerFolders = Get-ChildItem -Path $scan.FullName -Directory -ErrorAction SilentlyContinue
        $softwareFiles = Get-ChildItem -Path $scan.FullName -Recurse -Filter "InstalledSoftware.csv" -ErrorAction SilentlyContinue

        $totalSoftware = 0
        $uniquePublishers = @()

        foreach ($file in $softwareFiles) {
            $content = Import-Csv $file.FullName -ErrorAction SilentlyContinue
            $totalSoftware += ($content | Measure-Object).Count
            $uniquePublishers += $content | Select-Object -ExpandProperty Publisher -Unique -ErrorAction SilentlyContinue
        }

        $inventoryEvidence += [PSCustomObject]@{
            ScanName = $scan.Name
            ScanDate = $scan.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            ComputersScanned = $computerFolders.Count
            TotalSoftwareItems = $totalSoftware
            UniquePublishers = ($uniquePublishers | Select-Object -Unique).Count
            Path = $scan.FullName
        }

        # Copy summary to evidence folder
        if ($IncludeRawData -and $computerFolders.Count -gt 0) {
            $destPath = Join-Path (Join-Path $OutputPath "1-Inventory") $scan.Name
            Copy-Item -Path $scan.FullName -Destination $destPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $manifest.Evidence.Inventory = @{
        TotalScans = $scanFolders.Count
        LatestScan = if ($scanFolders.Count -gt 0) { $scanFolders[0].Name } else { "None" }
        TotalComputersScanned = ($inventoryEvidence | Measure-Object -Property ComputersScanned -Sum).Sum
        Details = $inventoryEvidence
    }

    # Export inventory summary
    $inventoryEvidence | Export-Csv -Path (Join-Path (Join-Path $OutputPath "1-Inventory") "InventorySummary.csv") -NoTypeInformation

    Write-Host "   Found $($scanFolders.Count) scan(s) covering $(($inventoryEvidence | Measure-Object -Property ComputersScanned -Sum).Sum) computers" -ForegroundColor Green
} else {
    Write-Host "   No scans found at $scansPath" -ForegroundColor Red
    $manifest.Findings += "CRITICAL: No software inventory scans found. Run scans before CORA audit."
}
#endregion

#region Step 2: Collect Event Evidence
$currentStep++
Write-Host "[$currentStep/$totalSteps] Collecting AppLocker event evidence..." -ForegroundColor Yellow

$eventsPath = Join-Path $projectRoot "Events"
$eventEvidence = @()

if (Test-Path $eventsPath) {
    $eventFolders = Get-ChildItem -Path $eventsPath -Directory | Sort-Object LastWriteTime -Descending

    foreach ($eventFolder in $eventFolders) {
        $uniqueBlockedFile = Get-ChildItem -Path $eventFolder.FullName -Filter "UniqueBlockedApps.csv" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        $blockedCount = 0
        $affectedComputers = 0

        if ($uniqueBlockedFile) {
            $blockedApps = Import-Csv $uniqueBlockedFile.FullName -ErrorAction SilentlyContinue
            $blockedCount = ($blockedApps | Measure-Object).Count
            $affectedComputers = ($blockedApps | Select-Object -ExpandProperty AffectedComputers -Unique -ErrorAction SilentlyContinue | Measure-Object).Count
        }

        $computerFolders = Get-ChildItem -Path $eventFolder.FullName -Directory -ErrorAction SilentlyContinue

        $eventEvidence += [PSCustomObject]@{
            CollectionName = $eventFolder.Name
            CollectionDate = $eventFolder.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            ComputersCollected = $computerFolders.Count
            UniqueBlockedApps = $blockedCount
            Path = $eventFolder.FullName
        }

        if ($IncludeRawData) {
            $destPath = Join-Path (Join-Path $OutputPath "2-Events") $eventFolder.Name
            Copy-Item -Path $eventFolder.FullName -Destination $destPath -Recurse -Force -ErrorAction SilentlyContinue
        } elseif ($uniqueBlockedFile) {
            # Just copy the summary file
            Copy-Item -Path $uniqueBlockedFile.FullName -Destination (Join-Path (Join-Path $OutputPath "2-Events") "$($eventFolder.Name)-UniqueBlockedApps.csv") -Force -ErrorAction SilentlyContinue
        }
    }

    $manifest.Evidence.Events = @{
        TotalCollections = $eventFolders.Count
        LatestCollection = if ($eventFolders.Count -gt 0) { $eventFolders[0].Name } else { "None" }
        TotalBlockedApps = ($eventEvidence | Measure-Object -Property UniqueBlockedApps -Sum).Sum
        Details = $eventEvidence
    }

    $eventEvidence | Export-Csv -Path (Join-Path (Join-Path $OutputPath "2-Events") "EventSummary.csv") -NoTypeInformation

    Write-Host "   Found $($eventFolders.Count) event collection(s) with $(($eventEvidence | Measure-Object -Property UniqueBlockedApps -Sum).Sum) unique blocked apps" -ForegroundColor Green
} else {
    Write-Host "   No event collections found at $eventsPath" -ForegroundColor Red
    $manifest.Findings += "WARNING: No AppLocker event collections found. Deploy policies in Audit mode first."
}
#endregion

#region Step 3: Collect Policy Evidence
$currentStep++
Write-Host "[$currentStep/$totalSteps] Collecting policy evidence..." -ForegroundColor Yellow

$outputsPath = Join-Path $projectRoot "Outputs"
$policyEvidence = @()

# Check specified policy
if ($PolicyPath -and (Test-Path $PolicyPath)) {
    $policy = Get-Item $PolicyPath
    $policyXml = [xml](Get-Content $PolicyPath)

    $ruleCount = @{
        Exe = ($policyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Exe" }).SelectNodes("*") | Measure-Object | Select-Object -ExpandProperty Count
        Msi = ($policyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Msi" }).SelectNodes("*") | Measure-Object | Select-Object -ExpandProperty Count
        Script = ($policyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Script" }).SelectNodes("*") | Measure-Object | Select-Object -ExpandProperty Count
        Dll = ($policyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Dll" }).SelectNodes("*") | Measure-Object | Select-Object -ExpandProperty Count
    }

    $policyEvidence += [PSCustomObject]@{
        PolicyName = $policy.Name
        PolicyPath = $policy.FullName
        LastModified = $policy.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        ExeRules = $ruleCount.Exe
        MsiRules = $ruleCount.Msi
        ScriptRules = $ruleCount.Script
        DllRules = $ruleCount.Dll
        TotalRules = $ruleCount.Exe + $ruleCount.Msi + $ruleCount.Script + $ruleCount.Dll
        Source = "Specified"
    }

    Copy-Item -Path $PolicyPath -Destination (Join-Path (Join-Path $OutputPath "3-Policies") $policy.Name) -Force
}

# Check Outputs folder
if (Test-Path $outputsPath) {
    $policyFiles = Get-ChildItem -Path $outputsPath -Filter "*.xml" -ErrorAction SilentlyContinue

    foreach ($policyFile in $policyFiles) {
        try {
            $policyXml = [xml](Get-Content $policyFile.FullName)

            $ruleCount = @{
                Exe = 0
                Msi = 0
                Script = 0
                Dll = 0
            }

            foreach ($collection in $policyXml.AppLockerPolicy.RuleCollection) {
                $rules = $collection.SelectNodes("*[not(self::text())]") | Where-Object { $_.Name -ne "#text" }
                $count = ($rules | Measure-Object).Count
                if ($collection.Type -eq "Exe") { $ruleCount.Exe = $count }
                elseif ($collection.Type -eq "Msi") { $ruleCount.Msi = $count }
                elseif ($collection.Type -eq "Script") { $ruleCount.Script = $count }
                elseif ($collection.Type -eq "Dll") { $ruleCount.Dll = $count }
            }

            $policyEvidence += [PSCustomObject]@{
                PolicyName = $policyFile.Name
                PolicyPath = $policyFile.FullName
                LastModified = $policyFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                ExeRules = $ruleCount.Exe
                MsiRules = $ruleCount.Msi
                ScriptRules = $ruleCount.Script
                DllRules = $ruleCount.Dll
                TotalRules = $ruleCount.Exe + $ruleCount.Msi + $ruleCount.Script + $ruleCount.Dll
                Source = "Generated"
            }

            Copy-Item -Path $policyFile.FullName -Destination (Join-Path (Join-Path $OutputPath "3-Policies") $policyFile.Name) -Force
        } catch {
            # Skip invalid XML files
        }
    }
}

$manifest.Evidence.Policies = @{
    TotalPolicies = $policyEvidence.Count
    TotalRules = ($policyEvidence | Measure-Object -Property TotalRules -Sum).Sum
    Details = $policyEvidence
}

$policyEvidence | Export-Csv -Path (Join-Path (Join-Path $OutputPath "3-Policies") "PolicySummary.csv") -NoTypeInformation

Write-Host "   Found $($policyEvidence.Count) policy file(s) with $(($policyEvidence | Measure-Object -Property TotalRules -Sum).Sum) total rules" -ForegroundColor Green
#endregion

#region Step 4: Generate Compliance Report
$currentStep++
Write-Host "[$currentStep/$totalSteps] Generating compliance report..." -ForegroundColor Yellow

$complianceReportScript = Join-Path $PSScriptRoot "New-ComplianceReport.ps1"
if (Test-Path $complianceReportScript) {
    $reportOutput = Join-Path $OutputPath "4-Reports"
    & $complianceReportScript -OutputPath $reportOutput -Format HTML -IncludeEvidence

    Write-Host "   Compliance report generated" -ForegroundColor Green
} else {
    Write-Host "   Compliance report script not found" -ForegroundColor Yellow
}
#endregion

#region Step 5: Run Health Checks
$currentStep++
Write-Host "[$currentStep/$totalSteps] Running policy health checks..." -ForegroundColor Yellow

$healthCheckScript = Join-Path $PSScriptRoot "Test-RuleHealth.ps1"
$healthResults = @()

if ((Test-Path $healthCheckScript) -and $policyEvidence.Count -gt 0) {
    foreach ($policy in $policyEvidence) {
        if (Test-Path $policy.PolicyPath) {
            try {
                $result = & $healthCheckScript -PolicyPath $policy.PolicyPath -ErrorAction SilentlyContinue
                $healthResults += [PSCustomObject]@{
                    PolicyName = $policy.PolicyName
                    HealthScore = if ($result.HealthScore) { $result.HealthScore } else { "N/A" }
                    Issues = if ($result.Issues) { $result.Issues.Count } else { 0 }
                }
            } catch {
                $healthResults += [PSCustomObject]@{
                    PolicyName = $policy.PolicyName
                    HealthScore = "Error"
                    Issues = "Check failed"
                }
            }
        }
    }

    $manifest.Evidence.HealthChecks = @{
        TotalChecked = $healthResults.Count
        Details = $healthResults
    }

    $healthResults | Export-Csv -Path (Join-Path (Join-Path $OutputPath "5-HealthChecks") "HealthCheckSummary.csv") -NoTypeInformation

    Write-Host "   Health checks completed for $($healthResults.Count) policies" -ForegroundColor Green
} else {
    Write-Host "   Health check script not found or no policies to check" -ForegroundColor Yellow
}
#endregion

#region Step 6: Generate Timeline
$currentStep++
Write-Host "[$currentStep/$totalSteps] Generating deployment timeline..." -ForegroundColor Yellow

$timeline = @()

# Add scan events
foreach ($scan in $inventoryEvidence) {
    $timeline += [PSCustomObject]@{
        Date = $scan.ScanDate
        Event = "Software Inventory Scan"
        Description = "$($scan.ScanName) - $($scan.ComputersScanned) computers scanned"
        Category = "Data Collection"
        Artifact = $scan.Path
    }
}

# Add event collections
foreach ($event in $eventEvidence) {
    $timeline += [PSCustomObject]@{
        Date = $event.CollectionDate
        Event = "AppLocker Event Collection"
        Description = "$($event.CollectionName) - $($event.UniqueBlockedApps) blocked apps found"
        Category = "Monitoring"
        Artifact = $event.Path
    }
}

# Add policy generations
foreach ($policy in $policyEvidence) {
    $timeline += [PSCustomObject]@{
        Date = $policy.LastModified
        Event = "Policy Generated/Modified"
        Description = "$($policy.PolicyName) - $($policy.TotalRules) rules"
        Category = "Policy Management"
        Artifact = $policy.PolicyPath
    }
}

# Sort by date
$timeline = $timeline | Sort-Object { [DateTime]::ParseExact($_.Date, "yyyy-MM-dd HH:mm", $null) } -Descending

$manifest.Evidence.Timeline = @{
    TotalEvents = $timeline.Count
    EarliestEvent = if ($timeline.Count -gt 0) { $timeline[-1].Date } else { "N/A" }
    LatestEvent = if ($timeline.Count -gt 0) { $timeline[0].Date } else { "N/A" }
    Details = $timeline
}

$timeline | Export-Csv -Path (Join-Path (Join-Path $OutputPath "6-Timeline") "DeploymentTimeline.csv") -NoTypeInformation

# Generate timeline HTML
$timelineHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>GA-AppLocker Deployment Timeline</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #1a5f7a; }
        .timeline { position: relative; padding: 20px 0; }
        .timeline-item { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #1a5f7a; }
        .timeline-date { color: #666; font-size: 0.9em; }
        .timeline-event { font-weight: bold; color: #1a5f7a; }
        .timeline-desc { margin-top: 5px; }
        .category { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; }
        .category-data { background: #e3f2fd; color: #1565c0; }
        .category-monitoring { background: #fff3e0; color: #ef6c00; }
        .category-policy { background: #e8f5e9; color: #2e7d32; }
    </style>
</head>
<body>
    <h1>AppLocker Deployment Timeline</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by $env:USERNAME</p>
    <div class="timeline">
"@

foreach ($item in $timeline) {
    $categoryClass = switch ($item.Category) {
        "Data Collection" { "category-data" }
        "Monitoring" { "category-monitoring" }
        "Policy Management" { "category-policy" }
        default { "" }
    }

    $timelineHtml += @"
        <div class="timeline-item">
            <div class="timeline-date">$($item.Date)</div>
            <div class="timeline-event">$($item.Event)<span class="category $categoryClass">$($item.Category)</span></div>
            <div class="timeline-desc">$($item.Description)</div>
        </div>
"@
}

$timelineHtml += @"
    </div>
</body>
</html>
"@

$timelineHtml | Out-File -FilePath (Join-Path (Join-Path $OutputPath "6-Timeline") "Timeline.html") -Encoding UTF8

Write-Host "   Timeline generated with $($timeline.Count) events" -ForegroundColor Green
#endregion

#region Step 7: Generate Control Mapping
$currentStep++
Write-Host "[$currentStep/$totalSteps] Generating compliance control mapping..." -ForegroundColor Yellow

$controlMapping = @(
    [PSCustomObject]@{
        ControlID = "NIST CM-7"
        ControlName = "Least Functionality"
        Description = "Configure systems to provide only essential capabilities"
        Evidence = "AppLocker policies restrict executable, script, and installer execution"
        Status = if ($policyEvidence.Count -gt 0) { "Implemented" } else { "Not Implemented" }
        Artifacts = ($policyEvidence | Select-Object -ExpandProperty PolicyName) -join ", "
    },
    [PSCustomObject]@{
        ControlID = "NIST CM-11"
        ControlName = "User-Installed Software"
        Description = "Control and monitor user-installed software"
        Evidence = "Software inventory scans identify installed applications; policies control installation"
        Status = if ($inventoryEvidence.Count -gt 0) { "Implemented" } else { "Not Implemented" }
        Artifacts = ($inventoryEvidence | Select-Object -ExpandProperty ScanName) -join ", "
    },
    [PSCustomObject]@{
        ControlID = "NIST SI-7"
        ControlName = "Software, Firmware, and Information Integrity"
        Description = "Verify integrity of software and firmware components"
        Evidence = "Publisher-based rules verify software signatures; hash rules verify file integrity"
        Status = if ($policyEvidence.Count -gt 0 -and ($policyEvidence | Measure-Object -Property TotalRules -Sum).Sum -gt 0) { "Implemented" } else { "Not Implemented" }
        Artifacts = "Policy rules use Authenticode signatures for verification"
    },
    [PSCustomObject]@{
        ControlID = "CIS 2.5"
        ControlName = "Allowlist Authorized Software"
        Description = "Use allowlisting technology to ensure only authorized software executes"
        Evidence = "AppLocker policies define authorized executables, scripts, and installers"
        Status = if ($policyEvidence.Count -gt 0) { "Implemented" } else { "Not Implemented" }
        Artifacts = ($policyEvidence | Select-Object -ExpandProperty PolicyName) -join ", "
    },
    [PSCustomObject]@{
        ControlID = "CIS 2.6"
        ControlName = "Allowlist Authorized Libraries"
        Description = "Use allowlisting technology to ensure only authorized libraries execute"
        Evidence = "AppLocker DLL rules control library execution (Phase 4 deployment)"
        Status = if (($policyEvidence | Where-Object { $_.DllRules -gt 0 }).Count -gt 0) { "Implemented" } else { "Planned" }
        Artifacts = "DLL rules in policy files"
    },
    [PSCustomObject]@{
        ControlID = "CMMC CM.L2-3.4.8"
        ControlName = "Application Execution Policy"
        Description = "Apply deny-by-exception policy to prevent unauthorized software execution"
        Evidence = "AppLocker policies implement deny-by-default with explicit allow rules"
        Status = if ($policyEvidence.Count -gt 0) { "Implemented" } else { "Not Implemented" }
        Artifacts = ($policyEvidence | Select-Object -ExpandProperty PolicyName) -join ", "
    }
)

$manifest.Evidence.ControlMapping = @{
    TotalControls = $controlMapping.Count
    ImplementedControls = ($controlMapping | Where-Object { $_.Status -eq "Implemented" }).Count
    Details = $controlMapping
}

$controlMapping | Export-Csv -Path (Join-Path (Join-Path $OutputPath "4-Reports") "ControlMapping.csv") -NoTypeInformation

Write-Host "   Control mapping generated for $($controlMapping.Count) controls" -ForegroundColor Green
#endregion

#region Step 8: Calculate Compliance Score and Finalize
$currentStep++
Write-Host "[$currentStep/$totalSteps] Calculating compliance score and finalizing..." -ForegroundColor Yellow

# Calculate compliance score (weighted)
$scoreComponents = @{
    HasInventoryScans = if ($inventoryEvidence.Count -gt 0) { 20 } else { 0 }
    HasRecentScan = if ($inventoryEvidence.Count -gt 0 -and ([DateTime]::ParseExact($inventoryEvidence[0].ScanDate, "yyyy-MM-dd HH:mm", $null) -gt (Get-Date).AddDays(-30))) { 10 } else { 0 }
    HasEventCollection = if ($eventEvidence.Count -gt 0) { 20 } else { 0 }
    HasPolicies = if ($policyEvidence.Count -gt 0) { 20 } else { 0 }
    HasMultipleRuleTypes = if (($policyEvidence | Where-Object { $_.ExeRules -gt 0 -and ($_.ScriptRules -gt 0 -or $_.MsiRules -gt 0) }).Count -gt 0) { 10 } else { 0 }
    ControlsImplemented = [math]::Round(($controlMapping | Where-Object { $_.Status -eq "Implemented" }).Count / $controlMapping.Count * 20)
}

$manifest.ComplianceScore = ($scoreComponents.Values | Measure-Object -Sum).Sum

# Generate recommendations based on gaps
if ($inventoryEvidence.Count -eq 0) {
    $manifest.Recommendations += "Run software inventory scans on target computers using [Scan] workflow"
}
if ($eventEvidence.Count -eq 0) {
    $manifest.Recommendations += "Deploy AppLocker policies in Audit mode and collect events using [Events] workflow"
}
if ($policyEvidence.Count -eq 0) {
    $manifest.Recommendations += "Generate AppLocker policies using [Generate] workflow after completing scans"
}
if (($policyEvidence | Where-Object { $_.DllRules -gt 0 }).Count -eq 0) {
    $manifest.Recommendations += "Consider implementing DLL rules (Phase 4) for comprehensive protection"
}

# Save manifest
$manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $OutputPath "EvidenceManifest.json") -Encoding UTF8

# Generate executive summary
$summaryHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>CORA Evidence Package - Executive Summary</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #1a5f7a; border-bottom: 3px solid #1a5f7a; padding-bottom: 10px; }
        h2 { color: #2d3436; margin-top: 30px; }
        .score-box { background: linear-gradient(135deg, #1a5f7a, #2d3436); color: white; padding: 30px; border-radius: 12px; text-align: center; margin: 20px 0; }
        .score-value { font-size: 48px; font-weight: bold; }
        .score-label { font-size: 18px; opacity: 0.9; }
        .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .evidence-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .evidence-card h3 { margin: 0 0 10px 0; color: #1a5f7a; }
        .evidence-card .value { font-size: 24px; font-weight: bold; color: #2d3436; }
        .controls-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .controls-table th, .controls-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .controls-table th { background: #1a5f7a; color: white; }
        .status-implemented { color: #27ae60; font-weight: bold; }
        .status-planned { color: #f39c12; font-weight: bold; }
        .status-not { color: #e74c3c; font-weight: bold; }
        .recommendation { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 10px 0; border-radius: 4px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>CORA Evidence Package - Executive Summary</h1>
    <p>Generated: $($manifest.GeneratedAt) by $($manifest.GeneratedBy)</p>
    <p>Toolkit: $($manifest.ToolkitVersion)</p>

    <div class="score-box">
        <div class="score-value">$($manifest.ComplianceScore)%</div>
        <div class="score-label">AppLocker Implementation Readiness Score</div>
    </div>

    <h2>Evidence Summary</h2>
    <div class="evidence-grid">
        <div class="evidence-card">
            <h3>Software Scans</h3>
            <div class="value">$($inventoryEvidence.Count)</div>
            <div>$(($inventoryEvidence | Measure-Object -Property ComputersScanned -Sum).Sum) computers</div>
        </div>
        <div class="evidence-card">
            <h3>Event Collections</h3>
            <div class="value">$($eventEvidence.Count)</div>
            <div>$(($eventEvidence | Measure-Object -Property UniqueBlockedApps -Sum).Sum) blocked apps</div>
        </div>
        <div class="evidence-card">
            <h3>Policies</h3>
            <div class="value">$($policyEvidence.Count)</div>
            <div>$(($policyEvidence | Measure-Object -Property TotalRules -Sum).Sum) rules</div>
        </div>
        <div class="evidence-card">
            <h3>Timeline Events</h3>
            <div class="value">$($timeline.Count)</div>
            <div>audit trail entries</div>
        </div>
    </div>

    <h2>Compliance Control Mapping</h2>
    <table class="controls-table">
        <tr><th>Control ID</th><th>Control Name</th><th>Status</th><th>Evidence</th></tr>
"@

foreach ($control in $controlMapping) {
    $statusClass = switch ($control.Status) {
        "Implemented" { "status-implemented" }
        "Planned" { "status-planned" }
        default { "status-not" }
    }
    $summaryHtml += "<tr><td>$($control.ControlID)</td><td>$($control.ControlName)</td><td class='$statusClass'>$($control.Status)</td><td>$($control.Evidence)</td></tr>"
}

$summaryHtml += @"
    </table>
"@

if ($manifest.Recommendations.Count -gt 0) {
    $summaryHtml += "<h2>Recommendations</h2>"
    foreach ($rec in $manifest.Recommendations) {
        $summaryHtml += "<div class='recommendation'>$rec</div>"
    }
}

$summaryHtml += @"

    <h2>Evidence Package Contents</h2>
    <ul>
        <li><strong>1-Inventory/</strong> - Software inventory scan results</li>
        <li><strong>2-Events/</strong> - AppLocker audit event collections</li>
        <li><strong>3-Policies/</strong> - Generated AppLocker policy files</li>
        <li><strong>4-Reports/</strong> - Compliance reports and control mappings</li>
        <li><strong>5-HealthChecks/</strong> - Policy health check results</li>
        <li><strong>6-Timeline/</strong> - Deployment timeline and audit trail</li>
        <li><strong>EvidenceManifest.json</strong> - Machine-readable evidence manifest</li>
    </ul>

    <div class="footer">
        <p>This evidence package was generated by GA-AppLocker Toolkit for CORA audit preparation.</p>
        <p>For questions, contact the IT Security team.</p>
    </div>
</body>
</html>
"@

$summaryHtml | Out-File -FilePath (Join-Path $OutputPath "ExecutiveSummary.html") -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CORA Evidence Package Complete!      " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Compliance Score: $($manifest.ComplianceScore)%" -ForegroundColor $(if ($manifest.ComplianceScore -ge 80) { "Green" } elseif ($manifest.ComplianceScore -ge 50) { "Yellow" } else { "Red" })
Write-Host ""
Write-Host "Evidence Package Location:" -ForegroundColor White
Write-Host "  $OutputPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Key Files:" -ForegroundColor White
Write-Host "  - ExecutiveSummary.html (show to auditor)" -ForegroundColor Gray
Write-Host "  - EvidenceManifest.json (machine-readable)" -ForegroundColor Gray
Write-Host "  - 4-Reports/ControlMapping.csv (NIST/CIS/CMMC)" -ForegroundColor Gray
Write-Host "  - 6-Timeline/Timeline.html (deployment history)" -ForegroundColor Gray
Write-Host ""

if ($manifest.Recommendations.Count -gt 0) {
    Write-Host "Recommendations to improve score:" -ForegroundColor Yellow
    foreach ($rec in $manifest.Recommendations) {
        Write-Host "  - $rec" -ForegroundColor Yellow
    }
}

# Return manifest for pipeline usage
return $manifest
#endregion
