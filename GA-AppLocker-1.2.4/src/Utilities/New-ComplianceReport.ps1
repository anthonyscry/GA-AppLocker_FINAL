<#
.SYNOPSIS
    Generates a compliance report for AppLocker implementation audit.

.DESCRIPTION
    Creates a comprehensive compliance report documenting the AppLocker implementation
    status, evidence artifacts, and compliance checklist verification. This report
    is designed for cybersecurity inspectors and auditors reviewing the organization's
    application control posture.

    The report includes:
    - Executive summary with compliance score
    - Evidence inventory (scans, events, policies, logs)
    - Compliance checklist verification
    - Risk assessment summary
    - Recommendations for improvement

.PARAMETER OutputPath
    Path to save the compliance report. Defaults to .\Reports folder.

.PARAMETER Format
    Report format: HTML, Markdown, or Text. Default is HTML.

.PARAMETER IncludeEvidence
    Include detailed evidence listings in the report.

.PARAMETER PolicyPath
    Path to the current AppLocker policy XML for analysis.

.EXAMPLE
    .\New-ComplianceReport.ps1
    # Generates HTML report in .\Reports folder

.EXAMPLE
    .\New-ComplianceReport.ps1 -Format Markdown -IncludeEvidence
    # Generates detailed Markdown report with evidence listings

.NOTES
    Author: GA-AppLocker Toolkit
    Version: 1.0

    This report supports compliance verification for:
    - NIST 800-53 (CM-7, CM-11, SI-7)
    - CIS Controls (2.5, 2.6)
    - CMMC (CM.L2-3.4.8)
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\Reports",

    [ValidateSet("HTML", "Markdown", "Text")]
    [string]$Format = "HTML",

    [switch]$IncludeEvidence,

    [string]$PolicyPath
)

#Requires -Version 5.1

$scriptRoot = Split-Path $PSScriptRoot -Parent

# Initialize report data
$reportData = [PSCustomObject]@{
    GeneratedAt = Get-Date
    GeneratedBy = "$env:USERNAME@$env:COMPUTERNAME"
    ToolkitVersion = "GA-AppLocker 2.0"
    ComplianceScore = 0
    MaxScore = 100
    Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    Evidence = [PSCustomObject]@{
        Scans = @()
        Events = @()
        Policies = @()
        Logs = @()
        SoftwareLists = @()
    }
    Checklist = @()
    Recommendations = [System.Collections.Generic.List[string]]::new()
}

Write-Host "=== GA-AppLocker Compliance Report Generator ===" -ForegroundColor Cyan
Write-Host "Analyzing implementation artifacts..." -ForegroundColor Gray

#region Evidence Collection

# Check for Scans folder
$scansPath = Join-Path $scriptRoot "Scans"
if (Test-Path $scansPath) {
    $scanFolders = Get-ChildItem -Path $scansPath -Directory | Sort-Object LastWriteTime -Descending
    foreach ($scan in $scanFolders) {
        $computerFolders = Get-ChildItem -Path $scan.FullName -Directory
        $reportData.Evidence.Scans += [PSCustomObject]@{
            Name = $scan.Name
            Date = $scan.LastWriteTime
            ComputerCount = $computerFolders.Count
            Path = $scan.FullName
            HasResults = (Test-Path (Join-Path $scan.FullName "ScanResults.csv"))
        }
    }
    Write-Host "  Found $($reportData.Evidence.Scans.Count) scan folders" -ForegroundColor Green
}
else {
    Write-Host "  No Scans folder found" -ForegroundColor Yellow
    $reportData.Recommendations.Add("Create baseline scans using [1] Scan from the main menu")
}

# Check for Events folder
$eventsPath = Join-Path $scriptRoot "Events"
if (Test-Path $eventsPath) {
    $eventFolders = Get-ChildItem -Path $eventsPath -Directory | Sort-Object LastWriteTime -Descending
    foreach ($event in $eventFolders) {
        $uniqueAppsPath = Join-Path $event.FullName "UniqueBlockedApps.csv"
        $blockedCount = 0
        if (Test-Path $uniqueAppsPath) {
            $blockedApps = Import-Csv -Path $uniqueAppsPath -ErrorAction SilentlyContinue
            $blockedCount = if ($blockedApps) { $blockedApps.Count } else { 0 }
        }
        $reportData.Evidence.Events += [PSCustomObject]@{
            Name = $event.Name
            Date = $event.LastWriteTime
            Path = $event.FullName
            UniqueBlockedApps = $blockedCount
            HasConsolidatedData = (Test-Path (Join-Path $event.FullName "AllBlockedEvents.csv"))
        }
    }
    Write-Host "  Found $($reportData.Evidence.Events.Count) event collection folders" -ForegroundColor Green
}
else {
    Write-Host "  No Events folder found" -ForegroundColor Yellow
    $reportData.Recommendations.Add("Collect AppLocker audit events using [E] Events from the main menu")
}

# Check for Outputs/Policies folder
$outputsPath = Join-Path $scriptRoot "Outputs"
if (Test-Path $outputsPath) {
    $policyFiles = Get-ChildItem -Path $outputsPath -Filter "*.xml" | Sort-Object LastWriteTime -Descending
    foreach ($policy in $policyFiles) {
        $policyInfo = [PSCustomObject]@{
            Name = $policy.Name
            Date = $policy.LastWriteTime
            Path = $policy.FullName
            Size = $policy.Length
            RuleCount = 0
            EnforcementMode = "Unknown"
        }

        # Parse policy for details
        try {
            [xml]$policyXml = Get-Content -Path $policy.FullName -Raw
            $ruleCount = 0
            $modes = @()
            foreach ($coll in $policyXml.AppLockerPolicy.RuleCollection) {
                $ruleCount += ($coll.FilePublisherRule | Measure-Object).Count
                $ruleCount += ($coll.FilePathRule | Measure-Object).Count
                $ruleCount += ($coll.FileHashRule | Measure-Object).Count
                $modes += "$($coll.Type):$($coll.EnforcementMode)"
            }
            $policyInfo.RuleCount = $ruleCount
            $policyInfo.EnforcementMode = ($modes -join ", ")
        }
        catch {
            $policyInfo.EnforcementMode = "Parse Error"
        }

        $reportData.Evidence.Policies += $policyInfo
    }
    Write-Host "  Found $($reportData.Evidence.Policies.Count) policy files" -ForegroundColor Green
}
else {
    Write-Host "  No Outputs folder found" -ForegroundColor Yellow
    $reportData.Recommendations.Add("Generate AppLocker policies using [2] Generate from the main menu")
}

# Check for Logs folder
$logsPath = Join-Path $scriptRoot "Logs"
if (Test-Path $logsPath) {
    $logFiles = Get-ChildItem -Path $logsPath -Filter "*.log" | Sort-Object LastWriteTime -Descending
    foreach ($log in $logFiles) {
        $reportData.Evidence.Logs += [PSCustomObject]@{
            Name = $log.Name
            Date = $log.LastWriteTime
            Path = $log.FullName
            Size = $log.Length
        }
    }
    Write-Host "  Found $($reportData.Evidence.Logs.Count) log files" -ForegroundColor Green
}

# Check for Software Lists
$softwareListsPath = Join-Path $scriptRoot "SoftwareLists"
if (Test-Path $softwareListsPath) {
    $listFiles = Get-ChildItem -Path $softwareListsPath -Filter "*.json" | Sort-Object LastWriteTime -Descending
    foreach ($list in $listFiles) {
        $reportData.Evidence.SoftwareLists += [PSCustomObject]@{
            Name = $list.Name
            Date = $list.LastWriteTime
            Path = $list.FullName
        }
    }
    Write-Host "  Found $($reportData.Evidence.SoftwareLists.Count) software lists" -ForegroundColor Green
}

#endregion

#region Compliance Checklist Verification

Write-Host "`nVerifying compliance checklist..." -ForegroundColor Gray

$checklistItems = @(
    @{
        ID = "INV-01"
        Category = "Inventory"
        Requirement = "Evidence of software inventory collection exists"
        Weight = 15
        Check = { $reportData.Evidence.Scans.Count -gt 0 }
        Evidence = { "Found $($reportData.Evidence.Scans.Count) scan folder(s)" }
    },
    @{
        ID = "INV-02"
        Category = "Inventory"
        Requirement = "Inventory includes multiple systems (14+ recommended)"
        Weight = 10
        Check = {
            $totalComputers = ($reportData.Evidence.Scans | Measure-Object -Property ComputerCount -Sum).Sum
            $totalComputers -ge 14
        }
        Evidence = {
            $total = ($reportData.Evidence.Scans | Measure-Object -Property ComputerCount -Sum).Sum
            "Total computers scanned: $total"
        }
    },
    @{
        ID = "POL-01"
        Category = "Policy"
        Requirement = "AppLocker policy XML files exist"
        Weight = 15
        Check = { $reportData.Evidence.Policies.Count -gt 0 }
        Evidence = { "Found $($reportData.Evidence.Policies.Count) policy file(s)" }
    },
    @{
        ID = "POL-02"
        Category = "Policy"
        Requirement = "Policy contains rules (not empty)"
        Weight = 10
        Check = {
            ($reportData.Evidence.Policies | Where-Object { $_.RuleCount -gt 0 }).Count -gt 0
        }
        Evidence = {
            $totalRules = ($reportData.Evidence.Policies | Measure-Object -Property RuleCount -Sum).Sum
            "Total rules across policies: $totalRules"
        }
    },
    @{
        ID = "AUD-01"
        Category = "Audit"
        Requirement = "Audit event collection has been performed"
        Weight = 15
        Check = { $reportData.Evidence.Events.Count -gt 0 }
        Evidence = { "Found $($reportData.Evidence.Events.Count) event collection(s)" }
    },
    @{
        ID = "AUD-02"
        Category = "Audit"
        Requirement = "Blocked applications have been reviewed"
        Weight = 10
        Check = {
            ($reportData.Evidence.Events | Where-Object { $_.HasConsolidatedData }).Count -gt 0
        }
        Evidence = {
            $withData = ($reportData.Evidence.Events | Where-Object { $_.HasConsolidatedData }).Count
            "Event collections with consolidated data: $withData"
        }
    },
    @{
        ID = "LOG-01"
        Category = "Logging"
        Requirement = "Operation logs are maintained"
        Weight = 10
        Check = { $reportData.Evidence.Logs.Count -gt 0 }
        Evidence = { "Found $($reportData.Evidence.Logs.Count) log file(s)" }
    },
    @{
        ID = "LOG-02"
        Category = "Logging"
        Requirement = "Recent activity logged (within 30 days)"
        Weight = 5
        Check = {
            $cutoff = (Get-Date).AddDays(-30)
            ($reportData.Evidence.Logs | Where-Object { $_.Date -ge $cutoff }).Count -gt 0
        }
        Evidence = {
            $cutoff = (Get-Date).AddDays(-30)
            $recent = ($reportData.Evidence.Logs | Where-Object { $_.Date -ge $cutoff }).Count
            "Logs from last 30 days: $recent"
        }
    },
    @{
        ID = "SWL-01"
        Category = "Software Lists"
        Requirement = "Curated software allowlists exist"
        Weight = 10
        Check = { $reportData.Evidence.SoftwareLists.Count -gt 0 }
        Evidence = { "Found $($reportData.Evidence.SoftwareLists.Count) software list(s)" }
    }
)

$totalScore = 0
$maxScore = 0

foreach ($item in $checklistItems) {
    $maxScore += $item.Weight
    $passed = & $item.Check
    $evidence = & $item.Evidence

    $checkResult = [PSCustomObject]@{
        ID = $item.ID
        Category = $item.Category
        Requirement = $item.Requirement
        Status = if ($passed) { "PASS" } else { "FAIL" }
        Weight = $item.Weight
        Score = if ($passed) { $item.Weight } else { 0 }
        Evidence = $evidence
    }

    $reportData.Checklist += $checkResult
    $totalScore += $checkResult.Score

    $statusColor = if ($passed) { "Green" } else { "Red" }
    $statusText = if ($passed) { "PASS" } else { "FAIL" }
    Write-Host "  [$statusText] $($item.ID): $($item.Requirement)" -ForegroundColor $statusColor
}

$reportData.ComplianceScore = [math]::Round(($totalScore / $maxScore) * 100)
$reportData.MaxScore = 100

Write-Host "`nCompliance Score: $($reportData.ComplianceScore)%" -ForegroundColor $(
    if ($reportData.ComplianceScore -ge 80) { "Green" }
    elseif ($reportData.ComplianceScore -ge 60) { "Yellow" }
    else { "Red" }
)

#endregion

#region Generate Recommendations

if ($reportData.Evidence.Scans.Count -eq 0) {
    $reportData.Recommendations.Add("CRITICAL: No inventory scans found. Run baseline scans immediately.")
}
elseif (($reportData.Evidence.Scans | Measure-Object -Property ComputerCount -Sum).Sum -lt 14) {
    $reportData.Recommendations.Add("Expand scan coverage to at least 14 representative systems.")
}

if ($reportData.Evidence.Policies.Count -eq 0) {
    $reportData.Recommendations.Add("CRITICAL: No policies generated. Create policies from scan data.")
}
elseif (($reportData.Evidence.Policies | Where-Object { $_.RuleCount -eq 0 }).Count -gt 0) {
    $reportData.Recommendations.Add("Some policies have no rules. Review and regenerate if needed.")
}

if ($reportData.Evidence.Events.Count -eq 0) {
    $reportData.Recommendations.Add("Deploy policies in Audit mode and collect events for 14+ days.")
}

$recentEvents = $reportData.Evidence.Events | Where-Object { $_.Date -ge (Get-Date).AddDays(-14) }
if ($recentEvents.Count -eq 0 -and $reportData.Evidence.Events.Count -gt 0) {
    $reportData.Recommendations.Add("Event collection is stale. Collect recent audit events.")
}

if ($reportData.Evidence.SoftwareLists.Count -eq 0) {
    $reportData.Recommendations.Add("Create curated software allowlists for better rule management.")
}

#endregion

#region Generate Report Output

# Create Reports folder
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportFileName = "ComplianceReport-$timestamp"

switch ($Format) {
    "HTML" {
        $reportPath = Join-Path $OutputPath "$reportFileName.html"

        $scoreColor = if ($reportData.ComplianceScore -ge 80) { "#28a745" }
                      elseif ($reportData.ComplianceScore -ge 60) { "#ffc107" }
                      else { "#dc3545" }

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>GA-AppLocker Compliance Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 15px; }
        h2 { color: #0066cc; margin-top: 30px; }
        h3 { color: #555; }
        .header-info { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .header-info p { margin: 5px 0; }
        .score-box { text-align: center; padding: 30px; background: linear-gradient(135deg, $scoreColor, $(if ($reportData.ComplianceScore -ge 80) { "#20c997" } elseif ($reportData.ComplianceScore -ge 60) { "#fd7e14" } else { "#c82333" })); color: white; border-radius: 10px; margin: 20px 0; }
        .score-box .score { font-size: 72px; font-weight: bold; }
        .score-box .label { font-size: 24px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0066cc; color: white; }
        tr:hover { background: #f5f5f5; }
        .pass { color: #28a745; font-weight: bold; }
        .fail { color: #dc3545; font-weight: bold; }
        .recommendation { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .critical { background: #f8d7da; border-left-color: #dc3545; }
        .evidence-section { background: #e9ecef; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-success { background: #28a745; color: white; }
        .badge-warning { background: #ffc107; color: black; }
        .badge-danger { background: #dc3545; color: white; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>GA-AppLocker Compliance Report</h1>

        <div class="header-info">
            <p><strong>Generated:</strong> $($reportData.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss"))</p>
            <p><strong>Generated By:</strong> $($reportData.GeneratedBy)</p>
            <p><strong>Toolkit Version:</strong> $($reportData.ToolkitVersion)</p>
        </div>

        <h2>Executive Summary</h2>
        <div class="score-box">
            <div class="score">$($reportData.ComplianceScore)%</div>
            <div class="label">Compliance Score</div>
        </div>

        <h2>Compliance Checklist</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Category</th>
                <th>Requirement</th>
                <th>Status</th>
                <th>Evidence</th>
            </tr>
            $($reportData.Checklist | ForEach-Object {
                $statusClass = if ($_.Status -eq "PASS") { "pass" } else { "fail" }
                "<tr><td>$($_.ID)</td><td>$($_.Category)</td><td>$($_.Requirement)</td><td class='$statusClass'>$($_.Status)</td><td>$($_.Evidence)</td></tr>"
            } | Out-String)
        </table>

        <h2>Recommendations</h2>
        $(if ($reportData.Recommendations.Count -eq 0) {
            "<p style='color: #28a745;'>No critical recommendations. Implementation meets baseline requirements.</p>"
        } else {
            $reportData.Recommendations | ForEach-Object {
                $class = if ($_ -match "CRITICAL") { "recommendation critical" } else { "recommendation" }
                "<div class='$class'>$_</div>"
            } | Out-String
        })

        <h2>Evidence Inventory</h2>

        <h3>Scan Data ($($reportData.Evidence.Scans.Count) folders)</h3>
        $(if ($reportData.Evidence.Scans.Count -gt 0) {
            "<table><tr><th>Folder</th><th>Date</th><th>Computers</th></tr>" +
            ($reportData.Evidence.Scans | ForEach-Object {
                "<tr><td>$($_.Name)</td><td>$($_.Date.ToString('yyyy-MM-dd HH:mm'))</td><td>$($_.ComputerCount)</td></tr>"
            } | Out-String) + "</table>"
        } else { "<p>No scan data found.</p>" })

        <h3>Event Collections ($($reportData.Evidence.Events.Count) folders)</h3>
        $(if ($reportData.Evidence.Events.Count -gt 0) {
            "<table><tr><th>Folder</th><th>Date</th><th>Unique Blocked Apps</th></tr>" +
            ($reportData.Evidence.Events | ForEach-Object {
                "<tr><td>$($_.Name)</td><td>$($_.Date.ToString('yyyy-MM-dd HH:mm'))</td><td>$($_.UniqueBlockedApps)</td></tr>"
            } | Out-String) + "</table>"
        } else { "<p>No event collections found.</p>" })

        <h3>Policies ($($reportData.Evidence.Policies.Count) files)</h3>
        $(if ($reportData.Evidence.Policies.Count -gt 0) {
            "<table><tr><th>File</th><th>Date</th><th>Rules</th><th>Enforcement</th></tr>" +
            ($reportData.Evidence.Policies | ForEach-Object {
                "<tr><td>$($_.Name)</td><td>$($_.Date.ToString('yyyy-MM-dd HH:mm'))</td><td>$($_.RuleCount)</td><td>$($_.EnforcementMode)</td></tr>"
            } | Out-String) + "</table>"
        } else { "<p>No policies found.</p>" })

        <h3>Operation Logs ($($reportData.Evidence.Logs.Count) files)</h3>
        $(if ($reportData.Evidence.Logs.Count -gt 0) {
            "<table><tr><th>File</th><th>Date</th><th>Size</th></tr>" +
            ($reportData.Evidence.Logs | Select-Object -First 10 | ForEach-Object {
                "<tr><td>$($_.Name)</td><td>$($_.Date.ToString('yyyy-MM-dd HH:mm'))</td><td>$([math]::Round($_.Size/1KB, 1)) KB</td></tr>"
            } | Out-String) + "</table>"
        } else { "<p>No logs found.</p>" })

        <div class="footer">
            <p>This report was generated by GA-AppLocker Compliance Report Generator.</p>
            <p>For questions about this report, contact your security administrator.</p>
            <p><strong>Control Framework Mappings:</strong> NIST 800-53 (CM-7, CM-11, SI-7) | CIS Controls (2.5, 2.6) | CMMC (CM.L2-3.4.8)</p>
        </div>
    </div>
</body>
</html>
"@
        $html | Out-File -FilePath $reportPath -Encoding UTF8
    }

    "Markdown" {
        $reportPath = Join-Path $OutputPath "$reportFileName.md"

        $md = @"
# GA-AppLocker Compliance Report

**Generated:** $($reportData.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss"))
**Generated By:** $($reportData.GeneratedBy)
**Toolkit Version:** $($reportData.ToolkitVersion)

---

## Executive Summary

### Compliance Score: $($reportData.ComplianceScore)%

$(if ($reportData.ComplianceScore -ge 80) { "Status: **COMPLIANT** - Implementation meets baseline requirements." }
elseif ($reportData.ComplianceScore -ge 60) { "Status: **PARTIAL** - Some improvements needed." }
else { "Status: **NON-COMPLIANT** - Significant gaps identified." })

---

## Compliance Checklist

| ID | Category | Requirement | Status | Evidence |
|----|----------|-------------|--------|----------|
$($reportData.Checklist | ForEach-Object {
    "| $($_.ID) | $($_.Category) | $($_.Requirement) | **$($_.Status)** | $($_.Evidence) |"
} | Out-String)

---

## Recommendations

$(if ($reportData.Recommendations.Count -eq 0) {
    "No critical recommendations. Implementation meets baseline requirements."
} else {
    $reportData.Recommendations | ForEach-Object { "- $_" } | Out-String
})

---

## Evidence Inventory

### Scan Data ($($reportData.Evidence.Scans.Count) folders)

$(if ($reportData.Evidence.Scans.Count -gt 0) {
    "| Folder | Date | Computers |`n|--------|------|-----------|`n" +
    ($reportData.Evidence.Scans | ForEach-Object {
        "| $($_.Name) | $($_.Date.ToString('yyyy-MM-dd')) | $($_.ComputerCount) |"
    } | Out-String)
} else { "No scan data found." })

### Event Collections ($($reportData.Evidence.Events.Count) folders)

$(if ($reportData.Evidence.Events.Count -gt 0) {
    "| Folder | Date | Unique Blocked Apps |`n|--------|------|---------------------|`n" +
    ($reportData.Evidence.Events | ForEach-Object {
        "| $($_.Name) | $($_.Date.ToString('yyyy-MM-dd')) | $($_.UniqueBlockedApps) |"
    } | Out-String)
} else { "No event collections found." })

### Policies ($($reportData.Evidence.Policies.Count) files)

$(if ($reportData.Evidence.Policies.Count -gt 0) {
    "| File | Date | Rules | Enforcement |`n|------|------|-------|-------------|`n" +
    ($reportData.Evidence.Policies | ForEach-Object {
        "| $($_.Name) | $($_.Date.ToString('yyyy-MM-dd')) | $($_.RuleCount) | $($_.EnforcementMode) |"
    } | Out-String)
} else { "No policies found." })

---

## Control Framework Mappings

| Framework | Control ID | Implementation |
|-----------|------------|----------------|
| NIST 800-53 | CM-7 | Least functionality via application allowlisting |
| NIST 800-53 | CM-11 | User-installed software control |
| NIST 800-53 | SI-7 | Software integrity verification |
| CIS Controls | 2.5 | Allowlist authorized software |
| CIS Controls | 2.6 | Allowlist authorized libraries |
| CMMC | CM.L2-3.4.8 | Application execution control |

---

*Report generated by GA-AppLocker Compliance Report Generator*
"@
        $md | Out-File -FilePath $reportPath -Encoding UTF8
    }

    "Text" {
        $reportPath = Join-Path $OutputPath "$reportFileName.txt"

        $txt = @"
================================================================================
                    GA-APPLOCKER COMPLIANCE REPORT
================================================================================

Generated:        $($reportData.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss"))
Generated By:     $($reportData.GeneratedBy)
Toolkit Version:  $($reportData.ToolkitVersion)

================================================================================
                           EXECUTIVE SUMMARY
================================================================================

COMPLIANCE SCORE: $($reportData.ComplianceScore)%

$(if ($reportData.ComplianceScore -ge 80) { "Status: COMPLIANT - Implementation meets baseline requirements." }
elseif ($reportData.ComplianceScore -ge 60) { "Status: PARTIAL - Some improvements needed." }
else { "Status: NON-COMPLIANT - Significant gaps identified." })

================================================================================
                          COMPLIANCE CHECKLIST
================================================================================

$($reportData.Checklist | ForEach-Object {
    "[$($_.Status.PadRight(4))] $($_.ID): $($_.Requirement)`n         Evidence: $($_.Evidence)`n"
} | Out-String)

================================================================================
                           RECOMMENDATIONS
================================================================================

$(if ($reportData.Recommendations.Count -eq 0) {
    "No critical recommendations. Implementation meets baseline requirements."
} else {
    $reportData.Recommendations | ForEach-Object { "* $_" } | Out-String
})

================================================================================
                          EVIDENCE INVENTORY
================================================================================

SCAN DATA: $($reportData.Evidence.Scans.Count) folder(s)
EVENT COLLECTIONS: $($reportData.Evidence.Events.Count) folder(s)
POLICIES: $($reportData.Evidence.Policies.Count) file(s)
OPERATION LOGS: $($reportData.Evidence.Logs.Count) file(s)
SOFTWARE LISTS: $($reportData.Evidence.SoftwareLists.Count) file(s)

================================================================================
Report generated by GA-AppLocker Compliance Report Generator
================================================================================
"@
        $txt | Out-File -FilePath $reportPath -Encoding UTF8
    }
}

#endregion

Write-Host "`nReport generated: $reportPath" -ForegroundColor Green

# Return report path
return $reportPath
