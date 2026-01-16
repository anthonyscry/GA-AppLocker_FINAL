<#
.SYNOPSIS
    Formatting utilities for GA-AppLocker GUI

.DESCRIPTION
    Provides report formatting functions (text and HTML), date/time
    formatting, and other presentation helpers.

.NOTES
    Version:        2.0
    Author:         General Atomics - ASI
    Creation Date:  2026-01-16
    Module:         Utilities\Formatting
#>

function Format-ReportAsText {
    <#
    .SYNOPSIS
        Format report data as plain text

    .DESCRIPTION
        Converts structured report data into a formatted plain text report

    .PARAMETER ReportData
        Hashtable containing report data with required properties

    .OUTPUTS
        Formatted text string

    .EXAMPLE
        $reportData = @{
            ReportTitle = "AppLocker Security Report"
            ReportType = "Executive"
            GeneratedAt = Get-Date
            # ... other properties
        }
        $text = Format-ReportAsText -ReportData $reportData
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData
    )

    $text = "=" * 80 + "`n"
    $text += "$($ReportData.ReportTitle)`n"
    $text += "=" * 80 + "`n`n"

    $text += "Generated: $($ReportData.GeneratedAt)`n"
    $text += "By: $($ReportData.GeneratedBy)`n"
    $text += "Computer: $($ReportData.ComputerName)`n"
    $text += "Report Period: $($ReportData.StartDate) to $($ReportData.EndDate)`n"

    if ($ReportData.TargetSystem) {
        $text += "Target System: $($ReportData.TargetSystem)`n"
    }

    $text += "`n"

    switch ($ReportData.ReportType) {
        "Executive" {
            $text += "-" * 80 + "`n"
            $text += "EXECUTIVE SUMMARY`n"
            $text += "-" * 80 + "`n`n"

            $text += "Overall Compliance: $($ReportData.OverallCompliance)%`n"
            $text += "Risk Score: $($ReportData.RiskScore) ($($ReportData.RiskLevel))`n"
            $text += "Total Events: $($ReportData.TotalEvents)`n`n"

            $text += "Event Breakdown:`n"
            $text += "  Allowed: $($ReportData.AllowedEvents)`n"
            $text += "  Blocked: $($ReportData.BlockedEvents)`n"
            $text += "  Audited: $($ReportData.AuditedEvents)`n`n"

            if ($ReportData.PolicyCoverage) {
                $text += "Policy Coverage:`n"
                $text += "  EXE: $($ReportData.PolicyCoverage.ExeCoverage)`n"
                $text += "  MSI: $($ReportData.PolicyCoverage.MsiCoverage)`n"
                $text += "  Script: $($ReportData.PolicyCoverage.ScriptCoverage)`n"
                $text += "  DLL: $($ReportData.PolicyCoverage.DllCoverage)`n`n"
            }

            if ($ReportData.TopViolatingApps) {
                $text += "Top Violating Applications:`n"
                foreach ($app in $ReportData.TopViolatingApps) {
                    $text += "  - $($app.Application): $($app.ViolationCount) violations ($($app.Percentage)%)`n"
                }
                $text += "`n"
            }

            if ($ReportData.TrendData) {
                $text += "Compliance Trends:`n"
                foreach ($trend in $ReportData.TrendData) {
                    $text += "  - $($trend.Period): $($trend.Compliance)% compliance ($($trend.EventCount) events)`n"
                }
                $text += "`n"
            }
        }

        "Technical" {
            $text += "-" * 80 + "`n"
            $text += "DETAILED TECHNICAL REPORT`n"
            $text += "-" * 80 + "`n`n"

            $text += "Total Events: $($ReportData.TotalEvents)`n`n"

            if ($ReportData.EventsByType) {
                $text += "Events by Type:`n"
                foreach ($type in $ReportData.EventsByType) {
                    $text += "  - $($type.Type): $($type.Count) ($($type.Percentage)%)`n"
                }
                $text += "`n"
            }

            if ($ReportData.TopFilePaths) {
                $text += "Top File Paths:`n"
                foreach ($path in $ReportData.TopFilePaths) {
                    $text += "  - $($path.FilePath): $($path.Count) events`n"
                }
                $text += "`n"
            }

            if ($ReportData.TopPublishers) {
                $text += "Top Publishers:`n"
                foreach ($pub in $ReportData.TopPublishers) {
                    $text += "  - $($pub.Publisher): $($pub.Count) events`n"
                }
                $text += "`n"
            }

            if ($ReportData.PolicyRules) {
                $text += "Policy Rules: $($ReportData.PolicyRules.Count)`n"
            }
        }

        "Audit" {
            $text += "-" * 80 + "`n"
            $text += "AUDIT TRAIL REPORT`n"
            $text += "-" * 80 + "`n`n"

            $text += "Total Audit Events: $($ReportData.TotalAuditEvents)`n`n"

            if ($ReportData.EventsByDate) {
                $text += "Events by Date:`n"
                foreach ($date in $ReportData.EventsByDate) {
                    $text += "  - $($date.Date): $($date.EventCount) events`n"
                }
                $text += "`n"
            }

            if ($ReportData.EventsByUser) {
                $text += "Top Users by Action Count:`n"
                foreach ($user in $ReportData.EventsByUser) {
                    $text += "  - $($user.User): $($user.ActionCount) actions`n"
                }
                $text += "`n"
            }
        }

        "Comparison" {
            $text += "-" * 80 + "`n"
            $text += "POLICY COMPARISON REPORT`n"
            $text += "-" * 80 + "`n`n"

            if ($ReportData.Period1) {
                $text += "Period 1: $($ReportData.Period1.StartDate) to $($ReportData.Period1.EndDate)`n"
                $text += "  Total Events: $($ReportData.Period1.Stats.TotalEvents)`n"
                $text += "  Blocked: $($ReportData.Period1.Stats.BlockedEvents)`n"
                $text += "  Allowed: $($ReportData.Period1.Stats.AllowedEvents)`n`n"
            }

            if ($ReportData.Period2) {
                $text += "Period 2: $($ReportData.Period2.StartDate) to $($ReportData.Period2.EndDate)`n"
                $text += "  Total Events: $($ReportData.Period2.Stats.TotalEvents)`n"
                $text += "  Blocked: $($ReportData.Period2.Stats.BlockedEvents)`n"
                $text += "  Allowed: $($ReportData.Period2.Stats.AllowedEvents)`n`n"
            }

            if ($ReportData.TotalEventsChange -ne $null) {
                $text += "Changes:`n"
                $text += "  Total Events: $($ReportData.TotalEventsChange)%`n"
                $text += "  Blocked Events: $($ReportData.BlockedEventsChange)%`n`n"
            }

            if ($ReportData.AppComparison) {
                $text += "Application Comparison:`n"
                foreach ($app in $ReportData.AppComparison) {
                    $changeText = if ($app.Change -gt 0) { "+$($app.Change)" } else { $app.Change.ToString() }
                    $text += "  - $($app.Application): Period1=$($app.Period1Count), Period2=$($app.Period2Count) (Change: $changeText)`n"
                }
                $text += "`n"
            }
        }
    }

    $text += "`n" + "=" * 80 + "`n"
    $text += "End of Report`n"
    $text += "=" * 80 + "`n"

    return $text
}

function Format-ReportAsHtml {
    <#
    .SYNOPSIS
        Format report data as HTML with embedded CSS

    .DESCRIPTION
        Converts structured report data into a formatted HTML report
        with GitHub dark theme styling

    .PARAMETER ReportData
        Hashtable containing report data with required properties

    .OUTPUTS
        HTML string with embedded CSS

    .EXAMPLE
        $html = Format-ReportAsHtml -ReportData $reportData
        $html | Out-File -FilePath "report.html" -Encoding UTF8
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ReportData
    )

    # HTML encode helper (use validation module if available)
    $encodeHtml = {
        param($text)
        if (Get-Command ConvertTo-HtmlEncoded -ErrorAction SilentlyContinue) {
            return ConvertTo-HtmlEncoded -Value $text
        }
        return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
    }

    $title = & $encodeHtml $ReportData.ReportTitle

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title - GA-AppLocker</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #0D1117 0%, #161B22 100%);
            color: #E6EDF3;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #21262D;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #238636 0%, #2EA043 100%);
            padding: 30px;
            border-bottom: 3px solid #30363D;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 14px;
            opacity: 0.9;
        }

        .metadata {
            background: #161B22;
            padding: 20px 30px;
            border-bottom: 1px solid #30363D;
            font-size: 13px;
            color: #8B949E;
        }

        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }

        .metadata-item {
            display: flex;
            justify-content: space-between;
        }

        .metadata-label {
            font-weight: 600;
            color: #58A6FF;
        }

        .content {
            padding: 30px;
        }

        .section {
            margin-bottom: 30px;
        }

        .section-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #58A6FF;
            border-bottom: 2px solid #30363D;
            padding-bottom: 10px;
        }

        .card {
            background: #0D1117;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #30363D;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .metric-card {
            background: #161B22;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border: 1px solid #30363D;
        }

        .metric-value {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .metric-label {
            font-size: 12px;
            color: #8B949E;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .metric-success { color: #3FB950; }
        .metric-warning { color: #D29922; }
        .metric-danger { color: #F85149; }
        .metric-info { color: #58A6FF; }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363D;
        }

        th {
            background: #161B22;
            font-weight: 600;
            color: #58A6FF;
            font-size: 13px;
            text-transform: uppercase;
        }

        td {
            font-size: 13px;
        }

        tr:hover {
            background: #161B22;
        }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-success {
            background: #238636;
            color: white;
        }

        .badge-warning {
            background: #D29922;
            color: white;
        }

        .badge-danger {
            background: #F85149;
            color: white;
        }

        .badge-info {
            background: #1F6FEB;
            color: white;
        }

        .footer {
            background: #161B22;
            padding: 20px 30px;
            text-align: center;
            font-size: 12px;
            color: #6E7681;
            border-top: 1px solid #30363D;
        }

        @media print {
            body {
                background: white;
                color: black;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$title</h1>
"@

    if ($ReportData.ReportSummary) {
        $html += "            <p>$(& $encodeHtml $ReportData.ReportSummary)</p>`n"
    }

    $html += @"
        </div>

        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">Generated:</span>
                    <span>$(& $encodeHtml $ReportData.GeneratedAt)</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">By:</span>
                    <span>$(& $encodeHtml $ReportData.GeneratedBy)</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Computer:</span>
                    <span>$(& $encodeHtml $ReportData.ComputerName)</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Period:</span>
                    <span>$(& $encodeHtml $ReportData.StartDate) to $(& $encodeHtml $ReportData.EndDate)</span>
                </div>
            </div>
        </div>

        <div class="content">
"@

    switch ($ReportData.ReportType) {
        "Executive" {
            $riskClass = switch ($ReportData.RiskLevel) {
                "Low" { "metric-success" }
                "Medium" { "metric-warning" }
                { $_ -in @("High", "Critical") } { "metric-danger" }
                default { "metric-info" }
            }

            $complianceClass = switch ($ReportData.OverallCompliance) {
                { $_ -ge 90 } { "metric-success" }
                { $_ -ge 70 } { "metric-warning" }
                default { "metric-danger" }
            }

            $html += @"
            <div class="section">
                <h2 class="section-title">Executive Summary</h2>
                <div class="metric-grid">
                    <div class="metric-card">
                        <div class="metric-value $complianceClass">$($ReportData.OverallCompliance)%</div>
                        <div class="metric-label">Compliance</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value $riskClass">$($ReportData.RiskScore)</div>
                        <div class="metric-label">Risk Score ($($ReportData.RiskLevel))</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value metric-info">$($ReportData.TotalEvents)</div>
                        <div class="metric-label">Total Events</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value metric-warning">$($ReportData.BlockedEvents)</div>
                        <div class="metric-label">Blocked</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Event Breakdown</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Event Type</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                        <tr>
                            <td>Allowed</td>
                            <td>$($ReportData.AllowedEvents)</td>
                            <td>$([math]::Round(($ReportData.AllowedEvents / [math]::Max(1, $ReportData.TotalEvents)) * 100, 2))%</td>
                        </tr>
                        <tr>
                            <td>Audited</td>
                            <td>$($ReportData.AuditedEvents)</td>
                            <td>$([math]::Round(($ReportData.AuditedEvents / [math]::Max(1, $ReportData.TotalEvents)) * 100, 2))%</td>
                        </tr>
                        <tr>
                            <td>Blocked</td>
                            <td>$($ReportData.BlockedEvents)</td>
                            <td>$([math]::Round(($ReportData.BlockedEvents / [math]::Max(1, $ReportData.TotalEvents)) * 100, 2))%</td>
                        </tr>
                    </table>
                </div>
            </div>
"@

            if ($ReportData.PolicyCoverage) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Policy Coverage</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Rule Type</th>
                            <th>Status</th>
                        </tr>
                        <tr>
                            <td>Executable (EXE)</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.ExeCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.ExeCoverage)</span></td>
                        </tr>
                        <tr>
                            <td>Installer (MSI)</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.MsiCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.MsiCoverage)</span></td>
                        </tr>
                        <tr>
                            <td>Script</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.ScriptCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.ScriptCoverage)</span></td>
                        </tr>
                        <tr>
                            <td>DLL</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.DllCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.DllCoverage)</span></td>
                        </tr>
                    </table>
                </div>
            </div>
"@
            }

            if ($ReportData.TopViolatingApps -and $ReportData.TopViolatingApps.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Top Violating Applications</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Application</th>
                            <th>Violation Count</th>
                            <th>Percentage</th>
                        </tr>
"@
                foreach ($app in $ReportData.TopViolatingApps) {
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $app.Application)</td>
                            <td>$($app.ViolationCount)</td>
                            <td>$($app.Percentage)%</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }

            if ($ReportData.TrendData -and $ReportData.TrendData.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Compliance Trends</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Period</th>
                            <th>Compliance</th>
                            <th>Event Count</th>
                        </tr>
"@
                foreach ($trend in $ReportData.TrendData) {
                    $trendClass = switch ($trend.Compliance) {
                        { $_ -ge 90 } { "badge-success" }
                        { $_ -ge 70 } { "badge-warning" }
                        default { "badge-danger" }
                    }
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $trend.Period)</td>
                            <td><span class="badge $trendClass">$($trend.Compliance)%</span></td>
                            <td>$($trend.EventCount)</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }
        }

        "Technical" {
            $html += @"
            <div class="section">
                <h2 class="section-title">Technical Details</h2>
                <div class="card">
                    <p><strong>Total Events:</strong> $($ReportData.TotalEvents)</p>
                </div>
            </div>
"@

            if ($ReportData.EventsByType -and $ReportData.EventsByType.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Events by Type</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
"@
                foreach ($type in $ReportData.EventsByType) {
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $type.Type)</td>
                            <td>$($type.Count)</td>
                            <td>$($type.Percentage)%</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }

            if ($ReportData.TopFilePaths -and $ReportData.TopFilePaths.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Top File Paths</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>File Path</th>
                            <th>Event Count</th>
                        </tr>
"@
                foreach ($path in $ReportData.TopFilePaths) {
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $path.FilePath)</td>
                            <td>$($path.Count)</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }

            if ($ReportData.TopPublishers -and $ReportData.TopPublishers.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Top Publishers</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Publisher</th>
                            <th>Event Count</th>
                        </tr>
"@
                foreach ($pub in $ReportData.TopPublishers) {
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $pub.Publisher)</td>
                            <td>$($pub.Count)</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }

            if ($ReportData.PolicyRules) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Policy Rules</h2>
                <div class="card">
                    <p><strong>Total Rules:</strong> $($ReportData.PolicyRules.Count)</p>
                </div>
            </div>
"@
            }
        }

        "Audit" {
            $html += @"
            <div class="section">
                <h2 class="section-title">Audit Trail</h2>
                <div class="card">
                    <p><strong>Total Audit Events:</strong> $($ReportData.TotalAuditEvents)</p>
                </div>
            </div>
"@

            if ($ReportData.EventsByDate -and $ReportData.EventsByDate.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Events by Date</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Date</th>
                            <th>Event Count</th>
                        </tr>
"@
                foreach ($date in $ReportData.EventsByDate) {
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $date.Date)</td>
                            <td>$($date.EventCount)</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }

            if ($ReportData.EventsByUser -and $ReportData.EventsByUser.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Top Users by Action Count</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>User</th>
                            <th>Action Count</th>
                        </tr>
"@
                foreach ($user in $ReportData.EventsByUser) {
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $user.User)</td>
                            <td>$($user.ActionCount)</td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }
        }

        "Comparison" {
            $html += @"
            <div class="section">
                <h2 class="section-title">Period Comparison</h2>
"@
            if ($ReportData.Period1) {
                $html += @"
                <div class="card">
                    <h3>Period 1</h3>
                    <p><strong>Date Range:</strong> $(& $encodeHtml $ReportData.Period1.StartDate) to $(& $encodeHtml $ReportData.Period1.EndDate)</p>
                    <p><strong>Total Events:</strong> $($ReportData.Period1.Stats.TotalEvents)</p>
                    <p><strong>Blocked:</strong> $($ReportData.Period1.Stats.BlockedEvents)</p>
                    <p><strong>Allowed:</strong> $($ReportData.Period1.Stats.AllowedEvents)</p>
                </div>
"@
            }

            if ($ReportData.Period2) {
                $html += @"
                <div class="card">
                    <h3>Period 2</h3>
                    <p><strong>Date Range:</strong> $(& $encodeHtml $ReportData.Period2.StartDate) to $(& $encodeHtml $ReportData.Period2.EndDate)</p>
                    <p><strong>Total Events:</strong> $($ReportData.Period2.Stats.TotalEvents)</p>
                    <p><strong>Blocked:</strong> $($ReportData.Period2.Stats.BlockedEvents)</p>
                    <p><strong>Allowed:</strong> $($ReportData.Period2.Stats.AllowedEvents)</p>
                </div>
            </div>
"@
            }

            if ($ReportData.TotalEventsChange -ne $null) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Changes</h2>
                <div class="metric-grid">
                    <div class="metric-card">
                        <div class="metric-value metric-info">$($ReportData.TotalEventsChange)%</div>
                        <div class="metric-label">Total Events Change</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value metric-warning">$($ReportData.BlockedEventsChange)%</div>
                        <div class="metric-label">Blocked Events Change</div>
                    </div>
                </div>
            </div>
"@
            }

            if ($ReportData.AppComparison -and $ReportData.AppComparison.Count -gt 0) {
                $html += @"
            <div class="section">
                <h2 class="section-title">Application Comparison</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Application</th>
                            <th>Period 1 Count</th>
                            <th>Period 2 Count</th>
                            <th>Change</th>
                        </tr>
"@
                foreach ($app in $ReportData.AppComparison) {
                    $changeClass = switch ($app.Change) {
                        { $_ -gt 0 } { "badge-danger" }
                        { $_ -lt 0 } { "badge-success" }
                        default { "badge-info" }
                    }
                    $changeText = if ($app.Change -gt 0) { "+$($app.Change)" } else { $app.Change.ToString() }
                    $html += @"
                        <tr>
                            <td>$(& $encodeHtml $app.Application)</td>
                            <td>$($app.Period1Count)</td>
                            <td>$($app.Period2Count)</td>
                            <td><span class="badge $changeClass">$changeText</span></td>
                        </tr>
"@
                }
                $html += @"
                    </table>
                </div>
            </div>
"@
            }
        }
    }

    $html += @"
        </div>

        <div class="footer">
            <p>Generated by GA-AppLocker Dashboard | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>This report contains confidential information. Handle with appropriate security measures.</p>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function Format-TimeSpan {
    <#
    .SYNOPSIS
        Format a timespan in human-readable form

    .PARAMETER TimeSpan
        The timespan to format

    .OUTPUTS
        Formatted string

    .EXAMPLE
        Format-TimeSpan -TimeSpan (New-TimeSpan -Hours 2 -Minutes 30)
        # Returns: "2 hours, 30 minutes"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [TimeSpan]$TimeSpan
    )

    $parts = @()

    if ($TimeSpan.Days -gt 0) {
        $parts += "$($TimeSpan.Days) day$(if ($TimeSpan.Days -ne 1) { 's' })"
    }

    if ($TimeSpan.Hours -gt 0) {
        $parts += "$($TimeSpan.Hours) hour$(if ($TimeSpan.Hours -ne 1) { 's' })"
    }

    if ($TimeSpan.Minutes -gt 0) {
        $parts += "$($TimeSpan.Minutes) minute$(if ($TimeSpan.Minutes -ne 1) { 's' })"
    }

    if ($parts.Count -eq 0 -and $TimeSpan.Seconds -ge 0) {
        $parts += "$($TimeSpan.Seconds) second$(if ($TimeSpan.Seconds -ne 1) { 's' })"
    }

    return $parts -join ", "
}

function Format-FileSize {
    <#
    .SYNOPSIS
        Format file size in human-readable form

    .PARAMETER Bytes
        Size in bytes

    .OUTPUTS
        Formatted string (e.g., "1.5 MB")

    .EXAMPLE
        Format-FileSize -Bytes 1572864
        # Returns: "1.50 MB"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    if ($Bytes -lt 1KB) {
        return "$Bytes B"
    }
    elseif ($Bytes -lt 1MB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    }
    elseif ($Bytes -lt 1GB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    }
    elseif ($Bytes -lt 1TB) {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    }
    else {
        return "{0:N2} TB" -f ($Bytes / 1TB)
    }
}

function Format-DateTime {
    <#
    .SYNOPSIS
        Format datetime with consistent formatting

    .PARAMETER DateTime
        The datetime to format

    .PARAMETER Format
        Format type: Short, Long, ISO8601, or custom format string

    .OUTPUTS
        Formatted datetime string

    .EXAMPLE
        Format-DateTime -DateTime (Get-Date) -Format "Short"
        # Returns: "2026-01-16 14:30"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$DateTime,

        [Parameter(Mandatory = $false)]
        [string]$Format = "Short"
    )

    switch ($Format) {
        "Short"    { return $DateTime.ToString("yyyy-MM-dd HH:mm") }
        "Long"     { return $DateTime.ToString("yyyy-MM-dd HH:mm:ss") }
        "ISO8601"  { return $DateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
        "DateOnly" { return $DateTime.ToString("yyyy-MM-dd") }
        "TimeOnly" { return $DateTime.ToString("HH:mm:ss") }
        default    { return $DateTime.ToString($Format) }
    }
}

# Export module members
Export-ModuleMember -Function Format-ReportAsText, Format-ReportAsHtml, Format-TimeSpan, `
                              Format-FileSize, Format-DateTime
