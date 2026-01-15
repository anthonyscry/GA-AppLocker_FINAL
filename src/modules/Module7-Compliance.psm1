# Module7-Compliance.psm1
# Compliance module for GA-AppLocker
# Collects evidence and generates compliance reports
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

<#
.SYNOPSIS
    Create Evidence Folder Structure
.DESCRIPTION
    Creates the folder structure for storing compliance evidence
.OUTPUTS
    System.Collections.Hashtable
#>
function New-EvidenceFolder {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$BasePath = 'C:\AppLocker\Evidence'
    )

    $folders = @(
        'Policies',
        'Events',
        'Inventory',
        'Reports',
        'Scans'
    )

    try {
        if (-not (Test-Path $BasePath)) {
            New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
        }

        $createdFolders = @{}
        foreach ($folder in $folders) {
            $fullPath = Join-Path -Path $BasePath -ChildPath $folder

            if (-not (Test-Path $fullPath)) {
                New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
            }

            $createdFolders[$folder] = $fullPath
        }

        return @{
            success = $true
            basePath = $BasePath
            folders = $createdFolders
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Export Current AppLocker Policy
.DESCRIPTION
    Saves the current AppLocker policy to a file with proper UTF-16 encoding (from AaronLocker)
.OUTPUTS
    System.Collections.Hashtable
#>
function Export-CurrentPolicy {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$OutputPath = 'C:\AppLocker\Evidence\Policies\CurrentPolicy.xml'
    )

    try {
        $policy = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($policy)) {
            return @{
                success = $false
                error = 'No AppLocker policy is configured'
            }
        }

        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        # Save with proper UTF-16 encoding (from AaronLocker pattern)
        # AppLocker policies MUST be UTF-16 encoded
        $xmlDoc = [xml]$policy
        Save-XmlDocAsUnicode -xmlDoc $xmlDoc -xmlFilename $OutputPath

        $exists = Test-Path $OutputPath
        return @{
            success = $exists
            path = $OutputPath
            timestamp = Get-Date -Format 'o'
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Export System Inventory
.DESCRIPTION
    Collects and exports system software inventory
.OUTPUTS
    System.Collections.Hashtable
#>
function Export-SystemInventory {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$OutputPath = 'C:\AppLocker\Evidence\Inventory\Inventory.json'
    )

    try {
        $inventory = @{
            timestamp = Get-Date -Format 'o'
            computerName = $env:COMPUTERNAME
            installedSoftware = @()
            runningProcesses = @()
        }

        $software64 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher
        $software32 = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher

        $inventory.installedSoftware = @($software64) + @($software32) | Where-Object { $_.DisplayName }
        $inventory.runningProcesses = Get-Process | Select-Object Name, Path, Company | Where-Object { $_.Path }

        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $inventory | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        return @{
            success = $true
            path = $OutputPath
            softwareCount = $inventory.installedSoftware.Count
            processCount = $inventory.runningProcesses.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Generate Compliance Summary
.DESCRIPTION
    Creates a summary of AppLocker compliance status
.OUTPUTS
    System.Collections.Hashtable
#>
function Get-ComplianceSummary {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # Import modules for Get-PolicyHealthScore and Get-AppLockerEventStats
    # Note: These functions should be defined in their respective modules
    # If not available, we'll use default values
    $hasPolicyHealth = $false
    $hasEventStats = $false

    try {
        Import-Module "$PSScriptRoot\Module1-Dashboard.psm1" -ErrorAction Stop
        $hasPolicyHealth = $true
    }
    catch {
        # Module not available, will use defaults
    }

    try {
        Import-Module "$PSScriptRoot\Module5-EventMonitor.psm1" -ErrorAction Stop
        $hasEventStats = $true
    }
    catch {
        # Module not available, will use defaults
    }

    $summary = @{
        timestamp = Get-Date -Format 'o'
        computerName = $env:COMPUTERNAME
    }

    if ($hasPolicyHealth) {
        try {
            $health = Get-PolicyHealthScore
            $summary.policyScore = $health.score
            $summary.hasExeRules = $health.hasExe
            $summary.hasMsiRules = $health.hasMsi
            $summary.hasScriptRules = $health.hasScript
            $summary.hasDllRules = $health.hasDll
        }
        catch {
            $summary.policyScore = 0
            $summary.hasExeRules = $false
            $summary.hasMsiRules = $false
            $summary.hasScriptRules = $false
            $summary.hasDllRules = $false
        }
    }
    else {
        $summary.policyScore = 0
        $summary.hasExeRules = $false
        $summary.hasMsiRules = $false
        $summary.hasScriptRules = $false
        $summary.hasDllRules = $false
    }

    if ($hasEventStats) {
        try {
            $events = Get-AppLockerEventStats
            $summary.eventsAllowed = $events.allowed
            $summary.eventsAudit = $events.audit
            $summary.eventsBlocked = $events.blocked
        }
        catch {
            $summary.eventsAllowed = 0
            $summary.eventsAudit = 0
            $summary.eventsBlocked = 0
        }
    }
    else {
        $summary.eventsAllowed = 0
        $summary.eventsAudit = 0
        $summary.eventsBlocked = 0
    }

    $summary.readyToEnforce = $summary.eventsAudit -lt 10
    $summary.tooRestrictive = $summary.eventsBlocked -gt 100

    if ($summary.policyScore -eq 100 -and $summary.readyToEnforce) {
        $summary.assessment = 'Excellent - Ready for enforcement'
    }
    elseif ($summary.policyScore -ge 50) {
        $summary.assessment = 'Good - Some categories need rules'
    }
    elseif ($summary.policyScore -gt 0) {
        $summary.assessment = 'Fair - More configuration needed'
    }
    else {
        $summary.assessment = 'Not Configured - AppLocker not set up'
    }

    return @{
        success = $true
        data = $summary
    }
}

<#
.SYNOPSIS
    Generate HTML Compliance Report
.DESCRIPTION
    Creates an HTML report of compliance status
.OUTPUTS
    System.Collections.Hashtable
#>
function New-ComplianceReport {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$OutputPath = 'C:\AppLocker\Evidence\Reports\ComplianceReport.html'
    )

    try {
        $compliance = Get-ComplianceSummary
        $data = $compliance.data

        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AppLocker Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .metric { flex: 1; background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
        .metric-value { font-size: 32px; font-weight: bold; color: #3498db; }
        .metric-label { font-size: 14px; color: #7f8c8d; text-transform: uppercase; }
        .score-excellent { color: #27ae60; }
        .score-good { color: #f39c12; }
        .score-fair { color: #e67e22; }
        .score-poor { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        tr:hover { background: #f5f5f5; }
        .assessment { padding: 15px; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AppLocker Compliance Report</h1>
        <p class="timestamp">Generated: $($data.timestamp)</p>
        <p class="timestamp">Computer: $($data.computerName)</p>

        <h2>Policy Health Score</h2>
        <div class="summary">
            <div class="metric">
                <div class="metric-value score-$(if ($data.policyScore -eq 100) { 'excellent' } elseif ($data.policyScore -ge 50) { 'good' } elseif ($data.policyScore -gt 0) { 'fair' } else { 'poor' })">$($data.policyScore)</div>
                <div class="metric-label">Overall Score</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(@($data.hasExeRules,$data.hasMsiRules,$data.hasScriptRules,$data.hasDllRules | Where-Object { $_ }).Count)</div>
                <div class="metric-label">Categories Configured</div>
            </div>
        </div>

        <div class="assessment" style="background: $(if ($data.assessment -like 'Excellent') { '#d4edda' } elseif ($data.assessment -like 'Good') { '#fff3cd' } else { '#f8d7da' }); color: $(if ($data.assessment -like 'Excellent') { '#155724' } elseif ($data.assessment -like 'Good') { '#856404' } else { '#721c24' });">
            Assessment: $($data.assessment)
        </div>

        <h2>Rule Categories</h2>
        <table>
            <tr><th>Category</th><th>Status</th></tr>
            <tr><td>Executable (EXE)</td><td>$(if ($data.hasExeRules) { '✓ Configured' } else { '✗ Not Configured' })</td></tr>
            <tr><td>Installer (MSI)</td><td>$(if ($data.hasMsiRules) { '✓ Configured' } else { '✗ Not Configured' })</td></tr>
            <tr><td>Script</td><td>$(if ($data.hasScriptRules) { '✓ Configured' } else { '✗ Not Configured' })</td></tr>
            <tr><td>DLL</td><td>$(if ($data.hasDllRules) { '✓ Configured' } else { '✗ Not Configured' })</td></tr>
        </table>

        <h2>Event Statistics</h2>
        <div class="summary">
            <div class="metric">
                <div class="metric-value" style="color: #27ae60;">$($data.eventsAllowed)</div>
                <div class="metric-label">Allowed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #f39c12;">$($data.eventsAudit)</div>
                <div class="metric-label">Audit (Would Block)</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #e74c3c;">$($data.eventsBlocked)</div>
                <div class="metric-label">Blocked</div>
            </div>
        </div>

        <h2>Enforcement Readiness</h2>
        <table>
            <tr><th>Metric</th><th>Status</th></tr>
            <tr><td>Ready to Enforce</td><td>$(if ($data.readyToEnforce) { '✓ Yes' } else { '✗ No - Too many audit events' })</td></tr>
            <tr><td>Too Restrictive</td><td>$(if ($data.tooRestrictive) { '⚠ Yes - Review blocked events' } else { '✓ No' })</td></tr>
        </table>
    </div>
</body>
</html>
"@

        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        return @{
            success = $true
            path = $OutputPath
            assessment = $data.assessment
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Export All Evidence
.DESCRIPTION
    Collects all compliance evidence and exports to files
.OUTPUTS
    System.Collections.Hashtable
#>
function Export-AllEvidence {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$BasePath = 'C:\AppLocker\Evidence'
    )

    try {
        $folders = New-EvidenceFolder -BasePath $BasePath
        if (-not $folders.success) {
            return $folders
        }

        $results = @{}

        $policy = Export-CurrentPolicy -OutputPath "$BasePath\Policies\CurrentPolicy.xml"
        $results.policy = $policy

        $inventory = Export-SystemInventory -OutputPath "$BasePath\Inventory\Inventory.json"
        $results.inventory = $inventory

        $report = New-ComplianceReport -OutputPath "$BasePath\Reports\ComplianceReport.html"
        $results.report = $report

        return @{
            success = $true
            basePath = $BasePath
            results = $results
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Export functions
Export-ModuleMember -Function New-EvidenceFolder, Export-CurrentPolicy, Export-SystemInventory,
                              Get-ComplianceSummary, New-ComplianceReport, Export-AllEvidence
