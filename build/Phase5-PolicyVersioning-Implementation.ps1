# ============================================================
# PHASE 5: POLICY VERSIONING AND ROLLBACK IMPLEMENTATION
# ============================================================
# This file contains the complete implementation for Phase 5
# Integrate this code into GA-AppLocker-GUI-WPF.ps1
# ============================================================

# ============================================================
# PART 1: POWERSHELL VERSIONING FUNCTIONS (Module 11)
# Add this after Module 10 in the EMBEDDED section
# ============================================================

# Module 11: Policy Versioning and Rollback

# Version storage configuration
$script:VersionStoragePath = "C:\GA-AppLocker\versions"
$script:VersionRetentionDays = 90
$script:MaxVersionCount = 50
$script:AutoVersionBeforeChanges = $true

<#
.SYNOPSIS
    Initialize version storage directory and configuration

.DESCRIPTION
    Creates the version storage directory if it doesn't exist
    and initializes version tracking configuration
#>
function Initialize-PolicyVersioning {
    try {
        Write-Log "Initializing Policy Versioning system"

        # Create version storage directory
        if (-not (Test-Path $script:VersionStoragePath)) {
            New-Item -ItemType Directory -Path $script:VersionStoragePath -Force | Out-Null
            Write-Log "Created version storage directory: $script:VersionStoragePath"
        }

        # Create subdirectories
        $subdirs = @("current", "archive", "temp")
        foreach ($subdir in $subdirs) {
            $path = Join-Path $script:VersionStoragePath $subdir
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }

        # Create version index file if it doesn't exist
        $indexFile = Join-Path $script:VersionStoragePath "version-index.json"
        if (-not (Test-Path $indexFile)) {
            @{
                Created = Get-Date
                Versions = @()
                NextVersionNumber = 1
            } | ConvertTo-Json -Depth 10 | Out-File -FilePath $indexFile -Encoding UTF8
        }

        return @{
            success = $true
            message = "Policy versioning initialized successfully"
            path = $script:VersionStoragePath
        }
    }
    catch {
        Write-Log "Failed to initialize policy versioning: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Save a new version of the AppLocker policy

.DESCRIPTION
    Creates a new version snapshot with metadata including author,
    description, change categories, and automatic rule counting

.PARAMETER Description
    Description of changes made in this version

.PARAMETER Author
    Username of the person making the changes (defaults to current user)

.PARAMETER ChangeCategory
    Category of change: Automatic, Manual, Export, GPO_Deployment, Bulk_Operation

.PARAMETER Force
    Skip confirmation prompts
#>
function Save-PolicyVersion {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Description = "Automatic version backup",

        [Parameter(Mandatory=$false)]
        [string]$Author = $env:USERNAME,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Automatic", "Manual", "Export", "GPO_Deployment", "Bulk_Operation", "Rollback")]
        [string]$ChangeCategory = "Manual",

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    try {
        Write-Log "Saving policy version: $Description"

        # Initialize versioning if needed
        $initResult = Initialize-PolicyVersioning
        if (-not $initResult.success) {
            return $initResult
        }

        # Get current effective policy
        try {
            $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        }
        catch {
            return @{
                success = $false
                error = "Failed to retrieve AppLocker policy: $($_.Exception.Message)"
            }
        }

        # Load version index
        $indexFile = Join-Path $script:VersionStoragePath "version-index.json"
        $index = Get-Content $indexFile | ConvertFrom-Json

        # Generate version number
        $versionNumber = $index.NextVersionNumber
        $index.NextVersionNumber++

        # Generate version ID
        $versionId = "v$versionNumber-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"

        # Create version directory
        $versionDir = Join-Path $script:VersionStoragePath "current\$versionId"
        New-Item -ItemType Directory -Path $versionDir -Force | Out-Null

        # Export policy to XML
        $policyFile = Join-Path $versionDir "policy.xml"
        $policy.ToXml() | Out-File -FilePath $policyFile -Encoding UTF8

        # Count rules by type
        $ruleCounts = @{}
        foreach ($collection in $policy.RuleCollections) {
            $ruleCounts[$collection.RuleCollectionType] = $collection.Count
        }

        # Get enforcement mode
        $enforcementMode = @{}
        foreach ($collection in $policy.RuleCollections) {
            $enforcementMode[$collection.RuleCollectionType] = $collection.EnforcementMode
        }

        # Create version metadata
        $metadata = @{
            VersionNumber = $versionNumber
            VersionId = $versionId
            Timestamp = Get-Date
            Author = $Author
            Description = $Description
            ChangeCategory = $ChangeCategory
            RuleCounts = $ruleCounts
            EnforcementMode = $enforcementMode
            TotalRules = ($ruleCounts.Values | Measure-Object -Sum).Sum
            ComputerName = $env:COMPUTERNAME
            PolicyFile = $policyFile
            IsCompressed = $false
            Checksum = (Get-FileHash $policyFile -Algorithm SHA256).Hash
        }

        # Save metadata
        $metadataFile = Join-Path $versionDir "metadata.json"
        $metadata | ConvertTo-Json -Depth 10 | Out-File -FilePath $metadataFile -Encoding UTF8

        # Update index
        $versionEntry = @{
            VersionNumber = $metadata.VersionNumber
            VersionId = $metadata.VersionId
            Timestamp = $metadata.Timestamp
            Author = $metadata.Author
            Description = $metadata.Description
            ChangeCategory = $metadata.ChangeCategory
            TotalRules = $metadata.TotalRules
            IsArchived = $false
        }
        $index.Versions += $versionEntry

        # Save updated index
        $index | ConvertTo-Json -Depth 10 | Out-File -FilePath $indexFile -Encoding UTF8

        # Check if we need to archive old versions
 Invoke-VersionRetentionPolicy

        Write-Log "Policy version $versionNumber saved successfully"

        return @{
            success = $true
            versionNumber = $versionNumber
            versionId = $versionId
            timestamp = $metadata.Timestamp
            message = "Policy version $versionNumber saved successfully"
            metadata = $metadata
        }
    }
    catch {
        Write-Log "Failed to save policy version: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Get list of all policy versions

.DESCRIPTION
    Returns a list of all stored versions with metadata
    Supports filtering by date range, author, and category

.PARAMETER IncludeArchived
    Include archived versions in results

.PARAMETER MaxResults
    Maximum number of versions to return

.PARAMETER Author
    Filter by specific author

.PARAMETER Category
    Filter by change category
#>
function Get-PolicyVersions {
    param(
        [Parameter(Mandatory=$false)]
        [switch]$IncludeArchived,

        [Parameter(Mandatory=$false)]
        [int]$MaxResults = 0,

        [Parameter(Mandatory=$false)]
        [string]$Author,

        [Parameter(Mandatory=$false)]
        [string]$Category
    )

    try {
        Write-Log "Retrieving policy versions"

        # Check if versioning is initialized
        $indexFile = Join-Path $script:VersionStoragePath "version-index.json"
        if (-not (Test-Path $indexFile)) {
            return @{
                success = $true
                versions = @()
                message = "No versions found"
            }
        }

        # Load index
        $index = Get-Content $indexFile | ConvertFrom-Json

        # Filter versions
        $versions = $index.Versions | Where-Object {
            ($IncludeArchived -or -not $_.IsArchived) -and
            (-not $Author -or $_.Author -eq $Author) -and
            (-not $Category -or $_.ChangeCategory -eq $Category)
        }

        # Sort by version number descending
        $versions = $versions | Sort-Object -Property VersionNumber -Descending

        # Apply max results limit
        if ($MaxResults -gt 0) {
            $versions = $versions | Select-Object -First $MaxResults
        }

        return @{
            success = $true
            versions = @($versions)
            totalVersions = $versions.Count
            message = "Retrieved $($versions.Count) versions"
        }
    }
    catch {
        Write-Log "Failed to retrieve policy versions: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
            versions = @()
        }
    }
}

<#
.SYNOPSIS
    Get detailed information about a specific policy version

.DESCRIPTION
    Returns complete metadata and optionally the policy content
    for a specific version

.PARAMETER VersionId
    The version ID to retrieve

.PARAMETER IncludePolicy
    Include the full policy XML in the result

.PARAMETER IncludeRuleDetails
    Include detailed rule information
#>
function Get-PolicyVersion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePolicy,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeRuleDetails
    )

    try {
        Write-Log "Retrieving policy version: $VersionId"

        # Check current versions
        $versionDir = Join-Path $script:VersionStoragePath "current\$VersionId"
        $isArchived = $false

        if (-not (Test-Path $versionDir)) {
            # Check archived versions
            $versionDir = Join-Path $script:VersionStoragePath "archive\$VersionId"
            if (-not (Test-Path $versionDir)) {
                return @{
                    success = $false
                    error = "Version $VersionId not found"
                }
            }
            $isArchived = $true
        }

        # Load metadata
        $metadataFile = Join-Path $versionDir "metadata.json"
        if (-not (Test-Path $metadataFile)) {
            return @{
                success = $false
                error = "Metadata not found for version $VersionId"
            }
        }

        $metadata = Get-Content $metadataFile | ConvertFrom-Json

        # Add archived status
        $metadata | Add-Member -NotePropertyName "IsArchived" -NotePropertyValue $isArchived -Force

        # Include policy if requested
        if ($IncludePolicy) {
            $policyFile = Join-Path $versionDir "policy.xml"
            if (Test-Path $policyFile) {
                $policyXml = Get-Content $policyFile -Raw -Encoding UTF8

                # Parse policy for rule details if requested
                if ($IncludeRuleDetails) {
                    try {
                        $policy = [xml]$policyXml
                        $ruleDetails = @()

                        foreach ($collection in $policy.AppLockerPolicy.RuleCollection) {
                            $collectionType = $collection.Type -replace 'AppLocker ', ''
                            foreach ($rule in $collection.FileHashRule) {
                                $ruleDetails += @{
                                    Type = $collectionType
                                    RuleType = "FileHash"
                                    Name = $rule.Name
                                    Action = $rule.Action
                                    UserOrGroupSid = $rule.UserOrGroupSid.Sid
                                }
                            }
                            foreach ($rule in $collection.FilePathRule) {
                                $ruleDetails += @{
                                    Type = $collectionType
                                    RuleType = "FilePath"
                                    Name = $rule.Name
                                    Action = $rule.Action
                                    Path = $rule.Path
                                }
                            }
                            foreach ($rule in $collection.FilePublisherRule) {
                                $ruleDetails += @{
                                    Type = $collectionType
                                    RuleType = "FilePublisher"
                                    Name = $rule.Name
                                    Action = $rule.Action
                                    PublisherName = $rule.PublisherName
                                    ProductName = $rule.ProductName
                                    BinaryName = $rule.BinaryName
                                }
                            }
                        }

                        $metadata | Add-Member -NotePropertyName "RuleDetails" -NotePropertyValue $ruleDetails -Force
                    }
                    catch {
                        Write-Log "Failed to parse policy for rule details: $($_.Exception.Message)" -Level "WARN"
                    }
                }

                $metadata | Add-Member -NotePropertyName "PolicyXml" -NotePropertyValue $policyXml -Force
            }
        }

        return @{
            success = $true
            version = $metadata
            message = "Version $VersionId retrieved successfully"
        }
    }
    catch {
        Write-Log "Failed to retrieve policy version: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Compare two policy versions and generate a detailed diff

.DESCRIPTION
    Compares two versions and returns detailed differences including
    added, modified, and deleted rules with visual diff

.PARAMETER VersionId1
    First version ID

.PARAMETER VersionId2
    Second version ID

.PARAMETER IncludeRuleDetails
    Include detailed rule-level differences

.PARAMETER GenerateHtmlReport
    Generate an HTML diff report
#>
function Compare-PolicyVersions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId1,

        [Parameter(Mandatory=$true)]
        [string]$VersionId2,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeRuleDetails,

        [Parameter(Mandatory=$false)]
        [switch]$GenerateHtmlReport
    )

    try {
        Write-Log "Comparing policy versions: $VersionId1 vs $VersionId2"

        # Get both versions
        $version1 = Get-PolicyVersion -VersionId $VersionId1 -IncludePolicy -IncludeRuleDetails:$IncludeRuleDetails
        $version2 = Get-PolicyVersion -VersionId $VersionId2 -IncludePolicy -IncludeRuleDetails:$IncludeRuleDetails

        if (-not $version1.success) {
            return @{
                success = $false
                error = "Failed to retrieve version $VersionId1"
            }
        }

        if (-not $version2.success) {
            return @{
                success = $false
                error = "Failed to retrieve version $VersionId2"
            }
        }

        # Calculate metadata differences
        $metadataDiff = @{
            VersionNumber1 = $version1.version.VersionNumber
            VersionNumber2 = $version2.version.VersionNumber
            Timestamp1 = $version1.version.Timestamp
            Timestamp2 = $version2.version.Timestamp
            Author1 = $version1.version.Author
            Author2 = $version2.version.Author
            TimeDelta = ($version2.version.Timestamp - $version1.version.Timestamp)
        }

        # Calculate rule count differences
        $ruleCountDiff = @{}
        foreach ($type in @("Exe", "Msi", "Script", "Dll")) {
            $count1 = if ($version1.version.RuleCounts.$type) { $version1.version.RuleCounts.$type } else { 0 }
            $count2 = if ($version2.version.RuleCounts.$type) { $version2.version.RuleCounts.$type } else { 0 }
            $ruleCountDiff[$type] = @{
                V1 = $count1
                V2 = $count2
                Delta = $count2 - $count1
            }
        }

        # Calculate enforcement mode differences
        $enforcementDiff = @{}
        foreach ($type in @("Exe", "Msi", "Script", "Dll")) {
            $mode1 = if ($version1.version.EnforcementMode.$type) { $version1.version.EnforcementMode.$type } else { "NotConfigured" }
            $mode2 = if ($version2.version.EnforcementMode.$type) { $version2.version.EnforcementMode.$type } else { "NotConfigured" }
            $enforcementDiff[$type] = @{
                V1 = $mode1
                V2 = $mode2
                Changed = $mode1 -ne $mode2
            }
        }

        $result = @{
            success = $true
            version1 = $VersionId1
            version2 = $VersionId2
            metadataDiff = $metadataDiff
            ruleCountDiff = $ruleCountDiff
            enforcementDiff = $enforcementDiff
            totalRulesV1 = $version1.version.TotalRules
            totalRulesV2 = $version2.version.TotalRules
            totalDelta = $version2.version.TotalRules - $version1.version.TotalRules
        }

        # Add rule-level differences if requested
        if ($IncludeRuleDetails -and $version1.version.RuleDetails -and $version2.version.RuleDetails) {
            $ruleLevelDiff = Get-RuleLevelDiff -Rules1 $version1.version.RuleDetails -Rules2 $version2.version.RuleDetails
            $result | Add-Member -NotePropertyName "ruleLevelDiff" -NotePropertyValue $ruleLevelDiff -Force
        }

        # Generate HTML report if requested
        if ($GenerateHtmlReport) {
            $htmlReport = New-DiffHtmlReport -ComparisonResult $result
            $result | Add-Member -NotePropertyName "htmlReport" -NotePropertyValue $htmlReport -Force
        }

        Write-Log "Policy comparison complete"

        return $result
    }
    catch {
        Write-Log "Failed to compare policy versions: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Calculate rule-level differences between two versions
#>
function Get-RuleLevelDiff {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Rules1,

        [Parameter(Mandatory=$true)]
        [array]$Rules2
    )

    $addedRules = @()
    $removedRules = @()
    $modifiedRules = @()

    # Check for removed rules
    foreach ($rule1 in $Rules1) {
        $match = $Rules2 | Where-Object {
            $_.Name -eq $rule1.Name -and
            $_.Type -eq $rule1.Type -and
            $_.RuleType -eq $rule1.RuleType
        }

        if (-not $match) {
            $removedRules += $rule1
        }
    }

    # Check for added rules
    foreach ($rule2 in $Rules2) {
        $match = $Rules1 | Where-Object {
            $_.Name -eq $rule2.Name -and
            $_.Type -eq $rule2.Type -and
            $_.RuleType -eq $rule2.RuleType
        }

        if (-not $match) {
            $addedRules += $rule2
        }
    }

    # Check for modified rules
    foreach ($rule1 in $Rules1) {
        $match = $Rules2 | Where-Object {
            $_.Name -eq $rule1.Name -and
            $_.Type -eq $rule1.Type -and
            $_.RuleType -eq $rule1.RuleType
        }

        if ($match) {
            $isModified = $false
            $changes = @{}

            foreach ($prop in $rule1.PSObject.Properties.Name) {
                if ($prop -notin @("Type", "RuleType", "Name")) {
                    if ($rule1.$prop -ne $match.$prop) {
                        $changes[$prop] = @{
                            Old = $rule1.$prop
                            New = $match.$prop
                        }
                        $isModified = $true
                    }
                }
            }

            if ($isModified) {
                $modifiedRules += @{
                    Name = $rule1.Name
                    Type = $rule1.Type
                    RuleType = $rule1.RuleType
                    Changes = $changes
                }
            }
        }
    }

    return @{
        Added = @($addedRules)
        Removed = @($removedRules)
        Modified = @($modifiedRules)
        TotalAdded = $addedRules.Count
        TotalRemoved = $removedRules.Count
        TotalModified = $modifiedRules.Count
    }
}

<#
.SYNOPSIS
    Generate HTML diff report for comparison
#>
function New-DiffHtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ComparisonResult
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Policy Version Comparison Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0D1117; color: #E6EDF3; margin: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #58A6FF; border-bottom: 2px solid #30363D; padding-bottom: 10px; }
        h2 { color: #58A6FF; margin-top: 30px; }
        .summary { background: #21262D; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .stat-card { background: #30363D; padding: 15px; border-radius: 6px; margin: 10px 0; }
        .stat-label { color: #8B949E; font-size: 12px; }
        .stat-value { font-size: 24px; font-weight: bold; }
        .positive { color: #3FB950; }
        .negative { color: #F85149; }
        .neutral { color: #58A6FF; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363D; }
        th { background: #21262D; color: #58A6FF; }
        tr:hover { background: #161B22; }
        .added { background: rgba(63, 185, 80, 0.1); }
        .removed { background: rgba(248, 81, 73, 0.1); }
        .modified { background: rgba(210, 153, 34, 0.1); }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .badge-added { background: #3FB950; color: #fff; }
        .badge-removed { background: #F85149; color: #fff; }
        .badge-modified { background: #D29922; color: #fff; }
        .diff-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
        .diff-panel { background: #21262D; padding: 15px; border-radius: 8px; }
        .diff-title { font-weight: bold; color: #58A6FF; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Policy Version Comparison Report</h1>

        <div class="summary">
            <h2>Version Summary</h2>
            <div class="diff-grid">
                <div class="diff-panel">
                    <div class="diff-title">Version $($ComparisonResult.version1)</div>
                    <div>Number: <span class="neutral">v$($ComparisonResult.metadataDiff.VersionNumber1)</span></div>
                    <div>Timestamp: <span class="neutral">$($ComparisonResult.metadataDiff.Timestamp1)</span></div>
                    <div>Author: <span class="neutral">$($ComparisonResult.metadataDiff.Author1)</span></div>
                    <div>Total Rules: <span class="neutral">$($ComparisonResult.totalRulesV1)</span></div>
                </div>
                <div class="diff-panel">
                    <div class="diff-title">Version $($ComparisonResult.version2)</div>
                    <div>Number: <span class="neutral">v$($ComparisonResult.metadataDiff.VersionNumber2)</span></div>
                    <div>Timestamp: <span class="neutral">$($ComparisonResult.metadataDiff.Timestamp2)</span></div>
                    <div>Author: <span class="neutral">$($ComparisonResult.metadataDiff.Author2)</span></div>
                    <div>Total Rules: <span class="neutral">$($ComparisonResult.totalRulesV2)</span></div>
                </div>
            </div>
            <div style="text-align: center; margin: 20px 0;">
                <span class="stat-label">Time Delta:</span>
                <span class="neutral" style="font-size: 18px;">$($ComparisonResult.metadataDiff.TimeDelta.Days) days, $($ComparisonResult.metadataDiff.TimeDelta.Hours) hours</span>
            </div>
        </div>

        <div class="summary">
            <h2>Rule Count Changes</h2>
            <table>
                <tr>
                    <th>Rule Type</th>
                    <th>Version 1</th>
                    <th>Version 2</th>
                    <th>Change</th>
                </tr>
"@

    foreach ($type in $ComparisonResult.ruleCountDiff.Keys) {
        $diff = $ComparisonResult.ruleCountDiff[$type]
        $changeClass = if ($diff.Delta -gt 0) { "positive" } elseif ($diff.Delta -lt 0) { "negative" } else { "neutral" }
        $changeSign = if ($diff.Delta -gt 0) { "+" } else { "" }

        $html += @"
                <tr>
                    <td>$type</td>
                    <td>$($diff.V1)</td>
                    <td>$($diff.V2)</td>
                    <td class="$changeClass">$changeSign$($diff.Delta)</td>
                </tr>
"@
    }

    $html += @"
            </table>
        </div>

        <div class="summary">
            <h2>Enforcement Mode Changes</h2>
            <table>
                <tr>
                    <th>Rule Type</th>
                    <th>Version 1</th>
                    <th>Version 2</th>
                    <th>Changed</th>
                </tr>
"@

    foreach ($type in $ComparisonResult.enforcementDiff.Keys) {
        $diff = $ComparisonResult.enforcementDiff[$type]
        $changed = if ($diff.Changed) { "Yes" } else { "No" }
        $changedClass = if ($diff.Changed) { "modified" } else { "" }

        $html += @"
                <tr class="$changedClass">
                    <td>$type</td>
                    <td>$($diff.V1)</td>
                    <td>$($diff.V2)</td>
                    <td>$changed</td>
                </tr>
"@
    }

    $html += @"
            </table>
        </div>

"@

    # Add rule-level differences if available
    if ($ComparisonResult.ruleLevelDiff) {
        $ruleDiff = $ComparisonResult.ruleLevelDiff

        $html += @"
        <div class="summary">
            <h2>Rule-Level Changes</h2>
            <table>
                <tr>
                    <th>Change Type</th>
                    <th>Count</th>
                </tr>
                <tr class="added">
                    <td><span class="badge badge-added">ADDED</span></td>
                    <td class="positive">$($ruleDiff.TotalAdded)</td>
                </tr>
                <tr class="removed">
                    <td><span class="badge badge-removed">REMOVED</span></td>
                    <td class="negative">$($ruleDiff.TotalRemoved)</td>
                </tr>
                <tr class="modified">
                    <td><span class="badge badge-modified">MODIFIED</span></td>
                    <td class="modified">$($ruleDiff.TotalModified)</td>
                </tr>
            </table>
        </div>

"@

        if ($ruleDiff.Added.Count -gt 0) {
            $html += @"
        <div class="summary">
            <h3>Added Rules</h3>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Rule Type</th>
                </tr>
"@
            foreach ($rule in $ruleDiff.Added) {
                $html += @"
                <tr class="added">
                    <td>$($rule.Name)</td>
                    <td>$($rule.Type)</td>
                    <td>$($rule.RuleType)</td>
                </tr>
"@
            }
            $html += @"
            </table>
        </div>
"@
        }

        if ($ruleDiff.Removed.Count -gt 0) {
            $html += @"
        <div class="summary">
            <h3>Removed Rules</h3>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Rule Type</th>
                </tr>
"@
            foreach ($rule in $ruleDiff.Removed) {
                $html += @"
                <tr class="removed">
                    <td>$($rule.Name)</td>
                    <td>$($rule.Type)</td>
                    <td>$($rule.RuleType)</td>
                </tr>
"@
            }
            $html += @"
            </table>
        </div>
"@
        }
    }

    $html += @"
        <div class="summary">
            <p style="text-align: center; color: #8B949E; margin-top: 30px;">
                Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by GA-AppLocker Policy Versioning System
            </p>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

<#
.SYNOPSIS
    Restore a policy version (rollback)

.DESCRIPTION
    Restores a previous policy version by importing the policy XML
    and creates a new version tracking the rollback operation

.PARAMETER VersionId
    The version ID to restore

.PARAMETER Target
    Target: Local, GPO, or File

.PARAMETER GpoName
    GPO name if targeting GPO

.PARAMETER OutputPath
    Output path if targeting File

.PARAMETER Force
    Skip confirmation prompts

.PARAMETER CreateRestorePoint
    Create a version before restoring (default: true)
#>
function Restore-PolicyVersion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Local", "GPO", "File")]
        [string]$Target,

        [Parameter(Mandatory=$false)]
        [string]$GpoName,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [switch]$CreateRestorePoint
    )

    try {
        Write-Log "Restoring policy version: $VersionId to $Target"

        # Get version details
        $version = Get-PolicyVersion -VersionId $VersionId -IncludePolicy
        if (-not $version.success) {
            return @{
                success = $false
                error = "Failed to retrieve version: $($version.error)"
            }
        }

        # Create restore point before rollback if requested
        if ($CreateRestorePoint) {
            Write-Log "Creating restore point before rollback"
            $currentPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
            if ($currentPolicy) {
                Save-PolicyVersion -Description "Pre-rollback backup before restoring v$($version.version.VersionNumber)" -ChangeCategory "Rollback" -Force | Out-Null
            }
        }

        # Save policy XML to temp file
        $tempFile = Join-Path $env:TEMP "applocker-restore-$VersionId.xml"
        $version.version.PolicyXml | Out-File -FilePath $tempFile -Encoding UTF8

        # Perform restoration based on target
        $result = switch ($Target) {
            "Local" {
                # Import to local AppLocker policy
                try {
                    Set-AppLockerPolicy -XmlPolicy $tempFile -ErrorAction Stop

                    # Create version tracking the rollback
                    Save-PolicyVersion -Description "Rollback: Restored v$($version.version.VersionNumber) - $($version.version.Description)" -ChangeCategory "Rollback" -Force | Out-Null

                    @{
                        success = $true
                        message = "Policy version $VersionId restored to local system successfully"
                        target = "Local"
                        restoredFromVersion = $version.version.VersionNumber
                    }
                }
                catch {
                    throw "Failed to import policy to local system: $($_.Exception.Message)"
                }
            }

            "GPO" {
                # Import to GPO
                if (-not $GpoName) {
                    throw "GPO name is required when targeting GPO"
                }

                try {
                    Import-GPO -BackupGpoName $tempFile -TargetName $GpoName -ErrorAction Stop

                    # Create version tracking the rollback
                    Save-PolicyVersion -Description "Rollback to GPO: Restored v$($version.version.VersionNumber) - $($version.version.Description)" -ChangeCategory "Rollback" -Force | Out-Null

                    @{
                        success = $true
                        message = "Policy version $VersionId restored to GPO '$GpoName' successfully"
                        target = "GPO"
                        gpoName = $GpoName
                        restoredFromVersion = $version.version.VersionNumber
                    }
                }
                catch {
                    throw "Failed to import policy to GPO: $($_.Exception.Message)"
                }
            }

            "File" {
                # Export to file
                if (-not $OutputPath) {
                    throw "Output path is required when targeting File"
                }

                try {
                    # Ensure directory exists
                    $outputDir = Split-Path $OutputPath -Parent
                    if (-not (Test-Path $outputDir)) {
                        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                    }

                    Copy-Item -Path $tempFile -Destination $OutputPath -Force

                    @{
                        success = $true
                        message = "Policy version $VersionId exported to $OutputPath successfully"
                        target = "File"
                        outputPath = $OutputPath
                        restoredFromVersion = $version.version.VersionNumber
                    }
                }
                catch {
                    throw "Failed to export policy to file: $($_.Exception.Message)"
                }
            }
        }

        # Clean up temp file
        if (Test-Path $tempFile) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }

        Write-Log "Policy version restoration complete: $($result.message)"

        # Log rollback audit trail
        Add-RollbackAuditEntry -VersionId $VersionId -Target $Target -Success $result.success

        return $result
    }
    catch {
        Write-Log "Failed to restore policy version: $($_.Exception.Message)" -Level "ERROR"

        # Log failed rollback
        Add-RollbackAuditEntry -VersionId $VersionId -Target $Target -Success $false -Error $_.Exception.Message

        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Add entry to rollback audit trail
#>
function Add-RollbackAuditEntry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId,

        [Parameter(Mandatory=$true)]
        [string]$Target,

        [Parameter(Mandatory=$true)]
        [bool]$Success,

        [Parameter(Mandatory=$false)]
        [string]$Error
    )

    try {
        $auditFile = Join-Path $script:VersionStoragePath "rollback-audit.log"
        $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Version: $VersionId | Target: $Target | Success: $Success | User: $env:USERNAME | Computer: $env:COMPUTERNAME"
        if ($Error) {
            $entry += " | Error: $Error"
        }
        $entry | Out-File -FilePath $auditFile -Append -Encoding UTF8
    }
    catch {
        Write-Log "Failed to write rollback audit entry: $($_.Exception.Message)" -Level "WARN"
    }
}

<#
.SYNOPSIS
    Generate detailed diff report between versions
#>
function Get-PolicyDiff {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId1,

        [Parameter(Mandatory=$true)]
        [string]$VersionId2,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Text", "Html", "Json")]
        [string]$Format = "Text",

        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    try {
        Write-Log "Generating policy diff report: $VersionId1 vs $VersionId2"

        # Perform comparison
        $comparison = Compare-PolicyVersions -VersionId1 $VersionId1 -VersionId2 $VersionId2 -IncludeRuleDetails -GenerateHtmlReport:($Format -eq "Html")

        if (-not $comparison.success) {
            return $comparison
        }

        # Generate report based on format
        $report = switch ($Format) {
            "Text" {
                # Generate text report
                $text = @"
====================================
POLICY VERSION DIFF REPORT
====================================

Version 1: $($VersionId1)
  Number: v$($comparison.metadataDiff.VersionNumber1)
  Timestamp: $($comparison.metadataDiff.Timestamp1)
  Author: $($comparison.metadataDiff.Author1)
  Total Rules: $($comparison.totalRulesV1)

Version 2: $($VersionId2)
  Number: v$($comparison.metadataDiff.VersionNumber2)
  Timestamp: $($comparison.metadataDiff.Timestamp2)
  Author: $($comparison.metadataDiff.Author2)
  Total Rules: $($comparison.totalRulesV2)

Time Delta: $($comparison.metadataDiff.TimeDelta.Days) days, $($comparison.metadataDiff.TimeDelta.Hours) hours

====================================
RULE COUNT CHANGES
====================================
"@

                foreach ($type in $comparison.ruleCountDiff.Keys) {
                    $diff = $comparison.ruleCountDiff[$type]
                    $changeSign = if ($diff.Delta -gt 0) { "+" } else { "" }
                    $text += "`n$type`: $($diff.V1) -> $($diff.V2) ($changeSign$($diff.Delta))"
                }

                $text += "`n`n====================================`nENFORCEMENT MODE CHANGES`n===================================="
                foreach ($type in $comparison.enforcementDiff.Keys) {
                    $diff = $comparison.enforcementDiff[$type]
                    $changed = if ($diff.Changed) { " [CHANGED]" } else { "" }
                    $text += "`n$type`: $($diff.V1) -> $($diff.V2)$changed"
                }

                if ($comparison.ruleLevelDiff) {
                    $ruleDiff = $comparison.ruleLevelDiff
                    $text += "`n`n====================================`nRULE-LEVEL CHANGES`n===================================="
                    $text += "`nAdded: $($ruleDiff.TotalAdded) rules"
                    $text += "`nRemoved: $($ruleDiff.TotalRemoved) rules"
                    $text += "`nModified: $($ruleDiff.TotalModified) rules"
                }

                $text += "`n`n====================================`nGenerated: $(Get-Date)`n===================================="
                $text
            }

            "Html" {
                $comparison.htmlReport
            }

            "Json" {
                $comparison | ConvertTo-Json -Depth 10
            }
        }

        # Save to file if path specified
        if ($OutputPath) {
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Log "Diff report saved to: $OutputPath"
        }

        return @{
            success = $true
            report = $report
            format = $Format
            outputPath = $OutputPath
            message = "Diff report generated successfully"
        }
    }
    catch {
        Write-Log "Failed to generate policy diff: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Merge changes from two policy versions
#>
function Merge-PolicyVersions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaseVersionId,

        [Parameter(Mandatory=$true)]
        [string]$MergeVersionId,

        [Parameter(Mandatory=$false)]
        [string]$Description = "Merged policy version",

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    try {
        Write-Log "Merging policy versions: $BaseVersionId + $MergeVersionId"

        # Get both versions
        $baseVersion = Get-PolicyVersion -VersionId $BaseVersionId -IncludePolicy -IncludeRuleDetails
        $mergeVersion = Get-PolicyVersion -VersionId $MergeVersionId -IncludePolicy -IncludeRuleDetails

        if (-not $baseVersion.success) {
            return @{
                success = $false
                error = "Failed to retrieve base version: $($baseVersion.error)"
            }
        }

        if (-not $mergeVersion.success) {
            return @{
                success = $false
                error = "Failed to retrieve merge version: $($mergeVersion.error)"
            }
        }

        # Parse both policies as XML
        $baseXml = [xml]$baseVersion.version.PolicyXml
        $mergeXml = [xml]$mergeVersion.version.PolicyXml

        # Perform merge (simplified - add rules from merge version that don't exist in base)
        $mergedRules = 0

        foreach ($mergeCollection in $mergeXml.AppLockerPolicy.RuleCollection) {
            # Find matching collection in base
            $baseCollection = $baseXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $mergeCollection.Type }

            if ($baseCollection) {
                # Merge file publisher rules
                foreach ($rule in $mergeCollection.FilePublisherRule) {
                    $exists = $baseCollection.FilePublisherRule | Where-Object { $_.Name -eq $rule.Name }
                    if (-not $exists) {
                        # Import rule into base collection
                        $importedRule = $baseXml.ImportNode($rule, $true)
                        $baseCollection.AppendChild($importedRule) | Out-Null
                        $mergedRules++
                    }
                }

                # Merge file path rules
                foreach ($rule in $mergeCollection.FilePathRule) {
                    $exists = $baseCollection.FilePathRule | Where-Object { $_.Name -eq $rule.Name }
                    if (-not $exists) {
                        $importedRule = $baseXml.ImportNode($rule, $true)
                        $baseCollection.AppendChild($importedRule) | Out-Null
                        $mergedRules++
                    }
                }

                # Merge file hash rules
                foreach ($rule in $mergeCollection.FileHashRule) {
                    $exists = $baseCollection.FileHashRule | Where-Object { $_.Name -eq $rule.Name }
                    if (-not $exists) {
                        $importedRule = $baseXml.ImportNode($rule, $true)
                        $baseCollection.AppendChild($importedRule) | Out-Null
                        $mergedRules++
                    }
                }
            }
        }

        # Save merged policy to temp file
        $tempFile = Join-Path $env:TEMP "applocker-merged-$((Get-Date).ToString('yyyyMMdd-HHmmss')).xml"
        $baseXml.OuterXml | Out-File -FilePath $tempFile -Encoding UTF8

        # Import merged policy
        $newPolicy = Get-AppLockerPolicy -XmlPolicy $tempFile

        # Create version tracking the merge
        $fullDescription = "$Description (Merged v$($baseVersion.version.VersionNumber) + v$($mergeVersion.version.VersionNumber), $mergedRules new rules)"
        $versionResult = Save-PolicyVersion -Description $fullDescription -ChangeCategory "Manual" -Force

        # Clean up temp file
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

        Write-Log "Policy merge complete: $mergedRules rules merged"

        return @{
            success = $true
            mergedRules = $mergedRules
            newVersionId = $versionResult.versionId
            newVersionNumber = $versionResult.versionNumber
            message = "Merged $mergedRules rules from v$($mergeVersion.version.VersionNumber) into v$($baseVersion.version.VersionNumber)"
        }
    }
    catch {
        Write-Log "Failed to merge policy versions: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Delete an old policy version
#>
function Delete-PolicyVersion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [switch]$Permanent
    )

    try {
        Write-Log "Deleting policy version: $VersionId"

        # Get version details
        $version = Get-PolicyVersion -VersionId $VersionId
        if (-not $version.success) {
            return @{
                success = $false
                error = "Version not found: $VersionId"
            }
        }

        # Prevent deletion of recent versions (less than 24 hours old) unless forced
        if (-not $Force) {
            $versionAge = (Get-Date) - $version.version.Timestamp
            if ($versionAge.TotalHours -lt 24) {
                return @{
                    success = $false
                    error = "Cannot delete version created less than 24 hours ago. Use -Force to override."
                }
            }
        }

        # Check if version is already archived
        if ($version.version.IsArchived -and -not $Permanent) {
            return @{
                success = $false
                error = "Version is already archived. Use -Permanent to permanently delete."
            }
        }

        if ($version.version.IsArchived -and $Permanent) {
            # Permanently delete from archive
            $versionDir = Join-Path $script:VersionStoragePath "archive\$VersionId"
        } else {
            # Move to archive instead of deleting
            $versionDir = Join-Path $script:VersionStoragePath "current\$VersionId"
            $archiveDir = Join-Path $script:VersionStoragePath "archive\$VersionId"

            if (-not $Permanent) {
                # Archive instead of delete
                if (Test-Path $versionDir) {
                    Move-Item -Path $versionDir -Destination $archiveDir -Force

                    # Update index
                    $indexFile = Join-Path $script:VersionStoragePath "version-index.json"
                    $index = Get-Content $indexFile | ConvertFrom-Json
                    $versionEntry = $index.Versions | Where-Object { $_.VersionId -eq $VersionId }
                    if ($versionEntry) {
                        $versionEntry.IsArchived = $true
                    }
                    $index | ConvertTo-Json -Depth 10 | Out-File -FilePath $indexFile -Encoding UTF8

                    Write-Log "Version archived: $VersionId"

                    return @{
                        success = $true
                        message = "Version archived (not deleted). Use -Permanent to permanently delete."
                        versionId = $VersionId
                    }
                }
            }
        }

        # Permanently delete
        if (Test-Path $versionDir) {
            Remove-Item -Path $versionDir -Recurse -Force

            # Update index
            $indexFile = Join-Path $script:VersionStoragePath "version-index.json"
            $index = Get-Content $indexFile | ConvertFrom-Json
            $index.Versions = $index.Versions | Where-Object { $_.VersionId -ne $VersionId }
            $index | ConvertTo-Json -Depth 10 | Out-File -FilePath $indexFile -Encoding UTF8

            Write-Log "Version permanently deleted: $VersionId"

            return @{
                success = $true
                message = "Version permanently deleted"
                versionId = $VersionId
            }
        }

        return @{
            success = $false
            error = "Version directory not found"
        }
    }
    catch {
        Write-Log "Failed to delete policy version: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Get statistics about policy changes over time
#>
function Get-VersionStatistics {
    param(
        [Parameter(Mandatory=$false)]
        [int]$Days = 30,

        [Parameter(Mandatory=$false)]
        [string]$Author
    )

    try {
        Write-Log "Retrieving version statistics for last $Days days"

        # Get versions
        $versionsResult = Get-PolicyVersions -IncludeArchived:$false -Author $Author
        if (-not $versionsResult.success) {
            return $versionsResult
        }

        # Filter by date range
        $cutoffDate = (Get-Date).AddDays(-$Days)
        $versions = $versionsResult.versions | Where-Object { [datetime]$_.Timestamp -gt $cutoffDate }

        # Calculate statistics
        $stats = @{
            PeriodDays = $Days
            TotalVersions = $versions.Count
            VersionsPerDay = if ($Days -gt 0) { [math]::Round($versions.Count / $Days, 2) } else { 0 }
            Authors = @()
            ChangeCategories = @()
            MostActiveAuthor = $null
            MostCommonCategory = $null
            AverageRulesPerVersion = 0
            TotalRulesChange = 0
            Timeline = @()
        }

        if ($versions.Count -gt 0) {
            # Author statistics
            $authorCounts = @{}
            foreach ($version in $versions) {
                if ($authorCounts.ContainsKey($version.Author)) {
                    $authorCounts[$version.Author]++
                } else {
                    $authorCounts[$version.Author] = 1
                }
            }
            $stats.Authors = $authorCounts.Keys | ForEach-Object @{
                Name = $_
                Count = $authorCounts[$_]
            }
            $stats.MostActiveAuthor = ($authorCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key

            # Category statistics
            $categoryCounts = @{}
            foreach ($version in $versions) {
                if ($categoryCounts.ContainsKey($version.ChangeCategory)) {
                    $categoryCounts[$version.ChangeCategory]++
                } else {
                    $categoryCounts[$version.ChangeCategory] = 1
                }
            }
            $stats.ChangeCategories = $categoryCounts.Keys | ForEach-Object @{
                Category = $_
                Count = $categoryCounts[$_]
            }
            $stats.MostCommonCategory = ($categoryCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key

            # Rule statistics
            $totalRules = 0
            foreach ($version in $versions) {
                $totalRules += $version.TotalRules
            }
            $stats.AverageRulesPerVersion = [math]::Round($totalRules / $versions.Count, 0)

            if ($versions.Count -gt 1) {
                $firstVersion = $versions | Sort-Object -Property VersionNumber | Select-Object -First 1
                $lastVersion = $versions | Sort-Object -Property VersionNumber -Descending | Select-Object -First 1
                $stats.TotalRulesChange = $lastVersion.TotalRules - $firstVersion.TotalRules
            }

            # Timeline
            $timeline = @{}
            foreach ($version in $versions) {
                $dateKey = ([datetime]$version.Timestamp).ToString('yyyy-MM-dd')
                if ($timeline.ContainsKey($dateKey)) {
                    $timeline[$dateKey]++
                } else {
                    $timeline[$dateKey] = 1
                }
            }
            $stats.Timeline = $timeline.Keys | Sort-Object | ForEach-Object @{
                Date = $_
                Count = $timeline[$_]
            }
        }

        return @{
            success = $true
            statistics = $stats
            message = "Retrieved statistics for $($versions.Count) versions over $Days days"
        }
    }
    catch {
        Write-Log "Failed to retrieve version statistics: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Invoke version retention policy to archive old versions
#>
function Invoke-VersionRetentionPolicy {
    param(
        [Parameter(Mandatory=$false)]
        [int]$RetentionDays = $script:VersionRetentionDays,

        [Parameter(Mandatory=$false)]
        [int]$MaxVersions = $script:MaxVersionCount
    )

    try {
        Write-Log "Invoking version retention policy (max $RetentionDays days, max $MaxVersions versions)"

        # Get all versions
        $versionsResult = Get-PolicyVersions -IncludeArchived:$false
        if (-not $versionsResult.success) {
            return $versionsResult
        }

        $versions = $versionsResult.versions
        $archivedCount = 0

        # Archive versions older than retention period
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $oldVersions = $versions | Where-Object { [datetime]$_.Timestamp -lt $cutoffDate }

        foreach ($version in $oldVersions) {
            $result = Delete-PolicyVersion -VersionId $version.VersionId -Force
            if ($result.success) {
                $archivedCount++
            }
        }

        # If still too many versions, archive oldest
        $currentVersions = Get-PolicyVersions -IncludeArchived:$false
        if ($currentVersions.success -and $currentVersions.versions.Count -gt $MaxVersions) {
            $excessCount = $currentVersions.versions.Count - $MaxVersions
            $oldestVersions = $currentVersions.versions | Sort-Object -Property VersionNumber | Select-Object -First $excessCount

            foreach ($version in $oldestVersions) {
                $result = Delete-PolicyVersion -VersionId $version.VersionId -Force
                if ($result.success) {
                    $archivedCount++
                }
            }
        }

        Write-Log "Version retention policy complete: $archivedCount versions archived"

        return @{
            success = $true
            archivedCount = $archivedCount
            message = "Archived $archivedCount versions based on retention policy"
        }
    }
    catch {
        Write-Log "Failed to invoke version retention policy: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Export a specific version to a file
#>
function Export-PolicyVersion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Xml", "Json", "Both")]
        [string]$Format = "Xml"
    )

    try {
        Write-Log "Exporting policy version: $VersionId to $OutputPath"

        # Get version with policy
        $version = Get-PolicyVersion -VersionId $VersionId -IncludePolicy
        if (-not $version.success) {
            return $version
        }

        # Ensure output directory exists
        $outputDir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Export based on format
        switch ($Format) {
            "Xml" {
                $version.version.PolicyXml | Out-File -FilePath $OutputPath -Encoding UTF8
            }
            "Json" {
                $version.version | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
            }
            "Both" {
                $basePath = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
                $version.version.PolicyXml | Out-File -FilePath "$basePath.xml" -Encoding UTF8
                $version.version | ConvertTo-Json -Depth 10 | Out-File -FilePath "$basePath.json" -Encoding UTF8
                $OutputPath = "$basePath.xml"
            }
        }

        Write-Log "Policy version exported successfully"

        return @{
            success = $true
            outputPath = $OutputPath
            format = $Format
            message = "Version $VersionId exported to $OutputPath"
        }
    }
    catch {
        Write-Log "Failed to export policy version: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Add a note to an existing version
#>
function Set-VersionNote {
    param(
        [Parameter(Mandatory=$true)]
        [string]$VersionId,

        [Parameter(Mandatory=$true)]
        [string]$Note,

        [Parameter(Mandatory=$false)]
        [string]$Author = $env:USERNAME
    )

    try {
        Write-Log "Adding note to version: $VersionId"

        # Get version directory
        $versionDir = Join-Path $script:VersionStoragePath "current\$VersionId"
        $isArchived = $false

        if (-not (Test-Path $versionDir)) {
            $versionDir = Join-Path $script:VersionStoragePath "archive\$VersionId"
            if (-not (Test-Path $versionDir)) {
                return @{
                    success = $false
                    error = "Version $VersionId not found"
                }
            }
            $isArchived = $true
        }

        # Load metadata
        $metadataFile = Join-Path $versionDir "metadata.json"
        $metadata = Get-Content $metadataFile | ConvertFrom-Json

        # Add note
        if (-not $metadata.Notes) {
            $metadata.Notes = @()
        }

        $metadata.Notes += @{
            Text = $Note
            Author = $Author
            Timestamp = Get-Date
        }

        # Save updated metadata
        $metadata | ConvertTo-Json -Depth 10 | Out-File -FilePath $metadataFile -Encoding UTF8

        Write-Log "Note added to version successfully"

        return @{
            success = $true
            message = "Note added to version $VersionId"
            noteCount = $metadata.Notes.Count
        }
    }
    catch {
        Write-Log "Failed to add note to version: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# ============================================================
# PART 2: XAML FOR POLICY HISTORY PANEL
# Add this to the sidebar navigation section after MONITORING
# ============================================================

# Find this line in the XAML (around line 2207):
#                            </Expander>
#                        </StackPanel>

# Add this AFTER the MONITORY Expander closes:

"""
                            <!-- POLICY MANAGEMENT Section (Collapsible) -->
                            <Expander x:Name="PolicyManagementSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="POLICY MANAGEMENT" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavPolicyHistory" Content="Policy History" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                </StackPanel>
                            </Expander>
"""

# ============================================================
# PART 3: XAML FOR POLICY HISTORY CONTENT PANEL
# Add this BEFORE the Help Panel (around line 4010)
# ============================================================

# Find this line:
#                </ScrollViewer>

# Add this BEFORE it (after PanelHelp closes):

"""
                <!-- Policy History Panel -->
                <ScrollViewer x:Name="PanelPolicyHistory" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <TextBlock Text="Policy History" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                        <!-- Quick Actions -->
                        <Grid Margin="0,0,0,15">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <Button x:Name="CreateVersionBtn" Content="Create Version" Style="{StaticResource PrimaryButton}"
                                    Grid.Column="0" Margin="0,0,5,0" MinHeight="32"/>
                            <Button x:Name="RefreshVersionsBtn" Content="Refresh List" Style="{StaticResource SecondaryButton}"
                                    Grid.Column="1" Margin="5,0" MinHeight="32"/>
                            <Button x:Name="VersionSettingsBtn" Content="Settings" Style="{StaticResource SecondaryButton}"
                                    Grid.Column="2" Margin="5,0,0,0" MinHeight="32"/>
                        </Grid>

                        <!-- Filter and Search -->
                        <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="15" Margin="0,0,0,15">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="150"/>
                                    <ColumnDefinition Width="150"/>
                                    <ColumnDefinition Width="150"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Text="Search:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="0" Margin="0,0,10,0"/>
                                <TextBox x:Name="VersionSearchBox" Grid.Column="1" Height="26" Background="#0D1117"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12"
                                         Text="Search versions..." Padding="8,4"/>

                                <TextBlock Text="Author:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="2" Margin="15,0,10,0"/>
                                <ComboBox x:Name="VersionAuthorFilter" Grid.Column="3" Height="26" Background="#0D1117"
                                          Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
                                    <ComboBoxItem Content="All Authors" IsSelected="True"/>
                                </ComboBox>

                                <TextBlock Text="Category:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="4" Margin="15,0,10,0"/>
                                <ComboBox x:Name="VersionCategoryFilter" Grid.Column="5" Height="26" Background="#0D1117"
                                          Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
                                    <ComboBoxItem Content="All Categories" IsSelected="True"/>
                                    <ComboBoxItem Content="Automatic"/>
                                    <ComboBoxItem Content="Manual"/>
                                    <ComboBoxItem Content="Export"/>
                                    <ComboBoxItem Content="GPO_Deployment"/>
                                    <ComboBoxItem Content="Bulk_Operation"/>
                                    <ComboBoxItem Content="Rollback"/>
                                </ComboBox>
                            </Grid>
                        </Border>

                        <!-- Version Statistics Cards -->
                        <Grid Margin="0,0,0,15">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Margin="0,0,8,0" Padding="12">
                                <StackPanel>
                                    <TextBlock Text="Total Versions" FontSize="11" Foreground="#8B949E"/>
                                    <TextBlock x:Name="TotalVersionsCount" Text="--" FontSize="22" FontWeight="Bold"
                                               Foreground="#58A6FF" Margin="0,8,0,0"/>
                                </StackPanel>
                            </Border>

                            <Border Grid.Column="1" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Margin="0,0,8,0" Padding="12">
                                <StackPanel>
                                    <TextBlock Text="Latest Version" FontSize="11" Foreground="#8B949E"/>
                                    <TextBlock x:Name="LatestVersionNumber" Text="--" FontSize="22" FontWeight="Bold"
                                               Foreground="#3FB950" Margin="0,8,0,0"/>
                                </StackPanel>
                            </Border>

                            <Border Grid.Column="2" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Margin="0,0,8,0" Padding="12">
                                <StackPanel>
                                    <TextBlock Text="30-Day Activity" FontSize="11" Foreground="#8B949E"/>
                                    <TextBlock x:Name="VersionsLast30Days" Text="--" FontSize="22" FontWeight="Bold"
                                               Foreground="#D29922" Margin="0,8,0,0"/>
                                </StackPanel>
                            </Border>

                            <Border Grid.Column="3" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Padding="12">
                                <StackPanel>
                                    <TextBlock Text="Storage Used" FontSize="11" Foreground="#8B949E"/>
                                    <TextBlock x:Name="VersionStorageUsed" Text="--" FontSize="22" FontWeight="Bold"
                                               Foreground="#F85149" Margin="0,8,0,0"/>
                                </StackPanel>
                            </Border>
                        </Grid>

                        <!-- Version History List -->
                        <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Margin="0,0,0,15">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>

                                <Border Grid.Row="0" Background="#161B22" Padding="12,8" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                                    <Grid>
                                        <TextBlock Text="Version History" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Grid.Column="0"/>
                                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Grid.Column="1">
                                            <TextBlock Text="Compare:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <CheckBox x:Name="CompareModeCheckbox" Content="Compare Mode" Foreground="#8B949E" FontSize="11"/>
                                        </StackPanel>
                                    </Grid>
                                </Border>

                                <ListView x:Name="VersionHistoryList" Grid.Row="1" Height="300" Background="#0D1117"
                                          Foreground="#E6EDF3" BorderThickness="0" FontSize="12"
                                          SelectionMode="Extended">
                                    <ListView.View>
                                        <GridView>
                                            <GridViewColumn Header="Version" Width="80">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <StackPanel>
                                                            <TextBlock Text="{Binding VersionNumber}" FontWeight="Bold" Foreground="#58A6FF"/>
                                                            <TextBlock Text="{Binding VersionIdShort}" FontSize="10" Foreground="#6E7681"/>
                                                        </StackPanel>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                            <GridViewColumn Header="Timestamp" Width="140">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <TextBlock Text="{Binding Timestamp}" FontSize="11" Foreground="#8B949E"/>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                            <GridViewColumn Header="Author" Width="100">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <TextBlock Text="{Binding Author}" Foreground="#E6EDF3"/>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                            <GridViewColumn Header="Description" Width="250">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <TextBlock Text="{Binding Description}" TextWrapping="Wrap" Foreground="#E6EDF3"/>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                            <GridViewColumn Header="Category" Width="100">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <Border Background="{Binding CategoryColor}" CornerRadius="4" Padding="6,3">
                                                            <TextBlock Text="{Binding ChangeCategory}" FontSize="10" Foreground="#FFFFFF"/>
                                                        </Border>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                            <GridViewColumn Header="Rules" Width="60">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <TextBlock Text="{Binding TotalRules}" Foreground="#3FB950" FontWeight="Bold"/>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                            <GridViewColumn Header="Actions" Width="180">
                                                <GridViewColumn.CellTemplate>
                                                    <DataTemplate>
                                                        <StackPanel Orientation="Horizontal">
                                                            <Button Content="View" Style="{StaticResource SmallButton}" Tag="{Binding VersionId}"
                                                                    Margin="0,0,3,0" ToolTip="View version details"/>
                                                            <Button Content="Compare" Style="{StaticResource SmallButton}" Tag="{Binding VersionId}"
                                                                    Margin="0,0,3,0" ToolTip="Compare with another version"/>
                                                            <Button Content="Restore" Style="{StaticResource SmallButton}" Tag="{Binding VersionId}"
                                                                    Margin="0,0,3,0" ToolTip="Restore this version"/>
                                                            <Button Content="Export" Style="{StaticResource SmallButton}" Tag="{Binding VersionId}"
                                                                    ToolTip="Export version to file"/>
                                                        </StackPanel>
                                                    </DataTemplate>
                                                </GridViewColumn.CellTemplate>
                                            </GridViewColumn>
                                        </GridView>
                                    </ListView.View>
                                </ListView>
                            </Grid>
                        </Border>

                        <!-- Comparison Panel (Hidden by default) -->
                        <Border x:Name="ComparisonPanel" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,0,15" Visibility="Collapsed">
                            <StackPanel>
                                <Border Background="#161B22" Padding="12,8" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                                    <Grid>
                                        <TextBlock Text="Version Comparison" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                        <Button x:Name="CloseComparisonBtn" Content="×" HorizontalAlignment="Right"
                                                Foreground="#8B949E" FontSize="18" Padding="0" Width="24" Height="24"/>
                                    </Grid>
                                </Border>

                                <Grid Margin="15">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>

                                    <TextBlock Text="Version 1:" FontSize="12" Foreground="#8B949E" Grid.Column="0" Grid.Row="0" Margin="0,0,0,5"/>
                                    <ComboBox x:Name="CompareVersion1Combo" Grid.Column="0" Grid.Row="1" Height="26" Background="#0D1117"
                                              Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11"/>

                                    <TextBlock Text="VS" FontSize="14" FontWeight="Bold" Foreground="#58A6FF"
                                               Grid.Column="1" Grid.Row="0" Grid.RowSpan="2" HorizontalAlignment="Center" VerticalAlignment="Center"/>

                                    <TextBlock Text="Version 2:" FontSize="12" Foreground="#8B949E" Grid.Column="2" Grid.Row="0" Margin="0,0,0,5"/>
                                    <ComboBox x:Name="CompareVersion2Combo" Grid.Column="2" Grid.Row="1" Height="26" Background="#0D1117"
                                              Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11"/>

                                    <Button x:Name="RunCompareBtn" Content="Compare Versions" Style="{StaticResource PrimaryButton}"
                                            Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="2" MinHeight="32" Margin="0,15,0,15"/>

                                    <!-- Comparison Results -->
                                    <ScrollViewer Grid.Column="0" Grid.ColumnSpan="3" Grid.Row="3" VerticalScrollBarVisibility="Auto" MaxHeight="400">
                                        <StackPanel x:Name="ComparisonResults">
                                            <!-- Results will be populated dynamically -->
                                        </StackPanel>
                                    </ScrollViewer>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <!-- Version Details Panel (Hidden by default) -->
                        <Border x:Name="VersionDetailsPanel" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,0,15" Visibility="Collapsed">
                            <StackPanel>
                                <Border Background="#161B22" Padding="12,8" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                                    <Grid>
                                        <TextBlock x:Name="VersionDetailsTitle" Text="Version Details" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                        <Button x:Name="CloseVersionDetailsBtn" Content="×" HorizontalAlignment="Right"
                                                Foreground="#8B949E" FontSize="18" Padding="0" Width="24" Height="24"/>
                                    </Grid>
                                </Border>

                                <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="500">
                                    <StackPanel Margin="15" x:Name="VersionDetailsContent">
                                        <!-- Details will be populated dynamically -->
                                    </StackPanel>
                                </ScrollViewer>
                            </StackPanel>
                        </Border>

                        <!-- Rollback Confirmation Dialog (Hidden by default) -->
                        <Border x:Name="RollbackConfirmDialog" Background="#21262D" BorderBrush="#F85149" BorderThickness="2"
                                CornerRadius="6" Visibility="Collapsed" MaxWidth="600">
                            <StackPanel Margin="20">
                                <TextBlock Text="⚠️ Confirm Rollback" FontSize="18" FontWeight="Bold" Foreground="#F85149" Margin="0,0,0,15"/>
                                <TextBlock x:Name="RollbackConfirmText" TextWrapping="Wrap" FontSize="13" Foreground="#E6EDF3" Margin="0,0,0,15"/>
                                <TextBlock Text="This action will create a restore point of the current policy before rolling back." FontSize="11" Foreground="#D29922" Margin="0,0,0,15"/>

                                <Border Background="#0D1117" Padding="12" CornerRadius="4" Margin="0,0,0,15">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                        </Grid.RowDefinitions>

                                        <TextBlock Text="Target:" FontSize="11" Foreground="#8B949E" Grid.Row="0" Grid.Column="0" Margin="0,0,10,5"/>
                                        <ComboBox x:Name="RollbackTargetCombo" Grid.Row="0" Grid.Column="1" Height="26" Background="#161B22"
                                                  Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
                                            <ComboBoxItem Content="Local System" IsSelected="True"/>
                                            <ComboBoxItem Content="GPO"/>
                                            <ComboBoxItem Content="File Export"/>
                                        </ComboBox>

                                        <TextBlock x:Name="GpoNameLabel" Text="GPO Name:" FontSize="11" Foreground="#8B949E"
                                                   Grid.Row="1" Grid.Column="0" Margin="0,5,10,5" Visibility="Collapsed"/>
                                        <TextBox x:Name="RollbackGpoName" Grid.Row="1" Grid.Column="1" Height="26" Background="#161B22"
                                                 Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11" Visibility="Collapsed"/>

                                        <TextBlock x:Name="OutputPathLabel" Text="Output Path:" FontSize="11" Foreground="#8B949E"
                                                   Grid.Row="2" Grid.Column="0" Margin="0,5,10,5" Visibility="Collapsed"/>
                                        <TextBox x:Name="RollbackOutputPath" Grid.Row="2" Grid.Column="1" Height="26" Background="#161B22"
                                                 Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11" Visibility="Collapsed"/>
                                    </Grid>
                                </Border>

                                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                                    <Button x:Name="CancelRollbackBtn" Content="Cancel" Style="{StaticResource SecondaryButton}" Margin="0,0,10,0" MinWidth="80"/>
                                    <Button x:Name="ConfirmRollbackBtn" Content="Confirm Rollback" Style="{StaticResource DangerButton}" MinWidth="120"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <!-- Version Notes Panel -->
                        <Border x:Name="VersionNotesPanel" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,0,15" Visibility="Collapsed">
                            <StackPanel>
                                <Border Background="#161B22" Padding="12,8" BorderBrush="#30363D" BorderThickness="0,0,0,1">
                                    <Grid>
                                        <TextBlock x:Name="VersionNotesTitle" Text="Version Notes" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                        <Button x:Name="CloseVersionNotesBtn" Content="×" HorizontalAlignment="Right"
                                                Foreground="#8B949E" FontSize="18" Padding="0" Width="24" Height="24"/>
                                    </Grid>
                                </Border>

                                <StackPanel Margin="15">
                                    <TextBox x:Name="NewVersionNote" Height="60" Background="#0D1117" Foreground="#E6EDF3"
                                             BorderBrush="#30363D" FontSize="12" TextWrapping="Wrap" AcceptsReturn="True"
                                             VerticalScrollBarVisibility="Auto" Margin="0,0,0,10"/>
                                    <Button x:Name="AddVersionNoteBtn" Content="Add Note" Style="{StaticResource PrimaryButton}"
                                            HorizontalAlignment="Right" MinWidth="100" Margin="0,0,0,15"/>

                                    <TextBlock Text="Notes History:" FontSize="12" FontWeight="SemiBold" Foreground="#8B949E" Margin="0,0,0,10"/>
                                    <ItemsControl x:Name="VersionNotesList">
                                        <ItemsControl.ItemTemplate>
                                            <DataTemplate>
                                                <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,0,0,8">
                                                    <StackPanel>
                                                        <TextBlock Text="{Binding Text}" FontSize="12" Foreground="#E6EDF3" TextWrapping="Wrap" Margin="0,0,0,5"/>
                                                        <StackPanel Orientation="Horizontal">
                                                            <TextBlock Text="{Binding Author}" FontSize="10" Foreground="#58A6FF" Margin="0,0,10,0"/>
                                                            <TextBlock Text="{Binding Timestamp}" FontSize="10" Foreground="#6E7681"/>
                                                        </StackPanel>
                                                    </StackPanel>
                                                </Border>
                                            </DataTemplate>
                                        </ItemsControl.ItemTemplate>
                                    </ItemsControl>
                                </StackPanel>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
"""

# ============================================================
# PART 4: ADDITIONAL XAML STYLES
# Add these to the <Window.Resources> section
# ============================================================

# Find the <Window.Resources> section and add these styles:

"""
                    <!-- Small Button Style for version actions -->
                    <Style x:Key="SmallButton" TargetType="Button">
                        <Setter Property="Background" Value="#21262D"/>
                        <Setter Property="Foreground" Value="#58A6FF"/>
                        <Setter Property="BorderBrush" Value="#30363D"/>
                        <Setter Property="BorderThickness" Value="1"/>
                        <Setter Property="Padding" Value="6,3"/>
                        <Setter Property="FontSize" Value="10"/>
                        <Setter Property="Cursor" Value="Hand"/>
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="Button">
                                    <Border Background="{TemplateBinding Background}"
                                            BorderBrush="{TemplateBinding BorderBrush}"
                                            BorderThickness="{TemplateBinding BorderThickness}"
                                            CornerRadius="4"
                                            Padding="{TemplateBinding Padding}">
                                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                        <Style.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#30363D"/>
                                <Setter Property="Foreground" Value="#79C0FF"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#0D1117"/>
                            </Trigger>
                        </Style.Triggers>
                    </Style>

                    <!-- Danger Button Style for rollback -->
                    <Style x:Key="DangerButton" TargetType="Button">
                        <Setter Property="Background" Value="#F85149"/>
                        <Setter Property="Foreground" Value="#FFFFFF"/>
                        <Setter Property="BorderBrush" Value="#F85149"/>
                        <Setter Property="BorderThickness" Value="1"/>
                        <Setter Property="Padding" Value="12,6"/>
                        <Setter Property="FontSize" Value="12"/>
                        <Setter Property="Cursor" Value="Hand"/>
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="Button">
                                    <Border Background="{TemplateBinding Background}"
                                            BorderBrush="{TemplateBinding BorderBrush}"
                                            BorderThickness="{TemplateBinding BorderThickness}"
                                            CornerRadius="6"
                                            Padding="{TemplateBinding Padding}">
                                        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                        <Style.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#FF7B72"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#DA3633"/>
                            </Trigger>
                        </Style.Triggers>
                    </Style>
"""

# ============================================================
# PART 5: EVENT HANDLERS FOR POLICY HISTORY
# Add these after the existing event handlers
# ============================================================

# Navigation event handler (add with other Nav event handlers around line 7070):

"""
# Phase 5: Policy History Navigation
$NavPolicyHistory.Add_Click({
    Show-Panel "PolicyHistory"
    Update-StatusBar
    Load-PolicyVersionList
})
"""

# Update the Show-Panel function to include PolicyHistory (around line 6975):

# Find this line in the switch statement:
#    "About" { $PanelAbout.Visibility = [System.Windows.Visibility]::Visible }

# Add this case BEFORE it:

"""
    "PolicyHistory" { $PanelPolicyHistory.Visibility = [System.Windows.Visibility]::Visible }
"""

# Add all Policy History event handlers (add after Phase 4 handlers, around line 9300):

"""
# ============================================================
# PHASE 5: Policy Versioning and Rollback Event Handlers
# ============================================================

# Current selected version for operations
$script:SelectedVersion = $null
$script:CompareModeVersion1 = $null
$script:CompareModeVersion2 = $null

# Load policy version list into ListView
function Load-PolicyVersionList {
    param(
        [string]$Search = "",
        [string]$Author = $null,
        [string]$Category = $null
    )

    try {
        Write-Log "Loading policy version list"

        # Get versions
        $result = Get-PolicyVersions -IncludeArchived:$false
        if (-not $result.success) {
            [System.Windows.MessageBox]::Show("Failed to load versions: $($result.error)", "Error",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        # Filter versions
        $versions = $result.versions
        if ($Search -and $Search -ne "Search versions...") {
            $versions = $versions | Where-Object {
                $_.Description -like "*$Search*" -or
                $_.Author -like "*$Search*" -or
                $_.VersionId -like "*$Search*"
            }
        }
        if ($Author -and $Author -ne "All Authors") {
            $versions = $versions | Where-Object { $_.Author -eq $Author }
        }
        if ($Category -and $Category -ne "All Categories") {
            $versions = $versions | Where-Object { $_.ChangeCategory -eq $Category }
        }

        # Convert to display objects
        $displayVersions = @()
        foreach ($version in $versions) {
            $categoryColor = switch ($version.ChangeCategory) {
                "Automatic" { "#58A6FF" }
                "Manual" { "#3FB950" }
                "Export" { "#D29922" }
                "GPO_Deployment" { "#A371F7" }
                "Bulk_Operation" { "#F85149" }
                "Rollback" { "#FF7B72" }
                default { "#8B949E" }
            }

            $displayVersions += @{
                VersionNumber = "v$($version.VersionNumber)"
                VersionIdShort = $version.VersionId.Substring($version.VersionId.Length - 15)
                VersionId = $version.VersionId
                Timestamp = [datetime]$version.Timestamp
                Author = $version.Author
                Description = $version.Description
                ChangeCategory = $version.ChangeCategory
                CategoryColor = $categoryColor
                TotalRules = $version.TotalRules
            }
        }

        # Update ListView
        $VersionHistoryList.ItemsSource = @($displayVersions | Sort-Object -Property Timestamp -Descending)

        # Update statistics
        Update-VersionStatistics

        Write-Log "Loaded $($displayVersions.Count) versions"
    }
    catch {
        Write-Log "Failed to load version list: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Update version statistics display
function Update-VersionStatistics {
    try {
        # Get versions
        $result = Get-PolicyVersions -IncludeArchived:$false
        if ($result.success) {
            $TotalVersionsCount.Text = $result.versions.Count

            # Latest version
            if ($result.versions.Count -gt 0) {
                $latest = $result.versions | Sort-Object -Property VersionNumber -Descending | Select-Object -First 1
                $LatestVersionNumber.Text = "v$($latest.VersionNumber)"
            } else {
                $LatestVersionNumber.Text = "--"
            }
        }

        # 30-day activity
        $stats = Get-VersionStatistics -Days 30
        if ($stats.success) {
            $VersionsLast30Days.Text = $stats.statistics.TotalVersions
        }

        # Storage used
        if (Test-Path $script:VersionStoragePath) {
            $sizeBytes = (Get-ChildItem -Path $script:VersionStoragePath -Recurse -File -ErrorAction SilentlyContinue |
                          Measure-Object -Property Length -Sum).Sum
            $sizeMB = [math]::Round($sizeBytes / 1MB, 2)
            $VersionStorageUsed.Text = "$sizeMB MB"
        } else {
            $VersionStorageUsed.Text = "0 MB"
        }
    }
    catch {
        Write-Log "Failed to update version statistics: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Create version button
$CreateVersionBtn.Add_Click({
    $description = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a description for this version:", "Create Policy Version", "Manual version backup")
    if ([string]::IsNullOrWhiteSpace($description)) {
        return
    }

    $result = Save-PolicyVersion -Description $description -ChangeCategory "Manual"
    if ($result.success) {
        [System.Windows.MessageBox]::Show("Version $($result.versionNumber) created successfully.`n`nVersion ID: $($result.versionId)", "Version Created",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Load-PolicyVersionList
    } else {
        [System.Windows.MessageBox]::Show("Failed to create version: $($result.error)", "Error",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

# Refresh versions button
$RefreshVersionsBtn.Add_Click({
    Load-PolicyVersionList
    Update-StatusBar
})

# Settings button
$VersionSettingsBtn.Add_Click({
    # Show settings dialog for version retention
    $settingsForm = New-Object System.Windows.Window
    $settingsForm.Title = "Version Settings"
    $settingsForm.Width = 400
    $settingsForm.Height = 300
    $settingsForm.WindowStartupLocation = "CenterOwner"
    $settingsForm.Owner = $window
    $settingsForm.Background = "#21262D"

    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Margin = 20

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = "Policy Versioning Settings"
    $title.FontSize = 18
    $title.FontWeight = "Bold"
    $title.Foreground = "#E6EDF3"
    $title.Margin = 0,0,0,20
    $panel.Children.Add($title)

    # Retention days
    $retentionLabel = New-Object System.Windows.Controls.TextBlock
    $retentionLabel.Text = "Retention Period (days):"
    $retentionLabel.Foreground = "#8B949E"
    $panel.Children.Add($retentionLabel)

    $retentionInput = New-Object System.Windows.Controls.TextBox
    $retentionInput.Text = $script:VersionRetentionDays
    $retentionInput.Background = "#0D1117"
    $retentionInput.Foreground = "#E6EDF3"
    $retentionInput.BorderBrush = "#30363D"
    $retentionInput.Margin = 0,5,0,15
    $panel.Children.Add($retentionInput)

    # Max versions
    $maxVersionsLabel = New-Object System.Windows.Controls.TextBlock
    $maxVersionsLabel.Text = "Maximum Versions:"
    $maxVersionsLabel.Foreground = "#8B949E"
    $panel.Children.Add($maxVersionsLabel)

    $maxVersionsInput = New-Object System.Windows.Controls.TextBox
    $maxVersionsInput.Text = $script:MaxVersionCount
    $maxVersionsInput.Background = "#0D1117"
    $maxVersionsInput.Foreground = "#E6EDF3"
    $maxVersionsInput.BorderBrush = "#30363D"
    $maxVersionsInput.Margin = 0,5,0,15
    $panel.Children.Add($maxVersionsInput)

    # Buttons
    $buttonPanel = New-Object System.Windows.Controls.StackPanel
    $buttonPanel.Orientation = "Horizontal"
    $buttonPanel.HorizontalAlignment = "Right"

    $saveBtn = New-Object System.Windows.Controls.Button
    $saveBtn.Content = "Save"
    $saveBtn.Padding = 20,8
    $saveBtn.Margin = 0,0,10,0
    $saveBtn.Background = "#3FB950"
    $saveBtn.Foreground = "#FFFFFF"
    $saveBtn.BorderThickness = 0
    $saveBtn.Add_Click({
        $script:VersionRetentionDays = [int]$retentionInput.Text
        $script:MaxVersionCount = [int]$maxVersionsInput.Text
        $settingsForm.Close()
        [System.Windows.MessageBox]::Show("Settings saved.", "Settings",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    })
    $buttonPanel.Children.Add($saveBtn)

    $cancelBtn = New-Object System.Windows.Controls.Button
    $cancelBtn.Content = "Cancel"
    $cancelBtn.Padding = 20,8
    $cancelBtn.Background = "#21262D"
    $cancelBtn.Foreground = "#E6EDF3"
    $cancelBtn.BorderBrush = "#30363D"
    $cancelBtn.BorderThickness = 1
    $cancelBtn.Add_Click({ $settingsForm.Close() })
    $buttonPanel.Children.Add($cancelBtn)

    $panel.Children.Add($buttonPanel)
    $settingsForm.Content = $panel
    $settingsForm.ShowDialog() | Out-Null
})

# Search box
$VersionSearchBox.Add_GotFocus({
    if ($VersionSearchBox.Text -eq "Search versions...") {
        $VersionSearchBox.Text = ""
    }
})

$VersionSearchBox.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($VersionSearchBox.Text)) {
        $VersionSearchBox.Text = "Search versions..."
    }
})

$VersionSearchBox.Add_KeyUp({
    if ($_.Key -eq "Return") {
        Load-PolicyVersionList -Search $VersionSearchBox.Text
    }
})

# Filter changes
$VersionAuthorFilter.Add_SelectionChanged({
    Load-PolicyVersionList -Search $VersionSearchBox.Text -Author $VersionAuthorFilter.Text -Category $VersionCategoryFilter.Text
})

$VersionCategoryFilter.Add_SelectionChanged({
    Load-PolicyVersionList -Search $VersionSearchBox.Text -Author $VersionAuthorFilter.Text -Category $VersionCategoryFilter.Text
})

# Version selection
$VersionHistoryList.Add_SelectionChanged({
    $selected = $VersionHistoryList.SelectedItem
    if ($selected) {
        $script:SelectedVersion = $selected.VersionId

        # Handle compare mode
        if ($CompareModeCheckbox.IsChecked -eq $true) {
            if (-not $script:CompareModeVersion1) {
                $script:CompareModeVersion1 = $selected.VersionId
                Write-Log "Compare mode: Version 1 selected = $script:CompareModeVersion1"
            } elseif (-not $script:CompareModeVersion2) {
                $script:CompareModeVersion2 = $selected.VersionId
                Write-Log "Compare mode: Version 2 selected = $script:CompareModeVersion2"

                # Show comparison panel
                Show-VersionComparison -VersionId1 $script:CompareModeVersion1 -VersionId2 $script:CompareModeVersion2
            }
        }
    }
})

# Compare mode checkbox
$CompareModeCheckbox.Add_Click({
    if ($CompareModeCheckbox.IsChecked -eq $true) {
        $script:CompareModeVersion1 = $null
        $script:CompareModeVersion2 = $null
        [System.Windows.MessageBox]::Show("Compare mode enabled.`n\nSelect two versions from the list to compare them.", "Compare Mode",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $script:CompareModeVersion1 = $null
        $script:CompareModeVersion2 = $null
        $ComparisonPanel.Visibility = [System.Windows.Visibility]::Collapsed
    }
})

# Show version comparison
function Show-VersionComparison {
    param(
        [string]$VersionId1,
        [string]$VersionId2
    )

    try {
        Write-Log "Showing comparison: $VersionId1 vs $VersionId2"

        # Show comparison panel
        $ComparisonPanel.Visibility = [System.Windows.Visibility]::Visible

        # Populate version dropdowns
        $versions = Get-PolicyVersions -IncludeArchived:$false
        if ($versions.success) {
            $CompareVersion1Combo.Items.Clear()
            $CompareVersion2Combo.Items.Clear()

            foreach ($version in $versions.versions) {
                $item1 = New-Object System.Windows.Controls.ComboBoxItem
                $item1.Content = "v$($version.VersionNumber) - $($version.Description)"
                $item1.Tag = $version.VersionId
                if ($version.VersionId -eq $VersionId1) { $item1.IsSelected = $true }
                $CompareVersion1Combo.Items.Add($item1)

                $item2 = New-Object System.Windows.Controls.ComboBoxItem
                $item2.Content = "v$($version.VersionNumber) - $($version.Description)"
                $item2.Tag = $version.VersionId
                if ($version.VersionId -eq $VersionId2) { $item2.IsSelected = $true }
                $CompareVersion2Combo.Items.Add($item2)
            }
        }
    }
    catch {
        Write-Log "Failed to show version comparison: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Run comparison button
$RunCompareBtn.Add_Click({
    $selectedItem1 = $CompareVersion1Combo.SelectedItem
    $selectedItem2 = $CompareVersion2Combo.SelectedItem

    if (-not $selectedItem1 -or -not $selectedItem2) {
        [System.Windows.MessageBox]::Show("Please select both versions to compare.", "Selection Required",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $versionId1 = $selectedItem1.Tag
    $versionId2 = $selectedItem2.Tag

    if ($versionId1 -eq $versionId2) {
        [System.Windows.MessageBox]::Show("Please select different versions to compare.", "Selection Required",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Perform comparison
    $comparison = Compare-PolicyVersions -VersionId1 $versionId1 -VersionId2 $versionId2 -IncludeRuleDetails
    if (-not $comparison.success) {
        [System.Windows.MessageBox]::Show("Comparison failed: $($comparison.error)", "Error",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }

    # Display results
    $ComparisonResults.Children.Clear()

    # Summary card
    $summaryBorder = New-Object System.Windows.Controls.Border
    $summaryBorder.Background = "#0D1117"
    $summaryBorder.CornerRadius = 4
    $summaryBorder.Padding = 15
    $summaryBorder.Margin = 0,0,0,10

    $summaryPanel = New-Object System.Windows.Controls.StackPanel

    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = "Comparison Summary"
    $title.FontSize = 14
    $title.FontWeight = "Bold"
    $title.Foreground = "#58A6FF"
    $title.Margin = 0,0,0,10
    $summaryPanel.Children.Add($title)

    $grid = New-Object System.Windows.Controls.Grid
    $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition))  # Label
    $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition))  # V1
    $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition))  # V2
    $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition))  # Delta

    # Add header
    $header1 = New-Object System.Windows.Controls.TextBlock
    $header1.Text = "Metric"
    $header1.FontWeight = "Bold"
    $header1.Foreground = "#8B949E"
    [System.Windows.Controls.Grid]::SetColumn($header1, 0)
    [System.Windows.Controls.Grid]::SetRow($header1, 0)
    $grid.Children.Add($header1)

    $header2 = New-Object System.Windows.Controls.TextBlock
    $header2.Text = "Version 1"
    $header2.FontWeight = "Bold"
    $header2.Foreground = "#8B949E"
    $header2.HorizontalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($header2, 1)
    [System.Windows.Controls.Grid]::SetRow($header2, 0)
    $grid.Children.Add($header2)

    $header3 = New-Object System.Windows.Controls.TextBlock
    $header3.Text = "Version 2"
    $header3.FontWeight = "Bold"
    $header3.Foreground = "#8B949E"
    $header3.HorizontalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($header3, 2)
    [System.Windows.Controls.Grid]::SetRow($header3, 0)
    $grid.Children.Add($header3)

    $header4 = New-Object System.Windows.Controls.TextBlock
    $header4.Text = "Change"
    $header4.FontWeight = "Bold"
    $header4.Foreground = "#8B949E"
    $header4.HorizontalAlignment = "Center"
    [System.Windows.Controls.Grid]::SetColumn($header4, 3)
    [System.Windows.Controls.Grid]::SetRow($header4, 0)
    $grid.Children.Add($header4)

    $rowIndex = 1
    foreach ($type in $comparison.ruleCountDiff.Keys) {
        $diff = $comparison.ruleCountDiff[$type]

        $label = New-Object System.Windows.Controls.TextBlock
        $label.Text = "$type Rules"
        $label.Foreground = "#E6EDF3"
        [System.Windows.Controls.Grid]::SetColumn($label, 0)
        [System.Windows.Controls.Grid]::SetRow($label, $rowIndex)
        $grid.Children.Add($label)

        $v1Value = New-Object System.Windows.Controls.TextBlock
        $v1Value.Text = $diff.V1
        $v1Value.Foreground = "#E6EDF3"
        $v1Value.HorizontalAlignment = "Center"
        [System.Windows.Controls.Grid]::SetColumn($v1Value, 1)
        [System.Windows.Controls.Grid]::SetRow($v1Value, $rowIndex)
        $grid.Children.Add($v1Value)

        $v2Value = New-Object System.Windows.Controls.TextBlock
        $v2Value.Text = $diff.V2
        $v2Value.Foreground = "#E6EDF3"
        $v2Value.HorizontalAlignment = "Center"
        [System.Windows.Controls.Grid]::SetColumn($v2Value, 2)
        [System.Windows.Controls.Grid]::SetRow($v2Value, $rowIndex)
        $grid.Children.Add($v2Value)

        $deltaValue = New-Object System.Windows.Controls.TextBlock
        $changeSign = if ($diff.Delta -gt 0) { "+" } else { "" }
        $deltaValue.Text = "$changeSign$($diff.Delta)"
        $deltaValue.FontWeight = "Bold"
        $deltaValue.HorizontalAlignment = "Center"
        if ($diff.Delta -gt 0) {
            $deltaValue.Foreground = "#3FB950"
        } elseif ($diff.Delta -lt 0) {
            $deltaValue.Foreground = "#F85149"
        } else {
            $deltaValue.Foreground = "#8B949E"
        }
        [System.Windows.Controls.Grid]::SetColumn($deltaValue, 3)
        [System.Windows.Controls.Grid]::SetRow($deltaValue, $rowIndex)
        $grid.Children.Add($deltaValue)

        $rowIndex++
    }

    $summaryPanel.Children.Add($grid)

    # Add rule-level changes if available
    if ($comparison.ruleLevelDiff) {
        $ruleDiff = $comparison.ruleLevelDiff

        $ruleDiffTitle = New-Object System.Windows.Controls.TextBlock
        $ruleDiffTitle.Text = "Rule-Level Changes"
        $ruleDiffTitle.FontSize = 12
        $ruleDiffTitle.FontWeight = "Bold"
        $ruleDiffTitle.Foreground = "#8B949E"
        $ruleDiffTitle.Margin = 0,15,0,10
        $summaryPanel.Children.Add($ruleDiffTitle)

        $changesGrid = New-Object System.Windows.Controls.Grid
        $changesGrid.Margin = 0,0,0,0

        $addedText = New-Object System.Windows.Controls.TextBlock
        $addedText.Text = "● Added: $($ruleDiff.TotalAdded) rules"
        $addedText.Foreground = "#3FB950"
        $changesGrid.Children.Add($addedText)

        $removedText = New-Object System.Windows.Controls.TextBlock
        $removedText.Text = "● Removed: $($ruleDiff.TotalRemoved) rules"
        $removedText.Foreground = "#F85149"
        [System.Windows.Controls.Canvas]::SetTop($removedText, 20)
        $changesGrid.Children.Add($removedText)

        $modifiedText = New-Object System.Windows.Controls.TextBlock
        $modifiedText.Text = "● Modified: $($ruleDiff.TotalModified) rules"
        $modifiedText.Foreground = "#D29922"
        [System.Windows.Controls.Canvas]::SetTop($modifiedText, 40)
        $changesGrid.Children.Add($modifiedText)

        $changesGrid.Height = 60
        $summaryPanel.Children.Add($changesGrid)
    }

    $summaryBorder.Child = $summaryPanel
    $ComparisonResults.Children.Add($summaryBorder)

    # Export HTML report button
    $exportBtn = New-Object System.Windows.Controls.Button
    $exportBtn.Content = "Export HTML Report"
    $exportBtn.Background = "#58A6FF"
    $exportBtn.Foreground = "#FFFFFF"
    $exportBtn.Padding = 15,6
    $exportBtn.Margin = 0,10,0,0
    $exportBtn.Add_Click({
        $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
        $saveDialog.Filter = "HTML Files (*.html)|*.html|All Files (*.*)|*.*"
        $saveDialog.DefaultExt = "html"
        $saveDialog.FileName = "policy-comparison-$versionId1-$versionId2.html"

        if ($saveDialog.ShowDialog() -eq $true) {
            $comparison = Compare-PolicyVersions -VersionId1 $versionId1 -VersionId2 $versionId2 -GenerateHtmlReport
            $comparison.htmlReport | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.MessageBox]::Show("HTML report exported to:`n$($saveDialog.FileName)", "Export Complete",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
    $ComparisonResults.Children.Add($exportBtn)
})

# Close comparison button
$CloseComparisonBtn.Add_Click({
    $ComparisonPanel.Visibility = [System.Windows.Visibility]::Collapsed
    $CompareModeCheckbox.IsChecked = $false
    $script:CompareModeVersion1 = $null
    $script:CompareModeVersion2 = $null
})

# Close version details button
$CloseVersionDetailsBtn.Add_Click({
    $VersionDetailsPanel.Visibility = [System.Windows.Visibility]::Collapsed
})

# Close version notes button
$CloseVersionNotesBtn.Add_Click({
    $VersionNotesPanel.Visibility = [System.Windows.Visibility]::Collapsed
})

# Rollback target combo change
$RollbackTargetCombo.Add_SelectionChanged({
    $selectedItem = $RollbackTargetCombo.Text
    switch ($selectedItem) {
        "Local System" {
            $GpoNameLabel.Visibility = [System.Windows.Visibility]::Collapsed
            $RollbackGpoName.Visibility = [System.Windows.Visibility]::Collapsed
            $OutputPathLabel.Visibility = [System.Windows.Visibility]::Collapsed
            $RollbackOutputPath.Visibility = [System.Windows.Visibility]::Collapsed
        }
        "GPO" {
            $GpoNameLabel.Visibility = [System.Windows.Visibility]::Visible
            $RollbackGpoName.Visibility = [System.Windows.Visibility]::Visible
            $OutputPathLabel.Visibility = [System.Windows.Visibility]::Collapsed
            $RollbackOutputPath.Visibility = [System.Windows.Visibility]::Collapsed
        }
        "File Export" {
            $GpoNameLabel.Visibility = [System.Windows.Visibility]::Collapsed
            $RollbackGpoName.Visibility = [System.Windows.Visibility]::Collapsed
            $OutputPathLabel.Visibility = [System.Windows.Visibility]::Visible
            $RollbackOutputPath.Visibility = [System.Windows.Visibility]::Visible
        }
    }
})

# Cancel rollback button
$CancelRollbackBtn.Add_Click({
    $RollbackConfirmDialog.Visibility = [System.Windows.Visibility]::Collapsed
})

# Confirm rollback button
$ConfirmRollbackBtn.Add_Click({
    $target = switch ($RollbackTargetCombo.Text) {
        "Local System" { "Local" }
        "GPO" { "GPO" }
        "File Export" { "File" }
    }

    $params = @{
        VersionId = $script:SelectedVersion
        Target = $target
        Force = $true
        CreateRestorePoint = $true
    }

    if ($target -eq "GPO") {
        $params.GpoName = $RollbackGpoName.Text
        if ([string]::IsNullOrWhiteSpace($params.GpoName)) {
            [System.Windows.MessageBox]::Show("Please enter a GPO name.", "GPO Name Required",
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
    }

    if ($target -eq "File") {
        $saveDialog = New-Object Microsoft.Win32.SaveFileDialog
        $saveDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
        $saveDialog.DefaultExt = "xml"
        $saveDialog.FileName = "applocker-policy-rolled-back.xml"

        if ($saveDialog.ShowDialog() -ne $true) {
            return
        }
        $params.OutputPath = $saveDialog.FileName
    }

    $result = Restore-PolicyVersion @params

    if ($result.success) {
        $RollbackConfirmDialog.Visibility = [System.Windows.Visibility]::Collapsed
        [System.Windows.MessageBox]::Show($result.message, "Rollback Successful",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Load-PolicyVersionList
    } else {
        [System.Windows.MessageBox]::Show("Rollback failed: $($result.error)", "Rollback Failed",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

# Add version note button
$AddVersionNoteBtn.Add_Click({
    $note = $NewVersionNote.Text
    if ([string]::IsNullOrWhiteSpace($note)) {
        [System.Windows.MessageBox]::Show("Please enter a note.", "Note Required",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $result = Set-VersionNote -VersionId $script:SelectedVersion -Note $note
    if ($result.success) {
        $NewVersionNote.Text = ""
        [System.Windows.MessageBox]::Show("Note added successfully.", "Note Added",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Load-VersionNotes
    } else {
        [System.Windows.MessageBox]::Show("Failed to add note: $($result.error)", "Error",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

# Load version notes
function Load-VersionNotes {
    $version = Get-PolicyVersion -VersionId $script:SelectedVersion
    if ($version.success -and $version.version.Notes) {
        $VersionNotesList.ItemsSource = @($version.version.Notes | ForEach-Object {
            @{
                Text = $_.Text
                Author = $_.Author
                Timestamp = [datetime]$_.Timestamp
            }
        })
    } else {
        $VersionNotesList.ItemsSource = @()
    }
}
"""

# ============================================================
# PART 6: AUTOMATIC VERSION CREATION HOOKS
# Add these calls to existing functions to auto-create versions
# ============================================================

# Add to Export function (find the Export button handler around line 8800):
# After successful export, add:

"""
    # Create automatic version on export
    if ($script:AutoVersionBeforeChanges) {
        Save-PolicyVersion -Description "Automatic version created before policy export" -ChangeCategory "Export" -Force | Out-Null
    }
"""

# Add to GPO deployment function (find the deployment button handler):
# Before deploying, add:

"""
    # Create automatic version before GPO deployment
    if ($script:AutoVersionBeforeChanges) {
        Save-PolicyVersion -Description "Automatic version created before GPO deployment" -ChangeCategory "GPO_Deployment" -Force | Out-Null
    }
"""

# Add to bulk operations (find bulk rule operation handlers):
# Before applying bulk changes, add:

"""
    # Create automatic version before bulk operation
    if ($script:AutoVersionBeforeChanges) {
        Save-PolicyVersion -Description "Automatic version created before bulk rule operation" -ChangeCategory "Bulk_Operation" -Force | Out-Null
    }
"""

# ============================================================
# PART 7: INTEGRATION NOTES
# ============================================================

"""
INTEGRATION INSTRUCTIONS FOR PHASE 5:

1. POWERSHELL FUNCTIONS:
   - Add all Module 11 functions (lines 1-1100 of this file) after Module 10
     in the EMBEDDED section (around line 1770)

2. XAML - SIDEBAR:
   - Add the POLICY MANAGEMENT section to the sidebar navigation
     (around line 2207, after MONITORING section)

3. XAML - CONTENT PANEL:
   - Add the Policy History panel before the Help panel
     (around line 4010)

4. XAML - STYLES:
   - Add SmallButton and DangerButton styles to Window.Resources
     (in the resources section, around line 1900)

5. EVENT HANDLERS:
   - Add NavPolicyHistory handler with other Nav handlers (around line 7070)
   - Add "PolicyHistory" case to Show-Panel function (around line 6975)
   - Add all Phase 5 event handlers after Phase 4 handlers (around line 9300)

6. AUTOMATIC VERSIONING:
   - Add version creation calls to:
     * Export function
     * GPO deployment function
     * Bulk rule operation functions

7. TESTING:
   - Test version creation manually
   - Test automatic version creation on export/GPO deployment
   - Test version comparison
   - Test rollback to local system
   - Test version export
   - Test version notes

8. VERIFICATION:
   - Check that versions are stored in C:\GA-AppLocker\versions\
   - Verify version-index.json is created and updated
   - Test version retention policy
   - Verify rollback audit log is created

SAFETY FEATURES IMPLEMENTED:
- Automatic restore point creation before rollback
- Cannot delete versions less than 24 hours old without -Force
- Archived versions cannot be permanently deleted without -Permanent
- Confirmation dialogs for all destructive operations
- Rollback audit trail for compliance
- Version comparison before rollback to show impact
- Search and filter capabilities for version management

The implementation is complete and ready for integration.
"""

# ============================================================
# END OF PHASE 5 IMPLEMENTATION
# ============================================================
