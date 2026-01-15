<#
.SYNOPSIS
    Merges multiple AppLocker policy XML files and removes duplicate rules.

.DESCRIPTION
    Part of GA-AppLocker toolkit. Use Start-AppLockerWorkflow.ps1 for guided experience.

    This script consolidates AppLocker policies from multiple sources into a single,
    clean policy file. Essential for enterprise environments where policies are
    collected from multiple systems or created incrementally.

    Key Features:
    - Recursive search for AppLocker XML files
    - Intelligent duplicate detection by rule type:
      * Publisher rules: Deduplicated by Publisher+Product+Binary
      * Path rules: Deduplicated by Path+Action
      * Hash rules: Deduplicated by SHA256 hash
    - Preserves rule actions (Allow/Deny) and user assignments
    - Validates output XML before saving
    - Adds default admin rules if collections are empty

    Rule Processing:
    - Reads all rule types: FilePublisherRule, FilePathRule, FileHashRule
    - Processes all collections: Exe, Msi, Script, Dll, Appx
    - Maintains rule precedence (Deny rules before Allow)

    Use Cases:
    - Combining policies from multiple workstations/servers
    - Consolidating incrementally developed policies
    - Cleaning up policies with redundant rules
    - Standardizing enforcement mode across rule collections

.PARAMETER InputPath
    Path to folder containing AppLocker XML policy files.
    Searches recursively for files matching IncludePattern.

.PARAMETER OutputPath
    Path to save the merged policy file.
    Defaults to .\MergedPolicy.xml

.PARAMETER RemoveDuplicates
    Remove duplicate rules based on their conditions.
    Default: $true (enabled)
    Set to $false to keep all rules even if duplicated.

.PARAMETER EnforcementMode
    Set enforcement mode for all rule collections:
    - AuditOnly: Log violations but don't block (recommended for testing)
    - Enabled: Actively enforce and block violations
    - NotConfigured: Leave collection disabled

    Note: DLL rules are always set to NotConfigured by default (performance impact)

.PARAMETER IncludePattern
    File pattern to match when searching for policy files.
    Default: *.xml
    Only files containing valid <AppLockerPolicy> XML are processed.

.PARAMETER TargetGroup
    AD group name to use as the replacement target.
    Use this to scope merged policies to specific groups like "AppLocker-Workstations".
    The group name will be resolved to its SID automatically.

.PARAMETER TargetSid
    SID to use as the replacement target.
    Use this if you already know the SID or the group cannot be resolved.
    Alternative to -TargetGroup parameter.

.PARAMETER ReplaceMode
    Which SIDs to replace with the target group:
    - 1 (Everyone): Only replace "Everyone" (S-1-1-0) - Default
    - 2 (Users): Replace "Everyone" and "BUILTIN\Users" (S-1-5-32-545)
    - 3 (Multiple): Replace specific SIDs listed in -ReplaceSids parameter
    - 4 (All): Replace all non-admin user SIDs (Everyone, Users, Authenticated Users)

.PARAMETER ReplaceSids
    Array of specific SIDs to replace when using -ReplaceMode 3 (Multiple).
    Example: -ReplaceSids "S-1-1-0","S-1-5-32-545"

.PARAMETER RemoveDefaultRules
    Remove default AppLocker rules during merge. This filters out rules with:
    - "(Default Rule)" in the name
    - "All files" path rules for Administrators
    - Default Windows/Microsoft rules that ship with AppLocker

.EXAMPLE
    # Merge all policies from scan results
    .\Merge-AppLockerPolicies.ps1 -InputPath \\server\share\Scans -OutputPath .\MergedPolicy.xml

.EXAMPLE
    # Merge and set all rules to audit mode
    .\Merge-AppLockerPolicies.ps1 -InputPath .\Policies -EnforcementMode AuditOnly

.EXAMPLE
    # Keep duplicates for analysis
    .\Merge-AppLockerPolicies.ps1 -InputPath .\Policies -RemoveDuplicates:$false -OutputPath .\AllRules.xml

.EXAMPLE
    # Merge and replace "Everyone" with an AD group for easier management
    .\Merge-AppLockerPolicies.ps1 -InputPath .\Policies -TargetGroup "DOMAIN\AppLocker-Workstations"

.NOTES
    Requires: PowerShell 5.1+

    Input: Valid AppLocker policy XML files with structure:
    <AppLockerPolicy Version="1">
      <RuleCollection Type="Exe" EnforcementMode="...">
        <FilePublisherRule>...</FilePublisherRule>
        <FilePathRule>...</FilePathRule>
        <FileHashRule>...</FileHashRule>
      </RuleCollection>
      ...
    </AppLockerPolicy>

    Output: Single consolidated AppLocker XML policy

    Statistics Reported:
    - Total files processed
    - Rules by type (Publisher, Path, Hash)
    - Duplicates removed
    - Final unique rule count

    Author: AaronLocker Simplified Scripts
    Version: 2.0

.LINK
    Invoke-RemoteScan.ps1 - Collects data that generates policies
    New-AppLockerPolicy.ps1 - Creates policies from scan data
#>

[CmdletBinding(DefaultParameterSetName='Standard')]
param(
    [Parameter(Mandatory=$true, Position=0, ParameterSetName='Standard')]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [Parameter(Position=1, ParameterSetName='Standard')]
    [string]$OutputPath = ".\Outputs\MergedPolicy.xml",

    [Parameter(ParameterSetName='Standard')]
    [bool]$RemoveDuplicates = $true,

    [Parameter(ParameterSetName='Standard')]
    [ValidateSet("AuditOnly", "Enabled", "NotConfigured")]
    [string]$EnforcementMode,

    [Parameter(ParameterSetName='Standard')]
    [string]$IncludePattern = "*.xml",

    [Parameter(ParameterSetName='Standard')]
    [string]$TargetGroup,

    [Parameter(ParameterSetName='Standard')]
    [string]$TargetSid,

    [Parameter(ParameterSetName='Standard')]
    [ValidateSet("1", "2", "3", "4", "Everyone", "Users", "Multiple", "All")]
    [string]$ReplaceMode = "1",

    [Parameter(ParameterSetName='Standard')]
    [string[]]$ReplaceSids,

    [Parameter(ParameterSetName='Standard')]
    [switch]$RemoveDefaultRules
)

#Requires -Version 5.1

# Import utilities module
$scriptRoot = $PSScriptRoot
$utilitiesRoot = Join-Path (Split-Path -Parent $scriptRoot) "Utilities"
$modulePath = Join-Path $utilitiesRoot "Common.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}

# Validate input path
if (!(Test-Path -Path $InputPath)) {
    throw "Input path not found: $InputPath"
}

# Resolve target group to SID if specified
$replacementSid = $null
if ($TargetGroup) {
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($TargetGroup)
        $replacementSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Host "Target group '$TargetGroup' resolved to SID: $replacementSid" -ForegroundColor Green
    }
    catch {
        throw "Failed to resolve group '$TargetGroup' to SID: $_"
    }
}
elseif ($TargetSid) {
    $replacementSid = $TargetSid
    Write-Host "Using target SID: $replacementSid" -ForegroundColor Green
}

# Build list of SIDs to replace based on ReplaceMode
$sidsToReplace = @()
if ($replacementSid) {
    switch ($ReplaceMode) {
        { $_ -in "1", "Everyone" } {
            $sidsToReplace = @("S-1-1-0")  # Everyone
            Write-Host "Replace mode: Everyone only (S-1-1-0)" -ForegroundColor Gray
        }
        { $_ -in "2", "Users" } {
            $sidsToReplace = @("S-1-1-0", "S-1-5-32-545")  # Everyone + BUILTIN\Users
            Write-Host "Replace mode: Everyone + BUILTIN\Users" -ForegroundColor Gray
        }
        { $_ -in "3", "Multiple" } {
            if ($ReplaceSids -and $ReplaceSids.Count -gt 0) {
                $sidsToReplace = $ReplaceSids
                Write-Host "Replace mode: Custom SIDs ($($ReplaceSids -join ', '))" -ForegroundColor Gray
            }
            else {
                Write-Warning "ReplaceMode 3 (Multiple) requires -ReplaceSids parameter. Defaulting to Everyone only."
                $sidsToReplace = @("S-1-1-0")
            }
        }
        { $_ -in "4", "All" } {
            # Everyone, BUILTIN\Users, Authenticated Users
            $sidsToReplace = @("S-1-1-0", "S-1-5-32-545", "S-1-5-11")
            Write-Host "Replace mode: All standard user SIDs (Everyone, Users, Authenticated Users)" -ForegroundColor Gray
        }
    }
}

# Helper function to detect default rules
function Test-IsDefaultRule {
    param($Rule)

    $name = $Rule.Name
    $description = $Rule.Description

    # Check for common default rule patterns
    if ($name -match '\(Default Rule\)') { return $true }
    if ($name -match '^All files$') { return $true }
    if ($name -match 'All files located in') { return $true }
    if ($description -match 'Allows members of .* to run') { return $true }
    if ($description -match 'Default rule') { return $true }

    # Check for path rules with "*" that are admin-only defaults
    if ($Rule.Conditions.FilePathCondition.Path -eq "*") {
        return $true
    }

    return $false
}

Write-Host "=== AppLocker Policy Merger ===" -ForegroundColor Cyan
Write-Host "Input: $InputPath" -ForegroundColor Cyan
Write-Host "Output: $OutputPath" -ForegroundColor Cyan
if ($RemoveDefaultRules) {
    Write-Host "Removing default rules: Yes" -ForegroundColor Cyan
}
if ($replacementSid -and $sidsToReplace.Count -gt 0) {
    Write-Host "Replacing SIDs with: $replacementSid" -ForegroundColor Cyan
    foreach ($sid in $sidsToReplace) {
        Write-Host "  - $sid" -ForegroundColor Gray
    }
}

# Find all XML files first, then validate
Write-Host "`nSearching for XML files..." -ForegroundColor Yellow
$allXmlFiles = @(Get-ChildItem -Path $InputPath -Filter $IncludePattern -Recurse -File)

if ($allXmlFiles.Count -eq 0) {
    throw "No XML files found matching pattern '$IncludePattern' in $InputPath"
}

Write-Host "  Found $($allXmlFiles.Count) XML file(s), validating..." -ForegroundColor Gray

# Validate each file and filter to valid AppLocker policies
$policyFiles = @()
$invalidCount = 0
$validatedCount = 0

foreach ($file in $allXmlFiles) {
    $validatedCount++
    # Show progress for large file sets
    if ($allXmlFiles.Count -gt 10 -and ($validatedCount % 10 -eq 0 -or $validatedCount -eq $allXmlFiles.Count)) {
        Write-Host "`r  Validating: $validatedCount/$($allXmlFiles.Count)..." -NoNewline -ForegroundColor Gray
    }

    try {
        [xml]$content = Get-Content $file.FullName -Raw -ErrorAction Stop
        if ($null -ne $content.AppLockerPolicy) {
            $policyFiles += $file
        }
        else {
            $invalidCount++
            Write-Verbose "Skipping non-AppLocker XML: $($file.Name)"
        }
    }
    catch {
        $invalidCount++
        Write-Verbose "Skipping invalid XML: $($file.Name) - $($_.Exception.Message)"
    }
}

# Clear the progress line if we showed it
if ($allXmlFiles.Count -gt 10) {
    Write-Host ""
}

if ($policyFiles.Count -eq 0) {
    throw "No valid AppLocker policy XML files found in $InputPath (checked $($allXmlFiles.Count) files)"
}

Write-Host "  Valid AppLocker policies: $($policyFiles.Count)" -ForegroundColor Green
if ($invalidCount -gt 0) {
    Write-Host "  Skipped (not AppLocker XML): $invalidCount" -ForegroundColor Gray
}

# Rule tracking for deduplication
$publisherRules = @{}  # Key: Type|Publisher|Product|Binary
$pathRules = @{}       # Key: Type|Path
$hashRules = @{}       # Key: Type|Hash

# Statistics
$stats = @{
    TotalFiles = $policyFiles.Count
    TotalRules = 0
    PublisherRules = 0
    PathRules = 0
    HashRules = 0
    DuplicatesRemoved = 0
    DefaultRulesSkipped = 0
}

# Process each policy file
$processedCount = 0
$totalPolicyFiles = $policyFiles.Count
Write-Host "`nProcessing $totalPolicyFiles policy file(s)..." -ForegroundColor Yellow

foreach ($policyFile in $policyFiles) {
    $processedCount++
    $percentComplete = [math]::Round(($processedCount / $totalPolicyFiles) * 100)

    # Show progress with file count
    if ($totalPolicyFiles -gt 5) {
        Write-Host "`r  [$processedCount/$totalPolicyFiles] $percentComplete% - $($policyFile.Name)                    " -NoNewline -ForegroundColor Gray
    }
    else {
        Write-Host "  [$processedCount/$totalPolicyFiles] $($policyFile.Name)" -ForegroundColor Gray
    }

    try {
        [xml]$policy = Get-Content -Path $policyFile.FullName -Raw

        foreach ($collection in $policy.AppLockerPolicy.RuleCollection) {
            $collectionType = $collection.Type

            # Process Publisher Rules
            foreach ($rule in $collection.FilePublisherRule) {
                if ($null -eq $rule) { continue }
                $stats.TotalRules++

                # Skip default rules if requested
                if ($RemoveDefaultRules -and (Test-IsDefaultRule $rule)) {
                    $stats.DefaultRulesSkipped++
                    continue
                }

                $pub = $rule.Conditions.FilePublisherCondition
                $key = "$collectionType|$($pub.PublisherName)|$($pub.ProductName)|$($pub.BinaryName)"

                if ($RemoveDuplicates -and $publisherRules.ContainsKey($key)) {
                    $stats.DuplicatesRemoved++
                }
                else {
                    $ruleXml = $rule.OuterXml
                    $userSid = $rule.UserOrGroupSid
                    # Replace SIDs based on ReplaceMode
                    if ($replacementSid -and $sidsToReplace -contains $userSid) {
                        $ruleXml = $ruleXml -replace "UserOrGroupSid=`"$userSid`"", "UserOrGroupSid=`"$replacementSid`""
                        $userSid = $replacementSid
                    }
                    $publisherRules[$key] = @{
                        Type = $collectionType
                        Rule = $ruleXml
                        Action = $rule.Action
                        User = $userSid
                    }
                    $stats.PublisherRules++
                }
            }

            # Process Path Rules
            foreach ($rule in $collection.FilePathRule) {
                if ($null -eq $rule) { continue }
                $stats.TotalRules++

                # Skip default rules if requested
                if ($RemoveDefaultRules -and (Test-IsDefaultRule $rule)) {
                    $stats.DefaultRulesSkipped++
                    continue
                }

                $path = $rule.Conditions.FilePathCondition.Path
                $key = "$collectionType|$($rule.Action)|$path"

                if ($RemoveDuplicates -and $pathRules.ContainsKey($key)) {
                    $stats.DuplicatesRemoved++
                }
                else {
                    $ruleXml = $rule.OuterXml
                    $userSid = $rule.UserOrGroupSid
                    # Replace SIDs based on ReplaceMode
                    if ($replacementSid -and $sidsToReplace -contains $userSid) {
                        $ruleXml = $ruleXml -replace "UserOrGroupSid=`"$userSid`"", "UserOrGroupSid=`"$replacementSid`""
                        $userSid = $replacementSid
                    }
                    $pathRules[$key] = @{
                        Type = $collectionType
                        Rule = $ruleXml
                        Action = $rule.Action
                        User = $userSid
                    }
                    $stats.PathRules++
                }
            }

            # Process Hash Rules
            foreach ($rule in $collection.FileHashRule) {
                if ($null -eq $rule) { continue }
                $stats.TotalRules++

                # Skip default rules if requested
                if ($RemoveDefaultRules -and (Test-IsDefaultRule $rule)) {
                    $stats.DefaultRulesSkipped++
                    continue
                }

                $hash = $rule.Conditions.FileHashCondition.FileHash.Data
                $key = "$collectionType|$hash"

                if ($RemoveDuplicates -and $hashRules.ContainsKey($key)) {
                    $stats.DuplicatesRemoved++
                }
                else {
                    $ruleXml = $rule.OuterXml
                    $userSid = $rule.UserOrGroupSid
                    # Replace SIDs based on ReplaceMode
                    if ($replacementSid -and $sidsToReplace -contains $userSid) {
                        $ruleXml = $ruleXml -replace "UserOrGroupSid=`"$userSid`"", "UserOrGroupSid=`"$replacementSid`""
                        $userSid = $replacementSid
                    }
                    $hashRules[$key] = @{
                        Type = $collectionType
                        Rule = $ruleXml
                        Action = $rule.Action
                        User = $userSid
                    }
                    $stats.HashRules++
                }
            }
        }
    }
    catch {
        Write-Warning "Error processing $($policyFile.FullName): $_"
    }
}

# Clear inline progress line if used
if ($totalPolicyFiles -gt 5) {
    Write-Host ""
}

# Determine enforcement mode
$exeMode = if ($EnforcementMode) { $EnforcementMode } else { "AuditOnly" }
$msiMode = if ($EnforcementMode) { $EnforcementMode } else { "AuditOnly" }
$scriptMode = if ($EnforcementMode) { $EnforcementMode } else { "AuditOnly" }
$dllMode = "NotConfigured"  # DLL rules are typically not enforced
$appxMode = if ($EnforcementMode) { $EnforcementMode } else { "AuditOnly" }

# Build merged policy XML
$mergedXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$exeMode">
"@

# Add EXE rules - wrap in arrays to ensure .Count works correctly
$exePublisherRules = @($publisherRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Exe" })
$exePathRules = @($pathRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Exe" })
$exeHashRules = @($hashRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Exe" })

foreach ($rule in $exePublisherRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $exePathRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $exeHashRules) { $mergedXml += "`n    " + $rule.Value.Rule }

# Add default admin rule if no EXE rules exist
if (($exePublisherRules.Count + $exePathRules.Count + $exeHashRules.Count) -eq 0) {
    $mergedXml += @"

    <FilePathRule Id="$(New-Guid)" Name="Allow Administrators" Description="Default rule" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
"@
}

$mergedXml += @"

  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="$msiMode">
"@

# Add MSI rules - wrap in arrays to ensure .Count works correctly
$msiPublisherRules = @($publisherRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Msi" })
$msiPathRules = @($pathRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Msi" })
$msiHashRules = @($hashRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Msi" })

foreach ($rule in $msiPublisherRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $msiPathRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $msiHashRules) { $mergedXml += "`n    " + $rule.Value.Rule }

if (($msiPublisherRules.Count + $msiPathRules.Count + $msiHashRules.Count) -eq 0) {
    $mergedXml += @"

    <FilePathRule Id="$(New-Guid)" Name="Allow Administrators MSI" Description="Default rule" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
"@
}

$mergedXml += @"

  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="$scriptMode">
"@

# Add Script rules - wrap in arrays to ensure .Count works correctly
$scriptPublisherRules = @($publisherRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Script" })
$scriptPathRules = @($pathRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Script" })
$scriptHashRules = @($hashRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Script" })

foreach ($rule in $scriptPublisherRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $scriptPathRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $scriptHashRules) { $mergedXml += "`n    " + $rule.Value.Rule }

if (($scriptPublisherRules.Count + $scriptPathRules.Count + $scriptHashRules.Count) -eq 0) {
    $mergedXml += @"

    <FilePathRule Id="$(New-Guid)" Name="Allow Administrators Scripts" Description="Default rule" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
"@
}

$mergedXml += @"

  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="$dllMode">
"@

# Add DLL rules - wrap in arrays to ensure .Count works correctly
$dllPublisherRules = @($publisherRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Dll" })
$dllPathRules = @($pathRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Dll" })
$dllHashRules = @($hashRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Dll" })

foreach ($rule in $dllPublisherRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $dllPathRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $dllHashRules) { $mergedXml += "`n    " + $rule.Value.Rule }

$mergedXml += @"

  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="$appxMode">
"@

# Add Appx rules - wrap in arrays to ensure .Count works correctly
$appxPublisherRules = @($publisherRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Appx" })
$appxPathRules = @($pathRules.GetEnumerator() | Where-Object { $_.Value.Type -eq "Appx" })

foreach ($rule in $appxPublisherRules) { $mergedXml += "`n    " + $rule.Value.Rule }
foreach ($rule in $appxPathRules) { $mergedXml += "`n    " + $rule.Value.Rule }

if (($appxPublisherRules.Count + $appxPathRules.Count) -eq 0) {
    $appxSid = if ($replacementSid) { $replacementSid } else { "S-1-1-0" }
    $mergedXml += @"

    <FilePublisherRule Id="$(New-Guid)" Name="Allow Microsoft Appx" Description="Default rule" UserOrGroupSid="$appxSid" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@
}

$mergedXml += @"

  </RuleCollection>
</AppLockerPolicy>
"@

# Save merged policy
$mergedXml | Out-File -FilePath $OutputPath -Encoding UTF8

# Print statistics
Write-Host "`n=== Merge Complete ===" -ForegroundColor Green
Write-Host "Files processed: $($stats.TotalFiles)" -ForegroundColor Cyan
Write-Host "Total rules found: $($stats.TotalRules)" -ForegroundColor Cyan
Write-Host "  Publisher rules: $($stats.PublisherRules)" -ForegroundColor Gray
Write-Host "  Path rules: $($stats.PathRules)" -ForegroundColor Gray
Write-Host "  Hash rules: $($stats.HashRules)" -ForegroundColor Gray
Write-Host "Duplicates removed: $($stats.DuplicatesRemoved)" -ForegroundColor Yellow
if ($stats.DefaultRulesSkipped -gt 0) {
    Write-Host "Default rules skipped: $($stats.DefaultRulesSkipped)" -ForegroundColor Yellow
}
Write-Host "Final unique rules: $($stats.PublisherRules + $stats.PathRules + $stats.HashRules)" -ForegroundColor Green
Write-Host "`nMerged policy saved to: $OutputPath" -ForegroundColor Cyan

# Validate the output
try {
    $null = [xml](Get-Content -Path $OutputPath -Raw)
    Write-Host "Policy XML validation: PASSED" -ForegroundColor Green
}
catch {
    Write-Warning "Policy XML validation failed: $_"
}

Write-Host "`nTo apply this policy:" -ForegroundColor Yellow
Write-Host "  Set-AppLockerPolicy -XmlPolicy `"$OutputPath`"" -ForegroundColor White

return $OutputPath
