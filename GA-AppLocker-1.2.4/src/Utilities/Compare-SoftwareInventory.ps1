<#
.SYNOPSIS
    Compares software inventory CSV files to find differences between machines.

.DESCRIPTION
    This script compares software inventory exports from multiple machines to identify:
    - Software present on one machine but missing from others
    - Version differences for the same software
    - Publisher/signature differences
    - Unique software per machine

    Use cases:
    - Baseline comparison (reference machine vs. targets)
    - Drift detection across fleet
    - Pre/post change comparison
    - AppLocker policy planning (identify unique software)

.PARAMETER ReferencePath
    Path to the reference/baseline CSV file (the "golden image" or standard).

.PARAMETER ComparePath
    Path(s) to CSV file(s) to compare against the reference.
    Accepts wildcards (e.g., ".\Scans\*.csv") or array of paths.

.PARAMETER OutputPath
    Path for the comparison report. Defaults to .\SoftwareComparison-{timestamp}.csv

.PARAMETER CompareBy
    Field(s) to use for comparison matching:
    - Name (default): Match by software name (DisplayName)
    - NameVersion: Match by name AND version (DisplayName + DisplayVersion)
    - Publisher: Match by publisher name

.PARAMETER IgnoreVersion
    Ignore version differences when comparing (only report missing/extra software).

.PARAMETER ExportFormat
    Output format: CSV (default), HTML, or Both.

.EXAMPLE
    # Compare two machines' installed software
    .\Compare-SoftwareInventory.ps1 -ReferencePath ".\Scans\Scan-20260109\PC01\InstalledSoftware.csv" -ComparePath ".\Scans\Scan-20260109\PC02\InstalledSoftware.csv"

.EXAMPLE
    # Compare multiple machines against a baseline
    .\Compare-SoftwareInventory.ps1 -ReferencePath ".\Scans\Scan-20260109\GoldenImage\InstalledSoftware.csv" -ComparePath ".\Scans\Scan-20260109\*\InstalledSoftware.csv"

.EXAMPLE
    # Compare by name and version
    .\Compare-SoftwareInventory.ps1 -ReferencePath ".\Baseline\InstalledSoftware.csv" -ComparePath ".\Target\InstalledSoftware.csv" -CompareBy NameVersion

.EXAMPLE
    # Generate HTML report
    .\Compare-SoftwareInventory.ps1 -ReferencePath ".\PC01\InstalledSoftware.csv" -ComparePath ".\PC02\InstalledSoftware.csv" -ExportFormat HTML

.NOTES
    Input CSV: InstalledSoftware.csv from scan data
    Expected columns: DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    Author: AaronLocker Utilities
    Version: 1.1

.LINK
    Get-InstalledSoftware.ps1 - Generate software inventory CSV
#>

#==============================================================================
# PARAMETERS
#==============================================================================
[CmdletBinding()]
param(
    # Reference/baseline CSV file
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ReferencePath,

    # Comparison CSV file(s) - supports wildcards and arrays
    [Parameter(Mandatory = $true)]
    [string[]]$ComparePath,

    # Output report path
    [string]$OutputPath,

    # Comparison method
    [ValidateSet("Name", "NameVersion", "Publisher")]
    [string]$CompareBy = "Name",

    # Ignore version differences
    [switch]$IgnoreVersion,

    # Output format
    [ValidateSet("CSV", "HTML", "Both")]
    [string]$ExportFormat = "CSV"
)

#==============================================================================
# INITIALIZATION
#==============================================================================
# Load System.Web assembly for HTML encoding (if available)
try {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
} catch {
    # Will use fallback encoding method
}

# Helper function for HTML encoding (works in all PowerShell versions)
function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }

    # Try System.Web.HttpUtility first, fall back to SecurityElement.Escape
    try {
        if ([Type]::GetType('System.Web.HttpUtility')) {
            return [System.Web.HttpUtility]::HtmlEncode($Text)
        }
    } catch {}

    # Fallback: manual HTML encoding
    return $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
}

#==============================================================================
# BANNER
#==============================================================================
Write-Host @"

================================================================================
                    Software Inventory Comparison Tool
================================================================================
  Compares software inventories to identify differences between machines.
  Useful for drift detection, baseline compliance, and AppLocker planning.
================================================================================

"@ -ForegroundColor Cyan

#==============================================================================
# LOAD REFERENCE DATA
#==============================================================================

Write-Host "Loading reference file..." -ForegroundColor Yellow
Write-Host "  Path: $ReferencePath" -ForegroundColor Gray

try {
    # Load the reference CSV
    $referenceData = Import-Csv -Path $ReferencePath -Encoding UTF8

    # Validate expected columns (InstalledSoftware.csv uses DisplayName)
    $requiredColumns = @("DisplayName")
    $csvColumns = $referenceData[0].PSObject.Properties.Name

    foreach ($col in $requiredColumns) {
        if ($col -notin $csvColumns) {
            Write-Error "Required column '$col' not found in reference file. Expected InstalledSoftware.csv format."
            exit 1
        }
    }

    # Get reference computer name (from data or filename)
    $refComputer = if ($referenceData[0].ComputerName) {
        $referenceData[0].ComputerName | Select-Object -First 1
    } else {
        [System.IO.Path]::GetFileNameWithoutExtension($ReferencePath)
    }

    Write-Host "  Reference: $refComputer ($($referenceData.Count) items)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load reference file: $_"
    exit 1
}

#==============================================================================
# RESOLVE COMPARISON FILE PATHS (expand wildcards)
#==============================================================================

Write-Host ""
Write-Host "Resolving comparison files..." -ForegroundColor Yellow

$compareFiles = @()

foreach ($path in $ComparePath) {
    # Handle wildcards
    if ($path -match '\*|\?') {
        $resolved = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
        $compareFiles += $resolved.FullName
    }
    elseif (Test-Path $path -PathType Leaf) {
        $compareFiles += (Resolve-Path $path).Path
    }
    else {
        Write-Warning "Path not found: $path"
    }
}

# Remove the reference file from comparison if accidentally included
$compareFiles = $compareFiles | Where-Object { $_ -ne (Resolve-Path $ReferencePath).Path }

if ($compareFiles.Count -eq 0) {
    Write-Error "No valid comparison files found."
    exit 1
}

Write-Host "  Found $($compareFiles.Count) file(s) to compare" -ForegroundColor Green

#==============================================================================
# HELPER FUNCTION: CREATE COMPARISON KEY
#==============================================================================
function Get-ComparisonKey {
    <#
    .SYNOPSIS
        Generates a comparison key based on the selected comparison method.
        Uses InstalledSoftware.csv columns: DisplayName, DisplayVersion, Publisher
    #>
    param(
        [PSCustomObject]$Item,
        [string]$Method
    )

    switch ($Method) {
        "Name" {
            # Match by DisplayName only (case-insensitive)
            $name = if ($Item.DisplayName) { $Item.DisplayName.ToLower().Trim() } else { "" }
            return $name
        }
        "NameVersion" {
            # Match by DisplayName AND DisplayVersion
            $name = if ($Item.DisplayName) { $Item.DisplayName.ToLower().Trim() } else { "" }
            $version = if ($Item.DisplayVersion) { $Item.DisplayVersion.Trim() } else { "" }
            return "$name|$version"
        }
        "Publisher" {
            # Match by publisher name
            $publisher = if ($Item.Publisher) { $Item.Publisher.ToLower().Trim() } else { "unknown" }
            return $publisher
        }
    }
}

#==============================================================================
# BUILD REFERENCE LOOKUP TABLE
#==============================================================================

Write-Host ""
Write-Host "Building reference lookup table (CompareBy: $CompareBy)..." -ForegroundColor Yellow

# Create hashtable for fast lookups
$referenceLookup = @{}

foreach ($item in $referenceData) {
    $key = Get-ComparisonKey -Item $item -Method $CompareBy

    if (-not $referenceLookup.ContainsKey($key)) {
        $referenceLookup[$key] = @()
    }
    $referenceLookup[$key] += $item
}

Write-Host "  Reference unique keys: $($referenceLookup.Count)" -ForegroundColor Gray

#==============================================================================
# PROCESS EACH COMPARISON FILE
#==============================================================================

$allResults = @()
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

foreach ($compareFile in $compareFiles) {
    Write-Host ""
    Write-Host "Comparing: $([System.IO.Path]::GetFileName($compareFile))" -ForegroundColor Cyan

    try {
        # Load comparison data
        $compareData = Import-Csv -Path $compareFile -Encoding UTF8

        # Get computer name
        $targetComputer = if ($compareData[0].ComputerName) {
            $compareData[0].ComputerName | Select-Object -First 1
        } else {
            [System.IO.Path]::GetFileNameWithoutExtension($compareFile)
        }

        Write-Host "  Target: $targetComputer ($($compareData.Count) items)" -ForegroundColor Gray

        # Build target lookup
        $targetLookup = @{}
        foreach ($item in $compareData) {
            $key = Get-ComparisonKey -Item $item -Method $CompareBy
            if (-not $targetLookup.ContainsKey($key)) {
                $targetLookup[$key] = @()
            }
            $targetLookup[$key] += $item
        }

        #----------------------------------------------------------------------
        # FIND ITEMS IN REFERENCE BUT NOT IN TARGET (MISSING)
        #----------------------------------------------------------------------
        $missingCount = 0

        foreach ($key in $referenceLookup.Keys) {
            if (-not $targetLookup.ContainsKey($key)) {
                # Item exists in reference but not in target
                foreach ($refItem in $referenceLookup[$key]) {
                    $allResults += [PSCustomObject]@{
                        ComparisonType   = "MISSING"
                        ReferencePC      = $refComputer
                        TargetPC         = $targetComputer
                        Name             = $refItem.DisplayName
                        ReferenceVersion = $refItem.DisplayVersion
                        TargetVersion    = ""
                        ReferencePublisher = $refItem.Publisher
                        TargetPublisher  = ""
                        InstallLocation  = $refItem.InstallLocation
                        Notes            = "Present in reference, missing from target"
                    }
                    $missingCount++
                }
            }
        }

        #----------------------------------------------------------------------
        # FIND ITEMS IN TARGET BUT NOT IN REFERENCE (EXTRA)
        #----------------------------------------------------------------------
        $extraCount = 0

        foreach ($key in $targetLookup.Keys) {
            if (-not $referenceLookup.ContainsKey($key)) {
                # Item exists in target but not in reference
                foreach ($targetItem in $targetLookup[$key]) {
                    $allResults += [PSCustomObject]@{
                        ComparisonType   = "EXTRA"
                        ReferencePC      = $refComputer
                        TargetPC         = $targetComputer
                        Name             = $targetItem.DisplayName
                        ReferenceVersion = ""
                        TargetVersion    = $targetItem.DisplayVersion
                        ReferencePublisher = ""
                        TargetPublisher  = $targetItem.Publisher
                        InstallLocation  = $targetItem.InstallLocation
                        Notes            = "Present in target, not in reference"
                    }
                    $extraCount++
                }
            }
        }

        #----------------------------------------------------------------------
        # FIND VERSION DIFFERENCES (if not ignoring versions)
        #----------------------------------------------------------------------
        $versionDiffCount = 0

        if (-not $IgnoreVersion -and $CompareBy -eq "Name") {
            foreach ($key in $referenceLookup.Keys) {
                if ($targetLookup.ContainsKey($key)) {
                    $refItem = $referenceLookup[$key][0]
                    $targetItem = $targetLookup[$key][0]

                    # Compare versions
                    if ($refItem.DisplayVersion -ne $targetItem.DisplayVersion) {
                        $allResults += [PSCustomObject]@{
                            ComparisonType   = "VERSION_DIFF"
                            ReferencePC      = $refComputer
                            TargetPC         = $targetComputer
                            Name             = $refItem.DisplayName
                            ReferenceVersion = $refItem.DisplayVersion
                            TargetVersion    = $targetItem.DisplayVersion
                            ReferencePublisher = $refItem.Publisher
                            TargetPublisher  = $targetItem.Publisher
                            InstallLocation  = $refItem.InstallLocation
                            Notes            = "Version mismatch"
                        }
                        $versionDiffCount++
                    }
                }
            }
        }

        #----------------------------------------------------------------------
        # SUMMARY FOR THIS COMPARISON
        #----------------------------------------------------------------------
        Write-Host "  Results:" -ForegroundColor Gray
        Write-Host "    Missing from target: $missingCount" -ForegroundColor $(if($missingCount -gt 0){"Yellow"}else{"Green"})
        Write-Host "    Extra on target:     $extraCount" -ForegroundColor $(if($extraCount -gt 0){"Yellow"}else{"Green"})
        if (-not $IgnoreVersion -and $CompareBy -eq "Name") {
            Write-Host "    Version differences: $versionDiffCount" -ForegroundColor $(if($versionDiffCount -gt 0){"Yellow"}else{"Green"})
        }
    }
    catch {
        Write-Warning "Failed to process $compareFile : $_"
    }
}

#==============================================================================
# EXPORT RESULTS
#==============================================================================

Write-Host ""
Write-Host "Exporting comparison results..." -ForegroundColor Yellow

# Generate output path if not specified - default to SoftwareLists/Comparisons
if (-not $OutputPath) {
    $comparisonsPath = ".\SoftwareLists\Comparisons"
    if (-not (Test-Path $comparisonsPath)) {
        New-Item -ItemType Directory -Path $comparisonsPath -Force | Out-Null
    }
    $OutputPath = "$comparisonsPath\SoftwareComparison-$timestamp"
}

# Remove extension from output path for multi-format support
$basePath = [System.IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.')

#------------------------------------------------------------------------------
# CSV EXPORT
#------------------------------------------------------------------------------
if ($ExportFormat -in @("CSV", "Both")) {
    $csvPath = "$basePath.csv"

    try {
        $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "  CSV: $csvPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}

#------------------------------------------------------------------------------
# HTML EXPORT
#------------------------------------------------------------------------------
if ($ExportFormat -in @("HTML", "Both")) {
    $htmlPath = "$basePath.html"

    try {
        # Build HTML report
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Software Inventory Comparison Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #0078d4; margin-top: 30px; }
        .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .summary-item { display: inline-block; margin-right: 30px; }
        .summary-count { font-size: 24px; font-weight: bold; }
        .missing { color: #d83b01; }
        .extra { color: #107c10; }
        .version { color: #8764b8; }
        table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f0f0f0; }
        .type-MISSING { background: #fde7e9; }
        .type-EXTRA { background: #dff6dd; }
        .type-VERSION_DIFF { background: #e8daef; }
        .timestamp { color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Software Inventory Comparison Report</h1>
    <p class="timestamp">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>

    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-item">
            <div class="summary-count missing">$($allResults | Where-Object {$_.ComparisonType -eq "MISSING"} | Measure-Object | Select-Object -ExpandProperty Count)</div>
            <div>Missing</div>
        </div>
        <div class="summary-item">
            <div class="summary-count extra">$($allResults | Where-Object {$_.ComparisonType -eq "EXTRA"} | Measure-Object | Select-Object -ExpandProperty Count)</div>
            <div>Extra</div>
        </div>
        <div class="summary-item">
            <div class="summary-count version">$($allResults | Where-Object {$_.ComparisonType -eq "VERSION_DIFF"} | Measure-Object | Select-Object -ExpandProperty Count)</div>
            <div>Version Diff</div>
        </div>
    </div>

    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Software Name</th>
            <th>Reference</th>
            <th>Target</th>
            <th>Ref Version</th>
            <th>Target Version</th>
            <th>Notes</th>
        </tr>
"@

        foreach ($result in ($allResults | Sort-Object ComparisonType, Name)) {
            $encodedName = ConvertTo-HtmlEncoded $result.Name
            $encodedRefVersion = ConvertTo-HtmlEncoded $result.ReferenceVersion
            $encodedTargetVersion = ConvertTo-HtmlEncoded $result.TargetVersion
            $html += @"
        <tr class="type-$($result.ComparisonType)">
            <td>$($result.ComparisonType)</td>
            <td>$encodedName</td>
            <td>$($result.ReferencePC)</td>
            <td>$($result.TargetPC)</td>
            <td>$encodedRefVersion</td>
            <td>$encodedTargetVersion</td>
            <td>$($result.Notes)</td>
        </tr>
"@
        }

        $html += @"
    </table>
</body>
</html>
"@

        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "  HTML: $htmlPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export HTML: $_"
    }
}

#==============================================================================
# FINAL SUMMARY
#==============================================================================

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  COMPARISON COMPLETE" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Total differences found: $($allResults.Count)" -ForegroundColor Cyan
Write-Host ""

# Group by type
$summary = $allResults | Group-Object ComparisonType

foreach ($group in $summary) {
    $color = switch ($group.Name) {
        "MISSING" { "Yellow" }
        "EXTRA" { "Cyan" }
        "VERSION_DIFF" { "Magenta" }
        default { "Gray" }
    }
    Write-Host "    $($group.Name): $($group.Count)" -ForegroundColor $color
}

Write-Host ""
Write-Host "  Comparison method: $CompareBy" -ForegroundColor Gray
Write-Host "  Reference file: $ReferencePath" -ForegroundColor Gray
Write-Host "  Compared against: $($compareFiles.Count) file(s)" -ForegroundColor Gray
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Gray

#==============================================================================
# RETURN OUTPUT PATH
#==============================================================================
return $basePath
