<#
.SYNOPSIS
    Post-edit hook that runs PSScriptAnalyzer on edited PowerShell files
.DESCRIPTION
    This hook is triggered after Write or Edit operations. It reads the
    hook input from stdin to determine the edited file, then runs
    PSScriptAnalyzer if it's a .ps1 or .psm1 file.
#>

# Read hook input from stdin
$hookInput = $null
try {
    $hookInput = $input | Out-String | ConvertFrom-Json -ErrorAction Stop
} catch {
    # If we can't parse input, exit silently
    exit 0
}

# Get the file path from hook input
$filePath = $null
if ($hookInput.tool_input.file_path) {
    $filePath = $hookInput.tool_input.file_path
}

# Exit if no file path or not a PowerShell file
if (-not $filePath) { exit 0 }
if ($filePath -notmatch '\.(ps1|psm1|psd1)$') { exit 0 }

# Check if file exists
if (-not (Test-Path $filePath)) { exit 0 }

# Check if PSScriptAnalyzer is available
$analyzer = Get-Module -ListAvailable PSScriptAnalyzer -ErrorAction SilentlyContinue
if (-not $analyzer) {
    Write-Host "`n[LINT] PSScriptAnalyzer not installed. Run: Install-Module PSScriptAnalyzer" -ForegroundColor Yellow
    exit 0
}

# Run PSScriptAnalyzer
Write-Host "`n[LINT] Analyzing: $filePath" -ForegroundColor Cyan

$results = Invoke-ScriptAnalyzer -Path $filePath -Severity Warning, Error -ErrorAction SilentlyContinue

if ($results) {
    Write-Host "[LINT] Found $($results.Count) issue(s):" -ForegroundColor Yellow
    foreach ($result in $results) {
        $color = if ($result.Severity -eq 'Error') { 'Red' } else { 'Yellow' }
        Write-Host "  [$($result.Severity)] Line $($result.Line): $($result.RuleName)" -ForegroundColor $color
        Write-Host "    $($result.Message)" -ForegroundColor Gray
    }
} else {
    Write-Host "[LINT] No issues found" -ForegroundColor Green
}

exit 0
