# Fix Null References in GA-AppLocker-GUI-WPF.ps1
# This script adds null checks for all FindName calls and event handlers

$scriptPath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1"
$backupPath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1.backup"
$outputPath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF-Fixed.ps1"

Write-Host "Backing up original file..." -ForegroundColor Cyan
Copy-Item $scriptPath $backupPath -Force

Write-Host "Reading file..." -ForegroundColor Cyan
$content = Get-Content $scriptPath -Raw

Write-Host "Applying fixes..." -ForegroundColor Cyan

# Fix 1: Add null checks for FindName calls (lines 5919-6190)
$findNamePattern = '(\$(\w+)\s*=\s*\$window\.FindName\("([^"]+)"\))'
$nullCheckReplacement = '$1' + "`nif (`$null -eq `$2) { Write-Log `"WARNING: Control '$3' not found in XAML`" -Level `"WARNING`" }"

# We need to be more careful - let's use a different approach
# Read line by line and process

$lines = Get-Content $scriptPath
$output = @()
$inFindNameSection = $false
$findNameEndLine = 6190

Write-Host "Processing $($lines.Count) lines..." -ForegroundColor Cyan

for ($i = 0; $i -lt $lines.Count; $i++) {
    $lineNumber = $i + 1
    $line = $lines[$i]

    # Check if this is a FindName assignment
    if ($line -match '^\$(\w+)\s*=\s*\$window\.FindName\("([^"]+)"\)') {
        $varName = $matches[1]
        $controlName = $matches[2]

        # Add the original line
        $output += $line

        # Add null check
        $output += "if (`$null -eq $varName) { Write-Log `"WARNING: Control '$controlName' not found in XAML`" -Level `"WARNING`" }"

        if ($lineNumber % 50 -eq 0) {
            Write-Host "Processed line $lineNumber" -ForegroundColor Gray
        }
    }
    # Fix 2: Wrap Add_Click calls with null check
    elseif ($line -match '^\$(\w+)\.Add_Click\(\{') {
        $varName = $matches[1]

        # Add null check before Add_Click
        $output += "if (`$null -ne $varName) {"
        $output += $line

        # Find the closing brace for this event handler
        $braceCount = 1
        $j = $i + 1
        while ($j -lt $lines.Count -and $braceCount -gt 0) {
            $output += $lines[$j]
            $braceCount += ($lines[$j] -replace '[^{}]', '').Length - 1
            $braceCount -= ($lines[$j] -replace '[^{}]', '').Length - 1
            # Simple count - this might need adjustment
            $actualBraces = $lines[$j].ToCharArray() | Where-Object { $_ -eq '{' }
            $closeBraces = $lines[$j].ToCharArray() | Where-Object { $_ -eq '}' }
            if ($actualBraces) { $braceCount += $actualBraces.Count }
            if ($closeBraces) { $braceCount -= $closeBraces.Count }
            $j++
        }

        $output += "}"
        $i = $j - 1 # Skip ahead

        if ($lineNumber % 50 -eq 0) {
            Write-Host "Processed line $lineNumber" -ForegroundColor Gray
        }
    }
    # Fix 3: Wrap panel visibility assignments
    elseif ($line -match '^\$(\w+)\.Visibility\s*=\s*\[System\.Windows\.Visibility\]::(\w+)') {
        $varName = $matches[1]
        $visibility = $matches[2]

        # Add null check
        $output += "if (`$null -ne $varName) {"
        $output += $line
        $output += "}"
    }
    else {
        $output += $line
    }
}

Write-Host "Writing fixed file..." -ForegroundColor Cyan
$output | Out-File -FilePath $outputPath -Encoding UTF8

Write-Host "Done!" -ForegroundColor Green
Write-Host "Original file backed up to: $backupPath"
Write-Host "Fixed file written to: $outputPath"
Write-Host ""
Write-Host "To use the fixed file:"
Write-Host "1. Review the changes: Compare-Object (Get-Content $scriptPath) (Get-Content $outputPath)"
Write-Host "2. If satisfied, replace the original: Move-Item -Path $outputPath -Destination $scriptPath -Force"
