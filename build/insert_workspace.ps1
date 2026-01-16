# Script to insert workspace functions into GA-AppLocker-GUI-WPF.ps1

$workspaceFunctionsPath = "C:\projects\GA-AppLocker_FINAL\build\workspace_functions.ps1"
$mainFilePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1"

# Read the workspace functions (skip first line which is the header)
$workspaceFunctionsLines = Get-Content $workspaceFunctionsPath
$workspaceFunctions = $workspaceFunctionsLines -join "`n"

# Read the main file
$mainLines = Get-Content $mainFilePath
$outputLines = @()

$inWriteAuditLog = $false
$foundInsertPoint = $false

for ($i = 0; $i -lt $mainLines.Count; $i++) {
    $line = $mainLines[$i]

    # Track when we're in Write-AuditLog function
    if ($line -match '^function Write-AuditLog') {
        $inWriteAuditLog = $true
    }

    # Check if this is the end of Write-AuditLog (closing brace followed by empty line then Show-ConfirmationDialog)
    if ($inWriteAuditLog -and $line -match '^}$' -and ($i + 1) -lt $mainLines.Count -and $mainLines[$i + 1] -match '^function Show-ConfirmationDialog') {
        # This is the closing brace of Write-AuditLog right before Show-ConfirmationDialog
        $outputLines += $line
        $outputLines += ""  # Empty line
        $outputLines += "# Workspace Save/Load Functions (Phase 4)"
        $outputLines += $workspaceFunctionsLines
        $outputLines += ""
        $foundInsertPoint = $true
        $inWriteAuditLog = $false
        continue
    }

    # If we haven't found the insert point yet, add the line
    if (-not $foundInsertPoint) {
        $outputLines += $line
    }
}

# If we found and processed the insert point, add the rest of the file
if ($foundInsertPoint) {
    # Find the index where Show-ConfirmationDialog starts
    for ($i = 0; $i -lt $mainLines.Count; $i++) {
        if ($mainLines[$i] -match '^function Show-ConfirmationDialog') {
            # Add everything from this point
            for ($j = $i; $j -lt $mainLines.Count; $j++) {
                $outputLines += $mainLines[$j]
            }
            break
        }
    }
}

# Write the modified content
$outputLines | Set-Content $mainFilePath -Force

Write-Host "Workspace functions inserted successfully!" -ForegroundColor Green
