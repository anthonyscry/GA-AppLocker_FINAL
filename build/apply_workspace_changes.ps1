# GA-AppLocker GUI - Apply Workspace Save/Export Changes
# This script applies all remaining Phase 4 workspace functionality

param(
    [switch]$Force = $false
)

$mainFilePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1"
$workspaceFunctionsPath = "C:\projects\GA-AppLocker_FINAL\build\workspace_functions.ps1"
$backupPath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF-Backup-$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"

Write-Host "=== GA-AppLocker GUI - Phase 4 Workspace Implementation ===" -ForegroundColor Cyan
Write-Host ""

# Check if main file exists
if (-not (Test-Path $mainFilePath)) {
    Write-Host "ERROR: Main file not found: $mainFilePath" -ForegroundColor Red
    exit 1
}

# Check if workspace functions file exists
if (-not (Test-Path $workspaceFunctionsPath)) {
    Write-Host "ERROR: Workspace functions file not found: $workspaceFunctionsPath" -ForegroundColor Red
    exit 1
}

# Create backup
Write-Host "Creating backup..." -ForegroundColor Yellow
try {
    Copy-Item $mainFilePath $backupPath -Force
    Write-Host "Backup created: $backupPath" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Could not create backup: $_" -ForegroundColor Red
    Write-Host "The file may be locked. Close any editors or processes using it." -ForegroundColor Yellow
    exit 1
}

# Read files
Write-Host "Reading files..." -ForegroundColor Yellow
$mainContent = Get-Content $mainFilePath -Raw
$workspaceFunctions = Get-Content $workspaceFunctionsPath -Raw

# Check if functions are already present
if ($mainContent -match 'function Save-Workspace') {
    Write-Host "WARNING: Save-Workspace function already exists!" -ForegroundColor Yellow
    if (-not $Force) {
        Write-Host "Use -Force to overwrite existing functions" -ForegroundColor Yellow
        exit 0
    }
}

# Apply changes
Write-Host "Applying changes..." -ForegroundColor Yellow

# 1. Insert workspace functions
$pattern = '(?s)(\}\s*# Fail silently for audit logging errors\s*\})(\s*function Show-ConfirmationDialog)'
if ($mainContent -match $pattern) {
    $replacement = '$1' + "`n`n# Workspace Save/Load Functions (Phase 4)`n" + $workspaceFunctions + "`n" + '$2'
    $mainContent = $mainContent -replace $pattern, $replacement
    Write-Host "  [+] Inserted workspace functions" -ForegroundColor Green
}
else {
    Write-Host "  [!] Could not find insertion point for workspace functions" -ForegroundColor Yellow
}

# 2. Add button click handlers
$navHelpPattern = '(?s)(\$NavAbout\.Add_Click\(\{[^}]+\}\))(\s*# Mouse wheel scroll)'
if ($mainContent -match $navHelpPattern -and $mainContent -notmatch '\$NavSaveWorkspace\.Add_Click') {
    $buttonHandlers = @'

# Workspace save/load event handlers (Phase 4)
$NavSaveWorkspace.Add_Click({
    Save-Workspace
    Update-StatusBar
})

$NavLoadWorkspace.Add_Click({
    # Show file dialog to select workspace
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select Workspace to Load"
    $openFileDialog.Filter = "Workspace Files (*.json)|*.json|All Files (*.*)|*.*"
    $openFileDialog.InitialDirectory = "C:\GA-AppLocker\Workspaces"

    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Load-Workspace -Path $openFileDialog.FileName
    }
    Update-StatusBar
})
'@
    $replacement = '$1' + $buttonHandlers + '$2'
    $mainContent = $mainContent -replace $navHelpPattern, $replacement
    Write-Host "  [+] Added button click handlers" -ForegroundColor Green
}
else {
    if ($mainContent -match '\$NavSaveWorkspace\.Add_Click') {
        Write-Host "  [i] Button handlers already exist" -ForegroundColor Cyan
    } else {
        Write-Host "  [!] Could not find location for button handlers" -ForegroundColor Yellow
    }
}

# 3. Add keyboard shortcuts (Ctrl+S and Ctrl+O)
$ctrlOPattern = '(?s)({ \$_ -eq "D0" -and \$isCtrl }[^}]+\.Handled = \$true\s*\})'
if ($mainContent -match $ctrlOPattern -and $mainContent -notmatch '\$_ -eq "S" -and \$isCtrl.*Save-Workspace') {
    $shortcuts = @'

            # Ctrl+S - Save Workspace
            { $_ -eq "S" -and $isCtrl } {
                Save-Workspace
                $e.Handled = $true
            }

            # Ctrl+O - Load Workspace
            { $_ -eq "O" -and $isCtrl } {
                $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $openFileDialog.Title = "Select Workspace to Load"
                $openFileDialog.Filter = "Workspace Files (*.json)|*.json|All Files (*.*)|*.*"
                $openFileDialog.InitialDirectory = "C:\GA-AppLocker\Workspaces"

                if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    Load-Workspace -Path $openFileDialog.FileName
                }
                $e.Handled = $true
            }
'@
    $mainContent = $mainContent -replace $ctrlOPattern, ('$1' + $shortcuts)
    Write-Host "  [+] Added keyboard shortcuts (Ctrl+S, Ctrl+O)" -ForegroundColor Green
}
else {
    if ($mainContent -match 'Ctrl\+S.*Save-Workspace') {
        Write-Host "  [i] Keyboard shortcuts already exist" -ForegroundColor Cyan
    } else {
        Write-Host "  [!] Could not find location for keyboard shortcuts" -ForegroundColor Yellow
    }
}

# 4. Add auto-save initialization
$initSessionPattern = '(?s)(# Initialize session management[^`n]+`n\s*Attach-ActivityTrackers[^`n]+`n)'
if ($mainContent -match $initSessionPattern -and $mainContent -notmatch 'Initialize-WorkspaceAutoSave') {
    $autoSaveInit = "`$1`n    # Phase 4: Initialize workspace auto-save`n    Initialize-WorkspaceAutoSave`n"
    $mainContent = $mainContent -replace $initSessionPattern, $autoSaveInit
    Write-Host "  [+] Added auto-save initialization" -ForegroundColor Green
}
else {
    if ($mainContent -match 'Initialize-WorkspaceAutoSave') {
        Write-Host "  [i] Auto-save initialization already exists" -ForegroundColor Cyan
    } else {
        Write-Host "  [!] Could not find location for auto-save initialization" -ForegroundColor Yellow
    }
}

# Write modified content
Write-Host "Writing changes..." -ForegroundColor Yellow
try {
    Set-Content $mainFilePath -Value $mainContent -NoNewline -Encoding UTF8
    Write-Host "Changes applied successfully!" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Could not write changes: $_" -ForegroundColor Red
    Write-Host "The file may be locked. Close any editors or processes using it." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Backup: $backupPath" -ForegroundColor White
Write-Host "Modified: $mainFilePath" -ForegroundColor White
Write-Host ""
Write-Host "Changes applied:" -ForegroundColor Green
Write-Host "  - Save-Workspace function" -ForegroundColor White
Write-Host "  - Load-Workspace function" -ForegroundColor White
Write-Host "  - Initialize-WorkspaceAutoSave function" -ForegroundColor White
Write-Host "  - Save/Load button click handlers" -ForegroundColor White
Write-Host "  - Keyboard shortcuts (Ctrl+S, Ctrl+O)" -ForegroundColor White
Write-Host "  - Auto-save timer initialization" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Test the GUI by launching GA-AppLocker-GUI-WPF.ps1" -ForegroundColor White
Write-Host "  2. Verify 'Save Workspace' and 'Load Workspace' buttons appear" -ForegroundColor White
Write-Host "  3. Test saving and loading workspaces" -ForegroundColor White
Write-Host "  4. Verify auto-save triggers after 10 minutes" -ForegroundColor White
Write-Host ""
