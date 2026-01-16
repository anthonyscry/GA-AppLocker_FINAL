# GA-AppLocker GUI - Phase 4 Workspace Save/Export Implementation

## Overview
This document provides the complete implementation for workspace save and export functionality in the GA-AppLocker GUI.

## Changes Made to Date

### 1. XAML Header Buttons (COMPLETED)
**Location:** Line ~2130
**Status:** Already applied

```xml
<Button x:Name="NavSaveWorkspace" Content="Save Workspace" Style="{StaticResource SecondaryButton}" Padding="12,4" Margin="0,0,6,0" ToolTip="Save current workspace state (Ctrl+S)"/>
<Button x:Name="NavLoadWorkspace" Content="Load Workspace" Style="{StaticResource SecondaryButton}" Padding="12,4" Margin="0,0,6,0" ToolTip="Load a previously saved workspace (Ctrl+O)"/>
```

### 2. Control Variables (COMPLETED)
**Location:** Line ~3943
**Status:** Already applied

```powershell
$NavSaveWorkspace = $window.FindName("NavSaveWorkspace")
$NavLoadWorkspace = $window.FindName("NavLoadWorkspace")
```

### 3. Workspace State Variables (COMPLETED)
**Location:** Line ~4173
**Status:** Already applied

```powershell
# Workspace state management (Phase 4)
$script:WorkspaceAutoSaveTimer = $null
$script:WorkspaceAutoSaveInterval = 10  # minutes
$script:LastWorkspaceSavePath = $null
$script:WorkspaceVersion = "1.0"
```

### 4. Workspaces Folder (COMPLETED)
**Location:** Line ~4208 in Initialize-AppLockerFolders
**Status:** Already applied

The "Workspaces" folder has been added to the subfolders array.

## Remaining Changes to Apply

### 5. Workspace Functions
**Location:** Insert after line 4402 (after Write-AuditLog function ends, before Show-ConfirmationDialog)

The file `workspace_functions.ps1` contains the complete implementations of:
- `Save-Workspace` - Serializes workspace state to JSON
- `Load-Workspace` - Deserializes and restores workspace state
- `Initialize-WorkspaceAutoSave` - Sets up automatic save timer

**Manual Insertion Instructions:**

1. Open `GA-AppLocker-GUI-WPF.ps1`
2. Find line containing `function Show-ConfirmationDialog` (around line 4404)
3. Insert the contents of `workspace_functions.ps1` just before that function
4. Ensure there are two blank lines between the inserted code and `function Show-ConfirmationDialog`

### 6. Button Click Event Handlers
**Location:** After navigation event handlers (around line 6867)

Add these event handlers after the `$NavAbout.Add_Click` block:

```powershell
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
```

### 7. Keyboard Shortcuts
**Location:** In Register-KeyboardShortcuts function (around line 4567)

Add these keyboard shortcut cases:

```powershell
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
```

### 8. Auto-Save Initialization
**Location:** In window.Loaded event handler (around line 10848)

Add this line after the session management initialization:

```powershell
# Phase 4: Initialize workspace auto-save
Initialize-WorkspaceAutoSave
```

## Workspace JSON Structure

The saved workspace files use this structure:

```json
{
  "Version": "1.0",
  "SavedAt": "2026-01-15T10:30:45.1234567-05:00",
  "SavedBy": "DOMAIN\username",
  "Computer": "COMPUTERNAME",
  "CurrentPanel": "Rules",
  "Settings": {
    "EventFilter": "All",
    "TargetGpo": "Domain Controllers",
    "ImportMode": "Merge (Add)",
    "DedupeType": "By File Hash",
    "DashboardTimeFilter": "Last 24 Hours",
    "DashboardSystemFilter": "All Systems",
    "IsWorkgroup": false
  },
  "Data": {
    "GeneratedRules": [...],
    "DiscoveredComputers": [...],
    "CollectedArtifacts": [...],
    "Events": [...],
    "BaselineSoftware": [...],
    "TargetSoftware": [...]
  },
  "Summary": {
    "RuleCount": 150,
    "ComputerCount": 25,
    "ArtifactCount": 450,
    "EventCount": 1000
  }
}
```

## Features Implemented

### Save-Workspace Function
- Serializes all workspace data to JSON
- Captures current UI panel and selections
- Saves with timestamp-based filename
- Supports custom path specification
- Silent mode for auto-save
- Workspace rotation (keeps last 10)
- Comprehensive error handling
- Audit logging

### Load-Workspace Function
- File dialog for workspace selection
- Version compatibility checking
- User confirmation before loading
- Restores all workspace data
- Restores UI state and selections
- Refreshes all UI components
- Navigates to saved panel
- Comprehensive error handling
- Audit logging

### Auto-Save Feature
- Configurable interval (default 10 minutes)
- Automatic timestamp-based naming
- User notification on save
- Uses DispatcherTimer for WPF compatibility

### Security Features
- Input sanitization for all data
- UTF-8 encoding for JSON files
- Version validation on load
- Audit logging for all operations
- Error handling for corrupt files

## Testing Checklist

- [ ] Save workspace with no data
- [ ] Save workspace with rules only
- [ ] Save workspace with full data (rules, computers, artifacts, events)
- [ ] Load workspace and verify data restoration
- [ ] Load workspace from different version (test compatibility warning)
- [ ] Test workspace rotation (create 11+ workspaces)
- [ ] Test auto-save triggers every 10 minutes
- [ ] Test keyboard shortcuts (Ctrl+S, Ctrl+O)
- [ ] Test with corrupt JSON file
- [ ] Test with missing workspace file
- [ ] Verify audit log entries
- [ ] Verify UI state restoration (combo boxes, filters, panel)

## File Locations

- Main GUI: `C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1`
- Workspace Functions: `C:\projects\GA-AppLocker_FINAL\build\workspace_functions.ps1`
- Workspace Directory: `C:\GA-AppLocker\Workspaces\`
- Audit Log: `C:\GA-AppLocker\Logs\audit.log`

## Notes

1. The file `GA-AppLocker-GUI-WPF.ps1` may be locked by an editor or process. Close any instances before applying changes.
2. Workspace files are limited to 1000 events to prevent excessive file sizes.
3. Auto-save files use the "autosave_" prefix to distinguish from manual saves.
4. All workspace operations are logged to the audit log for compliance.
5. The workspace version is stored to handle future schema changes.

## Troubleshooting

**Issue:** File is locked when trying to edit
**Solution:** Close any PowerShell ISE or VS Code instances that have the file open

**Issue:** Functions not found after adding
**Solution:** Ensure the functions are inserted BEFORE the Show-Panel function and button click handlers

**Issue:** Load fails with "cannot convert"
**Solution:** Check the JSON file format - it may have been manually edited or corrupted

**Issue:** Auto-save not triggering
**Solution:** Verify Initialize-WorkspaceAutoSave is called in window.Loaded event
