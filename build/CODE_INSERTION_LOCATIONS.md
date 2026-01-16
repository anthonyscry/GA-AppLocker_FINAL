# Code Insertion Locations - Visual Guide

## Location 1: Insert Workspace Functions

**Find this in GA-AppLocker-GUI-WPF.ps1 (around line 4402):**

```powershell
    }
    catch {
        # Fail silently for audit logging errors
    }
}

function Show-ConfirmationDialog {
    <#
    .SYNOPSIS
        Display confirmation dialog for destructive operations
```

**INSERT THE CONTENTS OF workspace_functions.ps1 RIGHT HERE (after the `}` on line 4402, before `function Show-ConfirmationDialog`):**

```powershell
    }
    catch {
        # Fail silently for audit logging errors
    }
}

# ========================================
# INSERT WORKSPACE_FUNCTIONS.PS1 CONTENTS HERE
# ========================================

function Show-ConfirmationDialog {
```

---

## Location 2: Add Button Click Handlers

**Find this in GA-AppLocker-GUI-WPF.ps1 (search for "NavAbout.Add_Click"):**

```powershell
$NavAbout.Add_Click({
    Show-Panel "About"
    Update-StatusBar
})

# Mouse wheel scroll event handler for sidebar ScrollViewer
```

**INSERT THIS CODE after the NavAbout.Add_Click block:**

```powershell
$NavAbout.Add_Click({
    Show-Panel "About"
    Update-StatusBar
})

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

# Mouse wheel scroll event handler for sidebar ScrollViewer
```

---

## Location 3: Add Keyboard Shortcuts

**Find this in GA-AppLocker-GUI-WPF.ps1 (search for "Ctrl+0 - About"):**

```powershell
            # Ctrl+0 - About
            { $_ -eq "D0" -and $isCtrl } {
                if ($NavAbout) { $NavAbout.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }
        }

        Register-UserActivity
```

**INSERT THIS CODE after the Ctrl+0 block:**

```powershell
            # Ctrl+0 - About
            { $_ -eq "D0" -and $isCtrl } {
                if ($NavAbout) { $NavAbout.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }

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
        }

        Register-UserActivity
```

---

## Location 4: Initialize Auto-Save Timer

**Find this in GA-AppLocker-GUI-WPF.ps1 (search for "Attach-ActivityTrackers"):**

```powershell
    # Initialize session management (Phase 2 security)
    Initialize-SessionTimer
    Attach-ActivityTrackers -Window $window

    # Phase 3: Register keyboard shortcuts
    Register-KeyboardShortcuts -Window $window
```

**INSERT THIS CODE after the Attach-ActivityTrackers line:**

```powershell
    # Initialize session management (Phase 2 security)
    Initialize-SessionTimer
    Attach-ActivityTrackers -Window $window

    # Phase 4: Initialize workspace auto-save
    Initialize-WorkspaceAutoSave

    # Phase 3: Register keyboard shortcuts
    Register-KeyboardShortcuts -Window $window
```

---

## Summary of 4 Insertions

| # | Location | Line # (approx) | What to Insert |
|---|----------|-----------------|----------------|
| 1 | After Write-AuditLog function | 4402 | Contents of workspace_functions.ps1 |
| 2 | After NavAbout.Add_Click block | 6867 | Button click handlers code |
| 3 | After Ctrl+0 keyboard shortcut | 4571 | Ctrl+S and Ctrl+O handlers |
| 4 | After Attach-ActivityTrackers | 10847 | Initialize-WorkspaceAutoSave call |

---

## Quick Copy-Paste Reference

### Insertion 1 (Location 1):
Open `workspace_functions.ps1`, copy ALL content, paste at line 4403.

### Insertion 2 (Location 2):
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

### Insertion 3 (Location 3):
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

### Insertion 4 (Location 4):
```powershell
    # Phase 4: Initialize workspace auto-save
    Initialize-WorkspaceAutoSave
```
