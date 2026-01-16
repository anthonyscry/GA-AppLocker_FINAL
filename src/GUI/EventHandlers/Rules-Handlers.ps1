function Register-RulesHandlers {
    <#
    .SYNOPSIS
        Register all rule generator event handlers
    .DESCRIPTION
        Thin wrapper for rule generator controls that calls ViewModels/BusinessLogic
        Handles rule generation, import/export, filtering, and bulk actions
    .PARAMETER Controls
        Hashtable of UI controls from main window
    .PARAMETER ViewModels
        Hashtable of ViewModels for rules data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Controls,

        [Parameter(Mandatory = $false)]
        [hashtable]$ViewModels
    )

    Write-Log "Registering rules event handlers"

    # Generate Rules Button
    if ($null -ne $Controls.GenerateRulesBtn) {
        $Controls.GenerateRulesBtn.Add_Click({
            try {
                if ($script:CollectedArtifacts.Count -eq 0) {
                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = "ERROR: No artifacts imported. Use Import Artifact or Import Folder first."
                    }
                    return
                }

                # Gather rule generation settings
                $ruleType = if ($Controls.RuleTypeAuto.IsChecked) { "Automated" }
                           elseif ($Controls.RuleTypePublisher.IsChecked) { "Publisher" }
                           elseif ($Controls.RuleTypeHash.IsChecked) { "Hash" }
                           else { "Path" }

                $action = if ($Controls.RuleActionAllow.IsChecked) { "Allow" } else { "Deny" }
                $selectedGroup = if ($Controls.RuleGroupCombo.SelectedItem) {
                    $Controls.RuleGroupCombo.SelectedItem.Content
                } else {
                    "Everyone"
                }

                # Confirmation dialog
                $confirmMsg = "[!] You are about to:`n`n"
                $confirmMsg += "- Generate rules from $($script:CollectedArtifacts.Count) artifacts`n"
                $confirmMsg += "- Rule Type: $ruleType`n"
                $confirmMsg += "- Action: $action`n"
                $confirmMsg += "- Apply To: $selectedGroup`n`n"
                $confirmMsg += "Continue?"

                $confirm = [System.Windows.MessageBox]::Show(
                    $confirmMsg,
                    "Confirm Rule Generation",
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Question)

                if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) {
                    Write-Log "Rule generation cancelled by user"
                    return
                }

                # Show progress
                if ($null -ne $Controls.RulesOutput) {
                    $Controls.RulesOutput.Text = "Generating rules ($ruleType mode)...`nProcessing $($script:CollectedArtifacts.Count) artifacts...`n"
                }

                # Call ViewModel to generate rules
                $result = Invoke-GenerateRules `
                    -Artifacts $script:CollectedArtifacts `
                    -RuleType $ruleType `
                    -Action $action `
                    -Group $selectedGroup

                if ($result.success) {
                    $script:GeneratedRules = $result.rules
                    Update-RulesDataGrid
                    Update-Badges

                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = $result.message
                    }

                    Write-Log "Generated $($result.rules.Count) rules"
                    Write-AuditLog -Action "RULES_GENERATED" -Target "$($result.rules.Count) rules" -Result 'SUCCESS' -Details "Type=$ruleType, Action=$action"
                } else {
                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = "ERROR: $($result.error)"
                    }
                    Write-Log "Rule generation failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Write-Log "Rule generation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to generate rules"
            }
        })
    }

    # Import Artifacts Button
    if ($null -ne $Controls.ImportArtifactsBtn) {
        $Controls.ImportArtifactsBtn.Add_Click({
            try {
                Write-Log "Import artifacts button clicked"

                $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $openFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $openFileDialog.Title = "Import Artifacts"
                $openFileDialog.InitialDirectory = "C:\GA-AppLocker\Artifacts"
                $openFileDialog.Multiselect = $true

                if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $result = Import-ArtifactsFromCSV -FilePaths $openFileDialog.FileNames

                    if ($result.success) {
                        $script:CollectedArtifacts = $result.artifacts
                        Update-ArtifactsDisplay -Controls $Controls
                        Update-Badges

                        [System.Windows.MessageBox]::Show(
                            "Imported $($result.artifacts.Count) artifacts from $($openFileDialog.FileNames.Count) file(s).",
                            "Import Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)

                        Write-Log "Imported $($result.artifacts.Count) artifacts"
                        Write-AuditLog -Action "ARTIFACTS_IMPORTED" -Target "$($result.artifacts.Count) artifacts" -Result 'SUCCESS' -Details "From $($openFileDialog.FileNames.Count) files"
                    } else {
                        Show-ErrorMessage -Error "Failed to import artifacts: $($result.error)"
                    }
                }
            }
            catch {
                Write-Log "Artifact import failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to import artifacts"
            }
        })
    }

    # Export Rules Button
    if ($null -ne $Controls.ExportRulesBtn) {
        $Controls.ExportRulesBtn.Add_Click({
            try {
                Write-Log "Export rules button clicked"

                if ($script:GeneratedRules.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No generated rules to export. Please generate rules first using the Rule Generator tab.",
                        "No Rules",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                # Validate rules before export
                $validation = Test-AppLockerRules -Rules $script:GeneratedRules

                if (-not $validation.success) {
                    $errorMsg = "The following validation errors were found:`n`n"
                    $errorMsg += ($validation.errors | Select-Object -First 5) -join "`n"
                    if ($validation.errors.Count -gt 5) {
                        $errorMsg += "`n... and $($validation.errors.Count - 5) more errors"
                    }
                    $errorMsg += "`n`nPlease fix these errors before exporting."

                    [System.Windows.MessageBox]::Show(
                        $errorMsg,
                        "Validation Failed",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error)
                    Write-Log "Rule validation failed: $($validation.errorCount) errors" -Level ERROR
                    return
                }

                if ($validation.warningCount -gt 0) {
                    $warningMsg = "Warnings:`n`n"
                    $warningMsg += ($validation.warnings -join "`n")
                    $warningMsg += "`n`nContinue with export?"

                    $result = [System.Windows.MessageBox]::Show(
                        $warningMsg,
                        "Validation Warnings",
                        [System.Windows.MessageBoxButton]::YesNo,
                        [System.Windows.MessageBoxImage]::Warning)

                    if ($result -ne [System.Windows.MessageBoxResult]::Yes) {
                        Write-Log "Export cancelled by user due to warnings"
                        return
                    }
                }

                $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
                $saveDialog.Title = "Export AppLocker Rules"
                $saveDialog.FileName = "AppLocker-Rules_$(Get-Date -Format 'yyyy-MM-dd').xml"
                $saveDialog.InitialDirectory = "C:\GA-AppLocker\Rules"

                if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $result = Export-RulesToXML -Rules $script:GeneratedRules -OutputPath $saveDialog.FileName

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Rules exported to: $($saveDialog.FileName)`n`n$($validation.validCount) rules exported.`n`nYou can now import this XML into a GPO using Group Policy Management.",
                            "Success",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-Log "Rules exported: $($saveDialog.FileName) ($($validation.validCount) rules)"
                        Write-AuditLog -Action "RULES_EXPORTED" -Target $saveDialog.FileName -Result 'SUCCESS' -Details "$($validation.validCount) rules"
                    } else {
                        Show-ErrorMessage -Error "Failed to export rules: $($result.error)"
                    }
                }
            }
            catch {
                Write-Log "Rule export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export rules"
            }
        })
    }

    # Import Rules to GPO Button
    if ($null -ne $Controls.ImportRulesBtn) {
        $Controls.ImportRulesBtn.Add_Click({
            try {
                Write-Log "Import rules to GPO button clicked"

                if ($script:IsWorkgroup) {
                    [System.Windows.MessageBox]::Show(
                        "GPO import requires Domain Controller access.",
                        "Workgroup Mode",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                # Get target GPO
                $targetGpoItem = $Controls.TargetGpoCombo.SelectedItem
                if (-not $targetGpoItem) {
                    [System.Windows.MessageBox]::Show(
                        "Please select a target GPO.",
                        "No GPO Selected",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $openDialog = New-Object System.Windows.Forms.OpenFileDialog
                $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
                $openDialog.Title = "Import AppLocker Rules to $($targetGpoItem.Content)"
                $openDialog.InitialDirectory = "C:\GA-AppLocker\Rules"

                if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $result = Import-RulesToGPO `
                        -GpoName $targetGpoItem.Content `
                        -RulesFilePath $openDialog.FileName

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Rules imported successfully to GPO: $($targetGpoItem.Content)",
                            "Import Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-AuditLog -Action "RULES_IMPORTED_TO_GPO" -Target $targetGpoItem.Content -Result 'SUCCESS' -Details $openDialog.FileName
                    } else {
                        Show-ErrorMessage -Error "Failed to import rules to GPO: $($result.error)"
                    }
                }
            }
            catch {
                Write-Log "Rule import to GPO failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to import rules to GPO"
            }
        })
    }

    # Delete Rules Button
    if ($null -ne $Controls.DeleteRulesBtn) {
        $Controls.DeleteRulesBtn.Add_Click({
            try {
                Write-Log "Delete rules button clicked"

                $selectedItems = $Controls.RulesDataGrid.SelectedItems
                if ($selectedItems.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No rules selected.`n`nSelect one or more rules from the list first.",
                        "No Selection",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                # Confirmation
                $confirm = [System.Windows.MessageBox]::Show(
                    "Are you sure you want to delete $($selectedItems.Count) rule(s)?`n`nThis action cannot be undone.",
                    "Confirm Delete",
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Warning)

                if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) {
                    Write-Log "Delete cancelled by user"
                    return
                }

                # Call ViewModel to delete rules
                $result = Invoke-DeleteRules -SelectedItems $selectedItems

                if ($result.success) {
                    $script:GeneratedRules = $result.remainingRules
                    Update-RulesDataGrid
                    Update-Badges

                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = "=== RULES DELETED ===`n`n"
                        $Controls.RulesOutput.Text += "Deleted: $($result.deletedCount) rule(s)`n"
                        $Controls.RulesOutput.Text += "Remaining: $($result.remainingRules.Count) rule(s)"
                    }

                    Write-Log "Deleted $($result.deletedCount) rules"
                    Write-AuditLog -Action "RULES_DELETED" -Target "$($result.deletedCount) rules" -Result 'SUCCESS' -Details "Remaining: $($result.remainingRules.Count)"
                } else {
                    Show-ErrorMessage -Error "Failed to delete rules: $($result.error)"
                }
            }
            catch {
                Write-Log "Delete rules failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to delete rules"
            }
        })
    }

    # Apply Group Change Button (Bulk Edit)
    if ($null -ne $Controls.ApplyGroupChangeBtn) {
        $Controls.ApplyGroupChangeBtn.Add_Click({
            try {
                Write-Log "Bulk group change button clicked"

                $selectedItems = $Controls.RulesDataGrid.SelectedItems
                if ($selectedItems.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No rules selected.`n`nSelect one or more rules from the list first.",
                        "No Selection",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                $selectedGroupItem = $Controls.BulkGroupCombo.SelectedItem
                if (-not $selectedGroupItem) {
                    [System.Windows.MessageBox]::Show(
                        "No group selected.`n`nPlease select a group from the dropdown.",
                        "No Group Selected",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $newGroup = $selectedGroupItem.Content

                # Confirmation
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm Bulk Group Change" `
                    -Message "Change AD group for $($selectedItems.Count) selected rule(s) to '$newGroup'?" `
                    -ActionType 'MODIFY'

                if (-not $confirmed) {
                    Write-Log "Bulk group change cancelled by user"
                    return
                }

                # Call ViewModel
                $result = Invoke-BulkChangeGroup -SelectedItems $selectedItems -NewGroup $newGroup

                if ($result.success) {
                    Update-RulesDataGrid
                    Update-StatusBar

                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = "=== BULK GROUP CHANGE COMPLETE ===`n`n"
                        $Controls.RulesOutput.Text += "Updated: $($result.updatedCount) rule(s)`n"
                        $Controls.RulesOutput.Text += "New Group: $newGroup`n`n"
                        $Controls.RulesOutput.Text += "Use Export Rules to save the changes."
                    }

                    Write-Log "Bulk group change completed: $($result.updatedCount) rules updated"
                    Write-AuditLog -Action "BULK_GROUP_CHANGE" -Target "$newGroup ($($result.updatedCount) rules)" -Result 'SUCCESS' -Details "Changed to $newGroup"
                } else {
                    Show-ErrorMessage -Error "Failed to change group: $($result.error)"
                }
            }
            catch {
                Write-Log "Bulk group change failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to change group"
            }
        })
    }

    # Apply Action Change Button (Bulk Edit)
    if ($null -ne $Controls.ApplyActionChangeBtn) {
        $Controls.ApplyActionChangeBtn.Add_Click({
            try {
                Write-Log "Bulk action change button clicked"

                $selectedItems = $Controls.RulesDataGrid.SelectedItems
                if ($selectedItems.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No rules selected.`n`nSelect one or more rules from the list first.",
                        "No Selection",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                $selectedActionItem = $Controls.BulkActionCombo.SelectedItem
                if (-not $selectedActionItem) {
                    [System.Windows.MessageBox]::Show(
                        "No action selected.`n`nPlease select an action from the dropdown.",
                        "No Action Selected",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $newAction = $selectedActionItem.Content

                # Confirmation
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm Bulk Action Change" `
                    -Message "Change action for $($selectedItems.Count) selected rule(s) to '$newAction'?" `
                    -ActionType 'MODIFY'

                if (-not $confirmed) {
                    Write-Log "Bulk action change cancelled by user"
                    return
                }

                # Call ViewModel
                $result = Invoke-BulkChangeAction -SelectedItems $selectedItems -NewAction $newAction

                if ($result.success) {
                    Update-RulesDataGrid
                    Update-StatusBar

                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = "=== BULK ACTION CHANGE COMPLETE ===`n`n"
                        $Controls.RulesOutput.Text += "Updated: $($result.updatedCount) rule(s)`n"
                        $Controls.RulesOutput.Text += "New Action: $newAction`n`n"
                        $Controls.RulesOutput.Text += "Use Export Rules to save the changes."
                    }

                    Write-Log "Bulk action change completed: $($result.updatedCount) rules updated"
                    Write-AuditLog -Action "BULK_ACTION_CHANGE" -Target "$newAction ($($result.updatedCount) rules)" -Result 'SUCCESS' -Details "Changed to $newAction"
                } else {
                    Show-ErrorMessage -Error "Failed to change action: $($result.error)"
                }
            }
            catch {
                Write-Log "Bulk action change failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to change action"
            }
        })
    }

    # Browser Deny Rules Button
    if ($null -ne $Controls.CreateBrowserDenyBtn) {
        $Controls.CreateBrowserDenyBtn.Add_Click({
            try {
                Write-Log "Create browser deny rules button clicked"

                # Confirmation
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm Browser Deny Rules" `
                    -Message "This will add deny rules for web browsers in the AppLocker-Admins group." `
                    -ActionType 'CREATE'

                if (-not $confirmed) {
                    Write-Log "Browser deny rules creation cancelled by user"
                    return
                }

                # Call ViewModel to create browser deny rules
                $result = Invoke-CreateBrowserDenyRules

                if ($result.success) {
                    $script:GeneratedRules += $result.rules
                    Update-RulesDataGrid
                    Update-Badges

                    if ($null -ne $Controls.RulesOutput) {
                        $Controls.RulesOutput.Text = "=== BROWSER DENY RULES CREATED ===`n`n"
                        $Controls.RulesOutput.Text += "Added: $($result.rules.Count) deny rule(s)`n`n"
                        $Controls.RulesOutput.Text += "Browsers blocked for AppLocker-Admins group.`n"
                        $Controls.RulesOutput.Text += "Use Export Rules to save the changes."
                    }

                    Write-Log "Created $($result.rules.Count) browser deny rules"
                    Write-AuditLog -Action "BROWSER_DENY_RULES_CREATED" -Target "$($result.rules.Count) rules" -Result 'SUCCESS' -Details "Deny rules for browsers"
                } else {
                    Show-ErrorMessage -Error "Failed to create browser deny rules: $($result.error)"
                }
            }
            catch {
                Write-Log "Browser deny rules creation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to create browser deny rules"
            }
        })
    }

    # Rule Filter Search TextBox
    if ($null -ne $Controls.RulesFilterSearch) {
        $Controls.RulesFilterSearch.Add_TextChanged({
            try {
                Filter-Rules
            }
            catch {
                Write-Log "Rules filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Rule Type Filter ComboBox
    if ($null -ne $Controls.RulesFilterType) {
        $Controls.RulesFilterType.Add_SelectionChanged({
            try {
                Filter-Rules
            }
            catch {
                Write-Log "Rules type filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Rule Action Filter ComboBox
    if ($null -ne $Controls.RulesFilterAction) {
        $Controls.RulesFilterAction.Add_SelectionChanged({
            try {
                Filter-Rules
            }
            catch {
                Write-Log "Rules action filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Rule Group Filter ComboBox
    if ($null -ne $Controls.RulesFilterGroup) {
        $Controls.RulesFilterGroup.Add_SelectionChanged({
            try {
                Filter-Rules
            }
            catch {
                Write-Log "Rules group filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Rules DataGrid Double-Click (Edit Rule)
    if ($null -ne $Controls.RulesDataGrid) {
        $Controls.RulesDataGrid.Add_MouseDoubleClick({
            try {
                if ($Controls.RulesDataGrid.SelectedItem) {
                    Write-Log "Rule double-clicked for editing"
                    Edit-RuleDialog -Rule $Controls.RulesDataGrid.SelectedItem.Rule
                }
            }
            catch {
                Write-Log "Rule edit failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to edit rule"
            }
        })
    }

    Write-Log "Rules event handlers registered successfully"
}

Export-ModuleMember -Function Register-RulesHandlers
