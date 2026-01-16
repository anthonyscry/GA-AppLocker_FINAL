function Register-DeploymentHandlers {
    <#
    .SYNOPSIS
        Register all deployment panel event handlers
    .DESCRIPTION
        Thin wrapper for deployment controls that calls ViewModels/BusinessLogic
        Handles GPO creation, policy export/import, and enforcement mode management
    .PARAMETER Controls
        Hashtable of UI controls from main window
    .PARAMETER ViewModels
        Hashtable of ViewModels for deployment data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Controls,

        [Parameter(Mandatory = $false)]
        [hashtable]$ViewModels
    )

    Write-Log "Registering deployment event handlers"

    # Create GPO Button (Single GPO creation)
    if ($null -ne $Controls.CreateGP0Btn) {
        $Controls.CreateGP0Btn.Add_Click({
            try {
                Write-Log "Create GPO button clicked"

                if ($script:IsWorkgroup) {
                    [System.Windows.MessageBox]::Show(
                        "GPO creation requires Domain Controller access.",
                        "Workgroup Mode",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                # Prompt for GPO name
                $gpoName = Show-InputDialog -Title "Create GPO" -Message "Enter GPO name:" -DefaultValue "GA-AppLocker-Custom"

                if ([string]::IsNullOrWhiteSpace($gpoName)) {
                    Write-Log "GPO creation cancelled by user"
                    return
                }

                # Confirmation
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm GPO Creation" `
                    -Message "Create new GPO: $gpoName" `
                    -ActionType 'CREATE'

                if (-not $confirmed) {
                    return
                }

                Show-ProgressOverlay -Message "Creating GPO: $gpoName..."

                # Call ViewModel to create GPO
                $result = Invoke-CreateGPO -GpoName $gpoName

                Remove-ProgressOverlay

                if ($result.success) {
                    if ($null -ne $Controls.DeploymentStatus) {
                        $Controls.DeploymentStatus.Text = "GPO created successfully: $gpoName`n`nNext: Import rules to the GPO using 'Import Rules to GPO' button."
                    }

                    [System.Windows.MessageBox]::Show(
                        "GPO created successfully: $gpoName",
                        "Success",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)

                    Write-Log "GPO created: $gpoName"
                    Write-AuditLog -Action "GPO_CREATED" -Target $gpoName -Result 'SUCCESS' -Details "Single GPO creation"
                } else {
                    Show-ErrorMessage -Error "Failed to create GPO: $($result.error)"
                    Write-Log "GPO creation failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "GPO creation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to create GPO"
            }
        })
    }

    # Disable GPO Button
    if ($null -ne $Controls.DisableGpoBtn) {
        $Controls.DisableGpoBtn.Add_Click({
            try {
                Write-Log "Disable GPO button clicked"

                if ($script:IsWorkgroup) {
                    [System.Windows.MessageBox]::Show(
                        "GPO operations require Domain Controller access.",
                        "Workgroup Mode",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                # Prompt for GPO name
                $gpoName = Show-InputDialog -Title "Disable GPO" -Message "Enter GPO name to disable:" -DefaultValue "GA-AppLocker-"

                if ([string]::IsNullOrWhiteSpace($gpoName)) {
                    Write-Log "GPO disable cancelled by user"
                    return
                }

                # Confirmation
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm GPO Disable" `
                    -Message "Disable GPO: $gpoName`n`nThis will prevent the policy from applying to computers." `
                    -ActionType 'MODIFY'

                if (-not $confirmed) {
                    return
                }

                Show-ProgressOverlay -Message "Disabling GPO: $gpoName..."

                # Call ViewModel to disable GPO
                $result = Invoke-DisableGPO -GpoName $gpoName

                Remove-ProgressOverlay

                if ($result.success) {
                    if ($null -ne $Controls.DeploymentStatus) {
                        $Controls.DeploymentStatus.Text = "GPO disabled successfully: $gpoName"
                    }

                    [System.Windows.MessageBox]::Show(
                        "GPO disabled successfully: $gpoName",
                        "Success",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)

                    Write-Log "GPO disabled: $gpoName"
                    Write-AuditLog -Action "GPO_DISABLED" -Target $gpoName -Result 'SUCCESS' -Details "GPO disabled"
                } else {
                    Show-ErrorMessage -Error "Failed to disable GPO: $($result.error)"
                    Write-Log "GPO disable failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "GPO disable failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to disable GPO"
            }
        })
    }

    # Export Policy Button (Export current effective policy)
    if ($null -ne $Controls.ExportPolicyBtn) {
        $Controls.ExportPolicyBtn.Add_Click({
            try {
                Write-Log "Export policy button clicked"

                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export AppLocker Policy"
                $saveFileDialog.FileName = "AppLocker-Policy_$(Get-Date -Format 'yyyy-MM-dd').xml"
                $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Policies"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    Show-ProgressOverlay -Message "Exporting policy..."

                    # Call ViewModel to export policy
                    $result = Export-EffectivePolicy -OutputPath $saveFileDialog.FileName

                    Remove-ProgressOverlay

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Policy exported to:`n$($saveFileDialog.FileName)",
                            "Export Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)

                        Write-Log "Policy exported: $($saveFileDialog.FileName)"
                        Write-AuditLog -Action "POLICY_EXPORTED" -Target $saveFileDialog.FileName -Result 'SUCCESS' -Details "Effective policy"
                    } else {
                        Show-ErrorMessage -Error "Failed to export policy: $($result.error)"
                    }
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "Policy export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export policy"
            }
        })
    }

    # Import Policy Button
    if ($null -ne $Controls.ImportPolicyBtn) {
        $Controls.ImportPolicyBtn.Add_Click({
            try {
                Write-Log "Import policy button clicked"

                $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $openFileDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
                $openFileDialog.Title = "Import AppLocker Policy"
                $openFileDialog.InitialDirectory = "C:\GA-AppLocker\Policies"

                if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    # Confirmation
                    $confirmed = Show-ConfirmationDialog `
                        -Title "Confirm Policy Import" `
                        -Message "Import policy from: $($openFileDialog.FileName)`n`nThis will merge with existing policy." `
                        -ActionType 'MODIFY'

                    if (-not $confirmed) {
                        return
                    }

                    Show-ProgressOverlay -Message "Importing policy..."

                    # Call ViewModel to import policy
                    $result = Import-PolicyFromFile -FilePath $openFileDialog.FileName

                    Remove-ProgressOverlay

                    if ($result.success) {
                        if ($null -ne $Controls.DeploymentStatus) {
                            $Controls.DeploymentStatus.Text = "Policy imported successfully from: $($openFileDialog.FileName)"
                        }

                        [System.Windows.MessageBox]::Show(
                            "Policy imported successfully.",
                            "Import Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)

                        Write-Log "Policy imported: $($openFileDialog.FileName)"
                        Write-AuditLog -Action "POLICY_IMPORTED" -Target $openFileDialog.FileName -Result 'SUCCESS' -Details "Policy imported"
                    } else {
                        Show-ErrorMessage -Error "Failed to import policy: $($result.error)"
                    }
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "Policy import failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to import policy"
            }
        })
    }

    # Toggle Audit/Enforce Button
    if ($null -ne $Controls.ToggleAuditEnforceBtn) {
        $Controls.ToggleAuditEnforceBtn.Add_Click({
            try {
                Write-Log "Toggle audit/enforce button clicked"

                # Get current mode
                $currentMode = Get-CurrentEnforcementMode

                $newMode = if ($currentMode -eq "Audit") { "Enforce" } else { "Audit" }

                # If switching to Enforce, run validation
                if ($newMode -eq "Enforce") {
                    $validation = Test-EnforceModeReadiness
                    Write-AuditLog -Action "ENFORCE_MODE_VALIDATION" -Target "Policy" -Result 'ATTEMPT' -Details "Validation performed"

                    $confirmed = Show-EnforceModeValidationDialog -ValidationResult $validation
                    if (-not $confirmed) {
                        if ($null -ne $Controls.DeploymentStatus) {
                            $Controls.DeploymentStatus.Text = "Enforce mode cancelled after validation."
                        }
                        Write-AuditLog -Action "ENFORCE_MODE_CANCELLED" -Target "Policy" -Result 'CANCELLED' -Details "User cancelled after validation"
                        return
                    }
                } else {
                    # Confirmation for switching to Audit
                    $confirmed = Show-ConfirmationDialog `
                        -Title "Confirm Mode Change" `
                        -Message "Switch enforcement mode to: $newMode" `
                        -ActionType 'MODIFY'

                    if (-not $confirmed) {
                        return
                    }
                }

                Show-ProgressOverlay -Message "Changing enforcement mode to $newMode..."

                # Call ViewModel to toggle mode
                $result = Invoke-ToggleEnforcementMode -NewMode $newMode

                Remove-ProgressOverlay

                if ($result.success) {
                    if ($null -ne $Controls.DeploymentStatus) {
                        $Controls.DeploymentStatus.Text = "Enforcement mode changed to: $newMode"
                    }

                    # Update button text
                    if ($null -ne $Controls.ToggleAuditEnforceBtn) {
                        $Controls.ToggleAuditEnforceBtn.Content = if ($newMode -eq "Audit") { "Switch to Enforce" } else { "Switch to Audit" }
                    }

                    [System.Windows.MessageBox]::Show(
                        "Enforcement mode changed to: $newMode",
                        "Mode Changed",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)

                    Write-Log "Enforcement mode changed to: $newMode"
                    Write-AuditLog -Action "ENFORCEMENT_MODE_CHANGED" -Target $newMode -Result 'SUCCESS' -Details "Mode changed to $newMode"
                } else {
                    Show-ErrorMessage -Error "Failed to change enforcement mode: $($result.error)"
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "Enforcement mode toggle failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to toggle enforcement mode"
            }
        })
    }

    # Test Policy Button (Simulate policy application)
    if ($null -ne $Controls.TestPolicyBtn) {
        $Controls.TestPolicyBtn.Add_Click({
            try {
                Write-Log "Test policy button clicked"

                Show-ProgressOverlay -Message "Testing policy configuration..."

                # Call ViewModel to test policy
                $result = Invoke-TestPolicy

                Remove-ProgressOverlay

                if ($result.success) {
                    if ($null -ne $Controls.DeploymentStatus) {
                        $Controls.DeploymentStatus.Text = "Policy test results:`n$($result.message)"
                    }

                    $icon = if ($result.hasErrors) {
                        [System.Windows.MessageBoxImage]::Warning
                    } else {
                        [System.Windows.MessageBoxImage]::Information
                    }

                    [System.Windows.MessageBox]::Show(
                        $result.message,
                        "Policy Test Results",
                        [System.Windows.MessageBoxButton]::OK,
                        $icon)

                    Write-Log "Policy test completed"
                    Write-AuditLog -Action "POLICY_TESTED" -Target "Current Policy" -Result 'SUCCESS' -Details $result.message
                } else {
                    Show-ErrorMessage -Error "Failed to test policy: $($result.error)"
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "Policy test failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to test policy"
            }
        })
    }

    # Refresh GPO Status Button
    if ($null -ne $Controls.RefreshGPOStatusBtn) {
        $Controls.RefreshGPOStatusBtn.Add_Click({
            try {
                Write-Log "Refresh GPO status button clicked"

                Show-ProgressOverlay -Message "Refreshing GPO status..."

                # Call ViewModel to get GPO status
                $result = Invoke-GetGPOStatus

                Remove-ProgressOverlay

                if ($result.success) {
                    # Update status displays
                    Update-GPOStatusDisplay -Controls $Controls -Results $result

                    if ($null -ne $Controls.DeploymentStatus) {
                        $Controls.DeploymentStatus.Text = "GPO status refreshed at $(Get-Date -Format 'HH:mm:ss')"
                    }

                    Write-Log "GPO status refreshed"
                } else {
                    Show-ErrorMessage -Error "Failed to refresh GPO status: $($result.error)"
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "GPO status refresh failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to refresh GPO status"
            }
        })
    }

    # Target GPO ComboBox Selection Changed
    if ($null -ne $Controls.TargetGpoCombo) {
        $Controls.TargetGpoCombo.Add_SelectionChanged({
            try {
                if ($Controls.TargetGpoCombo.SelectedItem) {
                    $gpoName = $Controls.TargetGpoCombo.SelectedItem.Content
                    Write-Log "Target GPO selected: $gpoName"

                    # Enable/disable import button based on selection
                    if ($null -ne $Controls.ImportRulesBtn) {
                        $Controls.ImportRulesBtn.IsEnabled = (-not [string]::IsNullOrWhiteSpace($gpoName))
                    }
                }
            }
            catch {
                Write-Log "Target GPO selection failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Import Mode ComboBox Selection Changed
    if ($null -ne $Controls.ImportModeCombo) {
        $Controls.ImportModeCombo.Add_SelectionChanged({
            try {
                if ($Controls.ImportModeCombo.SelectedItem) {
                    $importMode = $Controls.ImportModeCombo.SelectedItem.Content
                    Write-Log "Import mode selected: $importMode"
                }
            }
            catch {
                Write-Log "Import mode selection failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    Write-Log "Deployment event handlers registered successfully"
}

Export-ModuleMember -Function Register-DeploymentHandlers
