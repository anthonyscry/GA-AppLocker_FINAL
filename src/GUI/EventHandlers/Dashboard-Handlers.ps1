function Register-DashboardHandlers {
    <#
    .SYNOPSIS
        Register all dashboard panel event handlers
    .DESCRIPTION
        Thin wrapper for dashboard controls that calls ViewModels/BusinessLogic
        Handles refresh, filters, charts, and quick GPO creation
    .PARAMETER Controls
        Hashtable of UI controls from main window
    .PARAMETER ViewModels
        Hashtable of ViewModels for dashboard data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Controls,

        [Parameter(Mandatory = $false)]
        [hashtable]$ViewModels
    )

    Write-Log "Registering dashboard event handlers"

    # Refresh Dashboard Button
    if ($null -ne $Controls.RefreshDashboardBtn) {
        $Controls.RefreshDashboardBtn.Add_Click({
            try {
                Write-Log "Refreshing dashboard data"
                Refresh-Data
            }
            catch {
                Write-Log "Dashboard refresh failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to refresh dashboard"
            }
        })
    }

    # Time Filter Selection Changed
    if ($null -ne $Controls.DashboardTimeFilter) {
        $Controls.DashboardTimeFilter.Add_SelectionChanged({
            try {
                $timeFilter = if ($Controls.DashboardTimeFilter.SelectedItem) {
                    $Controls.DashboardTimeFilter.SelectedItem.Content
                } else {
                    "Last 7 Days"
                }
                Write-Log "Dashboard time filter changed to: $timeFilter"
                Refresh-Data
            }
            catch {
                Write-Log "Time filter change failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to apply time filter"
            }
        })
    }

    # System Filter Selection Changed
    if ($null -ne $Controls.DashboardSystemFilter) {
        $Controls.DashboardSystemFilter.Add_SelectionChanged({
            try {
                $systemFilter = if ($Controls.DashboardSystemFilter.SelectedItem) {
                    $Controls.DashboardSystemFilter.SelectedItem.Content
                } else {
                    "All Systems"
                }
                Write-Log "Dashboard system filter changed to: $systemFilter"
                Refresh-Data
            }
            catch {
                Write-Log "System filter change failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to apply system filter"
            }
        })
    }

    # Create GPOs Button (Quick GPO Creation)
    if ($null -ne $Controls.CreateGPOsBtn) {
        $Controls.CreateGPOsBtn.Add_Click({
            try {
                Write-Log "User requested creation of 3 AppLocker GPOs (DC, Servers, Workstations)"
                Write-AuditLog -Action "GPO_CREATE_ATTEMPT" -Target "GA-AppLocker-DC, GA-AppLocker-Servers, GA-AppLocker-Workstations" -Result 'ATTEMPT' -Details "User initiated bulk GPO creation"

                if ($script:IsWorkgroup) {
                    [System.Windows.MessageBox]::Show(
                        "GPO creation requires Domain Controller access.",
                        "Workgroup Mode",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text += "ERROR: GPO creation requires Domain Mode.`n"
                    }
                    Write-AuditLog -Action "GPO_CREATE_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
                    return
                }

                # Confirmation dialog
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm GPO Creation" `
                    -Message "This will create 3 Group Policy Objects:" `
                    -TargetObject "GA-AppLocker-DC, GA-AppLocker-Servers, GA-AppLocker-Workstations" `
                    -ActionType 'CREATE'

                if (-not $confirmed) {
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "GPO creation cancelled by user."
                    }
                    return
                }

                # Call ViewModel/BusinessLogic to create GPOs
                $result = Invoke-CreateBulkGPOs -GpoNames @("GA-AppLocker-DC", "GA-AppLocker-Servers", "GA-AppLocker-Workstations")

                if ($result.success) {
                    # Update UI with results
                    Update-GPOStatusDisplay -Controls $Controls -Results $result

                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = @"
=== GPO CREATION COMPLETE ===

$($result.message)

Next steps:
1. Click 'Link to OUs' to link GPOs to proper OUs
2. Import rules from Rule Generator
3. Apply rules to GPOs in Deployment panel
"@
                    }

                    Write-AuditLog -Action "GPO_CREATE_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details $result.message
                } else {
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "ERROR: $($result.error)"
                    }
                    Write-Log "GPO creation failed: $($result.error)" -Level ERROR
                    Write-AuditLog -Action "GPO_CREATE_BULK_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details $result.error
                }
            }
            catch {
                Write-Log "GPO creation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to create GPOs"
                Write-AuditLog -Action "GPO_CREATE_BULK_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details $_.Exception.Message
            }
        })
    }

    # Apply GPO Settings Button (Phase/Mode)
    if ($null -ne $Controls.ApplyGPOSettingsBtn) {
        $Controls.ApplyGPOSettingsBtn.Add_Click({
            try {
                Write-Log "User requested GPO Phase/Mode settings application"
                Write-AuditLog -Action "GPO_SETTINGS_ATTEMPT" -Target "Multiple GPOs" -Result 'ATTEMPT' -Details "User initiated GPO settings changes"

                if ($script:IsWorkgroup) {
                    [System.Windows.MessageBox]::Show(
                        "GPO modification requires Domain Controller access.",
                        "Workgroup Mode",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    Write-AuditLog -Action "GPO_SETTINGS_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
                    return
                }

                # Gather settings from UI
                $gpoSettings = Get-GPOSettingsFromUI -Controls $Controls

                # Check for enforce mode and validate if needed
                if ($gpoSettings.EnforceGPOs.Count -gt 0) {
                    $validation = Test-EnforceModeReadiness
                    Write-AuditLog -Action "ENFORCE_MODE_VALIDATION" -Target ($gpoSettings.EnforceGPOs -join ", ") -Result 'ATTEMPT' -Details "Validation performed"

                    $confirmed = Show-EnforceModeValidationDialog -ValidationResult $validation
                    if (-not $confirmed) {
                        if ($null -ne $Controls.DashboardOutput) {
                            $Controls.DashboardOutput.Text = "GPO settings cancelled by user after validation."
                        }
                        Write-AuditLog -Action "GPO_SETTINGS_CANCELLED" -Target "Multiple GPOs" -Result 'CANCELLED' -Details "User cancelled enforce mode after validation"
                        return
                    }
                    Write-AuditLog -Action "GPO_ENFORCE_MODE_CONFIRMED" -Target ($gpoSettings.EnforceGPOs -join ", ") -Result 'SUCCESS' -Details "User confirmed enforce mode"
                }

                # Apply settings via ViewModel
                $result = Invoke-ApplyGPOSettings -Settings $gpoSettings

                if ($result.success) {
                    Update-GPOStatusDisplay -Controls $Controls -Results $result
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "=== GPO SETTINGS APPLIED ===`n`n$($result.message)"
                    }
                    Write-AuditLog -Action "GPO_SETTINGS_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details "GPO settings applied successfully"
                } else {
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "ERROR: $($result.error)"
                    }
                    Write-Log "GPO settings application failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Write-Log "GPO settings application failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to apply GPO settings"
                Write-AuditLog -Action "GPO_SETTINGS_APPLY_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details $_.Exception.Message
            }
        })
    }

    # Link GPOs Button
    if ($null -ne $Controls.LinkGPOsBtn) {
        $Controls.LinkGPOsBtn.Add_Click({
            try {
                Write-Log "User requested linking GPOs to OUs"
                Write-AuditLog -Action "GPO_LINK_ATTEMPT" -Target "Multiple GPOs" -Result 'ATTEMPT' -Details "User initiated GPO linking"

                if ($script:IsWorkgroup) {
                    [System.Windows.MessageBox]::Show(
                        "GPO linking requires Domain Controller access.",
                        "Workgroup Mode",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    Write-AuditLog -Action "GPO_LINK_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
                    return
                }

                # Confirmation dialog
                $confirmed = Show-ConfirmationDialog `
                    -Title "Confirm GPO Linking" `
                    -Message "This will link GPOs to their target OUs" `
                    -ActionType 'MODIFY'

                if (-not $confirmed) {
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "GPO linking cancelled by user."
                    }
                    return
                }

                # Call ViewModel to link GPOs
                $result = Invoke-LinkGPOsToOUs

                if ($result.success) {
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "=== GPO LINKING COMPLETE ===`n`n$($result.message)"
                    }
                    Write-AuditLog -Action "GPO_LINK_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details $result.message
                } else {
                    if ($null -ne $Controls.DashboardOutput) {
                        $Controls.DashboardOutput.Text = "ERROR: $($result.error)"
                    }
                    Write-Log "GPO linking failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Write-Log "GPO linking failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to link GPOs"
                Write-AuditLog -Action "GPO_LINK_BULK_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details $_.Exception.Message
            }
        })
    }

    # Export Dashboard Button (if exists)
    if ($null -ne $Controls.ExportDashboardBtn) {
        $Controls.ExportDashboardBtn.Add_Click({
            try {
                Write-Log "Exporting dashboard data"

                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export Dashboard Data"
                $saveFileDialog.FileName = "Dashboard-Export_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
                $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Reports"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $result = Export-DashboardData -OutputPath $saveFileDialog.FileName

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Dashboard data exported to:`n$($saveFileDialog.FileName)",
                            "Export Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-Log "Dashboard data exported to: $($saveFileDialog.FileName)"
                    } else {
                        Show-ErrorMessage -Error "Failed to export dashboard data: $($result.error)"
                    }
                }
            }
            catch {
                Write-Log "Dashboard export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export dashboard data"
            }
        })
    }

    Write-Log "Dashboard event handlers registered successfully"
}

Export-ModuleMember -Function Register-DashboardHandlers
