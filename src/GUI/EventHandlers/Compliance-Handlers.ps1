function Register-ComplianceHandlers {
    <#
    .SYNOPSIS
        Register all compliance panel event handlers
    .DESCRIPTION
        Thin wrapper for compliance controls that calls ViewModels/BusinessLogic
        Handles evidence package generation, computer scanning, and report export
    .PARAMETER Controls
        Hashtable of UI controls from main window
    .PARAMETER ViewModels
        Hashtable of ViewModels for compliance data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Controls,

        [Parameter(Mandatory = $false)]
        [hashtable]$ViewModels
    )

    Write-Log "Registering compliance event handlers"

    # Generate Evidence Package Button
    if ($null -ne $Controls.GenerateEvidenceBtn) {
        $Controls.GenerateEvidenceBtn.Add_Click({
            try {
                Write-Log "Generating evidence package"

                if ($null -ne $Controls.ComplianceOutput) {
                    $Controls.ComplianceOutput.Text = "Generating compliance evidence package...`n`nPlease wait..."
                }

                # Get selected computers
                $selectedItems = $Controls.ComplianceComputersList.SelectedItems
                $computers = @()
                if ($selectedItems.Count -gt 0) {
                    $computers = $selectedItems | ForEach-Object { $_.Name }
                }

                Show-ProgressOverlay -Message "Generating evidence package for $($computers.Count + 1) computer(s)..."

                # Call ViewModel to generate evidence package
                $result = Invoke-GenerateEvidencePackage -Computers $computers

                Remove-ProgressOverlay

                if ($result.success) {
                    if ($null -ne $Controls.ComplianceOutput) {
                        $Controls.ComplianceOutput.Text = "`n=== COMPLIANCE EVIDENCE PACKAGE COMPLETE ===`n`n"
                        $Controls.ComplianceOutput.Text += "Location: $($result.basePath)`n`n"
                        $Controls.ComplianceOutput.Text += "Summary:`n"
                        $result.summary | ForEach-Object { $Controls.ComplianceOutput.Text += "  $_`n" }
                        $Controls.ComplianceOutput.Text += "`nFolder Structure:`n"
                        $Controls.ComplianceOutput.Text += "  Policies/      - AppLocker policy files`n"
                        $Controls.ComplianceOutput.Text += "  Inventory/     - Software and process inventory`n"
                        $Controls.ComplianceOutput.Text += "  Reports/       - HTML compliance report`n"
                        if ($computers.Count -gt 0) {
                            $Controls.ComplianceOutput.Text += "  [ComputerName]/ - Per-computer evidence`n"
                        }
                    }

                    Write-Log "Evidence package created: $($result.basePath)"
                    Write-AuditLog -Action "EVIDENCE_PACKAGE_GENERATED" -Target $result.basePath -Result 'SUCCESS' -Details "$($computers.Count + 1) computers"

                    # Open report in browser if available
                    if ($result.reportPath -and (Test-Path $result.reportPath)) {
                        Start-Process $result.reportPath
                    }
                } else {
                    if ($null -ne $Controls.ComplianceOutput) {
                        $Controls.ComplianceOutput.Text = "ERROR: $($result.error)"
                    }
                    Write-Log "Evidence package generation failed: $($result.error)" -Level ERROR
                    Show-ErrorMessage -Error "Failed to generate evidence package"
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "Evidence package generation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to generate evidence package"
            }
        })
    }

    # Scan Local Compliance Button
    if ($null -ne $Controls.ScanLocalComplianceBtn) {
        $Controls.ScanLocalComplianceBtn.Add_Click({
            try {
                Write-Log "Scan Local Compliance clicked"

                # Add localhost to compliance computers list
                $result = Invoke-AddLocalHostToCompliance

                if ($result.success) {
                    # Update computer list
                    if ($null -ne $Controls.ComplianceComputersList) {
                        $item = New-Object PSObject -Property @{
                            Name = $env:COMPUTERNAME
                            Status = "Online"
                            PolicyStatus = "Configured"
                            LastScanned = Get-Date
                        }

                        # Check if localhost already exists
                        $exists = $false
                        foreach ($existing in $Controls.ComplianceComputersList.Items) {
                            if ($existing.Name -eq $env:COMPUTERNAME) {
                                $exists = $true
                                break
                            }
                        }

                        if (-not $exists) {
                            $Controls.ComplianceComputersList.Items.Add($item) | Out-Null
                        }
                    }

                    if ($null -ne $Controls.ComplianceOutput) {
                        $Controls.ComplianceOutput.Text = "Added localhost to compliance list.`n`nUse AD Discovery to add more computers, or generate evidence package now."
                    }

                    Write-Log "Localhost added to compliance list"
                } else {
                    Show-ErrorMessage -Error "Failed to add localhost: $($result.error)"
                }
            }
            catch {
                Write-Log "Scan local compliance failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to scan local compliance"
            }
        })
    }

    # Scan Selected Computers Button
    if ($null -ne $Controls.ScanComplianceBtn) {
        $Controls.ScanComplianceBtn.Add_Click({
            try {
                Write-Log "Scan computers button clicked"

                # Load computers from AD Discovery
                $result = Invoke-LoadComputersFromADDiscovery

                if ($result.success) {
                    # Update computer list
                    if ($null -ne $Controls.ComplianceComputersList) {
                        $Controls.ComplianceComputersList.Items.Clear()

                        foreach ($comp in $result.computers) {
                            $item = New-Object PSObject -Property @{
                                Name = $comp.Name
                                Status = if ($comp.Online) { "Online" } else { "Offline" }
                                PolicyStatus = "Unknown"
                                LastScanned = Get-Date
                            }
                            $Controls.ComplianceComputersList.Items.Add($item) | Out-Null
                        }
                    }

                    if ($null -ne $Controls.ComplianceOutput) {
                        $Controls.ComplianceOutput.Text = "Loaded $($result.computers.Count) computers from AD Discovery.`n`n"
                        $Controls.ComplianceOutput.Text += "Select computers and click 'Generate Evidence Package' to collect compliance data."
                    }

                    Write-Log "Loaded $($result.computers.Count) computers for compliance scanning"
                } else {
                    if ($null -ne $Controls.ComplianceOutput) {
                        $Controls.ComplianceOutput.Text = "ERROR: $($result.error)`n`n"
                        $Controls.ComplianceOutput.Text += "Use AD Discovery panel to discover computers first."
                    }
                    Write-Log "Computer load failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Write-Log "Compliance computer scan failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to scan computers"
            }
        })
    }

    # Export Report Button (PDF)
    if ($null -ne $Controls.ExportReportPDFBtn) {
        $Controls.ExportReportPDFBtn.Add_Click({
            try {
                Write-Log "Export report to PDF clicked"

                if (-not $script:CurrentReportData) {
                    [System.Windows.MessageBox]::Show(
                        "No report data available. Generate evidence package first.",
                        "No Report Data",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "PDF Files (*.pdf)|*.pdf|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export Report to PDF"
                $saveFileDialog.FileName = "Compliance-Report_$(Get-Date -Format 'yyyy-MM-dd').pdf"
                $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Reports"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    Show-ProgressOverlay -Message "Exporting report to PDF..."

                    $result = Export-ReportToPdf -ReportData $script:CurrentReportData -OutputPath $saveFileDialog.FileName

                    Remove-ProgressOverlay

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Report exported to:`n$($saveFileDialog.FileName)",
                            "Export Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-Log "Report exported to PDF: $($saveFileDialog.FileName)"
                        Write-AuditLog -Action "REPORT_EXPORTED_PDF" -Target $saveFileDialog.FileName -Result 'SUCCESS' -Details "PDF export"
                    } else {
                        Show-ErrorMessage -Error "Failed to export report: $($result.error)"
                    }
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "PDF export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export report to PDF"
            }
        })
    }

    # Export Report Button (HTML)
    if ($null -ne $Controls.ExportReportHTMLBtn) {
        $Controls.ExportReportHTMLBtn.Add_Click({
            try {
                Write-Log "Export report to HTML clicked"

                if (-not $script:CurrentReportData) {
                    [System.Windows.MessageBox]::Show(
                        "No report data available. Generate evidence package first.",
                        "No Report Data",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "HTML Files (*.html)|*.html|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export Report to HTML"
                $saveFileDialog.FileName = "Compliance-Report_$(Get-Date -Format 'yyyy-MM-dd').html"
                $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Reports"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    Show-ProgressOverlay -Message "Exporting report to HTML..."

                    $result = Export-ReportToHtml -ReportData $script:CurrentReportData -OutputPath $saveFileDialog.FileName

                    Remove-ProgressOverlay

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Report exported to:`n$($saveFileDialog.FileName)",
                            "Export Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-Log "Report exported to HTML: $($saveFileDialog.FileName)"
                        Write-AuditLog -Action "REPORT_EXPORTED_HTML" -Target $saveFileDialog.FileName -Result 'SUCCESS' -Details "HTML export"
                    } else {
                        Show-ErrorMessage -Error "Failed to export report: $($result.error)"
                    }
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "HTML export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export report to HTML"
            }
        })
    }

    # Export Report Button (CSV)
    if ($null -ne $Controls.ExportReportCSVBtn) {
        $Controls.ExportReportCSVBtn.Add_Click({
            try {
                Write-Log "Export report to CSV clicked"

                if (-not $script:CurrentReportData) {
                    [System.Windows.MessageBox]::Show(
                        "No report data available. Generate evidence package first.",
                        "No Report Data",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export Report to CSV"
                $saveFileDialog.FileName = "Compliance-Report_$(Get-Date -Format 'yyyy-MM-dd').csv"
                $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Reports"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    Show-ProgressOverlay -Message "Exporting report to CSV..."

                    $result = Export-ReportToCsv -ReportData $script:CurrentReportData -OutputPath $saveFileDialog.FileName

                    Remove-ProgressOverlay

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Report exported to:`n$($saveFileDialog.FileName)",
                            "Export Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-Log "Report exported to CSV: $($saveFileDialog.FileName)"
                        Write-AuditLog -Action "REPORT_EXPORTED_CSV" -Target $saveFileDialog.FileName -Result 'SUCCESS' -Details "CSV export"
                    } else {
                        Show-ErrorMessage -Error "Failed to export report: $($result.error)"
                    }
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "CSV export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export report to CSV"
            }
        })
    }

    # Report Type Selection ComboBox
    if ($null -ne $Controls.ReportTypeCombo) {
        $Controls.ReportTypeCombo.Add_SelectionChanged({
            try {
                if ($Controls.ReportTypeCombo.SelectedItem) {
                    $reportType = $Controls.ReportTypeCombo.SelectedItem.Content
                    Write-Log "Report type selected: $reportType"

                    # Enable/disable controls based on report type
                    # Future: Can customize based on report type
                }
            }
            catch {
                Write-Log "Report type selection failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Compliance Computer List Selection Changed
    if ($null -ne $Controls.ComplianceComputersList) {
        $Controls.ComplianceComputersList.Add_SelectionChanged({
            try {
                $selectedCount = $Controls.ComplianceComputersList.SelectedItems.Count
                Write-Log "Selected $selectedCount computer(s) for compliance"

                # Update button state
                if ($null -ne $Controls.GenerateEvidenceBtn) {
                    $Controls.GenerateEvidenceBtn.IsEnabled = $true
                }
            }
            catch {
                Write-Log "Compliance computer selection failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Add Computer Button
    if ($null -ne $Controls.AddComplianceComputerBtn) {
        $Controls.AddComplianceComputerBtn.Add_Click({
            try {
                Write-Log "Add compliance computer button clicked"

                $computerName = Show-InputDialog -Title "Add Computer" -Message "Enter computer name:" -DefaultValue ""

                if ([string]::IsNullOrWhiteSpace($computerName)) {
                    return
                }

                # Add to list
                if ($null -ne $Controls.ComplianceComputersList) {
                    $item = New-Object PSObject -Property @{
                        Name = $computerName
                        Status = "Unknown"
                        PolicyStatus = "Unknown"
                        LastScanned = $null
                    }
                    $Controls.ComplianceComputersList.Items.Add($item) | Out-Null
                }

                Write-Log "Added computer to compliance list: $computerName"
            }
            catch {
                Write-Log "Add compliance computer failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to add computer"
            }
        })
    }

    # Remove Computer Button
    if ($null -ne $Controls.RemoveComplianceComputerBtn) {
        $Controls.RemoveComplianceComputerBtn.Add_Click({
            try {
                Write-Log "Remove compliance computer button clicked"

                $selectedItems = $Controls.ComplianceComputersList.SelectedItems
                if ($selectedItems.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No computers selected.",
                        "No Selection",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                # Remove selected items
                $itemsToRemove = @($selectedItems)
                foreach ($item in $itemsToRemove) {
                    $Controls.ComplianceComputersList.Items.Remove($item)
                }

                Write-Log "Removed $($itemsToRemove.Count) computer(s) from compliance list"
            }
            catch {
                Write-Log "Remove compliance computer failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to remove computer"
            }
        })
    }

    # Compliance Status Filter ComboBox
    if ($null -ne $Controls.ComplianceStatusFilter) {
        $Controls.ComplianceStatusFilter.Add_SelectionChanged({
            try {
                Filter-ComplianceComputers
            }
            catch {
                Write-Log "Compliance filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Compliance Search TextBox
    if ($null -ne $Controls.ComplianceFilterSearch) {
        $Controls.ComplianceFilterSearch.Add_TextChanged({
            try {
                Filter-ComplianceComputers
            }
            catch {
                Write-Log "Compliance search failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Schedule Report Button (if exists)
    if ($null -ne $Controls.ScheduleReportBtn) {
        $Controls.ScheduleReportBtn.Add_Click({
            try {
                Write-Log "Schedule report button clicked"

                # Future: Implement scheduled report generation
                [System.Windows.MessageBox]::Show(
                    "Scheduled reporting feature coming soon!",
                    "Feature Not Available",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)
            }
            catch {
                Write-Log "Schedule report failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to schedule report"
            }
        })
    }

    Write-Log "Compliance event handlers registered successfully"
}

Export-ModuleMember -Function Register-ComplianceHandlers
