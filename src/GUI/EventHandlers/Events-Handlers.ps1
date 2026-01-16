function Register-EventsHandlers {
    <#
    .SYNOPSIS
        Register all event monitor panel event handlers
    .DESCRIPTION
        Thin wrapper for event monitor controls that calls ViewModels/BusinessLogic
        Handles local/remote event scanning, computer list management, and filtering
    .PARAMETER Controls
        Hashtable of UI controls from main window
    .PARAMETER ViewModels
        Hashtable of ViewModels for events data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Controls,

        [Parameter(Mandatory = $false)]
        [hashtable]$ViewModels
    )

    Write-Log "Registering events event handlers"

    # Scan Local Events Button
    if ($null -ne $Controls.ScanLocalEventsBtn) {
        $Controls.ScanLocalEventsBtn.Add_Click({
            try {
                Write-Log "Scanning local AppLocker events"

                if ($null -ne $Controls.EventsOutput) {
                    $Controls.EventsOutput.Text = "=== SCANNING LOCAL EVENTS ===`n`nReading AppLocker logs from this computer...`n"
                }

                # Call ViewModel to scan local events
                $result = Invoke-ScanLocalEvents -MaxEvents 500

                if ($result.success) {
                    $script:AllEvents = $result.events

                    if ($null -ne $Controls.EventsOutput) {
                        $Controls.EventsOutput.Text += "Total events loaded: $($result.events.Count)`n`n"
                        $Controls.EventsOutput.Text += "Allowed: $($result.allowedCount) | Audit: $($result.auditCount) | Blocked: $($result.blockedCount)`n`n"
                        $Controls.EventsOutput.Text += "Use filters above to view specific event types.`nExport to CSV, then use Import Artifact in Rule Generator."
                    }

                    Update-EventsDisplay -Controls $Controls
                    Update-Badges

                    Write-Log "Local events scanned: $($result.events.Count) total"
                    Write-AuditLog -Action "LOCAL_EVENTS_SCANNED" -Target "localhost" -Result 'SUCCESS' -Details "$($result.events.Count) events"
                } else {
                    if ($null -ne $Controls.EventsOutput) {
                        $Controls.EventsOutput.Text += "`nERROR: $($result.error)"
                    }
                    Write-Log "Local event scan failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Write-Log "Local event scan failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to scan local events"
            }
        })
    }

    # Scan Remote Events Button
    if ($null -ne $Controls.ScanRemoteEventsBtn) {
        $Controls.ScanRemoteEventsBtn.Add_Click({
            try {
                Write-Log "Scanning remote AppLocker events (comprehensive)"

                # Get selected computers
                $selectedItems = $Controls.EventComputersList.SelectedItems
                if ($selectedItems.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "Please select at least one computer from the list.",
                        "No Computers Selected",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                    return
                }

                $computers = $selectedItems | ForEach-Object { $_.Name.ToString() }

                if ($null -ne $Controls.EventsOutput) {
                    $Controls.EventsOutput.Text = "=== COMPREHENSIVE REMOTE SCAN ===`n`nScanning $($computers.Count) selected computers via WinRM...`n"
                    $Controls.EventsOutput.Text += "Collecting: All AppLocker logs, policy status, system info`n"
                }

                # Show progress overlay
                Show-ProgressOverlay -Message "Scanning $($computers.Count) remote computers..."

                # Call ViewModel to scan remote events
                $result = Invoke-ScanRemoteEvents -ComputerNames $computers -DaysBack 7 -MaxEvents 500

                Remove-ProgressOverlay

                if ($result.success) {
                    $script:AllEvents += $result.events
                    $script:CollectedArtifacts += $result.artifacts

                    if ($null -ne $Controls.EventsOutput) {
                        $Controls.EventsOutput.Text += "`n`n=== SCAN COMPLETE ===`n"
                        $Controls.EventsOutput.Text += "Success: $($result.successCount)/$($computers.Count) computers`n"
                        $Controls.EventsOutput.Text += "Total events: $($result.events.Count)`n"
                        $Controls.EventsOutput.Text += "Total artifacts: $($result.artifacts.Count)`n`n"
                        $Controls.EventsOutput.Text += "Next steps:`n"
                        $Controls.EventsOutput.Text += "1. Export events to CSV for analysis`n"
                        $Controls.EventsOutput.Text += "2. Use artifacts in Rule Generator to create rules`n"
                        $Controls.EventsOutput.Text += "3. Review blocked events to identify needed rules"
                    }

                    Update-EventsDisplay -Controls $Controls
                    Update-Badges

                    Write-Log "Remote scan complete: $($result.events.Count) events from $($result.successCount) computers"
                    Write-AuditLog -Action "REMOTE_EVENTS_SCANNED" -Target "$($computers.Count) computers" -Result 'SUCCESS' -Details "$($result.events.Count) events"
                } else {
                    if ($null -ne $Controls.EventsOutput) {
                        $Controls.EventsOutput.Text += "`nERROR: $($result.error)"
                    }
                    Write-Log "Remote event scan failed: $($result.error)" -Level ERROR
                    Show-ErrorMessage -Error "Remote scan completed with errors. Check output panel for details."
                }
            }
            catch {
                Remove-ProgressOverlay
                Write-Log "Remote event scan failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to scan remote events"
            }
        })
    }

    # Refresh Computers Button
    if ($null -ne $Controls.RefreshComputersBtn) {
        $Controls.RefreshComputersBtn.Add_Click({
            try {
                Write-Log "Refreshing computer list from AD Discovery"

                if ($null -ne $Controls.EventsOutput) {
                    $Controls.EventsOutput.Text = "Refreshing computer list from AD Discovery...`n"
                }

                # Call ViewModel to get computers from AD Discovery
                $result = Invoke-GetComputersFromADDiscovery

                if ($result.success) {
                    # Update computer list
                    if ($null -ne $Controls.EventComputersList) {
                        $Controls.EventComputersList.Items.Clear()
                        foreach ($comp in $result.computers) {
                            $item = New-Object System.Windows.Controls.ListBoxItem
                            $item.Content = $comp.Name
                            $item.Tag = $comp
                            $Controls.EventComputersList.Items.Add($item) | Out-Null
                        }
                    }

                    if ($null -ne $Controls.EventsOutput) {
                        $Controls.EventsOutput.Text += "Loaded $($result.computers.Count) computers from AD Discovery.`n`n"
                        $Controls.EventsOutput.Text += "Select computers and click 'Scan Selected' to collect events."
                    }

                    Write-Log "Refreshed event computer list: $($result.computers.Count) computers"
                } else {
                    if ($null -ne $Controls.EventsOutput) {
                        $Controls.EventsOutput.Text += "ERROR: $($result.error)`n"
                    }
                    Write-Log "Computer list refresh failed: $($result.error)" -Level ERROR
                }
            }
            catch {
                Write-Log "Computer list refresh failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to refresh computer list"
            }
        })
    }

    # Export Events Button
    if ($null -ne $Controls.ExportEventsBtn) {
        $Controls.ExportEventsBtn.Add_Click({
            try {
                Write-Log "Exporting events to CSV"

                if (-not $script:AllEvents -or $script:AllEvents.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No events to export. Please scan for events first.",
                        "No Events",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $saveFileDialog.Title = "Export Events"
                $saveFileDialog.FileName = "AppLocker-Events_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
                $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Events"

                if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $result = Export-EventsToCSV -Events $script:AllEvents -OutputPath $saveFileDialog.FileName

                    if ($result.success) {
                        [System.Windows.MessageBox]::Show(
                            "Events exported to:`n$($saveFileDialog.FileName)`n`n$($script:AllEvents.Count) events exported.",
                            "Export Successful",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information)
                        Write-Log "Events exported: $($saveFileDialog.FileName) ($($script:AllEvents.Count) events)"
                        Write-AuditLog -Action "EVENTS_EXPORTED" -Target $saveFileDialog.FileName -Result 'SUCCESS' -Details "$($script:AllEvents.Count) events"
                    } else {
                        Show-ErrorMessage -Error "Failed to export events: $($result.error)"
                    }
                }
            }
            catch {
                Write-Log "Event export failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to export events"
            }
        })
    }

    # Event Filter Buttons (All, Allowed, Blocked, Audit)
    if ($null -ne $Controls.EventsFilterAll) {
        $Controls.EventsFilterAll.Add_Click({
            try {
                $script:EventsFilterType = "All"
                Filter-Events
                Update-EventFilterButtonStyles -Controls $Controls -SelectedFilter "All"
            }
            catch {
                Write-Log "Event filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    if ($null -ne $Controls.EventsFilterAllowed) {
        $Controls.EventsFilterAllowed.Add_Click({
            try {
                $script:EventsFilterType = "Allowed"
                Filter-Events
                Update-EventFilterButtonStyles -Controls $Controls -SelectedFilter "Allowed"
            }
            catch {
                Write-Log "Event filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    if ($null -ne $Controls.EventsFilterBlocked) {
        $Controls.EventsFilterBlocked.Add_Click({
            try {
                $script:EventsFilterType = "Blocked"
                Filter-Events
                Update-EventFilterButtonStyles -Controls $Controls -SelectedFilter "Blocked"
            }
            catch {
                Write-Log "Event filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    if ($null -ne $Controls.EventsFilterAudit) {
        $Controls.EventsFilterAudit.Add_Click({
            try {
                $script:EventsFilterType = "Audit"
                Filter-Events
                Update-EventFilterButtonStyles -Controls $Controls -SelectedFilter "Audit"
            }
            catch {
                Write-Log "Event filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Events Search TextBox
    if ($null -ne $Controls.EventsFilterSearch) {
        $Controls.EventsFilterSearch.Add_TextChanged({
            try {
                Filter-Events
            }
            catch {
                Write-Log "Event search failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Event DataGrid Selection Changed
    if ($null -ne $Controls.EventsDataGrid) {
        $Controls.EventsDataGrid.Add_SelectionChanged({
            try {
                if ($Controls.EventsDataGrid.SelectedItem) {
                    # Update details panel or perform other actions
                    Write-Log "Event selected: $($Controls.EventsDataGrid.SelectedItem.FileName)"
                }
            }
            catch {
                Write-Log "Event selection failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Computer List Selection Changed
    if ($null -ne $Controls.EventComputersList) {
        $Controls.EventComputersList.Add_SelectionChanged({
            try {
                $selectedCount = $Controls.EventComputersList.SelectedItems.Count
                Write-Log "Selected $selectedCount computer(s) for scanning"

                # Update button state or count display
                if ($null -ne $Controls.ScanRemoteEventsBtn) {
                    $Controls.ScanRemoteEventsBtn.IsEnabled = ($selectedCount -gt 0)
                }
            }
            catch {
                Write-Log "Computer selection failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    # Quick Date Filter Buttons (if exists)
    if ($null -ne $Controls.EventsFilterToday) {
        $Controls.EventsFilterToday.Add_Click({
            try {
                $script:EventsDateFilter = (Get-Date).Date
                Filter-Events
            }
            catch {
                Write-Log "Date filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    if ($null -ne $Controls.EventsFilterLast7Days) {
        $Controls.EventsFilterLast7Days.Add_Click({
            try {
                $script:EventsDateFilter = (Get-Date).AddDays(-7)
                Filter-Events
            }
            catch {
                Write-Log "Date filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    if ($null -ne $Controls.EventsFilterLast30Days) {
        $Controls.EventsFilterLast30Days.Add_Click({
            try {
                $script:EventsDateFilter = (Get-Date).AddDays(-30)
                Filter-Events
            }
            catch {
                Write-Log "Date filter failed: $($_.Exception.Message)" -Level ERROR
            }
        })
    }

    Write-Log "Events event handlers registered successfully"
}

Export-ModuleMember -Function Register-EventsHandlers
