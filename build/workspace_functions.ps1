# Workspace Save/Load Functions for GA-AppLocker GUI
# Phase 4 Implementation

function Save-Workspace {
    <#
    .SYNOPSIS
        Save current workspace state to JSON file
    .DESCRIPTION
        Serializes all workspace data (rules, systems, artifacts, events, settings) to a JSON file
        for later restoration. Includes workspace rotation to keep last 10 workspaces.
    .PARAMETER Path
        Optional custom path for workspace file. If not specified, uses timestamp-based naming.
    .PARAMETER Silent
        Suppress notification messages (useful for auto-save)
    #>
    param(
        [string]$Path = "",
        [bool]$Silent = $false
    )

    try {
        Write-Log "Saving workspace..." -Level "INFO"

        # Ensure workspace directory exists
        $workspaceDir = "C:\GA-AppLocker\Workspaces"
        if (-not (Test-Path $workspaceDir)) {
            New-Item -ItemType Directory -Path $workspaceDir -Force | Out-Null
        }

        # Generate filename if not provided
        if ([string]::IsNullOrWhiteSpace($Path)) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $Path = Join-Path $workspaceDir "workspace_$timestamp.json"
        }

        # Get current UI selections and settings
        $currentPanel = "Dashboard"
        foreach ($panelName @("Dashboard", "Discovery", "Artifacts", "Rules", "Deployment", "Events", "Compliance", "WinRM", "GroupMgmt", "AppLockerSetup", "GapAnalysis", "Help", "About")) {
            $panelVar = Get-Variable -Name "Panel$panelName" -ErrorAction SilentlyContinue
            if ($panelVar -and $panelVar.Value.Visibility -eq [System.Windows.Visibility]::Visible) {
                $currentPanel = $panelName
                break
            }
        }

        # Capture combo box selections (safe access)
        $targetGpoSelection = if ($TargetGpoCombo.SelectedItem) { $TargetGpoCombo.SelectedItem.Content.ToString() } else { $null }
        $importModeSelection = if ($ImportModeCombo.SelectedItem) { $ImportModeCombo.SelectedItem.Content.ToString() } else { $null }
        $dedupeTypeSelection = if ($DedupeTypeCombo -and $DedupeTypeCombo.SelectedItem) { $DedupeTypeCombo.SelectedItem.Content.ToString() } else { $null }
        $eventFilterSelection = $script:EventFilter
        $dashboardTimeFilter = if ($DashboardTimeFilter -and $DashboardTimeFilter.SelectedItem) { $DashboardTimeFilter.SelectedItem.Content.ToString() } else { $null }
        $dashboardSystemFilter = if ($DashboardSystemFilter -and $DashboardSystemFilter.SelectedItem) { $DashboardSystemFilter.SelectedItem.Content.ToString() } else { $null }

        # Serialize collected artifacts safely
        $artifactsData = @()
        foreach ($artifact in $script:CollectedArtifacts) {
            if ($artifact -is [PSCustomObject] -or $artifact -is [Hashtable]) {
                $artifactsData += [PSCustomObject]@{
                    ComputerName    = if ($artifact.ComputerName) { $artifact.ComputerName } else { $artifact.PSObject.Properties.Value[0] }
                    FilePath        = if ($artifact.FilePath) { $artifact.FilePath } else { $null }
                    FileHash        = if ($artifact.FileHash) { $artifact.FileHash } else { $null }
                    SignatureStatus = if ($artifact.SignatureStatus) { $artifact.SignatureStatus } else { $null }
                    Publisher       = if ($artifact.Publisher) { $artifact.Publisher } else { $null }
                    CollectionTime  = if ($artifact.CollectionTime) { $artifact.CollectionTime } else { (Get-Date -Format "o") }
                    FileType        = if ($artifact.FileType) { $artifact.FileType } else { $null }
                    Size            = if ($artifact.Size) { $artifact.Size } else { $null }
                }
            }
        }

        # Serialize generated rules safely
        $rulesData = @()
        foreach ($rule in $script:GeneratedRules) {
            if ($rule -is [PSCustomObject]) {
                $ruleProps = @{}
                foreach ($prop in $rule.PSObject.Properties) {
                    $ruleProps[$prop.Name] = $prop.Value
                }
                $rulesData += [PSCustomObject]$ruleProps
            } elseif ($rule -is [Hashtable]) {
                $rulesData += [PSCustomObject]$rule
            }
        }

        # Serialize discovered computers safely
        $computersData = @()
        foreach ($computer in $script:DiscoveredComputers) {
            if ($computer -is [PSCustomObject]) {
                $compProps = @{}
                foreach ($prop in $computer.PSObject.Properties) {
                    $compProps[$prop.Name] = $prop.Value
                }
                $computersData += [PSCustomObject]$compProps
            } elseif ($computer -is [string]) {
                $computersData += [PSCustomObject]@{ ComputerName = $computer }
            }
        }

        # Serialize events (limit to last 1000 to avoid huge files)
        $eventsData = @()
        if ($script:AllEvents.Count -gt 0) {
            $eventLimit = [Math]::Min(1000, $script:AllEvents.Count)
            for ($i = 0; $i -lt $eventLimit; $i++) {
                $evt = $script:AllEvents[$i]
                if ($evt -is [PSCustomObject]) {
                    $evtProps = @{}
                    foreach ($prop in $evt.PSObject.Properties) {
                        $evtProps[$prop.Name] = $prop.Value
                    }
                    $eventsData += [PSCustomObject]$evtProps
                }
            }
        }

        # Build workspace object
        $workspace = [PSCustomObject]@{
            Version         = $script:WorkspaceVersion
            SavedAt         = Get-Date -Format "o"
            SavedBy         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Computer        = $env:COMPUTERNAME
            CurrentPanel    = $currentPanel
            Settings        = [PSCustomObject]@{
                EventFilter           = $eventFilterSelection
                TargetGpo             = $targetGpoSelection
                ImportMode            = $importModeSelection
                DedupeType            = $dedupeTypeSelection
                DashboardTimeFilter   = $dashboardTimeFilter
                DashboardSystemFilter = $dashboardSystemFilter
                IsWorkgroup           = $script:IsWorkgroup
            }
            Data            = [PSCustomObject]@{
                GeneratedRules      = $rulesData
                DiscoveredComputers = $computersData
                CollectedArtifacts  = $artifactsData
                Events              = $eventsData
                BaselineSoftware    = $script:BaselineSoftware
                TargetSoftware      = $script:TargetSoftware
            }
            Summary         = [PSCustomObject]@{
                RuleCount     = $rulesData.Count
                ComputerCount = $computersData.Count
                ArtifactCount = $artifactsData.Count
                EventCount    = $eventsData.Count
            }
        }

        # Convert to JSON with proper formatting
        $json = $workspace | ConvertTo-Json -Depth 10 -Compress:$false

        # Write to file with UTF8 encoding
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))

        # Update last save path
        $script:LastWorkspaceSavePath = $Path

        # Perform workspace rotation (keep last 10)
        try {
            $existingWorkspaces = Get-ChildItem -Path $workspaceDir -Filter "workspace_*.json" |
                Sort-Object LastWriteTime -Descending
            if ($existingWorkspaces.Count -gt 10) {
                $toDelete = $existingWorkspaces | Select-Object -Skip 10
                foreach ($file in $toDelete) {
                    Remove-Item -Path $file.FullName -Force
                    Write-Log "Removed old workspace: $($file.Name)" -Level "INFO"
                }
            }
        }
        catch {
            Write-Log "Warning: Could not rotate workspace files: $_" -Level "WARNING"
        }

        # Write audit log
        Write-AuditLog -Action "WORKSPACE_SAVED" -Target $Path -Result "SUCCESS" -Details "Workspace saved with $($workspace.Summary.RuleCount) rules, $($workspace.Summary.ComputerCount) computers, $($workspace.Summary.ArtifactCount) artifacts"

        # Show notification
        if (-not $Silent) {
            $StatusText.Text = "Workspace saved: $(Split-Path $Path -Leaf)"
            [System.Windows.MessageBox]::Show("Workspace saved successfully to:`n`n$Path`n`nSummary:`n- Rules: $($workspace.Summary.RuleCount)`n- Computers: $($workspace.Summary.ComputerCount)`n- Artifacts: $($workspace.Summary.ArtifactCount)`n- Events: $($workspace.Summary.EventCount)", "Workspace Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }

        Write-Log "Workspace saved successfully to: $Path" -Level "INFO"
        return $true
    }
    catch {
        $errorMsg = "Failed to save workspace: $($_.Exception.Message)"
        Write-Log $errorMsg -Level "ERROR"
        Write-AuditLog -Action "WORKSPACE_SAVED" -Result "FAILURE" -Details $errorMsg

        if (-not $Silent) {
            [System.Windows.MessageBox]::Show($errorMsg, "Save Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
        return $false
    }
}

function Load-Workspace {
    <#
    .SYNOPSIS
        Load workspace state from JSON file
    .DESCRIPTION
        Deserializes workspace data and restores application state including rules,
        systems, artifacts, events, and UI settings.
    .PARAMETER Path
        Path to the workspace JSON file to load
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Write-Log "Loading workspace from: $Path" -Level "INFO"

        # Validate file exists
        if (-not (Test-Path $Path)) {
            throw "Workspace file not found: $Path"
        }

        # Read and parse JSON
        $json = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
        $workspace = $json | ConvertFrom-Json

        # Validate workspace version
        if ($workspace.Version -and $workspace.Version -ne $script:WorkspaceVersion) {
            $result = [System.Windows.MessageBox]::Show(
                "This workspace was created with version $($workspace.Version) but current version is $($script:WorkspaceVersion).`n`nLoading may cause compatibility issues. Continue?",
                "Version Mismatch",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Warning
            )
            if ($result -eq [System.Windows.MessageBoxResult]::No) {
                Write-AuditLog -Action "WORKSPACE_LOADED" -Target $Path -Result "CANCELLED" -Details "User cancelled due to version mismatch"
                return $false
            }
        }

        # Confirm loading with user
        $summaryMsg = "Load workspace from: $(Split-Path $Path -Leaf)`n`nSaved: $($workspace.SavedAt)`nSaved by: $($workspace.SavedBy)`n`nContains:`n- Rules: $($workspace.Summary.RuleCount)`n- Computers: $($workspace.Summary.ComputerCount)`n- Artifacts: $($workspace.Summary.ArtifactCount)`n- Events: $($workspace.Summary.EventCount)`n`nCurrent data will be replaced. Continue?"
        $result = [System.Windows.MessageBox]::Show($summaryMsg, "Confirm Load Workspace", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)

        if ($result -eq [System.Windows.MessageBoxResult]::No) {
            Write-AuditLog -Action "WORKSPACE_LOADED" -Target $Path -Result "CANCELLED" -Details "User cancelled workspace load"
            return $false
        }

        # Restore data
        # 1. Generated Rules
        $script:GeneratedRules = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
        foreach ($rule in $workspace.Data.GeneratedRules) {
            $script:GeneratedRules.Add($rule)
        }

        # 2. Discovered Computers
        $script:DiscoveredComputers = @()
        foreach ($computer in $workspace.Data.DiscoveredComputers) {
            $script:DiscoveredComputers += $computer
        }

        # 3. Collected Artifacts
        $script:CollectedArtifacts = @()
        foreach ($artifact in $workspace.Data.CollectedArtifacts) {
            $script:CollectedArtifacts += $artifact
        }

        # 4. Events
        $script:AllEvents = @()
        foreach ($evt in $workspace.Data.Events) {
            $script:AllEvents += $evt
        }

        # 5. Software lists
        $script:BaselineSoftware = @($workspace.Data.BaselineSoftware)
        $script:TargetSoftware = @($workspace.Data.TargetSoftware)

        # 6. Settings
        if ($workspace.Settings) {
            $script:IsWorkgroup = $workspace.Settings.IsWorkgroup
            $script:EventFilter = if ($workspace.Settings.EventFilter) { $workspace.Settings.EventFilter } else { "All" }

            # Restore UI selections (async to avoid UI thread issues)
            $window.Dispatcher.Invoke([Action]{
                try {
                    # Restore TargetGpoCombo selection
                    if ($workspace.Settings.TargetGpo -and $TargetGpoCombo.Items.Count -gt 0) {
                        foreach ($item in $TargetGpoCombo.Items) {
                            if ($item.Content.ToString() -eq $workspace.Settings.TargetGpo) {
                                $TargetGpoCombo.SelectedItem = $item
                                break
                            }
                        }
                    }

                    # Restore ImportModeCombo selection
                    if ($workspace.Settings.ImportMode -and $ImportModeCombo.Items.Count -gt 0) {
                        foreach ($item in $ImportModeCombo.Items) {
                            if ($item.Content.ToString() -eq $workspace.Settings.ImportMode) {
                                $ImportModeCombo.SelectedItem = $item
                                break
                            }
                        }
                    }

                    # Restore DedupeTypeCombo selection
                    if ($workspace.Settings.DedupeType -and $DedupeTypeCombo -and $DedupeTypeCombo.Items.Count -gt 0) {
                        foreach ($item in $DedupeTypeCombo.Items) {
                            if ($item.Content.ToString() -eq $workspace.Settings.DedupeType) {
                                $DedupeTypeCombo.SelectedItem = $item
                                break
                            }
                        }
                    }

                    # Restore Dashboard filters
                    if ($workspace.Settings.DashboardTimeFilter -and $DashboardTimeFilter -and $DashboardTimeFilter.Items.Count -gt 0) {
                        foreach ($item in $DashboardTimeFilter.Items) {
                            if ($item.Content.ToString() -eq $workspace.Settings.DashboardTimeFilter) {
                                $DashboardTimeFilter.SelectedItem = $item
                                break
                            }
                        }
                    }

                    if ($workspace.Settings.DashboardSystemFilter -and $DashboardSystemFilter -and $DashboardSystemFilter.Items.Count -gt 0) {
                        foreach ($item in $DashboardSystemFilter.Items) {
                            if ($item.Content.ToString() -eq $workspace.Settings.DashboardSystemFilter) {
                                $DashboardSystemFilter.SelectedItem = $item
                                break
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Warning: Could not restore all UI selections: $_" -Level "WARNING"
                }
            })
        }

        # Update last save path
        $script:LastWorkspaceSavePath = $Path

        # Refresh UI components
        $window.Dispatcher.Invoke([Action]{
            Update-Badges

            # Refresh rules display
            if ($script:GeneratedRules.Count -gt 0) {
                $RulesOutput.Document.Blocks.Clear()
                $ruleParagraph = [System.Windows.Documents.Paragraph]::new()
                foreach ($rule in $script:GeneratedRules | Select-Object -First 50) {
                    $ruleText = if ($rule.RuleString) { $rule.RuleString } elseif ($rule.ToString()) { $rule.ToString() } else { ($rule | ConvertTo-Json -Compress) }
                    $ruleParagraph.Inlines.Add([System.Windows.Documents.Run]::new("$ruleText`n`n"))
                }
                if ($script:GeneratedRules.Count -gt 50) {
                    $ruleParagraph.Inlines.Add([System.Windows.Documents.Run]::new("... and $($script:GeneratedRules.Count - 50) more rules`n`n"))
                }
                $RulesOutput.Document.Blocks.Add($ruleParagraph)
            }

            # Update dashboard text
            $DashboardOutput.Text = "=== WORKSPACE LOADED ===`n`nWorkspace: $(Split-Path $Path -Leaf)`nSaved: $($workspace.SavedAt)`n`nRestored Data:`n- Generated Rules: $($workspace.Summary.RuleCount)`n- Discovered Systems: $($workspace.Summary.ComputerCount)`n- Collected Artifacts: $($workspace.Summary.ArtifactCount)`n- Events: $($workspace.Summary.EventCount)`n`nSelect a tab to continue."
        })

        # Navigate to saved panel
        if ($workspace.CurrentPanel) {
            Show-Panel $workspace.CurrentPanel
        }

        # Write audit log
        Write-AuditLog -Action "WORKSPACE_LOADED" -Target $Path -Result "SUCCESS" -Details "Workspace loaded with $($workspace.Summary.RuleCount) rules, $($workspace.Summary.ComputerCount) computers, $($workspace.Summary.ArtifactCount) artifacts"

        # Show success message
        $StatusText.Text = "Workspace loaded: $(Split-Path $Path -Leaf)"
        Write-Log "Workspace loaded successfully from: $Path" -Level "INFO"

        return $true
    }
    catch {
        $errorMsg = "Failed to load workspace: $($_.Exception.Message)"
        Write-Log $errorMsg -Level "ERROR"
        Write-AuditLog -Action "WORKSPACE_LOADED" -Target $Path -Result "FAILURE" -Details $errorMsg
        [System.Windows.MessageBox]::Show($errorMsg, "Load Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return $false
    }
}

function Initialize-WorkspaceAutoSave {
    <#
    .SYNOPSIS
        Initialize automatic workspace save timer
    .DESCRIPTION
        Sets up a timer that automatically saves the workspace at configured intervals
    #>
    try {
        if ($script:WorkspaceAutoSaveTimer) {
            $script:WorkspaceAutoSaveTimer.Stop()
        }

        $script:WorkspaceAutoSaveTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:WorkspaceAutoSaveTimer.Interval = [TimeSpan]::FromMinutes($script:WorkspaceAutoSaveInterval)
        $script:WorkspaceAutoSaveTimer.Add_Tick({
            # Auto-save with notification
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $autoSavePath = Join-Path "C:\GA-AppLocker\Workspaces" "autosave_$timestamp.json"

            $success = Save-Workspace -Path $autoSavePath -Silent:$false

            if ($success) {
                $StatusText.Text = "Auto-saved workspace: $(Split-Path $autoSavePath -Leaf)"
            }
        }.GetNewClosure())

        $script:WorkspaceAutoSaveTimer.Start()
        Write-Log "Workspace auto-save initialized (interval: $($script:WorkspaceAutoSaveInterval) minutes)" -Level "INFO"
    }
    catch {
        Write-Log "Failed to initialize workspace auto-save: $_" -Level "ERROR"
    }
}
