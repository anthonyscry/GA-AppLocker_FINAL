# ============================================================
# Phase 5: Policy Simulator Event Handlers and Integration
# GA-AppLocker WPF GUI - Event Handlers for Policy Simulator
# ============================================================

# This file contains the event handlers and integration code
# to be added to GA-AppLocker-GUI-WPF.ps1

# ============================================================
# CONTROL REFERENCES (Add to FindName section after XAML parsing)
# ============================================================
# Find these controls after XAML parsing (around line 4200+)
# Add these lines to the control initialization section:

$NavPolicySimulator = $window.FindName("NavPolicySimulator")
$TestingSection = $window.FindName("TestingSection")

# Policy Simulator controls
$SimTestMode = $window.FindName("SimTestMode")
$SimPolicySelector = $window.FindName("SimPolicySelector")
$SimLoadPolicyBtn = $window.FindName("SimLoadPolicyBtn")
$SimTargetType = $window.FindName("SimTargetType")
$SimTargetPath = $window.FindName("SimTargetPath")
$SimIncludeUnsigned = $window.FindName("SimIncludeUnsigned")
$SimCheckBypasses = $window.FindName("SimCheckBypasses")
$SimAnalyzeImpact = $window.FindName("SimAnalyzeImpact")
$SimRunBtn = $window.FindName("SimRunBtn")

# Progress controls
$SimProgressPanel = $window.FindName("SimProgressPanel")
$SimProgressBar = $window.FindName("SimProgressBar")
$SimProgressText = $window.FindName("SimProgressText")

# Result controls
$SimFilesAnalyzed = $window.FindName("SimFilesAnalyzed")
$SimWouldAllow = $window.FindName("SimWouldAllow")
$SimWouldBlock = $window.FindName("SimWouldBlock")
$SimCoverage = $window.FindName("SimCoverage")
$SimOverallStatus = $window.FindName("SimOverallStatus")
$SimExportBtn = $window.FindName("SimExportBtn")

# Tab controls
$SimTabSummary = $window.FindName("SimTabSummary")
$SimTabDetailed = $window.FindName("SimTabDetailed")
$SimTabWarnings = $window.FindName("SimTabWarnings")
$SimTabRecommendations = $window.FindName("SimTabRecommendations")

# Tab panels
$SimSummaryPanel = $window.FindName("SimSummaryPanel")
$SimDetailedPanel = $window.FindName("SimDetailedPanel")
$SimWarningsPanel = $window.FindName("SimWarningsPanel")
$SimRecommendationsPanel = $window.FindName("SimRecommendationsPanel")

# Data grids
$SimResultsGrid = $window.FindName("SimResultsGrid")
$SimWarningsGrid = $window.FindName("SimWarningsGrid")
$SimRecommendationsGrid = $window.FindName("SimRecommendationsGrid")
$SimImpactGrid = $window.FindName("SimImpactGrid")

# ============================================================
# NAVIGATION EVENT HANDLERS (Add after existing navigation handlers)
# ============================================================
# Add these after line 7100+ (after $NavAbout.Add_Click)

$NavPolicySimulator.Add_Click({
    Show-Panel "PolicySimulator"
    Update-StatusBar

    # Initialize policy selector with available policies
    Update-SimPolicySelector
})

# ============================================================
# POLICY SIMULATOR EVENT HANDLERS (Add new section after Phase 4 handlers)
# ============================================================

# Variable to store loaded policy
$script:SimLoadedPolicy = $null
$script:SimLastResults = $null

# Load Policy Button
$SimLoadPolicyBtn.Add_Click({
    Write-Log "Load Policy button clicked"

    # Open file dialog
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "AppLocker Policy Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openFileDialog.Title = "Select AppLocker Policy XML"
    $openFileDialog.InitialDirectory = "C:\GA-AppLocker\Policies"

    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $policyPath = $openFileDialog.FileName

        try {
            # Load and validate policy
            $policyXml = [xml](Get-Content $policyPath -Raw -Encoding UTF8)

            if (-not $policyXml.AppLockerPolicy) {
                [System.Windows.MessageBox]::Show(
                    "Invalid AppLocker policy file.`n`nThe file does not contain a valid AppLockerPolicy element.",
                    "Invalid Policy",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                )
                return
            }

            # Store policy
            $script:SimLoadedPolicy = $policyXml

            # Update selector
            $SimPolicySelector.Items.Clear()
            $SimPolicySelector.Items.Add((Split-Path $policyPath -Leaf)) | Out-Null
            $SimPolicySelector.SelectedIndex = 0

            Write-Log "Policy loaded: $policyPath"
            Update-StatusBar "Policy loaded: $(Split-Path $policyPath -Leaf)"
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Failed to load policy file.`n`nError: $($_.Exception.Message)",
                "Load Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            )
            Write-Log "Failed to load policy: $($_.Exception.Message)" -Level "ERROR"
        }
    }
})

# Target Type Selection Change
$SimTargetType.Add_SelectionChanged({
    $selectedIndex = $SimTargetType.SelectedIndex

    switch ($selectedIndex) {
        0 { # Local System
            $SimTargetPath.Text = "C:\Program Files"
            $SimTargetPath.IsEnabled = $false
        }
        1 { # Specific Files/Folders
            $SimTargetPath.Text = ""
            $SimTargetPath.IsEnabled = $true
        }
        2 { # Remote Computer
            $SimTargetPath.Text = "\\computername\c$"
            $SimTargetPath.IsEnabled = $true
        }
        3 { # Test OU
            $SimTargetPath.Text = "OU=Test,DC=domain,DC=com"
            $SimTargetPath.IsEnabled = $true
        }
    }
})

# Run Simulation Button
$SimRunBtn.Add_Click({
    Write-Log "Run Simulation button clicked"

    # Validate policy is loaded
    if (-not $script:SimLoadedPolicy) {
        [System.Windows.MessageBox]::Show(
            "Please load a policy XML file first using the 'Load Policy XML' button.",
            "No Policy Loaded",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return
    }

    # Get test mode
    $testModeIndex = $SimTestMode.SelectedIndex
    $testMode = switch ($testModeIndex) {
        0 { "DryRun" }
        1 { "AuditMode" }
        2 { "TestEnvironment" }
        default { "DryRun" }
    }

    # Get target path
    $targetPath = $SimTargetPath.Text
    if ([string]::IsNullOrWhiteSpace($targetPath)) {
        [System.Windows.MessageBox]::Show(
            "Please specify a target path for simulation.",
            "No Target Specified",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return
    }

    # Get target type
    $targetTypeIndex = $SimTargetType.SelectedIndex
    $targetType = switch ($targetTypeIndex) {
        0 { "Local" }
        1 { "Files" }
        2 { "Remote" }
        3 { "OU" }
        default { "Local" }
    }

    # Get options
    $includeUnsigned = $SimIncludeUnsigned.IsChecked
    $checkBypasses = $SimCheckBypasses.IsChecked
    $analyzeImpact = $SimAnalyzeImpact.IsChecked

    # Show progress
    $SimProgressPanel.Visibility = [System.Windows.Visibility]::Visible
    $SimProgressBar.Value = 0
    $SimProgressText.Text = "Initializing simulation..."
    $SimRunBtn.IsEnabled = $false

    # Create progress callback
    $progressCallback = {
        param($percent, $message)

        # Update UI on dispatcher thread
        $window.Dispatcher.Invoke([action]{
            $SimProgressBar.Value = $percent
            $SimProgressText.Text = $message
        })
    }

    # Run simulation in background
    $job = Start-ThreadJob -ScriptBlock {
        param($policyXml, $testMode, $targetPath, $targetType, $includeUnsigned, $checkBypasses, $analyzeImpact, $progressCallback)

        # Import simulation functions
        . "C:\projects\GA-AppLocker_FINAL\build\Phase5-PolicySimulator-Functions.ps1"

        # Run simulation
        $result = Invoke-PolicySimulation `
            -PolicyXml $policyXml.OuterXml `
            -TestMode $testMode `
            -TargetPath $targetPath `
            -TargetType $targetType `
            -IncludeUnsigned:$includeUnsigned `
            -CheckBypasses:$checkBypasses `
            -AnalyzeImpact:$analyzeImpact `
            -ProgressCallback $progressCallback

        return $result
    } -ArgumentList @(
        $script:SimLoadedPolicy.OuterXml,
        $testMode,
        $targetPath,
        $targetType,
        $includeUnsigned,
        $checkBypasses,
        $analyzeImpact,
        $progressCallback
    )

    # Wait for job completion and update UI
    Register-ObjectEvent -InputObject $job -EventName StateChanged -Action {
        $job = $Event.Sender
        if ($job.State -eq 'Completed') {
            $result = $job | Receive-Job

            # Update UI on main thread
            $window.Dispatcher.Invoke([action]{
                # Hide progress
                $SimProgressPanel.Visibility = [System.Windows.Visibility]::Collapsed
                $SimRunBtn.IsEnabled = $true

                # Store results
                $script:SimLastResults = $result

                # Update summary tab
                Update-SimSummaryUI -Result $result

                # Update detailed results tab
                Update-SimDetailedUI -Result $result

                # Update warnings tab
                Update-SimWarningsUI -Result $result

                # Update recommendations tab
                Update-SimRecommendationsUI -Result $result

                # Update impact grid
                Update-SimImpactUI -Result $result

                Write-Log "Simulation completed: $($result.FilesAnalyzed) files analyzed"
            })
        } elseif ($job.State -eq 'Failed') {
            $window.Dispatcher.Invoke([action]{
                $SimProgressPanel.Visibility = [System.Windows.Visibility]::Collapsed
                $SimRunBtn.IsEnabled = $true

                [System.Windows.MessageBox]::Show(
                    "Simulation failed.`n`nError: $($job.Error.Message)",
                    "Simulation Error",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                )

                Write-Log "Simulation failed: $($job.Error.Message)" -Level "ERROR"
            })
        }

        # Cleanup
        $job | Remove-Job
        Unregister-Event -SubscriptionId $EventSubscriber.Id
    } | Out-Null
})

# Tab navigation handlers
$SimTabSummary.Add_Click({
    Show-SimTab "Summary"
})

$SimTabDetailed.Add_Click({
    Show-SimTab "Detailed"
})

$SimTabWarnings.Add_Click({
    Show-SimTab "Warnings"
})

$SimTabRecommendations.Add_Click({
    Show-SimTab "Recommendations"
})

# Export Report Button
$SimExportBtn.Add_Click({
    Write-Log "Export Report button clicked"

    if (-not $script:SimLastResults) {
        [System.Windows.MessageBox]::Show(
            "No simulation results to export. Please run a simulation first.",
            "No Results",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information
        )
        return
    }

    # Save file dialog
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $saveFileDialog.Title = "Export Simulation Report"
    $saveFileDialog.InitialDirectory = "C:\GA-AppLocker\Reports"
    $saveFileDialog.FileName = "Simulation-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            Export-SimulationReport -Result $script:SimLastResults -Path $saveFileDialog.FileName

            [System.Windows.MessageBox]::Show(
                "Report exported successfully.`n`nLocation: $($saveFileDialog.FileName)",
                "Export Complete",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )

            Write-Log "Report exported: $($saveFileDialog.FileName)"
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Failed to export report.`n`nError: $($_.Exception.Message)",
                "Export Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            )

            Write-Log "Failed to export report: $($_.Exception.Message)" -Level "ERROR"
        }
    }
})

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Function: Update-SimPolicySelector
# Description: Update policy selector with available policies
function Update-SimPolicySelector {
    $SimPolicySelector.Items.Clear()

    # Add "Current Effective Policy" option
    $SimPolicySelector.Items.Add("Current Effective Policy") | Out-Null

    # Add saved policies from directory
    $policyDir = "C:\GA-AppLocker\Policies"
    if (Test-Path $policyDir) {
        $policyFiles = Get-ChildItem -Path $policyDir -Filter "*.xml" -ErrorAction SilentlyContinue
        foreach ($file in $policyFiles) {
            $SimPolicySelector.Items.Add($file.Name) | Out-Null
        }
    }

    if ($SimPolicySelector.Items.Count -gt 0) {
        $SimPolicySelector.SelectedIndex = 0
    }
}

# Function: Show-SimTab
# Description: Show specified tab and hide others
function Show-SimTab {
    param([string]$TabName)

    # Hide all panels
    $SimSummaryPanel.Visibility = [System.Windows.Visibility]::Collapsed
    $SimDetailedPanel.Visibility = [System.Windows.Visibility]::Collapsed
    $SimWarningsPanel.Visibility = [System.Windows.Visibility]::Collapsed
    $SimRecommendationsPanel.Visibility = [System.Windows.Visibility]::Collapsed

    # Show selected panel
    switch ($TabName) {
        "Summary" {
            $SimSummaryPanel.Visibility = [System.Windows.Visibility]::Visible
        }
        "Detailed" {
            $SimDetailedPanel.Visibility = [System.Windows.Visibility]::Visible
        }
        "Warnings" {
            $SimWarningsPanel.Visibility = [System.Windows.Visibility]::Visible
        }
        "Recommendations" {
            $SimRecommendationsPanel.Visibility = [System.Windows.Visibility]::Visible
        }
    }
}

# Function: Update-SimSummaryUI
# Description: Update summary tab with results
function Update-SimSummaryUI {
    param($Result)

    $SimFilesAnalyzed.Text = $Result.FilesAnalyzed.ToString("N0")
    $SimWouldAllow.Text = $Result.WouldAllow.ToString("N0")
    $SimWouldBlock.Text = $Result.WouldBlock.ToString("N0")
    $SimCoverage.Text = "$($Result.Coverage)%"

    # Generate status message
    $statusText = ""

    if ($Result.Success) {
        $statusText += "Simulation completed successfully in $([math]::Round($Result.Duration, 2)) seconds.`n`n"

        $blockRate = if ($Result.FilesAnalyzed -gt 0) {
            ($Result.WouldBlock / $Result.FilesAnalyzed) * 100
        } else {
            0
        }

        if ($blockRate -lt 5) {
            $statusText += "Policy is well-tuned with low block rate ($([math]::Round($blockRate, 1))%). "
        } elseif ($blockRate -lt 20) {
            $statusText += "Policy has moderate block rate ($([math]::Round($blockRate, 1))%). "
        } else {
            $statusText += "Policy has high block rate ($([math]::Round($blockRate, 1))%). "
        }

        if ($Result.Bypasses.Count -gt 0) {
            $statusText += "Found $($Result.Bypasses.Count) potential bypass locations. "
        }

        if ($Result.Coverage -lt 80) {
            $statusText += "Coverage is below recommended 80%."
        } else {
            $statusText += "Coverage is good."
        }
    } else {
        $statusText = "Simulation failed: $($Result.Error)"
    }

    $SimOverallStatus.Text = $statusText
}

# Function: Update-SimDetailedUI
# Description: Update detailed results grid
function Update-SimDetailedUI {
    param($Result)

    $SimResultsGrid.ItemsSource = $null
    $SimResultsGrid.ItemsSource = $Result.DetailedResults
}

# Function: Update-SimWarningsUI
# Description: Update warnings grid
function Update-SimWarningsUI {
    param($Result)

    $SimWarningsGrid.ItemsSource = $null
    $SimWarningsGrid.ItemsSource = $Result.Warnings
}

# Function: Update-SimRecommendationsUI
# Description: Update recommendations grid
function Update-SimRecommendationsUI {
    param($Result)

    $SimRecommendationsGrid.ItemsSource = $null
    $SimRecommendationsGrid.ItemsSource = $Result.Recommendations
}

# Function: Update-SimImpactUI
# Description: Update impact grid
function Update-SimImpactUI {
    param($Result)

    $SimImpactGrid.ItemsSource = $null
    $SimImpactGrid.ItemsSource = $Result.ImpactAnalysis
}

# Function: Export-SimulationReport
# Description: Export simulation results to file
function Export-SimulationReport {
    <#
    .SYNOPSIS
        Export simulation results to file

    .PARAMETER Result
        Simulation result object

    .PARAMETER Path
        Output file path

    .EXAMPLE
        Export-SimulationReport -Result $result -Path "report.txt"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Result,

        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $report = @()
    $report += "=" * 80
    $report += "AppLocker Policy Simulation Report"
    $report += "=" * 80
    $report += ""
    $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += "Test Mode: $($Result.TestMode)"
    $report += "Test Target: $($Result.TestTarget)"
    $report += ""

    if ($Result.Success) {
        $report += "-" * 80
        $report += "SUMMARY"
        $report += "-" * 80
        $report += ""
        $report += "Files Analyzed:     $($Result.FilesAnalyzed)"
        $report += "Would Allow:        $($Result.WouldAllow)"
        $report += "Would Block:        $($Result.WouldBlock)"
        $report += "Coverage:           $($Result.Coverage)%"
        $report += "Duration:           $([math]::Round($Result.Duration, 2)) seconds"
        $report += ""

        $blockRate = if ($Result.FilesAnalyzed -gt 0) {
            ($Result.WouldBlock / $Result.FilesAnalyzed) * 100
        } else {
            0
        }
        $report += "Block Rate:         $([math]::Round($blockRate, 2))%"
        $report += ""

        # Recommendations
        if ($Result.Recommendations.Count -gt 0) {
            $report += "-" * 80
            $report += "RECOMMENDATIONS"
            $report += "-" * 80
            $report += ""

            foreach ($rec in $Result.Recommendations) {
                $report += "[$($rec.Priority)] $($rec.Type)"
                $report += "  Recommendation: $($rec.Recommendation)"
                $report += "  Benefit:        $($rec.Benefit)"
                $report += ""
            }
        }

        # Warnings
        if ($Result.Warnings.Count -gt 0) {
            $report += "-" * 80
            $report += "WARNINGS"
            $report += "-" * 80
            $report += ""

            foreach ($warn in $Result.Warnings) {
                $report += "[$($warn.Severity)] $($warn.Category)"
                $report += "  Message:        $($warn.Message)"
                $report += "  Recommendation: $($warn.Recommendation)"
                $report += ""
            }
        }

        # Impact Analysis
        if ($Result.ImpactAnalysis.Count -gt 0) {
            $report += "-" * 80
            $report += "IMPACT ANALYSIS"
            $report += "-" * 80
            $report += ""

            foreach ($impact in $Result.ImpactAnalysis) {
                $report += "$($impact.UserGroup):"
                $report += "  Files Affected:  $($impact.FilesAffected)"
                $report += "  Would Block:     $($impact.WouldBlock)"
                $report += "  Impact Level:    $($impact.ImpactLevel)"
                $report += ""
            }
        }

        # Detailed Results (first 100)
        if ($Result.DetailedResults.Count -gt 0) {
            $report += "-" * 80
            $report += "DETAILED RESULTS (showing first 100)"
            $report += "-" * 80
            $report += ""

            $count = 0
            foreach ($result in $Result.DetailedResults) {
                if ($count -ge 100) { break }

                $report += "[$($result.Result)] $($result.FileName)"
                $report += "  Path:       $($result.Path)"
                $report += "  Publisher:  $($result.Publisher)"
                $report += "  Rule:       $($result.MatchedRule)"
                $report += ""

                $count++
            }

            if ($Result.DetailedResults.Count -gt 100) {
                $report += "... and $($Result.DetailedResults.Count - 100) more entries"
                $report += ""
            }
        }
    } else {
        $report += "-" * 80
        $report += "SIMULATION FAILED"
        $report += "-" * 80
        $report += ""
        $report += "Error: $($Result.Error)"
        $report += ""
    }

    $report += "=" * 80
    $report += "END OF REPORT"
    $report += "=" * 80

    # Write to file
    $report | Out-File -FilePath $Path -Encoding UTF8
}

# ============================================================
# SHOW-PANEL UPDATE (Add case to Show-Panel function)
# ============================================================
# Find the Show-Panel function (around line 6990) and add this case:

# "PolicySimulator" { $PanelPolicySimulator.Visibility = [System.Windows.Visibility]::Visible }

# ============================================================
# INITIALIZATION (Add to startup section)
# ============================================================
# Add this initialization code after window creation (around line 12600):

# Initialize Policy Simulator
Write-Log "Initializing Policy Simulator..."

# Load simulation functions
try {
    . "C:\projects\GA-AppLocker_FINAL\build\Phase5-PolicySimulator-Functions.ps1"
    Write-Log "Policy Simulator functions loaded successfully"
} catch {
    Write-Log "Failed to load Policy Simulator functions: $($_.Exception.Message)" -Level "WARN"
}

# Initialize policy selector
Update-SimPolicySelector

Write-Log "Policy Simulator initialized"
