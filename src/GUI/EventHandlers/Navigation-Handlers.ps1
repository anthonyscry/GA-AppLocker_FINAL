function Register-NavigationHandlers {
    <#
    .SYNOPSIS
        Register all navigation button event handlers
    .DESCRIPTION
        Thin wrapper for navigation buttons that calls UI helpers
        Handles panel switching and status bar updates
    .PARAMETER Controls
        Hashtable of UI controls from main window
    .PARAMETER ViewModels
        Hashtable of ViewModels (not used for navigation)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Controls,

        [Parameter(Mandatory = $false)]
        [hashtable]$ViewModels
    )

    Write-Log "Registering navigation event handlers"

    # Dashboard Navigation
    if ($null -ne $Controls.NavDashboard) {
        $Controls.NavDashboard.Add_Click({
            try {
                Show-Panel "Dashboard"
                Update-StatusBar
            }
            catch {
                Write-Log "Dashboard navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Dashboard"
            }
        })
    }

    # Discovery Navigation
    if ($null -ne $Controls.NavDiscovery) {
        $Controls.NavDiscovery.Add_Click({
            try {
                Show-Panel "Discovery"
                Update-StatusBar
            }
            catch {
                Write-Log "Discovery navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Discovery"
            }
        })
    }

    # Artifacts Navigation
    if ($null -ne $Controls.NavArtifacts) {
        $Controls.NavArtifacts.Add_Click({
            try {
                Show-Panel "Artifacts"
                Update-StatusBar
            }
            catch {
                Write-Log "Artifacts navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Artifacts"
            }
        })
    }

    # Gap Analysis Navigation
    if ($null -ne $Controls.NavGapAnalysis) {
        $Controls.NavGapAnalysis.Add_Click({
            try {
                Show-Panel "GapAnalysis"
                Update-StatusBar
            }
            catch {
                Write-Log "Gap Analysis navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Gap Analysis"
            }
        })
    }

    # Rules Navigation
    if ($null -ne $Controls.NavRules) {
        $Controls.NavRules.Add_Click({
            try {
                Show-Panel "Rules"
                Update-StatusBar
            }
            catch {
                Write-Log "Rules navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Rules"
            }
        })
    }

    # Deployment Navigation
    if ($null -ne $Controls.NavDeployment) {
        $Controls.NavDeployment.Add_Click({
            try {
                Show-Panel "Deployment"
                Update-StatusBar
            }
            catch {
                Write-Log "Deployment navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Deployment"
            }
        })
    }

    # Events Navigation
    if ($null -ne $Controls.NavEvents) {
        $Controls.NavEvents.Add_Click({
            try {
                Show-Panel "Events"
                Update-StatusBar
            }
            catch {
                Write-Log "Events navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Events"
            }
        })
    }

    # Compliance Navigation
    if ($null -ne $Controls.NavCompliance) {
        $Controls.NavCompliance.Add_Click({
            try {
                Show-Panel "Compliance"
                Update-StatusBar
            }
            catch {
                Write-Log "Compliance navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Compliance"
            }
        })
    }

    # Reports Navigation
    if ($null -ne $Controls.NavReports) {
        $Controls.NavReports.Add_Click({
            try {
                Show-Panel "Reports"
                Update-StatusBar
            }
            catch {
                Write-Log "Reports navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Reports"
            }
        })
    }

    # WinRM Navigation
    if ($null -ne $Controls.NavWinRM) {
        $Controls.NavWinRM.Add_Click({
            try {
                Show-Panel "WinRM"
                Update-StatusBar
            }
            catch {
                Write-Log "WinRM navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to WinRM"
            }
        })
    }

    # Group Management Navigation
    if ($null -ne $Controls.NavGroupMgmt) {
        $Controls.NavGroupMgmt.Add_Click({
            try {
                Show-Panel "GroupMgmt"
                Update-StatusBar
            }
            catch {
                Write-Log "Group Management navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Group Management"
            }
        })
    }

    # AppLocker Setup Navigation
    if ($null -ne $Controls.NavAppLockerSetup) {
        $Controls.NavAppLockerSetup.Add_Click({
            try {
                Show-Panel "AppLockerSetup"
                Update-StatusBar
            }
            catch {
                Write-Log "AppLocker Setup navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to AppLocker Setup"
            }
        })
    }

    # Templates Navigation
    if ($null -ne $Controls.NavTemplates) {
        $Controls.NavTemplates.Add_Click({
            try {
                Show-Panel "Templates"
                Update-StatusBar
                Write-Log "Navigated to Templates panel"
            }
            catch {
                Write-Log "Templates navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Templates"
            }
        })
    }

    # Help Navigation
    if ($null -ne $Controls.NavHelp) {
        $Controls.NavHelp.Add_Click({
            try {
                Show-Panel "Help"
                Update-StatusBar
                # Load default help content
                if ($null -ne $Controls.HelpTitle) {
                    $Controls.HelpTitle.Text = "Help - Workflow"
                }
                if ($null -ne $Controls.HelpText) {
                    $Controls.HelpText.Text = Get-HelpContent "Workflow"
                }
            }
            catch {
                Write-Log "Help navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to Help"
            }
        })
    }

    # About Navigation
    if ($null -ne $Controls.NavAbout) {
        $Controls.NavAbout.Add_Click({
            try {
                Show-Panel "About"
                Update-StatusBar
            }
            catch {
                Write-Log "About navigation failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to navigate to About"
            }
        })
    }

    # Rule Wizard Button
    if ($null -ne $Controls.NavRuleWizard) {
        $Controls.NavRuleWizard.Add_Click({
            try {
                Write-Log "Rule Wizard button clicked"
                Invoke-RuleWizard
            }
            catch {
                Write-Log "Rule Wizard failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to launch Rule Wizard"
            }
        })
    }

    # Create Template Button
    if ($null -ne $Controls.NavCreateTemplate) {
        $Controls.NavCreateTemplate.Add_Click({
            try {
                Write-Log "Create Template button clicked"
                New-CustomTemplate
            }
            catch {
                Write-Log "Create Template failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to create template"
            }
        })
    }

    # Import Template Button
    if ($null -ne $Controls.NavImportTemplate) {
        $Controls.NavImportTemplate.Add_Click({
            try {
                Write-Log "Import Template button clicked"
                Import-RuleTemplateFromFile
            }
            catch {
                Write-Log "Import Template failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to import template"
            }
        })
    }

    # Workspace Save Button
    if ($null -ne $Controls.NavSaveWorkspace) {
        $Controls.NavSaveWorkspace.Add_Click({
            try {
                Write-Log "Save workspace button clicked"
                $savedFile = Save-Workspace
                if ($savedFile) {
                    [System.Windows.MessageBox]::Show(
                        "Workspace saved to:`n$savedFile",
                        "Workspace Saved",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information)
                }
            }
            catch {
                Write-Log "Save Workspace failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to save workspace"
            }
        })
    }

    # Workspace Load Button
    if ($null -ne $Controls.NavLoadWorkspace) {
        $Controls.NavLoadWorkspace.Add_Click({
            try {
                Write-Log "Load workspace button clicked"
                Load-Workspace
            }
            catch {
                Write-Log "Load Workspace failed: $($_.Exception.Message)" -Level ERROR
                Show-ErrorMessage -Error "Failed to load workspace"
            }
        })
    }

    Write-Log "Navigation event handlers registered successfully"
}

Export-ModuleMember -Function Register-NavigationHandlers
