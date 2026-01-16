<#
.SYNOPSIS
    UI Helper functions for GA-AppLocker GUI

.DESCRIPTION
    Provides utility functions for UI operations, panel management, and SID resolution

.NOTES
    This module contains extracted UI helper functions from the main GUI application.
    These functions handle panel switching, status updates, and SID/group name resolution.
#>

# ============================================================
# Panel Management
# ============================================================

function Show-Panel {
    <#
    .SYNOPSIS
        Shows the specified panel and hides all others

    .DESCRIPTION
        Manages panel visibility by hiding all panels and then showing the requested one.
        Also triggers panel-specific initialization like updating badges.

    .PARAMETER PanelName
        The name of the panel to show (Dashboard, Discovery, Artifacts, Rules, etc.)

    .EXAMPLE
        Show-Panel "Dashboard"
    #>
    param([string]$PanelName)

    if ($null -ne $PanelDashboard) {
        $PanelDashboard.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelDiscovery) {
        $PanelDiscovery.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelArtifacts) {
        $PanelArtifacts.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelRules) {
        $PanelRules.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelDeployment) {
        $PanelDeployment.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelEvents) {
        $PanelEvents.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelCompliance) {
        $PanelCompliance.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelReports) {
        $PanelReports.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelWinRM) {
        $PanelWinRM.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelGroupMgmt) {
        $PanelGroupMgmt.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelAppLockerSetup) {
        $PanelAppLockerSetup.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelGapAnalysis) {
        $PanelGapAnalysis.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelTemplates) {
        $PanelTemplates.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelHelp) {
        $PanelHelp.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelAbout) {
        $PanelAbout.Visibility = [System.Windows.Visibility]::Collapsed
    }

    # CRITICAL FIX: Add null checks to switch statement to prevent null reference errors
    switch ($PanelName) {
        "Dashboard" {
            if ($null -ne $PanelDashboard) {
                $PanelDashboard.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Discovery" {
            if ($null -ne $PanelDiscovery) {
                $PanelDiscovery.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Artifacts" {
            if ($null -ne $PanelArtifacts) {
                $PanelArtifacts.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Rules" {
            if ($null -ne $PanelRules) {
                $PanelRules.Visibility = [System.Windows.Visibility]::Visible
            }
            if (Get-Command Update-Badges -ErrorAction SilentlyContinue) {
                Update-Badges
            }
        }
        "Deployment" {
            if ($null -ne $PanelDeployment) {
                $PanelDeployment.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Events" {
            if ($null -ne $PanelEvents) {
                $PanelEvents.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Compliance" {
            if ($null -ne $PanelCompliance) {
                $PanelCompliance.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Reports" {
            if ($null -ne $PanelReports) {
                $PanelReports.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "WinRM" {
            if ($null -ne $PanelWinRM) {
                $PanelWinRM.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "GroupMgmt" {
            if ($null -ne $PanelGroupMgmt) {
                $PanelGroupMgmt.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "AppLockerSetup" {
            if ($null -ne $PanelAppLockerSetup) {
                $PanelAppLockerSetup.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "GapAnalysis" {
            if ($null -ne $PanelGapAnalysis) {
                $PanelGapAnalysis.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "Templates" {
            if ($null -ne $PanelTemplates) {
                $PanelTemplates.Visibility = [System.Windows.Visibility]::Visible
            }
            if (Get-Command Load-TemplatesList -ErrorAction SilentlyContinue) {
                Load-TemplatesList
            }
        }
        "Help" {
            if ($null -ne $PanelHelp) {
                $PanelHelp.Visibility = [System.Windows.Visibility]::Visible
            }
        }
        "About" {
            if ($null -ne $PanelAbout) {
                $PanelAbout.Visibility = [System.Windows.Visibility]::Visible
            }
        }
    }
}

# ============================================================
# Status Bar and Badge Management
# ============================================================

function Update-StatusBar {
    <#
    .SYNOPSIS
        Updates the main status bar with current environment information

    .DESCRIPTION
        Refreshes all mini status indicators including domain status, mode (Audit/Enforce),
        phase, connected systems, artifacts count, and last sync time.

    .EXAMPLE
        Update-StatusBar
    #>

    # CRITICAL FIX: Add null checks for all status bar controls
    try {
        # Update main status text
        if ($null -ne $StatusText) {
            if ($script:IsWorkgroup) {
                $StatusText.Text = "WORKGROUP MODE - Local scanning available"
            } elseif (-not $script:HasRSAT) {
                $StatusText.Text = "$($script:DomainInfo.dnsRoot) - RSAT required for GPO features"
            } else {
                $StatusText.Text = "$($script:DomainInfo.dnsRoot) - Full features available"
            }
        }

        # Phase 3: Enhanced Context Indicators
        # Domain/Workgroup indicator
        if ($null -ne $MiniStatusDomain) {
            if ($script:IsWorkgroup) {
                $MiniStatusDomain.Text = "WORKGROUP"
                $MiniStatusDomain.Foreground = "#8B949E"
            } else {
                $MiniStatusDomain.Text = "$($script:DomainInfo.netBIOSName)"
                $MiniStatusDomain.Foreground = "#3FB950"
            }
        }

        # Mode indicator (Audit vs Enforce)
        if ($null -ne $MiniStatusMode) {
            try {
                $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
                $hasEnforce = $false
                if ($policy) {
                    foreach ($collection in $policy.RuleCollections) {
                        if ($collection.EnforcementMode -eq "Enabled") {
                            $hasEnforce = $true
                            break
                        }
                    }
                }

                if ($hasEnforce) {
                    $MiniStatusMode.Text = "ENFORCE"
                    $MiniStatusMode.Foreground = "#F85149"
                } else {
                    $MiniStatusMode.Text = "AUDIT"
                    $MiniStatusMode.Foreground = "#3FB950"
                }
            }
            catch {
                $MiniStatusMode.Text = "UNKNOWN"
                $MiniStatusMode.Foreground = "#8B949E"
            }
        }

        # Phase indicator (from GPO quick assignment)
        if ($null -ne $MiniStatusPhase) {
            $currentPhase = $script:CurrentDeploymentPhase
            if ($currentPhase) {
                $MiniStatusPhase.Text = "P$currentPhase"
            } else {
                $MiniStatusPhase.Text = ""
            }
        }

        # Connected systems count
        if ($null -ne $MiniStatusConnected) {
            if ($script:DiscoveredSystems) {
                $onlineCount = @($script:DiscoveredSystems | Where-Object { $_.status -eq "Online" }).Count
                $MiniStatusConnected.Text = "$onlineCount online"
            } else {
                $MiniStatusConnected.Text = "0 systems"
            }
        }

        # Artifacts count
        if ($null -ne $MiniStatusArtifacts) {
            $artifactCount = if ($script:CollectedArtifacts) { $script:CollectedArtifacts.Count } else { 0 }
            $MiniStatusArtifacts.Text = "$artifactCount artifacts"
        }

        # Last sync time
        if ($null -ne $MiniStatusSync) {
            if ($script:LastSyncTime) {
                $timeDiff = (Get-Date) - $script:LastSyncTime
                if ($timeDiff.TotalMinutes -lt 1) {
                    $MiniStatusSync.Text = "Just now"
                } elseif ($timeDiff.TotalMinutes -lt 60) {
                    $MiniStatusSync.Text = "$([int]$timeDiff.TotalMinutes)m ago"
                } else {
                    $MiniStatusSync.Text = "$([int]$timeDiff.TotalHours)h ago"
                }
            } else {
                $MiniStatusSync.Text = "Ready"
            }
        }
    }
    catch {
        # Silently fail - status bar updates are not critical
        Write-Verbose "Update-StatusBar failed: $($_.Exception.Message)"
    }
}

function Update-Badges {
    <#
    .SYNOPSIS
        Updates the Quick Import badge counters in the Rule Generator panel

    .DESCRIPTION
        Refreshes artifact and event count badges with current counts and colors
        based on data availability.

    .EXAMPLE
        Update-Badges
    #>

    # CRITICAL FIX: Add null checks for badge controls
    try {
        # Update artifact count badge
        if ($null -ne $ArtifactCountBadge) {
            $artifactCount = if ($script:CollectedArtifacts) { $script:CollectedArtifacts.Count } else { 0 }
            $ArtifactCountBadge.Text = "$artifactCount"

            # Update badge colors based on availability
            if ($artifactCount -gt 0) {
                $ArtifactCountBadge.Foreground = "#3FB950"
                $ArtifactCountBadge.Background = "#1F6FEB"
            } else {
                $ArtifactCountBadge.Foreground = "#6E7681"
                $ArtifactCountBadge.Background = "#21262D"
            }
        }

        # Update event count badge
        if ($null -ne $EventCountBadge) {
            $eventCount = if ($script:AllEvents) { $script:AllEvents.Count } else { 0 }
            $EventCountBadge.Text = "$eventCount"

            # Update badge colors based on availability
            if ($eventCount -gt 0) {
                $EventCountBadge.Foreground = "#3FB950"
                $EventCountBadge.Background = "#1F6FEB"
            } else {
                $EventCountBadge.Foreground = "#6E7681"
                $EventCountBadge.Background = "#21262D"
            }
        }
    }
    catch {
        # Silently fail - badge updates are not critical
        Write-Verbose "Update-Badges failed: $($_.Exception.Message)"
    }
}

# ============================================================
# SID and Group Name Resolution
# ============================================================

function Get-SelectedSid {
    <#
    .SYNOPSIS
        Gets the SID for the currently selected group in the Rule Generator

    .DESCRIPTION
        Resolves the selected AppLocker group to its SID value, with fallback to Everyone (S-1-1-0)

    .OUTPUTS
        String - The SID value for the selected group

    .EXAMPLE
        $sid = Get-SelectedSid
    #>

    # CRITICAL FIX: Add null check for RuleGroupCombo control
    if ($null -eq $RuleGroupCombo) {
        Write-Verbose "Get-SelectedSid: RuleGroupCombo control is null, returning default SID"
        return "S-1-1-0"
    }

    $selectedItem = $RuleGroupCombo.SelectedItem
    if (-not $selectedItem) { return "S-1-1-0" }

    $tag = $selectedItem.Tag
    switch ($tag) {
        "AppLocker-Admins" {
            try {
                $group = Get-ADGroup "AppLocker-Admins" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-Admins group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "AppLocker-StandardUsers" {
            try {
                $group = Get-ADGroup "AppLocker-StandardUsers" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-StandardUsers group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "AppLocker-Service-Accounts" {
            try {
                $group = Get-ADGroup "AppLocker-Service-Accounts" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-Service-Accounts group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "AppLocker-Installers" {
            try {
                $group = Get-ADGroup "AppLocker-Installers" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-Installers group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "Custom" {
            # CRITICAL FIX: Add null check for CustomSidText control
            if ($null -ne $CustomSidText) {
                $customSid = $CustomSidText.Text.Trim()
                if ($customSid -match "^S-1-") { return $customSid }
            }
            return "S-1-1-0"
        }
        default { return "S-1-1-0" }
    }
}

function Resolve-SidToGroupName {
    <#
    .SYNOPSIS
        Converts a SID to a friendly group name

    .DESCRIPTION
        Resolves well-known SIDs to their friendly names. For AD SIDs, queries Active Directory.

    .PARAMETER Sid
        The SID string to resolve

    .OUTPUTS
        String - The friendly group name, or the original SID if not resolvable

    .EXAMPLE
        Resolve-SidToGroupName "S-1-1-0"
        Returns: "Everyone"
    #>
    param([string]$Sid)

    # Check common SIDs
    $commonSids = @{
        "S-1-1-0" = "Everyone"
        "S-1-5-32-544" = "Administrators"
        "S-1-5-32-545" = "Users"
        "S-1-5-32-546" = "Guests"
        "S-1-5-32-559" = "Performance Log Users"
    }

    if ($commonSids.ContainsKey($Sid)) {
        return $commonSids[$Sid]
    }

    # Check if it's an AppLocker group SID (pattern matching)
    if ($Sid -match "^S-1-5-21-\d+-\d+-\d+-\d+-\d+$") {
        # Try to get from AD
        if (-not $script:IsWorkgroup -and $script:HasRSAT) {
            try {
                $group = Get-ADGroup -Identity $Sid -ErrorAction SilentlyContinue
                if ($group) {
                    return $group.Name
                }
            } catch {
                # Fall through to default
            }
        }
    }

    return $Sid
}

function Get-SidFromGroupName {
    <#
    .SYNOPSIS
        Converts a group name to its SID

    .DESCRIPTION
        Resolves well-known group names to their SIDs. For AD groups, queries Active Directory.

    .PARAMETER GroupName
        The group name to resolve

    .OUTPUTS
        String - The SID value, or S-1-1-0 (Everyone) if not resolvable

    .EXAMPLE
        Get-SidFromGroupName "Administrators"
        Returns: "S-1-5-32-544"
    #>
    param([string]$GroupName)

    # Check common groups
    $commonGroups = @{
        "Everyone" = "S-1-1-0"
        "Administrators" = "S-1-5-32-544"
        "Users" = "S-1-5-32-545"
        "Guests" = "S-1-5-32-546"
    }

    if ($commonGroups.ContainsKey($GroupName)) {
        return $commonGroups[$GroupName]
    }

    # Check AppLocker groups
    if (-not $script:IsWorkgroup -and $script:HasRSAT) {
        try {
            $group = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
            if ($group) {
                return $group.SID.Value
            }
        } catch {
            # Fall through to default
        }
    }

    return "S-1-1-0"  # Default to Everyone
}

# Export module members
Export-ModuleMember -Function Show-Panel, Update-StatusBar, Update-Badges, Get-SelectedSid, Resolve-SidToGroupName, Get-SidFromGroupName
