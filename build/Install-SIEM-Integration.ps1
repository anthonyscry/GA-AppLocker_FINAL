# ============================================================
# AUTOMATED SIEM INTEGRATION INSTALLER
# Run this script to automatically integrate SIEM functionality
# into the GA-AppLocker-GUI-WPF.ps1 file
# ============================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$SourceFile = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1",

    [Parameter(Mandatory=$false)]
    [switch]$Backup = $true,

    [Parameter(Mandatory=$false)]
    [switch]$Force = $false
)

Write-Host @"
============================================================
GA-AppLocker SIEM Integration - Automated Installer
============================================================
"@

# Verify source file exists
if (-not (Test-Path $SourceFile)) {
    Write-Host "[ERROR] Source file not found: $SourceFile" -ForegroundColor Red
    exit 1
}

# Create backup
if ($Backup) {
    $backupPath = "$SourceFile.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "[INFO] Creating backup: $backupPath" -ForegroundColor Cyan
    Copy-Item -Path $SourceFile -Destination $backupPath -Force
}

Write-Host "[INFO] Reading source file..." -ForegroundColor Cyan
$content = Get-Content -Path $SourceFile -Raw -Encoding UTF8

# Check if already integrated
if ($content -match 'PanelSiem.*Visibility.*Collapsed') {
    if (-not $Force) {
        Write-Host "[WARN] SIEM Integration appears to already be installed." -ForegroundColor Yellow
        $response = Read-Host "Continue anyway? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Host "[INFO] Installation cancelled." -ForegroundColor Yellow
            exit 0
        }
    }
}

# Load patches
$siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
$xamlPatchPath = "C:\projects\GA-AppLocker_FINAL\build\SIEM-XAML-Patch.xml"

if (-not (Test-Path $siemModulePath)) {
    Write-Host "[ERROR] SIEM module not found: $siemModulePath" -ForegroundColor Red
    exit 1
}

# Import XAML patch
if (Test-Path $xamlPatchPath) {
    $xamlPatch = Import-Clixml -Path $xamlPatchPath
} else {
    Write-Host "[WARN] XAML patch not found, using embedded XAML..." -ForegroundColor Yellow
    # Use embedded XAML (truncated for brevity - in production, use the full XAML)
    Write-Host "[ERROR] Please run SIEM-Integration-Patch.ps1 first to generate patch files." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Applying patches..." -ForegroundColor Cyan

# Patch 1: Add SIEM button to navigation sidebar
$navButtonPattern = '(<Button x:Name="NavCompliance" Content="Compliance" Style="\{StaticResource NavButton\}"\s+HorizontalAlignment="Stretch" Margin="10,1,5,1"/>)'
$navButtonReplacement = '$1' + "`n" + '                                    <Button x:Name="NavSiem" Content="SIEM Integration" Style="{StaticResource NavButton}"' + "`n" + '                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>'

if ($content -match $navButtonPattern) {
    $content = $content -replace $navButtonPattern, $navButtonReplacement
    Write-Host "[SUCCESS] Added SIEM button to navigation" -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not find NavCompliance button, may already be patched" -ForegroundColor Yellow
}

# Patch 2: Add SIEM Panel XAML before About panel
$aboutPanelPattern = '(<!-- About Panel -->)'
$xamlInsert = $xamlPatch + "`n`n" + '$1'

if ($content -match '<!-- About Panel -->') {
    $content = $content -replace '(?s)(?<=</StackPanel>`n`n)(?=<!-- About Panel -->)', $xamlPatch + "`n`n"
    Write-Host "[SUCCESS] Added SIEM panel XAML" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Could not find About Panel marker" -ForegroundColor Red
    exit 1
}

# Patch 3: Update Show-Panel function
$showPanelPattern = '(?s)(\$PanelAbout\.Visibility = \[System\.Windows\.Visibility\]::Visible)'
if ($content -match $showPanelPattern) {
    $content = $content -replace '(?s)(?<=("Compliance" \{ \$NavCompliance\.Add_Click\(\{`n\s+Show-Panel "Compliance"`n\s+Update-StatusBar`n\s+\}\))', '`n    $NavSiem.Add_Click({`n        Show-Panel "Siem"`n        Update-StatusBar`n    })'
    Write-Host "[SUCCESS] Added NavSiem click handler" -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not find Show-Panel function" -ForegroundColor Yellow
}

# Patch 4: Add PanelSiem to collapse section
$collapsePattern = '\$PanelAbout\.Visibility = \[System\.Windows\.Visibility\]::Collapsed'
if ($content -match $collapsePattern) {
    $content = $content -replace $collapsePattern, '$PanelSiem.Visibility = [System.Windows.Visibility]::Collapsed`n    $PanelAbout.Visibility = [System.Windows.Visibility]::Collapsed'
    Write-Host "[SUCCESS] Added PanelSiem to collapse section" -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not find panel collapse section" -ForegroundColor Yellow
}

# Patch 5: Add PanelSiem to Show-Panel switch
$showPanelSwitchPattern = '(?s)("About" \{ \$PanelAbout\.Visibility = \[System\.Windows\.Visibility\]::Visible \})'
if ($content -match $showPanelSwitchPattern) {
    $content = $content -replace $showPanelSwitchPattern, '"Siem" { $PanelSiem.Visibility = [System.Windows.Visibility]::Visible }`n        $1'
    Write-Host "[SUCCESS] Added Siem case to Show-Panel switch" -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not find Show-Panel switch statement" -ForegroundColor Yellow
}

# Patch 6: Add control initialization
$controlInitPattern = '(?<=\$NavAbout = \$window\.FindName\("NavAbout"\))'
$controlInit = @'

$NavSiem = $window.FindName("NavSiem")
$PanelSiem = $window.FindName("PanelSiem")
$SiemTypeCombo = $window.FindName("SiemTypeCombo")
$SiemServerText = $window.FindName("SiemServerText")
$SiemPortText = $window.FindName("SiemPortText")
$SiemProtocolCombo = $window.FindName("SiemProtocolCombo")
$SiemAuthTypeCombo = $window.FindName("SiemAuthTypeCombo")
$SiemTokenLabel = $window.FindName("SiemTokenLabel")
$SiemTokenBox = $window.FindName("SiemTokenBox")
$SiemPasswordGrid = $window.FindName("SiemPasswordGrid")
$SiemPasswordBox = $window.FindName("SiemPasswordBox")
$SiemSslCheck = $window.FindName("SiemSslCheck")
$FilterAllowedCheck = $window.FindName("FilterAllowedCheck")
$FilterBlockedCheck = $window.FindName("FilterBlockedCheck")
$FilterAuditedCheck = $window.FindName("FilterAuditedCheck")
$SiemSeverityCombo = $window.FindName("SiemSeverityCombo")
$SiemIncludePatternText = $window.FindName("SiemIncludePatternText")
$SiemExcludePatternText = $window.FindName("SiemExcludePatternText")
$SiemBatchSizeText = $window.FindName("SiemBatchSizeText")
$SiemMaxRetriesText = $window.FindName("SiemMaxRetriesText")
$SiemRetryDelayText = $window.FindName("SiemRetryDelayText")
$SiemFallbackText = $window.FindName("SiemFallbackText")
$SiemTestConnectionBtn = $window.FindName("SiemTestConnectionBtn")
$SiemSaveConfigBtn = $window.FindName("SiemSaveConfigBtn")
$SiemLoadConfigBtn = $window.FindName("SiemLoadConfigBtn")
$SiemEnableForwardingCheck = $window.FindName("SiemEnableForwardingCheck")
$SiemToggleForwardingBtn = $window.FindName("SiemToggleForwardingBtn")
$SiemEventsSentText = $window.FindName("SiemEventsSentText")
$SiemEventsFailedText = $window.FindName("SiemEventsFailedText")
$SiemQueueSizeText = $window.FindName("SiemQueueSizeText")
$SiemRateText = $window.FindName("SiemRateText")
$SiemStatusIndicator = $window.FindName("SiemStatusIndicator")
$SiemStatusText = $window.FindName("SiemStatusText")
$SiemLastEventText = $window.FindName("SiemLastEventText")
$SiemEnrichHostCheck = $window.FindName("SiemEnrichHostCheck")
$SiemEnrichADCheck = $window.FindName("SiemEnrichADCheck")
$SiemEnrichThreatCheck = $window.FindName("SiemEnrichThreatCheck")
$SiemEnrichNormalizeCheck = $window.FindName("SiemEnrichNormalizeCheck")
$SiemOutputLog = $window.FindName("SiemOutputLog")
$SiemClearLogBtn = $window.FindName("SiemClearLogBtn")
'@

if ($content -match '\$NavAbout = \$window\.FindName\("NavAbout"\)') {
    $content = $content -replace '(?<=\$NavAbout = \$window\.FindName\("NavAbout"\))', $controlInit
    Write-Host "[SUCCESS] Added control initialization" -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not find control initialization section" -ForegroundColor Yellow
}

# Patch 7: Add event handlers before ShowDialog
$showDialogPattern = '(?s)(\$window\.ShowDialog\(\) \| Out-Null)'
$eventHandlers = @'

# ============================================================
# SIEM INTEGRATION - Load Module and Event Handlers
# ============================================================

# Load SIEM module
$siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
if (Test-Path $siemModulePath) {
    . $siemModulePath
}

# SIEM Type Selection Handler
$SiemTypeCombo.Add_SelectionChanged({
    $selectedItem = $SiemTypeCombo.SelectedItem
    if ($selectedItem) {
        $tag = $selectedItem.Tag.ToString()
        switch ($tag) {
            "Splunk"   { $SiemPortText.Text = "8088" }
            "QRadar"   { $SiemPortText.Text = "514" }
            "LogRhythm" { $SiemPortText.Text = "8300" }
            "Elastic"  { $SiemPortText.Text = "9200" }
            "Syslog"   { $SiemPortText.Text = "514" }
            "RestApi"  { $SiemPortText.Text = "443" }
        }
    }
})

# Authentication Type Handler
$SiemAuthTypeCombo.Add_SelectionChanged({
    $selectedItem = $SiemAuthTypeCombo.SelectedItem
    if ($selectedItem) {
        $content = $selectedItem.Content.ToString()
        switch ($content) {
            "Token/Bearer" {
                $SiemTokenLabel.Text = "Token:"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Collapsed
            }
            "Username/Password" {
                $SiemTokenLabel.Text = "Username:"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Visible
            }
            "Certificate" {
                $SiemTokenLabel.Text = "Certificate Path:"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Collapsed
            }
            "None" {
                $SiemTokenLabel.Text = "N/A"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Collapsed
            }
        }
    }
})

# Test Connection Button Handler
$SiemTestConnectionBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        $config = $script:SiemConfig.Clone()
        $config.SiemType = if ($SiemTypeCombo.SelectedItem) { $SiemTypeCombo.SelectedItem.Tag } else { "Splunk" }
        $config.Server = $SiemServerText.Text
        $config.Port = [int]$SiemPortText.Text
        $config.Protocol = if ($SiemProtocolCombo.SelectedItem) { $SiemProtocolCombo.SelectedItem.Content.ToString() } else { "HTTPS" }
        $config.AuthType = if ($SiemAuthTypeCombo.SelectedItem) { $SiemAuthTypeCombo.SelectedItem.Content.ToString() } else { "Token" }

        if ($SiemTokenBox.SecurePassword) {
            $config.Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SiemTokenBox.SecurePassword))
        } else { $config.Token = "" }

        $config.UseSSL = $SiemSslCheck.IsChecked

        $SiemOutputLog.Text += "`n[INFO] Testing connection to $($config.Server):$($config.Port)..."
        $SiemOutputLog.Foreground = "#58A6FF"

        $result = Test-SiemConnection -Config $config

        if ($result.Success) {
            $SiemOutputLog.Text += "`n[SUCCESS] Connection test successful!"
            $SiemOutputLog.Foreground = "#3FB950"
            $SiemStatusIndicator.Fill = "#3FB950"
            $SiemStatusText.Text = "Connected"
        } else {
            $SiemOutputLog.Text += "`n[ERROR] Connection test failed: $($result.Error)"
            $SiemOutputLog.Foreground = "#F85149"
            $SiemStatusIndicator.Fill = "#F85149"
            $SiemStatusText.Text = "Failed"
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Save Configuration Button Handler
$SiemSaveConfigBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        $script:SiemConfig.SiemType = if ($SiemTypeCombo.SelectedItem) { $SiemTypeCombo.SelectedItem.Tag } else { "Splunk" }
        $script:SiemConfig.Server = $SiemServerText.Text
        $script:SiemConfig.Port = [int]$SiemPortText.Text
        $script:SiemConfig.Protocol = if ($SiemProtocolCombo.SelectedItem) { $SiemProtocolCombo.SelectedItem.Content.ToString() } else { "HTTPS" }
        $script:SiemConfig.AuthType = if ($SiemAuthTypeCombo.SelectedItem) { $SiemAuthTypeCombo.SelectedItem.Content.ToString() } else { "Token" }

        if ($SiemTokenBox.SecurePassword) {
            $script:SiemConfig.Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SiemTokenBox.SecurePassword))
        }

        if ($SiemPasswordBox.SecurePassword) {
            $script:SiemConfig.Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SiemPasswordBox.SecurePassword))
        }

        $script:SiemConfig.UseSSL = $SiemSslCheck.IsChecked
        $script:SiemConfig.BatchSize = [int]$SiemBatchSizeText.Text
        $script:SiemConfig.MaxRetries = [int]$SiemMaxRetriesText.Text
        $script:SiemConfig.RetryDelay = [int]$SiemRetryDelayText.Text
        $script:SiemConfig.FallbackEndpoint = $SiemFallbackText.Text

        $script:SiemConfig.Filters.Allowed = $FilterAllowedCheck.IsChecked
        $script:SiemConfig.Filters.Blocked = $FilterBlockedCheck.IsChecked
        $script:SiemConfig.Filters.Audited = $FilterAuditedCheck.IsChecked
        $script:SiemConfig.Filters.MinSeverity = if ($SiemSeverityCombo.SelectedItem) { $SiemSeverityCombo.SelectedItem.Content.ToString() } else { "All" }
        $script:SiemConfig.Filters.IncludePattern = if ($SiemIncludePatternText.Text) { $SiemIncludePatternText.Text } else { $null }
        $script:SiemConfig.Filters.ExcludePattern = if ($SiemExcludePatternText.Text) { $SiemExcludePatternText.Text } else { $null }

        $script:SiemConfig.Enrichment.AddHostMetadata = $SiemEnrichHostCheck.IsChecked
        $script:SiemConfig.Enrichment.AddADInfo = $SiemEnrichADCheck.IsChecked
        $script:SiemConfig.Enrichment.AddThreatIntel = $SiemEnrichThreatCheck.IsChecked
        $script:SiemConfig.Enrichment.NormalizeTimestamps = $SiemEnrichNormalizeCheck.IsChecked

        $result = Save-SiemConfig

        if ($result.Success) {
            $SiemOutputLog.Text += "`n[SUCCESS] Configuration saved to: $($result.Path)"
            $SiemOutputLog.Foreground = "#3FB950"
        } else {
            $SiemOutputLog.Text += "`n[ERROR] Failed to save: $($result.Error)"
            $SiemOutputLog.Foreground = "#F85149"
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Load Configuration Button Handler
$SiemLoadConfigBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        $result = Load-SiemConfig

        if ($result.Success) {
            $config = $result.Config

            $SiemServerText.Text = $config.Server
            $SiemPortText.Text = $config.Port.ToString()
            $SiemBatchSizeText.Text = $config.BatchSize.ToString()
            $SiemMaxRetriesText.Text = $config.MaxRetries.ToString()
            $SiemRetryDelayText.Text = $config.RetryDelay.ToString()
            $SiemFallbackText.Text = $config.FallbackEndpoint

            foreach ($item in $SiemTypeCombo.Items) {
                if ($item.Tag -eq $config.SiemType) {
                    $SiemTypeCombo.SelectedItem = $item
                    break
                }
            }

            $SiemSslCheck.IsChecked = $config.UseSSL
            $FilterAllowedCheck.IsChecked = $config.Filters.Allowed
            $FilterBlockedCheck.IsChecked = $config.Filters.Blocked
            $FilterAuditedCheck.IsChecked = $config.Filters.Audited
            $SiemEnrichHostCheck.IsChecked = $config.Enrichment.AddHostMetadata
            $SiemEnrichADCheck.IsChecked = $config.Enrichment.AddADInfo
            $SiemEnrichThreatCheck.IsChecked = $config.Enrichment.AddThreatIntel
            $SiemEnrichNormalizeCheck.IsChecked = $config.Enrichment.NormalizeTimestamps

            $SiemOutputLog.Text += "`n[SUCCESS] Configuration loaded successfully"
            $SiemOutputLog.Foreground = "#3FB950"
        } else {
            $SiemOutputLog.Text += "`n[ERROR] Failed to load: $($result.Error)"
            $SiemOutputLog.Foreground = "#F85149"
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Toggle Forwarding Button Handler
$SiemToggleForwardingBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        if ($script:SiemConfig.Enabled) {
            $result = Stop-EventForwarder
            $SiemToggleForwardingBtn.Content = "Start Forwarding"
            $SiemStatusIndicator.Fill = "#6E7681"
            $SiemStatusText.Text = "Stopped"

            if ($result.Success) {
                $SiemOutputLog.Text += "`n[SUCCESS] Event forwarding stopped"
                $SiemOutputLog.Foreground = "#3FB950"
            }
        } else {
            $result = Start-EventForwarder

            if ($result.Success) {
                $SiemToggleForwardingBtn.Content = "Stop Forwarding"
                $SiemStatusIndicator.Fill = "#3FB950"
                $SiemStatusText.Text = "Running"
                $SiemOutputLog.Text += "`n[SUCCESS] Event forwarding started (Job ID: $($result.JobId))"
                $SiemOutputLog.Foreground = "#3FB950"

                $timer = New-Object System.Windows.Threading.DispatcherTimer
                $timer.Interval = [TimeSpan]::FromSeconds(5)
                $timer.Tag = @{ OutputLog = $SiemOutputLog; EventsSentText = $SiemEventsSentText; EventsFailedText = $SiemEventsFailedText; QueueSizeText = $SiemQueueSizeText; RateText = $SiemRateText; LastEventText = $SiemLastEventText }
                $timer.Add_Tick({
                    $stats = Get-ForwarderStatistics
                    $this.Tag.EventsSentText.Text = $stats.EventsSent.ToString()
                    $this.Tag.EventsFailedText.Text = $stats.EventsFailed.ToString()
                    $this.Tag.QueueSizeText.Text = $stats.QueueSize.ToString()
                    $this.Tag.RateText.Text = $stats.EventsPerMinute.ToString("F1")
                    if ($stats.LastEventTime) {
                        $this.Tag.LastEventText.Text = "Last event: " + $stats.LastEventTime.ToString("HH:mm:ss")
                    }
                })
                $timer.Start()
            } else {
                $SiemOutputLog.Text += "`n[ERROR] Failed to start forwarding: $($result.Error)"
                $SiemOutputLog.Foreground = "#F85149"
            }
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Clear Log Button Handler
$SiemClearLogBtn.Add_Click({
    $SiemOutputLog.Text = "SIEM Integration ready..."
    $SiemOutputLog.Foreground = "#3FB950"
})

'@

if ($content -match '\$window\.ShowDialog\(\)') {
    $content = $content -replace '(?s)(?=[^\n]*\$window\.ShowDialog\(\))', $eventHandlers
    Write-Host "[SUCCESS] Added SIEM event handlers" -ForegroundColor Green
} else {
    Write-Host "[WARN] Could not find ShowDialog() call" -ForegroundColor Yellow
}

# Write modified content
Write-Host "[INFO] Writing modified file..." -ForegroundColor Cyan
$content | Set-Content -Path $SourceFile -Encoding UTF8 -NoNewline

Write-Host @"
============================================================
INSTALLATION COMPLETE!
============================================================

Files modified:
- $SourceFile

Backup created:
- $backupPath

Next steps:
1. Launch GA-AppLocker-GUI-WPF.ps1
2. Click "SIEM Integration" in the sidebar
3. Configure your SIEM endpoint
4. Test the connection
5. Save your configuration
6. Start event forwarding

For detailed documentation, see:
C:\projects\GA-AppLocker_FINAL\build\SIEM-INTEGRATION-README.md

============================================================
"@ -ForegroundColor Green
