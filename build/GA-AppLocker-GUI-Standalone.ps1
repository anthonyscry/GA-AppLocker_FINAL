# GA-AppLocker Dashboard GUI - Standalone Version
# Self-contained GUI with embedded module functions
# Can be compiled with PS2EXE to create a standalone EXE

# Suppress all error popups
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Get the script directory (works for both compiled and script)
if ($env:PS2EXE -eq "1") {
    $scriptDir = $PSScriptRoot
} else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# ============================================================
# EMBEDDED: Common Library Functions
# ============================================================

function ConvertTo-JsonResponse {
    param([hashtable]$Data)
    return ($Data | ConvertTo-Json -Depth 10)
}

# ============================================================
# EMBEDDED: Module 1 - Dashboard Functions
# ============================================================

function Get-AppLockerEventStats {
    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'

    try {
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $logExists) {
            return @{
                success = $true
                allowed = 0
                audit = 0
                blocked = 0
                total = 0
                message = 'AppLocker log not found'
            }
        }
    }
    catch {
        return @{
            success = $true
            allowed = 0
            audit = 0
            blocked = 0
            total = 0
            message = 'AppLocker log not available'
        }
    }

    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction Stop

        $allowed = ($events | Where-Object { $_.Id -eq 8002 }).Count
        $audit = ($events | Where-Object { $_.Id -eq 8003 }).Count
        $blocked = ($events | Where-Object { $_.Id -eq 8004 }).Count

        return @{
            success = $true
            allowed = $allowed
            audit = $audit
            blocked = $blocked
            total = $events.Count
        }
    }
    catch {
        return @{
            success = $true
            allowed = 0
            audit = 0
            blocked = 0
            total = 0
            message = 'No events found'
        }
    }
}

function Get-PolicyHealthScore {
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    }
    catch {
        return @{
            success = $true
            score = 0
            hasPolicy = $false
            hasExe = $false
            hasMsi = $false
            hasScript = $false
            hasDll = $false
            message = 'No AppLocker policy'
        }
    }

    if ($null -eq $policy) {
        return @{
            success = $true
            score = 0
            hasPolicy = $false
            hasExe = $false
            hasMsi = $false
            hasScript = $false
            hasDll = $false
        }
    }

    $hasExe = $false
    $hasMsi = $false
    $hasScript = $false
    $hasDll = $false

    foreach ($collection in $policy.RuleCollections) {
        switch ($collection.RuleCollectionType) {
            'Exe'     { if ($collection.Count -gt 0) { $hasExe = $true } }
            'Msi'     { if ($collection.Count -gt 0) { $hasMsi = $true } }
            'Script'  { if ($collection.Count -gt 0) { $hasScript = $true } }
            'Dll'     { if ($collection.Count -gt 0) { $hasDll = $true } }
        }
    }

    $score = 0
    if ($hasExe)     { $score += 25 }
    if ($hasMsi)     { $score += 25 }
    if ($hasScript)  { $score += 25 }
    if ($hasDll)     { $score += 25 }

    return @{
        success = $true
        score = $score
        hasPolicy = $true
        hasExe = $hasExe
        hasMsi = $hasMsi
        hasScript = $hasScript
        hasDll = $hasDll
    }
}

function Get-DashboardSummary {
    $events = Get-AppLockerEventStats
    $health = Get-PolicyHealthScore

    return @{
        success = $true
        timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        events = $events
        policyHealth = $health
    }
}

# ============================================================
# GUI CODE
# ============================================================

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "GA-AppLocker Dashboard v1.0"
$form.Size = New-Object System.Drawing.Size(850, 650)
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(700, 500)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)

# Apply dark theme
$form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

# Create title panel
$titlePanel = New-Object System.Windows.Forms.Panel
$titlePanel.Location = New-Object System.Drawing.Point(0, 0)
$titlePanel.Size = New-Object System.Drawing.Size(850, 70)
$titlePanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$form.Controls.Add($titlePanel)

# Create title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "GA-AppLocker Dashboard"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.Location = New-Object System.Drawing.Point(20, 10)
$titleLabel.Size = New-Object System.Drawing.Size(400, 30)
$titleLabel.ForeColor = [System.Drawing.Color]::White
$titlePanel.Controls.Add($titleLabel)

# Create subtitle label
$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = "AppLocker Policy Management Tool"
$subtitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subtitleLabel.Location = New-Object System.Drawing.Point(20, 40)
$subtitleLabel.Size = New-Object System.Drawing.Size(300, 20)
$subtitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 200)
$titlePanel.Controls.Add($subtitleLabel)

# Create output textbox
$outputTextBox = New-Object System.Windows.Forms.TextBox
$outputTextBox.Multiline = $true
$outputTextBox.ScrollBars = "Vertical"
$outputTextBox.ReadOnly = $true
$outputTextBox.Location = New-Object System.Drawing.Point(20, 90)
$outputTextBox.Size = New-Object System.Drawing.Size(800, 400)
$outputTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$outputTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$outputTextBox.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 0)
$outputTextBox.BorderStyle = "FixedSingle"
$form.Controls.Add($outputTextBox)

# Function to write output
function Write-GUIOutput {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $outputTextBox.AppendText("[$timestamp] $Message`r`n")
    $outputTextBox.SelectionStart = $outputTextBox.Text.Length
    $outputTextBox.ScrollToCaret()
    $form.Refresh()
}

# Create status bar
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Ready"
$statusLabel.Spring = $true
$statusBar.Items.Add($statusLabel)
$form.Controls.Add($statusBar)

# Create button panel - TWO ROWS
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(20, 500)
$buttonPanel.Size = New-Object System.Drawing.Size(800, 100)
$buttonPanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$form.Controls.Add($buttonPanel)

# Function to create styled button
function New-StyledButton {
    param([string]$Text, [int]$X, [int]$Y, [scriptblock]$OnClick, [string]$Color = "#0078D7")

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size(115, 40)
    $button.FlatStyle = "Flat"
    $button.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $button.ForeColor = [System.Drawing.Color]::White
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $button.Cursor = "Hand"
    $button.Add_Click($OnClick)

    # Add hover effect
    $button.Add_MouseEnter({
        $this.BackColor = [System.Drawing.Color]::FromArgb(28, 151, 234)
    })
    $button.Add_MouseLeave({
        $this.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    })

    return $button
}

# ROW 1: Main function buttons (Y=5)
$dashboardBtn = New-StyledButton "Dashboard" 10 5 {
    $statusLabel.Text = "Getting dashboard summary..."
    Write-GUIOutput "=== DASHBOARD SUMMARY ==="
    try {
        $result = Get-DashboardSummary
        Write-GUIOutput "Timestamp: $($result.timestamp)"
        Write-GUIOutput "`n--- Event Statistics ---"
        Write-GUIOutput "Allowed: $($result.events.allowed)"
        Write-GUIOutput "Audit: $($result.events.audit)"
        Write-GUIOutput "Blocked: $($result.events.blocked)"
        Write-GUIOutput "`n--- Policy Health ---"
        Write-GUIOutput "Score: $($result.policyHealth.score)/100"
        Write-GUIOutput "Has EXE: $($result.policyHealth.hasExe)"
        Write-GUIOutput "Has MSI: $($result.policyHealth.hasMsi)"
        Write-GUIOutput "Has Script: $($result.policyHealth.hasScript)"
        Write-GUIOutput "Has DLL: $($result.policyHealth.hasDll)"
        $statusLabel.Text = "Dashboard summary retrieved"
    } catch {
        Write-GUIOutput "Error: $_"
        $statusLabel.Text = "Error occurred"
    }
}
$buttonPanel.Controls.Add($dashboardBtn)

$policyBtn = New-StyledButton "Policy Health" 135 5 {
    $statusLabel.Text = "Getting policy health score..."
    Write-GUIOutput "=== POLICY HEALTH SCORE ==="
    try {
        $result = Get-PolicyHealthScore
        Write-GUIOutput "Score: $($result.score)/100"
        Write-GUIOutput "Has Policy: $($result.hasPolicy)"
        Write-GUIOutput "`nRule Categories:"
        Write-GUIOutput "  EXE:     $(if ($result.hasExe) { '✓' } else { '✗' })"
        Write-GUIOutput "  MSI:     $(if ($result.hasMsi) { '✓' } else { '✗' })"
        Write-GUIOutput "  Script:  $(if ($result.hasScript) { '✓' } else { '✗' })"
        Write-GUIOutput "  DLL:     $(if ($result.hasDll) { '✓' } else { '✗' })"
        $statusLabel.Text = "Policy health retrieved"
    } catch {
        Write-GUIOutput "Error: $_"
        $statusLabel.Text = "Error occurred"
    }
}
$buttonPanel.Controls.Add($policyBtn)

$eventsBtn = New-StyledButton "Event Stats" 260 5 {
    $statusLabel.Text = "Getting event statistics..."
    Write-GUIOutput "=== APPLOCKER EVENT STATISTICS ==="
    try {
        $result = Get-AppLockerEventStats
        Write-GUIOutput "Total Events: $($result.total)"
        Write-GUIOutput "Allowed (8002): $($result.allowed)"
        Write-GUIOutput "Audit (8003): $($result.audit)"
        Write-GUIOutput "Blocked (8004): $($result.blocked)"
        if ($result.message) {
            Write-GUIOutput "`nMessage: $($result.message)"
        }
        $statusLabel.Text = "Event statistics retrieved"
    } catch {
        Write-GUIOutput "Error: $_"
        $statusLabel.Text = "Error occurred"
    }
}
$buttonPanel.Controls.Add($eventsBtn)

$clearBtn = New-StyledButton "Clear" 385 5 {
    $outputTextBox.Clear()
    Write-GUIOutput "Output cleared."
    $statusLabel.Text = "Output cleared"
}
$clearBtn.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$clearBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(120, 120, 120) })
$clearBtn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100) })
$buttonPanel.Controls.Add($clearBtn)

# ROW 2: Action buttons (Y=50)
$refreshBtn = New-StyledButton "Refresh All" 10 50 {
    $outputTextBox.Clear()
    $statusLabel.Text = "Refreshing all data..."

    Write-GUIOutput "=== REFRESHING ALL DATA ==="
    Write-GUIOutput ""

    # Dashboard
    Write-GUIOutput "--- Dashboard ---"
    try {
        $result = Get-DashboardSummary
        Write-GUIOutput "Timestamp: $($result.timestamp)"
        Write-GUIOutput "Events: Allowed=$($result.events.allowed) Audit=$($result.events.audit) Blocked=$($result.events.blocked)"
        Write-GUIOutput "Policy Score: $($result.policyHealth.score)/100"
    } catch {
        Write-GUIOutput "Error: $_"
    }

    Write-GUIOutput "`n"

    # Events
    Write-GUIOutput "--- Events ---"
    try {
        $result = Get-AppLockerEventStats
        Write-GUIOutput "Total: $($result.total) | Allowed: $($result.allowed) | Audit: $($result.audit) | Blocked: $($result.blocked)"
    } catch {
        Write-GUIOutput "Error: $_"
    }

    $statusLabel.Text = "All data refreshed"
}
$buttonPanel.Controls.Add($refreshBtn)

# Export button
$exportBtn = New-StyledButton "Export Data" 135 50 {
    $statusLabel.Text = "Exporting data..."
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
        $saveDialog.Title = "Export Dashboard Data"
        $saveDialog.FileName = "GA-AppLocker-Export-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

        if ($saveDialog.ShowDialog() -eq "OK") {
            $outputTextBox.Text | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Data exported to: $($saveDialog.FileName)", "Export Complete", "OK", "Information")
            Write-GUIOutput "Exported to: $($saveDialog.FileName)"
        }
        $statusLabel.Text = "Export complete"
    } catch {
        Write-GUIOutput "Export error: $_"
        $statusLabel.Text = "Export failed"
    }
}
$buttonPanel.Controls.Add($exportBtn)

# About button
$aboutBtn = New-StyledButton "About" 260 50 {
    [System.Windows.Forms.MessageBox]::Show(
        "GA-AppLocker Dashboard v1.0`n`nA PowerShell-based tool for managing AppLocker policies.`n`nFeatures:`n• Dashboard Summary`n• Policy Health Scoring`n• Event Statistics`n• Data Export`n`nBuilt with PowerShell and Windows Forms",
        "About GA-AppLocker Dashboard",
        "OK",
        "Information"
    )
}
$buttonPanel.Controls.Add($aboutBtn)

# Exit button
$exitBtn = New-Object System.Windows.Forms.Button
$exitBtn.Text = "Exit"
$exitBtn.Location = New-Object System.Drawing.Point(670, 50)
$exitBtn.Size = New-Object System.Drawing.Size(115, 40)
$exitBtn.FlatStyle = "Flat"
$exitBtn.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
$exitBtn.ForeColor = [System.Drawing.Color]::White
$exitBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$exitBtn.Cursor = "Hand"
$exitBtn.Add_Click({ $form.Close() })
$exitBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(220, 70, 70) })
$exitBtn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50) })
$buttonPanel.Controls.Add($exitBtn)

# Form load event
$form.Add_Load({
    Write-GUIOutput "GA-AppLocker Dashboard loaded successfully."
    Write-GUIOutput "Click a button to get started."
    $statusLabel.Text = "Ready"
})

# Show the form
[void]$form.ShowDialog()
