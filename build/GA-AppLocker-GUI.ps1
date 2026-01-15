# GA-AppLocker Dashboard GUI
# Windows Forms-based GUI wrapper for GA-AppLocker

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Get the script directory (works for both compiled and script)
if ($env:PS2EXE -eq "1") {
    $scriptDir = $PSScriptRoot
} else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Import modules
$modulePath = Join-Path $scriptDir "src\GA-AppLocker.psm1"
$libPath = Join-Path $scriptDir "src\lib\Common.psm1"

try {
    Import-Module $libPath -Force -ErrorAction Stop
    Import-Module $modulePath -Force -ErrorAction Stop
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load modules: $_`n`nMake sure you're running from the project root directory.",
        "GA-AppLocker Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "GA-AppLocker Dashboard v1.0"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(600, 400)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)

# Create title label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "GA-AppLocker Dashboard"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$titleLabel.Location = New-Object System.Drawing.Point(20, 20)
$titleLabel.Size = New-Object System.Drawing.Size(400, 40)
$form.Controls.Add($titleLabel)

# Create status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Location = New-Object System.Drawing.Point(20, 70)
$statusLabel.Size = New-Object System.Drawing.Size(750, 20)
$statusLabel.ForeColor = [System.Drawing.Color]::Green
$form.Controls.Add($statusLabel)

# Create output textbox
$outputTextBox = New-Object System.Windows.Forms.TextBox
$outputTextBox.Multiline = $true
$outputTextBox.ScrollBars = "Vertical"
$outputTextBox.ReadOnly = $true
$outputTextBox.Location = New-Object System.Drawing.Point(20, 100)
$outputTextBox.Size = New-Object System.Drawing.Size(750, 350)
$outputTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$outputTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$outputTextBox.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 0)
$form.Controls.Add($outputTextBox)

# Function to write output
function Write-Output {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $outputTextBox.AppendText("[$timestamp] $Message`r`n")
    $outputTextBox.SelectionStart = $outputTextBox.Text.Length
    $outputTextBox.ScrollToCaret()
}

# Create button panel
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(20, 460)
$buttonPanel.Size = New-Object System.Drawing.Size(750, 80)
$form.Controls.Add($buttonPanel)

# Create buttons
$buttons = @(
    @{ Name = "Dashboard"; Action = {
        Write-Output "Getting Dashboard Summary..."
        try {
            $result = Get-DashboardSummary | ConvertTo-Json -Depth 10
            $outputTextBox.AppendText("`r`n$result`r`n")
        } catch {
            Write-Output "Error: $_"
        }
    }}
    @{ Name = "Policy Health"; Action = {
        Write-Output "Getting Policy Health Score..."
        try {
            $result = Get-PolicyHealthScore | ConvertTo-Json -Depth 10
            $outputTextBox.AppendText("`r`n$result`r`n")
        } catch {
            Write-Output "Error: $_"
        }
    }}
    @{ Name = "Event Stats"; Action = {
        Write-Output "Getting AppLocker Event Statistics..."
        try {
            $result = Get-AppLockerEventStats | ConvertTo-Json -Depth 10
            $outputTextBox.AppendText("`r`n$result`r`n")
        } catch {
            Write-Output "Error: $_"
        }
    }}
    @{ Name = "Clear"; Action = {
        $outputTextBox.Clear()
        Write-Output "Output cleared."
    }}
)

$x = 0
foreach ($btn in $buttons) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $btn.Name
    $button.Location = New-Object System.Drawing.Point($x, 10)
    $button.Size = New-Object System.Drawing.Size(120, 35)
    $button.Add_Click($btn.Action)
    $buttonPanel.Controls.Add($button)
    $x += 130
}

# Exit button
$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Text = "Exit"
$exitButton.Location = New-Object System.Drawing.Point(650, 10)
$exitButton.Size = New-Object System.Drawing.Size(100, 35)
$exitButton.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
$exitButton.ForeColor = [System.Drawing.Color]::White
$exitButton.Add_Click({ $form.Close() })
$buttonPanel.Controls.Add($exitButton)

# Show the form
Write-Output "GA-AppLocker Dashboard loaded successfully."
[void]$form.ShowDialog()
