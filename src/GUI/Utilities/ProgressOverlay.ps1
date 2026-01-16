<#
.SYNOPSIS
    Progress overlay utilities for GA-AppLocker GUI

.DESCRIPTION
    Provides visual progress indicators with overlay functionality
    for long-running operations in the WPF interface.

.NOTES
    Version:        2.0
    Author:         General Atomics - ASI
    Creation Date:  2026-01-16
    Module:         Utilities\ProgressOverlay
#>

# Script-level variables for progress overlay
$script:ProgressOverlay = $null
$script:ProgressBar = $null
$script:ProgressText = $null
$script:ProgressDetailText = $null
$script:ProgressCancelButton = $null
$script:ProgressCallback = $null

function Show-ProgressOverlay {
    <#
    .SYNOPSIS
        Display a progress overlay for long-running operations

    .DESCRIPTION
        Creates a modal overlay with progress bar and messaging.
        Blocks user interaction with the main window until dismissed.

    .PARAMETER Window
        The WPF window to overlay

    .PARAMETER Message
        Main progress message

    .PARAMETER DetailMessage
        Optional detail message

    .PARAMETER IsIndeterminate
        Show indeterminate progress bar (marquee style)

    .PARAMETER CanCancel
        Show cancel button and provide callback

    .PARAMETER CancelCallback
        ScriptBlock to execute when cancel is clicked

    .EXAMPLE
        Show-ProgressOverlay -Window $window -Message "Loading data..." -IsIndeterminate

    .EXAMPLE
        Show-ProgressOverlay -Window $window -Message "Processing files" -CanCancel `
                            -CancelCallback { $script:cancelRequested = $true }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Window]$Window,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$DetailMessage = "",

        [Parameter(Mandatory = $false)]
        [switch]$IsIndeterminate,

        [Parameter(Mandatory = $false)]
        [switch]$CanCancel,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CancelCallback = $null
    )

    # Dismiss any existing overlay
    Remove-ProgressOverlay -Window $Window

    # Create overlay grid
    $script:ProgressOverlay = New-Object System.Windows.Controls.Grid
    $script:ProgressOverlay.Background = [System.Windows.Media.Brush]::Parse("#E0000000")
    $script:ProgressOverlay.Opacity = 0.85

    # Create progress panel
    $progressPanel = New-Object System.Windows.Controls.StackPanel
    $progressPanel.Width = 450
    $progressPanel.Background = [System.Windows.Media.Brush]::Parse("#161B22")
    $progressPanel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $progressPanel.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $progressPanel.Margin = [System.Windows.Thickness]::new(20)

    # Add border
    $border = New-Object System.Windows.Controls.Border
    $border.BorderBrush = [System.Windows.Media.Brush]::Parse("#30363D")
    $border.BorderThickness = [System.Windows.Thickness]::new(1)
    $border.CornerRadius = [System.Windows.CornerRadius]::new(6)
    $border.Padding = [System.Windows.Thickness]::new(24)
    $border.Child = $progressPanel

    # Loading spinner icon (using Unicode)
    $spinnerText = New-Object System.Windows.Controls.TextBlock
    $spinnerText.Text = [char]0x29D7  # Circled hourglass
    $spinnerText.FontSize = 48
    $spinnerText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $spinnerText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
    $spinnerText.Foreground = [System.Windows.Media.Brush]::Parse("#58A6FF")

    # Main message
    $script:ProgressText = New-Object System.Windows.Controls.TextBlock
    $script:ProgressText.Text = $Message
    $script:ProgressText.FontSize = 18
    $script:ProgressText.FontWeight = [System.Windows.FontWeights]::SemiBold
    $script:ProgressText.Foreground = [System.Windows.Media.Brush]::Parse("#FFFFFF")
    $script:ProgressText.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $script:ProgressText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $script:ProgressText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)

    # Progress bar
    $script:ProgressBar = New-Object System.Windows.Controls.ProgressBar
    $script:ProgressBar.Height = 6
    $script:ProgressBar.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
    $script:ProgressBar.Foreground = [System.Windows.Media.Brush]::Parse("#58A6FF")
    $script:ProgressBar.Background = [System.Windows.Media.Brush]::Parse("#30363D")

    if ($IsIndeterminate) {
        $script:ProgressBar.IsIndeterminate = $true
    }
    else {
        $script:ProgressBar.Minimum = 0
        $script:ProgressBar.Maximum = 100
        $script:ProgressBar.Value = 0
    }

    # Detail message
    $script:ProgressDetailText = New-Object System.Windows.Controls.TextBlock
    $script:ProgressDetailText.Text = $DetailMessage
    $script:ProgressDetailText.FontSize = 14
    $script:ProgressDetailText.Foreground = [System.Windows.Media.Brush]::Parse("#8B949E")
    $script:ProgressDetailText.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $script:ProgressDetailText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $script:ProgressDetailText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)

    # Cancel button (if enabled)
    if ($CanCancel) {
        $script:ProgressCancelButton = New-Object System.Windows.Controls.Button
        $script:ProgressCancelButton.Content = "Cancel"
        $script:ProgressCancelButton.Width = 100
        $script:ProgressCancelButton.Height = 36
        $script:ProgressCancelButton.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
        $script:ProgressCancelButton.Background = [System.Windows.Media.Brush]::Parse("#F85149")
        $script:ProgressCancelButton.Foreground = [System.Windows.Media.Brush]::Parse("#FFFFFF")
        $script:ProgressCancelButton.BorderThickness = [System.Windows.Thickness]::new(0)
        $script:ProgressCancelButton.FontSize = 14
        $script:ProgressCancelButton.Cursor = [System.Windows.Input.Cursors]::Hand

        # Hover effects
        $script:ProgressCancelButton.Add_MouseEnter({
            $this.Background = [System.Windows.Media.Brush]::Parse("#FF7B72")
        })
        $script:ProgressCancelButton.Add_MouseLeave({
            $this.Background = [System.Windows.Media.Brush]::Parse("#F85149")
        })

        # Click handler
        $script:ProgressCancelButton.Add_Click({
            Remove-ProgressOverlay -Window $Window
            if ($CancelCallback) {
                & $CancelCallback
            }
            # Log cancellation if logging module is available
            if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
                Write-AuditLog -Action "OPERATION_CANCELLED" -Target $Message -Result 'CANCELLED' `
                              -Details "User cancelled operation"
            }
        }.GetNewClosure())

        $script:ProgressCallback = $CancelCallback
    }

    # Add elements to panel
    $progressPanel.Children.Add($spinnerText) | Out-Null
    $progressPanel.Children.Add($script:ProgressText) | Out-Null
    $progressPanel.Children.Add($script:ProgressBar) | Out-Null
    $progressPanel.Children.Add($script:ProgressDetailText) | Out-Null
    if ($script:ProgressCancelButton) {
        $progressPanel.Children.Add($script:ProgressCancelButton) | Out-Null
    }

    # Add border to overlay
    $script:ProgressOverlay.Children.Add($border) | Out-Null

    # Add overlay to window
    $mainGrid = $Window.FindName("MainGrid")
    if ($mainGrid) {
        $mainGrid.Children.Add($script:ProgressOverlay) | Out-Null
    }
    else {
        # Fallback: add to window content if MainGrid not found
        Write-Warning "MainGrid not found. Progress overlay may not display correctly."
    }

    # Disable main window interaction
    $Window.IsEnabled = $false

    # Force UI update
    $Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [action]{})

    # Log progress start if logging available
    if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
        Write-AuditLog -Action "PROGRESS_STARTED" -Target $Message -Result 'SUCCESS' `
                      -Details "Progress overlay shown"
    }
}

function Update-Progress {
    <#
    .SYNOPSIS
        Update the progress overlay

    .DESCRIPTION
        Updates message, detail, and progress percentage on the overlay

    .PARAMETER Message
        New main message (optional)

    .PARAMETER DetailMessage
        New detail message

    .PARAMETER PercentComplete
        Progress percentage (0-100)

    .PARAMETER CurrentItem
        Current item being processed (for automatic detail generation)

    .PARAMETER TotalItems
        Total items to process

    .EXAMPLE
        Update-Progress -PercentComplete 50 -DetailMessage "Processing file 5 of 10..."

    .EXAMPLE
        Update-Progress -CurrentItem 3 -TotalItems 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$DetailMessage,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete = -1,

        [Parameter(Mandatory = $false)]
        [int]$CurrentItem = 0,

        [Parameter(Mandatory = $false)]
        [int]$TotalItems = 0
    )

    if (-not $script:ProgressOverlay) {
        Write-Warning "Progress overlay is not active. Call Show-ProgressOverlay first."
        return
    }

    # Update main message
    if ($Message) {
        $script:ProgressText.Dispatcher.Invoke([System.Action]{
            $script:ProgressText.Text = $Message
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    }

    # Update detail message
    if ($DetailMessage) {
        $script:ProgressDetailText.Dispatcher.Invoke([System.Action]{
            $script:ProgressDetailText.Text = $DetailMessage
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    }
    elseif ($TotalItems -gt 0) {
        $script:ProgressDetailText.Dispatcher.Invoke([System.Action]{
            $script:ProgressDetailText.Text = "Processing $CurrentItem of $TotalItems..."
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    }

    # Update progress bar
    if ($PercentComplete -ge 0 -and $PercentComplete -le 100) {
        $script:ProgressBar.Dispatcher.Invoke([System.Action]{
            $script:ProgressBar.IsIndeterminate = $false
            $script:ProgressBar.Value = $PercentComplete
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    }
    elseif ($TotalItems -gt 0 -and $CurrentItem -gt 0) {
        $percent = [math]::Min(100, [math]::Max(0, [int](($CurrentItem / $TotalItems) * 100)))
        $script:ProgressBar.Dispatcher.Invoke([System.Action]{
            $script:ProgressBar.IsIndeterminate = $false
            $script:ProgressBar.Value = $percent
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    }
}

function Remove-ProgressOverlay {
    <#
    .SYNOPSIS
        Remove the progress overlay

    .DESCRIPTION
        Dismisses the progress overlay and re-enables the main window

    .PARAMETER Window
        The WPF window

    .EXAMPLE
        Remove-ProgressOverlay -Window $window
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Window]$Window
    )

    if ($script:ProgressOverlay) {
        $mainGrid = $Window.FindName("MainGrid")
        if ($mainGrid) {
            $mainGrid.Dispatcher.Invoke([System.Action]{
                $mainGrid.Children.Remove($script:ProgressOverlay)
            }, [System.Windows.Threading.DispatcherPriority]::Normal)
        }
        $script:ProgressOverlay = $null
    }

    # Re-enable window
    $Window.Dispatcher.Invoke([System.Action]{
        $Window.IsEnabled = $true
    }, [System.Windows.Threading.DispatcherPriority]::Normal)

    # Clear script variables
    $script:ProgressBar = $null
    $script:ProgressText = $null
    $script:ProgressDetailText = $null
    $script:ProgressCancelButton = $null
    $script:ProgressCallback = $null
}

function Invoke-WithProgress {
    <#
    .SYNOPSIS
        Execute a scriptblock with progress indication

    .DESCRIPTION
        Wraps a long-running operation with automatic progress overlay

    .PARAMETER Window
        The WPF window

    .PARAMETER ScriptBlock
        The operation to execute

    .PARAMETER Message
        Progress message

    .PARAMETER IsIndeterminate
        Show indeterminate progress

    .OUTPUTS
        Result from scriptblock

    .EXAMPLE
        $result = Invoke-WithProgress -Window $window -Message "Loading data..." `
                                      -ScriptBlock { Get-AppLockerData } -IsIndeterminate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Window]$Window,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [switch]$IsIndeterminate
    )

    Show-ProgressOverlay -Window $Window -Message $Message -IsIndeterminate:$IsIndeterminate

    try {
        $result = & $ScriptBlock
        Remove-ProgressOverlay -Window $Window
        return $result
    }
    catch {
        Remove-ProgressOverlay -Window $Window
        throw
    }
}

# Export module members
Export-ModuleMember -Function Show-ProgressOverlay, Update-Progress, Remove-ProgressOverlay, Invoke-WithProgress
