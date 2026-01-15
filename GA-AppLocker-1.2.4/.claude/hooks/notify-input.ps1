# Notification Hook - Alerts when keyboard input is needed
# Called by Claude Code when automation requires user intervention

param(
    [string]$Message = "Keyboard input required",
    [string]$Title = "Automation Input Needed",
    [switch]$Urgent
)

$ErrorActionPreference = "SilentlyContinue"

# Console output with visual emphasis
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor $(if ($Urgent) { "Red" } else { "Yellow" })
Write-Host "  NOTIFICATION: $Title" -ForegroundColor $(if ($Urgent) { "Red" } else { "Cyan" })
Write-Host "  $Message" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor $(if ($Urgent) { "Red" } else { "Yellow" })
Write-Host ""

# Try Windows toast notification (Windows 10/11)
try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">$Title</text>
            <text id="2">$Message</text>
        </binding>
    </visual>
    <audio src="ms-winsoundevent:Notification.Default"/>
</toast>
"@
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)

    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("GA-AppLocker Automation").Show($toast)
}
catch {
    # Fallback: Try BurntToast module if available
    try {
        if (Get-Module -ListAvailable -Name BurntToast) {
            Import-Module BurntToast -ErrorAction Stop
            New-BurntToastNotification -Text $Title, $Message -Sound $(if ($Urgent) { "Alarm" } else { "Default" })
        }
    }
    catch {
        # No toast available, console output only
    }
}

# Play system sound for urgent notifications
if ($Urgent) {
    try {
        [System.Media.SystemSounds]::Exclamation.Play()
    }
    catch {
        # No audio available
    }
}

# Log to file
$logPath = Join-Path $PSScriptRoot "notification-log.txt"
$logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Title - $Message"
Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
