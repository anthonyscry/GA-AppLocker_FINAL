<#
.SYNOPSIS
    Application configuration and constants

.DESCRIPTION
    Centralized configuration management for the GA-AppLocker GUI,
    including color schemes, application metadata, and default settings.

.NOTES
    Version:        2.0
    Author:         General Atomics - ASI
    Creation Date:  2026-01-16
    Module:         Core\Configuration
#>

# ============================================================
# COLOR SCHEME (GitHub Dark Theme)
# ============================================================

$script:Colors = @{
    # Primary backgrounds
    Background = "#0D1117"          # Main background (darkest)
    BackgroundAlt = "#161B22"       # Alternative background (lighter)
    BackgroundPanel = "#21262D"     # Panel background

    # Foregrounds
    Foreground = "#C9D1D9"          # Primary text color
    ForegroundDim = "#8B949E"       # Dimmed text
    ForegroundBright = "#E6EDF3"    # Bright text

    # Accents
    Primary = "#58A6FF"             # Primary blue
    Success = "#3FB950"             # Success green
    Warning = "#D29922"             # Warning amber
    Danger = "#F85149"              # Error/danger red
    Info = "#1F6FEB"                # Info blue

    # Borders and dividers
    BorderDark = "#30363D"          # Dark border
    BorderLight = "#484F58"         # Light border

    # Special colors
    SuccessDark = "#238636"         # Dark green
    SuccessLight = "#2EA043"        # Light green
    DangerLight = "#FF7B72"         # Light red

    # Hover states
    HoverBackground = "#161B22"     # Hover background
    ActiveBackground = "#21262D"    # Active/selected background
}

# ============================================================
# APPLICATION METADATA
# ============================================================

$script:AppConfig = @{
    Title = "GA-AppLocker Management Console"
    Version = "2.0.0"
    Author = "General Atomics - ASI"
    Copyright = "Copyright � 2024-2026 General Atomics"
    Description = "Enterprise AppLocker policy management and monitoring"

    # Paths
    LogPath = "$env:TEMP\GA-AppLocker"
    AuditLogPath = "C:\GA-AppLocker\logs\audit.log"
    DefaultReportPath = "$env:USERPROFILE\Documents\GA-AppLocker\Reports"

    # Logging configuration
    MaxLogSizeMB = 50
    LogRetentionDays = 90

    # Session configuration
    SessionTimeoutMinutes = 30
    AutoSaveEnabled = $true

    # Performance settings
    MaxEventRecords = 10000
    MaxConcurrentOperations = 5
    DefaultProgressDelay = 100  # milliseconds
}

# ============================================================
# DEFAULT USER SETTINGS
# ============================================================

$script:DefaultSettings = @{
    # Dashboard filters
    TimeFilter = "Last 7 Days"
    SystemFilter = "All Systems"
    EventTypeFilter = "All Events"

    # Policy settings
    RuleGroup = "Everyone"
    DefaultAction = "Deny"
    DefaultRuleType = "Publisher"

    # UI preferences
    Theme = "Dark"
    CompactView = $false
    ShowTooltips = $true

    # Report preferences
    DefaultReportType = "Executive"
    DefaultReportFormat = "HTML"
    IncludeCharts = $true

    # Advanced options
    EnableDetailedLogging = $false
    EnableAuditTrail = $true
    EnableNotifications = $true
}

# ============================================================
# TIME FILTER OPTIONS
# ============================================================

$script:TimeFilterOptions = @(
    "Last Hour"
    "Last 24 Hours"
    "Last 7 Days"
    "Last 30 Days"
    "Last 90 Days"
    "Custom Range"
)

# ============================================================
# EVENT TYPE MAPPINGS
# ============================================================

$script:EventTypeMappings = @{
    8002 = @{ Name = "Allowed"; Color = "Success"; Icon = "✓" }
    8003 = @{ Name = "Audited"; Color = "Warning"; Icon = "!" }
    8004 = @{ Name = "Blocked"; Color = "Danger"; Icon = "✖" }
}

# ============================================================
# PUBLIC FUNCTIONS
# ============================================================

function Get-AppConfiguration {
    <#
    .SYNOPSIS
        Get application configuration settings

    .DESCRIPTION
        Returns the application configuration hashtable

    .OUTPUTS
        Hashtable containing application configuration

    .EXAMPLE
        $config = Get-AppConfiguration
        Write-Host "App Version: $($config.Version)"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:AppConfig.Clone()
}

function Get-ColorScheme {
    <#
    .SYNOPSIS
        Get the color scheme configuration

    .DESCRIPTION
        Returns the GitHub dark theme color scheme hashtable

    .OUTPUTS
        Hashtable containing color definitions

    .EXAMPLE
        $colors = Get-ColorScheme
        $backgroundColor = $colors.Background
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:Colors.Clone()
}

function Get-DefaultSettings {
    <#
    .SYNOPSIS
        Get default user settings

    .DESCRIPTION
        Returns the default settings hashtable

    .OUTPUTS
        Hashtable containing default settings

    .EXAMPLE
        $settings = Get-DefaultSettings
        $timeFilter = $settings.TimeFilter
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return $script:DefaultSettings.Clone()
}

function Get-TimeFilterOptions {
    <#
    .SYNOPSIS
        Get available time filter options

    .DESCRIPTION
        Returns an array of valid time filter options

    .OUTPUTS
        Array of time filter strings

    .EXAMPLE
        $filters = Get-TimeFilterOptions
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param()

    return $script:TimeFilterOptions
}

function Get-EventTypeMapping {
    <#
    .SYNOPSIS
        Get event type mapping information

    .DESCRIPTION
        Returns event type mappings for AppLocker event IDs

    .PARAMETER EventId
        Optional event ID to get specific mapping

    .OUTPUTS
        Hashtable containing event type mappings

    .EXAMPLE
        $mapping = Get-EventTypeMapping -EventId 8004
        Write-Host "Event type: $($mapping.Name)"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [int]$EventId
    )

    if ($EventId) {
        return $script:EventTypeMappings[$EventId]
    }

    return $script:EventTypeMappings.Clone()
}

function Set-AppConfiguration {
    <#
    .SYNOPSIS
        Update application configuration

    .DESCRIPTION
        Updates one or more application configuration values

    .PARAMETER Settings
        Hashtable of settings to update

    .EXAMPLE
        Set-AppConfiguration -Settings @{ SessionTimeoutMinutes = 60 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Settings
    )

    foreach ($key in $Settings.Keys) {
        if ($script:AppConfig.ContainsKey($key)) {
            $script:AppConfig[$key] = $Settings[$key]
            Write-Verbose "Updated configuration: $key = $($Settings[$key])"
        }
        else {
            Write-Warning "Unknown configuration key: $key"
        }
    }
}

# Export module members
Export-ModuleMember -Function Get-AppConfiguration, Get-ColorScheme, Get-DefaultSettings, `
                              Get-TimeFilterOptions, Get-EventTypeMapping, Set-AppConfiguration
