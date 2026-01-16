<#
.SYNOPSIS
    Dashboard data management and statistics ViewModel

.DESCRIPTION
    Manages dashboard state, health metrics, event statistics, and chart data.
    This ViewModel serves as the data layer for the Dashboard UI panel, providing
    real-time statistics and aggregated metrics without direct UI dependencies.

.NOTES
    Module Name: DashboardViewModel
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: BusinessLogic/EventProcessor, BusinessLogic/PolicyManager

.EXAMPLE
    Import-Module .\DashboardViewModel.ps1

    # Initialize and get dashboard data
    Initialize-DashboardData
    $data = Get-DashboardData
    Write-Host "Health Score: $($data.HealthScore)"

.EXAMPLE
    # Update dashboard with filters
    Update-DashboardData -TimeFilter "Last 24 Hours" -SystemFilter "Server01"
    $chartData = Get-ChartData -ChartType "EventsByType"

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# SCRIPT-SCOPE STATE
# ============================================================

$script:DashboardData = [hashtable]::Synchronized(@{
    HealthScore = 0
    TotalEvents = 0
    AllowedEvents = 0
    BlockedEvents = 0
    AuditEvents = 0
    TotalRules = 0
    ActiveRules = 0
    RulesByType = @{
        Exe = 0
        Msi = 0
        Script = 0
        Dll = 0
        Appx = 0
    }
    TimeFilter = "Last 7 Days"
    SystemFilter = "All Systems"
    LastUpdated = $null
    PolicyStatus = @{
        HasPolicy = $false
        HasExe = $false
        HasMsi = $false
        HasScript = $false
        HasDll = $false
        EnforcementMode = "NotConfigured"
    }
    SystemHealth = @{
        ServiceRunning = $false
        LogsAccessible = $false
        GPOConfigured = $false
        ErrorCount = 0
    }
})

$script:ChartDataCache = [hashtable]::Synchronized(@{
    EventsByType = @()
    EventsOverTime = @()
    RulesByType = @()
    TopBlockedApps = @()
    PublisherDistribution = @()
})

# ============================================================
# PUBLIC FUNCTIONS
# ============================================================

function Initialize-DashboardData {
    <#
    .SYNOPSIS
        Initializes the dashboard data with default values

    .DESCRIPTION
        Resets dashboard state to default values and performs initial data load

    .EXAMPLE
        Initialize-DashboardData
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Initializing dashboard data..."

        # Reset to defaults
        $script:DashboardData.HealthScore = 0
        $script:DashboardData.TotalEvents = 0
        $script:DashboardData.AllowedEvents = 0
        $script:DashboardData.BlockedEvents = 0
        $script:DashboardData.AuditEvents = 0
        $script:DashboardData.TotalRules = 0
        $script:DashboardData.ActiveRules = 0
        $script:DashboardData.TimeFilter = "Last 7 Days"
        $script:DashboardData.SystemFilter = "All Systems"
        $script:DashboardData.LastUpdated = Get-Date

        # Clear chart cache
        $script:ChartDataCache.EventsByType = @()
        $script:ChartDataCache.EventsOverTime = @()
        $script:ChartDataCache.RulesByType = @()
        $script:ChartDataCache.TopBlockedApps = @()
        $script:ChartDataCache.PublisherDistribution = @()

        # Perform initial data load
        Update-DashboardData -TimeFilter "Last 7 Days" -SystemFilter "All Systems"

        Write-Verbose "Dashboard data initialized successfully"
        return @{ success = $true; message = "Dashboard initialized" }
    }
    catch {
        Write-Warning "Failed to initialize dashboard data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-DashboardData {
    <#
    .SYNOPSIS
        Returns current dashboard data

    .DESCRIPTION
        Retrieves the current state of dashboard metrics and statistics

    .OUTPUTS
        Hashtable containing all dashboard metrics

    .EXAMPLE
        $data = Get-DashboardData
        Write-Host "Health Score: $($data.HealthScore)%"
    #>
    [CmdletBinding()]
    param()

    try {
        # Return a copy to prevent external modification
        return @{
            HealthScore = $script:DashboardData.HealthScore
            TotalEvents = $script:DashboardData.TotalEvents
            AllowedEvents = $script:DashboardData.AllowedEvents
            BlockedEvents = $script:DashboardData.BlockedEvents
            AuditEvents = $script:DashboardData.AuditEvents
            TotalRules = $script:DashboardData.TotalRules
            ActiveRules = $script:DashboardData.ActiveRules
            RulesByType = $script:DashboardData.RulesByType.Clone()
            TimeFilter = $script:DashboardData.TimeFilter
            SystemFilter = $script:DashboardData.SystemFilter
            LastUpdated = $script:DashboardData.LastUpdated
            PolicyStatus = $script:DashboardData.PolicyStatus.Clone()
            SystemHealth = $script:DashboardData.SystemHealth.Clone()
        }
    }
    catch {
        Write-Warning "Failed to get dashboard data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-DashboardData {
    <#
    .SYNOPSIS
        Updates dashboard data with current metrics

    .DESCRIPTION
        Queries BusinessLogic layer for current statistics and updates dashboard state.
        Applies time and system filters to the data.

    .PARAMETER TimeFilter
        Time range filter: "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"

    .PARAMETER SystemFilter
        System filter: "All Systems" or specific computer name

    .PARAMETER ForceRefresh
        Forces a refresh even if data was recently updated

    .EXAMPLE
        Update-DashboardData -TimeFilter "Last 24 Hours" -SystemFilter "All Systems"

    .EXAMPLE
        Update-DashboardData -ForceRefresh
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet("Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time")]
        [string]$TimeFilter = "Last 7 Days",

        [Parameter()]
        [string]$SystemFilter = "All Systems",

        [Parameter()]
        [switch]$ForceRefresh
    )

    try {
        Write-Verbose "Updating dashboard data (TimeFilter: $TimeFilter, SystemFilter: $SystemFilter)..."

        # Update filters
        $script:DashboardData.TimeFilter = $TimeFilter
        $script:DashboardData.SystemFilter = $SystemFilter

        # Calculate date range
        $startDate = switch ($TimeFilter) {
            "Last 24 Hours" { (Get-Date).AddHours(-24) }
            "Last 7 Days"   { (Get-Date).AddDays(-7) }
            "Last 30 Days"  { (Get-Date).AddDays(-30) }
            "All Time"      { (Get-Date).AddYears(-1) }
            default         { (Get-Date).AddDays(-7) }
        }

        # Get event statistics (call BusinessLogic layer)
        $eventStats = Get-EventStatistics -StartDate $startDate -ComputerName $SystemFilter

        if ($eventStats -and $eventStats.success) {
            $script:DashboardData.TotalEvents = $eventStats.totalEvents
            $script:DashboardData.AllowedEvents = $eventStats.allowedEvents
            $script:DashboardData.BlockedEvents = $eventStats.blockedEvents
            $script:DashboardData.AuditEvents = $eventStats.auditEvents
        }

        # Get policy health score
        $healthScore = Get-PolicyHealthMetrics

        if ($healthScore -and $healthScore.success) {
            $script:DashboardData.HealthScore = $healthScore.score
            $script:DashboardData.PolicyStatus.HasPolicy = $healthScore.hasPolicy
            $script:DashboardData.PolicyStatus.HasExe = $healthScore.hasExe
            $script:DashboardData.PolicyStatus.HasMsi = $healthScore.hasMsi
            $script:DashboardData.PolicyStatus.HasScript = $healthScore.hasScript
            $script:DashboardData.PolicyStatus.HasDll = $healthScore.hasDll
            $script:DashboardData.PolicyStatus.EnforcementMode = $healthScore.enforcementMode
        }

        # Get rule statistics
        $ruleStats = Get-RuleStatistics

        if ($ruleStats -and $ruleStats.success) {
            $script:DashboardData.TotalRules = $ruleStats.totalRules
            $script:DashboardData.ActiveRules = $ruleStats.activeRules
            $script:DashboardData.RulesByType = @{
                Exe = $ruleStats.exeRules
                Msi = $ruleStats.msiRules
                Script = $ruleStats.scriptRules
                Dll = $ruleStats.dllRules
                Appx = $ruleStats.appxRules
            }
        }

        # Update system health
        Update-SystemHealthStatus

        # Update timestamp
        $script:DashboardData.LastUpdated = Get-Date

        # Invalidate chart cache
        Clear-ChartDataCache

        Write-Verbose "Dashboard data updated successfully"
        return @{ success = $true; message = "Dashboard updated" }
    }
    catch {
        Write-Warning "Failed to update dashboard data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-ChartData {
    <#
    .SYNOPSIS
        Prepares data for dashboard charts

    .DESCRIPTION
        Returns formatted data optimized for charting libraries.
        Uses cached data when available to improve performance.

    .PARAMETER ChartType
        Type of chart data to retrieve

    .OUTPUTS
        Array of chart data objects

    .EXAMPLE
        $data = Get-ChartData -ChartType "EventsByType"
        # Returns: @( @{Label="Allowed"; Value=100}, @{Label="Blocked"; Value=50} )

    .EXAMPLE
        $data = Get-ChartData -ChartType "EventsOverTime"
        # Returns time-series data for line charts
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("EventsByType", "EventsOverTime", "RulesByType", "TopBlockedApps", "PublisherDistribution")]
        [string]$ChartType
    )

    try {
        Write-Verbose "Getting chart data for: $ChartType"

        # Check cache
        if ($script:ChartDataCache[$ChartType] -and $script:ChartDataCache[$ChartType].Count -gt 0) {
            Write-Verbose "Returning cached chart data"
            return $script:ChartDataCache[$ChartType]
        }

        # Generate chart data based on type
        $chartData = switch ($ChartType) {
            "EventsByType" {
                Get-EventsByTypeChartData
            }
            "EventsOverTime" {
                Get-EventsOverTimeChartData
            }
            "RulesByType" {
                Get-RulesByTypeChartData
            }
            "TopBlockedApps" {
                Get-TopBlockedAppsChartData
            }
            "PublisherDistribution" {
                Get-PublisherDistributionChartData
            }
        }

        # Cache the result
        $script:ChartDataCache[$ChartType] = $chartData

        return $chartData
    }
    catch {
        Write-Warning "Failed to get chart data: $($_.Exception.Message)"
        return @()
    }
}

function Get-DashboardSummary {
    <#
    .SYNOPSIS
        Gets a concise summary of dashboard metrics

    .DESCRIPTION
        Returns key metrics formatted for quick overview display

    .OUTPUTS
        Hashtable with summary metrics

    .EXAMPLE
        $summary = Get-DashboardSummary
        Write-Host "Health: $($summary.Health), Events: $($summary.TotalEvents)"
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            Health = "$($script:DashboardData.HealthScore)%"
            TotalEvents = $script:DashboardData.TotalEvents
            BlockedEvents = $script:DashboardData.BlockedEvents
            TotalRules = $script:DashboardData.TotalRules
            Status = if ($script:DashboardData.HealthScore -ge 75) { "Healthy" }
                     elseif ($script:DashboardData.HealthScore -ge 50) { "Warning" }
                     else { "Critical" }
            LastUpdated = if ($script:DashboardData.LastUpdated) {
                $script:DashboardData.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss")
            } else { "Never" }
        }
    }
    catch {
        Write-Warning "Failed to get dashboard summary: $($_.Exception.Message)"
        return @{ Status = "Error"; Message = $_.Exception.Message }
    }
}

function Clear-DashboardData {
    <#
    .SYNOPSIS
        Clears all dashboard data

    .DESCRIPTION
        Resets dashboard state to initial values

    .EXAMPLE
        Clear-DashboardData
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Clearing dashboard data..."
        Initialize-DashboardData
        return @{ success = $true; message = "Dashboard data cleared" }
    }
    catch {
        Write-Warning "Failed to clear dashboard data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================

function Get-EventStatistics {
    param([datetime]$StartDate, [string]$ComputerName)

    # Placeholder - would call BusinessLogic/EventProcessor
    # For now, return sample data structure
    return @{
        success = $true
        totalEvents = 0
        allowedEvents = 0
        blockedEvents = 0
        auditEvents = 0
    }
}

function Get-PolicyHealthMetrics {
    # Placeholder - would call BusinessLogic/PolicyManager
    return @{
        success = $true
        score = 0
        hasPolicy = $false
        hasExe = $false
        hasMsi = $false
        hasScript = $false
        hasDll = $false
        enforcementMode = "NotConfigured"
    }
}

function Get-RuleStatistics {
    # Placeholder - would call BusinessLogic/RuleGenerator
    return @{
        success = $true
        totalRules = 0
        activeRules = 0
        exeRules = 0
        msiRules = 0
        scriptRules = 0
        dllRules = 0
        appxRules = 0
    }
}

function Update-SystemHealthStatus {
    # Check AppLocker service
    try {
        $service = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        $script:DashboardData.SystemHealth.ServiceRunning = ($service -and $service.Status -eq 'Running')
    } catch {
        $script:DashboardData.SystemHealth.ServiceRunning = $false
    }

    # Check log accessibility
    try {
        $log = Get-WinEvent -ListLog "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue
        $script:DashboardData.SystemHealth.LogsAccessible = ($null -ne $log)
    } catch {
        $script:DashboardData.SystemHealth.LogsAccessible = $false
    }

    # Check GPO configuration
    $script:DashboardData.SystemHealth.GPOConfigured = $script:DashboardData.PolicyStatus.HasPolicy
}

function Get-EventsByTypeChartData {
    return @(
        @{ Label = "Allowed"; Value = $script:DashboardData.AllowedEvents; Color = "#28a745" }
        @{ Label = "Blocked"; Value = $script:DashboardData.BlockedEvents; Color = "#dc3545" }
        @{ Label = "Audit"; Value = $script:DashboardData.AuditEvents; Color = "#ffc107" }
    )
}

function Get-EventsOverTimeChartData {
    # Placeholder - would generate time-series data
    return @()
}

function Get-RulesByTypeChartData {
    return @(
        @{ Label = "Exe"; Value = $script:DashboardData.RulesByType.Exe; Color = "#007bff" }
        @{ Label = "Msi"; Value = $script:DashboardData.RulesByType.Msi; Color = "#17a2b8" }
        @{ Label = "Script"; Value = $script:DashboardData.RulesByType.Script; Color = "#6f42c1" }
        @{ Label = "Dll"; Value = $script:DashboardData.RulesByType.Dll; Color = "#fd7e14" }
        @{ Label = "Appx"; Value = $script:DashboardData.RulesByType.Appx; Color = "#20c997" }
    )
}

function Get-TopBlockedAppsChartData {
    # Placeholder - would query top blocked applications
    return @()
}

function Get-PublisherDistributionChartData {
    # Placeholder - would query publisher distribution
    return @()
}

function Clear-ChartDataCache {
    $script:ChartDataCache.EventsByType = @()
    $script:ChartDataCache.EventsOverTime = @()
    $script:ChartDataCache.RulesByType = @()
    $script:ChartDataCache.TopBlockedApps = @()
    $script:ChartDataCache.PublisherDistribution = @()
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Initialize-DashboardData',
    'Get-DashboardData',
    'Update-DashboardData',
    'Get-ChartData',
    'Get-DashboardSummary',
    'Clear-DashboardData'
)
