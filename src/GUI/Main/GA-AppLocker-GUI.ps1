<#
.SYNOPSIS
    GA-AppLocker Management Console - Modular Architecture

.DESCRIPTION
    Main entry point for the refactored GA-AppLocker GUI application.
    Loads all modules and orchestrates the application startup.

    This is a complete rewrite of the original monolithic GUI into a clean,
    modular architecture following MVVM patterns and separation of concerns.

.PARAMETER Verbose
    Enable verbose logging output during startup

.PARAMETER Debug
    Enable debug mode with additional diagnostic information

.PARAMETER NoSplash
    Skip the splash screen and load directly

.PARAMETER DevelopmentMode
    Enable development mode with relaxed error handling and extra logging

.PARAMETER ModuleValidation
    Perform thorough module validation before loading

.EXAMPLE
    .\GA-AppLocker-GUI.ps1
    Start the application normally

.EXAMPLE
    .\GA-AppLocker-GUI.ps1 -Verbose -Debug
    Start with detailed logging and debug information

.EXAMPLE
    .\GA-AppLocker-GUI.ps1 -DevelopmentMode
    Start in development mode for testing

.NOTES
    Author: General Atomics - ASI
    Version: 2.0.0 (Refactored)
    Date: 2026-01-16
    Requires: PowerShell 5.1 or higher

    Architecture Overview:
    ├── Core/               - Application initialization and configuration
    ├── Utilities/          - Cross-cutting concerns (logging, validation, formatting)
    ├── DataAccess/         - Data layer for external systems (AD, Registry, EventLog)
    ├── BusinessLogic/      - Core business rules and processing
    ├── UI/                 - UI helpers and components
    ├── ViewModels/         - MVVM data binding and state management
    ├── EventHandlers/      - UI event handling and coordination
    ├── HelpSystem/         - Context-sensitive help
    ├── Charting/           - Dashboard visualizations
    ├── Filtering/          - Advanced filtering capabilities
    └── Main/               - Application orchestration (this file)
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Verbose,

    [Parameter(Mandatory=$false)]
    [switch]$Debug,

    [Parameter(Mandatory=$false)]
    [switch]$NoSplash,

    [Parameter(Mandatory=$false)]
    [switch]$DevelopmentMode,

    [Parameter(Mandatory=$false)]
    [switch]$ModuleValidation
)

#region Script Configuration and Global Variables

$ErrorActionPreference = if ($DevelopmentMode) { "Continue" } else { "Stop" }
$VerbosePreference = if ($Verbose -or $Debug) { "Continue" } else { "SilentlyContinue" }
$DebugPreference = if ($Debug) { "Continue" } else { "SilentlyContinue" }

# Script paths
$script:ScriptPath = $PSScriptRoot
$script:GuiRoot = Split-Path $script:ScriptPath -Parent
$script:ProjectRoot = Split-Path (Split-Path $script:GuiRoot -Parent) -Parent

# Performance tracking
$script:StartupTimer = [System.Diagnostics.Stopwatch]::StartNew()
$script:ModuleLoadTimes = @{}

# Module metadata
$script:RequiredModuleVersion = "2.0.0"
$script:LoadedModules = @{}

# Application state
$script:Window = $null
$script:Controls = @{}
$script:ViewModels = @{}
$script:IsInitialized = $false

#endregion

#region Helper Functions

function Write-StartupLog {
    <#
    .SYNOPSIS
        Writes formatted startup log messages
    #>
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info',
        [switch]$NoNewline
    )

    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Debug'   { 'Magenta' }
        default   { 'Cyan' }
    }

    $prefix = switch ($Level) {
        'Success' { '[OK]' }
        'Warning' { '[!!]' }
        'Error'   { '[XX]' }
        'Debug'   { '[DBG]' }
        default   { '[**]' }
    }

    $params = @{
        Object = "[$timestamp] $prefix $Message"
        ForegroundColor = $color
    }

    if ($NoNewline) { $params['NoNewline'] = $true }

    Write-Host @params
}

function Get-ModuleLoadOrder {
    <#
    .SYNOPSIS
        Returns modules in correct dependency order
    #>
    return @(
        # Layer 1: Core (no dependencies)
        @{
            Path = "$script:GuiRoot/Core/Initialize-Application.ps1"
            Name = "Core.Initialize"
            Layer = 1
        }
        @{
            Path = "$script:GuiRoot/Core/Configuration.ps1"
            Name = "Core.Configuration"
            Layer = 1
        }

        # Layer 2: Utilities (depends on Core)
        @{
            Path = "$script:GuiRoot/Utilities/Logging.ps1"
            Name = "Utilities.Logging"
            Layer = 2
        }
        @{
            Path = "$script:GuiRoot/Utilities/ProgressOverlay.ps1"
            Name = "Utilities.ProgressOverlay"
            Layer = 2
        }
        @{
            Path = "$script:GuiRoot/Utilities/Validation.ps1"
            Name = "Utilities.Validation"
            Layer = 2
        }
        @{
            Path = "$script:GuiRoot/Utilities/Formatting.ps1"
            Name = "Utilities.Formatting"
            Layer = 2
        }

        # Layer 3: DataAccess (depends on Utilities)
        @{
            Path = "$script:GuiRoot/DataAccess/EventLog-DataAccess.ps1"
            Name = "DataAccess.EventLog"
            Layer = 3
        }
        @{
            Path = "$script:GuiRoot/DataAccess/ActiveDirectory-DataAccess.ps1"
            Name = "DataAccess.ActiveDirectory"
            Layer = 3
        }
        @{
            Path = "$script:GuiRoot/DataAccess/FileSystem-DataAccess.ps1"
            Name = "DataAccess.FileSystem"
            Layer = 3
        }
        @{
            Path = "$script:GuiRoot/DataAccess/Registry-DataAccess.ps1"
            Name = "DataAccess.Registry"
            Layer = 3
        }

        # Layer 4: BusinessLogic (depends on DataAccess, Utilities)
        @{
            Path = "$script:GuiRoot/BusinessLogic/RuleGenerator.ps1"
            Name = "BusinessLogic.RuleGenerator"
            Layer = 4
        }
        @{
            Path = "$script:GuiRoot/BusinessLogic/EventProcessor.ps1"
            Name = "BusinessLogic.EventProcessor"
            Layer = 4
        }
        @{
            Path = "$script:GuiRoot/BusinessLogic/PolicyManager.ps1"
            Name = "BusinessLogic.PolicyManager"
            Layer = 4
        }
        @{
            Path = "$script:GuiRoot/BusinessLogic/ComplianceReporter.ps1"
            Name = "BusinessLogic.ComplianceReporter"
            Layer = 4
        }

        # Layer 5: UI Components (depends on Utilities)
        @{
            Path = "$script:GuiRoot/UI/UI-Helpers.ps1"
            Name = "UI.Helpers"
            Layer = 5
        }
        @{
            Path = "$script:GuiRoot/UI/UI-Components.ps1"
            Name = "UI.Components"
            Layer = 5
        }

        # Layer 6: Supporting Services (depends on Utilities, BusinessLogic)
        @{
            Path = "$script:GuiRoot/HelpSystem/HelpContent.ps1"
            Name = "HelpSystem.Content"
            Layer = 6
        }
        @{
            Path = "$script:GuiRoot/HelpSystem/HelpViewer.ps1"
            Name = "HelpSystem.Viewer"
            Layer = 6
        }
        @{
            Path = "$script:GuiRoot/Charting/ChartData.ps1"
            Name = "Charting.Data"
            Layer = 6
        }
        @{
            Path = "$script:GuiRoot/Charting/ChartRendering.ps1"
            Name = "Charting.Rendering"
            Layer = 6
        }
        @{
            Path = "$script:GuiRoot/Filtering/FilterHelpers.ps1"
            Name = "Filtering.Helpers"
            Layer = 6
        }
        @{
            Path = "$script:GuiRoot/Filtering/RuleFilters.ps1"
            Name = "Filtering.Rules"
            Layer = 6
        }
        @{
            Path = "$script:GuiRoot/Filtering/EventFilters.ps1"
            Name = "Filtering.Events"
            Layer = 6
        }

        # Layer 7: ViewModels (depends on BusinessLogic, DataAccess)
        @{
            Path = "$script:GuiRoot/ViewModels/DashboardViewModel.ps1"
            Name = "ViewModel.Dashboard"
            Layer = 7
        }
        @{
            Path = "$script:GuiRoot/ViewModels/RulesViewModel.ps1"
            Name = "ViewModel.Rules"
            Layer = 7
        }
        @{
            Path = "$script:GuiRoot/ViewModels/EventsViewModel.ps1"
            Name = "ViewModel.Events"
            Layer = 7
        }
        @{
            Path = "$script:GuiRoot/ViewModels/DeploymentViewModel.ps1"
            Name = "ViewModel.Deployment"
            Layer = 7
        }
        @{
            Path = "$script:GuiRoot/ViewModels/ComplianceViewModel.ps1"
            Name = "ViewModel.Compliance"
            Layer = 7
        }
        @{
            Path = "$script:GuiRoot/ViewModels/DiscoveryViewModel.ps1"
            Name = "ViewModel.Discovery"
            Layer = 7
        }

        # Layer 8: EventHandlers (depends on ViewModels, UI-Helpers, all above)
        @{
            Path = "$script:GuiRoot/EventHandlers/Navigation-Handlers.ps1"
            Name = "EventHandlers.Navigation"
            Layer = 8
        }
        @{
            Path = "$script:GuiRoot/EventHandlers/Dashboard-Handlers.ps1"
            Name = "EventHandlers.Dashboard"
            Layer = 8
        }
        @{
            Path = "$script:GuiRoot/EventHandlers/Rules-Handlers.ps1"
            Name = "EventHandlers.Rules"
            Layer = 8
        }
        @{
            Path = "$script:GuiRoot/EventHandlers/Events-Handlers.ps1"
            Name = "EventHandlers.Events"
            Layer = 8
        }
        @{
            Path = "$script:GuiRoot/EventHandlers/Deployment-Handlers.ps1"
            Name = "EventHandlers.Deployment"
            Layer = 8
        }
        @{
            Path = "$script:GuiRoot/EventHandlers/Compliance-Handlers.ps1"
            Name = "EventHandlers.Compliance"
            Layer = 8
        }
    )
}

function Test-ModuleFile {
    <#
    .SYNOPSIS
        Validates a module file before loading
    #>
    param(
        [string]$Path,
        [string]$ModuleName
    )

    if (-not (Test-Path $Path)) {
        throw "Module file not found: $Path"
    }

    if ($ModuleValidation) {
        # Perform syntax validation
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize(
            (Get-Content $Path -Raw),
            [ref]$errors
        )

        if ($errors.Count -gt 0) {
            $errorMsg = $errors | ForEach-Object { "  Line $($_.Token.StartLine): $($_.Message)" }
            throw "Syntax errors in $ModuleName:`n$($errorMsg -join "`n")"
        }
    }

    return $true
}

function Import-GuiModule {
    <#
    .SYNOPSIS
        Imports a single GUI module with error handling and timing
    #>
    param(
        [hashtable]$ModuleInfo
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        Write-StartupLog "Loading $($ModuleInfo.Name)..." -Level Debug

        # Validate module file exists
        if (-not (Test-Path $ModuleInfo.Path)) {
            throw "Module file not found: $($ModuleInfo.Path)"
        }

        # Validate module file syntax if requested
        if ($ModuleValidation) {
            Test-ModuleFile -Path $ModuleInfo.Path -ModuleName $ModuleInfo.Name | Out-Null
        }

        # Dot-source the module in the current scope
        # NOTE: Export-ModuleMember in modules has no effect with dot-sourcing
        # All functions are automatically available in the calling scope
        . $ModuleInfo.Path

        # Verify the module actually loaded something
        if (-not $?) {
            throw "Dot-sourcing returned error for $($ModuleInfo.Path)"
        }

        $timer.Stop()
        $script:ModuleLoadTimes[$ModuleInfo.Name] = $timer.ElapsedMilliseconds
        $script:LoadedModules[$ModuleInfo.Name] = @{
            Path = $ModuleInfo.Path
            LoadTime = $timer.ElapsedMilliseconds
            Layer = $ModuleInfo.Layer
            LoadedAt = Get-Date
        }

        Write-StartupLog "$($ModuleInfo.Name) loaded ($($timer.ElapsedMilliseconds)ms)" -Level Success

        return @{
            Success = $true
            Module = $ModuleInfo.Name
            LoadTime = $timer.ElapsedMilliseconds
        }
    }
    catch {
        $timer.Stop()
        Write-StartupLog "Failed to load $($ModuleInfo.Name): $_" -Level Error

        if (-not $DevelopmentMode) {
            throw "Critical module load failure: $($ModuleInfo.Name) - $_"
        }

        return @{
            Success = $false
            Module = $ModuleInfo.Name
            Error = $_.Exception.Message
        }
    }
}

function Import-GuiModules {
    <#
    .SYNOPSIS
        Loads all GUI modules in correct dependency order
    #>

    Write-StartupLog "Loading GA-AppLocker GUI modules..." -Level Info

    $modules = Get-ModuleLoadOrder

    # Filter out already-loaded modules (Core modules loaded during startup)
    $modulesToLoad = $modules | Where-Object {
        -not $script:LoadedModules.ContainsKey($_.Name)
    }

    $totalModules = $modulesToLoad.Count
    $loadedCount = 0
    $failedModules = @()

    if ($totalModules -eq 0) {
        Write-StartupLog "All modules already loaded" -Level Success
        return
    }

    Write-StartupLog "Loading $totalModules remaining modules..." -Level Info

    # Group by layer for progress reporting
    $layers = $modulesToLoad | Group-Object -Property Layer | Sort-Object Name

    foreach ($layer in $layers) {
        Write-StartupLog "Loading Layer $($layer.Name) ($($layer.Count) modules)..." -Level Info

        foreach ($module in $layer.Group) {
            $loadedCount++
            $percentComplete = [math]::Round(($loadedCount / $totalModules) * 100)

            Write-Progress -Activity "Loading GUI Modules" `
                          -Status "Layer $($module.Layer): $($module.Name)" `
                          -PercentComplete $percentComplete `
                          -CurrentOperation "$loadedCount of $totalModules"

            $result = Import-GuiModule -ModuleInfo $module

            if (-not $result.Success) {
                $failedModules += $module.Name
            }
        }
    }

    Write-Progress -Activity "Loading GUI Modules" -Completed

    # Report results
    $successCount = $totalModules - $failedModules.Count
    Write-StartupLog "Module loading complete: $successCount/$totalModules successful" `
        -Level $(if ($failedModules.Count -eq 0) { 'Success' } else { 'Warning' })

    if ($failedModules.Count -gt 0) {
        Write-StartupLog "Failed modules: $($failedModules -join ', ')" -Level Warning

        if (-not $DevelopmentMode) {
            throw "Cannot continue with failed module loads"
        }
    }

    # Show timing summary if verbose
    if ($Verbose -or $Debug) {
        Write-StartupLog "`nModule Load Times:" -Level Debug
        $script:ModuleLoadTimes.GetEnumerator() |
            Sort-Object Value -Descending |
            ForEach-Object {
                Write-StartupLog "  $($_.Key): $($_.Value)ms" -Level Debug
            }
    }
}

function Get-XamlControlNames {
    <#
    .SYNOPSIS
        Extracts all x:Name attributes from XAML file
    #>
    param(
        [string]$XamlPath
    )

    Write-StartupLog "Extracting control names from XAML..." -Level Debug

    $xamlContent = Get-Content $XamlPath -Raw
    $pattern = 'x:Name="([^"]+)"'
    $matches = [regex]::Matches($xamlContent, $pattern)

    $controlNames = @()
    foreach ($match in $matches) {
        $controlName = $match.Groups[1].Value
        # Filter out template parts and internal controls
        if ($controlName -notmatch '^PART_|^(Header|Content|Expander).*Content$') {
            $controlNames += $controlName
        }
    }

    Write-StartupLog "Found $($controlNames.Count) named controls in XAML" -Level Debug

    return $controlNames | Sort-Object -Unique
}

function Initialize-XamlWindow {
    <#
    .SYNOPSIS
        Loads and parses XAML to create the main window
    #>

    Write-StartupLog "Loading XAML..." -Level Info

    $xamlPath = Join-Path $script:GuiRoot "UI/MainWindow.xaml"

    if (-not (Test-Path $xamlPath)) {
        throw "XAML file not found: $xamlPath"
    }

    try {
        $xamlContent = Get-Content $xamlPath -Raw

        # Parse XAML
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xamlContent))
        $script:Window = [Windows.Markup.XamlReader]::Load($reader)
        $reader.Close()

        Write-StartupLog "XAML loaded successfully" -Level Success

        return $script:Window
    }
    catch {
        Write-StartupLog "Failed to load XAML: $_" -Level Error
        throw "XAML parsing failed: $_"
    }
}

function Initialize-UiControls {
    <#
    .SYNOPSIS
        Initializes all UI controls from the window
    #>

    Write-StartupLog "Initializing UI controls..." -Level Info

    # CRITICAL: Check if window exists before attempting to access it
    if ($null -eq $script:Window) {
        $errorMsg = "Cannot initialize controls: Window object is null. XAML loading may have failed."
        Write-StartupLog $errorMsg -Level Error
        throw $errorMsg
    }

    try {
        $xamlPath = Join-Path $script:GuiRoot "UI/MainWindow.xaml"

        if (-not (Test-Path $xamlPath)) {
            throw "XAML file not found at: $xamlPath"
        }

        $controlNames = Get-XamlControlNames -XamlPath $xamlPath

        $foundCount = 0
        $missingCount = 0
        $missingControls = @()

        foreach ($name in $controlNames) {
            try {
                # Safely call FindName with error handling
                $control = $script:Window.FindName($name)

                if ($null -ne $control) {
                    # Store in hashtable
                    $script:Controls[$name] = $control

                    # CRITICAL FIX: Also create script-scoped variables for direct access
                    # This allows UI-Helpers to access controls as $StatusText instead of $script:Controls["StatusText"]
                    Set-Variable -Name $name -Value $control -Scope Script -ErrorAction SilentlyContinue

                    $foundCount++
                    Write-Verbose "Control bound: $name ($($control.GetType().Name))"
                }
                else {
                    $missingCount++
                    $missingControls += $name
                    Write-Verbose "Control not found in window: $name"
                }
            }
            catch {
                $missingCount++
                $missingControls += $name
                Write-Warning "Error binding control '$name': $($_.Exception.Message)"
            }
        }

        Write-StartupLog "Controls initialized: $foundCount found, $missingCount missing" `
            -Level $(if ($missingCount -eq 0) { 'Success' } else { 'Warning' })

        if ($Debug -and $missingControls.Count -gt 0) {
            Write-StartupLog "Missing controls: $($missingControls -join ', ')" -Level Debug
        }

        # Verify critical controls exist
        $criticalControls = @('StatusText', 'PanelDashboard')
        $missingCritical = $criticalControls | Where-Object { -not $script:Controls.ContainsKey($_) }

        if ($missingCritical.Count -gt 0) {
            Write-StartupLog "WARNING: Critical controls missing: $($missingCritical -join ', ')" -Level Warning
        }

        return $script:Controls
    }
    catch {
        $errorMsg = "Failed to initialize UI controls: $($_.Exception.Message)"
        Write-StartupLog $errorMsg -Level Error
        throw $errorMsg
    }
}

function Initialize-ViewModels {
    <#
    .SYNOPSIS
        Initializes all ViewModel data stores
    #>

    Write-StartupLog "Initializing ViewModels..." -Level Info

    $viewModelInitializers = @(
        @{ Name = "Dashboard"; Function = "Initialize-DashboardData" }
        @{ Name = "Rules"; Function = "Initialize-RulesCollection" }
        @{ Name = "Events"; Function = "Initialize-EventsCollection" }
        @{ Name = "Deployment"; Function = "Initialize-DeploymentState" }
        @{ Name = "Compliance"; Function = "Initialize-ComplianceData" }
        @{ Name = "Discovery"; Function = "Initialize-Discovery" }
    )

    foreach ($vm in $viewModelInitializers) {
        try {
            if (Get-Command $vm.Function -ErrorAction SilentlyContinue) {
                & $vm.Function
                Write-StartupLog "$($vm.Name) ViewModel initialized" -Level Success
            }
            else {
                Write-StartupLog "$($vm.Name) ViewModel function not found: $($vm.Function)" -Level Warning
            }
        }
        catch {
            Write-StartupLog "Failed to initialize $($vm.Name) ViewModel: $_" -Level Error

            if (-not $DevelopmentMode) {
                throw
            }
        }
    }

    Write-StartupLog "ViewModels initialization complete" -Level Success
}

function Register-EventHandlers {
    <#
    .SYNOPSIS
        Registers all event handlers for UI controls
    #>

    Write-StartupLog "Registering event handlers..." -Level Info

    $handlerRegistrations = @(
        @{ Name = "Navigation"; Function = "Register-NavigationHandlers" }
        @{ Name = "Dashboard"; Function = "Register-DashboardHandlers" }
        @{ Name = "Rules"; Function = "Register-RulesHandlers" }
        @{ Name = "Events"; Function = "Register-EventsHandlers" }
        @{ Name = "Deployment"; Function = "Register-DeploymentHandlers" }
        @{ Name = "Compliance"; Function = "Register-ComplianceHandlers" }
    )

    $registeredCount = 0

    foreach ($handler in $handlerRegistrations) {
        try {
            if (Get-Command $handler.Function -ErrorAction SilentlyContinue) {
                & $handler.Function -Controls $script:Controls
                $registeredCount++
                Write-StartupLog "$($handler.Name) handlers registered" -Level Success
            }
            else {
                Write-StartupLog "$($handler.Name) handler function not found: $($handler.Function)" -Level Warning
            }
        }
        catch {
            Write-StartupLog "Failed to register $($handler.Name) handlers: $_" -Level Error

            if (-not $DevelopmentMode) {
                throw
            }
        }
    }

    Write-StartupLog "Event handlers registration complete ($registeredCount registered)" -Level Success
}

function Initialize-DefaultUiState {
    <#
    .SYNOPSIS
        Sets up the initial UI state
    #>

    Write-StartupLog "Setting up initial UI state..." -Level Info

    try {
        # Show dashboard panel by default
        if (Get-Command Show-Panel -ErrorAction SilentlyContinue) {
            Show-Panel -PanelName "Dashboard"
        }

        # Set initial status - with comprehensive null checks
        if ($script:Controls.ContainsKey("StatusText") -and $null -ne $script:Controls["StatusText"]) {
            try {
                $script:Controls["StatusText"].Text = "Ready"
                $script:Controls["StatusText"].Foreground = "#3FB950"
            }
            catch {
                Write-StartupLog "Could not set StatusText: $($_.Exception.Message)" -Level Debug
            }
        }

        # Set version info - with comprehensive null checks
        if ($script:Controls.ContainsKey("HeaderVersion") -and $null -ne $script:Controls["HeaderVersion"]) {
            try {
                $script:Controls["HeaderVersion"].Text = "v$script:RequiredModuleVersion"
            }
            catch {
                Write-StartupLog "Could not set HeaderVersion: $($_.Exception.Message)" -Level Debug
            }
        }

        Write-StartupLog "Initial UI state configured" -Level Success
    }
    catch {
        Write-StartupLog "Failed to set initial UI state: $_" -Level Warning
        # Don't throw - this is not critical to application startup
    }
}

function Register-CleanupHandlers {
    <#
    .SYNOPSIS
        Registers cleanup handlers for application exit
    #>

    Write-StartupLog "Registering cleanup handlers..." -Level Debug

    # Window closing event
    if ($script:Window) {
        $script:Window.Add_Closing({
            param($sender, $e)

            Write-StartupLog "Application closing..." -Level Info

            # Cleanup ViewModels
            if (Get-Command Clear-DashboardData -ErrorAction SilentlyContinue) {
                Clear-DashboardData
            }
            if (Get-Command Clear-RulesCollection -ErrorAction SilentlyContinue) {
                Clear-RulesCollection
            }
            if (Get-Command Clear-EventsCollection -ErrorAction SilentlyContinue) {
                Clear-EventsCollection
            }

            # Stop any background jobs
            Get-Job | Where-Object { $_.Name -like "GAAppLocker*" } | Stop-Job -PassThru | Remove-Job

            $script:StartupTimer.Stop()
            Write-StartupLog "Application closed (Total runtime: $($script:StartupTimer.Elapsed.ToString('hh\:mm\:ss')))" -Level Info
        })
    }

    # Process exit handler
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Write-Host "PowerShell exiting - cleanup complete" -ForegroundColor Gray
    } | Out-Null
}

function Show-StartupSummary {
    <#
    .SYNOPSIS
        Displays startup performance summary
    #>

    $elapsed = $script:StartupTimer.Elapsed

    Write-Host "`n" -NoNewline
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " GA-AppLocker Management Console v$script:RequiredModuleVersion" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Startup Time: " -NoNewline -ForegroundColor Gray
    Write-Host "$($elapsed.TotalMilliseconds)ms" -ForegroundColor Green
    Write-Host "Modules Loaded: " -NoNewline -ForegroundColor Gray
    Write-Host "$($script:LoadedModules.Count)" -ForegroundColor Green
    Write-Host "Controls Bound: " -NoNewline -ForegroundColor Gray
    Write-Host "$($script:Controls.Count)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "`n"

    if ($Debug) {
        Write-Host "Debug Information:" -ForegroundColor Magenta
        Write-Host "  Script Path: $script:ScriptPath" -ForegroundColor Gray
        Write-Host "  GUI Root: $script:GuiRoot" -ForegroundColor Gray
        Write-Host "  Project Root: $script:ProjectRoot" -ForegroundColor Gray
        Write-Host "`n"
    }
}

#endregion

#region Main Execution

try {
    # Display header
    Clear-Host
    Write-Host "`n"
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "║         GA-AppLocker Management Console v2.0               ║" -ForegroundColor White
    Write-Host "║         Modular Architecture - Refactored Edition          ║" -ForegroundColor Gray
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n"

    # Step 1: Load Core modules first (they contain Initialize-GuiApplication)
    Write-StartupLog "Loading core modules..." -Level Info

    $coreModules = @(
        @{
            Path = "$script:GuiRoot/Core/Initialize-Application.ps1"
            Name = "Core.Initialize"
            Layer = 1
        }
        @{
            Path = "$script:GuiRoot/Core/Configuration.ps1"
            Name = "Core.Configuration"
            Layer = 1
        }
    )

    foreach ($module in $coreModules) {
        $result = Import-GuiModule -ModuleInfo $module
        if (-not $result.Success) {
            throw "Failed to load critical core module: $($module.Name)"
        }
    }

    Write-StartupLog "Core modules loaded successfully" -Level Success

    # Step 2: Initialize WPF Application (now that Initialize-GuiApplication is loaded)
    Write-StartupLog "Initializing WPF application..." -Level Info

    # Verify the function exists before calling it
    if (-not (Get-Command Initialize-GuiApplication -ErrorAction SilentlyContinue)) {
        throw "Initialize-GuiApplication function not found after loading core modules"
    }

    $initResult = Initialize-GuiApplication

    # Add null check for $initResult
    if ($null -eq $initResult) {
        throw "Initialize-GuiApplication returned null result"
    }

    if (-not $initResult.Success) {
        throw "Application initialization failed: $($initResult.Error)"
    }

    Write-StartupLog "WPF assemblies loaded successfully" -Level Success

    # Step 3: Load all remaining modules
    Import-GuiModules

    # Step 4: Load and parse XAML
    Initialize-XamlWindow | Out-Null

    # Step 5: Initialize UI controls
    Initialize-UiControls | Out-Null

    # Step 6: Initialize ViewModels
    Initialize-ViewModels

    # Step 7: Register event handlers
    Register-EventHandlers

    # Step 8: Set initial UI state
    Initialize-DefaultUiState

    # Step 9: Register cleanup handlers
    Register-CleanupHandlers

    # Step 10: Show startup summary
    if (-not $NoSplash) {
        Show-StartupSummary
    }

    # Mark as initialized
    $script:IsInitialized = $true

    # Step 11: Show the window - with critical null check
    Write-StartupLog "Launching GA-AppLocker Management Console..." -Level Success
    Write-Host "`n"

    # CRITICAL: Verify window exists before showing
    if ($null -eq $script:Window) {
        throw "Cannot show window: Window object is null. Application initialization may have failed."
    }

    try {
        $script:Window.ShowDialog() | Out-Null
    }
    catch {
        Write-StartupLog "Window.ShowDialog() failed: $($_.Exception.Message)" -Level Error
        throw "Failed to display main window: $_"
    }

}
catch {
    # Critical error handling
    $errorMsg = "Critical startup error: $($_.Exception.Message)"
    Write-StartupLog $errorMsg -Level Error

    if ($Debug) {
        Write-Host "`nStack Trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    }

    # Show error dialog if WPF is available
    if ([System.Windows.MessageBox] -as [type]) {
        [System.Windows.MessageBox]::Show(
            "Failed to start GA-AppLocker GUI:`n`n$errorMsg`n`nSee console for details.",
            "Startup Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }

    exit 1
}
finally {
    # Cleanup
    if ($script:StartupTimer) {
        $script:StartupTimer.Stop()
    }

    # Unregister event handlers
    Get-EventSubscriber | Where-Object { $_.SourceIdentifier -eq "PowerShell.Exiting" } | Unregister-Event
}

#endregion
