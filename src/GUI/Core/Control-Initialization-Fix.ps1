<#
.SYNOPSIS
    Control Initialization Fix for GA-AppLocker GUI

.DESCRIPTION
    This module provides enhanced control initialization with proper null safety,
    script-level variable creation, and comprehensive error handling.

.NOTES
    Author: General Atomics - ASI
    Version: 2.0.1
    Date: 2026-01-16
    Purpose: Fix control initialization errors in refactored GUI
#>

#region Enhanced Control Initialization

function Initialize-UiControls {
    <#
    .SYNOPSIS
        Initializes all UI controls from the window with enhanced null safety

    .DESCRIPTION
        This function:
        1. Extracts all x:Name attributes from XAML
        2. Uses FindName to locate each control
        3. Stores controls in $script:Controls hashtable
        4. Creates script-level variables for backward compatibility
        5. Logs missing controls for diagnostics
        6. Returns detailed initialization results

    .PARAMETER Window
        The WPF Window object (optional, uses $script:Window if not provided)

    .PARAMETER XamlPath
        Path to XAML file (optional, uses default path if not provided)

    .OUTPUTS
        Hashtable with initialization results

    .EXAMPLE
        $result = Initialize-UiControls
        if ($result.MissingControls.Count -gt 0) {
            Write-Warning "Some controls were not found"
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [System.Windows.Window]$Window = $script:Window,

        [Parameter(Mandatory = $false)]
        [string]$XamlPath
    )

    Write-Verbose "Starting enhanced UI control initialization..."

    # Validate window object
    if ($null -eq $Window) {
        throw "Window object is null. Ensure XAML is loaded before initializing controls."
    }

    # Determine XAML path
    if (-not $XamlPath) {
        $XamlPath = Join-Path $script:GuiRoot "UI/MainWindow.xaml"
    }

    if (-not (Test-Path $XamlPath)) {
        throw "XAML file not found: $XamlPath"
    }

    # Initialize result object
    $initResult = @{
        Success = $true
        FoundControls = @()
        MissingControls = @()
        ControlTypes = @{}
        TotalExpected = 0
        TotalFound = 0
        TotalMissing = 0
        Errors = @()
    }

    try {
        # Extract control names from XAML
        Write-Verbose "Extracting control names from XAML..."
        $controlNames = Get-XamlControlNames -XamlPath $XamlPath
        $initResult.TotalExpected = $controlNames.Count

        Write-Verbose "Found $($controlNames.Count) named controls in XAML"

        # Initialize the Controls hashtable if it doesn't exist
        if ($null -eq $script:Controls) {
            $script:Controls = @{}
        }

        # Process each control
        foreach ($name in $controlNames) {
            try {
                Write-Verbose "Looking up control: $name"

                # Use FindName to locate the control
                $control = $Window.FindName($name)

                if ($null -ne $control) {
                    # Store in hashtable
                    $script:Controls[$name] = $control

                    # Create script-level variable for backward compatibility
                    Set-Variable -Name $name -Value $control -Scope Script -Force

                    # Track control type
                    $controlType = $control.GetType().Name
                    $initResult.ControlTypes[$name] = $controlType
                    $initResult.FoundControls += $name
                    $initResult.TotalFound++

                    Write-Verbose "  ✓ Found: $name ($controlType)"
                }
                else {
                    # Control not found
                    $initResult.MissingControls += $name
                    $initResult.TotalMissing++

                    Write-Warning "  ✗ Not found: $name"

                    # Store null in hashtable to prevent KeyNotFound errors
                    $script:Controls[$name] = $null

                    # Create null script variable
                    Set-Variable -Name $name -Value $null -Scope Script -Force
                }
            }
            catch {
                $errorMsg = "Error processing control '$name': $($_.Exception.Message)"
                Write-Error $errorMsg
                $initResult.Errors += $errorMsg
                $initResult.MissingControls += $name
                $initResult.TotalMissing++
            }
        }

        # Determine overall success
        if ($initResult.TotalMissing -gt 0) {
            Write-Warning "Control initialization completed with $($initResult.TotalMissing) missing controls"
            $initResult.Success = $false
        }
        else {
            Write-Verbose "All controls initialized successfully"
        }

        # Log summary
        $summary = @"
Control Initialization Summary:
  Total Expected:  $($initResult.TotalExpected)
  Found:           $($initResult.TotalFound) ($(($initResult.TotalFound / $initResult.TotalExpected * 100).ToString('F1'))%)
  Missing:         $($initResult.TotalMissing)
"@
        Write-Verbose $summary

        if ($initResult.MissingControls.Count -gt 0 -and $VerbosePreference -ne 'SilentlyContinue') {
            Write-Verbose "Missing Controls:"
            $initResult.MissingControls | ForEach-Object { Write-Verbose "  - $_" }
        }
    }
    catch {
        $initResult.Success = $false
        $initResult.Errors += $_.Exception.Message
        throw "Control initialization failed: $_"
    }

    return $initResult
}

#endregion

#region Safe Control Property Access

function Set-ControlProperty {
    <#
    .SYNOPSIS
        Safely sets a property on a control with null checking

    .DESCRIPTION
        Provides safe property assignment with automatic null checks and error handling

    .PARAMETER ControlName
        Name of the control (will lookup in $script:Controls)

    .PARAMETER PropertyName
        Name of the property to set

    .PARAMETER Value
        Value to assign to the property

    .PARAMETER SuppressWarnings
        Suppress warnings for null controls

    .RETURNS
        Boolean indicating success

    .EXAMPLE
        Set-ControlProperty "StatusText" "Text" "Ready"

    .EXAMPLE
        Set-ControlProperty "MiniStatusDomain" "Foreground" "#3FB950"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlName,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [switch]$SuppressWarnings
    )

    try {
        # Check if control exists in hashtable
        if (-not $script:Controls.ContainsKey($ControlName)) {
            if (-not $SuppressWarnings) {
                Write-Warning "Control '$ControlName' not found in Controls hashtable"
            }
            return $false
        }

        # Get control reference
        $control = $script:Controls[$ControlName]

        # Check if control is null
        if ($null -eq $control) {
            if (-not $SuppressWarnings) {
                Write-Warning "Control '$ControlName' is null"
            }
            return $false
        }

        # Check if property exists
        $propertyInfo = $control.GetType().GetProperty($PropertyName)
        if ($null -eq $propertyInfo) {
            if (-not $SuppressWarnings) {
                Write-Warning "Property '$PropertyName' not found on control '$ControlName' (Type: $($control.GetType().Name))"
            }
            return $false
        }

        # Set the property
        $control.$PropertyName = $Value
        Write-Verbose "Set $ControlName.$PropertyName = $Value"

        return $true
    }
    catch {
        Write-Error "Error setting property $PropertyName on control $ControlName: $($_.Exception.Message)"
        return $false
    }
}

function Get-ControlProperty {
    <#
    .SYNOPSIS
        Safely gets a property from a control with null checking

    .DESCRIPTION
        Provides safe property retrieval with automatic null checks

    .PARAMETER ControlName
        Name of the control

    .PARAMETER PropertyName
        Name of the property to get

    .PARAMETER DefaultValue
        Default value to return if control or property is null

    .RETURNS
        The property value, or DefaultValue if not found

    .EXAMPLE
        $text = Get-ControlProperty "StatusText" "Text" "Unknown"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlName,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        [object]$DefaultValue = $null
    )

    try {
        if (-not $script:Controls.ContainsKey($ControlName)) {
            return $DefaultValue
        }

        $control = $script:Controls[$ControlName]
        if ($null -eq $control) {
            return $DefaultValue
        }

        $propertyInfo = $control.GetType().GetProperty($PropertyName)
        if ($null -eq $propertyInfo) {
            return $DefaultValue
        }

        return $control.$PropertyName
    }
    catch {
        Write-Verbose "Error getting property $PropertyName from control $ControlName: $($_.Exception.Message)"
        return $DefaultValue
    }
}

function Test-ControlExists {
    <#
    .SYNOPSIS
        Tests if a control exists and is not null

    .DESCRIPTION
        Validates control existence in both hashtable and as non-null reference

    .PARAMETER ControlName
        Name of the control to test

    .RETURNS
        Boolean indicating if control exists and is not null

    .EXAMPLE
        if (Test-ControlExists "StatusText") {
            $StatusText.Text = "Ready"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlName
    )

    return ($script:Controls.ContainsKey($ControlName) -and ($null -ne $script:Controls[$ControlName]))
}

#endregion

#region Diagnostic Functions

function Test-AllControls {
    <#
    .SYNOPSIS
        Tests all controls and reports their status

    .DESCRIPTION
        Comprehensive diagnostic function that checks all controls in the hashtable
        and reports which are found, missing, or null

    .OUTPUTS
        Hashtable with detailed diagnostic information

    .EXAMPLE
        $diagnostics = Test-AllControls
        $diagnostics | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $diagnostics = @{
        TotalControls = $script:Controls.Count
        ValidControls = @()
        NullControls = @()
        ControlDetails = @()
    }

    foreach ($controlName in $script:Controls.Keys | Sort-Object) {
        $control = $script:Controls[$controlName]

        $detail = [PSCustomObject]@{
            Name = $controlName
            IsNull = ($null -eq $control)
            Type = if ($null -ne $control) { $control.GetType().Name } else { "NULL" }
            HasTextProperty = if ($null -ne $control) {
                $null -ne $control.GetType().GetProperty("Text")
            } else {
                $false
            }
            HasContentProperty = if ($null -ne $control) {
                $null -ne $control.GetType().GetProperty("Content")
            } else {
                $false
            }
            HasVisibilityProperty = if ($null -ne $control) {
                $null -ne $control.GetType().GetProperty("Visibility")
            } else {
                $false
            }
        }

        $diagnostics.ControlDetails += $detail

        if ($null -eq $control) {
            $diagnostics.NullControls += $controlName
        }
        else {
            $diagnostics.ValidControls += $controlName
        }
    }

    return $diagnostics
}

function Export-ControlReport {
    <#
    .SYNOPSIS
        Exports a detailed control report to a file

    .DESCRIPTION
        Creates a comprehensive CSV report of all controls and their status

    .PARAMETER OutputPath
        Path to save the report (optional, defaults to Desktop)

    .EXAMPLE
        Export-ControlReport -OutputPath "C:\Temp\control-report.csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )

    if (-not $OutputPath) {
        $desktop = [Environment]::GetFolderPath("Desktop")
        $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $OutputPath = Join-Path $desktop "GAAppLocker-ControlReport_$timestamp.csv"
    }

    $diagnostics = Test-AllControls
    $diagnostics.ControlDetails | Export-Csv -Path $OutputPath -NoTypeInformation

    Write-Host "Control report exported to: $OutputPath" -ForegroundColor Green
    return $OutputPath
}

#endregion

# Export module members
Export-ModuleMember -Function Initialize-UiControls, Set-ControlProperty, Get-ControlProperty, Test-ControlExists, Test-AllControls, Export-ControlReport
