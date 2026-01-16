<#
.SYNOPSIS
    Application initialization and assembly loading

.DESCRIPTION
    Handles startup sequence, .NET assembly loading, and environment checks
    for the GA-AppLocker GUI application.

.NOTES
    Version:        2.0
    Author:         General Atomics - ASI
    Creation Date:  2026-01-16
    Module:         Core\Initialize-Application
#>

function Initialize-GuiApplication {
    <#
    .SYNOPSIS
        Initialize the GUI application with required assemblies and environment checks

    .DESCRIPTION
        Loads required .NET assemblies for WPF, performs environment validation,
        and returns initialization status

    .OUTPUTS
        Hashtable with initialization results

    .EXAMPLE
        $result = Initialize-GuiApplication
        if (-not $result.success) {
            Write-Error $result.error
            exit 1
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $initResult = @{
        success = $true
        assembliesLoaded = @()
        errors = @()
        warnings = @()
        environment = @{}
    }

    Write-Verbose "Starting GUI application initialization..."

    # Required assemblies for WPF
    $requiredAssemblies = @(
        'PresentationFramework'
        'PresentationCore'
        'WindowsBase'
        'System.Windows.Forms'
        'System.Web'
    )

    # Load assemblies
    foreach ($assembly in $requiredAssemblies) {
        try {
            # System.Windows.Forms and System.Web are optional
            $errorAction = if ($assembly -in @('System.Windows.Forms', 'System.Web')) {
                'SilentlyContinue'
            } else {
                'Stop'
            }

            Add-Type -AssemblyName $assembly -ErrorAction $errorAction
            $initResult.assembliesLoaded += $assembly
            Write-Verbose "Loaded assembly: $assembly"
        }
        catch {
            $errorMsg = "Failed to load assembly '$assembly': $($_.Exception.Message)"

            # Critical assemblies cause failure
            if ($assembly -notin @('System.Windows.Forms', 'System.Web')) {
                $initResult.success = $false
                $initResult.errors += $errorMsg
                Write-Error $errorMsg
            }
            else {
                $initResult.warnings += $errorMsg
                Write-Warning $errorMsg
            }
        }
    }

    # Check .NET Framework version
    try {
        $netVersion = [System.Environment]::Version
        $initResult.environment.DotNetVersion = $netVersion.ToString()
        Write-Verbose ".NET Framework Version: $($netVersion.ToString())"

        # Require .NET 4.5 or later (Major version 4, Build >= 30319)
        if ($netVersion.Major -lt 4 -or ($netVersion.Major -eq 4 -and $netVersion.Build -lt 30319)) {
            $initResult.success = $false
            $initResult.errors += ".NET Framework 4.5 or later is required. Current version: $($netVersion.ToString())"
        }
    }
    catch {
        $initResult.warnings += "Could not determine .NET Framework version: $($_.Exception.Message)"
    }

    # Detect environment information
    try {
        $initResult.environment.PSVersion = $PSVersionTable.PSVersion.ToString()
        $initResult.environment.OSVersion = [System.Environment]::OSVersion.ToString()
        $initResult.environment.MachineName = $env:COMPUTERNAME
        $initResult.environment.UserName = $env:USERNAME
        $initResult.environment.UserDomain = $env:USERDOMAIN
        $initResult.environment.Is64Bit = [System.Environment]::Is64BitProcess

        Write-Verbose "PowerShell Version: $($initResult.environment.PSVersion)"
        Write-Verbose "OS Version: $($initResult.environment.OSVersion)"
        Write-Verbose "64-bit Process: $($initResult.environment.Is64Bit)"
    }
    catch {
        $initResult.warnings += "Could not gather all environment information: $($_.Exception.Message)"
    }

    # If initialization failed, prepare error message for display
    if (-not $initResult.success) {
        $errorMessage = "ERROR: Failed to initialize GA-AppLocker GUI`n`n"
        $errorMessage += "This application requires .NET Framework 4.5 or later.`n`n"

        if ($initResult.errors.Count -gt 0) {
            $errorMessage += "Errors:`n"
            foreach ($error in $initResult.errors) {
                $errorMessage += "  - $error`n"
            }
        }

        # Try to display error message
        try {
            if ('System.Windows.Forms' -in $initResult.assembliesLoaded) {
                [System.Windows.Forms.MessageBox]::Show(
                    $errorMessage,
                    "GA-AppLocker Startup Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
            else {
                Write-Host $errorMessage -ForegroundColor Red
                Write-Host "Press any key to exit..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
        catch {
            # Last resort - output to console
            Write-Host $errorMessage -ForegroundColor Red
        }

        $initResult.error = $errorMessage
    }

    Write-Verbose "Initialization complete. Success: $($initResult.success)"
    return $initResult
}

# Export module members
Export-ModuleMember -Function Initialize-GuiApplication
