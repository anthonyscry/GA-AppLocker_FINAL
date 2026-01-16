<#
.SYNOPSIS
    Registry data access layer

.DESCRIPTION
    Provides read-only access to Windows Registry for querying installed software,
    AppLocker policies, and system configuration.
    All functions return data objects only - no modifications, no UI updates.

.NOTES
    Version: 1.0.0
    Layer: Data Access (Read-Only)
#>

function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Retrieves installed software from registry

    .DESCRIPTION
        Queries registry uninstall keys for installed software information.
        Supports both local and remote computers.
        Read-only operation.

    .PARAMETER ComputerName
        Target computer name (default: local computer)

    .EXAMPLE
        Get-InstalledSoftware

    .EXAMPLE
        Get-InstalledSoftware -ComputerName "SERVER01"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        Write-Verbose "Scanning software on: $ComputerName"
    }

    process {
        try {
            $software = @()

            # Get software from registry (both 32-bit and 64-bit)
            $regPaths = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )

            foreach ($regPath in $regPaths) {
                if ($ComputerName -eq $env:COMPUTERNAME) {
                    # Local registry
                    $regKey = "HKLM:\$regPath"

                    if (Test-Path $regKey) {
                        Write-Verbose "Querying local registry: $regKey"

                        Get-ChildItem -Path $regKey -ErrorAction SilentlyContinue | ForEach-Object {
                            $item = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue

                            if ($item.DisplayName -and $item.DisplayVersion) {
                                $software += [PSCustomObject]@{
                                    ComputerName = $ComputerName
                                    Name = $item.DisplayName
                                    Version = $item.DisplayVersion
                                    Publisher = $item.Publisher
                                    InstallDate = $item.InstallDate
                                    Path = $item.InstallLocation
                                    UninstallString = $item.UninstallString
                                }
                            }
                        }
                    }
                }
                else {
                    # Remote registry
                    try {
                        Write-Verbose "Querying remote registry: $regPath on $ComputerName"

                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                        $regKey = $reg.OpenSubKey($regPath)

                        if ($regKey) {
                            foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                                try {
                                    $subKey = $regKey.OpenSubKey($subKeyName)
                                    $displayName = $subKey.GetValue("DisplayName")
                                    $displayVersion = $subKey.GetValue("DisplayVersion")
                                    $publisher = $subKey.GetValue("Publisher")
                                    $installDate = $subKey.GetValue("InstallDate")
                                    $installLocation = $subKey.GetValue("InstallLocation")
                                    $uninstallString = $subKey.GetValue("UninstallString")

                                    if ($displayName -and $displayVersion) {
                                        $software += [PSCustomObject]@{
                                            ComputerName = $ComputerName
                                            Name = $displayName
                                            Version = $displayVersion
                                            Publisher = $publisher
                                            InstallDate = $installDate
                                            Path = $installLocation
                                            UninstallString = $uninstallString
                                        }
                                    }

                                    $subKey.Close()
                                }
                                catch {
                                    Write-Verbose "Failed to read subkey: $subKeyName"
                                }
                            }

                            $regKey.Close()
                        }

                        $reg.Close()
                    }
                    catch {
                        Write-Warning "Failed to access remote registry on $ComputerName`: $($_.Exception.Message)"
                    }
                }
            }

            Write-Verbose "Found $($software.Count) software items on $ComputerName"
            return $software
        }
        catch {
            Write-Error "Software scan failed on $ComputerName`: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-AppLockerPolicyFromRegistry {
    <#
    .SYNOPSIS
        Retrieves AppLocker policy from registry

    .DESCRIPTION
        Queries the registry for AppLocker policy configuration.
        Read-only operation.

    .EXAMPLE
        Get-AppLockerPolicyFromRegistry
    #>
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose "Retrieving AppLocker policy from registry"
    }

    process {
        try {
            $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

            if (-not (Test-Path $policyPath)) {
                Write-Verbose "AppLocker policy not found in registry"
                return $null
            }

            $policyData = @{
                Exe = @()
                Msi = @()
                Script = @()
                Dll = @()
                Appx = @()
            }

            # Query each rule collection
            $ruleTypes = @{
                "Exe" = "EXE"
                "Msi" = "MSI"
                "Script" = "Script"
                "Dll" = "DLL"
                "Appx" = "Appx"
            }

            foreach ($type in $ruleTypes.Keys) {
                $typePath = Join-Path $policyPath $type

                if (Test-Path $typePath) {
                    Write-Verbose "Reading $type rules from registry"

                    $rules = Get-ChildItem -Path $typePath -ErrorAction SilentlyContinue

                    foreach ($rule in $rules) {
                        $ruleProps = Get-ItemProperty -Path $rule.PSPath -ErrorAction SilentlyContinue

                        if ($ruleProps) {
                            $policyData[$type] += [PSCustomObject]@{
                                Id = $rule.PSChildName
                                Name = $ruleProps.Name
                                Description = $ruleProps.Description
                                UserOrGroupSid = $ruleProps.UserOrGroupSid
                                Action = $ruleProps.Action
                            }
                        }
                    }
                }
            }

            Write-Verbose "Retrieved AppLocker policy from registry"
            return $policyData
        }
        catch {
            Write-Error "Failed to retrieve AppLocker policy from registry: $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-RegistryValue {
    <#
    .SYNOPSIS
        Safe registry value reader

    .DESCRIPTION
        Reads a value from the registry with error handling.
        Read-only operation.

    .PARAMETER Path
        Registry path (e.g., "HKLM:\SOFTWARE\Microsoft")

    .PARAMETER Name
        Value name to read

    .PARAMETER DefaultValue
        Value to return if key/value doesn't exist

    .EXAMPLE
        Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"

    .EXAMPLE
        Get-RegistryValue -Path "HKLM:\SOFTWARE\MyApp" -Name "InstallPath" -DefaultValue "C:\Program Files\MyApp"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [object]$DefaultValue = $null
    )

    begin {
        Write-Verbose "Reading registry value: $Path\$Name"
    }

    process {
        try {
            if (-not (Test-Path $Path)) {
                Write-Verbose "Registry path does not exist: $Path"
                return $DefaultValue
            }

            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name

            if ($null -eq $value) {
                Write-Verbose "Registry value is null: $Path\$Name"
                return $DefaultValue
            }

            Write-Verbose "Registry value retrieved: $value"
            return $value
        }
        catch {
            Write-Verbose "Failed to read registry value '$Path\$Name': $($_.Exception.Message)"
            return $DefaultValue
        }
    }
}

function Test-RegistryKeyExists {
    <#
    .SYNOPSIS
        Checks if a registry key exists

    .DESCRIPTION
        Verifies existence of a registry key.
        Read-only operation.

    .PARAMETER Path
        Registry path to check

    .EXAMPLE
        Test-RegistryKeyExists -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    begin {
        Write-Verbose "Checking if registry key exists: $Path"
    }

    process {
        try {
            $exists = Test-Path -Path $Path -ErrorAction Stop

            Write-Verbose "Registry key exists: $exists"
            return $exists
        }
        catch {
            Write-Verbose "Failed to check registry key: $($_.Exception.Message)"
            return $false
        }
    }
}

function Test-RegistryValueExists {
    <#
    .SYNOPSIS
        Checks if a registry value exists

    .DESCRIPTION
        Verifies existence of a specific registry value.
        Read-only operation.

    .PARAMETER Path
        Registry path

    .PARAMETER Name
        Value name to check

    .EXAMPLE
        Test-RegistryValueExists -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    begin {
        Write-Verbose "Checking if registry value exists: $Path\$Name"
    }

    process {
        try {
            if (-not (Test-Path $Path)) {
                Write-Verbose "Registry path does not exist: $Path"
                return $false
            }

            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop

            if ($null -eq $item.$Name) {
                Write-Verbose "Registry value does not exist: $Path\$Name"
                return $false
            }

            Write-Verbose "Registry value exists: $Path\$Name"
            return $true
        }
        catch {
            Write-Verbose "Registry value does not exist or is not accessible: $Path\$Name"
            return $false
        }
    }
}

function Get-RegistrySubKeys {
    <#
    .SYNOPSIS
        Enumerates subkeys of a registry key

    .DESCRIPTION
        Lists all subkeys under a specified registry path.
        Read-only operation.

    .PARAMETER Path
        Registry path to enumerate

    .EXAMPLE
        Get-RegistrySubKeys -Path "HKLM:\SOFTWARE\Microsoft"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    begin {
        Write-Verbose "Enumerating registry subkeys: $Path"
    }

    process {
        try {
            if (-not (Test-Path $Path)) {
                Write-Verbose "Registry path does not exist: $Path"
                return @()
            }

            $subKeys = Get-ChildItem -Path $Path -ErrorAction Stop

            Write-Verbose "Found $($subKeys.Count) subkeys"
            return $subKeys
        }
        catch {
            Write-Warning "Failed to enumerate registry subkeys: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-RegistryKeyProperties {
    <#
    .SYNOPSIS
        Retrieves all properties of a registry key

    .DESCRIPTION
        Gets all values from a registry key as a hashtable.
        Read-only operation.

    .PARAMETER Path
        Registry path to query

    .EXAMPLE
        Get-RegistryKeyProperties -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    begin {
        Write-Verbose "Retrieving registry key properties: $Path"
    }

    process {
        try {
            if (-not (Test-Path $Path)) {
                Write-Verbose "Registry path does not exist: $Path"
                return $null
            }

            $properties = Get-ItemProperty -Path $Path -ErrorAction Stop

            # Remove PowerShell-added properties
            $properties.PSObject.Properties.Remove('PSPath')
            $properties.PSObject.Properties.Remove('PSParentPath')
            $properties.PSObject.Properties.Remove('PSChildName')
            $properties.PSObject.Properties.Remove('PSDrive')
            $properties.PSObject.Properties.Remove('PSProvider')

            Write-Verbose "Retrieved $($properties.PSObject.Properties.Count) properties"
            return $properties
        }
        catch {
            Write-Warning "Failed to retrieve registry key properties: $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-AppLockerEnforcementMode {
    <#
    .SYNOPSIS
        Retrieves AppLocker enforcement mode from registry

    .DESCRIPTION
        Queries registry for current AppLocker enforcement configuration.
        Read-only operation.

    .EXAMPLE
        Get-AppLockerEnforcementMode
    #>
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose "Retrieving AppLocker enforcement mode"
    }

    process {
        try {
            $enforcementPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

            if (-not (Test-Path $enforcementPath)) {
                Write-Verbose "AppLocker enforcement configuration not found"
                return $null
            }

            $ruleTypes = @("Exe", "Msi", "Script", "Dll", "Appx")
            $enforcementData = @{}

            foreach ($type in $ruleTypes) {
                $typePath = Join-Path $enforcementPath $type

                if (Test-Path $typePath) {
                    $enforcementMode = Get-RegistryValue -Path $typePath -Name "EnforcementMode" -DefaultValue 0

                    $mode = switch ($enforcementMode) {
                        0 { "NotConfigured" }
                        1 { "Enabled" }
                        2 { "AuditOnly" }
                        default { "Unknown" }
                    }

                    $enforcementData[$type] = $mode
                    Write-Verbose "$type enforcement mode: $mode"
                }
            }

            return $enforcementData
        }
        catch {
            Write-Error "Failed to retrieve AppLocker enforcement mode: $($_.Exception.Message)"
            return $null
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-InstalledSoftware',
    'Get-AppLockerPolicyFromRegistry',
    'Get-RegistryValue',
    'Test-RegistryKeyExists',
    'Test-RegistryValueExists',
    'Get-RegistrySubKeys',
    'Get-RegistryKeyProperties',
    'Get-AppLockerEnforcementMode'
)
