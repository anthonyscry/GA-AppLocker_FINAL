#Requires -Version 5.1
<#
.SYNOPSIS
    GA-AppLocker Scanning Module
.DESCRIPTION
    Functions for scanning computers for AppLocker artifacts.
#>

# ============================================================
# SCANNING FUNCTIONS
# ============================================================

function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Get installed software from registry.
    .PARAMETER ComputerName
        Target computer (local or remote).
    .OUTPUTS
        Array of software objects.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $software = @()
    $isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq "localhost")

    if ($isLocal) {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    ForEach-Object {
                        $software += [PSCustomObject]@{
                            Computer        = $ComputerName
                            Name            = $_.DisplayName
                            Version         = $_.DisplayVersion
                            Publisher       = $_.Publisher
                            InstallLocation = $_.InstallLocation
                        }
                    }
            }
        }
    } else {
        # Remote registry access
        try {
            $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $uninstallKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")

            if ($uninstallKey) {
                foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                    try {
                        $subKey = $uninstallKey.OpenSubKey($subKeyName)
                        $displayName = $subKey.GetValue("DisplayName")
                        if ($displayName) {
                            $software += [PSCustomObject]@{
                                Computer        = $ComputerName
                                Name            = $displayName
                                Version         = $subKey.GetValue("DisplayVersion")
                                Publisher       = $subKey.GetValue("Publisher")
                                InstallLocation = $subKey.GetValue("InstallLocation")
                            }
                        }
                        $subKey.Close()
                    } catch { }
                }
                $uninstallKey.Close()
            }
            $remoteReg.Close()
        } catch {
            Write-Warning "Cannot access remote registry on $ComputerName : $_"
        }
    }

    return $software | Sort-Object Name -Unique
}

function Get-Executables {
    <#
    .SYNOPSIS
        Scan for executables in common paths.
    .PARAMETER ComputerName
        Target computer.
    .PARAMETER MaxFiles
        Maximum files to return.
    .OUTPUTS
        Array of executable info objects.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [int]$MaxFiles = 500
    )

    $executables = @()
    $publishers = @{}
    $isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq "localhost")

    $scanPaths = @("Program Files", "Program Files (x86)")

    foreach ($basePath in $scanPaths) {
        $fullPath = if ($isLocal) {
            Join-Path $env:SystemDrive $basePath
        } else {
            "\\$ComputerName\C`$\$basePath"
        }

        if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $fullPath -Recurse -File -Include "*.exe" -ErrorAction SilentlyContinue |
                Select-Object -First $MaxFiles |
                ForEach-Object {
                    try {
                        $file = $_
                        $vInfo = $file.VersionInfo
                        $publisher = if ($vInfo.CompanyName) { $vInfo.CompanyName.Trim() } else { "Unknown" }
                        $product = if ($vInfo.ProductName) { $vInfo.ProductName.Trim() } else { "" }
                        $version = if ($vInfo.FileVersion) { $vInfo.FileVersion.Trim() } else { "" }

                        # Track publishers
                        if ($publisher -ne "Unknown" -and -not $publishers.ContainsKey($publisher)) {
                            $publishers[$publisher] = @{ Publisher = $publisher; Product = $product; Count = 0 }
                        }
                        if ($publisher -ne "Unknown") { $publishers[$publisher].Count++ }

                        $executables += [PSCustomObject]@{
                            Computer  = $ComputerName
                            FileName  = $file.Name
                            FullPath  = $file.FullName
                            Publisher = $publisher
                            Product   = $product
                            Version   = $version
                        }
                    } catch { }
                }
        }
    }

    return @{
        Executables = $executables
        Publishers  = $publishers
    }
}

function Get-AppLockerEvents {
    <#
    .SYNOPSIS
        Get AppLocker events from event log.
    .PARAMETER MaxEvents
        Maximum events per log.
    .OUTPUTS
        Array of event objects.
    #>
    param([int]$MaxEvents = 500)

    $events = @()
    $logNames = @(
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution"
    )

    foreach ($logName in $logNames) {
        try {
            Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $events += [PSCustomObject]@{
                        Computer    = $env:COMPUTERNAME
                        TimeCreated = $_.TimeCreated
                        Id          = $_.Id
                        Level       = $_.LevelDisplayName
                        Message     = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
                    }
                }
        } catch { }
    }

    return $events
}

function Invoke-ComprehensiveScan {
    <#
    .SYNOPSIS
        Run comprehensive scan on computer.
    .PARAMETER ComputerName
        Target computer.
    .PARAMETER OutputPath
        Where to save results.
    .PARAMETER IncludeEvents
        Include AppLocker events.
    .OUTPUTS
        Hashtable with scan results.
    #>
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$OutputPath = "C:\GA-AppLocker\Scans",
        [switch]$IncludeEvents
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $scanFolder = Join-Path $OutputPath "${ComputerName}_${timestamp}"

    if (-not (Test-Path $scanFolder)) {
        New-Item -ItemType Directory -Path $scanFolder -Force | Out-Null
    }

    $results = @{
        ComputerName = $ComputerName
        ScanFolder   = $scanFolder
        Timestamp    = $timestamp
        Files        = @{}
        Stats        = @{}
    }

    # 1. Installed Software
    Write-Host "  Scanning installed software..." -ForegroundColor Gray
    $software = Get-InstalledSoftware -ComputerName $ComputerName
    $softwarePath = Join-Path $scanFolder "InstalledSoftware.csv"
    $software | Export-Csv -Path $softwarePath -NoTypeInformation -Encoding UTF8
    $results.Files["InstalledSoftware"] = $softwarePath
    $results.Stats["InstalledSoftware"] = $software.Count

    # 2. Executables
    Write-Host "  Scanning executables..." -ForegroundColor Gray
    $execData = Get-Executables -ComputerName $ComputerName
    $execPath = Join-Path $scanFolder "Executables.csv"
    $execData.Executables | Export-Csv -Path $execPath -NoTypeInformation -Encoding UTF8
    $results.Files["Executables"] = $execPath
    $results.Stats["Executables"] = $execData.Executables.Count

    # 3. Publishers
    $pubPath = Join-Path $scanFolder "Publishers.csv"
    $execData.Publishers.Values | ForEach-Object {
        [PSCustomObject]@{ Publisher = $_.Publisher; Product = $_.Product; Count = $_.Count }
    } | Export-Csv -Path $pubPath -NoTypeInformation -Encoding UTF8
    $results.Files["Publishers"] = $pubPath
    $results.Stats["Publishers"] = $execData.Publishers.Count
    $results.Publishers = $execData.Publishers

    # 4. Events (local only)
    $isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq "localhost")
    if ($IncludeEvents -and $isLocal) {
        Write-Host "  Scanning AppLocker events..." -ForegroundColor Gray
        $events = Get-AppLockerEvents
        if ($events.Count -gt 0) {
            $eventsPath = Join-Path $scanFolder "AppLockerEvents.csv"
            $events | Export-Csv -Path $eventsPath -NoTypeInformation -Encoding UTF8
            $results.Files["AppLockerEvents"] = $eventsPath
            $results.Stats["AppLockerEvents"] = $events.Count
        }
    }

    return $results
}

# ============================================================
# EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Get-InstalledSoftware',
    'Get-Executables',
    'Get-AppLockerEvents',
    'Invoke-ComprehensiveScan'
)
