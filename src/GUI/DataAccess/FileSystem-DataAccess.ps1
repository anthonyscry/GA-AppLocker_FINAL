<#
.SYNOPSIS
    File system data access layer

.DESCRIPTION
    Provides read-only access to file system for querying executables, file metadata,
    publisher information, and installed applications.
    All functions return data objects only - no modifications, no UI updates.

.NOTES
    Version: 1.0.0
    Layer: Data Access (Read-Only)
#>

function Get-LocalExecutableArtifacts {
    <#
    .SYNOPSIS
        Retrieves executable artifacts from specified paths

    .DESCRIPTION
        Scans file system paths for executable files and returns metadata.
        Read-only operation - does not modify files.

    .PARAMETER Paths
        Array of paths to scan (default: common program directories)

    .PARAMETER MaxFiles
        Maximum number of files to return (default: 1000)

    .EXAMPLE
        Get-LocalExecutableArtifacts

    .EXAMPLE
        Get-LocalExecutableArtifacts -Paths @("C:\CustomApps") -MaxFiles 500
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Paths = @(
            "C:\Program Files",
            "C:\Program Files (x86)",
            "$env:LOCALAPPDATA",
            "$env:PROGRAMDATA"
        ),

        [Parameter()]
        [ValidateRange(1, 100000)]
        [int]$MaxFiles = 1000
    )

    begin {
        Write-Verbose "Scanning for executable artifacts in $($Paths.Count) paths"
        $extensions = @(".exe", ".msi", ".bat", ".cmd", ".ps1")
    }

    process {
        try {
            $artifacts = @()

            foreach ($basePath in $Paths) {
                if (-not (Test-Path $basePath)) {
                    Write-Verbose "Path does not exist: $basePath"
                    continue
                }

                try {
                    Write-Verbose "Scanning path: $basePath"

                    $files = Get-ChildItem -Path $basePath -Recurse -File -ErrorAction SilentlyContinue |
                             Where-Object { $extensions -contains $_.Extension } |
                             Select-Object -First $MaxFiles

                    foreach ($file in $files) {
                        try {
                            $versionInfo = $file.VersionInfo
                            $publisher = if ($versionInfo.CompanyName) {
                                $versionInfo.CompanyName
                            } else {
                                "Unknown"
                            }

                            # Skip Windows system files
                            if ($file.FullName -like "*Windows\*") {
                                continue
                            }

                            $artifacts += @{
                                name = $file.Name
                                publisher = $publisher
                                path = $file.FullName
                                hash = "N/A"
                                version = if ($versionInfo.FileVersion) {
                                    $versionInfo.FileVersion
                                } else {
                                    "Unknown"
                                }
                                size = $file.Length
                                modifiedDate = $file.LastWriteTime
                            }

                            if ($artifacts.Count -ge $MaxFiles) {
                                break
                            }
                        }
                        catch {
                            Write-Verbose "Failed to process file: $($file.FullName)"
                            continue
                        }
                    }
                }
                catch {
                    Write-Verbose "Failed to scan path '$basePath': $($_.Exception.Message)"
                }

                if ($artifacts.Count -ge $MaxFiles) {
                    break
                }
            }

            Write-Verbose "Retrieved $($artifacts.Count) artifacts"

            return @{
                success = $true
                artifacts = $artifacts
                count = $artifacts.Count
            }
        }
        catch {
            Write-Error "Failed to retrieve executable artifacts: $($_.Exception.Message)"
            return @{
                success = $false
                artifacts = @()
                count = 0
                error = $_.Exception.Message
            }
        }
    }
}

function Get-FilePublisher {
    <#
    .SYNOPSIS
        Extracts publisher information from a file

    .DESCRIPTION
        Reads file version information to determine publisher/company name.
        Read-only operation.

    .PARAMETER FilePath
        Path to the file to query

    .EXAMPLE
        Get-FilePublisher -FilePath "C:\Program Files\MyApp\app.exe"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    begin {
        Write-Verbose "Retrieving publisher info for: $FilePath"
    }

    process {
        try {
            if (-not (Test-Path $FilePath)) {
                Write-Warning "File not found: $FilePath"
                return $null
            }

            $file = Get-Item -Path $FilePath -ErrorAction Stop
            $versionInfo = $file.VersionInfo

            $publisherInfo = [PSCustomObject]@{
                FilePath = $FilePath
                FileName = $file.Name
                CompanyName = if ($versionInfo.CompanyName) { $versionInfo.CompanyName } else { "Unknown" }
                ProductName = if ($versionInfo.ProductName) { $versionInfo.ProductName } else { "" }
                FileVersion = if ($versionInfo.FileVersion) { $versionInfo.FileVersion } else { "" }
                ProductVersion = if ($versionInfo.ProductVersion) { $versionInfo.ProductVersion } else { "" }
                FileDescription = if ($versionInfo.FileDescription) { $versionInfo.FileDescription } else { "" }
                OriginalFilename = if ($versionInfo.OriginalFilename) { $versionInfo.OriginalFilename } else { "" }
            }

            Write-Verbose "Publisher: $($publisherInfo.CompanyName)"
            return $publisherInfo
        }
        catch {
            Write-Warning "Failed to retrieve publisher info: $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-FileHashData {
    <#
    .SYNOPSIS
        Calculates file hash

    .DESCRIPTION
        Computes cryptographic hash of a file.
        Read-only operation.

    .PARAMETER FilePath
        Path to the file

    .PARAMETER Algorithm
        Hash algorithm (default: SHA256)

    .EXAMPLE
        Get-FileHashData -FilePath "C:\Program Files\MyApp\app.exe"

    .EXAMPLE
        Get-FileHashData -FilePath "C:\temp\file.exe" -Algorithm SHA1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter()]
        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
        [string]$Algorithm = 'SHA256'
    )

    begin {
        Write-Verbose "Calculating $Algorithm hash for: $FilePath"
    }

    process {
        try {
            if (-not (Test-Path $FilePath)) {
                Write-Warning "File not found: $FilePath"
                return $null
            }

            $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop

            Write-Verbose "Hash calculated: $($hash.Hash)"

            return [PSCustomObject]@{
                FilePath = $FilePath
                Algorithm = $Algorithm
                Hash = $hash.Hash
            }
        }
        catch {
            Write-Warning "Failed to calculate file hash: $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-InstalledApplications {
    <#
    .SYNOPSIS
        Enumerates installed applications

    .DESCRIPTION
        Queries system for installed applications from multiple sources.
        Read-only operation.

    .PARAMETER ComputerName
        Target computer (default: local)

    .EXAMPLE
        Get-InstalledApplications

    .EXAMPLE
        Get-InstalledApplications -ComputerName "SERVER01"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        Write-Verbose "Enumerating installed applications on: $ComputerName"
    }

    process {
        try {
            $applications = @()

            # Registry paths for installed software
            $regPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )

            foreach ($regPath in $regPaths) {
                if (Test-Path $regPath) {
                    try {
                        Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName } |
                            ForEach-Object {
                                $applications += [PSCustomObject]@{
                                    ComputerName = $ComputerName
                                    Name = $_.DisplayName
                                    Version = $_.DisplayVersion
                                    Publisher = $_.Publisher
                                    InstallDate = $_.InstallDate
                                    InstallLocation = $_.InstallLocation
                                    UninstallString = $_.UninstallString
                                }
                            }
                    }
                    catch {
                        Write-Verbose "Failed to query registry path '$regPath': $($_.Exception.Message)"
                    }
                }
            }

            # Remove duplicates based on Name and Version
            $applications = $applications | Sort-Object Name, Version -Unique

            Write-Verbose "Found $($applications.Count) installed applications"
            return $applications
        }
        catch {
            Write-Error "Failed to enumerate installed applications: $($_.Exception.Message)"
            return @()
        }
    }
}

function Search-ExecutablesInPath {
    <#
    .SYNOPSIS
        Finds executable files in specified path

    .DESCRIPTION
        Searches for .exe files in a directory tree.
        Read-only operation.

    .PARAMETER Path
        Root path to search

    .PARAMETER Recurse
        Search subdirectories

    .PARAMETER MaxDepth
        Maximum recursion depth

    .PARAMETER Filter
        Filename filter pattern

    .EXAMPLE
        Search-ExecutablesInPath -Path "C:\Program Files"

    .EXAMPLE
        Search-ExecutablesInPath -Path "C:\Apps" -Recurse -Filter "*setup*"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [switch]$Recurse,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxDepth = 5,

        [Parameter()]
        [string]$Filter = "*.exe"
    )

    begin {
        Write-Verbose "Searching for executables in: $Path"
    }

    process {
        try {
            if (-not (Test-Path $Path)) {
                Write-Warning "Path not found: $Path"
                return @()
            }

            $searchParams = @{
                Path = $Path
                Filter = $Filter
                File = $true
                ErrorAction = 'SilentlyContinue'
            }

            if ($Recurse) {
                $searchParams['Recurse'] = $true
                $searchParams['Depth'] = $MaxDepth
            }

            $executables = Get-ChildItem @searchParams

            Write-Verbose "Found $($executables.Count) executables"

            return $executables
        }
        catch {
            Write-Error "Failed to search for executables: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-SystemInformation {
    <#
    .SYNOPSIS
        Retrieves system information

    .DESCRIPTION
        Queries basic system details including OS, architecture, and hardware.
        Read-only operation.

    .PARAMETER ComputerName
        Target computer (default: local)

    .EXAMPLE
        Get-SystemInformation
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        Write-Verbose "Retrieving system information for: $ComputerName"
    }

    process {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

            $sysInfo = [PSCustomObject]@{
                ComputerName = $ComputerName
                Domain = $cs.Domain
                OperatingSystem = $os.Caption
                OSVersion = $os.Version
                OSBuild = $os.BuildNumber
                Architecture = $os.OSArchitecture
                LastBootTime = $os.LastBootUpTime
                TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
            }

            Write-Verbose "System: $($sysInfo.OperatingSystem) $($sysInfo.Architecture)"
            return $sysInfo
        }
        catch {
            Write-Error "Failed to retrieve system information: $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-RunningProcesses {
    <#
    .SYNOPSIS
        Retrieves running processes with file details

    .DESCRIPTION
        Queries active processes and includes publisher/version information.
        Read-only operation.

    .EXAMPLE
        Get-RunningProcesses
    #>
    [CmdletBinding()]
    param()

    begin {
        Write-Verbose "Retrieving running processes"
    }

    process {
        try {
            $processes = Get-Process -ErrorAction Stop | ForEach-Object {
                try {
                    $proc = $_
                    $path = $proc.Path
                    $publisher = "Unknown"
                    $version = "Unknown"

                    if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                        $vInfo = (Get-Item $path -ErrorAction SilentlyContinue).VersionInfo
                        $publisher = if ($vInfo.CompanyName) {
                            $vInfo.CompanyName
                        } else {
                            "Unknown"
                        }
                        $version = if ($vInfo.FileVersion) {
                            $vInfo.FileVersion
                        } else {
                            "Unknown"
                        }
                    }

                    [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        PID = $proc.Id
                        Path = $path
                        Publisher = $publisher
                        Version = $version
                        WorkingSetMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                        StartTime = $proc.StartTime
                    }
                }
                catch {
                    # Skip processes we can't access
                    $null
                }
            } | Where-Object { $_.Path }

            Write-Verbose "Retrieved $($processes.Count) running processes"
            return $processes
        }
        catch {
            Write-Error "Failed to retrieve running processes: $($_.Exception.Message)"
            return @()
        }
    }
}

function Test-PathWritable {
    <#
    .SYNOPSIS
        Tests if a path is writable

    .DESCRIPTION
        Checks if the current user has write access to a directory.
        Read-only operation (test file is immediately deleted).

    .PARAMETER Path
        Directory path to test

    .EXAMPLE
        Test-PathWritable -Path "C:\Program Files"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    begin {
        Write-Verbose "Testing write access to: $Path"
    }

    process {
        try {
            if (-not (Test-Path $Path)) {
                Write-Verbose "Path does not exist: $Path"
                return $false
            }

            $testFile = Join-Path $Path ".writetest_$(Get-Random)"

            try {
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                Write-Verbose "Path is writable: $Path"
                return $true
            }
            catch {
                Write-Verbose "Path is not writable: $Path"
                return $false
            }
        }
        catch {
            Write-Verbose "Failed to test path writability: $($_.Exception.Message)"
            return $false
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-LocalExecutableArtifacts',
    'Get-FilePublisher',
    'Get-FileHashData',
    'Get-InstalledApplications',
    'Search-ExecutablesInPath',
    'Get-SystemInformation',
    'Get-RunningProcesses',
    'Test-PathWritable'
)
