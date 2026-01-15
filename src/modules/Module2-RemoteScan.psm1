# Module2-RemoteScan.psm1
# Remote Scan module for GA-AppLocker
# Discovers machines in AD and scans them for software artifacts
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

<#
.SYNOPSIS
    Classify Directory Safety
.DESCRIPTION
    Determines if a directory is safe for scanning (from AaronLocker)
.PARAMETER DirectoryPath
    The directory path to classify
.OUTPUTS
    SafeDir, UnsafeDir, or UnknownDir
#>
function Get-DirectorySafetyClassification {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath
    )

    if ([string]::IsNullOrWhiteSpace($DirectoryPath)) {
        return $UnknownDir
    }

    # Normalize the path
    $normalizedPath = $DirectoryPath.TrimEnd('\')

    # Unsafe directories - user-writable or temp locations (from AaronLocker)
    # Use 4 backslashes in PowerShell single quotes to match literal backslash in regex
    $unsafePatterns = @(
        'C:\\\\Users\\\\.*\\\\AppData\\\\Local\\\\Temp',
        'C:\\\\Windows\\\\Temp',
        'C:\\\\Temp',
        'C:\\\\ProgramData\\\\.*\\\\Temp',
        'C:\\\\Users\\\\.*\\\\Downloads',
        'C:\\\\Users\\\\Public\\\\Downloads',
        'C:\\\\Users\\\\.*\\\\Desktop',
        '\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup'
    )

    foreach ($pattern in $unsafePatterns) {
        if ($normalizedPath -match $pattern) {
            return $UnsafeDir
        }
    }

    # Safe directories - well-known locations (from AaronLocker)
    $safePatterns = @(
        '^C:\\\\Windows\\\\system32$',
        '^C:\\\\Windows\\\\SysWOW64$',
        '^C:\\\\Windows\\\\.*$',
        '^C:\\\\Program Files\\\\.*$',
        '^C:\\\\Program Files \\(x86\\)\\\\.*$',
        '^C:\\\\Program Files\\\\WindowsApps\\\\.*$',
        '^C:\\\\Program Files\\\\Common Files\\\\.*$',
        '^C:\\\\Program Files \\(x86\\)\\\\Common Files\\\\.*$'
    )

    foreach ($pattern in $safePatterns) {
        if ($normalizedPath -match $pattern) {
            return $SafeDir
        }
    }

    # Default to unknown for unclassified paths
    return $UnknownDir
}

<#
.SYNOPSIS
    Get Directory Files with Junction Handling
.DESCRIPTION
    Recursively gets files from a directory while handling junctions and reparse points (from AaronLocker)
.PARAMETER Path
    The directory path to scan
.PARAMETER Extension
    File extension filter
.PARAMETER MaxFiles
    Maximum number of files to return
.OUTPUTS
    Array of FileInfo objects
#>
function Get-DirectoryFilesSafe {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string[]]$Extension = @('.exe'),
        [int]$MaxFiles = 500
    )

    if (-not (Test-Path $Path)) {
        return @()
    }

    $files = @()
    $visitedPaths = @{}  # Track visited paths to avoid infinite loops
    $queue = @(@{ Path = $Path; Depth = 0 })

    while ($queue.Count -gt 0 -and $files.Count -lt $MaxFiles) {
        $current = $queue[0]
        $queue = $queue[1..($queue.Count - 1)]

        $currentPath = $current.Path
        $currentDepth = $current.Depth

        # Skip if we've already visited this path
        if ($visitedPaths.ContainsKey($currentPath)) {
            continue
        }
        $visitedPaths[$currentPath] = $true

        # Check for junction/reparse point (from AaronLocker)
        try {
            $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
            if ($item.LinkType -eq 'Junction' -or $item.Target -is [System.IO.DirectoryInfo]) {
                $reparsePoint = [System.IO.Directory]::EnumerateFiles($currentPath, '*', [System.IO.EnumerationOptions]::new())
                # Skip scanning into junctions/reparse points to avoid infinite loops
                continue
            }
        }
        catch {
            # Skip paths we can't access
            continue
        }

        # Get files in current directory
        try {
            $dirFiles = Get-ChildItem -LiteralPath $currentPath -File -ErrorAction Stop |
                Where-Object { $Extension -contains $_.Extension }

            foreach ($file in $dirFiles) {
                if ($files.Count -ge $MaxFiles) {
                    break
                }
                $files += $file
            }
        }
        catch {
            # Skip directories we can't read
        }

        # Limit recursion depth
        if ($currentDepth -lt 10) {
            # Add subdirectories to queue
            try {
                $subdirs = Get-ChildItem -LiteralPath $currentPath -Directory -ErrorAction Stop
                foreach ($subdir in $subdirs) {
                    if (-not $visitedPaths.ContainsKey($subdir.FullName)) {
                        $queue += @{ Path = $subdir.FullName; Depth = $currentDepth + 1 }
                    }
                }
            }
            catch {
                # Skip directories we can't read
            }
        }
    }

    return $files
}

<#
.SYNOPSIS
    Get All AD Computers
.DESCRIPTION
    Retrieves all computers from Active Directory with properties
#>
function Get-AllADComputers {
    [CmdletBinding()]
    param(
        [int]$MaxResults = 500
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate, Description |
            Select-Object -First $MaxResults

        $results = @()
        foreach ($computer in $computers) {
            $dn = $computer.DistinguishedName
            $ou = ($dn -split ',', 2)[1]

            $results += @{
                hostname = $computer.Name
                os = $computer.OperatingSystem
                lastLogon = if ($computer.LastLogonDate) {
                    $computer.LastLogonDate.ToString('yyyy-MM-dd')
                } else { 'Never' }
                ou = $ou
                description = $computer.Description
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Get Computers by OU
.DESCRIPTION
    Retrieves computers from a specific Organizational Unit
#>
function Get-ComputersByOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OUPath
    )

    if ([string]::IsNullOrWhiteSpace($OUPath)) {
        return @{
            success = $false
            error = 'OU path is required'
            data = @()
        }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $computers = Get-ADComputer -SearchBase $OUPath -SearchScope Subtree -Filter * `
            -Properties OperatingSystem, LastLogonDate

        $results = @()
        foreach ($computer in $computers) {
            $results += @{
                hostname = $computer.Name
                os = $computer.OperatingSystem
                lastLogon = if ($computer.LastLogonDate) {
                    $computer.LastLogonDate.ToString('yyyy-MM-dd')
                } else { 'Never' }
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
            ou = $OUPath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Test if Computer is Online
.DESCRIPTION
    Pings a computer to check if it's reachable with configurable timeout
.PARAMETER ComputerName
    The name of the computer to test
.PARAMETER TimeoutMs
    Timeout in milliseconds (default 1000ms = 1 second)
#>
function Test-ComputerOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMs = 1000
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return @{
            success = $false
            online = $false
            error = 'Computer name is required'
        }
    }

    try {
        # Use .NET Ping for faster timeout control
        $ping = New-Object System.Net.NetworkInformation.Ping
        $result = $ping.Send($ComputerName, $TimeoutMs)
        $pingResult = ($result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
        $ping.Dispose()
    }
    catch {
        $pingResult = $false
    }

    return @{
        success = $true
        computerName = $ComputerName
        online = $pingResult
    }
}

<#
.SYNOPSIS
    Scan Local Path for Executables
.DESCRIPTION
    Finds all EXE files in a folder and collects file information with PE detection (from AaronLocker)
.PARAMETER TargetPath
    The directory path to scan
.PARAMETER MaxFiles
    Maximum number of files to return
.PARAMETER IncludeUnsafe
    Include files from unsafe directories
#>
function Get-ExecutableArtifacts {
    [CmdletBinding()]
    param(
        [string]$TargetPath = 'C:\Program Files',
        [int]$MaxFiles = 500,
        [switch]$IncludeUnsafe
    )

    if (-not (Test-Path $TargetPath)) {
        return @{
            success = $false
            error = "Path not found: $TargetPath"
            data = @()
        }
    }

    # Check directory safety classification (from AaronLocker)
    $safetyClass = Get-DirectorySafetyClassification -DirectoryPath $TargetPath
    if ($safetyClass -eq $UnsafeDir -and -not $IncludeUnsafe) {
        return @{
            success = $false
            error = "Path is in unsafe directory: $TargetPath. Use -IncludeUnsafe to scan anyway."
            data = @()
            safetyClassification = $safetyClass
        }
    }

    try {
        # Use safe directory scanning with junction handling (from AaronLocker)
        $files = Get-DirectoryFilesSafe -Path $TargetPath -Extension @('.exe') -MaxFiles $MaxFiles

        if (-not $files -or $files.Count -eq 0) {
            return @{
                success = $true
                data = @()
                message = "No executables found in $TargetPath"
                safetyClassification = $safetyClass
            }
        }

        $results = @()
        $filteredOut = 0

        foreach ($file in $files) {
            $filePath = $file.FullName
            $fileName = $file.Name
            $parentDir = Split-Path -Parent $filePath

            # Check parent directory safety
            $parentSafety = Get-DirectorySafetyClassification -DirectoryPath $parentDir
            if ($parentSafety -eq $UnsafeDir -and -not $IncludeUnsafe) {
                $filteredOut++
                continue
            }

            # Use PE detection from AaronLocker to verify it's a real executable
            $peType = IsWin32Executable -filename $filePath
            if ($peType -ne 'EXE') {
                # Skip non-EXE files (even if they have .exe extension)
                continue
            }

            # Get file hash
            $hashResult = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
            $hash = if ($hashResult) { $hashResult.Hash } else { '' }

            # Get signature
            $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
            $publisher = 'Unknown'
            $isSigned = $false
            if ($signature -and $signature.SignerCertificate) {
                $subject = $signature.SignerCertificate.Subject
                if ($subject -match 'CN=([^,]+)') {
                    $publisher = $matches[1]
                }
                $isSigned = ($signature.Status -eq 'Valid')
            }

            $version = $file.VersionInfo.FileVersion

            # Get generic path for portability (from AaronLocker)
            $genericPath = ConvertTo-AppLockerGenericPath -FilePath $filePath

            $results += @{
                name = $fileName
                path = $filePath
                genericPath = $genericPath
                hash = $hash
                publisher = $publisher
                isSigned = $isSigned
                version = $version
                size = $file.Length
                safetyClassification = $parentSafety
                peType = $peType
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
            scannedPath = $TargetPath
            safetyClassification = $safetyClass
            filteredOut = $filteredOut
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Scan Remote Computer for Artifacts
.DESCRIPTION
    Runs artifact scan on a remote computer via WinRM
#>
function Get-RemoteArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [PSCredential]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return @{
            success = $false
            error = 'Computer name is required'
            data = @()
        }
    }

    # Test WinRM
    $winrmTest = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
    if (-not $winrmTest) {
        return @{
            success = $false
            error = "WinRM not available on '$ComputerName'"
            data = @()
        }
    }

    $scanScript = {
        $results = @()
        $paths = @('C:\Program Files', 'C:\Program Files (x86)')

        foreach ($path in $paths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -Recurse -Include *.exe -ErrorAction SilentlyContinue |
                    Select-Object -First 50

                foreach ($file in $files) {
                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                    $publisher = 'Unknown'
                    if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') {
                        $publisher = $matches[1]
                    }

                    $results += @{
                        name = $file.Name
                        path = $file.FullName
                        publisher = $publisher
                    }
                }
            }
        }

        return $results
    }

    try {
        if ($Credential) {
            $remoteResults = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scanScript -ErrorAction Stop
        }
        else {
            $remoteResults = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scanScript -ErrorAction Stop
        }

        return @{
            success = $true
            data = $remoteResults
            count = $remoteResults.Count
            computerName = $ComputerName
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Export Scan Results to CSV
.DESCRIPTION
    Saves scan results to a CSV file
#>
function Export-ScanResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Artifacts,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if (-not $Artifacts -or $Artifacts.Count -eq 0) {
        return @{
            success = $false
            error = 'No artifacts to export'
        }
    }

    try {
        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $Artifacts | Export-Csv -Path $OutputPath -NoTypeInformation -Force

        return @{
            success = $true
            path = $OutputPath
            count = $Artifacts.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Import Scan Results from CSV
.DESCRIPTION
    Loads previously saved scan results
#>
function Import-ScanResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path $CsvPath)) {
        return @{
            success = $false
            error = "File not found: $CsvPath"
            data = @()
        }
    }

    try {
        $data = Import-Csv -Path $CsvPath -ErrorAction Stop

        $artifacts = @()
        foreach ($row in $data) {
            $artifacts += @{
                name = $row.Name
                path = $row.Path
                publisher = $row.Publisher
                hash = $row.Hash
                version = $row.Version
            }
        }

        return @{
            success = $true
            data = $artifacts
            count = $artifacts.Count
            source = $CsvPath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

# Export functions
Export-ModuleMember -Function Get-DirectorySafetyClassification, Get-DirectoryFilesSafe,
                              Get-AllADComputers, Get-ComputersByOU, Test-ComputerOnline,
                              Get-ExecutableArtifacts, Get-RemoteArtifacts,
                              Export-ScanResults, Import-ScanResults
