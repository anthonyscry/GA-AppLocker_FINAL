# Module2-RemoteScan.psm1
# Remote Scan module for GA-AppLocker
# Discovers machines in AD and scans them for software artifacts
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

# Import required modules at module level for performance
# These imports are done once at module load instead of per function call
Import-Module ActiveDirectory -ErrorAction SilentlyContinue -Verbose:$false

# Import variables from Common module into local scope
$script:UnsafeDir = (Get-Module Common).ExportedVariables['UnsafeDir'].Value
$script:SafeDir = (Get-Module Common).ExportedVariables['SafeDir'].Value
$script:UnknownDir = (Get-Module Common).ExportedVariables['UnknownDir'].Value

# Fallback if module variables aren't accessible
if (-not $script:UnsafeDir) { $script:UnsafeDir = "UnsafeDir" }
if (-not $script:SafeDir) { $script:SafeDir = "SafeDir" }
if (-not $script:UnknownDir) { $script:UnknownDir = "UnknownDir" }

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
        return $script:UnknownDir
    }

    # Normalize the path
    $normalizedPath = $DirectoryPath.TrimEnd('\')

    # Unsafe directories - user-writable or temp locations (from AaronLocker)
    # Using [regex]::Escape for robust path matching
    $unsafePatterns = @(
        [regex]::Escape('C:\Users') + '.+' + [regex]::Escape('\AppData\Local\Temp'),
        [regex]::Escape('C:\Windows\Temp'),
        [regex]::Escape('C:\Temp'),
        [regex]::Escape('C:\ProgramData') + '.+' + [regex]::Escape('\Temp'),
        [regex]::Escape('C:\Users') + '.+' + [regex]::Escape('\Downloads'),
        [regex]::Escape('C:\Users\Public\Downloads'),
        [regex]::Escape('C:\Users') + '.+' + [regex]::Escape('\Desktop'),
        [regex]::Escape('\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
    )

    foreach ($pattern in $unsafePatterns) {
        if ($normalizedPath -match $pattern) {
            return $script:UnsafeDir
        }
    }

    # Safe directories - well-known locations (from AaronLocker)
    # Using [regex]::Escape for robust path matching with wildcards
    $safePatterns = @(
        '^' + [regex]::Escape('C:\Windows\system32') + '$',
        '^' + [regex]::Escape('C:\Windows\SysWOW64') + '$',
        '^' + [regex]::Escape('C:\Windows') + '.*$',
        '^' + [regex]::Escape('C:\Program Files') + '.*$',
        '^' + [regex]::Escape('C:\Program Files (x86)') + '.*$',
        '^' + [regex]::Escape('C:\Program Files\WindowsApps') + '.*$',
        '^' + [regex]::Escape('C:\Program Files\Common Files') + '.*$',
        '^' + [regex]::Escape('C:\Program Files (x86)\Common Files') + '.*$'
    )

    foreach ($pattern in $safePatterns) {
        if ($normalizedPath -match $pattern) {
            return $script:SafeDir
        }
    }

    # Default to unknown for unclassified paths
    return $script:UnknownDir
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
            # Skip any reparse points (junctions, symbolic links) to avoid infinite loops
            # LinkType is 'Junction', 'SymbolicLink', 'HardLink' or $null for regular dirs
            # Target is a string array with the link destination, or $null for regular dirs
            if ($item.LinkType -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                # Skip scanning into reparse points
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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. This feature requires a Domain Controller or domain-joined computer with RSAT installed.'
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

    # Check if ActiveDirectory module is available (imported at module level)
    if (-not (Get-Module ActiveDirectory)) {
        return @{
            success = $false
            error = 'ActiveDirectory module not available. This feature requires a Domain Controller or domain-joined computer with RSAT installed.'
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

    $ping = $null
    try {
        # Use .NET Ping for faster timeout control
        $ping = New-Object System.Net.NetworkInformation.Ping
        $result = $ping.Send($ComputerName, $TimeoutMs)
        $pingResult = ($result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    }
    catch {
        $pingResult = $false
    }
    finally {
        if ($ping) {
            $ping.Dispose()
        }
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
    Finds executable files in a folder using Get-AppLockerFileInformation (like AaronLocker).
    Scans for EXE, DLL, MSI, and script files.
.PARAMETER TargetPath
    The directory path to scan
.PARAMETER MaxFiles
    Maximum number of files to return
.PARAMETER IncludeUnsafe
    Include files from unsafe directories
.PARAMETER Recurse
    Recurse into subdirectories (default: true)
#>
function Get-ExecutableArtifacts {
    [CmdletBinding()]
    param(
        [Alias('Path')]
        [string]$TargetPath = 'C:\Program Files',
        [int]$MaxFiles = 500,
        [switch]$IncludeUnsafe,
        [switch]$Recurse = $true
    )

    # Validate target path
    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        return @()
    }

    if (-not (Test-Path $TargetPath)) {
        return @()
    }

    # File extensions to scan (from AaronLocker)
    $executableExtensions = @('.exe', '.dll', '.com', '.ocx', '.msi', '.msp', '.mst', '.bat', '.cmd', '.ps1', '.vbs', '.js')

    $results = @()

    try {
        # Get files with executable extensions
        $getChildParams = @{
            Path = $TargetPath
            File = $true
            ErrorAction = 'SilentlyContinue'
        }
        if ($Recurse) {
            $getChildParams.Recurse = $true
        }

        $files = Get-ChildItem @getChildParams | Where-Object {
            $executableExtensions -contains $_.Extension.ToLower()
        } | Select-Object -First $MaxFiles

        if (-not $files -or $files.Count -eq 0) {
            return @()
        }

        foreach ($file in $files) {
            if ($results.Count -ge $MaxFiles) { break }

            $filePath = $file.FullName
            $fileName = $file.Name

            # Skip zero-length files (Get-AppLockerFileInformation fails on them)
            if ($file.Length -eq 0) { continue }

            try {
                # Use Get-AppLockerFileInformation like AaronLocker does
                $alfi = Get-AppLockerFileInformation -Path $filePath -ErrorAction SilentlyContinue

                $publisher = 'Unknown'
                $productName = ''
                $binaryName = ''
                $version = ''
                $hash = ''

                if ($alfi) {
                    # Get publisher info
                    if ($alfi.Publisher) {
                        $publisher = $alfi.Publisher.PublisherName
                        $productName = $alfi.Publisher.ProductName
                        $binaryName = $alfi.Publisher.BinaryName
                        $version = if ($alfi.Publisher.BinaryVersion) { $alfi.Publisher.BinaryVersion.ToString() } else { '' }
                    }
                    # Get hash
                    if ($alfi.Hash -and $alfi.Hash.HashDataString) {
                        $hash = $alfi.Hash.HashDataString
                    }
                }

                # Fallback to manual methods if Get-AppLockerFileInformation didn't get everything
                if ([string]::IsNullOrEmpty($hash)) {
                    $hashResult = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue
                    if ($hashResult) { $hash = $hashResult.Hash }
                }

                if ($publisher -eq 'Unknown' -or [string]::IsNullOrEmpty($publisher)) {
                    $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
                        if ($sig.SignerCertificate.Subject -match 'CN=([^,]+)') {
                            $publisher = $matches[1]
                        }
                    }
                }

                if ([string]::IsNullOrEmpty($version)) {
                    $version = $file.VersionInfo.FileVersion
                }

                # Determine file type
                $fileType = switch ($file.Extension.ToLower()) {
                    '.exe' { 'EXE' }
                    '.dll' { 'DLL' }
                    '.com' { 'EXE' }
                    '.ocx' { 'DLL' }
                    '.msi' { 'MSI' }
                    '.msp' { 'MSI' }
                    '.mst' { 'MSI' }
                    '.bat' { 'Script' }
                    '.cmd' { 'Script' }
                    '.ps1' { 'Script' }
                    '.vbs' { 'Script' }
                    '.js'  { 'Script' }
                    default { 'Unknown' }
                }

                $results += [PSCustomObject]@{
                    FileName = $fileName
                    Path = $filePath
                    Publisher = if ($publisher) { $publisher } else { 'Unknown' }
                    ProductName = $productName
                    BinaryName = $binaryName
                    Version = $version
                    Hash = $hash
                    Size = $file.Length
                    FileType = $fileType
                    ModifiedDate = $file.LastWriteTime
                }
            }
            catch {
                # Skip files that cause errors
                continue
            }
        }

        return $results
    }
    catch {
        return @()
    }
}

<#
.SYNOPSIS
    Scan Remote Computer for Artifacts
.DESCRIPTION
    Runs artifact scan on a remote computer via WinRM using Get-AppLockerFileInformation.
    Scans for EXE, DLL, MSI, and script files (like AaronLocker).
.PARAMETER ComputerName
    Remote computer name
.PARAMETER Credential
    Optional credentials for remote access
.PARAMETER MaxFiles
    Maximum files to return per path (default: 100)
#>
function Get-RemoteArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [PSCredential]$Credential,
        [int]$MaxFiles = 100
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
        param($MaxFilesParam)

        $results = @()
        $paths = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData')
        $executableExtensions = @('.exe', '.dll', '.msi', '.msp', '.bat', '.cmd', '.ps1', '.vbs')

        foreach ($path in $paths) {
            if (-not (Test-Path $path)) { continue }

            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $executableExtensions -contains $_.Extension.ToLower() } |
                Select-Object -First $MaxFilesParam

            foreach ($file in $files) {
                if ($file.Length -eq 0) { continue }

                try {
                    # Use Get-AppLockerFileInformation like AaronLocker
                    $alfi = Get-AppLockerFileInformation -Path $file.FullName -ErrorAction SilentlyContinue

                    $publisher = 'Unknown'
                    $productName = ''
                    $version = ''
                    $hash = ''

                    if ($alfi) {
                        if ($alfi.Publisher) {
                            $publisher = $alfi.Publisher.PublisherName
                            $productName = $alfi.Publisher.ProductName
                            $version = if ($alfi.Publisher.BinaryVersion) { $alfi.Publisher.BinaryVersion.ToString() } else { '' }
                        }
                        if ($alfi.Hash -and $alfi.Hash.HashDataString) {
                            $hash = $alfi.Hash.HashDataString
                        }
                    }

                    # Fallback to signature if publisher not found
                    if ($publisher -eq 'Unknown' -or [string]::IsNullOrEmpty($publisher)) {
                        $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                        if ($sig -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') {
                            $publisher = $matches[1]
                        }
                    }

                    # Determine file type
                    $fileType = switch ($file.Extension.ToLower()) {
                        '.exe' { 'EXE' }
                        '.dll' { 'DLL' }
                        '.msi' { 'MSI' }
                        '.msp' { 'MSI' }
                        { $_ -in '.bat', '.cmd', '.ps1', '.vbs' } { 'Script' }
                        default { 'Unknown' }
                    }

                    $results += [PSCustomObject]@{
                        FileName = $file.Name
                        Path = $file.FullName
                        Publisher = if ($publisher) { $publisher } else { 'Unknown' }
                        ProductName = $productName
                        Version = $version
                        Hash = $hash
                        Size = $file.Length
                        FileType = $fileType
                        ModifiedDate = $file.LastWriteTime
                    }
                }
                catch {
                    continue
                }
            }
        }

        return $results
    }

    try {
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock = $scanScript
            ArgumentList = @($MaxFiles)
            ErrorAction = 'Stop'
        }

        if ($Credential) {
            $invokeParams.Credential = $Credential
        }

        $remoteResults = Invoke-Command @invokeParams

        return @{
            success = $true
            data = $remoteResults
            count = if ($remoteResults) { $remoteResults.Count } else { 0 }
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

# ======================================================================
# REMOTE APPLOCKER EVENT LOG SCANNING
# Comprehensive remote event log collection for rule generation
# ======================================================================

<#
.SYNOPSIS
    Get Remote AppLocker Event Logs
.DESCRIPTION
    Scans a remote computer for AppLocker event logs and returns comprehensive data
    including system info, policy status, and events formatted for rule generation.
    This is a comprehensive scan that collects all AppLocker-relevant data from a target.
.PARAMETER ComputerName
    The name of the remote computer to scan
.PARAMETER Credential
    Optional credentials for remote authentication
.PARAMETER DaysBack
    Number of days of event history to retrieve (default: 7)
.PARAMETER MaxEvents
    Maximum number of events to retrieve per log (default: 1000)
.PARAMETER IncludePolicyXml
    Include the full effective policy XML in results (default: false, can be large)
.OUTPUTS
    Hashtable with system info, policy status, and events formatted for rule generator
.EXAMPLE
    $result = Get-RemoteAppLockerEvents -ComputerName "WORKSTATION01"
    $result.artifacts | ForEach-Object { New-PublisherRule -PublisherName $_.publisher }
#>
function Get-RemoteAppLockerEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = 7,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = 1000,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePolicyXml
    )

    # Validate computer name
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return @{
            success = $false
            error = 'Computer name is required'
            computerName = $ComputerName
        }
    }

    # Test WinRM connectivity before attempting remote scan
    $winrmTest = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
    if (-not $winrmTest) {
        return @{
            success = $false
            error = "WinRM not available on '$ComputerName'. Ensure WinRM is enabled and firewall allows connections."
            computerName = $ComputerName
        }
    }

    # Define the remote script block that runs on the target computer
    # This collects all AppLocker-related data in a single remote session
    $scanScript = {
        param($DaysBack, $MaxEvents, $IncludePolicyXml)

        $Result = [ordered]@{
            success = $true
            timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }

        # ----------------------------
        # SYSTEM INFORMATION
        # Collect basic system info for inventory and troubleshooting
        # ----------------------------
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $Result.System = @{
                ComputerName = $env:COMPUTERNAME
                OS           = $os.Caption
                Build        = $os.BuildNumber
                Version      = $os.Version
                Architecture = $env:PROCESSOR_ARCHITECTURE
            }
        }
        catch {
            $Result.System = @{
                ComputerName = $env:COMPUTERNAME
                error = $_.Exception.Message
            }
        }

        # ----------------------------
        # APPLOCKER SERVICE STATE
        # Check if AppIDSvc is running (required for AppLocker enforcement)
        # ----------------------------
        try {
            $svc = Get-Service AppIDSvc -ErrorAction Stop
            $svcWmi = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" -ErrorAction SilentlyContinue
            $Result.AppIDSvc = @{
                Status      = $svc.Status.ToString()
                StartupType = if ($svcWmi) { $svcWmi.StartMode } else { 'Unknown' }
                IsRunning   = ($svc.Status -eq 'Running')
            }
        }
        catch {
            $Result.AppIDSvc = @{
                Status      = 'NotInstalled'
                StartupType = 'Unknown'
                IsRunning   = $false
                error       = $_.Exception.Message
            }
        }

        # ----------------------------
        # EFFECTIVE APPLOCKER POLICY
        # Get current policy enforcement modes and rule counts
        # ----------------------------
        try {
            $Policy = Get-AppLockerPolicy -Effective -ErrorAction Stop

            # Extract enforcement mode for each rule collection
            $Result.PolicyMode = @{
                Exe    = if ($Policy.RuleCollections["Exe"]) { $Policy.RuleCollections["Exe"].EnforcementMode.ToString() } else { 'NotConfigured' }
                Dll    = if ($Policy.RuleCollections["Dll"]) { $Policy.RuleCollections["Dll"].EnforcementMode.ToString() } else { 'NotConfigured' }
                Msi    = if ($Policy.RuleCollections["Msi"]) { $Policy.RuleCollections["Msi"].EnforcementMode.ToString() } else { 'NotConfigured' }
                Script = if ($Policy.RuleCollections["Script"]) { $Policy.RuleCollections["Script"].EnforcementMode.ToString() } else { 'NotConfigured' }
                Appx   = if ($Policy.RuleCollections["Appx"]) { $Policy.RuleCollections["Appx"].EnforcementMode.ToString() } else { 'NotConfigured' }
            }

            # Count rules in each collection
            $Result.RuleCounts = @{
                ExeRules    = if ($Policy.RuleCollections["Exe"]) { $Policy.RuleCollections["Exe"].Count } else { 0 }
                DllRules    = if ($Policy.RuleCollections["Dll"]) { $Policy.RuleCollections["Dll"].Count } else { 0 }
                MsiRules    = if ($Policy.RuleCollections["Msi"]) { $Policy.RuleCollections["Msi"].Count } else { 0 }
                ScriptRules = if ($Policy.RuleCollections["Script"]) { $Policy.RuleCollections["Script"].Count } else { 0 }
                AppxRules   = if ($Policy.RuleCollections["Appx"]) { $Policy.RuleCollections["Appx"].Count } else { 0 }
            }

            $Result.HasPolicy = $true

            # Optionally include full policy XML (can be large)
            if ($IncludePolicyXml) {
                $PolicyXml = Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
                $Result.PolicyXml = if ($PolicyXml) { $PolicyXml.OuterXml } else { $null }
            }
        }
        catch {
            $Result.PolicyMode = @{
                Exe = 'NotConfigured'; Dll = 'NotConfigured'; Msi = 'NotConfigured'
                Script = 'NotConfigured'; Appx = 'NotConfigured'
            }
            $Result.RuleCounts = @{
                ExeRules = 0; DllRules = 0; MsiRules = 0; ScriptRules = 0; AppxRules = 0
            }
            $Result.HasPolicy = $false
            $Result.PolicyError = $_.Exception.Message
        }

        # ----------------------------
        # APPLOCKER EVENT LOGS
        # Collect events from all AppLocker log channels
        # ----------------------------
        $Since = (Get-Date).AddDays(-$DaysBack)

        # Define all AppLocker event log channels
        $LogNames = @(
            "Microsoft-Windows-AppLocker/EXE and DLL",
            "Microsoft-Windows-AppLocker/MSI and Script",
            "Microsoft-Windows-AppLocker/Packaged app-Deployment",
            "Microsoft-Windows-AppLocker/Packaged app-Execution"
        )

        $AllEvents = @()
        $EventSummary = @{
            TotalEvents = 0
            AllowedCount = 0
            AuditCount = 0
            BlockedCount = 0
            ByEventId = @{}
        }

        foreach ($LogName in $LogNames) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName   = $LogName
                    StartTime = $Since
                } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

                if ($events) {
                    foreach ($event in $events) {
                        # Parse event message to extract file path and other details
                        # AppLocker events contain file path, publisher, hash in XML data
                        $eventData = @{
                            TimeCreated     = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                            EventId         = $event.Id
                            Level           = $event.LevelDisplayName
                            LogName         = $LogName
                            Message         = $event.Message
                            UserSid         = $null
                            FilePath        = $null
                            FileHash        = $null
                            Publisher       = $null
                            ProductName     = $null
                            FileName        = $null
                            EventType       = $null
                        }

                        # Classify event by ID
                        # EXE/DLL: 8002=Allowed, 8003=Audit, 8004=Blocked
                        # MSI/Script: 8005=Allowed, 8006=Audit, 8007=Blocked
                        # Packaged App: 8020=Allowed, 8021=Audit, 8022=Blocked
                        switch ($event.Id) {
                            8002 { $eventData.EventType = 'Allowed'; $EventSummary.AllowedCount++ }
                            8003 { $eventData.EventType = 'Audit'; $EventSummary.AuditCount++ }
                            8004 { $eventData.EventType = 'Blocked'; $EventSummary.BlockedCount++ }
                            8005 { $eventData.EventType = 'Allowed'; $EventSummary.AllowedCount++ }
                            8006 { $eventData.EventType = 'Audit'; $EventSummary.AuditCount++ }
                            8007 { $eventData.EventType = 'Blocked'; $EventSummary.BlockedCount++ }
                            8020 { $eventData.EventType = 'Allowed'; $EventSummary.AllowedCount++ }
                            8021 { $eventData.EventType = 'Audit'; $EventSummary.AuditCount++ }
                            8022 { $eventData.EventType = 'Blocked'; $EventSummary.BlockedCount++ }
                            default { $eventData.EventType = 'Other' }
                        }

                        # Track counts by event ID
                        if (-not $EventSummary.ByEventId.ContainsKey($event.Id.ToString())) {
                            $EventSummary.ByEventId[$event.Id.ToString()] = 0
                        }
                        $EventSummary.ByEventId[$event.Id.ToString()]++

                        # Parse XML event data for detailed file information
                        try {
                            $xmlData = [xml]$event.ToXml()
                            $eventDataNode = $xmlData.Event.EventData

                            if ($eventDataNode -and $eventDataNode.Data) {
                                foreach ($dataItem in $eventDataNode.Data) {
                                    $name = $dataItem.Name
                                    $value = $dataItem.'#text'

                                    switch ($name) {
                                        'FilePath'    { $eventData.FilePath = $value }
                                        'FileHash'    { $eventData.FileHash = $value }
                                        'Fqbn'        {
                                            # Fully Qualified Binary Name contains publisher info
                                            # Format: O=Publisher, L=Location, S=State, C=Country\ProductName\FileName\Version
                                            if ($value -match '^O=([^\\,]+)') {
                                                $eventData.Publisher = $matches[1]
                                            }
                                            if ($value -match '\\([^\\]+)\\([^\\]+)\\') {
                                                $eventData.ProductName = $matches[1]
                                                $eventData.FileName = $matches[2]
                                            }
                                        }
                                        'UserSid'     { $eventData.UserSid = $value }
                                        'PolicyName'  { $eventData.PolicyName = $value }
                                        'RuleName'    { $eventData.RuleName = $value }
                                        'RuleSddl'    { $eventData.RuleSddl = $value }
                                    }
                                }
                            }

                            # Extract file name from path if not already set
                            if (-not $eventData.FileName -and $eventData.FilePath) {
                                $eventData.FileName = Split-Path -Path $eventData.FilePath -Leaf
                            }
                        }
                        catch {
                            # XML parsing failed, continue with message-based extraction
                        }

                        # Fallback: Extract file path from message if XML parsing failed
                        if (-not $eventData.FilePath -and $event.Message) {
                            # Common patterns in AppLocker event messages
                            if ($event.Message -match '([A-Z]:\\[^\s]+\.(exe|dll|msi|ps1|bat|cmd|vbs|js))') {
                                $eventData.FilePath = $matches[1]
                                $eventData.FileName = Split-Path -Path $matches[1] -Leaf
                            }
                        }

                        $AllEvents += $eventData
                        $EventSummary.TotalEvents++
                    }
                }
            }
            catch {
                # Log not available or no events, continue to next log
            }
        }

        $Result.Events = $AllEvents
        $Result.EventSummary = $EventSummary

        # ----------------------------
        # GENERATE ARTIFACTS FOR RULE GENERATOR
        # Convert events to artifact format compatible with New-RulesFromArtifacts
        # ----------------------------
        $Artifacts = @()
        $SeenPaths = @{}
        $SeenPublishers = @{}

        foreach ($event in $AllEvents) {
            # Skip events without file path
            if (-not $event.FilePath) {
                continue
            }

            # Deduplicate by path
            if ($SeenPaths.ContainsKey($event.FilePath)) {
                continue
            }
            $SeenPaths[$event.FilePath] = $true

            # Create artifact in format expected by Module3-RuleGenerator
            $artifact = @{
                name           = $event.FileName
                path           = $event.FilePath
                publisher      = if ($event.Publisher) { $event.Publisher } else { 'Unknown' }
                hash           = $event.FileHash
                productName    = $event.ProductName
                eventType      = $event.EventType
                eventId        = $event.EventId
                sourceComputer = $env:COMPUTERNAME
                lastSeen       = $event.TimeCreated
            }

            $Artifacts += $artifact

            # Track unique publishers
            if ($artifact.publisher -and $artifact.publisher -ne 'Unknown') {
                if (-not $SeenPublishers.ContainsKey($artifact.publisher)) {
                    $SeenPublishers[$artifact.publisher] = @{
                        count = 0
                        files = @()
                    }
                }
                $SeenPublishers[$artifact.publisher].count++
                $SeenPublishers[$artifact.publisher].files += $artifact.name
            }
        }

        $Result.Artifacts = $Artifacts
        $Result.ArtifactCount = $Artifacts.Count

        # Publisher summary for easy review
        $PublisherSummary = @()
        foreach ($pub in $SeenPublishers.Keys) {
            $PublisherSummary += @{
                publisher = $pub
                fileCount = $SeenPublishers[$pub].count
                files     = $SeenPublishers[$pub].files | Select-Object -Unique
            }
        }
        $Result.PublisherSummary = $PublisherSummary | Sort-Object { $_.fileCount } -Descending

        return [PSCustomObject]$Result
    }

    try {
        # Execute remote scan with appropriate credentials
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $scanScript
            ArgumentList = @($DaysBack, $MaxEvents, $IncludePolicyXml.IsPresent)
            ErrorAction  = 'Stop'
        }

        if ($Credential) {
            $invokeParams.Credential = $Credential
        }

        $remoteResult = Invoke-Command @invokeParams

        # Convert result to hashtable for consistent return format
        $result = @{
            success          = $true
            computerName     = $ComputerName
            timestamp        = $remoteResult.timestamp
            system           = $remoteResult.System
            appIdSvc         = $remoteResult.AppIDSvc
            policyMode       = $remoteResult.PolicyMode
            ruleCounts       = $remoteResult.RuleCounts
            hasPolicy        = $remoteResult.HasPolicy
            eventSummary     = $remoteResult.EventSummary
            events           = $remoteResult.Events
            artifacts        = $remoteResult.Artifacts
            artifactCount    = $remoteResult.ArtifactCount
            publisherSummary = $remoteResult.PublisherSummary
            daysBack         = $DaysBack
        }

        # Include policy XML if requested
        if ($IncludePolicyXml -and $remoteResult.PolicyXml) {
            $result.policyXml = $remoteResult.PolicyXml
        }

        # Include any policy errors
        if ($remoteResult.PolicyError) {
            $result.policyError = $remoteResult.PolicyError
        }

        return $result
    }
    catch {
        return @{
            success      = $false
            computerName = $ComputerName
            error        = $_.Exception.Message
            errorType    = $_.Exception.GetType().Name
        }
    }
}

<#
.SYNOPSIS
    Get AppLocker Events from Multiple Computers
.DESCRIPTION
    Scans multiple remote computers for AppLocker event logs in parallel-style execution.
    Returns aggregated results with artifacts formatted for rule generation.
.PARAMETER ComputerNames
    Array of computer names to scan
.PARAMETER Credential
    Optional credentials for remote authentication
.PARAMETER DaysBack
    Number of days of event history to retrieve (default: 7)
.PARAMETER MaxEvents
    Maximum number of events to retrieve per log per computer (default: 500)
.PARAMETER ContinueOnError
    Continue scanning remaining computers if one fails (default: true)
.OUTPUTS
    Hashtable with aggregated results from all computers
.EXAMPLE
    $computers = @("WS01", "WS02", "WS03")
    $result = Get-RemoteAppLockerEventsMultiple -ComputerNames $computers -DaysBack 14
    # Get all unique artifacts across all computers
    $allArtifacts = $result.allArtifacts
#>
function Get-RemoteAppLockerEventsMultiple {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = 7,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 5000)]
        [int]$MaxEvents = 500,

        [Parameter(Mandatory = $false)]
        [bool]$ContinueOnError = $true
    )

    if (-not $ComputerNames -or $ComputerNames.Count -eq 0) {
        return @{
            success = $false
            error   = 'No computer names provided'
        }
    }

    $results = @{
        success        = $true
        timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        computerCount  = $ComputerNames.Count
        successCount   = 0
        failedCount    = 0
        computers      = @()
        failedComputers = @()
        allArtifacts   = @()
        allPublishers  = @{}
        eventSummary   = @{
            TotalEvents   = 0
            AllowedCount  = 0
            AuditCount    = 0
            BlockedCount  = 0
        }
    }

    # Scan each computer
    foreach ($computerName in $ComputerNames) {
        Write-Verbose "Scanning $computerName..."

        $scanParams = @{
            ComputerName = $computerName
            DaysBack     = $DaysBack
            MaxEvents    = $MaxEvents
        }

        if ($Credential) {
            $scanParams.Credential = $Credential
        }

        $scanResult = Get-RemoteAppLockerEvents @scanParams

        if ($scanResult.success) {
            $results.successCount++
            $results.computers += @{
                computerName   = $computerName
                system         = $scanResult.system
                hasPolicy      = $scanResult.hasPolicy
                policyMode     = $scanResult.policyMode
                artifactCount  = $scanResult.artifactCount
                eventSummary   = $scanResult.eventSummary
            }

            # Aggregate artifacts (add source computer to each)
            if ($scanResult.artifacts) {
                foreach ($artifact in $scanResult.artifacts) {
                    # Ensure source computer is set
                    if (-not $artifact.sourceComputer) {
                        $artifact.sourceComputer = $computerName
                    }
                    $results.allArtifacts += $artifact

                    # Track publishers across all computers
                    $pub = $artifact.publisher
                    if ($pub -and $pub -ne 'Unknown') {
                        if (-not $results.allPublishers.ContainsKey($pub)) {
                            $results.allPublishers[$pub] = @{
                                count     = 0
                                computers = @()
                                files     = @()
                            }
                        }
                        $results.allPublishers[$pub].count++
                        if ($results.allPublishers[$pub].computers -notcontains $computerName) {
                            $results.allPublishers[$pub].computers += $computerName
                        }
                        if ($results.allPublishers[$pub].files -notcontains $artifact.name) {
                            $results.allPublishers[$pub].files += $artifact.name
                        }
                    }
                }
            }

            # Aggregate event counts
            if ($scanResult.eventSummary) {
                $results.eventSummary.TotalEvents += $scanResult.eventSummary.TotalEvents
                $results.eventSummary.AllowedCount += $scanResult.eventSummary.AllowedCount
                $results.eventSummary.AuditCount += $scanResult.eventSummary.AuditCount
                $results.eventSummary.BlockedCount += $scanResult.eventSummary.BlockedCount
            }
        }
        else {
            $results.failedCount++
            $results.failedComputers += @{
                computerName = $computerName
                error        = $scanResult.error
            }

            if (-not $ContinueOnError) {
                $results.success = $false
                $results.error = "Scan failed for $computerName`: $($scanResult.error)"
                break
            }
        }
    }

    # Create deduplicated artifact list (by path)
    $seenPaths = @{}
    $uniqueArtifacts = @()
    foreach ($artifact in $results.allArtifacts) {
        $key = $artifact.path
        if (-not $seenPaths.ContainsKey($key)) {
            $seenPaths[$key] = $true
            $uniqueArtifacts += $artifact
        }
    }
    $results.uniqueArtifacts = $uniqueArtifacts
    $results.uniqueArtifactCount = $uniqueArtifacts.Count

    # Convert publisher hashtable to sorted array
    $publisherList = @()
    foreach ($pub in $results.allPublishers.Keys) {
        $publisherList += @{
            publisher     = $pub
            totalCount    = $results.allPublishers[$pub].count
            computerCount = $results.allPublishers[$pub].computers.Count
            computers     = $results.allPublishers[$pub].computers
            files         = $results.allPublishers[$pub].files
        }
    }
    $results.publisherSummary = $publisherList | Sort-Object { $_.totalCount } -Descending

    return $results
}

<#
.SYNOPSIS
    Convert AppLocker Events to Rule Generator Artifacts
.DESCRIPTION
    Filters and converts raw AppLocker event data to artifact format for rule generation.
    Allows filtering by event type (Audit, Blocked) to create targeted allow rules.
.PARAMETER Events
    Array of events from Get-RemoteAppLockerEvents
.PARAMETER IncludeEventTypes
    Array of event types to include: 'Audit', 'Blocked', 'Allowed' (default: Audit, Blocked)
.PARAMETER RequirePublisher
    Only include artifacts with known publisher (default: false)
.PARAMETER RequireHash
    Only include artifacts with file hash (default: false)
.OUTPUTS
    Array of artifacts formatted for New-RulesFromArtifacts
.EXAMPLE
    $events = (Get-RemoteAppLockerEvents -ComputerName "WS01").events
    $artifacts = ConvertTo-RuleGeneratorArtifacts -Events $events -IncludeEventTypes @('Audit', 'Blocked')
    $rules = New-RulesFromArtifacts -Artifacts $artifacts -RuleType Publisher -Action Allow
#>
function ConvertTo-RuleGeneratorArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Audit', 'Blocked', 'Allowed', 'Other')]
        [string[]]$IncludeEventTypes = @('Audit', 'Blocked'),

        [Parameter(Mandatory = $false)]
        [switch]$RequirePublisher,

        [Parameter(Mandatory = $false)]
        [switch]$RequireHash
    )

    if (-not $Events -or $Events.Count -eq 0) {
        return @()
    }

    $artifacts = @()
    $seenPaths = @{}

    foreach ($event in $Events) {
        # Filter by event type
        if ($IncludeEventTypes -and $event.EventType -notin $IncludeEventTypes) {
            continue
        }

        # Skip events without file path
        if (-not $event.FilePath) {
            continue
        }

        # Skip if publisher required but not available
        if ($RequirePublisher -and (-not $event.Publisher -or $event.Publisher -eq 'Unknown')) {
            continue
        }

        # Skip if hash required but not available
        if ($RequireHash -and -not $event.FileHash) {
            continue
        }

        # Deduplicate by path
        if ($seenPaths.ContainsKey($event.FilePath)) {
            continue
        }
        $seenPaths[$event.FilePath] = $true

        # Create artifact compatible with Module3-RuleGenerator
        $artifact = @{
            name        = $event.FileName
            path        = $event.FilePath
            publisher   = if ($event.Publisher) { $event.Publisher } else { 'Unknown' }
            hash        = $event.FileHash
            version     = $null
            productName = $event.ProductName
            eventType   = $event.EventType
            eventId     = $event.EventId
            lastSeen    = $event.TimeCreated
        }

        $artifacts += $artifact
    }

    return $artifacts
}

# Export functions
Export-ModuleMember -Function Get-DirectorySafetyClassification, Get-DirectoryFilesSafe,
                              Get-AllADComputers, Get-ComputersByOU, Test-ComputerOnline,
                              Get-ExecutableArtifacts, Get-RemoteArtifacts,
                              Export-ScanResults, Import-ScanResults,
                              Get-RemoteAppLockerEvents, Get-RemoteAppLockerEventsMultiple,
                              ConvertTo-RuleGeneratorArtifacts
