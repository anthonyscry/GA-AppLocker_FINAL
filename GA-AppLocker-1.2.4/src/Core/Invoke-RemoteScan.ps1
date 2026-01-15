<#
.SYNOPSIS
    Remotely collects AppLocker data from target computers for policy creation.

.DESCRIPTION
    Part of GA-AppLocker toolkit. Use Start-AppLockerWorkflow.ps1 for guided experience.

    This script connects to remote computers via WinRM (Windows Remote Management) and
    collects comprehensive data needed for AppLocker policy creation:

    Data Collected:
    - Current AppLocker policy (if any) - exported as XML
    - Installed software from registry (both 32-bit and 64-bit)
    - Signed executables with publisher information (for publisher rules)
    - User-writable directories (critical for security - deny rules)
    - Running processes and their paths (shows what's actively executing)
    - System information (OS version, architecture, domain)

    This data is consumed by New-AppLockerPolicy.ps1 to create comprehensive policies.

    Key Features:
    - Modernized for Windows 11/Server 2019+ (no AccessChk.exe dependency)
    - Uses native PowerShell ACL inspection for writable directory detection
    - Parallel processing with configurable throttle limit
    - Extracts publisher info from Authenticode signatures
    - Calculates SHA256 hashes for hash-based rules

    Authentication Note:
    - Uses '-Authentication Default' to work around environments with
      $PSDefaultParameterValues["*:Authentication"] = "None" set in profiles
    - Jobs explicitly remove this default at start of script block

.PARAMETER ComputerListPath
    Path to a file containing computer names. Supports two formats:
    - CSV: Must have a 'ComputerName' column header
    - TXT: One computer name per line (lines starting with # are comments)

.PARAMETER SharePath
    UNC path (or local path) to save collected results.
    A timestamped subfolder will be created automatically.

.PARAMETER Credential
    Credential for remote connections (DOMAIN\username format).
    If not provided, prompts interactively.

.PARAMETER ThrottleLimit
    Maximum concurrent connections (default: 10).
    Increase for faster scans, decrease if overwhelming the network.

.PARAMETER ScanPaths
    Additional paths to scan for executables beyond the defaults.
    Default paths: Program Files, Windows\System32, Windows\SysWOW64

.PARAMETER ScanUserProfiles
    Also scan user profile directories (AppData, Desktop, Downloads).
    Important for finding user-installed applications.

.PARAMETER SkipWritableDirectoryScan
    Skip the scan for user-writable directories.
    Faster but misses critical security information.

.EXAMPLE
    # Basic scan using CSV computer list
    .\Invoke-RemoteScan.ps1 -ComputerListPath .\ADManagement\computers.csv -SharePath \\server\share\Scans

.EXAMPLE
    # Include user profile scanning for more thorough results
    .\Invoke-RemoteScan.ps1 -ComputerListPath .\ADManagement\computers.csv -SharePath \\server\share\Scans -ScanUserProfiles

.EXAMPLE
    # Fast scan skipping writable directory detection
    .\Invoke-RemoteScan.ps1 -ComputerListPath .\ADManagement\computers.csv -SharePath .\LocalScans -SkipWritableDirectoryScan

.NOTES
    Requires: PowerShell 5.1+
    Requires: WinRM enabled on target computers (Enable-PSRemoting)
    Requires: Admin credentials with remote access to targets
    Requires: Firewall allowing WinRM (TCP 5985/5986)

    Output Structure:
    ├── Scan-{timestamp}/
    │   ├── ScanResults.csv          (summary log)
    │   ├── COMPUTER1/
    │   │   ├── AppLockerPolicy.xml  (current policy if any)
    │   │   ├── InstalledSoftware.csv
    │   │   ├── Executables.csv      (with signature info)
    │   │   ├── Publishers.csv       (unique publishers found)
    │   │   ├── WritableDirectories.csv
    │   │   ├── RunningProcesses.csv
    │   │   └── SystemInfo.csv
    │   └── COMPUTER2/
    │       └── ...

    Author: AaronLocker Simplified Scripts
    Version: 2.0 (Windows 11/Server 2019+ compatible)

.LINK
    New-AppLockerPolicy.ps1 - Creates policies from this scan data
    Merge-AppLockerPolicies.ps1 - Merges multiple policies together
#>

[CmdletBinding(DefaultParameterSetName='Standard')]
param(
    [Parameter(Mandatory=$true, Position=0, ParameterSetName='Standard',
        HelpMessage="Path to file containing computer names (TXT or CSV with ComputerName column)")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
            throw "Computer list file not found: $_"
        }
        $ext = [System.IO.Path]::GetExtension($_).ToLower()
        if ($ext -notin '.txt', '.csv') {
            throw "Computer list must be a .txt or .csv file"
        }
        $true
    })]
    [string]$ComputerListPath,

    [Parameter(Mandatory=$true, Position=1, ParameterSetName='Standard',
        HelpMessage="Path to save scan results (local or UNC path)")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        # Allow path to be created if parent exists
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Parent directory does not exist: $parent"
        }
        $true
    })]
    [Alias("OutputPath")]
    [string]$SharePath,

    [Parameter(ParameterSetName='Standard',
        HelpMessage="Credentials for remote connections (DOMAIN\username)")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential,

    [Parameter(ParameterSetName='Standard',
        HelpMessage="Separate credentials for Domain Controllers (DOMAIN\username)")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DCCredential,

    [Parameter(ParameterSetName='Standard',
        HelpMessage="Maximum concurrent remote connections (1-100)")]
    [ValidateRange(1, 100)]
    [int]$ThrottleLimit = 10,

    [Parameter(ParameterSetName='Standard',
        HelpMessage="Additional paths to scan for executables")]
    [string[]]$ScanPaths = @(),

    [Parameter(ParameterSetName='Standard',
        HelpMessage="Include user profile directories in scan")]
    [switch]$ScanUserProfiles,

    [Parameter(ParameterSetName='Standard',
        HelpMessage="Skip user-writable directory detection")]
    [switch]$SkipWritableDirectoryScan
)

#Requires -Version 5.1

# Import utilities module
$scriptRoot = $PSScriptRoot
$utilitiesRoot = Join-Path (Split-Path -Parent $scriptRoot) "Utilities"
$modulePath = Join-Path $utilitiesRoot "Common.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    Write-Warning "Common.psm1 not found at $modulePath - some features may be limited"
}

# Initialize logging
if (Get-Command Start-Logging -ErrorAction SilentlyContinue) {
    Start-Logging -LogName "RemoteScan"
    Write-Log "Remote scan operation started" -Level Info
    Write-Log "Computer list: $ComputerListPath" -Level Info
    Write-Log "Output path: $SharePath" -Level Info
}

# Note: Path validation is now handled by ValidateScript in parameter declaration

# Create output directory (use absolute path so jobs can find it)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputRoot = Join-Path $SharePath "Scan-$timestamp"
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
# Convert to absolute path - jobs run in different working directory
$outputRoot = (Resolve-Path $outputRoot).Path

# Get credentials if not provided
if ($null -eq $Credential) {
    try {
        $Credential = Get-Credential -Message "Enter credentials for remote connections (DOMAIN\username)"
    }
    catch {
        $errorMsg = "Failed to prompt for credentials: $_"
        if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
        throw $errorMsg
    }
}

# Validate credentials were provided (user may have cancelled the dialog)
if ($null -eq $Credential) {
    $errorMsg = "Credentials are required for remote scanning. Operation cancelled."
    if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
    throw $errorMsg
}

if (Test-LoggingEnabled) {
    Write-Log "Credentials provided for user: $($Credential.UserName)" -Level Info
}

# Load computer list - uses Get-ComputerList from Common.psm1 (supports TXT and CSV)
try {
    if (Get-Command Get-ComputerList -ErrorAction SilentlyContinue) {
        $computers = @(Get-ComputerList -Path $ComputerListPath)
    }
    else {
        # Fallback for standalone usage
        $extension = [System.IO.Path]::GetExtension($ComputerListPath).ToLower()
        if ($extension -eq ".csv") {
            $csv = Import-Csv -Path $ComputerListPath
            $computers = @($csv | Where-Object { $_.ComputerName } | ForEach-Object { $_.ComputerName.Trim() })
        }
        else {
            $computers = @(Get-Content -Path $ComputerListPath |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith("#") } |
                ForEach-Object { $_.Trim() })
        }
    }
}
catch {
    $errorMsg = "Failed to load computer list: $_"
    if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
    throw $errorMsg
}

if ($computers.Count -eq 0) {
    $errorMsg = "No computers found in $ComputerListPath"
    if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
    throw $errorMsg
}

if (Test-LoggingEnabled) {
    Write-Log "Loaded $($computers.Count) computers from list" -Level Info
    Write-LogSection "Target Computers"
    foreach ($comp in $computers) {
        Write-Log "  - $comp" -Level Debug
    }
}

# Display banner
if (Get-Command Write-Banner -ErrorAction SilentlyContinue) {
    Write-Banner -Title "GA-AppLocker Remote Scanner" -Subtitle "Scanning $($computers.Count) computers"
} else {
    Write-Host "=== GA-AppLocker Remote Scanner ===" -ForegroundColor Cyan
    Write-Host "Scanning $($computers.Count) computers..." -ForegroundColor Cyan
    Write-Host ""
}
Write-Host "Results will be saved to: $outputRoot" -ForegroundColor Gray

# Results collection
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Clean up any leftover jobs from previous runs
$oldJobs = Get-Job -Name "Scan-*" -ErrorAction SilentlyContinue
if ($oldJobs) {
    Write-Host "Cleaning up $($oldJobs.Count) leftover jobs from previous runs..." -ForegroundColor Yellow
    $oldJobs | Remove-Job -Force -ErrorAction SilentlyContinue
}

# Process each computer
$jobCount = 0

# Extract credential components to pass through job (PSCredential doesn't serialize properly in Start-Job)
$credUsername = $Credential.UserName
$credPassword = $Credential.Password

# Extract DC credential components if provided
$dcCredUsername = if ($DCCredential) { $DCCredential.UserName } else { $null }
$dcCredPassword = if ($DCCredential) { $DCCredential.Password } else { $null }

# Try to identify Domain Controllers from AD if available
$domainControllers = @()
try {
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        $domainControllers = @((Get-ADDomainController -Filter *).HostName)
        if ($domainControllers.Count -gt 0) {
            Write-Host "Detected $($domainControllers.Count) Domain Controller(s)" -ForegroundColor Cyan
            if ($DCCredential) {
                Write-Host "DC credentials will be used for: $($domainControllers -join ', ')" -ForegroundColor Cyan
            }
        }
    }
}
catch {
    # AD module not available or not domain joined - continue without DC detection
}

# Clear any default parameter values that might interfere with Start-Job
# (some environments set $PSDefaultParameterValues that cause parameter set conflicts)
$savedDefaults = @{}
foreach ($key in $PSDefaultParameterValues.Keys) {
    $savedDefaults[$key] = $PSDefaultParameterValues[$key]
}
$PSDefaultParameterValues.Clear()

# Prepare ScanPaths for ArgumentList - convert to JSON string to avoid array flattening issues
$scanPathsJson = if ($ScanPaths -and $ScanPaths.Count -gt 0) { $ScanPaths | ConvertTo-Json -Compress } else { "[]" }

foreach ($computer in $computers) {
    $jobCount++

    # Determine if this computer is a Domain Controller and select appropriate credentials
    $isDC = $domainControllers | Where-Object { $_ -eq $computer -or $_ -like "$computer.*" }
    $useUsername = $credUsername
    $usePassword = $credPassword

    if ($isDC -and $dcCredUsername -and $dcCredPassword) {
        $useUsername = $dcCredUsername
        $usePassword = $dcCredPassword
        Write-Host "[$jobCount/$($computers.Count)] Starting (DC): $computer" -ForegroundColor Magenta
    }
    else {
        Write-Host "[$jobCount/$($computers.Count)] Starting: $computer" -ForegroundColor Gray
    }

    # Start job for this computer
    # Note: Pass username and SecureString password separately, then reconstruct credential inside job
    # ScanPaths is passed as JSON to avoid array flattening issues with ArgumentList
    Start-Job -Name "Scan-$computer" -ArgumentList $computer, $useUsername, $usePassword, $outputRoot, $scanPathsJson, $ScanUserProfiles.IsPresent, $SkipWritableDirectoryScan.IsPresent -ScriptBlock {
        param($Computer, $UserName, $SecurePass, $OutputRoot, $ExtraScanPathsJson, $ScanUserProfiles, $SkipWritableScan)

        # Reconstruct the credential from username and SecureString password
        $Credential = New-Object System.Management.Automation.PSCredential($UserName, $SecurePass)

        # Parse ScanPaths from JSON
        $ExtraScanPaths = @()
        if ($ExtraScanPathsJson -and $ExtraScanPathsJson -ne "[]") {
            try {
                $parsed = $ExtraScanPathsJson | ConvertFrom-Json
                if ($parsed) {
                    $ExtraScanPaths = @($parsed)
                }
            }
            catch {
                # JSON parsing failed - continue with empty extra paths
                $ExtraScanPaths = @()
            }
        }

        # Clear any problematic defaults that could cause parameter binding issues
        $PSDefaultParameterValues.Clear()

        $start = Get-Date
        $result = [PSCustomObject]@{
            Computer = $Computer
            Status = "Failed"
            Message = ""
            StartTime = $start
            EndTime = $null
            ExeCount = 0
            SignedCount = 0
            WritableDirCount = 0
        }

        try {
            # Test connectivity and create session
            $session = New-PSSession -ComputerName $Computer -Credential $Credential -Authentication Default -ErrorAction Stop

            # Create output folder for this computer
            $computerFolder = Join-Path $OutputRoot $Computer
            New-Item -ItemType Directory -Path $computerFolder -Force | Out-Null

            #region 1. Export current AppLocker policy
            $policyXml = Invoke-Command -Session $session -ScriptBlock {
                try {
                    Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
                }
                catch { $null }
            }

            if ($null -ne $policyXml -and $policyXml.Length -gt 0) {
                $policyXml | Out-File -FilePath (Join-Path $computerFolder "AppLockerPolicy.xml") -Encoding UTF8
            }
            #endregion

            #region 2. Collect installed software from registry
            $software = Invoke-Command -Session $session -ScriptBlock {
                $paths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName } |
                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
                    Sort-Object DisplayName
            }

            if ($null -ne $software -and $software.Count -gt 0) {
                $software | Export-Csv -Path (Join-Path $computerFolder "InstalledSoftware.csv") -NoTypeInformation
            }
            #endregion

            #region 3. Scan for executables and extract publisher info
            $exeData = Invoke-Command -Session $session -ArgumentList $ExtraScanPaths, $ScanUserProfiles -ScriptBlock {
                param($ExtraPaths, $IncludeUserProfiles)

                $scanPaths = @(
                    $env:ProgramFiles,
                    ${env:ProgramFiles(x86)},
                    "$env:SystemRoot\System32",
                    "$env:SystemRoot\SysWOW64"
                )

                # Add user profiles if requested
                if ($IncludeUserProfiles) {
                    $scanPaths += "$env:SystemDrive\Users\*\AppData\Local\Programs"
                    $scanPaths += "$env:SystemDrive\Users\*\AppData\Local\Microsoft"
                    $scanPaths += "$env:SystemDrive\Users\*\Desktop"
                    $scanPaths += "$env:SystemDrive\Users\*\Downloads"
                }

                # Add any extra paths
                if ($ExtraPaths) {
                    $scanPaths += $ExtraPaths
                }

                $executables = @()
                $extensions = @("*.exe", "*.dll", "*.msi", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js")

                # Scan limits - matches Config.psd1 ScanLimits section
                # Note: Hardcoded here because remote scriptblocks can't access local Config.psd1
                # To change this limit, update both here AND in Config.psd1 ScanLimits.MaxFilesPerPath
                $maxFilesPerPath = 5000

                foreach ($basePath in $scanPaths) {
                    if (!(Test-Path $basePath -ErrorAction SilentlyContinue)) { continue }

                    foreach ($ext in $extensions) {
                        try {
                            $files = Get-ChildItem -Path $basePath -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                                Select-Object -First $maxFilesPerPath  # Limit per path to avoid timeout

                            foreach ($file in $files) {
                                try {
                                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue

                                    $executables += [PSCustomObject]@{
                                        Path = $file.FullName
                                        Name = $file.Name
                                        Extension = $file.Extension
                                        Size = $file.Length
                                        LastWriteTime = $file.LastWriteTime
                                        IsSigned = ($sig.Status -eq "Valid")
                                        SignerCertificate = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                                        Publisher = if ($sig.SignerCertificate) {
                                            # Extract O= from certificate subject
                                            if ($sig.SignerCertificate.Subject -match "O=([^,]+)") {
                                                $matches[1].Trim('"')
                                            } else { "" }
                                        } else { "" }
                                        Hash = try {
                                            (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                                        } catch { "" }
                                    }
                                }
                                catch {
                                    # Skip files that cannot be processed (locked, permissions, etc.)
                                    continue
                                }
                            }
                        }
                        catch {
                            # Skip extensions that fail to enumerate (access denied, etc.)
                            continue
                        }
                    }
                }

                return $executables
            }

            # Use @() to ensure consistent array behavior for .Count
            $exeCount = @($exeData).Count
            if ($null -ne $exeData -and $exeCount -gt 0) {
                $exeData | Export-Csv -Path (Join-Path $computerFolder "Executables.csv") -NoTypeInformation
                $result.ExeCount = $exeCount
                $result.SignedCount = @($exeData | Where-Object { $_.IsSigned }).Count

                # Also create a summary of unique publishers
                $publishers = $exeData |
                    Where-Object { $_.Publisher -and $_.IsSigned } |
                    Group-Object Publisher |
                    Select-Object @{N="Publisher";E={$_.Name}}, Count |
                    Sort-Object Count -Descending

                if (@($publishers).Count -gt 0) {
                    $publishers | Export-Csv -Path (Join-Path $computerFolder "Publishers.csv") -NoTypeInformation
                }
            }
            #endregion

            #region 4. Scan for user-writable directories (core AaronLocker functionality)
            if (-not $SkipWritableScan) {
                $writableDirs = Invoke-Command -Session $session -ScriptBlock {
                    $writable = @()
                    $checkPaths = @(
                        "$env:SystemRoot",
                        $env:ProgramFiles,
                        ${env:ProgramFiles(x86)}
                    )

                    # Scan limits - matches Config.psd1 ScanLimits section
                    # Note: Hardcoded here because remote scriptblocks can't access local Config.psd1
                    # To change this limit, update both here AND in Config.psd1 ScanLimits.MaxDirectoriesPerPath
                    $maxDirectoriesPerPath = 2000

                    # Get current user's SID for comparison
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $userSid = $currentUser.User.Value

                    # Well-known SIDs for non-admin groups
                    $nonAdminSids = @(
                        "S-1-1-0",        # Everyone
                        "S-1-5-11",       # Authenticated Users
                        "S-1-5-32-545",   # Users
                        $userSid
                    )

                    foreach ($basePath in $checkPaths) {
                        if (!(Test-Path $basePath)) { continue }

                        try {
                            $dirs = Get-ChildItem -Path $basePath -Directory -Recurse -ErrorAction SilentlyContinue -Force |
                                Select-Object -First $maxDirectoriesPerPath  # Limit to avoid timeout

                            foreach ($dir in $dirs) {
                                try {
                                    $acl = Get-Acl -Path $dir.FullName -ErrorAction SilentlyContinue
                                    if ($null -eq $acl) { continue }

                                    foreach ($ace in $acl.Access) {
                                        # Check if non-admin has write access
                                        $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

                                        if ($nonAdminSids -contains $sid) {
                                            $rights = $ace.FileSystemRights.ToString()
                                            if ($rights -match "Write|Modify|FullControl|CreateFiles") {
                                                $writable += [PSCustomObject]@{
                                                    Path = $dir.FullName
                                                    Identity = $ace.IdentityReference.Value
                                                    Rights = $rights
                                                    AccessType = $ace.AccessControlType.ToString()
                                                }
                                                break  # Found writable, move to next dir
                                            }
                                        }
                                    }
                                }
                                catch {
                                    # Skip directories where ACL cannot be read (access denied, etc.)
                                    continue
                                }
                            }
                        }
                        catch {
                            # Skip base paths that fail to enumerate
                            continue
                        }
                    }

                    return $writable
                }

                $writableDirCount = @($writableDirs).Count
                if ($null -ne $writableDirs -and $writableDirCount -gt 0) {
                    $writableDirs | Export-Csv -Path (Join-Path $computerFolder "WritableDirectories.csv") -NoTypeInformation
                    $result.WritableDirCount = $writableDirCount
                }
            }
            #endregion

            #region 5. Get OS and system info
            $osInfo = Invoke-Command -Session $session -ScriptBlock {
                try {
                    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        OSName = if ($os) { $os.Caption } else { "Unknown" }
                        OSVersion = if ($os) { $os.Version } else { "Unknown" }
                        OSBuild = if ($os) { $os.BuildNumber } else { "Unknown" }
                        Architecture = if ($os) { $os.OSArchitecture } else { "Unknown" }
                        Domain = if ($cs) { $cs.Domain } else { "Unknown" }
                        Manufacturer = if ($cs) { $cs.Manufacturer } else { "Unknown" }
                        Model = if ($cs) { $cs.Model } else { "Unknown" }
                        TotalMemoryGB = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }
                    }
                }
                catch {
                    [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        OSName = "Error"
                        OSVersion = "Error"
                        OSBuild = "Error"
                        Architecture = "Error"
                        Domain = "Error"
                        Manufacturer = "Error"
                        Model = "Error"
                        TotalMemoryGB = 0
                    }
                }
            }

            if ($null -ne $osInfo) {
                $osInfo | Export-Csv -Path (Join-Path $computerFolder "SystemInfo.csv") -NoTypeInformation
            }
            #endregion

            #region 6. Get running processes (to see what's actually executing)
            $processes = Invoke-Command -Session $session -ScriptBlock {
                try {
                    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } |
                        Select-Object Name, Path, Company, ProductVersion, Description |
                        Sort-Object Path -Unique
                }
                catch { @() }
            }

            if ($null -ne $processes -and @($processes).Count -gt 0) {
                $processes | Export-Csv -Path (Join-Path $computerFolder "RunningProcesses.csv") -NoTypeInformation
            }
            #endregion

            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            $result.Status = "Success"
        }
        catch {
            $result.Message = $_.Exception.Message
            # Clean up session if it exists
            if ($null -ne $session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        }
        finally {
            $result.EndTime = Get-Date
        }

        return $result
    } -ErrorAction SilentlyContinue | Out-Null

    # Throttle: wait if we have too many jobs (only count our scan jobs)
    $runningJobs = Get-Job -Name "Scan-*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    while ($runningJobs.Count -ge $ThrottleLimit) {
        Start-Sleep -Seconds 2
        $runningJobs = Get-Job -Name "Scan-*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    }
}

# Restore default parameter values
if ($null -ne $savedDefaults) {
    foreach ($key in $savedDefaults.Keys) {
        $PSDefaultParameterValues[$key] = $savedDefaults[$key]
    }
}

# Wait for all jobs to complete
Write-Host "`nWaiting for scans to complete..." -ForegroundColor Yellow
Write-Host "  (This can take 10-30+ minutes per computer)" -ForegroundColor Gray

$allJobs = Get-Job -Name "Scan-*" -ErrorAction SilentlyContinue
$completedCount = 0
$spinChars = @('|', '/', '-', '\')
$spinIndex = 0
$startWait = Get-Date

# Note: Get-Job doesn't allow -Name and -State together in some PS versions
# So we get by name and filter with Where-Object
while (($allJobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
    $runningCount = ($allJobs | Where-Object { $_.State -eq 'Running' }).Count
    $newCompleted = ($allJobs | Where-Object { $_.State -eq 'Completed' }).Count
    $elapsed = [math]::Round(((Get-Date) - $startWait).TotalMinutes, 1)

    # Show spinner and status
    $spin = $spinChars[$spinIndex % 4]
    Write-Host "`r  [$spin] Running: $runningCount | Completed: $newCompleted / $($computers.Count) | Elapsed: $elapsed min   " -NoNewline -ForegroundColor Cyan
    $spinIndex++

    if ($newCompleted -gt $completedCount) {
        $completedCount = $newCompleted
        Write-Host ""  # New line when something completes
        Write-Host "  Completed: $completedCount / $($computers.Count)" -ForegroundColor Green
    }
    Start-Sleep -Seconds 3
    # Refresh job list to get updated states
    $allJobs = Get-Job -Name "Scan-*" -ErrorAction SilentlyContinue
}
Write-Host ""  # Final newline after spinner

# Collect results - use SilentlyContinue to prevent job errors from propagating
if ($null -ne $allJobs -and $allJobs.Count -gt 0) {
    foreach ($job in $allJobs) {
        $computerName = $job.Name -replace '^Scan-', ''
        try {
            # Check job state first
            if ($job.State -eq 'Failed') {
                # Job itself failed (not just the scriptblock) - extract detailed error info
                $errorMsg = if ($job.ChildJobs -and $job.ChildJobs[0].JobStateInfo.Reason) {
                    "Remote job failed: $($job.ChildJobs[0].JobStateInfo.Reason.Message)"
                } elseif ($job.JobStateInfo.Reason) {
                    "Job execution failed: $($job.JobStateInfo.Reason.Message)"
                } else {
                    "Job failed to execute (no error details available - check WinRM connectivity)"
                }
                $results.Add([PSCustomObject]@{
                    Computer = $computerName
                    Status = "Failed"
                    Message = $errorMsg
                    StartTime = $null
                    EndTime = Get-Date
                    ExeCount = 0
                    SignedCount = 0
                    WritableDirCount = 0
                })
            }
            else {
                $jobResult = Receive-Job -Job $job -ErrorAction SilentlyContinue
                if ($null -ne $jobResult) {
                    $results.Add($jobResult)
                } else {
                    # Job returned no result - create a failure entry
                    $results.Add([PSCustomObject]@{
                        Computer = $computerName
                        Status = "Failed"
                        Message = "Job completed but returned no result"
                        StartTime = $null
                        EndTime = Get-Date
                        ExeCount = 0
                        SignedCount = 0
                        WritableDirCount = 0
                    })
                }
            }
        }
        catch {
            # If we couldn't receive the job result, create a failure entry
            $results.Add([PSCustomObject]@{
                Computer = $computerName
                Status = "Failed"
                Message = $_.Exception.Message
                StartTime = $null
                EndTime = Get-Date
                ExeCount = 0
                SignedCount = 0
                WritableDirCount = 0
            })
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

# Export results log
$logPath = Join-Path $outputRoot "ScanResults.csv"
try {
    $results | Export-Csv -Path $logPath -NoTypeInformation -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Warning: Could not write results log: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Summary
$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Failed" }).Count
$totalExes = ($results | Measure-Object -Property ExeCount -Sum).Sum
$totalSigned = ($results | Measure-Object -Property SignedCount -Sum).Sum
$totalWritable = ($results | Measure-Object -Property WritableDirCount -Sum).Sum

Write-Host "`n=== Scan Complete ===" -ForegroundColor Green
Write-Host "Computers scanned: $($results.Count)" -ForegroundColor Cyan
Write-Host "  Success: $successCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Data collected:" -ForegroundColor Cyan
Write-Host "  Executables found: $totalExes" -ForegroundColor Gray
Write-Host "  Signed executables: $totalSigned" -ForegroundColor Gray
Write-Host "  Writable directories: $totalWritable" -ForegroundColor Gray
Write-Host ""
Write-Host "Results saved to: $outputRoot" -ForegroundColor Cyan
Write-Host "Log file: $logPath" -ForegroundColor Cyan

# Show failures
$failures = $results | Where-Object { $_.Status -eq "Failed" }
if ($failures.Count -gt 0) {
    Write-Host "`nFailed computers:" -ForegroundColor Yellow
    foreach ($f in $failures) {
        Write-Host "  $($f.Computer): $($f.Message)" -ForegroundColor Red
    }
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Review Publishers.csv files to see what software is signed" -ForegroundColor White
Write-Host "  2. Review WritableDirectories.csv for security concerns" -ForegroundColor White
Write-Host "  3. Run: .\Merge-AppLockerPolicies.ps1 -InputPath '$outputRoot'" -ForegroundColor White

# Finalize logging
if (Test-LoggingEnabled) {
    Write-LogSection "Scan Summary"
    Write-Log "Computers scanned: $($results.Count)" -Level Info
    Write-Log "Success: $successCount" -Level Success
    Write-Log "Failed: $failCount" -Level $(if ($failCount -gt 0) { "Warning" } else { "Info" })
    Write-Log "Executables found: $totalExes" -Level Info
    Write-Log "Signed executables: $totalSigned" -Level Info
    Write-Log "Writable directories: $totalWritable" -Level Info
    Write-Log "Output path: $outputRoot" -Level Info

    # Log results with per-computer details
    Write-LogResults -Results $results

    $logFile = Stop-Logging -Summary "Scanned $($results.Count) computers, $successCount successful, $failCount failed"
    Write-Host "Log file: $logFile" -ForegroundColor Gray
}
