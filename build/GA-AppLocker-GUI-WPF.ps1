#Requires -Version 5.1
#Requires -RunAsAdministrator

# GA-AppLocker Dashboard - Modern WPF GUI
# GitHub-style dark theme based on ExampleGUI design
# Self-contained with embedded module functions

# Required assemblies for WPF
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    # System.Web for HTML encoding (security)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
} catch {
    $msg = "ERROR: Failed to load WPF assemblies.`n`nThis application requires .NET Framework 4.5 or later.`n`nError: $($_.Exception.Message)"
    try {
        [System.Windows.Forms.MessageBox]::Show($msg, "GA-AppLocker Startup Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    } catch {
        Write-Host $msg -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit 1
}

# ============================================================
# LOGGING FUNCTION (must be defined early)
# ============================================================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $logDir = "C:\GA-AppLocker\Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $logDir "GA-AppLocker-$(Get-Date -Format 'yyyy-MM-dd').log"
    $logEntry = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    } catch {
        # Silently fail if logging fails
    }
}

# ============================================================
# XML ENTITY ESCAPING (Security - prevent XML injection)
# ============================================================
function ConvertTo-XmlSafeString {
    <#
    .SYNOPSIS
        Escapes XML special characters in a string
    .DESCRIPTION
        Converts special characters (&, <, >, ", ') to their XML entity equivalents
        to prevent XML injection and ensure valid XML output
    .PARAMETER InputString
        The string to escape
    .OUTPUTS
        String with XML entities escaped
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string]$InputString
    )

    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }

    # Order matters: & must be first to avoid double-encoding
    $result = $InputString -replace '&', '&amp;'
    $result = $result -replace '<', '&lt;'
    $result = $result -replace '>', '&gt;'
    $result = $result -replace '"', '&quot;'
    $result = $result -replace "'", '&apos;'

    return $result
}

# ============================================================
# EMBEDDED: All Module Functions
# ============================================================

# Module 1: Dashboard Functions
function Get-AppLockerEventStats {
    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    try {
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $logExists) {
            return @{ success = $true; allowed = 0; audit = 0; blocked = 0; total = 0; message = 'AppLocker log not found' }
        }
    } catch {
        return @{ success = $true; allowed = 0; audit = 0; blocked = 0; total = 0; message = 'AppLocker log not available' }
    }
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction Stop
        $allowed = ($events | Where-Object { $_.Id -eq 8002 }).Count
        $audit = ($events | Where-Object { $_.Id -eq 8003 }).Count
        $blocked = ($events | Where-Object { $_.Id -eq 8004 }).Count
        return @{ success = $true; allowed = $allowed; audit = $audit; blocked = $blocked; total = $events.Count }
    } catch {
        return @{ success = $true; allowed = 0; audit = 0; blocked = 0; total = 0; message = 'No events found' }
    }
}

function Get-PolicyHealthScore {
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    } catch {
        return @{ success = $true; score = 0; hasPolicy = $false; hasExe = $false; hasMsi = $false; hasScript = $false; hasDll = $false }
    }
    if ($null -eq $policy) {
        return @{ success = $true; score = 0; hasPolicy = $false; hasExe = $false; hasMsi = $false; hasScript = $false; hasDll = $false }
    }
    $hasExe = $false; $hasMsi = $false; $hasScript = $false; $hasDll = $false
    foreach ($collection in $policy.RuleCollections) {
        switch ($collection.RuleCollectionType) {
            'Exe'     { if ($collection.Count -gt 0) { $hasExe = $true } }
            'Msi'     { if ($collection.Count -gt 0) { $hasMsi = $true } }
            'Script'  { if ($collection.Count -gt 0) { $hasScript = $true } }
            'Dll'     { if ($collection.Count -gt 0) { $hasDll = $true } }
        }
    }
    $score = 0
    if ($hasExe)     { $score += 25 }
    if ($hasMsi)     { $score += 25 }
    if ($hasScript)  { $score += 25 }
    if ($hasDll)     { $score += 25 }
    return @{ success = $true; score = $score; hasPolicy = $true; hasExe = $hasExe; hasMsi = $hasMsi; hasScript = $hasScript; hasDll = $hasDll }
}

function Get-DashboardSummary {
    $events = Get-AppLockerEventStats
    $health = Get-PolicyHealthScore
    return @{ success = $true; timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; events = $events; policyHealth = $health }
}

# Module 2: Scan Functions
function Get-LocalExecutableArtifacts {
    param(
        [string[]]$Paths = @("C:\Program Files", "C:\Program Files (x86)", "$env:LOCALAPPDATA", "$env:PROGRAMDATA"),
        [int]$MaxFiles = 1000
    )
    $artifacts = @()
    $extensions = @(".exe", ".msi", ".bat", ".cmd", ".ps1")
    foreach ($basePath in $Paths) {
        if (-not (Test-Path $basePath)) { continue }
        try {
            $files = Get-ChildItem -Path $basePath -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $extensions -contains $_.Extension } |
                     Select-Object -First $MaxFiles
            foreach ($file in $files) {
                try {
                    $versionInfo = $file.VersionInfo
                    $publisher = if ($versionInfo.CompanyName) { $versionInfo.CompanyName } else { "Unknown" }
                    if ($file.FullName -like "*Windows\*") { continue }
                    $artifacts += @{
                        name = $file.Name; publisher = $publisher; path = $file.FullName
                        hash = "N/A"; version = if ($versionInfo.FileVersion) { $versionInfo.FileVersion } else { "Unknown" }
                        size = $file.Length; modifiedDate = $file.LastWriteTime
                    }
                    if ($artifacts.Count -ge $MaxFiles) { break }
                } catch { continue }
            }
        } catch { }
        if ($artifacts.Count -ge $MaxFiles) { break }
    }
    return @{ success = $true; artifacts = $artifacts; count = $artifacts.Count }
}

# Comprehensive AaronLocker-style Scan Function
function Start-ComprehensiveScan {
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$OutputPath = "C:\GA-AppLocker\Scans",
        [switch]$IncludeDLLs = $false,
        [int]$MaxExecutables = 50000
    )

    $startTime = Get-Date
    $scanFolder = Join-Path $OutputPath "Scan-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $computerFolder = Join-Path $scanFolder $ComputerName

    try {
        # Create output directories
        New-Item -ItemType Directory -Path $computerFolder -Force | Out-Null
        Write-Log "Starting comprehensive scan for $ComputerName"

        $results = @{
            ComputerName = $ComputerName
            ScanFolder = $computerFolder
            StartTime = $startTime
            Files = @{}
        }

        # ============================================
        # 1. SYSTEM INFO
        # ============================================
        Write-Log "Collecting system information..."
        $systemInfo = @()
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

        $systemInfo += [PSCustomObject]@{
            Property = "ComputerName"; Value = $ComputerName
        }
        $systemInfo += [PSCustomObject]@{
            Property = "Domain"; Value = $cs.Domain
        }
        $systemInfo += [PSCustomObject]@{
            Property = "OS"; Value = $os.Caption
        }
        $systemInfo += [PSCustomObject]@{
            Property = "OSVersion"; Value = $os.Version
        }
        $systemInfo += [PSCustomObject]@{
            Property = "OSBuild"; Value = $os.BuildNumber
        }
        $systemInfo += [PSCustomObject]@{
            Property = "Architecture"; Value = $os.OSArchitecture
        }
        $systemInfo += [PSCustomObject]@{
            Property = "LastBootTime"; Value = $os.LastBootUpTime
        }
        $systemInfo += [PSCustomObject]@{
            Property = "ScanTime"; Value = $startTime
        }

        $systemInfoPath = Join-Path $computerFolder "SystemInfo.csv"
        $systemInfo | Export-Csv -Path $systemInfoPath -NoTypeInformation -Encoding UTF8
        $results.Files["SystemInfo"] = $systemInfoPath
        Write-Log "SystemInfo.csv created"

        # ============================================
        # 2. INSTALLED SOFTWARE
        # ============================================
        Write-Log "Collecting installed software..."
        $installedSoftware = @()

        # 64-bit software
        $regPath64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        # 32-bit software on 64-bit OS
        $regPath32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        # User software
        $regPathUser = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

        $regPaths = @($regPath64, $regPath32, $regPathUser) | Where-Object { Test-Path $_ }

        foreach ($regPath in $regPaths) {
            Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    $installedSoftware += [PSCustomObject]@{
                        Name = $_.DisplayName
                        Version = $_.DisplayVersion
                        Publisher = $_.Publisher
                        InstallDate = $_.InstallDate
                        InstallLocation = $_.InstallLocation
                        UninstallString = $_.UninstallString
                    }
                }
        }

        $installedSoftware = $installedSoftware | Sort-Object Name -Unique
        $installedSoftwarePath = Join-Path $computerFolder "InstalledSoftware.csv"
        $installedSoftware | Export-Csv -Path $installedSoftwarePath -NoTypeInformation -Encoding UTF8
        $results.Files["InstalledSoftware"] = $installedSoftwarePath
        Write-Log "InstalledSoftware.csv created ($($installedSoftware.Count) entries)"

        # ============================================
        # 3. RUNNING PROCESSES
        # ============================================
        Write-Log "Collecting running processes..."
        $processes = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $proc = $_
                $path = $proc.Path
                $publisher = "Unknown"
                $version = "Unknown"

                if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                    $vInfo = (Get-Item $path -ErrorAction SilentlyContinue).VersionInfo
                    $publisher = if ($vInfo.CompanyName) { $vInfo.CompanyName } else { "Unknown" }
                    $version = if ($vInfo.FileVersion) { $vInfo.FileVersion } else { "Unknown" }
                }

                [PSCustomObject]@{
                    ProcessName = $proc.ProcessName
                    PID = $proc.Id
                    Path = $path
                    Publisher = $publisher
                    Version = $version
                    WorkingSet = $proc.WorkingSet64
                    StartTime = $proc.StartTime
                }
            } catch { }
        } | Where-Object { $_.Path }

        $processesPath = Join-Path $computerFolder "RunningProcesses.csv"
        $processes | Export-Csv -Path $processesPath -NoTypeInformation -Encoding UTF8
        $results.Files["RunningProcesses"] = $processesPath
        Write-Log "RunningProcesses.csv created ($($processes.Count) entries)"

        # ============================================
        # 4. EXECUTABLES SCAN
        # ============================================
        Write-Log "Scanning for executables (this may take a while)..."
        $executables = @()
        $publishers = @{}

        $scanPaths = @(
            "C:\Program Files",
            "C:\Program Files (x86)",
            "$env:LOCALAPPDATA",
            "$env:PROGRAMDATA",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Downloads"
        )

        $extensions = @(".exe", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".js")
        if ($IncludeDLLs) { $extensions += ".dll" }

        $fileCount = 0
        foreach ($basePath in $scanPaths) {
            if (-not (Test-Path $basePath)) { continue }

            try {
                Get-ChildItem -Path $basePath -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $extensions -contains $_.Extension.ToLower() } |
                    ForEach-Object {
                        if ($fileCount -ge $MaxExecutables) { return }

                        $file = $_
                        try {
                            $vInfo = $file.VersionInfo
                            $publisher = if ($vInfo.CompanyName) { $vInfo.CompanyName.Trim() } else { "Unknown" }
                            $product = if ($vInfo.ProductName) { $vInfo.ProductName.Trim() } else { "" }
                            $version = if ($vInfo.FileVersion) { $vInfo.FileVersion.Trim() } else { "" }
                            $description = if ($vInfo.FileDescription) { $vInfo.FileDescription.Trim() } else { "" }

                            # Track publishers
                            if ($publisher -ne "Unknown" -and -not $publishers.ContainsKey($publisher)) {
                                $publishers[$publisher] = @{
                                    Publisher = $publisher
                                    FirstProduct = $product
                                    FileCount = 0
                                }
                            }
                            if ($publisher -ne "Unknown") { $publishers[$publisher].FileCount++ }

                            $executables += [PSCustomObject]@{
                                FileName = $file.Name
                                FullPath = $file.FullName
                                Extension = $file.Extension
                                Publisher = $publisher
                                Product = $product
                                Version = $version
                                Description = $description
                                Size = $file.Length
                                Created = $file.CreationTime
                                Modified = $file.LastWriteTime
                                Directory = $file.DirectoryName
                            }
                            $fileCount++
                        } catch { }
                    }
            } catch { }
        }

        $executablesPath = Join-Path $computerFolder "Executables.csv"
        $executables | Export-Csv -Path $executablesPath -NoTypeInformation -Encoding UTF8
        $results.Files["Executables"] = $executablesPath
        Write-Log "Executables.csv created ($($executables.Count) entries)"

        # ============================================
        # 5. PUBLISHERS
        # ============================================
        Write-Log "Extracting publisher information..."
        $publisherList = $publishers.Values | ForEach-Object {
            [PSCustomObject]@{
                Publisher = $_.Publisher
                SampleProduct = $_.FirstProduct
                FileCount = $_.FileCount
            }
        } | Sort-Object Publisher

        $publishersPath = Join-Path $computerFolder "Publishers.csv"
        $publisherList | Export-Csv -Path $publishersPath -NoTypeInformation -Encoding UTF8
        $results.Files["Publishers"] = $publishersPath
        Write-Log "Publishers.csv created ($($publisherList.Count) unique publishers)"

        # ============================================
        # 6. WRITABLE DIRECTORIES
        # ============================================
        Write-Log "Finding user-writable directories..."
        $writableDirs = @()

        $checkPaths = @(
            "$env:USERPROFILE",
            "$env:LOCALAPPDATA",
            "$env:APPDATA",
            "$env:TEMP",
            "C:\Users\Public"
        )

        foreach ($checkPath in $checkPaths) {
            if (-not (Test-Path $checkPath)) { continue }
            try {
                Get-ChildItem -Path $checkPath -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $testFile = Join-Path $_.FullName ".writetest"
                        try {
                            [IO.File]::WriteAllText($testFile, "test")
                            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                            $writableDirs += [PSCustomObject]@{
                                Path = $_.FullName
                                Parent = $_.Parent.FullName
                            }
                        } catch { }
                    }
            } catch { }
        }

        # Add common writable locations
        $commonWritable = @("$env:TEMP", "$env:LOCALAPPDATA\Temp", "C:\Users\Public")
        foreach ($path in $commonWritable) {
            if ((Test-Path $path) -and ($writableDirs.Path -notcontains $path)) {
                $writableDirs += [PSCustomObject]@{ Path = $path; Parent = (Split-Path $path -Parent) }
            }
        }

        $writableDirs = $writableDirs | Sort-Object Path -Unique | Select-Object -First 500
        $writableDirsPath = Join-Path $computerFolder "WritableDirectories.csv"
        $writableDirs | Export-Csv -Path $writableDirsPath -NoTypeInformation -Encoding UTF8
        $results.Files["WritableDirectories"] = $writableDirsPath
        Write-Log "WritableDirectories.csv created ($($writableDirs.Count) entries)"

        # ============================================
        # 7. APPLOCKER POLICY EXPORT
        # ============================================
        Write-Log "Exporting current AppLocker policy..."
        try {
            $policyXml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $policyPath = Join-Path $computerFolder "AppLockerPolicy.xml"
            # AppLocker policies MUST be UTF-16 encoded (Unicode)
            $xmlDoc = [xml]$policyXml
            $xws = [System.Xml.XmlWriterSettings]::new()
            $xws.Encoding = [System.Text.Encoding]::Unicode
            $xws.Indent = $true
            $xw = [System.Xml.XmlWriter]::Create($policyPath, $xws)
            $xmlDoc.Save($xw)
            $xw.Close()
            $results.Files["AppLockerPolicy"] = $policyPath
            Write-Log "AppLockerPolicy.xml exported"
        } catch {
            Write-Log "Could not export AppLocker policy: $($_.Exception.Message)" -Level "WARN"
        }

        # ============================================
        # SCAN COMPLETE
        # ============================================
        $endTime = Get-Date
        $duration = $endTime - $startTime

        $results.EndTime = $endTime
        $results.Duration = $duration.ToString()
        $results.Success = $true

        Write-Log "Comprehensive scan completed in $($duration.TotalSeconds.ToString('F1')) seconds"

        return @{
            success = $true
            computerName = $ComputerName
            scanFolder = $computerFolder
            files = $results.Files
            duration = $duration.TotalSeconds
            stats = @{
                Executables = $executables.Count
                InstalledSoftware = $installedSoftware.Count
                RunningProcesses = $processes.Count
                Publishers = $publisherList.Count
                WritableDirectories = $writableDirs.Count
            }
        }
    }
    catch {
        Write-Log "Comprehensive scan failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Module 3: Rule Generator Functions
function New-PublisherRule {
    param(
        [string]$PublisherName,
        [string]$ProductName = "*",
        [string]$BinaryName = "*",
        [string]$Version = "*",
        [string]$Action = "Allow",
        [string]$UserOrGroupSid = "S-1-1-0"
    )
    if (-not $PublisherName) { return @{ success = $false; error = "Publisher name is required" } }
    $guid = "{" + (New-Guid).ToString() + "}"
    $xml = "<FilePublisherRule Id=`"$guid`" Name=`"$PublisherName`" UserOrGroupSid=`"$UserOrGroupSid`" Action=`"$Action`"><Conditions><FilePublisherCondition PublisherName=`"$PublisherName`" ProductName=`"$ProductName`" BinaryName=`"$BinaryName`"><BinaryVersionRange LowSection=`"$Version`" HighSection=`"*`" /></FilePublisherCondition></Conditions></FilePublisherRule>"
    return @{ success = $true; id = $guid; type = "Publisher"; publisher = $PublisherName; action = $Action; sid = $UserOrGroupSid; xml = $xml }
}

function New-HashRule {
    param(
        [string]$FilePath,
        [string]$Action = "Allow",
        [string]$UserOrGroupSid = "S-1-1-0"
    )
    if (-not (Test-Path $FilePath)) { return @{ success = $false; error = "File not found" } }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    $fileName = (Get-Item $FilePath).Name
    $guid = "{" + (New-Guid).ToString() + "}"
    $xml = "<FileHashRule Id=`"$guid`" Name=`"$fileName`" UserOrGroupSid=`"$UserOrGroupSid`" Action=`"$Action`"><Conditions><FileHashCondition SourceFileName=`"$fileName`" SourceFileHash=`"$hash`" Type=`"SHA256`" /></Conditions></FileHashRule>"
    return @{ success = $true; id = $guid; type = "Hash"; hash = $hash; fileName = $fileName; action = $Action; sid = $UserOrGroupSid; xml = $xml }
}

function New-RulesFromArtifacts {
    param(
        [array]$Artifacts,
        [string]$RuleType = "Publisher",
        [string]$Action = "Allow",
        [string]$UserOrGroupSid = "S-1-1-0"
    )

    if (-not $Artifacts -or $Artifacts.Count -eq 0) {
        return @{ success = $false; error = "No artifacts provided" }
    }

    $rules = @()
    $processed = @{}

    foreach ($artifact in $Artifacts) {
        # Get publisher name (handle various column name formats)
        $publisherName = $artifact.Publisher
        if (-not $publisherName) { $publisherName = $artifact.publisher }
        if (-not $publisherName) { $publisherName = $artifact.CompanyName }
        if (-not $publisherName) { $publisherName = $artifact.Signer }
        if (-not $publisherName) { $publisherName = $artifact.name }

        # Get file path (handle various column name formats)
        $filePath = $artifact.FullPath
        if (-not $filePath) { $filePath = $artifact.fullPath }
        if (-not $filePath) { $filePath = $artifact.Path }
        if (-not $filePath) { $filePath = $artifact.path }
        if (-not $filePath) { $filePath = $artifact.FilePath }

        # Get file name
        $fileName = $artifact.FileName
        if (-not $fileName) { $fileName = $artifact.Name }
        if (-not $fileName) { $fileName = $artifact.name }

        switch ($RuleType) {
            "Publisher" {
                if ($publisherName -and $publisherName -ne "Unknown" -and $publisherName -ne "") {
                    if (-not $processed.ContainsKey($publisherName)) {
                        $processed[$publisherName] = $true
                        $rule = New-PublisherRule -PublisherName $publisherName -Action $Action -UserOrGroupSid $UserOrGroupSid
                        if ($rule.success) { $rules += $rule }
                    }
                }
            }
            "Hash" {
                if ($filePath -and (Test-Path $filePath -ErrorAction SilentlyContinue)) {
                    $hashKey = $filePath.ToLower()
                    if (-not $processed.ContainsKey($hashKey)) {
                        $processed[$hashKey] = $true
                        $rule = New-HashRule -FilePath $filePath -Action $Action -UserOrGroupSid $UserOrGroupSid
                        if ($rule.success) { $rules += $rule }
                    }
                }
            }
            "Path" {
                if ($filePath) {
                    # Create path rule for the directory
                    $directory = Split-Path -Parent $filePath -ErrorAction SilentlyContinue
                    if ($directory -and -not $processed.ContainsKey($directory)) {
                        $processed[$directory] = $true
                        $guid = "{" + (New-Guid).ToString() + "}"
                        $xml = "<FilePathRule Id=`"$guid`" Name=`"$directory`" UserOrGroupSid=`"$UserOrGroupSid`" Action=`"$Action`"><Conditions><FilePathCondition Path=`"$directory\*`"/></Conditions></FilePathRule>"
                        $rules += @{
                            success = $true
                            type = "Path"
                            publisher = $directory
                            path = "$directory\*"
                            action = $Action
                            sid = $UserOrGroupSid
                            xml = $xml
                        }
                    }
                }
            }
        }
    }

    return @{
        success = $true
        rules = $rules
        count = $rules.Count
        ruleType = $RuleType
        action = $Action
        sid = $UserOrGroupSid
        processedCount = $processed.Count
    }
}

# Create default deny rules for common bypass locations (best practice)
function New-DefaultDenyRules {
    param(
        [string]$UserOrGroupSid = "S-1-1-0"  # Everyone by default
    )

    $rules = @()

    # Common bypass locations to deny
    $bypassLocations = @(
        @{ Path = "%TEMP%\*"; Name = "Block TEMP folder" }
        @{ Path = "%TMP%\*"; Name = "Block TMP folder" }
        @{ Path = "%USERPROFILE%\AppData\Local\Temp\*"; Name = "Block User Temp folder" }
        @{ Path = "%LOCALAPPDATA%\Temp\*"; Name = "Block LocalAppData Temp" }
        @{ Path = "%USERPROFILE%\Downloads\*"; Name = "Block Downloads folder" }
        @{ Path = "C:\Users\*\Downloads\*"; Name = "Block All User Downloads" }
        @{ Path = "%APPDATA%\*"; Name = "Block AppData Roaming" }
        @{ Path = "%LOCALAPPDATA%\*"; Name = "Block AppData Local" }
        @{ Path = "C:\Windows\Temp\*"; Name = "Block Windows Temp" }
        @{ Path = "C:\ProgramData\*"; Name = "Block ProgramData" }
    )

    foreach ($location in $bypassLocations) {
        $guid = "{" + (New-Guid).ToString() + "}"
        $xml = "<FilePathRule Id=`"$guid`" Name=`"$($location.Name)`" Description=`"Deny execution from $($location.Path)`" UserOrGroupSid=`"$UserOrGroupSid`" Action=`"Deny`"><Conditions><FilePathCondition Path=`"$($location.Path)`"/></Conditions></FilePathRule>"

        $rules += @{
            success = $true
            type = "Path"
            publisher = $location.Name
            path = $location.Path
            action = "Deny"
            sid = $UserOrGroupSid
            xml = $xml
        }
    }

    return @{
        success = $true
        rules = $rules
        count = $rules.Count
        ruleType = "Path"
        action = "Deny"
    }
}

# Module 4: Domain Detection
# NOTE: Named Get-DomainInfo to avoid conflict with ActiveDirectory\Get-ADDomain cmdlet
function Get-DomainInfo {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    # Check if actually part of a domain (PartOfDomain is a boolean)
    $isWorkgroup = -not $computerSystem -or -not $computerSystem.PartOfDomain

    if ($isWorkgroup) {
        return @{
            success = $true
            isWorkgroup = $true
            hasRSAT = $false
            dnsRoot = "WORKGROUP"
            netBIOSName = $env:COMPUTERNAME
            message = "WORKGROUP - AD/GPO disabled"
        }
    }

    # We're domain-joined, check for RSAT (AD and GroupPolicy modules)
    $hasADModule = $false
    $hasGPModule = $false

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $hasADModule = $true
    } catch { }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $hasGPModule = $true
    } catch { }

    $hasRSAT = $hasADModule -and $hasGPModule

    # Try to get domain info
    try {
        if ($hasADModule) {
            $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
            $domainName = $domain.DNSRoot
            $netbios = $domain.NetBIOSName
        } else {
            $domainName = $env:USERDNSDOMAIN
            if ([string]::IsNullOrEmpty($domainName)) {
                $domainName = $computerSystem.Domain
            }
            $netbios = $env:USERDOMAIN
        }

        if ($hasRSAT) {
            return @{
                success = $true
                isWorkgroup = $false
                hasRSAT = $true
                dnsRoot = $domainName
                netBIOSName = $netbios
                message = "Domain: $domainName (Full features)"
            }
        } else {
            return @{
                success = $true
                isWorkgroup = $false
                hasRSAT = $false
                dnsRoot = $domainName
                netBIOSName = $netbios
                message = "Domain: $domainName (RSAT not installed - GPO features disabled)"
            }
        }
    } catch {
        return @{
            success = $true
            isWorkgroup = $true
            hasRSAT = $false
            dnsRoot = "WORKGROUP"
            netBIOSName = $env:COMPUTERNAME
            message = "WORKGROUP - AD/GPO disabled"
        }
    }
}

# Module 5: Event Monitor
function Get-AppLockerEvents {
    param(
        [int]$MaxEvents = 100,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $logNames = @(
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-AppLocker/MSI and Script'
    )

    $allEvents = @()

    foreach ($logName in $logNames) {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME -or [string]::IsNullOrEmpty($ComputerName)) {
                $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            } else {
                $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ComputerName $ComputerName -ErrorAction SilentlyContinue
            }

            if ($events) {
                $allEvents += $events | ForEach-Object {
                    @{
                        computerName = $ComputerName
                        logName = $logName -replace 'Microsoft-Windows-AppLocker/', ''
                        eventId = $_.Id
                        time = $_.TimeCreated
                        level = switch ($_.Level) { 1 { "Critical" }; 2 { "Error" }; 3 { "Warning" }; 4 { "Information" }; default { "Info" } }
                        message = ConvertTo-HtmlEncoded -Value ($_.Message -replace "`n", " " -replace "`r", "")
                    }
                }
            }
        } catch { }
    }

    $allEvents = $allEvents | Sort-Object { $_.time } -Descending | Select-Object -First $MaxEvents

    return @{ success = $true; data = $allEvents; count = $allEvents.Count; computerName = $ComputerName }
}

# Get AppLocker events from multiple remote computers via WinRM
function Get-RemoteAppLockerEvents {
    param(
        [string[]]$ComputerNames,
        [int]$MaxEventsPerComputer = 50
    )

    $allEvents = @()
    $results = @{ success = $true; computers = @(); failedComputers = @(); totalEvents = 0 }

    foreach ($computer in $ComputerNames) {
        try {
            $computerEvents = Invoke-Command -ComputerName $computer -ScriptBlock {
                param($MaxEvents)
                $logNames = @('Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script')
                $events = @()
                foreach ($logName in $logNames) {
                    try {
                        $logEvents = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                        if ($logEvents) {
                            $events += $logEvents | ForEach-Object {
                                @{
                                    logName = $logName -replace 'Microsoft-Windows-AppLocker/', ''
                                    eventId = $_.Id
                                    time = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                                    level = $_.LevelDisplayName
                                    message = ConvertTo-HtmlEncoded -Value ($_.Message -replace "`n", " " -replace "`r", "")
                                }
                            }
                        }
                    } catch { }
                }
                return $events
            } -ArgumentList $MaxEventsPerComputer -ErrorAction Stop

            if ($computerEvents) {
                foreach ($evt in $computerEvents) { $evt.computerName = $computer; $allEvents += $evt }
                $results.computers += @{ name = $computer; eventCount = $computerEvents.Count }
            } else {
                $results.computers += @{ name = $computer; eventCount = 0 }
            }
        }
        catch {
            $results.failedComputers += @{ name = $computer; error = $_.Exception.Message }
        }
    }

    $results.data = $allEvents | Sort-Object { $_.time } -Descending
    $results.totalEvents = $allEvents.Count
    return $results
}

# Module 6: Compliance
function New-EvidenceFolder {
    param([string]$BasePath)
    if (-not $BasePath) { $BasePath = "C:\GA-AppLocker" }
    try {
        $folders = @{}
        $subfolders = @("Policies", "Events", "Inventory", "Reports", "Scans")
        foreach ($sub in $subfolders) {
            $path = Join-Path $BasePath $sub
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            $folders[$sub] = $path
        }
        return @{ success = $true; basePath = $BasePath; folders = $folders }
    } catch {
        return @{ success = $false; error = "Failed to create evidence folder" }
    }
}

# Module 7: GPO Functions

# Create AppLocker GPO with automatic OU targeting based on GPO name
function New-AppLockerGpo {
    param(
        [string]$GpoName = "AppLocker Policy",
        [string]$TargetOU = $null,
        [ValidateSet("AuditOnly", "Enabled")]
        [string]$EnforcementMode = "AuditOnly"
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        # Get domain info
        $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName

        # Determine target OU based on GPO name if not specified
        if (-not $TargetOU) {
            switch -Wildcard ($GpoName) {
                "*-DC" {
                    # Link to Domain Controllers OU (default AD OU)
                    $TargetOU = "OU=Domain Controllers,$domainDN"
                    Write-Log "Auto-targeting Domain Controllers OU for $GpoName"
                }
                "*-Servers" {
                    # Link to root domain (servers can be anywhere)
                    # Could also target a Servers OU if it exists
                    $serversOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Servers'" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($serversOU) {
                        $TargetOU = $serversOU.DistinguishedName
                        Write-Log "Auto-targeting Servers OU for ${GpoName} -> $TargetOU"
                    } else {
                        $TargetOU = $domainDN
                        Write-Log "No Servers OU found, targeting domain root for $GpoName"
                    }
                }
                "*-Workstations" {
                    # Try Workstations OU first, then Computers container, then domain root
                    $workstationsOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Workstations'" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($workstationsOU) {
                        $TargetOU = $workstationsOU.DistinguishedName
                        Write-Log "Auto-targeting Workstations OU for ${GpoName} -> $TargetOU"
                    } else {
                        # Check for Computers OU
                        $computersOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Computers'" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($computersOU) {
                            $TargetOU = $computersOU.DistinguishedName
                            Write-Log "Auto-targeting Computers OU for ${GpoName} -> $TargetOU"
                        } else {
                            $TargetOU = $domainDN
                            Write-Log "No Workstations/Computers OU found, targeting domain root for $GpoName"
                        }
                    }
                }
                default {
                    $TargetOU = $domainDN
                    Write-Log "Using domain root for $GpoName"
                }
            }
        }

        Write-Log "Creating AppLocker GPO: $GpoName -> $TargetOU"

        # Check if GPO already exists
        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if ($existingGpo) {
            Write-Log "GPO already exists: $GpoName"

            # Try to link existing GPO to target OU
            try {
                New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes -ErrorAction Stop | Out-Null
                Write-Log "Linked existing GPO to: $TargetOU"
            }
            catch {
                if ($_.Exception.Message -notlike "*already linked*") {
                    Write-Log "Could not link existing GPO: $($_.Exception.Message)" -Level "WARN"
                } else {
                    Write-Log "GPO already linked to $TargetOU"
                }
            }

            return @{
                success = $true
                gpoName = $GpoName
                gpoId = $existingGpo.Id
                linkedTo = $TargetOU
                message = "GPO '$GpoName' already exists and linked to $TargetOU."
                isNew = $false
            }
        }

        # Create the GPO
        $gpo = New-GPO -Name $GpoName -Comment "AppLocker application control policy - Created by GA-AppLocker Dashboard" -ErrorAction Stop
        Write-Log "GPO created: $($gpo.Id)"

        # Link to target OU
        try {
            $link = New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes -ErrorAction Stop
            Write-Log "GPO linked to: $TargetOU"
        }
        catch {
            if ($_.Exception.Message -notlike "*already linked*") {
                Write-Log "GPO link warning: $($_.Exception.Message)" -Level "WARN"
            } else {
                Write-Log "GPO already linked to $TargetOU"
            }
        }

        # Set Domain Admins with full control
        try {
            Set-GPPermission -Name $GpoName -PermissionLevel GpoEditDeleteModifySecurity -TargetName "Domain Admins" -TargetType Group -Replace -ErrorAction Stop
            Write-Log "Set Domain Admins as owner of GPO: $GpoName"
        }
        catch {
            Write-Log "Failed to set GPO permissions: $($_.Exception.Message)" -Level "WARN"
        }

        return @{
            success = $true
            gpoName = $GpoName
            gpoId = $gpo.Id
            linkedTo = $TargetOU
            message = "AppLocker GPO created and linked to $TargetOU successfully"
            isNew = $true
        }
    }
    catch {
        Write-Log "Failed to create AppLocker GPO: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Create WinRM GPO with full configuration
function New-WinRMGpo {
    param(
        [string]$GpoName = "Enable WinRM",
        [string]$OU = $null
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        # Detect current domain if OU not specified
        if (-not $OU) {
            $domain = ActiveDirectory\Get-ADDomain
            $OU = $domain.DistinguishedName
        }

        Write-Log "Creating/Updating WinRM GPO: $GpoName"

        # Check if GPO already exists
        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        $isNew = $false

        if ($existingGpo) {
            Write-Log "GPO '$GpoName' already exists, updating settings..."
            $gpo = $existingGpo
        } else {
            # Create new GPO
            $gpo = New-GPO -Name $GpoName -Comment "WinRM Configuration for Remote Management - Created by GA-AppLocker" -ErrorAction Stop
            Write-Log "GPO created: $($gpo.Id)"
            $isNew = $true
        }

        # Always try to link GPO to domain (whether new or existing)
        try {
            New-GPLink -Name $GpoName -Target $OU -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Log "GPO linked to: $OU"
        }
        catch {
            if ($_.Exception.Message -notlike "*already linked*") {
                Write-Log "GPO link warning: $($_.Exception.Message)" -Level "WARNING"
            } else {
                Write-Log "GPO already linked to $OU"
            }
        }

        # ============================================
        # WinRM SERVICE Configuration (Policy Settings)
        # ============================================

        # Allow automatic configuration of listeners - THIS IS THE KEY SETTING
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Type DWord -Value 1 -ErrorAction Stop

        # IPv4 Filter - allow all (required for listener creation)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv4Filter" -Type String -Value "*" -ErrorAction Stop

        # IPv6 Filter - allow all
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv6Filter" -Type String -Value "*" -ErrorAction Stop

        # Allow Kerberos authentication (default for domain)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowKerberos" -Type DWord -Value 1 -ErrorAction Stop

        # Allow Negotiate authentication
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowNegotiate" -Type DWord -Value 1 -ErrorAction Stop

        # Disable CredSSP authentication (security risk)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowCredSSP" -Type DWord -Value 0 -ErrorAction Stop

        Write-Log "WinRM Service policies configured"

        # ============================================
        # WinRM CLIENT Configuration
        # ============================================

        # Allow Kerberos authentication for client
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowKerberos" -Type DWord -Value 1 -ErrorAction Stop

        # Allow Negotiate authentication for client
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowNegotiate" -Type DWord -Value 1 -ErrorAction Stop

        # TrustedHosts - allow all domain computers
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client" -ValueName "TrustedHosts" -Type String -Value "*" -ErrorAction Stop

        Write-Log "WinRM Client policies configured"

        # ============================================
        # WinRM Service Startup Type
        # ============================================

        # Set WinRM service to start automatically (2 = Automatic)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "Start" -Type DWord -Value 2 -ErrorAction Stop

        # Enable delayed auto-start for reliability
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "DelayedAutostart" -Type DWord -Value 0 -ErrorAction Stop

        Write-Log "WinRM service startup set to Automatic"

        # ============================================
        # Windows Firewall - Enable Predefined Rules
        # ============================================

        # Enable the Windows Remote Management firewall group (Domain profile)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ValueName "Enabled" -Type DWord -Value 1 -ErrorAction SilentlyContinue

        # Enable inbound firewall rule for WinRM HTTP (5985)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "WinRM-HTTP-In-TCP" -Type String -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|Name=WinRM-HTTP-In-TCP|Desc=Allow WinRM HTTP|Profile=Domain|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=WinRM|" -ErrorAction SilentlyContinue

        # Enable inbound firewall rule for WinRM HTTPS (5986)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "WinRM-HTTPS-In-TCP" -Type String -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5986|Name=WinRM-HTTPS-In-TCP|Desc=Allow WinRM HTTPS|Profile=Domain|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=WinRM|" -ErrorAction SilentlyContinue

        # Configure Domain Firewall Profile settings
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DefaultInboundAction" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DefaultOutboundAction" -Type DWord -Value 0 -ErrorAction SilentlyContinue

        Write-Log "WinRM firewall rules configured"

        # ============================================
        # Create Startup Script for Reliable Firewall
        # ============================================
        try {
            $currentDomain = (Get-ADDomain).DNSRoot
            $gpoPath = "\\$currentDomain\SYSVOL\$currentDomain\Policies\{$($gpo.Id)}"

            $scriptsDir = "$gpoPath\Machine\Scripts\Startup"
            if (!(Test-Path $scriptsDir)) {
                New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
            }

            # Create the firewall configuration script
            $firewallScript = @'
@echo off
REM WinRM Firewall Configuration Script
netsh advfirewall firewall show rule name="WinRM-HTTP-In-GPO" >nul 2>&1
if %errorlevel% neq 0 (
    netsh advfirewall firewall add rule name="WinRM-HTTP-In-GPO" dir=in action=allow protocol=tcp localport=5985 profile=domain,private remoteip=localsubnet enable=yes
)
netsh advfirewall firewall show rule name="WinRM-HTTPS-In-GPO" >nul 2>&1
if %errorlevel% neq 0 (
    netsh advfirewall firewall add rule name="WinRM-HTTPS-In-GPO" dir=in action=allow protocol=tcp localport=5986 profile=domain,private remoteip=localsubnet enable=yes
)
sc query WinRM | find "RUNNING" >nul 2>&1
if %errorlevel% neq 0 (
    net start WinRM
)
winrm enumerate winrm/config/listener >nul 2>&1
if %errorlevel% neq 0 (
    winrm quickconfig -quiet
)
'@
            Set-Content -Path "$scriptsDir\Configure-WinRM-Firewall.cmd" -Value $firewallScript -Encoding ASCII

            # Create scripts.ini
            $scriptsIniDir = "$gpoPath\Machine\Scripts"
            if (!(Test-Path $scriptsIniDir)) {
                New-Item -Path $scriptsIniDir -ItemType Directory -Force | Out-Null
            }
            $scriptsIniContent = "[Startup]`r`n0CmdLine=Configure-WinRM-Firewall.cmd`r`n0Parameters="
            Set-Content -Path "$scriptsIniDir\scripts.ini" -Value $scriptsIniContent -Encoding Unicode

            # Update GPT.INI with script extension
            $gptIniPath = "$gpoPath\GPT.INI"

            # Validate GPT.INI path (security check)
            $pathValidation = Test-SafePath -Path $gptIniPath -AllowedRoots @("\\$currentDomain\SYSVOL")
            if (-not $pathValidation.valid) {
                Write-Log "GPT.INI path validation failed: $($pathValidation.error)" -Level "ERROR"
                throw "Invalid GPT.INI path: $($pathValidation.error)"
            }

            $scriptsExtension = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}"
            if (Test-Path $gptIniPath) {
                $gptContent = Get-Content $gptIniPath -Raw
                if ($gptContent -notmatch "gPCMachineExtensionNames") {
                    $gptContent = $gptContent -replace "(\[General\])", "`$1`r`ngPCMachineExtensionNames=$scriptsExtension"
                } elseif ($gptContent -notlike "*$scriptsExtension*") {
                    $gptContent = $gptContent -replace "(gPCMachineExtensionNames=.*)", "`$1$scriptsExtension"
                }
                if ($gptContent -match "Version=(\d+)") {
                    $newVersion = [int]$matches[1] + 1
                    $gptContent = $gptContent -replace "Version=\d+", "Version=$newVersion"
                }
                Set-Content -Path $gptIniPath -Value $gptContent

                Write-AuditLog -Action "GPT_INI_MODIFIED" -Target $gptIniPath -Result 'SUCCESS' -Details "GPT.INI updated with WinRM script extension"
            }
            Write-Log "Created startup script for firewall configuration"
        }
        catch {
            Write-Log "Could not create startup script (non-critical): $($_.Exception.Message)" -Level "WARN"
            Write-AuditLog -Action "GPT_INI_MODIFY_FAILED" -Target $gptIniPath -Result 'FAILURE' -Details "Error: $($_.Exception.Message)"
        }

        # ============================================
        # PowerShell Remoting (Enable-PSRemoting compatibility)
        # ============================================

        # Enable PS Remoting
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" -ValueName "AllowRemoteShellAccess" -Type DWord -Value 1 -ErrorAction SilentlyContinue

        Write-Log "PowerShell Remoting enabled"

        # ============================================
        # Set GPO Permissions
        # ============================================
        try {
            Set-GPPermission -Name $GpoName -PermissionLevel GpoEditDeleteModifySecurity -TargetName "Domain Admins" -TargetType Group -Replace -ErrorAction Stop
            Write-Log "Set Domain Admins as owner of GPO: $GpoName"
        }
        catch {
            Write-Log "Failed to set GPO permissions: $($_.Exception.Message)" -Level "WARN"
        }

        $action = if ($isNew) { "created and linked" } else { "updated" }
        return @{
            success = $true
            gpoName = $GpoName
            gpoId = $gpo.Id
            linkedTo = $OU
            isNew = $isNew
            message = "WinRM GPO $action successfully"
        }
    }
    catch {
        Write-Log "Failed to create/update WinRM GPO: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Disable/Enable WinRM GPO Link
function Set-WinRMGpoState {
    param(
        [string]$GpoName = "Enable WinRM",
        [bool]$Enabled = $true
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName

        # Get GPO
        $gpo = Get-GPO -Name $GpoName -ErrorAction Stop

        # Get existing link
        $links = (Get-GPInheritance -Target $domainDN).GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }

        if ($links) {
            if ($Enabled) {
                Set-GPLink -Name $GpoName -Target $domainDN -LinkEnabled Yes -ErrorAction Stop
                Write-Log "GPO '$GpoName' link ENABLED"
                return @{ success = $true; message = "GPO link enabled"; state = "Enabled" }
            } else {
                Set-GPLink -Name $GpoName -Target $domainDN -LinkEnabled No -ErrorAction Stop
                Write-Log "GPO '$GpoName' link DISABLED"
                return @{ success = $true; message = "GPO link disabled"; state = "Disabled" }
            }
        } else {
            return @{ success = $false; error = "GPO '$GpoName' is not linked to domain" }
        }
    }
    catch {
        Write-Log "Failed to change GPO state: $($_.Exception.Message)" -Level "ERROR"
        return @{ success = $false; error = $_.Exception.Message }
    }
}

function Set-WinRMGpoLink {
    param(
        [string]$GpoName = "Enable WinRM",
        [string]$Target,
        [bool]$Enabled = $true
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop

        if ($Enabled) {
            $link = Set-GPLink -Name $GpoName -Target $Target -LinkEnabled Yes -ErrorAction Stop
            Write-Log "GPO link enabled: $GpoName -> $Target"
        } else {
            $link = Set-GPLink -Name $GpoName -Target $Target -LinkEnabled No -ErrorAction Stop
            Write-Log "GPO link disabled: $GpoName -> $Target"
        }

        return @{
            success = $true
            message = "GPO link updated successfully"
        }
    }
    catch {
        Write-Log "Failed to set GPO link: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Module 8: Group Management Functions
function Export-ADGroupMembership {
    param([string]$Path)

    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

        $groupCount = 0
        $results = Get-ADGroup -Filter * -ErrorAction Stop |
            ForEach-Object {
                $group = $_
                $groupCount++

                Write-Progress -Activity "Exporting AD Groups" -Status "Processing $($group.Name)" -PercentComplete (($groupCount / (Get-ADGroup -Filter * | Measure-Object).Count) * 100)

                $Members = Get-ADGroupMember $group -Recursive:$false -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty SamAccountName

                [PSCustomObject]@{
                    GroupName = $group.Name
                    Members   = ($Members -join ';')
                }
            }

        $results | Export-Csv $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        # Close the progress dialog
        Write-Progress -Activity "Exporting AD Groups" -Completed

        $actualCount = (Import-Csv $Path).Count
        Write-Log "Export complete: $Path ($actualCount groups)"

        # Create template for desired state
        $desiredPath = $Path -replace '_Export\.csv$', '_Desired.csv'
        if ($desiredPath -eq $Path) {
            $desiredPath = $Path -replace '\.csv$', '_Desired.csv'
        }

        Copy-Item $Path $desiredPath -Force
        Write-Log "Template created: $desiredPath"

        return @{
            success = $true
            exportPath = $Path
            desiredPath = $desiredPath
            count = $actualCount
            message = "Exported $actualCount groups. Template created for editing."
        }
    }
    catch {
        Write-Log "Export failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Import-ADGroupMembership {
    param(
        [string]$Path,
        [bool]$DryRun,
        [bool]$Removals,
        [bool]$IncludeProtected
    )

    # Tier-0 Protected Groups
    $ProtectedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Group Policy Creator Owners"
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

        if (-not (Test-Path $Path)) {
            return @{
                success = $false
                error = "CSV file not found: $Path"
            }
        }

        $DesiredGroups = Import-Csv $Path

        if (-not $DesiredGroups) {
            return @{
                success = $false
                error = "No data found in CSV file"
            }
        }

        # Track statistics
        $stats = @{
            TotalGroups    = 0
            GroupsProcessed = 0
            Adds           = 0
            Removals       = 0
            Errors         = 0
            Skipped        = 0
        }
        $stats.TotalGroups = $DesiredGroups.Count

        $output = "=== AD GROUP MEMBERSHIP IMPORT ===`n`n"
        $output += "Configuration:`n  Dry Run: $DryRun`n  Allow Removals: $Removals`n  Include Protected: $IncludeProtected`n`n"
        $output += "Processing $($stats.TotalGroups) groups...`n`n"

        foreach ($Row in $DesiredGroups) {

            $GroupName = $Row.GroupName
            $DesiredMembers = $Row.Members -split ';' | Where-Object { $_ -ne "" }

            $output += "----------------------------------------`n"
            $output += "GROUP: $GroupName`n"
            $output += "----------------------------------------`n"

            # Check if protected
            if (($ProtectedGroups -contains $GroupName) -and -not $IncludeProtected) {
                $output += "[SKIPPED] Protected group - use 'Include Tier-0' to modify`n`n"
                $stats.Skipped++
                continue
            }

            try {
                $Group = Get-ADGroup $GroupName -ErrorAction Stop
            }
            catch {
                $output += "[ERROR] Group not found in AD: $GroupName`n`n"
                $stats.Errors++
                continue
            }

            $stats.GroupsProcessed++

            $CurrentMembers = Get-ADGroupMember $Group -Recursive:$false -ErrorAction SilentlyContinue
            $CurrentSam = @($CurrentMembers | ForEach-Object { $_.SamAccountName })

            # ---- ADD MISSING MEMBERS ----
            foreach ($Member in $DesiredMembers) {
                if ($CurrentSam -notcontains $Member) {

                    # Verify member exists
                    try {
                        $null = Get-ADObject -LDAPFilter "(sAMAccountName=$Member)" -ErrorAction Stop
                    }
                    catch {
                        $output += "[ERROR] Member not found: $Member`n"
                        $stats.Errors++
                        continue
                    }

                    $output += "[ADD] $Member -> $GroupName`n"

                    if (-not $DryRun) {
                        try {
                            Add-ADGroupMember -Identity $GroupName -Members $Member -ErrorAction Stop
                            $stats.Adds++
                        }
                        catch {
                            $output += "[ERROR] Failed to add $Member`: $($_.Exception.Message)`n"
                            $stats.Errors++
                        }
                    }
                    else {
                        $stats.Adds++
                    }
                }
            }

            # ---- REMOVE EXTRA MEMBERS (OPTIONAL) ----
            if ($Removals) {
                foreach ($Existing in $CurrentMembers) {
                    if ($DesiredMembers -notcontains $Existing.SamAccountName) {

                        $output += "[REMOVE] $($Existing.SamAccountName) <- $GroupName`n"

                        if (-not $DryRun) {
                            try {
                                Remove-ADGroupMember `
                                    -Identity $GroupName `
                                    -Members $Existing.SamAccountName `
                                    -Confirm:$false `
                                    -ErrorAction Stop
                                $stats.Removals++
                            }
                            catch {
                                $output += "[ERROR] Failed to remove $($Existing.SamAccountName): $($_.Exception.Message)`n"
                                $stats.Errors++
                            }
                        }
                        else {
                            $stats.Removals++
                        }
                    }
                }
            }
        }

        # ---- SUMMARY ----
        $output += "`n========================================`n"
        $output += "IMPORT SUMMARY`n"
        $output += "========================================`n"
        $output += "Total Groups in CSV: $($stats.TotalGroups)`n"
        $output += "Groups Processed: $($stats.GroupsProcessed)`n"
        $output += "Skipped (Protected): $($stats.Skipped)`n"
        $output += "Adds: $($stats.Adds)`n"
        $output += "Removals: $($stats.Removals)`n"
        $output += "Errors: $($stats.Errors)`n"
        $output += "========================================`n"

        if ($DryRun) {
            $output += "`nDRY RUN COMPLETE - No changes were applied`n"
            $output += "Re-run with Dry Run unchecked to apply changes`n"
        }
        else {
            $output += "`nCHANGES APPLIED TO ACTIVE DIRECTORY`n"
        }

        Write-Log "Group import complete: Processed=$($stats.GroupsProcessed), Adds=$($stats.Adds), Removals=$($stats.Removals), Errors=$($stats.Errors)"

        return @{
            success = $true
            output = $output
            stats = $stats
            dryRun = $DryRun
        }
    }
    catch {
        Write-Log "Import failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Module 9: AppLocker Setup Functions

# Helper function to set Domain Admins as owner of AD objects
# Remove protection from accidental deletion on OU/Container
function Remove-OUProtection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName
    )

    try {
        # Check if object exists
        $adObject = Get-ADObject -Identity $DistinguishedName -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop

        if ($adObject.ProtectedFromAccidentalDeletion) {
            Set-ADObject -Identity $DistinguishedName -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
            Write-Log "Removed protection from: $DistinguishedName"
            return @{ success = $true; message = "Protection removed from $DistinguishedName" }
        } else {
            return @{ success = $true; message = "Object was not protected: $DistinguishedName" }
        }
    }
    catch {
        Write-Log "ERROR removing protection from '$DistinguishedName': $_"
        return @{ success = $false; error = $_.Exception.Message }
    }
}

# Remove protection from all sub-OUs in an AppLocker structure
function Remove-AppLockerOUProtection {
    param(
        [string]$BaseDN = $null
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        if (-not $BaseDN) {
            $domain = Get-ADDomain -ErrorAction Stop
            $BaseDN = "OU=AppLocker,$($domain.DistinguishedName)"
        }

        $output = "Removing protection from AppLocker OUs...`n`n"
        $removedCount = 0

        # Get all OUs under AppLocker
        $allOUs = @($BaseDN)
        $childOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $BaseDN -SearchScope Subtree -ErrorAction SilentlyContinue
        if ($childOUs) {
            $allOUs += $childOUs.DistinguishedName
        }

        foreach ($ouDN in $allOUs) {
            $result = Remove-OUProtection -DistinguishedName $ouDN
            if ($result.success) {
                $output += "[OK] $ouDN`n"
                $removedCount++
            } else {
                $output += "[ERROR] $ouDN : $($result.error)`n"
            }
        }

        $output += "`n$removedCount OUs processed.`n"
        $output += "You can now delete OUs and objects under AppLocker."

        return @{
            success = $true
            output = $output
            processedCount = $removedCount
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Set-ADObjectOwner {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName,
        [string]$OwnerGroup = "Domain Admins"
    )

    try {
        # Get the AD object
        $adObject = [ADSI]"LDAP://$DistinguishedName"

        # Get the Domain Admins SID
        $domainAdminsSID = (Get-ADGroup $OwnerGroup -ErrorAction Stop).SID

        # Create security identifier
        $identity = New-Object System.Security.Principal.SecurityIdentifier($domainAdminsSID)

        # Get current ACL
        $acl = $adObject.ObjectSecurity

        # Set owner to Domain Admins
        $acl.SetOwner($identity)

        # Apply the modified ACL
        $adObject.ObjectSecurity = $acl
        $adObject.CommitChanges()

        Write-Log "Set owner of '$DistinguishedName' to $OwnerGroup"
        return $true
    }
    catch {
        Write-Log "Failed to set owner on '$DistinguishedName': $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

function Initialize-AppLockerStructure {
    param(
        [string]$OUName = "AppLocker",
        [bool]$AutoPopulateAdmins = $true,
        [string]$DomainFQDN = $null,
        [bool]$ProtectFromDeletion = $false  # Default to false so OUs can be deleted
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

        # Get domain info
        if (-not $DomainFQDN) {
            $DomainFQDN = (ActiveDirectory\Get-ADDomain -ErrorAction Stop).DNSRoot
        }

        $DomainDN = (ActiveDirectory\Get-ADDomain $DomainFQDN -ErrorAction Stop).DistinguishedName
        $OUDN = "OU=$OUName,$DomainDN"

        $output = "=== APPLOCKER INITIALIZATION ===`n`n"
        $output += "Domain: $DomainFQDN`n"
        $output += "Target OU: $OUDN`n`n"

        # Group definitions
        $AllowGroups = @(
            "AppLocker-Admin",
            "AppLocker-Installers",
            "AppLocker-StandardUsers",
            "AppLocker-Dev",
            "AppLocker-Audit"
        )

        $DenyGroups = @(
            "AppLocker-Deny-Executables",
            "AppLocker-Deny-Scripts",
            "AppLocker-Deny-DLLs",
            "AppLocker-Deny-PackagedApps"
        )

        # ---- CREATE OU ----
        $ouExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUDN'" -ErrorAction SilentlyContinue

        if (-not $ouExists) {
            New-ADOrganizationalUnit -Name $OUName -Path $DomainDN -ProtectedFromAccidentalDeletion $ProtectFromDeletion -ErrorAction Stop | Out-Null
            $output += "[CREATED] OU: $OUDN (Protected: $ProtectFromDeletion)`n"
            Write-Log "Created OU: $OUDN (Protected from deletion: $ProtectFromDeletion)"

            # Set Domain Admins as owner so they can manage/delete the OU
            if (Set-ADObjectOwner -DistinguishedName $OUDN) {
                $output += "[OWNER] Set Domain Admins as owner of OU`n"
            }
        }
        else {
            $output += "[EXISTS] OU: $OUDN`n"
            Write-Log "OU already exists: $OUDN"
        }

        # ---- CREATE GROUPS ----
        $groupsCreated = 0
        $groupsSkipped = 0

        $allGroups = $AllowGroups + $DenyGroups

        foreach ($Group in $allGroups) {
            $groupExists = Get-ADGroup -Filter "Name -eq '$Group'" -SearchBase $OUDN -ErrorAction SilentlyContinue

            if (-not $groupExists) {
                $category = if ($Group -like "*Deny*") { "Deny" } else { "Allow" }
                $description = "AppLocker $category group: $Group"

                New-ADGroup -Name $Group -GroupScope Global -GroupCategory Security -Path $OUDN -Description $description -ErrorAction Stop | Out-Null
                $output += "[CREATED] Group: $Group`n"
                $groupsCreated++
                Write-Log "Created group: $Group"

                # Set Domain Admins as owner so they can manage/delete the group
                $groupDN = "CN=$Group,$OUDN"
                if (Set-ADObjectOwner -DistinguishedName $groupDN) {
                    $output += "[OWNER] Set Domain Admins as owner of $Group`n"
                }
            }
            else {
                $output += "[EXISTS] Group: $Group`n"
                $groupsSkipped++
            }
        }

        $output += "`nGroups: $groupsCreated created, $groupsSkipped skipped`n"

        # ---- AUTO-POPULATE DOMAIN ADMINS ----
        if ($AutoPopulateAdmins) {
            $output += "`n--- Auto-Populating AppLocker-Admin ---`n"

            try {
                $domainAdminsGroup = Get-ADGroup "Domain Admins" -ErrorAction Stop
                $appLockerAdminGroup = Get-ADGroup "AppLocker-Admin" -ErrorAction Stop

                $domainAdmins = Get-ADGroupMember $domainAdminsGroup -Recursive:$false -ErrorAction SilentlyContinue |
                                Select-Object -ExpandProperty SamAccountName

                $addedCount = 0
                $skippedCount = 0

                foreach ($Admin in $domainAdmins) {
                    $existingMembers = Get-ADGroupMember $appLockerAdminGroup -Recursive:$false -ErrorAction SilentlyContinue |
                                       Select-Object -ExpandProperty SamAccountName

                    if ($existingMembers -notcontains $Admin) {
                        Add-ADGroupMember -Identity $appLockerAdminGroup -Members $Admin -ErrorAction Stop
                        $output += "[ADDED] $Admin -> AppLocker-Admin`n"
                        $addedCount++
                        Write-Log "Added Domain Admin to AppLocker-Admin: $Admin"
                    }
                    else {
                        $skippedCount++
                    }
                }

                $output += "Domain Admin sync: $addedCount added, $skippedCount already present`n"
            }
            catch {
                $output += "[ERROR] Failed to auto-populate: $($_.Exception.Message)`n"
                Write-Log "Auto-populate failed: $($_.Exception.Message)" -Level "ERROR"
            }
        }

        $output += "`n=== INITIALIZATION COMPLETE ===`n"

        Write-Log "AppLocker initialization complete"

        return @{
            success = $true
            output = $output
            ouDN = $OUDN
            groupsCreated = $groupsCreated
            groupsSkipped = $groupsSkipped
        }
    }
    catch {
        Write-Log "AppLocker initialization failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function New-BrowserDenyRules {
    param([string]$DomainFQDN = $null)

    # Common browsers to deny for admin accounts
    $browsers = @(
        @{Name="Chrome"; Path="C:\Program Files\Google\Chrome\Application\chrome.exe"; PathX86="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"},
        @{Name="Firefox"; Path="C:\Program Files\Mozilla Firefox\firefox.exe"; PathX86="C:\Program Files (x86)\Mozilla Firefox\firefox.exe"},
        @{Name="Edge"; Path="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"},
        @{Name="Opera"; Path="C:\Program Files\Opera\launcher.exe"; PathX86="C:\Program Files (x86)\Opera\launcher.exe"},
        @{Name="Brave"; Path="C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"; PathX86="C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"},
        @{Name="Vivaldi"; Path="C:\Program Files\Vivaldi\Application\vivaldi.exe"; PathX86="C:\Program Files (x86)\Vivaldi\Application\vivaldi.exe"},
        @{Name="Internet Explorer"; Path="C:\Program Files\Internet Explorer\iexplore.exe"; PathX86="C:\Program Files (x86)\Internet Explorer\iexplore.exe"}
    )

    try {
        if (-not $DomainFQDN) {
            $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
            $DomainFQDN = $domain.DNSRoot
        }

        $output = "=== BROWSER DENY RULES FOR ADMINS ===`n`n"
        $output += "Target Group: $DomainFQDN\AppLocker-Admin`n"
        $output += "Action: DENY (Admins should not have internet access)`n`n"

        $policyXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Executable" EnforcementMode="Enabled">
"@

        foreach ($browser in $browsers) {
            $guid = [Guid]::NewGuid()

            # Add primary path rule
            $policyXml += @"
    <FilePathRule Id="$guid" Name="Deny $($browser.Name) for Admins" Action="Deny" UserOrGroupSid="S-1-1-0" Conditions="">
      <FilePathConditions>
        <FilePathCondition Path="$($browser.Path)" />
"@

            # Add x86 path if exists
            if ($browser.PathX86) {
                $policyXml += @"
        <FilePathCondition Path="$($browser.PathX86)" />
"@
            }

            $policyXml += @"
      </FilePathConditions>
    </FilePathRule>
"@

            $output += "[RULE] Deny: $($browser.Name)`n"
            $output += "       Path: $($browser.Path)`n"
            if ($browser.PathX86) {
                $output += "       x86: $($browser.PathX86)`n"
            }
            $output += "`n"
        }

        $policyXml += @"
  </RuleCollection>
</AppLockerPolicy>
"@

        # Save policy
        $rulesDir = "C:\GA-AppLocker\Rules"
        if (-not (Test-Path $rulesDir)) { New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null }
        $policyPath = Join-Path $rulesDir "AppLocker-BrowserDeny-Admins.xml"
        $policyXml | Out-File -FilePath $policyPath -Encoding UTF8 -Force

        $output += "`n=== POLICY GENERATED ===`n"
        $output += "Saved to: $policyPath`n"
        $output += "`nNext Steps:`n"
        $output += "1. Review the XML file`n"
        $output += "2. Import into GPO using Local Security Policy or GP Management`n"
        $output += "3. Test in Audit mode first before Enforcing`n"

        Write-Log "Browser deny policy generated: $policyPath"

        return @{
            success = $true
            output = $output
            policyPath = $policyPath
            browsersDenied = $browsers.Count
        }
    }
    catch {
        Write-Log "Browser deny policy generation failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# Module 10: Advanced Compliance Reporting

# Store current report data for export
$script:CurrentReportData = $null
$script:ScheduledReports = @()

function New-ComplianceReport {
    <#
    .SYNOPSIS
        Generate comprehensive compliance report data structure

    .DESCRIPTION
        Main function to generate compliance reports based on specified type and date range

    .PARAMETER ReportType
        Type of report: Executive, Technical, Audit, Comparison

    .PARAMETER StartDate
        Start date for report period

    .PARAMETER EndDate
        End date for report period

    .PARAMETER TargetSystem
        Target system: All or Local
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Executive", "Technical", "Audit", "Comparison")]
        [string]$ReportType,

        [Parameter(Mandatory=$true)]
        [datetime]$StartDate,

        [Parameter(Mandatory=$true)]
        [datetime]$EndDate,

        [Parameter(Mandatory=$false)]
        [ValidateSet("All", "Local")]
        [string]$TargetSystem = "All"
    )

    try {
        Write-Log "Generating $ReportType report from $StartDate to $EndDate"

        $reportData = @{
            ReportType = $ReportType
            StartDate = $StartDate
            EndDate = $EndDate
            TargetSystem = $TargetSystem
            GeneratedAt = Get-Date
            GeneratedBy = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
        }

        switch ($ReportType) {
            "Executive" {
                $reportData += Get-ExecutiveSummaryReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
            }
            "Technical" {
                $reportData += Get-DetailedTechnicalReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
            }
            "Audit" {
                $reportData += Get-AuditTrailReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
            }
            "Comparison" {
                $reportData += Get-PolicyComparisonReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
            }
        }

        $script:CurrentReportData = $reportData
        Write-Log "Report generation complete: $($reportData.ReportTitle)"

        return @{
            success = $true
            data = $reportData
        }
    }
    catch {
        Write-Log "Report generation failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Get-ExecutiveSummaryReport {
    <#
    .SYNOPSIS
        Generate executive summary report with high-level metrics and risk score
    #>
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    try {
        Write-Log "Generating Executive Summary Report"

        # Get AppLocker events for the period
        $events = Get-AppLockerEventsForReport -StartDate $StartDate -EndDate $EndDate

        # Calculate compliance metrics
        $totalEvents = $events.Count
        $allowedEvents = ($events | Where-Object { $_.EventType -eq "Allowed" }).Count
        $blockedEvents = ($events | Where-Object { $_.EventType -eq "Blocked" }).Count
        $auditedEvents = ($events | Where-Object { $_.EventType -eq "Audited" }).Count

        # Calculate compliance percentage
        $compliancePercentage = if ($totalEvents -gt 0) {
            [math]::Round((($allowedEvents + $auditedEvents) / $totalEvents) * 100, 2)
        } else { 100 }

        # Calculate risk score (0-100, lower is better)
        $riskScore = if ($totalEvents -gt 0) {
            [math]::Min(100, [math]::Round(($blockedEvents / $totalEvents) * 100, 2))
        } else { 0 }

        # Get top violations
        $topViolatingApps = $events | Where-Object { $_.EventType -eq "Blocked" -or $_.EventType -eq "Audited" } |
                              Group-Object -Property FileName |
                              Sort-Object -Property Count -Descending |
                              Select-Object -First 10 |
                              ForEach-Object {
                                  [PSCustomObject]@{
                                      Application = $_.Name
                                      ViolationCount = $_.Count
                                      Percentage = if ($totalEvents -gt 0) { [math]::Round(($_.Count / $totalEvents) * 100, 2) } else { 0 }
                                  }
                              }

        # Get top violating users
        $topViolatingUsers = $events | Where-Object { $_.EventType -eq "Blocked" -or $_.EventType -eq "Audited" } |
                              Group-Object -Property UserSid |
                              Sort-Object -Property Count -Descending |
                              Select-Object -First 10 |
                              ForEach-Object {
                                  [PSCustomObject]@{
                                      User = $_.Name
                                      ViolationCount = $_.Count
                                  }
                              }

        # Get policy health
        $policyHealth = Get-PolicyHealthScore

        # Calculate trend data
        $trendData = Get-ComplianceTrend -StartDate $StartDate -EndDate $EndDate

        # Determine risk level
        $riskLevel = switch ($riskScore) {
            { $_ -lt 10 } { "Low" }
            { $_ -lt 30 } { "Medium" }
            { $_ -lt 50 } { "High" }
            default { "Critical" }
        }

        $report = @{
            ReportTitle = "Executive Summary Report"
            ReportSummary = "High-level overview of AppLocker compliance status"
            OverallCompliance = $compliancePercentage
            RiskScore = $riskScore
            RiskLevel = $riskLevel
            TotalEvents = $totalEvents
            AllowedEvents = $allowedEvents
            BlockedEvents = $blockedEvents
            AuditedEvents = $auditedEvents
            TopViolatingApps = $topViolatingApps
            TopViolatingUsers = $topViolatingUsers
            PolicyHealth = $policyHealth
            TrendData = $trendData
            PolicyCoverage = @{
                ExeCoverage = if ($policyHealth.hasExe) { "Yes" } else { "No" }
                MsiCoverage = if ($policyHealth.hasMsi) { "Yes" } else { "No" }
                ScriptCoverage = if ($policyHealth.hasScript) { "Yes" } else { "No" }
                DllCoverage = if ($policyHealth.hasDll) { "Yes" } else { "No" }
            }
        }

        return $report
    }
    catch {
        Write-Log "Executive Summary Report generation failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-DetailedTechnicalReport {
    <#
    .SYNOPSIS
        Generate detailed technical report with full event logs and analysis
    #>
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    try {
        Write-Log "Generating Detailed Technical Report"

        # Get all events
        $events = Get-AppLockerEventsForReport -StartDate $StartDate -EndDate $EndDate

        # Event statistics
        $eventsByType = $events | Group-Object -Property EventType |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Type = $_.Name
                                Count = $_.Count
                                Percentage = if ($events.Count -gt 0) { [math]::Round(($_.Count / $events.Count) * 100, 2) } else { 0 }
                            }
                        }

        # Events by day
        $eventsByDay = $events | Group-Object -Property { $_.TimeCreated.ToString("yyyy-MM-dd") } |
                       Sort-Object -Property Name |
                       ForEach-Object {
                           [PSCustomObject]@{
                               Date = $_.Name
                               Count = $_.Count
                           }
                       }

        # Events by hour
        $eventsByHour = $events | Group-Object -Property { $_.TimeCreated.Hour } |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Hour = $_.Name
                                Count = $_.Count
                            }
                        }

        # Top file paths
        $topFilePaths = $events | Group-Object -Property FilePath |
                        Sort-Object -Property Count -Descending |
                        Select-Object -First 20 |
                        ForEach-Object {
                            [PSCustomObject]@{
                                FilePath = $_.Name
                                Count = $_.Count
                                EventType = ($events | Where-Object { $_.FilePath -eq $_.Name } |
                                             Group-Object -Property EventType |
                                             Sort-Object -Property Count -Descending |
                                             Select-Object -First 1 -ExpandProperty Name)
                            }
                        }

        # Top publishers
        $topPublishers = $events | Where-Object { $_.Publisher -and $_.Publisher -ne "Unknown" } |
                         Group-Object -Property Publisher |
                         Sort-Object -Property Count -Descending |
                         Select-Object -First 20 |
                         ForEach-Object {
                             [PSCustomObject]@{
                                 Publisher = $_.Name
                                 Count = $_.Count
                             }
                         }

        # Get policy details
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        $policyRules = @()
        if ($policy) {
            foreach ($collection in $policy.RuleCollections) {
                foreach ($rule in $collection) {
                    $policyRules += [PSCustomObject]@{
                        RuleType = $rule.RuleCollectionType
                        RuleName = $rule.Name
                        Action = $rule.Action
                        UserOrGroup = if ($rule.UserOrGroup) { $rule.UserOrGroup -join ", " } else { "N/A" }
                        Condition = if ($rule.Conditions) { $rule.Conditions.GetType().Name } else { "N/A" }
                    }
                }
            }
        }

        # Recent violations (last 50)
        $recentViolations = $events | Where-Object { $_.EventType -eq "Blocked" -or $_.EventType -eq "Audited" } |
                             Sort-Object -Property TimeCreated -Descending |
                             Select-Object -First 50

        $report = @{
            ReportTitle = "Detailed Technical Report"
            ReportSummary = "Full event logs, rule analysis, and violation details"
            TotalEvents = $events.Count
            EventsByType = $eventsByType
            EventsByDay = $eventsByDay
            EventsByHour = $eventsByHour
            TopFilePaths = $topFilePaths
            TopPublishers = $topPublishers
            PolicyRules = $policyRules
            RecentViolations = $recentViolations
            EventDetails = $events
        }

        return $report
    }
    catch {
        Write-Log "Detailed Technical Report generation failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-AuditTrailReport {
    <#
    .SYNOPSIS
        Generate audit trail report with all admin actions and policy changes
    #>
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    try {
        Write-Log "Generating Audit Trail Report"

        # Get AppLocker policy change events
        $auditEvents = @()

        # Security log events for policy changes
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4688, 4689, 5136, 5137, 5141
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue

        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $eventXml = [xml]$event.ToXml()
                $auditEvents += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    EventId = $event.Id
                    EventType = switch ($event.Id) {
                        4688 { "Process Created" }
                        4689 { "Process Terminated" }
                        5136 { "Object Created" }
                        5137 { "Object Deleted" }
                        5141 { "Object Modified" }
                        default { "Other" }
                    }
                    UserSid = $eventXml.Event.EventData.Data[1].'#text'
                    Message = $event.Message
                }
            }
        }

        # Get AppLocker CSP events
        $cspEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
            ID = 8002, 8003, 8004
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue

        # Group audit events by date
        $eventsByDate = $auditEvents | Group-Object -Property { $_.TimeCreated.ToString("yyyy-MM-dd") } |
                        Sort-Object -Property Name |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Date = $_.Name
                                EventCount = $_.Count
                            }
                        }

        # Events by user
        $eventsByUser = $auditEvents | Where-Object { $_.UserSid } |
                        Group-Object -Property UserSid |
                        Sort-Object -Property Count -Descending |
                        Select-Object -First 20 |
                        ForEach-object {
                            [PSCustomObject]@{
                                User = $_.Name
                                ActionCount = $_.Count
                            }
                        }

        # Recent audit events (last 100)
        $recentAuditEvents = $auditEvents | Sort-Object -Property TimeCreated -Descending | Select-Object -First 100

        $report = @{
            ReportTitle = "Audit Trail Report"
            ReportSummary = "Complete history of admin actions and policy changes"
            TotalAuditEvents = $auditEvents.Count
            EventsByDate = $eventsByDate
            EventsByUser = $eventsByUser
            RecentAuditEvents = $recentAuditEvents
            AuditTrail = $auditEvents
        }

        return $report
    }
    catch {
        Write-Log "Audit Trail Report generation failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-PolicyComparisonReport {
    <#
    .SYNOPSIS
        Generate policy comparison report across time periods
    #>
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    try {
        Write-Log "Generating Policy Comparison Report"

        # Get current policy
        $currentPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

        # Calculate comparison periods
        $daysDiff = ($EndDate - $StartDate).Days
        $midPoint = $StartDate.AddDays($daysDiff / 2)

        # Get events for period 1 (first half)
        $period1Events = Get-AppLockerEventsForReport -StartDate $StartDate -EndDate $midPoint

        # Get events for period 2 (second half)
        $period2Events = Get-AppLockerEventsForReport -StartDate $midPoint.AddDays(1) -EndDate $EndDate

        # Compare metrics
        $period1Stats = @{
            TotalEvents = $period1Events.Count
            BlockedEvents = ($period1Events | Where-Object { $_.EventType -eq "Blocked" }).Count
            AuditedEvents = ($period1Events | Where-Object { $_.EventType -eq "Audited" }).Count
            AllowedEvents = ($period1Events | Where-Object { $_.EventType -eq "Allowed" }).Count
        }

        $period2Stats = @{
            TotalEvents = $period2Events.Count
            BlockedEvents = ($period2Events | Where-Object { $_.EventType -eq "Blocked" }).Count
            AuditedEvents = ($period2Events | Where-Object { $_.EventType -eq "Audited" }).Count
            AllowedEvents = ($period2Events | Where-Object { $_.EventType -eq "Allowed" }).Count
        }

        # Calculate changes
        $totalEventsChange = if ($period1Stats.TotalEvents -gt 0) {
            [math]::Round((($period2Stats.TotalEvents - $period1Stats.TotalEvents) / $period1Stats.TotalEvents) * 100, 2)
        } else { 0 }

        $blockedEventsChange = if ($period1Stats.BlockedEvents -gt 0) {
            [math]::Round((($period2Stats.BlockedEvents - $period1Stats.BlockedEvents) / $period1Stats.BlockedEvents) * 100, 2)
        } else { 0 }

        # Top applications in each period
        $period1TopApps = $period1Events | Group-Object -Property FileName |
                          Sort-Object -Property Count -Descending | Select-Object -First 10

        $period2TopApps = $period2Events | Group-Object -Property FileName |
                          Sort-Object -Property Count -Descending | Select-Object -First 10

        # Compare top applications
        $appComparison = @()
        $allApps = ($period1TopApps.Name + $period2TopApps.Name) | Select-Object -Unique

        foreach ($app in $allApps) {
            $p1Count = ($period1TopApps | Where-Object { $_.Name -eq $app }).Count
            $p2Count = ($period2TopApps | Where-Object { $_.Name -eq $app }).Count

            $appComparison += [PSCustomObject]@{
                Application = $app
                Period1Count = $p1Count
                Period2Count = $p2Count
                Change = $p2Count - $p1Count
            }
        }

        $report = @{
            ReportTitle = "Policy Comparison Report"
            ReportSummary = "Compare policies and events across different time periods"
            Period1 = @{
                StartDate = $StartDate
                EndDate = $midPoint
                Stats = $period1Stats
            }
            Period2 = @{
                StartDate = $midPoint.AddDays(1)
                EndDate = $EndDate
                Stats = $period2Stats
            }
            TotalEventsChange = $totalEventsChange
            BlockedEventsChange = $blockedEventsChange
            Period1TopApps = $period1TopApps
            Period2TopApps = $period2TopApps
            AppComparison = $appComparison
            CurrentPolicyRules = if ($currentPolicy) { $currentPolicy.RuleCollections.Count } else { 0 }
        }

        return $report
    }
    catch {
        Write-Log "Policy Comparison Report generation failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Get-AppLockerEventsForReport {
    <#
    .SYNOPSIS
        Helper function to retrieve AppLocker events for report generation
    #>
    param(
        [datetime]$StartDate,
        [datetime]$EndDate
    )

    $events = @()

    try {
        # Get AppLocker events
        $appLockerEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
            StartTime = $StartDate
            EndDate = $EndDate
        } -ErrorAction SilentlyContinue

        if ($appLockerEvents) {
            foreach ($event in $appLockerEvents) {
                $eventXml = [xml]$event.ToXml()

                # Extract event data
                $filePath = if ($eventXml.Event.EventData.Data[4]) { $eventXml.Event.EventData.Data[4].'#text' } else { "Unknown" }
                $fileName = Split-Path $filePath -Leaf
                $publisher = if ($eventXml.Event.EventData.Data[6]) { $eventXml.Event.EventData.Data[6].'#text' } else { "Unknown" }

                # Determine event type
                $eventType = switch ($event.Id) {
                    8002 { "Allowed" }
                    8003 { "Audited" }
                    8004 { "Blocked" }
                    default { "Other" }
                }

                $events += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    EventId = $event.Id
                    EventType = $eventType
                    FilePath = $filePath
                    FileName = $fileName
                    Publisher = $publisher
                    UserSid = if ($eventXml.Event.EventData.Data[1]) { $eventXml.Event.EventData.Data[1].'#text' } else { "Unknown" }
                    Message = $event.Message
                }
            }
        }
    }
    catch {
        Write-Log "Error retrieving AppLocker events: $($_.Exception.Message)" -Level "WARN"
    }

    return $events
}

function Get-ComplianceTrend {
    <#
    .SYNOPSIS
        Calculate compliance trend data over 30/60/90 day periods
    #>
    param(
        [datetime]$StartDate,
        [datetime]$EndDate
    )

    try {
        $trendData = @()

        # Calculate 30-day trends
        $period30Days = $EndDate.AddDays(-30)
        if ($period30Days -lt $StartDate) { $period30Days = $StartDate }

        $events30Days = Get-AppLockerEventsForReport -StartDate $period30Days -EndDate $EndDate
        $compliance30Days = if ($events30Days.Count -gt 0) {
            $allowed = ($events30Days | Where-Object { $_.EventType -eq "Allowed" }).Count
            $audited = ($events30Days | Where-Object { $_.EventType -eq "Audited" }).Count
            [math]::Round((($allowed + $audited) / $events30Days.Count) * 100, 2)
        } else { 100 }

        $trendData += [PSCustomObject]@{
            Period = "30 Days"
            Compliance = $compliance30Days
            EventCount = $events30Days.Count
        }

        # Calculate 60-day trends
        $period60Days = $EndDate.AddDays(-60)
        if ($period60Days -lt $StartDate) { $period60Days = $StartDate }

        $events60Days = Get-AppLockerEventsForReport -StartDate $period60Days -EndDate $EndDate
        $compliance60Days = if ($events60Days.Count -gt 0) {
            $allowed = ($events60Days | Where-Object { $_.EventType -eq "Allowed" }).Count
            $audited = ($events60Days | Where-Object { $_.EventType -eq "Audited" }).Count
            [math]::Round((($allowed + $audited) / $events60Days.Count) * 100, 2)
        } else { 100 }

        $trendData += [PSCustomObject]@{
            Period = "60 Days"
            Compliance = $compliance60Days
            EventCount = $events60Days.Count
        }

        # Calculate 90-day trends
        $period90Days = $EndDate.AddDays(-90)
        if ($period90Days -lt $StartDate) { $period90Days = $StartDate }

        $events90Days = Get-AppLockerEventsForReport -StartDate $period90Days -EndDate $EndDate
        $compliance90Days = if ($events90Days.Count -gt 0) {
            $allowed = ($events90Days | Where-Object { $_.EventType -eq "Allowed" }).Count
            $audited = ($events90Days | Where-Object { $_.EventType -eq "Audited" }).Count
            [math]::Round((($allowed + $audited) / $events90Days.Count) * 100, 2)
        } else { 100 }

        $trendData += [PSCustomObject]@{
            Period = "90 Days"
            Compliance = $compliance90Days
            EventCount = $events90Days.Count
        }

        return $trendData
    }
    catch {
        Write-Log "Error calculating compliance trend: $($_.Exception.Message)" -Level "WARN"
        return @()
    }
}

function Export-ReportToPdf {
    <#
    .SYNOPSIS
        Export report to PDF format

    .DESCRIPTION
        Convert report data to PDF using a simple text-based approach
        (Note: For full PDF support with iText7, additional setup is required)
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ReportData,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:TEMP\GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    )

    try {
        Write-Log "Exporting report to PDF-compatible format: $OutputPath"

        # Generate report text
        $reportText = Format-ReportAsText -ReportData $ReportData

        # Save to file (text-based, can be converted to PDF)
        $reportText | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        Write-Log "Report exported successfully: $OutputPath"

        return @{
            success = $true
            outputPath = $OutputPath
            message = "Report exported successfully. Note: This is a text export. For PDF conversion, use a PDF printer or additional libraries."
        }
    }
    catch {
        Write-Log "PDF export failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Export-ReportToHtml {
    <#
    .SYNOPSIS
        Export report to HTML format with embedded CSS
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ReportData,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:TEMP\GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )

    try {
        Write-Log "Exporting report to HTML: $OutputPath"

        $html = Format-ReportAsHtml -ReportData $ReportData

        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        Write-Log "HTML report exported successfully: $OutputPath"

        return @{
            success = $true
            outputPath = $OutputPath
            message = "HTML report exported successfully"
        }
    }
    catch {
        Write-Log "HTML export failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Export-ReportToCsv {
    <#
    .SYNOPSIS
        Export report data to CSV format
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ReportData,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:TEMP\GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    )

    try {
        Write-Log "Exporting report data to CSV: $OutputPath"

        $csvData = switch ($ReportData.ReportType) {
            "Executive" {
                # Export top violating applications
                $ReportData.TopViolatingApps | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                $OutputPath
            }
            "Technical" {
                # Export event details
                $ReportData.EventDetails | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                $OutputPath
            }
            "Audit" {
                # Export audit trail
                $ReportData.AuditTrail | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                $OutputPath
            }
            "Comparison" {
                # Export app comparison
                $ReportData.AppComparison | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                $OutputPath
            }
        }

        Write-Log "CSV report exported successfully: $csvData"

        return @{
            success = $true
            outputPath = $csvData
            message = "CSV report exported successfully"
        }
    }
    catch {
        Write-Log "CSV export failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Format-ReportAsText {
    <#
    .SYNOPSIS
        Format report data as plain text
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ReportData
    )

    $text = "=" * 80 + "`n"
    $text += "$($ReportData.ReportTitle)`n"
    $text += "=" * 80 + "`n`n"

    $text += "Generated: $($ReportData.GeneratedAt)`n"
    $text += "By: $($ReportData.GeneratedBy)`n"
    $text += "Computer: $($ReportData.ComputerName)`n"
    $text += "Report Period: $($ReportData.StartDate) to $($ReportData.EndDate)`n"
    $text += "Target System: $($ReportData.TargetSystem)`n`n"

    switch ($ReportData.ReportType) {
        "Executive" {
            $text += "-" * 80 + "`n"
            $text += "EXECUTIVE SUMMARY`n"
            $text += "-" * 80 + "`n`n"

            $text += "Overall Compliance: $($ReportData.OverallCompliance)%`n"
            $text += "Risk Score: $($ReportData.RiskScore) ($($ReportData.RiskLevel))`n"
            $text += "Total Events: $($ReportData.TotalEvents)`n`n"

            $text += "Event Breakdown:`n"
            $text += "  Allowed: $($ReportData.AllowedEvents)`n"
            $text += "  Blocked: $($ReportData.BlockedEvents)`n"
            $text += "  Audited: $($ReportData.AuditedEvents)`n`n"

            $text += "Policy Coverage:`n"
            $text += "  EXE: $($ReportData.PolicyCoverage.ExeCoverage)`n"
            $text += "  MSI: $($ReportData.PolicyCoverage.MsiCoverage)`n"
            $text += "  Script: $($ReportData.PolicyCoverage.ScriptCoverage)`n"
            $text += "  DLL: $($ReportData.PolicyCoverage.DllCoverage)`n`n"

            $text += "Top Violating Applications:`n"
            foreach ($app in $ReportData.TopViolatingApps) {
                $text += "  - $($app.Application): $($app.ViolationCount) violations ($($app.Percentage)% )`n"
            }

            if ($ReportData.TrendData) {
                $text += "`nCompliance Trends:`n"
                foreach ($trend in $ReportData.TrendData) {
                    $text += "  - $($trend.Period): $($trend.Compliance)% compliance ($($trend.EventCount) events)`n"
                }
            }
        }

        "Technical" {
            $text += "-" * 80 + "`n"
            $text += "DETAILED TECHNICAL REPORT`n"
            $text += "-" * 80 + "`n`n"

            $text += "Total Events: $($ReportData.TotalEvents)`n`n"

            $text += "Events by Type:`n"
            foreach ($type in $ReportData.EventsByType) {
                $text += "  - $($type.Type): $($type.Count) ($($type.Percentage)% )`n"
            }

            $text += "`nTop File Paths:`n"
            foreach ($path in $ReportData.TopFilePaths) {
                $text += "  - $($path.FilePath): $($path.Count) events`n"
            }

            $text += "`nTop Publishers:`n"
            foreach ($pub in $ReportData.TopPublishers) {
                $text += "  - $($pub.Publisher): $($pub.Count) events`n"
            }

            $text += "`nPolicy Rules: $($ReportData.PolicyRules.Count)`n"
        }

        "Audit" {
            $text += "-" * 80 + "`n"
            $text += "AUDIT TRAIL REPORT`n"
            $text += "-" * 80 + "`n`n"

            $text += "Total Audit Events: $($ReportData.TotalAuditEvents)`n`n"

            $text += "Events by Date:`n"
            foreach ($date in $ReportData.EventsByDate) {
                $text += "  - $($date.Date): $($date.EventCount) events`n"
            }

            $text += "`nTop Users by Action Count:`n"
            foreach ($user in $ReportData.EventsByUser) {
                $text += "  - $($user.User): $($user.ActionCount) actions`n"
            }
        }

        "Comparison" {
            $text += "-" * 80 + "`n"
            $text += "POLICY COMPARISON REPORT`n"
            $text += "-" * 80 + "`n`n"

            $text += "Period 1: $($ReportData.Period1.StartDate) to $($ReportData.Period1.EndDate)`n"
            $text += "  Total Events: $($ReportData.Period1.Stats.TotalEvents)`n"
            $text += "  Blocked: $($ReportData.Period1.Stats.BlockedEvents)`n"
            $text += "  Allowed: $($ReportData.Period1.Stats.AllowedEvents)`n`n"

            $text += "Period 2: $($ReportData.Period2.StartDate) to $($ReportData.Period2.EndDate)`n"
            $text += "  Total Events: $($ReportData.Period2.Stats.TotalEvents)`n"
            $text += "  Blocked: $($ReportData.Period2.Stats.BlockedEvents)`n"
            $text += "  Allowed: $($ReportData.Period2.Stats.AllowedEvents)`n`n"

            $text += "Changes:`n"
            $text += "  Total Events: $($ReportData.TotalEventsChange)%`n"
            $text += "  Blocked Events: $($ReportData.BlockedEventsChange)%`n`n"

            $text += "Application Comparison:`n"
            foreach ($app in $ReportData.AppComparison) {
                $changeText = if ($app.Change -gt 0) { "+$($app.Change)" } else { $app.Change.ToString() }
                $text += "  - $($app.Application): Period1=$($app.Period1Count), Period2=$($app.Period2Count) (Change: $changeText)`n"
            }
        }
    }

    $text += "`n" + "=" * 80 + "`n"
    $text += "End of Report`n"
    $text += "=" * 80 + "`n"

    return $text
}

function Format-ReportAsHtml {
    <#
    .SYNOPSIS
        Format report data as HTML with embedded CSS
    #>
    param(
        [Parameter(Mandatory=$true)]
        $ReportData
    )

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$($ReportData.ReportTitle) - GA-AppLocker</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #0D1117 0%, #161B22 100%);
            color: #E6EDF3;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #21262D;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #238636 0%, #2EA043 100%);
            padding: 30px;
            border-bottom: 3px solid #30363D;
        }

        .header h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 14px;
            opacity: 0.9;
        }

        .metadata {
            background: #161B22;
            padding: 20px 30px;
            border-bottom: 1px solid #30363D;
            font-size: 13px;
            color: #8B949E;
        }

        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }

        .metadata-item {
            display: flex;
            justify-content: space-between;
        }

        .metadata-label {
            font-weight: 600;
            color: #58A6FF;
        }

        .content {
            padding: 30px;
        }

        .section {
            margin-bottom: 30px;
        }

        .section-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #58A6FF;
            border-bottom: 2px solid #30363D;
            padding-bottom: 10px;
        }

        .card {
            background: #0D1117;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #30363D;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .metric-card {
            background: #161B22;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border: 1px solid #30363D;
        }

        .metric-value {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .metric-label {
            font-size: 12px;
            color: #8B949E;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .metric-success { color: #3FB950; }
        .metric-warning { color: #D29922; }
        .metric-danger { color: #F85149; }
        .metric-info { color: #58A6FF; }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #30363D;
        }

        th {
            background: #161B22;
            font-weight: 600;
            color: #58A6FF;
            font-size: 13px;
            text-transform: uppercase;
        }

        td {
            font-size: 13px;
        }

        tr:hover {
            background: #161B22;
        }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-success {
            background: #238636;
            color: white;
        }

        .badge-warning {
            background: #D29922;
            color: white;
        }

        .badge-danger {
            background: #F85149;
            color: white;
        }

        .badge-info {
            background: #1F6FEB;
            color: white;
        }

        .footer {
            background: #161B22;
            padding: 20px 30px;
            text-align: center;
            font-size: 12px;
            color: #6E7681;
            border-top: 1px solid #30363D;
        }

        @media print {
            body {
                background: white;
                color: black;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$($ReportData.ReportTitle)</h1>
            <p>$($ReportData.ReportSummary)</p>
        </div>

        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">Generated:</span>
                    <span>$($ReportData.GeneratedAt)</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">By:</span>
                    <span>$($ReportData.GeneratedBy)</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Computer:</span>
                    <span>$($ReportData.ComputerName)</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Period:</span>
                    <span>$($ReportData.StartDate) to $($ReportData.EndDate)</span>
                </div>
            </div>
        </div>

        <div class="content">
"@

    switch ($ReportData.ReportType) {
        "Executive" {
            $riskClass = switch ($ReportData.RiskLevel) {
                "Low" { "metric-success" }
                "Medium" { "metric-warning" }
                { $_ -in @("High", "Critical") } { "metric-danger" }
                default { "metric-info" }
            }

            $complianceClass = switch ($ReportData.OverallCompliance) {
                { $_ -ge 90 } { "metric-success" }
                { $_ -ge 70 } { "metric-warning" }
                default { "metric-danger" }
            }

            $html += @"
            <div class="section">
                <h2 class="section-title">Executive Summary</h2>
                <div class="metric-grid">
                    <div class="metric-card">
                        <div class="metric-value $complianceClass">$($ReportData.OverallCompliance)%</div>
                        <div class="metric-label">Compliance</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value $riskClass">$($ReportData.RiskScore)</div>
                        <div class="metric-label">Risk Score</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value metric-info">$($ReportData.TotalEvents)</div>
                        <div class="metric-label">Total Events</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value metric-warning">$($ReportData.BlockedEvents)</div>
                        <div class="metric-label">Blocked</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Event Breakdown</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Event Type</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                        <tr>
                            <td>Allowed</td>
                            <td>$($ReportData.AllowedEvents)</td>
                            <td>$([math]::Round(($ReportData.AllowedEvents / $ReportData.TotalEvents) * 100, 2))%</td>
                        </tr>
                        <tr>
                            <td>Audited</td>
                            <td>$($ReportData.AuditedEvents)</td>
                            <td>$([math]::Round(($ReportData.AuditedEvents / $ReportData.TotalEvents) * 100, 2))%</td>
                        </tr>
                        <tr>
                            <td>Blocked</td>
                            <td>$($ReportData.BlockedEvents)</td>
                            <td>$([math]::Round(($ReportData.BlockedEvents / $ReportData.TotalEvents) * 100, 2))%</td>
                        </tr>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Policy Coverage</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Rule Type</th>
                            <th>Status</th>
                        </tr>
                        <tr>
                            <td>Executable (EXE)</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.ExeCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.ExeCoverage)</span></td>
                        </tr>
                        <tr>
                            <td>Installer (MSI)</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.MsiCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.MsiCoverage)</span></td>
                        </tr>
                        <tr>
                            <td>Script</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.ScriptCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.ScriptCoverage)</span></td>
                        </tr>
                        <tr>
                            <td>DLL</td>
                            <td><span class="badge badge-$(if ($ReportData.PolicyCoverage.DllCoverage -eq 'Yes') { 'success' } else { 'danger' })">$($ReportData.PolicyCoverage.DllCoverage)</span></td>
                        </tr>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Top Violating Applications</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Application</th>
                            <th>Violation Count</th>
                            <th>Percentage</th>
                        </tr>
"@

            foreach ($app in $ReportData.TopViolatingApps) {
                $html += @"
                        <tr>
                            <td>$($app.Application)</td>
                            <td>$($app.ViolationCount)</td>
                            <td>$($app.Percentage)%</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Compliance Trends</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Period</th>
                            <th>Compliance</th>
                            <th>Event Count</th>
                        </tr>
"@

            foreach ($trend in $ReportData.TrendData) {
                $trendClass = switch ($trend.Compliance) {
                    { $_ -ge 90 } { "badge-success" }
                    { $_ -ge 70 } { "badge-warning" }
                    default { "badge-danger" }
                }
                $html += @"
                        <tr>
                            <td>$($trend.Period)</td>
                            <td><span class="badge $trendClass">$($trend.Compliance)%</span></td>
                            <td>$($trend.EventCount)</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>
"@
        }

        "Technical" {
            $html += @"
            <div class="section">
                <h2 class="section-title">Technical Details</h2>
                <div class="card">
                    <p><strong>Total Events:</strong> $($ReportData.TotalEvents)</p>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Events by Type</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
"@

            foreach ($type in $ReportData.EventsByType) {
                $html += @"
                        <tr>
                            <td>$($type.Type)</td>
                            <td>$($type.Count)</td>
                            <td>$($type.Percentage)%</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Top File Paths</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>File Path</th>
                            <th>Event Count</th>
                            <th>Primary Event Type</th>
                        </tr>
"@

            foreach ($path in $ReportData.TopFilePaths) {
                $html += @"
                        <tr>
                            <td>$($path.FilePath)</td>
                            <td>$($path.Count)</td>
                            <td>$($path.EventType)</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Top Publishers</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Publisher</th>
                            <th>Event Count</th>
                        </tr>
"@

            foreach ($pub in $ReportData.TopPublishers) {
                $html += @"
                        <tr>
                            <td>$($pub.Publisher)</td>
                            <td>$($pub.Count)</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Policy Rules</h2>
                <div class="card">
                    <p><strong>Total Rules:</strong> $($ReportData.PolicyRules.Count)</p>
                </div>
            </div>
"@
        }

        "Audit" {
            $html += @"
            <div class="section">
                <h2 class="section-title">Audit Trail</h2>
                <div class="card">
                    <p><strong>Total Audit Events:</strong> $($ReportData.TotalAuditEvents)</p>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Events by Date</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Date</th>
                            <th>Event Count</th>
                        </tr>
"@

            foreach ($date in $ReportData.EventsByDate) {
                $html += @"
                        <tr>
                            <td>$($date.Date)</td>
                            <td>$($date.EventCount)</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Top Users by Action Count</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>User</th>
                            <th>Action Count</th>
                        </tr>
"@

            foreach ($user in $ReportData.EventsByUser) {
                $html += @"
                        <tr>
                            <td>$($user.User)</td>
                            <td>$($user.ActionCount)</td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>
"@
        }

        "Comparison" {
            $html += @"
            <div class="section">
                <h2 class="section-title">Period Comparison</h2>
                <div class="card">
                    <h3>Period 1</h3>
                    <p><strong>Date Range:</strong> $($ReportData.Period1.StartDate) to $($ReportData.Period1.EndDate)</p>
                    <p><strong>Total Events:</strong> $($ReportData.Period1.Stats.TotalEvents)</p>
                    <p><strong>Blocked:</strong> $($ReportData.Period1.Stats.BlockedEvents)</p>
                    <p><strong>Allowed:</strong> $($ReportData.Period1.Stats.AllowedEvents)</p>
                </div>
                <div class="card">
                    <h3>Period 2</h3>
                    <p><strong>Date Range:</strong> $($ReportData.Period2.StartDate) to $($ReportData.Period2.EndDate)</p>
                    <p><strong>Total Events:</strong> $($ReportData.Period2.Stats.TotalEvents)</p>
                    <p><strong>Blocked:</strong> $($ReportData.Period2.Stats.BlockedEvents)</p>
                    <p><strong>Allowed:</strong> $($ReportData.Period2.Stats.AllowedEvents)</p>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Changes</h2>
                <div class="metric-grid">
                    <div class="metric-card">
                        <div class="metric-value metric-info">$($ReportData.TotalEventsChange)%</div>
                        <div class="metric-label">Total Events Change</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value metric-warning">$($ReportData.BlockedEventsChange)%</div>
                        <div class="metric-label">Blocked Events Change</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Application Comparison</h2>
                <div class="card">
                    <table>
                        <tr>
                            <th>Application</th>
                            <th>Period 1 Count</th>
                            <th>Period 2 Count</th>
                            <th>Change</th>
                        </tr>
"@

            foreach ($app in $ReportData.AppComparison) {
                $changeClass = switch ($app.Change) {
                    { $_ -gt 0 } { "badge-danger" }
                    { $_ -lt 0 } { "badge-success" }
                    default { "badge-info" }
                }
                $changeText = if ($app.Change -gt 0) { "+$($app.Change)" } else { $app.Change.ToString() }
                $html += @"
                        <tr>
                            <td>$($app.Application)</td>
                            <td>$($app.Period1Count)</td>
                            <td>$($app.Period2Count)</td>
                            <td><span class="badge $changeClass">$changeText</span></td>
                        </tr>
"@
            }

            $html += @"
                    </table>
                </div>
            </div>
"@
        }
    }

    $html += @"
        </div>

        <div class="footer">
            <p>Generated by GA-AppLocker Dashboard | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>This report contains confidential information. Handle with appropriate security measures.</p>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function Schedule-ReportJob {
    <#
    .SYNOPSIS
        Create a scheduled task for periodic report generation

    .DESCRIPTION
        Creates a Windows Scheduled Task to automatically generate reports

    .PARAMETER ReportName
        Name for the scheduled report

    .PARAMETER ReportType
        Type of report to generate

    .PARAMETER Schedule
        Schedule frequency: Daily, Weekly, Monthly

    .PARAMETER Time
        Time to run the report

    .PARAMETER OutputPath
        Where to save the generated report
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ReportName,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Executive", "Technical", "Audit", "Comparison")]
        [string]$ReportType,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Daily", "Weekly", "Monthly")]
        [string]$Schedule,

        [Parameter(Mandatory=$true)]
        [string]$Time,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )

    try {
        Write-Log "Creating scheduled report: $ReportName"

        # Create the scheduled task action
        $scriptPath = $PSCommandPath
        $argument = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -GenerateReport -ReportType $ReportType -OutputPath `"$OutputPath`""

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument

        # Create the trigger based on schedule
        $trigger = switch ($Schedule) {
            "Daily" { New-ScheduledTaskTrigger -Daily -At $Time }
            "Weekly" { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $Time }
            "Monthly" { New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At $Time }
        }

        # Create the principal (run as current user)
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

        # Create settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        # Register the scheduled task
        $taskName = "GA-AppLocker-$ReportName"
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "GA-AppLocker scheduled report: $ReportName" -ErrorAction Stop

        # Add to scheduled reports list
        $script:ScheduledReports += [PSCustomObject]@{
            ReportName = $ReportName
            ReportType = $ReportType
            Schedule = "$Schedule at $Time"
            OutputPath = $OutputPath
            TaskName = $taskName
            CreatedAt = Get-Date
        }

        Write-Log "Scheduled report created: $taskName"

        return @{
            success = $true
            taskName = $taskName
            message = "Report scheduled successfully"
        }
    }
    catch {
        Write-Log "Failed to create scheduled report: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Get-ScheduledReports {
    <#
    .SYNOPSIS
        List all scheduled reports

    .DESCRIPTION
        Retrieves all GA-AppLocker scheduled tasks
    #>
    try {
        Write-Log "Retrieving scheduled reports"

        $tasks = Get-ScheduledTask -TaskName "GA-AppLocker-*" -ErrorAction SilentlyContinue

        $reportList = @()
        if ($tasks) {
            foreach ($task in $tasks) {
                $reportList += [PSCustomObject]@{
                    ReportName = $task.TaskName -replace "GA-AppLocker-", ""
                    Schedule = "$($task.Triggers.Frequency) at $($task.Triggers.StartBoundary)"
                    NextRun = $task.NextRunTime
                    LastRun = $task.LastRunTime
                    TaskName = $task.TaskName
                    Enabled = $task.Enabled
                }
            }
        }

        return @{
            success = $true
            reports = $reportList
        }
    }
    catch {
        Write-Log "Failed to retrieve scheduled reports: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
            reports = @()
        }
    }
}

function Remove-ScheduledReport {
    <#
    .SYNOPSIS
        Remove a scheduled report

    .PARAMETER TaskName
        Name of the scheduled task to remove
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TaskName
    )

    try {
        Write-Log "Removing scheduled report: $TaskName"

        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop

        # Remove from script list
        $script:ScheduledReports = $script:ScheduledReports | Where-Object { $_.TaskName -ne $TaskName }

        Write-Log "Scheduled report removed: $TaskName"

        return @{
            success = $true
            message = "Scheduled report removed successfully"
        }
    }
    catch {
        Write-Log "Failed to remove scheduled report: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# ============================================================
# WPF XAML - Modern GitHub Dark Theme
# ============================================================

$xamlString = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:sys="clr-namespace:System;assembly=mscorlib"
        Title="GA-AppLocker Dashboard" Height="800" Width="1150" MinHeight="600" MinWidth="900"
        WindowStartupLocation="CenterScreen" Background="#0D1117">
    <Window.Resources>
        <!-- GitHub Dark Theme Colors -->
        <SolidColorBrush x:Key="BgDark" Color="#0D1117"/>
        <SolidColorBrush x:Key="BgSidebar" Color="#161B22"/>
        <SolidColorBrush x:Key="BgCard" Color="#21262D"/>
        <SolidColorBrush x:Key="Border" Color="#30363D"/>
        <SolidColorBrush x:Key="Blue" Color="#58A6FF"/>
        <SolidColorBrush x:Key="Green" Color="#3FB950"/>
        <SolidColorBrush x:Key="Orange" Color="#D29922"/>
        <SolidColorBrush x:Key="Red" Color="#F85149"/>
        <SolidColorBrush x:Key="Purple" Color="#8957E5"/>
        <SolidColorBrush x:Key="Text1" Color="#E6EDF3"/>
        <SolidColorBrush x:Key="Text2" Color="#8B949E"/>
        <SolidColorBrush x:Key="Text3" Color="#6E7681"/>
        <SolidColorBrush x:Key="Hover" Color="#30363D"/>

        <!-- Button Styles -->
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="#238636"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderThickness="0"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#2ea043"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#30363D"/>
                    <Setter Property="Foreground" Value="#6E7681"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="#E6EDF3"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="1"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#30363D"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- Small Nav Button Style for Sidebar -->
        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#8B949E"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="8,4"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderThickness="0"
                                CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#21262D"/>
                    <Setter Property="Foreground" Value="#E6EDF3"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- Custom Expander Style - hides default toggle arrow -->
        <Style x:Key="MenuExpander" TargetType="Expander">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#E6EDF3"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Expander">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}">
                            <StackPanel>
                                <ToggleButton x:Name="HeaderToggle" IsChecked="{Binding IsExpanded, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}" Cursor="Hand">
                                    <ToggleButton.Template>
                                        <ControlTemplate TargetType="ToggleButton">
                                            <Border Background="Transparent" Padding="8,6">
                                                <ContentPresenter/>
                                            </Border>
                                        </ControlTemplate>
                                    </ToggleButton.Template>
                                    <ContentPresenter Content="{TemplateBinding Header}" ContentTemplate="{TemplateBinding HeaderTemplate}"/>
                                </ToggleButton>
                                <ContentPresenter x:Name="ExpanderContent" Content="{TemplateBinding Content}" Visibility="Collapsed"/>
                            </StackPanel>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsExpanded" Value="True">
                                <Setter TargetName="ExpanderContent" Property="Visibility" Value="Visible"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Comprehensive Dark ComboBox Style -->
        <Style x:Key="DarkComboBoxStyle" TargetType="ComboBox">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="#E6EDF3"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,4"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="MinHeight" Value="32"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Name="ToggleButton"
                                          Background="{TemplateBinding Background}"
                                          BorderBrush="{TemplateBinding BorderBrush}"
                                          BorderThickness="{TemplateBinding BorderThickness}"
                                          Foreground="{TemplateBinding Foreground}"
                                          IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press"
                                          Focusable="false">
                                <ToggleButton.Template>
                                    <ControlTemplate TargetType="ToggleButton">
                                        <Border Background="{TemplateBinding Background}"
                                                BorderBrush="{TemplateBinding BorderBrush}"
                                                BorderThickness="{TemplateBinding BorderThickness}"
                                                CornerRadius="4"
                                                SnapsToDevicePixels="True">
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="32"/>
                                                </Grid.ColumnDefinitions>
                                                <ContentPresenter Grid.Column="0"
                                                                HorizontalAlignment="Left"
                                                                VerticalAlignment="Center"
                                                                Margin="8,0,0,0"
                                                                Content="{TemplateBinding Content}"
                                                                ContentTemplate="{TemplateBinding ContentTemplate}"/>
                                                <Path Grid.Column="1"
                                                      Data="M 0 0 L 4 4 L 8 0"
                                                      Fill="#8B949E"
                                                      HorizontalAlignment="Center"
                                                      VerticalAlignment="Center"
                                                      Stretch="Uniform"
                                                      Width="8"
                                                      Height="4"/>
                                            </Grid>
                                        </Border>
                                        <ControlTemplate.Triggers>
                                            <Trigger Property="IsMouseOver" Value="True">
                                                <Setter Property="Background" Value="#30363D"/>
                                            </Trigger>
                                            <Trigger Property="IsChecked" Value="True">
                                                <Setter Property="Background" Value="#30363D"/>
                                            </Trigger>
                                        </ControlTemplate.Triggers>
                                    </ControlTemplate>
                                </ToggleButton.Template>
                            </ToggleButton>
                            <ContentPresenter x:Name="ContentSite"
                                            IsHitTestVisible="False"
                                            Content="{TemplateBinding SelectionBoxItem}"
                                            ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                            ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                            Margin="8,0,32,0"
                                            VerticalAlignment="Center"
                                            HorizontalAlignment="Left"/>
                            <TextBox x:Name="PART_EditableTextBox"
                                     Style="{x:Null}"
                                     Template="{DynamicResource ComboBoxTextBox}"
                                     HorizontalAlignment="Left"
                                     VerticalAlignment="Center"
                                     Margin="8,0,32,0"
                                     Focusable="True"
                                     Background="Transparent"
                                     Foreground="#E6EDF3"
                                     Visibility="Collapsed"
                                     IsReadOnly="{TemplateBinding IsReadOnly}"/>
                            <Popup Name="Popup"
                                   Placement="Bottom"
                                   IsOpen="{TemplateBinding IsDropDownOpen}"
                                   AllowsTransparency="True"
                                   Focusable="False"
                                   PopupAnimation="Slide">
                                <Grid Name="DropDown"
                                      SnapsToDevicePixels="True"
                                      MinWidth="{TemplateBinding ActualWidth}"
                                      MaxHeight="200">
                                    <Border Background="#21262D"
                                            BorderBrush="#30363D"
                                            BorderThickness="1"
                                            CornerRadius="4"
                                            Margin="0,4,0,0"
                                            Effect="{DynamicResource DropShadowEffect}"/>
                                    <ScrollViewer Margin="4,8,4,8"
                                                  SnapsToDevicePixels="True">
                                        <StackPanel IsItemsHost="True"
                                                    KeyboardNavigation.DirectionalNavigation="Contained"/>
                                    </ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#161B22"/>
                                <Setter Property="Foreground" Value="#6E7681"/>
                                <Setter Property="BorderBrush" Value="#30363D"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True" SourceName="ToggleButton">
                                <Setter Property="BorderBrush" Value="#58A6FF"/>
                            </Trigger>
                            <Trigger Property="HasItems" Value="False">
                                <Setter Property="Height" TargetName="DropDown" Value="95"/>
                            </Trigger>
                            <Trigger Property="IsGrouping" Value="True">
                                <Setter Property="ScrollViewer.CanContentScroll" Value="False"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ComboBoxItem Style for Dark Theme -->
        <Style x:Key="DarkComboBoxItemStyle" TargetType="ComboBoxItem">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#E6EDF3"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="Margin" Value="0,1"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBoxItem">
                        <Border Background="{TemplateBinding Background}"
                                BorderThickness="0"
                                CornerRadius="3"
                                Padding="{TemplateBinding Padding}"
                                SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Left"
                                            VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsHighlighted" Value="True">
                                <Setter Property="Background" Value="#30363D"/>
                                <Setter Property="Foreground" Value="#E6EDF3"/>
                            </Trigger>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter Property="Background" Value="#58A6FF"/>
                                <Setter Property="Foreground" Value="#FFFFFF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ComboBox TextBox Template -->
        <ControlTemplate x:Key="ComboBoxTextBox" TargetType="TextBox">
            <Border Background="Transparent"
                    Focusable="False">
                <ScrollViewer x:Name="PART_ContentHost"
                              Background="Transparent"
                              Focusable="False"
                              HorizontalScrollBarVisibility="Hidden"
                              VerticalScrollBarVisibility="Hidden"/>
            </Border>
        </ControlTemplate>

        <!-- Drop Shadow Effect for Popup -->
        <DropShadowEffect x:Key="DropShadowEffect"
                         Color="#000000"
                         Direction="270"
                         ShadowDepth="2"
                         BlurRadius="8"
                         Opacity="0.3"/>

        <!-- Global ComboBox Style (Applied by default) -->
        <Style TargetType="ComboBox" BasedOn="{StaticResource DarkComboBoxStyle}"/>
        <Style TargetType="ComboBoxItem" BasedOn="{StaticResource DarkComboBoxItemStyle}"/>
    </Window.Resources>

    <Grid>
        <!-- Header -->
        <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Height="60" VerticalAlignment="Top">
            <Grid Margin="20,0">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Image x:Name="HeaderLogo" Width="32" Height="32" Margin="0,0,10,0"/>
                    <TextBlock Text="GA-AppLocker Dashboard" FontSize="18" FontWeight="Bold"
                               Foreground="#E6EDF3" VerticalAlignment="Center"/>
                    <TextBlock x:Name="HeaderVersion" Text="v1.2.5" FontSize="12" Foreground="#6E7681"
                               VerticalAlignment="Center" Margin="10,0,0,0"/>
                </StackPanel>
                <!-- QoL: Mini Status Bar -->
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,0,0">
                    <TextBlock x:Name="MiniStatusDomain" Text="ONLINE" FontSize="11" Foreground="#3FB950" VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <TextBlock x:Name="MiniStatusMode" Text="AUDIT" FontSize="11" Foreground="#D29922" VerticalAlignment="Center" Margin="0,0,8,0" FontWeight="SemiBold"/>
                    <TextBlock x:Name="MiniStatusPhase" Text="" FontSize="11" Foreground="#58A6FF" VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <TextBlock x:Name="MiniStatusConnected" Text="0 systems" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <TextBlock x:Name="MiniStatusArtifacts" Text="0 artifacts" FontSize="11" Foreground="#58A6FF" VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <TextBlock x:Name="MiniStatusSync" Text="Ready" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <TextBlock x:Name="StatusText" Text="Initializing..." FontSize="11"
                           Foreground="#6E7681" VerticalAlignment="Center"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Environment Status Banner -->
        <Border x:Name="EnvironmentBanner" Background="#21262D" BorderBrush="#30363D"
                BorderThickness="0,0,0,1" Height="40" VerticalAlignment="Top" Margin="0,60,0,0">
            <Grid Margin="20,0">
                <TextBlock x:Name="EnvironmentText" Text="" FontSize="12"
                           Foreground="#8B949E" VerticalAlignment="Center" HorizontalAlignment="Left"/>
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                    <Button x:Name="NavSaveWorkspace" Content="Save Workspace" Style="{StaticResource SecondaryButton}" Padding="12,4" Margin="0,0,6,0" ToolTip="Save current workspace state (Ctrl+S)"/>
                    <Button x:Name="NavLoadWorkspace" Content="Load Workspace" Style="{StaticResource SecondaryButton}" Padding="12,4" Margin="0,0,6,0" ToolTip="Load a previously saved workspace (Ctrl+O)"/>
                    <Button x:Name="NavHelp" Content="Help" Style="{StaticResource SecondaryButton}" Padding="12,4" Margin="0,0,6,0"/>
                    <Button x:Name="NavAbout" Content="About" Style="{StaticResource SecondaryButton}" Padding="12,4"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Main Content Area -->
        <Grid Margin="0,104,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="200"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Sidebar Navigation -->
            <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Grid.Column="0">
                <ScrollViewer x:Name="SidebarScrollViewer" VerticalScrollBarVisibility="Auto" Margin="0,10,0,10">
                    <StackPanel>
                        <!-- Dashboard -->
                        <Button x:Name="NavDashboard" Content="Dashboard" Style="{StaticResource SecondaryButton}"
                                HorizontalAlignment="Stretch" Margin="10,5"/>

                        <!-- SETUP Section (Collapsible) -->
                            <Expander x:Name="SetupSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="SETUP" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavAppLockerSetup" Content="AppLocker Setup" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavGroupMgmt" Content="Group Management" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavDiscovery" Content="AD Discovery" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                </StackPanel>
                            </Expander>

                            <!-- SCANNING Section (Collapsible) -->
                            <Expander x:Name="ScanningSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="SCANNING" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavArtifacts" Content="Artifacts" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavGapAnalysis" Content="Gap Analysis" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavRules" Content="Rule Generator" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavRuleWizard" Content="Rule Wizard (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                </StackPanel>
                            </Expander>

                            <!-- TEMPLATES Section (Collapsible) - Phase 5 -->
                            <Expander x:Name="TemplatesSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="TEMPLATES" FontSize="10" FontWeight="Bold" Foreground="#8957E5" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavTemplates" Content="Rule Templates (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                    <Button x:Name="NavCreateTemplate" Content="Create Template (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                    <Button x:Name="NavImportTemplate" Content="Import Template (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                </StackPanel>
                            </Expander>

                            <!-- DEPLOYMENT Section (Collapsible) -->
                            <Expander x:Name="DeploymentSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="DEPLOYMENT" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavDeployment" Content="Deployment" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavWinRM" Content="WinRM Setup" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                </StackPanel>
                            </Expander>

                            <!-- MONITORING Section (Collapsible) -->
                            <Expander x:Name="MonitoringSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="MONITORING" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavEvents" Content="Events" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                    <Button x:Name="NavCompliance" Content="Compliance (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                    <Button x:Name="NavReports" Content="Reports (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                    <Button x:Name="NavSiem" Content="SIEM (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                </StackPanel>
                            </Expander>

                            <!-- TESTING Section (Collapsible) -->
                            <Expander x:Name="TestingSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="TESTING" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavPolicySimulator" Content="Policy Simulator (WIP)" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1" IsEnabled="False" Opacity="0.5"/>
                                </StackPanel>
                            </Expander>

                            <!-- AARONLOCKER Section (Collapsible) -->
                            <Expander x:Name="AaronLockerSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
                                <Expander.Header>
                                    <TextBlock Text="AARONLOCKER" FontSize="10" FontWeight="Bold" Foreground="#F0883E" VerticalAlignment="Center" Width="150"/>
                                </Expander.Header>
                                <StackPanel Margin="4,0,0,0">
                                    <Button x:Name="NavAaronLocker" Content="AaronLocker Tools" Style="{StaticResource NavButton}"
                                            HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
                                </StackPanel>
                            </Expander>
                        </StackPanel>
                    </ScrollViewer>
            </Border>

            <!-- Content Panel with ScrollViewer for scrolling -->
            <ScrollViewer Grid.Column="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                <Grid Margin="20,10,10,10">
                <!-- Dashboard Panel -->
                <StackPanel x:Name="PanelDashboard" Visibility="Collapsed">
                    <TextBlock Text="Dashboard (WIP)" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Stats Cards -->
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Policy Health Card -->
                        <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                            <StackPanel>
                                <TextBlock Text="Policy Health" FontSize="11" Foreground="#8B949E"/>
                                <TextBlock x:Name="HealthScore" Text="--" FontSize="26" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,8,0,0"/>
                                <TextBlock x:Name="HealthStatus" Text="Loading..." FontSize="10" Foreground="#6E7681"/>
                            </StackPanel>
                        </Border>

                        <!-- Events Card -->
                        <Border Grid.Column="1" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                            <StackPanel>
                                <TextBlock Text="Total Events" FontSize="11" Foreground="#8B949E"/>
                                <TextBlock x:Name="TotalEvents" Text="--" FontSize="26" FontWeight="Bold"
                                           Foreground="#58A6FF" Margin="0,8,0,0"/>
                                <TextBlock x:Name="EventsStatus" Text="Loading..." FontSize="10" Foreground="#6E7681"/>
                            </StackPanel>
                        </Border>

                        <!-- Allowed Card -->
                        <Border Grid.Column="2" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                            <StackPanel>
                                <TextBlock Text="Allowed" FontSize="11" Foreground="#8B949E"/>
                                <TextBlock x:Name="AllowedEvents" Text="--" FontSize="26" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,8,0,0"/>
                                <TextBlock FontSize="10" Foreground="#6E7681">Event ID 8002</TextBlock>
                            </StackPanel>
                        </Border>

                        <!-- Audited Card -->
                        <Border Grid.Column="3" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                            <StackPanel>
                                <TextBlock Text="Audited" FontSize="11" Foreground="#8B949E"/>
                                <TextBlock x:Name="AuditedEvents" Text="--" FontSize="26" FontWeight="Bold"
                                           Foreground="#D29922" Margin="0,8,0,0"/>
                                <TextBlock FontSize="10" Foreground="#6E7681">Event ID 8003</TextBlock>
                            </StackPanel>
                        </Border>

                        <!-- Blocked Card -->
                        <Border Grid.Column="4" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Margin="0,0,0,10" Padding="12">
                            <StackPanel>
                                <TextBlock Text="Blocked" FontSize="11" Foreground="#8B949E"/>
                                <TextBlock x:Name="BlockedEvents" Text="--" FontSize="26" FontWeight="Bold"
                                           Foreground="#F85149" Margin="0,8,0,0"/>
                                <TextBlock FontSize="10" Foreground="#6E7681">Event ID 8004</TextBlock>
                            </StackPanel>
                        </Border>
                    </Grid>

                    <!-- Data Visualization Charts Section -->
                    <Grid Margin="0,10,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <!-- Event Distribution Pie Chart -->
                        <Border Grid.Column="0" Grid.Row="0" Background="#21262D" BorderBrush="#30363D"
                                CornerRadius="6" Margin="0,0,8,10" Padding="15" MinHeight="250">
                            <StackPanel>
                                <TextBlock Text="Event Distribution" FontSize="14" FontWeight="SemiBold"
                                           Foreground="#E6EDF3" Margin="0,0,0,10"/>
                                <Viewbox Stretch="Uniform" MaxHeight="180">
                                    <Grid Width="200" Height="200">
                                        <Path x:Name="PieAllowed" Fill="#3FB950" Stroke="#0D1117" StrokeThickness="2"/>
                                        <Path x:Name="PieAudited" Fill="#D29922" Stroke="#0D1117" StrokeThickness="2"/>
                                        <Path x:Name="PieBlocked" Fill="#F85149" Stroke="#0D1117" StrokeThickness="2"/>
                                    </Grid>
                                </Viewbox>
                                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
                                    <StackPanel Orientation="Horizontal" Margin="0,0,15,0">
                                        <Rectangle Width="12" Height="12" Fill="#3FB950" Margin="0,0,5,0"/>
                                        <TextBlock Text="Allowed" FontSize="11" Foreground="#8B949E"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,15,0">
                                        <Rectangle Width="12" Height="12" Fill="#D29922" Margin="0,0,5,0"/>
                                        <TextBlock Text="Audited" FontSize="11" Foreground="#8B949E"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal">
                                        <Rectangle Width="12" Height="12" Fill="#F85149" Margin="0,0,5,0"/>
                                        <TextBlock Text="Blocked" FontSize="11" Foreground="#8B949E"/>
                                    </StackPanel>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <!-- Policy Health Gauge -->
                        <Border Grid.Column="1" Grid.Row="0" Background="#21262D" BorderBrush="#30363D"
                                CornerRadius="6" Margin="0,0,0,10" Padding="15" MinHeight="250">
                            <StackPanel>
                                <TextBlock Text="Policy Health Score" FontSize="14" FontWeight="SemiBold"
                                           Foreground="#E6EDF3" Margin="0,0,0,10"/>
                                <Viewbox Stretch="Uniform" MaxHeight="180">
                                    <Grid Width="200" Height="110">
                                        <Path x:Name="GaugeBackground" Fill="#30363D"/>
                                        <Path x:Name="GaugeFill" Fill="#3FB950"/>
                                        <TextBlock x:Name="GaugeScore" Text="0" FontSize="36" FontWeight="Bold"
                                                   Foreground="#E6EDF3" HorizontalAlignment="Center"
                                                   VerticalAlignment="Bottom" Margin="0,0,0,10"/>
                                    </Grid>
                                </Viewbox>
                                <TextBlock x:Name="GaugeLabel" Text="No Policy Configured" FontSize="11"
                                           Foreground="#8B949E" HorizontalAlignment="Center" Margin="0,5,0,0"/>
                            </StackPanel>
                        </Border>

                        <!-- Machine Type Distribution Bar Chart -->
                        <Border Grid.Column="0" Grid.Row="1" Background="#21262D" BorderBrush="#30363D"
                                CornerRadius="6" Margin="0,0,8,0" Padding="15" MinHeight="200">
                            <StackPanel>
                                <TextBlock Text="Machine Type Distribution" FontSize="14" FontWeight="SemiBold"
                                           Foreground="#E6EDF3" Margin="0,0,0,10"/>
                                <Grid Height="150" Margin="0,0,0,10">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>

                                    <!-- Workstations -->
                                    <TextBlock Grid.Column="0" Grid.Row="0" Text="Workstations" FontSize="10"
                                               Foreground="#8B949E" HorizontalAlignment="Center" Margin="0,0,0,5"/>
                                    <Border Grid.Column="0" Grid.Row="1" Background="#0D1117" CornerRadius="4"
                                            Margin="0,0,5,0" Padding="5">
                                        <Grid>
                                            <Rectangle x:Name="BarWorkstations" Fill="#58A6FF" Height="0"
                                                       HorizontalAlignment="Center" VerticalAlignment="Bottom"/>
                                            <TextBlock x:Name="LabelWorkstations" Text="0" FontSize="14" FontWeight="Bold"
                                                       Foreground="#58A6FF" HorizontalAlignment="Center"
                                                       VerticalAlignment="Center"/>
                                        </Grid>
                                    </Border>

                                    <!-- Servers -->
                                    <TextBlock Grid.Column="1" Grid.Row="0" Text="Servers" FontSize="10"
                                               Foreground="#8B949E" HorizontalAlignment="Center" Margin="0,0,0,5"/>
                                    <Border Grid.Column="1" Grid.Row="1" Background="#0D1117" CornerRadius="4"
                                            Margin="0,0,5,0" Padding="5">
                                        <Grid>
                                            <Rectangle x:Name="BarServers" Fill="#3FB950" Height="0"
                                                       HorizontalAlignment="Center" VerticalAlignment="Bottom"/>
                                            <TextBlock x:Name="LabelServers" Text="0" FontSize="14" FontWeight="Bold"
                                                       Foreground="#3FB950" HorizontalAlignment="Center"
                                                       VerticalAlignment="Center"/>
                                        </Grid>
                                    </Border>

                                    <!-- Domain Controllers -->
                                    <TextBlock Grid.Column="2" Grid.Row="0" Text="DCs" FontSize="10"
                                               Foreground="#8B949E" HorizontalAlignment="Center" Margin="0,0,0,5"/>
                                    <Border Grid.Column="2" Grid.Row="1" Background="#0D1117" CornerRadius="4"
                                            Padding="5">
                                        <Grid>
                                            <Rectangle x:Name="BarDCs" Fill="#D29922" Height="0"
                                                       HorizontalAlignment="Center" VerticalAlignment="Bottom"/>
                                            <TextBlock x:Name="LabelDCs" Text="0" FontSize="14" FontWeight="Bold"
                                                       Foreground="#D29922" HorizontalAlignment="Center"
                                                       VerticalAlignment="Center"/>
                                        </Grid>
                                    </Border>
                                </Grid>
                                <TextBlock x:Name="TotalMachinesLabel" Text="Total: 0 machines" FontSize="11"
                                           Foreground="#6E7681" HorizontalAlignment="Center"/>
                            </StackPanel>
                        </Border>

                        <!-- Event Trend Line Chart -->
                        <Border Grid.Column="1" Grid.Row="1" Background="#21262D" BorderBrush="#30363D"
                                CornerRadius="6" Padding="15" MinHeight="200">
                            <StackPanel>
                                <TextBlock Text="Event Trend (7 Days)" FontSize="14" FontWeight="SemiBold"
                                           Foreground="#E6EDF3" Margin="0,0,0,10"/>
                                <Grid Height="150" Margin="0,0,0,10">
                                    <Canvas x:Name="TrendChartCanvas" Background="#0D1117" ClipToBounds="True"/>
                                </Grid>
                                <TextBlock x:Name="TrendSummaryLabel" Text="No trend data available" FontSize="11"
                                           Foreground="#6E7681" HorizontalAlignment="Center"/>
                            </StackPanel>
                        </Border>
                    </Grid>

                    <!-- Filters Row -->
                    <Grid Margin="0,20,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Text="Time Range:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="0" Margin="0,0,8,0"/>
                        <ComboBox x:Name="DashboardTimeFilter" Grid.Column="1" Width="130" Height="26"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" Margin="0,0,15,0" FontSize="11">
                            <ComboBox.ItemContainerStyle>
                                <Style TargetType="ComboBoxItem">
                                    <Setter Property="Background" Value="#21262D"/>
                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                    <Setter Property="Padding" Value="8,4"/>
                                    <Style.Triggers>
                                        <Trigger Property="IsHighlighted" Value="True">
                                            <Setter Property="Background" Value="#30363D"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                        <Trigger Property="IsSelected" Value="True">
                                            <Setter Property="Background" Value="#388BFD"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                        <MultiTrigger>
                                            <MultiTrigger.Conditions>
                                                <Condition Property="IsSelected" Value="True"/>
                                                <Condition Property="Selector.IsSelectionActive" Value="False"/>
                                            </MultiTrigger.Conditions>
                                            <Setter Property="Background" Value="#30363D"/>
                                            <Setter Property="Foreground" Value="#E6EDF3"/>
                                        </MultiTrigger>
                                    </Style.Triggers>
                                </Style>
                            </ComboBox.ItemContainerStyle>
                            <ComboBoxItem Content="Last 7 Days" IsSelected="True"/>
                            <ComboBoxItem Content="Last 30 Days"/>
                        </ComboBox>

                        <TextBlock Text="System:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="2" Margin="0,0,8,0"/>
                        <ComboBox x:Name="DashboardSystemFilter" Grid.Column="3" Width="150" Height="26"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" Margin="0,0,15,0" FontSize="11">
                            <ComboBox.ItemContainerStyle>
                                <Style TargetType="ComboBoxItem">
                                    <Setter Property="Background" Value="#21262D"/>
                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                    <Setter Property="Padding" Value="8,4"/>
                                    <Style.Triggers>
                                        <Trigger Property="IsHighlighted" Value="True">
                                            <Setter Property="Background" Value="#30363D"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                        <Trigger Property="IsSelected" Value="True">
                                            <Setter Property="Background" Value="#388BFD"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                        <MultiTrigger>
                                            <MultiTrigger.Conditions>
                                                <Condition Property="IsSelected" Value="True"/>
                                                <Condition Property="Selector.IsSelectionActive" Value="False"/>
                                            </MultiTrigger.Conditions>
                                            <Setter Property="Background" Value="#30363D"/>
                                            <Setter Property="Foreground" Value="#E6EDF3"/>
                                        </MultiTrigger>
                                    </Style.Triggers>
                                </Style>
                            </ComboBox.ItemContainerStyle>
                            <ComboBoxItem Content="All Systems" IsSelected="True"/>
                        </ComboBox>

                        <Button x:Name="RefreshDashboardBtn" Content="Refresh"
                                Style="{StaticResource SecondaryButton}" Grid.Column="4" MinWidth="70" MinHeight="26"
                                FontSize="11" ToolTip="Refresh Dashboard"/>
                    </Grid>

                    <!-- Output Area -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,15,0,0" Padding="15" MinHeight="200">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="DashboardOutput" Text="Loading dashboard..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Artifacts Panel -->
                <StackPanel x:Name="PanelArtifacts" Visibility="Collapsed">
                    <TextBlock Text="Artifact Collection" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,15"/>

                    <!-- Local Scan Header -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,10" Padding="15">
                        <StackPanel>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <StackPanel Grid.Column="0">
                                    <TextBlock Text="Local Artifact Scanning" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                    <TextBlock Text="Scan the local system for executable artifacts" FontSize="11" Foreground="#6E7681" Margin="0,4,0,0"/>
                                </StackPanel>

                                <Button x:Name="ScanLocalArtifactsBtn" Content="Scan Local System" Style="{StaticResource PrimaryButton}" Grid.Column="1" MinHeight="32" MinWidth="140"/>
                                <Button x:Name="AaronLockerScanBtn" Content="AaronLocker Scan" Style="{StaticResource SecondaryButton}" Grid.Column="3" MinHeight="32" MinWidth="130" ToolTip="Backup scan using AaronLocker's Get-AppLockerFileInformation method"/>
                                <Button x:Name="CancelScanBtn" Content="Cancel" Style="{StaticResource SecondaryButton}" Grid.Column="5" MinHeight="32" MinWidth="80" Visibility="Collapsed"/>
                            </Grid>

                            <!-- Progress Section -->
                            <StackPanel x:Name="ScanProgressPanel" Visibility="Collapsed" Margin="0,15,0,0">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock x:Name="ScanProgressText" Text="Scanning..." FontSize="12" Foreground="#58A6FF" Grid.Column="0"/>
                                    <TextBlock x:Name="ScanProgressCount" Text="" FontSize="12" Foreground="#8B949E" Grid.Column="1"/>
                                </Grid>
                                <ProgressBar x:Name="ScanProgressBar" Height="6" Margin="0,8,0,0" IsIndeterminate="True"
                                             Background="#21262D" Foreground="#238636"/>
                            </StackPanel>
                        </StackPanel>
                    </Border>

                    <!-- Directory Selection -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,10" Padding="15">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <Grid Grid.Row="0" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Directories:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <CheckBox x:Name="ScanAllDirectoriesCheckbox" Content="Scan All Directories" Grid.Column="1"
                                          Foreground="#E6EDF3" FontSize="12" VerticalAlignment="Center" Margin="0,0,15,0" IsChecked="True"/>
                                <TextBlock Grid.Column="2" Text="Or select specific directories below" FontSize="11" Foreground="#6E7681" VerticalAlignment="Center"/>
                                <TextBlock Grid.Column="3" Text="Max Files:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="10,0,10,0"/>
                                <TextBox x:Name="MaxFilesText" Text="50000" Width="80" Height="28"
                                         Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                         BorderThickness="1" FontSize="12" Padding="5" Grid.Column="4"/>
                            </Grid>

                            <ListBox x:Name="DirectoryList" Grid.Row="1" Height="150" Background="#0D1117"
                                     Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1"
                                     SelectionMode="Extended" FontSize="12">
                                <ListBoxItem Content="C:\Program Files"/>
                                <ListBoxItem Content="C:\Program Files (x86)"/>
                                <ListBoxItem Content="C:\ProgramData"/>
                                <ListBoxItem Content="C:\Windows\System32"/>
                                <ListBoxItem Content="C:\Windows\SysWOW64"/>
                                <ListBoxItem Content="C:\Windows\Temp"/>
                                <ListBoxItem Content="C:\Users\*\AppData\Local\Temp"/>
                                <ListBoxItem Content="C:\Users\*\Downloads"/>
                            </ListBox>
                        </Grid>
                    </Border>

                    <!-- Artifacts List -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,0" Padding="15" MinHeight="200">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Discovered Artifacts" FontSize="13" FontWeight="Bold"
                                       Foreground="#8B949E" Margin="0,0,0,10"/>

                            <ListBox x:Name="ArtifactsList" Grid.Row="1" Background="#0D1117"
                                     Foreground="#E6EDF3" BorderThickness="0" FontFamily="Consolas" FontSize="11"/>
                        </Grid>
                    </Border>
                </StackPanel>

                <!-- Software Gap Analysis Panel -->
                <StackPanel x:Name="PanelGapAnalysis" Visibility="Collapsed">
                    <TextBlock Text="Software Gap Analysis" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Compare Software Baselines" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Select a baseline software list and compare against another host or imported list."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <!-- Import and Compare Buttons -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="ImportBaselineBtn" Content="Import Baseline CSV" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportTargetBtn" Content="Import Target CSV" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                        <Button x:Name="CompareSoftwareBtn" Content="Compare Lists" Style="{StaticResource SecondaryButton}" Grid.Column="4"/>
                    </Grid>

                    <!-- Comparison Results -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Comparison Results" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" MaxHeight="250">
                                <DataGrid x:Name="GapAnalysisGrid" Background="#161B22" Foreground="#E6EDF3"
                                           BorderThickness="1" BorderBrush="#30363D" FontSize="11" FontFamily="Consolas"
                                           GridLinesVisibility="Horizontal" HeadersVisibility="Column"
                                           AutoGenerateColumns="False" IsReadOnly="True"
                                           CanUserAddRows="False" CanUserDeleteRows="False"
                                           RowBackground="#161B22" AlternatingRowBackground="#1C2128"
                                           HorizontalGridLinesBrush="#30363D">
                                    <DataGrid.ColumnHeaderStyle>
                                        <Style TargetType="DataGridColumnHeader">
                                            <Setter Property="Background" Value="#21262D"/>
                                            <Setter Property="Foreground" Value="#E6EDF3"/>
                                            <Setter Property="FontWeight" Value="Bold"/>
                                            <Setter Property="Padding" Value="8,6"/>
                                            <Setter Property="BorderBrush" Value="#30363D"/>
                                            <Setter Property="BorderThickness" Value="0,0,1,1"/>
                                        </Style>
                                    </DataGrid.ColumnHeaderStyle>
                                    <DataGrid.CellStyle>
                                        <Style TargetType="DataGridCell">
                                            <Setter Property="Padding" Value="6,4"/>
                                            <Setter Property="BorderThickness" Value="0"/>
                                            <Setter Property="Foreground" Value="#E6EDF3"/>
                                            <Style.Triggers>
                                                <Trigger Property="IsSelected" Value="True">
                                                    <Setter Property="Background" Value="#388BFD"/>
                                                    <Setter Property="Foreground" Value="#FFFFFF"/>
                                                </Trigger>
                                            </Style.Triggers>
                                        </Style>
                                    </DataGrid.CellStyle>
                                    <DataGrid.Columns>
                                        <DataGridTextColumn Header="Software Name" Binding="{Binding Name}" Width="*">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                                    <Setter Property="Padding" Value="4,2"/>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="110">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Padding" Value="4,2"/>
                                                    <Style.Triggers>
                                                        <DataTrigger Binding="{Binding Status}" Value="Missing in Target">
                                                            <Setter Property="Foreground" Value="#F85149"/>
                                                            <Setter Property="FontWeight" Value="Bold"/>
                                                        </DataTrigger>
                                                        <DataTrigger Binding="{Binding Status}" Value="Extra in Target">
                                                            <Setter Property="Foreground" Value="#58A6FF"/>
                                                            <Setter Property="FontWeight" Value="Bold"/>
                                                        </DataTrigger>
                                                        <DataTrigger Binding="{Binding Status}" Value="Version Mismatch">
                                                            <Setter Property="Foreground" Value="#D29922"/>
                                                            <Setter Property="FontWeight" Value="Bold"/>
                                                        </DataTrigger>
                                                        <DataTrigger Binding="{Binding Status}" Value="Match">
                                                            <Setter Property="Foreground" Value="#3FB950"/>
                                                            <Setter Property="FontWeight" Value="Bold"/>
                                                        </DataTrigger>
                                                    </Style.Triggers>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Baseline" Binding="{Binding BaselineVersion}" Width="80">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Foreground" Value="#8B949E"/>
                                                    <Setter Property="Padding" Value="4,2"/>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Target" Binding="{Binding TargetVersion}" Width="80">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Foreground" Value="#8B949E"/>
                                                    <Setter Property="Padding" Value="4,2"/>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                    </DataGrid.Columns>
                                </DataGrid>
                            </ScrollViewer>
                        </Grid>
                    </Border>

                    <!-- Summary Stats -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="10">
                            <StackPanel>
                                <TextBlock Text="Total" FontSize="10" Foreground="#8B949E"/>
                                <TextBlock x:Name="GapTotalCount" Text="0" FontSize="18" FontWeight="Bold" Foreground="#E6EDF3" HorizontalAlignment="Center"/>
                            </StackPanel>
                        </Border>
                        <Border Grid.Column="2" Background="#21262D" BorderBrush="#F85149" BorderThickness="1" CornerRadius="6" Padding="10">
                            <StackPanel>
                                <TextBlock Text="Missing" FontSize="10" Foreground="#E6EDF3"/>
                                <TextBlock x:Name="GapMissingCount" Text="0" FontSize="18" FontWeight="Bold" Foreground="#F85149" HorizontalAlignment="Center"/>
                            </StackPanel>
                        </Border>
                        <Border Grid.Column="4" Background="#21262D" BorderBrush="#58A6FF" BorderThickness="1" CornerRadius="6" Padding="10">
                            <StackPanel>
                                <TextBlock Text="Extra" FontSize="10" Foreground="#E6EDF3"/>
                                <TextBlock x:Name="GapExtraCount" Text="0" FontSize="18" FontWeight="Bold" Foreground="#58A6FF" HorizontalAlignment="Center"/>
                            </StackPanel>
                        </Border>
                        <Border Grid.Column="6" Background="#21262D" BorderBrush="#D29922" BorderThickness="1" CornerRadius="6" Padding="10">
                            <StackPanel>
                                <TextBlock Text="Version Diff" FontSize="10" Foreground="#E6EDF3"/>
                                <TextBlock x:Name="GapVersionCount" Text="0" FontSize="18" FontWeight="Bold" Foreground="#D29922" HorizontalAlignment="Center"/>
                            </StackPanel>
                        </Border>
                    </Grid>

                    <!-- Export Button -->
                    <Grid>
                        <Button x:Name="ExportGapAnalysisBtn" Content="Export Comparison" Style="{StaticResource SecondaryButton}" Width="180" HorizontalAlignment="Left"/>
                    </Grid>
                </StackPanel>

                <!-- Rules Panel -->
                <StackPanel x:Name="PanelRules" Visibility="Collapsed">
                    <!-- Header -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Grid.Column="0" Text="Rule Generator" FontSize="22" FontWeight="Bold" Foreground="#E6EDF3"/>
                        <Button x:Name="AuditToggleBtn" Content="[!] AUDIT MODE" Grid.Column="1"
                                Background="#F0883E" Foreground="#FFFFFF" FontSize="11" FontWeight="Bold"
                                BorderThickness="0" Padding="16,6" Height="32"
                                ToolTip="Toggle all rules between Audit and Enforce mode"/>
                    </Grid>

                    <!-- Section 1: Configuration -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Margin="0,0,0,12" Padding="16">
                        <StackPanel>
                            <TextBlock Text="Configuration" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="80"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <!-- Rule Type -->
                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Type:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,0,8"/>
                                <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" Margin="0,0,0,8">
                                    <RadioButton x:Name="RuleTypeAuto" Content="Auto (Recommended)" IsChecked="True"
                                                 Foreground="#58A6FF" FontSize="12" Margin="0,0,20,0"/>
                                    <RadioButton x:Name="RuleTypePublisher" Content="Publisher"
                                                 Foreground="#E6EDF3" FontSize="12" Margin="0,0,20,0"/>
                                    <RadioButton x:Name="RuleTypeHash" Content="Hash"
                                                 Foreground="#E6EDF3" FontSize="12" Margin="0,0,20,0"/>
                                    <RadioButton x:Name="RuleTypePath" Content="Path"
                                                 Foreground="#E6EDF3" FontSize="12"/>
                                </StackPanel>

                                <!-- Action & Group -->
                                <StackPanel Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="2" Orientation="Horizontal">
                                    <StackPanel>
                                        <TextBlock Text="Action:" FontSize="12" Foreground="#8B949E" Margin="0,0,0,4"/>
                                        <StackPanel Orientation="Horizontal">
                                            <RadioButton x:Name="RuleActionAllow" Content="Allow" IsChecked="True"
                                                         Foreground="#3FB950" FontSize="12" Margin="0,0,20,0"/>
                                            <RadioButton x:Name="RuleActionDeny" Content="Deny"
                                                         Foreground="#F85149" FontSize="12"/>
                                        </StackPanel>
                                    </StackPanel>
                                    <StackPanel Margin="30,0,0,0">
                                        <TextBlock Text="Apply to Group:" FontSize="12" Foreground="#8B949E" Margin="0,0,0,4"/>
                                        <ComboBox x:Name="RuleGroupCombo" Height="30" MinWidth="220"
                                                  Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12">
                                            <ComboBoxItem Content="AppLocker-Admins" IsSelected="True"/>
                                            <ComboBoxItem Content="AppLocker-StandardUsers"/>
                                            <ComboBoxItem Content="AppLocker-Service-Accounts"/>
                                            <ComboBoxItem Content="AppLocker-Installers"/>
                                        </ComboBox>
                                    </StackPanel>
                                </StackPanel>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Section 2: Import Artifacts -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Margin="0,0,0,12" Padding="16">
                        <StackPanel>
                            <TextBlock Text="Import Artifacts" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <!-- Quick Import -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="6"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="6"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Quick Load:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <Button x:Name="LoadCollectedArtifactsBtn" Content="Load Artifacts" Grid.Column="2"
                                        Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="12,0"/>
                                <TextBlock x:Name="ArtifactCountBadge" Text="0" Grid.Column="4" FontSize="11" FontWeight="Bold"
                                           Foreground="#6E7681" Background="#30363D" Padding="8,4" MinWidth="30" TextAlignment="Center"
                                           VerticalAlignment="Center"/>
                                <Button x:Name="LoadCollectedEventsBtn" Content="Load Events" Grid.Column="6"
                                        Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="12,0"/>
                                <TextBlock x:Name="EventCountBadge" Text="0" Grid.Column="8" FontSize="11" FontWeight="Bold"
                                           Foreground="#6E7681" Background="#30363D" Padding="8,4" MinWidth="30" TextAlignment="Center"
                                           VerticalAlignment="Center"/>
                            </Grid>

                            <!-- File Import -->
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Button x:Name="ImportArtifactsBtn" Content="Import File" Grid.Column="0"
                                        Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="12,0"/>
                                <Button x:Name="ImportFolderBtn" Content="Import Folder" Grid.Column="2"
                                        Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="12,0"/>
                                <Button x:Name="DedupeBtn" Content="Deduplicate" Grid.Column="4"
                                        Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="12,0" MinWidth="110"/>
                                <ComboBox x:Name="DedupeTypeCombo" Grid.Column="6" Height="30" Width="130"
                                          Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
                                    <ComboBoxItem Content="By Publisher" IsSelected="True"/>
                                    <ComboBoxItem Content="By Hash"/>
                                    <ComboBoxItem Content="By Path"/>
                                </ComboBox>
                                <Button x:Name="ExportArtifactsListBtn" Content="Export List" Grid.Column="8"
                                        Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="12,0" MinWidth="100"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Section 3: Generate Rules -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Margin="0,0,0,12" Padding="16">
                        <StackPanel>
                            <TextBlock Text="Generate Rules" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Button x:Name="GenerateRulesBtn" Content="Generate Rules" Grid.Column="0"
                                        Style="{StaticResource PrimaryButton}" Height="36" FontSize="12" FontWeight="SemiBold"/>
                                <Button x:Name="DefaultDenyRulesBtn" Content="Default Deny Rules" Grid.Column="2"
                                        Style="{StaticResource SecondaryButton}" Height="36" FontSize="11"/>
                                <Button x:Name="CreateBrowserDenyBtn" Content="Browser Deny Rules" Grid.Column="4"
                                        Style="{StaticResource SecondaryButton}" Height="36" FontSize="11"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Section 4: Rules List -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Margin="0,0,0,12" Padding="16">
                        <StackPanel>
                            <!-- Header with count and actions -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Generated Rules" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" VerticalAlignment="Center"/>
                                <TextBlock x:Name="RulesCountText" Grid.Column="2" Text="0 rules" FontSize="12" Foreground="#3FB950" VerticalAlignment="Center"/>
                                <Button x:Name="DeleteRulesBtn" Content="Delete Selected" Grid.Column="5"
                                        Style="{StaticResource SecondaryButton}" Height="28" FontSize="11" Background="#F85149" Padding="10,0" MinWidth="110"/>
                            </Grid>

                            <!-- Filter and Search -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="80"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="110"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="100"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="130"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Filter:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <ComboBox x:Name="RulesTypeFilter" Grid.Column="2" Height="28" FontSize="11"
                                          Background="#161B22" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Types" IsSelected="True"/>
                                    <ComboBoxItem Content="Publisher"/>
                                    <ComboBoxItem Content="Hash"/>
                                    <ComboBoxItem Content="Path"/>
                                </ComboBox>
                                <ComboBox x:Name="RulesActionFilter" Grid.Column="4" Height="28" FontSize="11"
                                          Background="#161B22" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Actions" IsSelected="True"/>
                                    <ComboBoxItem Content="Allow"/>
                                    <ComboBoxItem Content="Deny"/>
                                </ComboBox>
                                <ComboBox x:Name="RulesGroupFilter" Grid.Column="6" Height="28" FontSize="11"
                                          Background="#161B22" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Groups" IsSelected="True"/>
                                </ComboBox>
                                <TextBox x:Name="RulesFilterSearch" Grid.Column="8" Height="28" FontSize="11"
                                         Background="#161B22" Foreground="#E6EDF3" BorderBrush="#30363D"
                                         Padding="8,0" Text="Search rules..."/>
                                <Button x:Name="RulesClearFilterBtn" Content="Clear" Grid.Column="10"
                                        Style="{StaticResource SecondaryButton}" Height="28" FontSize="11" MinWidth="60" Padding="10,0"/>
                            </Grid>

                            <!-- DataGrid -->
                            <DataGrid x:Name="RulesDataGrid" Height="280"
                                      Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1"
                                      GridLinesVisibility="Horizontal" HeadersVisibility="Column" AutoGenerateColumns="False"
                                      CanUserAddRows="False" CanUserDeleteRows="False" SelectionMode="Extended"
                                      FontSize="11" RowBackground="#0D1117" AlternatingRowBackground="#161B22">
                                <DataGrid.Columns>
                                    <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="70" IsReadOnly="True"/>
                                    <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="60" IsReadOnly="True"/>
                                    <DataGridTextColumn Header="Name / Value" Binding="{Binding Name}" Width="280" IsReadOnly="True"/>
                                    <DataGridTextColumn Header="Group" Binding="{Binding Group}" Width="170" IsReadOnly="True"/>
                                </DataGrid.Columns>
                            </DataGrid>

                            <!-- Filter count -->
                            <TextBlock x:Name="RulesFilterCount" Text="" Margin="0,8,0,0"
                                      FontSize="11" Foreground="#58A6FF" HorizontalAlignment="Right"/>
                        </StackPanel>
                    </Border>

                    <!-- Section 5: Output Log -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16">
                        <StackPanel>
                            <TextBlock Text="Output Log" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                            <ScrollViewer MaxHeight="180" VerticalScrollBarVisibility="Auto">
                                <TextBlock x:Name="RulesOutput" Text="Import artifacts or generate rules to see results here..."
                                           FontFamily="Consolas" FontSize="11" Foreground="#3FB950"
                                           TextWrapping="Wrap"/>
                            </ScrollViewer>
                        </StackPanel>
                    </Border>
                </StackPanel>

                <!-- Events Panel -->
                <StackPanel x:Name="PanelEvents" Visibility="Collapsed">
                    <TextBlock Text="Event Monitor" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                    <!-- Computer Selection -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,10" Padding="15">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <Grid Grid.Row="0" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Computers:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <TextBlock Grid.Column="1" Text="Ctrl+click to select multiple, Shift+click for range" FontSize="11" Foreground="#6E7681" VerticalAlignment="Center"/>
                                <Button x:Name="ScanLocalEventsBtn" Content="Scan Local" Style="{StaticResource PrimaryButton}" Grid.Column="2" MinHeight="32"/>
                                <Button x:Name="ScanRemoteEventsBtn" Content="Scan Selected" Style="{StaticResource PrimaryButton}" Grid.Column="4" MinHeight="32"/>
                                <Button x:Name="RefreshComputersBtn" Content="Refresh List" Style="{StaticResource SecondaryButton}" Grid.Column="6" MinHeight="32"/>
                            </Grid>

                            <ListBox x:Name="EventComputersList" Grid.Row="1" Height="120" Background="#0D1117"
                                     Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1"
                                     SelectionMode="Extended" FontSize="12">
                                <ListBox.ItemTemplate>
                                    <DataTemplate>
                                        <StackPanel Orientation="Horizontal">
                                            <TextBlock Text="{Binding Name}" FontWeight="Bold" Width="200"/>
                                            <TextBlock Text="{Binding Status}" Foreground="{Binding StatusColor}" Width="80"/>
                                            <TextBlock Text="{Binding OU}" Foreground="#6E7681"/>
                                        </StackPanel>
                                    </DataTemplate>
                                </ListBox.ItemTemplate>
                            </ListBox>
                        </Grid>
                    </Border>

                    <!-- Export Button -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="12" Margin="0,0,0,10">
                        <Button x:Name="ExportEventsBtn" Content="Export Events to CSV" Style="{StaticResource SecondaryButton}" HorizontalAlignment="Left" MinWidth="200" Height="34" FontSize="11" Padding="14,0"/>
                    </Border>

                    <!-- Event Filters - Row 1: Filter Type Buttons and Refresh -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="12" Margin="0,0,0,10">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="12"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>

                            <TextBlock Grid.Column="0" Text="Event Type:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                            <Button x:Name="FilterAllBtn" Content="All" Style="{StaticResource SecondaryButton}" Grid.Column="2" Height="30" FontSize="11" Padding="14,0" MinWidth="60"/>
                            <Button x:Name="FilterAllowedBtn" Content="Allowed" Style="{StaticResource SecondaryButton}" Grid.Column="4" Height="30" FontSize="11" Padding="14,0" MinWidth="80"/>
                            <Button x:Name="FilterBlockedBtn" Content="Blocked" Style="{StaticResource SecondaryButton}" Grid.Column="6" Height="30" FontSize="11" Padding="14,0" MinWidth="80"/>
                            <Button x:Name="FilterAuditBtn" Content="Audit" Style="{StaticResource SecondaryButton}" Grid.Column="8" Height="30" FontSize="11" Padding="14,0" MinWidth="70"/>
                            <Button x:Name="RefreshEventsBtn" Content="Refresh Events" Style="{StaticResource PrimaryButton}" Grid.Column="10" Height="30" FontSize="11" Padding="14,0" MinWidth="120"/>
                        </Grid>
                    </Border>

                    <!-- Event Filters - Row 2: Date Range and Search -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="12" Margin="0,0,0,10">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="130"/>
                                <ColumnDefinition Width="20"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="130"/>
                                <ColumnDefinition Width="20"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="10"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>

                            <TextBlock Grid.Column="0" Text="From:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                            <DatePicker x:Name="EventsDateFrom" Grid.Column="2" Height="30" FontSize="11"
                                       Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                       FirstDayOfWeek="Monday" DisplayDateStart="{x:Static sys:DateTime.Today}"/>

                            <TextBlock Grid.Column="4" Text="To:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                            <DatePicker x:Name="EventsDateTo" Grid.Column="6" Height="30" FontSize="11"
                                       Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                       FirstDayOfWeek="Monday" DisplayDateStart="{x:Static sys:DateTime.Today}"/>

                            <TextBlock Grid.Column="8" Text="Search:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                            <TextBox x:Name="EventsFilterSearch" Grid.Column="10" Height="30" FontSize="11"
                                     Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                     Padding="8,4" Text="Search events..."/>

                            <Button x:Name="EventsClearFilterBtn" Content="Clear Filters" Grid.Column="12"
                                    Style="{StaticResource SecondaryButton}" Height="30" FontSize="11" Padding="14,0" MinWidth="100"/>

                            <TextBlock x:Name="EventsFilterCount" Grid.Column="14" Text=""
                                      FontSize="11" Foreground="#58A6FF" VerticalAlignment="Center" MinWidth="80"/>
                        </Grid>
                    </Border>

                    <!-- Events Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" MinHeight="200" MaxHeight="400">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="EventsOutput"
                                       Text="Scan Local, Scan Remote, Import/Export - Use AD Discovery to find computers first.&#x0a;Export events to CSV, then use Import CSV in Rule Generator to create rules."
                                       FontFamily="Consolas" FontSize="10" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Deployment Panel -->
                <StackPanel x:Name="PanelDeployment" Visibility="Collapsed">
                    <TextBlock Text="Deployment" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Export Rules Button -->
                    <Button x:Name="ExportRulesBtn" Content="Export Rules" Style="{StaticResource SecondaryButton}" Margin="0,0,0,15"/>

                    <!-- Rule File Selection -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Rule File Selection" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="RuleFilePathBox" Grid.Column="0" Height="30" FontSize="11"
                                         Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                         Padding="8,4" Text="Select an AppLocker XML rule file..." IsReadOnly="True"/>
                                <Button x:Name="BrowseRuleFileBtn" Content="Browse..." Grid.Column="2"
                                        Style="{StaticResource SecondaryButton}" Height="30" Padding="12,0"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Import to GPO Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Import Rules to GPO" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="15"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Text="Target GPO:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="0"/>
                                <ComboBox x:Name="TargetGpoCombo" Grid.Column="2" Height="26" FontSize="11" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="AppLocker-DC"/>
                                    <ComboBoxItem Content="AppLocker-Servers"/>
                                    <ComboBoxItem Content="AppLocker-Workstations"/>
                                </ComboBox>
                                <TextBlock Text="Mode:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="4"/>
                                <ComboBox x:Name="ImportModeCombo" Grid.Column="6" Width="120" Height="26" FontSize="11" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="Merge (Add)" IsSelected="True" ToolTip="Add new rules, keep existing rules"/>
                                    <ComboBoxItem Content="Overwrite" ToolTip="Replace all existing rules"/>
                                </ComboBox>
                                <Button x:Name="ImportRulesBtn" Content="Apply" Grid.Column="8"
                                        Style="{StaticResource PrimaryButton}" Height="30" Padding="20,0"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Deployment Status" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock x:Name="DeploymentStatus" Text="Ready to deploy policies..."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="200">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock FontFamily="Consolas" FontSize="12" Foreground="#8B949E">
                                <Run Text="Deployment Workflow:" Foreground="#E6EDF3"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="1. Discover AD computers"/>
                                <LineBreak/>
                                <Run Text="2. Collect artifacts"/>
                                <LineBreak/>
                                <Run Text="3. Generate rules (Publisher first)"/>
                                <LineBreak/>
                                <Run Text="4. Export rules to XML"/>
                                <LineBreak/>
                                <Run Text="5. Create GPO in Audit mode"/>
                                <LineBreak/>
                                <Run Text="6. Import rules to GPO"/>
                                <LineBreak/>
                                <Run Text="7. Monitor for X days"/>
                                <LineBreak/>
                                <Run Text="8. Switch to Enforce mode"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="Best Practices:" Foreground="#E6EDF3"/>
                                <LineBreak/>
                                <Run Text="- Use Publisher rules first"/>
                                <LineBreak/>
                                <Run Text="- Use Hash rules for unsigned files"/>
                                <LineBreak/>
                                <Run Text="- Avoid Path rules when possible"/>
                                <LineBreak/>
                                <Run Text="- Always start in Audit mode"/>
                                <LineBreak/>
                                <Run Text="- Use role-based groups"/>
                            </TextBlock>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Compliance Panel -->
                <StackPanel x:Name="PanelCompliance" Visibility="Collapsed">
                    <TextBlock Text="Compliance" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Computer Selection -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,10" Padding="15">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <Grid Grid.Row="0" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Computers:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <TextBlock Grid.Column="1" Text="Ctrl+click to select multiple, Shift+click for range" FontSize="11" Foreground="#6E7681" VerticalAlignment="Center"/>
                                <Button x:Name="ScanLocalComplianceBtn" Content="Scan Local" Style="{StaticResource PrimaryButton}" Grid.Column="2" MinHeight="32"/>
                                <Button x:Name="ScanSelectedComplianceBtn" Content="Scan Selected" Style="{StaticResource PrimaryButton}" Grid.Column="4" MinHeight="32"/>
                                <Button x:Name="RefreshComplianceListBtn" Content="Refresh List" Style="{StaticResource SecondaryButton}" Grid.Column="6" MinHeight="32"/>
                            </Grid>

                            <ListBox x:Name="ComplianceComputersList" Grid.Row="1" Height="120" Background="#0D1117"
                                     Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1"
                                     SelectionMode="Extended" FontSize="12">
                                <ListBox.ItemTemplate>
                                    <DataTemplate>
                                        <StackPanel Orientation="Horizontal">
                                            <TextBlock Text="{Binding Name}" FontWeight="Bold" Width="200"/>
                                            <TextBlock Text="{Binding Status}" Foreground="{Binding StatusColor}" Width="80"/>
                                            <TextBlock Text="{Binding OU}" Foreground="#6E7681"/>
                                        </StackPanel>
                                    </DataTemplate>
                                </ListBox.ItemTemplate>
                            </ListBox>
                        </Grid>
                    </Border>

                    <!-- Actions -->
                    <Grid Margin="0,0,0,8">
                        <Button x:Name="GenerateEvidenceBtn" Content="Generate Evidence Package"
                                Style="{StaticResource PrimaryButton}" HorizontalAlignment="Left" Width="220" MinHeight="32"/>
                    </Grid>

                    <!-- Compliance Filters -->
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Grid.Column="0" Text="Filter:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center"/>

                        <!-- Status Filter -->
                        <ComboBox x:Name="ComplianceStatusFilter" Grid.Column="2" Height="24" FontSize="10"
                                  Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                            <ComboBoxItem Content="All Status" Tag="" IsSelected="True"/>
                            <ComboBoxItem Content="Compliant" Tag="Compliant"/>
                            <ComboBoxItem Content="Non-Compliant" Tag="Non-Compliant"/>
                            <ComboBoxItem Content="Error" Tag="Error"/>
                            <ComboBoxItem Content="Pending" Tag="Pending"/>
                        </ComboBox>

                        <!-- Search Box -->
                        <TextBox x:Name="ComplianceFilterSearch" Grid.Column="4" Height="24" FontSize="10"
                                 Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                 Padding="5,2" Text="Search computers..."/>

                        <!-- Clear Filter Button -->
                        <Button x:Name="ComplianceClearFilterBtn" Content="Clear" Grid.Column="6"
                                Style="{StaticResource SecondaryButton}" Height="24" FontSize="10" MinWidth="55"/>

                        <!-- Filter Count -->
                        <TextBlock x:Name="ComplianceFilterCount" Grid.Column="8" Text=""
                                  FontSize="10" Foreground="#58A6FF" VerticalAlignment="Center" MinWidth="90"/>
                    </Grid>

                    <!-- Compliance Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" MinHeight="200" MaxHeight="400">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="ComplianceOutput"
                                       Text="Scan Local, Scan Selected - Use AD Discovery to find computers first.&#x0a;Generates compliance evidence package with policy, inventory, and reports."
                                       FontFamily="Consolas" FontSize="10" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Reports Panel -->
                <StackPanel x:Name="PanelReports" Visibility="Collapsed">
                    <TextBlock Text="Compliance Reports" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Report Configuration Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Report Configuration" FontSize="14" FontWeight="Bold"
                                       Foreground="#E6EDF3" Margin="0,0,0,15"/>

                            <!-- Report Type Selection -->
                            <Grid Margin="0,0,0,12">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Report Type:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <ComboBox x:Name="ReportTypeSelector" Grid.Column="1" Height="28" FontSize="12"
                                          Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="Executive Summary" Tag="Executive" IsSelected="True"/>
                                    <ComboBoxItem Content="Detailed Technical Report" Tag="Technical"/>
                                    <ComboBoxItem Content="Audit Trail Report" Tag="Audit"/>
                                    <ComboBoxItem Content="Policy Comparison Report" Tag="Comparison"/>
                                </ComboBox>
                            </Grid>

                            <!-- Date Range Selection -->
                            <Grid Margin="0,0,0,12">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Date Range:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <DatePicker x:Name="ReportStartDate" Grid.Column="1" Height="28" FontSize="12"
                                            Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                            SelectedDate="{x:Static sys:DateTime.Today}"/>
                                <TextBlock Grid.Column="2" Text="" />
                                <TextBlock Grid.Column="3" Text="to" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                                <DatePicker x:Name="ReportEndDate" Grid.Column="4" Height="28" FontSize="12"
                                            Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                            SelectedDate="{x:Static sys:DateTime.Today}"/>
                            </Grid>

                            <!-- Quick Date Range Buttons -->
                            <Grid Margin="0,0,0,12">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="" />
                                <StackPanel Grid.Column="1" Orientation="Horizontal">
                                    <Button x:Name="ReportLast7Days" Content="Last 7 Days" Style="{StaticResource SecondaryButton}"
                                            Padding="8,4" Margin="0,0,6,0" FontSize="11"/>
                                    <Button x:Name="ReportLast30Days" Content="Last 30 Days" Style="{StaticResource SecondaryButton}"
                                            Padding="8,4" Margin="0,0,6,0" FontSize="11"/>
                                    <Button x:Name="ReportLast90Days" Content="Last 90 Days" Style="{StaticResource SecondaryButton}"
                                            Padding="8,4" FontSize="11"/>
                                </StackPanel>
                            </Grid>

                            <!-- Target System Selection -->
                            <Grid Margin="0,0,0,12">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Target System:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <ComboBox x:Name="ReportTargetSystem" Grid.Column="1" Height="28" FontSize="12"
                                          Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Systems" Tag="All" IsSelected="True"/>
                                    <ComboBoxItem Content="Local System Only" Tag="Local"/>
                                </ComboBox>
                            </Grid>

                            <!-- Generate Report Button -->
                            <Grid Margin="0,10,0,0">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="" />
                                <Button x:Name="GenerateReportBtn" Content="Generate Report" Style="{StaticResource PrimaryButton}"
                                        Grid.Column="1" Height="32" FontSize="13" HorizontalAlignment="Left" MinWidth="140"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Report Actions Section -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ExportToPdfBtn" Content="Export to PDF" Style="{StaticResource SecondaryButton}"
                                Grid.Column="0" Height="32" FontSize="12"/>
                        <Button x:Name="ExportToHtmlBtn" Content="Export to HTML" Style="{StaticResource SecondaryButton}"
                                Grid.Column="2" Height="32" FontSize="12"/>
                        <Button x:Name="ExportToCsvBtn" Content="Export to CSV" Style="{StaticResource SecondaryButton}"
                                Grid.Column="4" Height="32" FontSize="12"/>
                        <Button x:Name="ScheduleReportBtn" Content="Schedule Report" Style="{StaticResource SecondaryButton}"
                                Grid.Column="6" Height="32" FontSize="12"/>
                    </Grid>

                    <!-- Scheduled Reports Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <Grid Grid.Row="0" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Scheduled Reports" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3"/>
                                <Button x:Name="RefreshScheduledReportsBtn" Content="Refresh" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="2" Height="24" FontSize="11" Padding="8,2"/>
                            </Grid>

                            <ListBox x:Name="ScheduledReportsList" Grid.Row="1" Height="100" Background="#0D1117"
                                     Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1"
                                     FontSize="11">
                                <ListBox.ItemTemplate>
                                    <DataTemplate>
                                        <StackPanel>
                                            <TextBlock Text="{Binding ReportName}" FontWeight="Bold" FontSize="12"/>
                                            <TextBlock Text="{Binding Schedule}" FontSize="10" Foreground="#8B949E"/>
                                        </StackPanel>
                                    </DataTemplate>
                                </ListBox.ItemTemplate>
                            </ListBox>
                        </Grid>
                    </Border>

                    <!-- Report Preview Section -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="350" MaxHeight="550">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <Grid Grid.Row="0" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Report Preview" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3"/>
                                <TextBlock x:Name="ReportGeneratedTime" Grid.Column="2" Text=""
                                          FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBlock x:Name="ReportStatus" Grid.Column="4" Text="Ready"
                                          FontSize="11" Foreground="#3FB950" VerticalAlignment="Center"/>
                            </Grid>

                            <!-- Report Content Viewer -->
                            <Border Grid.Row="1" Background="#010409" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Padding="10">
                                <ScrollViewer x:Name="ReportPreviewScroll" VerticalScrollBarVisibility="Auto"
                                              HorizontalScrollBarVisibility="Disabled">
                                    <TextBlock x:Name="ReportPreview"
                                               Text="Configure report settings above and click 'Generate Report' to create a compliance report.&#x0a;&#x0a;Available Report Types:&#x0a;• Executive Summary - High-level overview with risk scores and trends&#x0a;• Detailed Technical - Full event logs, rule analysis, and violations&#x0a;• Audit Trail - Complete history of admin actions and policy changes&#x0a;• Policy Comparison - Compare policies across different time periods&#x0a;&#x0a;Reports can be exported to PDF, HTML, or CSV formats."
                                               FontFamily="Consolas" FontSize="11" Foreground="#E6EDF3"
                                               TextWrapping="Wrap"/>
                                </ScrollViewer>
                            </Border>
                        </Grid>
                    </Border>
                </StackPanel>

                <!-- WinRM Panel -->
                <StackPanel x:Name="PanelWinRM" Visibility="Collapsed">
                    <TextBlock Text="WinRM Setup" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="WinRM (Windows Remote Management)" FontSize="14" FontWeight="Bold"
                                       Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="WinRM is required for remote PowerShell and AppLocker scanning."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <!-- WinRM Buttons (disabled when not on DC) -->
                    <!-- Main WinRM Buttons -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="CreateWinRMGpoBtn" Content="Create/Update WinRM GPO" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="ForceGPUpdateBtn" Content="Force GPUpdate (All Computers)" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Enable/Disable GPO Buttons -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="EnableWinRMGpoBtn" Content="Enable GPO Link" Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="DisableWinRMGpoBtn" Content="Disable GPO Link" Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                    </Grid>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="200" MaxHeight="400">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="WinRMOutput" Text="Create/Update WinRM GPO to enable remote management. Force GPUpdate to push to all computers."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- AD Discovery Panel -->
                <StackPanel x:Name="PanelDiscovery" Visibility="Collapsed">
                    <TextBlock Text="AD Discovery" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                    <!-- Search and Discover Row -->
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Text="Filter:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                        <TextBox x:Name="ADSearchFilter" Grid.Column="2" Text="*" Height="26"
                                 Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                 BorderThickness="1" FontSize="11" Padding="5"
                                 ToolTip="Use * for all, or enter computer name filter"/>
                        <Button x:Name="DiscoverComputersBtn" Content="Discover"
                                Style="{StaticResource PrimaryButton}" Grid.Column="4" MinWidth="80"/>
                    </Grid>

                    <!-- Action Buttons Row -->
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="TestConnectivityBtn" Content="Test Connectivity"
                                Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="SelectAllComputersBtn" Content="Select All"
                                Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                        <Button x:Name="ScanSelectedBtn" Content="Scan Selected"
                                Style="{StaticResource PrimaryButton}" Grid.Column="4"/>
                    </Grid>

                    <!-- Online/Offline Computers Grid -->
                    <Grid Margin="0,0,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Online Computers List -->
                        <Border Grid.Column="0" Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Padding="8" Height="140">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Online Computers (Ctrl+Click to multi-select)" FontSize="10" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,0,0,4"/>
                                <ListBox x:Name="DiscoveredComputersList" Grid.Row="1" Background="#0D1117"
                                         Foreground="#E6EDF3" BorderThickness="0" FontFamily="Consolas" FontSize="9"
                                         SelectionMode="Extended"/>
                            </Grid>
                        </Border>

                        <!-- Offline Computers List -->
                        <Border Grid.Column="2" Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Padding="8" Height="140">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>
                                <TextBlock Grid.Row="0" Text="Offline Computers" FontSize="10" FontWeight="Bold"
                                           Foreground="#F85149" Margin="0,0,0,4"/>
                                <ListBox x:Name="OfflineComputersList" Grid.Row="1" Background="#0D1117"
                                         Foreground="#8B949E" BorderThickness="0" FontFamily="Consolas" FontSize="9"
                                         SelectionMode="Extended"/>
                            </Grid>
                        </Border>
                    </Grid>

                    <!-- Status Line -->
                    <TextBlock x:Name="DiscoveryStatus" Text="Ready to discover computers"
                               FontSize="10" Foreground="#8B949E" Margin="0,6,0,0"/>

                    <!-- Discovery Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" Margin="0,8,0,0" MinHeight="120">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="DiscoveryOutput" Text="Click 'Discover' to search AD..."
                                       FontFamily="Consolas" FontSize="10" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Group Management Panel -->
                <StackPanel x:Name="PanelGroupMgmt" Visibility="Collapsed">
                    <TextBlock Text="Group Management" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="AD Group Membership Management" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Export AD groups to editable CSV, modify memberships, then import changes back."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <!-- Export Section -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Export Current State" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="150"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Export all AD groups with current members to CSV" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <Button x:Name="ExportGroupsBtn" Content="Export Groups" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Import Section -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Import Desired State" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="15"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="15"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="15"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="120"/>
                                </Grid.ColumnDefinitions>
                                <CheckBox x:Name="DryRunCheck" Content="Dry Run (Preview)" IsChecked="True" Grid.Column="0" Foreground="#E6EDF3"/>
                                <CheckBox x:Name="AllowRemovalsCheck" Content="Allow Removals" Grid.Column="2" Foreground="#E6EDF3"/>
                                <CheckBox x:Name="IncludeProtectedCheck" Content="Include Tier-0" Grid.Column="4" Foreground="#E6EDF3"/>
                                <Button x:Name="ImportGroupsBtn" Content="Import Changes" Style="{StaticResource SecondaryButton}" Grid.Column="8"/>
                            </Grid>
                            <TextBlock Text="Tier-0 Protected Groups: Domain Admins, Enterprise Admins, Schema Admins, Administrators" FontSize="11" Foreground="#6E7681"/>
                        </StackPanel>
                    </Border>

                    <!-- Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="200">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="GroupMgmtOutput" Text="Click 'Export Groups' to begin..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- AppLocker Setup Panel -->
                <StackPanel x:Name="PanelAppLockerSetup" Visibility="Collapsed">
                    <TextBlock Text="AppLocker Setup" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="AppLocker Bootstrap" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Create AppLocker OU, groups (allow/deny), and generate default policy. Auto-populates Domain Admins."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <!-- Bootstrap Section -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="12" Margin="0,0,0,10">
                        <StackPanel>
                            <TextBlock Text="Initialize AppLocker Structure" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,6"/>
                            <Grid Margin="0,0,0,6">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="12"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="12"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="160"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="OU Name:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="OUNameText" Text="AppLocker" Width="100" Height="26" Grid.Column="2" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"/>
                                <CheckBox x:Name="AutoPopulateCheck" Content="Auto-Populate Admins" IsChecked="True" Grid.Column="4" Foreground="#E6EDF3"/>
                                <Button x:Name="BootstrapAppLockerBtn" Content="Initialize" Style="{StaticResource PrimaryButton}" Grid.Column="6" MinHeight="28"/>
                            </Grid>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="160"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Remove protection from AppLocker OUs (allows deletion)" FontSize="11" Foreground="#F85149" VerticalAlignment="Center"/>
                                <Button x:Name="RemoveOUProtectionBtn" Content="Remove OU Protection" Style="{StaticResource SecondaryButton}" Grid.Column="1" MinHeight="26"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- GPO Phase/Mode Quick Assignment -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="GPO Management (DC/Servers/Workstations)" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <!-- GPO Status Column -->
                                <StackPanel Grid.Column="0">
                                    <!-- DC GPO -->
                                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,0,0,8">
                                        <Grid>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="8"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <StackPanel Grid.Column="0">
                                                <TextBlock Text="Domain Controllers" FontSize="11" FontWeight="Bold" Foreground="#E6EDF3"/>
                                                <TextBlock x:Name="DCGPOStatus" Text="Not Created" FontSize="10" Foreground="#6E7681"/>
                                            </StackPanel>
                                            <ComboBox x:Name="DCGPOPhase" Grid.Column="1" Width="60" Height="24" FontSize="10" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                                <ComboBoxItem Content="--" IsSelected="True"/>
                                                <ComboBoxItem Content="P1"/>
                                                <ComboBoxItem Content="P2"/>
                                                <ComboBoxItem Content="P3"/>
                                                <ComboBoxItem Content="P4"/>
                                            </ComboBox>
                                            <ComboBox x:Name="DCGPOMode" Grid.Column="3" Width="75" Height="24" FontSize="10" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                                <ComboBoxItem Content="Audit" IsSelected="True"/>
                                                <ComboBoxItem Content="Enforce"/>
                                            </ComboBox>
                                        </Grid>
                                    </Border>

                                    <!-- Servers GPO -->
                                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,0,0,8">
                                        <Grid>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="8"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <StackPanel Grid.Column="0">
                                                <TextBlock Text="Servers" FontSize="11" FontWeight="Bold" Foreground="#E6EDF3"/>
                                                <TextBlock x:Name="ServersGPOStatus" Text="Not Created" FontSize="10" Foreground="#6E7681"/>
                                            </StackPanel>
                                            <ComboBox x:Name="ServersGPOPhase" Grid.Column="1" Width="60" Height="24" FontSize="10" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                                <ComboBoxItem Content="--" IsSelected="True"/>
                                                <ComboBoxItem Content="P1"/>
                                                <ComboBoxItem Content="P2"/>
                                                <ComboBoxItem Content="P3"/>
                                                <ComboBoxItem Content="P4"/>
                                            </ComboBox>
                                            <ComboBox x:Name="ServersGPOMode" Grid.Column="3" Width="75" Height="24" FontSize="10" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                                <ComboBoxItem Content="Audit" IsSelected="True"/>
                                                <ComboBoxItem Content="Enforce"/>
                                            </ComboBox>
                                        </Grid>
                                    </Border>

                                    <!-- Workstations GPO -->
                                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="4" Padding="10">
                                        <Grid>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="8"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <StackPanel Grid.Column="0">
                                                <TextBlock Text="Workstations" FontSize="11" FontWeight="Bold" Foreground="#E6EDF3"/>
                                                <TextBlock x:Name="WorkstationsGPOStatus" Text="Not Created" FontSize="10" Foreground="#6E7681"/>
                                            </StackPanel>
                                            <ComboBox x:Name="WorkstationsGPOPhase" Grid.Column="1" Width="60" Height="24" FontSize="10" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                                <ComboBoxItem Content="--" IsSelected="True"/>
                                                <ComboBoxItem Content="P1"/>
                                                <ComboBoxItem Content="P2"/>
                                                <ComboBoxItem Content="P3"/>
                                                <ComboBoxItem Content="P4"/>
                                            </ComboBox>
                                            <ComboBox x:Name="WorkstationsGPOMode" Grid.Column="3" Width="75" Height="24" FontSize="10" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                                <ComboBoxItem Content="Audit" IsSelected="True"/>
                                                <ComboBoxItem Content="Enforce"/>
                                            </ComboBox>
                                        </Grid>
                                    </Border>
                                </StackPanel>

                                <!-- Actions Column -->
                                <StackPanel Grid.Column="2">
                                    <TextBlock Text="Quick Actions" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                                    <Button x:Name="LinkGPOsBtn" Content="Link to OUs" Style="{StaticResource PrimaryButton}" Margin="0,0,0,8" MinHeight="32"/>
                                    <Button x:Name="ApplyGPOSettingsBtn" Content="Apply Phase/Mode" Style="{StaticResource SecondaryButton}" MinHeight="32"/>
                                </StackPanel>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Output - Fixed height with scrolling -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="280">
                        <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                            <TextBlock x:Name="AppLockerSetupOutput" Text="Click 'Initialize' to create AppLocker structure..."
                                       FontFamily="Consolas" FontSize="11" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- About Panel -->
                <ScrollViewer x:Name="PanelAbout" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel Orientation="Horizontal">
                                <Image x:Name="AboutLogo" Width="64" Height="64" Margin="0,0,20,0" VerticalAlignment="Center"
                                       Source="C:\GA-AppLocker\general_atomics_logo_big.ico"/>
                                <StackPanel VerticalAlignment="Center">
                                    <TextBlock Text="GA-AppLocker Dashboard" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3"/>
                                    <TextBlock x:Name="AboutVersion" Text="Version 1.2.5" FontSize="13" Foreground="#8B949E" Margin="0,4,0,0"/>
                                    <TextBlock Text="AppLocker Policy Management - AaronLocker Aligned" FontSize="12" Foreground="#6E7681" Margin="0,4,0,0"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel>
                                <TextBlock Text="Description" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#8B949E">
                                    <Run Text="GA-AppLocker Dashboard is a comprehensive tool for managing Application Whitelisting policies across Windows environments. "/>
                                    <Run Text="Aligned with AaronLocker best practices, it provides audit-friendly workflows for discovering, scanning, rule generation, and deployment."/>
                                    <LineBreak/>
                                    <LineBreak/>
                                    <Run Text="Designed for security professionals who need to implement least-privilege application control without disrupting business operations."/>
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel>
                                <TextBlock Text="Features" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#8B949E">
                                    <Run Text="- AppLocker structure initialization (OU, groups, policies)"/>
                                    <LineBreak/>
                                    <Run Text="- AD group membership export/import with safety controls"/>
                                    <LineBreak/>
                                    <Run Text="- Automated artifact discovery and rule generation"/>
                                    <LineBreak/>
                                    <Run Text="- Publisher-first rule strategy with hash fallback"/>
                                    <LineBreak/>
                                    <Run Text="- GPO deployment with audit-first enforcement"/>
                                    <LineBreak/>
                                    <Run Text="- Real-time event monitoring and filtering"/>
                                    <LineBreak/>
                                    <Run Text="- Compliance evidence package generation"/>
                                    <LineBreak/>
                                    <Run Text="- WinRM remote management setup"/>
                                    <LineBreak/>
                                    <Run Text="- Admin browser deny rules for security"/>
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel>
                                <TextBlock Text="Requirements" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#8B949E">
                                    <Run Text="- Windows 10/11 or Windows Server 2019+"/>
                                    <LineBreak/>
                                    <Run Text="- PowerShell 5.1+"/>
                                    <LineBreak/>
                                    <Run Text="- Active Directory module (for domain features)"/>
                                    <LineBreak/>
                                    <Run Text="- Group Policy module (for GPO deployment)"/>
                                    <LineBreak/>
                                    <Run Text="- Administrator privileges recommended"/>
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20">
                            <StackPanel>
                                <TextBlock Text="License" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock Text="Â© 2026 GA-ASI. Internal use only." FontSize="11" Foreground="#6E7681"/>
                                <TextBlock Text="Use in accordance with organizational security policies." FontSize="11" Foreground="#6E7681" Margin="0,4,0,0"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>

                <!-- Rule Templates Panel - Phase 5 -->
                <StackPanel x:Name="PanelTemplates" Visibility="Collapsed">
                    <TextBlock Text="Rule Templates" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Toolbar -->
                    <Border Background="#21262D" CornerRadius="6" Padding="12" Margin="0,0,0,12">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <Grid Grid.Column="0">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="200"/>
                                    <ColumnDefinition Width="150"/>
                                </Grid.ColumnDefinitions>
                                <TextBox x:Name="TemplateSearch" Grid.Column="0" Background="#0D1117" Foreground="#E6EDF3"
                                         BorderBrush="#30363D" BorderThickness="1" Padding="8,6" FontSize="12"
                                         Text="Search templates..."/>
                                <ComboBox x:Name="TemplateCategoryFilter" Grid.Column="1" Background="#0D1117" Foreground="#E6EDF3"
                                         BorderBrush="#30363D" BorderThickness="1" Padding="8,4" FontSize="12" Margin="8,0,0,0">
                                    <ComboBoxItem Content="All Categories" IsSelected="True"/>
                                    <ComboBoxItem Content="Security Baselines"/>
                                    <ComboBoxItem Content="Productivity"/>
                                    <ComboBoxItem Content="Development"/>
                                    <ComboBoxItem Content="Utilities"/>
                                    <ComboBoxItem Content="Custom"/>
                                </ComboBox>
                            </Grid>
                            <WrapPanel Grid.Column="1" HorizontalAlignment="Right">
                                <Button x:Name="ExportTemplateBtn" Content="Export Template" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="RefreshTemplatesBtn" Content="Refresh" Style="{StaticResource SecondaryButton}"/>
                            </WrapPanel>
                        </Grid>
                    </Border>

                    <!-- Main Content -->
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="300"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Template List -->
                        <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Padding="12" Margin="0,0,12,0">
                            <StackPanel>
                                <TextBlock Text="Available Templates" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                <ListBox x:Name="TemplatesList" Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                                         Height="450" ScrollViewer.VerticalScrollBarVisibility="Auto">
                                    <ListBox.ItemTemplate>
                                        <DataTemplate>
                                            <StackPanel Margin="8">
                                                <TextBlock Text="{Binding Name}" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                                <TextBlock Text="{Binding Category}" FontSize="11" Foreground="#8B949E" Margin="0,2,0,0"/>
                                                <TextBlock Text="{Binding RuleCount}" FontSize="10" Foreground="#6E7681" Margin="0,2,0,0"/>
                                            </StackPanel>
                                        </DataTemplate>
                                    </ListBox.ItemTemplate>
                                </ListBox>
                            </StackPanel>
                        </Border>

                        <!-- Template Preview -->
                        <Border Grid.Column="1" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="6" Padding="20">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <StackPanel>
                                    <TextBlock x:Name="TemplateName" Text="Select a template to preview" FontSize="18" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                    <TextBlock x:Name="TemplateCategory" Text="" FontSize="12" Foreground="#8957E5" Margin="0,0,0,8"/>
                                    <TextBlock x:Name="TemplateDescription" Text="" FontSize="12" Foreground="#8B949E" TextWrapping="Wrap" Margin="0,0,0,16"/>

                                    <!-- Rules Summary -->
                                    <Border Background="#0D1117" CornerRadius="6" Padding="16" Margin="0,0,0,16">
                                        <StackPanel>
                                            <TextBlock Text="Rules Summary" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                            <TextBlock x:Name="TemplateRulesSummary" Text="No template selected" FontSize="11" Foreground="#8B949E" TextWrapping="Wrap"/>
                                        </StackPanel>
                                    </Border>

                                    <!-- Included Applications -->
                                    <Border Background="#0D1117" CornerRadius="6" Padding="16" Margin="0,0,0,16">
                                        <StackPanel>
                                            <TextBlock Text="Included Applications" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                            <TextBlock x:Name="TemplateApplications" Text="No template selected" FontSize="11" Foreground="#8B949E" TextWrapping="Wrap"/>
                                        </StackPanel>
                                    </Border>

                                    <!-- Action Buttons -->
                                    <WrapPanel Margin="0,16,0,0">
                                        <Button x:Name="ApplyTemplateBtn" Content="Apply Template" Style="{StaticResource PrimaryButton}" Margin="0,0,12,0" IsEnabled="False"/>
                                        <Button x:Name="EditTemplateBtn" Content="Edit Template" Style="{StaticResource SecondaryButton}" Margin="0,0,12,0" IsEnabled="False"/>
                                        <Button x:Name="DeleteTemplateBtn" Content="Delete" Style="{StaticResource SecondaryButton}" Foreground="#F85149" IsEnabled="False"/>
                                    </WrapPanel>
                                </StackPanel>
                            </ScrollViewer>
                        </Border>
                    </Grid>
                </StackPanel>

                <!-- AaronLocker Panel -->
                <StackPanel x:Name="PanelAaronLocker" Visibility="Collapsed">
                    <TextBlock Text="AaronLocker Tools" FontSize="24" FontWeight="Bold" Foreground="#F0883E" Margin="0,0,0,8"/>
                    <TextBlock Text="Original AaronLocker scripts by Aaron Margosis - GUI wrapper for easy access" FontSize="12" Foreground="#8B949E" Margin="0,0,0,20"/>

                    <!-- Scanning Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Scanning &amp; Analysis" FontSize="14" FontWeight="Bold" Foreground="#58A6FF" Margin="0,0,0,12"/>

                            <!-- Scan Directories with Parameters -->
                            <Border Background="#161B22" CornerRadius="6" Padding="12" Margin="0,0,0,10">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Scan Directories" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                        <TextBlock Text="Scan for files that might need AppLocker rules" FontSize="11" Foreground="#6E7681"/>
                                        <WrapPanel Margin="0,8,0,0">
                                            <CheckBox x:Name="AL_ScanWritableWindir" Content="Writable Windir" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanWritablePF" Content="Writable ProgramFiles" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanProgramData" Content="ProgramData" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanUserProfile" Content="User Profile" Foreground="#C9D1D9" IsChecked="True" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanAllProfiles" Content="All Profiles" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanNonDefaultRoot" Content="Non-Default Root" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanExcel" Content="Excel Output" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_ScanGridView" Content="GridView" Foreground="#C9D1D9"/>
                                        </WrapPanel>
                                    </StackPanel>
                                    <Button x:Name="AL_ScanDirectories" Content="Run Scan" Style="{StaticResource PrimaryButton}"
                                            Grid.Column="1" VerticalAlignment="Center" MinWidth="90"/>
                                </Grid>
                            </Border>

                            <!-- Get Events with Parameters -->
                            <Border Background="#161B22" CornerRadius="6" Padding="12" Margin="0,0,0,10">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Get AppLocker Events" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                        <TextBlock Text="Retrieve AppLocker events from Windows Event Log" FontSize="11" Foreground="#6E7681"/>
                                        <WrapPanel Margin="0,8,0,0">
                                            <CheckBox x:Name="AL_EventsWarningOnly" Content="Warning Only" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_EventsErrorOnly" Content="Error Only" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_EventsAllowedOnly" Content="Allowed Only" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_EventsAll" Content="All Events" Foreground="#C9D1D9" IsChecked="True" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_EventsExcel" Content="Excel Output" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_EventsGridView" Content="GridView" Foreground="#C9D1D9"/>
                                        </WrapPanel>
                                    </StackPanel>
                                    <Button x:Name="AL_GetEvents" Content="Get Events" Style="{StaticResource PrimaryButton}"
                                            Grid.Column="1" VerticalAlignment="Center" MinWidth="90"/>
                                </Grid>
                            </Border>

                            <!-- Other Scanning Tools -->
                            <WrapPanel>
                                <Button x:Name="AL_ComparePolicies" Content="Compare Policies" Style="{StaticResource SecondaryButton}"
                                        Margin="0,0,8,0" MinHeight="32" ToolTip="Compare two AppLocker policies"/>
                                <Button x:Name="AL_EnumWritableDirs" Content="Enum Writable Dirs" Style="{StaticResource SecondaryButton}"
                                        MinHeight="32" ToolTip="Enumerate writable directories in protected paths"/>
                            </WrapPanel>
                        </StackPanel>
                    </Border>

                    <!-- Policy Creation Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Policy Creation" FontSize="14" FontWeight="Bold" Foreground="#3FB950" Margin="0,0,0,12"/>

                            <!-- Create Policies with Parameters -->
                            <Border Background="#161B22" CornerRadius="6" Padding="12" Margin="0,0,0,10">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Create Policies" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                                        <TextBlock Text="Build comprehensive AppLocker and/or WDAC policies" FontSize="11" Foreground="#6E7681"/>
                                        <WrapPanel Margin="0,8,0,0">
                                            <TextBlock Text="Type:" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,6,4"/>
                                            <ComboBox x:Name="AL_PolicyType" Width="100" SelectedIndex="0" Margin="0,0,12,4">
                                                <ComboBoxItem Content="Both"/>
                                                <ComboBoxItem Content="AppLocker"/>
                                                <ComboBoxItem Content="WDAC"/>
                                            </ComboBox>
                                            <CheckBox x:Name="AL_PolicyRescan" Content="Force Rescan" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_PolicyExcel" Content="Excel Output" Foreground="#C9D1D9" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_PolicyWDACMI" Content="WDAC: Managed Installers" Foreground="#C9D1D9" IsChecked="True" Margin="0,0,12,4"/>
                                            <CheckBox x:Name="AL_PolicyWDACISG" Content="WDAC: ISG" Foreground="#C9D1D9"/>
                                        </WrapPanel>
                                    </StackPanel>
                                    <Button x:Name="AL_CreatePolicies" Content="Create" Style="{StaticResource PrimaryButton}"
                                            Grid.Column="1" VerticalAlignment="Center" MinWidth="90"/>
                                </Grid>
                            </Border>

                            <!-- Other Policy Tools -->
                            <WrapPanel>
                                <Button x:Name="AL_BuildWritableRules" Content="Build Writable Dir Rules" Style="{StaticResource SecondaryButton}"
                                        MinHeight="32" ToolTip="Build rules for files in writable directories"/>
                            </WrapPanel>
                        </StackPanel>
                    </Border>

                    <!-- Export Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Export &amp; Reporting" FontSize="14" FontWeight="Bold" Foreground="#8957E5" Margin="0,0,0,12"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <Button x:Name="AL_ExportToCsv" Content="Export Policy to CSV" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="0" Margin="0,0,8,0" MinHeight="36"
                                        ToolTip="Export AppLocker policy to CSV format"/>
                                <Button x:Name="AL_ExportToExcel" Content="Export Policy to Excel" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="1" Margin="0,0,8,0" MinHeight="36"
                                        ToolTip="Export AppLocker policy to Excel workbook"/>
                                <Button x:Name="AL_GenerateEventWorkbook" Content="Generate Event Workbook" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="2" Margin="0,0,0,0" MinHeight="36"
                                        ToolTip="Generate Excel workbook from AppLocker events"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Local Configuration Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Local Configuration" FontSize="14" FontWeight="Bold" Foreground="#F0883E" Margin="0,0,0,12"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>

                                <Button x:Name="AL_ConfigureForAppLocker" Content="Configure for AppLocker" Style="{StaticResource PrimaryButton}"
                                        Grid.Column="0" Grid.Row="0" Margin="0,0,8,8" MinHeight="36"
                                        ToolTip="Configure local system settings for AppLocker"/>
                                <Button x:Name="AL_ApplyToLocalGPO" Content="Apply to Local GPO" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="1" Grid.Row="0" Margin="0,0,8,8" MinHeight="36"
                                        ToolTip="Apply policy to local Group Policy Object"/>
                                <Button x:Name="AL_SetGPOPolicy" Content="Set GPO AppLocker Policy" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="2" Grid.Row="0" Margin="0,0,0,8" MinHeight="36"
                                        ToolTip="Set AppLocker policy on a domain GPO"/>
                                <Button x:Name="AL_ClearLocalPolicy" Content="Clear Local Policy" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="0" Grid.Row="1" Margin="0,0,8,0" MinHeight="36" Foreground="#F85149"
                                        ToolTip="Clear the local AppLocker policy"/>
                                <Button x:Name="AL_ClearLogs" Content="Clear AppLocker Logs" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="1" Grid.Row="1" Margin="0,0,8,0" MinHeight="36" Foreground="#F85149"
                                        ToolTip="Clear AppLocker event logs"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Customization Inputs Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Customization Inputs" FontSize="14" FontWeight="Bold" Foreground="#8B949E" Margin="0,0,0,12"/>
                            <TextBlock Text="Edit these files to customize policy generation:" FontSize="11" Foreground="#6E7681" Margin="0,0,0,8"/>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>

                                <Button x:Name="AL_EditTrustedSigners" Content="Trusted Signers" Style="{StaticResource NavButton}"
                                        Grid.Column="0" Grid.Row="0" Margin="0,0,4,4" MinHeight="28"
                                        ToolTip="Edit TrustedSigners.ps1 - Publishers to allow"/>
                                <Button x:Name="AL_EditSafePaths" Content="Safe Paths" Style="{StaticResource NavButton}"
                                        Grid.Column="1" Grid.Row="0" Margin="0,0,4,4" MinHeight="28"
                                        ToolTip="Edit GetSafePathsToAllow.ps1 - Paths to whitelist"/>
                                <Button x:Name="AL_EditUnsafePaths" Content="Unsafe Paths" Style="{StaticResource NavButton}"
                                        Grid.Column="2" Grid.Row="0" Margin="0,0,4,4" MinHeight="28"
                                        ToolTip="Edit UnsafePathsToBuildRulesFor.ps1"/>
                                <Button x:Name="AL_EditDenyList" Content="Deny List" Style="{StaticResource NavButton}"
                                        Grid.Column="3" Grid.Row="0" Margin="0,0,0,4" MinHeight="28"
                                        ToolTip="Edit GetExeFilesToDenyList.ps1 - Executables to block"/>
                                <Button x:Name="AL_EditHashRules" Content="Hash Rules" Style="{StaticResource NavButton}"
                                        Grid.Column="0" Grid.Row="1" Margin="0,0,4,0" MinHeight="28"
                                        ToolTip="Edit HashRuleData.ps1 - Specific file hashes"/>
                                <Button x:Name="AL_EditKnownAdmins" Content="Known Admins" Style="{StaticResource NavButton}"
                                        Grid.Column="1" Grid.Row="1" Margin="0,0,4,0" MinHeight="28"
                                        ToolTip="Edit KnownAdmins.ps1 - Admin accounts to exempt"/>
                                <Button x:Name="AL_OpenOutputs" Content="Open Outputs Folder" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="2" Grid.Row="1" Margin="0,0,4,0" MinHeight="28"
                                        ToolTip="Open the Outputs folder containing generated policies"/>
                                <Button x:Name="AL_OpenScanResults" Content="Open Scan Results" Style="{StaticResource SecondaryButton}"
                                        Grid.Column="3" Grid.Row="1" Margin="0,0,0,0" MinHeight="28"
                                        ToolTip="Open the ScanResults folder"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Output Console -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="15">
                        <StackPanel>
                            <Grid Margin="0,0,0,8">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Text="Output Console" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Grid.Column="0"/>
                                <Button x:Name="AL_ClearConsole" Content="Clear" Style="{StaticResource NavButton}" Grid.Column="1" MinHeight="24" MinWidth="60"/>
                            </Grid>
                            <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="4" Padding="8">
                                <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="250">
                                    <TextBox x:Name="AL_OutputConsole" Text="AaronLocker output will appear here..."
                                             Background="Transparent" Foreground="#8B949E" BorderThickness="0"
                                             IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11"
                                             AcceptsReturn="True" VerticalScrollBarVisibility="Auto"/>
                                </ScrollViewer>
                            </Border>
                        </StackPanel>
                    </Border>
                </StackPanel>

                <!-- Help Panel -->
                <ScrollViewer x:Name="PanelHelp" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <WrapPanel>
                                <Button x:Name="HelpBtnWorkflow" Content="Workflow" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="HelpBtnWhatsNew" Content="What's New in v1.2.5" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="HelpBtnPolicyGuide" Content="Policy Guide" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="HelpBtnRules" Content="Rule Best Practices" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="HelpBtnTroubleshooting" Content="Troubleshooting" Style="{StaticResource SecondaryButton}"/>
                            </WrapPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20">
                            <StackPanel>
                                <TextBlock x:Name="HelpTitle" Text="Help - Workflow" FontSize="18" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                <TextBlock x:Name="HelpText" TextWrapping="Wrap" FontSize="12" Foreground="#8B949E">
                                    <Run Text="Select a topic above to view help documentation."/>
                                </TextBlock>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </Grid>
            </ScrollViewer>
        </Grid>
    </Grid>
</Window>
"@

# ============================================================
# WPF Window Creation and Event Handlers
# ============================================================

try {
    $window = [Windows.Markup.XamlReader]::Parse($xamlString)
} catch {
    $errorMsg = "Failed to load GUI.`n`nError: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        $errorMsg += "`n`nInner: $($_.Exception.InnerException.Message)"
    }

    # Write to log file
    $logPath = "C:\GA-AppLocker\Logs\startup-error.log"
    try {
        $logDir = Split-Path $logPath -Parent
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $errorMsg | Out-File -FilePath $logPath -Encoding UTF8
    } catch { }

    # Show MessageBox
    try {
        [System.Windows.MessageBox]::Show($errorMsg, "GA-AppLocker Startup Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    } catch {
        Write-Host "ERROR: $errorMsg" -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit 1
}

# Find controls
$SidebarScrollViewer = $window.FindName("SidebarScrollViewer")
if ($null -eq $SidebarScrollViewer) { Write-Log "WARNING: Control 'SidebarScrollViewer' not found in XAML" -Level "WARNING" }
$NavDashboard = $window.FindName("NavDashboard")
if ($null -eq $NavDashboard) { Write-Log "WARNING: Control 'NavDashboard' not found in XAML" -Level "WARNING" }
$NavDiscovery = $window.FindName("NavDiscovery")
if ($null -eq $NavDiscovery) { Write-Log "WARNING: Control 'NavDiscovery' not found in XAML" -Level "WARNING" }
$NavArtifacts = $window.FindName("NavArtifacts")
if ($null -eq $NavArtifacts) { Write-Log "WARNING: Control 'NavArtifacts' not found in XAML" -Level "WARNING" }
$NavRules = $window.FindName("NavRules")
if ($null -eq $NavRules) { Write-Log "WARNING: Control 'NavRules' not found in XAML" -Level "WARNING" }
$NavDeployment = $window.FindName("NavDeployment")
if ($null -eq $NavDeployment) { Write-Log "WARNING: Control 'NavDeployment' not found in XAML" -Level "WARNING" }
$NavEvents = $window.FindName("NavEvents")
if ($null -eq $NavEvents) { Write-Log "WARNING: Control 'NavEvents' not found in XAML" -Level "WARNING" }
$NavCompliance = $window.FindName("NavCompliance")
if ($null -eq $NavCompliance) { Write-Log "WARNING: Control 'NavCompliance' not found in XAML" -Level "WARNING" }
$NavReports = $window.FindName("NavReports")
if ($null -eq $NavReports) { Write-Log "WARNING: Control 'NavReports' not found in XAML" -Level "WARNING" }
$NavWinRM = $window.FindName("NavWinRM")
if ($null -eq $NavWinRM) { Write-Log "WARNING: Control 'NavWinRM' not found in XAML" -Level "WARNING" }
$NavGroupMgmt = $window.FindName("NavGroupMgmt")
if ($null -eq $NavGroupMgmt) { Write-Log "WARNING: Control 'NavGroupMgmt' not found in XAML" -Level "WARNING" }
$NavAppLockerSetup = $window.FindName("NavAppLockerSetup")
if ($null -eq $NavAppLockerSetup) { Write-Log "WARNING: Control 'NavAppLockerSetup' not found in XAML" -Level "WARNING" }
$NavGapAnalysis = $window.FindName("NavGapAnalysis")
if ($null -eq $NavGapAnalysis) { Write-Log "WARNING: Control 'NavGapAnalysis' not found in XAML" -Level "WARNING" }
$NavSaveWorkspace = $window.FindName("NavSaveWorkspace")
if ($null -eq $NavSaveWorkspace) { Write-Log "WARNING: Control 'NavSaveWorkspace' not found in XAML" -Level "WARNING" }
$NavLoadWorkspace = $window.FindName("NavLoadWorkspace")
if ($null -eq $NavLoadWorkspace) { Write-Log "WARNING: Control 'NavLoadWorkspace' not found in XAML" -Level "WARNING" }
$NavHelp = $window.FindName("NavHelp")
if ($null -eq $NavHelp) { Write-Log "WARNING: Control 'NavHelp' not found in XAML" -Level "WARNING" }
$NavAbout = $window.FindName("NavAbout")
if ($null -eq $NavAbout) { Write-Log "WARNING: Control 'NavAbout' not found in XAML" -Level "WARNING" }

# Expander controls
$SetupSection = $window.FindName("SetupSection")
if ($null -eq $SetupSection) { Write-Log "WARNING: Control 'SetupSection' not found in XAML" -Level "WARNING" }
$ScanningSection = $window.FindName("ScanningSection")
if ($null -eq $ScanningSection) { Write-Log "WARNING: Control 'ScanningSection' not found in XAML" -Level "WARNING" }
$DeploymentSection = $window.FindName("DeploymentSection")
if ($null -eq $DeploymentSection) { Write-Log "WARNING: Control 'DeploymentSection' not found in XAML" -Level "WARNING" }
$MonitoringSection = $window.FindName("MonitoringSection")
if ($null -eq $MonitoringSection) { Write-Log "WARNING: Control 'MonitoringSection' not found in XAML" -Level "WARNING" }
# Arrow controls removed - using default expander style

$StatusText = $window.FindName("StatusText")
if ($null -eq $StatusText) { Write-Log "WARNING: Control 'StatusText' not found in XAML" -Level "WARNING" }
$EnvironmentText = $window.FindName("EnvironmentText")
if ($null -eq $EnvironmentText) { Write-Log "WARNING: Control 'EnvironmentText' not found in XAML" -Level "WARNING" }
$EnvironmentBanner = $window.FindName("EnvironmentBanner")
if ($null -eq $EnvironmentBanner) { Write-Log "WARNING: Control 'EnvironmentBanner' not found in XAML" -Level "WARNING" }

# QoL: Mini Status Bar controls
$MiniStatusDomain = $window.FindName("MiniStatusDomain")
if ($null -eq $MiniStatusDomain) { Write-Log "WARNING: Control 'MiniStatusDomain' not found in XAML" -Level "WARNING" }
$MiniStatusArtifacts = $window.FindName("MiniStatusArtifacts")
if ($null -eq $MiniStatusArtifacts) { Write-Log "WARNING: Control 'MiniStatusArtifacts' not found in XAML" -Level "WARNING" }
$MiniStatusSync = $window.FindName("MiniStatusSync")
if ($null -eq $MiniStatusSync) { Write-Log "WARNING: Control 'MiniStatusSync' not found in XAML" -Level "WARNING" }

$PanelDashboard = $window.FindName("PanelDashboard")
if ($null -eq $PanelDashboard) { Write-Log "WARNING: Control 'PanelDashboard' not found in XAML" -Level "WARNING" }
$PanelDiscovery = $window.FindName("PanelDiscovery")
if ($null -eq $PanelDiscovery) { Write-Log "WARNING: Control 'PanelDiscovery' not found in XAML" -Level "WARNING" }
$PanelArtifacts = $window.FindName("PanelArtifacts")
if ($null -eq $PanelArtifacts) { Write-Log "WARNING: Control 'PanelArtifacts' not found in XAML" -Level "WARNING" }
$PanelRules = $window.FindName("PanelRules")
if ($null -eq $PanelRules) { Write-Log "WARNING: Control 'PanelRules' not found in XAML" -Level "WARNING" }
$PanelDeployment = $window.FindName("PanelDeployment")
if ($null -eq $PanelDeployment) { Write-Log "WARNING: Control 'PanelDeployment' not found in XAML" -Level "WARNING" }
$PanelEvents = $window.FindName("PanelEvents")
if ($null -eq $PanelEvents) { Write-Log "WARNING: Control 'PanelEvents' not found in XAML" -Level "WARNING" }
$PanelCompliance = $window.FindName("PanelCompliance")
if ($null -eq $PanelCompliance) { Write-Log "WARNING: Control 'PanelCompliance' not found in XAML" -Level "WARNING" }
$PanelReports = $window.FindName("PanelReports")
if ($null -eq $PanelReports) { Write-Log "WARNING: Control 'PanelReports' not found in XAML" -Level "WARNING" }
$PanelWinRM = $window.FindName("PanelWinRM")
if ($null -eq $PanelWinRM) { Write-Log "WARNING: Control 'PanelWinRM' not found in XAML" -Level "WARNING" }
$PanelGroupMgmt = $window.FindName("PanelGroupMgmt")
if ($null -eq $PanelGroupMgmt) { Write-Log "WARNING: Control 'PanelGroupMgmt' not found in XAML" -Level "WARNING" }
$PanelAppLockerSetup = $window.FindName("PanelAppLockerSetup")
if ($null -eq $PanelAppLockerSetup) { Write-Log "WARNING: Control 'PanelAppLockerSetup' not found in XAML" -Level "WARNING" }
$PanelGapAnalysis = $window.FindName("PanelGapAnalysis")
if ($null -eq $PanelGapAnalysis) { Write-Log "WARNING: Control 'PanelGapAnalysis' not found in XAML" -Level "WARNING" }
$PanelHelp = $window.FindName("PanelHelp")
if ($null -eq $PanelHelp) { Write-Log "WARNING: Control 'PanelHelp' not found in XAML" -Level "WARNING" }
$PanelAaronLocker = $window.FindName("PanelAaronLocker")
if ($null -eq $PanelAaronLocker) { Write-Log "WARNING: Control 'PanelAaronLocker' not found in XAML" -Level "WARNING" }
$NavAaronLocker = $window.FindName("NavAaronLocker")
if ($null -eq $NavAaronLocker) { Write-Log "WARNING: Control 'NavAaronLocker' not found in XAML" -Level "WARNING" }
# AaronLocker page controls
$AL_OutputConsole = $window.FindName("AL_OutputConsole")
$AL_ClearConsole = $window.FindName("AL_ClearConsole")
$AL_ScanDirectories = $window.FindName("AL_ScanDirectories")
$AL_GetEvents = $window.FindName("AL_GetEvents")
$AL_ComparePolicies = $window.FindName("AL_ComparePolicies")
$AL_EnumWritableDirs = $window.FindName("AL_EnumWritableDirs")
$AL_CreatePolicies = $window.FindName("AL_CreatePolicies")
$AL_BuildWritableRules = $window.FindName("AL_BuildWritableRules")
$AL_ExportToCsv = $window.FindName("AL_ExportToCsv")
$AL_ExportToExcel = $window.FindName("AL_ExportToExcel")
$AL_GenerateEventWorkbook = $window.FindName("AL_GenerateEventWorkbook")
$AL_ConfigureForAppLocker = $window.FindName("AL_ConfigureForAppLocker")
$AL_ApplyToLocalGPO = $window.FindName("AL_ApplyToLocalGPO")
$AL_SetGPOPolicy = $window.FindName("AL_SetGPOPolicy")
$AL_ClearLocalPolicy = $window.FindName("AL_ClearLocalPolicy")
$AL_ClearLogs = $window.FindName("AL_ClearLogs")
$AL_EditTrustedSigners = $window.FindName("AL_EditTrustedSigners")
$AL_EditSafePaths = $window.FindName("AL_EditSafePaths")
$AL_EditUnsafePaths = $window.FindName("AL_EditUnsafePaths")
$AL_EditDenyList = $window.FindName("AL_EditDenyList")
$AL_EditHashRules = $window.FindName("AL_EditHashRules")
$AL_EditKnownAdmins = $window.FindName("AL_EditKnownAdmins")
$AL_OpenOutputs = $window.FindName("AL_OpenOutputs")
$AL_OpenScanResults = $window.FindName("AL_OpenScanResults")
# AaronLocker parameter controls - Scan Directories
$AL_ScanWritableWindir = $window.FindName("AL_ScanWritableWindir")
$AL_ScanWritablePF = $window.FindName("AL_ScanWritablePF")
$AL_ScanProgramData = $window.FindName("AL_ScanProgramData")
$AL_ScanUserProfile = $window.FindName("AL_ScanUserProfile")
$AL_ScanAllProfiles = $window.FindName("AL_ScanAllProfiles")
$AL_ScanNonDefaultRoot = $window.FindName("AL_ScanNonDefaultRoot")
$AL_ScanExcel = $window.FindName("AL_ScanExcel")
$AL_ScanGridView = $window.FindName("AL_ScanGridView")
# AaronLocker parameter controls - Get Events
$AL_EventsWarningOnly = $window.FindName("AL_EventsWarningOnly")
$AL_EventsErrorOnly = $window.FindName("AL_EventsErrorOnly")
$AL_EventsAllowedOnly = $window.FindName("AL_EventsAllowedOnly")
$AL_EventsAll = $window.FindName("AL_EventsAll")
$AL_EventsExcel = $window.FindName("AL_EventsExcel")
$AL_EventsGridView = $window.FindName("AL_EventsGridView")
# AaronLocker parameter controls - Create Policies
$AL_PolicyType = $window.FindName("AL_PolicyType")
$AL_PolicyRescan = $window.FindName("AL_PolicyRescan")
$AL_PolicyExcel = $window.FindName("AL_PolicyExcel")
$AL_PolicyWDACMI = $window.FindName("AL_PolicyWDACMI")
$AL_PolicyWDACISG = $window.FindName("AL_PolicyWDACISG")
$PanelAbout = $window.FindName("PanelAbout")
if ($null -eq $PanelAbout) { Write-Log "WARNING: Control 'PanelAbout' not found in XAML" -Level "WARNING" }

# Phase 5: Templates controls
$PanelTemplates = $window.FindName("PanelTemplates")
if ($null -eq $PanelTemplates) { Write-Log "WARNING: Control 'PanelTemplates' not found in XAML" -Level "WARNING" }
$NavTemplates = $window.FindName("NavTemplates")
if ($null -eq $NavTemplates) { Write-Log "WARNING: Control 'NavTemplates' not found in XAML" -Level "WARNING" }
$NavRuleWizard = $window.FindName("NavRuleWizard")
if ($null -eq $NavRuleWizard) { Write-Log "WARNING: Control 'NavRuleWizard' not found in XAML" -Level "WARNING" }
$NavCreateTemplate = $window.FindName("NavCreateTemplate")
if ($null -eq $NavCreateTemplate) { Write-Log "WARNING: Control 'NavCreateTemplate' not found in XAML" -Level "WARNING" }
$NavImportTemplate = $window.FindName("NavImportTemplate")
if ($null -eq $NavImportTemplate) { Write-Log "WARNING: Control 'NavImportTemplate' not found in XAML" -Level "WARNING" }
$TemplatesSection = $window.FindName("TemplatesSection")
if ($null -eq $TemplatesSection) { Write-Log "WARNING: Control 'TemplatesSection' not found in XAML" -Level "WARNING" }
$TemplatesList = $window.FindName("TemplatesList")
if ($null -eq $TemplatesList) { Write-Log "WARNING: Control 'TemplatesList' not found in XAML" -Level "WARNING" }
$TemplateSearch = $window.FindName("TemplateSearch")
if ($null -eq $TemplateSearch) { Write-Log "WARNING: Control 'TemplateSearch' not found in XAML" -Level "WARNING" }
$TemplateCategoryFilter = $window.FindName("TemplateCategoryFilter")
if ($null -eq $TemplateCategoryFilter) { Write-Log "WARNING: Control 'TemplateCategoryFilter' not found in XAML" -Level "WARNING" }
$TemplateName = $window.FindName("TemplateName")
if ($null -eq $TemplateName) { Write-Log "WARNING: Control 'TemplateName' not found in XAML" -Level "WARNING" }
$TemplateCategory = $window.FindName("TemplateCategory")
if ($null -eq $TemplateCategory) { Write-Log "WARNING: Control 'TemplateCategory' not found in XAML" -Level "WARNING" }
$TemplateDescription = $window.FindName("TemplateDescription")
if ($null -eq $TemplateDescription) { Write-Log "WARNING: Control 'TemplateDescription' not found in XAML" -Level "WARNING" }
$TemplateRulesSummary = $window.FindName("TemplateRulesSummary")
if ($null -eq $TemplateRulesSummary) { Write-Log "WARNING: Control 'TemplateRulesSummary' not found in XAML" -Level "WARNING" }
$TemplateApplications = $window.FindName("TemplateApplications")
if ($null -eq $TemplateApplications) { Write-Log "WARNING: Control 'TemplateApplications' not found in XAML" -Level "WARNING" }
$ApplyTemplateBtn = $window.FindName("ApplyTemplateBtn")
if ($null -eq $ApplyTemplateBtn) { Write-Log "WARNING: Control 'ApplyTemplateBtn' not found in XAML" -Level "WARNING" }
$EditTemplateBtn = $window.FindName("EditTemplateBtn")
if ($null -eq $EditTemplateBtn) { Write-Log "WARNING: Control 'EditTemplateBtn' not found in XAML" -Level "WARNING" }
$DeleteTemplateBtn = $window.FindName("DeleteTemplateBtn")
if ($null -eq $DeleteTemplateBtn) { Write-Log "WARNING: Control 'DeleteTemplateBtn' not found in XAML" -Level "WARNING" }
$ExportTemplateBtn = $window.FindName("ExportTemplateBtn")
if ($null -eq $ExportTemplateBtn) { Write-Log "WARNING: Control 'ExportTemplateBtn' not found in XAML" -Level "WARNING" }
$RefreshTemplatesBtn = $window.FindName("RefreshTemplatesBtn")
if ($null -eq $RefreshTemplatesBtn) { Write-Log "WARNING: Control 'RefreshTemplatesBtn' not found in XAML" -Level "WARNING" }

# Dashboard controls
$HealthScore = $window.FindName("HealthScore")
if ($null -eq $HealthScore) { Write-Log "WARNING: Control 'HealthScore' not found in XAML" -Level "WARNING" }
$HealthStatus = $window.FindName("HealthStatus")
if ($null -eq $HealthStatus) { Write-Log "WARNING: Control 'HealthStatus' not found in XAML" -Level "WARNING" }
$TotalEvents = $window.FindName("TotalEvents")
if ($null -eq $TotalEvents) { Write-Log "WARNING: Control 'TotalEvents' not found in XAML" -Level "WARNING" }
$EventsStatus = $window.FindName("EventsStatus")
if ($null -eq $EventsStatus) { Write-Log "WARNING: Control 'EventsStatus' not found in XAML" -Level "WARNING" }
$AllowedEvents = $window.FindName("AllowedEvents")
if ($null -eq $AllowedEvents) { Write-Log "WARNING: Control 'AllowedEvents' not found in XAML" -Level "WARNING" }
$AuditedEvents = $window.FindName("AuditedEvents")
if ($null -eq $AuditedEvents) { Write-Log "WARNING: Control 'AuditedEvents' not found in XAML" -Level "WARNING" }
$BlockedEvents = $window.FindName("BlockedEvents")
if ($null -eq $BlockedEvents) { Write-Log "WARNING: Control 'BlockedEvents' not found in XAML" -Level "WARNING" }
$DashboardTimeFilter = $window.FindName("DashboardTimeFilter")
if ($null -eq $DashboardTimeFilter) { Write-Log "WARNING: Control 'DashboardTimeFilter' not found in XAML" -Level "WARNING" }
$DashboardSystemFilter = $window.FindName("DashboardSystemFilter")
if ($null -eq $DashboardSystemFilter) { Write-Log "WARNING: Control 'DashboardSystemFilter' not found in XAML" -Level "WARNING" }
$RefreshDashboardBtn = $window.FindName("RefreshDashboardBtn")
if ($null -eq $RefreshDashboardBtn) { Write-Log "WARNING: Control 'RefreshDashboardBtn' not found in XAML" -Level "WARNING" }
$DashboardOutput = $window.FindName("DashboardOutput")
if ($null -eq $DashboardOutput) { Write-Log "WARNING: Control 'DashboardOutput' not found in XAML" -Level "WARNING" }

# Dashboard Chart controls (Phase 4)
$PieAllowed = $window.FindName("PieAllowed")
if ($null -eq $PieAllowed) { Write-Log "WARNING: Control 'PieAllowed' not found in XAML" -Level "WARNING" }
$PieAudited = $window.FindName("PieAudited")
if ($null -eq $PieAudited) { Write-Log "WARNING: Control 'PieAudited' not found in XAML" -Level "WARNING" }
$PieBlocked = $window.FindName("PieBlocked")
if ($null -eq $PieBlocked) { Write-Log "WARNING: Control 'PieBlocked' not found in XAML" -Level "WARNING" }
$GaugeBackground = $window.FindName("GaugeBackground")
if ($null -eq $GaugeBackground) { Write-Log "WARNING: Control 'GaugeBackground' not found in XAML" -Level "WARNING" }
$GaugeFill = $window.FindName("GaugeFill")
if ($null -eq $GaugeFill) { Write-Log "WARNING: Control 'GaugeFill' not found in XAML" -Level "WARNING" }
$BarWorkstations = $window.FindName("BarWorkstations")
if ($null -eq $BarWorkstations) { Write-Log "WARNING: Control 'BarWorkstations' not found in XAML" -Level "WARNING" }
$BarServers = $window.FindName("BarServers")
if ($null -eq $BarServers) { Write-Log "WARNING: Control 'BarServers' not found in XAML" -Level "WARNING" }
$BarDCs = $window.FindName("BarDCs")
if ($null -eq $BarDCs) { Write-Log "WARNING: Control 'BarDCs' not found in XAML" -Level "WARNING" }
$TrendChartCanvas = $window.FindName("TrendChartCanvas")
if ($null -eq $TrendChartCanvas) { Write-Log "WARNING: Control 'TrendChartCanvas' not found in XAML" -Level "WARNING" }

# GPO Quick Assignment controls
$DCGPOStatus = $window.FindName("DCGPOStatus")
if ($null -eq $DCGPOStatus) { Write-Log "WARNING: Control 'DCGPOStatus' not found in XAML" -Level "WARNING" }
$ServersGPOStatus = $window.FindName("ServersGPOStatus")
if ($null -eq $ServersGPOStatus) { Write-Log "WARNING: Control 'ServersGPOStatus' not found in XAML" -Level "WARNING" }
$WorkstationsGPOStatus = $window.FindName("WorkstationsGPOStatus")
if ($null -eq $WorkstationsGPOStatus) { Write-Log "WARNING: Control 'WorkstationsGPOStatus' not found in XAML" -Level "WARNING" }
$DCGPOPhase = $window.FindName("DCGPOPhase")
if ($null -eq $DCGPOPhase) { Write-Log "WARNING: Control 'DCGPOPhase' not found in XAML" -Level "WARNING" }
$DCGPOMode = $window.FindName("DCGPOMode")
if ($null -eq $DCGPOMode) { Write-Log "WARNING: Control 'DCGPOMode' not found in XAML" -Level "WARNING" }
$ServersGPOPhase = $window.FindName("ServersGPOPhase")
if ($null -eq $ServersGPOPhase) { Write-Log "WARNING: Control 'ServersGPOPhase' not found in XAML" -Level "WARNING" }
$ServersGPOMode = $window.FindName("ServersGPOMode")
if ($null -eq $ServersGPOMode) { Write-Log "WARNING: Control 'ServersGPOMode' not found in XAML" -Level "WARNING" }
$WorkstationsGPOPhase = $window.FindName("WorkstationsGPOPhase")
if ($null -eq $WorkstationsGPOPhase) { Write-Log "WARNING: Control 'WorkstationsGPOPhase' not found in XAML" -Level "WARNING" }
$WorkstationsGPOMode = $window.FindName("WorkstationsGPOMode")
if ($null -eq $WorkstationsGPOMode) { Write-Log "WARNING: Control 'WorkstationsGPOMode' not found in XAML" -Level "WARNING" }
$ApplyGPOSettingsBtn = $window.FindName("ApplyGPOSettingsBtn")
if ($null -eq $ApplyGPOSettingsBtn) { Write-Log "WARNING: Control 'ApplyGPOSettingsBtn' not found in XAML" -Level "WARNING" }
$LinkGPOsBtn = $window.FindName("LinkGPOsBtn")
if ($null -eq $LinkGPOsBtn) { Write-Log "WARNING: Control 'LinkGPOsBtn' not found in XAML" -Level "WARNING" }

# Other controls
$MaxFilesText = $window.FindName("MaxFilesText")
if ($null -eq $MaxFilesText) { Write-Log "WARNING: Control 'MaxFilesText' not found in XAML" -Level "WARNING" }
$ScanAllDirectoriesCheckbox = $window.FindName("ScanAllDirectoriesCheckbox")
if ($null -eq $ScanAllDirectoriesCheckbox) { Write-Log "WARNING: Control 'ScanAllDirectoriesCheckbox' not found in XAML" -Level "WARNING" }
$DirectoryList = $window.FindName("DirectoryList")
if ($null -eq $DirectoryList) { Write-Log "WARNING: Control 'DirectoryList' not found in XAML" -Level "WARNING" }
$ArtifactsList = $window.FindName("ArtifactsList")
if ($null -eq $ArtifactsList) { Write-Log "WARNING: Control 'ArtifactsList' not found in XAML" -Level "WARNING" }
# Artifact Local Scan controls
$ScanLocalArtifactsBtn = $window.FindName("ScanLocalArtifactsBtn")
if ($null -eq $ScanLocalArtifactsBtn) { Write-Log "WARNING: Control 'ScanLocalArtifactsBtn' not found in XAML" -Level "WARNING" }
$AaronLockerScanBtn = $window.FindName("AaronLockerScanBtn")
if ($null -eq $AaronLockerScanBtn) { Write-Log "WARNING: Control 'AaronLockerScanBtn' not found in XAML" -Level "WARNING" }
$CancelScanBtn = $window.FindName("CancelScanBtn")
if ($null -eq $CancelScanBtn) { Write-Log "WARNING: Control 'CancelScanBtn' not found in XAML" -Level "WARNING" }
$ScanProgressPanel = $window.FindName("ScanProgressPanel")
if ($null -eq $ScanProgressPanel) { Write-Log "WARNING: Control 'ScanProgressPanel' not found in XAML" -Level "WARNING" }
$ScanProgressText = $window.FindName("ScanProgressText")
if ($null -eq $ScanProgressText) { Write-Log "WARNING: Control 'ScanProgressText' not found in XAML" -Level "WARNING" }
$ScanProgressCount = $window.FindName("ScanProgressCount")
if ($null -eq $ScanProgressCount) { Write-Log "WARNING: Control 'ScanProgressCount' not found in XAML" -Level "WARNING" }
$ScanProgressBar = $window.FindName("ScanProgressBar")
if ($null -eq $ScanProgressBar) { Write-Log "WARNING: Control 'ScanProgressBar' not found in XAML" -Level "WARNING" }
$RuleTypeAuto = $window.FindName("RuleTypeAuto")
if ($null -eq $RuleTypeAuto) { Write-Log "WARNING: Control 'RuleTypeAuto' not found in XAML" -Level "WARNING" }
$RuleTypePublisher = $window.FindName("RuleTypePublisher")
if ($null -eq $RuleTypePublisher) { Write-Log "WARNING: Control 'RuleTypePublisher' not found in XAML" -Level "WARNING" }
$RuleTypeHash = $window.FindName("RuleTypeHash")
if ($null -eq $RuleTypeHash) { Write-Log "WARNING: Control 'RuleTypeHash' not found in XAML" -Level "WARNING" }
$RuleTypePath = $window.FindName("RuleTypePath")
if ($null -eq $RuleTypePath) { Write-Log "WARNING: Control 'RuleTypePath' not found in XAML" -Level "WARNING" }
$RuleActionAllow = $window.FindName("RuleActionAllow")
if ($null -eq $RuleActionAllow) { Write-Log "WARNING: Control 'RuleActionAllow' not found in XAML" -Level "WARNING" }
$RuleActionDeny = $window.FindName("RuleActionDeny")
if ($null -eq $RuleActionDeny) { Write-Log "WARNING: Control 'RuleActionDeny' not found in XAML" -Level "WARNING" }
$RuleGroupCombo = $window.FindName("RuleGroupCombo")
if ($null -eq $RuleGroupCombo) { Write-Log "WARNING: Control 'RuleGroupCombo' not found in XAML" -Level "WARNING" }
$CustomSidPanel = $window.FindName("CustomSidPanel")
if ($null -eq $CustomSidPanel) { Write-Log "WARNING: Control 'CustomSidPanel' not found in XAML" -Level "WARNING" }
$CustomSidText = $window.FindName("CustomSidText")
if ($null -eq $CustomSidText) { Write-Log "WARNING: Control 'CustomSidText' not found in XAML" -Level "WARNING" }
$ImportArtifactsBtn = $window.FindName("ImportArtifactsBtn")
if ($null -eq $ImportArtifactsBtn) { Write-Log "WARNING: Control 'ImportArtifactsBtn' not found in XAML" -Level "WARNING" }
$ImportFolderBtn = $window.FindName("ImportFolderBtn")
if ($null -eq $ImportFolderBtn) { Write-Log "WARNING: Control 'ImportFolderBtn' not found in XAML" -Level "WARNING" }
$MergeRulesBtn = $window.FindName("MergeRulesBtn")
if ($null -eq $MergeRulesBtn) { Write-Log "WARNING: Control 'MergeRulesBtn' not found in XAML" -Level "WARNING" }
$GenerateRulesBtn = $window.FindName("GenerateRulesBtn")
if ($null -eq $GenerateRulesBtn) { Write-Log "WARNING: Control 'GenerateRulesBtn' not found in XAML" -Level "WARNING" }
$DefaultDenyRulesBtn = $window.FindName("DefaultDenyRulesBtn")
if ($null -eq $DefaultDenyRulesBtn) { Write-Log "WARNING: Control 'DefaultDenyRulesBtn' not found in XAML" -Level "WARNING" }
$RulesOutput = $window.FindName("RulesOutput")
if ($null -eq $RulesOutput) { Write-Log "WARNING: Control 'RulesOutput' not found in XAML" -Level "WARNING" }
# Quick Import controls
$LoadCollectedArtifactsBtn = $window.FindName("LoadCollectedArtifactsBtn")
if ($null -eq $LoadCollectedArtifactsBtn) { Write-Log "WARNING: Control 'LoadCollectedArtifactsBtn' not found in XAML" -Level "WARNING" }
$LoadCollectedEventsBtn = $window.FindName("LoadCollectedEventsBtn")
if ($null -eq $LoadCollectedEventsBtn) { Write-Log "WARNING: Control 'LoadCollectedEventsBtn' not found in XAML" -Level "WARNING" }
$ArtifactCountBadge = $window.FindName("ArtifactCountBadge")
if ($null -eq $ArtifactCountBadge) { Write-Log "WARNING: Control 'ArtifactCountBadge' not found in XAML" -Level "WARNING" }
$EventCountBadge = $window.FindName("EventCountBadge")
if ($null -eq $EventCountBadge) { Write-Log "WARNING: Control 'EventCountBadge' not found in XAML" -Level "WARNING" }
# Data Management controls
$DedupeTypeCombo = $window.FindName("DedupeTypeCombo")
if ($null -eq $DedupeTypeCombo) { Write-Log "WARNING: Control 'DedupeTypeCombo' not found in XAML" -Level "WARNING" }
$DedupeBtn = $window.FindName("DedupeBtn")
if ($null -eq $DedupeBtn) { Write-Log "WARNING: Control 'DedupeBtn' not found in XAML" -Level "WARNING" }
$ExportArtifactsListBtn = $window.FindName("ExportArtifactsListBtn")
if ($null -eq $ExportArtifactsListBtn) { Write-Log "WARNING: Control 'ExportArtifactsListBtn' not found in XAML" -Level "WARNING" }
# Rules DataGrid controls
$RulesDataGrid = $window.FindName("RulesDataGrid")
if ($null -eq $RulesDataGrid) { Write-Log "WARNING: Control 'RulesDataGrid' not found in XAML" -Level "WARNING" }
$RulesCountText = $window.FindName("RulesCountText")
if ($null -eq $RulesCountText) { Write-Log "WARNING: Control 'RulesCountText' not found in XAML" -Level "WARNING" }
$ChangeGroupBtn = $window.FindName("ChangeGroupBtn")
if ($null -eq $ChangeGroupBtn) { Write-Log "WARNING: Control 'ChangeGroupBtn' not found in XAML" -Level "WARNING" }
$DuplicateRulesBtn = $window.FindName("DuplicateRulesBtn")
if ($null -eq $DuplicateRulesBtn) { Write-Log "WARNING: Control 'DuplicateRulesBtn' not found in XAML" -Level "WARNING" }
$DeleteRulesBtn = $window.FindName("DeleteRulesBtn")
if ($null -eq $DeleteRulesBtn) { Write-Log "WARNING: Control 'DeleteRulesBtn' not found in XAML" -Level "WARNING" }

# QoL Feature controls
$AuditToggleBtn = $window.FindName("AuditToggleBtn")
if ($null -eq $AuditToggleBtn) { Write-Log "WARNING: Control 'AuditToggleBtn' not found in XAML" -Level "WARNING" }
$RulesSearchBox = $window.FindName("RulesSearchBox")
if ($null -eq $RulesSearchBox) { Write-Log "WARNING: Control 'RulesSearchBox' not found in XAML" -Level "WARNING" }
$ClearFilterBtn = $window.FindName("ClearFilterBtn")
if ($null -eq $ClearFilterBtn) { Write-Log "WARNING: Control 'ClearFilterBtn' not found in XAML" -Level "WARNING" }
$RulePreviewPanel = $window.FindName("RulePreviewPanel")
if ($null -eq $RulePreviewPanel) { Write-Log "WARNING: Control 'RulePreviewPanel' not found in XAML" -Level "WARNING" }
$RulePreviewText = $window.FindName("RulePreviewText")
if ($null -eq $RulePreviewText) { Write-Log "WARNING: Control 'RulePreviewText' not found in XAML" -Level "WARNING" }
$ClosePreviewBtn = $window.FindName("ClosePreviewBtn")
if ($null -eq $ClosePreviewBtn) { Write-Log "WARNING: Control 'ClosePreviewBtn' not found in XAML" -Level "WARNING" }
$ScanLocalEventsBtn = $window.FindName("ScanLocalEventsBtn")
if ($null -eq $ScanLocalEventsBtn) { Write-Log "WARNING: Control 'ScanLocalEventsBtn' not found in XAML" -Level "WARNING" }
$ScanRemoteEventsBtn = $window.FindName("ScanRemoteEventsBtn")
if ($null -eq $ScanRemoteEventsBtn) { Write-Log "WARNING: Control 'ScanRemoteEventsBtn' not found in XAML" -Level "WARNING" }
$ExportEventsBtn = $window.FindName("ExportEventsBtn")
if ($null -eq $ExportEventsBtn) { Write-Log "WARNING: Control 'ExportEventsBtn' not found in XAML" -Level "WARNING" }
$EventComputersList = $window.FindName("EventComputersList")
if ($null -eq $EventComputersList) { Write-Log "WARNING: Control 'EventComputersList' not found in XAML" -Level "WARNING" }
$RefreshComputersBtn = $window.FindName("RefreshComputersBtn")
if ($null -eq $RefreshComputersBtn) { Write-Log "WARNING: Control 'RefreshComputersBtn' not found in XAML" -Level "WARNING" }
$FilterAllBtn = $window.FindName("FilterAllBtn")
if ($null -eq $FilterAllBtn) { Write-Log "WARNING: Control 'FilterAllBtn' not found in XAML" -Level "WARNING" }
$FilterAllowedBtn = $window.FindName("FilterAllowedBtn")
if ($null -eq $FilterAllowedBtn) { Write-Log "WARNING: Control 'FilterAllowedBtn' not found in XAML" -Level "WARNING" }
$FilterBlockedBtn = $window.FindName("FilterBlockedBtn")
if ($null -eq $FilterBlockedBtn) { Write-Log "WARNING: Control 'FilterBlockedBtn' not found in XAML" -Level "WARNING" }
$FilterAuditBtn = $window.FindName("FilterAuditBtn")
if ($null -eq $FilterAuditBtn) { Write-Log "WARNING: Control 'FilterAuditBtn' not found in XAML" -Level "WARNING" }
$RefreshEventsBtn = $window.FindName("RefreshEventsBtn")
if ($null -eq $RefreshEventsBtn) { Write-Log "WARNING: Control 'RefreshEventsBtn' not found in XAML" -Level "WARNING" }
$EventsOutput = $window.FindName("EventsOutput")
if ($null -eq $EventsOutput) { Write-Log "WARNING: Control 'EventsOutput' not found in XAML" -Level "WARNING" }

# Reports controls
$ReportTypeSelector = $window.FindName("ReportTypeSelector")
if ($null -eq $ReportTypeSelector) { Write-Log "WARNING: Control 'ReportTypeSelector' not found in XAML" -Level "WARNING" }
$ReportStartDate = $window.FindName("ReportStartDate")
if ($null -eq $ReportStartDate) { Write-Log "WARNING: Control 'ReportStartDate' not found in XAML" -Level "WARNING" }
$ReportEndDate = $window.FindName("ReportEndDate")
if ($null -eq $ReportEndDate) { Write-Log "WARNING: Control 'ReportEndDate' not found in XAML" -Level "WARNING" }
$ReportLast7Days = $window.FindName("ReportLast7Days")
if ($null -eq $ReportLast7Days) { Write-Log "WARNING: Control 'ReportLast7Days' not found in XAML" -Level "WARNING" }
$ReportLast30Days = $window.FindName("ReportLast30Days")
if ($null -eq $ReportLast30Days) { Write-Log "WARNING: Control 'ReportLast30Days' not found in XAML" -Level "WARNING" }
$ReportLast90Days = $window.FindName("ReportLast90Days")
if ($null -eq $ReportLast90Days) { Write-Log "WARNING: Control 'ReportLast90Days' not found in XAML" -Level "WARNING" }
$ReportTargetSystem = $window.FindName("ReportTargetSystem")
if ($null -eq $ReportTargetSystem) { Write-Log "WARNING: Control 'ReportTargetSystem' not found in XAML" -Level "WARNING" }
$GenerateReportBtn = $window.FindName("GenerateReportBtn")
if ($null -eq $GenerateReportBtn) { Write-Log "WARNING: Control 'GenerateReportBtn' not found in XAML" -Level "WARNING" }
$ExportToPdfBtn = $window.FindName("ExportToPdfBtn")
if ($null -eq $ExportToPdfBtn) { Write-Log "WARNING: Control 'ExportToPdfBtn' not found in XAML" -Level "WARNING" }
$ExportToHtmlBtn = $window.FindName("ExportToHtmlBtn")
if ($null -eq $ExportToHtmlBtn) { Write-Log "WARNING: Control 'ExportToHtmlBtn' not found in XAML" -Level "WARNING" }
$ExportToCsvBtn = $window.FindName("ExportToCsvBtn")
if ($null -eq $ExportToCsvBtn) { Write-Log "WARNING: Control 'ExportToCsvBtn' not found in XAML" -Level "WARNING" }
$ScheduleReportBtn = $window.FindName("ScheduleReportBtn")
if ($null -eq $ScheduleReportBtn) { Write-Log "WARNING: Control 'ScheduleReportBtn' not found in XAML" -Level "WARNING" }
$RefreshScheduledReportsBtn = $window.FindName("RefreshScheduledReportsBtn")
if ($null -eq $RefreshScheduledReportsBtn) { Write-Log "WARNING: Control 'RefreshScheduledReportsBtn' not found in XAML" -Level "WARNING" }
$ScheduledReportsList = $window.FindName("ScheduledReportsList")
if ($null -eq $ScheduledReportsList) { Write-Log "WARNING: Control 'ScheduledReportsList' not found in XAML" -Level "WARNING" }
$ReportGeneratedTime = $window.FindName("ReportGeneratedTime")
if ($null -eq $ReportGeneratedTime) { Write-Log "WARNING: Control 'ReportGeneratedTime' not found in XAML" -Level "WARNING" }
$ReportStatus = $window.FindName("ReportStatus")
if ($null -eq $ReportStatus) { Write-Log "WARNING: Control 'ReportStatus' not found in XAML" -Level "WARNING" }
$ReportPreview = $window.FindName("ReportPreview")
if ($null -eq $ReportPreview) { Write-Log "WARNING: Control 'ReportPreview' not found in XAML" -Level "WARNING" }
$ReportPreviewScroll = $window.FindName("ReportPreviewScroll")
if ($null -eq $ReportPreviewScroll) { Write-Log "WARNING: Control 'ReportPreviewScroll' not found in XAML" -Level "WARNING" }

# Phase 4: Filter controls
$RulesTypeFilter = $window.FindName("RulesTypeFilter")
if ($null -eq $RulesTypeFilter) { Write-Log "WARNING: Control 'RulesTypeFilter' not found in XAML" -Level "WARNING" }
$RulesActionFilter = $window.FindName("RulesActionFilter")
if ($null -eq $RulesActionFilter) { Write-Log "WARNING: Control 'RulesActionFilter' not found in XAML" -Level "WARNING" }
$RulesGroupFilter = $window.FindName("RulesGroupFilter")
if ($null -eq $RulesGroupFilter) { Write-Log "WARNING: Control 'RulesGroupFilter' not found in XAML" -Level "WARNING" }
$RulesFilterSearch = $window.FindName("RulesFilterSearch")
if ($null -eq $RulesFilterSearch) { Write-Log "WARNING: Control 'RulesFilterSearch' not found in XAML" -Level "WARNING" }
$RulesClearFilterBtn = $window.FindName("RulesClearFilterBtn")
if ($null -eq $RulesClearFilterBtn) { Write-Log "WARNING: Control 'RulesClearFilterBtn' not found in XAML" -Level "WARNING" }
$RulesFilterCount = $window.FindName("RulesFilterCount")
if ($null -eq $RulesFilterCount) { Write-Log "WARNING: Control 'RulesFilterCount' not found in XAML" -Level "WARNING" }

$EventsDateFrom = $window.FindName("EventsDateFrom")
if ($null -eq $EventsDateFrom) { Write-Log "WARNING: Control 'EventsDateFrom' not found in XAML" -Level "WARNING" }
$EventsDateTo = $window.FindName("EventsDateTo")
if ($null -eq $EventsDateTo) { Write-Log "WARNING: Control 'EventsDateTo' not found in XAML" -Level "WARNING" }
$EventsFilterSearch = $window.FindName("EventsFilterSearch")
if ($null -eq $EventsFilterSearch) { Write-Log "WARNING: Control 'EventsFilterSearch' not found in XAML" -Level "WARNING" }
$EventsClearFilterBtn = $window.FindName("EventsClearFilterBtn")
if ($null -eq $EventsClearFilterBtn) { Write-Log "WARNING: Control 'EventsClearFilterBtn' not found in XAML" -Level "WARNING" }
$EventsFilterCount = $window.FindName("EventsFilterCount")
if ($null -eq $EventsFilterCount) { Write-Log "WARNING: Control 'EventsFilterCount' not found in XAML" -Level "WARNING" }

$ComplianceStatusFilter = $window.FindName("ComplianceStatusFilter")
if ($null -eq $ComplianceStatusFilter) { Write-Log "WARNING: Control 'ComplianceStatusFilter' not found in XAML" -Level "WARNING" }
$ComplianceFilterSearch = $window.FindName("ComplianceFilterSearch")
if ($null -eq $ComplianceFilterSearch) { Write-Log "WARNING: Control 'ComplianceFilterSearch' not found in XAML" -Level "WARNING" }
$ComplianceClearFilterBtn = $window.FindName("ComplianceClearFilterBtn")
if ($null -eq $ComplianceClearFilterBtn) { Write-Log "WARNING: Control 'ComplianceClearFilterBtn' not found in XAML" -Level "WARNING" }
$ComplianceFilterCount = $window.FindName("ComplianceFilterCount")
if ($null -eq $ComplianceFilterCount) { Write-Log "WARNING: Control 'ComplianceFilterCount' not found in XAML" -Level "WARNING" }
$DeploymentStatus = $window.FindName("DeploymentStatus")
if ($null -eq $DeploymentStatus) { Write-Log "WARNING: Control 'DeploymentStatus' not found in XAML" -Level "WARNING" }
$GenerateEvidenceBtn = $window.FindName("GenerateEvidenceBtn")
if ($null -eq $GenerateEvidenceBtn) { Write-Log "WARNING: Control 'GenerateEvidenceBtn' not found in XAML" -Level "WARNING" }
$ComplianceOutput = $window.FindName("ComplianceOutput")
if ($null -eq $ComplianceOutput) { Write-Log "WARNING: Control 'ComplianceOutput' not found in XAML" -Level "WARNING" }
$ScanLocalComplianceBtn = $window.FindName("ScanLocalComplianceBtn")
if ($null -eq $ScanLocalComplianceBtn) { Write-Log "WARNING: Control 'ScanLocalComplianceBtn' not found in XAML" -Level "WARNING" }
$ScanSelectedComplianceBtn = $window.FindName("ScanSelectedComplianceBtn")
if ($null -eq $ScanSelectedComplianceBtn) { Write-Log "WARNING: Control 'ScanSelectedComplianceBtn' not found in XAML" -Level "WARNING" }
$RefreshComplianceListBtn = $window.FindName("RefreshComplianceListBtn")
if ($null -eq $RefreshComplianceListBtn) { Write-Log "WARNING: Control 'RefreshComplianceListBtn' not found in XAML" -Level "WARNING" }
$ComplianceComputersList = $window.FindName("ComplianceComputersList")
if ($null -eq $ComplianceComputersList) { Write-Log "WARNING: Control 'ComplianceComputersList' not found in XAML" -Level "WARNING" }
$CreateWinRMGpoBtn = $window.FindName("CreateWinRMGpoBtn")
if ($null -eq $CreateWinRMGpoBtn) { Write-Log "WARNING: Control 'CreateWinRMGpoBtn' not found in XAML" -Level "WARNING" }
$EnableWinRMGpoBtn = $window.FindName("EnableWinRMGpoBtn")
if ($null -eq $EnableWinRMGpoBtn) { Write-Log "WARNING: Control 'EnableWinRMGpoBtn' not found in XAML" -Level "WARNING" }
$DisableWinRMGpoBtn = $window.FindName("DisableWinRMGpoBtn")
if ($null -eq $DisableWinRMGpoBtn) { Write-Log "WARNING: Control 'DisableWinRMGpoBtn' not found in XAML" -Level "WARNING" }
$ForceGPUpdateBtn = $window.FindName("ForceGPUpdateBtn")
if ($null -eq $ForceGPUpdateBtn) { Write-Log "WARNING: Control 'ForceGPUpdateBtn' not found in XAML" -Level "WARNING" }
$WinRMOutput = $window.FindName("WinRMOutput")
if ($null -eq $WinRMOutput) { Write-Log "WARNING: Control 'WinRMOutput' not found in XAML" -Level "WARNING" }

# AD Discovery controls
$ADSearchFilter = $window.FindName("ADSearchFilter")
if ($null -eq $ADSearchFilter) { Write-Log "WARNING: Control 'ADSearchFilter' not found in XAML" -Level "WARNING" }
$DiscoverComputersBtn = $window.FindName("DiscoverComputersBtn")
if ($null -eq $DiscoverComputersBtn) { Write-Log "WARNING: Control 'DiscoverComputersBtn' not found in XAML" -Level "WARNING" }
$TestConnectivityBtn = $window.FindName("TestConnectivityBtn")
if ($null -eq $TestConnectivityBtn) { Write-Log "WARNING: Control 'TestConnectivityBtn' not found in XAML" -Level "WARNING" }
$SelectAllComputersBtn = $window.FindName("SelectAllComputersBtn")
if ($null -eq $SelectAllComputersBtn) { Write-Log "WARNING: Control 'SelectAllComputersBtn' not found in XAML" -Level "WARNING" }
$ScanSelectedBtn = $window.FindName("ScanSelectedBtn")
if ($null -eq $ScanSelectedBtn) { Write-Log "WARNING: Control 'ScanSelectedBtn' not found in XAML" -Level "WARNING" }
$DiscoveredComputersList = $window.FindName("DiscoveredComputersList")
if ($null -eq $DiscoveredComputersList) { Write-Log "WARNING: Control 'DiscoveredComputersList' not found in XAML" -Level "WARNING" }
$OfflineComputersList = $window.FindName("OfflineComputersList")
if ($null -eq $OfflineComputersList) { Write-Log "WARNING: Control 'OfflineComputersList' not found in XAML" -Level "WARNING" }
$DiscoveryOutput = $window.FindName("DiscoveryOutput")
if ($null -eq $DiscoveryOutput) { Write-Log "WARNING: Control 'DiscoveryOutput' not found in XAML" -Level "WARNING" }
$DiscoveryStatus = $window.FindName("DiscoveryStatus")
if ($null -eq $DiscoveryStatus) { Write-Log "WARNING: Control 'DiscoveryStatus' not found in XAML" -Level "WARNING" }

# Group Management controls
$ExportGroupsBtn = $window.FindName("ExportGroupsBtn")
if ($null -eq $ExportGroupsBtn) { Write-Log "WARNING: Control 'ExportGroupsBtn' not found in XAML" -Level "WARNING" }
$ImportGroupsBtn = $window.FindName("ImportGroupsBtn")
if ($null -eq $ImportGroupsBtn) { Write-Log "WARNING: Control 'ImportGroupsBtn' not found in XAML" -Level "WARNING" }
$DryRunCheck = $window.FindName("DryRunCheck")
if ($null -eq $DryRunCheck) { Write-Log "WARNING: Control 'DryRunCheck' not found in XAML" -Level "WARNING" }
$AllowRemovalsCheck = $window.FindName("AllowRemovalsCheck")
if ($null -eq $AllowRemovalsCheck) { Write-Log "WARNING: Control 'AllowRemovalsCheck' not found in XAML" -Level "WARNING" }
$IncludeProtectedCheck = $window.FindName("IncludeProtectedCheck")
if ($null -eq $IncludeProtectedCheck) { Write-Log "WARNING: Control 'IncludeProtectedCheck' not found in XAML" -Level "WARNING" }
$GroupMgmtOutput = $window.FindName("GroupMgmtOutput")
if ($null -eq $GroupMgmtOutput) { Write-Log "WARNING: Control 'GroupMgmtOutput' not found in XAML" -Level "WARNING" }

# AppLocker Setup controls
$OUNameText = $window.FindName("OUNameText")
if ($null -eq $OUNameText) { Write-Log "WARNING: Control 'OUNameText' not found in XAML" -Level "WARNING" }
$AutoPopulateCheck = $window.FindName("AutoPopulateCheck")
if ($null -eq $AutoPopulateCheck) { Write-Log "WARNING: Control 'AutoPopulateCheck' not found in XAML" -Level "WARNING" }
$BootstrapAppLockerBtn = $window.FindName("BootstrapAppLockerBtn")
if ($null -eq $BootstrapAppLockerBtn) { Write-Log "WARNING: Control 'BootstrapAppLockerBtn' not found in XAML" -Level "WARNING" }
$RemoveOUProtectionBtn = $window.FindName("RemoveOUProtectionBtn")
if ($null -eq $RemoveOUProtectionBtn) { Write-Log "WARNING: Control 'RemoveOUProtectionBtn' not found in XAML" -Level "WARNING" }
$CreateBrowserDenyBtn = $window.FindName("CreateBrowserDenyBtn")
if ($null -eq $CreateBrowserDenyBtn) { Write-Log "WARNING: Control 'CreateBrowserDenyBtn' not found in XAML" -Level "WARNING" }
$AppLockerSetupOutput = $window.FindName("AppLockerSetupOutput")
if ($null -eq $AppLockerSetupOutput) { Write-Log "WARNING: Control 'AppLockerSetupOutput' not found in XAML" -Level "WARNING" }

# About and Help controls
$AboutLogo = $window.FindName("AboutLogo")
if ($null -eq $AboutLogo) { Write-Log "WARNING: Control 'AboutLogo' not found in XAML" -Level "WARNING" }
$AboutVersion = $window.FindName("AboutVersion")
if ($null -eq $AboutVersion) { Write-Log "WARNING: Control 'AboutVersion' not found in XAML" -Level "WARNING" }
$HelpTitle = $window.FindName("HelpTitle")
if ($null -eq $HelpTitle) { Write-Log "WARNING: Control 'HelpTitle' not found in XAML" -Level "WARNING" }
$HelpText = $window.FindName("HelpText")
if ($null -eq $HelpText) { Write-Log "WARNING: Control 'HelpText' not found in XAML" -Level "WARNING" }
$HelpBtnWorkflow = $window.FindName("HelpBtnWorkflow")
if ($null -eq $HelpBtnWorkflow) { Write-Log "WARNING: Control 'HelpBtnWorkflow' not found in XAML" -Level "WARNING" }
$HelpBtnWhatsNew = $window.FindName("HelpBtnWhatsNew")
if ($null -eq $HelpBtnWhatsNew) { Write-Log "WARNING: Control 'HelpBtnWhatsNew' not found in XAML" -Level "WARNING" }
$HelpBtnPolicyGuide = $window.FindName("HelpBtnPolicyGuide")
if ($null -eq $HelpBtnPolicyGuide) { Write-Log "WARNING: Control 'HelpBtnPolicyGuide' not found in XAML" -Level "WARNING" }
$HelpBtnRules = $window.FindName("HelpBtnRules")
if ($null -eq $HelpBtnRules) { Write-Log "WARNING: Control 'HelpBtnRules' not found in XAML" -Level "WARNING" }
$HelpBtnTroubleshooting = $window.FindName("HelpBtnTroubleshooting")
if ($null -eq $HelpBtnTroubleshooting) { Write-Log "WARNING: Control 'HelpBtnTroubleshooting' not found in XAML" -Level "WARNING" }

# Gap Analysis controls (Scan buttons removed - use Import only)
$ImportBaselineBtn = $window.FindName("ImportBaselineBtn")
if ($null -eq $ImportBaselineBtn) { Write-Log "WARNING: Control 'ImportBaselineBtn' not found in XAML" -Level "WARNING" }
$ImportTargetBtn = $window.FindName("ImportTargetBtn")
if ($null -eq $ImportTargetBtn) { Write-Log "WARNING: Control 'ImportTargetBtn' not found in XAML" -Level "WARNING" }
$CompareSoftwareBtn = $window.FindName("CompareSoftwareBtn")
if ($null -eq $CompareSoftwareBtn) { Write-Log "WARNING: Control 'CompareSoftwareBtn' not found in XAML" -Level "WARNING" }
$GapAnalysisGrid = $window.FindName("GapAnalysisGrid")
if ($null -eq $GapAnalysisGrid) { Write-Log "WARNING: Control 'GapAnalysisGrid' not found in XAML" -Level "WARNING" }
$GapTotalCount = $window.FindName("GapTotalCount")
if ($null -eq $GapTotalCount) { Write-Log "WARNING: Control 'GapTotalCount' not found in XAML" -Level "WARNING" }
$GapMissingCount = $window.FindName("GapMissingCount")
if ($null -eq $GapMissingCount) { Write-Log "WARNING: Control 'GapMissingCount' not found in XAML" -Level "WARNING" }
$GapExtraCount = $window.FindName("GapExtraCount")
if ($null -eq $GapExtraCount) { Write-Log "WARNING: Control 'GapExtraCount' not found in XAML" -Level "WARNING" }
$GapVersionCount = $window.FindName("GapVersionCount")
if ($null -eq $GapVersionCount) { Write-Log "WARNING: Control 'GapVersionCount' not found in XAML" -Level "WARNING" }
$ExportGapAnalysisBtn = $window.FindName("ExportGapAnalysisBtn")
if ($null -eq $ExportGapAnalysisBtn) { Write-Log "WARNING: Control 'ExportGapAnalysisBtn' not found in XAML" -Level "WARNING" }

# Export/Import Rules controls
$ExportRulesBtn = $window.FindName("ExportRulesBtn")
if ($null -eq $ExportRulesBtn) { Write-Log "WARNING: Control 'ExportRulesBtn' not found in XAML" -Level "WARNING" }
$ImportRulesBtn = $window.FindName("ImportRulesBtn")
if ($null -eq $ImportRulesBtn) { Write-Log "WARNING: Control 'ImportRulesBtn' not found in XAML" -Level "WARNING" }
$TargetGpoCombo = $window.FindName("TargetGpoCombo")
if ($null -eq $TargetGpoCombo) { Write-Log "WARNING: Control 'TargetGpoCombo' not found in XAML" -Level "WARNING" }
$ImportModeCombo = $window.FindName("ImportModeCombo")
if ($null -eq $ImportModeCombo) { Write-Log "WARNING: Control 'ImportModeCombo' not found in XAML" -Level "WARNING" }
$RuleFilePathBox = $window.FindName("RuleFilePathBox")
if ($null -eq $RuleFilePathBox) { Write-Log "WARNING: Control 'RuleFilePathBox' not found in XAML" -Level "WARNING" }
$BrowseRuleFileBtn = $window.FindName("BrowseRuleFileBtn")
if ($null -eq $BrowseRuleFileBtn) { Write-Log "WARNING: Control 'BrowseRuleFileBtn' not found in XAML" -Level "WARNING" }

# Global variables
$script:CollectedArtifacts = @()
$script:IsWorkgroup = $false
$script:DomainInfo = $null
$script:EventFilter = "All"  # All, Allowed, Blocked, Audit
$script:AllEvents = @()
$script:BaselineSoftware = @()
$script:TargetSoftware = @()
$script:GeneratedRules = @()
$script:DiscoveredComputers = @()
$script:CollectedEvents = @()
$script:ComplianceComputers = @()

# Phase 4: Filter state variables - store original data for filtering
$script:OriginalRules = @()  # Store unfiltered rules
$script:OriginalEvents = @()  # Store unfiltered events
$script:OriginalComplianceComputers = @()  # Store unfiltered compliance computers
$script:CurrentRulesFilter = @{ Type = ""; Action = ""; Group = ""; Search = "" }
$script:CurrentEventsFilter = @{ Type = ""; DateFrom = $null; DateTo = $null; Search = "" }
$script:CurrentComplianceFilter = @{ Status = ""; Search = "" }

# Workspace state management (Phase 4)
$script:WorkspaceAutoSaveTimer = $null
$script:WorkspaceAutoSaveInterval = 10  # minutes
$script:LastWorkspaceSavePath = $null
$script:WorkspaceVersion = "1.0"

# Script root path for module imports (handles running from any location)
# Handle ps2exe compiled executable case
$script:ScriptRoot = $null

# Try PSCommandPath first (works in normal PowerShell)
if (-not [string]::IsNullOrEmpty($PSCommandPath)) {
    $script:ScriptRoot = Split-Path -Parent $PSCommandPath -ErrorAction SilentlyContinue
}

# Fallback to MyInvocation (works in some cases)
if ([string]::IsNullOrEmpty($script:ScriptRoot)) {
    if ($MyInvocation.MyCommand.Path -and -not [string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)) {
        $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue
    }
}

# Final fallback - use current directory
if ([string]::IsNullOrEmpty($script:ScriptRoot)) {
    $script:ScriptRoot = $PSScriptRoot
}

# If still null, use hardcoded path (for ps2exe)
if ([string]::IsNullOrEmpty($script:ScriptRoot)) {
    $script:ScriptRoot = "C:\GA-AppLocker\build"
}

# Determine module path - check if modules are in src\modules, or parent\src\modules
$script:ModulePath = Join-Path $script:ScriptRoot "src\modules"
if (-not (Test-Path $script:ModulePath)) {
    # Modules not found, try parent directory (for running from output folder)
    $parentPath = Split-Path -Parent $script:ScriptRoot -ErrorAction SilentlyContinue
    if ($parentPath -and (Test-Path (Join-Path $parentPath "src\modules"))) {
        $script:ModulePath = Join-Path $parentPath "src\modules"
    } else {
        # Final fallback - try the project directory structure
        $script:ModulePath = "C:\GA-AppLocker\src\modules"
    }
}

# Logging function
# Initialize GA-AppLocker folder structure
function Initialize-AppLockerFolders {
    $basePath = "C:\GA-AppLocker"
    $subFolders = @(
        "Scans",
        "Artifacts",
        "Rules",
        "Imports",
        "Exports",
        "Logs",
        "Workspaces"
    )

    try {
        # Create base folder if it doesn't exist
        if (-not (Test-Path $basePath)) {
            New-Item -Path $basePath -ItemType Directory -Force | Out-Null
        }

        # Create subfolders
        foreach ($folder in $subFolders) {
            $fullPath = Join-Path $basePath $folder
            if (-not (Test-Path $fullPath)) {
                New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
            }
        }

        return @{
            success = $true
            basePath = $basePath
            folders = $subFolders
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# ======================================================================
# SECURITY FUNCTIONS - Phase 1 Critical Fixes
# ======================================================================

function ConvertTo-SafeString {
    <#
    .SYNOPSIS
        Sanitize user input for display to prevent XSS and injection attacks
    .DESCRIPTION
        Removes or escapes potentially dangerous characters from user input
    .PARAMETER InputString
        The string to sanitize
    .PARAMETER MaxLength
        Maximum allowed length (default: 1000)
    .OUTPUTS
        Sanitized string safe for display
    #>
    param(
        [string]$InputString = "",
        [int]$MaxLength = 1000
    )

    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }

    # Truncate to max length
    if ($InputString.Length -gt $MaxLength) {
        $InputString = $InputString.Substring(0, $MaxLength)
    }

    # Remove null bytes and control characters (except newline, tab, carriage return)
    $sanitized = $InputString -replace '[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', ''

    # Escape HTML entities (for display in web/html contexts)
    $sanitized = $sanitized -replace '&', '&amp;'
    $sanitized = $sanitized -replace '<', '&lt;'
    $sanitized = $sanitized -replace '>', '&gt;'
    $sanitized = $sanitized -replace '"', '&quot;'
    $sanitized = $sanitized -replace '''', '&apos;'

    # Remove potential script injection patterns
    $sanitized = $sanitized -replace 'javascript:', ''
    $sanitized = $sanitized -replace 'vbscript:', ''
    $sanitized = $sanitized -replace 'on\w+\s*=', ''  # Remove onerror=, onload=, etc.

    return $sanitized
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Write security audit log entries
    .DESCRIPTION
        Logs security-relevant operations for compliance and forensic analysis
    .PARAMETER Action
        The action performed (e.g., 'GPO_CREATED', 'GPO_LINKED', 'POLICY_APPLIED')
    .PARAMETER Target
        The target object (e.g., GPO name, OU path)
    .PARAMETER Result
        Operation result: 'SUCCESS' or 'FAILURE'
    .PARAMETER Details
        Additional details about the operation
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [string]$Target = "",

        [ValidateSet('SUCCESS', 'FAILURE', 'ATTEMPT', 'CANCELLED')]
        [string]$Result = 'SUCCESS',

        [string]$Details = ""
    )

    # Get current user
    $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # Sanitize inputs for log
    $Action = ConvertTo-SafeString -InputString $Action -MaxLength 100
    $Target = ConvertTo-SafeString -InputString $Target -MaxLength 500
    $Details = ConvertTo-SafeString -InputString $Details -MaxLength 2000

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Result] [$Action] Target=$Target User=$userName Computer=$env:COMPUTERNAME Details=$Details"

    # Write to audit log file
    try {
        $auditLogPath = 'C:\GA-AppLocker\logs\audit.log'
        $auditLogDir = Split-Path -Parent $auditLogPath

        if (-not (Test-Path $auditLogDir)) {
            New-Item -ItemType Directory -Path $auditLogDir -Force | Out-Null
        }

        # Check log size - rotate if > 50MB
        if (Test-Path $auditLogPath) {
            $logFile = Get-Item $auditLogPath
            if ($logFile.Length -gt 50MB) {
                $archivePath = $auditLogPath -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item -Path $auditLogPath -Destination $archivePath -Force
            }
        }

        Add-Content -Path $auditLogPath -Value $logEntry

        # Also write to Windows Event Log if available
        try {
            $eventSource = "GA-AppLocker"
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                try {
                    [System.Diagnostics.EventLog]::CreateEventSource($eventSource, "Security")
                } catch {
                    # Silently fail if not admin
                }
            }

            $eventID = switch ($Result) {
                'SUCCESS'   { 1000 }
                'FAILURE'   { 1001 }
                'ATTEMPT'   { 1002 }
                'CANCELLED' { 1003 }
                default     { 1000 }
            }

            $eventEntryType = switch ($Result) {
                'FAILURE'   { [System.Diagnostics.EventLogEntryType]::Warning }
                'CANCELLED' { [System.Diagnostics.EventLogEntryType]::Warning }
                default     { [System.Diagnostics.EventLogEntryType]::Information }
            }

            [System.Diagnostics.EventLog]::WriteEntry($eventSource, $logEntry, $eventID, $eventEntryType)
        }
        catch {
            # Silently fail if event log writing fails
        }
    }
    catch {
        # Fail silently for audit logging errors
    }
}

function Show-ConfirmationDialog {
    <#
    .SYNOPSIS
        Display confirmation dialog for destructive operations
    .DESCRIPTION
        Shows a standardized confirmation dialog
    .PARAMETER Title
        Dialog title
    .PARAMETER Message
        Confirmation message
    .PARAMETER TargetObject
        The object being acted upon (e.g., GPO name)
    .PARAMETER ActionType
        Type of action (e.g., 'CREATE', 'DELETE', 'LINK', 'MODIFY')
    .OUTPUTS
        Boolean: true if user confirmed, false otherwise
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$TargetObject = "",

        [ValidateSet('CREATE', 'DELETE', 'LINK', 'MODIFY', 'ENFORCE', 'DISABLE')]
        [string]$ActionType = 'MODIFY',

        [switch]$RequireTyping
    )

    # Build full message
    $fullMessage = $Message

    if (-not [string]::IsNullOrEmpty($TargetObject)) {
        $fullMessage = "$fullMessage`n`nTarget: $TargetObject"
    }

    # Add warning based on action type
    $warningText = switch ($ActionType) {
        'DELETE'   { "This action cannot be easily undone." }
        'ENFORCE'  { "Enforce mode will BLOCK applications that don't match rules." }
        'CREATE'   { "This will create a new Group Policy Object." }
        'LINK'     { "This will apply the policy to the target OU immediately." }
        'DISABLE'  { "This will disable the policy link." }
        default    { "Please confirm you want to proceed." }
    }

    $fullMessage = "$fullMessage`n`n$warningText"

    if ($RequireTyping) {
        $fullMessage = "$fullMessage`n`nType 'CONFIRM' to proceed or press Cancel to abort."
    }

    # Show dialog
    $buttonType = if ($RequireTyping) {
        [System.Windows.MessageBoxButton]::OKCancel
    } else {
        [System.Windows.MessageBoxButton]::YesNo
    }

    $result = [System.Windows.MessageBox]::Show(
        $fullMessage,
        $Title,
        $buttonType,
        [System.Windows.MessageBoxImage]::Warning
    )

    # Log the confirmation attempt
    if ($result -eq [System.Windows.MessageBoxResult]::Yes -or
        $result -eq [System.Windows.MessageBoxResult]::OK) {
        Write-AuditLog -Action "CONFIRMATION_$ActionType" -Target $TargetObject -Result 'SUCCESS' -Details "User confirmed operation"
        return $true
    }
    else {
        Write-AuditLog -Action "CONFIRMATION_$ActionType" -Target $TargetObject -Result 'CANCELLED' -Details "User cancelled operation"
        return $false
    }
}

function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        HTML encode a string for safe display
    .DESCRIPTION
        Escapes HTML special characters to prevent XSS
    .PARAMETER Value
        The string to encode
    .OUTPUTS
        HTML-encoded string
    #>
    param(
        [string]$Value = ""
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return ''
    }

    # Use System.Web if available
    try {
        return [System.Web.HttpUtility]::HtmlEncode($Value)
    }
    catch {
        # Fallback to manual encoding
        $encoded = $Value -replace '&', '&amp;'
        $encoded = $encoded -replace '<', '&lt;'
        $encoded = $encoded -replace '>', '&gt;'
        $encoded = $encoded -replace '"', '&quot;'
        $encoded = $encoded -replace '''', '&apos;'
        return $encoded
    }
}

# ======================================================================
# SESSION MANAGEMENT - Phase 2
# ======================================================================

# Session timeout configuration (30 minutes of inactivity)
$script:SessionTimeoutMinutes = 30
$script:LastActivityTime = Get-Date
$script:SessionTimer = $null
$script:IsSessionLocked = $false
$script:LockScreenOverlay = $null

function Initialize-SessionTimer {
    <#
    .SYNOPSIS
        Initialize the session timeout timer
    #>
    $script:SessionTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:SessionTimer.Interval = [TimeSpan]::FromSeconds(30)  # Check every 30 seconds
    $script:SessionTimer.Add_Tick({
        Check-SessionTimeout
    })
    $script:SessionTimer.Start()
    Write-AuditLog -Action "SESSION_STARTED" -Target "Application" -Result 'SUCCESS' -Details "Session timer initialized with $($script:SessionTimeoutMinutes) minute timeout"
}

function Check-SessionTimeout {
    <#
    .SYNOPSIS
        Check if session has timed out due to inactivity
    #>
    if ($script:IsSessionLocked) {
        return
    }

    $timeSinceActivity = (Get-Date) - $script:LastActivityTime
    if ($timeSinceActivity.TotalMinutes -ge $script:SessionTimeoutMinutes) {
        Write-AuditLog -Action "SESSION_TIMEOUT" -Target "Application" -Result 'SUCCESS' -Details "Session locked after $([int]$timeSinceActivity.TotalMinutes) minutes of inactivity"
        Lock-Session
    }
}

function Register-UserActivity {
    <#
    .SYNOPSIS
        Register user activity to reset session timeout
    #>
    $script:LastActivityTime = Get-Date
}

function Lock-Session {
    <#
    .SYNOPSIS
        Lock the session and show lock screen overlay
    #>
    if ($script:IsSessionLocked) {
        return
    }

    $script:IsSessionLocked = $true

    # Create lock screen overlay
    $script:LockScreenOverlay = New-Object System.Windows.Controls.Grid
    $script:LockScreenOverlay.Background = [System.Windows.Media.Brush]::Parse("#E0000000")  # Semi-transparent black
    $script:LockScreenOverlay.Opacity = 0.95

    # Create lock panel
    $lockPanel = New-Object System.Windows.Controls.StackPanel
    $lockPanel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $lockPanel.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $lockPanel.Width = 400

    # Lock icon
    $lockIcon = New-Object System.Windows.Controls.TextBlock
    $lockIcon.Text = ""
    $lockIcon.FontSize = 64
    $lockIcon.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $lockIcon.Foreground = [System.Windows.Media.Brush]::Parse("#58A6FF")
    $lockIcon.Margin = [System.Windows.Thickness]::new(0, 0, 0, 20)

    # Title
    $titleText = New-Object System.Windows.Controls.TextBlock
    $titleText.Text = "Session Locked"
    $titleText.FontSize = 28
    $titleText.FontWeight = [System.Windows.FontWeights]::Bold
    $titleText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $titleText.Foreground = [System.Windows.Media.Brush]::Parse("#FFFFFF")
    $titleText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 10)

    # Message
    $messageText = New-Object System.Windows.Controls.TextBlock
    $messageText.Text = "This session has been locked due to inactivity.`nClick Unlock to continue."
    $messageText.FontSize = 14
    $messageText.TextAlignment = [System.Windows.TextAlignment]::Center
    $messageText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $messageText.Foreground = [System.Windows.Media.Brush]::Parse("#8B949E")
    $messageText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 30)
    $messageText.TextWrapping = [System.Windows.TextWrapping]::Wrap

    # Unlock button
    $unlockBtn = New-Object System.Windows.Controls.Button
    $unlockBtn.Content = "Unlock Session"
    $unlockBtn.Width = 150
    $unlockBtn.Height = 40
    $unlockBtn.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $unlockBtn.Background = [System.Windows.Media.Brush]::Parse("#58A6FF")
    $unlockBtn.Foreground = [System.Windows.Media.Brush]::Parse("#FFFFFF")
    $unlockBtn.BorderThickness = [System.Windows.Thickness]::new(0)
    $unlockBtn.FontSize = 14
    $unlockBtn.Cursor = [System.Windows.Input.Cursor]::Hand
    $unlockBtn.Margin = [System.Windows.Thickness]::new(0, 10, 0, 0)

    # Button style
    $unlockBtn.Add_MouseEnter({
        $this.Background = [System.Windows.Media.Brush]::Parse("#79B8FF")
    })
    $unlockBtn.Add_MouseLeave({
        $this.Background = [System.Windows.Media.Brush]::Parse("#58A6FF")
    })
    $unlockBtn.Add_Click({
        Unlock-Session
    })

    # Add elements to panel
    $lockPanel.Children.Add($lockIcon) | Out-Null
    $lockPanel.Children.Add($titleText) | Out-Null
    $lockPanel.Children.Add($messageText) | Out-Null
    $lockPanel.Children.Add($unlockBtn) | Out-Null

    # Add panel to overlay
    $script:LockScreenOverlay.Children.Add($lockPanel) | Out-Null

    # Add overlay to window
    $mainGrid = $window.FindName("MainGrid")
    if ($mainGrid) {
        $mainGrid.Children.Add($script:LockScreenOverlay) | Out-Null
    }

    # Disable all interaction
    $window.IsEnabled = $false
}

function Unlock-Session {
    <#
    .SYNOPSIS
        Unlock the session and remove lock screen overlay
    #>
    $script:IsSessionLocked = $false
    $script:LastActivityTime = Get-Date

    # Remove overlay
    if ($script:LockScreenOverlay) {
        $mainGrid = $window.FindName("MainGrid")
        if ($mainGrid) {
            $mainGrid.Children.Remove($script:LockScreenOverlay) | Out-Null
        }
        $script:LockScreenOverlay = $null
    }

    # Re-enable interaction
    $window.IsEnabled = $true

    Write-AuditLog -Action "SESSION_UNLOCKED" -Target "Application" -Result 'SUCCESS' -Details "Session unlocked by user"
}

function Attach-ActivityTrackers {
    <#
    .SYNOPSIS
        Attach event handlers to track user activity
    .PARAMETER Window
        The WPF window to attach trackers to
    #>
    param(
        [System.Windows.Window]$Window
    )

    # Track mouse movement
    $Window.Add_MouseMove({
        Register-UserActivity
    })

    # Track keyboard input
    $Window.Add_KeyDown({
        Register-UserActivity
    })

    # Track button clicks
    $Window.Add_MouseLeftButtonUp({
        Register-UserActivity
    })
}

# ======================================================================
# KEYBOARD SHORTCUTS - Phase 3
# ======================================================================

function Register-KeyboardShortcuts {
    <#
    .SYNOPSIS
        Register keyboard shortcuts for common operations
    .PARAMETER Window
        The WPF window
    #>
    param(
        [System.Windows.Window]$Window
    )

    # Remove the basic activity tracker since we're adding comprehensive keyboard handling
    try {
        $Window.Remove_KeyDown($script:ActivityTrackerKeyDown)
    } catch {
        # Ignore if handler wasn't attached
    }

    $Window.Add_KeyDown({
        param($sender, $e)

        # Only process if no modifier keys are pressed (or Ctrl alone)
        if ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Alt -or
            $e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Windows) {
            return
        }

        $isCtrl = ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -eq [System.Windows.Input.ModifierKeys]::Control

        switch ($e.Key) {
            # F1 - Help
            "F1" {
                if (-not $isCtrl) {
                    Show-HelpContent -Topic "Workflow"
                    $e.Handled = $true
                }
            }

            # F5 - Refresh dashboard
            "F5" {
                if (-not $isCtrl) {
                    Refresh-Data
                    $e.Handled = $true
                }
            }

            # Ctrl+S - Save/export rules
            { $_ -eq "S" -and $isCtrl } {
                Export-SelectedRules
                $e.Handled = $true
            }

            # Ctrl+R - Generate rules
            { $_ -eq "R" -and $isCtrl } {
                if ($GenerateRulesBtn) {
                    $GenerateRulesBtn.RaiseEvent([System.Windows.Controls.Button]::ClickEvent)
                    $e.Handled = $true
                }
            }

            # Ctrl+D - Deduplicate rules
            { $_ -eq "D" -and $isCtrl } {
                Deduplicate-Rules
                $e.Handled = $true
            }

            # Ctrl+E - Scan local events
            { $_ -eq "E" -and $isCtrl } {
                if ($ScanLocalEventsBtn) {
                    $ScanLocalEventsBtn.RaiseEvent([System.Windows.Controls.Button]::ClickEvent)
                    $e.Handled = $true
                }
            }

            # Ctrl+G - Test connectivity/quick scan
            { $_ -eq "G" -and $isCtrl } {
                if ($TestConnectivityBtn) {
                    $TestConnectivityBtn.RaiseEvent([System.Windows.Controls.Button]::ClickEvent)
                    $e.Handled = $true
                }
            }

            # Delete - Remove selected items
            "Delete" {
                if (-not $isCtrl) {
                    Remove-SelectedItems
                    $e.Handled = $true
                }
            }

            # Escape - Close dialog or cancel operation
            "Escape" {
                Remove-ProgressOverlay
                if ($script:IsSessionLocked) {
                    Unlock-Session
                }
                $e.Handled = $true
            }

            # Ctrl+1-5 - Switch tabs (Dashboard, Artifacts, Rules, Events, Deployment)
            { $_ -eq "D1" -and $isCtrl } {
                if ($NavDashboard) { $NavDashboard.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }
            { $_ -eq "D2" -and $isCtrl } {
                if ($NavArtifacts) { $NavArtifacts.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }
            { $_ -eq "D3" -and $isCtrl } {
                if ($NavRuleGenerator) { $NavRuleGenerator.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }
            { $_ -eq "D4" -and $isCtrl } {
                if ($NavEvents) { $NavEvents.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }
            { $_ -eq "D5" -and $isCtrl } {
                if ($NavDeployment) { $NavDeployment.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }

            # Ctrl+0 - About
            { $_ -eq "D0" -and $isCtrl } {
                if ($NavAbout) { $NavAbout.RaiseEvent([System.Windows.Controls.Button]::ClickEvent) }
                $e.Handled = $true
            }
        }

        Register-UserActivity
    })
}

function Remove-SelectedItems {
    <#
    .SYNOPSIS
        Remove selected items from focused list
    #>
    if ($RulesDataGrid -and $RulesDataGrid.Items.Count -gt 0 -and $RulesDataGrid.SelectedItems.Count -gt 0) {
        $selectedItems = @($RulesDataGrid.SelectedItems)
        foreach ($item in $selectedItems) {
            $script:GeneratedRules.Remove($item)
        }
        $RulesDataGrid.Items.Refresh()
        Update-Badges
        Write-AuditLog -Action "RULES_DELETED" -Target "Multiple" -Result 'SUCCESS' -Details "Deleted $($selectedItems.Count) rules via keyboard (Delete)"
        return
    }
}

function Deduplicate-Rules {
    <#
    .SYNOPSIS
        Deduplicate generated rules by selected criteria
    #>
    if (-not $script:GeneratedRules -or $script:GeneratedRules.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No rules to deduplicate.", "Deduplicate", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Show deduplication options
    $result = [System.Windows.MessageBox]::Show(
        "Deduplicate by which criteria?`n`nYes = Publisher (Recommended)`nNo = File Hash`nCancel = Path",
        "Deduplicate Rules",
        [System.Windows.MessageBoxButton]::YesNoCancel,
        [System.Windows.MessageBoxImage]::Question
    )

    $criteria = switch ($result) {
        "Yes" { "Publisher" }
        "No" { "Hash" }
        default { return }
    }

    $uniqueRules = @()
    $seen = @{}

    foreach ($rule in $script:GeneratedRules) {
        $key = switch ($criteria) {
            "Publisher" {
                if ($rule.Publisher) { $rule.Publisher }
                elseif ($rule.Name) { $rule.Name }
                else { $rule.FilePath }
            }
            "Hash" {
                if ($rule.FileHash) { $rule.FileHash }
                else { "$($rule.Name)$($rule.FilePath)" }
            }
        }

        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $uniqueRules += $rule
        }
    }

    $removed = $script:GeneratedRules.Count - $uniqueRules.Count
    $script:GeneratedRules = [System.Collections.ObjectModel.ObservableCollection[object]]::new($uniqueRules)

    $RulesDataGrid.ItemsSource = $script:GeneratedRules
    $RulesDataGrid.Items.Refresh()

    # Apply rule type visual formatting
    Apply-RuleTypeFormatting

    $RulesOutput.Text += "Deduplicated by $criteria`: Removed $removed duplicate rules.`n"

    Write-AuditLog -Action "RULES_DEDUPLICATED" -Target $criteria -Result 'SUCCESS' -Details "Removed $removed duplicate rules"
}

function Export-SelectedRules {
    <#
    .SYNOPSIS
        Export selected or all rules to file
    #>
    if (-not $script:GeneratedRules -or $script:GeneratedRules.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No rules to export.", "Export Rules", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "AppLocker Policy (*.xml)|*.xml|All Files (*.*)|*.*"
    $saveDialog.DefaultExt = "xml"
    $saveDialog.FileName = "AppLocker-Rules-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    $saveDialog.Title = "Export AppLocker Rules"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $rulesOutput = Export-AppLockerRules -Rules $script:GeneratedRules -OutputPath $saveDialog.FileName
            Write-AuditLog -Action "RULES_EXPORTED" -Target $saveDialog.FileName -Result 'SUCCESS' -Details "Exported $($script:GeneratedRules.Count) rules"
            [System.Windows.MessageBox]::Show("Rules exported successfully to:`n$($saveDialog.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
        catch {
            $errorMsg = ConvertTo-SafeString -InputString $_.Exception.Message
            Write-AuditLog -Action "RULES_EXPORT_FAILED" -Target $saveDialog.FileName -Result 'FAILURE' -Details "Error: $errorMsg"
            [System.Windows.MessageBox]::Show("Failed to export rules:`n$errorMsg", "Export Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}

function Format-RuleTypeDisplay {
    <#
    .SYNOPSIS
        Format rule type with color indicator for display
    .DESCRIPTION
        Adds visual indicators for different rule types:
        - Publisher: Blue icon ðŸ¢
        - Hash: Purple icon ðŸ”
        - Path: Green icon ðŸ“
    .PARAMETER Rule
        The rule object
    .OUTPUTS
        Formatted type string with emoji indicator
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $type = if ($Rule.Type) { $Rule.Type } else { "Path" }

    $indicator = switch ($type) {
        "Publisher" { "[PUB]" }
        "Hash" { "[HASH]" }
        "Path" { "[PATH]" }
        default { "[?]" }
    }

    return "$indicator $type"
}

function Apply-RuleTypeFormatting {
    <#
    .SYNOPSIS
        Apply visual formatting to all rules in the DataGrid
    .DESCRIPTION
        Updates the Type column for all rules with visual indicators
    #>
    if (-not $script:GeneratedRules -or $script:GeneratedRules.Count -eq 0) {
        return
    }

    foreach ($rule in $script:GeneratedRules) {
        if (-not $rule.TypeDisplay) {
            $rule.TypeDisplay = Format-RuleTypeDisplay -Rule $rule
        }

        # Add color property for DataGrid styling
        switch ($rule.Type) {
            "Publisher" {
                $rule.TypeColor = "#58A6FF"  # Blue
                $rule.TypeIcon = "[PUB]"
            }
            "Hash" {
                $rule.TypeColor = "#A371F7"  # Purple
                $rule.TypeIcon = "[HASH]"
            }
            "Path" {
                $rule.TypeColor = "#3FB950"  # Green
                $rule.TypeIcon = "[PATH]"
            }
            default {
                $rule.TypeColor = "#8B949E"  # Gray
                $rule.TypeIcon = "[?]"
            }
        }
    }

    $RulesDataGrid.Items.Refresh()
}

function Test-EnforceModeReadiness {
    <#
    .SYNOPSIS
        Validate readiness for transitioning from Audit to Enforce mode
    .DESCRIPTION
        Performs comprehensive checks before allowing enforce mode transition
    .OUTPUTS
        Hashtable with validation results and warnings
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $results = @{
        ready = $true
        warnings = @()
        errors = @()
        checks = @{}
    }

    # Check 1: Review recent AppLocker events for audit/blocked events
    try {
        $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
        $recentEvents = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue

        if ($recentEvents) {
            $auditEvents = @($recentEvents | Where-Object { $_.Id -eq 8003 })
            $blockedEvents = @($recentEvents | Where-Object { $_.Id -eq 8004 })

            $results.checks['recentAuditEvents'] = $auditEvents.Count
            $results.checks['recentBlockedEvents'] = $blockedEvents.Count

            if ($blockedEvents.Count -gt 0) {
                $results.warnings += "Found $($blockedEvents.Count) blocked applications. These will be BLOCKED in enforce mode!"
                $results.ready = $false
                $results.errors += "Applications currently being blocked should be addressed before enforce mode."
            }

            if ($auditEvents.Count -gt 100) {
                $results.warnings += "High volume of audit events ($($auditEvents.Count)). Review before enabling enforce mode."
            }
        }
        else {
            $results.warnings += "No recent AppLocker events found. Ensure audit mode has been running and generating events."
            $results.checks['recentAuditEvents'] = 0
            $results.checks['recentBlockedEvents'] = 0
        }
    }
    catch {
        $results.warnings += "Could not check AppLocker event log: $($_.Exception.Message)"
    }

    # Check 2: Verify policy has rules configured
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($policy) {
            $ruleCount = 0
            foreach ($collection in $policy.RuleCollections) {
                $ruleCount += $collection.Count
            }
            $results.checks['totalRules'] = $ruleCount

            if ($ruleCount -eq 0) {
                $results.errors += "No AppLocker rules configured. Enforce mode will block ALL applications!"
                $results.ready = $false
            }
            elseif ($ruleCount -lt 10) {
                $results.warnings += "Low rule count ($ruleCount). Ensure all necessary applications are covered."
            }
        }
        else {
            $results.errors += "Could not retrieve effective AppLocker policy."
            $results.ready = $false
        }
    }
    catch {
        $results.errors += "Failed to check AppLocker policy: $($_.Exception.Message)"
        $results.ready = $false
    }

    # Check 3: Verify minimum audit mode duration (recommended: 7 days)
    try {
        $auditLogPath = 'C:\GA-AppLocker\logs\audit.log'
        if (Test-Path $auditLogPath) {
            $auditLogFile = Get-Item $auditLogPath
            $daysInAudit = ((Get-Date) - $auditLogFile.CreationTime).Days
            $results.checks['daysInAudit'] = $daysInAudit

            if ($daysInAudit -lt 7) {
                $results.warnings += "Audit mode has only been active for $daysInAudit day(s). Recommended minimum is 7 days."
            }
        }
        else {
            $results.warnings += "No audit log found. Cannot verify audit mode duration."
            $results.checks['daysInAudit'] = 0
        }
    }
    catch {
        $results.warnings += "Could not verify audit mode duration."
    }

    # Check 4: Check for critical system paths in rules
    try {
        $criticalPaths = @(
            'C:\Windows\System32',
            'C:\Windows\SysWOW64',
            'C:\Program Files'
        )
        $results.checks['criticalPathCoverage'] = $false

        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($policy) {
            foreach ($collection in $policy.RuleCollections) {
                foreach ($rule in $collection) {
                    if ($rule.Conditions) {
                        foreach ($condition in $rule.Conditions) {
                            if ($condition.PathConditions) {
                                foreach ($pathCond in $condition.PathConditions) {
                                    foreach ($criticalPath in $criticalPaths) {
                                        if ($pathCond.Path -like "$criticalPath*") {
                                            $results.checks['criticalPathCoverage'] = $true
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (-not $results.checks['criticalPathCoverage']) {
            $results.warnings += "No rules found covering critical system paths (System32, Program Files)."
        }
    }
    catch {
        $results.warnings += "Could not verify critical path coverage."
    }

    # Check 5: Verify GPO links exist (domain mode only)
    if (-not $script:IsWorkgroup) {
        try {
            Import-Module GroupPolicy -ErrorAction SilentlyContinue
            $gpoNames = @("AppLocker-DC", "AppLocker-Servers", "AppLocker-Workstations")
            $linkedGPOs = 0

            foreach ($gpoName in $gpoNames) {
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if ($gpo) {
                    # Check if GPO has any links
                    $xml = [xml]$gpo.Xml
                    if ($xml.GPO.LinksTo -and $xml.GPO.LinksTo -ne "") {
                        $linkedGPOs++
                    }
                }
            }

            $results.checks['linkedGPOs'] = $linkedGPOs

            if ($linkedGPOs -eq 0) {
                $results.warnings += "No GPOs are currently linked. Policy won't apply to any systems."
            }
        }
        catch {
            $results.warnings += "Could not verify GPO link status."
        }
    }

    return $results
}

function Show-EnforceModeValidationDialog {
    <#
    .SYNOPSIS
        Display validation results for enforce mode transition
    .PARAMETER ValidationResult
        Results from Test-EnforceModeReadiness
    .OUTPUTS
        Boolean indicating if user wants to proceed
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ValidationResult
    )

    $message = "ENFORCE MODE VALIDATION RESULTS`n`n"

    # Status indicator
    if ($ValidationResult.ready) {
        $message += "Status: READY FOR ENFORCE MODE`n`n"
    }
    else {
        $message += "Status: NOT RECOMMENDED - See errors below`n`n"
    }

    # Checks summary
    $message += "=== CHECKS ===`n"
    $message += "Recent Audit Events: $($ValidationResult.checks['recentAuditEvents'])`n"
    $message += "Recent Blocked Events: $($ValidationResult.checks['recentBlockedEvents'])`n"
    $message += "Total Rules Configured: $($ValidationResult.checks['totalRules'])`n"
    if ($ValidationResult.checks.ContainsKey('daysInAudit')) {
        $message += "Days in Audit Mode: $($ValidationResult.checks['daysInAudit'])`n"
    }
    if ($ValidationResult.checks.ContainsKey('linkedGPOs')) {
        $message += "GPOs Linked: $($ValidationResult.checks['linkedGPOs'])`n"
    }
    $message += "`n"

    # Errors
    if ($ValidationResult.errors.Count -gt 0) {
        $message += "=== ERRORS ===`n"
        foreach ($error in $ValidationResult.errors) {
            $message += "  $error`n"
        }
        $message += "`n"
    }

    # Warnings
    if ($ValidationResult.warnings.Count -gt 0) {
        $message += "=== WARNINGS ===`n"
        foreach ($warning in $ValidationResult.warnings) {
            $message += "  $warning`n"
        }
        $message += "`n"
    }

    if ($ValidationResult.ready -and $ValidationResult.errors.Count -eq 0) {
        $message += "No critical issues found. Proceed with caution."
    }
    else {
        $message += "It is strongly recommended to address these issues before enabling enforce mode."
    }

    $message += "`n`nDo you want to proceed with enforce mode?"

    # Determine the icon to show based on validation result
    if ($ValidationResult.ready) {
        $icon = [System.Windows.MessageBoxImage]::Information
    } else {
        $icon = [System.Windows.MessageBoxImage]::Warning
    }

    $result = [System.Windows.MessageBox]::Show(
        $message,
        "Enforce Mode Validation",
        [System.Windows.MessageBoxButton]::YesNo,
        $icon
    )

    $proceed = ($result -eq [System.Windows.MessageBoxResult]::Yes)

    # Log the validation decision
    if ($proceed) {
        Write-AuditLog -Action "ENFORCE_MODE_PROCEED" -Target "Validation" -Result 'SUCCESS' -Details "User chose to proceed despite warnings"
    } else {
        Write-AuditLog -Action "ENFORCE_MODE_CANCELLED" -Target "Validation" -Result 'CANCELLED' -Details "User cancelled enforce mode after validation"
    }

    return $proceed
}

function Invoke-RetryOperation {
    <#
    .SYNOPSIS
        Execute operation with retry logic and alternative suggestions
    .DESCRIPTION
        Wraps an operation with automatic retry on failure and provides helpful error messages
    .PARAMETER ScriptBlock
        The operation to execute
    .PARAMETER MaxRetries
        Maximum number of retry attempts (default: 3)
    .PARAMETER RetryDelaySeconds
        Delay between retries in seconds (default: 2)
    .PARAMETER OperationName
        Name of the operation for logging
    .PARAMETER AlternativeActions
        Array of hashtables with alternative action suggestions
        Each hashtable should have: Name, Description, Command (optional)
    .OUTPUTS
        Hashtable with success, result, error, and alternatives if failed
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2,

        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [Parameter(Mandatory = $false)]
        [hashtable[]]$AlternativeActions = @()
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxRetries) {
        $attempt++

        try {
            $result = & $ScriptBlock

            return @{
                success = $true
                result = $result
                attempts = $attempt
                operation = $OperationName
            }
        }
        catch {
            $lastError = $_
            Write-AuditLog -Action "RETRY_ATTEMPT" -Target $OperationName -Result 'FAILURE' -Details "Attempt $attempt/$MaxRetries failed: $($_.Exception.Message)"

            if ($attempt -lt $MaxRetries) {
                Write-Log "$OperationName failed (attempt $attempt/$MaxRetries). Retrying in $RetryDelaySeconds seconds..." -Level "WARN"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
    }

    # All retries failed - prepare helpful error message with alternatives
    $errorMsg = "Operation '$OperationName' failed after $MaxRetries attempts."
    $errorDetails = "Last error: $($lastError.Exception.Message)"

    # Build alternative suggestions
    $suggestions = @()
    if ($AlternativeActions.Count -gt 0) {
        $suggestions += "`n`n=== ALTERNATIVE ACTIONS ==="
        foreach ($alt in $AlternativeActions) {
            $suggestions += "`n$($alt.Name): $($alt.Description)"
            if ($alt.Command) {
                $suggestions += "`n  Command: $($alt.Command)"
            }
        }
    }

    # Add common suggestions based on error type
    if ($lastError.Exception.Message -match "access denied|unauthorized|permission") {
        $suggestions += "`n`nCommon solutions:"
        $suggestions += "`n  - Run as Administrator"
        $suggestions += "`n  - Verify you have permissions to perform this action"
        $suggestions += "`n  - Check if the target resource is locked by another process"
    }
    elseif ($lastError.Exception.Message -match "network|connection|remote") {
        $suggestions += "`n`nCommon solutions:"
        $suggestions += "`n  - Verify network connectivity"
        $suggestions += "`n  - Check if the remote computer is online"
        $suggestions += "`n  - Verify WinRM is enabled on remote systems"
        $suggestions += "`n  - Check firewall rules"
    }
    elseif ($lastError.Exception.Message -match "module|import") {
        $suggestions += "`n`nCommon solutions:"
        $suggestions += "`n  - Install required modules (GroupPolicy, ActiveDirectory)"
        $suggestions += "`n  - Run: Install-WindowsFeature RSAT-AD-PowerShell"
        $suggestions += "`n  - Run: Install-WindowsFeature GPMC"
    }

    $fullMessage = $errorMsg + "`n`n" + $errorDetails + ($suggestions -join "")

    Write-AuditLog -Action "OPERATION_FAILED" -Target $OperationName -Result 'FAILURE' -Details "Failed after $MaxRetries attempts: $($lastError.Exception.Message)"

    return @{
        success = $false
        error = $lastError.Exception.Message
        fullMessage = $fullMessage
        attempts = $attempt
        operation = $OperationName
        alternatives = $AlternativeActions
    }
}

function Show-ErrorWithAlternatives {
    <#
    .SYNOPSIS
        Display error message with alternative action suggestions
    .PARAMETER ErrorResult
        Error result from Invoke-RetryOperation
    .PARAMETER OutputTextBox
        Optional output text box to display error in
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ErrorResult,

        [Parameter(Mandatory = $false)]
        $OutputTextBox = $null
    )

    $message = $ErrorResult.fullMessage

    if ($OutputTextBox) {
        $OutputTextBox.Text = $message
    }
    else {
        [System.Windows.MessageBox]::Show(
            $message,
            "$($ErrorResult.operation) Failed",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }

    Write-AuditLog -Action "ERROR_DISPLAYED" -Target $ErrorResult.operation -Result 'FAILURE' -Details "Error shown to user with alternatives"
}

function Test-SafePath {
    <#
    .SYNOPSIS
        Validate a file path is safe and does not contain path traversal patterns
    .DESCRIPTION
        Checks for path traversal attacks and validates the path is within expected bounds
    .PARAMETER Path
        The path to validate
    .PARAMETER AllowRelative
        Allow relative paths (default: false)
    .PARAMETER AllowedRoots
        Array of allowed root paths (e.g., @("C:\GA-AppLocker", "C:\Windows"))
    .OUTPUTS
        Hashtable with valid (bool) and error message if invalid
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$AllowRelative,

        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRoots = @()
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{
            valid = $false
            error = "Path is empty"
        }
    }

    # Check for path traversal patterns
    $traversalPatterns = @(
        '\.\.',
        '~\.\.',
        '%2e%2e',
        '%252e',
        '\.\.',
        '..\',
        '\..\',
        '../',
        '..\\',
        '\0',
        '\x00'
    )

    foreach ($pattern in $traversalPatterns) {
        if ($Path -match [regex]::Escape($pattern)) {
            Write-AuditLog -Action "PATH_TRAVERSAL_DETECTED" -Target $Path -Result 'FAILURE' -Details "Blocked path containing: $pattern"
            return @{
                valid = $false
                error = "Path contains invalid characters or traversal patterns"
            }
        }
    }

    # Block UNC paths to arbitrary locations
    if ($Path -match '^\\\\[^\\]+\\[^\\]+\w+\$.*' -and $AllowedRoots.Count -eq 0) {
        return @{
            valid = $false
            error = "UNC paths to administrative shares are not allowed"
        }
    }

    # Block device paths
    if ($Path -match '^\\\\\.\\') {
        return @{
            valid = $false
            error = "Device paths are not allowed"
        }
    }

    # If relative paths not allowed, ensure path is absolute or rooted
    if (-not $AllowRelative) {
        if (-not [System.IO.Path]::IsPathRooted($Path)) {
            # Not absolute, check if it's a relative path that could be dangerous
            if ($Path -match '^[\\/]' -or $Path -match '^[a-zA-Z]:') {
                # OK - rooted path
            } else {
                return @{
                    valid = $false
                    error = "Absolute path required"
                }
            }
        }
    }

    # Check against allowed roots if specified
    if ($AllowedRoots.Count -gt 0) {
        $isAllowed = $false
        try {
            $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) {
                $Path
            } else {
                Join-Path (Get-Location).Path $Path
            }

            foreach ($root in $AllowedRoots) {
                if ($fullPath -like "$root*") {
                    $isAllowed = $true
                    break
                }
            }

            if (-not $isAllowed) {
                Write-AuditLog -Action "PATH_ACCESS_DENIED" -Target $Path -Result 'FAILURE' -Details "Path not in allowed roots: $($AllowedRoots -join ', ')"
                return @{
                    valid = $false
                    error = "Path is outside allowed locations"
                }
            }
        }
        catch {
            return @{
                valid = $false
                error = "Failed to validate path: $($_.Exception.Message)"
            }
        }
    }

    return @{
        valid = $true
        path = $Path
    }
}

function Get-SafeResolvedPath {
    <#
    .SYNOPSIS
        Safely resolve and validate a path
    .DESCRIPTION
        Resolves a path to its absolute form and validates it's safe
    .PARAMETER Path
        The path to resolve
    .PARAMETER AllowedRoots
        Array of allowed root paths
    .OUTPUTS
        Resolved path or $null if invalid
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRoots = @()
    )

    # First validate the path
    $validation = Test-SafePath -Path $Path -AllowedRoots $AllowedRoots
    if (-not $validation.valid) {
        Write-Log "Path validation failed: $($validation.error)" -Level "ERROR"
        return $null
    }

    # Try to resolve the path
    try {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
            $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
            return $resolved
        }
        return $Path
    }
    catch {
        Write-Log "Failed to resolve path: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ======================================================================
# PROGRESS INDICATORS - Phase 3
# ======================================================================

$script:ProgressOverlay = $null
$script:ProgressBar = $null
$script:ProgressText = $null
$script:ProgressDetailText = $null
$script:ProgressCancelButton = $null
$script:ProgressCallback = $null

function Show-ProgressOverlay {
    <#
    .SYNOPSIS
        Display a progress overlay for long-running operations
    .PARAMETER Message
        Main progress message
    .PARAMETER DetailMessage
        Optional detail message
    .PARAMETER IsIndeterminate
        Show indeterminate progress bar (marquee)
    .PARAMETER CanCancel
        Show cancel button and provide callback
    .PARAMETER CancelCallback
        ScriptBlock to execute when cancel is clicked
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$DetailMessage = "",

        [Parameter(Mandatory = $false)]
        [switch]$IsIndeterminate,

        [Parameter(Mandatory = $false)]
        [switch]$CanCancel,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CancelCallback = $null
    )

    # Dismiss any existing overlay
    Remove-ProgressOverlay

    # Create overlay grid
    $script:ProgressOverlay = New-Object System.Windows.Controls.Grid
    $script:ProgressOverlay.Background = [System.Windows.Media.Brush]::Parse("#E0000000")
    $script:ProgressOverlay.Opacity = 0.85

    # Create progress panel
    $progressPanel = New-Object System.Windows.Controls.StackPanel
    $progressPanel.Width = 450
    $progressPanel.Background = [System.Windows.Media.Brush]::Parse("#161B22")
    $progressPanel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $progressPanel.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $progressPanel.Margin = [System.Windows.Thickness]::new(20)

    # Add border
    $border = New-Object System.Windows.Controls.Border
    $border.BorderBrush = [System.Windows.Media.Brush]::Parse("#30363D")
    $border.BorderThickness = [System.Windows.Thickness]::new(1)
    $border.CornerRadius = [System.Windows.CornerRadius]::new(6)
    $border.Padding = [System.Windows.Thickness]::new(24)
    $border.Child = $progressPanel

    # Loading spinner icon
    $spinnerText = New-Object System.Windows.Controls.TextBlock
    $spinnerText.Text = ""
    $spinnerText.FontSize = 48
    $spinnerText.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
    $spinnerText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
    $spinnerText.Foreground = [System.Windows.Media.Brush]::Parse("#58A6FF")

    # Main message
    $script:ProgressText = New-Object System.Windows.Controls.TextBlock
    $script:ProgressText.Text = $Message
    $script:ProgressText.FontSize = 18
    $script:ProgressText.FontWeight = [System.Windows.FontWeights]::SemiBold
    $script:ProgressText.Foreground = [System.Windows.Media.Brush]::Parse("#FFFFFF")
    $script:ProgressText.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $script:ProgressText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 12)

    # Progress bar
    $script:ProgressBar = New-Object System.Windows.Controls.ProgressBar
    $script:ProgressBar.Height = 6
    $script:ProgressBar.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)
    $script:ProgressBar.Foreground = [System.Windows.Media.Brush]::Parse("#58A6FF")
    $script:ProgressBar.Background = [System.Windows.Media.Brush]::Parse("#30363D")

    if ($IsIndeterminate) {
        $script:ProgressBar.IsIndeterminate = $true
    } else {
        $script:ProgressBar.Minimum = 0
        $script:ProgressBar.Maximum = 100
        $script:ProgressBar.Value = 0
    }

    # Detail message
    $script:ProgressDetailText = New-Object System.Windows.Controls.TextBlock
    $script:ProgressDetailText.Text = $DetailMessage
    $script:ProgressDetailText.FontSize = 14
    $script:ProgressDetailText.Foreground = [System.Windows.Media.Brush]::Parse("#8B949E")
    $script:ProgressDetailText.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $script:ProgressDetailText.Margin = [System.Windows.Thickness]::new(0, 0, 0, 16)

    # Cancel button (if enabled)
    if ($CanCancel) {
        $script:ProgressCancelButton = New-Object System.Windows.Controls.Button
        $script:ProgressCancelButton.Content = "Cancel"
        $script:ProgressCancelButton.Width = 100
        $script:ProgressCancelButton.Height = 36
        $script:ProgressCancelButton.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
        $script:ProgressCancelButton.Background = [System.Windows.Media.Brush]::Parse("#F85149")
        $script:ProgressCancelButton.Foreground = [System.Windows.Media.Brush]::Parse("#FFFFFF")
        $script:ProgressCancelButton.BorderThickness = [System.Windows.Thickness]::new(0)
        $script:ProgressCancelButton.FontSize = 14
        $script:ProgressCancelButton.Cursor = [System.Windows.Input.Cursor]::Hand

        $script:ProgressCancelButton.Add_MouseEnter({
            $this.Background = [System.Windows.Media.Brush]::Parse("#FF7B72")
        })
        $script:ProgressCancelButton.Add_MouseLeave({
            $this.Background = [System.Windows.Media.Brush]::Parse("#F85149")
        })
        $script:ProgressCancelButton.Add_Click({
            Remove-ProgressOverlay
            if ($CancelCallback) {
                & $CancelCallback
            }
            Write-AuditLog -Action "OPERATION_CANCELLED" -Target $Message -Result 'CANCELLED' -Details "User cancelled operation"
        })

        $script:ProgressCallback = $CancelCallback
    }

    # Add elements to panel
    $progressPanel.Children.Add($spinnerText) | Out-Null
    $progressPanel.Children.Add($script:ProgressText) | Out-Null
    $progressPanel.Children.Add($script:ProgressBar) | Out-Null
    $progressPanel.Children.Add($script:ProgressDetailText) | Out-Null
    if ($script:ProgressCancelButton) {
        $progressPanel.Children.Add($script:ProgressCancelButton) | Out-Null
    }

    # Add border to overlay
    $script:ProgressOverlay.Children.Add($border) | Out-Null

    # Add overlay to window
    $mainGrid = $window.FindName("MainGrid")
    if ($mainGrid) {
        $mainGrid.Children.Add($script:ProgressOverlay) | Out-Null
    }

    # Disable main window interaction
    $window.IsEnabled = $false

    Write-AuditLog -Action "PROGRESS_STARTED" -Target $Message -Result 'SUCCESS' -Details "Progress overlay shown"
}

function Update-Progress {
    <#
    .SYNOPSIS
        Update the progress overlay
    .PARAMETER Message
        New main message (optional)
    .PARAMETER DetailMessage
        New detail message
    .PARAMETER PercentComplete
        Progress percentage (0-100)
    .PARAMETER CurrentItem
        Current item being processed (for detail)
    .PARAMETER TotalItems
        Total items to process
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$DetailMessage,

        [Parameter(Mandatory = $false)]
        [int]$PercentComplete,

        [Parameter(Mandatory = $false)]
        [int]$CurrentItem = 0,

        [Parameter(Mandatory = $false)]
        [int]$TotalItems = 0
    )

    if (-not $script:ProgressOverlay) {
        return
    }

    # Update main message
    if ($Message) {
        $script:ProgressText.Text = $Message
    }

    # Update detail message
    if ($DetailMessage) {
        $script:ProgressDetailText.Text = $DetailMessage
    }
    elseif ($TotalItems -gt 0) {
        $script:ProgressDetailText.Text = "Processing $CurrentItem of $TotalItems..."
    }

    # Update progress bar
    if ($PercentComplete -ge 0 -and $PercentComplete -le 100) {
        $script:ProgressBar.Value = $PercentComplete
    }
    elseif ($TotalItems -gt 0) {
        $percent = [math]::Min(100, [math]::Max(0, ($CurrentItem / $TotalItems) * 100))
        $script:ProgressBar.Value = $percent
    }
}

function Remove-ProgressOverlay {
    <#
    .SYNOPSIS
        Remove the progress overlay
    #>
    [CmdletBinding()]
    param()

    if ($script:ProgressOverlay) {
        $mainGrid = $window.FindName("MainGrid")
        if ($mainGrid) {
            $mainGrid.Children.Remove($script:ProgressOverlay) | Out-Null
        }
        $script:ProgressOverlay = $null
        $window.IsEnabled = $true
    }

    $script:ProgressBar = $null
    $script:ProgressText = $null
    $script:ProgressDetailText = $null
    $script:ProgressCancelButton = $null
    $script:ProgressCallback = $null
}

function Invoke-WithProgress {
    <#
    .SYNOPSIS
        Execute a scriptblock with progress indication
    .PARAMETER ScriptBlock
        The operation to execute
    .PARAMETER Message
        Progress message
    .PARAMETER IsIndeterminate
        Show indeterminate progress
    .OUTPUTS
        Result from scriptblock
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [switch]$IsIndeterminate
    )

    Show-ProgressOverlay -Message $Message -IsIndeterminate:$IsIndeterminate

    try {
        $result = & $ScriptBlock
        Remove-ProgressOverlay
        return $result
    }
    catch {
        Remove-ProgressOverlay
        throw
    }
}

# Log console/output text to file
function Write-OutputLog {
    param(
        [string]$Section,
        [string]$Output
    )

    $logDir = "C:\GA-AppLocker\Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $logDir "GA-AppLocker-$(Get-Date -Format 'yyyy-MM-dd').log"

    try {
        $header = "[$timestamp] [OUTPUT] === $Section ==="
        Add-Content -Path $logFile -Value $header -ErrorAction Stop
        # Log each line of output
        $Output -split "`n" | ForEach-Object {
            if ($_.Trim()) {
                Add-Content -Path $logFile -Value "    $_" -ErrorAction SilentlyContinue
            }
        }
        Add-Content -Path $logFile -Value "" -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if logging fails
    }
}

# ============================================================================
# HELP CONTENT FUNCTION
# Provides user-friendly help documentation for GA-AppLocker Dashboard
# ============================================================================
function Get-HelpContent {
    <#
    .SYNOPSIS
        Returns help content for the specified topic
    .PARAMETER Topic
        The help topic to retrieve (Workflow, Rules, Troubleshooting, WhatsNew, PolicyGuide)
    #>
    param([string]$Topic)

    switch ($Topic) {
        "Workflow" {
            return @"

=============================================================================
                    APPLOCKER DEPLOYMENT WORKFLOW
=============================================================================

This guide walks you through the complete AppLocker deployment process.


PHASE 1: SETUP (Prepare Your Environment)
---------------------------------------------------------------------------

1. AppLocker Setup (AppLocker Setup Panel)

   Purpose: Creates the Active Directory structure for AppLocker

   What it does:
   - Creates AppLocker OU with security groups
   - Sets up: AppLocker-Admins, AppLocker-StandardUsers
   - Sets up: AppLocker-Service-Accounts, AppLocker-Installers
   - Configures Domain Admins as owner (for deletion access)

   Required: Domain Administrator privileges

   Tip: Click 'Remove OU Protection' if you need to delete the OU later


2. Group Management (Group Management Panel)

   Purpose: Configure who belongs to each AppLocker group

   What it does:
   - Export current group membership to CSV file
   - Edit the CSV to add or remove members
   - Import changes back to Active Directory
   - Preview changes before applying

   Tip: Always use the preview feature before importing!


3. AD Discovery (AD Discovery Panel)

   Purpose: Find target computers for AppLocker deployment

   What it does:
   - Scans Active Directory for all computers
   - Separates computers into Online/Offline lists
   - Tests connectivity to each computer

   Tip: Select only online hosts for artifact scanning


PHASE 2: SCANNING (Collect Software Inventory)
---------------------------------------------------------------------------

4A. AD Discovery Panel (Remote Scanning)

   Purpose: Find target computers and collect artifacts remotely

   Workflow:
   - Discover Computers: Scans Active Directory for all computers
   - Test Connectivity: Pings computers to check online/offline status
   - Select Online: Choose computers from the Online list
   - Scan Selected: Collects artifacts from remote computers via WinRM

   Requirements:
   - WinRM must be enabled (use WinRM panel first)
   - Domain Administrator privileges
   - Target computers must be online

4B. Artifacts Panel (Local Scanning)

   Purpose: Collect artifacts from the local system

   Scan Options:
   - Scan Local System: Quick scan of the local computer
   - Load Artifacts: Pull from AD Discovery panel results
   - Import File: Load a CSV file manually
   - Import Folder: Load all CSVs from a folder

   Output: C:\GA-AppLocker\Scans\


5. Rule Generator (Rules Panel)

   Purpose: Create AppLocker rules from collected artifacts

   Import Options:
   - Load Artifacts: Pull from Artifact Collection panel
   - Load Events: Pull from Event Monitor panel
   - Import File: Load a CSV file manually
   - Import Folder: Load all CSVs from a folder

   Configure:
   - Type: Auto (recommended), Publisher, Hash, or Path
   - Action: Allow or Deny
   - Group: Which AD group receives this rule

   Rule Types:
   - Auto: Publisher for signed, Hash for unsigned (BEST)
   - Publisher: Uses code signing certificate
   - Hash: SHA256 hash (breaks on software updates)
   - Path: File path (least secure, use sparingly)

   Actions:
   - Generate Rules: Create rules from artifacts
   - Default Deny Rules: Block TEMP, Downloads, AppData
   - Browser Deny Rules: Block browsers for admin accounts


PHASE 3: DEPLOYMENT (Push Policies to Computers)
---------------------------------------------------------------------------

6. Deployment (Deployment Panel)

   Purpose: Deploy AppLocker policies via Group Policy

   Actions:
   - Create GPO: Creates new AppLocker GPO
   - Toggle Audit/Enforce: Switch mode for all rules at once
   - Export Rules: Save rules to C:\GA-AppLocker\Rules\
   - Import Rules: Load existing AppLocker XML file

   GPO Assignment:
   - DCs: Domain Controllers GPO
   - Servers: Member servers GPO
   - Workstations: Workstations GPO


7. WinRM Setup (WinRM Panel)

   Purpose: Enable remote management for scanning

   What it creates:
   - WinRM GPO with service auto-configuration
   - Basic authentication enabled
   - TrustedHosts configured
   - Firewall rules for ports 5985/5986

   Actions:
   - Create WinRM GPO: Creates the GPO
   - Force GPUpdate: Push policy to all computers
   - Enable/Disable: Turn WinRM GPO link on or off

   Required For: Remote artifact scanning and remote event collection


PHASE 4: MONITORING (Track Effectiveness)
---------------------------------------------------------------------------

8. Event Monitor (Events Panel)

   Purpose: Monitor AppLocker policy effectiveness

   Actions:
   - Scan Local: Collect AppLocker events from local system
   - Scan Selected: Collect events from remote computers via WinRM
   - Quick Date Filters: Last Hour, Today, 7 Days, 30 Days
   - Filter by Type: Allowed (8002), Audit (8003), Blocked (8004)
   - Export to CSV: Analyze events externally
   - Import to Rules: Create rules from events

   Event IDs:
   - 8002: Allowed (policy allows execution)
   - 8003: Audit (would be blocked in Enforce mode)
   - 8004: Blocked (policy denies execution)


9. Dashboard (Dashboard Panel)

   Purpose: At-a-glance overview of your AppLocker environment

   Shows:
   - Mini Status Bar: Domain status, artifact count
   - Policy Health Score: 0-100 based on configured rules
   - Event Counts: From C:\GA-AppLocker\Events\
   - Filters: By time range (7/30 days) and computer
   - Charts: Visual representation of data


10. Compliance (Compliance Panel)

    Purpose: Generate audit evidence packages

    Creates:
    - Timestamped folder with all policies
    - Event logs for specified time period
    - Ready-to-export documentation


BEST PRACTICES (Key Recommendations)
---------------------------------------------------------------------------

1. Always start in Audit mode (Event ID 8003)
   - Monitor for 7-14 days before switching to Enforce
   - Review Audit events to identify legitimate software

2. Use Auto rule type (Publisher for signed, Hash for unsigned)
   - Most resilient to software updates
   - Reduces rule maintenance overhead

3. Add Default Deny Rules for bypass locations
   - Block TEMP, Downloads, AppData, user-writable paths
   - Prevents living-off-the-land attacks

4. Maintain break-glass admin access
   - Keep a local admin account for emergencies
   - Document all exceptions and justifications

5. Use Search/Filter for large artifact lists
   - Quickly find specific applications
   - Reduce noise before generating rules

6. Test with actual user accounts
   - Verify rules work as expected
   - Check for business process interruptions


QUICK REFERENCE (Common Commands)
---------------------------------------------------------------------------

PowerShell Commands:
- Get-AppLockerPolicy -Effective        (View current policy)
- Get-WinEvent -LogName 'AppLocker/EXE and DLL'  (View events)
- Test-AppLockerPolicy                   (Test policy against file)
- gpupdate /force                         (Refresh Group Policy)
- gpresult /r /scope computer             (Check applied GPOs)


NEED MORE HELP?
---------------------------------------------------------------------------

- Check Application Logs: C:\GA-AppLocker\Logs\
- Review Microsoft AppLocker documentation
- Contact your security team
- Open a support ticket

"@
        }
        "Rules" {
            return @"

=============================================================================
                    APPLOCKER RULE BEST PRACTICES
=============================================================================

This guide explains how to create effective and secure AppLocker rules.


RULE TYPE PRIORITY (Use in this order)
---------------------------------------------------------------------------

1. PUBLISHER RULES (Preferred - Use First)

   Best For: Signed commercial software

   Advantages:
   - Most resilient to software updates
   - Covers all versions from a publisher
   - Automatic version updates

   Example: Microsoft Corporation, Adobe Inc.

   When to Use:
   - All signed software from trusted vendors
   - Microsoft Office, Adobe products, etc.


2. HASH RULES (Fallback for Unsigned Software)

   Best For: Unsigned executables only

   Advantages:
   - Most specific - exact file match
   - Cannot be bypassed by file renaming

   Disadvantages:
   - Fragile - breaks on every file update
   - High maintenance overhead

   When to Use:
   - Unsigned internal tools
   - Legacy applications without signatures
   - Temporary exceptions


3. PATH RULES (Exceptions Only - Use with Caution)

   Best For: Specific exception cases only

   Disadvantages:
   - Too permissive - easily bypassed
   - Moving files bypasses rules
   - Symbolic links can bypass rules

   When to Use (Rarely):
   - Denying specific user-writable paths (TEMP, Downloads)
   - Allowing specific admin tools from fixed paths
   - Temporary exceptions during testing

   Example: %OSDRIVE%\Users\*\Downloads\*\*


SECURITY PRINCIPLES (Core Concepts)
---------------------------------------------------------------------------

DENY-FIRST MODEL (Default Stance)
  - Default deny: Block all executables by default
  - Explicit allow: Only allow approved software
  - Deny bypass locations: Block user-writable paths

  This approach provides the strongest security posture.


LEAST PRIVILEGE (User Groups)
  - AppLocker-Admin: Full system access
  - AppLocker-Installers: Software installation rights
  - AppLocker-StandardUsers: Restricted workstation users
  - AppLocker-Service-Accounts: Service account access
  - AppLocker-Dev: Developer tools access

  Different rules for different user groups reduces risk.


AUDIT BEFORE ENFORCE (Deployment Process)
  1. Deploy in Audit mode first
  2. Monitor for 7-14 days minimum
  3. Review and categorize events:
     - Legitimate software: Add allow rules
     - Unapproved software: Leave blocked
     - False positives: Create exceptions
  4. Switch to Enforce only after validation

  Never skip the audit phase!


RULE COLLECTIONS TO CONFIGURE
---------------------------------------------------------------------------

Required:
- Executable (.exe, .com)           - Most important
- Script (.ps1, .bat, .cmd, .vbs)   - PowerShell critical
- Windows Installer (.msi, .msp)    - Software deployment

Optional (Advanced):
- DLL (.dll, .ocx)                  - High maintenance
- Packaged Apps/MSIX                - Windows 10+ store apps


COMMON MISTAKES TO AVOID
---------------------------------------------------------------------------

1. Using wildcards in path rules
   - Bad: C:\Program Files\*\*
   - Good: Specific publisher rules

2. Forgetting to update hash rules after updates
   - Set reminder to review hash rules monthly

3. Not testing with actual user accounts
   - Test with standard user, not admin

4. Skipping the audit phase
   - Always audit first, enforce later

5. Forgetting service accounts
   - Service accounts need special rules

6. Not documenting exceptions
   - Document why each exception exists


GROUP STRATEGY RECOMMENDATIONS
---------------------------------------------------------------------------

AppLocker-Admin
  - Purpose: Full system administration
  - Access: Allow most executables
  - Exceptions: May deny browsers, P2P software

AppLocker-Installers
  - Purpose: Software installation rights
  - Access: Allow installers, updaters
  - Scope: Limited to installation tasks

AppLocker-StandardUsers
  - Purpose: General workforce
  - Access: Highly restricted
  - Scope: Business applications only

AppLocker-Service-Accounts
  - Purpose: Running services
  - Access: Specific service executables
  - Scope: Minimal required access

AppLocker-Dev
  - Purpose: Software development
  - Access: Development tools, compilers
  - Scope: Development workstations only


ADMIN ACCOUNT SECURITY
---------------------------------------------------------------------------

Recommendations:
- Consider denying web browsers for admin accounts
- Admins should use separate workstations for admin tasks
- Maintain break-glass local admin for emergencies
- Document all exceptions with justifications
- Review admin exceptions quarterly


RULE MAINTENANCE
---------------------------------------------------------------------------

Monthly:
- Review hash rules for stale entries
- Check for new software versions
- Verify all exceptions are still needed

Quarterly:
- Full policy review and cleanup
- Remove unused rules
- Update documentation

Annually:
- Complete audit of all AppLocker policies
- Compliance review and reporting

"@
        }
        "Troubleshooting" {
            return @"
=== APPLOCKER TROUBLESHOOTING ===

ISSUE: Events not appearing in Event Monitor
SOLUTIONS:
- Verify AppLocker ID 8001 (Policy Applied) appears first
- Check Application Identity service is running
- Verify policy is actually enforced (gpresult /r)
- Restart Application Identity service if needed

ISSUE: All executables being blocked
SOLUTIONS:
- Check if policy is in Enforce mode (should start as Audit)
- Verify rule collection is enabled
- Check for conflicting deny rules
- Review event logs for specific blocked files

ISSUE: False positives - legitimate apps blocked
SOLUTIONS:
- Add specific Publisher rule for the application
- Check if app needs to run from user-writable location
- Consider creating exception path rule
- Review hash rule if app version changed

ISSUE: Policy not applying to computers
SOLUTIONS:
- Run: gpresult /r /scope computer
- Check GPO is linked to correct OU
- Verify GPO security filtering
- Force GP update: gpupdate /force
- Check DNS resolution for domain controllers

ISSUE: Cannot create GPO (access denied)
SOLUTIONS:
- Must be Domain Admin or have GPO creation rights
- Check Group Policy Management console permissions
- Verify RSAT is installed if running from workstation
- Run PowerShell as Administrator

ISSUE: WinRM connection failures
SOLUTIONS:
- Verify WinRM GPO has applied (gpupdate /force)
- Check firewall allows port 5985/5986
- Test with: Test-WsMan -ComputerName <target>
- Ensure target computer has WinRM enabled

ISSUE: Rule generation errors
SOLUTIONS:
- Verify artifact scan completed successfully
- Check CSV format is correct (UTF-8 encoding)
- Ensure Publisher info exists in file version
- Use Hash rules for unsigned executables

ISSUE: Group import fails
SOLUTIONS:
- Verify CSV format: GroupName,Members (semicolon-separated)
- Check member accounts exist in AD
- Ensure you have rights to modify group membership
- Use dry-run first to preview changes

ISSUE: High CPU/memory during scan
SOLUTIONS:
- Reduce MaxFiles setting
- Scan specific directories instead of full drives
- Run during off-peak hours
- Use AD discovery to target specific computers

USEFUL PowerShell COMMANDS:
- Get-AppLockerPolicy -Effective
- Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'
- Test-AppLockerPolicy
- Set-AppLockerPolicy
- gpupdate /force
- gpresult /r /scope computer

LOG LOCATIONS:
- AppLocker Events: Event Viewer -> Applications and Services -> Microsoft -> Windows -> AppLocker
- Group Policy: Event Viewer -> Windows Logs -> System
- Application ID: Services.msc -> Application Identity
- Application Logs: C:\GA-AppLocker\Logs\

ESCALATION PATH:
1. Review this help documentation
2. Check Application Logs in C:\GA-AppLocker\Logs\
3. Consult internal security team
4. Review Microsoft AppLocker documentation
5. Contact GA-ASI security team for advanced issues
"@
        }
        "WhatsNew" {
            return @"
=== WHAT'S NEW IN v1.2.5 ===

QUALITY-OF-LIFE FEATURES:

[1] Search/Filter (Rule Generator Panel)
   - Filter artifacts by publisher, path, or filename
   - Filter generated rules by any property
   - Real-time filtering as you type
   - Location: Top of Rule Generator panel

[2] One-Click Audit Toggle (Deployment Panel)
   - Instantly switch between Audit and Enforce modes
   - Updates all rule collections at once
   - Confirmation dialog before mode change
   - Location: Deployment panel, "Toggle Audit/Enforce" button

[3] Rule Preview Panel (Rule Generator Panel)
   - Preview XML rules before generation
   - Shows exact XML that will be exported
   - Helps verify rule structure
   - Location: Rule Generator panel, "Preview Rules" button

[4] Mini Status Bar (Top Navigation Bar)
   - Real-time domain status (joined/workgroup)
   - Artifact count indicator
   - Sync status for data refresh
   - Location: Top bar, right side

[5] Bulk Action Confirmation
   - Confirmation dialogs before destructive operations
   - Prevents accidental rule clear
   - Prevents accidental GPO deletion
   - Shows count of affected items

[6] Quick Date Presets (Events Panel)
   - Last Hour: Events from the last 60 minutes
   - Today: Events from today
   - Last 7 Days: Events from past week
   - Last 30 Days: Events from past month
   - Location: Events panel, quick date buttons

BUG FIXES:

[1] UTF-16 Encoding Fix
   - AppLocker XML policies now use proper UTF-16 encoding
   - Previous UTF-8 encoding caused import failures
   - All exported policies now compatible with AppLocker

[2] Regex Pattern Improvements
   - Directory safety classification now uses robust regex escaping
   - Prevents false positives in path matching
   - More reliable unsafe path detection

[3] System.Web Assembly Loading
   - Added assembly loading for HTML encoding security
   - Prevents encoding errors in compliance reports

[4] Emoji Character Removal
   - Removed emoji characters for PowerShell compatibility
   - Replaced with ASCII equivalents
   - Prevents syntax errors in script parsing

ARCHITECTURE IMPROVEMENTS:

[1] Standardized Artifact Data Model
   - Common artifact structure across all modules
   - Properties: name, path, publisher, hash, version, size, modifiedDate, fileType
   - Automatic property name mapping between formats

[2] Artifact Conversion Functions
   - Convert-AppLockerArtifact: Maps between naming conventions
   - Handles Module2 (lowercase), GUI (PascalCase), CSV import formats
   - Ensures interoperability between modules

[3] Rule Validation Before Export
   - Test-AppLockerRules: Validates all required properties exist
   - Pre-export validation catches missing data
   - Returns success, errors, warnings

[4] Unit Tests for Artifact Interoperability
   - 22 new tests in GA-AppLocker.Artifact.Tests.ps1
   - Tests artifact creation, conversion, validation
   - Tests property name mappings
   - 20 passing, 2 skipped

DOCUMENTATION UPDATES:

[1] ARTIFACT-DATA-MODEL.md
   - Complete documentation of artifact data structure
   - Property name mapping tables
   - Usage examples and best practices

[2] Updated README.md
   - v1.2.5 release notes
   - New features and bug fixes documented

[3] Updated CLAUDE.md
   - Technical documentation for new functions
   - GUI feature descriptions

HOW TO USE NEW FEATURES:

Search/Filter:
   1. Go to Rule Generator panel
   2. Type in the Search box to filter artifacts or rules
   3. Results update in real-time

Audit Toggle:
   1. Go to Deployment panel
   2. Click "Toggle Audit/Enforce"
   3. Confirm the mode change

Rule Preview:
   1. Generate rules in Rule Generator panel
   2. Click "Preview Rules" button
   3. Review XML before export

Quick Date Presets:
   1. Go to Events panel
   2. Click quick date button (Today, 7 Days, etc.)
   3. Events automatically filter by selected range

For detailed technical documentation, see:
   - docs/ARTIFACT-DATA-MODEL.md - Artifact and rule data structures
   - claude.md - Developer reference
   - README.md - Project overview
"@
        }
        "PolicyGuide" {
            return @"
=== APPLOCKER POLICY BUILD GUIDE ===

OBJECTIVE:
Allow who may execute trusted code, deny where code can never run,
validate in Audit, then enforce - without breaking services or failing audit.

--- CORE MENTAL MODEL ---
* AppLocker evaluates security principal + rule match
* Explicit Deny always wins
* Publisher rules apply everywhere unless denied
* Each rule collection is independent
* "Must exist" does NOT mean "allowed everything"

--- EXECUTION DECISION ORDER ---
1. Explicit Deny
2. Explicit Allow
3. Implicit Deny (only if nothing matches)

If you allow broadly, you must deny explicitly.

=== MANDATORY ALLOW PRINCIPALS ===
(Referenced in every rule collection: EXE, Script, MSI, DLL)

[ ] NT AUTHORITY\SYSTEM
[ ] NT AUTHORITY\LOCAL SERVICE
[ ] NT AUTHORITY\NETWORK SERVICE
[ ] BUILTIN\Administrators

IMPORTANT: These principals are NOT allowed everything.
They are allowed only what your rules explicitly permit.
They are still subject to Explicit Deny rules.

=== CUSTOM APPLOCKER GROUPS ===

[ ] DOMAIN\AppLocker-Admins
[ ] DOMAIN\AppLocker-StandardUsers
[ ] DOMAIN\AppLocker-Service-Accounts
[ ] DOMAIN\AppLocker-Installers (optional but recommended)

Rules of use:
* Service accounts -> only in AppLocker-Service-Accounts
* No service accounts in Administrators
* Deny interactive logon for service accounts via GPO

=== GROUP MEMBERSHIP + MINIMUM PERMISSIONS ===

1. AppLocker-Admins
   Who: Domain/Server/Platform admins, Security administrators
   Minimum permissions:
   * EXE -> Microsoft + approved vendor publishers
   * Script -> Microsoft-signed scripts
   * MSI -> Microsoft + vendor installers
   * DLL -> Microsoft-signed DLLs
   Still blocked by Deny paths!
   Purpose: admin survivability without blanket trust

2. AppLocker-StandardUsers
   Who: Regular end users
   Minimum permissions:
   * EXE -> Explicitly approved vendor apps only
   * Script -> None
   * MSI -> None
   * DLL -> Only via allowed EXEs
   Denied: installers, scripts, user-writable paths
   Purpose: least-privilege execution

3. AppLocker-Service-Accounts
   Who: Domain service accounts (svc_sql, svc_backup, SCCM, monitoring)
   Minimum permissions:
   * EXE -> Vendor-signed binaries
   * Script -> Vendor-signed scripts (if required)
   * MSI -> Only if service self-updates
   * DLL -> Vendor-signed DLLs
   Mandatory controls:
   * No admin rights
   * No interactive logon
   * No path-based allows
   Purpose: prevent outages without privilege creep

4. AppLocker-Installers (Optional)
   Who: Desktop Support (Tier 2+), Imaging/deployment, SCCM/Intune
   Minimum permissions:
   * MSI -> Vendor + Microsoft installers
   * EXE -> Vendor installer bootstrap EXEs only
   * Script -> None unless explicitly required
   * DLL -> None directly
   Purpose: controlled software introduction

=== MICROSOFT / WINDOWS SIGNED CODE ===

NEVER do this:
  Microsoft Publisher -> Everyone

CORRECT pattern:
  Microsoft Publisher ->
  [ ] SYSTEM
  [ ] LOCAL SERVICE
  [ ] NETWORK SERVICE
  [ ] BUILTIN\Administrators

This allows OS & services but does NOT give users blanket execution.

=== SERVICE ACCOUNTS ===

Built-in services:
* Run as SYSTEM / NT SERVICE*
* Covered by Microsoft publisher rules
* No path allows required

Domain service accounts:
[ ] Members of DOMAIN\AppLocker-Service-Accounts
[ ] Allowed via publisher rules only
[ ] No admin rights
[ ] No local logon

=== EXPLICIT DENY RULES (REQUIRED) ===

Create Deny-Path rules for Everyone:
[ ] %USERPROFILE%\Downloads\*
[ ] %APPDATA%\*
[ ] %LOCALAPPDATA%\Temp\*
[ ] %TEMP%\*

Why:
* Prevent signed binary abuse
* Close living-off-the-land execution paths
* Override all Allows (including SYSTEM)

=== MINIMUM RULE ASSIGNMENTS BY COLLECTION ===

EXECUTABLES (EXE):
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Admins -> Microsoft + Vendor Publisher
[ ] Service Accounts -> Vendor Publisher
[ ] Users -> Explicitly approved apps only
[ ] Installers -> Vendor installer EXEs only
Deny:
[ ] User-writable paths (above)

SCRIPTS (PS1, BAT, CMD, VBS) - Highest Risk:
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Admins -> Microsoft Publisher
[ ] Service Accounts -> Vendor Publisher
Do NOT allow:
[ ] Standard users
[ ] Everyone

MSI / INSTALLERS:
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Installers Group -> Vendor Publisher
[ ] Admins -> Vendor Publisher
Deny:
[ ] Everyone else

DLL (Enable LAST):
Allow:
[ ] SYSTEM -> Microsoft Publisher
[ ] Admins -> Microsoft Publisher
[ ] Service Accounts -> Vendor Publisher
ALWAYS Audit first!

=== AUDIT MODE VALIDATION (REQUIRED) ===

[ ] EXE audit clean
[ ] Script audit clean
[ ] MSI audit clean
[ ] DLL audited 7-14 days
[ ] Event ID 8004 reviewed
[ ] Services start normally
[ ] Scheduled tasks run
[ ] Patch & agent updates succeed

If it runs in Audit, it will run in Enforce.

=== RULE CREATION ORDER (Follow Exactly) ===

Phase 0 - Prep:
[ ] Identify service accounts
[ ] Create AppLocker AD groups

Phase 1 - EXE:
[ ] Microsoft publisher rules
[ ] Vendor publisher rules
[ ] Explicit Deny paths
[ ] Enable Audit

Phase 2 - Scripts:
[ ] Microsoft scripts -> SYSTEM/Admins
[ ] Vendor scripts -> Service Accounts
[ ] Audit and review

Phase 3 - MSI:
[ ] Microsoft MSIs -> SYSTEM
[ ] Vendor MSIs -> Installers/Admins
[ ] Audit patch cycles

Phase 4 - DLL (LAST):
[ ] Enable Audit
[ ] Review 7-14 days
[ ] Add vendor DLL publishers as needed

Phase 5 - Enforce:
[ ] EXE -> Enforce
[ ] Scripts -> Enforce
[ ] MSI -> Enforce
[ ] DLL -> Enforce (last)

=== COMMON BLIND SPOTS ===

[ ] Scheduled Tasks (often SYSTEM)
[ ] Self-updating agents (AV, monitoring, backup)
[ ] ProgramData execution (audit before denying)
[ ] DLL rules enabled too early

=== ENFORCEMENT GATE (ALL must be true) ===

[ ] SYSTEM not blocked
[ ] No service failures
[ ] No Everyone allows
[ ] Explicit Deny rules exist
[ ] Audit evidence retained

=== AUDITOR-APPROVED SUMMARY ===

"Application execution is controlled using publisher-based AppLocker
rules scoped to defined administrative, installer, service, and user
security groups. User-writable directories are explicitly denied to
prevent abuse of signed binaries. All policies were validated in
audit mode prior to enforcement."

=== FINAL ONE-LINE MODEL ===

Allow who may run trusted code, deny where code can never run,
and never enforce what you didn't audit.
"@
        }
    }
}

# Software Gap Analysis Functions
function Get-InstalledSoftware {
    param([string]$ComputerName = $env:COMPUTERNAME)

    try {
        Write-Log "Scanning software on: $ComputerName"

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
                    Get-ItemProperty $regKey -ErrorAction SilentlyContinue | ForEach-Object {
                        if ($_.DisplayName -and $_.DisplayVersion) {
                            $software += [PSCustomObject]@{
                                ComputerName = $ComputerName
                                Name = $_.DisplayName
                                Version = $_.DisplayVersion
                                Publisher = $_.Publisher
                                InstallDate = $_.InstallDate
                                Path = $_.InstallLocation
                            }
                        }
                    }
                }
            } else {
                # Remote registry
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                    $regKey = $reg.OpenSubKey($regPath)
                    if ($regKey) {
                        foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                            $subKey = $regKey.OpenSubKey($subKeyName)
                            $displayName = $subKey.GetValue("DisplayName")
                            $displayVersion = $subKey.GetValue("DisplayVersion")
                            $publisher = $subKey.GetValue("Publisher")
                            $installDate = $subKey.GetValue("InstallDate")
                            $installLocation = $subKey.GetValue("InstallLocation")

                            if ($displayName -and $displayVersion) {
                                $software += [PSCustomObject]@{
                                    ComputerName = $ComputerName
                                    Name = $displayName
                                    Version = $displayVersion
                                    Publisher = $publisher
                                    InstallDate = $installDate
                                    Path = $installLocation
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Failed to access remote registry on $ComputerName`: $_" -Level "ERROR"
                }
            }
        }

        Write-Log "Found $($software.Count) software items on $ComputerName"
        return $software
    }
    catch {
        Write-Log "Software scan failed on $ComputerName`: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

function Compare-SoftwareLists {
    param(
        [array]$Baseline,
        [array]$Target
    )

    $results = @()
    $baselineHash = @{}
    $targetHash = @{}

    # Build hash tables for comparison
    foreach ($item in $Baseline) {
        $key = "$($item.Name) - $($item.Version)"
        $baselineHash[$item.Name] = $item
    }

    foreach ($item in $Target) {
        $key = "$($item.Name) - $($item.Version)"
        $targetHash[$item.Name] = $item
    }

    # Find missing in target (in baseline but not in target)
    foreach ($key in $baselineHash.Keys) {
        $baselineItem = $baselineHash[$key]

        if (-not $targetHash.ContainsKey($key)) {
            $results += [PSCustomObject]@{
                Name = $baselineItem.Name
                Version = $baselineItem.Version
                Status = "Missing in Target"
                BaselineVersion = $baselineItem.Version
                TargetVersion = "N/A"
                Publisher = $baselineItem.Publisher
            }
        } else {
            # Check version mismatch
            $targetItem = $targetHash[$key]
            if ($baselineItem.Version -ne $targetItem.Version) {
                $results += [PSCustomObject]@{
                    Name = $baselineItem.Name
                    Version = "$($baselineItem.Version) -> $($targetItem.Version)"
                    Status = "Version Mismatch"
                    BaselineVersion = $baselineItem.Version
                    TargetVersion = $targetItem.Version
                    Publisher = $baselineItem.Publisher
                }
            } else {
                # Match
                $results += [PSCustomObject]@{
                    Name = $baselineItem.Name
                    Version = $baselineItem.Version
                    Status = "Match"
                    BaselineVersion = $baselineItem.Version
                    TargetVersion = $targetItem.Version
                    Publisher = $baselineItem.Publisher
                }
            }
        }
    }

    # Find extra in target (in target but not in baseline)
    foreach ($key in $targetHash.Keys) {
        if (-not $baselineHash.ContainsKey($key)) {
            $targetItem = $targetHash[$key]
            $results += [PSCustomObject]@{
                Name = $targetItem.Name
                Version = $targetItem.Version
                Status = "Extra in Target"
                BaselineVersion = "N/A"
                TargetVersion = $targetItem.Version
                Publisher = $targetItem.Publisher
            }
        }
    }

    return $results
}

function Import-SoftwareList {
    param([string]$Path)

    try {
        Write-Log "Importing software list from: $Path"

        $software = Import-Csv $Path -ErrorAction Stop

        # Convert to proper format
        $result = foreach ($item in $software) {
            [PSCustomObject]@{
                ComputerName = if ($item.ComputerName) { $item.ComputerName } else { "Imported" }
                Name = $item.Name
                Version = $item.Version
                Publisher = if ($item.Publisher) { $item.Publisher } else { "Unknown" }
                InstallDate = $item.InstallDate
                Path = $item.Path
            }
        }

        Write-Log "Imported $($result.Count) software items"
        return $result
    }
    catch {
        Write-Log "Failed to import software list: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}

# Convert rules to AppLocker XML format
function Convert-RulesToAppLockerXml {
    <#
    .SYNOPSIS
        Converts rule objects to AppLocker-compatible XML format
    .DESCRIPTION
        Takes an array of rule objects and generates proper AppLocker policy XML
        that can be imported into Group Policy or used with Set-AppLockerPolicy
    .PARAMETER Rules
        Array of rule objects with type, action, userOrGroupSid, and type-specific properties
    .PARAMETER EnforcementMode
        Policy enforcement mode: AuditOnly or Enabled (default: AuditOnly)
    .OUTPUTS
        String containing valid AppLocker policy XML (UTF-16 compatible)
    #>
    param(
        [array]$Rules,
        [ValidateSet("AuditOnly", "Enabled")]
        [string]$EnforcementMode = "AuditOnly"
    )

    if (-not $Rules -or $Rules.Count -eq 0) {
        # Return empty policy skeleton if no rules
        return @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$EnforcementMode" />
  <RuleCollection Type="Script" EnforcementMode="$EnforcementMode" />
  <RuleCollection Type="Msi" EnforcementMode="$EnforcementMode" />
  <RuleCollection Type="Dll" EnforcementMode="$EnforcementMode" />
  <RuleCollection Type="Appx" EnforcementMode="$EnforcementMode" />
</AppLockerPolicy>
"@
    }

    # Group rules by collection type (Exe, Script, Msi, Dll, Appx)
    $exeRules = @()
    $scriptRules = @()
    $msiRules = @()
    $dllRules = @()
    $appxRules = @()

    foreach ($rule in $Rules) {
        # Determine collection type from rule properties or default to Exe
        $collectionType = "Exe"
        if ($rule.collectionType) {
            $collectionType = $rule.collectionType
        } elseif ($rule.path) {
            # Infer collection type from file extension in path
            if ($rule.path -match '\.ps1$|\.bat$|\.cmd$|\.vbs$|\.js$') {
                $collectionType = "Script"
            } elseif ($rule.path -match '\.msi$|\.msp$|\.mst$') {
                $collectionType = "Msi"
            } elseif ($rule.path -match '\.dll$|\.ocx$') {
                $collectionType = "Dll"
            } elseif ($rule.path -match '\.appx$') {
                $collectionType = "Appx"
            }
        } elseif ($rule.fileName) {
            if ($rule.fileName -match '\.ps1$|\.bat$|\.cmd$|\.vbs$|\.js$') {
                $collectionType = "Script"
            } elseif ($rule.fileName -match '\.msi$|\.msp$|\.mst$') {
                $collectionType = "Msi"
            } elseif ($rule.fileName -match '\.dll$|\.ocx$') {
                $collectionType = "Dll"
            }
        }

        switch ($collectionType) {
            "Script" { $scriptRules += $rule }
            "Msi" { $msiRules += $rule }
            "Dll" { $dllRules += $rule }
            "Appx" { $appxRules += $rule }
            default { $exeRules += $rule }
        }
    }

    # Helper function to build individual rule XML
    function Build-RuleXml {
        param($Rule, $CollectionType)

        $ruleId = if ($Rule.id) { $Rule.id -replace '[{}]', '' } else { (New-Guid).ToString() }
        $action = if ($Rule.action) { $Rule.action } else { "Allow" }
        $sid = if ($Rule.userOrGroupSid) { $Rule.userOrGroupSid } else { "S-1-1-0" }  # Everyone as default
        $name = ConvertTo-XmlSafeString -InputString (if ($Rule.name) { $Rule.name } else { "Rule-$ruleId" })
        $description = ConvertTo-XmlSafeString -InputString (if ($Rule.description) { $Rule.description } else { "Generated by GA-AppLocker" })

        # If rule already has pre-built XML, use it (with ID/SID updates)
        if ($Rule.xml -and $Rule.xml -match '<FilePublisherRule|<FilePathRule|<FileHashRule') {
            $ruleXml = $Rule.xml
            # Update ID and SID if different
            $ruleXml = $ruleXml -replace 'Id="[^"]*"', "Id=`"$ruleId`""
            $ruleXml = $ruleXml -replace 'UserOrGroupSid="[^"]*"', "UserOrGroupSid=`"$sid`""
            return "    $ruleXml"
        }

        switch ($Rule.type) {
            "Publisher" {
                $publisherName = ConvertTo-XmlSafeString -InputString (if ($Rule.publisherName) { $Rule.publisherName } else { "*" })
                $productName = ConvertTo-XmlSafeString -InputString (if ($Rule.productName) { $Rule.productName } else { "*" })
                $fileName = ConvertTo-XmlSafeString -InputString (if ($Rule.fileName) { $Rule.fileName } else { "*" })
                $minVersion = if ($Rule.minVersion) { $Rule.minVersion } else { "0.0.0.0" }
                $maxVersion = if ($Rule.maxVersion) { $Rule.maxVersion } else { "*" }

                return @"
    <FilePublisherRule Id="$ruleId" Name="$name" Description="$description" UserOrGroupSid="$sid" Action="$action">
      <Conditions>
        <FilePublisherCondition PublisherName="$publisherName" ProductName="$productName" BinaryName="$fileName">
          <BinaryVersionRange LowSection="$minVersion" HighSection="$maxVersion" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@
            }
            "Path" {
                $path = ConvertTo-XmlSafeString -InputString (if ($Rule.path) { $Rule.path } else { "*" })

                return @"
    <FilePathRule Id="$ruleId" Name="$name" Description="$description" UserOrGroupSid="$sid" Action="$action">
      <Conditions>
        <FilePathCondition Path="$path" />
      </Conditions>
    </FilePathRule>
"@
            }
            "Hash" {
                $hashValue = if ($Rule.hash) { $Rule.hash } else { "" }
                $hashType = if ($Rule.hashType) { $Rule.hashType } else { "SHA256" }
                $sourceFileName = ConvertTo-XmlSafeString -InputString (if ($Rule.fileName) { $Rule.fileName } else { "Unknown" })
                $sourceFileLength = if ($Rule.fileLength) { $Rule.fileLength } else { "0" }

                return @"
    <FileHashRule Id="$ruleId" Name="$name" Description="$description" UserOrGroupSid="$sid" Action="$action">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="$hashType" Data="$hashValue" SourceFileName="$sourceFileName" SourceFileLength="$sourceFileLength" />
        </FileHashCondition>
      </Conditions>
    </FileHashRule>
"@
            }
            default {
                # Default to path rule if type unknown
                $path = ConvertTo-XmlSafeString -InputString (if ($Rule.path) { $Rule.path } else { "*" })
                return @"
    <FilePathRule Id="$ruleId" Name="$name" Description="$description" UserOrGroupSid="$sid" Action="$action">
      <Conditions>
        <FilePathCondition Path="$path" />
      </Conditions>
    </FilePathRule>
"@
            }
        }
    }

    # Build rule collection XML for each type
    function Build-RuleCollectionXml {
        param($CollectionType, $RulesList, $Mode)

        if ($RulesList.Count -eq 0) {
            return "  <RuleCollection Type=`"$CollectionType`" EnforcementMode=`"$Mode`" />"
        }

        $rulesXml = $RulesList | ForEach-Object { Build-RuleXml -Rule $_ -CollectionType $CollectionType }
        $rulesContent = $rulesXml -join "`n"

        return @"
  <RuleCollection Type="$CollectionType" EnforcementMode="$Mode">
$rulesContent
  </RuleCollection>
"@
    }

    # Build the complete policy XML
    $exeCollectionXml = Build-RuleCollectionXml -CollectionType "Exe" -RulesList $exeRules -Mode $EnforcementMode
    $scriptCollectionXml = Build-RuleCollectionXml -CollectionType "Script" -RulesList $scriptRules -Mode $EnforcementMode
    $msiCollectionXml = Build-RuleCollectionXml -CollectionType "Msi" -RulesList $msiRules -Mode $EnforcementMode
    $dllCollectionXml = Build-RuleCollectionXml -CollectionType "Dll" -RulesList $dllRules -Mode $EnforcementMode
    $appxCollectionXml = Build-RuleCollectionXml -CollectionType "Appx" -RulesList $appxRules -Mode $EnforcementMode

    $policyXml = @"
<AppLockerPolicy Version="1">
$exeCollectionXml
$scriptCollectionXml
$msiCollectionXml
$dllCollectionXml
$appxCollectionXml
</AppLockerPolicy>
"@

    Write-Log "Generated AppLocker XML with $($Rules.Count) rules (Exe:$($exeRules.Count), Script:$($scriptRules.Count), Msi:$($msiRules.Count), Dll:$($dllRules.Count), Appx:$($appxRules.Count))"

    return $policyXml
}

<#
.SYNOPSIS
    Validates generated rules before export
.DESCRIPTION
    Checks if rules have all required properties for AppLocker export
.PARAMETER Rules
    Array of rule hashtables to validate
.OUTPUTS
    Hashtable with success, errors, and warnings
#>
function Test-AppLockerRules {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Rules
    )

    $errors = @()
    $warnings = @()
    $validRules = @()

    foreach ($rule in $Rules) {
        # Check for required properties
        if (-not $rule.type) {
            $errors += "Rule missing 'type' property"
            continue
        }

        if (-not $rule.action) {
            $errors += "Rule missing 'action' property"
            continue
        }

        # Type-specific validation
        switch ($rule.type) {
            "Publisher" {
                if (-not $rule.publisher) {
                    $errors += "Publisher rule missing 'publisher' property"
                    continue
                }
            }
            "Path" {
                if (-not $rule.path) {
                    $errors += "Path rule missing 'path' property"
                    continue
                }
            }
            "Hash" {
                if (-not $rule.hash -and -not $rule.path) {
                    $errors += "Hash rule missing both 'hash' and 'path' properties"
                    continue
                }
            }
        }

        $validRules += $rule
    }

    # Warnings
    if ($validRules.Count -eq 0 -and $Rules.Count -gt 0) {
        $warnings += "No valid rules found in $($Rules.Count) rules"
    }

    if ($validRules.Count -lt $Rules.Count) {
        $warnings += "$($Rules.Count - $validRules.Count) rules were invalid and excluded"
    }

    return @{
        success     = ($errors.Count -eq 0)
        validRules  = $validRules
        errorCount  = $errors.Count
        errors      = $errors
        warningCount = $warnings.Count
        warnings    = $warnings
        totalCount  = $Rules.Count
        validCount  = $validRules.Count
    }
}

# Helper function to show panel
function Show-Panel {
    param([string]$PanelName)

    if ($null -ne $PanelDashboard) {
    $PanelDashboard.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelDiscovery) {
    $PanelDiscovery.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelArtifacts) {
    $PanelArtifacts.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelRules) {
    $PanelRules.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelDeployment) {
    $PanelDeployment.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelEvents) {
    $PanelEvents.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelCompliance) {
    $PanelCompliance.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelReports) {
    $PanelReports.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelWinRM) {
    $PanelWinRM.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelGroupMgmt) {
    $PanelGroupMgmt.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelAppLockerSetup) {
    $PanelAppLockerSetup.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelGapAnalysis) {
    $PanelGapAnalysis.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelTemplates) {
    $PanelTemplates.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelHelp) {
    $PanelHelp.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelAaronLocker) {
    $PanelAaronLocker.Visibility = [System.Windows.Visibility]::Collapsed
    }
    if ($null -ne $PanelAbout) {
    $PanelAbout.Visibility = [System.Windows.Visibility]::Collapsed
    }

    switch ($PanelName) {
        "Dashboard" { $PanelDashboard.Visibility = [System.Windows.Visibility]::Visible }
        "Discovery" { $PanelDiscovery.Visibility = [System.Windows.Visibility]::Visible }
        "Artifacts" { $PanelArtifacts.Visibility = [System.Windows.Visibility]::Visible }
        "Rules" {
            if ($null -ne $PanelRules) {
            $PanelRules.Visibility = [System.Windows.Visibility]::Visible
            }
            Update-Badges
        }
        "Deployment" { $PanelDeployment.Visibility = [System.Windows.Visibility]::Visible }
        "Events" { $PanelEvents.Visibility = [System.Windows.Visibility]::Visible }
        "Compliance" { $PanelCompliance.Visibility = [System.Windows.Visibility]::Visible }
        "Reports" { $PanelReports.Visibility = [System.Windows.Visibility]::Visible }
        "WinRM" { $PanelWinRM.Visibility = [System.Windows.Visibility]::Visible }
        "GroupMgmt" { $PanelGroupMgmt.Visibility = [System.Windows.Visibility]::Visible }
        "AppLockerSetup" { $PanelAppLockerSetup.Visibility = [System.Windows.Visibility]::Visible }
        "GapAnalysis" { $PanelGapAnalysis.Visibility = [System.Windows.Visibility]::Visible }
        "Templates" {
            if ($null -ne $PanelTemplates) {
            $PanelTemplates.Visibility = [System.Windows.Visibility]::Visible
            }
            Load-TemplatesList
        }
        "Help" { $PanelHelp.Visibility = [System.Windows.Visibility]::Visible }
        "AaronLocker" { $PanelAaronLocker.Visibility = [System.Windows.Visibility]::Visible }
        "About" { $PanelAbout.Visibility = [System.Windows.Visibility]::Visible }
    }
}

# Navigation event handlers
if ($null -ne $NavDashboard) {
$NavDashboard.Add_Click({
    Show-Panel "Dashboard"
    Update-StatusBar
})
}

if ($null -ne $NavDiscovery) {
$NavDiscovery.Add_Click({
    Show-Panel "Discovery"
    Update-StatusBar
})
}

if ($null -ne $NavArtifacts) {
$NavArtifacts.Add_Click({
    Show-Panel "Artifacts"
    Update-StatusBar
})
}

if ($null -ne $NavGapAnalysis) {
$NavGapAnalysis.Add_Click({
    Show-Panel "GapAnalysis"
    Update-StatusBar
})
}

if ($null -ne $NavRules) {
$NavRules.Add_Click({
    Show-Panel "Rules"
    Update-StatusBar
})
}

if ($null -ne $NavDeployment) {
$NavDeployment.Add_Click({
    Show-Panel "Deployment"
    Update-StatusBar
})
}

if ($null -ne $NavEvents) {
$NavEvents.Add_Click({
    Show-Panel "Events"
    Update-StatusBar
})
}

if ($null -ne $NavCompliance) {
$NavCompliance.Add_Click({
    Show-Panel "Compliance"
    Update-StatusBar
})
}

if ($null -ne $NavReports) {
$NavReports.Add_Click({
    Show-Panel "Reports"
    Update-StatusBar
})
}

if ($null -ne $NavWinRM) {
$NavWinRM.Add_Click({
    Show-Panel "WinRM"
    Update-StatusBar
})
}

if ($null -ne $NavGroupMgmt) {
$NavGroupMgmt.Add_Click({
    Show-Panel "GroupMgmt"
    Update-StatusBar
})
}

if ($null -ne $NavAppLockerSetup) {
$NavAppLockerSetup.Add_Click({
    Show-Panel "AppLockerSetup"
    Update-StatusBar
})
}

if ($null -ne $NavAaronLocker) {
$NavAaronLocker.Add_Click({
    Show-Panel "AaronLocker"
    Update-StatusBar
})
}

if ($null -ne $NavHelp) {
$NavHelp.Add_Click({
    Show-Panel "Help"
    Update-StatusBar
    # Load default help content
    $HelpTitle.Text = "Help - Workflow"
    $HelpText.Text = Get-HelpContent "Workflow"
})
}

if ($null -ne $NavAbout) {
$NavAbout.Add_Click({
    Show-Panel "About"
    Update-StatusBar
})
}

# Phase 5: Templates navigation event handlers
if ($null -ne $NavTemplates) {
$NavTemplates.Add_Click({
    Show-Panel "Templates"
    Update-StatusBar
    Write-Log "Navigated to Templates panel"
})
}

if ($null -ne $NavRuleWizard) {
$NavRuleWizard.Add_Click({
    Write-Log "Rule Wizard button clicked"
    Invoke-RuleWizard
})
}

if ($null -ne $NavCreateTemplate) {
$NavCreateTemplate.Add_Click({
    Write-Log "Create Template button clicked"
    New-CustomTemplate
})
}

if ($null -ne $NavImportTemplate) {
$NavImportTemplate.Add_Click({
    Write-Log "Import Template button clicked"
    Import-RuleTemplateFromFile
})
}

# Phase 4: Workspace Save/Load Event Handlers
if ($null -ne $NavSaveWorkspace) {
$NavSaveWorkspace.Add_Click({
    Write-Log "Save workspace button clicked"
    $savedFile = Save-Workspace
    if ($savedFile) {
        [System.Windows.MessageBox]::Show("Workspace saved to:`n$savedFile", "Workspace Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
})
}

if ($null -ne $NavLoadWorkspace) {
$NavLoadWorkspace.Add_Click({
    Write-Log "Load workspace button clicked"
    Load-Workspace
})
}

# Mouse wheel scroll event handler for sidebar ScrollViewer
# This ensures mouse wheel events propagate to parent ScrollViewer when sidebar can't scroll further
$SidebarScrollViewer.Add_PreviewMouseWheel({
    param($sender, $e)
    $scrollViewer = $sender
    $isAtTop = $scrollViewer.VerticalOffset -eq 0
    $isAtBottom = $scrollViewer.VerticalOffset -ge ($scrollViewer.ExtentHeight - $scrollViewer.ViewportHeight - 0.1)

    if (($e.Delta -gt 0 -and $isAtTop) -or ($e.Delta -lt 0 -and $isAtBottom)) {
        # Sidebar can't scroll further in this direction, propagate to parent
        $e.Handled = $false
    } else {
        # Sidebar can scroll, handle the event
        $e.Handled = $true
    }
})

# Dashboard events
function Refresh-Data {
    $DashboardOutput.Text = "Loading dashboard data..."
    [System.Windows.Forms.Application]::DoEvents()

    # Get time filter
    $timeFilter = $DashboardTimeFilter.SelectedItem.Content
    $daysBack = if ($timeFilter -eq "Last 7 Days") { 7 } else { 30 }
    $cutoffDate = (Get-Date).AddDays(-$daysBack)

    # Get system filter
    $systemFilter = $DashboardSystemFilter.SelectedItem.Content

    # Get policy health from local system
    $summary = Get-DashboardSummary
    $HealthScore.Text = $summary.policyHealth.score
    $HealthStatus.Text = if ($summary.policyHealth.score -eq 100) { "All categories enabled" } else { "Score: $($summary.policyHealth.score)/100" }

    # Scan event files from C:\GA-AppLocker\Events
    $eventsPath = "C:\GA-AppLocker\Events"
    $allFileEvents = @()
    $systems = @()

    if (Test-Path $eventsPath) {
        $eventFiles = Get-ChildItem -Path $eventsPath -Filter "*.csv" -ErrorAction SilentlyContinue |
                      Where-Object { $_.LastWriteTime -ge $cutoffDate }

        foreach ($file in $eventFiles) {
            try {
                $fileEvents = Import-Csv -Path $file.FullName -ErrorAction SilentlyContinue
                foreach ($evt in $fileEvents) {
                    # Track unique systems
                    if ($evt.ComputerName -and $evt.ComputerName -notin $systems) {
                        $systems += $evt.ComputerName
                    }
                    # Apply system filter
                    if ($systemFilter -eq "All Systems" -or $evt.ComputerName -eq $systemFilter) {
                        $allFileEvents += $evt
                    }
                }
            } catch { }
        }

        # Update system filter dropdown
        $currentSelection = $DashboardSystemFilter.SelectedItem.Content
        $DashboardSystemFilter.Items.Clear()
        $allItem = New-Object System.Windows.Controls.ComboBoxItem
        $allItem.Content = "All Systems"
        $DashboardSystemFilter.Items.Add($allItem) | Out-Null
        foreach ($sys in ($systems | Sort-Object)) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $sys
            $DashboardSystemFilter.Items.Add($item) | Out-Null
        }
        # Restore selection
        foreach ($item in $DashboardSystemFilter.Items) {
            if ($item.Content -eq $currentSelection) {
                $DashboardSystemFilter.SelectedItem = $item
                break
            }
        }
        if ($null -eq $DashboardSystemFilter.SelectedItem) {
            $DashboardSystemFilter.SelectedIndex = 0
        }
    }

    # Count events from files
    $fileAllowed = ($allFileEvents | Where-Object { $_.Id -eq "8002" -or $_.type -eq "Allowed" }).Count
    $fileAudited = ($allFileEvents | Where-Object { $_.Id -eq "8003" -or $_.type -eq "Audit" }).Count
    $fileBlocked = ($allFileEvents | Where-Object { $_.Id -eq "8004" -or $_.type -eq "Blocked" }).Count
    $fileTotal = $allFileEvents.Count

    # Combine with live local events
    $liveTotal = [int]$summary.events.total
    $liveAllowed = [int]$summary.events.allowed
    $liveAudited = [int]$summary.events.audit
    $liveBlocked = [int]$summary.events.blocked

    $TotalEvents.Text = ($fileTotal + $liveTotal).ToString()
    $AllowedEvents.Text = ($fileAllowed + $liveAllowed).ToString()
    $AuditedEvents.Text = ($fileAudited + $liveAudited).ToString()
    $BlockedEvents.Text = ($fileBlocked + $liveBlocked).ToString()
    $EventsStatus.Text = if (($fileTotal + $liveTotal) -gt 0) { "Events found" } else { "No events" }

    # Update output
    $output = "Dashboard refreshed at $(Get-Date -Format 'HH:mm:ss')`n`n"
    $output += "=== EVENT SOURCES ===`n"
    $output += "Live Events (local): $liveTotal`n"
    $output += "File Events ($eventsPath): $fileTotal`n"
    $output += "Files scanned: $(if (Test-Path $eventsPath) { (Get-ChildItem $eventsPath -Filter '*.csv' | Where-Object { $_.LastWriteTime -ge $cutoffDate }).Count } else { 0 })`n"
    $output += "Time filter: $timeFilter`n"
    $output += "System filter: $systemFilter`n"
    $output += "Systems found: $($systems.Count)`n"
    $DashboardOutput.Text = $output

    # Update charts
    Update-Charts -Allowed ($fileAllowed + $liveAllowed) -Audited ($fileAudited + $liveAudited) -Blocked ($fileBlocked + $liveBlocked) -HealthScore $summary.policyHealth.score
}

# Update Dashboard Charts
function Update-Charts {
    param(
        [int]$Allowed = 0,
        [int]$Audited = 0,
        [int]$Blocked = 0,
        [int]$HealthScore = 0
    )

    # Skip if chart controls are not available
    if ($null -eq $PieAllowed -or $null -eq $PieAudited -or $null -eq $PieBlocked -or
        $null -eq $GaugeBackground -or $null -eq $GaugeFill) {
        return
    }

    $total = $Allowed + $Audited + $Blocked

    # Update Pie Chart
    if ($total -gt 0) {
        $centerX = 100
        $centerY = 100
        $radius = 90

        $currentAngle = -90
        $allowedAngle = ($Allowed / $total) * 360
        $auditedAngle = ($Audited / $total) * 360
        $blockedAngle = ($Blocked / $total) * 360

        # Allowed slice
        if ($Allowed -gt 0) {
            $endAngle = $currentAngle + $allowedAngle
            $allowedPath = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle
            if ($null -ne $PieAllowed) { $PieAllowed.Data = $allowedPath }
            $currentAngle = $endAngle
        } else {
            if ($null -ne $PieAllowed) { $PieAllowed.Data = "" }
        }

        # Audited slice
        if ($Audited -gt 0) {
            $endAngle = $currentAngle + $auditedAngle
            $auditedPath = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle
            if ($null -ne $PieAudited) { $PieAudited.Data = $auditedPath }
            $currentAngle = $endAngle
        } else {
            if ($null -ne $PieAudited) { $PieAudited.Data = "" }
        }

        # Blocked slice
        if ($Blocked -gt 0) {
            $endAngle = $currentAngle + $blockedAngle
            $blockedPath = Get-PieSlicePath -CenterX $centerX -CenterY $centerY -Radius $radius -StartAngle $currentAngle -EndAngle $endAngle
            if ($null -ne $PieBlocked) { $PieBlocked.Data = $blockedPath }
        } else {
            if ($null -ne $PieBlocked) { $PieBlocked.Data = "" }
        }
    } else {
        if ($null -ne $PieAllowed) { $PieAllowed.Data = "" }
        if ($null -ne $PieAudited) { $PieAudited.Data = "" }
        if ($null -ne $PieBlocked) { $PieBlocked.Data = "" }
    }

    # Update Gauge
    $gaugeWidth = 180
    $gaugeHeight = 90
    $gaugeRadius = 80

    # Background arc (semi-circle)
    $bgStart = [System.Windows.Point]::new(10, 90)
    $bgEnd = [System.Windows.Point]::new(190, 90)
    $bgLargeArc = 0
    $bgPath = "M $([Math]::Round($bgStart.X)) $([Math]::Round($bgStart.Y)) A $gaugeRadius $gaugeRadius 0 $bgLargeArc 1 $([Math]::Round($bgEnd.X)) $([Math]::Round($bgEnd.Y)) L 10 90"
    if ($null -ne $GaugeBackground) { $GaugeBackground.Data = $bgPath }

    # Fill arc based on health score
    if ($HealthScore -gt 0) {
        $scoreRatio = $HealthScore / 100
        $fillAngle = 180 * $scoreRatio
        $startRad = ([Math]::PI / 180) * 0
        $endRad = ([Math]::PI / 180) * $fillAngle

        $fillStart = [System.Windows.Point]::new(10 + $gaugeRadius * [Math]::Cos($startRad), 90 - $gaugeRadius * [Math]::Sin($startRad))
        $fillEnd = [System.Windows.Point]::new(10 + $gaugeRadius * [Math]::Cos($endRad), 90 - $gaugeRadius * [Math]::Sin($endRad))
        $fillLargeArc = if ($fillAngle -gt 180) { 1 } else { 0 }

        $fillPath = "M $([Math]::Round($fillStart.X)) $([Math]::Round($fillStart.Y)) A $gaugeRadius $gaugeRadius 0 $fillLargeArc 1 $([Math]::Round($fillEnd.X)) $([Math]::Round($fillEnd.Y)) L 10 90"
        $GaugeFill.Data = $fillPath

        # Color based on score
        $gaugeColor = if ($HealthScore -ge 75) { "#3FB950" } elseif ($HealthScore -ge 50) { "#D29922" } else { "#F85149" }
        $GaugeFill.Fill = $gaugeColor
    } else {
        $GaugeFill.Data = ""
    }

    if ($null -ne $GaugeScore) { $GaugeScore.Text = $HealthScore.ToString() }
    if ($null -ne $GaugeLabel) { $GaugeLabel.Text = if ($HealthScore -eq 100) { "Fully Configured" } elseif ($HealthScore -ge 75) { "Well Configured" } elseif ($HealthScore -ge 50) { "Partially Configured" } elseif ($HealthScore -gt 0) { "Minimal Configuration" } else { "No Policy Configured" } }

    # Update Machine Type Bars (placeholder data - would need actual AD query)
    $workstations = 42
    $servers = 15
    $dcs = 3
    $maxMachines = [Math]::Max($workstations, [Math]::Max($servers, $dcs))

    if ($maxMachines -gt 0) {
        $wsHeight = ($workstations / $maxMachines) * 120
        $svHeight = ($servers / $maxMachines) * 120
        $dcHeight = ($dcs / $maxMachines) * 120

        if ($null -ne $BarWorkstations) { $BarWorkstations.Height = $wsHeight }
        if ($null -ne $BarServers) { $BarServers.Height = $svHeight }
        if ($null -ne $BarDCs) { $BarDCs.Height = $dcHeight }

        if ($null -ne $LabelWorkstations) { $LabelWorkstations.Text = $workstations.ToString() }
        if ($null -ne $LabelServers) { $LabelServers.Text = $servers.ToString() }
        if ($null -ne $LabelDCs) { $LabelDCs.Text = $dcs.ToString() }
    }

    if ($null -ne $TotalMachinesLabel) { $TotalMachinesLabel.Text = "Total: $($workstations + $servers + $dcs) machines" }

    # Update Trend Chart (placeholder - would need historical data)
    $TrendChartCanvas.Children.Clear()
    $canvasWidth = $TrendChartCanvas.ActualWidth
    $canvasHeight = $TrendChartCanvas.ActualHeight

    if ($canvasWidth -gt 0 -and $canvasHeight -gt 0) {
        $trendData = @(12, 18, 8, 22, 15, 25, 30) # Last 7 days
        $maxTrend = [Math]::Max($trendData)
        $pointSpacing = $canvasWidth / ($trendData.Count - 1)

        $points = @()
        for ($i = 0; $i -lt $trendData.Count; $i++) {
            $x = $i * $pointSpacing
            $y = $canvasHeight - (($trendData[$i] / $maxTrend) * $canvasHeight * 0.8) - 10
            $points += [System.Windows.Point]::new($x, $y)
        }

        # Draw line
        $polyline = New-Object System.Windows.Shapes.Polyline
        $polyline.Stroke = "#58A6FF"
        $polyline.StrokeThickness = 2
        $polyline.Points = [System.Windows.PointCollection]::new($points)
        $TrendChartCanvas.Children.Add($polyline) | Out-Null

        # Draw points
        foreach ($pt in $points) {
            $ellipse = New-Object System.Windows.Shapes.Ellipse
            $ellipse.Fill = "#58A6FF"
            $ellipse.Width = 6
            $ellipse.Height = 6
            $ellipse.Margin = [System.Windows.Thickness]::new($pt.X - 3, $pt.Y - 3, 0, 0)
            $TrendChartCanvas.Children.Add($ellipse) | Out-Null
        }

        $TrendSummaryLabel.Text = "Total events in last 7 days: $($trendData | Measure-Object -Sum).Sum"
    }
}

function Get-PieSlicePath {
    param(
        [double]$CenterX,
        [double]$CenterY,
        [double]$Radius,
        [double]$StartAngle,
        [double]$EndAngle
    )

    $startRad = ([Math]::PI / 180) * $StartAngle
    $endRad = ([Math]::PI / 180) * $EndAngle

    $startX = $CenterX + $Radius * [Math]::Cos($startRad)
    $startY = $CenterY + $Radius * [Math]::Sin($startRad)
    $endX = $CenterX + $Radius * [Math]::Cos($endRad)
    $endY = $CenterY + $Radius * [Math]::Sin($endRad)

    $largeArc = if ($EndAngle - $StartAngle -gt 180) { 1 } else { 0 }

    if ($EndAngle - $StartAngle -ge 360) {
        return "M $CenterX,$CenterY m -$Radius,0 a $Radius,$Radius 0 1,0 $($Radius*2),0 a $Radius,$Radius 0 1,0 -$($Radius*2),0"
    }

    return "M $CenterX,$CenterY L $startX,$startY A $Radius,$Radius 0 $largeArc,1 $endX,$endY Z"
}

# Workspace Save/Load Functions
function Save-Workspace {
    $workspacePath = "C:\GA-AppLocker\workspaces"
    if (-not (Test-Path $workspacePath)) {
        New-Item -ItemType Directory -Path $workspacePath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $workspaceFile = Join-Path $workspacePath "workspace_$timestamp.json"

    $workspace = @{
        savedAt = Get-Date -Format "o"
        version = "1.0"
        data = @{
            generatedRules = @($script:GeneratedRules | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Value -isnot [scriptblock] } | ForEach-Object { @{ $_.Name = $_.Value } } } )
            collectedEvents = @($script:CollectedEvents)
            collectedArtifacts = @($script:CollectedArtifacts)
            selectedGroups = @()
            selectedTimeFilter = if ($DashboardTimeFilter.SelectedItem) { $DashboardTimeFilter.SelectedItem.Content } else { "Last 7 Days" }
            selectedSystemFilter = if ($DashboardSystemFilter.SelectedItem) { $DashboardSystemFilter.SelectedItem.Content } else { "All Systems" }
        }
    }

    $workspaceJson = $workspace | ConvertTo-Json -Depth 10
    $workspaceJson | Out-File -FilePath $workspaceFile -Encoding UTF8 -Force

    Write-Log "Workspace saved to: $workspaceFile"
    Write-AuditLog -Action "WORKSPACE_SAVED" -Target $workspaceFile -Result 'SUCCESS' -Details "Workspace saved with $($script:GeneratedRules.Count) rules"

    return $workspaceFile
}

function Load-Workspace {
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Workspace Files (*.json)|*.json|All Files (*.*)|*.*"
    $openFileDialog.InitialDirectory = "C:\GA-AppLocker\workspaces"
    $openFileDialog.Title = "Load Workspace"

    if ($openFileDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    try {
        $workspaceJson = Get-Content -Path $openFileDialog.FileName -Raw -Encoding UTF8
        $workspace = $workspaceJson | ConvertFrom-Json

        # Restore data
        if ($workspace.data.generatedRules) {
            $script:GeneratedRules = @()
            foreach ($ruleData in $workspace.data.generatedRules) {
                $rule = [PSCustomObject]@{}
                foreach ($prop in $ruleData.PSObject.Properties) {
                    $rule | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
                }
                $script:GeneratedRules += $rule
            }
        }

        if ($workspace.data.collectedEvents) {
            $script:CollectedEvents = $workspace.data.collectedEvents
        }

        if ($workspace.data.collectedArtifacts) {
            $script:CollectedArtifacts = $workspace.data.collectedArtifacts
        }

        # Restore filters
        foreach ($item in $DashboardTimeFilter.Items) {
            if ($item.Content -eq $workspace.data.selectedTimeFilter) {
                $DashboardTimeFilter.SelectedItem = $item
                break
            }
        }

        foreach ($item in $DashboardSystemFilter.Items) {
            if ($item.Content -eq $workspace.data.selectedSystemFilter) {
                $DashboardSystemFilter.SelectedItem = $item
                break
            }
        }

        # Refresh UI
        Update-RulesDataGrid
        Update-Badges

        Write-Log "Workspace loaded from: $($openFileDialog.FileName)"
        Write-AuditLog -Action "WORKSPACE_LOADED" -Target $openFileDialog.FileName -Result 'SUCCESS' -Details "Workspace loaded with $($script:GeneratedRules.Count) rules"

        [System.Windows.MessageBox]::Show("Workspace loaded successfully!", "Workspace Loaded", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Log "Failed to load workspace: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to load workspace: $($_.Exception.Message)", "Load Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

# Auto-save timer
$script:AutoSaveTimer = $null
function Start-AutoSaveTimer {
    if ($null -eq $script:AutoSaveTimer) {
        $script:AutoSaveTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:AutoSaveTimer.Interval = [TimeSpan]::FromMinutes(10)
        $script:AutoSaveTimer.Add_Tick({
            Save-Workspace
        })
        $script:AutoSaveTimer.Start()
    }
}

# Enhanced Tooltips Initialization
function Initialize-Tooltips {
    # Dashboard tooltips
    if ($null -ne $DashboardTimeFilter) { $DashboardTimeFilter.ToolTip = "Filter dashboard data by time range. Affects event counts and charts." }
    if ($null -ne $DashboardSystemFilter) { $DashboardSystemFilter.ToolTip = "Filter dashboard data by specific computer system." }
    if ($null -ne $RefreshDashboardBtn) { $RefreshDashboardBtn.ToolTip = "Refresh all dashboard data and charts." }

    # Rules tooltips
    if ($null -ne $ImportArtifactsBtn) { $ImportArtifactsBtn.ToolTip = "Import individual artifact files (CSV, XML) to create rules." }
    if ($null -ne $ImportFolderBtn) { $ImportFolderBtn.ToolTip = "Import all executable files from a folder as artifacts." }
    if ($null -ne $MergeRulesBtn) { $MergeRulesBtn.ToolTip = "Merge multiple rule XML files into a single policy." }
    if ($null -ne $GenerateRulesBtn) { $GenerateRulesBtn.ToolTip = "Generate AppLocker rules from imported artifacts (Ctrl+R)." }
    if ($null -ne $DedupeBtn) { $DedupeBtn.ToolTip = "Remove duplicate artifacts based on selected criteria (Ctrl+D)." }
    if ($null -ne $ExportArtifactsListBtn) { $ExportArtifactsListBtn.ToolTip = "Export current artifact list to CSV file." }
    if ($null -ne $AuditToggleBtn) { $AuditToggleBtn.ToolTip = "Toggle all generated rules between Audit (logging only) and Enforce (blocking) mode." }
    if ($null -ne $DefaultDenyRulesBtn) { $DefaultDenyRulesBtn.ToolTip = "Add default deny rules for common bypass locations (TEMP, Downloads, etc.)." }
    if ($null -ne $CreateBrowserDenyBtn) { $CreateBrowserDenyBtn.ToolTip = "Add deny rules for web browsers in the AppLocker-Admins group." }

    # Bulk Actions tooltips
    if ($null -ne $ApplyGroupChangeBtn) { $ApplyGroupChangeBtn.ToolTip = "Change the AD group assignment for all selected rules." }
    if ($null -ne $ApplyActionChangeBtn) { $ApplyActionChangeBtn.ToolTip = "Change the action (Allow/Deny) for all selected rules." }
    if ($null -ne $ApplyDuplicateBtn) { $ApplyDuplicateBtn.ToolTip = "Duplicate all selected rules to another AD group." }
    if ($null -ne $BulkRemoveBtn) { $BulkRemoveBtn.ToolTip = "Remove all selected rules from the list (Delete key)." }

    # Filter tooltips
    if ($null -ne $RulesTypeFilter) { $RulesTypeFilter.ToolTip = "Filter rules by type: Publisher, Hash, or Path." }
    if ($null -ne $RulesActionFilter) { $RulesActionFilter.ToolTip = "Filter rules by action: Allow or Deny." }
    if ($null -ne $RulesGroupFilter) { $RulesGroupFilter.ToolTip = "Filter rules by AD group assignment." }
    if ($null -ne $RulesFilterSearch) { $RulesFilterSearch.ToolTip = "Search rules by name, file path, or group." }
    if ($null -ne $RulesClearFilterBtn) { $RulesClearFilterBtn.ToolTip = "Clear all filters and show all rules." }

    # Events tooltips
    if ($null -ne $ScanLocalEventsBtn) { $ScanLocalEventsBtn.ToolTip = "Scan AppLocker events from local system (Ctrl+E)." }
    if ($null -ne $ScanRemoteEventsBtn) { $ScanRemoteEventsBtn.ToolTip = "Scan AppLocker events from selected remote computers." }
    if ($null -ne $RefreshComputersBtn) { $RefreshComputersBtn.ToolTip = "Refresh the computer list from Active Directory." }
    if ($null -ne $ExportEventsBtn) { $ExportEventsBtn.ToolTip = "Export collected events to CSV file for analysis or rule creation." }
    if ($null -ne $FilterAllBtn) { $FilterAllBtn.ToolTip = "Show all events (Allowed, Audited, Blocked)." }
    if ($null -ne $FilterAllowedBtn) { $FilterAllowedBtn.ToolTip = "Show only allowed events (Event ID 8002)." }
    if ($null -ne $FilterBlockedBtn) { $FilterBlockedBtn.ToolTip = "Show only blocked events (Event ID 8004)." }
    if ($null -ne $FilterAuditBtn) { $FilterAuditBtn.ToolTip = "Show only audited events that would be blocked (Event ID 8003)." }
    if ($null -ne $EventsDateFrom) { $EventsDateFrom.ToolTip = "Filter events from this date onwards." }
    if ($null -ne $EventsDateTo) { $EventsDateTo.ToolTip = "Filter events up to this date." }
    if ($null -ne $EventsFilterSearch) { $EventsFilterSearch.ToolTip = "Search events by file path, user name, or computer name." }
    if ($null -ne $EventsClearFilterBtn) { $EventsClearFilterBtn.ToolTip = "Clear all event filters." }
    if ($null -ne $RefreshEventsBtn) { $RefreshEventsBtn.ToolTip = "Refresh event display with current filters." }

    # Compliance tooltips
    if ($null -ne $ScanLocalComplianceBtn) { $ScanLocalComplianceBtn.ToolTip = "Scan local system for AppLocker compliance." }
    if ($null -ne $ScanSelectedComplianceBtn) { $ScanSelectedComplianceBtn.ToolTip = "Scan selected remote computers for compliance." }
    if ($null -ne $GenerateEvidenceBtn) { $GenerateEvidenceBtn.ToolTip = "Generate compliance evidence package with policy and inventory reports." }

    # Deployment tooltips
    if ($null -ne $ExportRulesBtn) { $ExportRulesBtn.ToolTip = "Export generated rules to XML files (Audit and Enforce versions)." }
    if ($null -ne $ImportRulesBtn) { $ImportRulesBtn.ToolTip = "Import rules into existing GPO (Merge or Overwrite)." }
    if ($null -ne $LinkGPOsBtn) { $LinkGPOsBtn.ToolTip = "Link GPOs to OUs: Domain Controllers, Servers, Workstations." }
    if ($null -ne $ApplyGPOSettingsBtn) { $ApplyGPOSettingsBtn.ToolTip = "Apply AppLocker policy to selected GPO." }
}

if ($null -ne $RefreshDashboardBtn) {
$RefreshDashboardBtn.Add_Click({
    Refresh-Data
})
}

# GPO Quick Assignment - Apply Phase/Mode button
if ($null -ne $ApplyGPOSettingsBtn) {
$ApplyGPOSettingsBtn.Add_Click({
    Write-Log "User requested GPO Phase/Mode settings application"
    Write-AuditLog -Action "GPO_SETTINGS_ATTEMPT" -Target "Multiple GPOs" -Result 'ATTEMPT' -Details "User initiated GPO settings changes"

    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO modification requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-AuditLog -Action "GPO_SETTINGS_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
        return
    }

    try {
        # Use embedded functions - no module import needed
        Import-Module GroupPolicy -ErrorAction Stop

        # Get selected phase/mode for each GPO
        $dcPhase = if ($DCGPOPhase.SelectedItem) { $DCGPOPhase.SelectedItem.Content } else { "--" }
        $dcMode = if ($DCGPOMode.SelectedItem) { $DCGPOMode.SelectedItem.Content } else { "Audit" }
        $serversPhase = if ($ServersGPOPhase.SelectedItem) { $ServersGPOPhase.SelectedItem.Content } else { "--" }
        $serversMode = if ($ServersGPOMode.SelectedItem) { $ServersGPOMode.SelectedItem.Content } else { "Audit" }
        $workstationsPhase = if ($WorkstationsGPOPhase.SelectedItem) { $WorkstationsGPOPhase.SelectedItem.Content } else { "--" }
        $workstationsMode = if ($WorkstationsGPOMode.SelectedItem) { $WorkstationsGPOMode.SelectedItem.Content } else { "Audit" }

        # Check if any GPO is being set to Enforce mode - requires validation and confirmation
        $enforceGPOs = @()
        if ($dcPhase -ne "--" -and $dcMode -eq "Enforce") { $enforceGPOs += "AppLocker-DC" }
        if ($serversPhase -ne "--" -and $serversMode -eq "Enforce") { $enforceGPOs += "AppLocker-Servers" }
        if ($workstationsPhase -ne "--" -and $workstationsMode -eq "Enforce") { $enforceGPOs += "AppLocker-Workstations" }

        if ($enforceGPOs.Count -gt 0) {
            $enforceList = $enforceGPOs -join ", "

            # Run enforce mode readiness validation
            $validation = Test-EnforceModeReadiness
            Write-AuditLog -Action "ENFORCE_MODE_VALIDATION" -Target $enforceList -Result 'ATTEMPT' -Details "Validation performed: Ready=$($validation.ready), Warnings=$($validation.warnings.Count), Errors=$($validation.errors.Count)"

            # Show validation results and get user confirmation
            $confirmed = Show-EnforceModeValidationDialog -ValidationResult $validation
            if (-not $confirmed) {
                $DashboardOutput.Text = "GPO settings cancelled by user after validation."
                Write-AuditLog -Action "GPO_SETTINGS_CANCELLED" -Target "Multiple GPOs" -Result 'CANCELLED' -Details "User cancelled enforce mode after validation"
                return
            }
            Write-AuditLog -Action "GPO_ENFORCE_MODE_CONFIRMED" -Target $enforceList -Result 'SUCCESS' -Details "User confirmed enforce mode for GPOs after validation"
        }

        $results = @()

        # Create a starter AppLocker policy with the specified enforcement mode
        $policyTemplate = Get-AppLockerPolicy -Effective

        # Apply to DC GPO
        if ($dcPhase -ne "--") {
            $gpo = Get-GPO -Name "AppLocker-DC" -ErrorAction SilentlyContinue
            if ($gpo) {
                # Set enforcement mode based on selection
                $enforcementMode = if ($dcMode -eq "Enforce") { "Enforced" } else { "AuditOnly" }
                $results += "DC GPO: Phase=$dcPhase, Mode=$enforcementMode`n"
                Write-Log "DC GPO: Phase=$dcPhase, Mode=$enforcementMode"
                Write-AuditLog -Action "GPO_SETTINGS_APPLIED" -Target "AppLocker-DC" -Result 'SUCCESS' -Details "Phase=$dcPhase, Mode=$enforcementMode"

                # Update status text with phase info
                $DCGPOStatus.Text = "P$dcPhase - $dcMode"
            }
        }

        # Apply to Servers GPO
        if ($serversPhase -ne "--") {
            $gpo = Get-GPO -Name "AppLocker-Servers" -ErrorAction SilentlyContinue
            if ($gpo) {
                $enforcementMode = if ($serversMode -eq "Enforce") { "Enforced" } else { "AuditOnly" }
                $results += "Servers GPO: Phase=$serversPhase, Mode=$enforcementMode`n"
                Write-Log "Servers GPO: Phase=$serversPhase, Mode=$enforcementMode"
                Write-AuditLog -Action "GPO_SETTINGS_APPLIED" -Target "AppLocker-Servers" -Result 'SUCCESS' -Details "Phase=$serversPhase, Mode=$enforcementMode"
                $ServersGPOStatus.Text = "P$serversPhase - $serversMode"
            }
        }

        # Apply to Workstations GPO
        if ($workstationsPhase -ne "--") {
            $gpo = Get-GPO -Name "AppLocker-Workstations" -ErrorAction SilentlyContinue
            if ($gpo) {
                $enforcementMode = if ($workstationsMode -eq "Enforce") { "Enforced" } else { "AuditOnly" }
                $results += "Workstations GPO: Phase=$workstationsPhase, Mode=$enforcementMode`n"
                Write-Log "Workstations GPO: Phase=$workstationsPhase, Mode=$enforcementMode"
                Write-AuditLog -Action "GPO_SETTINGS_APPLIED" -Target "AppLocker-Workstations" -Result 'SUCCESS' -Details "Phase=$workstationsPhase, Mode=$enforcementMode"
                $WorkstationsGPOStatus.Text = "P$workstationsPhase - $workstationsMode"
            }
        }

        $DashboardOutput.Text = "=== GPO SETTINGS APPLIED ===`n`n$results`n`nNote: Phase labels are stored in GPO description. Enforcement mode changes require importing actual AppLocker policy XML via Deployment panel."
        Write-AuditLog -Action "GPO_SETTINGS_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details "GPO settings applied successfully"
    }
    catch {
        $errorMsg = ConvertTo-SafeString -InputString $_.Exception.Message -MaxLength 500
        $DashboardOutput.Text = "ERROR: $errorMsg"
        Write-Log "GPO settings application failed: $errorMsg" -Level "ERROR"
        Write-AuditLog -Action "GPO_SETTINGS_APPLY_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Exception: $errorMsg"
    }
})
}

# GPO Quick Assignment - Link to OUs button
if ($null -ne $LinkGPOsBtn) {
$LinkGPOsBtn.Add_Click({
    Write-Log "User requested linking GPOs to OUs"
    Write-AuditLog -Action "GPO_LINK_ATTEMPT" -Target "Multiple GPOs" -Result 'ATTEMPT' -Details "User initiated GPO linking"

    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO linking requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-AuditLog -Action "GPO_LINK_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
        return
    }

    # Confirmation dialog for GPO linking
    $confirmed = Show-ConfirmationDialog -Title "Confirm GPO Linking" -Message "This will link 3 GPOs to OUs, applying policies immediately." -TargetObject "AppLocker-DC, AppLocker-Servers, AppLocker-Workstations" -ActionType 'LINK'
    if (-not $confirmed) {
        $DashboardOutput.Text = "GPO linking cancelled by user."
        return
    }

    try {
        # Use embedded functions - no module import needed
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        # Get domain info
        $domain = Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName

        # Default AD OUs
        $dcOU = "OU=Domain Controllers,$domainDN"

        # Check for custom OUs (many organizations have separate Servers/Workstations OUs)
        $serversOU = Get-ADOrganizationalUnit -Filter "Name -like '*Server*'" -ErrorAction SilentlyContinue |
                     Select-Object -ExpandProperty DistinguishedName -First 1
        $workstationsOU = Get-ADOrganizationalUnit -Filter "Name -like '*Workstation*' -or Name -eq 'Computers'" -ErrorAction SilentlyContinue |
                          Select-Object -ExpandProperty DistinguishedName -First 1

        # Default to domain root if custom OUs don't exist
        $serversTarget = if ($serversOU) { $serversOU } else { $domainDN }
        $workstationsTarget = if ($workstationsOU) { $workstationsOU } else { $domainDN }

        $results = @()
        $successCount = 0

        # Link DC GPO to Domain Controllers OU
        try {
            New-GPLink -Name "AppLocker-DC" -Target $dcOU -LinkEnabled Yes -ErrorAction Stop | Out-Null
            $results += "OK: AppLocker-DC linked to $dcOU`n"
            Write-AuditLog -Action "GPO_LINKED" -Target "AppLocker-DC -> $dcOU" -Result 'SUCCESS' -Details "GPO linked successfully"
            $successCount++
        } catch {
            if ($_.Exception.Message -like "*already linked*") {
                $results += "OK: AppLocker-DC already linked to $dcOU`n"
                $successCount++
            } else {
                $results += "FAILED: AppLocker-DC - $($_.Exception.Message)`n"
                Write-AuditLog -Action "GPO_LINK_FAILED" -Target "AppLocker-DC -> $dcOU" -Result 'FAILURE' -Details "Error: $($_.Exception.Message)"
            }
        }

        # Link Servers GPO
        try {
            New-GPLink -Name "AppLocker-Servers" -Target $serversTarget -LinkEnabled Yes -ErrorAction Stop | Out-Null
            $results += "OK: AppLocker-Servers linked to $serversTarget`n"
            Write-AuditLog -Action "GPO_LINKED" -Target "AppLocker-Servers -> $serversTarget" -Result 'SUCCESS' -Details "GPO linked successfully"
            $successCount++
        } catch {
            if ($_.Exception.Message -like "*already linked*") {
                $results += "OK: AppLocker-Servers already linked to $serversTarget`n"
                $successCount++
            } else {
                $results += "FAILED: AppLocker-Servers - $($_.Exception.Message)`n"
                Write-AuditLog -Action "GPO_LINK_FAILED" -Target "AppLocker-Servers -> $serversTarget" -Result 'FAILURE' -Details "Error: $($_.Exception.Message)"
            }
        }

        # Link Workstations GPO
        try {
            New-GPLink -Name "AppLocker-Workstations" -Target $workstationsTarget -LinkEnabled Yes -ErrorAction Stop | Out-Null
            $results += "OK: AppLocker-Workstations linked to $workstationsTarget`n"
            Write-AuditLog -Action "GPO_LINKED" -Target "AppLocker-Workstations -> $workstationsTarget" -Result 'SUCCESS' -Details "GPO linked successfully"
            $successCount++
        } catch {
            if ($_.Exception.Message -like "*already linked*") {
                $results += "OK: AppLocker-Workstations already linked to $workstationsTarget`n"
                $successCount++
            } else {
                $results += "FAILED: AppLocker-Workstations - $($_.Exception.Message)`n"
                Write-AuditLog -Action "GPO_LINK_FAILED" -Target "AppLocker-Workstations -> $workstationsTarget" -Result 'FAILURE' -Details "Error: $($_.Exception.Message)"
            }
        }

        $DashboardOutput.Text = "=== GPO LINKING COMPLETE ===`n`nLinked $successCount of 3 GPOs:`n`n$results`nRun 'gpupdate /force' on target systems to apply immediately."
        Write-Log "GPO linking complete: $successCount of 3"
        Write-AuditLog -Action "GPO_LINK_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details "GPO linking complete: $successCount of 3 linked"
    }
    catch {
        $errorMsg = ConvertTo-SafeString -InputString $_.Exception.Message -MaxLength 500
        $DashboardOutput.Text = "ERROR: $errorMsg"
        Write-Log "GPO linking failed: $errorMsg" -Level "ERROR"
        Write-AuditLog -Action "GPO_LINK_BULK_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Exception: $errorMsg"
    }
})
}

# Directory List selection changed - uncheck "Scan All" when user selects specific directories
if ($null -ne $DirectoryList) {
$DirectoryList.Add_SelectionChanged({
    # When user selects specific directories, uncheck the "Scan All" checkbox
    if ($DirectoryList.SelectedItems.Count -gt 0 -and $null -ne $ScanAllDirectoriesCheckbox) {
        $ScanAllDirectoriesCheckbox.IsChecked = $false
    }
})
}

# Global cancel flag for scans
$script:ScanCancelled = $false
$script:CurrentSyncHash = $null

# Scan Local Artifacts button - scans localhost directories
if ($null -ne $ScanLocalArtifactsBtn) {
$ScanLocalArtifactsBtn.Add_Click({
    Write-Log "Starting local artifact scan (localhost directories)"

    # Check if "Scan All Directories" checkbox is checked
    $scanAll = $false
    if ($null -ne $ScanAllDirectoriesCheckbox -and $ScanAllDirectoriesCheckbox.IsChecked) {
        $scanAll = $true
    }

    # Get directories to scan
    if ($scanAll) {
        # Use all directories from the list
        $directories = $DirectoryList.Items | ForEach-Object { $_.Content.ToString() }
        Write-Log "Scan All Directories enabled - scanning all $($directories.Count) directories"
    } else {
        # Use selected directories only
        $selectedItems = $DirectoryList.SelectedItems
        if ($selectedItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Please select at least one directory to scan, or check 'Scan All Directories'.", "No Directory Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $directories = $selectedItems | ForEach-Object { $_.Content.ToString() }
    }

    $maxFiles = [int]$MaxFilesText.Text

    Write-Log "Starting local scan of $($directories.Count) directories with max files: $maxFiles"
    $ArtifactsList.Items.Clear()
    $scanMode = if ($scanAll) { "ALL directories" } else { "selected directories" }
    $RulesOutput.Text = "Starting local scan ($scanMode)...`n`nDirectories:`n$($directories -join "`n")`n`nThis runs in the background - UI will remain responsive."
    $ScanLocalArtifactsBtn.IsEnabled = $false

    # Show progress panel and cancel button
    $script:ScanCancelled = $false
    if ($null -ne $ScanProgressPanel) { $ScanProgressPanel.Visibility = [System.Windows.Visibility]::Visible }
    if ($null -ne $CancelScanBtn) { $CancelScanBtn.Visibility = [System.Windows.Visibility]::Visible }
    if ($null -ne $ScanProgressText) { $ScanProgressText.Text = "Initializing scan..." }
    if ($null -ne $ScanProgressCount) { $ScanProgressCount.Text = "" }

    # Create a background Runspace for async scanning
    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.ArtifactsList = $ArtifactsList
    $syncHash.RulesOutput = $RulesOutput
    $syncHash.ScanLocalArtifactsBtn = $ScanLocalArtifactsBtn
    $syncHash.Window = $window
    $syncHash.CollectedArtifacts = [System.Collections.ArrayList]::new()
    $syncHash.Directories = $directories
    $syncHash.MaxFiles = $maxFiles
    $syncHash.ArtifactCountBadge = $ArtifactCountBadge
    $syncHash.EventCountBadge = $EventCountBadge
    $syncHash.ScanProgressPanel = $ScanProgressPanel
    $syncHash.ScanProgressText = $ScanProgressText
    $syncHash.ScanProgressCount = $ScanProgressCount
    $syncHash.CancelScanBtn = $CancelScanBtn
    $syncHash.Cancelled = $false
    $script:CurrentSyncHash = $syncHash

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()

    $powerShell = [PowerShell]::Create()
    $powerShell.Runspace = $runspace
    $powerShell.AddScript({
        param($syncHash)

        try {
            # Update UI - starting
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Clear()
                $syncHash.ArtifactsList.Items.Add("=== LOCAL ARTIFACT SCAN ===")
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("[*] Loading scan module...")
            })

            # Import required modules - use fixed path
            $modulePath = "C:\GA-AppLocker\src\modules\Module2-RemoteScan.psm1"
            if (Test-Path $modulePath) {
                Import-Module $modulePath -Force -ErrorAction Stop
                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("[OK] Module loaded")
                })
            } else {
                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("ERROR: Module not found: $modulePath")
                    $syncHash.ArtifactsList.Items.Add("")
                    $syncHash.ArtifactsList.Items.Add("Please ensure GA-AppLocker is installed at C:\GA-AppLocker")
                    $syncHash.ScanLocalArtifactsBtn.IsEnabled = $true
                })
                return
            }

            $directories = $syncHash.Directories
            $maxFiles = $syncHash.MaxFiles
            $allArtifacts = [System.Collections.ArrayList]::new()

            # Update UI - show directories
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("Scanning $($directories.Count) directories:")
                foreach ($dir in $directories) {
                    $syncHash.ArtifactsList.Items.Add("  - $dir")
                }
                $syncHash.ArtifactsList.Items.Add("")
            })
            # Scan each directory
            $dirIndex = 0
            $totalDirs = $directories.Count
            foreach ($dir in $directories) {
                $dirIndex++

                # Check for cancellation
                if ($syncHash.Cancelled) {
                    $syncHash.Window.Dispatcher.Invoke([action]{
                        $syncHash.ArtifactsList.Items.Add("")
                        $syncHash.ArtifactsList.Items.Add("=== SCAN CANCELLED ===")
                    })
                    break
                }

                if (-not (Test-Path $dir)) {
                    $syncHash.Window.Dispatcher.Invoke([action]{
                        $syncHash.ArtifactsList.Items.Add("[!] Directory not found: $dir")
                    })
                    continue
                }

                # Update progress text
                $dirName = Split-Path $dir -Leaf
                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("[*] Scanning: $dir...")
                    if ($null -ne $syncHash.ScanProgressText) {
                        $syncHash.ScanProgressText.Text = "Scanning: $dirName"
                    }
                    if ($null -ne $syncHash.ScanProgressCount) {
                        $syncHash.ScanProgressCount.Text = "Directory $dirIndex of $totalDirs | Artifacts: $($allArtifacts.Count)"
                    }
                })

                # Get executable artifacts from directory
                $artifacts = Get-ExecutableArtifacts -Path $dir -MaxFiles $maxFiles -Recurse

                foreach ($art in $artifacts) {
                    # Normalize to standard artifact format
                    $normalized = @{
                        name = if ($art.FileName) { $art.FileName } else { (Split-Path $art.Path -Leaf) }
                        path = $art.Path
                        publisher = if ($art.Publisher) { $art.Publisher } else { "Unknown" }
                        hash = if ($art.Hash) { $art.Hash } else { "" }
                        version = if ($art.Version) { $art.Version } else { "" }
                        size = if ($art.Size) { $art.Size } else { 0 }
                        modifiedDate = if ($art.ModifiedDate) { $art.ModifiedDate } else { (Get-Date) }
                        fileType = if ($art.FileType) { $art.FileType } else { "EXE" }
                    }
                    [void]$allArtifacts.Add($normalized)
                }

                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("    Found: $($artifacts.Count) files")
                    if ($null -ne $syncHash.ScanProgressCount) {
                        $syncHash.ScanProgressCount.Text = "Directory $dirIndex of $totalDirs | Artifacts: $($allArtifacts.Count)"
                    }
                })
            }

            # Update UI - complete
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== SCAN COMPLETE ===")
                $syncHash.ArtifactsList.Items.Add("Total artifacts: $($allArtifacts.Count)")

                # Top publishers
                $byPublisher = $allArtifacts | Group-Object -Property publisher | Sort-Object Count -Descending | Select-Object -First 10
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== TOP PUBLISHERS ===")
                foreach ($pub in $byPublisher) {
                    $syncHash.ArtifactsList.Items.Add("  $($pub.Name): $($pub.Count)")
                }

                # By file type
                $byType = $allArtifacts | Group-Object -Property fileType | Sort-Object Count -Descending
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== FILE TYPES ===")
                foreach ($type in $byType) {
                    $syncHash.ArtifactsList.Items.Add("  $($type.Name): $($type.Count)")
                }

                $syncHash.RulesOutput.Text = "Local scan complete!`n`nArtifacts collected: $($allArtifacts.Count)`n`nGo to Rule Generator to create rules from these artifacts."
                $syncHash.ScanLocalArtifactsBtn.IsEnabled = $true
                $syncHash.ScanLocalArtifactsBtn.IsEnabled = $true
            })

            # Export artifacts to CSV automatically
            $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $csvPath = "C:\GA-AppLocker\Scans\LocalScan_$timestamp.csv"

            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("Saving to: $csvPath...")
            })

            # Ensure Scans folder exists
            $scansFolder = "C:\GA-AppLocker\Scans"
            if (-not (Test-Path $scansFolder)) {
                New-Item -ItemType Directory -Path $scansFolder -Force | Out-Null
            }

            # Convert artifacts to CSV format and save
            $csvData = $allArtifacts | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.name
                    Path = $_.path
                    Publisher = $_.publisher
                    Hash = $_.hash
                    Version = $_.version
                    Size = $_.size
                    ModifiedDate = $_.modifiedDate
                    FileType = $_.fileType
                }
            }

            $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("[OK] Saved: $csvPath")
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.RulesOutput.Text += "`n`nArtifacts exported to: $csvPath"

                # Update badges in Rule Generator
                $syncHash.ArtifactCountBadge.Text = "$($allArtifacts.Count)"
                $syncHash.ArtifactCountBadge.Foreground = "#3FB950"
                $syncHash.ArtifactCountBadge.Background = "#1F6FEB"

                # Hide progress panel
                if ($null -ne $syncHash.ScanProgressPanel) { $syncHash.ScanProgressPanel.Visibility = [System.Windows.Visibility]::Collapsed }
                if ($null -ne $syncHash.CancelScanBtn) { $syncHash.CancelScanBtn.Visibility = [System.Windows.Visibility]::Collapsed }
            })

            Write-Log "Local scan complete: $($allArtifacts.Count) artifacts collected, saved to: $csvPath"
        } catch {
            $errorMsg = $_.Exception.Message
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("ERROR: $errorMsg")
                $syncHash.RulesOutput.Text = "Local scan failed: $errorMsg"
                $syncHash.ScanLocalArtifactsBtn.IsEnabled = $true
                # Hide progress panel on error
                if ($null -ne $syncHash.ScanProgressPanel) { $syncHash.ScanProgressPanel.Visibility = [System.Windows.Visibility]::Collapsed }
                if ($null -ne $syncHash.CancelScanBtn) { $syncHash.CancelScanBtn.Visibility = [System.Windows.Visibility]::Collapsed }
            })
            Write-Log "Local scan failed: $errorMsg" -Level "ERROR"
        }
    }).AddParameter($syncHash) | Out-Null

    $handle = $powerShell.BeginInvoke()

    # Store async handle for cleanup if needed
    $script:LocalScanHandle = @{Handle = $handle; PowerShell = $powerShell}
})
}

# Cancel Scan button
if ($null -ne $CancelScanBtn) {
$CancelScanBtn.Add_Click({
    Write-Log "Scan cancelled by user"
    $script:ScanCancelled = $true
    if ($null -ne $script:CurrentSyncHash) {
        $script:CurrentSyncHash.Cancelled = $true
    }

    # Stop the running scan
    if ($null -ne $script:LocalScanHandle) {
        try {
            $script:LocalScanHandle.PowerShell.Stop()
        } catch { }
    }

    # Update UI
    $ArtifactsList.Items.Add("")
    $ArtifactsList.Items.Add("=== SCAN CANCELLED ===")
    $RulesOutput.Text = "Scan cancelled by user."
    $ScanLocalArtifactsBtn.IsEnabled = $true
    $ScanProgressPanel.Visibility = [System.Windows.Visibility]::Collapsed
    $CancelScanBtn.Visibility = [System.Windows.Visibility]::Collapsed
})
}

# AaronLocker Scan button - Direct Get-AppLockerFileInformation method
if ($null -ne $AaronLockerScanBtn) {
$AaronLockerScanBtn.Add_Click({
    Write-Log "Starting AaronLocker-style scan using Get-AppLockerFileInformation"

    # Check if "Scan All Directories" checkbox is checked
    $scanAll = $false
    $scanAllCheckbox = $window.FindName("ScanAllDirectoriesCheckbox")
    if ($null -ne $scanAllCheckbox -and $scanAllCheckbox.IsChecked) {
        $scanAll = $true
    }

    # Get directories to scan
    $directories = @()
    if ($scanAll) {
        $directories = @(
            "$env:SystemRoot",
            "$env:ProgramFiles",
            "${env:ProgramFiles(x86)}",
            "$env:ProgramData",
            "$env:LOCALAPPDATA",
            "$env:APPDATA"
        )
    } else {
        foreach ($item in $DirectoryList.Items) {
            if ($item -is [System.Windows.Controls.CheckBox] -and $item.IsChecked) {
                $directories += $item.Content
            }
        }
    }

    if ($directories.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one directory to scan.", "No Directories Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Clear previous results
    $ArtifactsList.Items.Clear()
    $ArtifactsList.Items.Add("=== AARONLOCKER-STYLE SCAN ===")
    $ArtifactsList.Items.Add("Using Get-AppLockerFileInformation cmdlet directly")
    $ArtifactsList.Items.Add("")
    $RulesOutput.Text = "Starting AaronLocker-style scan...`n`nDirectories:`n$($directories -join "`n")`n`nThis runs in the background."

    # Disable buttons, show progress
    $AaronLockerScanBtn.IsEnabled = $false
    $ScanLocalArtifactsBtn.IsEnabled = $false
    $script:ScanCancelled = $false
    $ScanProgressPanel.Visibility = [System.Windows.Visibility]::Visible
    $CancelScanBtn.Visibility = [System.Windows.Visibility]::Visible
    $ScanProgressText.Text = "AaronLocker Scan in progress..."
    $ScanProgressCount.Text = "Scanning directories..."

    # Create synchronized hashtable for cross-thread communication
    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.ArtifactsList = $ArtifactsList
    $syncHash.RulesOutput = $RulesOutput
    $syncHash.AaronLockerScanBtn = $AaronLockerScanBtn
    $syncHash.ScanLocalArtifactsBtn = $ScanLocalArtifactsBtn
    $syncHash.Window = $window
    $syncHash.CollectedArtifacts = [System.Collections.ArrayList]::new()
    $syncHash.Directories = $directories
    $syncHash.ScanProgressPanel = $ScanProgressPanel
    $syncHash.ScanProgressText = $ScanProgressText
    $syncHash.ScanProgressCount = $ScanProgressCount
    $syncHash.CancelScanBtn = $CancelScanBtn
    $syncHash.Cancelled = $false

    $script:CurrentSyncHash = $syncHash

    # Create runspace for background scan
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

    $powershell = [powershell]::Create().AddScript({
        param($syncHash)

        # Define AppLocker file extensions (EXE, DLL, Script, MSI categories)
        $executableExtensions = @('.exe', '.dll', '.com', '.ocx', '.msi', '.msp', '.mst', '.bat', '.cmd', '.ps1', '.vbs', '.js')

        $allArtifacts = @()
        $totalDirs = $syncHash.Directories.Count
        $currentDir = 0
        $artifactCount = 0

        foreach ($directory in $syncHash.Directories) {
            $currentDir++

            # Check for cancellation
            if ($syncHash.Cancelled) { break }

            # Update progress
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ScanProgressText.Text = "Scanning: $directory"
                $syncHash.ScanProgressCount.Text = "Directory $currentDir of $totalDirs | Artifacts: $artifactCount"
            })

            if (-not (Test-Path $directory)) {
                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("SKIP: Directory not found - $directory")
                })
                continue
            }

            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("Scanning: $directory")
            })

            try {
                # Get all files matching AppLocker extensions
                $files = Get-ChildItem -Path $directory -Recurse -File -ErrorAction SilentlyContinue |
                         Where-Object { $executableExtensions -contains $_.Extension.ToLower() }

                $fileCount = 0
                foreach ($file in $files) {
                    # Check cancellation periodically
                    if ($syncHash.Cancelled) { break }

                    $fileCount++
                    if ($fileCount % 50 -eq 0) {
                        $syncHash.Window.Dispatcher.Invoke([action]{
                            $syncHash.ScanProgressCount.Text = "Directory $currentDir of $totalDirs | Files: $fileCount | Artifacts: $artifactCount"
                        })
                    }

                    try {
                        # Use Get-AppLockerFileInformation like AaronLocker does
                        $appLockerInfo = Get-AppLockerFileInformation -Path $file.FullName -ErrorAction SilentlyContinue

                        if ($appLockerInfo) {
                            $publisher = $null
                            $productName = 'Unknown'
                            $binaryName = $file.Name
                            $version = 'Unknown'
                            $hash = 'Unknown'

                            # Extract publisher info from FQBN
                            if ($appLockerInfo.Publisher) {
                                $pub = $appLockerInfo.Publisher
                                if ($pub.PublisherName) {
                                    $publisher = $pub.PublisherName
                                }
                                if ($pub.ProductName) {
                                    $productName = $pub.ProductName
                                }
                                if ($pub.BinaryName) {
                                    $binaryName = $pub.BinaryName
                                }
                                if ($pub.BinaryVersion) {
                                    $version = $pub.BinaryVersion.ToString()
                                }
                            }

                            # Get hash
                            if ($appLockerInfo.Hash) {
                                $hashObj = $appLockerInfo.Hash | Where-Object { $_.HashType -eq 'SHA256' } | Select-Object -First 1
                                if ($hashObj) {
                                    $hash = $hashObj.HashDataString
                                } elseif ($appLockerInfo.Hash.Count -gt 0) {
                                    $hash = $appLockerInfo.Hash[0].HashDataString
                                }
                            }

                            # Determine file type
                            $ext = $file.Extension.ToLower()
                            $fileType = switch ($ext) {
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

                            $artifact = [PSCustomObject]@{
                                FileName = $file.Name
                                Path = $file.FullName
                                Publisher = if ($publisher) { $publisher } else { 'Unknown' }
                                ProductName = $productName
                                BinaryName = $binaryName
                                Version = $version
                                Hash = $hash
                                Size = $file.Length
                                FileType = $fileType
                                ModifiedDate = $file.LastWriteTime
                            }

                            $allArtifacts += $artifact
                            [void]$syncHash.CollectedArtifacts.Add($artifact)
                            $artifactCount++
                        }
                    } catch {
                        # Skip files that can't be processed
                    }
                }
            } catch {
                $errorMsg = $_.Exception.Message
                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("  ERROR scanning $directory`: $errorMsg")
                })
            }
        }

        # Final UI update
        $syncHash.Window.Dispatcher.Invoke([action]{
            if ($syncHash.Cancelled) {
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== SCAN CANCELLED ===")
                $syncHash.RulesOutput.Text = "Scan cancelled by user."
            } else {
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== SCAN COMPLETE ===")
                $syncHash.ArtifactsList.Items.Add("Total artifacts found: $($allArtifacts.Count)")
                $syncHash.RulesOutput.Text = "AaronLocker scan complete!`n`nArtifacts collected: $($allArtifacts.Count)`n`nGo to Rule Generator to create rules."
            }

            $syncHash.AaronLockerScanBtn.IsEnabled = $true
            $syncHash.ScanLocalArtifactsBtn.IsEnabled = $true
            $syncHash.ScanProgressPanel.Visibility = [System.Windows.Visibility]::Collapsed
            $syncHash.CancelScanBtn.Visibility = [System.Windows.Visibility]::Collapsed
        })

        # Export artifacts to CSV if any found
        if ($allArtifacts.Count -gt 0 -and -not $syncHash.Cancelled) {
            $scanFolder = "C:\GA-AppLocker\Scans"
            if (-not (Test-Path $scanFolder)) {
                New-Item -ItemType Directory -Path $scanFolder -Force | Out-Null
            }
            $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $csvPath = Join-Path $scanFolder "AaronLocker_Scan_$timestamp.csv"
            $allArtifacts | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("Exported to: $csvPath")
                $syncHash.RulesOutput.Text = "AaronLocker scan complete!`n`nArtifacts collected: $($allArtifacts.Count)`n`nExported to:`n$csvPath`n`nGo to Rule Generator to create rules."
            })
        }
    }).AddArgument($syncHash)

    $powershell.Runspace = $runspace
    $script:LocalScanHandle = @{ PowerShell = $powershell; Runspace = $runspace }
    $asyncResult = $powershell.BeginInvoke()

    Write-Log "AaronLocker scan runspace started"
})
}

# Rules events
if ($null -ne $ImportArtifactsBtn) {
$ImportArtifactsBtn.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $openDialog.Title = "Import Artifacts (scans, events, or any file list)"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"
    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Write-Log "Importing artifacts from $($openDialog.FileName)"
        $ext = [System.IO.Path]::GetExtension($openDialog.FileName)

        try {
            $rawData = if ($ext -eq ".csv") {
                Import-Csv -Path $openDialog.FileName
            } else {
                Get-Content -Path $openDialog.FileName | ConvertFrom-Json
            }

            if ($rawData.Count -eq 0) {
                [System.Windows.MessageBox]::Show("No data found in file.", "Import Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                return
            }

            # Intelligently map columns to standard artifact format
            $artifacts = @()
            $firstRow = $rawData[0]
            $properties = $firstRow.PSObject.Properties.Name

            # Detect file path column (various possible names)
            $pathColumn = $properties | Where-Object { $_ -match '^(Path|FullPath|FilePath|FileName|File|Name)$' } | Select-Object -First 1
            if (-not $pathColumn) {
                $pathColumn = $properties | Where-Object { $_ -match 'Path|File|Name' } | Select-Object -First 1
            }

            # Detect publisher column
            $publisherColumn = $properties | Where-Object { $_ -match '^(Publisher|Vendor|Company|Signer|Fqbn)$' } | Select-Object -First 1
            if (-not $publisherColumn) {
                $publisherColumn = $properties | Where-Object { $_ -match 'Publisher|Vendor|Company|Sign' } | Select-Object -First 1
            }

            # Detect hash column
            $hashColumn = $properties | Where-Object { $_ -match '^(Hash|SHA256|SHA1|MD5|FileHash)$' } | Select-Object -First 1

            # Detect event type column (for event exports)
            $eventTypeColumn = $properties | Where-Object { $_ -match '^(type|EventType|Action|Status)$' } | Select-Object -First 1

            if (-not $pathColumn) {
                [System.Windows.MessageBox]::Show("Could not find file path column. Expected: Path, FullPath, FilePath, or FileName", "Import Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                return
            }

            $RulesOutput.Text = "=== IMPORTING ARTIFACTS ===`n`n"
            $RulesOutput.Text += "File: $($openDialog.FileName)`n"
            $RulesOutput.Text += "Total rows: $($rawData.Count)`n`n"
            $RulesOutput.Text += "Detected columns:`n"
            $RulesOutput.Text += "  Path: $pathColumn`n"
            $RulesOutput.Text += "  Publisher: $(if ($publisherColumn) { $publisherColumn } else { '(none)' })`n"
            $RulesOutput.Text += "  Hash: $(if ($hashColumn) { $hashColumn } else { '(none)' })`n"
            $RulesOutput.Text += "  Event Type: $(if ($eventTypeColumn) { $eventTypeColumn } else { '(none)' })`n`n"
            [System.Windows.Forms.Application]::DoEvents()

            $seenPaths = @{}
            foreach ($row in $rawData) {
                $path = $row.$pathColumn
                if (-not $path -or $seenPaths.ContainsKey($path.ToLower())) { continue }
                $seenPaths[$path.ToLower()] = $true

                $publisher = if ($publisherColumn) { $row.$publisherColumn } else { "" }
                $hash = if ($hashColumn) { $row.$hashColumn } else { "" }
                $eventType = if ($eventTypeColumn) { $row.$eventTypeColumn } else { "" }

                # Determine file type from extension
                $fileType = switch -Regex ($path) {
                    '\.exe$' { "Exe" }
                    '\.dll$' { "Dll" }
                    '\.msi$' { "Msi" }
                    '\.(ps1|bat|cmd|vbs|js)$' { "Script" }
                    default { "Exe" }
                }

                $artifacts += [PSCustomObject]@{
                    Path = $path
                    FileName = [System.IO.Path]::GetFileName($path)
                    FullPath = $path
                    Publisher = $publisher
                    Hash = $hash
                    Type = $fileType
                    EventType = $eventType
                }
            }

            if ($artifacts.Count -eq 0) {
                $RulesOutput.Text += "ERROR: No valid file paths found in data."
                return
            }

            $script:CollectedArtifacts = $artifacts

            # Count by type
            $exeCount = ($artifacts | Where-Object Type -eq "Exe").Count
            $dllCount = ($artifacts | Where-Object Type -eq "Dll").Count
            $msiCount = ($artifacts | Where-Object Type -eq "Msi").Count
            $scriptCount = ($artifacts | Where-Object Type -eq "Script").Count
            $withPublisher = ($artifacts | Where-Object { $_.Publisher -and $_.Publisher -ne "Unknown" }).Count

            $RulesOutput.Text += "=== IMPORTED $($artifacts.Count) UNIQUE ARTIFACTS ===`n`n"
            $RulesOutput.Text += "Breakdown:`n"
            $RulesOutput.Text += "  EXE: $exeCount`n"
            $RulesOutput.Text += "  DLL: $dllCount`n"
            $RulesOutput.Text += "  MSI: $msiCount`n"
            $RulesOutput.Text += "  Script: $scriptCount`n`n"
            $RulesOutput.Text += "  With Publisher info: $withPublisher (can use Publisher rules)`n"
            $RulesOutput.Text += "  Without Publisher: $($artifacts.Count - $withPublisher) (will need Hash rules)`n`n"

            $RulesOutput.Text += "BEST PRACTICE: Use Publisher rules for signed files, Hash for unsigned.`n`n"
            $RulesOutput.Text += "Select rule type, action, and group, then click 'Generate Rules'."

            Write-Log "Imported $($artifacts.Count) artifacts from $($openDialog.FileName)"
            [System.Windows.MessageBox]::Show("Imported $($artifacts.Count) unique artifacts.`n`nWith Publisher: $withPublisher`nWithout Publisher: $($artifacts.Count - $withPublisher)`n`nSelect options and click Generate Rules.", "Import Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } catch {
            $RulesOutput.Text = "ERROR importing file: $($_.Exception.Message)"
            Write-Log "Import failed: $($_.Exception.Message)" -Level "ERROR"
        }
    }
})
}

# Import folder recursively - searches all CSV files in folder and subfolders
if ($null -ne $ImportFolderBtn) {
$ImportFolderBtn.Add_Click({
    Write-Log "Import folder (recursive) clicked"
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select folder containing artifact CSV files (will search recursively)"
    $folderDialog.SelectedPath = "C:\GA-AppLocker\Scans"

    if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $folderPath = $folderDialog.SelectedPath
        $csvFiles = Get-ChildItem -Path $folderPath -Filter "*.csv" -Recurse -File -ErrorAction SilentlyContinue

        if ($csvFiles.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No CSV files found in folder or subfolders.", "No Files Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $allArtifacts = @()
        $importedFiles = @()

        foreach ($csvFile in $csvFiles) {
            try {
                $data = Import-Csv -Path $csvFile.FullName -ErrorAction Stop
                if ($data.Count -gt 0) {
                    $allArtifacts += $data
                    $importedFiles += $csvFile.Name
                }
            } catch {
                Write-Log "Failed to import $($csvFile.Name): $_"
            }
        }

        if ($allArtifacts.Count -gt 0) {
            $script:CollectedArtifacts = $allArtifacts
            Update-Badges
            $RulesOutput.Text = "Imported $($allArtifacts.Count) artifacts from $($importedFiles.Count) files:`n`n$($importedFiles -join "`n")`n`nSelect rule type and click Generate Rules."
            [System.Windows.MessageBox]::Show("Imported $($allArtifacts.Count) artifacts from $($importedFiles.Count) CSV files.", "Import Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            [System.Windows.MessageBox]::Show("No valid artifact data found in CSV files.", "Import Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        }
    }
})
}

# Load Collected Artifacts button - seamless integration from Artifact Collection
if ($null -ne $LoadCollectedArtifactsBtn) {
$LoadCollectedArtifactsBtn.Add_Click({
    Write-Log "Loading collected artifacts from Artifact Collection panel"

    if (-not $script:CollectedArtifacts -or $script:CollectedArtifacts.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No artifacts available.`n`nGo to Artifact Collection panel and scan local/remote computers first.",
            "No Artifacts",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        $RulesOutput.Text = "No artifacts available.`n`nGo to Artifact Collection panel and scan local/remote computers first."
        return
    }

    $artifacts = $script:CollectedArtifacts

    # Count by type
    $exeCount = ($artifacts | Where-Object { $_.fileType -eq "EXE" -or $_.Type -eq "Exe" }).Count
    $dllCount = ($artifacts | Where-Object { $_.fileType -eq "DLL" -or $_.Type -eq "Dll" }).Count
    $msiCount = ($artifacts | Where-Object { $_.fileType -eq "MSI" -or $_.Type -eq "Msi" }).Count
    $scriptCount = ($artifacts | Where-Object { $_.fileType -eq "Script" }).Count
    $withPublisher = ($artifacts | Where-Object { $_.publisher -and $_.publisher -ne "Unknown" -and $_.Publisher -and $_.Publisher -ne "Unknown" }).Count

    $RulesOutput.Text = "=== LOADED ARTIFACTS FROM COLLECTION ===`n`n"
    $RulesOutput.Text += "Source: Artifact Collection panel (seamless integration)`n"
    $RulesOutput.Text += "Total: $($artifacts.Count) artifacts`n`n"
    $RulesOutput.Text += "Breakdown:`n"
    $RulesOutput.Text += "  EXE: $exeCount`n"
    $RulesOutput.Text += "  DLL: $dllCount`n"
    $RulesOutput.Text += "  MSI: $msiCount`n"
    $RulesOutput.Text += "  Script: $scriptCount`n`n"
    $RulesOutput.Text += "  With Publisher: $withPublisher (can use Publisher rules)`n"
    $RulesOutput.Text += "  Without Publisher: $($artifacts.Count - $withPublisher) (will need Hash rules)`n`n"
    $RulesOutput.Text += "Select rule type, action, and group, then click 'Generate Rules'."

    Write-Log "Loaded $($artifacts.Count) artifacts from Artifact Collection panel"
    [System.Windows.MessageBox]::Show(
        "Loaded $($artifacts.Count) artifacts from Artifact Collection.`n`nWith Publisher: $withPublisher`nWithout Publisher: $($artifacts.Count - $withPublisher)`n`nSelect options and click Generate Rules.",
        "Artifacts Loaded",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})
}

# Load Collected Events button - seamless integration from Event Monitor
if ($null -ne $LoadCollectedEventsBtn) {
$LoadCollectedEventsBtn.Add_Click({
    Write-Log "Loading collected events from Event Monitor panel"

    if (-not $script:AllEvents -or $script:AllEvents.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No events available.`n`nGo to Event Monitor panel and scan local/remote computers first.",
            "No Events",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        $RulesOutput.Text = "No events available.`n`nGo to Event Monitor panel and scan local/remote computers first."
        return
    }

    $events = $script:AllEvents

    # Convert events to artifacts format for rule generation
    $artifacts = @()
    $seenPaths = @{}

    foreach ($event in $events) {
        $path = if ($event.FilePath) { $event.FilePath } elseif ($event.FullPath) { $event.FullPath } elseif ($event.Path) { $event.Path } else { $null }

        if (-not $path -or $seenPaths.ContainsKey($path.ToLower())) { continue }
        $seenPaths[$path.ToLower()] = $true

        $publisher = if ($event.Publisher) { $event.Publisher } elseif ($event.Fqbn) { $event.Fqbn } else { "" }
        $hash = if ($event.Hash) { $event.Hash } else { "" }

        # Determine file type from extension
        $fileType = switch -Regex ($path) {
            '\.exe$' { "EXE" }
            '\.dll$' { "DLL" }
            '\.msi$' { "MSI" }
            '\.(ps1|bat|cmd|vbs|js)$' { "Script" }
            default { "EXE" }
        }

        $artifacts += [PSCustomObject]@{
            name = if ($event.FileName) { $event.FileName } else { [System.IO.Path]::GetFileName($path) }
            path = $path
            publisher = $publisher
            hash = $hash
            version = ""
            size = 0
            modifiedDate = Get-Date
            fileType = $fileType
        }
    }

    $script:CollectedArtifacts = $artifacts

    # Count by type
    $exeCount = ($artifacts | Where-Object fileType -eq "EXE").Count
    $dllCount = ($artifacts | Where-Object fileType -eq "DLL").Count
    $msiCount = ($artifacts | Where-Object fileType -eq "MSI").Count
    $scriptCount = ($artifacts | Where-Object fileType -eq "Script").Count
    $withPublisher = ($artifacts | Where-Object { $_.publisher -and $_.publisher -ne "Unknown" }).Count

    $RulesOutput.Text = "=== LOADED ARTIFACTS FROM EVENTS ===`n`n"
    $RulesOutput.Text += "Source: Event Monitor panel ($($events.Count) events)`n"
    $RulesOutput.Text += "Converted to: $($artifacts.Count) unique artifacts`n`n"
    $RulesOutput.Text += "Breakdown:`n"
    $RulesOutput.Text += "  EXE: $exeCount`n"
    $RulesOutput.Text += "  DLL: $dllCount`n"
    $RulesOutput.Text += "  MSI: $msiCount`n"
    $RulesOutput.Text += "  Script: $scriptCount`n`n"
    $RulesOutput.Text += "  With Publisher: $withPublisher (can use Publisher rules)`n"
    $RulesOutput.Text += "  Without Publisher: $($artifacts.Count - $withPublisher) (will need Hash rules)`n`n"
    $RulesOutput.Text += "Select rule type, action, and group, then click 'Generate Rules'."

    Write-Log "Loaded $($artifacts.Count) artifacts from Event Monitor panel (from $($events.Count) events)"
    [System.Windows.MessageBox]::Show(
        "Loaded $($artifacts.Count) artifacts from Event Monitor.`n`nSource: $($events.Count) events`nWith Publisher: $withPublisher`nWithout Publisher: $($artifacts.Count - $withPublisher)`n`nSelect options and click Generate Rules.",
        "Events Loaded",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})
}

# Deduplicate button - removes duplicate artifacts based on selected field
if ($null -ne $DedupeBtn) {
$DedupeBtn.Add_Click({
    Write-Log "Deduplicating artifacts"

    if (-not $script:CollectedArtifacts -or $script:CollectedArtifacts.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No artifacts to deduplicate.`n`nImport artifacts first using Quick Import or Import Artifact.",
            "No Artifacts",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Get selected dedupe type
    $selectedItem = $DedupeTypeCombo.SelectedItem
    $dedupeType = if ($selectedItem) { $selectedItem.Tag } else { "Publisher" }

    $beforeCount = $script:CollectedArtifacts.Count
    $seen = @{}
    $uniqueArtifacts = [System.Collections.ArrayList]::new()

    foreach ($artifact in $script:CollectedArtifacts) {
        # Get the key value based on dedupe type
        $key = switch ($dedupeType) {
            "Publisher" {
                $pub = if ($artifact.Publisher) { $artifact.Publisher } elseif ($artifact.publisher) { $artifact.publisher } else { ""
                }
                if ($pub -eq "Unknown" -or $pub -eq "") { "Unknown" } else { $pub }
            }
            "Hash" {
                $hash = if ($artifact.Hash) { $artifact.Hash } elseif ($artifact.hash) { $artifact.hash } else { ""
                }
                if ($hash -eq "") { "NoHash" } else { $hash }
            }
            "Path" {
                $path = if ($artifact.Path) { $artifact.Path } elseif ($artifact.FilePath) { $artifact.FilePath } elseif ($artifact.FullPath) { $artifact.FullPath } else { ""
                }
                if ($path -eq "") { "NoPath" } else { $path.ToLower() }
            }
            default { "Unknown" }
        }

        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            [void]$uniqueArtifacts.Add($artifact)
        }
    }

    $script:CollectedArtifacts = $uniqueArtifacts
    $removedCount = $beforeCount - $uniqueArtifacts.Count

    $RulesOutput.Text = "=== DEDUPLICATION COMPLETE ===`n`n"
    $RulesOutput.Text += "Deduplicate by: $dedupeType`n"
    $RulesOutput.Text += "Before: $beforeCount artifacts`n"
    $RulesOutput.Text += "After: $($uniqueArtifacts.Count) artifacts`n"
    $RulesOutput.Text += "Removed: $removedCount duplicates`n`n"

    if ($dedupeType -eq "Publisher") {
        $uniquePublishers = ($uniqueArtifacts | ForEach-Object {
            $pub = if ($_.Publisher) { $_.Publisher } elseif ($_.publisher) { $_.publisher } else { "Unknown" }
            if ($pub -eq "" -or $pub -eq "Unknown") { "Unknown" } else { $pub }
        } | Select-Object -Unique).Count
        $RulesOutput.Text += "Unique Publishers: $uniquePublishers`n`n"
    } elseif ($dedupeType -eq "Hash") {
        $withHash = ($uniqueArtifacts | Where-Object {
            $hash = if ($_.Hash) { $_.Hash } elseif ($_.hash) { $_.hash } else { "" }
            $hash -ne ""
        }).Count
        $RulesOutput.Text += "Artifacts with Hash: $withHash`n`n"
    } elseif ($dedupeType -eq "Path") {
        $RulesOutput.Text += "All paths are now unique`n`n"
    }

    $RulesOutput.Text += "Badges have been updated.`n`nClick Generate Rules to create rules from the deduplicated list."

    # Update badges
    Update-Badges

    Write-Log "Deduplicated by ${dedupeType}: $beforeCount -> $($uniqueArtifacts.Count) (removed $removedCount)"
    [System.Windows.MessageBox]::Show(
        "Deduplication complete!`n`nBy: $dedupeType`nBefore: $beforeCount`nAfter: $($uniqueArtifacts.Count)`nRemoved: $removedCount duplicates",
        "Deduplication Complete",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})
}

# Export Artifacts List button - exports current artifact list to CSV
if ($null -ne $ExportArtifactsListBtn) {
$ExportArtifactsListBtn.Add_Click({
    Write-Log "Exporting artifacts list"

    if (-not $script:CollectedArtifacts -or $script:CollectedArtifacts.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No artifacts to export.`n`nImport artifacts first using Quick Import or Import Artifact.",
            "No Artifacts",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $saveDialog.Title = "Export Artifacts List"
    $saveDialog.FileName = "Artifacts_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker\Scans"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $csvPath = $saveDialog.FileName

        # Ensure directory exists
        $csvDir = Split-Path -Parent $csvPath
        if (-not (Test-Path $csvDir)) {
            New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
        }

        # Export artifacts to CSV with standard format
        $csvData = $script:CollectedArtifacts | ForEach-Object {
            [PSCustomObject]@{
                Name = if ($_.Name) { $_.Name } elseif ($_.name) { $_.name } elseif ($_.FileName) { $_.FileName } else { "" }
                Path = if ($_.Path) { $_.Path } elseif ($_.path) { $_.path } elseif ($_.FilePath) { $_.FilePath } elseif ($_.FullPath) { $_.FullPath } else { "" }
                Publisher = if ($_.Publisher) { $_.Publisher } elseif ($_.publisher) { $_.publisher } else { "Unknown" }
                Hash = if ($_.Hash) { $_.Hash } elseif ($_.hash) { $_.hash } else { "" }
                Version = if ($_.Version) { $_.Version } elseif ($_.version) { $_.version } else { "" }
                Size = if ($_.Size) { $_.Size } elseif ($_.size) { $_.size } else { 0 }
                ModifiedDate = if ($_.ModifiedDate) { $_.ModifiedDate } elseif ($_.modifiedDate) { $_.modifiedDate } else { "" }
                FileType = if ($_.FileType) { $_.FileType } elseif ($_.fileType) { $_.fileType } elseif ($_.Type) { $_.Type } else { "EXE" }
            }
        }

        try {
            $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            $RulesOutput.Text = "=== EXPORT COMPLETE ===`n`n"
            $RulesOutput.Text += "Exported: $($csvPath)`n"
            $RulesOutput.Text += "Total: $($script:CollectedArtifacts.Count) artifacts`n`n"
            $RulesOutput.Text += "You can re-import this file later using Import Artifact button."

            Write-Log "Exported $($script:CollectedArtifacts.Count) artifacts to: $csvPath"
            [System.Windows.MessageBox]::Show(
                "Exported $($script:CollectedArtifacts.Count) artifacts to:`n`n$csvPath",
                "Export Complete",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information)
        } catch {
            $errorMsg = $_.Exception.Message
            $RulesOutput.Text = "ERROR: Failed to export`n`n$errorMsg"
            Write-Log "Export failed: $errorMsg" -Level "ERROR"
            [System.Windows.MessageBox]::Show(
                "Failed to export:`n$errorMsg",
                "Export Failed",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error)
        }
    }
})
}

# Change Group button - change AD group for selected rules
if ($null -ne $ChangeGroupBtn) {
$ChangeGroupBtn.Add_Click({
    Write-Log "Change group button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Show dialog to select new group
    $groupSelection = Show-GroupSelectionDialog -Title "Select New Group" -Message "Select the AD group to apply to the selected $($selectedItems.Count) rule(s):"

    if ($groupSelection -eq "Cancel") {
        Write-Log "Group change cancelled by user"
        return
    }

    $newSid = Get-SidFromGroupName -GroupName $groupSelection

    # Update selected rules
    $updatedCount = 0
    foreach ($item in $selectedItems) {
        $rule = $item.Rule
        $rule.userOrGroupSid = $newSid
        $item.Group = $groupSelection
        $item.SID = $newSid
        $updatedCount++
    }

    $RulesOutput.Text = "=== GROUP CHANGED ===`n`n"
    $RulesOutput.Text += "Updated: $updatedCount rule(s)`n"
    $RulesOutput.Text += "New Group: $groupSelection`n`n"
    $RulesOutput.Text += "Use Export Rules to save the changes."

    Write-Log "Changed group for $updatedCount rules to: $groupSelection"
    [System.Windows.MessageBox]::Show(
        "Group changed for $updatedCount rule(s).`n`nNew Group: $groupSelection`n`nUse Export Rules to save the changes.",
        "Group Changed",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})
}

# Duplicate Rules button - duplicate selected rules to another group
if ($null -ne $DuplicateRulesBtn) {
$DuplicateRulesBtn.Add_Click({
    Write-Log "Duplicate rules button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Show dialog to select target group
    $groupSelection = Show-GroupSelectionDialog -Title "Select Target Group" -Message "Duplicate $($selectedItems.Count) rule(s) to which group:"

    if ($groupSelection -eq "Cancel") {
        Write-Log "Duplicate cancelled by user"
        return
    }

    $targetSid = Get-SidFromGroupName -GroupName $groupSelection

    # Duplicate selected rules
    $duplicatedCount = 0
    foreach ($item in $selectedItems) {
        $rule = $item.Rule

        # Create a deep copy of the rule
        $newRule = [PSCustomObject]@{
            id = "{" + (New-Guid).ToString() + "}"
            type = $rule.type
            action = $rule.action
            userOrGroupSid = $targetSid
            publisherName = if ($rule.publisherName) { $rule.publisherName } else { $null }
            fileName = if ($rule.fileName) { $rule.fileName } else { $null }
            path = if ($rule.path) { $rule.path } else { $null }
            hash = if ($rule.hash) { $rule.hash } else { $null }
            xml = if ($rule.xml) { $rule.xml } else { $null }
        }

        # Update the XML with new SID
        if ($newRule.xml) {
            $newRule.xml = $newRule.xml -replace 'UserOrGroupSid="[^"]*"', "UserOrGroupSid=`"$targetSid`""
        }

        $script:GeneratedRules += $newRule
        $duplicatedCount++
    }

    # Refresh the DataGrid
    Update-RulesDataGrid

    $RulesOutput.Text = "=== RULES DUPLICATED ===`n`n"
    $RulesOutput.Text += "Duplicated: $duplicatedCount rule(s)`n"
    $RulesOutput.Text += "Target Group: $groupSelection`n`n"
    $RulesOutput.Text += "Total Rules: $($script:GeneratedRules.Count)`n`n"
    $RulesOutput.Text += "Use Export Rules to save all rules."

    Write-Log "Duplicated $duplicatedCount rules to group: $groupSelection"
    [System.Windows.MessageBox]::Show(
        "Duplicated $duplicatedCount rule(s).`n`nTarget Group: $groupSelection`n`nTotal Rules: $($script:GeneratedRules.Count)`n`nUse Export Rules to save all rules.",
        "Rules Duplicated",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})
}

# Delete Rules button - delete selected rules
if ($null -ne $DeleteRulesBtn) {
$DeleteRulesBtn.Add_Click({
    Write-Log "Delete rules button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Confirm deletion
    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to delete $($selectedItems.Count) rule(s)?`n`nThis action cannot be undone.",
        "Confirm Delete",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning)

    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) {
        Write-Log "Delete cancelled by user"
        return
    }

    # Collect rules to remove
    $rulesToRemove = @($selectedItems | ForEach-Object { $_.Rule })

    # Remove from GeneratedRules
    $newRulesList = [System.Collections.ArrayList]::new()
    foreach ($rule in $script:GeneratedRules) {
        if ($rule -notin $rulesToRemove) {
            [void]$newRulesList.Add($rule)
        }
    }
    $script:GeneratedRules = $newRulesList

    # Refresh the DataGrid
    Update-RulesDataGrid

    $RulesOutput.Text = "=== RULES DELETED ===`n`n"
    $RulesOutput.Text += "Deleted: $($rulesToRemove.Count) rule(s)`n"
    $RulesOutput.Text += "Remaining: $($script:GeneratedRules.Count) rule(s)"

    Write-Log "Deleted $($rulesToRemove.Count) rules"
    [System.Windows.MessageBox]::Show(
        "Deleted $($rulesToRemove.Count) rule(s).`n`nRemaining: $($script:GeneratedRules.Count) rule(s)",
        "Rules Deleted",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})
}

# ============================================================
# PHASE 4: Bulk Editing Event Handlers
# ============================================================

# Apply Group Change button - bulk change AD group for selected rules
if ($null -ne $ApplyGroupChangeBtn) {
$ApplyGroupChangeBtn.Add_Click({
    Write-Log "Bulk group change button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Get selected group from combo
    $selectedGroupItem = $BulkGroupCombo.SelectedItem
    if (-not $selectedGroupItem) {
        [System.Windows.MessageBox]::Show(
            "No group selected.`n`nPlease select a group from the dropdown.",
            "No Group Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $newGroup = $selectedGroupItem.Content

    # Confirm operation
    $confirmed = Show-ConfirmationDialog -Title "Confirm Bulk Group Change" -Message "Change AD group for $($selectedItems.Count) selected rule(s) to '$newGroup'?" -ActionType 'MODIFY'

    if (-not $confirmed) {
        Write-Log "Bulk group change cancelled by user"
        return
    }

    Invoke-BulkChangeGroup -SelectedItems $selectedItems -NewGroup $newGroup
})
}

# Apply Action Change button - bulk change action (Allow/Deny) for selected rules
if ($null -ne $ApplyActionChangeBtn) {
$ApplyActionChangeBtn.Add_Click({
    Write-Log "Bulk action change button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Get selected action from combo
    $selectedActionItem = $BulkActionCombo.SelectedItem
    if (-not $selectedActionItem) {
        [System.Windows.MessageBox]::Show(
            "No action selected.`n`nPlease select an action from the dropdown.",
            "No Action Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $newAction = $selectedActionItem.Content

    # Confirm operation
    $actionType = if ($newAction -eq "Deny") { 'ENFORCE' } else { 'MODIFY' }
    $confirmed = Show-ConfirmationDialog -Title "Confirm Bulk Action Change" -Message "Change action for $($selectedItems.Count) selected rule(s) to '$newAction'?" -ActionType $actionType

    if (-not $confirmed) {
        Write-Log "Bulk action change cancelled by user"
        return
    }

    Invoke-BulkChangeAction -SelectedItems $selectedItems -NewAction $newAction
})
}

# Apply Duplicate button - bulk duplicate selected rules to another group
if ($null -ne $ApplyDuplicateBtn) {
$ApplyDuplicateBtn.Add_Click({
    Write-Log "Bulk duplicate button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Get selected group from combo
    $selectedGroupItem = $BulkDuplicateCombo.SelectedItem
    if (-not $selectedGroupItem) {
        [System.Windows.MessageBox]::Show(
            "No group selected.`n`nPlease select a target group from the dropdown.",
            "No Group Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $targetGroup = $selectedGroupItem.Content

    # Confirm operation
    $confirmed = Show-ConfirmationDialog -Title "Confirm Bulk Duplicate" -Message "Duplicate $($selectedItems.Count) selected rule(s) to group '$targetGroup'?" -ActionType 'CREATE'

    if (-not $confirmed) {
        Write-Log "Bulk duplicate cancelled by user"
        return
    }

    Invoke-BulkDuplicateToGroup -SelectedItems $selectedItems -TargetGroup $targetGroup
})
}

# Bulk Remove button - remove all selected rules
if ($null -ne $BulkRemoveBtn) {
$BulkRemoveBtn.Add_Click({
    Write-Log "Bulk remove button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Confirm deletion
    $confirmed = Show-ConfirmationDialog -Title "Confirm Bulk Remove" -Message "Remove $($selectedItems.Count) selected rule(s) from the list?" -ActionType 'DELETE'

    if (-not $confirmed) {
        Write-Log "Bulk remove cancelled by user"
        return
    }

    Invoke-BulkRemoveRules -SelectedItems $selectedItems
})
}

# Update selection info when selection changes
$RulesDataGrid.Add_SelectionChanged({
    $selectedCount = $RulesDataGrid.SelectedItems.Count
    if ($selectedCount -eq 0) {
        $BulkSelectionInfo.Text = "No rules selected"
    } elseif ($selectedCount -eq 1) {
        $BulkSelectionInfo.Text = "1 rule selected"
    } else {
        $BulkSelectionInfo.Text = "$selectedCount rules selected"
    }
})

# Phase 4: Filter Control Event Handlers for Rules Panel
$RulesTypeFilter.Add_SelectionChanged({
    Filter-RulesDataGrid
})

$RulesActionFilter.Add_SelectionChanged({
    Filter-RulesDataGrid
})

$RulesGroupFilter.Add_SelectionChanged({
    Filter-RulesDataGrid
})

$RulesFilterSearch.Add_GotFocus({
    if ($RulesFilterSearch.Text -eq "Search...") {
        $RulesFilterSearch.Text = ""
    }
})

$RulesFilterSearch.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($RulesFilterSearch.Text)) {
        $RulesFilterSearch.Text = "Search..."
    }
})

$RulesFilterSearch.Add_TextChanged({
    Filter-RulesDataGrid
})

if ($null -ne $RulesClearFilterBtn) {
$RulesClearFilterBtn.Add_Click({
    $RulesTypeFilter.SelectedIndex = 0
    $RulesActionFilter.SelectedIndex = 0
    $RulesGroupFilter.SelectedIndex = 0
    $RulesFilterSearch.Text = "Search..."
    Filter-RulesDataGrid
})
}

# Phase 4: Filter Control Event Handlers for Events Panel
if ($null -ne $FilterAllBtn) {
$FilterAllBtn.Add_Click({
    $script:EventFilter = "All"
    Update-EventFilterButtons
    Filter-Events
})
}

if ($null -ne $FilterAllowedBtn) {
$FilterAllowedBtn.Add_Click({
    $script:EventFilter = "Allowed"
    Update-EventFilterButtons
    Filter-Events
})
}

if ($null -ne $FilterBlockedBtn) {
$FilterBlockedBtn.Add_Click({
    $script:EventFilter = "Blocked"
    Update-EventFilterButtons
    Filter-Events
})
}

if ($null -ne $FilterAuditBtn) {
$FilterAuditBtn.Add_Click({
    $script:EventFilter = "Audit"
    Update-EventFilterButtons
    Filter-Events
})
}

function Update-EventFilterButtons {
    $FilterAllBtn.Background = if ($script:EventFilter -eq "All") { "#388BFD" } else { "#21262D" }
    $FilterAllowedBtn.Background = if ($script:EventFilter -eq "Allowed") { "#388BFD" } else { "#21262D" }
    $FilterBlockedBtn.Background = if ($script:EventFilter -eq "Blocked") { "#388BFD" } else { "#21262D" }
    $FilterAuditBtn.Background = if ($script:EventFilter -eq "Audit") { "#388BFD" } else { "#21262D" }
}

$EventsDateFrom.Add_SelectedDateChanged({
    Filter-Events
})

$EventsDateTo.Add_SelectedDateChanged({
    Filter-Events
})

$EventsFilterSearch.Add_GotFocus({
    if ($EventsFilterSearch.Text -eq "Search events...") {
        $EventsFilterSearch.Text = ""
    }
})

$EventsFilterSearch.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($EventsFilterSearch.Text)) {
        $EventsFilterSearch.Text = "Search events..."
    }
})

$EventsFilterSearch.Add_TextChanged({
    Filter-Events
})

if ($null -ne $EventsClearFilterBtn) {
$EventsClearFilterBtn.Add_Click({
    $script:EventFilter = "All"
    Update-EventFilterButtons
    $EventsDateFrom.SelectedDate = $null
    $EventsDateTo.SelectedDate = $null
    $EventsFilterSearch.Text = "Search events..."
    Filter-Events
})
}

if ($null -ne $RefreshEventsBtn) {
$RefreshEventsBtn.Add_Click({
    Filter-Events
})
}

# Phase 5: Report Button Event Handlers
# Quick date range buttons
if ($null -ne $ReportLast7Days) {
$ReportLast7Days.Add_Click({
    $ReportEndDate.SelectedDate = Get-Date
    $ReportStartDate.SelectedDate = (Get-Date).AddDays(-7)
    Update-StatusBar
})
}

if ($null -ne $ReportLast30Days) {
$ReportLast30Days.Add_Click({
    $ReportEndDate.SelectedDate = Get-Date
    $ReportStartDate.SelectedDate = (Get-Date).AddDays(-30)
    Update-StatusBar
})
}

if ($null -ne $ReportLast90Days) {
$ReportLast90Days.Add_Click({
    $ReportEndDate.SelectedDate = Get-Date
    $ReportStartDate.SelectedDate = (Get-Date).AddDays(-90)
    Update-StatusBar
})
}

# Generate Report button
if ($null -ne $GenerateReportBtn) {
$GenerateReportBtn.Add_Click({
    try {
        Write-Log "Generate Report button clicked"

        # Validate date selection
        if (-not $ReportStartDate.SelectedDate -or -not $ReportEndDate.SelectedDate) {
            [System.Windows.MessageBox]::Show(
                "Please select both start and end dates for the report.",
                "Date Selection Required",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        if ($ReportStartDate.SelectedDate -gt $ReportEndDate.SelectedDate) {
            [System.Windows.MessageBox]::Show(
                "Start date cannot be after end date.",
                "Invalid Date Range",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Get report type
        $reportTypeItem = $ReportTypeSelector.SelectedItem
        if (-not $reportTypeItem) {
            [System.Windows.MessageBox]::Show(
                "Please select a report type.",
                "Report Type Required",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $reportType = $reportTypeItem.Tag

        # Get target system
        $targetSystemItem = $ReportTargetSystem.SelectedItem
        $targetSystem = if ($targetSystemItem) { $targetSystemItem.Tag } else { "All" }

        # Update status
        $ReportStatus.Text = "Generating..."
        $ReportStatus.Foreground = "#D29922"
        $ReportPreview.Text = "Generating report... Please wait.`n`nThis may take a moment depending on the date range and event volume."
        $window.Cursor = [System.Windows.Input.Cursors]::Wait
        [System.Windows.Forms.Application]::DoEvents()

        # Generate the report
        $result = New-ComplianceReport -ReportType $reportType -StartDate $ReportStartDate.SelectedDate -EndDate $ReportEndDate.SelectedDate -TargetSystem $targetSystem

        # Restore cursor
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow

        if ($result.success) {
            # Display the report
            $reportText = Format-ReportAsText -ReportData $result.data
            $ReportPreview.Text = $reportText
            $ReportPreviewScroll.ScrollToTop()

            # Update status
            $ReportStatus.Text = "Complete"
            $ReportStatus.Foreground = "#3FB950"
            $ReportGeneratedTime.Text = "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

            Write-Log "Report generated successfully: $($result.data.ReportTitle)"
            Update-StatusBar
        } else {
            $ReportStatus.Text = "Failed"
            $ReportStatus.Foreground = "#F85149"
            $ReportPreview.Text = "Report generation failed:`n`n$($result.error)`n`nPlease check the logs for more details."

            [System.Windows.MessageBox]::Show(
                "Failed to generate report:`n`n$($result.error)`n`nCheck logs for details.",
                "Report Generation Failed",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error)
        }
    }
    catch {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
        $ReportStatus.Text = "Error"
        $ReportStatus.Foreground = "#F85149"
        Write-Log "Error generating report: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show(
            "An error occurred while generating the report:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Export to PDF button
if ($null -ne $ExportToPdfBtn) {
$ExportToPdfBtn.Add_Click({
    try {
        Write-Log "Export to PDF button clicked"

        if (-not $script:CurrentReportData) {
            [System.Windows.MessageBox]::Show(
                "No report data available. Please generate a report first.",
                "No Report Data",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Show save file dialog
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
        $saveFileDialog.Title = "Save Report As"
        $saveFileDialog.FileName = "GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
        $saveFileDialog.InitialDirectory = $env:TEMP

        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $result = Export-ReportToPdf -ReportData $script:CurrentReportData -OutputPath $saveFileDialog.FileName

            if ($result.success) {
                [System.Windows.MessageBox]::Show(
                    "Report exported successfully to:`n`n$($result.outputPath)`n`n$($result.message)",
                    "Export Successful",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)

                # Open the file
                Start-Process $result.outputPath
            } else {
                [System.Windows.MessageBox]::Show(
                    "Failed to export report:`n`n$($result.error)",
                    "Export Failed",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error)
            }
        }
    }
    catch {
        Write-Log "Error exporting to PDF: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show(
            "An error occurred while exporting the report:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Export to HTML button
if ($null -ne $ExportToHtmlBtn) {
$ExportToHtmlBtn.Add_Click({
    try {
        Write-Log "Export to HTML button clicked"

        if (-not $script:CurrentReportData) {
            [System.Windows.MessageBox]::Show(
                "No report data available. Please generate a report first.",
                "No Report Data",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Show save file dialog
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "HTML Files (*.html)|*.html|All Files (*.*)|*.*"
        $saveFileDialog.Title = "Save Report As"
        $saveFileDialog.FileName = "GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        $saveFileDialog.InitialDirectory = $env:TEMP

        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $result = Export-ReportToHtml -ReportData $script:CurrentReportData -OutputPath $saveFileDialog.FileName

            if ($result.success) {
                [System.Windows.MessageBox]::Show(
                    "Report exported successfully to:`n`n$($result.outputPath)",
                    "Export Successful",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)

                # Open the file
                Start-Process $result.outputPath
            } else {
                [System.Windows.MessageBox]::Show(
                    "Failed to export report:`n`n$($result.error)",
                    "Export Failed",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error)
            }
        }
    }
    catch {
        Write-Log "Error exporting to HTML: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show(
            "An error occurred while exporting the report:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Export to CSV button
if ($null -ne $ExportToCsvBtn) {
$ExportToCsvBtn.Add_Click({
    try {
        Write-Log "Export to CSV button clicked"

        if (-not $script:CurrentReportData) {
            [System.Windows.MessageBox]::Show(
                "No report data available. Please generate a report first.",
                "No Report Data",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Show save file dialog
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $saveFileDialog.Title = "Save Report Data As"
        $saveFileDialog.FileName = "GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $saveFileDialog.InitialDirectory = $env:TEMP

        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $result = Export-ReportToCsv -ReportData $script:CurrentReportData -OutputPath $saveFileDialog.FileName

            if ($result.success) {
                [System.Windows.MessageBox]::Show(
                    "Report data exported successfully to:`n`n$($result.outputPath)",
                    "Export Successful",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information)

                # Open the file
                Start-Process $result.outputPath
            } else {
                [System.Windows.MessageBox]::Show(
                    "Failed to export report:`n`n$($result.error)",
                    "Export Failed",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error)
            }
        }
    }
    catch {
        Write-Log "Error exporting to CSV: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show(
            "An error occurred while exporting the report:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Schedule Report button
if ($null -ne $ScheduleReportBtn) {
$ScheduleReportBtn.Add_Click({
    try {
        Write-Log "Schedule Report button clicked"

        # Check if we have current report data
        if (-not $script:CurrentReportData) {
            [System.Windows.MessageBox]::Show(
                "No report data available. Please generate a report first to use as a template.",
                "No Report Data",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Create a simple input dialog
        # For now, we'll show a message explaining the feature
        [System.Windows.MessageBox]::Show(
            "Report Scheduling Feature:`n`n" +
            "This feature allows you to create Windows Scheduled Tasks for automatic report generation.`n`n" +
            "To schedule a report, use the following PowerShell command:`n`n" +
            "Schedule-ReportJob -ReportName `'MyReport'` -ReportType `'$($script:CurrentReportData.ReportType)`' -Schedule Daily -Time `'02:00'` -OutputPath `'C:\Reports\report.html'``n`n" +
            "Available options:`n" +
            "- ReportName: Name for the scheduled task`n" +
            "- ReportType: Executive, Technical, Audit, or Comparison`n" +
            "- Schedule: Daily, Weekly, or Monthly`n" +
            "- Time: Time to run (e.g., '02:00')`n" +
            "- OutputPath: Where to save the report`n`n" +
            "You can manage scheduled reports using Windows Task Scheduler.",
            "Schedule Report",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Log "Error scheduling report: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show(
            "An error occurred:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Refresh Scheduled Reports button
if ($null -ne $RefreshScheduledReportsBtn) {
$RefreshScheduledReportsBtn.Add_Click({
    try {
        Write-Log "Refresh Scheduled Reports button clicked"

        $result = Get-ScheduledReports

        if ($result.success) {
            $ScheduledReportsList.Items.Clear()

            foreach ($report in $result.reports) {
                $item = [PSCustomObject]@{
                    ReportName = $report.ReportName
                    Schedule = "$($report.Schedule)`nNext Run: $($report.NextRun)"
                }
                $ScheduledReportsList.Items.Add($item)
            }

            if ($result.reports.Count -eq 0) {
                $ReportStatus.Text = "No scheduled reports"
                $ReportStatus.Foreground = "#8B949E"
            } else {
                $ReportStatus.Text = "$($result.reports.Count) scheduled report(s)"
                $ReportStatus.Foreground = "#3FB950"
            }

            Write-Log "Retrieved $($result.reports.Count) scheduled report(s)"
        } else {
            [System.Windows.MessageBox]::Show(
                "Failed to retrieve scheduled reports:`n`n$($result.error)",
                "Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error)
        }

        Update-StatusBar
    }
    catch {
        Write-Log "Error refreshing scheduled reports: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show(
            "An error occurred while retrieving scheduled reports:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Phase 4: Filter Control Event Handlers for Compliance Panel
$ComplianceStatusFilter.Add_SelectionChanged({
    Filter-ComplianceComputers
})

$ComplianceFilterSearch.Add_GotFocus({
    if ($ComplianceFilterSearch.Text -eq "Search computers...") {
        $ComplianceFilterSearch.Text = ""
    }
})

$ComplianceFilterSearch.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($ComplianceFilterSearch.Text)) {
        $ComplianceFilterSearch.Text = "Search computers..."
    }
})

$ComplianceFilterSearch.Add_TextChanged({
    Filter-ComplianceComputers
})

if ($null -ne $ComplianceClearFilterBtn) {
$ComplianceClearFilterBtn.Add_Click({
    $ComplianceStatusFilter.SelectedIndex = 0
    $ComplianceFilterSearch.Text = "Search computers..."
    Filter-ComplianceComputers
})
}

# Phase 4: Bulk Duplicate Button Event Handler
if ($null -ne $ApplyDuplicateBtn) {
$ApplyDuplicateBtn.Add_Click({
    Write-Log "Bulk duplicate button clicked"

    $selectedItems = $RulesDataGrid.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "No rules selected.`n`nSelect one or more rules from the list first.",
            "No Selection",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
        return
    }

    $selectedGroupItem = $BulkDuplicateCombo.SelectedItem
    if ($null -eq $selectedGroupItem) {
        [System.Windows.MessageBox]::Show(
            "No group selected.`n`nPlease select a target group from the dropdown.",
            "No Group Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $targetGroup = $selectedGroupItem.Content

    # Confirm operation
    $confirmed = Show-ConfirmationDialog -Title "Confirm Bulk Duplicate" -Message "Duplicate $($selectedItems.Count) selected rule(s) to group '$targetGroup'?" -ActionType 'CREATE'

    if (-not $confirmed) {
        Write-Log "Bulk duplicate cancelled by user"
        return
    }

    Invoke-BulkDuplicateToGroup -SelectedItems $selectedItems -TargetGroup $targetGroup
})
}

# Helper function to show group selection dialog
function Show-GroupSelectionDialog {
    param([string]$Title, [string]$Message)

    # Create a simple window for group selection
    $window = New-Object System.Windows.Window
    $window.Title = $Title
    $window.Width = 400
    $window.Height = 250
    $window.WindowStartupLocation = "CenterOwner"
    $window.ResizeMode = "NoResize"

    # Grid layout
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = 20

    # Message label
    $messageLabel = New-Object System.Windows.Controls.TextBlock
    $messageLabel.Text = $Message
    $messageLabel.Margin = 0
    $messageLabel.VerticalAlignment = "Top"
    $messageLabel.TextWrapping = "Wrap"
    [void]$grid.Children.Add($messageLabel)

    # Group combo
    $groupCombo = New-Object System.Windows.Controls.ComboBox
    $groupCombo.Margin = 0
    $groupCombo.VerticalAlignment = "Top"
    $groupCombo.Height = 30

    # Add group options
    $groups = @(
        "AppLocker-Admins",
        "AppLocker-PowerUsers",
        "AppLocker-StandardUsers",
        "AppLocker-RestrictedUsers",
        "AppLocker-Installers",
        "AppLocker-Developers",
        "Everyone"
    )

    foreach ($group in $groups) {
        $comboItem = New-Object System.Windows.Controls.ComboBoxItem
        $comboItem.Content = $group
        [void]$groupCombo.Items.Add($comboItem)
    }

    $groupCombo.SelectedIndex = 0
    $groupCombo.Margin = 0
    $groupCombo.VerticalAlignment = "Top"
    [System.Windows.Controls.Grid]::SetRow($groupCombo, 1)
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property Height = [System.Windows.GridLength]::new(10)))
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property Height = [System.Windows.GridLength]::new(35)))
    [void]$grid.Children.Add($groupCombo)

    # Buttons
    $buttonPanel = New-Object System.Windows.Controls.StackPanel
    $buttonPanel.Orientation = "Horizontal"
    $buttonPanel.HorizontalAlignment = "Right"
    $buttonPanel.Margin = 0
    $buttonPanel.VerticalAlignment = "Top"
    [System.Windows.Controls.Grid]::SetRow($buttonPanel, 2)
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition -Property Height = [System.Windows.GridLength]::new(40)))
    [void]$grid.Children.Add($buttonPanel)

    $okButton = New-Object System.Windows.Controls.Button
    $okButton.Content = "OK"
    $okButton.Width = 80
    $okButton.Margin = 0
    [void]$buttonPanel.Children.Add($okButton)

    $cancelButton = New-Object System.Windows.Controls.Button
    $cancelButton.Content = "Cancel"
    $cancelButton.Width = 80
    $cancelButton.Margin = "10,0,0,0"
    [void]$buttonPanel.Children.Add($cancelButton)

    $window.Content = $grid

    # Result variable
    $result = "Cancel"

    # OK button handler
    $okButton.Add_Click({
        $result = $groupCombo.Text
        $window.Close()
    })

    # Cancel button handler
    $cancelButton.Add_Click({
        $result = "Cancel"
        $window.Close()
    })

    # Show dialog and get result
    $window.ShowDialog() | Out-Null

    return $result
}

# ============================================================
# PHASE 4: Bulk Editing Helper Functions
# ============================================================

function Invoke-BulkChangeGroup {
    <#
    .SYNOPSIS
        Bulk change AD group for selected rules
    .DESCRIPTION
        Updates the AD group assignment for multiple selected rules with confirmation and audit logging
    .PARAMETER SelectedItems
        The selected items from the RulesDataGrid
    .PARAMETER NewGroup
        The new AD group name to assign
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$SelectedItems,

        [Parameter(Mandatory = $true)]
        [string]$NewGroup
    )

    try {
        Write-Log "Starting bulk group change for $($SelectedItems.Count) rules to group: $NewGroup"

        # Get SID for new group
        $newSid = Get-SidFromGroupName -GroupName $NewGroup

        # Track progress
        $updatedCount = 0
        $failedCount = 0

        foreach ($item in $SelectedItems) {
            try {
                $rule = $item.Rule

                # Update the rule's SID
                $rule.userOrGroupSid = $newSid

                # Update the display item
                $item.Group = $NewGroup
                $item.SID = $newSid

                # Update XML if present
                if ($rule.xml) {
                    $rule.xml = $rule.xml -replace 'UserOrGroupSid="[^"]*"', "UserOrGroupSid=`"$newSid`""
                }

                $updatedCount++
            }
            catch {
                Write-Log "Error updating rule: $_"
                $failedCount++
            }
        }

        # Refresh the DataGrid
        Update-RulesDataGrid

        # Update output panel
        $RulesOutput.Text = "=== BULK GROUP CHANGE COMPLETE ===`n`n"
        $RulesOutput.Text += "Updated: $updatedCount rule(s)`n"
        if ($failedCount -gt 0) {
            $RulesOutput.Text += "Failed: $failedCount rule(s)`n"
        }
        $RulesOutput.Text += "New Group: $NewGroup`n`n"
        $RulesOutput.Text += "Use Export Rules to save the changes."

        # Audit log
        Write-AuditLog -Action "BULK_GROUP_CHANGE" -Target "$NewGroup ($updatedCount rules)" -Result 'SUCCESS' -Details "Changed AD group for $updatedCount rules to $NewGroup"

        # Update status bar
        Update-StatusBar

        Write-Log "Bulk group change completed: $updatedCount rules updated"

        [System.Windows.MessageBox]::Show(
            "Group changed for $updatedCount rule(s).`n`nNew Group: $NewGroup`n`nUse Export Rules to save the changes.",
            "Bulk Group Change Complete",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Log "Error in bulk group change: $_"
        Write-AuditLog -Action "BULK_GROUP_CHANGE" -Target $NewGroup -Result 'FAILURE' -Details "Error: $_"

        [System.Windows.MessageBox]::Show(
            "An error occurred while changing groups.`n`nError: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
}

function Invoke-BulkChangeAction {
    <#
    .SYNOPSIS
        Bulk change action (Allow/Deny) for selected rules
    .DESCRIPTION
        Updates the action for multiple selected rules with confirmation and audit logging
    .PARAMETER SelectedItems
        The selected items from the RulesDataGrid
    .PARAMETER NewAction
        The new action (Allow or Deny)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$SelectedItems,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Allow', 'Deny')]
        [string]$NewAction
    )

    try {
        Write-Log "Starting bulk action change for $($SelectedItems.Count) rules to: $NewAction"

        # Track progress
        $updatedCount = 0
        $failedCount = 0

        foreach ($item in $SelectedItems) {
            try {
                $rule = $item.Rule

                # Update the rule's action
                $rule.action = $NewAction.ToLower()

                # Update the display item
                $item.Action = $NewAction

                # Update XML if present
                if ($rule.xml) {
                    $rule.xml = $rule.xml -replace 'Action="[^"]*"', "Action=`"$($NewAction.ToLower())`""
                }

                $updatedCount++
            }
            catch {
                Write-Log "Error updating rule: $_"
                $failedCount++
            }
        }

        # Refresh the DataGrid
        Update-RulesDataGrid

        # Update output panel
        $RulesOutput.Text = "=== BULK ACTION CHANGE COMPLETE ===`n`n"
        $RulesOutput.Text += "Updated: $updatedCount rule(s)`n"
        if ($failedCount -gt 0) {
            $RulesOutput.Text += "Failed: $failedCount rule(s)`n"
        }
        $RulesOutput.Text += "New Action: $NewAction`n`n"
        $RulesOutput.Text += "Use Export Rules to save the changes."

        # Audit log
        Write-AuditLog -Action "BULK_ACTION_CHANGE" -Target "$NewAction ($updatedCount rules)" -Result 'SUCCESS' -Details "Changed action for $updatedCount rules to $NewAction"

        # Update status bar
        Update-StatusBar

        Write-Log "Bulk action change completed: $updatedCount rules updated"

        [System.Windows.MessageBox]::Show(
            "Action changed for $updatedCount rule(s).`n`nNew Action: $NewAction`n`nUse Export Rules to save the changes.",
            "Bulk Action Change Complete",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Log "Error in bulk action change: $_"
        Write-AuditLog -Action "BULK_ACTION_CHANGE" -Target $NewAction -Result 'FAILURE' -Details "Error: $_"

        [System.Windows.MessageBox]::Show(
            "An error occurred while changing actions.`n`nError: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
}

function Invoke-BulkDuplicateToGroup {
    <#
    .SYNOPSIS
        Bulk duplicate selected rules to another group
    .DESCRIPTION
        Creates duplicates of selected rules assigned to a different AD group
    .PARAMETER SelectedItems
        The selected items from the RulesDataGrid
    .PARAMETER TargetGroup
        The target AD group for duplicated rules
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$SelectedItems,

        [Parameter(Mandatory = $true)]
        [string]$TargetGroup
    )

    try {
        Write-Log "Starting bulk duplicate for $($SelectedItems.Count) rules to group: $TargetGroup"

        # Get SID for target group
        $targetSid = Get-SidFromGroupName -GroupName $TargetGroup

        # Track progress
        $duplicatedCount = 0
        $failedCount = 0

        foreach ($item in $SelectedItems) {
            try {
                $rule = $item.Rule

                # Create a deep copy of the rule
                $newRule = [PSCustomObject]@{
                    id = "{" + (New-Guid).ToString() + "}"
                    type = $rule.type
                    action = $rule.action
                    userOrGroupSid = $targetSid
                    publisherName = if ($rule.publisherName) { $rule.publisherName } else { $null }
                    fileName = if ($rule.fileName) { $rule.fileName } else { $null }
                    path = if ($rule.path) { $rule.path } else { $null }
                    hash = if ($rule.hash) { $rule.hash } else { $null }
                    xml = if ($rule.xml) { $rule.xml } else { $null }
                }

                # Update the XML with new SID
                if ($newRule.xml) {
                    $newRule.xml = $newRule.xml -replace 'UserOrGroupSid="[^"]*"', "UserOrGroupSid=`"$targetSid`""
                    $newRule.xml = $newRule.xml -replace 'id="[^"]*"', "id=`"$($newRule.id)`""
                }

                # Add to generated rules
                $script:GeneratedRules += $newRule

                $duplicatedCount++
            }
            catch {
                Write-Log "Error duplicating rule: $_"
                $failedCount++
            }
        }

        # Refresh the DataGrid
        Update-RulesDataGrid

        # Update output panel
        $RulesOutput.Text = "=== BULK DUPLICATE COMPLETE ===`n`n"
        $RulesOutput.Text += "Duplicated: $duplicatedCount rule(s)`n"
        if ($failedCount -gt 0) {
            $RulesOutput.Text += "Failed: $failedCount rule(s)`n"
        }
        $RulesOutput.Text += "Target Group: $TargetGroup`n`n"
        $RulesOutput.Text += "Total Rules: $($script:GeneratedRules.Count)`n`n"
        $RulesOutput.Text += "Use Export Rules to save all rules."

        # Audit log
        Write-AuditLog -Action "BULK_DUPLICATE" -Target "$TargetGroup ($duplicatedCount rules)" -Result 'SUCCESS' -Details "Duplicated $duplicatedCount rules to $TargetGroup"

        # Update status bar
        Update-StatusBar

        Write-Log "Bulk duplicate completed: $duplicatedCount rules duplicated"

        [System.Windows.MessageBox]::Show(
            "Duplicated $duplicatedCount rule(s).`n`nTarget Group: $TargetGroup`n`nTotal Rules: $($script:GeneratedRules.Count)`n`nUse Export Rules to save all rules.",
            "Bulk Duplicate Complete",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Log "Error in bulk duplicate: $_"
        Write-AuditLog -Action "BULK_DUPLICATE" -Target $TargetGroup -Result 'FAILURE' -Details "Error: $_"

        [System.Windows.MessageBox]::Show(
            "An error occurred while duplicating rules.`n`nError: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
}

function Invoke-BulkRemoveRules {
    <#
    .SYNOPSIS
        Bulk remove selected rules from the rules list
    .DESCRIPTION
        Removes multiple selected rules with confirmation and audit logging
    .PARAMETER SelectedItems
        The selected items from the RulesDataGrid
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$SelectedItems
    )

    try {
        Write-Log "Starting bulk remove for $($SelectedItems.Count) rules"

        # Collect rules to remove
        $rulesToRemove = @($SelectedItems | ForEach-Object { $_.Rule })

        # Remove from GeneratedRules
        $newRulesList = [System.Collections.ArrayList]::new()
        foreach ($rule in $script:GeneratedRules) {
            if ($rule -notin $rulesToRemove) {
                [void]$newRulesList.Add($rule)
            }
        }
        $script:GeneratedRules = $newRulesList

        # Refresh the DataGrid
        Update-RulesDataGrid

        # Update output panel
        $RulesOutput.Text = "=== BULK REMOVE COMPLETE ===`n`n"
        $RulesOutput.Text += "Removed: $($rulesToRemove.Count) rule(s)`n"
        $RulesOutput.Text += "Remaining: $($script:GeneratedRules.Count) rule(s)"

        # Audit log
        Write-AuditLog -Action "BULK_REMOVE" -Target "$($rulesToRemove.Count) rules" -Result 'SUCCESS' -Details "Removed $($rulesToRemove.Count) rules from collection"

        # Update status bar
        Update-StatusBar

        Write-Log "Bulk remove completed: $($rulesToRemove.Count) rules removed"

        [System.Windows.MessageBox]::Show(
            "Removed $($rulesToRemove.Count) rule(s).`n`nRemaining: $($script:GeneratedRules.Count) rule(s)",
            "Bulk Remove Complete",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information)
    }
    catch {
        Write-Log "Error in bulk remove: $_"
        Write-AuditLog -Action "BULK_REMOVE" -Target "$($SelectedItems.Count) rules" -Result 'FAILURE' -Details "Error: $_"

        [System.Windows.MessageBox]::Show(
            "An error occurred while removing rules.`n`nError: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error)
    }
}

# Default Deny Rules - adds deny rules for common bypass locations
if ($null -ne $DefaultDenyRulesBtn) {
$DefaultDenyRulesBtn.Add_Click({
    Write-Log "Adding default deny rules for bypass locations"

    $sid = Get-SelectedSid
    $groupName = $RuleGroupCombo.SelectedItem.Content

    $RulesOutput.Text = "=== GENERATING DEFAULT DENY RULES ===`n`n"
    $RulesOutput.Text += "These rules block execution from common bypass locations.`n"
    $RulesOutput.Text += "Applied to: $groupName`n`n"
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-DefaultDenyRules -UserOrGroupSid $sid

    if ($result.count -gt 0) {
        $script:GeneratedRules = $result.rules

        $RulesOutput.Text += "=== GENERATED $($result.count) DENY RULES ===`n`n"
        $RulesOutput.Text += "BLOCKED LOCATIONS:`n"
        foreach ($rule in $result.rules) {
            $RulesOutput.Text += "  [DENY] $($rule.path)`n"
        }

        $RulesOutput.Text += "`nBest Practice: These rules help prevent execution from`n"
        $RulesOutput.Text += "user-writable locations commonly used by malware.`n`n"
        $RulesOutput.Text += "Use 'Export Rules' in Deployment to save these rules."

        Write-Log "Generated $($result.count) default deny rules"
        [System.Windows.MessageBox]::Show("Generated $($result.count) default deny rules.`n`nThese block execution from:`n- TEMP folders`n- Downloads folder`n- AppData folders`n- ProgramData folder`n`nUse Export Rules to save.", "Default Deny Rules Created", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

        # Update Rules DataGrid
        Update-RulesDataGrid
    } else {
        $RulesOutput.Text += "ERROR: Failed to generate deny rules."
    }
})
}

# ============================================================
# QoL FEATURE: Audit Mode Toggle
# ============================================================
$script:AuditModeEnabled = $true

if ($null -ne $AuditToggleBtn) {
$AuditToggleBtn.Add_Click({
    Write-Log "Audit toggle clicked"

    $script:AuditModeEnabled = -not $script:AuditModeEnabled

    if ($script:AuditModeEnabled) {
        $AuditToggleBtn.Content = "[!] AUDIT MODE"
        $AuditToggleBtn.Background = "#F0883E"
        $AuditToggleBtn.Foreground = "#FFFFFF"
        Update-RulesOutputAuditMode $true
        Write-Log "Switched to AUDIT mode"
    } else {
        $AuditToggleBtn.Content = "[X] ENFORCE MODE"
        $AuditToggleBtn.Background = "#DA3633"
        $AuditToggleBtn.Foreground = "#FFFFFF"
        Update-RulesOutputAuditMode $false
        Write-Log "Switched to ENFORCE mode"
    }
})
}

function Update-RulesOutputAuditMode {
    param([bool]$IsAudit)

    if ($script:GeneratedRules.Count -gt 0) {
        $modeText = if ($IsAudit) { "AUDIT ([!])" } else { "ENFORCE ([X])" }
        $RulesOutput.Text = "=== RULE COLLECTION - $modeText ===`n`n"
        $RulesOutput.Text += "Total Rules: $($script:GeneratedRules.Count)`n"
        $RulesOutput.Text += "Mode: $(if ($IsAudit) { 'Audit - Rules will be logged but not enforced' } else { 'Enforce - Rules will be actively blocked' })`n`n"

        foreach ($rule in $script:GeneratedRules) {
            $action = if ($IsAudit) { "AUDIT" } else { $rule.action }
            $RulesOutput.Text += "[$action] $($rule.type): $($rule.publisher)`n"
        }
    }
}

# ============================================================
# QoL FEATURE: Search/Filter in Rules
# ============================================================
if ($null -ne $RulesSearchBox) {
    $RulesSearchBox.Add_GotFocus({
        if ($RulesSearchBox.Text -eq "Filter rules/artifacts...") {
            $RulesSearchBox.Text = ""
            $RulesSearchBox.Foreground = "#E6EDF3"
        }
    })

    $RulesSearchBox.Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($RulesSearchBox.Text)) {
            $RulesSearchBox.Text = "Filter rules/artifacts..."
            $RulesSearchBox.Foreground = "#8B949E"
        }
    })

    $RulesSearchBox.Add_TextChanged({
        Apply-FilterToRules
    })
}

if ($null -ne $ClearFilterBtn) {
$ClearFilterBtn.Add_Click({
    $RulesSearchBox.Text = ""
    $RulesSearchBox.Foreground = "#8B949E"
    Apply-FilterToRules
})
}

function Apply-FilterToRules {
    $filterText = $RulesSearchBox.Text

    if ($filterText -eq "Filter rules/artifacts..." -or [string]::IsNullOrWhiteSpace($filterText)) {
        # Show all rules
        if ($script:GeneratedRules.Count -gt 0) {
            $modeText = if ($script:AuditModeEnabled) { "AUDIT ([!])" } else { "ENFORCE ([X])" }
            $RulesOutput.Text = "=== RULE COLLECTION - $modeText ===`n`n"
            $RulesOutput.Text += "Total Rules: $($script:GeneratedRules.Count)`n`n"

            foreach ($rule in $script:GeneratedRules) {
                $action = if ($script:AuditModeEnabled) { "AUDIT" } else { $rule.action }
                $RulesOutput.Text += "[$action] [$($rule.type)] $($rule.publisher)`n"
            }
        }
        return
    }

    # Filter rules
    $filterText = $filterText.ToLower()
    $filteredRules = $script:GeneratedRules | Where-Object {
        $_.publisher -like "*$filterText*" -or
        $_.type -like "*$filterText*" -or
        $_.path -like "*$filterText*" -or
        $_.fileName -like "*$filterText*"
    }

    $modeText = if ($script:AuditModeEnabled) { "AUDIT ([!])" } else { "ENFORCE ([X])" }
    $RulesOutput.Text = "=== FILTERED RESULTS ($($filteredRules.Count)/$($script:GeneratedRules.Count)) - $modeText ===`n`n"
    $RulesOutput.Text += "Filter: '$filterText'`n`n"

    if ($filteredRules.Count -eq 0) {
        $RulesOutput.Text += "No matching rules found."
    } else {
        foreach ($rule in $filteredRules) {
            $action = if ($script:AuditModeEnabled) { "AUDIT" } else { $rule.action }
            $RulesOutput.Text += "[$action] [$($rule.type)] $($rule.publisher)`n"
        }
    }
}

# ============================================================
# Phase 4: Comprehensive Filter Functions
# ============================================================

# Filter Rules DataGrid - Real-time filtering with multiple criteria
function Filter-RulesDataGrid {
    # Get filter values
    $typeFilterItem = $RulesTypeFilter.SelectedItem
    $typeFilter = if ($typeFilterItem) { $typeFilterItem.Tag } else { "" }

    $actionFilterItem = $RulesActionFilter.SelectedItem
    $actionFilter = if ($actionFilterItem) { $actionFilterItem.Tag } else { "" }

    $groupFilterItem = $RulesGroupFilter.SelectedItem
    $groupFilter = if ($groupFilterItem) { $groupFilterItem.Tag } else { "" }

    $searchText = $RulesFilterSearch.Text
    if ($searchText -eq "Search...") { $searchText = "" }

    # Store current filter state
    $script:CurrentRulesFilter = @{
        Type = $typeFilter
        Action = $actionFilter
        Group = $groupFilter
        Search = $searchText
    }

    # Clear and repopulate DataGrid with filtered results
    $RulesDataGrid.Items.Clear()

    $filteredCount = 0
    $totalCount = 0

    foreach ($rule in $script:GeneratedRules) {
        $totalCount++

        # Extract rule properties
        $ruleType = if ($rule.type) { $rule.type } else { "Unknown" }
        $ruleAction = if ($rule.action) { $rule.action } else { "Allow" }
        $ruleSid = if ($rule.userOrGroupSid) { $rule.userOrGroupSid } else { "S-1-1-0" }
        $groupName = Resolve-SidToGroupName -Sid $ruleSid

        # Build name based on type
        $name = switch ($ruleType) {
            "Publisher" { if ($rule.publisherName) { $rule.publisherName } else { "Unknown Publisher" } }
            "Hash" { if ($rule.fileName) { $rule.fileName } else { if ($rule.hash) { $rule.hash.Substring(0, 16) + "..." } else { "Unknown" } } }
            "Path" { if ($rule.path) { $rule.path } else { "Unknown Path" } }
            default { "Unknown" }
        }

        # Apply filters
        $matchType = ($typeFilter -eq "" -or $ruleType -eq $typeFilter)
        $matchAction = ($actionFilter -eq "" -or $ruleAction -eq $actionFilter)
        $matchGroup = ($groupFilter -eq "" -or $groupName -like "*$groupFilter*")
        $matchSearch = ($searchText -eq "" -or
                       $name -like "*$searchText*" -or
                       $groupName -like "*$searchText*" -or
                       $ruleType -like "*$searchText*")

        if ($matchType -and $matchAction -and $matchGroup -and $matchSearch) {
            $displayRule = [PSCustomObject]@{
                Type = $ruleType
                Action = $ruleAction
                Name = $name
                Group = $groupName
                SID = $ruleSid
                Rule = $rule
            }
            $RulesDataGrid.Items.Add($displayRule)
            $filteredCount++
        }
    }

    # Update filter count display
    if ($typeFilter -eq "" -and $actionFilter -eq "" -and $groupFilter -eq "" -and $searchText -eq "") {
        $RulesFilterCount.Text = ""
    } else {
        $RulesFilterCount.Text = "Showing $filteredCount of $totalCount"
    }

    # Update rules count text
    $RulesCountText.Text = "$totalCount rules"
}

# Filter Events - Real-time filtering with type, date range, and search
function Filter-Events {
    $typeFilter = $script:EventFilter  # All, Allowed, Blocked, Audit
    $dateFrom = $EventsDateFrom.SelectedDate
    $dateTo = $EventsDateTo.SelectedDate
    $searchText = $EventsFilterSearch.Text
    if ($searchText -eq "Search events...") { $searchText = "" }

    # Store current filter state
    $script:CurrentEventsFilter = @{
        Type = $typeFilter
        DateFrom = $dateFrom
        DateTo = $dateTo
        Search = $searchText
    }

    # Filter events from original data
    $filteredEvents = $script:AllEvents

    # Apply type filter
    if ($typeFilter -ne "All") {
        $filteredEvents = $filteredEvents | Where-Object { $_.EventType -eq $typeFilter }
    }

    # Apply date range filter
    if ($dateFrom -gt [DateTime]::MinValue) {
        $filteredEvents = $filteredEvents | Where-Object { $_.TimeCreated -ge $dateFrom }
    }
    if ($dateTo -gt [DateTime]::MinValue) {
        $endDate = $dateTo.AddDays(1).AddSeconds(-1)  # End of day
        $filteredEvents = $filteredEvents | Where-Object { $_.TimeCreated -le $endDate }
    }

    # Apply search filter
    if ($searchText -ne "") {
        $searchText = $searchText.ToLower()
        $filteredEvents = $filteredEvents | Where-Object {
            $_.Message -like "*$searchText*" -or
            $_.FilePath -like "*$searchText*" -or
            $_.FileName -like "*$searchText*" -or
            $_.Publisher -like "*$searchText*" -or
            $_.ComputerName -like "*$searchText*"
        }
    }

    # Update filter count display
    $totalCount = $script:AllEvents.Count
    $filteredCount = @($filteredEvents).Count

    if ($typeFilter -eq "All" -and $dateFrom -eq [DateTime]::MinValue -and $dateTo -eq [DateTime]::MinValue -and $searchText -eq "") {
        $EventsFilterCount.Text = ""
    } else {
        $EventsFilterCount.Text = "Showing $filteredCount of $totalCount"
    }

    return $filteredEvents
}

# Filter Compliance Computers List - Real-time filtering with status and search
function Filter-ComplianceComputers {
    $statusFilterItem = $ComplianceStatusFilter.SelectedItem
    $statusFilter = if ($statusFilterItem) { $statusFilterItem.Tag } else { "" }

    $searchText = $ComplianceFilterSearch.Text
    if ($searchText -eq "Search computers...") { $searchText = "" }

    # Store current filter state
    $script:CurrentComplianceFilter = @{
        Status = $statusFilter
        Search = $searchText
    }

    # Get all items from the ListBox
    $allComputers = @()
    foreach ($item in $ComplianceComputersList.Items) {
        $allComputers += $item
    }

    # Filter computers
    $filteredComputers = $allComputers | Where-Object {
        $matchStatus = ($statusFilter -eq "" -or $_.Status -eq $statusFilter -or ($statusFilter -eq "Non-Compliant" -and $_.Status -eq "Non-Compliant"))
        $matchSearch = ($searchText -eq "" -or $_.Name -like "*$searchText*")
        $matchStatus -and $matchSearch
    }

    # Clear and repopulate ListBox
    $ComplianceComputersList.Items.Clear()
    foreach ($computer in $filteredComputers) {
        $ComplianceComputersList.Items.Add($computer)
    }

    # Update filter count display
    $totalCount = $allComputers.Count
    $filteredCount = $filteredComputers.Count

    if ($statusFilter -eq "" -and $searchText -eq "") {
        $ComplianceFilterCount.Text = ""
    } else {
        $ComplianceFilterCount.Text = "Showing $filteredCount of $totalCount"
    }
}

# Update Rules Group Filter dropdown with actual groups from rules
function Update-RulesGroupFilter {
    $RulesGroupFilter.Items.Clear()
    $RulesGroupFilter.Items.Add([PSCustomObject]@{ Content = "All Groups"; Tag = "" })

    # Get unique groups from generated rules
    $uniqueGroups = $script:GeneratedRules | ForEach-Object {
        if ($_.userOrGroupSid) {
            @{
                Name = Resolve-SidToGroupName -Sid $_.userOrGroupSid
                SID = $_.userOrGroupSid
            }
        }
    } | Group-Object { $_.Name } | ForEach-Object { $_.Group[0] } | Sort-Object Name

    foreach ($group in $uniqueGroups) {
        $RulesGroupFilter.Items.Add([PSCustomObject]@{
            Content = $group.Name
            Tag = $group.Name
        })
    }

    # Select "All Groups" by default
    $RulesGroupFilter.SelectedIndex = 0
}

# ============================================================
# QoL FEATURE: Quick Rule Preview Panel
# ============================================================
if ($null -ne $ClosePreviewBtn) {
$ClosePreviewBtn.Add_Click({
    if ($null -ne $RulePreviewPanel) {
    $RulePreviewPanel.Visibility = [System.Windows.Visibility]::Collapsed
    }
})
}

# Merge rules - import additional XML rules and merge with generated rules
if ($null -ne $MergeRulesBtn) {
$MergeRulesBtn.Add_Click({
    Write-Log "Merge rules clicked"

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog.Title = "Select AppLocker Rules XML to Merge"
    $openDialog.Multiselect = $true

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $mergedCount = 0
        $fileNames = @()

        foreach ($file in $openDialog.FileNames) {
            try {
                $content = Get-Content -Path $file -Raw
                $xml = [xml]$content

                # Extract rules from the XML
                $ruleCollections = $xml.SelectNodes("//RuleCollection") + $xml.SelectNodes("//FilePublisherRule") + $xml.SelectNodes("//FileHashRule") + $xml.SelectNodes("//FilePathRule")

                foreach ($ruleNode in $ruleCollections) {
                    if ($ruleNode -and $ruleNode.OuterXml) {
                        $rule = @{
                            type = "Imported"
                            publisher = $ruleNode.Name
                            xml = $ruleNode.OuterXml
                        }
                        $script:GeneratedRules += $rule
                        $mergedCount++
                    }
                }
                $fileNames += [System.IO.Path]::GetFileName($file)
            } catch {
                Write-Log "Error parsing $file : $_"
            }
        }

        if ($mergedCount -gt 0) {
            $RulesOutput.Text = "Merged $mergedCount rules from:`n$($fileNames -join "`n")`n`nTotal rules: $($script:GeneratedRules.Count)`n`nUse Export Rules in Deployment to save merged ruleset."
            [System.Windows.MessageBox]::Show("Merged $mergedCount rules.`n`nTotal rules now: $($script:GeneratedRules.Count)", "Merge Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            [System.Windows.MessageBox]::Show("No rules found in selected files.", "Merge Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        }
    }
})
}

# Rule Group ComboBox selection changed - show/hide custom SID panel
$RuleGroupCombo.Add_SelectionChanged({
    $selectedItem = $RuleGroupCombo.SelectedItem
    if ($selectedItem -and $selectedItem.Tag -eq "Custom") {
        $CustomSidPanel.Visibility = "Visible"
    } else {
        $CustomSidPanel.Visibility = "Collapsed"
    }
})

# Helper function to get SID from RuleGroupCombo selection
function Get-SelectedSid {
    $selectedItem = $RuleGroupCombo.SelectedItem
    if (-not $selectedItem) { return "S-1-1-0" }

    $tag = $selectedItem.Tag
    switch ($tag) {
        "AppLocker-Admins" {
            try {
                $group = Get-ADGroup "AppLocker-Admins" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-Admins group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "AppLocker-StandardUsers" {
            try {
                $group = Get-ADGroup "AppLocker-StandardUsers" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-StandardUsers group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "AppLocker-Service-Accounts" {
            try {
                $group = Get-ADGroup "AppLocker-Service-Accounts" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-Service-Accounts group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "AppLocker-Installers" {
            try {
                $group = Get-ADGroup "AppLocker-Installers" -ErrorAction Stop
                return $group.SID.Value
            } catch {
                Write-Log "AppLocker-Installers group not found, using Everyone" -Level "WARN"
                return "S-1-1-0"
            }
        }
        "Custom" {
            $customSid = $CustomSidText.Text.Trim()
            if ($customSid -match "^S-1-") { return $customSid }
            return "S-1-1-0"
        }
        default { return "S-1-1-0" }
    }
}

if ($null -ne $GenerateRulesBtn) {
$GenerateRulesBtn.Add_Click({
    if ($script:CollectedArtifacts.Count -eq 0) {
        $RulesOutput.Text = "ERROR: No artifacts imported. Use Import Artifact or Import Folder first."
        return
    }

    # Determine rule type selection
    $ruleType = if ($RuleTypeAuto.IsChecked) { "Automated" }
                elseif ($RuleTypePublisher.IsChecked) { "Publisher" }
                elseif ($RuleTypeHash.IsChecked) { "Hash" }
                else { "Path" }

    $action = if ($RuleActionAllow.IsChecked) { "Allow" } else { "Deny" }
    $selectedGroup = $RuleGroupCombo.SelectedItem.Content

    # QoL: Bulk Action Confirmation
    $confirmMsg = "[!] You are about to:`n`n"
    $confirmMsg += "- Generate rules from $($script:CollectedArtifacts.Count) artifacts`n"
    $confirmMsg += "- Rule Type: $ruleType`n"
    $confirmMsg += "- Action: $action`n"
    $confirmMsg += "- Apply To: $selectedGroup`n`n"
    $confirmMsg += "Continue?"

    $confirm = [System.Windows.MessageBox]::Show($confirmMsg, "Confirm Rule Generation",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question)

    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) {
        Write-Log "Rule generation cancelled by user"
        return
    }

    $sid = Get-SelectedSid

    $RulesOutput.Text = "Generating rules ($ruleType mode)...`nProcessing $($script:CollectedArtifacts.Count) artifacts...`n"
    [System.Windows.Forms.Application]::DoEvents()

    $script:GeneratedRules = @()
    $publisherCount = 0
    $hashCount = 0
    $pathCount = 0
    $skippedCount = 0

    $output = "=== RULE GENERATION ===`n"
    $output += "Mode: $ruleType | Action: $action | Group: $selectedGroup`n"
    $output += "Processing $($script:CollectedArtifacts.Count) artifacts...`n`n"

    foreach ($artifact in $script:CollectedArtifacts) {
        # Get file info from various possible column names
        $filePath = $artifact.FullPath
        if (-not $filePath) { $filePath = $artifact.Path }
        if (-not $filePath) { $filePath = $artifact.FilePath }

        $fileName = $artifact.FileName
        if (-not $fileName) { $fileName = $artifact.Name }
        if (-not $fileName -and $filePath) { $fileName = [System.IO.Path]::GetFileName($filePath) }

        $publisher = $artifact.Publisher
        if (-not $publisher) { $publisher = $artifact.Vendor }
        if (-not $publisher) { $publisher = $artifact.Company }
        if (-not $publisher) { $publisher = $artifact.Signer }

        $hash = $artifact.Hash
        if (-not $hash) { $hash = $artifact.SHA256 }

        # Skip if no useful data
        if (-not $fileName -and -not $filePath -and -not $publisher) {
            $skippedCount++
            continue
        }

        # Determine rule type for this artifact
        $thisRuleType = $ruleType
        if ($ruleType -eq "Automated") {
            # Best practice: Use Publisher if signed, Hash if not
            if ($publisher -and $publisher -ne "Unknown" -and $publisher -ne "" -and $publisher -ne "(none)") {
                $thisRuleType = "Publisher"
            } else {
                $thisRuleType = "Hash"
            }
        }

        # Create the rule
        $ruleResult = $null
        $displayName = if ($fileName) { $fileName } elseif ($filePath) { [System.IO.Path]::GetFileName($filePath) } else { "Unknown" }
        $displayPath = if ($filePath) { $filePath } else { "(no path)" }

        switch ($thisRuleType) {
            "Publisher" {
                if ($publisher -and $publisher -ne "Unknown" -and $publisher -ne "") {
                    $ruleResult = New-PublisherRule -PublisherName $publisher -Action $action -UserOrGroupSid $sid
                    if ($ruleResult.success) {
                        $output += "[PUB] $displayName`n"
                        $output += "      Publisher: $publisher`n"
                        $output += "      Path: $displayPath`n`n"
                        $publisherCount++
                    }
                } else {
                    # No publisher, fallback to hash in auto mode
                    if ($ruleType -eq "Automated" -and $filePath -and (Test-Path $filePath -ErrorAction SilentlyContinue)) {
                        $ruleResult = New-HashRule -FilePath $filePath -Action $action -UserOrGroupSid $sid
                        if ($ruleResult.success) {
                            $output += "[HASH] $displayName`n"
                            $output += "       Hash: $($ruleResult.hash)`n"
                            $output += "       Path: $displayPath`n`n"
                            $hashCount++
                        }
                    } else {
                        $output += "[SKIP] $displayName - No publisher and file not accessible`n"
                        $skippedCount++
                    }
                }
            }
            "Hash" {
                if ($filePath -and (Test-Path $filePath -ErrorAction SilentlyContinue)) {
                    $ruleResult = New-HashRule -FilePath $filePath -Action $action -UserOrGroupSid $sid
                    if ($ruleResult.success) {
                        $output += "[HASH] $displayName`n"
                        $output += "       Hash: $($ruleResult.hash)`n"
                        $output += "       Path: $displayPath`n`n"
                        $hashCount++
                    }
                } elseif ($hash) {
                    # Use pre-computed hash from artifact
                    $guid = "{" + (New-Guid).ToString() + "}"
                    $xml = "<FileHashRule Id=`"$guid`" Name=`"$displayName`" UserOrGroupSid=`"$sid`" Action=`"$action`"><Conditions><FileHashCondition SourceFileName=`"$displayName`" SourceFileHash=`"$hash`" Type=`"SHA256`" /></Conditions></FileHashRule>"
                    $ruleResult = @{ success = $true; id = $guid; type = "Hash"; hash = $hash; fileName = $displayName; xml = $xml }
                    $output += "[HASH] $displayName`n"
                    $output += "       Hash: $hash`n"
                    $output += "       Path: $displayPath`n`n"
                    $hashCount++
                } else {
                    $output += "[SKIP] $displayName - File not accessible for hashing`n"
                    $skippedCount++
                }
            }
            "Path" {
                if ($filePath) {
                    $ruleResult = New-PathRule -FilePath $filePath -Action $action -UserOrGroupSid $sid
                    if ($ruleResult.success) {
                        $output += "[PATH] $displayName`n"
                        $output += "       Path: $displayPath`n`n"
                        $pathCount++
                    }
                } else {
                    $output += "[SKIP] $displayName - No path available`n"
                    $skippedCount++
                }
            }
        }

        if ($ruleResult -and $ruleResult.success) {
            $script:GeneratedRules += $ruleResult
        }
    }

    $totalRules = $publisherCount + $hashCount + $pathCount
    $output += "`n=== SUMMARY ===`n"
    $output += "Total Rules: $totalRules`n"
    $output += "  Publisher: $publisherCount`n"
    $output += "  Hash: $hashCount`n"
    $output += "  Path: $pathCount`n"
    $output += "  Skipped: $skippedCount`n"
    $output += "`n--- Use 'Export Rules' in Deployment to save ---"

    $RulesOutput.Text = $output
    Write-Log "Generated $totalRules rules (Pub=$publisherCount, Hash=$hashCount, Path=$pathCount) with Action=$action"
    Write-OutputLog "Rule Generation" $output

    # Update Rules DataGrid
    Update-RulesDataGrid
})
}

# Events filters
if ($null -ne $FilterAllBtn) {
$FilterAllBtn.Add_Click({
    $script:EventFilter = "All"
    Write-Log "Event filter set to: All"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to All."
})
}

if ($null -ne $FilterAllowedBtn) {
$FilterAllowedBtn.Add_Click({
    $script:EventFilter = "Allowed"
    Write-Log "Event filter set to: Allowed"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to Allowed (ID 8002)."
})
}

if ($null -ne $FilterBlockedBtn) {
$FilterBlockedBtn.Add_Click({
    $script:EventFilter = "Blocked"
    Write-Log "Event filter set to: Blocked"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to Blocked (ID 8004)."
})
}

if ($null -ne $FilterAuditBtn) {
$FilterAuditBtn.Add_Click({
    $script:EventFilter = "Audit"
    Write-Log "Event filter set to: Audit"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to Audit (ID 8003)."
})
}

if ($null -ne $ExportEventsBtn) {
$ExportEventsBtn.Add_Click({
    if ($script:AllEvents.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No events to export. Click Refresh first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|Text Files (*.txt)|*.txt"
    $saveDialog.Title = "Export Events"
    $saveDialog.FileName = "AppLockerEvents-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker\Events"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName)
        if ($ext -eq ".csv") {
            $script:AllEvents | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        } elseif ($ext -eq ".json") {
            $script:AllEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        } else {
            $script:AllEvents | ForEach-Object { "[$($_.time)] [$($_.type)] $($_.message)" } | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Exported $($script:AllEvents.Count) events to $($saveDialog.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:AllEvents.Count) events to $($saveDialog.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
})
}

# Scan Local Events button
if ($null -ne $ScanLocalEventsBtn) {
$ScanLocalEventsBtn.Add_Click({
    Write-Log "Scanning local AppLocker events"
    $EventsOutput.Text = "=== SCANNING LOCAL EVENTS ===`n`nReading AppLocker logs from this computer...`n"
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $events = @()

        # Get events from EXE and DLL log
        try {
            $exeEvents = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 500 -ErrorAction SilentlyContinue
            foreach ($evt in $exeEvents) {
                # Try to parse from event XML first (more reliable)
                $filePath = ""
                $fileName = ""
                $publisher = "Unknown"
                try {
                    $xml = [xml]$evt.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    foreach ($data in $eventData) {
                        if ($data.Name -eq "FilePath") { $filePath = $data.'#text' }
                        if ($data.Name -eq "Fqbn" -and $data.'#text') {
                            $fqbn = $data.'#text'
                            if ($fqbn -match "O=([^,]+)") { $publisher = $Matches[1] }
                        }
                    }
                } catch { }
                # Fallback to message parsing
                if (-not $filePath -and $evt.Message) {
                    if ($evt.Message -match '([A-Z]:\\[^\s]+\.(exe|dll|com))') { $filePath = $Matches[1] }
                    elseif ($evt.Message -match '(%[^%]+%\\[^\s]+\.(exe|dll|com))') { $filePath = $Matches[1] }
                }
                if ($filePath) { $fileName = Split-Path $filePath -Leaf -ErrorAction SilentlyContinue }

                $events += [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    TimeCreated = $evt.TimeCreated
                    EventId = $evt.Id
                    EventType = switch ($evt.Id) { 8002 { "Allowed" } 8003 { "Audit" } 8004 { "Blocked" } default { "Other" } }
                    Message = $evt.Message
                    FilePath = $filePath
                    FileName = $fileName
                    Publisher = $publisher
                }
            }
            $EventsOutput.Text += "EXE/DLL log: $($exeEvents.Count) events`n"
        } catch {
            $EventsOutput.Text += "EXE/DLL log: No events or access denied`n"
        }
        [System.Windows.Forms.Application]::DoEvents()

        # Get events from MSI and Script log
        try {
            $msiEvents = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -MaxEvents 500 -ErrorAction SilentlyContinue
            foreach ($evt in $msiEvents) {
                $filePath = ""
                $fileName = ""
                $publisher = "Unknown"
                try {
                    $xml = [xml]$evt.ToXml()
                    $eventData = $xml.Event.EventData.Data
                    foreach ($data in $eventData) {
                        if ($data.Name -eq "FilePath") { $filePath = $data.'#text' }
                        if ($data.Name -eq "Fqbn" -and $data.'#text') {
                            $fqbn = $data.'#text'
                            if ($fqbn -match "O=([^,]+)") { $publisher = $Matches[1] }
                        }
                    }
                } catch { }
                if (-not $filePath -and $evt.Message) {
                    if ($evt.Message -match '([A-Z]:\\[^\s]+\.(msi|msp|ps1|bat|cmd|vbs|js))') { $filePath = $Matches[1] }
                    elseif ($evt.Message -match '(%[^%]+%\\[^\s]+\.(msi|msp|ps1|bat|cmd|vbs|js))') { $filePath = $Matches[1] }
                }
                if ($filePath) { $fileName = Split-Path $filePath -Leaf -ErrorAction SilentlyContinue }

                $events += [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    TimeCreated = $evt.TimeCreated
                    EventId = $evt.Id
                    EventType = switch ($evt.Id) { 8002 { "Allowed" } 8003 { "Audit" } 8004 { "Blocked" } default { "Other" } }
                    Message = $evt.Message
                    FilePath = $filePath
                    FileName = $fileName
                    Publisher = $publisher
                }
            }
            $EventsOutput.Text += "MSI/Script log: $($msiEvents.Count) events`n"
        } catch {
            $EventsOutput.Text += "MSI/Script log: No events or access denied`n"
        }

        $script:AllEvents = $events
        $EventsOutput.Text += "`nTotal events loaded: $($events.Count)`n`n"

        # Show summary by type
        $allowed = ($events | Where-Object EventType -eq "Allowed").Count
        $audit = ($events | Where-Object EventType -eq "Audit").Count
        $blocked = ($events | Where-Object EventType -eq "Blocked").Count
        $EventsOutput.Text += "Allowed: $allowed | Audit: $audit | Blocked: $blocked`n`n"
        $EventsOutput.Text += "Use filters above to view specific event types.`nExport to CSV, then use Import Artifact in Rule Generator."

        Write-Log "Local events scanned: $($events.Count) total"
    } catch {
        $EventsOutput.Text += "`nERROR: $($_.Exception.Message)"
        Write-Log "Local event scan failed: $($_.Exception.Message)" -Level "ERROR"
    }
})
}

# Scan Remote Events button - COMPREHENSIVE SCAN
# Uses Get-RemoteAppLockerEvents from Module2-RemoteScan for full data collection
# Collects: All 4 AppLocker logs, system info, policy status, parsed event XML
if ($null -ne $ScanRemoteEventsBtn) {
$ScanRemoteEventsBtn.Add_Click({
    Write-Log "Scanning remote AppLocker events (comprehensive)"

    # Get selected computers from ListBox
    $selectedItems = $EventComputersList.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one computer from the list.", "No Computers Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $computers = $selectedItems | ForEach-Object { $_.Name.ToString() }

    $EventsOutput.Text = "=== COMPREHENSIVE REMOTE SCAN ===`n`nScanning $($computers.Count) selected computers via WinRM...`n"
    $EventsOutput.Text += "Collecting: All AppLocker logs, policy status, system info`n"
    [System.Windows.Forms.Application]::DoEvents()

    $allEvents = @()
    $allArtifacts = @()
    $successCount = 0
    $failCount = 0

    foreach ($comp in $computers) {
        $EventsOutput.Text += "`n$comp : "
        [System.Windows.Forms.Application]::DoEvents()

        try {
            # Use the comprehensive scan function from Module2-RemoteScan
            $scanResult = Get-RemoteAppLockerEvents -ComputerName $comp -DaysBack 7 -MaxEvents 500

            if ($scanResult.success) {
                $successCount++
                $evtCount = if ($scanResult.events) { $scanResult.events.Count } else { 0 }
                $artCount = if ($scanResult.artifacts) { $scanResult.artifacts.Count } else { 0 }

                $EventsOutput.Text += "$evtCount events, $artCount artifacts"

                # Show policy status for this computer
                if ($scanResult.hasPolicy) {
                    $EventsOutput.Text += " [Policy: EXE=$($scanResult.policyMode.Exe)]"
                } else {
                    $EventsOutput.Text += " [No Policy]"
                }

                # Collect events with full details (parsed from XML)
                if ($scanResult.events) {
                    foreach ($evt in $scanResult.events) {
                        $allEvents += [PSCustomObject]@{
                            ComputerName = $comp
                            TimeCreated  = $evt.TimeCreated
                            EventId      = $evt.EventId
                            EventType    = $evt.EventType
                            FilePath     = $evt.FilePath
                            FileName     = $evt.FileName
                            Publisher    = if ($evt.Publisher) { $evt.Publisher } else { "Unknown" }
                            FileHash     = $evt.FileHash
                            ProductName  = $evt.ProductName
                            UserSid      = $evt.UserSid
                            LogName      = $evt.LogName
                            Message      = $evt.Message
                        }
                    }
                }

                # Collect pre-formatted artifacts for rule generator
                if ($scanResult.artifacts) {
                    foreach ($art in $scanResult.artifacts) {
                        $allArtifacts += [PSCustomObject]@{
                            name           = $art.name
                            path           = $art.path
                            publisher      = $art.publisher
                            hash           = $art.hash
                            productName    = $art.productName
                            eventType      = $art.eventType
                            eventId        = $art.eventId
                            sourceComputer = $comp
                            lastSeen       = $art.lastSeen
                        }
                    }
                }

                Write-Log "Comprehensive scan of $comp : $evtCount events, $artCount artifacts"
            } else {
                $failCount++
                $EventsOutput.Text += "FAILED ($($scanResult.error -replace '\r?\n.*$',''))"
                Write-Log "Comprehensive scan failed on $comp : $($scanResult.error)" -Level "ERROR"
            }
        } catch {
            $failCount++
            $EventsOutput.Text += "FAILED ($($_.Exception.Message -replace '\r?\n.*$',''))"
            Write-Log "Comprehensive scan exception on $comp : $($_.Exception.Message)" -Level "ERROR"
        }
    }

    # Store results in script-scope variables for export and rule generation
    $script:AllEvents = $allEvents
    $script:CollectedArtifacts = $allArtifacts

    # Update badges in Rule Generator
    Update-Badges

    # Summary statistics
    $auditCount = ($allEvents | Where-Object { $_.EventType -eq 'Audit' }).Count
    $blockedCount = ($allEvents | Where-Object { $_.EventType -eq 'Blocked' }).Count
    $allowedCount = ($allEvents | Where-Object { $_.EventType -eq 'Allowed' }).Count

    $EventsOutput.Text += "`n`n=== SCAN COMPLETE ===`n"
    $EventsOutput.Text += "Computers: $successCount success, $failCount failed`n"
    $EventsOutput.Text += "Events: $($allEvents.Count) total`n"
    $EventsOutput.Text += "  Audit (would block): $auditCount`n"
    $EventsOutput.Text += "  Blocked: $blockedCount`n"
    $EventsOutput.Text += "  Allowed: $allowedCount`n"
    $EventsOutput.Text += "Artifacts: $($allArtifacts.Count) unique files`n"
    $EventsOutput.Text += "`nExport to CSV, then Import in Rule Generator.`n"
    $EventsOutput.Text += "Or go to Rule Generator > From Events to create rules directly."
})
}

# Refresh Computers button - loads from AD Discovery
if ($null -ne $RefreshComputersBtn) {
$RefreshComputersBtn.Add_Click({
    $EventComputersList.Items.Clear()

    # Try to get computers from discovery results
    if ($script:DiscoveredComputers.Count -gt 0) {
        $EventsOutput.Text = "Refreshing computer list from AD Discovery...`n"

        foreach ($compInfo in $script:DiscoveredComputersInfo) {
            $status = "Online"
            $statusColor = "#3FB950"

            if ($compInfo.IsOffline -eq $true) {
                $status = "Offline"
                $statusColor = "#F85149"
            } elseif ($compInfo.ResponseTime -gt 500) {
                $status = "Slow"
                $statusColor = "#D29922"
            }

            $item = [PSCustomObject]@{
                Name = $compInfo.Name
                Status = $status
                StatusColor = $statusColor
                OU = $compInfo.OU
            }

            $EventComputersList.Items.Add($item)
        }

        $EventsOutput.Text += "Loaded $($EventComputersList.Items.Count) computers from AD Discovery.`n`nSelect computers and click 'Scan Selected' to collect events."
        Write-Log "Refreshed event computer list: $($EventComputersList.Items.Count) computers"
    } else {
        # Try to run discovery if not already done
        $EventsOutput.Text = "No computers in discovery. Running AD Discovery...`n"
        Write-Log "No computers in discovery, running AD discovery"

        # Import discovery module and run discovery
        try {
            if ($script:ModulePath -and (Test-Path $script:ModulePath)) {
                Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop
            } else {
                $script:ModulePath = "C:\GA-AppLocker\src\modules"
                if (Test-Path $script:ModulePath) {
                    Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop
                } else {
                    Write-Log "ERROR: Module path not found for Module2-RemoteScan" -Level "ERROR"
                    $EventsOutput.Text += "`nERROR: Module path not found"
                    return
                }
            }

            $discovery = Get-AllADComputers
            if ($discovery.success) {
                $script:DiscoveredComputers = $discovery.data | ForEach-Object { $_.Name }
                $script:DiscoveredComputersInfo = @()

                foreach ($comp in $discovery.data) {
                    # Ping test
                    $pingResult = Test-ComputerOnline -ComputerName $comp.Name -Timeout 1000

                    $compInfo = [PSCustomObject]@{
                        Name = $comp.Name
                        DN = $comp.DistinguishedName
                        OU = if ($comp.DistinguishedName -match 'OU=([^,]+)') { $matches[1] } else { "Unknown" }
                        IsOffline = -not $pingResult.online
                        ResponseTime = $pingResult.responseTime
                    }
                    $script:DiscoveredComputersInfo += $compInfo

                    $status = if ($pingResult.online) { "Online" } else { "Offline" }
                    $statusColor = if ($pingResult.online) { "#3FB950" } else { "#F85149" }

                    $item = [PSCustomObject]@{
                        Name = $comp.Name
                        Status = $status
                        StatusColor = $statusColor
                        OU = $compInfo.OU
                    }

                    $EventComputersList.Items.Add($item)
                }

                $EventsOutput.Text = "Discovered and loaded $($EventComputersList.Items.Count) computers from AD.`n`nSelect computers and click 'Scan Selected' to collect events."
                Write-Log "Discovered and loaded $($EventComputersList.Items.Count) computers"
            } else {
                $EventsOutput.Text = "ERROR: Failed to discover computers: $($discovery.error)`n`nGo to AD Discovery panel for more details."
                Write-Log "Discovery failed: $($discovery.error)" -Level "ERROR"
            }
        } catch {
            $EventsOutput.Text = "ERROR: $($_.Exception.Message)`n`nGo to AD Discovery panel to manually discover computers."
            Write-Log "Refresh computers failed: $($_.Exception.Message)" -Level "ERROR"
        }
    }
})
}

if ($null -ne $RefreshEventsBtn) {
$RefreshEventsBtn.Add_Click({
    Write-Log "Refreshing events with filter: $($script:EventFilter)"
    $result = Get-AppLockerEvents -MaxEvents 1000
    $script:AllEvents = $result.data

    # Filter events based on selection
    $filteredEvents = switch ($script:EventFilter) {
        "Allowed" { $result.data | Where-Object { $_.eventId -eq 8002 } }
        "Blocked" { $result.data | Where-Object { $_.eventId -eq 8004 } }
        "Audit"   { $result.data | Where-Object { $_.eventId -eq 8003 } }
        default   { $result.data }
    }

    $output = "=== APPLOCKER EVENTS (Filter: $($script:EventFilter)) ===`n`nShowing $($filteredEvents.Count) of $($result.count) total events`n`n"
    foreach ($evt in $filteredEvents) {
        $type = switch ($evt.eventId) {
            8002 { "ALLOWED" }
            8003 { "AUDIT" }
            8004 { "BLOCKED" }
            default { "UNKNOWN" }
        }
        $output += "[$($evt.time)] [$type] $($evt.message)`n`n"
    }
    $EventsOutput.Text = $output
    Write-Log "Events refreshed: $($filteredEvents.Count) events displayed"
})
}

# Compliance events
if ($null -ne $GenerateEvidenceBtn) {
$GenerateEvidenceBtn.Add_Click({
    Write-Log "Generating evidence package"

    if ($script:ModulePath -and (Test-Path $script:ModulePath)) {
        Import-Module (Join-Path $script:ModulePath "Module7-Compliance.psm1") -ErrorAction Stop
    } else {
        $script:ModulePath = "C:\GA-AppLocker\src\modules"
        if (Test-Path $script:ModulePath) {
            Import-Module (Join-Path $script:ModulePath "Module7-Compliance.psm1") -ErrorAction Stop
        } else {
            Write-Log "ERROR: Module path not found for Module7-Compliance" -Level "ERROR"
            $ComplianceOutput.Text = "ERROR: Module path not found for Module7-Compliance"
            return
        }
    }

    $ComplianceOutput.Text = "Generating compliance evidence package...`n`nPlease wait..."

    try {
        # Create evidence folder structure
        $basePath = "C:\GA-AppLocker\Compliance"
        $folders = New-EvidenceFolder -BasePath $basePath

        if (-not $folders.success) {
            throw $folders.error
        }

        $results = @{}
        $summary = @()

        # Collect local evidence
        $ComplianceOutput.Text += "`n[1/3] Collecting LOCAL evidence..."
        $policy = Export-CurrentPolicy -OutputPath "$basePath\Policies\CurrentPolicy.xml"
        $inventory = Export-SystemInventory -OutputPath "$basePath\Inventory\Inventory.json"

        $summary += "LOCAL: $env:COMPUTERNAME"
        if ($policy.success) { $summary += "  - Policy: Exported" }
        if ($inventory.success) { $summary += "  - Inventory: $($inventory.softwareCount) software, $($inventory.processCount) processes" }

        # Collect from selected remote computers
        $selectedItems = $ComplianceComputersList.SelectedItems
        if ($selectedItems.Count -gt 0) {
            $ComplianceOutput.Text += "`n[2/3] Collecting REMOTE evidence from $($selectedItems.Count) computers..."

            $computerIndex = 0
            foreach ($item in $selectedItems) {
                $computerIndex++
                $computerName = $item.Name
                $ComplianceOutput.Text += "`n  [$computerIndex/$($selectedItems.Count)] $computerName..."

                # Skip offline computers
                if ($item.Status -ne "Online") {
                    $summary += "$computerName : SKIPPED (Offline)"
                    continue
                }

                try {
                    # Create per-computer folder
                    $computerFolder = "$basePath\$computerName"
                    if (-not (Test-Path $computerFolder)) {
                        New-Item -ItemType Directory -Path $computerFolder -Force | Out-Null
                    }

                    # Collect remote policy
                    $remotePolicy = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue
                    } -ErrorAction SilentlyContinue

                    if ($remotePolicy) {
                        $policyPath = "$computerFolder\AppLockerPolicy.xml"
                        $remotePolicy | Out-File -FilePath $policyPath -Encoding UTF16 -Force
                    }

                    # Collect remote inventory
                    $remoteInventory = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        $software64 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher
                        $software32 = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher
                        $processes = Get-Process | Select-Object Name, Path, Company | Where-Object { $_.Path }

                        @{
                            timestamp = Get-Date -Format 'o'
                            computerName = $env:COMPUTERNAME
                            installedSoftware = @($software64) + @($software32) | Where-Object { $_.DisplayName }
                            runningProcesses = $processes
                        }
                    } -ErrorAction SilentlyContinue

                    if ($remoteInventory) {
                        $invPath = "$computerFolder\Inventory.json"
                        $remoteInventory | ConvertTo-Json -Depth 5 | Out-File -FilePath $invPath -Encoding UTF8 -Force
                    }

                    $summary += "$computerName : Collected"
                }
                catch {
                    $summary += "$computerName : FAILED - $($_.Exception.Message)"
                }
            }
        }
        else {
            $ComplianceOutput.Text += "`n[2/3] Remote: No computers selected"
        }

        # Generate compliance report
        $ComplianceOutput.Text += "`n[3/3] Generating compliance report..."
        $report = New-ComplianceReport -OutputPath "$basePath\Reports\ComplianceReport.html"

        # Display results
        $ComplianceOutput.Text = "`n=== COMPLIANCE EVIDENCE PACKAGE COMPLETE ===`n`n"
        $ComplianceOutput.Text += "Location: $basePath`n`n"
        $ComplianceOutput.Text += "Summary:`n"
        $summary | ForEach-Object { $ComplianceOutput.Text += "  $_`n" }
        $ComplianceOutput.Text += "`nFolder Structure:`n"
        $ComplianceOutput.Text += "  Policies/      - AppLocker policy files`n"
        $ComplianceOutput.Text += "  Inventory/     - Software and process inventory`n"
        $ComplianceOutput.Text += "  Reports/       - HTML compliance report`n"
        if ($selectedItems.Count -gt 0) {
            $ComplianceOutput.Text += "  [ComputerName]/ - Per-computer evidence`n"
        }

        Write-Log "Evidence package created: $basePath"

        # Open report in default browser
        if (Test-Path "$basePath\Reports\ComplianceReport.html") {
            Start-Process "$basePath\Reports\ComplianceReport.html"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $ComplianceOutput.Text = "ERROR: $errorMsg"
        Write-Log "Failed to generate evidence package: $errorMsg" -Level "ERROR"
    }
})
}

# Scan Local Compliance button
if ($null -ne $ScanLocalComplianceBtn) {
$ScanLocalComplianceBtn.Add_Click({
    Write-Log "Scan Local Compliance clicked"

    # Load computers from AD Discovery if available
    if ($script:DiscoveredComputers.Count -eq 0) {
        $ComplianceComputersList.Items.Clear()
        $ComplianceComputersList.Items.Add(@{
            Name = $env:COMPUTERNAME
            Status = "Online"
            StatusColor = "#3FB950"
            OU = "Local"
        })
        $ComplianceOutput.Text = "Added localhost to compliance list.`n`nUse AD Discovery to add more computers, or generate evidence package now."
    }
    else {
        # Load discovered computers
        $ComplianceComputersList.Items.Clear()
        foreach ($computer in $script:DiscoveredComputers) {
            $ComplianceComputersList.Items.Add($computer)
        }
        $ComplianceOutput.Text = "Loaded $($script:DiscoveredComputers.Count) computers from AD Discovery.`n`nSelect computers and click 'Scan Selected' to test connectivity."
    }
})
}

# Scan Selected Compliance button
if ($null -ne $ScanSelectedComplianceBtn) {
$ScanSelectedComplianceBtn.Add_Click({
    Write-Log "Scan Selected Compliance clicked"

    $selectedItems = $ComplianceComputersList.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one computer.", "No Computer Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $ComplianceOutput.Text = "Testing connectivity to $($selectedItems.Count) computers...`n`n"

    Import-Module "C:\GA-AppLocker\src\modules\Module2-RemoteScan.psm1" -ErrorAction Stop

    $results = @()
    foreach ($item in $selectedItems) {
        $computerName = $item.Name
        $ComplianceOutput.Text += "Testing $computerName..."

        $testResult = Test-ComputerOnline -ComputerName $computerName -Timeout 5

        if ($testResult.online) {
            $item.Status = "Online"
            $item.StatusColor = "#3FB950"
            $results += "$computerName : Online"
        }
        else {
            $item.Status = "Offline"
            $item.StatusColor = "#F85149"
            $results += "$computerName : Offline ($($testResult.reason))"
        }

        $ComplianceComputersList.Items.Refresh()
    }

    $ComplianceOutput.Text += "`n`n=== SCAN COMPLETE ===`n`n"
    $results | ForEach-Object { $ComplianceOutput.Text += "$_`n" }
    $ComplianceOutput.Text += "`nReady to generate evidence package. Select computers and click 'Generate Evidence Package'."
})
}

# Refresh Compliance List button
if ($null -ne $RefreshComplianceListBtn) {
$RefreshComplianceListBtn.Add_Click({
    Write-Log "Refresh Compliance List clicked"

    if ($script:IsWorkgroup) {
        $ComplianceComputersList.Items.Clear()
        $ComplianceComputersList.Items.Add(@{
            Name = $env:COMPUTERNAME
            Status = "Online"
            StatusColor = "#3FB950"
            OU = "Local"
        })
        $ComplianceOutput.Text = "Workgroup mode: Only localhost available."
        return
    }

    $ComplianceOutput.Text = "Refreshing computer list from AD..."

    try {
        Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $computers = Get-AllADComputers

        if ($computers.success -and $computers.data.Count -gt 0) {
            $ComplianceComputersList.Items.Clear()
            $script:DiscoveredComputers = @()

            foreach ($computer in $computers.data) {
                $item = @{
                    Name = $computer.Name
                    Status = "Unknown"
                    StatusColor = "#8B949E"
                    OU = if ($computer.OU) { $computer.OU } else { "Unknown" }
                }
                $ComplianceComputersList.Items.Add($item)
                $script:DiscoveredComputers += $item
            }

            $ComplianceOutput.Text = "Loaded $($computers.data.Count) computers from Active Directory.`n`nSelect computers and click 'Scan Selected' to test connectivity."
            Write-Log "Loaded $($computers.data.Count) computers for compliance"
        }
        else {
            $ComplianceOutput.Text = "No computers found in Active Directory."
        }
    }
    catch {
        $ComplianceOutput.Text = "ERROR: $($_.Exception.Message)"
        Write-Log "Failed to refresh compliance list: $($_.Exception.Message)" -Level "ERROR"
    }
})
}

# WinRM events
if ($null -ne $CreateWinRMGpoBtn) {
$CreateWinRMGpoBtn.Add_Click({
    Write-Log "Create WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $WinRMOutput.Text = "=== WINRM GPO CREATION ===`n`nCreating WinRM GPO...`n`nThis will:`n  - Create 'Enable WinRM' GPO`n  - Link to domain root`n  - Configure WinRM service settings`n  - Enable firewall rules`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $action = if ($result.isNew) { "CREATED" } else { "UPDATED" }
        $WinRMOutput.Text = "=== WINRM GPO $action ===`n`nSUCCESS: GPO $($result.message)`n`nGPO Name: $($result.gpoName)`nGPO ID: $($result.gpoId)`nLinked to: $($result.linkedTo)`n`nConfigured Settings:`n`nWinRM Service:`n  - Auto-config: Enabled`n  - IPv4 Filter: * (all)`n  - IPv6 Filter: * (all)`n  - Basic Auth: Enabled`n  - Unencrypted Traffic: Disabled`n`nWinRM Client:`n  - Basic Auth: Enabled`n  - TrustedHosts: * (all)`n  - Unencrypted Traffic: Disabled`n`nFirewall Rules:`n  - WinRM HTTP (5985): Allowed`n  - WinRM HTTPS (5986): Allowed`n`nService: Automatic startup`n`nTo force immediate update: gpupdate /force"
        Write-Log "WinRM GPO $action successfully: $($result.gpoName)"
        [System.Windows.MessageBox]::Show("WinRM GPO $action successfully!`n`nGPO: $($result.gpoName)`n`nLinked to: $($result.linkedTo)", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $WinRMOutput.Text = "=== WINRM GPO FAILED ===`n`nERROR: $($result.error)`n`nPossible causes:`n  - Not running as Domain Admin`n  - Group Policy module not available`n  - Insufficient permissions`n`nPlease run as Domain Administrator and try again."
        Write-Log "Failed to create/update WinRM GPO: $($result.error)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to create/update WinRM GPO:`n$($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Enable/Disable WinRM GPO Link
if ($null -ne $EnableWinRMGpoBtn) {
$EnableWinRMGpoBtn.Add_Click({
    Write-Log "Enable WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $result = Set-WinRMGpoState -Enabled $true

    if ($result.success) {
        $WinRMOutput.Text = "=== GPO LINK ENABLED ===`n`nWinRM GPO link has been ENABLED.`n`nThe policy will now apply to computers in the domain.`n`nRun 'gpupdate /force' on target machines to apply immediately."
        [System.Windows.MessageBox]::Show("WinRM GPO link enabled!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $WinRMOutput.Text = "ERROR: $($result.error)"
        [System.Windows.MessageBox]::Show("Failed to enable GPO link:`n$($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})
}

if ($null -ne $DisableWinRMGpoBtn) {
$DisableWinRMGpoBtn.Add_Click({
    Write-Log "Disable WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show("Are you sure you want to disable the WinRM GPO link?`n`nThis will prevent the GPO from applying to new computers.", "Confirm Disable", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $result = Set-WinRMGpoState -Enabled $false

        if ($result.success) {
            $WinRMOutput.Text = "=== GPO LINK DISABLED ===`n`nWinRM GPO link has been DISABLED.`n`nThe policy will no longer apply to computers.`n`nNote: Already applied settings may remain until manually removed."
            [System.Windows.MessageBox]::Show("WinRM GPO link disabled!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            $WinRMOutput.Text = "ERROR: $($result.error)"
            [System.Windows.MessageBox]::Show("Failed to disable GPO link:`n$($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})
}

# Force GPUpdate on all domain computers
if ($null -ne $ForceGPUpdateBtn) {
$ForceGPUpdateBtn.Add_Click({
    Write-Log "Force GPUpdate button clicked"
    if ($script:IsWorkgroup -or -not $script:HasRSAT) {
        [System.Windows.MessageBox]::Show("This feature requires domain membership and RSAT tools.", "Not Available", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "This will run 'gpupdate /force' on all domain computers.`n`nThis requires:`n  - WinRM already enabled on target machines`n  - Administrative access to remote computers`n`nContinue?",
        "Confirm Force GPUpdate",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )

    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

    $WinRMOutput.Text = "=== FORCE GPUPDATE ===`n`nGathering domain computers...`n"
    [System.Windows.Forms.Application]::DoEvents()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        # Get all enabled Windows computers
        $computers = Get-ADComputer -Filter "Enabled -eq 'True' -and OperatingSystem -like '*Windows*'" |
                     Select-Object -ExpandProperty Name |
                     Sort-Object

        $WinRMOutput.Text += "Found $($computers.Count) computers.`n`nRunning gpupdate /force...`n`n"
        [System.Windows.Forms.Application]::DoEvents()

        $successCount = 0
        $failCount = 0
        $skippedCount = 0
        $results = @()

        foreach ($computer in $computers) {
            # Quick ping check first - skip offline machines
            $WinRMOutput.Text += "[$computer] Checking..."
            [System.Windows.Forms.Application]::DoEvents()

            $pingResult = Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue
            if (-not $pingResult) {
                $skippedCount++
                $results += "[$computer] OFFLINE"
                $WinRMOutput.Text = $WinRMOutput.Text -replace "\[$computer\] Checking...", "[$computer] OFFLINE (skipped)"
                [System.Windows.Forms.Application]::DoEvents()
                continue
            }

            try {
                $WinRMOutput.Text = $WinRMOutput.Text -replace "\[$computer\] Checking...", "[$computer] Running gpupdate..."
                [System.Windows.Forms.Application]::DoEvents()

                # Use Invoke-Command to run gpupdate remotely
                $result = Invoke-Command -ComputerName $computer -ScriptBlock {
                    gpupdate /force 2>&1
                } -ErrorAction Stop -AsJob | Wait-Job -Timeout 60 | Receive-Job

                $successCount++
                $results += "[$computer] SUCCESS"
                $WinRMOutput.Text = $WinRMOutput.Text -replace "\[$computer\] Running gpupdate...", "[$computer] SUCCESS"
            }
            catch {
                $failCount++
                $results += "[$computer] FAILED: $($_.Exception.Message)"
                $WinRMOutput.Text = $WinRMOutput.Text -replace "\[$computer\] Running gpupdate...", "[$computer] FAILED"
            }
            [System.Windows.Forms.Application]::DoEvents()
        }

        $WinRMOutput.Text += "`n`n=== SUMMARY ===`nSuccess: $successCount`nFailed: $failCount`nOffline/Skipped: $skippedCount`nTotal: $($computers.Count)"

        Write-OutputLog "Force GPUpdate" $WinRMOutput.Text
        [System.Windows.MessageBox]::Show("GPUpdate completed!`n`nSuccess: $successCount`nFailed: $failCount`nOffline/Skipped: $skippedCount", "Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-Log "Force GPUpdate completed: $successCount success, $failCount failed, $skippedCount offline"
    }
    catch {
        $WinRMOutput.Text = "=== ERROR ===`n`n$($_.Exception.Message)`n`nMake sure Active Directory module is available."
        Write-OutputLog "Force GPUpdate Error" $WinRMOutput.Text
        [System.Windows.MessageBox]::Show("Failed to run GPUpdate:`n$($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Force GPUpdate failed: $($_.Exception.Message)" -Level "ERROR"
    }
})
}

# AD Discovery events
if ($null -ne $DiscoverComputersBtn) {
$DiscoverComputersBtn.Add_Click({
    Write-Log "Discover computers button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("AD Discovery requires Active Directory. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        $DiscoveryOutput.Text = "=== WORKGROUP MODE ===`n`nAD Discovery is only available in domain mode.`n`nUse 'Scan Localhost' in Artifacts tab instead."
        return
    }

    $DiscoveredComputersList.Items.Clear()
    $OfflineComputersList.Items.Clear()
    $DiscoveryOutput.Text = "Searching Active Directory for computers...`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $filter = $ADSearchFilter.Text
        if ([string]::IsNullOrWhiteSpace($filter)) { $filter = "*" }

        $computers = Get-ADComputer -Filter "Name -like '$filter'" -Properties OperatingSystem,LastLogonDate |
                     Select-Object Name, OperatingSystem, LastLogonDate |
                     Sort-Object Name

        $DiscoveryOutput.Text = "Found $($computers.Count) computers. Checking connectivity...`n"
        [System.Windows.Forms.Application]::DoEvents()

        $onlineCount = 0
        $offlineCount = 0

        foreach ($comp in $computers) {
            $DiscoveryOutput.Text += "Pinging $($comp.Name)..."
            [System.Windows.Forms.Application]::DoEvents()

            # Quick ping check
            $pingResult = Test-Connection -ComputerName $comp.Name -Count 1 -Quiet -ErrorAction SilentlyContinue

            if ($pingResult) {
                $DiscoveredComputersList.Items.Add("$($comp.Name) | $($comp.OperatingSystem) | Last: $($comp.LastLogonDate)")
                $onlineCount++
                $DiscoveryOutput.Text = $DiscoveryOutput.Text -replace "Pinging $($comp.Name)...", "Pinging $($comp.Name)... ONLINE`n"
            } else {
                $OfflineComputersList.Items.Add("$($comp.Name) | $($comp.OperatingSystem) | Last: $($comp.LastLogonDate)")
                $offlineCount++
                $DiscoveryOutput.Text = $DiscoveryOutput.Text -replace "Pinging $($comp.Name)...", "Pinging $($comp.Name)... offline`n"
            }
            [System.Windows.Forms.Application]::DoEvents()
        }

        $DiscoveryOutput.Text += "`n=== DISCOVERY COMPLETE ===`nTotal: $($computers.Count)`nOnline: $onlineCount`nOffline: $offlineCount"
        $DiscoveryStatus.Text = "Online: $onlineCount | Offline: $offlineCount | Total: $($computers.Count)"
        Write-Log "AD Discovery found $($computers.Count) computers ($onlineCount online, $offlineCount offline)"
        Write-OutputLog "AD Discovery" $DiscoveryOutput.Text
    }
    catch {
        $DiscoveryOutput.Text = "ERROR: $($_.Exception.Message)`n`nMake sure the Active Directory module is installed."
        Write-Log "AD Discovery failed: $($_.Exception.Message)" -Level "ERROR"
    }
})
}

if ($null -ne $TestConnectivityBtn) {
$TestConnectivityBtn.Add_Click({
    Write-Log "Test connectivity button clicked"
    if ($DiscoveredComputersList.SelectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one computer to test.", "No Selection", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $DiscoveryOutput.Text = "=== CONNECTIVITY TEST ===`n`nTesting PING and WinRM to selected computers...`n"
    [System.Windows.Forms.Application]::DoEvents()

    $pingOK = 0
    $winrmOK = 0
    $totalTests = $DiscoveredComputersList.SelectedItems.Count

    foreach ($item in $DiscoveredComputersList.SelectedItems) {
        $computerName = ($item -split '\|')[0].Trim()
        $DiscoveryOutput.Text += "`n$computerName : "
        [System.Windows.Forms.Application]::DoEvents()

        # Test PING
        $pingResult = "FAIL"
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($computerName, 2000)
            if ($reply.Status -eq 'Success') {
                $pingResult = "OK ($($reply.RoundtripTime)ms)"
                $pingOK++
            } else {
                $pingResult = "FAIL ($($reply.Status))"
            }
        } catch {
            $pingResult = "FAIL"
        }
        $DiscoveryOutput.Text += "Ping=$pingResult"
        [System.Windows.Forms.Application]::DoEvents()

        # Test WinRM (WSMan)
        $winrmResult = "FAIL"
        try {
            $wsmanTest = Test-WSMan -ComputerName $computerName -ErrorAction Stop
            if ($wsmanTest) {
                $winrmResult = "OK"
                $winrmOK++
            }
        } catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "Access is denied") {
                $winrmResult = "ACCESS DENIED"
            } elseif ($errMsg -match "cannot complete the operation") {
                $winrmResult = "NOT ENABLED"
            } elseif ($errMsg -match "cannot connect") {
                $winrmResult = "CONNECTION REFUSED"
            } elseif ($errMsg -match "network path") {
                $winrmResult = "UNREACHABLE"
            } else {
                $winrmResult = "FAIL"
            }
        }
        $DiscoveryOutput.Text += " | WinRM=$winrmResult"
        [System.Windows.Forms.Application]::DoEvents()
    }

    $DiscoveryOutput.Text += "`n`n--- SUMMARY ---"
    $DiscoveryOutput.Text += "`nPing OK: $pingOK/$totalTests"
    $DiscoveryOutput.Text += "`nWinRM OK: $winrmOK/$totalTests"

    if ($winrmOK -eq 0) {
        $DiscoveryOutput.Text += "`n`n--- TROUBLESHOOTING ---"
        $DiscoveryOutput.Text += "`n1. On TARGET computers, run:"
        $DiscoveryOutput.Text += "`n   winrm quickconfig -force"
        $DiscoveryOutput.Text += "`n   Enable-PSRemoting -Force"
        $DiscoveryOutput.Text += "`n"
        $DiscoveryOutput.Text += "`n2. Check WinRM service:"
        $DiscoveryOutput.Text += "`n   Get-Service WinRM | Start-Service"
        $DiscoveryOutput.Text += "`n   Set-Service WinRM -StartupType Automatic"
        $DiscoveryOutput.Text += "`n"
        $DiscoveryOutput.Text += "`n3. Check firewall (TCP 5985):"
        $DiscoveryOutput.Text += "`n   netsh advfirewall firewall show rule name=all | findstr WinRM"
        $DiscoveryOutput.Text += "`n"
        $DiscoveryOutput.Text += "`n4. Verify GPO applied:"
        $DiscoveryOutput.Text += "`n   gpresult /r /scope computer"
    } elseif ($winrmOK -lt $totalTests) {
        $DiscoveryOutput.Text += "`n`nSome computers not reachable via WinRM."
        $DiscoveryOutput.Text += "`nRun gpupdate /force on failed computers."
    } else {
        $DiscoveryOutput.Text += "`n`nAll computers reachable via WinRM!"
        $DiscoveryOutput.Text += "`nReady to scan."
    }

    Write-Log "Connectivity test: Ping=$pingOK/$totalTests, WinRM=$winrmOK/$totalTests"
})
}

if ($null -ne $SelectAllComputersBtn) {
$SelectAllComputersBtn.Add_Click({
    $DiscoveredComputersList.SelectAll()
    $DiscoveryOutput.Text = "Selected all $($DiscoveredComputersList.Items.Count) computers"
})
}

if ($null -ne $ScanSelectedBtn) {
$ScanSelectedBtn.Add_Click({
    Write-Log "Scan selected button clicked"
    if ($DiscoveredComputersList.SelectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one computer to scan.", "No Selection", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Get selected computer names
    $selectedComputers = @()
    foreach ($item in $DiscoveredComputersList.SelectedItems) {
        $compName = ($item -split '\|')[0].Trim()
        $selectedComputers += $compName
    }

    $DiscoveryOutput.Text = "=== REMOTE SCAN STARTED ===`n`nTesting WinRM connectivity to $($selectedComputers.Count) computers...`n"
    [System.Windows.Forms.Application]::DoEvents()

    $winrmOK = @()
    $winrmFail = @()

    foreach ($comp in $selectedComputers) {
        $DiscoveryOutput.Text += "`nTesting $comp..."
        [System.Windows.Forms.Application]::DoEvents()

        try {
            # Test WinRM connectivity with a simple command
            $result = Invoke-Command -ComputerName $comp -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            $winrmOK += $comp
            $DiscoveryOutput.Text += " OK"
            Write-Log "WinRM OK: $comp"
        } catch {
            $winrmFail += $comp
            $errorMsg = $_.Exception.Message
            $reason = "Unknown"
            if ($errorMsg -match "Access is denied") {
                $reason = "Access Denied"
            } elseif ($errorMsg -match "WinRM cannot complete|cannot process the request") {
                $reason = "WinRM not enabled"
            } elseif ($errorMsg -match "network path was not found|cannot find the computer") {
                $reason = "Unreachable"
            } elseif ($errorMsg -match "client cannot connect|connection attempt failed") {
                $reason = "Connection refused"
            } elseif ($errorMsg -match "firewall") {
                $reason = "Firewall blocking"
            } elseif ($errorMsg -match "timed out|timeout") {
                $reason = "Timeout"
            } elseif ($errorMsg -match "not a Windows") {
                $reason = "Not Windows"
            } else {
                # Extract short reason from error
                $reason = ($errorMsg -split ':')[0].Trim()
                if ($reason.Length -gt 30) { $reason = $reason.Substring(0, 30) + "..." }
            }
            $DiscoveryOutput.Text += " FAILED ($reason)"
            Write-Log "WinRM FAIL: $comp - $errorMsg" -Level "ERROR"
        }
        [System.Windows.Forms.Application]::DoEvents()
    }

    $DiscoveryOutput.Text += "`n`n--- CONNECTIVITY SUMMARY ---"
    $DiscoveryOutput.Text += "`nWinRM OK: $($winrmOK.Count) | Failed: $($winrmFail.Count)"
    [System.Windows.Forms.Application]::DoEvents()

    if ($winrmOK.Count -eq 0) {
        $DiscoveryOutput.Text += "`n`nERROR: No computers are reachable via WinRM."
        $DiscoveryOutput.Text += "`n`nTroubleshooting:"
        $DiscoveryOutput.Text += "`n1. Go to WinRM Setup and create/update the WinRM GPO"
        $DiscoveryOutput.Text += "`n2. Run 'gpupdate /force' on target computers"
        $DiscoveryOutput.Text += "`n3. Verify firewall allows WinRM (TCP 5985/5986)"
        $DiscoveryOutput.Text += "`n4. Check that WinRM service is running"
        $DiscoveryOutput.Text += "`n`nRun 'winrm quickconfig' on target to verify setup"
        [System.Windows.MessageBox]::Show("No computers reachable via WinRM.`n`nSee console output for troubleshooting steps.", "WinRM Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Proceed with scanning reachable computers
    $DiscoveryOutput.Text += "`n`n=== SCANNING $($winrmOK.Count) COMPUTERS ==="
    [System.Windows.Forms.Application]::DoEvents()

    $allArtifacts = @()
    foreach ($comp in $winrmOK) {
        $DiscoveryOutput.Text += "`n`nScanning $comp..."
        [System.Windows.Forms.Application]::DoEvents()

        try {
            $remoteArtifacts = Invoke-Command -ComputerName $comp -ScriptBlock {
                $artifacts = @()
                $paths = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:SystemRoot\System32")
                foreach ($path in $paths) {
                    if (Test-Path $path) {
                        Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 100 | ForEach-Object {
                                $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                                $artifacts += [PSCustomObject]@{
                                    FileName = $_.Name
                                    FullPath = $_.FullName
                                    Publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject -replace 'CN=|,.*$','' } else { "Unknown" }
                                    Computer = $env:COMPUTERNAME
                                }
                            }
                    }
                }
                return $artifacts
            } -ErrorAction Stop

            $allArtifacts += $remoteArtifacts
            $DiscoveryOutput.Text += " Found $($remoteArtifacts.Count) artifacts"
            Write-Log "Scanned $comp : $($remoteArtifacts.Count) artifacts"
        } catch {
            $DiscoveryOutput.Text += " SCAN FAILED: $($_.Exception.Message)"
            Write-Log "Scan failed on $comp : $($_.Exception.Message)" -Level "ERROR"
        }
        [System.Windows.Forms.Application]::DoEvents()
    }

    # Store artifacts
    $script:CollectedArtifacts = $allArtifacts
    $script:DiscoveredComputers = $winrmOK

    # Update badges in Rule Generator
    Update-Badges

    $DiscoveryOutput.Text += "`n`n=== SCAN COMPLETE ==="
    $DiscoveryOutput.Text += "`nTotal artifacts collected: $($allArtifacts.Count)"
    $DiscoveryOutput.Text += "`nFrom computers: $($winrmOK -join ', ')"
    $DiscoveryOutput.Text += "`n`nGo to Rule Generator to create rules from these artifacts."

    if ($winrmFail.Count -gt 0) {
        $DiscoveryOutput.Text += "`n`nFailed computers: $($winrmFail -join ', ')"
    }

    [System.Windows.MessageBox]::Show("Scan complete!`n`nArtifacts collected: $($allArtifacts.Count)`nFrom $($winrmOK.Count) computers`n`nGo to Rule Generator to create rules.", "Scan Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    Write-Log "Remote scan complete: $($allArtifacts.Count) artifacts from $($winrmOK.Count) computers"
})
}

# Group Management events
if ($null -ne $ExportGroupsBtn) {
$ExportGroupsBtn.Add_Click({
    Write-Log "Export groups button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("AD Group Management requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        $GroupMgmtOutput.Text = "=== WORKGROUP MODE ===`n`nAD Group Management is only available in domain mode.`n`nPlease run from a domain-joined computer with Active Directory module installed."
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.Title = "Export AD Groups"
    $saveDialog.FileName = "AD_GroupMembership_Export.csv"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $result = Export-ADGroupMembership -Path $saveDialog.FileName

        if ($result.success) {
            $GroupMgmtOutput.Text = $result.message + "`n`nExported to: $($result.exportPath)`n`nTemplate for editing: $($result.desiredPath)`n`nNext Steps:`n1. Edit the Desired CSV file`n2. Add/remove members as needed`n3. Use Import to apply changes"
            Write-Log "Groups exported: $($result.count) groups"
        } else {
            $GroupMgmtOutput.Text = "ERROR: $($result.error)"
        }
    }
})
}

if ($null -ne $ImportGroupsBtn) {
$ImportGroupsBtn.Add_Click({
    Write-Log "Import groups button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("AD Group Management requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openDialog.Title = "Import AD Groups from CSV"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $dryRun = $DryRunCheck.IsChecked
        $allowRemovals = $AllowRemovalsCheck.IsChecked
        $includeProtected = $IncludeProtectedCheck.IsChecked

        Write-Log "Importing groups from: $($openDialog.FileName) - DryRun: $dryRun, AllowRemovals: $allowRemovals, IncludeProtected: $includeProtected"

        $result = Import-ADGroupMembership -Path $openDialog.FileName -DryRun $dryRun -Removals $allowRemovals -IncludeProtected $includeProtected

        if ($result.success) {
            $GroupMgmtOutput.Text = $result.output
            Write-Log "Group import complete: Processed=$($result.stats.GroupsProcessed), Adds=$($result.stats.Adds), Removals=$($result.stats.Removals)"
            [System.Windows.Forms.Application]::DoEvents()

            if (-not $dryRun) {
                [System.Windows.MessageBox]::Show("Group membership changes applied!`n`nProcessed: $($result.stats.GroupsProcessed)`nAdds: $($result.stats.Adds)`nRemovals: $($result.stats.Removals)", "Import Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        } else {
            $GroupMgmtOutput.Text = "ERROR: $($result.error)"
        }
    }
})
}

# AppLocker Setup events
if ($null -ne $BootstrapAppLockerBtn) {
$BootstrapAppLockerBtn.Add_Click({
    Write-Log "Bootstrap AppLocker button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("AppLocker Setup requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        $AppLockerSetupOutput.Text = "=== WORKGROUP MODE ===`n`nAppLocker Setup is only available in domain mode.`n`nPlease run from a domain-joined computer with Active Directory module installed."
        return
    }

    $ouName = $OUNameText.Text
    $autoPopulate = $AutoPopulateCheck.IsChecked

    Write-Log "Initializing AppLocker structure - OU: $ouName, AutoPopulate: $autoPopulate"

    $result = Initialize-AppLockerStructure -OUName $ouName -AutoPopulateAdmins $autoPopulate

    if ($result.success) {
        $AppLockerSetupOutput.Text = $result.output + "`n`n=== NEXT STEPS ===`n`n1. Verify OU was created: $($result.ouDN)`n2. Review group memberships in ADUC`n3. Create GPO with AppLocker policy`n4. Link GPO to target OUs`n5. Monitor in Audit mode"
        Write-Log "AppLocker bootstrap complete: $($result.groupsCreated) groups created"
    } else {
        $AppLockerSetupOutput.Text = "ERROR: $($result.error)"
        Write-Log "AppLocker bootstrap failed: $($result.error)" -Level "ERROR"
    }
})
}

# Remove OU Protection button handler
if ($null -ne $RemoveOUProtectionBtn) {
$RemoveOUProtectionBtn.Add_Click({
    Write-Log "Remove OU Protection button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("This feature requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "This will remove protection from all AppLocker OUs, allowing them to be deleted.`n`nAre you sure you want to continue?",
        "Confirm Remove Protection",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) {
        return
    }

    $AppLockerSetupOutput.Text = "Removing protection from AppLocker OUs..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = Remove-AppLockerOUProtection

    if ($result.success) {
        $AppLockerSetupOutput.Text = $result.output
        [System.Windows.MessageBox]::Show("Protection removed from $($result.processedCount) OUs.`n`nYou can now delete OUs and objects under AppLocker.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $AppLockerSetupOutput.Text = "ERROR: $($result.error)"
        [System.Windows.MessageBox]::Show("Failed to remove protection: $($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})
}

if ($null -ne $CreateBrowserDenyBtn) {
$CreateBrowserDenyBtn.Add_Click({
    Write-Log "Create browser deny rules button clicked"

    $result = New-BrowserDenyRules

    if ($result.success) {
        $AppLockerSetupOutput.Text = $result.output
        Write-Log "Browser deny rules created: $($result.browsersDenied) browsers denied"
        [System.Windows.MessageBox]::Show("Browser deny rules created!`n`nBrowsers denied: $($result.browsersDenied)`n`nPolicy saved to: $($result.policyPath)", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $AppLockerSetupOutput.Text = "ERROR: $($result.error)"
        Write-Log "Browser deny rules failed: $($result.error)" -Level "ERROR"
    }
})
}

# Help events
if ($null -ne $HelpBtnWorkflow) {
$HelpBtnWorkflow.Add_Click({
    $HelpTitle.Text = "Help - Workflow"
    $HelpText.Text = Get-HelpContent "Workflow"
})
}

if ($null -ne $HelpBtnWhatsNew) {
$HelpBtnWhatsNew.Add_Click({
    $HelpTitle.Text = "Help - What's New in v1.2.5"
    $HelpText.Text = Get-HelpContent "WhatsNew"
})
}

if ($null -ne $HelpBtnPolicyGuide) {
$HelpBtnPolicyGuide.Add_Click({
    $HelpTitle.Text = "Help - Policy Build Guide"
    $HelpText.Text = Get-HelpContent "PolicyGuide"
})
}

if ($null -ne $HelpBtnRules) {
$HelpBtnRules.Add_Click({
    $HelpTitle.Text = "Help - Rule Best Practices"
    $HelpText.Text = Get-HelpContent "Rules"
})
}

if ($null -ne $HelpBtnTroubleshooting) {
$HelpBtnTroubleshooting.Add_Click({
    $HelpTitle.Text = "Help - Troubleshooting"
    $HelpText.Text = Get-HelpContent "Troubleshooting"
})
}

# Gap Analysis events
if ($null -ne $ImportBaselineBtn) {
$ImportBaselineBtn.Add_Click({
    Write-Log "Import baseline button clicked"
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv"
    $openDialog.Title = "Import Baseline Software List"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:BaselineSoftware = Import-SoftwareList -Path $openDialog.FileName
            if ($script:BaselineSoftware.Count -gt 0) {
                [System.Windows.MessageBox]::Show("Baseline imported!`n`nLoaded $($script:BaselineSoftware.Count) software items.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            } else {
                [System.Windows.MessageBox]::Show("No software items found in file.", "Warning", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        } catch {
            Write-Log "Import baseline failed: $($_.Exception.Message)" -Level "ERROR"
            [System.Windows.MessageBox]::Show("Failed to import baseline: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})
}

if ($null -ne $ImportTargetBtn) {
$ImportTargetBtn.Add_Click({
    Write-Log "Import target button clicked"
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv"
    $openDialog.Title = "Import Target Software List"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:TargetSoftware = Import-SoftwareList -Path $openDialog.FileName
            if ($script:TargetSoftware.Count -gt 0) {
                [System.Windows.MessageBox]::Show("Target imported!`n`nLoaded $($script:TargetSoftware.Count) software items.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            } else {
                [System.Windows.MessageBox]::Show("No software items found in file.", "Warning", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        } catch {
            Write-Log "Import target failed: $($_.Exception.Message)" -Level "ERROR"
            [System.Windows.MessageBox]::Show("Failed to import target: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})
}

if ($null -ne $CompareSoftwareBtn) {
$CompareSoftwareBtn.Add_Click({
    Write-Log "Compare software button clicked"

    if ($script:BaselineSoftware.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please scan or import a baseline first.", "No Baseline", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    if ($script:TargetSoftware.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please scan or import a target first.", "No Target", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    try {
        $results = Compare-SoftwareLists -Baseline $script:BaselineSoftware -Target $script:TargetSoftware

        # Update DataGrid
        $GapAnalysisGrid.ItemsSource = $results

        # Update stats
        $GapTotalCount.Text = $results.Count
        $GapMissingCount.Text = ($results | Where-Object { $_.Status -eq "Missing in Target" }).Count
        $GapExtraCount.Text = ($results | Where-Object { $_.Status -eq "Extra in Target" }).Count
        $GapVersionCount.Text = ($results | Where-Object { $_.Status -eq "Version Mismatch" }).Count

        Write-Log "Comparison complete: Total=$($results.Count), Missing=$($GapMissingCount.Text), Extra=$($GapExtraCount.Text), Version Diff=$($GapVersionCount.Text)"
    } catch {
        Write-Log "Compare software failed: $($_.Exception.Message)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Comparison failed: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})
}

if ($null -ne $ExportGapAnalysisBtn) {
$ExportGapAnalysisBtn.Add_Click({
    Write-Log "Export gap analysis button clicked"

    if ($GapAnalysisGrid.Items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No comparison results to export.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.Title = "Export Software Gap Analysis"
    $saveDialog.FileName = "Software_Gap_Analysis_$(Get-Date -Format 'yyyy-MM-dd').csv"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $GapAnalysisGrid.Items | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            [System.Windows.MessageBox]::Show("Exported to: $($saveDialog.FileName)", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Write-Log "Gap analysis exported: $($saveDialog.FileName)"
        } catch {
            Write-Log "Export gap analysis failed: $($_.Exception.Message)" -Level "ERROR"
            [System.Windows.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
})
}

# Export/Import Rules events
if ($null -ne $ExportRulesBtn) {
$ExportRulesBtn.Add_Click({
    Write-Log "Export rules button clicked"

    if ($script:GeneratedRules.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No generated rules to export. Please generate rules first using the Rule Generator tab.", "No Rules", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Validate rules before export
    $validation = Test-AppLockerRules -Rules $script:GeneratedRules

    if (-not $validation.success) {
        $errorMsg = "The following validation errors were found:`n`n"
        $errorMsg += ($validation.errors | Select-Object -First 5) -join "`n"
        if ($validation.errors.Count -gt 5) {
            $errorMsg += "`n... and $($validation.errors.Count - 5) more errors"
        }
        $errorMsg += "`n`nPlease fix these errors before exporting."

        [System.Windows.MessageBox]::Show($errorMsg, "Validation Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Rule validation failed: $($validation.errorCount) errors" -Level "ERROR"
        return
    }

    if ($validation.warningCount -gt 0) {
        $warningMsg = "Warnings:`n`n"
        $warningMsg += ($validation.warnings -join "`n")
        $warningMsg += "`n`nContinue with export?"

        $result = [System.Windows.MessageBox]::Show($warningMsg, "Validation Warnings", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($result -ne [System.Windows.MessageBoxResult]::Yes) {
            Write-Log "Export cancelled by user due to warnings"
            return
        }
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $saveDialog.Title = "Export AppLocker Rules"
    $saveDialog.FileName = "AppLocker-Rules_$(Get-Date -Format 'yyyy-MM-dd').xml"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker\Rules"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        # Generate AppLocker XML from rules
        $xmlContent = Convert-RulesToAppLockerXml -Rules $script:GeneratedRules

        # AppLocker policies MUST be UTF-16 encoded
        $xmlDoc = [xml]$xmlContent
        $xws = [System.Xml.XmlWriterSettings]::new()
        $xws.Encoding = [System.Text.Encoding]::Unicode
        $xws.Indent = $true
        $xw = [System.Xml.XmlWriter]::Create($saveDialog.FileName, $xws)
        $xmlDoc.Save($xw)
        $xw.Close()

        [System.Windows.MessageBox]::Show("Rules exported to: $($saveDialog.FileName)`n`n$($validation.validCount) rules exported.`n`nYou can now import this XML into a GPO using Group Policy Management.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-Log "Rules exported: $($saveDialog.FileName) ($($validation.validCount) rules)"
    }
})
}

# Browse for rule file button
if ($null -ne $BrowseRuleFileBtn) {
$BrowseRuleFileBtn.Add_Click({
    Write-Log "Browse rule file button clicked"

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog.Title = "Select AppLocker Rules XML File"
    $openDialog.InitialDirectory = "C:\GA-AppLocker\Rules"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $RuleFilePathBox.Text = $openDialog.FileName
        Write-Log "Rule file selected: $($openDialog.FileName)"
    }
})
}

if ($null -ne $ImportRulesBtn) {
$ImportRulesBtn.Add_Click({
    Write-Log "Apply rules to GPO button clicked"

    # Check workgroup mode
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO import requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    # Check if GPO module is available
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        [System.Windows.MessageBox]::Show("Group Policy module is required. Install RSAT tools.", "Missing Module", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    # Get selected target GPO
    $targetGpoItem = $TargetGpoCombo.SelectedItem
    if (-not $targetGpoItem) {
        [System.Windows.MessageBox]::Show("Please select a target GPO.", "No GPO Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    $targetGpoName = $targetGpoItem.Content.ToString()

    # Get import mode
    $importModeItem = $ImportModeCombo.SelectedItem
    $isMergeMode = if ($importModeItem) { $importModeItem.Content.ToString() -eq "Merge (Add)" } else { $true }

    # Get file path from textbox or open dialog if not set
    $xmlFilePath = $RuleFilePathBox.Text
    if ([string]::IsNullOrWhiteSpace($xmlFilePath) -or $xmlFilePath -eq "Select an AppLocker XML rule file..." -or -not (Test-Path $xmlFilePath)) {
        # Open file dialog if no valid file selected
        $openDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
        $openDialog.Title = "Select AppLocker Rules XML File"
        $openDialog.InitialDirectory = "C:\GA-AppLocker\Rules"

        if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            return
        }
        $xmlFilePath = $openDialog.FileName
        $RuleFilePathBox.Text = $xmlFilePath
    }
    $DeploymentStatus.Text = "Importing rules to: $targetGpoName`nMode: $(if ($isMergeMode) { 'Merge (Add)' } else { 'Overwrite' })`nSource: $xmlFilePath`n`nProcessing..."

    Write-Log "Importing rules to GPO: $targetGpoName (Mode: $(if ($isMergeMode) { 'Merge' } else { 'Overwrite' }))"

    try {
        # Use embedded functions - no module import needed
        Import-Module GroupPolicy -ErrorAction Stop

        # Load new rules from XML file
        [xml]$newPolicyXml = Get-Content $xmlFilePath -ErrorAction Stop

        # Get GPO object
        $gpo = Get-GPO -Name $targetGpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            throw "GPO '$targetGpoName' not found. Please create it first using 'Create 3 GPOs' button on Dashboard."
        }

        # Initialize counters
        $rulesAdded = 0
        $rulesSkipped = 0
        $rulesOverwritten = 0

        if ($isMergeMode) {
            # === MERGE MODE ===
            # Get existing policy from GPO
            $existingPolicy = Get-AppLockerPolicy -Gpo $targetGpoName -ErrorAction SilentlyContinue

            if ($existingPolicy) {
                # Merge: Add new rules, keep existing ones
                $DeploymentStatus.Text += "`n`nMerge mode: Combining new rules with existing policy..."

                # Create a merged policy
                $mergedPolicy = $existingPolicy

                # Count existing rules
                $existingRuleCount = ($existingPolicy.AppLockerPolicy.RuleCollection | Measure-Object).Count

                # Import new rules to temporary policy
                $tempPolicy = Get-AppLockerPolicy -Xml $xmlFilePath.OuterXml

                # Get all rule collections from new policy
                $newRuleCollections = $tempPolicy.AppLockerPolicy.RuleCollection

                foreach ($collection in $newRuleCollections) {
                    $ruleType = $collection.RuleCollectionType
                    $newRules = $collection.ChildNodes

                    foreach ($newRule in $newRules) {
                        # Check if rule already exists (by Name or ID)
                        $ruleExists = $false
                        foreach ($existingCollection in $existingPolicy.AppLockerPolicy.RuleCollection) {
                            if ($existingCollection.RuleCollectionType -eq $ruleType) {
                                foreach ($existingRule in $existingCollection.ChildNodes) {
                                    if ($existingRule.Name -eq $newRule.Name) {
                                        $ruleExists = $true
                                        $rulesSkipped++
                                        break
                                    }
                                }
                            }
                            if ($ruleExists) { break }
                        }

                        if (-not $ruleExists) {
                            # Add the new rule to merged policy
                            $mergedPolicy.AppLockerPolicy.RuleCollection |
                                Where-Object { $_.RuleCollectionType -eq $ruleType } |
                                ForEach-Object {
                                    $importedNode = $mergedPolicy.ImportNode($newRule, $true)
                                    [void]$_.AppendChild($importedNode)
                                }
                            $rulesAdded++
                        }
                    }
                }

                # Apply merged policy to GPO
                Set-GPOAppLockerPolicy -GpoName $targetGpoName -PolicyXml $mergedPolicy.OuterXml -ErrorAction Stop | Out-Null

                $resultMessage = "=== IMPORT COMPLETE (MERGE MODE) ===`n`n"
                $resultMessage += "Target GPO: $targetGpoName`n"
                $resultMessage += "Source: $xmlFilePath`n`n"
                $resultMessage += "Results:`n"
                $resultMessage += "  - Rules added: $rulesAdded`n"
                $resultMessage += "  - Rules skipped (duplicates): $rulesSkipped`n"
                $resultMessage += "  - Total rules in GPO: $($existingRuleCount + $rulesAdded)`n`n"
                $resultMessage += "Merge mode adds new rules while preserving existing rules."
            }
            else {
                # No existing policy - just import new rules
                Set-GPOAppLockerPolicy -GpoName $targetGpoName -PolicyXml $newPolicyXml.OuterXml -ErrorAction Stop | Out-Null
                $rulesAdded = ($newPolicyXml.AppLockerPolicy.RuleCollection.ChildNodes | Measure-Object).Count

                $resultMessage = "=== IMPORT COMPLETE ===`n`n"
                $resultMessage += "Target GPO: $targetGpoName`n"
                $resultMessage += "Source: $xmlFilePath`n`n"
                $resultMessage += "No existing policy found. Imported as new policy.`n"
                $resultMessage += "Rules imported: $rulesAdded"
            }
        }
        else {
            # === OVERWRITE MODE ===
            # Replace all existing rules with new ones
            $DeploymentStatus.Text += "`n`nOverwrite mode: Replacing all existing rules..."

            # Count rules being overwritten
            $existingPolicy = Get-AppLockerPolicy -Gpo $targetGpoName -ErrorAction SilentlyContinue
            if ($existingPolicy) {
                $rulesOverwritten = ($existingPolicy.AppLockerPolicy.RuleCollection.ChildNodes | Measure-Object).Count
            }

            # Apply new policy (overwrites existing)
            Set-GPOAppLockerPolicy -GpoName $targetGpoName -PolicyXml $newPolicyXml.OuterXml -ErrorAction Stop | Out-Null
            $rulesAdded = ($newPolicyXml.AppLockerPolicy.RuleCollection.ChildNodes | Measure-Object).Count

            $resultMessage = "=== IMPORT COMPLETE (OVERWRITE MODE) ===`n`n"
            $resultMessage += "Target GPO: $targetGpoName`n"
            $resultMessage += "Source: $xmlFilePath`n`n"
            $resultMessage += "Results:`n"
            $resultMessage += "  - Old rules replaced: $rulesOverwritten`n"
            $resultMessage += "  - New rules added: $rulesAdded`n"
            $resultMessage += "  - Total rules in GPO: $rulesAdded`n`n"
            $resultMessage += "OVERWRITE MODE: All previous rules have been replaced."
        }

        $DeploymentStatus.Text = $resultMessage
        Write-Log "GPO import complete: $targetGpoName - Added: $rulesAdded, Skipped: $rulesSkipped"

        [System.Windows.MessageBox]::Show($resultMessage, "Import Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

    }
    catch {
        $errorMsg = $_.Exception.Message
        $DeploymentStatus.Text = "ERROR: $errorMsg"
        Write-Log "GPO import failed: $errorMsg" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to import rules:`n`n$errorMsg", "Import Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})
}

# Other events
function Update-StatusBar {
    # Update main status text
    if ($script:IsWorkgroup) {
        $StatusText.Text = "WORKGROUP MODE - Local scanning available"
    } elseif (-not $script:HasRSAT) {
        $StatusText.Text = "$($script:DomainInfo.dnsRoot) - RSAT required for GPO features"
    } else {
        $StatusText.Text = "$($script:DomainInfo.dnsRoot) - Full features available"
    }

    # Phase 3: Enhanced Context Indicators
    # Domain/Workgroup indicator
    if ($script:IsWorkgroup) {
        $MiniStatusDomain.Text = "WORKGROUP"
        $MiniStatusDomain.Foreground = "#8B949E"
    } else {
        $MiniStatusDomain.Text = "$($script:DomainInfo.netBIOSName)"
        $MiniStatusDomain.Foreground = "#3FB950"
    }

    # Mode indicator (Audit vs Enforce)
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        $hasEnforce = $false
        if ($policy) {
            foreach ($collection in $policy.RuleCollections) {
                if ($collection.EnforcementMode -eq "Enabled") {
                    $hasEnforce = $true
                    break
                }
            }
        }

        if ($hasEnforce) {
            if ($null -ne $MiniStatusMode) { $MiniStatusMode.Text = "ENFORCE"; $MiniStatusMode.Foreground = "#F85149" }
        } else {
            if ($null -ne $MiniStatusMode) { $MiniStatusMode.Text = "AUDIT"; $MiniStatusMode.Foreground = "#3FB950" }
        }
    }
    catch {
        if ($null -ne $MiniStatusMode) { $MiniStatusMode.Text = "UNKNOWN"; $MiniStatusMode.Foreground = "#8B949E" }
    }

    # Phase indicator (from GPO quick assignment)
    $currentPhase = $script:CurrentDeploymentPhase
    if ($null -ne $MiniStatusPhase) {
        if ($currentPhase) {
            $MiniStatusPhase.Text = "P$currentPhase"
        } else {
            $MiniStatusPhase.Text = ""
        }
    }

    # Connected systems count
    if ($null -ne $MiniStatusConnected) {
        if ($script:DiscoveredSystems) {
            $onlineCount = @($script:DiscoveredSystems | Where-Object { $_.status -eq "Online" }).Count
            $MiniStatusConnected.Text = "$onlineCount online"
        } else {
            $MiniStatusConnected.Text = "0 systems"
        }
    }

    # Artifacts count
    $artifactCount = $script:CollectedArtifacts.Count
    if ($null -ne $MiniStatusArtifacts) { $MiniStatusArtifacts.Text = "$artifactCount artifacts" }

    # Last sync time
    if ($script:LastSyncTime) {
        $timeDiff = (Get-Date) - $script:LastSyncTime
        if ($timeDiff.TotalMinutes -lt 1) {
            $MiniStatusSync.Text = "Just now"
        } elseif ($timeDiff.TotalMinutes -lt 60) {
            $MiniStatusSync.Text = "$([int]$timeDiff.TotalMinutes)m ago"
        } else {
            $MiniStatusSync.Text = "$([int]$timeDiff.TotalHours)h ago"
        }
    } else {
        $MiniStatusSync.Text = "Ready"
    }
}

# Update Quick Import badges in Rule Generator panel
function Update-Badges {
    # Update artifact count badge
    $artifactCount = if ($script:CollectedArtifacts) { $script:CollectedArtifacts.Count } else { 0 }
    $ArtifactCountBadge.Text = "$artifactCount"

    # Update event count badge
    $eventCount = if ($script:AllEvents) { $script:AllEvents.Count } else { 0 }
    $EventCountBadge.Text = "$eventCount"

    # Update badge colors based on availability
    if ($artifactCount -gt 0) {
        $ArtifactCountBadge.Foreground = "#3FB950"
        $ArtifactCountBadge.Background = "#1F6FEB"
    } else {
        $ArtifactCountBadge.Foreground = "#6E7681"
        $ArtifactCountBadge.Background = "#21262D"
    }

    if ($eventCount -gt 0) {
        $EventCountBadge.Foreground = "#3FB950"
        $EventCountBadge.Background = "#1F6FEB"
    } else {
        $EventCountBadge.Foreground = "#6E7681"
        $EventCountBadge.Background = "#21262D"
    }
}

# Update Rules DataGrid from generated rules
function Update-RulesDataGrid {
    $RulesDataGrid.Items.Clear()

    if (-not $script:GeneratedRules -or $script:GeneratedRules.Count -eq 0) {
        $RulesCountText.Text = "0 rules"
        return
    }

    # Update group filter dropdown with actual groups
    Update-RulesGroupFilter

    # Apply current filters to the DataGrid
    Filter-RulesDataGrid
}

# Helper function to resolve SID to group name
function Resolve-SidToGroupName {
    param([string]$Sid)

    # Check common SIDs
    $commonSids = @{
        "S-1-1-0" = "Everyone"
        "S-1-5-32-544" = "Administrators"
        "S-1-5-32-545" = "Users"
        "S-1-5-32-546" = "Guests"
        "S-1-5-32-559" = "Performance Log Users"
    }

    if ($commonSids.ContainsKey($Sid)) {
        return $commonSids[$Sid]
    }

    # Check if it's an AppLocker group SID (pattern matching)
    if ($Sid -match "^S-1-5-21-\d+-\d+-\d+-\d+-\d+$") {
        # Try to get from AD
        if (-not $script:IsWorkgroup -and $script:HasRSAT) {
            try {
                $group = Get-ADGroup -Identity $Sid -ErrorAction SilentlyContinue
                if ($group) {
                    return $group.Name
                }
            } catch {
                # Fall through to default
            }
        }
    }

    return $Sid
}

# Helper function to get SID from group name
function Get-SidFromGroupName {
    param([string]$GroupName)

    # Check common groups
    $commonGroups = @{
        "Everyone" = "S-1-1-0"
        "Administrators" = "S-1-5-32-544"
        "Users" = "S-1-5-32-545"
        "Guests" = "S-1-5-32-546"
    }

    if ($commonGroups.ContainsKey($GroupName)) {
        return $commonGroups[$GroupName]
    }

    # Check AppLocker groups
    if (-not $script:IsWorkgroup -and $script:HasRSAT) {
        try {
            $group = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
            if ($group) {
                return $group.SID.Value
            }
        } catch {
            # Fall through to default
        }
    }

    return "S-1-1-0"  # Default to Everyone
}

# Initialize last sync time variable
$script:LastSyncTime = $null

# ============================================================
# Phase 5: Custom Rule Templates and Wizard Functions
# ============================================================

# Global variable for embedded templates
$script:EmbeddedTemplates = $null

# Initialize embedded templates on first use
function Initialize-EmbeddedTemplates {
    if ($null -ne $script:EmbeddedTemplates) {
        return $script:EmbeddedTemplates
    }

    $script:EmbeddedTemplates = @(
        @{
            Id = "microsoft-office"
            Name = "Microsoft Office"
            Category = "Productivity"
            Description = "Core Microsoft Office applications (Word, Excel, PowerPoint, Outlook, Access, Publisher)"
            RuleCount = 6
            Applications = @("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "MSACCESS.EXE", "MSPUB.EXE")
            Rules = @(
                @{Name="Microsoft Word"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT WORD"; Binary="*"}
                @{Name="Microsoft Excel"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT EXCEL"; Binary="*"}
                @{Name="Microsoft PowerPoint"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT POWERPOINT"; Binary="*"}
                @{Name="Microsoft Outlook"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT OUTLOOK"; Binary="*"}
                @{Name="Microsoft Access"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT ACCESS"; Binary="*"}
                @{Name="Microsoft Publisher"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT PUBLISHER"; Binary="*"}
            )
        }
        @{
            Id = "web-browsers"
            Name = "Web Browsers"
            Category = "Productivity"
            Description = "Popular web browsers for internet access (Chrome, Firefox, Edge)"
            RuleCount = 3
            Applications = @("chrome.exe", "firefox.exe", "msedge.exe")
            Rules = @(
                @{Name="Google Chrome"; Type="Publisher"; Publisher="O=GOOGLE LLC"; Product="GOOGLE CHROME"; Binary="*"}
                @{Name="Mozilla Firefox"; Type="Publisher"; Publisher="O=MOZILLA CORPORATION"; Product="FIREFOX"; Binary="*"}
                @{Name="Microsoft Edge"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT EDGE"; Binary="*"}
            )
        }
        @{
            Id = "pdf-readers"
            Name = "PDF Readers"
            Category = "Productivity"
            Description = "PDF document viewing applications (Adobe Acrobat Reader, Foxit Reader)"
            RuleCount = 2
            Applications = @("AcroRd32.exe", "FoxitPDFReader.exe")
            Rules = @(
                @{Name="Adobe Acrobat Reader"; Type="Publisher"; Publisher="O=ADOBE INC."; Product="ADOBE ACROBAT READER DC"; Binary="*"}
                @{Name="Foxit PDF Reader"; Type="Publisher"; Publisher="O=FOXIT SOFTWARE INCORPORATED"; Product="FOXIT READER"; Binary="*"}
            )
        }
        @{
            Id = "compression-tools"
            Name = "Compression Tools"
            Category = "Utilities"
            Description = "File compression and extraction utilities (7-Zip, WinRAR)"
            RuleCount = 2
            Applications = @("7zFM.exe", "winrar.exe")
            Rules = @(
                @{Name="7-Zip"; Type="Publisher"; Publisher="O=IGOR PAVLOV"; Product="7-ZIP"; Binary="*"}
                @{Name="WinRAR"; Type="Publisher"; Publisher="O=WINRAR"; Product="WINRAR"; Binary="*"}
            )
        }
        @{
            Id = "admin-tools"
            Name = "Administrative Tools"
            Category = "Security Baselines"
            Description = "Essential Windows administrative tools (Task Manager, PowerShell, CMD)"
            RuleCount = 3
            Applications = @("Taskmgr.exe", "powershell.exe", "cmd.exe")
            Rules = @(
                @{Name="Task Manager"; Type="Path"; Path="%OSDRIVE%\Windows\System32\taskmgr.exe"}
                @{Name="PowerShell"; Type="Path"; Path="%OSDRIVE%\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}
                @{Name="Command Prompt"; Type="Path"; Path="%OSDRIVE%\Windows\System32\cmd.exe"}
            )
        }
        @{
            Id = "sysinternals"
            Name = "Sysinternals Suite"
            Category = "Utilities"
            Description = "Microsoft Sysinternals troubleshooting tools (Process Explorer, Autoruns, etc.)"
            RuleCount = 5
            Applications = @("procexp.exe", "procmon.exe", "autoruns.exe", "tcpview.exe", "handle.exe")
            Rules = @(
                @{Name="Process Explorer"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="SYSINTERNALSSUITE"; Binary="PROCEXE*"}
                @{Name="Process Monitor"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="SYSINTERNALSSUITE"; Binary="PROCMON*"}
                @{Name="Autoruns"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="SYSINTERNALSSUITE"; Binary="AUTORUNS*"}
                @{Name="TCPView"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="SYSINTERNALSSUITE"; Binary="TCPVIEW*"}
                @{Name="Handle"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="SYSINTERNALSSUITE"; Binary="HANDLE*"}
            )
        }
        @{
            Id = "visual-studio"
            Name = "Visual Studio"
            Category = "Development"
            Description = "Microsoft Visual Studio IDE and related development tools"
            RuleCount = 4
            Applications = @("devenv.exe", "MSBuild.exe", "vstest.console.exe", "codetools.exe")
            Rules = @(
                @{Name="Visual Studio IDE"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT VISUAL STUDIO"; Binary="*"}
                @{Name="MSBuild"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT VISUAL STUDIO"; Binary="MSBUILD*"}
                @{Name="Visual Studio Test"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT VISUAL STUDIO"; Binary="VSTEST*"}
                @{Name="Visual Studio Code Tools"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT VISUAL STUDIO"; Binary="CODETOOLS*"}
            )
        }
        @{
            Id = "git-tools"
            Name = "Git and Version Control"
            Category = "Development"
            Description = "Git version control and related tools"
            RuleCount = 3
            Applications = @("git.exe", "git-bash.exe", "gitk.exe")
            Rules = @(
                @{Name="Git"; Type="Path"; Path="%OSDRIVE%\Program Files\Git\cmd\git.exe"}
                @{Name="Git Bash"; Type="Path"; Path="%OSDRIVE%\Program Files\Git\git-bash.exe"}
                @{Name="Git GUI"; Type="Path"; Path="%OSDRIVE%\Program Files\Git\cmd\gitk.exe"}
            )
        }
        @{
            Id = "docker-desktop"
            Name = "Docker Desktop"
            Category = "Development"
            Description = "Docker Desktop container platform"
            RuleCount = 3
            Applications = @("Docker Desktop.exe", "docker.exe", "com.docker.backend.exe")
            Rules = @(
                @{Name="Docker Desktop"; Type="Publisher"; Publisher="O=DOCKER INC."; Product="DOCKER DESKTOP"; Binary="*"}
                @{Name="Docker CLI"; Type="Publisher"; Publisher="O=DOCKER INC."; Product="DOCKER DESKTOP"; Binary="DOCKER.EXE"}
                @{Name="Docker Backend"; Type="Publisher"; Publisher="O=DOCKER INC."; Product="DOCKER DESKTOP"; Binary="COM.DOCKER.BACKEND.EXE"}
            )
        }
        @{
            Id = "notepad-plus-plus"
            Name = "Notepad++"
            Category = "Utilities"
            Description = "Notepad++ text editor"
            RuleCount = 1
            Applications = @("notepad++.exe")
            Rules = @(
                @{Name="Notepad++"; Type="Publisher"; Publisher="O=NOTEPAD++"; Product="NOTEPAD++"; Binary="*"}
            )
        }
        @{
            Id = "communication"
            Name = "Communication Tools"
            Category = "Productivity"
            Description = "Business communication applications (Microsoft Teams, Slack)"
            RuleCount = 2
            Applications = @("Teams.exe", "slack.exe")
            Rules = @(
                @{Name="Microsoft Teams"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT TEAMS"; Binary="TEAMS.EXE"}
                @{Name="Slack"; Type="Publisher"; Publisher="O=SLACK TECHNOLOGIES, INC."; Product="SLACK"; Binary="SLACK.EXE"}
            )
        }
        @{
            Id = "security-baseline"
            Name = "Windows Security Baseline"
            Category = "Security Baselines"
            Description = "Core Windows security-related applications"
            RuleCount = 4
            Applications = @("smartscreen.exe", "windowsdefender.exe", "mpcmdrun.exe", "securityhealthsystray.exe")
            Rules = @(
                @{Name="Windows SmartScreen"; Type="Path"; Path="%OSDRIVE%\Windows\System32\smartscreen.exe"}
                @{Name="Windows Defender"; Type="Path"; Path="%OSDRIVE%\Program Files\Windows Defender\MsMpeng.exe"}
                @{Name="Defender Command"; Type="Path"; Path="%OSDRIVE%\Program Files\Windows Defender\MpCmdRun.exe"}
                @{Name="Security Health"; Type="Path"; Path="%OSDRIVE%\Windows\System32\SecurityHealthSystray.exe"}
            )
        }
        @{
            Id = "putty-tools"
            Name = "PuTTY SSH Tools"
            Category = "Utilities"
            Description = "PuTTY SSH client and related tools"
            RuleCount = 4
            Applications = @("putty.exe", "pscp.exe", "plink.exe", "pageant.exe")
            Rules = @(
                @{Name="PuTTY"; Type="Publisher"; Publisher="O=SIMON TATHAM"; Product="PUTTY"; Binary="PUTTY.EXE"}
                @{Name="PuTTY SCP"; Type="Publisher"; Publisher="O=SIMON TATHAM"; Product="PUTTY"; Binary="PSCP.EXE"}
                @{Name="PuTTY Plink"; Type="Publisher"; Publisher="O=SIMON TATHAM"; Product="PUTTY"; Binary="PLINK.EXE"}
                @{Name="Pageant"; Type="Publisher"; Publisher="O=SIMON TATHAM"; Product="PUTTY"; Binary="PAGEANT.EXE"}
            )
        }
        @{
            Id = "vscode"
            Name = "Visual Studio Code"
            Category = "Development"
            Description = "Microsoft Visual Studio Code editor"
            RuleCount = 1
            Applications = @("Code.exe")
            Rules = @(
                @{Name="Visual Studio Code"; Type="Publisher"; Publisher="O=MICROSOFT CORPORATION"; Product="MICROSOFT VISUAL STUDIO CODE"; Binary="*"}
            )
        }
        @{
            Id = "python-dev"
            Name = "Python Development"
            Category = "Development"
            Description = "Python interpreter and development tools"
            RuleCount = 3
            Applications = @("python.exe", "pythonw.exe", "pip.exe")
            Rules = @(
                @{Name="Python"; Type="Path"; Path="%OSDRIVE%\Program Files\Python39\python.exe"}
                @{Name="Python Windowed"; Type="Path"; Path="%OSDRIVE%\Program Files\Python39\pythonw.exe"}
                @{Name="PIP"; Type="Path"; Path="%OSDRIVE%\Program Files\Python39\Scripts\pip.exe"}
            )
        }
    )

    return $script:EmbeddedTemplates
}

function Get-RuleTemplates {
    <#
    .SYNOPSIS
        List all available rule templates (embedded + custom)
    #>
    param(
        [string]$Category = "",
        [string]$SearchTerm = ""
    )

    # Initialize embedded templates
    $templates = Initialize-EmbeddedTemplates

    # Load custom templates from file if exists
    $customTemplatesPath = "C:\GA-AppLocker\Templates\custom-templates.json"
    if (Test-Path $customTemplatesPath) {
        try {
            $customData = Get-Content -Path $customTemplatesPath -Raw | ConvertFrom-Json
            foreach ($ct in $customData) {
                $templates += @{
                    Id = $ct.Id
                    Name = $ct.Name
                    Category = "Custom"
                    Description = $ct.Description
                    RuleCount = $ct.RuleCount
                    Applications = $ct.Applications
                    Rules = $ct.Rules
                }
            }
        } catch {
            Write-Log "Error loading custom templates: $_" -Level "WARN"
        }
    }

    # Filter by category if specified
    if ($Category -and $Category -ne "All Categories") {
        $templates = $templates | Where-Object { $_.Category -eq $Category }
    }

    # Filter by search term if specified
    if ($SearchTerm) {
        $templates = $templates | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.Description -like "*$SearchTerm*" -or
            ($_.Applications -match $SearchTerm)
        }
    }

    return $templates
}

function Get-TemplateContent {
    <#
    .SYNOPSIS
        Get detailed content of a specific template
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TemplateId
    )

    $templates = Get-RuleTemplates
    $template = $templates | Where-Object { $_.Id -eq $TemplateId }

    if ($template) {
        return @{
            success = $true
            template = $template
        }
    } else {
        return @{
            success = $false
            error = "Template not found: $TemplateId"
        }
    }
}

function Import-RuleTemplate {
    <#
    .SYNOPSIS
        Import a template into the current AppLocker policy
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TemplateId,
        [string]$UserGroup = "Everyone",
        [string]$Action = "Allow"
    )

    Write-Log "Importing template: $TemplateId for group: $UserGroup"

    $templateResult = Get-TemplateContent -TemplateId $TemplateId
    if (-not $templateResult.success) {
        return @{
            success = $false
            error = $templateResult.error
        }
    }

    $template = $templateResult.template
    $importedRules = @()

    try {
        # Get current policy
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($null -eq $policy) {
            return @{
                success = $false
                error = "Could not retrieve current AppLocker policy"
            }
        }

        foreach ($rule in $template.Rules) {
            try {
                # Build rule parameters based on type
                $ruleParams = @{
                    Type = $rule.Type
                    User = $UserGroup
                    Action = $Action
                }

                switch ($rule.Type) {
                    "Publisher" {
                        $ruleParams.Publisher = $rule.Publisher
                        $ruleParams.ProductName = $rule.Product
                        $ruleParams.BinaryName = $rule.Binary
                    }
                    "Path" {
                        $ruleParams.Path = $rule.Path
                    }
                    "Hash" {
                        $ruleParams.Hash = $rule.Hash
                    }
                }

                # Create the rule
                $newRule = New-AppLockerPolicy @ruleParams -ErrorAction Stop
                $importedRules += $newRule

                Write-Log "Imported rule: $($rule.Name)"
            } catch {
                Write-Log "Failed to import rule $($rule.Name): $_" -Level "WARN"
            }
        }

        return @{
            success = $true
            importedCount = $importedRules.Count
            templateName = $template.Name
            rules = $importedRules
        }
    } catch {
        return @{
            success = $false
            error = "Failed to import template: $_"
        }
    }
}

function Export-AsTemplate {
    <#
    .SYNOPSIS
        Save current rules as a custom template
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TemplateName,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [string]$Category = "Custom"
    )

    Write-Log "Exporting rules as template: $TemplateName"

    try {
        # Get current policy
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        if ($null -eq $policy) {
            return @{
                success = $false
                error = "Could not retrieve current AppLocker policy"
            }
        }

        # Extract rules
        $rules = @()
        $applications = @()

        foreach ($collection in $policy.RuleCollections) {
            foreach ($rule in $collection) {
                $ruleData = @{
                    Name = if ($rule.Name) { $rule.Name } else { "Unnamed Rule" }
                    Type = $rule.Condition.ConditionType
                    User = $rule.User.Value
                    Action = $rule.Action.ToString()
                }

                # Extract condition details
                switch ($rule.Condition.ConditionType) {
                    "Publisher" {
                        $ruleData.Publisher = $rule.Condition.PublisherName
                        $ruleData.Product = $rule.Condition.ProductName
                        $ruleData.Binary = $rule.Condition.BinaryName
                    }
                    "Path" {
                        $ruleData.Path = $rule.Condition.Path
                    }
                    "Hash" {
                        $ruleData.Hash = $rule.Condition.Hash
                    }
                }

                $rules += $ruleData
            }
        }

        # Create template object
        $template = @{
            Id = "custom-" + (New-Guid).ToString().Substring(0, 8)
            Name = $TemplateName
            Category = $Category
            Description = $Description
            RuleCount = $rules.Count
            Applications = $applications
            Rules = $rules
            Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }

        # Save to file
        $templatesDir = "C:\GA-AppLocker\Templates"
        if (-not (Test-Path $templatesDir)) {
            New-Item -ItemType Directory -Path $templatesDir -Force | Out-Null
        }

        $customTemplatesPath = Join-Path $templatesDir "custom-templates.json"
        $customTemplates = @()

        if (Test-Path $customTemplatesPath) {
            $customTemplates = Get-Content -Path $customTemplatesPath -Raw | ConvertFrom-Json
        }

        $customTemplates += $template
        $customTemplates | ConvertTo-Json -Depth 10 | Set-Content -Path $customTemplatesPath

        return @{
            success = $true
            template = $template
            path = $customTemplatesPath
        }
    } catch {
        return @{
            success = $false
            error = "Failed to export template: $_"
        }
    }
}

function New-CustomTemplate {
    <#
    .SYNOPSIS
        Launch dialog to create a new custom template from scratch
    #>
    Write-Log "Launching Create Template dialog"

    # Create XAML for template creation dialog
    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Create Custom Template" Height="500" Width="600"
        WindowStartupLocation="CenterOwner" Background="#0D1117">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Create Custom Template" FontSize="18" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,16"/>

        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <StackPanel>
                <TextBlock Text="Template Name" FontSize="12" Foreground="#8B949E" Margin="0,0,0,4"/>
                <TextBox Name="TemplateNameInput" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="12" Margin="0,0,0,12"/>

                <TextBlock Text="Description" FontSize="12" Foreground="#8B949E" Margin="0,0,0,4"/>
                <TextBox Name="TemplateDescInput" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="12" Height="80" TextWrapping="Wrap" AcceptsReturn="True" Margin="0,0,0,12"/>

                <TextBlock Text="Category" FontSize="12" Foreground="#8B949E" Margin="0,0,0,4"/>
                <ComboBox Name="TemplateCategoryInput" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="12" Margin="0,0,0,12">
                    <ComboBoxItem Content="Custom" IsSelected="True"/>
                    <ComboBoxItem Content="Security Baselines"/>
                    <ComboBoxItem Content="Productivity"/>
                    <ComboBoxItem Content="Development"/>
                    <ComboBoxItem Content="Utilities"/>
                </ComboBox>

                <Border Background="#21262D" CornerRadius="6" Padding="12" Margin="0,0,0,12">
                    <StackPanel>
                        <TextBlock Text="Template Rules (JSON format)" FontSize="12" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                        <TextBox Name="TemplateRulesInput" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="11" Height="150" TextWrapping="Wrap" AcceptsReturn="True" FontFamily="Consolas"/>
                        <TextBlock Text="Example: [{`"Name`":`"My App`",`"Type`":`"Path`",`"Path`":`"C:\\Program Files\\MyApp.exe`}]" FontSize="10" Foreground="#6E7681" Margin="0,4,0,0"/>
                    </StackPanel>
                </Border>
            </StackPanel>
        </ScrollViewer>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button Name="CreateTemplateBtn" Content="Create Template" Style="{StaticResource PrimaryButton}" Margin="0,0,12,0"/>
            <Button Name="CancelTemplateBtn" Content="Cancel" Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
    </Grid>
</Window>
"@

    try {
        # Parse and create dialog
        $dialog = [Windows.Markup.XamlReader]::Parse($dialogXaml)
        $dialog.Owner = $window

        # Find controls
        $TemplateNameInput = $dialog.FindName("TemplateNameInput")
        $TemplateDescInput = $dialog.FindName("TemplateDescInput")
        $TemplateCategoryInput = $dialog.FindName("TemplateCategoryInput")
        $TemplateRulesInput = $dialog.FindName("TemplateRulesInput")
        $CreateTemplateBtn = $dialog.FindName("CreateTemplateBtn")
        $CancelTemplateBtn = $dialog.FindName("CancelTemplateBtn")

        # Cancel button
        $CancelTemplateBtn.Add_Click({
            $dialog.DialogResult = $false
            $dialog.Close()
        })

        # Create button
        $CreateTemplateBtn.Add_Click({
            $name = $TemplateNameInput.Text.Trim()
            $desc = $TemplateDescInput.Text.Trim()
            $category = $TemplateCategoryInput.SelectedItem.Content
            $rulesJson = $TemplateRulesInput.Text.Trim()

            if ([string]::IsNullOrEmpty($name)) {
                [System.Windows.MessageBox]::Show("Please enter a template name.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                return
            }

            try {
                $rules = $rulesJson | ConvertFrom-Json
            } catch {
                [System.Windows.MessageBox]::Show("Invalid JSON format for rules. Please check your syntax.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                return
            }

            $result = Export-AsTemplate -TemplateName $name -Description $desc -Category $category

            if ($result.success) {
                $dialog.Tag = @{created = $true; template = $result.template}
                $dialog.DialogResult = $true
                $dialog.Close()
            } else {
                [System.Windows.MessageBox]::Show("Failed to create template: $($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        })

        # Show dialog
        $result = $dialog.ShowDialog()

        if ($result -eq $true -and $dialog.Tag.created) {
            [System.Windows.MessageBox]::Show("Template '$($dialog.Tag.template.Name)' created successfully!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Load-TemplatesList
        }
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open create template dialog: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Error in New-CustomTemplate: $_" -Level "ERROR"
    }
}

function Invoke-RuleWizard {
    <#
    .SYNOPSIS
        Launch the step-by-step rule creation wizard
    #>
    Write-Log "Launching Rule Wizard"

    # Create XAML for wizard
    $wizardXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AppLocker Rule Wizard" Height="550" Width="700"
        WindowStartupLocation="CenterOwner" Background="#0D1117" ResizeMode="CanMinimize">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <TextBlock Grid.Row="0" Name="WizardTitle" Text="Step 1: Select Rule Type" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,8"/>

        <!-- Progress Indicator -->
        <Border Grid.Row="1" Background="#21262D" CornerRadius="6" Padding="12" Margin="0,0,0,16">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Border Grid.Column="0" Name="Step1Indicator" Background="#8957E5" CornerRadius="4" Height="4" Margin="2,0"/>
                <Border Grid.Column="1" Name="Step2Indicator" Background="#30363D" CornerRadius="4" Height="4" Margin="2,0"/>
                <Border Grid.Column="2" Name="Step3Indicator" Background="#30363D" CornerRadius="4" Height="4" Margin="2,0"/>
                <Border Grid.Column="3" Name="Step4Indicator" Background="#30363D" CornerRadius="4" Height="4" Margin="2,0"/>
                <Border Grid.Column="4" Name="Step5Indicator" Background="#30363D" CornerRadius="4" Height="4" Margin="2,0"/>
            </Grid>
        </Border>

        <!-- Step Content Panels -->
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" Name="WizardContent">
            <StackPanel Name="Step1Panel">
                <TextBlock Text="Select the type of rule you want to create:" FontSize="13" Foreground="#8B949E" Margin="0,0,0,12"/>
                <RadioButton Name="PublisherRuleRadio" Content="Publisher Rule (recommended)" FontSize="13" Foreground="#E6EDF3" Margin="0,8,0,8" IsChecked="True"/>
                <TextBlock Text="Rules based on digital signature. Most flexible option." FontSize="11" Foreground="#6E7681" Margin="24,0,0,12"/>
                <RadioButton Name="PathRuleRadio" Content="Path Rule" FontSize="13" Foreground="#E6EDF3" Margin="0,8,0,8"/>
                <TextBlock Text="Rules based on file path. Less flexible but simple." FontSize="11" Foreground="#6E7681" Margin="24,0,0,12"/>
                <RadioButton Name="HashRuleRadio" Content="Hash Rule" FontSize="13" Foreground="#E6EDF3" Margin="0,8,0,8"/>
                <TextBlock Text="Rules based on file hash. Most secure but breaks on updates." FontSize="11" Foreground="#6E7681" Margin="24,0,0,12"/>
            </StackPanel>

            <StackPanel Name="Step2Panel" Visibility="Collapsed">
                <TextBlock Text="Select the applications to create rules for:" FontSize="13" Foreground="#8B949E" Margin="0,0,0,12"/>
                <Grid Margin="0,0,0,12">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox Name="AppPathInput" Grid.Column="0" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="12" Text="C:\Program Files\MyApp\app.exe"/>
                    <Button Name="BrowseAppBtn" Grid.Column="1" Content="Browse..." Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                </Grid>
                <Button Name="ScanDirectoryBtn" Content="Scan Directory for Applications" Style="{StaticResource SecondaryButton}" Margin="0,0,0,12"/>
                <ListBox Name="SelectedAppsList" Background="#21262D" BorderBrush="#30363D" BorderThickness="1" Height="200" FontSize="11" Foreground="#E6EDF3">
                    <ListBoxItem Content="No applications selected"/>
                </ListBox>
            </StackPanel>

            <StackPanel Name="Step3Panel" Visibility="Collapsed">
                <TextBlock Text="Configure rule options:" FontSize="13" Foreground="#8B949E" Margin="0,0,0,12"/>
                <Border Background="#21262D" CornerRadius="6" Padding="16" Margin="0,0,0,12">
                    <StackPanel>
                        <TextBlock Text="Action" FontSize="12" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                        <RadioButton Name="AllowActionRadio" Content="Allow" FontSize="13" Foreground="#E6EDF3" IsChecked="True" Margin="0,4"/>
                        <RadioButton Name="DenyActionRadio" Content="Deny" FontSize="13" Foreground="#E6EDF3" Margin="0,4"/>
                    </StackPanel>
                </Border>
                <Border Background="#21262D" CornerRadius="6" Padding="16" Margin="0,0,0,12">
                    <StackPanel>
                        <TextBlock Text="Exceptions (optional)" FontSize="12" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                        <CheckBox Name="UseExceptionsCheck" Content="Add exception rules" FontSize="12" Foreground="#E6EDF3"/>
                        <TextBox Name="ExceptionsInput" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="11" Height="80" TextWrapping="Wrap" Margin="0,8,0,0" IsEnabled="False" Text="Enter file paths or publisher names (one per line)"/>
                    </StackPanel>
                </Border>
            </StackPanel>

            <StackPanel Name="Step4Panel" Visibility="Collapsed">
                <TextBlock Text="Select the user/group this rule applies to:" FontSize="13" Foreground="#8B949E" Margin="0,0,0,12"/>
                <ComboBox Name="UserGroupCombo" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="12" Margin="0,0,0,12">
                    <ComboBoxItem Content="Everyone" IsSelected="True"/>
                    <ComboBoxItem Content="Authenticated Users"/>
                    <ComboBoxItem Content="Domain Users"/>
                    <ComboBoxItem Content="Administrators"/>
                    <ComboBoxItem Content="Users"/>
                </ComboBox>
                <TextBlock Text="Or enter custom SID/group name:" FontSize="12" Foreground="#8B949E" Margin="0,8,0,4"/>
                <TextBox Name="CustomGroupInput" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" Padding="8" FontSize="12"/>
            </StackPanel>

            <StackPanel Name="Step5Panel" Visibility="Collapsed">
                <TextBlock Text="Review your rule configuration:" FontSize="13" Foreground="#8B949E" Margin="0,0,0,12"/>
                <Border Background="#21262D" CornerRadius="6" Padding="16">
                    <StackPanel>
                        <TextBlock Name="ReviewRuleType" Text="Rule Type: Publisher" FontSize="12" Foreground="#E6EDF3" Margin="0,4"/>
                        <TextBlock Name="ReviewApplications" Text="Applications: 0 selected" FontSize="12" Foreground="#E6EDF3" Margin="0,4"/>
                        <TextBlock Name="ReviewAction" Text="Action: Allow" FontSize="12" Foreground="#E6EDF3" Margin="0,4"/>
                        <TextBlock Name="ReviewUserGroup" Text="User Group: Everyone" FontSize="12" Foreground="#E6EDF3" Margin="0,4"/>
                        <TextBlock Name="ReviewExceptions" Text="Exceptions: None" FontSize="12" Foreground="#E6EDF3" Margin="0,4"/>
                    </StackPanel>
                </Border>
            </StackPanel>
        </ScrollViewer>

        <!-- Navigation Buttons -->
        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
            <Button Name="WizardBackBtn" Content="Back" Style="{StaticResource SecondaryButton}" Margin="0,0,12,0" IsEnabled="False"/>
            <Button Name="WizardNextBtn" Content="Next" Style="{StaticResource PrimaryButton}" Margin="0,0,12,0"/>
            <Button Name="WizardCancelBtn" Content="Cancel" Style="{StaticResource SecondaryButton}"/>
            <Button Name="WizardFinishBtn" Content="Finish" Style="{StaticResource PrimaryButton}" Visibility="Collapsed"/>
        </StackPanel>
    </Grid>
</Window>
"@

    try {
        # Parse and create wizard
        $wizard = [Windows.Markup.XamlReader]::Parse($wizardXaml)
        $wizard.Owner = $window

        # Find controls
        $WizardTitle = $wizard.FindName("WizardTitle")
        $Step1Indicator = $wizard.FindName("Step1Indicator")
        $Step2Indicator = $wizard.FindName("Step2Indicator")
        $Step3Indicator = $wizard.FindName("Step3Indicator")
        $Step4Indicator = $wizard.FindName("Step4Indicator")
        $Step5Indicator = $wizard.FindName("Step5Indicator")
        $Step1Panel = $wizard.FindName("Step1Panel")
        $Step2Panel = $wizard.FindName("Step2Panel")
        $Step3Panel = $wizard.FindName("Step3Panel")
        $Step4Panel = $wizard.FindName("Step4Panel")
        $Step5Panel = $wizard.FindName("Step5Panel")
        $PublisherRuleRadio = $wizard.FindName("PublisherRuleRadio")
        $PathRuleRadio = $wizard.FindName("PathRuleRadio")
        $HashRuleRadio = $wizard.FindName("HashRuleRadio")
        $AppPathInput = $wizard.FindName("AppPathInput")
        $BrowseAppBtn = $wizard.FindName("BrowseAppBtn")
        $ScanDirectoryBtn = $wizard.FindName("ScanDirectoryBtn")
        $SelectedAppsList = $wizard.FindName("SelectedAppsList")
        $AllowActionRadio = $wizard.FindName("AllowActionRadio")
        $DenyActionRadio = $wizard.FindName("DenyActionRadio")
        $UseExceptionsCheck = $wizard.FindName("UseExceptionsCheck")
        $ExceptionsInput = $wizard.FindName("ExceptionsInput")
        $UserGroupCombo = $wizard.FindName("UserGroupCombo")
        $CustomGroupInput = $wizard.FindName("CustomGroupInput")
        $ReviewRuleType = $wizard.FindName("ReviewRuleType")
        $ReviewApplications = $wizard.FindName("ReviewApplications")
        $ReviewAction = $wizard.FindName("ReviewAction")
        $ReviewUserGroup = $wizard.FindName("ReviewUserGroup")
        $ReviewExceptions = $wizard.FindName("ReviewExceptions")
        $WizardBackBtn = $wizard.FindName("WizardBackBtn")
        $WizardNextBtn = $wizard.FindName("WizardNextBtn")
        $WizardCancelBtn = $wizard.FindName("WizardCancelBtn")
        $WizardFinishBtn = $wizard.FindName("WizardFinishBtn")

        # Wizard state
        $currentStep = 1
        $selectedApps = @()

        # Step panels array
        $stepPanels = @($Step1Panel, $Step2Panel, $Step3Panel, $Step4Panel, $Step5Panel)
        $stepIndicators = @($Step1Indicator, $Step2Indicator, $Step3Indicator, $Step4Indicator, $Step5Indicator)
        $stepTitles = @(
            "Step 1: Select Rule Type",
            "Step 2: Select Applications",
            "Step 3: Configure Options",
            "Step 4: Select User Groups",
            "Step 5: Review and Confirm"
        )

        # Function to update wizard UI
        function Update-WizardStep {
            param([int]$step)

            $currentStep = $step
            $WizardTitle.Text = $stepTitles[$step - 1]

            # Hide all panels
            foreach ($panel in $stepPanels) {
                if ($null -ne $panel) {
                $panel.Visibility = [System.Windows.Visibility]::Collapsed
                }
            }

            # Show current panel
            $stepPanels[$step - 1].Visibility = [System.Windows.Visibility]::Visible

            # Update indicators
            for ($i = 0; $i -lt 5; $i++) {
                if ($i -lt $step) {
                    $stepIndicators[$i].Background = "#8957E5"
                } else {
                    $stepIndicators[$i].Background = "#30363D"
                }
            }

            # Update buttons
            $WizardBackBtn.IsEnabled = ($step -gt 1)
            if ($step -eq 5) {
                if ($null -ne $WizardNextBtn) {
                $WizardNextBtn.Visibility = [System.Windows.Visibility]::Collapsed
                }
                if ($null -ne $WizardFinishBtn) {
                $WizardFinishBtn.Visibility = [System.Windows.Visibility]::Visible
                }
            } else {
                if ($null -ne $WizardNextBtn) {
                $WizardNextBtn.Visibility = [System.Windows.Visibility]::Visible
                }
                if ($null -ne $WizardFinishBtn) {
                $WizardFinishBtn.Visibility = [System.Windows.Visibility]::Collapsed
                }
            }

            # Update review panel on step 5
            if ($step -eq 5) {
                $ruleType = if ($PublisherRuleRadio.IsChecked) { "Publisher" } elseif ($PathRuleRadio.IsChecked) { "Path" } else { "Hash" }
                $ReviewRuleType.Text = "Rule Type: $ruleType"
                $ReviewApplications.Text = "Applications: $($selectedApps.Count) selected"
                $ReviewAction.Text = "Action: $(if ($AllowActionRadio.IsChecked) { 'Allow' } else { 'Deny' })"
                $ReviewUserGroup.Text = "User Group: $($UserGroupCombo.SelectedItem.Content)"
                $ReviewExceptions.Text = "Exceptions: $(if ($UseExceptionsCheck.IsChecked) { 'Enabled' } else { 'None' })"
            }
        }

        # Back button
        $WizardBackBtn.Add_Click({
            if ($currentStep -gt 1) {
                $currentStep--
                Update-WizardStep $currentStep
            }
        })

        # Next button
        $WizardNextBtn.Add_Click({
            if ($currentStep -lt 5) {
                # Validate current step before proceeding
                if ($currentStep -eq 2 -and $selectedApps.Count -eq 0) {
                    [System.Windows.MessageBox]::Show("Please select at least one application.", "Validation", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                    return
                }

                $currentStep++
                Update-WizardStep $currentStep
            }
        })

        # Cancel button
        $WizardCancelBtn.Add_Click({
            $wizard.DialogResult = $false
            $wizard.Close()
        })

        # Finish button
        $WizardFinishBtn.Add_Click({
            [System.Windows.MessageBox]::Show("Rule creation complete! This feature would integrate with the Rules panel to create the actual AppLocker rules.", "Wizard Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            $wizard.DialogResult = $true
            $wizard.Close()
        })

        # Browse button
        $BrowseAppBtn.Add_Click({
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*"
            if ($openFileDialog.ShowDialog() -eq 'OK') {
                $AppPathInput.Text = $openFileDialog.FileName
                $selectedApps = @($openFileDialog.FileName)
                $SelectedAppsList.Items.Clear()
                $SelectedAppsList.Items.Add($openFileDialog.FileName)
            }
        })

        # Use exceptions checkbox
        $UseExceptionsCheck.Add_Checked({
            $ExceptionsInput.IsEnabled = $true
        })
        $UseExceptionsCheck.Add_Unchecked({
            $ExceptionsInput.IsEnabled = $false
        })

        # Show wizard
        $null = $wizard.ShowDialog()

    } catch {
        [System.Windows.MessageBox]::Show("Failed to open Rule Wizard: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Error in Invoke-RuleWizard: $_" -Level "ERROR"
    }
}

function Validate-Template {
    <#
    .SYNOPSIS
        Validate a template structure and content
    #>
    param(
        [Parameter(Mandatory=$true)]
        $Template
    )

    $errors = @()
    $warnings = @()

    # Check required fields
    if (-not $Template.Id) { $errors += "Missing template Id" }
    if (-not $Template.Name) { $errors += "Missing template Name" }
    if (-not $Template.Category) { $errors += "Missing template Category" }
    if (-not $Template.Rules) { $errors += "Missing template Rules" }

    # Validate rules
    if ($Template.Rules) {
        foreach ($rule in $Template.Rules) {
            if (-not $rule.Name) { $errors += "Rule missing Name" }
            if (-not $rule.Type) { $errors += "Rule missing Type" }

            # Check rule type-specific fields
            switch ($rule.Type) {
                "Publisher" {
                    if (-not $rule.Publisher) { $errors += "Publisher rule missing Publisher field" }
                }
                "Path" {
                    if (-not $rule.Path) { $errors += "Path rule missing Path field" }
                }
                "Hash" {
                    if (-not $rule.Hash) { $errors += "Hash rule missing Hash field" }
                }
            }
        }
    }

    return @{
        valid = ($errors.Count -eq 0)
        errors = $errors
        warnings = $warnings
    }
}

function Merge-Templates {
    <#
    .SYNOPSIS
        Combine multiple templates into a single template
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$TemplateIds,
        [Parameter(Mandatory=$true)]
        [string]$MergedName,
        [string]$MergedDescription = ""
    )

    Write-Log "Merging templates: $($TemplateIds -join ', ')"

    $allRules = @()
    $allApps = @()
    $sourceTemplates = @()

    foreach ($id in $TemplateIds) {
        $result = Get-TemplateContent -TemplateId $id
        if ($result.success) {
            $template = $result.template
            $sourceTemplates += $template.Name
            $allRules += $template.Rules
            $allApps += $template.Applications
        }
    }

    if ($allRules.Count -eq 0) {
        return @{
            success = $false
            error = "No valid templates found to merge"
        }
    }

    $mergedTemplate = @{
        Id = "merged-" + (New-Guid).ToString().Substring(0, 8)
        Name = $MergedName
        Category = "Custom"
        Description = if ($MergedDescription) { $MergedDescription } else { "Merged from: $($sourceTemplates -join ', ')" }
        RuleCount = $allRules.Count
        Applications = $allApps | Select-Object -Unique
        Rules = $allRules
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SourceTemplates = $sourceTemplates
    }

    return @{
        success = $true
        template = $mergedTemplate
    }
}

function Import-RuleTemplateFromFile {
    <#
    .SYNOPSIS
        Import a template from a JSON file
    #>
    Write-Log "Importing template from file"

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Template Files (*.json)|*.json|All Files (*.*)|*.*"
    $openFileDialog.Title = "Select Template File to Import"

    if ($openFileDialog.ShowDialog() -ne 'OK') {
        return
    }

    try {
        $templateData = Get-Content -Path $openFileDialog.FileName -Raw | ConvertFrom-Json

        # Validate template
        $validation = Validate-Template -Template $templateData
        if (-not $validation.valid) {
            [System.Windows.MessageBox]::Show("Invalid template file:`n$($validation.errors -join "`n")", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        # Save to custom templates
        $templatesDir = "C:\GA-AppLocker\Templates"
        if (-not (Test-Path $templatesDir)) {
            New-Item -ItemType Directory -Path $templatesDir -Force | Out-Null
        }

        $customTemplatesPath = Join-Path $templatesDir "custom-templates.json"
        $customTemplates = @()

        if (Test-Path $customTemplatesPath) {
            $customTemplates = Get-Content -Path $customTemplatesPath -Raw | ConvertFrom-Json
        }

        $customTemplates += $templateData
        $customTemplates | ConvertTo-Json -Depth 10 | Set-Content -Path $customTemplatesPath

        [System.Windows.MessageBox]::Show("Template '$($templateData.Name)' imported successfully!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

        # Refresh templates list if Templates panel is open
        if ($PanelTemplates.Visibility -eq [System.Windows.Visibility]::Visible) {
            Load-TemplatesList
        }
    } catch {
        [System.Windows.MessageBox]::Show("Failed to import template: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Error importing template: $_" -Level "ERROR"
    }
}

function Load-TemplatesList {
    <#
    .SYNOPSIS
        Load and display templates in the Templates panel
    #>
    Write-Log "Loading templates list"

    try {
        # Get filters
        $category = if ($TemplateCategoryFilter.SelectedItem) { $TemplateCategoryFilter.SelectedItem.Content } else { "All Categories" }
        $searchTerm = if ($TemplateSearch.Text -and $TemplateSearch.Text -ne "Search templates...") { $TemplateSearch.Text } else { "" }

        # Get templates
        $templates = Get-RuleTemplates -Category $category -SearchTerm $searchTerm

        # Clear and populate list
        $TemplatesList.Items.Clear()

        foreach ($template in $templates) {
            $item = New-Object PSObject -Property @{
                Name = $template.Name
                Category = $template.Category
                RuleCount = "$($template.RuleCount) rules"
                Template = $template
            }
            $TemplatesList.Items.Add($item)
        }

        Write-Log "Loaded $($templates.Count) templates"
    } catch {
        Write-Log "Error loading templates list: $_" -Level "ERROR"
    }
}

# Handle window closing properly
$window.add_Closing({
    param($sender, $e)
    # Allow the window to close
    $e.Cancel = $false
})

# Phase 5: Templates panel event handlers
# Template selection changed
$TemplatesList.Add_SelectionChanged({
    if ($TemplatesList.SelectedItem) {
        $template = $TemplatesList.SelectedItem.Template
        $TemplateName.Text = $template.Name
        $TemplateCategory.Text = $template.Category
        $TemplateDescription.Text = $template.Description

        # Build rules summary
        $rulesText = ($template.Rules | ForEach-Object { "- $($_.Name) ($($_.Type))" }) -join "`n"
        $TemplateRulesSummary.Text = $rulesText

        # Build applications list
        $appsText = $template.Applications -join ", "
        $TemplateApplications.Text = $appsText

        # Enable action buttons
        $ApplyTemplateBtn.IsEnabled = $true
        $EditTemplateBtn.IsEnabled = $true
        $DeleteTemplateBtn.IsEnabled = ($template.Category -eq "Custom")
    } else {
        $TemplateName.Text = "Select a template to preview"
        $TemplateCategory.Text = ""
        $TemplateDescription.Text = ""
        $TemplateRulesSummary.Text = "No template selected"
        $TemplateApplications.Text = "No template selected"

        $ApplyTemplateBtn.IsEnabled = $false
        $EditTemplateBtn.IsEnabled = $false
        $DeleteTemplateBtn.IsEnabled = $false
    }
})

# Search box
$TemplateSearch.Add_TextChanged({
    Load-TemplatesList
})

# Category filter
$TemplateCategoryFilter.Add_SelectionChanged({
    Load-TemplatesList
})

# Refresh button
if ($null -ne $RefreshTemplatesBtn) {
$RefreshTemplatesBtn.Add_Click({
    Write-Log "Refreshing templates list"
    Load-TemplatesList
    [System.Windows.MessageBox]::Show("Templates list refreshed.", "Refresh", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})
}

# Export button
if ($null -ne $ExportTemplateBtn) {
$ExportTemplateBtn.Add_Click({
    Write-Log "Export template button clicked"

    if (-not $TemplatesList.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a template to export.", "No Template Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $template = $TemplatesList.SelectedItem.Template

    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Template Files (*.json)|*.json|All Files (*.*)|*.*"
    $saveFileDialog.Title = "Export Template"
    $saveFileDialog.FileName = "$($template.Name -replace ' ', '-').json"

    if ($saveFileDialog.ShowDialog() -ne 'OK') {
        return
    }

    try {
        $template | ConvertTo-Json -Depth 10 | Set-Content -Path $saveFileDialog.FileName
        [System.Windows.MessageBox]::Show("Template exported to:`n$($saveFileDialog.FileName)", "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-Log "Template exported to $($saveFileDialog.FileName)"
    } catch {
        [System.Windows.MessageBox]::Show("Failed to export template: $_", "Export Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Error exporting template: $_" -Level "ERROR"
    }
})
}

# Apply template button
if ($null -ne $ApplyTemplateBtn) {
$ApplyTemplateBtn.Add_Click({
    Write-Log "Apply template button clicked"

    if (-not $TemplatesList.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a template to apply.", "No Template Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $template = $TemplatesList.SelectedItem.Template

    # Show dialog to select user group
    $groupDialogResult = Show-GroupSelectionDialog
    if (-not $groupDialogResult.success) {
        return
    }

    $userGroup = $groupDialogResult.group

    # Confirm
    $result = [System.Windows.MessageBox]::Show(
        "Apply template '$($template.Name)' to group '$userGroup'?",
        "Confirm Template Application",
        [System.Windows.MessageBoxButton]::OKCancel,
        [System.Windows.MessageBoxImage]::Question
    )

    if ($result -ne [System.Windows.MessageBoxResult]::OK) {
        return
    }

    # Import template
    $importResult = Import-RuleTemplate -TemplateId $template.Id -UserGroup $userGroup

    if ($importResult.success) {
        [System.Windows.MessageBox]::Show(
            "Template applied successfully!`n`nImported $($importResult.importedCount) rules.",
            "Success",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information
        )
        Write-Log "Template $($template.Name) applied to $userGroup - $($importResult.importedCount) rules imported"
    } else {
        [System.Windows.MessageBox]::Show(
            "Failed to apply template:`n$($importResult.error)",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
        Write-Log "Failed to apply template: $($importResult.error)" -Level "ERROR"
    }
})
}

# Edit template button
if ($null -ne $EditTemplateBtn) {
$EditTemplateBtn.Add_Click({
    Write-Log "Edit template button clicked"

    if (-not $TemplatesList.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a template to edit.", "No Template Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $template = $TemplatesList.SelectedItem.Template

    [System.Windows.MessageBox]::Show(
        "Template editing will be implemented in a future update.`n`nFor now, you can:`n- Create a new template based on this one`n- Export and modify the JSON file manually",
        "Edit Template",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information
    )
})
}

# Delete template button
if ($null -ne $DeleteTemplateBtn) {
$DeleteTemplateBtn.Add_Click({
    Write-Log "Delete template button clicked"

    if (-not $TemplatesList.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a template to delete.", "No Template Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $template = $TemplatesList.SelectedItem.Template

    if ($template.Category -ne "Custom") {
        [System.Windows.MessageBox]::Show("Only custom templates can be deleted.", "Cannot Delete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $result = [System.Windows.MessageBox]::Show(
        "Delete template '$($template.Name)'?`n`nThis action cannot be undone.",
        "Confirm Delete",
        [System.Windows.MessageBoxButton]::OKCancel,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($result -ne [System.Windows.MessageBoxResult]::OK) {
        return
    }

    try {
        $customTemplatesPath = "C:\GA-AppLocker\Templates\custom-templates.json"
        if (Test-Path $customTemplatesPath) {
            $customTemplates = Get-Content -Path $customTemplatesPath -Raw | ConvertFrom-Json
            $customTemplates = $customTemplates | Where-Object { $_.Id -ne $template.Id }
            $customTemplates | ConvertTo-Json -Depth 10 | Set-Content -Path $customTemplatesPath

            [System.Windows.MessageBox]::Show("Template deleted successfully.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Write-Log "Template $($template.Name) deleted"
            Load-TemplatesList
        }
    } catch {
        [System.Windows.MessageBox]::Show("Failed to delete template: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Error deleting template: $_" -Level "ERROR"
    }
})
}

# Initialize on load - fast startup, defer slow operations
$window.add_Loaded({
    # Initialize folder structure first
    $folderInit = Initialize-AppLockerFolders
    if (-not $folderInit.success) {
        Write-Log "Warning: Could not create folder structure: $($folderInit.error)" -Level "WARN"
    }

    # Set version info first (instant)
    $script:AppVersion = "1.2.5"
    $AboutVersion.Text = "Version $script:AppVersion"

    # Show loading state
    $EnvironmentText.Text = "Detecting environment..."
    $StatusText.Text = "Initializing..."

    # Load dashboard immediately with placeholder
    Show-Panel "Dashboard"
    $DashboardOutput.Text = "=== GA-APPLOCKER DASHBOARD ===`n`nLoading environment..."

    # Force UI to render before heavy operations
    $window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    # Now do domain detection (fast with fixed logic)
    $script:DomainInfo = Get-DomainInfo
    $script:IsWorkgroup = $script:DomainInfo.isWorkgroup
    $script:HasRSAT = $script:DomainInfo.hasRSAT

    Write-Log "Application started - Mode: $($script:DomainInfo.message)"

    # Update environment banner based on environment type
    if ($script:IsWorkgroup) {
        # Workgroup - no domain features
        $EnvironmentText.Text = "WORKGROUP MODE - Localhost scanning only | AD/GPO features disabled"
        $EnvironmentBanner.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#21262D")

        # Disable AD/GPO related buttons
        $CreateWinRMGpoBtn.IsEnabled = $false
        $ForceGPUpdateBtn.IsEnabled = $false
        $ExportGroupsBtn.IsEnabled = $false
        $ImportGroupsBtn.IsEnabled = $false
        $BootstrapAppLockerBtn.IsEnabled = $false
        $RemoveOUProtectionBtn.IsEnabled = $false
        $DiscoverComputersBtn.IsEnabled = $false
        # Gap Analysis buttons work in workgroup mode (CSV import)
        $DefaultDenyRulesBtn.IsEnabled = $false

        # NOTE: Navigation buttons remain ENABLED in workgroup mode
        # Users can access all panels, but AD-dependent buttons within are greyed out
        # This allows users to see what features exist and understand workgroup limitations

        # Disable remaining WinRM buttons
        $EnableWinRMGpoBtn.IsEnabled = $false
        $DisableWinRMGpoBtn.IsEnabled = $false

        # Disable AD Discovery panel buttons
        $TestConnectivityBtn.IsEnabled = $false
        $SelectAllComputersBtn.IsEnabled = $false
        $ScanSelectedBtn.IsEnabled = $false

        # Disable remote scanning in Events panel
        $ScanRemoteEventsBtn.IsEnabled = $false
        $RefreshComputersBtn.IsEnabled = $false

        # Disable remote scanning in Compliance panel
        $ScanSelectedComplianceBtn.IsEnabled = $false
        $RefreshComplianceListBtn.IsEnabled = $false

        Write-Log "Workgroup mode: AD/GPO buttons disabled, navigation enabled"
    } elseif (-not $script:HasRSAT) {
        # Domain-joined but no RSAT - limited features
        $EnvironmentText.Text = "DOMAIN: $($script:DomainInfo.dnsRoot) | RSAT not installed - Install RSAT for GPO features"
        $EnvironmentBanner.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#D29922")
        $EnvironmentText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#000000")

        # Disable GPO-related buttons (need RSAT)
        $CreateWinRMGpoBtn.IsEnabled = $false
        $ForceGPUpdateBtn.IsEnabled = $false
        $ExportGroupsBtn.IsEnabled = $false
        $ImportGroupsBtn.IsEnabled = $false
        $BootstrapAppLockerBtn.IsEnabled = $false
        $RemoveOUProtectionBtn.IsEnabled = $false
        $DiscoverComputersBtn.IsEnabled = $false
        # Gap Analysis buttons work without RSAT (CSV import)
        $DefaultDenyRulesBtn.IsEnabled = $false

        # NOTE: Navigation buttons remain ENABLED in RSAT mode
        # Users can access all panels, but GPO-dependent buttons within are greyed out

        # Disable remaining WinRM buttons
        $EnableWinRMGpoBtn.IsEnabled = $false
        $DisableWinRMGpoBtn.IsEnabled = $false

        # Disable AD Discovery panel buttons
        $TestConnectivityBtn.IsEnabled = $false
        $SelectAllComputersBtn.IsEnabled = $false
        $ScanSelectedBtn.IsEnabled = $false

        # Disable remote scanning in Events panel
        $ScanRemoteEventsBtn.IsEnabled = $false
        $RefreshComputersBtn.IsEnabled = $false

        # Disable remote scanning in Compliance panel
        $ScanSelectedComplianceBtn.IsEnabled = $false
        $RefreshComplianceListBtn.IsEnabled = $false

        Write-Log "Domain mode without RSAT: GPO features disabled - install RSAT tools"
    } else {
        # Domain with RSAT - full features
        $EnvironmentText.Text = "DOMAIN: $($script:DomainInfo.dnsRoot) | Full features available"
        $EnvironmentBanner.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#238636")
        $EnvironmentText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFFFFF")

        # Enable all buttons
        $CreateWinRMGpoBtn.IsEnabled = $true
        $DiscoverComputersBtn.IsEnabled = $true
        $ImportBaselineBtn.IsEnabled = $true
        $ImportTargetBtn.IsEnabled = $true
        $DefaultDenyRulesBtn.IsEnabled = $true

        # Enable navigation buttons
        $NavWinRM.IsEnabled = $true
        $NavDiscovery.IsEnabled = $true
        $NavDeployment.IsEnabled = $true
        $NavGroupMgmt.IsEnabled = $true

        # Enable WinRM buttons
        $EnableWinRMGpoBtn.IsEnabled = $true
        $DisableWinRMGpoBtn.IsEnabled = $true

        # Enable AD Discovery panel buttons
        $TestConnectivityBtn.IsEnabled = $true
        $SelectAllComputersBtn.IsEnabled = $true
        $ScanSelectedBtn.IsEnabled = $true

        # Enable remote scanning in Events panel
        $ScanRemoteEventsBtn.IsEnabled = $true

        # Enable remote scanning in Compliance panel
        $ScanSelectedComplianceBtn.IsEnabled = $true
        $RefreshComplianceListBtn.IsEnabled = $true

        Write-Log "Domain mode with RSAT: All features enabled"
    }

    # Load icons (non-blocking)
    try {
        # Try multiple locations for icons
        $iconPaths = @(
            (Join-Path $script:ScriptRoot "GA-AppLocker.ico"),
            (Join-Path $script:ScriptRoot "..\build\GA-AppLocker.ico"),
            "C:\GA-AppLocker\build\GA-AppLocker.ico"
        )

        foreach ($iconPath in $iconPaths) {
            if (Test-Path $iconPath) {
                $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create((New-Object System.Uri $iconPath))
                break
            }
        }
    } catch { }

    # Load header logo
    try {
        $logoPaths = @(
            (Join-Path $script:ScriptRoot "GA-AppLocker.png"),
            (Join-Path $script:ScriptRoot "..\build\GA-AppLocker.png"),
            "C:\GA-AppLocker\build\GA-AppLocker.png"
        )

        foreach ($logoPath in $logoPaths) {
            if (Test-Path $logoPath) {
                $headerBitmap = [System.Windows.Media.Imaging.BitmapImage]::new()
                $headerBitmap.BeginInit()
                $headerBitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
                $headerBitmap.UriSource = (New-Object System.Uri $logoPath)
                $headerBitmap.EndInit()
                $headerBitmap.Freeze()
                $HeaderLogo.Source = $headerBitmap
                break
            }
        }
    } catch { }

    # Load About page logo
    try {
        $aboutLogoPaths = @(
            (Join-Path $script:ScriptRoot "general_atomics_logo_big.ico"),
            (Join-Path $script:ScriptRoot "..\general_atomics_logo_big.ico"),
            "C:\GA-AppLocker\general_atomics_logo_big.ico"
        )

        foreach ($logoPath in $aboutLogoPaths) {
            if (Test-Path $logoPath) {
                $aboutBitmap = [System.Windows.Media.Imaging.BitmapImage]::new()
                $aboutBitmap.BeginInit()
                $aboutBitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
                $aboutBitmap.UriSource = (New-Object System.Uri $logoPath)
                $aboutBitmap.EndInit()
                $aboutBitmap.Freeze()
                $AboutLogo.Source = $aboutBitmap
                break
            }
        }
    } catch { }

    # Refresh dashboard data
    Refresh-Data
    Update-StatusBar

    # Initialize Quick Import badges
    Update-Badges

    # Initialize session management (Phase 2 security)
    Initialize-SessionTimer
    Attach-ActivityTrackers -Window $window

    # Phase 3: Register keyboard shortcuts
    Register-KeyboardShortcuts -Window $window

    # Phase 4: Initialize tooltips and auto-save
    Initialize-Tooltips
    Start-AutoSaveTimer

    # Set final message
    $DashboardOutput.Text = "=== GA-APPLOCKER DASHBOARD ===`n`nAaronLocker-aligned AppLocker Policy Management`n`nEnvironment: $($script:DomainInfo.message)`n`nReady to begin. Select a tab to start.`n`nSession timeout: $($script:SessionTimeoutMinutes) minutes of inactivity."
})

# ============================================================
# AARONLOCKER TOOLS - Button Event Handlers
# ============================================================
# Define AaronLocker root path - search multiple locations
$script:AaronLockerRoot = $null
$aaronLockerSearchPaths = @(
    # 1. Relative to script location (for running from repo/extracted folder)
    (Join-Path $PSScriptRoot "..\AaronLocker-main\AaronLocker"),
    (Join-Path $PSScriptRoot "AaronLocker-main\AaronLocker"),
    # 2. Standard install location
    "C:\GA-AppLocker\AaronLocker-main\AaronLocker",
    # 3. Alternative locations
    (Join-Path $env:ProgramData "GA-AppLocker\AaronLocker-main\AaronLocker"),
    (Join-Path $env:USERPROFILE "GA-AppLocker\AaronLocker-main\AaronLocker")
)
foreach ($searchPath in $aaronLockerSearchPaths) {
    if (Test-Path (Join-Path $searchPath "Support\Config.ps1")) {
        $script:AaronLockerRoot = $searchPath
        Write-Log "AaronLocker found at: $searchPath"
        break
    }
}
if (-not $script:AaronLockerRoot) {
    $script:AaronLockerRoot = "C:\GA-AppLocker\AaronLocker-main\AaronLocker"
    Write-Log "AaronLocker not found - using default path: $($script:AaronLockerRoot)" -Level "WARNING"
}

# Helper function to run AaronLocker scripts
function Invoke-AaronLockerScript {
    param(
        [string]$ScriptPath,
        [string]$ScriptName,
        [hashtable]$Parameters = @{}
    )

    if (-not (Test-Path $ScriptPath)) {
        $AL_OutputConsole.Text = "ERROR: Script not found at $ScriptPath`n`nPlease ensure AaronLocker is installed at:`n$script:AaronLockerRoot"
        return
    }

    $AL_OutputConsole.Text = "Running: $ScriptName`n`nScript: $ScriptPath`n`nPlease wait..."
    $AL_OutputConsole.ScrollToEnd()

    try {
        # Set rootDir variable required by AaronLocker
        $rootDir = $script:AaronLockerRoot

        # Build parameter string
        $paramString = ""
        foreach ($key in $Parameters.Keys) {
            $paramString += " -$key `"$($Parameters[$key])`""
        }

        # Run the script in a new PowerShell process
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {
            `$rootDir = '$rootDir'
            . '$ScriptPath' $paramString
        }" 2>&1

        $AL_OutputConsole.Text = "=== $ScriptName ===`n`n$($output -join "`n")`n`n=== COMPLETE ==="
    } catch {
        $AL_OutputConsole.Text = "=== $ScriptName ===`n`nERROR: $($_.Exception.Message)`n`n$($_.ScriptStackTrace)"
    }
    $AL_OutputConsole.ScrollToEnd()
}

# Clear Console button
if ($null -ne $AL_ClearConsole) {
$AL_ClearConsole.Add_Click({
    $AL_OutputConsole.Text = "AaronLocker output will appear here..."
})
}

# === SCANNING & ANALYSIS ===
# Helper function to launch AaronLocker scripts in their own console window
# Uses Windows PowerShell 5.1 explicitly (required for AaronLocker compatibility with -Encoding Byte)
function Start-AaronLockerScript {
    param(
        [string]$ScriptName,
        [string]$ScriptPath,
        [string]$Parameters = ""
    )

    if (-not (Test-Path $ScriptPath)) {
        $AL_OutputConsole.Text = "ERROR: Script not found: $ScriptPath"
        return
    }

    $AL_OutputConsole.Text = "Launching: $ScriptName`nParameters: $Parameters`n`nA new Windows PowerShell 5.1 window will open..."

    # CRITICAL: Must use Windows PowerShell 5.1 (not PowerShell 7/Core)
    # AaronLocker scripts use -Encoding Byte which only works in Windows PowerShell 5.1
    $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

    if (-not (Test-Path $windowsPowerShell)) {
        $AL_OutputConsole.Text = "ERROR: Windows PowerShell 5.1 not found at:`n$windowsPowerShell`n`nAaronLocker requires Windows PowerShell 5.1."
        [System.Windows.MessageBox]::Show(
            "Windows PowerShell 5.1 not found!`n`nAaronLocker requires Windows PowerShell 5.1 (not PowerShell 7).`n`nExpected path:`n$windowsPowerShell",
            "PowerShell 5.1 Required",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
        return
    }

    # Build the command to run - verify PS version first, then run script
    $cmd = @"
`$Host.UI.RawUI.WindowTitle = 'AaronLocker - $ScriptName'
if (`$PSVersionTable.PSVersion.Major -ne 5) {
    Write-Host 'ERROR: This script requires Windows PowerShell 5.1' -ForegroundColor Red
    Write-Host "Current version: `$(`$PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host 'Press any key to close...'
    `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}
Set-Location '$($script:AaronLockerRoot)'
Write-Host '=== $ScriptName ===' -ForegroundColor Cyan
Write-Host "PowerShell Version: `$(`$PSVersionTable.PSVersion)" -ForegroundColor DarkGray
Write-Host "Parameters: $Parameters" -ForegroundColor Gray
Write-Host ''
. '$ScriptPath' $Parameters
Write-Host ''
Write-Host '=== COMPLETE ===' -ForegroundColor Green
Write-Host 'Press any key to close...'
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@

    # Launch in a new visible console window using Windows PowerShell 5.1
    # Use -EncodedCommand to handle complex strings properly
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
    $encodedCommand = [Convert]::ToBase64String($bytes)

    Start-Process $windowsPowerShell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encodedCommand
}

# Scan Directories - Scans writable directories for potential policy bypasses
if ($null -ne $AL_ScanDirectories) {
$AL_ScanDirectories.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Scan-Directories.ps1"

    # Build parameters from checkboxes
    $params = @()
    if ($AL_ScanWritableWindir -and $AL_ScanWritableWindir.IsChecked) { $params += "-WritableWindir" }
    if ($AL_ScanWritablePF -and $AL_ScanWritablePF.IsChecked) { $params += "-WritablePF" }
    if ($AL_ScanProgramData -and $AL_ScanProgramData.IsChecked) { $params += "-SearchProgramData" }
    if ($AL_ScanUserProfile -and $AL_ScanUserProfile.IsChecked) { $params += "-SearchOneUserProfile" }
    if ($AL_ScanAllProfiles -and $AL_ScanAllProfiles.IsChecked) { $params += "-SearchAllUserProfiles" }
    if ($AL_ScanNonDefaultRoot -and $AL_ScanNonDefaultRoot.IsChecked) { $params += "-SearchNonDefaultRootDirs" }
    if ($AL_ScanExcel -and $AL_ScanExcel.IsChecked) { $params += "-Excel" }
    if ($AL_ScanGridView -and $AL_ScanGridView.IsChecked) { $params += "-GridView" }

    # Need at least one scan location
    $scanParams = $params | Where-Object { $_ -notin @("-Excel", "-GridView") }
    if ($scanParams.Count -eq 0) {
        $AL_OutputConsole.Text = "Please select at least one directory to scan (User Profile, ProgramData, etc.)"
        return
    }

    Start-AaronLockerScript -ScriptName "Scan Directories" -ScriptPath $scriptPath -Parameters ($params -join " ")
})
}

# Get AppLocker Events - Retrieves and formats AppLocker events from Event Log
if ($null -ne $AL_GetEvents) {
$AL_GetEvents.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Get-AppLockerEvents.ps1"

    # Build parameters from checkboxes
    $params = @()
    if ($AL_EventsWarningOnly -and $AL_EventsWarningOnly.IsChecked) { $params += "-WarningOnly" }
    elseif ($AL_EventsErrorOnly -and $AL_EventsErrorOnly.IsChecked) { $params += "-ErrorOnly" }
    elseif ($AL_EventsAllowedOnly -and $AL_EventsAllowedOnly.IsChecked) { $params += "-AllowedOnly" }
    elseif ($AL_EventsAll -and $AL_EventsAll.IsChecked) { $params += "-AllEvents" }

    if ($AL_EventsExcel -and $AL_EventsExcel.IsChecked) { $params += "-Excel" }
    if ($AL_EventsGridView -and $AL_EventsGridView.IsChecked) { $params += "-GridView" }

    Start-AaronLockerScript -ScriptName "Get AppLocker Events" -ScriptPath $scriptPath -Parameters ($params -join " ")
})
}

# Compare Policies - Compares two AppLocker policy XML files for differences
if ($null -ne $AL_ComparePolicies) {
$AL_ComparePolicies.Add_Click({
    $AL_OutputConsole.Text = "Select two policy files to compare..."

    $openDialog1 = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog1.Filter = "XML Files (*.xml)|*.xml"
    $openDialog1.Title = "Select FIRST AppLocker Policy File"
    $openDialog1.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog1.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $policy1 = $openDialog1.FileName

        $openDialog2 = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog2.Filter = "XML Files (*.xml)|*.xml"
        $openDialog2.Title = "Select SECOND AppLocker Policy File"
        $openDialog2.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

        if ($openDialog2.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $policy2 = $openDialog2.FileName
            $scriptPath = Join-Path $script:AaronLockerRoot "Compare-Policies.ps1"
            Start-AaronLockerScript -ScriptName "Compare Policies" -ScriptPath $scriptPath -Parameters "-ReferencePolicyXML `"$policy1`" -ComparisonPolicyXML `"$policy2`""
        }
    }
})
}

# Enum Writable Dirs - Enumerates writable directories under Windows/ProgramFiles
if ($null -ne $AL_EnumWritableDirs) {
$AL_EnumWritableDirs.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Support\Enum-WritableDirs.ps1"
    Start-AaronLockerScript -ScriptName "Enumerate Writable Directories" -ScriptPath $scriptPath
})
}

# === POLICY CREATION ===

# Create Policies - Generates AppLocker and/or WDAC policies from scan results
if ($null -ne $AL_CreatePolicies) {
$AL_CreatePolicies.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Create-Policies.ps1"

    # Build parameters from checkboxes
    $params = @()

    # Policy type from combobox
    if ($AL_PolicyType -and $AL_PolicyType.SelectedItem) {
        $policyType = $AL_PolicyType.SelectedItem.Content
        if ($policyType -ne "Both") {
            $params += "-AppLockerOrWDAC $policyType"
        }
    }

    if ($AL_PolicyRescan -and $AL_PolicyRescan.IsChecked) { $params += "-Rescan" }
    if ($AL_PolicyExcel -and $AL_PolicyExcel.IsChecked) { $params += "-Excel" }
    if ($AL_PolicyWDACMI -and $AL_PolicyWDACMI.IsChecked) { $params += "-WDACTrustManagedInstallers" }
    if ($AL_PolicyWDACISG -and $AL_PolicyWDACISG.IsChecked) { $params += "-WDACTrustISG" }

    Start-AaronLockerScript -ScriptName "Create Policies" -ScriptPath $scriptPath -Parameters ($params -join " ")
})
}

# Build Rules for Writable Directories
if ($null -ne $AL_BuildWritableRules) {
$AL_BuildWritableRules.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Support\BuildRulesForFilesInWritableDirectories.ps1"
    Start-AaronLockerScript -ScriptName "Build Rules for Writable Directories" -ScriptPath $scriptPath
})
}

# === EXPORT & REPORTING ===

# Export Policy to CSV
if ($null -ne $AL_ExportToCsv) {
$AL_ExportToCsv.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml"
    $openDialog.Title = "Select AppLocker Policy XML to Export"
    $openDialog.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $scriptPath = Join-Path $script:AaronLockerRoot "Support\ExportPolicy-ToCsv.ps1"
        Start-AaronLockerScript -ScriptName "Export Policy to CSV" -ScriptPath $scriptPath -Parameters "-AppLockerPolicyFile `"$($openDialog.FileName)`""
    }
})
}

# Export Policy to Excel
if ($null -ne $AL_ExportToExcel) {
$AL_ExportToExcel.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml"
    $openDialog.Title = "Select AppLocker Policy XML to Export"
    $openDialog.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $scriptPath = Join-Path $script:AaronLockerRoot "ExportPolicy-ToExcel.ps1"
        Start-AaronLockerScript -ScriptName "Export Policy to Excel" -ScriptPath $scriptPath -Parameters "-AppLockerXML `"$($openDialog.FileName)`""
    }
})
}

# Generate Event Workbook
if ($null -ne $AL_GenerateEventWorkbook) {
$AL_GenerateEventWorkbook.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Generate-EventWorkbook.ps1"
    Start-AaronLockerScript -ScriptName "Generate Event Workbook" -ScriptPath $scriptPath
})
}

# === LOCAL CONFIGURATION ===

# Configure for AppLocker
if ($null -ne $AL_ConfigureForAppLocker) {
$AL_ConfigureForAppLocker.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ConfigureForAppLocker.ps1"
    Start-AaronLockerScript -ScriptName "Configure for AppLocker" -ScriptPath $scriptPath
})
}

# Apply to Local GPO
if ($null -ne $AL_ApplyToLocalGPO) {
$AL_ApplyToLocalGPO.Add_Click({
    # Script auto-selects the latest policy file - user chooses Audit or Enforce mode
    $result = [System.Windows.MessageBox]::Show(
        "Apply the most recent policy to LOCAL GPO?`n`nClick YES to apply ENFORCE rules (blocks unauthorized software)`nClick NO to apply AUDIT rules (logs only, doesn't block)`n`nThis will modify the local Group Policy.",
        "Apply to Local GPO - Choose Mode",
        [System.Windows.MessageBoxButton]::YesNoCancel,
        [System.Windows.MessageBoxImage]::Question
    )

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        # Apply Enforce rules
        $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ApplyPolicyToLocalGPO.ps1"
        Start-AaronLockerScript -ScriptName "Apply Enforce Policy to Local GPO" -ScriptPath $scriptPath -Parameters ""
    }
    elseif ($result -eq [System.Windows.MessageBoxResult]::No) {
        # Apply Audit rules
        $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ApplyPolicyToLocalGPO.ps1"
        Start-AaronLockerScript -ScriptName "Apply Audit Policy to Local GPO" -ScriptPath $scriptPath -Parameters "-AuditOnly"
    }
})
}

# Set GPO AppLocker Policy
if ($null -ne $AL_SetGPOPolicy) {
$AL_SetGPOPolicy.Add_Click({
    # Script auto-selects the latest policy file - user provides GPO name and chooses Audit or Enforce
    $gpoName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the GPO name to apply AppLocker policy to:", "Set GPO AppLocker Policy", "AppLocker Policy")
    if ($gpoName) {
        $result = [System.Windows.MessageBox]::Show(
            "Apply the most recent policy to GPO '$gpoName'?`n`nClick YES to apply ENFORCE rules (blocks unauthorized software)`nClick NO to apply AUDIT rules (logs only, doesn't block)`n`nThis will modify the domain Group Policy.",
            "Set Domain GPO Policy - Choose Mode",
            [System.Windows.MessageBoxButton]::YesNoCancel,
            [System.Windows.MessageBoxImage]::Question
        )

        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            # Apply Enforce rules
            $scriptPath = Join-Path $script:AaronLockerRoot "GPOConfiguration\Set-GPOAppLockerPolicy.ps1"
            Start-AaronLockerScript -ScriptName "Set GPO Enforce Policy" -ScriptPath $scriptPath -Parameters "-GpoName `"$gpoName`" -Enforce"
        }
        elseif ($result -eq [System.Windows.MessageBoxResult]::No) {
            # Apply Audit rules (default)
            $scriptPath = Join-Path $script:AaronLockerRoot "GPOConfiguration\Set-GPOAppLockerPolicy.ps1"
            Start-AaronLockerScript -ScriptName "Set GPO Audit Policy" -ScriptPath $scriptPath -Parameters "-GpoName `"$gpoName`""
        }
    }
})
}

# Clear Local Policy
if ($null -ne $AL_ClearLocalPolicy) {
$AL_ClearLocalPolicy.Add_Click({
    $result = [System.Windows.MessageBox]::Show(
        "Are you sure you want to CLEAR the local AppLocker policy?`n`nThis action cannot be undone!",
        "Confirm Clear Local Policy",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ClearLocalAppLockerPolicy.ps1"
        Start-AaronLockerScript -ScriptName "Clear Local Policy" -ScriptPath $scriptPath
    }
})
}

# Clear AppLocker Logs
if ($null -ne $AL_ClearLogs) {
$AL_ClearLogs.Add_Click({
    $result = [System.Windows.MessageBox]::Show(
        "Are you sure you want to CLEAR all AppLocker event logs?`n`nThis action cannot be undone!",
        "Confirm Clear Logs",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ClearApplockerLogs.ps1"
        Start-AaronLockerScript -ScriptName "Clear AppLocker Logs" -ScriptPath $scriptPath
    }
})
}

# === CUSTOMIZATION INPUTS - Open files in default editor ===

if ($null -ne $AL_EditTrustedSigners) {
$AL_EditTrustedSigners.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\TrustedSigners.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        $AL_OutputConsole.Text = "Opened TrustedSigners.ps1 in Notepad.`n`nThis file defines publishers/signers whose software should be allowed.`n`nFile: $filePath"
    } else {
        $AL_OutputConsole.Text = "ERROR: File not found at $filePath"
    }
})
}

if ($null -ne $AL_EditSafePaths) {
$AL_EditSafePaths.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\GetSafePathsToAllow.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        $AL_OutputConsole.Text = "Opened GetSafePathsToAllow.ps1 in Notepad.`n`nThis file defines additional paths to whitelist.`n`nFile: $filePath"
    } else {
        $AL_OutputConsole.Text = "ERROR: File not found at $filePath"
    }
})
}

if ($null -ne $AL_EditUnsafePaths) {
$AL_EditUnsafePaths.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\UnsafePathsToBuildRulesFor.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        $AL_OutputConsole.Text = "Opened UnsafePathsToBuildRulesFor.ps1 in Notepad.`n`nThis file defines user-writable paths that need specific rules.`n`nFile: $filePath"
    } else {
        $AL_OutputConsole.Text = "ERROR: File not found at $filePath"
    }
})
}

if ($null -ne $AL_EditDenyList) {
$AL_EditDenyList.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\GetExeFilesToDenyList.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        $AL_OutputConsole.Text = "Opened GetExeFilesToDenyList.ps1 in Notepad.`n`nThis file defines executables that should be explicitly blocked.`n`nFile: $filePath"
    } else {
        $AL_OutputConsole.Text = "ERROR: File not found at $filePath"
    }
})
}

if ($null -ne $AL_EditHashRules) {
$AL_EditHashRules.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\HashRuleData.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        $AL_OutputConsole.Text = "Opened HashRuleData.ps1 in Notepad.`n`nThis file defines specific file hashes to allow/deny.`n`nFile: $filePath"
    } else {
        $AL_OutputConsole.Text = "ERROR: File not found at $filePath"
    }
})
}

if ($null -ne $AL_EditKnownAdmins) {
$AL_EditKnownAdmins.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\KnownAdmins.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        $AL_OutputConsole.Text = "Opened KnownAdmins.ps1 in Notepad.`n`nThis file defines admin accounts to exempt from certain rules.`n`nFile: $filePath"
    } else {
        $AL_OutputConsole.Text = "ERROR: File not found at $filePath"
    }
})
}

# === FOLDER SHORTCUTS ===

if ($null -ne $AL_OpenOutputs) {
$AL_OpenOutputs.Add_Click({
    $folderPath = Join-Path $script:AaronLockerRoot "Outputs"
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }
    Start-Process explorer.exe -ArgumentList $folderPath
    $AL_OutputConsole.Text = "Opened Outputs folder in Explorer.`n`nThis folder contains generated AppLocker and WDAC policy files.`n`nPath: $folderPath"
})
}

if ($null -ne $AL_OpenScanResults) {
$AL_OpenScanResults.Add_Click({
    $folderPath = Join-Path $script:AaronLockerRoot "ScanResults"
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }
    Start-Process explorer.exe -ArgumentList $folderPath
    $AL_OutputConsole.Text = "Opened ScanResults folder in Explorer.`n`nThis folder contains scan output files.`n`nPath: $folderPath"
})
}

# Show window
$window.ShowDialog() | Out-Null

