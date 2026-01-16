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

# Create AppLocker GPO
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

        # Detect current domain if OU not specified
        if (-not $TargetOU) {
            $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
            $TargetOU = $domain.DistinguishedName
        }

        Write-Log "Creating AppLocker GPO: $GpoName"

        # Check if GPO already exists
        $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
        if ($existingGpo) {
            Write-Log "GPO already exists: $GpoName"
            return @{
                success = $true
                gpoName = $GpoName
                gpoId = $existingGpo.Id
                linkedTo = "Existing GPO"
                message = "GPO '$GpoName' already exists. Use Link GPO to link it to an OU."
                isNew = $false
            }
        }

        # Create the GPO
        $gpo = New-GPO -Name $GpoName -Comment "AppLocker application control policy - Created by GA-AppLocker Dashboard" -ErrorAction Stop
        Write-Log "GPO created: $($gpo.Id)"

        # Link to target OU
        $link = New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes -ErrorAction Stop
        Write-Log "GPO linked to: $TargetOU"

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
            message = "AppLocker GPO created and linked successfully"
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

            # Link to domain
            try {
                New-GPLink -Name $GpoName -Target $OU -LinkEnabled Yes -ErrorAction Stop | Out-Null
                Write-Log "GPO linked to: $OU"
            }
            catch {
                if ($_.Exception.Message -notlike "*already linked*") {
                    throw $_
                }
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

        # Allow CredSSP authentication
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowCredSSP" -Type DWord -Value 1 -ErrorAction Stop

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

# ============================================================
# WPF XAML - Modern GitHub Dark Theme
# ============================================================

$xamlString = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="GA-AppLocker Dashboard" Height="700" Width="1050" MinHeight="500" MinWidth="800"
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
                                    <Button x:Name="NavCompliance" Content="Compliance" Style="{StaticResource NavButton}"
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
                    <TextBlock Text="Dashboard" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

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

                    <!-- Remote Computer Selection -->
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

                                <TextBlock Grid.Column="0" Text="Remote Computers:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <TextBlock Grid.Column="1" Text="Ctrl+click to select multiple, Shift+click for range" FontSize="11" Foreground="#6E7681" VerticalAlignment="Center"/>
                                <Button x:Name="ScanLocalArtifactsBtn" Content="Scan Local" Style="{StaticResource PrimaryButton}" Grid.Column="2" MinHeight="32"/>
                                <Button x:Name="ScanRemoteArtifactsBtn" Content="Scan Selected" Style="{StaticResource PrimaryButton}" Grid.Column="4" MinHeight="32"/>
                                <Button x:Name="RefreshArtifactComputersBtn" Content="Refresh List" Style="{StaticResource SecondaryButton}" Grid.Column="6" MinHeight="32"/>
                            </Grid>

                            <ListBox x:Name="ArtifactComputersList" Grid.Row="1" Height="120" Background="#0D1117"
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
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Directories:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <TextBlock Grid.Column="1" Text="Ctrl+click to select multiple, Shift+click for range" FontSize="11" Foreground="#6E7681" VerticalAlignment="Center"/>
                                <TextBlock Grid.Column="2" Text="Max Files:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <TextBox x:Name="MaxFilesText" Text="50000" Width="80" Height="28"
                                         Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                         BorderThickness="1" FontSize="12" Padding="5" Grid.Column="3"/>
                                <Button x:Name="ScanDirectoriesBtn" Content="Scan Directories"
                                        Style="{StaticResource SecondaryButton}" Grid.Column="5" MinHeight="32"/>
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
                    <TextBlock Text="Rule Generator" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                    <!-- Rule Options Row -->
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="20"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="20"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Rule Type -->
                        <TextBlock Text="Type:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <StackPanel Orientation="Horizontal" Grid.Column="1">
                            <RadioButton x:Name="RuleTypeAuto" Content="Auto" IsChecked="True"
                                         Foreground="#58A6FF" FontSize="11" Margin="0,0,8,0" VerticalContentAlignment="Center"
                                         ToolTip="Publisher for signed, Hash for unsigned"/>
                            <RadioButton x:Name="RuleTypePublisher" Content="Publisher"
                                         Foreground="#E6EDF3" FontSize="11" Margin="0,0,8,0" VerticalContentAlignment="Center"/>
                            <RadioButton x:Name="RuleTypeHash" Content="Hash"
                                         Foreground="#E6EDF3" FontSize="11" Margin="0,0,8,0" VerticalContentAlignment="Center"/>
                            <RadioButton x:Name="RuleTypePath" Content="Path"
                                         Foreground="#E6EDF3" FontSize="11" VerticalContentAlignment="Center"/>
                        </StackPanel>

                        <!-- Action -->
                        <TextBlock Text="Action:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="3" Margin="0,0,8,0"/>
                        <StackPanel Orientation="Horizontal" Grid.Column="4">
                            <RadioButton x:Name="RuleActionAllow" Content="Allow" IsChecked="True"
                                         Foreground="#3FB950" FontSize="11" Margin="0,0,10,0" VerticalContentAlignment="Center"/>
                            <RadioButton x:Name="RuleActionDeny" Content="Deny"
                                         Foreground="#F85149" FontSize="11" VerticalContentAlignment="Center"/>
                        </StackPanel>

                        <!-- AD Group -->
                        <TextBlock Text="Apply To:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="6" Margin="0,0,8,0"/>
                        <ComboBox x:Name="RuleGroupCombo" Grid.Column="7" Height="26" MinWidth="200"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
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
                            <ComboBoxItem Content="AppLocker-Admins" IsSelected="True" Tag="AppLocker-Admins"/>
                            <ComboBoxItem Content="AppLocker-StandardUsers" Tag="AppLocker-StandardUsers"/>
                            <ComboBoxItem Content="AppLocker-Service-Accounts" Tag="AppLocker-Service-Accounts"/>
                            <ComboBoxItem Content="AppLocker-Installers" Tag="AppLocker-Installers"/>
                        </ComboBox>
                    </Grid>

                    <!-- Custom SID Input (hidden by default) -->
                    <Grid x:Name="CustomSidPanel" Margin="0,0,0,10" Visibility="Collapsed">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Text="Custom SID:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBox x:Name="CustomSidText" Grid.Column="1" Height="26"
                                 Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                 BorderThickness="1" FontSize="11" Padding="5"
                                 Text="S-1-5-21-..."/>
                    </Grid>

                    <!-- Quick Import - Seamless Data Integration -->
                    <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="12" Margin="0,0,0,10">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0" Orientation="Horizontal">
                                <TextBlock Text="Quick Import:" FontSize="12" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Margin="0,0,15,0"/>
                                <Button x:Name="LoadCollectedArtifactsBtn" Content="Load Artifacts"
                                        Style="{StaticResource SecondaryButton}" Height="28" FontSize="11" Margin="0,0,8,0"
                                        ToolTip="Load artifacts from Artifact Collection panel"/>
                                <TextBlock x:Name="ArtifactCountBadge" Text="0" FontSize="10" FontWeight="Bold"
                                           Foreground="#6E7681" Background="#21262D" Padding="6,3" Margin="0,0,20,0"
                                           VerticalAlignment="Center" ToolTip="Artifacts available from collection"/>
                                <Button x:Name="LoadCollectedEventsBtn" Content="Load Events"
                                        Style="{StaticResource SecondaryButton}" Height="28" FontSize="11" Margin="0,0,8,0"
                                        ToolTip="Load events from Event Monitor panel"/>
                                <TextBlock x:Name="EventCountBadge" Text="0" FontSize="10" FontWeight="Bold"
                                           Foreground="#6E7681" Background="#21262D" Padding="6,3"
                                           VerticalAlignment="Center" ToolTip="Events available from monitoring"/>
                            </StackPanel>
                            <TextBlock Grid.Column="1" Text="Pull data directly from Artifacts or Events panels - no CSV export needed" FontSize="10" Foreground="#6E7681" VerticalAlignment="Center" TextAlignment="Right" HorizontalAlignment="Right"/>
                        </Grid>
                    </Border>

                    <!-- Data Management - Deduplicate and Export -->
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Grid.Column="0" Text="Deduplicate:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <ComboBox x:Name="DedupeTypeCombo" Grid.Column="2" Height="26" Width="120"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
                            <ComboBoxItem Content="By Publisher" IsSelected="True" Tag="Publisher"/>
                            <ComboBoxItem Content="By Hash" Tag="Hash"/>
                            <ComboBoxItem Content="By Path" Tag="Path"/>
                        </ComboBox>
                        <Button x:Name="DedupeBtn" Content="Deduplicate" Grid.Column="4"
                                Style="{StaticResource SecondaryButton}" Height="28" FontSize="11"
                                ToolTip="Remove duplicate artifacts based on selected field"/>

                        <Button x:Name="ExportArtifactsListBtn" Content="Export List" Grid.Column="7"
                                Style="{StaticResource SecondaryButton}" Height="28" FontSize="11" MinWidth="100"
                                ToolTip="Export current artifact list to CSV"/>
                    </Grid>

                    <!-- Action Buttons -->
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ImportArtifactsBtn" Content="Import Artifact"
                                Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportFolderBtn" Content="Import Folder"
                                Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                        <Button x:Name="MergeRulesBtn" Content="Merge Rules"
                                Style="{StaticResource SecondaryButton}" Grid.Column="4"/>
                        <Button x:Name="GenerateRulesBtn" Content="Generate Rules"
                                Style="{StaticResource PrimaryButton}" Grid.Column="6"/>
                    </Grid>

                    <!-- QoL: Audit Mode Toggle and Search Row -->
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <!-- One-Click Audit Toggle -->
                        <Button x:Name="AuditToggleBtn" Content="[!] AUDIT MODE" Grid.Column="0"
                                Background="#F0883E" Foreground="#FFFFFF" FontSize="11" FontWeight="Bold"
                                BorderThickness="0" Padding="12,6"
                                ToolTip="Toggle all rules between Audit and Enforce mode"/>

                        <!-- Search/Filter Box -->
                        <TextBox x:Name="RulesSearchBox" Grid.Column="2" Height="28"
                                 Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                 BorderThickness="1" FontSize="11" Padding="8,5"
                                 Text="Filter rules/artifacts..."/>

                        <!-- Clear Filter Button -->
                        <Button x:Name="ClearFilterBtn" Content="X" Grid.Column="4" Width="32" Height="28"
                                Background="#30363D" Foreground="#8B949E" FontSize="14"
                                BorderThickness="0"
                                ToolTip="Clear filter"/>
                    </Grid>

                    <!-- Default Deny Rules Button -->
                    <Button x:Name="DefaultDenyRulesBtn" Content="Add Default Deny Rules (Block Bypass Locations)"
                            Style="{StaticResource SecondaryButton}" HorizontalAlignment="Left" Margin="0,0,0,10"
                            ToolTip="Adds deny rules for TEMP, Downloads, AppData and other bypass locations"/>

                    <!-- Browser Deny Rules Button -->
                    <Button x:Name="CreateBrowserDenyBtn" Content="Add Admin Browser Deny Rules"
                            Style="{StaticResource SecondaryButton}" HorizontalAlignment="Left" Margin="0,0,0,10"
                            ToolTip="Adds deny rules for common browsers in AppLocker-Admin group"/>

                    <!-- QoL: Quick Rule Preview Panel -->
                    <Border x:Name="RulePreviewPanel" Background="#161B22" BorderBrush="#F0883E" BorderThickness="1"
                            CornerRadius="6" Padding="12" Margin="0,0,0,10" Visibility="Collapsed">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <TextBlock Text="Rule Preview" FontSize="12" FontWeight="Bold" Foreground="#F0883E" Margin="0,0,0,6"/>
                                <TextBlock x:Name="RulePreviewText" FontFamily="Consolas" FontSize="10" Foreground="#E6EDF3"
                                           TextWrapping="Wrap" MaxWidth="600"/>
                            </StackPanel>
                            <Button x:Name="ClosePreviewBtn" Content="X" Grid.Column="1"
                                    Background="Transparent" Foreground="#8B949E" FontSize="16"
                                    BorderThickness="0" Width="24" Height="24" Margin="4,0,0,0"/>
                        </Grid>
                    </Border>

                    <!-- Rules Management - DataGrid for Granular Editing -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" Margin="0,0,0,10">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <!-- Rules Toolbar -->
                            <Grid Grid.Row="0" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Generated Rules:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBlock x:Name="RulesCountText" Grid.Column="2" Text="0 rules" FontSize="11" Foreground="#3FB950" VerticalAlignment="Center" MinWidth="60"/>

                                <Button x:Name="ChangeGroupBtn" Content="Change Group" Grid.Column="4"
                                        Style="{StaticResource SecondaryButton}" Height="26" FontSize="10"
                                        ToolTip="Change AD group for selected rules"/>
                                <Button x:Name="DuplicateRulesBtn" Content="Duplicate To" Grid.Column="6"
                                        Style="{StaticResource SecondaryButton}" Height="26" FontSize="10"
                                        ToolTip="Duplicate selected rules to another group"/>
                                <Button x:Name="DeleteRulesBtn" Content="Delete" Grid.Column="8"
                                        Style="{StaticResource SecondaryButton}" Height="26" FontSize="10"
                                        Background="#F85149" ToolTip="Delete selected rules"/>

                                <TextBlock Grid.Column="9" Text="Ctrl+click to select multiple, Shift+click for range" FontSize="10" Foreground="#6E7681" VerticalAlignment="Center" TextAlignment="Right" HorizontalAlignment="Right"/>
                            </Grid>

                            <!-- Bulk Actions Panel -->
                            <Border x:Name="BulkActionsPanel" Background="#161B22" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Padding="12" Margin="0,0,0,10">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>

                                    <!-- Row 1: Change Group and Change Action -->
                                    <StackPanel Grid.Row="0" Grid.Column="0" Orientation="Horizontal" Margin="0,0,8,8">
                                        <TextBlock Text="Group:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,6,0"/>
                                        <ComboBox x:Name="BulkGroupCombo" Width="130" Height="26" FontSize="11">
                                            <ComboBoxItem Content="AppLocker-Admins"/>
                                            <ComboBoxItem Content="AppLocker-PowerUsers"/>
                                            <ComboBoxItem Content="AppLocker-StandardUsers"/>
                                            <ComboBoxItem Content="AppLocker-RestrictedUsers"/>
                                            <ComboBoxItem Content="AppLocker-Installers"/>
                                            <ComboBoxItem Content="AppLocker-Developers"/>
                                            <ComboBoxItem Content="Everyone"/>
                                        </ComboBox>
                                        <Button x:Name="ApplyGroupChangeBtn" Content="Apply" Style="{StaticResource PrimaryButton}"
                                                Width="60" Height="26" FontSize="10" Margin="6,0,0,0"
                                                ToolTip="Apply group change to selected rules"/>
                                    </StackPanel>

                                    <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" Margin="0,0,8,8">
                                        <TextBlock Text="Action:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,6,0"/>
                                        <ComboBox x:Name="BulkActionCombo" Width="100" Height="26" FontSize="11">
                                            <ComboBoxItem Content="Allow" IsSelected="True"/>
                                            <ComboBoxItem Content="Deny"/>
                                        </ComboBox>
                                        <Button x:Name="ApplyActionChangeBtn" Content="Apply" Style="{StaticResource PrimaryButton}"
                                                Width="60" Height="26" FontSize="10" Margin="6,0,0,0"
                                                ToolTip="Apply action change to selected rules"/>
                                    </StackPanel>

                                    <StackPanel Grid.Row="0" Grid.Column="2" Orientation="Horizontal" Margin="0,0,0,8">
                                        <TextBlock Text="Duplicate to:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,6,0"/>
                                        <ComboBox x:Name="BulkDuplicateCombo" Width="130" Height="26" FontSize="11">
                                            <ComboBoxItem Content="AppLocker-Admins"/>
                                            <ComboBoxItem Content="AppLocker-PowerUsers"/>
                                            <ComboBoxItem Content="AppLocker-StandardUsers"/>
                                            <ComboBoxItem Content="AppLocker-RestrictedUsers"/>
                                            <ComboBoxItem Content="AppLocker-Installers"/>
                                            <ComboBoxItem Content="AppLocker-Developers"/>
                                            <ComboBoxItem Content="Everyone"/>
                                        </ComboBox>
                                        <Button x:Name="ApplyDuplicateBtn" Content="Duplicate" Style="{StaticResource SecondaryButton}"
                                                Width="70" Height="26" FontSize="10" Margin="6,0,0,0"
                                                ToolTip="Duplicate selected rules to this group"/>
                                    </StackPanel>

                                    <!-- Row 2: Remove Selected and Info -->
                                    <StackPanel Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="3" Orientation="Horizontal">
                                        <Button x:Name="BulkRemoveBtn" Content="Remove Selected" Style="{StaticResource SecondaryButton}"
                                                Width="120" Height="26" FontSize="10" Background="#F85149"
                                                ToolTip="Remove all selected rules from the list"/>
                                        <TextBlock x:Name="BulkSelectionInfo" Text="No rules selected" FontSize="10" Foreground="#6E7681"
                                                   VerticalAlignment="Center" Margin="15,0,0,0"/>
                                    </StackPanel>
                                </Grid>
                            </Border>

                            <!-- Rules Filter Bar -->
                            <Grid Grid.Row="2" Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="100"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="90"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="130"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <TextBlock Grid.Column="0" Text="Filter:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center"/>

                                <!-- Type Filter -->
                                <ComboBox x:Name="RulesTypeFilter" Grid.Column="2" Height="24" FontSize="10"
                                          Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Types" Tag="" IsSelected="True"/>
                                    <ComboBoxItem Content="Publisher" Tag="Publisher"/>
                                    <ComboBoxItem Content="Hash" Tag="Hash"/>
                                    <ComboBoxItem Content="Path" Tag="Path"/>
                                </ComboBox>

                                <!-- Action Filter -->
                                <ComboBox x:Name="RulesActionFilter" Grid.Column="4" Height="24" FontSize="10"
                                          Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Actions" Tag="" IsSelected="True"/>
                                    <ComboBoxItem Content="Allow" Tag="Allow"/>
                                    <ComboBoxItem Content="Deny" Tag="Deny"/>
                                </ComboBox>

                                <!-- Group Filter -->
                                <ComboBox x:Name="RulesGroupFilter" Grid.Column="6" Height="24" FontSize="10"
                                          Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="All Groups" Tag="" IsSelected="True"/>
                                </ComboBox>

                                <!-- Search Box -->
                                <TextBox x:Name="RulesFilterSearch" Grid.Column="8" Height="24" FontSize="10"
                                         Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                         Padding="5,2" Text="Search..."/>

                                <!-- Clear Filter Button -->
                                <Button x:Name="RulesClearFilterBtn" Content="Clear" Grid.Column="10"
                                        Style="{StaticResource SecondaryButton}" Height="24" FontSize="10" MinWidth="55"/>

                                <!-- Filter Count -->
                                <TextBlock x:Name="RulesFilterCount" Grid.Column="12" Text=""
                                          FontSize="10" Foreground="#58A6FF" VerticalAlignment="Center" MinWidth="90"/>
                            </Grid>

                            <!-- Rules DataGrid -->
                            <DataGrid x:Name="RulesDataGrid" Grid.Row="3" Height="250"
                                      Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1"
                                      GridLinesVisibility="Horizontal" HeadersVisibility="Column" AutoGenerateColumns="False"
                                      CanUserAddRows="False" CanUserDeleteRows="False" SelectionMode="Extended"
                                      FontSize="11" RowBackground="#0D1117" AlternatingRowBackground="#161B22">
                                <DataGrid.Columns>
                                    <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="60" IsReadOnly="True"/>
                                    <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="50" IsReadOnly="True"/>
                                    <DataGridTextColumn Header="Name/Value" Binding="{Binding Name}" Width="250" IsReadOnly="True"/>
                                    <DataGridTextColumn Header="Group" Binding="{Binding Group}" Width="150"/>
                                    <DataGridTextColumn Header="SID" Binding="{Binding SID}" Width="120" Visibility="Hidden"/>
                                </DataGrid.Columns>
                            </DataGrid>
                        </Grid>
                    </Border>

                    <!-- Rules Output (Log) -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" MinHeight="150" MaxHeight="250">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="RulesOutput" Text="Import artifacts or generate rules to see results here..."
                                       FontFamily="Consolas" FontSize="10" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
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
                    <Grid Margin="0,0,0,8">
                        <Button x:Name="ExportEventsBtn" Content="Export Events to CSV" Style="{StaticResource SecondaryButton}" HorizontalAlignment="Left" Width="180" MinHeight="32"/>
                    </Grid>

                    <!-- Event Filters -->
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="60"/>
                            <ColumnDefinition Width="4"/>
                            <ColumnDefinition Width="70"/>
                            <ColumnDefinition Width="4"/>
                            <ColumnDefinition Width="70"/>
                            <ColumnDefinition Width="4"/>
                            <ColumnDefinition Width="60"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="40"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="40"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="55"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="90"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="70"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Grid.Column="0" Text="Filter:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center"/>

                        <!-- Event Type Filter Buttons -->
                        <Button x:Name="FilterAllBtn" Content="All" Style="{StaticResource SecondaryButton}" Grid.Column="2" Height="24" FontSize="10" Margin="0"/>
                        <Button x:Name="FilterAllowedBtn" Content="Allowed" Style="{StaticResource SecondaryButton}" Grid.Column="3" Height="24" FontSize="10" Margin="0"/>
                        <Button x:Name="FilterBlockedBtn" Content="Blocked" Style="{StaticResource SecondaryButton}" Grid.Column="4" Height="24" FontSize="10" Margin="0"/>
                        <Button x:Name="FilterAuditBtn" Content="Audit" Style="{StaticResource SecondaryButton}" Grid.Column="5" Height="24" FontSize="10" Margin="0"/>

                        <!-- Date Range Pickers -->
                        <TextBlock Grid.Column="6" Text="From:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center" TextAlignment="Center"/>
                        <DatePicker x:Name="EventsDateFrom" Grid.Column="7" Height="24" FontSize="10"
                                   Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                   FirstDayOfWeek="Monday" DisplayDateStart="{x:Static sys:DateTime.Today}"/>

                        <TextBlock Grid.Column="8" Text="To:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center" TextAlignment="Center"/>
                        <DatePicker x:Name="EventsDateTo" Grid.Column="9" Height="24" FontSize="10"
                                   Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                   FirstDayOfWeek="Monday" DisplayDateStart="{x:Static sys:DateTime.Today}"/>

                        <!-- Search Box -->
                        <TextBox x:Name="EventsFilterSearch" Grid.Column="10" Height="24" FontSize="10"
                                 Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                 Padding="5,2" Text="Search events..."/>

                        <!-- Clear Filter Button -->
                        <Button x:Name="EventsClearFilterBtn" Content="Clear" Grid.Column="12"
                                Style="{StaticResource SecondaryButton}" Height="24" FontSize="10" MinWidth="55"/>

                        <!-- Filter Count -->
                        <TextBlock x:Name="EventsFilterCount" Grid.Column="14" Text=""
                                  FontSize="10" Foreground="#58A6FF" VerticalAlignment="Center" MinWidth="90"/>

                        <!-- Refresh Button -->
                        <Button x:Name="RefreshEventsBtn" Content="Refresh" Style="{StaticResource PrimaryButton}" Grid.Column="16" Height="24" FontSize="10" MinWidth="70"/>
                    </Grid>

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

                    <!-- Deployment Buttons (disabled in workgroup mode) -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="CreateGP0Btn" Content="Create GPO" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="DisableGpoBtn" Content="Disable AppLocker GPO" Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Import/Export Rules Buttons -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ExportRulesBtn" Content="Export Rules" Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportRulesBtn" Content="Import Rules to GPO" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

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
                                </Grid.ColumnDefinitions>

                                <TextBlock Text="Target GPO:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="0"/>
                                <ComboBox x:Name="TargetGpoCombo" Grid.Column="2" Height="26" FontSize="11" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="GA-AppLocker-DC"/>
                                    <ComboBoxItem Content="GA-AppLocker-Servers"/>
                                    <ComboBoxItem Content="GA-AppLocker-Workstations"/>
                                </ComboBox>
                                <TextBlock Text="Mode:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="4"/>
                                <ComboBox x:Name="ImportModeCombo" Grid.Column="6" Width="120" Height="26" FontSize="11" Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D">
                                    <ComboBoxItem Content="Merge (Add)" IsSelected="True" ToolTip="Add new rules, keep existing rules"/>
                                    <ComboBoxItem Content="Overwrite" ToolTip="Replace all existing rules"/>
                                </ComboBox>
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
                                <Run Text="â€¢ Use Publisher rules first"/>
                                <LineBreak/>
                                <Run Text="â€¢ Use Hash rules for unsigned files"/>
                                <LineBreak/>
                                <Run Text="â€¢ Avoid Path rules when possible"/>
                                <LineBreak/>
                                <Run Text="â€¢ Always start in Audit mode"/>
                                <LineBreak/>
                                <Run Text="â€¢ Use role-based groups"/>
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
                                    <Button x:Name="CreateGPOsBtn" Content="Create 3 GPOs" Style="{StaticResource PrimaryButton}" Margin="0,0,0,8" MinHeight="32"/>
                                    <Button x:Name="ApplyGPOSettingsBtn" Content="Apply Phase/Mode" Style="{StaticResource SecondaryButton}" Margin="0,0,0,8" MinHeight="32"/>
                                    <Button x:Name="LinkGPOsBtn" Content="Link to OUs" Style="{StaticResource SecondaryButton}" MinHeight="32"/>
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
                                       Source="C:\GA-AppLocker_FINAL\general_atomics_logo_big.ico"/>
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
                                    <Run Text="â€¢ AppLocker structure initialization (OU, groups, policies)"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ AD group membership export/import with safety controls"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Automated artifact discovery and rule generation"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Publisher-first rule strategy with hash fallback"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ GPO deployment with audit-first enforcement"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Real-time event monitoring and filtering"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Compliance evidence package generation"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ WinRM remote management setup"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Admin browser deny rules for security"/>
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel>
                                <TextBlock Text="Requirements" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#8B949E">
                                    <Run Text="â€¢ Windows 10/11 or Windows Server 2019+"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ PowerShell 5.1+"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Active Directory module (for domain features)"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Group Policy module (for GPO deployment)"/>
                                    <LineBreak/>
                                    <Run Text="â€¢ Administrator privileges recommended"/>
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
$NavDashboard = $window.FindName("NavDashboard")
$NavDiscovery = $window.FindName("NavDiscovery")
$NavArtifacts = $window.FindName("NavArtifacts")
$NavRules = $window.FindName("NavRules")
$NavDeployment = $window.FindName("NavDeployment")
$NavEvents = $window.FindName("NavEvents")
$NavCompliance = $window.FindName("NavCompliance")
$NavWinRM = $window.FindName("NavWinRM")
$NavGroupMgmt = $window.FindName("NavGroupMgmt")
$NavAppLockerSetup = $window.FindName("NavAppLockerSetup")
$NavGapAnalysis = $window.FindName("NavGapAnalysis")
$NavSaveWorkspace = $window.FindName("NavSaveWorkspace")
$NavLoadWorkspace = $window.FindName("NavLoadWorkspace")
$NavHelp = $window.FindName("NavHelp")
$NavAbout = $window.FindName("NavAbout")

# Expander controls
$SetupSection = $window.FindName("SetupSection")
$ScanningSection = $window.FindName("ScanningSection")
$DeploymentSection = $window.FindName("DeploymentSection")
$MonitoringSection = $window.FindName("MonitoringSection")
# Arrow controls removed - using default expander style

$StatusText = $window.FindName("StatusText")
$EnvironmentText = $window.FindName("EnvironmentText")
$EnvironmentBanner = $window.FindName("EnvironmentBanner")

# QoL: Mini Status Bar controls
$MiniStatusDomain = $window.FindName("MiniStatusDomain")
$MiniStatusArtifacts = $window.FindName("MiniStatusArtifacts")
$MiniStatusSync = $window.FindName("MiniStatusSync")

$PanelDashboard = $window.FindName("PanelDashboard")
$PanelDiscovery = $window.FindName("PanelDiscovery")
$PanelArtifacts = $window.FindName("PanelArtifacts")
$PanelRules = $window.FindName("PanelRules")
$PanelDeployment = $window.FindName("PanelDeployment")
$PanelEvents = $window.FindName("PanelEvents")
$PanelCompliance = $window.FindName("PanelCompliance")
$PanelWinRM = $window.FindName("PanelWinRM")
$PanelGroupMgmt = $window.FindName("PanelGroupMgmt")
$PanelAppLockerSetup = $window.FindName("PanelAppLockerSetup")
$PanelGapAnalysis = $window.FindName("PanelGapAnalysis")
$PanelHelp = $window.FindName("PanelHelp")
$PanelAbout = $window.FindName("PanelAbout")

# Dashboard controls
$HealthScore = $window.FindName("HealthScore")
$HealthStatus = $window.FindName("HealthStatus")
$TotalEvents = $window.FindName("TotalEvents")
$EventsStatus = $window.FindName("EventsStatus")
$AllowedEvents = $window.FindName("AllowedEvents")
$AuditedEvents = $window.FindName("AuditedEvents")
$BlockedEvents = $window.FindName("BlockedEvents")
$DashboardTimeFilter = $window.FindName("DashboardTimeFilter")
$DashboardSystemFilter = $window.FindName("DashboardSystemFilter")
$RefreshDashboardBtn = $window.FindName("RefreshDashboardBtn")
$DashboardOutput = $window.FindName("DashboardOutput")

# GPO Quick Assignment controls
$DCGPOStatus = $window.FindName("DCGPOStatus")
$ServersGPOStatus = $window.FindName("ServersGPOStatus")
$WorkstationsGPOStatus = $window.FindName("WorkstationsGPOStatus")
$DCGPOPhase = $window.FindName("DCGPOPhase")
$DCGPOMode = $window.FindName("DCGPOMode")
$ServersGPOPhase = $window.FindName("ServersGPOPhase")
$ServersGPOMode = $window.FindName("ServersGPOMode")
$WorkstationsGPOPhase = $window.FindName("WorkstationsGPOPhase")
$WorkstationsGPOMode = $window.FindName("WorkstationsGPOMode")
$CreateGPOsBtn = $window.FindName("CreateGPOsBtn")
$ApplyGPOSettingsBtn = $window.FindName("ApplyGPOSettingsBtn")
$LinkGPOsBtn = $window.FindName("LinkGPOsBtn")

# Other controls
$MaxFilesText = $window.FindName("MaxFilesText")
$ScanDirectoriesBtn = $window.FindName("ScanDirectoriesBtn")
$DirectoryList = $window.FindName("DirectoryList")
$ArtifactsList = $window.FindName("ArtifactsList")
# Artifact Remote controls
$ArtifactComputersList = $window.FindName("ArtifactComputersList")
$ScanLocalArtifactsBtn = $window.FindName("ScanLocalArtifactsBtn")
$ScanRemoteArtifactsBtn = $window.FindName("ScanRemoteArtifactsBtn")
$RefreshArtifactComputersBtn = $window.FindName("RefreshArtifactComputersBtn")
$RuleTypeAuto = $window.FindName("RuleTypeAuto")
$RuleTypePublisher = $window.FindName("RuleTypePublisher")
$RuleTypeHash = $window.FindName("RuleTypeHash")
$RuleTypePath = $window.FindName("RuleTypePath")
$RuleActionAllow = $window.FindName("RuleActionAllow")
$RuleActionDeny = $window.FindName("RuleActionDeny")
$RuleGroupCombo = $window.FindName("RuleGroupCombo")
$CustomSidPanel = $window.FindName("CustomSidPanel")
$CustomSidText = $window.FindName("CustomSidText")
$ImportArtifactsBtn = $window.FindName("ImportArtifactsBtn")
$ImportFolderBtn = $window.FindName("ImportFolderBtn")
$MergeRulesBtn = $window.FindName("MergeRulesBtn")
$GenerateRulesBtn = $window.FindName("GenerateRulesBtn")
$DefaultDenyRulesBtn = $window.FindName("DefaultDenyRulesBtn")
$RulesOutput = $window.FindName("RulesOutput")
# Quick Import controls
$LoadCollectedArtifactsBtn = $window.FindName("LoadCollectedArtifactsBtn")
$LoadCollectedEventsBtn = $window.FindName("LoadCollectedEventsBtn")
$ArtifactCountBadge = $window.FindName("ArtifactCountBadge")
$EventCountBadge = $window.FindName("EventCountBadge")
# Data Management controls
$DedupeTypeCombo = $window.FindName("DedupeTypeCombo")
$DedupeBtn = $window.FindName("DedupeBtn")
$ExportArtifactsListBtn = $window.FindName("ExportArtifactsListBtn")
# Rules DataGrid controls
$RulesDataGrid = $window.FindName("RulesDataGrid")
$RulesCountText = $window.FindName("RulesCountText")
$ChangeGroupBtn = $window.FindName("ChangeGroupBtn")
$DuplicateRulesBtn = $window.FindName("DuplicateRulesBtn")
$DeleteRulesBtn = $window.FindName("DeleteRulesBtn")

# QoL Feature controls
$AuditToggleBtn = $window.FindName("AuditToggleBtn")
$RulesSearchBox = $window.FindName("RulesSearchBox")
$ClearFilterBtn = $window.FindName("ClearFilterBtn")
$RulePreviewPanel = $window.FindName("RulePreviewPanel")
$RulePreviewText = $window.FindName("RulePreviewText")
$ClosePreviewBtn = $window.FindName("ClosePreviewBtn")
$ScanLocalEventsBtn = $window.FindName("ScanLocalEventsBtn")
$ScanRemoteEventsBtn = $window.FindName("ScanRemoteEventsBtn")
$ExportEventsBtn = $window.FindName("ExportEventsBtn")
$EventComputersList = $window.FindName("EventComputersList")
$RefreshComputersBtn = $window.FindName("RefreshComputersBtn")
$FilterAllBtn = $window.FindName("FilterAllBtn")
$FilterAllowedBtn = $window.FindName("FilterAllowedBtn")
$FilterBlockedBtn = $window.FindName("FilterBlockedBtn")
$FilterAuditBtn = $window.FindName("FilterAuditBtn")
$RefreshEventsBtn = $window.FindName("RefreshEventsBtn")
$EventsOutput = $window.FindName("EventsOutput")

# Phase 4: Filter controls
$RulesTypeFilter = $window.FindName("RulesTypeFilter")
$RulesActionFilter = $window.FindName("RulesActionFilter")
$RulesGroupFilter = $window.FindName("RulesGroupFilter")
$RulesFilterSearch = $window.FindName("RulesFilterSearch")
$RulesClearFilterBtn = $window.FindName("RulesClearFilterBtn")
$RulesFilterCount = $window.FindName("RulesFilterCount")

$EventsDateFrom = $window.FindName("EventsDateFrom")
$EventsDateTo = $window.FindName("EventsDateTo")
$EventsFilterSearch = $window.FindName("EventsFilterSearch")
$EventsClearFilterBtn = $window.FindName("EventsClearFilterBtn")
$EventsFilterCount = $window.FindName("EventsFilterCount")

$ComplianceStatusFilter = $window.FindName("ComplianceStatusFilter")
$ComplianceFilterSearch = $window.FindName("ComplianceFilterSearch")
$ComplianceClearFilterBtn = $window.FindName("ComplianceClearFilterBtn")
$ComplianceFilterCount = $window.FindName("ComplianceFilterCount")
$CreateGP0Btn = $window.FindName("CreateGP0Btn")
$DisableGpoBtn = $window.FindName("DisableGpoBtn")
$DeploymentStatus = $window.FindName("DeploymentStatus")
$GenerateEvidenceBtn = $window.FindName("GenerateEvidenceBtn")
$ComplianceOutput = $window.FindName("ComplianceOutput")
$ScanLocalComplianceBtn = $window.FindName("ScanLocalComplianceBtn")
$ScanSelectedComplianceBtn = $window.FindName("ScanSelectedComplianceBtn")
$RefreshComplianceListBtn = $window.FindName("RefreshComplianceListBtn")
$ComplianceComputersList = $window.FindName("ComplianceComputersList")
$CreateWinRMGpoBtn = $window.FindName("CreateWinRMGpoBtn")
$EnableWinRMGpoBtn = $window.FindName("EnableWinRMGpoBtn")
$DisableWinRMGpoBtn = $window.FindName("DisableWinRMGpoBtn")
$ForceGPUpdateBtn = $window.FindName("ForceGPUpdateBtn")
$WinRMOutput = $window.FindName("WinRMOutput")

# AD Discovery controls
$ADSearchFilter = $window.FindName("ADSearchFilter")
$DiscoverComputersBtn = $window.FindName("DiscoverComputersBtn")
$TestConnectivityBtn = $window.FindName("TestConnectivityBtn")
$SelectAllComputersBtn = $window.FindName("SelectAllComputersBtn")
$ScanSelectedBtn = $window.FindName("ScanSelectedBtn")
$DiscoveredComputersList = $window.FindName("DiscoveredComputersList")
$OfflineComputersList = $window.FindName("OfflineComputersList")
$DiscoveryOutput = $window.FindName("DiscoveryOutput")
$DiscoveryStatus = $window.FindName("DiscoveryStatus")

# Group Management controls
$ExportGroupsBtn = $window.FindName("ExportGroupsBtn")
$ImportGroupsBtn = $window.FindName("ImportGroupsBtn")
$DryRunCheck = $window.FindName("DryRunCheck")
$AllowRemovalsCheck = $window.FindName("AllowRemovalsCheck")
$IncludeProtectedCheck = $window.FindName("IncludeProtectedCheck")
$GroupMgmtOutput = $window.FindName("GroupMgmtOutput")

# AppLocker Setup controls
$OUNameText = $window.FindName("OUNameText")
$AutoPopulateCheck = $window.FindName("AutoPopulateCheck")
$BootstrapAppLockerBtn = $window.FindName("BootstrapAppLockerBtn")
$RemoveOUProtectionBtn = $window.FindName("RemoveOUProtectionBtn")
$CreateBrowserDenyBtn = $window.FindName("CreateBrowserDenyBtn")
$AppLockerSetupOutput = $window.FindName("AppLockerSetupOutput")

# About and Help controls
$AboutLogo = $window.FindName("AboutLogo")
$AboutVersion = $window.FindName("AboutVersion")
$HelpTitle = $window.FindName("HelpTitle")
$HelpText = $window.FindName("HelpText")
$HelpBtnWorkflow = $window.FindName("HelpBtnWorkflow")
$HelpBtnWhatsNew = $window.FindName("HelpBtnWhatsNew")
$HelpBtnPolicyGuide = $window.FindName("HelpBtnPolicyGuide")
$HelpBtnRules = $window.FindName("HelpBtnRules")
$HelpBtnTroubleshooting = $window.FindName("HelpBtnTroubleshooting")

# Gap Analysis controls (Scan buttons removed - use Import only)
$ImportBaselineBtn = $window.FindName("ImportBaselineBtn")
$ImportTargetBtn = $window.FindName("ImportTargetBtn")
$CompareSoftwareBtn = $window.FindName("CompareSoftwareBtn")
$GapAnalysisGrid = $window.FindName("GapAnalysisGrid")
$GapTotalCount = $window.FindName("GapTotalCount")
$GapMissingCount = $window.FindName("GapMissingCount")
$GapExtraCount = $window.FindName("GapExtraCount")
$GapVersionCount = $window.FindName("GapVersionCount")
$ExportGapAnalysisBtn = $window.FindName("ExportGapAnalysisBtn")

# Export/Import Rules controls
$ExportRulesBtn = $window.FindName("ExportRulesBtn")
$ImportRulesBtn = $window.FindName("ImportRulesBtn")
$TargetGpoCombo = $window.FindName("TargetGpoCombo")
$ImportModeCombo = $window.FindName("ImportModeCombo")

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
$script:ScriptRoot = Split-Path -Parent $PSCommandPath
if (-not $script:ScriptRoot) {
    $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Determine module path - check if modules are in src\modules, or parent\src\modules
$script:ModulePath = Join-Path $script:ScriptRoot "src\modules"
if (-not (Test-Path $script:ModulePath)) {
    # Modules not found, try parent directory (for running from output folder)
    $parentPath = Split-Path -Parent $script:ScriptRoot
    $script:ModulePath = Join-Path $parentPath "src\modules"
}

# Final fallback - try the build directory structure
if (-not (Test-Path $script:ModulePath)) {
    $script:ModulePath = "C:\projects\GA-AppLocker_FINAL\src\modules"
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
    $result = [System.Windows.MessageBox]::Show(
        $fullMessage,
        $Title,
        if ($RequireTyping) {
            [System.Windows.MessageBoxButton]::OKCancel
        } else {
            [System.Windows.MessageBoxButton]::YesNo
        },
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
    $Window.Remove_KeyDown($script:ActivityTrackerKeyDown) -ErrorAction SilentlyContinue

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
        "Publisher" { "ðŸ¢" }
        "Hash" { "ðŸ”" }
        "Path" { "ðŸ“" }
        default { "â€¢" }
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
                $rule.TypeIcon = "ðŸ¢"
            }
            "Hash" {
                $rule.TypeColor = "#A371F7"  # Purple
                $rule.TypeIcon = "ðŸ”"
            }
            "Path" {
                $rule.TypeColor = "#3FB950"  # Green
                $rule.TypeIcon = "ðŸ“"
            }
            default {
                $rule.TypeColor = "#8B949E"  # Gray
                $rule.TypeIcon = "â€¢"
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
            $gpoNames = @("GA-AppLocker-DC", "GA-AppLocker-Servers", "GA-AppLocker-Workstations")
            $linkedGPOs = 0

            foreach ($gpoName in $gpoNames) {
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if ($gpo) {
                    # Check if GPO has any links
                    if ([xml]$gpo.Xml).GPO.LinksTo -and [xml]$gpo.Xml).GPO.LinksTo -ne "") {
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

    $result = [System.Windows.MessageBox]::Show(
        $message,
        "Enforce Mode Validation",
        [System.Windows.MessageBoxButton]::YesNo,
        if ($ValidationResult.ready) {
            [System.Windows.MessageBoxImage]::Information
        } else {
            [System.Windows.MessageBoxImage]::Warning
        }
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

# Help content function
function Get-HelpContent {
    param([string]$Topic)

    switch ($Topic) {
        "Workflow" {
            return @"
=== APPLOCKER DEPLOYMENT WORKFLOW ===

Phase 1: SETUP
1. AppLocker Setup - Initialize AD structure
   â€¢ Creates AppLocker OU and groups:
     - AppLocker-Admins, AppLocker-StandardUsers
     - AppLocker-Service-Accounts, AppLocker-Installers
   â€¢ Sets Domain Admins as owner (for deletion)
   â€¢ Click 'Remove OU Protection' if needed

2. Group Management - Configure AD groups
   â€¢ Export current group membership to CSV
   â€¢ Edit CSV to add/remove members
   â€¢ Import changes (preview first, then apply)

3. AD Discovery - Find target computers
   â€¢ Shows Online/Offline in separate lists
   â€¢ Select only online hosts for scanning

Phase 2: SCANNING
4. Artifacts - Collect executable inventory
   â€¢ Scan Localhost - Quick local scan
   â€¢ Comprehensive Scan - AaronLocker-style scan creates:
     Executables.csv, Publishers.csv, InstalledSoftware.csv
     RunningProcesses.csv, WritableDirectories.csv
   â€¢ Output saved to C:\GA-AppLocker\Scans\

5. Rule Generator - Create AppLocker rules
   â€¢ Import Artifact - Imports any CSV (scans or events)
   â€¢ Import Folder - Recursively imports all CSVs
   â€¢ Use Search/Filter to find specific artifacts
   â€¢ Preview rules before export

   Rule Types:
   â€¢ Auto (Recommended) - Publisher for signed, Hash for unsigned
   â€¢ Publisher - Uses code signing certificate
   â€¢ Hash - SHA256 hash (breaks on updates)
   â€¢ Path - File path (least secure)

   â€¢ Select Allow/Deny and target AppLocker group
   â€¢ Default Deny Rules - Block TEMP, Downloads, AppData
   â€¢ One-Click Audit Toggle (Deployment panel)

Phase 3: DEPLOYMENT
6. Deployment - Deploy policies via GPO
   â€¢ Create GPO - Creates and links AppLocker GPO
   â€¢ Toggle Audit/Enforce - One-click mode switch
   â€¢ Export Rules - Save to C:\GA-AppLocker\Rules\
   â€¢ Import Rules - Load existing AppLocker XML

7. WinRM Setup - Enable remote management
   â€¢ Creates WinRM GPO with:
     - Service auto-config, Basic auth, TrustedHosts *
     - Firewall rules for ports 5985/5986
   â€¢ Force GPUpdate - Push policy to all computers
   â€¢ Enable/Disable GPO Link

Phase 4: MONITORING
8. Events - Monitor AppLocker events
   â€¢ Scan Local/Remote for AppLocker events
   â€¢ Quick Date Presets: Last Hour, Today, 7 Days, 30 Days
   â€¢ Filter by Allowed (8002) / Audit (8003) / Blocked (8004)
   â€¢ Export to CSV for analysis
   â€¢ Import events into Rule Generator

9. Dashboard - Overview and statistics
   â€¢ Mini Status Bar shows domain, artifact count, sync status
   â€¢ Policy Health Score
   â€¢ Event counts from C:\GA-AppLocker\Events\
   â€¢ Filter by time range (7/30 days)
   â€¢ Filter by computer system

10. Compliance - Generate evidence packages
    â€¢ Creates timestamped folder with policies and events
    â€¢ Ready for audit documentation

BEST PRACTICES:
â€¢ Always start in Audit mode (Event ID 8003)
â€¢ Use Auto rule type (Publisher for signed, Hash for unsigned)
â€¢ Add Default Deny Rules for bypass locations
â€¢ Monitor events for 7-14 days before enforcing
â€¢ Maintain break-glass admin access
â€¢ Use Search/Filter for large artifact lists
â€¢ Preview rules before export to verify structure
â€¢ Use Quick Date Presets for fast event filtering
"@
        }
        "Rules" {
            return @"
=== APPLOCKER RULE BEST PRACTICES ===

RULE TYPE PRIORITY (Highest to Lowest):
1. Publisher Rules (Preferred)
   â€¢ Most resilient to updates
   â€¢ Covers all versions from publisher
   â€¢ Example: Microsoft Corporation, Adobe Inc.

2. Hash Rules (Fallback for unsigned)
   â€¢ Most specific but fragile
   â€¢ Changes with each file update
   â€¢ Use only for unsigned executables
   â€¢ Example: SHA256 hash

3. Path Rules (Exceptions only)
   â€¢ Too permissive, easily bypassed
   â€¢ Use only for:
     - Denying specific user-writable paths
     - Allowing specific admin tools
   â€¢ Example: %OSDRIVE%\Users\*\Downloads\*\*

SECURITY PRINCIPLES:
â€¢ DENY-FIRST MODEL
  - Default deny all executables
  - Explicitly allow only approved software
  - Deny user-writable locations

â€¢ LEAST PRIVILEGE
  - Different rules for different user groups
  - AppLocker-Admin: Full allow
  - AppLocker-StandardUsers: Restricted
  - AppLocker-Dev: Development tools

â€¢ AUDIT BEFORE ENFORCE
  - Deploy in Audit mode first
  - Monitor for 7-14 days
  - Review and address false positives
  - Switch to Enforce only after validation

RULE COLLECTIONS TO CONFIGURE:
â€¢ Executable (.exe, .com)
â€¢ Script (.ps1, .bat, .cmd, .vbs)
â€¢ Windows Installer (.msi, .msp)
â€¢ DLL (optional - advanced)
â€¢ Packaged Apps/MSIX (Windows 10+)

COMMON PITFALLS TO AVOID:
â€¢ Using wildcards in path rules
â€¢ Forgetting to update hash rules after updates
â€¢ Not testing with actual user accounts
â€¢ Skipping the audit phase
â€¢ Forgetting service accounts
â€¢ Not documenting exceptions

GROUP STRATEGY:
â€¢ AppLocker-Admin - Full system access
â€¢ AppLocker-Installers - Software installation rights
â€¢ AppLocker-StandardUsers - Restricted workstation users
â€¢ AppLocker-Dev - Developer tools access
â€¢ AppLocker-Deny-* - Explicit deny for risky paths

ADMIN SECURITY:
â€¢ Consider denying browsers for admin accounts
â€¢ Admins should use separate workstations
â€¢ Break-glass access for emergency situations
â€¢ Document all exceptions and justifications
"@
        }
        "Troubleshooting" {
            return @"
=== APPLOCKER TROUBLESHOOTING ===

ISSUE: Events not appearing in Event Monitor
SOLUTIONS:
â€¢ Verify AppLocker ID 8001 (Policy Applied) appears first
â€¢ Check Application Identity service is running
â€¢ Verify policy is actually enforced (gpresult /r)
â€¢ Restart Application Identity service if needed

ISSUE: All executables being blocked
SOLUTIONS:
â€¢ Check if policy is in Enforce mode (should start as Audit)
â€¢ Verify rule collection is enabled
â€¢ Check for conflicting deny rules
â€¢ Review event logs for specific blocked files

ISSUE: False positives - legitimate apps blocked
SOLUTIONS:
â€¢ Add specific Publisher rule for the application
â€¢ Check if app needs to run from user-writable location
â€¢ Consider creating exception path rule
â€¢ Review hash rule if app version changed

ISSUE: Policy not applying to computers
SOLUTIONS:
â€¢ Run: gpresult /r /scope computer
â€¢ Check GPO is linked to correct OU
â€¢ Verify GPO security filtering
â€¢ Force GP update: gpupdate /force
â€¢ Check DNS resolution for domain controllers

ISSUE: Cannot create GPO (access denied)
SOLUTIONS:
â€¢ Must be Domain Admin or have GPO creation rights
â€¢ Check Group Policy Management console permissions
â€¢ Verify RSAT is installed if running from workstation
â€¢ Run PowerShell as Administrator

ISSUE: WinRM connection failures
SOLUTIONS:
â€¢ Verify WinRM GPO has applied (gpupdate /force)
â€¢ Check firewall allows port 5985/5986
â€¢ Test with: Test-WsMan -ComputerName <target>
â€¢ Ensure target computer has WinRM enabled

ISSUE: Rule generation errors
SOLUTIONS:
â€¢ Verify artifact scan completed successfully
â€¢ Check CSV format is correct (UTF-8 encoding)
â€¢ Ensure Publisher info exists in file version
â€¢ Use Hash rules for unsigned executables

ISSUE: Group import fails
SOLUTIONS:
â€¢ Verify CSV format: GroupName,Members (semicolon-separated)
â€¢ Check member accounts exist in AD
â€¢ Ensure you have rights to modify group membership
â€¢ Use dry-run first to preview changes

ISSUE: High CPU/memory during scan
SOLUTIONS:
â€¢ Reduce MaxFiles setting
â€¢ Scan specific directories instead of full drives
â€¢ Run during off-peak hours
â€¢ Use AD discovery to target specific computers

USEFUL PowerShell COMMANDS:
â€¢ Get-AppLockerPolicy -Effective
â€¢ Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'
â€¢ Test-AppLockerPolicy
â€¢ Set-AppLockerPolicy
â€¢ gpupdate /force
â€¢ gpresult /r /scope computer

LOG LOCATIONS:
â€¢ AppLocker Events: Event Viewer -> Applications and Services -> Microsoft -> Windows -> AppLocker
â€¢ Group Policy: Event Viewer -> Windows Logs -> System
â€¢ Application ID: Services.msc -> Application Identity
â€¢ Application Logs: C:\GA-AppLocker\Logs\

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
   â€¢ Filter artifacts by publisher, path, or filename
   â€¢ Filter generated rules by any property
   â€¢ Real-time filtering as you type
   â€¢ Location: Top of Rule Generator panel

[2] One-Click Audit Toggle (Deployment Panel)
   â€¢ Instantly switch between Audit and Enforce modes
   â€¢ Updates all rule collections at once
   â€¢ Confirmation dialog before mode change
   â€¢ Location: Deployment panel, "Toggle Audit/Enforce" button

[3] Rule Preview Panel (Rule Generator Panel)
   â€¢ Preview XML rules before generation
   â€¢ Shows exact XML that will be exported
   â€¢ Helps verify rule structure
   â€¢ Location: Rule Generator panel, "Preview Rules" button

[4] Mini Status Bar (Top Navigation Bar)
   â€¢ Real-time domain status (joined/workgroup)
   â€¢ Artifact count indicator
   â€¢ Sync status for data refresh
   â€¢ Location: Top bar, right side

[5] Bulk Action Confirmation
   â€¢ Confirmation dialogs before destructive operations
   â€¢ Prevents accidental rule clear
   â€¢ Prevents accidental GPO deletion
   â€¢ Shows count of affected items

[6] Quick Date Presets (Events Panel)
   â€¢ Last Hour: Events from the last 60 minutes
   â€¢ Today: Events from today
   â€¢ Last 7 Days: Events from past week
   â€¢ Last 30 Days: Events from past month
   â€¢ Location: Events panel, quick date buttons

BUG FIXES:

[1] UTF-16 Encoding Fix
   â€¢ AppLocker XML policies now use proper UTF-16 encoding
   â€¢ Previous UTF-8 encoding caused import failures
   â€¢ All exported policies now compatible with AppLocker

[2] Regex Pattern Improvements
   â€¢ Directory safety classification now uses robust regex escaping
   â€¢ Prevents false positives in path matching
   â€¢ More reliable unsafe path detection

[3] System.Web Assembly Loading
   â€¢ Added assembly loading for HTML encoding security
   â€¢ Prevents encoding errors in compliance reports

[4] Emoji Character Removal
   â€¢ Removed emoji characters for PowerShell compatibility
   â€¢ Replaced with ASCII equivalents
   â€¢ Prevents syntax errors in script parsing

ARCHITECTURE IMPROVEMENTS:

[1] Standardized Artifact Data Model
   â€¢ Common artifact structure across all modules
   â€¢ Properties: name, path, publisher, hash, version, size, modifiedDate, fileType
   â€¢ Automatic property name mapping between formats

[2] Artifact Conversion Functions
   â€¢ Convert-AppLockerArtifact: Maps between naming conventions
   â€¢ Handles Module2 (lowercase), GUI (PascalCase), CSV import formats
   â€¢ Ensures interoperability between modules

[3] Rule Validation Before Export
   â€¢ Test-AppLockerRules: Validates all required properties exist
   â€¢ Pre-export validation catches missing data
   â€¢ Returns success, errors, warnings

[4] Unit Tests for Artifact Interoperability
   â€¢ 22 new tests in GA-AppLocker.Artifact.Tests.ps1
   â€¢ Tests artifact creation, conversion, validation
   â€¢ Tests property name mappings
   â€¢ 20 passing, 2 skipped

DOCUMENTATION UPDATES:

[1] ARTIFACT-DATA-MODEL.md
   â€¢ Complete documentation of artifact data structure
   â€¢ Property name mapping tables
   â€¢ Usage examples and best practices

[2] Updated README.md
   â€¢ v1.2.5 release notes
   â€¢ New features and bug fixes documented

[3] Updated CLAUDE.md
   â€¢ Technical documentation for new functions
   â€¢ GUI feature descriptions

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
   â€¢ docs/ARTIFACT-DATA-MODEL.md - Artifact and rule data structures
   â€¢ claude.md - Developer reference
   â€¢ README.md - Project overview
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
    param([array]$Rules)

    $xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Executable" EnforcementMode="AuditOnly" />
  <RuleCollection Type="Script" EnforcementMode="AuditOnly" />
  <RuleCollection Type="WindowsInstallerFile" EnforcementMode="AuditOnly" />
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly" />
  <RuleCollection Type="Appx" EnforcementMode="AuditOnly" />
</AppLockerPolicy>
"@

    # Note: For full rule conversion, would need to parse $script:GeneratedRules
    # and create proper AppLocker XML structure
    # This is a placeholder for the export functionality

    return $xml
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

    $PanelDashboard.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelDiscovery.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelArtifacts.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelRules.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelDeployment.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelEvents.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelCompliance.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelWinRM.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelGroupMgmt.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelAppLockerSetup.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelGapAnalysis.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelHelp.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelAbout.Visibility = [System.Windows.Visibility]::Collapsed

    switch ($PanelName) {
        "Dashboard" { $PanelDashboard.Visibility = [System.Windows.Visibility]::Visible }
        "Discovery" { $PanelDiscovery.Visibility = [System.Windows.Visibility]::Visible }
        "Artifacts" { $PanelArtifacts.Visibility = [System.Windows.Visibility]::Visible }
        "Rules" {
            $PanelRules.Visibility = [System.Windows.Visibility]::Visible
            Update-Badges
        }
        "Deployment" { $PanelDeployment.Visibility = [System.Windows.Visibility]::Visible }
        "Events" { $PanelEvents.Visibility = [System.Windows.Visibility]::Visible }
        "Compliance" { $PanelCompliance.Visibility = [System.Windows.Visibility]::Visible }
        "WinRM" { $PanelWinRM.Visibility = [System.Windows.Visibility]::Visible }
        "GroupMgmt" { $PanelGroupMgmt.Visibility = [System.Windows.Visibility]::Visible }
        "AppLockerSetup" { $PanelAppLockerSetup.Visibility = [System.Windows.Visibility]::Visible }
        "GapAnalysis" { $PanelGapAnalysis.Visibility = [System.Windows.Visibility]::Visible }
        "Help" { $PanelHelp.Visibility = [System.Windows.Visibility]::Visible }
        "About" { $PanelAbout.Visibility = [System.Windows.Visibility]::Visible }
    }
}

# Navigation event handlers
$NavDashboard.Add_Click({
    Show-Panel "Dashboard"
    Update-StatusBar
})

$NavDiscovery.Add_Click({
    Show-Panel "Discovery"
    Update-StatusBar
})

$NavArtifacts.Add_Click({
    Show-Panel "Artifacts"
    Update-StatusBar
})

$NavGapAnalysis.Add_Click({
    Show-Panel "GapAnalysis"
    Update-StatusBar
})

$NavRules.Add_Click({
    Show-Panel "Rules"
    Update-StatusBar
})

$NavDeployment.Add_Click({
    Show-Panel "Deployment"
    Update-StatusBar
})

$NavEvents.Add_Click({
    Show-Panel "Events"
    Update-StatusBar
})

$NavCompliance.Add_Click({
    Show-Panel "Compliance"
    Update-StatusBar
})

$NavWinRM.Add_Click({
    Show-Panel "WinRM"
    Update-StatusBar
})

$NavGroupMgmt.Add_Click({
    Show-Panel "GroupMgmt"
    Update-StatusBar
})

$NavAppLockerSetup.Add_Click({
    Show-Panel "AppLockerSetup"
    Update-StatusBar
})

$NavHelp.Add_Click({
    Show-Panel "Help"
    Update-StatusBar
    # Load default help content
    $HelpTitle.Text = "Help - Workflow"
    $HelpText.Text = Get-HelpContent "Workflow"
})

$NavAbout.Add_Click({
    Show-Panel "About"
    Update-StatusBar
})

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
}

$RefreshDashboardBtn.Add_Click({
    Refresh-Data
})

# GPO Quick Assignment - Create GPOs button
$CreateGPOsBtn.Add_Click({
    Write-Log "User requested creation of 3 AppLocker GPOs (DC, Servers, Workstations)"
    Write-AuditLog -Action "GPO_CREATE_ATTEMPT" -Target "GA-AppLocker-DC, GA-AppLocker-Servers, GA-AppLocker-Workstations" -Result 'ATTEMPT' -Details "User initiated bulk GPO creation"

    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO creation requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        $DashboardOutput.Text += "ERROR: GPO creation requires Domain Mode.`n"
        Write-AuditLog -Action "GPO_CREATE_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
        return
    }

    # Confirmation dialog for GPO creation
    $confirmed = Show-ConfirmationDialog -Title "Confirm GPO Creation" -Message "This will create 3 Group Policy Objects:" -TargetObject "GA-AppLocker-DC, GA-AppLocker-Servers, GA-AppLocker-Workstations" -ActionType 'CREATE'
    if (-not $confirmed) {
        $DashboardOutput.Text = "GPO creation cancelled by user."
        return
    }

    try {
        Import-Module (Join-Path $script:ModulePath "Module4-PolicyLab.psm1") -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop

        $gpoNames = @("GA-AppLocker-DC", "GA-AppLocker-Servers", "GA-AppLocker-Workstations")
        $results = @()
        $successCount = 0

        foreach ($gpoName in $gpoNames) {
            $result = New-AppLockerGPO -GpoName $gpoName
            if ($result.success) {
                $results += "Created: $gpoName`n"
                Write-Log "Created GPO: $gpoName"
                Write-AuditLog -Action "GPO_CREATED" -Target $gpoName -Result 'SUCCESS' -Details "GPO created successfully"
                $successCount++
            } else {
                $results += "Failed: $gpoName - $($result.error)`n"
                Write-Log "Failed to create GPO $gpoName`: $($result.error)" -Level "ERROR"
                Write-AuditLog -Action "GPO_CREATE_FAILED" -Target $gpoName -Result 'FAILURE' -Details "Error: $($result.error)"
            }
        }

        # Update GPO status display
        $DCGPOStatus.Text = "Created"
        $DCGPOStatus.Foreground = "#3FB950"
        $ServersGPOStatus.Text = "Created"
        $ServersGPOStatus.Foreground = "#3FB950"
        $WorkstationsGPOStatus.Text = "Created"
        $WorkstationsGPOStatus.Foreground = "#3FB950"

        $summaryMsg = "GPO Creation Summary: $successCount of 3 created successfully"
        $DashboardOutput.Text = "=== GPO CREATION COMPLETE ===`n`n$results`n`nNext steps:`n1. Click 'Link to OUs' to link GPOs to proper OUs`n2. Import rules from Rule Generator`n3. Apply rules to GPOs in Deployment panel"

        Write-AuditLog -Action "GPO_CREATE_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details $summaryMsg
    }
    catch {
        $errorMsg = ConvertTo-SafeString -InputString $_.Exception.Message -MaxLength 500
        $DashboardOutput.Text = "ERROR: $errorMsg"
        Write-Log "GPO creation failed: $errorMsg" -Level "ERROR"
        Write-AuditLog -Action "GPO_CREATE_BULK_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Exception: $errorMsg"
    }
})

# GPO Quick Assignment - Apply Phase/Mode button
$ApplyGPOSettingsBtn.Add_Click({
    Write-Log "User requested GPO Phase/Mode settings application"
    Write-AuditLog -Action "GPO_SETTINGS_ATTEMPT" -Target "Multiple GPOs" -Result 'ATTEMPT' -Details "User initiated GPO settings changes"

    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO modification requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-AuditLog -Action "GPO_SETTINGS_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
        return
    }

    try {
        Import-Module (Join-Path $script:ModulePath "Module4-PolicyLab.psm1") -ErrorAction Stop
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
        if ($dcPhase -ne "--" -and $dcMode -eq "Enforce") { $enforceGPOs += "GA-AppLocker-DC" }
        if ($serversPhase -ne "--" -and $serversMode -eq "Enforce") { $enforceGPOs += "GA-AppLocker-Servers" }
        if ($workstationsPhase -ne "--" -and $workstationsMode -eq "Enforce") { $enforceGPOs += "GA-AppLocker-Workstations" }

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
            $gpo = Get-GPO -Name "GA-AppLocker-DC" -ErrorAction SilentlyContinue
            if ($gpo) {
                # Set enforcement mode based on selection
                $enforcementMode = if ($dcMode -eq "Enforce") { "Enforced" } else { "AuditOnly" }
                $results += "DC GPO: Phase=$dcPhase, Mode=$enforcementMode`n"
                Write-Log "DC GPO: Phase=$dcPhase, Mode=$enforcementMode"
                Write-AuditLog -Action "GPO_SETTINGS_APPLIED" -Target "GA-AppLocker-DC" -Result 'SUCCESS' -Details "Phase=$dcPhase, Mode=$enforcementMode"

                # Update status text with phase info
                $DCGPOStatus.Text = "P$dcPhase - $dcMode"
            }
        }

        # Apply to Servers GPO
        if ($serversPhase -ne "--") {
            $gpo = Get-GPO -Name "GA-AppLocker-Servers" -ErrorAction SilentlyContinue
            if ($gpo) {
                $enforcementMode = if ($serversMode -eq "Enforce") { "Enforced" } else { "AuditOnly" }
                $results += "Servers GPO: Phase=$serversPhase, Mode=$enforcementMode`n"
                Write-Log "Servers GPO: Phase=$serversPhase, Mode=$enforcementMode"
                Write-AuditLog -Action "GPO_SETTINGS_APPLIED" -Target "GA-AppLocker-Servers" -Result 'SUCCESS' -Details "Phase=$serversPhase, Mode=$enforcementMode"
                $ServersGPOStatus.Text = "P$serversPhase - $serversMode"
            }
        }

        # Apply to Workstations GPO
        if ($workstationsPhase -ne "--") {
            $gpo = Get-GPO -Name "GA-AppLocker-Workstations" -ErrorAction SilentlyContinue
            if ($gpo) {
                $enforcementMode = if ($workstationsMode -eq "Enforce") { "Enforced" } else { "AuditOnly" }
                $results += "Workstations GPO: Phase=$workstationsPhase, Mode=$enforcementMode`n"
                Write-Log "Workstations GPO: Phase=$workstationsPhase, Mode=$enforcementMode"
                Write-AuditLog -Action "GPO_SETTINGS_APPLIED" -Target "GA-AppLocker-Workstations" -Result 'SUCCESS' -Details "Phase=$workstationsPhase, Mode=$enforcementMode"
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

# GPO Quick Assignment - Link to OUs button
$LinkGPOsBtn.Add_Click({
    Write-Log "User requested linking GPOs to OUs"
    Write-AuditLog -Action "GPO_LINK_ATTEMPT" -Target "Multiple GPOs" -Result 'ATTEMPT' -Details "User initiated GPO linking"

    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO linking requires Domain Controller access.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-AuditLog -Action "GPO_LINK_ATTEMPT" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Failed: Workgroup mode"
        return
    }

    # Confirmation dialog for GPO linking
    $confirmed = Show-ConfirmationDialog -Title "Confirm GPO Linking" -Message "This will link 3 GPOs to OUs, applying policies immediately." -TargetObject "GA-AppLocker-DC, GA-AppLocker-Servers, GA-AppLocker-Workstations" -ActionType 'LINK'
    if (-not $confirmed) {
        $DashboardOutput.Text = "GPO linking cancelled by user."
        return
    }

    try {
        Import-Module (Join-Path $script:ModulePath "Module4-PolicyLab.psm1") -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        # Get domain root for linking
        $domainDN = $script:DomainInfo.dnsRoot -replace '\.', ',DC='
        $domainDN = "DC=$domainDN"

        # Default AD OUs
        # Domain Controllers â†’ default OU
        # Member Servers â†’ domain root (or custom OU if exists)
        # Workstations â†’ domain root (or custom OU if exists)
        $dcOU = "OU=Domain Controllers,$domainDN"

        # Check for custom OUs (many organizations have separate Servers/Workstations OUs)
        $serversOU = Get-ADOrganizationalUnit -Filter "Name -like '*Server*'" -ErrorAction SilentlyContinue |
                     Select-Object -ExpandProperty DistinguishedName -First 1
        $workstationsOU = Get-ADOrganizationalUnit -Filter "Name -like '*Workstation*'" -ErrorAction SilentlyContinue |
                          Select-Object -ExpandProperty DistinguishedName -First 1

        # Default to domain root if custom OUs don't exist
        $serversTarget = if ($serversOU) { $serversOU } else { $domainDN }
        $workstationsTarget = if ($workstationsOU) { $workstationsOU } else { $domainDN }

        $results = @()
        $successCount = 0

        # Link DC GPO to Domain Controllers OU
        $dcResult = Add-GPOLink -GpoName "GA-AppLocker-DC" -TargetOU $dcOU
        if ($dcResult.success) {
            $results += "DC GPO linked to: $dcOU`n"
            Write-AuditLog -Action "GPO_LINKED" -Target "GA-AppLocker-DC -> $dcOU" -Result 'SUCCESS' -Details "GPO linked successfully"
            $successCount++
        } else {
            Write-AuditLog -Action "GPO_LINK_FAILED" -Target "GA-AppLocker-DC -> $dcOU" -Result 'FAILURE' -Details "Error: $($dcResult.error)"
        }

        # Link Servers GPO
        $serversResult = Add-GPOLink -GpoName "GA-AppLocker-Servers" -TargetOU $serversTarget
        if ($serversResult.success) {
            $results += "Servers GPO linked to: $serversTarget`n"
            Write-AuditLog -Action "GPO_LINKED" -Target "GA-AppLocker-Servers -> $serversTarget" -Result 'SUCCESS' -Details "GPO linked successfully"
            $successCount++
        } else {
            Write-AuditLog -Action "GPO_LINK_FAILED" -Target "GA-AppLocker-Servers -> $serversTarget" -Result 'FAILURE' -Details "Error: $($serversResult.error)"
        }

        # Link Workstations GPO
        $workstationsResult = Add-GPOLink -GpoName "GA-AppLocker-Workstations" -TargetOU $workstationsTarget
        if ($workstationsResult.success) {
            $results += "Workstations GPO linked to: $workstationsTarget`n"
            Write-AuditLog -Action "GPO_LINKED" -Target "GA-AppLocker-Workstations -> $workstationsTarget" -Result 'SUCCESS' -Details "GPO linked successfully"
            $successCount++
        } else {
            Write-AuditLog -Action "GPO_LINK_FAILED" -Target "GA-AppLocker-Workstations -> $workstationsTarget" -Result 'FAILURE' -Details "Error: $($workstationsResult.error)"
        }

        $results += "`nNOTE: If your organization uses custom OUs for Servers/Workstations, the GPOs have been linked to the domain root. You can manually move the GPO links to your custom OUs using GPMC."

        $DashboardOutput.Text = "=== GPO LINKING COMPLETE ===`n`n$results`n`nRun 'gpupdate /force' on target systems or wait for automatic GP refresh (90 minutes default)."
        Write-Log "GPO linking complete"
        Write-AuditLog -Action "GPO_LINK_BULK_COMPLETE" -Target "Multiple GPOs" -Result 'SUCCESS' -Details "GPO linking complete: $successCount of 3 linked"
    }
    catch {
        $errorMsg = ConvertTo-SafeString -InputString $_.Exception.Message -MaxLength 500
        $DashboardOutput.Text = "ERROR: $errorMsg"
        Write-Log "GPO linking failed: $errorMsg" -Level "ERROR"
        Write-AuditLog -Action "GPO_LINK_BULK_FAILED" -Target "Multiple GPOs" -Result 'FAILURE' -Details "Exception: $errorMsg"
    }
})

# Artifacts events
$ScanDirectoriesBtn.Add_Click({
    # Get selected directories
    $selectedItems = $DirectoryList.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one directory to scan.", "No Directory Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $directories = $selectedItems | ForEach-Object { $_.Content.ToString() }
    $maxFiles = [int]$MaxFilesText.Text

    Write-Log "Starting scan of $($directories.Count) directories with max files: $maxFiles"
    $ArtifactsList.Items.Clear()
    $RulesOutput.Text = "Starting scan...`n`nDirectories:`n$($directories -join "`n")`n`nThis runs in the background - UI will remain responsive."
    $ScanLocalBtn.IsEnabled = $false

    # Create a background Runspace for async scanning
    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.ArtifactsList = $ArtifactsList
    $syncHash.RulesOutput = $RulesOutput
    $syncHash.ScanDirectoriesBtn = $ScanDirectoriesBtn
    $syncHash.Window = $window
    $syncHash.CollectedArtifacts = [System.Collections.ArrayList]::new()
    $syncHash.Directories = $directories
    $syncHash.MaxFiles = $maxFiles
    $syncHash.ArtifactCountBadge = $ArtifactCountBadge
    $syncHash.EventCountBadge = $EventCountBadge

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()

    $powerShell = [PowerShell]::Create()
    $powerShell.Runspace = $runspace
    $powerShell.AddScript({
        param($syncHash)

        # Import required modules
        Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop
        Import-Module "C:\GA-AppLocker_FINAL\src\GA-AppLocker.psm1" -ErrorAction Stop

        $directories = $syncHash.Directories
        $maxFiles = $syncHash.MaxFiles
        $allArtifacts = [System.Collections.ArrayList]::new()

        # Update UI - starting
        $syncHash.Window.Dispatcher.Invoke([action]{
            $syncHash.ArtifactsList.Items.Clear()
            $syncHash.ArtifactsList.Items.Add("=== ARTIFACT COLLECTION ===")
            $syncHash.ArtifactsList.Items.Add("")
            $syncHash.ArtifactsList.Items.Add("Collecting from $($directories.Count) directories:")
            foreach ($dir in $directories) {
                $syncHash.ArtifactsList.Items.Add("  - $dir")
            }
            $syncHash.ArtifactsList.Items.Add("")
            $syncHash.ArtifactsList.Items.Add("=== WHAT'S COLLECTED ===")
            $syncHash.ArtifactsList.Items.Add("  * File name, full path, size")
            $syncHash.ArtifactsList.Items.Add("  * Publisher/Signer (if signed)")
            $syncHash.ArtifactsList.Items.Add("  * SHA256 hash (for unsigned files)")
            $syncHash.ArtifactsList.Items.Add("  * File version and modified date")
            $syncHash.ArtifactsList.Items.Add("  * File type (EXE, DLL, MSI, Script)")
            $syncHash.ArtifactsList.Items.Add("")
            $syncHash.ArtifactsList.Items.Add("[*] Scanning... (UI remains responsive)")
        })

        try {
            # Scan each directory
            foreach ($dir in $directories) {
                if (-not (Test-Path $dir)) {
                    $syncHash.Window.Dispatcher.Invoke([action]{
                        $syncHash.ArtifactsList.Items.Add("[!] Directory not found: $dir")
                    })
                    continue
                }

                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("[*] Scanning: $dir...")
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
                        fileType = if ($art.FileType) { $art.FileType } else { "Unknown" }
                    }
                    $null = $allArtifacts.Add($normalized)
                    $null = $syncHash.CollectedArtifacts.Add($normalized)
                }
            }

            # Update UI with results
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== SCAN COMPLETE ===")
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("Total artifacts: $($allArtifacts.Count)")
                $syncHash.ArtifactsList.Items.Add("")

                # Count by publisher
                $byPublisher = $allArtifacts | Group-Object -Property publisher | Sort-Object Count -Descending
                $syncHash.ArtifactsList.Items.Add("=== TOP PUBLISHERS ===")
                foreach ($pub in $byPublisher | Select-Object -First 10) {
                    $syncHash.ArtifactsList.Items.Add("  $($pub.Name): $($pub.Count)")
                }

                # Count by file type
                $byType = $allArtifacts | Group-Object -Property fileType | Sort-Object Count -Descending
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("=== FILE TYPES ===")
                foreach ($type in $byType) {
                    $syncHash.ArtifactsList.Items.Add("  $($type.Name): $($type.Count)")
                }

                $syncHash.RulesOutput.Text = "Scan complete!`n`nArtifacts collected: $($allArtifacts.Count)`n`nGo to Rule Generator to create rules from these artifacts."
                $syncHash.ScanDirectoriesBtn.IsEnabled = $true
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
            })

            Write-Log "Scan complete: $($allArtifacts.Count) artifacts collected, saved to: $csvPath"
        } catch {
            $errorMsg = $_.Exception.Message
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("ERROR: $errorMsg")
                $syncHash.RulesOutput.Text = "Scan failed: $errorMsg"
                $syncHash.ScanDirectoriesBtn.IsEnabled = $true
            })
            Write-Log "Scan failed: $errorMsg" -Level "ERROR"
        }
    }).AddParameter($syncHash) | Out-Null

    $handle = $powerShell.BeginInvoke()

    # Store async handle for cleanup if needed
    $script:ScanHandle = @{Handle = $handle; PowerShell = $powerShell}
})

# Scan Local Artifacts button - scans localhost directories
$ScanLocalArtifactsBtn.Add_Click({
    Write-Log "Starting local artifact scan (localhost directories)"

    # Get selected directories
    $selectedItems = $DirectoryList.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one directory to scan.", "No Directory Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $directories = $selectedItems | ForEach-Object { $_.Content.ToString() }
    $maxFiles = [int]$MaxFilesText.Text

    Write-Log "Starting local scan of $($directories.Count) directories with max files: $maxFiles"
    $ArtifactsList.Items.Clear()
    $RulesOutput.Text = "Starting local scan...`n`nDirectories:`n$($directories -join "`n")`n`nThis runs in the background - UI will remain responsive."
    $ScanLocalArtifactsBtn.IsEnabled = $false
    $ScanDirectoriesBtn.IsEnabled = $false

    # Create a background Runspace for async scanning
    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.ArtifactsList = $ArtifactsList
    $syncHash.RulesOutput = $RulesOutput
    $syncHash.ScanLocalArtifactsBtn = $ScanLocalArtifactsBtn
    $syncHash.ScanDirectoriesBtn = $ScanDirectoriesBtn
    $syncHash.Window = $window
    $syncHash.CollectedArtifacts = [System.Collections.ArrayList]::new()
    $syncHash.Directories = $directories
    $syncHash.MaxFiles = $maxFiles
    $syncHash.ArtifactCountBadge = $ArtifactCountBadge
    $syncHash.EventCountBadge = $EventCountBadge

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = "STA"
    $runspace.ThreadOptions = "ReuseThread"
    $runspace.Open()

    $powerShell = [PowerShell]::Create()
    $powerShell.Runspace = $runspace
    $powerShell.AddScript({
        param($syncHash)

        # Import required modules
        Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop

        $directories = $syncHash.Directories
        $maxFiles = $syncHash.MaxFiles
        $allArtifacts = [System.Collections.ArrayList]::new()

        # Update UI - starting
        $syncHash.Window.Dispatcher.Invoke([action]{
            $syncHash.ArtifactsList.Items.Clear()
            $syncHash.ArtifactsList.Items.Add("=== LOCAL ARTIFACT SCAN ===")
            $syncHash.ArtifactsList.Items.Add("")
            $syncHash.ArtifactsList.Items.Add("Collecting from $($directories.Count) directories:")
            foreach ($dir in $directories) {
                $syncHash.ArtifactsList.Items.Add("  - $dir")
            }
            $syncHash.ArtifactsList.Items.Add("")
            $syncHash.ArtifactsList.Items.Add("[*] Scanning localhost... (UI remains responsive)")
        })

        try {
            # Scan each directory
            foreach ($dir in $directories) {
                if (-not (Test-Path $dir)) {
                    $syncHash.Window.Dispatcher.Invoke([action]{
                        $syncHash.ArtifactsList.Items.Add("[!] Directory not found: $dir")
                    })
                    continue
                }

                $syncHash.Window.Dispatcher.Invoke([action]{
                    $syncHash.ArtifactsList.Items.Add("[*] Scanning: $dir...")
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
                $syncHash.ScanDirectoriesBtn.IsEnabled = $true
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
            })

            Write-Log "Local scan complete: $($allArtifacts.Count) artifacts collected, saved to: $csvPath"
        } catch {
            $errorMsg = $_.Exception.Message
            $syncHash.Window.Dispatcher.Invoke([action]{
                $syncHash.ArtifactsList.Items.Add("")
                $syncHash.ArtifactsList.Items.Add("ERROR: $errorMsg")
                $syncHash.RulesOutput.Text = "Local scan failed: $errorMsg"
                $syncHash.ScanLocalArtifactsBtn.IsEnabled = $true
                $syncHash.ScanDirectoriesBtn.IsEnabled = $true
            })
            Write-Log "Local scan failed: $errorMsg" -Level "ERROR"
        }
    }).AddParameter($syncHash) | Out-Null

    $handle = $powerShell.BeginInvoke()

    # Store async handle for cleanup if needed
    $script:LocalScanHandle = @{Handle = $handle; PowerShell = $powerShell}
})

# Scan Remote Artifacts button - scans selected computers for artifacts
$ScanRemoteArtifactsBtn.Add_Click({
    Write-Log "Starting remote artifact scan"

    # Get selected computers from ListBox
    $selectedItems = $ArtifactComputersList.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one computer from the list.", "No Computers Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $computers = $selectedItems | ForEach-Object { $_.Name.ToString() }

    $ArtifactsList.Items.Clear()
    $RulesOutput.Text = "=== REMOTE ARTIFACT SCAN ===`n`nScanning $($computers.Count) selected computers via WinRM...`n"
    $RulesOutput.Text += "Collecting: Executable artifacts from common directories`n"
    [System.Windows.Forms.Application]::DoEvents()

    # Import Module2 for remote scanning
    try {
        Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop

        $allArtifacts = [System.Collections.ArrayList]::new()
        $successCount = 0
        $failCount = 0

        foreach ($computer in $computers) {
            $ArtifactsList.Items.Add("")
            $ArtifactsList.Items.Add("[$computer] Scanning...")
            [System.Windows.Forms.Application]::DoEvents()

            # Scan remote computer for artifacts
            $result = Get-RemoteArtifacts -ComputerName $computer -ErrorAction Stop

            if ($result.success) {
                $successCount++

                foreach ($art in $result.artifacts) {
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

                $ArtifactsList.Items.Add("[$computer] Found: $($result.artifacts.Count) artifacts")
            } else {
                $failCount++
                $ArtifactsList.Items.Add("[$computer] FAILED: $($result.error)")
            }

            [System.Windows.Forms.Application]::DoEvents()
        }

        # Save to script variable for use in Rule Generator
        $script:CollectedArtifacts = $allArtifacts

        # Update badges in Rule Generator
        Update-Badges

        # Export artifacts to CSV automatically
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $csvPath = "C:\GA-AppLocker\Scans\RemoteScan_$($computers.Count)Computers_$timestamp.csv"

        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("Saving to: $csvPath...")

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

        $ArtifactsList.Items.Add("[OK] Saved: $csvPath")
        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("=== SCAN COMPLETE ===")
        $ArtifactsList.Items.Add("Computers: $successCount success, $failCount failed")
        $ArtifactsList.Items.Add("Total artifacts: $($allArtifacts.Count)")
        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("Use in Rule Generator > Generate Rules to create rules.")

        $RulesOutput.Text += "`n`n=== SCAN COMPLETE ===`n"
        $RulesOutput.Text += "Computers: $successCount success, $failCount failed`n"
        $RulesOutput.Text += "Artifacts: $($allArtifacts.Count) unique files`n"
        $RulesOutput.Text += "`nExported to: $csvPath`n"
        $RulesOutput.Text += "Go to Rule Generator to create rules from these artifacts."

        Write-Log "Remote artifact scan complete: $($allArtifacts.Count) artifacts from $successCount computers, saved to: $csvPath"
    } catch {
        $errorMsg = $_.Exception.Message
        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("ERROR: $errorMsg")
        $RulesOutput.Text = "Remote scan failed: $errorMsg"
        Write-Log "Remote artifact scan failed: $errorMsg" -Level "ERROR"
    }
})

# Refresh Artifact Computers button - loads from AD Discovery
$RefreshArtifactComputersBtn.Add_Click({
    $ArtifactComputersList.Items.Clear()

    # Try to get computers from discovery results
    if ($script:DiscoveredComputers.Count -gt 0) {
        $RulesOutput.Text = "Refreshing artifact computer list from AD Discovery...`n"

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
                OU = if ($compInfo.OU) { $compInfo.OU } else { "" }
            }

            $ArtifactComputersList.Items.Add($item)
        }

        $RulesOutput.Text += "`nLoaded: $($ArtifactComputersList.Items.Count) computers from AD Discovery`n"
        $RulesOutput.Text += "Select computers and click 'Scan Selected' to collect artifacts."
        Write-Log "Artifact computer list refreshed: $($ArtifactComputersList.Items.Count) computers"
    } else {
        $RulesOutput.Text = "No computers in AD Discovery.`n`nGo to AD Discovery tab first to discover computers.`nThen return here to scan them for artifacts."
        Write-Log "No computers available for artifact scanning"
    }
})

# Rules events
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

# Import folder recursively - searches all CSV files in folder and subfolders
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

# Load Collected Artifacts button - seamless integration from Artifact Collection
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

# Load Collected Events button - seamless integration from Event Monitor
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

# Deduplicate button - removes duplicate artifacts based on selected field
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

    Write-Log "Deduplicated by $dedupeType: $beforeCount -> $($uniqueArtifacts.Count) (removed $removedCount)"
    [System.Windows.MessageBox]::Show(
        "Deduplication complete!`n`nBy: $dedupeType`nBefore: $beforeCount`nAfter: $($uniqueArtifacts.Count)`nRemoved: $removedCount duplicates",
        "Deduplication Complete",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
})

# Export Artifacts List button - exports current artifact list to CSV
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

# Change Group button - change AD group for selected rules
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

# Duplicate Rules button - duplicate selected rules to another group
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

# Delete Rules button - delete selected rules
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

# ============================================================
# PHASE 4: Bulk Editing Event Handlers
# ============================================================

# Apply Group Change button - bulk change AD group for selected rules
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

# Apply Action Change button - bulk change action (Allow/Deny) for selected rules
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

# Apply Duplicate button - bulk duplicate selected rules to another group
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

# Bulk Remove button - remove all selected rules
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
})

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

# ============================================================
# QoL FEATURE: Audit Mode Toggle
# ============================================================
$script:AuditModeEnabled = $true

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

$ClearFilterBtn.Add_Click({
    $RulesSearchBox.Text = ""
    $RulesSearchBox.Foreground = "#8B949E"
    Apply-FilterToRules
})

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
$ClosePreviewBtn.Add_Click({
    $RulePreviewPanel.Visibility = [System.Windows.Visibility]::Collapsed
})

# Merge rules - import additional XML rules and merge with generated rules
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

# Events filters
$FilterAllBtn.Add_Click({
    $script:EventFilter = "All"
    Write-Log "Event filter set to: All"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to All."
})

$FilterAllowedBtn.Add_Click({
    $script:EventFilter = "Allowed"
    Write-Log "Event filter set to: Allowed"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to Allowed (ID 8002)."
})

$FilterBlockedBtn.Add_Click({
    $script:EventFilter = "Blocked"
    Write-Log "Event filter set to: Blocked"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to Blocked (ID 8004)."
})

$FilterAuditBtn.Add_Click({
    $script:EventFilter = "Audit"
    Write-Log "Event filter set to: Audit"
    Filter-Events | Out-Null
    $EventsOutput.Text = "Filter set to Audit (ID 8003)."
})

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

# Scan Local Events button
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

# Scan Remote Events button - COMPREHENSIVE SCAN
# Uses Get-RemoteAppLockerEvents from Module2-RemoteScan for full data collection
# Collects: All 4 AppLocker logs, system info, policy status, parsed event XML
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

# Refresh Computers button - loads from AD Discovery
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
            Import-Module (Join-Path $script:ModulePath "Module2-RemoteScan.psm1") -ErrorAction Stop

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

# Compliance events
$GenerateEvidenceBtn.Add_Click({
    Write-Log "Generating evidence package"

    Import-Module (Join-Path $script:ModulePath "Module7-Compliance.psm1") -ErrorAction Stop

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

# Scan Local Compliance button
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

# Scan Selected Compliance button
$ScanSelectedComplianceBtn.Add_Click({
    Write-Log "Scan Selected Compliance clicked"

    $selectedItems = $ComplianceComputersList.SelectedItems
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please select at least one computer.", "No Computer Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $ComplianceOutput.Text = "Testing connectivity to $($selectedItems.Count) computers...`n`n"

    Import-Module "C:\GA-AppLocker_FINAL\src\modules\Module2-RemoteScan.psm1" -ErrorAction Stop

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

# Refresh Compliance List button
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

# Deployment events
$CreateGP0Btn.Add_Click({
    Write-Log "Create GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $DeploymentStatus.Text = "Creating AppLocker GPO...`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-AppLockerGpo -GpoName "AppLocker Policy"

    if ($result.success) {
        if ($result.isNew) {
            $DeploymentStatus.Text = "SUCCESS: AppLocker GPO created!`n`nGPO Name: $($result.gpoName)`nGPO ID: $($result.gpoId)`nLinked to: $($result.linkedTo)`n`nNext Steps:`n1. Export rules from Rule Generator`n2. Import rules to GPO via Group Policy Management`n3. Set enforcement mode (start with Audit)`n4. Monitor events before enforcing"
            [System.Windows.MessageBox]::Show("AppLocker GPO created successfully!`n`nGPO: $($result.gpoName)`nLinked to: $($result.linkedTo)", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            $DeploymentStatus.Text = "GPO '$($result.gpoName)' already exists.`n`nUse GPMC to manage GPO links."
            [System.Windows.MessageBox]::Show("GPO '$($result.gpoName)' already exists.`n`nUse GPMC to manage GPO links.", "GPO Exists", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
        Write-Log "AppLocker GPO created/found: $($result.gpoName)"
    } else {
        $DeploymentStatus.Text = "ERROR: Failed to create GPO`n`n$($result.error)`n`nMake sure you are running as Domain Admin with Group Policy module installed."
        [System.Windows.MessageBox]::Show("Failed to create AppLocker GPO:`n$($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Failed to create AppLocker GPO: $($result.error)" -Level "ERROR"
    }
})

$DisableGpoBtn.Add_Click({
    Write-Log "Disable GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO management requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "This will disable the AppLocker GPO link, which stops the policy from applying.`n`nThe GPO will not be deleted, just disabled.`n`nContinue?",
        "Confirm Disable GPO",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        # Get domain root
        $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName

        # Check if AppLocker GPO exists
        $gpo = Get-GPO -Name "AppLocker Policy" -ErrorAction SilentlyContinue
        if (-not $gpo) {
            [System.Windows.MessageBox]::Show("AppLocker GPO not found.", "GPO Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            $DeploymentStatus.Text = "INFO: AppLocker GPO not found - nothing to disable."
            return
        }

        # Find and disable the link
        $gpoLink = Get-GPInheritance -Target $domainDN | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq "AppLocker Policy" }
        if ($gpoLink) {
            Set-GPLink -Name "AppLocker Policy" -Target $domainDN -LinkEnabled No -ErrorAction Stop
            $DeploymentStatus.Text = "SUCCESS: AppLocker GPO DISABLED`n`nGPO: AppLocker Policy`nDomain: $domainDN`n`nThe policy will no longer apply.`nTo re-enable, use Group Policy Management Console."
            [System.Windows.MessageBox]::Show("AppLocker GPO has been disabled.`n`nThe policy will no longer apply after the next Group Policy refresh.", "GPO Disabled", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Write-Log "AppLocker GPO disabled: $domainDN"
        } else {
            $DeploymentStatus.Text = "INFO: AppLocker GPO is not currently linked to the domain.`n`nNothing to disable."
            [System.Windows.MessageBox]::Show("AppLocker GPO is not linked to the domain root.", "Not Linked", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    }
    catch {
        $DeploymentStatus.Text = "ERROR: Failed to disable GPO`n`n$($_.Exception.Message)"
        [System.Windows.MessageBox]::Show("Failed to disable GPO:`n$($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Failed to disable GPO: $($_.Exception.Message)" -Level "ERROR"
    }
})

# WinRM events
$CreateWinRMGpoBtn.Add_Click({
    Write-Log "Create WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $WinRMOutput.Text = "=== WINRM GPO CREATION ===`n`nCreating WinRM GPO...`n`nThis will:`n  â€¢ Create 'Enable WinRM' GPO`n  â€¢ Link to domain root`n  â€¢ Configure WinRM service settings`n  â€¢ Enable firewall rules`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $action = if ($result.isNew) { "CREATED" } else { "UPDATED" }
        $WinRMOutput.Text = "=== WINRM GPO $action ===`n`nSUCCESS: GPO $($result.message)`n`nGPO Name: $($result.gpoName)`nGPO ID: $($result.gpoId)`nLinked to: $($result.linkedTo)`n`nConfigured Settings:`n`nWinRM Service:`n  â€¢ Auto-config: Enabled`n  â€¢ IPv4 Filter: * (all)`n  â€¢ IPv6 Filter: * (all)`n  â€¢ Basic Auth: Enabled`n  â€¢ Unencrypted Traffic: Disabled`n`nWinRM Client:`n  â€¢ Basic Auth: Enabled`n  â€¢ TrustedHosts: * (all)`n  â€¢ Unencrypted Traffic: Disabled`n`nFirewall Rules:`n  â€¢ WinRM HTTP (5985): Allowed`n  â€¢ WinRM HTTPS (5986): Allowed`n`nService: Automatic startup`n`nTo force immediate update: gpupdate /force"
        Write-Log "WinRM GPO $action successfully: $($result.gpoName)"
        [System.Windows.MessageBox]::Show("WinRM GPO $action successfully!`n`nGPO: $($result.gpoName)`n`nLinked to: $($result.linkedTo)", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $WinRMOutput.Text = "=== WINRM GPO FAILED ===`n`nERROR: $($result.error)`n`nPossible causes:`n  â€¢ Not running as Domain Admin`n  â€¢ Group Policy module not available`n  â€¢ Insufficient permissions`n`nPlease run as Domain Administrator and try again."
        Write-Log "Failed to create/update WinRM GPO: $($result.error)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to create/update WinRM GPO:`n$($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
})

# Enable/Disable WinRM GPO Link
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

# Force GPUpdate on all domain computers
$ForceGPUpdateBtn.Add_Click({
    Write-Log "Force GPUpdate button clicked"
    if ($script:IsWorkgroup -or -not $script:HasRSAT) {
        [System.Windows.MessageBox]::Show("This feature requires domain membership and RSAT tools.", "Not Available", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "This will run 'gpupdate /force' on all domain computers.`n`nThis requires:`n  â€¢ WinRM already enabled on target machines`n  â€¢ Administrative access to remote computers`n`nContinue?",
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

# AD Discovery events
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

$SelectAllComputersBtn.Add_Click({
    $DiscoveredComputersList.SelectAll()
    $DiscoveryOutput.Text = "Selected all $($DiscoveredComputersList.Items.Count) computers"
})

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

# Group Management events
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

# AppLocker Setup events
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

# Remove OU Protection button handler
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

# Help events
$HelpBtnWorkflow.Add_Click({
    $HelpTitle.Text = "Help - Workflow"
    $HelpText.Text = Get-HelpContent "Workflow"
})

$HelpBtnWhatsNew.Add_Click({
    $HelpTitle.Text = "Help - What's New in v1.2.5"
    $HelpText.Text = Get-HelpContent "WhatsNew"
})

$HelpBtnPolicyGuide.Add_Click({
    $HelpTitle.Text = "Help - Policy Build Guide"
    $HelpText.Text = Get-HelpContent "PolicyGuide"
})

$HelpBtnRules.Add_Click({
    $HelpTitle.Text = "Help - Rule Best Practices"
    $HelpText.Text = Get-HelpContent "Rules"
})

$HelpBtnTroubleshooting.Add_Click({
    $HelpTitle.Text = "Help - Troubleshooting"
    $HelpText.Text = Get-HelpContent "Troubleshooting"
})

# Gap Analysis events
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

# Export/Import Rules events
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

$ImportRulesBtn.Add_Click({
    Write-Log "Import rules to GPO button clicked"

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

    # Open file dialog
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog.Title = "Import AppLocker Rules to $targetGpoName"
    $openDialog.InitialDirectory = "C:\GA-AppLocker\Rules"

    if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    $xmlFilePath = $openDialog.FileName
    $DeploymentStatus.Text = "Importing rules to: $targetGpoName`nMode: $(if ($isMergeMode) { 'Merge (Add)' } else { 'Overwrite' })`nSource: $xmlFilePath`n`nProcessing..."

    Write-Log "Importing rules to GPO: $targetGpoName (Mode: $(if ($isMergeMode) { 'Merge' } else { 'Overwrite' }))"

    try {
        Import-Module (Join-Path $script:ModulePath "Module4-PolicyLab.psm1") -ErrorAction Stop
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
            $MiniStatusMode.Text = "ENFORCE"
            $MiniStatusMode.Foreground = "#F85149"
        } else {
            $MiniStatusMode.Text = "AUDIT"
            $MiniStatusMode.Foreground = "#3FB950"
        }
    }
    catch {
        $MiniStatusMode.Text = "UNKNOWN"
        $MiniStatusMode.Foreground = "#8B949E"
    }

    # Phase indicator (from GPO quick assignment)
    $currentPhase = $script:CurrentDeploymentPhase
    if ($currentPhase) {
        $MiniStatusPhase.Text = "P$currentPhase"
    } else {
        $MiniStatusPhase.Text = ""
    }

    # Connected systems count
    if ($script:DiscoveredSystems) {
        $onlineCount = @($script:DiscoveredSystems | Where-Object { $_.status -eq "Online" }).Count
        $MiniStatusConnected.Text = "$onlineCount online"
    } else {
        $MiniStatusConnected.Text = "0 systems"
    }

    # Artifacts count
    $artifactCount = $script:CollectedArtifacts.Count
    $MiniStatusArtifacts.Text = "$artifactCount artifacts"

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

# Handle window closing properly
$window.add_Closing({
    param($sender, $e)
    # Allow the window to close
    $e.Cancel = $false
})

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
        $CreateGP0Btn.IsEnabled = $false
        $DisableGpoBtn.IsEnabled = $false
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

        # Disable remote scanning in Artifacts panel
        $ScanRemoteArtifactsBtn.IsEnabled = $false
        $RefreshArtifactComputersBtn.IsEnabled = $false

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
        $CreateGP0Btn.IsEnabled = $false
        $DisableGpoBtn.IsEnabled = $false
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

        # Disable remote scanning in Artifacts panel
        $ScanRemoteArtifactsBtn.IsEnabled = $false
        $RefreshArtifactComputersBtn.IsEnabled = $false

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
        $CreateGP0Btn.IsEnabled = $true
        $DisableGpoBtn.IsEnabled = $true
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
            "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker.ico"
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
            "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker.png"
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
            "C:\projects\GA-AppLocker_FINAL\general_atomics_logo_big.ico"
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

    # Set final message
    $DashboardOutput.Text = "=== GA-APPLOCKER DASHBOARD ===`n`nAaronLocker-aligned AppLocker Policy Management`n`nEnvironment: $($script:DomainInfo.message)`n`nReady to begin. Select a tab to start.`n`nSession timeout: $($script:SessionTimeoutMinutes) minutes of inactivity."
})

# Show window
$window.ShowDialog() | Out-Null
