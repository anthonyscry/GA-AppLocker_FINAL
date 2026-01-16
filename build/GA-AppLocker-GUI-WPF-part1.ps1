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
                                <Run Text="• Use Publisher rules first"/>
                                <LineBreak/>
                                <Run Text="• Use Hash rules for unsigned files"/>
                                <LineBreak/>
                                <Run Text="• Avoid Path rules when possible"/>
                                <LineBreak/>
                                <Run Text="• Always start in Audit mode"/>
                                <LineBreak/>
                                <Run Text="• Use role-based groups"/>
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
                                    <Run Text="• AppLocker structure initialization (OU, groups, policies)"/>
                                    <LineBreak/>
                                    <Run Text="• AD group membership export/import with safety controls"/>
                                    <LineBreak/>
                                    <Run Text="• Automated artifact discovery and rule generation"/>
                                    <LineBreak/>
                                    <Run Text="• Publisher-first rule strategy with hash fallback"/>
                                    <LineBreak/>
                                    <Run Text="• GPO deployment with audit-first enforcement"/>
                                    <LineBreak/>
                                    <Run Text="• Real-time event monitoring and filtering"/>
                                    <LineBreak/>
                                    <Run Text="• Compliance evidence package generation"/>
                                    <LineBreak/>
                                    <Run Text="• WinRM remote management setup"/>
                                    <LineBreak/>
                                    <Run Text="• Admin browser deny rules for security"/>
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel>
                                <TextBlock Text="Requirements" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#8B949E">
                                    <Run Text="• Windows 10/11 or Windows Server 2019+"/>
                                    <LineBreak/>
                                    <Run Text="• PowerShell 5.1+"/>
                                    <LineBreak/>
                                    <Run Text="• Active Directory module (for domain features)"/>
                                    <LineBreak/>
                                    <Run Text="• Group Policy module (for GPO deployment)"/>
                                    <LineBreak/>
                                    <Run Text="• Administrator privileges recommended"/>
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20">
                            <StackPanel>
                                <TextBlock Text="License" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <TextBlock Text="© 2026 GA-ASI. Internal use only." FontSize="11" Foreground="#6E7681"/>
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
