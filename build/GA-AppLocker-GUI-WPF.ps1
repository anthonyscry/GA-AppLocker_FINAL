# GA-AppLocker Dashboard - Modern WPF GUI
# GitHub-style dark theme based on ExampleGUI design
# Self-contained with embedded module functions

# Required assemblies for WPF
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
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
            $policyXml | Out-File -FilePath $policyPath -Encoding UTF8
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
                        message = $_.Message -replace "`n", " " -replace "`r", ""
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
                                    message = $_.Message -replace "`n", " " -replace "`r", ""
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

        # Enable inbound firewall rule for WinRM HTTP
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "WINRM-HTTP-In-TCP-NoScope" -Type String -Value "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=Windows Remote Management (HTTP-In)|Desc=Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]|EmbedCtxt=Windows Remote Management|" -ErrorAction SilentlyContinue

        Write-Log "WinRM firewall rules configured"

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
        Title="GA-AppLocker Dashboard" Height="600" Width="1000" MinHeight="500" MinWidth="800"
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
    </Window.Resources>

    <Grid>
        <!-- Header -->
        <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Height="60" VerticalAlignment="Top">
            <Grid Margin="20,0">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="GA-AppLocker Dashboard" FontSize="18" FontWeight="Bold"
                               Foreground="#E6EDF3" VerticalAlignment="Center"/>
                    <TextBlock x:Name="HeaderVersion" Text="v1.2.4" FontSize="12" Foreground="#6E7681"
                               VerticalAlignment="Center" Margin="10,0,0,0"/>
                </StackPanel>
                <TextBlock x:Name="StatusText" Text="Initializing..." FontSize="12"
                           Foreground="#6E7681" VerticalAlignment="Center" HorizontalAlignment="Right"/>
            </Grid>
        </Border>

        <!-- Environment Status Banner -->
        <Border x:Name="EnvironmentBanner" Background="#21262D" BorderBrush="#30363D"
                BorderThickness="0,0,0,1" Height="40" VerticalAlignment="Top" Margin="0,60,0,0">
            <Grid Margin="20,0">
                <TextBlock x:Name="EnvironmentText" Text="" FontSize="12"
                           Foreground="#8B949E" VerticalAlignment="Center" HorizontalAlignment="Left"/>
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
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
                <ScrollViewer VerticalScrollBarVisibility="Auto" Margin="0,10,0,10">
                    <StackPanel>
                        <!-- Dashboard -->
                        <Button x:Name="NavDashboard" Content="Dashboard" Style="{StaticResource SecondaryButton}"
                                HorizontalAlignment="Stretch" Margin="10,5"/>

                        <!-- SETUP Section (Collapsible) -->
                            <Expander x:Name="SetupSection" IsExpanded="False" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
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
                            <Expander x:Name="ScanningSection" IsExpanded="False" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
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
                            <Expander x:Name="DeploymentSection" IsExpanded="False" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
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
                            <Expander x:Name="MonitoringSection" IsExpanded="False" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
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
                            <ComboBox.Resources>
                                <SolidColorBrush x:Key="{x:Static SystemColors.WindowBrushKey}" Color="#21262D"/>
                                <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#30363D"/>
                            </ComboBox.Resources>
                            <ComboBox.ItemContainerStyle>
                                <Style TargetType="ComboBoxItem">
                                    <Setter Property="Background" Value="#21262D"/>
                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                    <Style.Triggers>
                                        <Trigger Property="IsHighlighted" Value="True">
                                            <Setter Property="Background" Value="#30363D"/>
                                        </Trigger>
                                    </Style.Triggers>
                                </Style>
                            </ComboBox.ItemContainerStyle>
                            <ComboBoxItem Content="Last 7 Days" IsSelected="True"/>
                            <ComboBoxItem Content="Last 30 Days"/>
                        </ComboBox>

                        <TextBlock Text="System:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center" Grid.Column="2" Margin="0,0,8,0"/>
                        <ComboBox x:Name="DashboardSystemFilter" Grid.Column="3" Width="150" Height="26"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" Margin="0,0,15,0" FontSize="11">
                            <ComboBox.Resources>
                                <SolidColorBrush x:Key="{x:Static SystemColors.WindowBrushKey}" Color="#21262D"/>
                                <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#30363D"/>
                            </ComboBox.Resources>
                            <ComboBox.ItemContainerStyle>
                                <Style TargetType="ComboBoxItem">
                                    <Setter Property="Background" Value="#21262D"/>
                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                    <Style.Triggers>
                                        <Trigger Property="IsHighlighted" Value="True">
                                            <Setter Property="Background" Value="#30363D"/>
                                        </Trigger>
                                    </Style.Triggers>
                                </Style>
                            </ComboBox.ItemContainerStyle>
                            <ComboBoxItem Content="All Systems" IsSelected="True"/>
                        </ComboBox>

                        <Button x:Name="RefreshDashboardBtn" Content="Refresh"
                                Style="{StaticResource SecondaryButton}" Grid.Column="4" Width="80" Height="26"/>
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

                    <!-- Row 1: Max Files and basic buttons -->
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <StackPanel Grid.Column="0" Orientation="Horizontal">
                            <TextBlock Text="Max Files:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                            <TextBox x:Name="MaxFilesText" Text="50000" Width="80" Height="32"
                                     Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                     BorderThickness="1" FontSize="13" Padding="5"/>
                        </StackPanel>

                        <Button x:Name="ScanLocalBtn" Content="Scan Localhost"
                                Style="{StaticResource SecondaryButton}" Grid.Column="2" Margin="0,0,10,0"/>
                        <Button x:Name="ExportArtifactsBtn" Content="Export CSV"
                                Style="{StaticResource SecondaryButton}" Grid.Column="3"/>
                    </Grid>

                    <!-- Row 2: Comprehensive Scan (full width) -->
                    <Button x:Name="ComprehensiveScanBtn" Content="Comprehensive Scan (AaronLocker-style)"
                            Style="{StaticResource PrimaryButton}" HorizontalAlignment="Stretch" Margin="0,0,0,10"/>

                    <!-- Info about Comprehensive Scan -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="10" Margin="0,0,0,10">
                        <TextBlock Text="Creates: Executables.csv, InstalledSoftware.csv, Publishers.csv, RunningProcesses.csv, SystemInfo.csv, WritableDirectories.csv, AppLockerPolicy.xml"
                                   FontSize="10" Foreground="#8B949E" TextWrapping="Wrap"/>
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

                    <!-- Import Buttons (Scan removed per user request) -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="ImportBaselineBtn" Content="Import Baseline CSV" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportTargetBtn" Content="Import Target CSV" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Compare Button -->
                    <Grid Margin="0,0,0,15">
                        <Button x:Name="CompareSoftwareBtn" Content="Compare Software Lists" Style="{StaticResource PrimaryButton}" Width="250" HorizontalAlignment="Left"/>
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
                                        <DataGridTextColumn Header="Software Name" Binding="{Binding Name}" Width="200">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                                    <Setter Property="Padding" Value="4,2"/>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Version" Binding="{Binding Version}" Width="100">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Foreground" Value="#8B949E"/>
                                                    <Setter Property="Padding" Value="4,2"/>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="120">
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
                                        <DataGridTextColumn Header="Baseline Ver" Binding="{Binding BaselineVersion}" Width="100">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
                                                    <Setter Property="Foreground" Value="#8B949E"/>
                                                    <Setter Property="Padding" Value="4,2"/>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Target Ver" Binding="{Binding TargetVersion}" Width="100">
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
                            <RadioButton x:Name="RuleTypePublisher" Content="Publisher" IsChecked="True"
                                         Foreground="#E6EDF3" FontSize="11" Margin="0,0,10,0" VerticalContentAlignment="Center"/>
                            <RadioButton x:Name="RuleTypeHash" Content="Hash"
                                         Foreground="#E6EDF3" FontSize="11" Margin="0,0,10,0" VerticalContentAlignment="Center"/>
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
                        <ComboBox x:Name="RuleGroupCombo" Grid.Column="7" Height="26" MinWidth="180"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="11">
                            <ComboBox.ItemContainerStyle>
                                <Style TargetType="ComboBoxItem">
                                    <Setter Property="Background" Value="#21262D"/>
                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                    <Setter Property="Padding" Value="8,4"/>
                                    <Style.Triggers>
                                        <Trigger Property="IsHighlighted" Value="True">
                                            <Setter Property="Background" Value="#388BFD"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                        <Trigger Property="IsSelected" Value="True">
                                            <Setter Property="Background" Value="#238636"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                    </Style.Triggers>
                                </Style>
                            </ComboBox.ItemContainerStyle>
                            <ComboBoxItem Content="Everyone (S-1-1-0)" IsSelected="True" Tag="S-1-1-0"/>
                            <ComboBoxItem Content="Administrators (S-1-5-32-544)" Tag="S-1-5-32-544"/>
                            <ComboBoxItem Content="Users (S-1-5-32-545)" Tag="S-1-5-32-545"/>
                            <ComboBoxItem Content="Domain Users" Tag="DomainUsers"/>
                            <ComboBoxItem Content="Domain Admins" Tag="DomainAdmins"/>
                            <ComboBoxItem Content="Custom (Enter SID below)" Tag="Custom"/>
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
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ImportArtifactsBtn" Content="Import CSV"
                                Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportFolderBtn" Content="Import Folder"
                                Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                        <Button x:Name="CreateRulesFromEventsBtn" Content="From Events"
                                Style="{StaticResource SecondaryButton}" Grid.Column="4"/>
                        <Button x:Name="MergeRulesBtn" Content="Merge Rules"
                                Style="{StaticResource SecondaryButton}" Grid.Column="6"/>
                        <Button x:Name="GenerateRulesBtn" Content="Generate Rules"
                                Style="{StaticResource PrimaryButton}" Grid.Column="8"/>
                    </Grid>

                    <!-- Rules Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" MinHeight="180" MaxHeight="350">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="RulesOutput" Text="Import artifacts or generate rules to see results here..."
                                       FontFamily="Consolas" FontSize="11" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Events Panel -->
                <StackPanel x:Name="PanelEvents" Visibility="Collapsed">
                    <TextBlock Text="Event Monitor" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                    <!-- Scan Buttons Row -->
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="8"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="ScanLocalEventsBtn" Content="Scan Local" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="ScanRemoteEventsBtn" Content="Scan Remote" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                        <Button x:Name="ImportEventsBtn" Content="Import" Style="{StaticResource SecondaryButton}" Grid.Column="4"/>
                        <Button x:Name="ExportEventsBtn" Content="Export" Style="{StaticResource SecondaryButton}" Grid.Column="6"/>
                    </Grid>

                    <!-- Remote Computer Input -->
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBlock Text="Computers:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBox x:Name="EventComputersText" Grid.Column="1" Height="24"
                                 Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                 BorderThickness="1" FontSize="10" Padding="4"
                                 Text="(comma-separated or use Load from Discovery)"/>
                        <Button x:Name="LoadFromDiscoveryBtn" Content="Load from Discovery"
                                Style="{StaticResource SecondaryButton}" Grid.Column="2" Margin="8,0,0,0"/>
                    </Grid>

                    <!-- Event Filters -->
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                        <TextBlock Text="Filter:" FontSize="10" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <Button x:Name="FilterAllBtn" Content="All" Style="{StaticResource SecondaryButton}" Margin="0,0,4,0"/>
                        <Button x:Name="FilterAllowedBtn" Content="Allowed" Style="{StaticResource SecondaryButton}" Margin="0,0,4,0"/>
                        <Button x:Name="FilterBlockedBtn" Content="Blocked" Style="{StaticResource SecondaryButton}" Margin="0,0,4,0"/>
                        <Button x:Name="FilterAuditBtn" Content="Audit" Style="{StaticResource SecondaryButton}" Margin="0,0,4,0"/>
                        <Button x:Name="RefreshEventsBtn" Content="Refresh" Style="{StaticResource PrimaryButton}" Margin="15,0,0,0"/>
                    </StackPanel>

                    <!-- Events Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="6" Padding="10" MinHeight="200" MaxHeight="400">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="EventsOutput"
                                       Text="Scan Local, Scan Remote, Import/Export - Use AD Discovery to find computers first."
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
                        <Button x:Name="LinkGP0Btn" Content="Link GPO to Domain" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Import/Export Rules Buttons -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ExportRulesBtn" Content="Export Rules" Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportRulesBtn" Content="Import Rules" Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                    </Grid>

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

                    <Button x:Name="GenerateEvidenceBtn" Content="Generate Evidence Package"
                            Style="{StaticResource PrimaryButton}" Width="220" HorizontalAlignment="Left"
                            Margin="0,0,0,15"/>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="300">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="ComplianceOutput" Text="Click 'Generate Evidence Package' to create compliance artifacts..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
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
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Initialize AppLocker Structure" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="15"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="15"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="150"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="OU Name:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="OUNameText" Text="AppLocker" Width="120" Height="28" Grid.Column="2" Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"/>
                                <CheckBox x:Name="AutoPopulateCheck" Content="Auto-Populate Admins" IsChecked="True" Grid.Column="4" Foreground="#E6EDF3"/>
                                <Button x:Name="BootstrapAppLockerBtn" Content="Initialize" Style="{StaticResource PrimaryButton}" Grid.Column="6"/>
                            </Grid>
                            <Grid Margin="0,10,0,0">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="180"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Remove protection from AppLocker OUs (allows deletion)" FontSize="11" Foreground="#F85149" VerticalAlignment="Center"/>
                                <Button x:Name="RemoveOUProtectionBtn" Content="Remove OU Protection" Style="{StaticResource SecondaryButton}" Grid.Column="1"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Browser Deny Section -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Admin Browser Deny Rules" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Deny internet access for admin accounts (security best practice)" FontSize="11" Foreground="#D29922" Margin="0,0,0,5"/>
                            <Grid Margin="0,5,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="150"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Create deny rules for common browsers in AppLocker-Admin" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <Button x:Name="CreateBrowserDenyBtn" Content="Create Deny Rules" Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                            </Grid>
                            <TextBlock FontSize="11" Foreground="#6E7681" TextWrapping="Wrap">
                                Browsers: Chrome, Firefox, Edge, Opera, Brave, Vivaldi, Internet Explorer
                            </TextBlock>
                        </StackPanel>
                    </Border>

                    <!-- Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="200" MaxHeight="400">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="AppLockerSetupOutput" Text="Click 'Initialize' to create AppLocker structure..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- About Panel -->
                <ScrollViewer x:Name="PanelAbout" Visibility="Collapsed" VerticalScrollBarVisibility="Auto">
                    <StackPanel>
                        <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                            <StackPanel Orientation="Horizontal">
                                <Image x:Name="AboutLogo" Width="64" Height="64" Margin="0,0,20,0" VerticalAlignment="Center"/>
                                <StackPanel VerticalAlignment="Center">
                                    <TextBlock Text="GA-AppLocker Dashboard" FontSize="20" FontWeight="Bold" Foreground="#E6EDF3"/>
                                    <TextBlock x:Name="AboutVersion" Text="Version 1.0" FontSize="13" Foreground="#8B949E" Margin="0,4,0,0"/>
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
                                <Button x:Name="HelpBtnPolicyGuide" Content="Policy Guide" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="HelpBtnRules" Content="Rule Best Practices" Style="{StaticResource SecondaryButton}" Margin="0,0,8,0"/>
                                <Button x:Name="HelpBtnTroubleshooting" Content="Troubleshooting" Style="{StaticResource SecondaryButton}"/>
                            </WrapPanel>
                        </Border>

                        <Border Background="#21262D" CornerRadius="8" Padding="20">
                            <StackPanel>
                                <TextBlock x:Name="HelpTitle" Text="Help - Workflow" FontSize="18" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                <TextBlock x:Name="HelpText" TextWrapping="Wrap" FontSize="12" Foreground="#8B949E" LineHeight="20">
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

# Other controls
$MaxFilesText = $window.FindName("MaxFilesText")
$ScanLocalBtn = $window.FindName("ScanLocalBtn")
$ExportArtifactsBtn = $window.FindName("ExportArtifactsBtn")
$ComprehensiveScanBtn = $window.FindName("ComprehensiveScanBtn")
$ArtifactsList = $window.FindName("ArtifactsList")
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
$CreateRulesFromEventsBtn = $window.FindName("CreateRulesFromEventsBtn")
$MergeRulesBtn = $window.FindName("MergeRulesBtn")
$GenerateRulesBtn = $window.FindName("GenerateRulesBtn")
$RulesOutput = $window.FindName("RulesOutput")
$ScanLocalEventsBtn = $window.FindName("ScanLocalEventsBtn")
$ScanRemoteEventsBtn = $window.FindName("ScanRemoteEventsBtn")
$ImportEventsBtn = $window.FindName("ImportEventsBtn")
$ExportEventsBtn = $window.FindName("ExportEventsBtn")
$EventComputersText = $window.FindName("EventComputersText")
$LoadFromDiscoveryBtn = $window.FindName("LoadFromDiscoveryBtn")
$FilterAllBtn = $window.FindName("FilterAllBtn")
$FilterAllowedBtn = $window.FindName("FilterAllowedBtn")
$FilterBlockedBtn = $window.FindName("FilterBlockedBtn")
$FilterAuditBtn = $window.FindName("FilterAuditBtn")
$RefreshEventsBtn = $window.FindName("RefreshEventsBtn")
$EventsOutput = $window.FindName("EventsOutput")
$CreateGP0Btn = $window.FindName("CreateGP0Btn")
$LinkGP0Btn = $window.FindName("LinkGP0Btn")
$DeploymentStatus = $window.FindName("DeploymentStatus")
$GenerateEvidenceBtn = $window.FindName("GenerateEvidenceBtn")
$ComplianceOutput = $window.FindName("ComplianceOutput")
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
        "Logs"
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
   • Creates AppLocker OU and groups
   • Auto-populates Domain Admins to AppLocker-Admin
   • Generates starter policy in audit mode

2. Group Management - Configure AD groups
   • Export current group membership
   • Edit CSV to add/remove members
   • Import changes (dry-run first, then apply)

3. AD Discovery - Find target computers
   • Discover computers by OU
   • Test connectivity
   • Select hosts for scanning

Phase 2: SCANNING
4. Artifacts - Collect executable inventory
   • Scan local or remote computers
   • Collect publisher, hash, path info
   • Export to CSV for review

5. Rule Generator - Create AppLocker rules
   • Import artifacts from scan
   • Generate Publisher rules (preferred)
   • Generate Hash rules (fallback)
   • Export rules for GPO deployment

Phase 3: DEPLOYMENT
6. Deployment - Deploy policies via GPO
   • Create GPO with AppLocker policy
   • Link to target OUs
   • Start in Audit mode
   • Monitor for 7-14 days

7. WinRM Setup - Enable remote management
   • Create WinRM GPO
   • Configure firewall rules
   • Test remote connectivity

Phase 4: MONITORING
8. Events - Monitor AppLocker events
   • Filter by Allowed/Blocked/Audit
   • Review false positives
   • Export events for analysis

9. Compliance - Generate evidence packages
   • Collect policies and events
   • Create audit artifacts
   • Document compliance status

BEST PRACTICES:
• Always start in Audit mode
• Use Publisher rules first
• Use Hash rules only for unsigned files
• Avoid Path rules except for exceptions
• Create deny rules for user-writable paths
• Test in pilot group before full deployment
• Maintain break-glass admin access
"@
        }
        "Rules" {
            return @"
=== APPLOCKER RULE BEST PRACTICES ===

RULE TYPE PRIORITY (Highest to Lowest):
1. Publisher Rules (Preferred)
   • Most resilient to updates
   • Covers all versions from publisher
   • Example: Microsoft Corporation, Adobe Inc.

2. Hash Rules (Fallback for unsigned)
   • Most specific but fragile
   • Changes with each file update
   • Use only for unsigned executables
   • Example: SHA256 hash

3. Path Rules (Exceptions only)
   • Too permissive, easily bypassed
   • Use only for:
     - Denying specific user-writable paths
     - Allowing specific admin tools
   • Example: %OSDRIVE%\Users\*\Downloads\*\*

SECURITY PRINCIPLES:
• DENY-FIRST MODEL
  - Default deny all executables
  - Explicitly allow only approved software
  - Deny user-writable locations

• LEAST PRIVILEGE
  - Different rules for different user groups
  - AppLocker-Admin: Full allow
  - AppLocker-StandardUsers: Restricted
  - AppLocker-Dev: Development tools

• AUDIT BEFORE ENFORCE
  - Deploy in Audit mode first
  - Monitor for 7-14 days
  - Review and address false positives
  - Switch to Enforce only after validation

RULE COLLECTIONS TO CONFIGURE:
• Executable (.exe, .com)
• Script (.ps1, .bat, .cmd, .vbs)
• Windows Installer (.msi, .msp)
• DLL (optional - advanced)
• Packaged Apps/MSIX (Windows 10+)

COMMON PITFALLS TO AVOID:
• Using wildcards in path rules
• Forgetting to update hash rules after updates
• Not testing with actual user accounts
• Skipping the audit phase
• Forgetting service accounts
• Not documenting exceptions

GROUP STRATEGY:
• AppLocker-Admin - Full system access
• AppLocker-Installers - Software installation rights
• AppLocker-StandardUsers - Restricted workstation users
• AppLocker-Dev - Developer tools access
• AppLocker-Deny-* - Explicit deny for risky paths

ADMIN SECURITY:
• Consider denying browsers for admin accounts
• Admins should use separate workstations
• Break-glass access for emergency situations
• Document all exceptions and justifications
"@
        }
        "Troubleshooting" {
            return @"
=== APPLOCKER TROUBLESHOOTING ===

ISSUE: Events not appearing in Event Monitor
SOLUTIONS:
• Verify AppLocker ID 8001 (Policy Applied) appears first
• Check Application Identity service is running
• Verify policy is actually enforced (gpresult /r)
• Restart Application Identity service if needed

ISSUE: All executables being blocked
SOLUTIONS:
• Check if policy is in Enforce mode (should start as Audit)
• Verify rule collection is enabled
• Check for conflicting deny rules
• Review event logs for specific blocked files

ISSUE: False positives - legitimate apps blocked
SOLUTIONS:
• Add specific Publisher rule for the application
• Check if app needs to run from user-writable location
• Consider creating exception path rule
• Review hash rule if app version changed

ISSUE: Policy not applying to computers
SOLUTIONS:
• Run: gpresult /r /scope computer
• Check GPO is linked to correct OU
• Verify GPO security filtering
• Force GP update: gpupdate /force
• Check DNS resolution for domain controllers

ISSUE: Cannot create GPO (access denied)
SOLUTIONS:
• Must be Domain Admin or have GPO creation rights
• Check Group Policy Management console permissions
• Verify RSAT is installed if running from workstation
• Run PowerShell as Administrator

ISSUE: WinRM connection failures
SOLUTIONS:
• Verify WinRM GPO has applied (gpupdate /force)
• Check firewall allows port 5985/5986
• Test with: Test-WsMan -ComputerName <target>
• Ensure target computer has WinRM enabled

ISSUE: Rule generation errors
SOLUTIONS:
• Verify artifact scan completed successfully
• Check CSV format is correct (UTF-8 encoding)
• Ensure Publisher info exists in file version
• Use Hash rules for unsigned executables

ISSUE: Group import fails
SOLUTIONS:
• Verify CSV format: GroupName,Members (semicolon-separated)
• Check member accounts exist in AD
• Ensure you have rights to modify group membership
• Use dry-run first to preview changes

ISSUE: High CPU/memory during scan
SOLUTIONS:
• Reduce MaxFiles setting
• Scan specific directories instead of full drives
• Run during off-peak hours
• Use AD discovery to target specific computers

USEFUL PowerShell COMMANDS:
• Get-AppLockerPolicy -Effective
• Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'
• Test-AppLockerPolicy
• Set-AppLockerPolicy
• gpupdate /force
• gpresult /r /scope computer

LOG LOCATIONS:
• AppLocker Events: Event Viewer -> Applications and Services -> Microsoft -> Windows -> AppLocker
• Group Policy: Event Viewer -> Windows Logs -> System
• Application ID: Services.msc -> Application Identity
• Application Logs: C:\GA-AppLocker\Logs\

ESCALATION PATH:
1. Review this help documentation
2. Check Application Logs in C:\GA-AppLocker\Logs\
3. Consult internal security team
4. Review Microsoft AppLocker documentation
5. Contact GA-ASI security team for advanced issues
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
        "Rules" { $PanelRules.Visibility = [System.Windows.Visibility]::Visible }
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

# Artifacts events
$ExportArtifactsBtn.Add_Click({
    if ($script:CollectedArtifacts.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No artifacts to export. Run a scan first.", "No Data", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json"
    $saveDialog.Title = "Export Artifacts"
    $saveDialog.FileName = "Artifacts-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName)
        if ($ext -eq ".csv") {
            $script:CollectedArtifacts | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        } else {
            $script:CollectedArtifacts | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Exported $($script:CollectedArtifacts.Count) artifacts to $($saveDialog.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:CollectedArtifacts.Count) artifacts to $($saveDialog.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
})

$ScanLocalBtn.Add_Click({
    Write-Log "Starting localhost scan with max files: $($MaxFilesText.Text)"
    $ArtifactsList.Items.Clear()
    $RulesOutput.Text = "Scanning localhost for executables...`n`nThis may take a few minutes..."
    [System.Windows.Forms.Application]::DoEvents()

    $max = [int]$MaxFilesText.Text
    $result = Get-LocalExecutableArtifacts -MaxFiles $max
    $script:CollectedArtifacts = $result.artifacts

    foreach ($art in $result.artifacts) {
        $ArtifactsList.Items.Add("$($art.name) | $($art.publisher)")
    }

    $RulesOutput.Text = "Scan complete! Found $($result.count) artifacts.`n`nNow go to Rule Generator to create AppLocker rules."
    Write-Log "Localhost scan complete: $($result.count) artifacts found"
})

# Comprehensive Scan (AaronLocker-style)
$ComprehensiveScanBtn.Add_Click({
    Write-Log "Starting comprehensive AaronLocker-style scan"
    $ArtifactsList.Items.Clear()

    # Ask for output folder
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select output folder for scan artifacts"
    $folderDialog.SelectedPath = "C:\GA-AppLocker\Scans"

    if ($folderDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    $outputPath = $folderDialog.SelectedPath
    $max = [int]$MaxFilesText.Text

    $ArtifactsList.Items.Add("Starting comprehensive scan...")
    $ArtifactsList.Items.Add("Output: $outputPath")
    $ArtifactsList.Items.Add("Max Executables: $max")
    $ArtifactsList.Items.Add("")
    [System.Windows.Forms.Application]::DoEvents()

    $result = Start-ComprehensiveScan -OutputPath $outputPath -MaxExecutables $max

    $ArtifactsList.Items.Clear()
    if ($result.success) {
        $ArtifactsList.Items.Add("=== COMPREHENSIVE SCAN COMPLETE ===")
        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("Output Folder: $($result.scanFolder)")
        $ArtifactsList.Items.Add("Computer: $($result.computerName)")
        $ArtifactsList.Items.Add("Duration: $($result.duration) seconds")
        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("=== ARTIFACTS CREATED ===")
        foreach ($key in $result.files.Keys) {
            $ArtifactsList.Items.Add("  $key.csv")
        }
        $ArtifactsList.Items.Add("")
        $ArtifactsList.Items.Add("=== COUNTS ===")
        $ArtifactsList.Items.Add("  Executables: $($result.stats.Executables)")
        $ArtifactsList.Items.Add("  Publishers: $($result.stats.Publishers)")
        $ArtifactsList.Items.Add("  Installed Software: $($result.stats.InstalledSoftware)")
        $ArtifactsList.Items.Add("  Running Processes: $($result.stats.RunningProcesses)")
        $ArtifactsList.Items.Add("  Writable Directories: $($result.stats.WritableDirectories)")

        $fileList = ($result.files.Keys | ForEach-Object { "$_.csv" }) -join "`n"
        [System.Windows.MessageBox]::Show("Comprehensive scan complete!`n`nArtifacts saved to:`n$($result.scanFolder)`n`nFiles created:`n$fileList", "Scan Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $ArtifactsList.Items.Add("ERROR: $($result.error)")
        [System.Windows.MessageBox]::Show("Scan failed: $($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }

    Write-Log "Comprehensive scan complete"
})

# Rules events
$ImportArtifactsBtn.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $openDialog.Title = "Import Scan Artifacts"
    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $ext = [System.IO.Path]::GetExtension($openDialog.FileName)
        if ($ext -eq ".csv") {
            $script:CollectedArtifacts = Import-Csv -Path $openDialog.FileName
        } else {
            $script:CollectedArtifacts = Get-Content -Path $openDialog.FileName | ConvertFrom-Json
        }
        $RulesOutput.Text = "Imported $($script:CollectedArtifacts.Count) artifacts. Select rule type and click Generate Rules."
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
            $RulesOutput.Text = "Imported $($allArtifacts.Count) artifacts from $($importedFiles.Count) files:`n`n$($importedFiles -join "`n")`n`nSelect rule type and click Generate Rules."
            [System.Windows.MessageBox]::Show("Imported $($allArtifacts.Count) artifacts from $($importedFiles.Count) CSV files.", "Import Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            [System.Windows.MessageBox]::Show("No valid artifact data found in CSV files.", "Import Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        }
    }
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
        "S-1-1-0" { return "S-1-1-0" }
        "S-1-5-32-544" { return "S-1-5-32-544" }
        "S-1-5-32-545" { return "S-1-5-32-545" }
        "DomainUsers" {
            try {
                $domainSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
                return "$domainSid-513"
            } catch {
                return "S-1-1-0"
            }
        }
        "DomainAdmins" {
            try {
                $domainSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
                return "$domainSid-512"
            } catch {
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
        $RulesOutput.Text = "ERROR: No artifacts imported. Use Import CSV, Import Folder, or From Events first."
        return
    }

    $ruleType = if ($RuleTypePublisher.IsChecked) { "Publisher" }
                elseif ($RuleTypeHash.IsChecked) { "Hash" }
                else { "Path" }

    $action = if ($RuleActionAllow.IsChecked) { "Allow" } else { "Deny" }
    $sid = Get-SelectedSid

    $selectedGroup = $RuleGroupCombo.SelectedItem.Content
    $RulesOutput.Text = "Generating $action $ruleType rules for $selectedGroup...`nProcessing $($script:CollectedArtifacts.Count) artifacts..."

    $result = New-RulesFromArtifacts -Artifacts $script:CollectedArtifacts -RuleType $ruleType -Action $action -UserOrGroupSid $sid

    $script:GeneratedRules = $result.rules

    $output = "=== GENERATED $($result.count) $ruleType RULES ===`n"
    $output += "Action: $action | Applied To: $selectedGroup`n"
    $output += "SID: $sid`n`n"

    foreach ($rule in $result.rules) {
        $output += "[$($rule.type)] $($rule.publisher)`n"
    }

    $output += "`n--- Use 'Export Rules' in Deployment to save ---"
    $RulesOutput.Text = $output
    Write-Log "Generated $($result.count) $ruleType rules with Action=$action, SID=$sid"
})

# Create Rules from Events button
$CreateRulesFromEventsBtn.Add_Click({
    if ($script:AllEvents.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No events loaded. Go to Event Monitor and scan for events first.", "No Events", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $RulesOutput.Text = "Creating artifacts from $($script:AllEvents.Count) events..."

    # Convert events to artifacts format
    $eventArtifacts = @()
    foreach ($event in $script:AllEvents) {
        # Parse event message to extract file info
        $artifact = @{
            FileName = $event.FileName
            FullPath = $event.FilePath
            Publisher = $event.Publisher
            EventType = $event.EventType
            Computer = $event.ComputerName
        }
        if ($artifact.FileName -or $artifact.FullPath) {
            $eventArtifacts += [PSCustomObject]$artifact
        }
    }

    if ($eventArtifacts.Count -eq 0) {
        $RulesOutput.Text = "ERROR: Could not extract file information from events."
        return
    }

    # Add to collected artifacts
    $script:CollectedArtifacts = $eventArtifacts

    $RulesOutput.Text = "Loaded $($eventArtifacts.Count) artifacts from events.`n`nReady to generate rules - click 'Generate Rules'"
    [System.Windows.MessageBox]::Show("Loaded $($eventArtifacts.Count) artifacts from Event Viewer.`n`nSelect rule type, action, and group, then click Generate Rules.", "Events Loaded", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})

# Events events
$FilterAllBtn.Add_Click({
    $script:EventFilter = "All"
    Write-Log "Event filter set to: All"
    $EventsOutput.Text = "Filter set to All. Click Refresh to load events."
})

$FilterAllowedBtn.Add_Click({
    $script:EventFilter = "Allowed"
    Write-Log "Event filter set to: Allowed"
    $EventsOutput.Text = "Filter set to Allowed (ID 8002). Click Refresh to load events."
})

$FilterBlockedBtn.Add_Click({
    $script:EventFilter = "Blocked"
    Write-Log "Event filter set to: Blocked"
    $EventsOutput.Text = "Filter set to Blocked (ID 8004). Click Refresh to load events."
})

$FilterAuditBtn.Add_Click({
    $script:EventFilter = "Audit"
    Write-Log "Event filter set to: Audit"
    $EventsOutput.Text = "Filter set to Audit (ID 8003). Click Refresh to load events."
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
                $events += [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    TimeCreated = $evt.TimeCreated
                    EventId = $evt.Id
                    EventType = switch ($evt.Id) { 8002 { "Allowed" } 8003 { "Audit" } 8004 { "Blocked" } default { "Other" } }
                    Message = $evt.Message
                    FilePath = if ($evt.Message -match '([A-Z]:\\[^"]+\.(exe|dll))') { $Matches[1] } else { "" }
                    FileName = if ($evt.Message -match '\\([^\\]+\.(exe|dll))') { $Matches[1] } else { "" }
                    Publisher = if ($evt.Message -match 'was (allowed|blocked).*signed by ([^\.]+)') { $Matches[2] } else { "Unknown" }
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
                $events += [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    TimeCreated = $evt.TimeCreated
                    EventId = $evt.Id
                    EventType = switch ($evt.Id) { 8002 { "Allowed" } 8003 { "Audit" } 8004 { "Blocked" } default { "Other" } }
                    Message = $evt.Message
                    FilePath = if ($evt.Message -match '([A-Z]:\\[^"]+\.(msi|ps1|vbs|js))') { $Matches[1] } else { "" }
                    FileName = if ($evt.Message -match '\\([^\\]+\.(msi|ps1|vbs|js))') { $Matches[1] } else { "" }
                    Publisher = "Unknown"
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
        $EventsOutput.Text += "Use filters above to view specific event types.`nClick 'From Events' in Rule Generator to create rules."

        Write-Log "Local events scanned: $($events.Count) total"
    } catch {
        $EventsOutput.Text += "`nERROR: $($_.Exception.Message)"
        Write-Log "Local event scan failed: $($_.Exception.Message)" -Level "ERROR"
    }
})

# Scan Remote Events button
$ScanRemoteEventsBtn.Add_Click({
    Write-Log "Scanning remote AppLocker events"
    $computerInput = $EventComputersText.Text.Trim()

    if ($computerInput -match "^\(|comma-separated") {
        [System.Windows.MessageBox]::Show("Please enter computer names or use 'Load from Discovery' first.", "No Computers", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $computers = $computerInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    if ($computers.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No computers specified.", "No Computers", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $EventsOutput.Text = "=== SCANNING REMOTE EVENTS ===`n`nScanning $($computers.Count) computers via WinRM...`n"
    [System.Windows.Forms.Application]::DoEvents()

    $allEvents = @()

    foreach ($comp in $computers) {
        $EventsOutput.Text += "`n$comp : "
        [System.Windows.Forms.Application]::DoEvents()

        try {
            $remoteEvents = Invoke-Command -ComputerName $comp -ScriptBlock {
                $events = @()
                try {
                    $exeEvents = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 100 -ErrorAction SilentlyContinue
                    foreach ($evt in $exeEvents) {
                        $events += [PSCustomObject]@{
                            TimeCreated = $evt.TimeCreated
                            EventId = $evt.Id
                            Message = $evt.Message
                        }
                    }
                } catch {}
                return $events
            } -ErrorAction Stop

            foreach ($evt in $remoteEvents) {
                $allEvents += [PSCustomObject]@{
                    ComputerName = $comp
                    TimeCreated = $evt.TimeCreated
                    EventId = $evt.EventId
                    EventType = switch ($evt.EventId) { 8002 { "Allowed" } 8003 { "Audit" } 8004 { "Blocked" } default { "Other" } }
                    Message = $evt.Message
                    FilePath = if ($evt.Message -match '([A-Z]:\\[^"]+\.(exe|dll))') { $Matches[1] } else { "" }
                    FileName = if ($evt.Message -match '\\([^\\]+\.(exe|dll))') { $Matches[1] } else { "" }
                    Publisher = "Unknown"
                }
            }
            $EventsOutput.Text += "$($remoteEvents.Count) events"
            Write-Log "Remote events from $comp : $($remoteEvents.Count)"
        } catch {
            $EventsOutput.Text += "FAILED ($($_.Exception.Message -replace '\r?\n.*$',''))"
            Write-Log "Remote event scan failed on $comp : $($_.Exception.Message)" -Level "ERROR"
        }
    }

    $script:AllEvents = $allEvents
    $EventsOutput.Text += "`n`n--- TOTAL: $($allEvents.Count) events from $($computers.Count) computers ---"
    $EventsOutput.Text += "`n`nClick 'From Events' in Rule Generator to create rules."
})

# Import Events button
$ImportEventsBtn.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openDialog.Title = "Import Events"
    $openDialog.InitialDirectory = "C:\GA-AppLocker\Events"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $imported = Import-Csv -Path $openDialog.FileName
            $script:AllEvents = $imported
            $EventsOutput.Text = "=== EVENTS IMPORTED ===`n`nLoaded $($imported.Count) events from:`n$($openDialog.FileName)`n`n"
            $EventsOutput.Text += "Use filters above to view specific event types.`nClick 'From Events' in Rule Generator to create rules."
            Write-Log "Imported $($imported.Count) events from $($openDialog.FileName)"
        } catch {
            $EventsOutput.Text = "ERROR importing events: $($_.Exception.Message)"
            Write-Log "Event import failed: $($_.Exception.Message)" -Level "ERROR"
        }
    }
})

# Load from Discovery button
$LoadFromDiscoveryBtn.Add_Click({
    if ($script:DiscoveredComputers.Count -gt 0) {
        $EventComputersText.Text = $script:DiscoveredComputers -join ", "
        $EventsOutput.Text = "Loaded $($script:DiscoveredComputers.Count) computers from AD Discovery:`n$($script:DiscoveredComputers -join ', ')`n`nClick 'Scan Remote' to get events."
        Write-Log "Loaded $($script:DiscoveredComputers.Count) computers from discovery"
    } elseif ($DiscoveredComputersList -and $DiscoveredComputersList.SelectedItems.Count -gt 0) {
        $computers = @()
        foreach ($item in $DiscoveredComputersList.SelectedItems) {
            $compName = ($item -split '\|')[0].Trim()
            $computers += $compName
        }
        $EventComputersText.Text = $computers -join ", "
        $EventsOutput.Text = "Loaded $($computers.Count) selected computers from AD Discovery.`n`nClick 'Scan Remote' to get events."
        Write-Log "Loaded $($computers.Count) computers from discovery selection"
    } else {
        [System.Windows.MessageBox]::Show("No computers available. Go to AD Discovery first and discover computers.", "No Computers", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
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
    $result = New-EvidenceFolder
    if ($result.success) {
        $ComplianceOutput.Text = "Evidence package created at:`n$($result.basePath)`n`nSub-folders:`n"
        foreach ($folder in $result.folders.GetEnumerator()) {
            $ComplianceOutput.Text += "  - $($folder.Key): $($folder.Value)`n"
        }
        Write-Log "Evidence package created at: $($result.basePath)"
    } else {
        $ComplianceOutput.Text = "ERROR: $($result.error)"
        Write-Log "Failed to create evidence package: $($result.error)" -Level "ERROR"
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
            $DeploymentStatus.Text = "GPO '$($result.gpoName)' already exists.`n`nUse 'Link GPO to Domain' to link it to additional OUs."
            [System.Windows.MessageBox]::Show("GPO '$($result.gpoName)' already exists.`n`nUse 'Link GPO to Domain' to link it to additional OUs.", "GPO Exists", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
        Write-Log "AppLocker GPO created/found: $($result.gpoName)"
    } else {
        $DeploymentStatus.Text = "ERROR: Failed to create GPO`n`n$($result.error)`n`nMake sure you are running as Domain Admin with Group Policy module installed."
        [System.Windows.MessageBox]::Show("Failed to create AppLocker GPO:`n$($result.error)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Failed to create AppLocker GPO: $($result.error)" -Level "ERROR"
    }
})

$LinkGP0Btn.Add_Click({
    Write-Log "Link GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO linking requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        # Get domain root
        $domain = ActiveDirectory\Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName

        # Check if AppLocker GPO exists
        $gpo = Get-GPO -Name "AppLocker Policy" -ErrorAction SilentlyContinue
        if (-not $gpo) {
            [System.Windows.MessageBox]::Show("AppLocker GPO not found. Please create it first using 'Create GPO'.", "GPO Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            $DeploymentStatus.Text = "ERROR: AppLocker GPO not found.`n`nPlease create it first using the 'Create GPO' button."
            return
        }

        # Link to domain root
        $existingLink = Get-GPInheritance -Target $domainDN | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq "AppLocker Policy" }
        if ($existingLink) {
            $DeploymentStatus.Text = "GPO 'AppLocker Policy' is already linked to the domain root.`n`nLinked to: $domainDN"
            [System.Windows.MessageBox]::Show("GPO is already linked to the domain root.", "Already Linked", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            New-GPLink -Name "AppLocker Policy" -Target $domainDN -LinkEnabled Yes -ErrorAction Stop
            $DeploymentStatus.Text = "SUCCESS: GPO linked to domain!`n`nGPO: AppLocker Policy`nLinked to: $domainDN`n`nThe policy will apply during the next Group Policy refresh."
            [System.Windows.MessageBox]::Show("GPO linked to domain successfully!`n`nLinked to: $domainDN", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
        Write-Log "GPO linking complete: AppLocker Policy -> $domainDN"
    }
    catch {
        $DeploymentStatus.Text = "ERROR: Failed to link GPO`n`n$($_.Exception.Message)"
        [System.Windows.MessageBox]::Show("Failed to link GPO:`n$($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Write-Log "Failed to link GPO: $($_.Exception.Message)" -Level "ERROR"
    }
})

# WinRM events
$CreateWinRMGpoBtn.Add_Click({
    Write-Log "Create WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $WinRMOutput.Text = "=== WINRM GPO CREATION ===`n`nCreating WinRM GPO...`n`nThis will:`n  • Create 'Enable WinRM' GPO`n  • Link to domain root`n  • Configure WinRM service settings`n  • Enable firewall rules`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $action = if ($result.isNew) { "CREATED" } else { "UPDATED" }
        $WinRMOutput.Text = "=== WINRM GPO $action ===`n`nSUCCESS: GPO $($result.message)`n`nGPO Name: $($result.gpoName)`nGPO ID: $($result.gpoId)`nLinked to: $($result.linkedTo)`n`nConfigured Settings:`n`nWinRM Service:`n  • Auto-config: Enabled`n  • IPv4 Filter: * (all)`n  • IPv6 Filter: * (all)`n  • Basic Auth: Enabled`n  • Unencrypted Traffic: Disabled`n`nWinRM Client:`n  • Basic Auth: Enabled`n  • TrustedHosts: * (all)`n  • Unencrypted Traffic: Disabled`n`nFirewall Rules:`n  • WinRM HTTP (5985): Allowed`n  • WinRM HTTPS (5986): Allowed`n`nService: Automatic startup`n`nTo force immediate update: gpupdate /force"
        Write-Log "WinRM GPO $action successfully: $($result.gpoName)"
        [System.Windows.MessageBox]::Show("WinRM GPO $action successfully!`n`nGPO: $($result.gpoName)`n`nLinked to: $($result.linkedTo)", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    } else {
        $WinRMOutput.Text = "=== WINRM GPO FAILED ===`n`nERROR: $($result.error)`n`nPossible causes:`n  • Not running as Domain Admin`n  • Group Policy module not available`n  • Insufficient permissions`n`nPlease run as Domain Administrator and try again."
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
        "This will run 'gpupdate /force' on all domain computers.`n`nThis requires:`n  • WinRM already enabled on target machines`n  • Administrative access to remote computers`n`nContinue?",
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

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $saveDialog.Title = "Export AppLocker Rules"
    $saveDialog.FileName = "AppLocker-Rules_$(Get-Date -Format 'yyyy-MM-dd').xml"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        # Generate AppLocker XML from rules
        $xmlContent = Convert-RulesToAppLockerXml -Rules $script:GeneratedRules
        $xmlContent | Out-File -FilePath $saveDialog.FileName -Encoding UTF8 -Force
        [System.Windows.MessageBox]::Show("Rules exported to: $($saveDialog.FileName)`n`nYou can now import this XML into a GPO using Group Policy Management.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Write-Log "Rules exported: $($saveDialog.FileName)"
    }
})

$ImportRulesBtn.Add_Click({
    Write-Log "Import rules button clicked"

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog.Title = "Import AppLocker Rules"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $DeploymentStatus.Text = "Importing rules from: $($openDialog.FileName)`n`nNote: Use Group Policy Management console to import XML into GPO.`n`n1. Open GPO`n2. Go to: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker`n3. Right-click -> Import Policy`n`nThis feature prepares the XML for manual import."
        Write-Log "Rules imported for GPO deployment: $($openDialog.FileName)"
        [System.Windows.MessageBox]::Show("Rules loaded!`n`nTo apply to a GPO:`n1. Open Group Policy Management`n2. Edit target GPO`n3. Navigate to: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker`n4. Right-click -> Import Policy`n5. Select the exported XML file", "Import Ready", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
})

# Other events
function Update-StatusBar {
    if ($script:IsWorkgroup) {
        $StatusText.Text = "WORKGROUP MODE - Local scanning available"
    } elseif (-not $script:HasRSAT) {
        $StatusText.Text = "$($script:DomainInfo.dnsRoot) - RSAT required for GPO features"
    } else {
        $StatusText.Text = "$($script:DomainInfo.dnsRoot) - Full features available"
    }
}

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
        $LinkGP0Btn.IsEnabled = $false
        $CreateWinRMGpoBtn.IsEnabled = $false
                $ForceGPUpdateBtn.IsEnabled = $false
        $ExportGroupsBtn.IsEnabled = $false
        $ImportGroupsBtn.IsEnabled = $false
        $BootstrapAppLockerBtn.IsEnabled = $false
        $RemoveOUProtectionBtn.IsEnabled = $false

        Write-Log "Workgroup mode: AD/GPO buttons disabled"
    } elseif (-not $script:HasRSAT) {
        # Domain-joined but no RSAT - limited features
        $EnvironmentText.Text = "DOMAIN: $($script:DomainInfo.dnsRoot) | RSAT not installed - Install RSAT for GPO features"
        $EnvironmentBanner.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#D29922")
        $EnvironmentText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#000000")

        # Disable GPO-related buttons (need RSAT)
        $CreateGP0Btn.IsEnabled = $false
        $LinkGP0Btn.IsEnabled = $false
        $CreateWinRMGpoBtn.IsEnabled = $false
                $ForceGPUpdateBtn.IsEnabled = $false
        $ExportGroupsBtn.IsEnabled = $false
        $ImportGroupsBtn.IsEnabled = $false
        $BootstrapAppLockerBtn.IsEnabled = $false
        $RemoveOUProtectionBtn.IsEnabled = $false

        Write-Log "Domain mode without RSAT: GPO features disabled - install RSAT tools"
    } else {
        # Domain with RSAT - full features
        $EnvironmentText.Text = "DOMAIN: $($script:DomainInfo.dnsRoot) | Full features available"
        $EnvironmentBanner.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#238636")
        $EnvironmentText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFFFFF")

        # Enable all buttons
        $CreateGP0Btn.IsEnabled = $true
        $LinkGP0Btn.IsEnabled = $true
        $CreateWinRMGpoBtn.IsEnabled = $true

        Write-Log "Domain mode with RSAT: All features enabled"
    }

    # Load icons (non-blocking)
    try {
        $scriptPath = Split-Path -Parent $PSCommandPath
        $iconPath = Join-Path $scriptPath "GA-AppLocker.ico"
        if (Test-Path $iconPath) {
            $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create((New-Object System.Uri $iconPath))
        }
    } catch { }

    try {
        $scriptPath = Split-Path -Parent $PSCommandPath
        $logoPath = Join-Path $scriptPath "GA-AppLocker.png"
        if (Test-Path $logoPath) {
            $aboutBitmap = [System.Windows.Media.Imaging.BitmapImage]::new()
            $aboutBitmap.BeginInit()
            $aboutBitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
            $aboutBitmap.UriSource = (New-Object System.Uri $logoPath)
            $aboutBitmap.EndInit()
            $aboutBitmap.Freeze()
            $AboutLogo.Source = $aboutBitmap
        }
    } catch { }

    # Refresh dashboard data
    Refresh-Data
    Update-StatusBar

    # Set final message
    $DashboardOutput.Text = "=== GA-APPLOCKER DASHBOARD ===`n`nAaronLocker-aligned AppLocker Policy Management`n`nEnvironment: $($script:DomainInfo.message)`n`nReady to begin. Select a tab to start."
})

# Show window
$window.ShowDialog() | Out-Null
