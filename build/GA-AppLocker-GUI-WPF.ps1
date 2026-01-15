# GA-AppLocker Dashboard - Modern WPF GUI
# GitHub-style dark theme based on ExampleGUI design
# Self-contained with embedded module functions

# Required assemblies for WPF
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
} catch {
    Write-Host "ERROR: Failed to load WPF assemblies. This application requires .NET Framework 4.5 or later." -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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

# Module 3: Rule Generator Functions
function New-PublisherRule {
    param([string]$PublisherName, [string]$ProductName = "*", [string]$BinaryName = "*", [string]$Version = "*")
    if (-not $PublisherName) { return @{ success = $false; error = "Publisher name is required" } }
    $guid = "{" + (New-Guid).ToString() + "}"
    $xml = "<FilePublisherRule Id=`"$guid`" Name=`"$PublisherName`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FilePublisherCondition PublisherName=`"$PublisherName`" ProductName=`"$ProductName`" BinaryName=`"$BinaryName`"><BinaryVersionRange LowSection=`"$Version`" HighSection=`"*`" /></FilePublisherCondition></Conditions></FilePublisherRule>"
    return @{ success = $true; id = $guid; type = "Publisher"; publisher = $PublisherName; xml = $xml }
}

function New-HashRule {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return @{ success = $false; error = "File not found" } }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    $fileName = (Get-Item $FilePath).Name
    $guid = "{" + (New-Guid).ToString() + "}"
    $xml = "<FileHashRule Id=`"$guid`" Name=`"$fileName`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FileHashCondition SourceFileName=`"$fileName`" SourceFileHash=`"$hash`" Type=`"SHA256`" /></Conditions></FileHashRule>"
    return @{ success = $true; id = $guid; type = "Hash"; hash = $hash; fileName = $fileName; xml = $xml }
}

function New-RulesFromArtifacts {
    param([array]$Artifacts, [string]$RuleType = "Publisher")
    if (-not $Artifacts -or $Artifacts.Count -eq 0) { return @{ success = $false; error = "No artifacts provided" } }
    $rules = @()
    $publishers = @{}
    foreach ($artifact in $Artifacts) {
        if ($RuleType -eq "Publisher" -and $artifact.publisher) {
            if (-not $publishers.ContainsKey($artifact.publisher)) {
                $publishers[$artifact.publisher] = $true
                $rule = New-PublisherRule -PublisherName $artifact.publisher
                if ($rule.success) { $rules += $rule }
            }
        }
    }
    return @{ success = $true; rules = $rules; count = $rules.Count; ruleType = $RuleType }
}

# Module 4: Domain Detection
function Get-ADDomain {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isWorkgroup = $computerSystem -and ($computerSystem.Workgroup -eq "WORKGROUP" -or $null -eq $computerSystem.PartOfDomain)
    if ($isWorkgroup) {
        return @{ success = $true; isWorkgroup = $true; dnsRoot = "WORKGROUP"; netBIOSName = $computerSystem.Name; message = "WORKGROUP - AD/GPO disabled" }
    }
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $domain = Get-ADDomain -ErrorAction Stop
        return @{ success = $true; isWorkgroup = $false; dnsRoot = $domain.DNSRoot; netBIOSName = $domain.NetBIOSName; message = "Domain: $($domain.DNSRoot)" }
    } catch {
        $dnsDomain = $env:USERDNSDOMAIN
        if ([string]::IsNullOrEmpty($dnsDomain)) {
            return @{ success = $true; isWorkgroup = $true; dnsRoot = "WORKGROUP"; netBIOSName = $env:COMPUTERNAME; message = "WORKGROUP - AD/GPO disabled" }
        }
        return @{ success = $true; isWorkgroup = $false; dnsRoot = $dnsDomain; netBIOSName = $env:USERDOMAIN; message = "Domain detected" }
    }
}

# Module 5: Event Monitor
function Get-AppLockerEvents {
    param([int]$MaxEvents = 100)
    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop
        $data = $events | ForEach-Object { @{
            eventId = $_.Id; time = $_.TimeCreated; message = $_.Message -replace "`n", " " -replace "`r", ""
        } }
        return @{ success = $true; data = $data; count = $data.Count }
    } catch {
        return @{ success = $true; data = @(); count = 0; message = "No events found" }
    }
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

# Module 7: WinRM GPO Functions
function New-WinRMGpo {
    param(
        [string]$GpoName = "Enable WinRM",
        [string]$OU = $null
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop

        # Detect current domain if OU not specified
        if (-not $OU) {
            $domain = Get-ADDomain
            $OU = "DC=$($domain.DNSRoot -replace '\.', ',DC=')"
        }

        Write-Log "Creating WinRM GPO: $GpoName"

        # 1. Create and link the GPO
        $gpo = New-GPO -Name $GpoName -ErrorAction Stop
        Write-Log "GPO created: $($gpo.Id)"

        $link = New-GPLink -Name $GpoName -Target $OU -LinkEnabled Yes -ErrorAction Stop
        Write-Log "GPO linked to: $OU"

        # 2. Enable WinRM service via policy (XML-backed registry policy)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Type DWord -Value 1 -ErrorAction Stop
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0 -ErrorAction Stop
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv4Filter" -Type String -Value "*" -ErrorAction Stop
        Write-Log "WinRM service policies configured"

        # 3. Ensure WinRM service starts automatically
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "Start" -Type DWord -Value 2 -ErrorAction Stop
        Write-Log "WinRM service startup type set to Automatic"

        # 4. Enable Windows Firewall rules for WinRM
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\WinRM" -ValueName "Enabled" -Type DWord -Value 1 -ErrorAction Stop
        Write-Log "WinRM firewall rules configured"

        return @{
            success = $true
            gpoName = $GpoName
            gpoId = $gpo.Id
            linkedTo = $OU
            message = "WinRM GPO created and linked successfully"
        }
    }
    catch {
        Write-Log "Failed to create WinRM GPO: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
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
function Initialize-AppLockerStructure {
    param(
        [string]$OUName = "AppLocker",
        [bool]$AutoPopulateAdmins = $true,
        [string]$DomainFQDN = $null
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

        # Get domain info
        if (-not $DomainFQDN) {
            $DomainFQDN = (Get-ADDomain -ErrorAction Stop).DNSRoot
        }

        $DomainDN = (Get-ADDomain $DomainFQDN -ErrorAction Stop).DistinguishedName
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
            New-ADOrganizationalUnit -Name $OUName -Path $DomainDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop | Out-Null
            $output += "[CREATED] OU: $OUDN`n"
            Write-Log "Created OU: $OUDN"
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
            $domain = Get-ADDomain -ErrorAction Stop
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
        $policyPath = ".\AppLocker-BrowserDeny-Admins.xml"
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
        Title="GA-AppLocker Dashboard" Height="720" Width="1280" MinHeight="600" MinWidth="1000"
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
    </Window.Resources>

    <Grid>
        <!-- Header -->
        <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Height="60" VerticalAlignment="Top">
            <Grid Margin="20,0">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="GA-AppLocker Dashboard" FontSize="18" FontWeight="Bold"
                               Foreground="#E6EDF3" VerticalAlignment="Center"/>
                    <TextBlock Text="v1.0" FontSize="12" Foreground="#6E7681"
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
                            <Expander x:Name="SetupSection" IsExpanded="False" BorderBrush="#30363D" BorderThickness="0,0,0,1" Margin="0,8,0,0">
                                <Expander.Header>
                                    <Grid>
                                        <TextBlock Text="SETUP" FontSize="11" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center"/>
                                    <Path x:Name="SetupSectionArrow" Data="M 0 0 L 4 4 L 8 0" Stroke="#58A6FF" StrokeThickness="1.5" Fill="Transparent" Width="10" Height="6" HorizontalAlignment="Right" RenderTransformOrigin="0.5,0.5">
                                        <Path.RenderTransform>
                                            <RotateTransform Angle="-90"/>
                                        </Path.RenderTransform>
                                    </Path>
                                    </Grid>
                                </Expander.Header>
                                <StackPanel Margin="8,0,0,0">
                                    <Button x:Name="NavAppLockerSetup" Content="AppLocker Setup" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                    <Button x:Name="NavGroupMgmt" Content="Group Management" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                    <Button x:Name="NavDiscovery" Content="AD Discovery" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                </StackPanel>
                            </Expander>

                            <!-- SCANNING Section (Collapsible) -->
                            <Expander x:Name="ScanningSection" IsExpanded="False" BorderBrush="#30363D" BorderThickness="0,0,0,1" Margin="0,8,0,0">
                                <Expander.Header>
                                    <Grid>
                                        <TextBlock Text="SCANNING" FontSize="11" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center"/>
                                        <Path x:Name="ScanningSectionArrow" Data="M 0 0 L 4 4 L 8 0" Stroke="#58A6FF" StrokeThickness="1.5" Fill="Transparent" Width="10" Height="6" HorizontalAlignment="Right" RenderTransformOrigin="0.5,0.5">
                                            <Path.RenderTransform>
                                                <RotateTransform Angle="-90"/>
                                            </Path.RenderTransform>
                                        </Path>
                                    </Grid>
                                </Expander.Header>
                                <StackPanel Margin="8,0,0,0">
                                    <Button x:Name="NavArtifacts" Content="Artifacts" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                    <Button x:Name="NavGapAnalysis" Content="Software Gap Analysis" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                    <Button x:Name="NavRules" Content="Rule Generator" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                </StackPanel>
                            </Expander>

                            <!-- DEPLOYMENT Section (Collapsible) -->
                            <Expander x:Name="DeploymentSection" IsExpanded="False" BorderBrush="#30363D" BorderThickness="0,0,0,1" Margin="0,8,0,0">
                                <Expander.Header>
                                    <Grid>
                                        <TextBlock Text="DEPLOYMENT" FontSize="11" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center"/>
                                        <Path x:Name="DeploymentSectionArrow" Data="M 0 0 L 4 4 L 8 0" Stroke="#58A6FF" StrokeThickness="1.5" Fill="Transparent" Width="10" Height="6" HorizontalAlignment="Right" RenderTransformOrigin="0.5,0.5">
                                            <Path.RenderTransform>
                                                <RotateTransform Angle="-90"/>
                                            </Path.RenderTransform>
                                        </Path>
                                    </Grid>
                                </Expander.Header>
                                <StackPanel Margin="8,0,0,0">
                                    <Button x:Name="NavDeployment" Content="Deployment" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                    <Button x:Name="NavWinRM" Content="WinRM Setup" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                </StackPanel>
                            </Expander>

                            <!-- MONITORING Section (Collapsible) -->
                            <Expander x:Name="MonitoringSection" IsExpanded="False" BorderBrush="#30363D" BorderThickness="0,0,0,1" Margin="0,8,0,0">
                                <Expander.Header>
                                    <Grid>
                                        <TextBlock Text="MONITORING" FontSize="11" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center"/>
                                        <Path x:Name="MonitoringSectionArrow" Data="M 0 0 L 4 4 L 8 0" Stroke="#58A6FF" StrokeThickness="1.5" Fill="Transparent" Width="10" Height="6" HorizontalAlignment="Right" RenderTransformOrigin="0.5,0.5">
                                            <Path.RenderTransform>
                                                <RotateTransform Angle="-90"/>
                                            </Path.RenderTransform>
                                        </Path>
                                    </Grid>
                                </Expander.Header>
                                <StackPanel Margin="8,0,0,0">
                                    <Button x:Name="NavEvents" Content="Events" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                    <Button x:Name="NavCompliance" Content="Compliance" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Stretch" Margin="15,3,10,3"/>
                                </StackPanel>
                            </Expander>
                        </StackPanel>
                    </ScrollViewer>
            </Border>

            <!-- Content Panel -->
            <Grid Grid.Column="1" Margin="20,10,10,10">
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
                        </Grid.ColumnDefinitions>

                        <!-- Policy Health Card -->
                        <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,10,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Policy Health" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="HealthScore" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,10,0,0"/>
                                <TextBlock x:Name="HealthStatus" Text="Loading..." FontSize="11" Foreground="#6E7681"/>
                            </StackPanel>
                        </Border>

                        <!-- Events Card -->
                        <Border Grid.Column="1" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,10,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Total Events" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="TotalEvents" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#58A6FF" Margin="0,10,0,0"/>
                                <TextBlock x:Name="EventsStatus" Text="Loading..." FontSize="11" Foreground="#6E7681"/>
                            </StackPanel>
                        </Border>

                        <!-- Allowed Card -->
                        <Border Grid.Column="2" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,10,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Allowed" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="AllowedEvents" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,10,0,0"/>
                                <TextBlock FontSize="11" Foreground="#6E7681">Event ID 8002</TextBlock>
                            </StackPanel>
                        </Border>

                        <!-- Blocked Card -->
                        <Border Grid.Column="3" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,0,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Blocked" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="BlockedEvents" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#F85149" Margin="0,10,0,0"/>
                                <TextBlock FontSize="11" Foreground="#6E7681">Event ID 8004</TextBlock>
                            </StackPanel>
                        </Border>
                    </Grid>

                    <!-- Refresh Button -->
                    <Button x:Name="RefreshDashboardBtn" Content="Refresh Dashboard"
                            Style="{StaticResource PrimaryButton}" Width="180" HorizontalAlignment="Left"
                            Margin="0,20,0,0"/>

                    <!-- Output Area -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,10,0,0" Padding="15" Height="300">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="DashboardOutput" Text="Loading dashboard..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Artifacts Panel -->
                <StackPanel x:Name="PanelArtifacts" Visibility="Collapsed">
                    <TextBlock Text="Artifact Collection" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="120"/>
                            <ColumnDefinition Width="120"/>
                        </Grid.ColumnDefinitions>

                        <StackPanel Grid.Column="0" Orientation="Horizontal">
                            <TextBlock Text="Max Files:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                            <TextBox x:Name="MaxFilesText" Text="1000" Width="80" Height="32"
                                     Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                     BorderThickness="1" FontSize="13" Padding="5"/>
                        </StackPanel>

                        <Button x:Name="ExportArtifactsBtn" Content="Export CSV"
                                Style="{StaticResource SecondaryButton}" Grid.Column="1" Margin="0,0,5,0"/>
                        <Button x:Name="ScanLocalBtn" Content="Scan Localhost"
                                Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Artifacts List -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,0" Padding="15" Height="380">
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

                    <!-- Baseline Selection -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="ScanBaselineBtn" Content="Scan Baseline Host" Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportBaselineBtn" Content="Import Baseline" Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Target Selection -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="ScanTargetBtn" Content="Scan Target Host" Style="{StaticResource SecondaryButton}" Grid.Column="0"/>
                        <Button x:Name="ImportTargetBtn" Content="Import Target" Style="{StaticResource SecondaryButton}" Grid.Column="2"/>
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
                            <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" MaxHeight="300">
                                <DataGrid x:Name="GapAnalysisGrid" Background="#0D1117" Foreground="#E6EDF3"
                                           BorderThickness="0" FontSize="11" FontFamily="Consolas"
                                           GridLinesVisibility="Horizontal" HeadersVisibility="Column"
                                           AutoGenerateColumns="False" IsReadOnly="True"
                                           CanUserAddRows="False" CanUserDeleteRows="False">
                                    <DataGrid.Columns>
                                        <DataGridTextColumn Header="Software Name" Binding="{Binding Name}" Width="200"/>
                                        <DataGridTextColumn Header="Version" Binding="{Binding Version}" Width="100"/>
                                        <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="120">
                                            <DataGridTextColumn.ElementStyle>
                                                <Style TargetType="TextBlock">
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
                                                        </DataTrigger>
                                                    </Style.Triggers>
                                                </Style>
                                            </DataGridTextColumn.ElementStyle>
                                        </DataGridTextColumn>
                                        <DataGridTextColumn Header="Baseline Version" Binding="{Binding BaselineVersion}" Width="100"/>
                                        <DataGridTextColumn Header="Target Version" Binding="{Binding TargetVersion}" Width="100"/>
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
                    <TextBlock Text="Rule Generator" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Grid Margin="0,0,0,15">
                        <TextBlock Text="Rule Type (Best Practice Order):" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center"/>
                        <ComboBox x:Name="RuleTypeCombo" Width="250" Height="32" HorizontalAlignment="Left" Margin="10,5,0,0"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="13">
                            <ComboBox.Resources>
                                <SolidColorBrush x:Key="PrimaryBrush" Color="#21262D"/>
                                <Style TargetType="ComboBoxItem">
                                    <Setter Property="Background" Value="#21262D"/>
                                    <Setter Property="Foreground" Value="#E6EDF3"/>
                                    <Setter Property="Padding" Value="8,4"/>
                                    <Style.Triggers>
                                        <Trigger Property="IsMouseOver" Value="True">
                                            <Setter Property="Background" Value="#30363D"/>
                                            <Setter Property="Foreground" Value="#58A6FF"/>
                                        </Trigger>
                                        <Trigger Property="IsSelected" Value="True">
                                            <Setter Property="Background" Value="#58A6FF"/>
                                            <Setter Property="Foreground" Value="#FFFFFF"/>
                                        </Trigger>
                                    </Style.Triggers>
                                </Style>
                            </ComboBox.Resources>
                            <ComboBoxItem Content="Publisher (Preferred)"/>
                            <ComboBoxItem Content="Hash (Fallback)"/>
                            <ComboBoxItem Content="Path (Exceptions Only)"/>
                        </ComboBox>
                    </Grid>

                    <Grid Margin="0,10,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ImportArtifactsBtn" Content="Import Artifacts"
                                Style="{StaticResource SecondaryButton}"/>

                        <Button x:Name="GenerateRulesBtn" Content="Generate Rules"
                                Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Rules Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="320">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="RulesOutput" Text="Import artifacts or generate rules to see results here..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Events Panel -->
                <StackPanel x:Name="PanelEvents" Visibility="Collapsed">
                    <TextBlock Text="Event Monitor" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Event Filters and Export -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="120"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Grid.Column="0" Text="Filter by event type:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center"/>

                        <Button x:Name="FilterAllBtn" Content="All" Style="{StaticResource SecondaryButton}" Grid.Column="1" Margin="5,0"/>
                        <Button x:Name="FilterAllowedBtn" Content="Allowed" Style="{StaticResource SecondaryButton}" Grid.Column="2" Margin="5,0"/>
                        <Button x:Name="FilterBlockedBtn" Content="Blocked" Style="{StaticResource SecondaryButton}" Grid.Column="3" Margin="5,0"/>
                        <Button x:Name="FilterAuditBtn" Content="Audit" Style="{StaticResource SecondaryButton}" Grid.Column="4" Margin="5,0"/>
                        <Button x:Name="RefreshEventsBtn" Content="Refresh" Style="{StaticResource PrimaryButton}" Grid.Column="5" Margin="5,0"/>
                        <Button x:Name="ExportEventsBtn" Content="Export" Style="{StaticResource PrimaryButton}" Grid.Column="6" Margin="5,0,0,0"/>
                    </Grid>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="440">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="EventsOutput" Text="Click refresh to load events..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
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
                            CornerRadius="8" Padding="15" Height="320">
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
                            CornerRadius="8" Padding="15" Height="440">
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
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="CreateWinRMGpoBtn" Content="Create WinRM GPO" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="FullWorkflowBtn" Content="Full Workflow" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="380">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="WinRMOutput" Text="Click 'Full Workflow' to set up WinRM..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- AD Discovery Panel -->
                <StackPanel x:Name="PanelDiscovery" Visibility="Collapsed">
                    <TextBlock Text="AD Discovery" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock x:Name="DiscoveryStatus" Text="Active Directory Discovery" FontSize="14"
                                       FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Discover computers in Active Directory by OU or search criteria."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="420">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock FontFamily="Consolas" FontSize="12" Foreground="#8B949E">
                                <Run Text="AD Discovery Features:" Foreground="#E6EDF3"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="• Search computers by OU path"/>
                                <LineBreak/>
                                <Run Text="• Test connectivity to discovered hosts"/>
                                <LineBreak/>
                                <Run Text="• Select hosts for artifact scanning"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="Note: In workgroup mode, AD features are disabled."/>
                                <Run Text=" Use 'Scan Localhost' in the Artifacts tab instead." Foreground="#D29922"/>
                            </TextBlock>
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
                            CornerRadius="8" Padding="15" Height="280">
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
                            CornerRadius="8" Padding="15" Height="250">
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
    Write-Host "ERROR: Failed to load WPF GUI: $_" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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
$SetupSectionArrow = $window.FindName("SetupSectionArrow")
$ScanningSectionArrow = $window.FindName("ScanningSectionArrow")
$DeploymentSectionArrow = $window.FindName("DeploymentSectionArrow")
$MonitoringSectionArrow = $window.FindName("MonitoringSectionArrow")

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
$BlockedEvents = $window.FindName("BlockedEvents")
$RefreshDashboardBtn = $window.FindName("RefreshDashboardBtn")
$DashboardOutput = $window.FindName("DashboardOutput")

# Other controls
$MaxFilesText = $window.FindName("MaxFilesText")
$ScanLocalBtn = $window.FindName("ScanLocalBtn")
$ExportArtifactsBtn = $window.FindName("ExportArtifactsBtn")
$ArtifactsList = $window.FindName("ArtifactsList")
$RuleTypeCombo = $window.FindName("RuleTypeCombo")
$ImportArtifactsBtn = $window.FindName("ImportArtifactsBtn")
$GenerateRulesBtn = $window.FindName("GenerateRulesBtn")
$RulesOutput = $window.FindName("RulesOutput")
$FilterAllBtn = $window.FindName("FilterAllBtn")
$FilterAllowedBtn = $window.FindName("FilterAllowedBtn")
$FilterBlockedBtn = $window.FindName("FilterBlockedBtn")
$FilterAuditBtn = $window.FindName("FilterAuditBtn")
$RefreshEventsBtn = $window.FindName("RefreshEventsBtn")
$ExportEventsBtn = $window.FindName("ExportEventsBtn")
$EventsOutput = $window.FindName("EventsOutput")
$CreateGP0Btn = $window.FindName("CreateGP0Btn")
$LinkGP0Btn = $window.FindName("LinkGP0Btn")
$DeploymentStatus = $window.FindName("DeploymentStatus")
$GenerateEvidenceBtn = $window.FindName("GenerateEvidenceBtn")
$ComplianceOutput = $window.FindName("ComplianceOutput")
$CreateWinRMGpoBtn = $window.FindName("CreateWinRMGpoBtn")
$FullWorkflowBtn = $window.FindName("FullWorkflowBtn")
$WinRMOutput = $window.FindName("WinRMOutput")

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
$CreateBrowserDenyBtn = $window.FindName("CreateBrowserDenyBtn")
$AppLockerSetupOutput = $window.FindName("AppLockerSetupOutput")

# About and Help controls
$AboutLogo = $window.FindName("AboutLogo")
$AboutVersion = $window.FindName("AboutVersion")
$HelpTitle = $window.FindName("HelpTitle")
$HelpText = $window.FindName("HelpText")
$HelpBtnWorkflow = $window.FindName("HelpBtnWorkflow")
$HelpBtnRules = $window.FindName("HelpBtnRules")
$HelpBtnTroubleshooting = $window.FindName("HelpBtnTroubleshooting")

# Gap Analysis controls
$ScanBaselineBtn = $window.FindName("ScanBaselineBtn")
$ImportBaselineBtn = $window.FindName("ImportBaselineBtn")
$ScanTargetBtn = $window.FindName("ScanTargetBtn")
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

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $logDir = ".\Logs"
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

# Expander event handlers - animate arrows on expand/collapse
$SetupSection.Add_Expanded({
    if ($_.NewValue -eq $true) {
        $SetupSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(90)
    } else {
        $SetupSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(-90)
    }
})

$ScanningSection.Add_Expanded({
    if ($_.NewValue -eq $true) {
        $ScanningSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(90)
    } else {
        $ScanningSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(-90)
    }
})

$DeploymentSection.Add_Expanded({
    if ($_.NewValue -eq $true) {
        $DeploymentSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(90)
    } else {
        $DeploymentSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(-90)
    }
})

$MonitoringSection.Add_Expanded({
    if ($_.NewValue -eq $true) {
        $MonitoringSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(90)
    } else {
        $MonitoringSectionArrow.RenderTransform = [System.Windows.Media.RotateTransform]::new(-90)
    }
})

# Dashboard events
function Refresh-Data {
    $summary = Get-DashboardSummary
    $HealthScore.Text = $summary.policyHealth.score
    $HealthStatus.Text = if ($summary.policyHealth.score -eq 100) { "All categories enabled" } else { "Score: $($summary.policyHealth.score)/100" }
    $TotalEvents.Text = $summary.events.total
    $EventsStatus.Text = if ($summary.events.total -gt 0) { "Events found" } else { "No events" }
    $AllowedEvents.Text = $summary.events.allowed
    $BlockedEvents.Text = $summary.events.blocked
}

$RefreshDashboardBtn.Add_Click({
    Refresh-Data
    $DashboardOutput.Text = "Dashboard refreshed at $(Get-Date -Format 'HH:mm:ss')"
})

# Artifacts events
$ExportArtifactsBtn.Add_Click({
    if ($script:CollectedArtifacts.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No artifacts to export. Run a scan first.", "No Data", "OK", "Information")
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json"
    $saveDialog.Title = "Export Artifacts"
    $saveDialog.FileName = "Artifacts-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName)
        if ($ext -eq ".csv") {
            $script:CollectedArtifacts | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        } else {
            $script:CollectedArtifacts | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Exported $($script:CollectedArtifacts.Count) artifacts to $($saveDialog.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:CollectedArtifacts.Count) artifacts to $($saveDialog.FileName)", "Export Complete", "OK", "Information")
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

# Rules events
$ImportArtifactsBtn.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $openDialog.Title = "Import Scan Artifacts"
    if ($openDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($openDialog.FileName)
        if ($ext -eq ".csv") {
            $script:CollectedArtifacts = Import-Csv -Path $openDialog.FileName
        } else {
            $script:CollectedArtifacts = Get-Content -Path $openDialog.FileName | ConvertFrom-Json
        }
        $RulesOutput.Text = "Imported $($script:CollectedArtifacts.Count) artifacts. Select rule type and click Generate Rules."
    }
})

$GenerateRulesBtn.Add_Click({
    if ($script:CollectedArtifacts.Count -eq 0) {
        $RulesOutput.Text = "ERROR: No artifacts imported. Use Import Artifacts first."
        return
    }

    $ruleType = switch ($RuleTypeCombo.SelectedIndex) {
        0 { "Publisher" }
        1 { "Hash" }
        2 { "Path" }
    }

    $result = New-RulesFromArtifacts -Artifacts $script:CollectedArtifacts -RuleType $ruleType

    $output = "Generated $($result.count) $ruleType rules:`n`n"
    foreach ($rule in $result.rules) {
        $output += "[$($rule.type)] $($rule.publisher)`n"
    }
    $RulesOutput.Text = $output
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
        [System.Windows.MessageBox]::Show("No events to export. Click Refresh first.", "No Data", "OK", "Information")
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|Text Files (*.txt)|*.txt"
    $saveDialog.Title = "Export Events"
    $saveDialog.FileName = "AppLockerEvents-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker\Scans"

    if ($saveDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName)
        if ($ext -eq ".csv") {
            $script:AllEvents | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        } elseif ($ext -eq ".json") {
            $script:AllEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        } else {
            $script:AllEvents | ForEach-Object { "[$($_.time)] [$($_.type)] $($_.message)" } | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Exported $($script:AllEvents.Count) events to $($saveDialog.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:AllEvents.Count) events to $($saveDialog.FileName)", "Export Complete", "OK", "Information")
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
        [System.Windows.MessageBox]::Show("GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }
    $DeploymentStatus.Text = "GPO creation requires Domain Admin privileges. In production, this would create a new GPO in the domain."
    Write-Log "GPO creation initiated (domain mode)"
})

$LinkGP0Btn.Add_Click({
    Write-Log "Link GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO linking requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }
    $DeploymentStatus.Text = "GPO linking requires Domain Admin privileges. In production, this would link the GPO to an OU."
    Write-Log "GPO linking initiated (domain mode)"
})

# WinRM events
$CreateWinRMGpoBtn.Add_Click({
    Write-Log "Create WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }

    $WinRMOutput.Text = "=== WINRM GPO CREATION ===`n`nCreating WinRM GPO...`n`nThis will:`n  • Create 'Enable WinRM' GPO`n  • Link to domain root`n  • Configure WinRM service settings`n  • Enable firewall rules`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $WinRMOutput.Text = "=== WINRM GPO CREATED ===`n`nSUCCESS: GPO created and linked`n`nGPO Name: $($result.gpoName)`n`nGPO ID: $($result.gpoId)`n`nLinked to: $($result.linkedTo)`n`nConfigured Settings:`n  • WinRM service: Auto-config enabled`n  • Unencrypted traffic: Disabled`n  • IPv4 filter: * (all addresses)`n  • Service startup: Automatic`n  • Firewall rules: Enabled`n`n`nThe GPO will be applied during the next Group Policy refresh (typically every 90 minutes).`n`nTo force immediate update: gpupdate /force"
        Write-Log "WinRM GPO created successfully: $($result.gpoName)"
        [System.Windows.MessageBox]::Show("WinRM GPO created successfully!`n`nGPO: $($result.gpoName)`n`nLinked to: $($result.linkedTo)", "Success", "OK", "Information")
    } else {
        $WinRMOutput.Text = "=== WINRM GPO CREATION FAILED ===`n`nERROR: $($result.error)`n`n`nPossible causes:`n  • Not running as Domain Admin`n  • Group Policy module not available`n  • Insufficient permissions`n`n`nPlease run as Domain Administrator and try again."
        Write-Log "Failed to create WinRM GPO: $($result.error)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to create WinRM GPO:`n$($result.error)", "Error", "OK", "Error")
    }
})

# WinRM events
$FullWorkflowBtn.Add_Click({
    Write-Log "Full WinRM workflow button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO deployment requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        $WinRMOutput.Text = "=== WINRM SETUP (WORKGROUP MODE) ===`n`nWinRM GPO deployment is only available in domain mode.`n`nIn workgroup mode, you can:`n  • Manually enable WinRM on each machine`n  • Use: `Enable-PSRemoting -Force` in PowerShell`n  • Configure firewall rules manually"
        return
    }

    $WinRMOutput.Text = "=== WINRM FULL WORKFLOW ===`n`nStep 1: Creating and linking WinRM GPO...`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $WinRMOutput.Text = "=== WINRM SETUP COMPLETE ===`n`nSUCCESS: WinRM GPO deployed!`n`nWhat was done:`n`n1. Created GPO: $($result.gpoName)`n`n2. Linked to: $($result.linkedTo)`n`n3. Configured registry policies:`n   • WinRM Auto-Config: Enabled`n   • Unencrypted Traffic: Disabled`n   • IPv4 Filter: * (all)`n`n4. Service startup: Automatic`n`n5. Firewall rules: Enabled (Domain profile)`n`n`n=== NEXT STEPS ===`n`n1. Wait for Group Policy refresh (up to 90 min)`n   Or run: gpupdate /force`n`n2. Test WinRM: Test-WsMan -ComputerName <target>`n`n3. Enter-PSSession to test remote access`n`n`nGPO will apply to all computers in the domain."
        Write-Log "Full WinRM workflow completed successfully"
        [System.Windows.MessageBox]::Show("WinRM GPO deployed successfully!`n`nGPO: $($result.gpoName)`n`nThe GPO will apply during the next Group Policy refresh.", "Success", "OK", "Information")
    } else {
        $WinRMOutput.Text = "=== WINRM SETUP FAILED ===`n`nERROR: $($result.error)`n`n`nPlease ensure you are running as Domain Administrator."
        Write-Log "Full WinRM workflow failed: $($result.error)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to deploy WinRM GPO:`n$($result.error)", "Error", "OK", "Error")
    }
})

# Group Management events
$ExportGroupsBtn.Add_Click({
    Write-Log "Export groups button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("AD Group Management requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        $GroupMgmtOutput.Text = "=== WORKGROUP MODE ===`n`nAD Group Management is only available in domain mode.`n`nPlease run from a domain-joined computer with Active Directory module installed."
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.Title = "Export AD Groups"
    $saveDialog.FileName = "AD_GroupMembership_Export.csv"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq "OK") {
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
        [System.Windows.MessageBox]::Show("AD Group Management requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openDialog.Title = "Import AD Groups from CSV"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq "OK") {
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
                [System.Windows.MessageBox]::Show("Group membership changes applied!`n`nProcessed: $($result.stats.GroupsProcessed)`nAdds: $($result.stats.Adds)`nRemovals: $($result.stats.Removals)", "Import Complete", "OK", "Information")
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
        [System.Windows.MessageBox]::Show("AppLocker Setup requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
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

$CreateBrowserDenyBtn.Add_Click({
    Write-Log "Create browser deny rules button clicked"

    $result = New-BrowserDenyRules

    if ($result.success) {
        $AppLockerSetupOutput.Text = $result.output
        Write-Log "Browser deny rules created: $($result.browsersDenied) browsers denied"
        [System.Windows.MessageBox]::Show("Browser deny rules created!`n`nBrowsers denied: $($result.browsersDenied)`n`nPolicy saved to: $($result.policyPath)", "Success", "OK", "Information")
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

$HelpBtnRules.Add_Click({
    $HelpTitle.Text = "Help - Rule Best Practices"
    $HelpText.Text = Get-HelpContent "Rules"
})

$HelpBtnTroubleshooting.Add_Click({
    $HelpTitle.Text = "Help - Troubleshooting"
    $HelpText.Text = Get-HelpContent "Troubleshooting"
})

# Gap Analysis events
$ScanBaselineBtn.Add_Click({
    Write-Log "Scan baseline button clicked"
    $computerName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter computer name for baseline scan:", "Baseline Scan", $env:COMPUTERNAME)

    if ([string]::IsNullOrWhiteSpace($computerName)) { return }

    $script:BaselineSoftware = Get-InstalledSoftware -ComputerName $computerName

    if ($script:BaselineSoftware.Count -gt 0) {
        [System.Windows.MessageBox]::Show("Baseline scan complete!`n`nFound $($script:BaselineSoftware.Count) software items on $computerName", "Success", "OK", "Information")
        Write-Log "Baseline scan complete: $($script:BaselineSoftware.Count) items"
    } else {
        [System.Windows.MessageBox]::Show("Failed to scan baseline computer. Check logs for details.", "Error", "OK", "Error")
    }
})

$ImportBaselineBtn.Add_Click({
    Write-Log "Import baseline button clicked"
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv"
    $openDialog.Title = "Import Baseline Software List"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq "OK") {
        $script:BaselineSoftware = Import-SoftwareList -Path $openDialog.FileName
        if ($script:BaselineSoftware.Count -gt 0) {
            [System.Windows.MessageBox]::Show("Baseline imported!`n`nLoaded $($script:BaselineSoftware.Count) software items.", "Success", "OK", "Information")
        } else {
            [System.Windows.MessageBox]::Show("Failed to import baseline. Check logs for details.", "Error", "OK", "Error")
        }
    }
})

$ScanTargetBtn.Add_Click({
    Write-Log "Scan target button clicked"
    $computerName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter computer name for target scan:", "Target Scan", $env:COMPUTERNAME)

    if ([string]::IsNullOrWhiteSpace($computerName)) { return }

    $script:TargetSoftware = Get-InstalledSoftware -ComputerName $computerName

    if ($script:TargetSoftware.Count -gt 0) {
        [System.Windows.MessageBox]::Show("Target scan complete!`n`nFound $($script:TargetSoftware.Count) software items on $computerName", "Success", "OK", "Information")
        Write-Log "Target scan complete: $($script:TargetSoftware.Count) items"
    } else {
        [System.Windows.MessageBox]::Show("Failed to scan target computer. Check logs for details.", "Error", "OK", "Error")
    }
})

$ImportTargetBtn.Add_Click({
    Write-Log "Import target button clicked"
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv"
    $openDialog.Title = "Import Target Software List"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq "OK") {
        $script:TargetSoftware = Import-SoftwareList -Path $openDialog.FileName
        if ($script:TargetSoftware.Count -gt 0) {
            [System.Windows.MessageBox]::Show("Target imported!`n`nLoaded $($script:TargetSoftware.Count) software items.", "Success", "OK", "Information")
        } else {
            [System.Windows.MessageBox]::Show("Failed to import target. Check logs for details.", "Error", "OK", "Error")
        }
    }
})

$CompareSoftwareBtn.Add_Click({
    Write-Log "Compare software button clicked"

    if ($script:BaselineSoftware.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please scan or import a baseline first.", "No Baseline", "OK", "Warning")
        return
    }

    if ($script:TargetSoftware.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please scan or import a target first.", "No Target", "OK", "Warning")
        return
    }

    $results = Compare-SoftwareLists -Baseline $script:BaselineSoftware -Target $script:TargetSoftware

    # Update DataGrid
    $GapAnalysisGrid.ItemsSource = $results

    # Update stats
    $GapTotalCount.Text = $results.Count
    $GapMissingCount.Text = ($results | Where-Object { $_.Status -eq "Missing in Target" }).Count
    $GapExtraCount.Text = ($results | Where-Object { $_.Status -eq "Extra in Target" }).Count
    $GapVersionCount.Text = ($results | Where-Object { $_.Status -eq "Version Mismatch" }).Count

    Write-Log "Comparison complete: Total=$($results.Count), Missing=$($GapMissingCount.Text), Extra=$($GapExtraCount.Text), Version Diff=$($GapVersionCount.Text)"
})

$ExportGapAnalysisBtn.Add_Click({
    Write-Log "Export gap analysis button clicked"

    if ($GapAnalysisGrid.Items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No comparison results to export.", "No Data", "OK", "Warning")
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.Title = "Export Software Gap Analysis"
    $saveDialog.FileName = "Software_Gap_Analysis_$(Get-Date -Format 'yyyy-MM-dd').csv"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq "OK") {
        $GapAnalysisGrid.Items | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.MessageBox]::Show("Exported to: $($saveDialog.FileName)", "Success", "OK", "Information")
        Write-Log "Gap analysis exported: $($saveDialog.FileName)"
    }
})

# Export/Import Rules events
$ExportRulesBtn.Add_Click({
    Write-Log "Export rules button clicked"

    if ($script:GeneratedRules.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No generated rules to export. Please generate rules first using the Rule Generator tab.", "No Rules", "OK", "Warning")
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $saveDialog.Title = "Export AppLocker Rules"
    $saveDialog.FileName = "AppLocker-Rules_$(Get-Date -Format 'yyyy-MM-dd').xml"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq "OK") {
        # Generate AppLocker XML from rules
        $xmlContent = Convert-RulesToAppLockerXml -Rules $script:GeneratedRules
        $xmlContent | Out-File -FilePath $saveDialog.FileName -Encoding UTF8 -Force
        [System.Windows.MessageBox]::Show("Rules exported to: $($saveDialog.FileName)`n`nYou can now import this XML into a GPO using Group Policy Management.", "Success", "OK", "Information")
        Write-Log "Rules exported: $($saveDialog.FileName)"
    }
})

$ImportRulesBtn.Add_Click({
    Write-Log "Import rules button clicked"

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog.Title = "Import AppLocker Rules"
    $openDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($openDialog.ShowDialog() -eq "OK") {
        $DeploymentStatus.Text = "Importing rules from: $($openDialog.FileName)`n`nNote: Use Group Policy Management console to import XML into GPO.`n`n1. Open GPO`n2. Go to: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker`n3. Right-click -> Import Policy`n`nThis feature prepares the XML for manual import."
        Write-Log "Rules imported for GPO deployment: $($openDialog.FileName)"
        [System.Windows.MessageBox]::Show("Rules loaded!`n`nTo apply to a GPO:`n1. Open Group Policy Management`n2. Edit target GPO`n3. Navigate to: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker`n4. Right-click -> Import Policy`n5. Select the exported XML file", "Import Ready", "OK", "Information")
    }
})

# Other events
function Update-StatusBar {
    if ($script:IsWorkgroup) {
        $StatusText.Text = "WORKGROUP MODE - Local scanning available"
    } else {
        $StatusText.Text = "$($script:DomainInfo.dnsRoot) - Full features available"
    }
}

# Initialize on load
$window.add_Loaded({
    # Detect domain/workgroup
    $script:DomainInfo = Get-ADDomain
    $script:IsWorkgroup = $script:DomainInfo.isWorkgroup

    Write-Log "Application started - Mode: $($script:DomainInfo.message)"

    # Update environment banner
    if ($script:IsWorkgroup) {
        $EnvironmentText.Text = "WORKGROUP MODE - Localhost scanning available | AD/GPO features disabled"
        $EnvironmentBanner.Background = "#21262D" # BgCard

        # Disable AD/GPO related buttons in workgroup mode
        $CreateGP0Btn.IsEnabled = $false
        $LinkGP0Btn.IsEnabled = $false
        $CreateWinRMGpoBtn.IsEnabled = $false
        $FullWorkflowBtn.IsEnabled = $false
        $ExportGroupsBtn.IsEnabled = $false
        $ImportGroupsBtn.IsEnabled = $false
        $BootstrapAppLockerBtn.IsEnabled = $false

        Write-Log "Workgroup mode: Deployment, WinRM, Group Management, and AppLocker Setup buttons disabled"
    } else {
        $EnvironmentText.Text = "DOMAIN: $($script:DomainInfo.dnsRoot) | Full features available"
        $EnvironmentBanner.Background = "#238636" # Green

        # Enable all buttons in domain mode
        $CreateGP0Btn.IsEnabled = $true
        $LinkGP0Btn.IsEnabled = $true
        $CreateWinRMGpoBtn.IsEnabled = $true
        $FullWorkflowBtn.IsEnabled = $true

        Write-Log "Domain mode: All features enabled"
    }

    # Load app icon and About logo
    try {
        $scriptPath = Split-Path -Parent $PSCommandPath
        # Try to load icon from script directory
        $iconPath = Join-Path $scriptPath "GA-AppLocker.ico"
        if (Test-Path $iconPath) {
            $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create((New-Object System.Uri $iconPath))
        }
    } catch {
        # Icon load failed - using default
    }

    # Try to load About logo
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
    } catch {
        # Logo load failed - using default
    }

    # Set version info
    $script:AppVersion = "1.1.0"
    $AboutVersion.Text = "Version $script:AppVersion"

    # Load dashboard
    Show-Panel "Dashboard"
    Refresh-Data
    Update-StatusBar

    # Load initial message
    $DashboardOutput.Text = "=== GA-APPLOCKER DASHBOARD ===`n`nAaronLocker-aligned AppLocker Policy Management`n`nEnvironment: $($script:DomainInfo.message)`n`nReady to begin. Select a tab to start."
})

# Show window
$window.ShowDialog() | Out-Null
