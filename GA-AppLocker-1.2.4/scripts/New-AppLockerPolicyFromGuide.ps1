<#
.SYNOPSIS
Creates AppLocker policies using Build Guide methodology or simplified mode.

.DESCRIPTION
Part of GA-AppLocker toolkit. Use Start-AppLockerWorkflow.ps1 for guided experience.

Generates enterprise-ready AppLocker policies with two operational modes:

BUILD GUIDE MODE (default):
- Proper principal scoping (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Administrators)
- Custom AD group support (Admins, StandardUsers, ServiceAccounts, Installers)
- Microsoft Publisher rules scoped correctly (NOT Everyone)
- Explicit deny rules for user-writable paths
- Phased deployment support (Phase 1-4)
- Target-specific policies (Workstation, Server, DomainController)

SIMPLIFIED MODE (-Simplified switch):
- Single target user/group (e.g., "Everyone", "BUILTIN\Users")
- Administrators get full access
- Publisher rules from scan data (auto-deduplicated)
- Optional hash rules for unsigned executables
- Optional deny rules for LOLBins
- Good for quick deployments or testing

Follows the principle: "Allow who may run trusted code, deny where code can never run"

.PARAMETER Simplified
Use simplified mode instead of Build Guide methodology.
Requires -ScanPath, does not require -TargetType or -DomainName.

.PARAMETER ScanPath
Path to scan results from Invoke-RemoteScan.ps1.
Required for -Simplified mode, optional for Build Guide mode.

.PARAMETER OutputPath
Path to save generated policies. Defaults to .\Outputs.

.PARAMETER TargetType
(Build Guide mode) Type of systems: Workstation, Server, or DomainController.

.PARAMETER DomainName
(Build Guide mode) Domain name for group resolution (e.g., "CONTOSO").

.PARAMETER TargetUser
(Simplified mode) User/group for rules. Examples:
- "Everyone" (S-1-1-0) - Default
- "BUILTIN\Users" (S-1-5-32-545)
- "DOMAIN\GroupName" - Custom AD group

.PARAMETER AdminGroup
(Simplified mode) Admin group with full access. Default: "BUILTIN\Administrators"

.PARAMETER AdminsGroup
(Build Guide mode) Custom AppLocker Admins group.

.PARAMETER StandardUsersGroup
(Build Guide mode) Custom Standard Users group.

.PARAMETER ServiceAccountsGroup
(Build Guide mode) Custom Service Accounts group.

.PARAMETER InstallersGroup
(Build Guide mode) Custom Installers group.

.PARAMETER Phase
(Build Guide mode) Build phase 1-4.

.PARAMETER EnforcementMode
AuditOnly (default) or Enabled.

.PARAMETER IncludeVendorPublishers
Include vendor publisher rules from scan data.

.PARAMETER VendorPublishers
Additional vendor publishers to trust (array).

.PARAMETER IncludeDenyRules
(Simplified mode) Include deny rules for LOLBins.

.PARAMETER SkipDenyRules
(Build Guide mode) Skip explicit deny rules.

.PARAMETER IncludeHashRules
(Simplified mode) Include hash rules for unsigned files.

.PARAMETER RuleGranularity
(Simplified mode) Publisher rule specificity:
- Publisher: Trust all from publisher (broadest)
- PublisherProduct: Trust publisher + product
- PublisherProductBinary: Trust specific binary (default)

.PARAMETER DLLEnforcement
DLL rule enforcement: NotConfigured (default), AuditOnly, or Enabled.

.EXAMPLE
# BUILD GUIDE: Phase 1 for workstations
.\New-AppLockerPolicyFromGuide.ps1 -TargetType Workstation -DomainName "CONTOSO" -Phase 1

.EXAMPLE
# BUILD GUIDE: Full policy for servers with vendors
.\New-AppLockerPolicyFromGuide.ps1 -TargetType Server -DomainName "CONTOSO" -Phase 4 `
    -ScanPath \\share\Scans -IncludeVendorPublishers

.EXAMPLE
# SIMPLIFIED: Quick policy for testing
.\New-AppLockerPolicyFromGuide.ps1 -Simplified -ScanPath .\Scans -TargetUser "BUILTIN\Users"

.EXAMPLE
# SIMPLIFIED: With deny rules for LOLBins
.\New-AppLockerPolicyFromGuide.ps1 -Simplified -ScanPath .\Scans -TargetUser "Everyone" -IncludeDenyRules

.EXAMPLE
# SIMPLIFIED: With hash rules for unsigned files
.\New-AppLockerPolicyFromGuide.ps1 -Simplified -ScanPath .\Scans -IncludeHashRules -IncludeDenyRules

.EXAMPLE
# SIMPLIFIED: Generate from software list (signature/hash based)
.\New-AppLockerPolicyFromGuide.ps1 -Simplified -SoftwareListPath .\SoftwareLists\ApprovedSoftware.json

.EXAMPLE
# SIMPLIFIED: Generate from collected blocked events (from audit mode)
.\New-AppLockerPolicyFromGuide.ps1 -Simplified -EventPath .\Events\Events-20240115-120000

.EXAMPLE
# SIMPLIFIED: Combine scan data and blocked events for comprehensive policy
.\New-AppLockerPolicyFromGuide.ps1 -Simplified -ScanPath .\Scans -EventPath .\Events -IncludeHashRules

.EXAMPLE
# BUILD GUIDE: Use software list for vendor publishers
.\New-AppLockerPolicyFromGuide.ps1 -TargetType Workstation -DomainName "CONTOSO" -Phase 1 `
    -SoftwareListPath .\SoftwareLists\BusinessApps.json
#>

[CmdletBinding(DefaultParameterSetName='BuildGuide', SupportsShouldProcess=$true)]
param(
    # === SIMPLIFIED MODE ===
    [Parameter(ParameterSetName='Simplified', Mandatory=$true)]
    [switch]$Simplified,

    [Parameter(ParameterSetName='Simplified')]
    [string]$TargetUser = "Everyone",

    [Parameter(ParameterSetName='Simplified')]
    [string]$AdminGroup = "BUILTIN\Administrators",

    [Parameter(ParameterSetName='Simplified')]
    [switch]$IncludeDenyRules,

    [Parameter(ParameterSetName='Simplified')]
    [switch]$IncludeHashRules,

    [Parameter(ParameterSetName='Simplified')]
    [ValidateSet("Publisher", "PublisherProduct", "PublisherProductBinary")]
    [string]$RuleGranularity = "PublisherProductBinary",

    # === BUILD GUIDE MODE ===
    [Parameter(ParameterSetName='BuildGuide', Mandatory=$true)]
    [ValidateSet("Workstation", "Server", "DomainController")]
    [string]$TargetType,

    [Parameter(ParameterSetName='BuildGuide', Mandatory=$true)]
    [string]$DomainName,

    [Parameter(ParameterSetName='BuildGuide')]
    [string]$AdminsGroup,

    [Parameter(ParameterSetName='BuildGuide')]
    [string]$StandardUsersGroup,

    [Parameter(ParameterSetName='BuildGuide')]
    [string]$ServiceAccountsGroup,

    [Parameter(ParameterSetName='BuildGuide')]
    [string]$InstallersGroup,

    [Parameter(ParameterSetName='BuildGuide')]
    [ValidateRange(1,4)]
    [int]$Phase = 1,

    [Parameter(ParameterSetName='BuildGuide')]
    [switch]$SkipDenyRules,

    # === COMMON PARAMETERS ===
    [string]$ScanPath,

    [string]$SoftwareListPath,

    [Parameter(HelpMessage="Path to collected event data from Invoke-RemoteEventCollection.ps1")]
    [string]$EventPath,

    [string]$OutputPath = ".\Outputs",

    [ValidateSet("AuditOnly", "Enabled")]
    [string]$EnforcementMode = "AuditOnly",

    [switch]$IncludeVendorPublishers,

    [string[]]$VendorPublishers = @(),

    [ValidateSet("NotConfigured", "AuditOnly", "Enabled")]
    [string]$DLLEnforcement = "NotConfigured"
)

#Requires -Version 5.1

# Import utilities module and config
$scriptRoot = $PSScriptRoot
$utilitiesRoot = Join-Path (Split-Path -Parent $scriptRoot) "Utilities"
$modulePath = Join-Path $utilitiesRoot "Common.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
    $config = Get-AppLockerConfig
}
else {
    $config = $null
}

# Import software list module
$softwareListModule = Join-Path $utilitiesRoot "Manage-SoftwareLists.ps1"
if (Test-Path $softwareListModule) {
    . $softwareListModule
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

#region Simplified Mode Validation
if ($Simplified) {
    $hasScanPath = $ScanPath -and (Test-Path $ScanPath)
    $hasSoftwareList = $SoftwareListPath -and (Test-Path $SoftwareListPath)
    $hasEventPath = $EventPath -and (Test-Path $EventPath)

    if (-not $hasScanPath -and -not $hasSoftwareList -and -not $hasEventPath) {
        throw "Simplified mode requires either -ScanPath with valid scan data, -SoftwareListPath with a software list, or -EventPath with collected event data"
    }
}
#endregion

#==============================================================================
# SIMPLIFIED MODE - Quick policy from scan data
#==============================================================================
if ($Simplified) {

    Write-Host @"

================================================================================
                    AppLocker Policy Generator (Simplified Mode)
================================================================================
  Creates policies from scan data or software lists with signature/hash rules.
  Use Build Guide mode (-TargetType) for enterprise deployments.
================================================================================

"@ -ForegroundColor Cyan

    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Mode: Simplified" -ForegroundColor Gray
    if ($ScanPath) { Write-Host "  Scan Path: $ScanPath" -ForegroundColor Gray }
    if ($SoftwareListPath) { Write-Host "  Software List: $SoftwareListPath" -ForegroundColor Gray }
    if ($EventPath) { Write-Host "  Event Path: $EventPath" -ForegroundColor Gray }
    Write-Host "  Target User: $TargetUser" -ForegroundColor Gray
    Write-Host "  Enforcement: $EnforcementMode" -ForegroundColor Gray
    Write-Host ""

    #region SID Resolution (Simplified)
    # Use Resolve-AccountToSid from Common.psm1
    $targetSid = Resolve-AccountToSid -Name $TargetUser
    $adminSid = Resolve-AccountToSid -Name $AdminGroup

    Write-Host "Target SID: $targetSid" -ForegroundColor Gray
    Write-Host "Admin SID: $adminSid" -ForegroundColor Gray
    Write-Host ""
    #endregion

    #region Load Data Sources (Scan Data and/or Software Lists)

    $allExecutables = @()
    $allWritableDirs = @()
    $softwareListItems = @()
    $softwareListRulesXml = @()

    # Load software list if provided
    if ($SoftwareListPath -and (Test-Path $SoftwareListPath)) {
        Write-Host "Loading software list..." -ForegroundColor Cyan
        $softwareList = Get-SoftwareList -ListPath $SoftwareListPath
        $softwareListItems = @($softwareList.items | Where-Object { $_.approved -eq $true })
        Write-Host "  List: $($softwareList.metadata.name)" -ForegroundColor Gray
        Write-Host "  Approved items: $($softwareListItems.Count)" -ForegroundColor Gray

        # Get pre-generated rules from software list
        $listRules = Get-SoftwareListRules -ListPath $SoftwareListPath -ApprovedOnly -UserOrGroupSid $targetSid
        $softwareListRulesXml = $listRules | ForEach-Object { $_.Xml }

        Write-Host "  Publisher rules: $(($listRules | Where-Object { $_.Type -eq 'Publisher' }).Count)" -ForegroundColor Gray
        Write-Host "  Hash rules: $(($listRules | Where-Object { $_.Type -eq 'Hash' }).Count)" -ForegroundColor Gray
        Write-Host "  Path rules: $(($listRules | Where-Object { $_.Type -eq 'Path' }).Count)" -ForegroundColor Gray
    }

    # Load scan data if provided
    if ($ScanPath -and (Test-Path $ScanPath)) {
        Write-Host "Loading scan data..." -ForegroundColor Cyan

        $computerFolders = Get-ChildItem -Path $ScanPath -Directory |
            Where-Object { Test-Path (Join-Path $_.FullName "*.csv") }

        if ($computerFolders.Count -eq 0 -and -not $SoftwareListPath) {
            throw "No scan data found in $ScanPath. Run Invoke-RemoteScan.ps1 first."
        }

        if ($computerFolders.Count -gt 0) {
            Write-Host "  Found data from $($computerFolders.Count) computers" -ForegroundColor Gray

            foreach ($folder in $computerFolders) {
                $exePath = Join-Path $folder.FullName "Executables.csv"
                if (Test-Path $exePath) {
                    $allExecutables += Import-Csv -Path $exePath
                }
                $writablePath = Join-Path $folder.FullName "WritableDirectories.csv"
                if (Test-Path $writablePath) {
                    $allWritableDirs += Import-Csv -Path $writablePath
                }
            }

            Write-Host "  Total executables: $($allExecutables.Count)" -ForegroundColor Gray
            Write-Host "  Writable directories: $($allWritableDirs.Count)" -ForegroundColor Gray
        }
    }

    # Load event data if provided (blocked events from audit mode)
    $eventApps = @()
    if ($EventPath -and (Test-Path $EventPath)) {
        Write-Host "Loading event data (blocked applications)..." -ForegroundColor Cyan

        # Look for UniqueBlockedApps.csv in root or timestamped subfolder
        $uniqueBlockedPath = Join-Path $EventPath "UniqueBlockedApps.csv"
        if (-not (Test-Path $uniqueBlockedPath)) {
            # Try finding in timestamped subfolder
            $eventSubfolders = Get-ChildItem -Path $EventPath -Directory -Filter "Events-*" | Sort-Object Name -Descending
            if ($eventSubfolders.Count -gt 0) {
                $uniqueBlockedPath = Join-Path $eventSubfolders[0].FullName "UniqueBlockedApps.csv"
            }
        }

        if (Test-Path $uniqueBlockedPath) {
            $eventApps = @(Import-Csv -Path $uniqueBlockedPath)
            Write-Host "  Unique blocked apps: $($eventApps.Count)" -ForegroundColor Gray
            $signedEvents = @($eventApps | Where-Object { $_.Publisher -and $_.Publisher -ne "" })
            $unsignedEvents = @($eventApps | Where-Object { -not $_.Publisher -or $_.Publisher -eq "" })
            Write-Host "  With publisher info: $($signedEvents.Count)" -ForegroundColor Gray
            Write-Host "  Without publisher (hash only): $($unsignedEvents.Count)" -ForegroundColor Gray
        }
        else {
            Write-Warning "No UniqueBlockedApps.csv found in $EventPath"
        }
    }
    #endregion

    #region Build Publisher Rules (deduplicated from scan data and events)
    # Uses Add-PublisherRule helper from Common.psm1 to avoid duplicate logic
    $publisherRules = @{}

    if ($allExecutables.Count -gt 0) {
        Write-Host "`nBuilding publisher rules from scan data..." -ForegroundColor Cyan

        $signedExes = $allExecutables | Where-Object { $_.IsSigned -eq "True" -and $_.Publisher }

        foreach ($exe in $signedExes) {
            $publisher = $exe.Publisher
            $product = if ($exe.Path -match "\\([^\\]+)\\[^\\]+$") { $matches[1] } else { "*" }
            $binary = $exe.Name

            # Use helper function to add rule with deduplication
            Add-PublisherRule -Rules $publisherRules `
                -Publisher $publisher `
                -Product $product `
                -Binary $binary `
                -Granularity $RuleGranularity `
                -Source "ScanData" | Out-Null
        }

        Write-Host "  Unique publisher rules from scans: $($publisherRules.Count)" -ForegroundColor Green
    }

    # Add publisher rules from event data (blocked apps with publisher info)
    if ($eventApps.Count -gt 0) {
        Write-Host "`nBuilding publisher rules from blocked events..." -ForegroundColor Cyan
        $beforeCount = $publisherRules.Count

        $signedEvents = $eventApps | Where-Object { $_.Publisher -and $_.Publisher -ne "" }

        foreach ($evt in $signedEvents) {
            $publisher = $evt.Publisher
            $product = if ($evt.ProductName -and $evt.ProductName -ne "") { $evt.ProductName } else { "*" }
            $binary = if ($evt.FileName -and $evt.FileName -ne "") { $evt.FileName } else { "*" }

            # Use helper function to add rule with deduplication
            Add-PublisherRule -Rules $publisherRules `
                -Publisher $publisher `
                -Product $product `
                -Binary $binary `
                -Granularity $RuleGranularity `
                -Source "BlockedEvent" | Out-Null
        }

        $eventRuleCount = $publisherRules.Count - $beforeCount
        Write-Host "  Publisher rules from events: $eventRuleCount" -ForegroundColor Green
        Write-Host "  Total unique publisher rules: $($publisherRules.Count)" -ForegroundColor Green
    }
    #endregion

    #region Build Hash Rules (from scan data and events)
    $hashRules = @{}

    if ($IncludeHashRules -and $allExecutables.Count -gt 0) {
        Write-Host "`nBuilding hash rules for unsigned files from scan data..." -ForegroundColor Cyan
        $writablePaths = $allWritableDirs | Select-Object -ExpandProperty Path -Unique

        $unsignedInWritable = $allExecutables | Where-Object {
            $_.IsSigned -ne "True" -and $_.Hash -and $_.Extension -in @(".exe", ".dll", ".msi")
        } | Where-Object {
            $exePath = $_.Path
            foreach ($wp in $writablePaths) {
                if ($exePath -like "$wp*") { return $true }
            }
            return $false
        }

        foreach ($exe in $unsignedInWritable) {
            if (-not $hashRules.ContainsKey($exe.Hash)) {
                $hashRules[$exe.Hash] = @{
                    Name = $exe.Name
                    Path = $exe.Path
                    Hash = $exe.Hash
                    Size = $exe.Size
                }
            }
        }
        Write-Host "  Unique hash rules from scans: $($hashRules.Count)" -ForegroundColor Green
    }

    # Add hash rules from event data for unsigned blocked apps
    if ($IncludeHashRules -and $eventApps.Count -gt 0) {
        Write-Host "`nBuilding hash rules for unsigned blocked events..." -ForegroundColor Cyan
        $eventHashCount = 0

        $unsignedEvents = $eventApps | Where-Object {
            (-not $_.Publisher -or $_.Publisher -eq "") -and $_.FileHash -and $_.FileHash -ne ""
        }

        foreach ($evt in $unsignedEvents) {
            $hash = $evt.FileHash -replace '^0x', ''  # Remove 0x prefix if present
            if (-not $hashRules.ContainsKey($hash)) {
                $hashRules[$hash] = @{
                    Name = $evt.FileName
                    Path = $evt.FilePath
                    Hash = $hash
                    Size = "0"  # Event data doesn't include size, use 0
                    Source = "BlockedEvent"
                }
                $eventHashCount++
            }
        }

        Write-Host "  Hash rules from events: $eventHashCount" -ForegroundColor Green
        Write-Host "  Total unique hash rules: $($hashRules.Count)" -ForegroundColor Green
    }
    #endregion

    #region Build Deny Rules for LOLBins (if requested)
    $simplifiedDenyRules = @()

    if ($IncludeDenyRules) {
        Write-Host "`nBuilding deny rules for LOLBins..." -ForegroundColor Yellow
        # Load LOLBins from config or use defaults
        $lolbins = if ($config -and $config.LOLBins) {
            $config.LOLBins | ForEach-Object { @{ Name = $_.Name; Desc = $_.Description } }
        }
        else {
            @(
                @{ Name = "mshta.exe"; Desc = "HTML Application Host" },
                @{ Name = "PresentationHost.exe"; Desc = "XAML Browser Applications" },
                @{ Name = "InstallUtil.exe"; Desc = ".NET Installation Utility" },
                @{ Name = "RegAsm.exe"; Desc = ".NET Assembly Registration" },
                @{ Name = "RegSvcs.exe"; Desc = ".NET Component Services" },
                @{ Name = "MSBuild.exe"; Desc = "Microsoft Build Engine" },
                @{ Name = "cscript.exe"; Desc = "Console Script Host" },
                @{ Name = "wscript.exe"; Desc = "Windows Script Host" }
            )
        }
        foreach ($lolbin in $lolbins) {
            $simplifiedDenyRules += @{
                Name = $lolbin.Name
                Description = "Deny $($lolbin.Desc)"
                Path = "%SYSTEM32%\$($lolbin.Name)"
            }
        }
        Write-Host "  Deny rules: $($simplifiedDenyRules.Count)" -ForegroundColor Yellow
    }
    #endregion

    #region Generate Simplified Policy XML
    Write-Host "`nGenerating policy XML..." -ForegroundColor Cyan

    # Pre-compute GUIDs for EXE compilation compatibility
    # (Using New-Guid inside here-strings can cause issues with PS2EXE)
    $guidAdminExe = [Guid]::NewGuid().ToString()
    $guidWinDir = [Guid]::NewGuid().ToString()
    $guidProgFiles = [Guid]::NewGuid().ToString()
    $generatedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $simplifiedXml = @"
<?xml version="1.0" encoding="utf-8"?>
<!--
  AppLocker Policy - Simplified Mode
  Generated: $generatedDate
  Target User: $TargetUser
  Enforcement: $EnforcementMode
-->
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$EnforcementMode">
    <!-- Admin full access -->
    <FilePathRule Id="$guidAdminExe" Name="(Default) All files - Administrators" Description="Administrators can run anything" UserOrGroupSid="$adminSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>

    <!-- Default safe paths -->
    <FilePathRule Id="$guidWinDir" Name="(Default) Windows Directory" Description="Allow from Windows" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$guidProgFiles" Name="(Default) Program Files" Description="Allow from Program Files" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>

"@

    # Add deny rules
    foreach ($deny in $simplifiedDenyRules) {
        $denyGuid = [Guid]::NewGuid().ToString()
        $simplifiedXml += @"
    <FilePathRule Id="$denyGuid" Name="(Deny) $($deny.Name)" Description="$($deny.Description)" UserOrGroupSid="$targetSid" Action="Deny">
      <Conditions>
        <FilePathCondition Path="$($deny.Path)"/>
      </Conditions>
    </FilePathRule>

"@
    }

    # Add publisher rules
    foreach ($rule in $publisherRules.Values) {
        $pubGuid = [Guid]::NewGuid().ToString()
        $pubXml = [System.Security.SecurityElement]::Escape($rule.Publisher)
        $prodXml = [System.Security.SecurityElement]::Escape($rule.Product)
        $binXml = [System.Security.SecurityElement]::Escape($rule.Binary)
        $ruleName = "Publisher: $($rule.Publisher)"
        if ($rule.Product -ne "*") { $ruleName += " - $($rule.Product)" }
        if ($rule.Binary -ne "*") { $ruleName += " - $($rule.Binary)" }
        $ruleNameXml = [System.Security.SecurityElement]::Escape($ruleName)

        $simplifiedXml += @"
    <FilePublisherRule Id="$pubGuid" Name="$ruleNameXml" Description="Auto-generated" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=$pubXml*" ProductName="$prodXml" BinaryName="$binXml">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

"@
    }

    # Add hash rules from scan data
    foreach ($rule in $hashRules.Values) {
        $hashGuid = [Guid]::NewGuid().ToString()
        $simplifiedXml += @"
    <FileHashRule Id="$hashGuid" Name="Hash: $($rule.Name)" Description="From: $($rule.Path)" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="SHA256" Data="0x$($rule.Hash)" SourceFileName="$($rule.Name)" SourceFileLength="$($rule.Size)"/>
        </FileHashCondition>
      </Conditions>
    </FileHashRule>

"@
    }

    # Add rules from software list (includes publisher, hash, and path rules)
    if ($softwareListRulesXml.Count -gt 0) {
        Write-Host "  Adding $($softwareListRulesXml.Count) rules from software list..." -ForegroundColor Cyan
        foreach ($ruleXml in $softwareListRulesXml) {
            $simplifiedXml += "$ruleXml`n"
        }
    }

    # Pre-compute remaining GUIDs for EXE compilation compatibility
    $guidAdminMsi = [Guid]::NewGuid().ToString()
    $guidWinInstaller = [Guid]::NewGuid().ToString()
    $guidAdminScript = [Guid]::NewGuid().ToString()
    $guidWinScript = [Guid]::NewGuid().ToString()
    $guidProgScript = [Guid]::NewGuid().ToString()
    $guidMsStore = [Guid]::NewGuid().ToString()

    $simplifiedXml += @"
  </RuleCollection>

  <RuleCollection Type="Msi" EnforcementMode="$EnforcementMode">
    <FilePathRule Id="$guidAdminMsi" Name="(Default) All MSI - Administrators" Description="Administrators can install" UserOrGroupSid="$adminSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$guidWinInstaller" Name="(Default) Windows Installer" Description="Allow from Installer cache" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Script" EnforcementMode="$EnforcementMode">
    <FilePathRule Id="$guidAdminScript" Name="(Default) All scripts - Administrators" Description="Administrators can run scripts" UserOrGroupSid="$adminSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$guidWinScript" Name="(Default) Windows scripts" Description="Allow from Windows" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$guidProgScript" Name="(Default) Program Files scripts" Description="Allow from Program Files" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Dll" EnforcementMode="NotConfigured">
  </RuleCollection>

  <RuleCollection Type="Appx" EnforcementMode="$EnforcementMode">
    <FilePublisherRule Id="$guidMsStore" Name="(Default) Microsoft Store apps" Description="Microsoft-signed apps" UserOrGroupSid="$targetSid" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@
    #endregion

    #region Save Simplified Policy
    $policyFileName = "AppLockerPolicy-Simplified-$EnforcementMode-$timestamp.xml"
    $policyPath = Join-Path $OutputPath $policyFileName

    # Build summary for -WhatIf support
    $policySummary = [PSCustomObject]@{
        Mode = "Simplified"
        TargetUser = $TargetUser
        TargetSid = $targetSid
        PublisherRules = $publisherRules.Count
        HashRules = $hashRules.Count
        SoftwareListRules = $softwareListRulesXml.Count
        DenyRules = $simplifiedDenyRules.Count
        EventsProcessed = $eventApps.Count
        EnforcementMode = $EnforcementMode
        OutputPath = $policyPath
        DataSources = @{
            ScanPath = $ScanPath
            SoftwareListPath = $SoftwareListPath
            EventPath = $EventPath
        }
    }

    # -WhatIf support: Show what would be created without actually creating
    if ($WhatIfPreference -or $PSCmdlet.ShouldProcess($policyPath, "Create AppLocker policy file")) {
        if ($WhatIfPreference) {
            Write-Host @"

================================================================================
                    WHAT-IF: POLICY PREVIEW (Simplified Mode)
================================================================================
"@ -ForegroundColor Cyan

            Write-Host "Would create policy file:" -ForegroundColor Yellow
            Write-Host "  $policyPath" -ForegroundColor White
            Write-Host ""
            Write-Host "Policy Summary:" -ForegroundColor Yellow
            Write-Host "  Target User: $TargetUser ($targetSid)" -ForegroundColor Gray
            Write-Host "  Enforcement Mode: $EnforcementMode" -ForegroundColor Gray
            Write-Host ""
            Write-Host "Rules that would be created:" -ForegroundColor Yellow
            Write-Host "  Publisher Rules: $($publisherRules.Count)" -ForegroundColor Gray
            Write-Host "  Hash Rules: $($hashRules.Count)" -ForegroundColor Gray
            if ($softwareListRulesXml.Count -gt 0) {
                Write-Host "  Software List Rules: $($softwareListRulesXml.Count)" -ForegroundColor Gray
            }
            Write-Host "  Deny Rules: $($simplifiedDenyRules.Count)" -ForegroundColor Gray
            Write-Host ""

            if ($publisherRules.Count -gt 0) {
                Write-Host "Top Publishers (first 10):" -ForegroundColor Yellow
                $publisherRules.Values | Select-Object -First 10 | ForEach-Object {
                    Write-Host "    - $($_.Publisher)" -ForegroundColor DarkGray
                }
                if ($publisherRules.Count -gt 10) {
                    Write-Host "    ... and $($publisherRules.Count - 10) more" -ForegroundColor DarkGray
                }
            }

            if ($simplifiedDenyRules.Count -gt 0) {
                Write-Host ""
                Write-Host "Deny Rules:" -ForegroundColor Yellow
                foreach ($deny in $simplifiedDenyRules) {
                    Write-Host "    - $($deny.Name): $($deny.Path)" -ForegroundColor DarkGray
                }
            }

            Write-Host ""
            Write-Host "Data Sources:" -ForegroundColor Yellow
            if ($SoftwareListPath) { Write-Host "  Software List: $SoftwareListPath" -ForegroundColor Gray }
            if ($ScanPath) { Write-Host "  Scan Data: $ScanPath" -ForegroundColor Gray }
            if ($EventPath) { Write-Host "  Event Data: $EventPath" -ForegroundColor Gray }
            Write-Host ""
            Write-Host "Run without -WhatIf to create the policy file." -ForegroundColor Cyan
            Write-Host ""

            return $policySummary
        }

        # Actually create the file
        $simplifiedXml | Out-File -FilePath $policyPath -Encoding UTF8
    } else {
        # User cancelled via -Confirm:$false or other means
        Write-Host "Policy creation cancelled." -ForegroundColor Yellow
        return $null
    }

    Write-Host @"

================================================================================
                         SIMPLIFIED POLICY COMPLETE
================================================================================
"@ -ForegroundColor Green

    Write-Host "Policy File: $policyPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Yellow
    Write-Host "  Target: $TargetUser ($targetSid)"
    Write-Host "  Publisher rules: $($publisherRules.Count)"
    Write-Host "  Hash rules: $($hashRules.Count)"
    if ($softwareListRulesXml.Count -gt 0) {
        Write-Host "  Software list rules: $($softwareListRulesXml.Count)" -ForegroundColor Cyan
    }
    if ($eventApps.Count -gt 0) {
        Write-Host "  Blocked events processed: $($eventApps.Count)" -ForegroundColor Yellow
    }
    Write-Host "  Deny rules: $($simplifiedDenyRules.Count)"
    Write-Host "  Enforcement: $EnforcementMode"
    Write-Host ""

    # Show data sources
    $hasDataSource = $SoftwareListPath -or $ScanPath -or $EventPath
    if ($hasDataSource) {
        Write-Host "Data Sources:" -ForegroundColor Yellow
        if ($SoftwareListPath) { Write-Host "  Software List: $SoftwareListPath" }
        if ($ScanPath) { Write-Host "  Scan Data: $ScanPath" }
        if ($EventPath) { Write-Host "  Event Data: $EventPath" -ForegroundColor Yellow }
        Write-Host ""
    }

    Write-Host "To apply:" -ForegroundColor Cyan
    Write-Host "  Set-AppLockerPolicy -XmlPolicy `"$policyPath`"" -ForegroundColor White
    Write-Host ""

    return $policyPath
}
#endregion

#==============================================================================
# BUILD GUIDE MODE - Enterprise deployment with proper principal scoping
#==============================================================================

#region Banner and Configuration Display
Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    AppLocker Policy Generator (Build Guide)                   ║
║                                                                              ║
║  "Allow who may run trusted code, deny where code can never run"             ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Target Type: $TargetType" -ForegroundColor Gray
Write-Host "  Domain: $DomainName" -ForegroundColor Gray
Write-Host "  Phase: $Phase" -ForegroundColor Gray
Write-Host "  Enforcement: $EnforcementMode" -ForegroundColor Gray
Write-Host ""
#endregion

#region Set default group names if not provided
if (-not $AdminsGroup) { $AdminsGroup = "$DomainName\AppLocker-Admins" }
if (-not $StandardUsersGroup) { $StandardUsersGroup = "$DomainName\AppLocker-StandardUsers" }
if (-not $ServiceAccountsGroup) { $ServiceAccountsGroup = "$DomainName\AppLocker-ServiceAccounts" }
if (-not $InstallersGroup) { $InstallersGroup = "$DomainName\AppLocker-Installers" }

Write-Host "Security Groups:" -ForegroundColor Yellow
Write-Host "  Admins: $AdminsGroup" -ForegroundColor Gray
Write-Host "  Standard Users: $StandardUsersGroup" -ForegroundColor Gray
Write-Host "  Service Accounts: $ServiceAccountsGroup" -ForegroundColor Gray
Write-Host "  Installers: $InstallersGroup" -ForegroundColor Gray
Write-Host ""
#endregion

#region Resolve all SIDs
Write-Host "Resolving Security Identifiers..." -ForegroundColor Cyan

$sids = @{
    # Mandatory Allow Principals (Build Guide requirement)
    SYSTEM = Resolve-AccountToSid "NT AUTHORITY\SYSTEM"
    LocalService = Resolve-AccountToSid "NT AUTHORITY\LOCAL SERVICE"
    NetworkService = Resolve-AccountToSid "NT AUTHORITY\NETWORK SERVICE"
    BuiltinAdmins = Resolve-AccountToSid "BUILTIN\Administrators"
    Everyone = Resolve-AccountToSid "Everyone"

    # Custom AppLocker Groups
    Admins = Resolve-AccountToSid $AdminsGroup
    StandardUsers = Resolve-AccountToSid $StandardUsersGroup
    ServiceAccounts = Resolve-AccountToSid $ServiceAccountsGroup
    Installers = Resolve-AccountToSid $InstallersGroup
}

Write-Host "  SYSTEM: $($sids.SYSTEM)" -ForegroundColor DarkGray
Write-Host "  Admins Group: $($sids.Admins)" -ForegroundColor DarkGray
Write-Host ""
#endregion

#region Load vendor publishers from software list and/or scan data
$vendorPubs = @()

# Load from software list if provided
if ($SoftwareListPath -and (Test-Path $SoftwareListPath)) {
    Write-Host "Loading vendor publishers from software list..." -ForegroundColor Cyan

    $softwareList = Get-SoftwareList -ListPath $SoftwareListPath
    $approvedItems = $softwareList.items | Where-Object { $_.approved -eq $true -and $_.ruleType -eq "Publisher" }

    foreach ($item in $approvedItems) {
        if ($item.publisher -and $item.publisher -notmatch "MICROSOFT") {
            $vendorPubs += $item.publisher
        }
    }
    Write-Host "  Found $($vendorPubs.Count) vendor publishers from software list" -ForegroundColor Gray
}

# Load from scan data if requested
if ($IncludeVendorPublishers -and $ScanPath -and (Test-Path $ScanPath)) {
    Write-Host "Loading vendor publishers from scan data..." -ForegroundColor Cyan

    $publisherFiles = Get-ChildItem -Path $ScanPath -Filter "Publishers.csv" -Recurse
    foreach ($file in $publisherFiles) {
        $pubs = Import-Csv -Path $file.FullName
        foreach ($pub in $pubs) {
            if ($pub.Publisher -and $pub.Publisher -notmatch "MICROSOFT") {
                $vendorPubs += $pub.Publisher
            }
        }
    }
    $vendorPubs = $vendorPubs | Select-Object -Unique
    Write-Host "  Found $($vendorPubs.Count) unique vendor publishers from scans" -ForegroundColor Gray
}

# Add manually specified vendors
$vendorPubs += $VendorPublishers
$vendorPubs = $vendorPubs | Select-Object -Unique
#endregion

#region Explicit Deny Paths (Build Guide requirement)
# Load deny paths from config or use defaults
$denyPaths = if ($config -and $config.DefaultDenyPaths) {
    $config.DefaultDenyPaths | ForEach-Object { @{ Path = $_.Path; Desc = $_.Description } }
}
else {
    @(
        @{ Path = "%USERPROFILE%\Downloads\*"; Desc = "User Downloads folder" },
        @{ Path = "%APPDATA%\*"; Desc = "Roaming AppData" },
        @{ Path = "%LOCALAPPDATA%\Temp\*"; Desc = "Local Temp folder" },
        @{ Path = "%TEMP%\*"; Desc = "System Temp folder" },
        @{ Path = "%USERPROFILE%\Desktop\*"; Desc = "User Desktop" }
    )
}

# Additional deny paths for servers/DCs
if ($TargetType -in @("Server", "DomainController")) {
    $serverPaths = if ($config -and $config.ServerDenyPaths) {
        $config.ServerDenyPaths | ForEach-Object { @{ Path = $_.Path; Desc = $_.Description } }
    }
    else {
        @(
            @{ Path = "C:\inetpub\wwwroot\*"; Desc = "IIS Web Root" },
            @{ Path = "%SYSTEMDRIVE%\Temp\*"; Desc = "System Temp" }
        )
    }
    $denyPaths += $serverPaths
}
#endregion

#region Helper function aliases for module functions
# Using New-AppLockerRuleXml, New-PathConditionXml, New-PublisherConditionXml from Common.psm1
#endregion

#region Build EXE Rules
Write-Host "Building EXE Rules..." -ForegroundColor Yellow

$exeRules = ""

# === MANDATORY PRINCIPALS - Microsoft Publisher ===
# Build Guide: Microsoft Publisher → SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Administrators (NOT Everyone)

foreach ($principal in @(
    @{ Name = "SYSTEM"; Sid = $sids.SYSTEM },
    @{ Name = "LOCAL SERVICE"; Sid = $sids.LocalService },
    @{ Name = "NETWORK SERVICE"; Sid = $sids.NetworkService },
    @{ Name = "BUILTIN\Administrators"; Sid = $sids.BuiltinAdmins }
)) {
    $exeRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Microsoft) All Microsoft-signed - $($principal.Name)" `
        -Description "Allow Microsoft-signed executables for $($principal.Name)" `
        -Sid $principal.Sid `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
    $exeRules += "`n"
}

# === APPLOCKER-ADMINS ===
# Build Guide: Admins → Microsoft + approved vendor publishers (still blocked by Deny paths)

$exeRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
    -Name "(Admins) Microsoft Publisher" `
    -Description "Allow Microsoft-signed for AppLocker Admins" `
    -Sid $sids.Admins `
    -Action "Allow" `
    -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
$exeRules += "`n"

foreach ($vendor in $vendorPubs) {
    $exeRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Admins) Vendor: $vendor" `
        -Description "Allow vendor-signed for AppLocker Admins" `
        -Sid $sids.Admins `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=$vendor*")
    $exeRules += "`n"
}

# === APPLOCKER-SERVICE-ACCOUNTS ===
# Build Guide: Service Accounts → Vendor Publisher only (no path allows)

foreach ($vendor in $vendorPubs) {
    $exeRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Service) Vendor: $vendor" `
        -Description "Allow vendor-signed for Service Accounts" `
        -Sid $sids.ServiceAccounts `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=$vendor*")
    $exeRules += "`n"
}

# === APPLOCKER-STANDARDUSERS ===
# Build Guide: Users → Explicitly approved vendor apps only
# For Standard Users, we allow from safe paths but vendors must be explicit

$exeRules += New-AppLockerRuleXml -Type "FilePathRule" `
    -Name "(Users) Windows Directory" `
    -Description "Allow execution from Windows for Standard Users" `
    -Sid $sids.StandardUsers `
    -Action "Allow" `
    -Condition (New-PathConditionXml -Path "%WINDIR%\*")
$exeRules += "`n"

$exeRules += New-AppLockerRuleXml -Type "FilePathRule" `
    -Name "(Users) Program Files" `
    -Description "Allow execution from Program Files for Standard Users" `
    -Sid $sids.StandardUsers `
    -Action "Allow" `
    -Condition (New-PathConditionXml -Path "%PROGRAMFILES%\*")
$exeRules += "`n"

# === EXPLICIT DENY RULES (Everyone) ===
# Build Guide: These override ALL allows including SYSTEM

if (-not $SkipDenyRules) {
    foreach ($deny in $denyPaths) {
        $exeRules += New-AppLockerRuleXml -Type "FilePathRule" `
            -Name "(DENY) $($deny.Desc)" `
            -Description "Block execution from $($deny.Path)" `
            -Sid $sids.Everyone `
            -Action "Deny" `
            -Condition (New-PathConditionXml -Path $deny.Path)
        $exeRules += "`n"
    }
}

Write-Host "  EXE rules created" -ForegroundColor Green
#endregion

#region Build Script Rules (Phase 2+)
$scriptRules = ""

if ($Phase -ge 2) {
    Write-Host "Building Script Rules..." -ForegroundColor Yellow

    # Build Guide: Scripts - Highest Risk
    # Allow: SYSTEM → Microsoft, Admins → Microsoft, Service Accounts → Vendor
    # Do NOT allow: Standard Users, Everyone

    foreach ($principal in @(
        @{ Name = "SYSTEM"; Sid = $sids.SYSTEM },
        @{ Name = "LOCAL SERVICE"; Sid = $sids.LocalService },
        @{ Name = "NETWORK SERVICE"; Sid = $sids.NetworkService },
        @{ Name = "BUILTIN\Administrators"; Sid = $sids.BuiltinAdmins }
    )) {
        $scriptRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Microsoft) Scripts - $($principal.Name)" `
            -Description "Allow Microsoft-signed scripts for $($principal.Name)" `
            -Sid $principal.Sid `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
        $scriptRules += "`n"
    }

    # Admins - Microsoft scripts only
    $scriptRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Admins) Microsoft Scripts" `
        -Description "Allow Microsoft-signed scripts for AppLocker Admins" `
        -Sid $sids.Admins `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
    $scriptRules += "`n"

    # Service Accounts - Vendor scripts if required
    foreach ($vendor in $vendorPubs) {
        $scriptRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Service) Vendor Scripts: $vendor" `
            -Description "Allow vendor-signed scripts for Service Accounts" `
            -Sid $sids.ServiceAccounts `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=$vendor*")
        $scriptRules += "`n"
    }

    # Explicit deny for scripts in user-writable paths
    if (-not $SkipDenyRules) {
        foreach ($deny in $denyPaths) {
            $scriptRules += New-AppLockerRuleXml -Type "FilePathRule" `
                -Name "(DENY) Scripts - $($deny.Desc)" `
                -Description "Block scripts from $($deny.Path)" `
                -Sid $sids.Everyone `
                -Action "Deny" `
                -Condition (New-PathConditionXml -Path $deny.Path)
            $scriptRules += "`n"
        }
    }

    Write-Host "  Script rules created" -ForegroundColor Green
}
#endregion

#region Build MSI Rules (Phase 3+)
$msiRules = ""

if ($Phase -ge 3) {
    Write-Host "Building MSI/Installer Rules..." -ForegroundColor Yellow

    # Build Guide: MSI - Allow SYSTEM → Microsoft, Installers → Vendor, Admins → Vendor

    foreach ($principal in @(
        @{ Name = "SYSTEM"; Sid = $sids.SYSTEM },
        @{ Name = "BUILTIN\Administrators"; Sid = $sids.BuiltinAdmins }
    )) {
        $msiRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Microsoft) MSI - $($principal.Name)" `
            -Description "Allow Microsoft installers for $($principal.Name)" `
            -Sid $principal.Sid `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
        $msiRules += "`n"
    }

    # Installers group - vendor installers
    $msiRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Installers) Microsoft MSI" `
        -Description "Allow Microsoft installers for Installers group" `
        -Sid $sids.Installers `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
    $msiRules += "`n"

    foreach ($vendor in $vendorPubs) {
        $msiRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Installers) Vendor MSI: $vendor" `
            -Description "Allow vendor installers for Installers group" `
            -Sid $sids.Installers `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=$vendor*")
        $msiRules += "`n"
    }

    # Admins - vendor installers
    $msiRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Admins) Microsoft MSI" `
        -Description "Allow Microsoft installers for AppLocker Admins" `
        -Sid $sids.Admins `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
    $msiRules += "`n"

    foreach ($vendor in $vendorPubs) {
        $msiRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Admins) Vendor MSI: $vendor" `
            -Description "Allow vendor installers for AppLocker Admins" `
            -Sid $sids.Admins `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=$vendor*")
        $msiRules += "`n"
    }

    # Windows Installer cache
    $msiRules += New-AppLockerRuleXml -Type "FilePathRule" `
        -Name "(SYSTEM) Windows Installer Cache" `
        -Description "Allow MSI from Windows Installer cache" `
        -Sid $sids.SYSTEM `
        -Action "Allow" `
        -Condition (New-PathConditionXml -Path "%WINDIR%\Installer\*")
    $msiRules += "`n"

    Write-Host "  MSI rules created" -ForegroundColor Green
}
#endregion

#region Build DLL Rules (Phase 4 - Enable LAST)
$dllRules = ""

if ($Phase -ge 4) {
    Write-Host "Building DLL Rules (CAUTION: Enable last, audit 7-14 days first)..." -ForegroundColor Yellow

    # Build Guide: DLL - Allow SYSTEM → Microsoft, Admins → Microsoft, Service Accounts → Vendor

    foreach ($principal in @(
        @{ Name = "SYSTEM"; Sid = $sids.SYSTEM },
        @{ Name = "LOCAL SERVICE"; Sid = $sids.LocalService },
        @{ Name = "NETWORK SERVICE"; Sid = $sids.NetworkService },
        @{ Name = "BUILTIN\Administrators"; Sid = $sids.BuiltinAdmins }
    )) {
        $dllRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Microsoft) DLL - $($principal.Name)" `
            -Description "Allow Microsoft-signed DLLs for $($principal.Name)" `
            -Sid $principal.Sid `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
        $dllRules += "`n"
    }

    # Admins - Microsoft DLLs
    $dllRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
        -Name "(Admins) Microsoft DLL" `
        -Description "Allow Microsoft-signed DLLs for AppLocker Admins" `
        -Sid $sids.Admins `
        -Action "Allow" `
        -Condition (New-PublisherConditionXml -Publisher "O=MICROSOFT CORPORATION*")
    $dllRules += "`n"

    # Service Accounts - Vendor DLLs
    foreach ($vendor in $vendorPubs) {
        $dllRules += New-AppLockerRuleXml -Type "FilePublisherRule" `
            -Name "(Service) Vendor DLL: $vendor" `
            -Description "Allow vendor-signed DLLs for Service Accounts" `
            -Sid $sids.ServiceAccounts `
            -Action "Allow" `
            -Condition (New-PublisherConditionXml -Publisher "O=$vendor*")
        $dllRules += "`n"
    }

    Write-Host "  DLL rules created (remember: audit 7-14 days before enforcing)" -ForegroundColor Green
}
#endregion

#region Assemble Final Policy XML
Write-Host "`nAssembling policy XML..." -ForegroundColor Cyan

# Determine enforcement modes
$exeMode = $EnforcementMode
$scriptMode = if ($Phase -ge 2) { $EnforcementMode } else { "NotConfigured" }
$msiMode = if ($Phase -ge 3) { $EnforcementMode } else { "NotConfigured" }
$dllMode = if ($Phase -ge 4) { $DLLEnforcement } else { "NotConfigured" }

$policyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<!--
  ============================================================================
  AppLocker Policy - Generated by Build Guide Script
  ============================================================================
  Target: $TargetType
  Domain: $DomainName
  Phase: $Phase
  Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

  ============================================================================
  SECURITY DESIGN RATIONALE
  ============================================================================

  This policy implements a least-privilege application control strategy aligned
  with NIST SP 800-167, CIS Controls, and DISA STIG requirements.

  PRINCIPAL-BASED RULE SCOPING:

  1. SYSTEM/Administrators - Publisher-based rules (Microsoft + Vendors)
     Rationale: Administrative contexts require flexibility to run signed
     management tools, scripts, and utilities from any location.

  2. Standard Users - Path-based rules only (%PROGRAMFILES%, %WINDIR%)
     Rationale: Standard users can execute software ONLY from administrator-
     protected directories. This ensures that even validly-signed malicious
     software cannot execute from user-writable locations (Downloads, %TEMP%,
     %APPDATA%, Desktop, etc.).

  3. Service Accounts - Publisher-based rules (Approved Vendors only)
     Rationale: Service accounts require specific vendor software but should
     not have blanket path-based execution rights.

  WHY PATH-BASED FOR STANDARD USERS (Inspector Explanation):

  We deliberately chose path-based rules over publisher-based rules for
  standard users because:

  a) DEFENSE IN DEPTH: Code signing certificates can be stolen or compromised
     (ref: SolarWinds 2020, CCleaner 2017, ASUS ShadowHammer 2019). Path-based
     rules ensure that even legitimately-signed malware dropped in user-writable
     locations cannot execute.

  b) LEAST PRIVILEGE: Users can only execute software that administrators have
     explicitly installed to protected directories. This prevents execution of:
     - Portable applications downloaded by users
     - Malware masquerading as legitimate software
     - Unauthorized software installations

  c) AUDIT TRAIL: All executable software must pass through admin-controlled
     installation, creating a clear chain of custody.

  d) ATTACK SURFACE REDUCTION: By limiting execution to protected paths, we
     eliminate entire classes of attacks that rely on dropping payloads in
     user-writable locations.

  EXPLICIT DENY RULES:

  User-writable paths are explicitly denied to prevent bypass attempts:
  - %USERPROFILE%\Downloads\*
  - %USERPROFILE%\Desktop\*
  - %TEMP%\*
  - %APPDATA%\*
  - %LOCALAPPDATA%\*

  REFERENCES:
  - NIST SP 800-167: Guide to Application Whitelisting
  - CIS Control 2: Inventory and Control of Software Assets
  - DISA STIG: Application Control Requirements
  - Microsoft Security Baseline: AppLocker Recommendations

  ============================================================================
  IMPORTANT: Audit mode recommended for 14+ days before enforcement!
  ============================================================================
-->
<AppLockerPolicy Version="1">
  <!-- EXE Rules - Phase 1+ -->
  <RuleCollection Type="Exe" EnforcementMode="$exeMode">
$exeRules  </RuleCollection>

  <!-- Script Rules - Phase 2+ (Highest Risk) -->
  <RuleCollection Type="Script" EnforcementMode="$scriptMode">
$scriptRules  </RuleCollection>

  <!-- MSI/Installer Rules - Phase 3+ -->
  <RuleCollection Type="Msi" EnforcementMode="$msiMode">
$msiRules  </RuleCollection>

  <!-- DLL Rules - Phase 4 (Enable LAST, audit 7-14 days) -->
  <RuleCollection Type="Dll" EnforcementMode="$dllMode">
$dllRules  </RuleCollection>

  <!-- Packaged Apps (APPX) -->
  <RuleCollection Type="Appx" EnforcementMode="$exeMode">
    <FilePublisherRule Id="$([Guid]::NewGuid().ToString())" Name="(Microsoft) Store Apps" Description="Allow Microsoft-signed packaged apps" UserOrGroupSid="$($sids.Everyone)" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@
#endregion

#region Save Policy
$policyFileName = "AppLockerPolicy-$TargetType-Phase$Phase-$EnforcementMode-$timestamp.xml"
$policyPath = Join-Path $OutputPath $policyFileName

# Build summary for -WhatIf support
$policySummary = [PSCustomObject]@{
    Mode = "BuildGuide"
    TargetType = $TargetType
    DomainName = $DomainName
    Phase = $Phase
    EnforcementModes = @{
        Exe = $exeMode
        Script = $scriptMode
        Msi = $msiMode
        Dll = $dllMode
    }
    VendorPublishers = $vendorPubs.Count
    DenyPaths = $denyPaths.Count
    SecurityGroups = @{
        Admins = $AdminsGroup
        StandardUsers = $StandardUsersGroup
        ServiceAccounts = $ServiceAccountsGroup
        Installers = $InstallersGroup
    }
    OutputPath = $policyPath
}

# -WhatIf support: Show what would be created without actually creating
if ($WhatIfPreference -or $PSCmdlet.ShouldProcess($policyPath, "Create AppLocker policy file")) {
    if ($WhatIfPreference) {
        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║               WHAT-IF: POLICY PREVIEW (Build Guide Mode)                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        Write-Host "Would create policy file:" -ForegroundColor Yellow
        Write-Host "  $policyPath" -ForegroundColor White
        Write-Host ""
        Write-Host "Policy Configuration:" -ForegroundColor Yellow
        Write-Host "  Target Type: $TargetType" -ForegroundColor Gray
        Write-Host "  Domain: $DomainName" -ForegroundColor Gray
        Write-Host "  Phase: $Phase of 4" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Rule Collections:" -ForegroundColor Yellow
        Write-Host "  EXE Rules: $exeMode" -ForegroundColor Gray
        Write-Host "  Script Rules: $scriptMode" -ForegroundColor Gray
        Write-Host "  MSI Rules: $msiMode" -ForegroundColor Gray
        Write-Host "  DLL Rules: $dllMode" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Vendor Publishers ($($vendorPubs.Count) total):" -ForegroundColor Yellow
        if ($vendorPubs.Count -gt 0) {
            $vendorPubs | Select-Object -First 10 | ForEach-Object {
                Write-Host "    - $_" -ForegroundColor DarkGray
            }
            if ($vendorPubs.Count -gt 10) {
                Write-Host "    ... and $($vendorPubs.Count - 10) more" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    (none - only Microsoft publishers)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "Deny Paths ($($denyPaths.Count) total):" -ForegroundColor Yellow
        foreach ($deny in $denyPaths) {
            Write-Host "    - $($deny.Desc): $($deny.Path)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "Security Groups Required:" -ForegroundColor Yellow
        Write-Host "  Admins: $AdminsGroup" -ForegroundColor Gray
        Write-Host "  Standard Users: $StandardUsersGroup" -ForegroundColor Gray
        Write-Host "  Service Accounts: $ServiceAccountsGroup" -ForegroundColor Gray
        Write-Host "  Installers: $InstallersGroup" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Run without -WhatIf to create the policy file." -ForegroundColor Cyan
        Write-Host ""

        return $policySummary
    }

    # Actually create the file
    $policyXml | Out-File -FilePath $policyPath -Encoding UTF8
} else {
    # User cancelled via -Confirm:$false or other means
    Write-Host "Policy creation cancelled." -ForegroundColor Yellow
    return $null
}

Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           POLICY GENERATION COMPLETE                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "Policy File: $policyPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "  Target Type: $TargetType"
Write-Host "  Phase: $Phase of 4"
Write-Host "  EXE Rules: $exeMode"
Write-Host "  Script Rules: $scriptMode"
Write-Host "  MSI Rules: $msiMode"
Write-Host "  DLL Rules: $dllMode"
Write-Host "  Vendor Publishers: $($vendorPubs.Count)"
Write-Host ""

Write-Host "Security Groups Required in AD:" -ForegroundColor Yellow
Write-Host "  ☐ $AdminsGroup"
Write-Host "  ☐ $StandardUsersGroup"
Write-Host "  ☐ $ServiceAccountsGroup"
Write-Host "  ☐ $InstallersGroup"
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Yellow
switch ($Phase) {
    1 {
        Write-Host "  1. Create the AD groups listed above"
        Write-Host "  2. Apply policy via GPO in AUDIT mode"
        Write-Host "  3. Review Event ID 8004 in Application log"
        Write-Host "  4. When EXE audit is clean, run Phase 2"
    }
    2 {
        Write-Host "  1. Apply policy via GPO (still AUDIT mode)"
        Write-Host "  2. Review Script events - expect more blocks"
        Write-Host "  3. Add vendor script publishers if needed"
        Write-Host "  4. When Script audit is clean, run Phase 3"
    }
    3 {
        Write-Host "  1. Apply policy via GPO (still AUDIT mode)"
        Write-Host "  2. Test software installation workflows"
        Write-Host "  3. Verify SCCM/Intune/patches work"
        Write-Host "  4. When MSI audit is clean, run Phase 4"
    }
    4 {
        Write-Host "  1. Apply policy via GPO (still AUDIT mode)"
        Write-Host "  2. DLL rules: AUDIT FOR 7-14 DAYS minimum"
        Write-Host "  3. Review all 8004 events thoroughly"
        Write-Host "  4. Only then switch to -EnforcementMode Enabled"
    }
}
Write-Host ""
Write-Host "To apply policy:" -ForegroundColor Cyan
Write-Host "  Set-AppLockerPolicy -XmlPolicy `"$policyPath`"" -ForegroundColor White
Write-Host ""
#endregion

return $policyPath
