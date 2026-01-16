#Requires -Version 5.1

<#
.SYNOPSIS
    Scan local or remote computers and create importable AppLocker XML policies.

.DESCRIPTION
    This script scans a computer for:
    - Installed software
    - Executables in common paths
    - AppLocker events

    Then creates AppLocker XML policies that can be directly imported into Group Policy.

.PARAMETER ComputerName
    The computer to scan. Defaults to localhost.

.PARAMETER OutputPath
    Where to save scan results and policies. Defaults to C:\GA-AppLocker\Scans

.PARAMETER IncludeEvents
    Include AppLocker events in the scan (local only).

.PARAMETER CreatePolicy
    Create AppLocker XML policy from scan results.

.PARAMETER PolicyMode
    Policy enforcement mode: Audit or Enforce. Defaults to Audit.

.PARAMETER MergeWithPolicy
    Path to existing policy XML to merge new rules into.

.PARAMETER ApplyToLocalGPO
    Apply the policy directly to local Group Policy (requires admin).

.PARAMETER MergeWhenApplying
    When using -ApplyToLocalGPO, merge with existing rules instead of replacing.

.EXAMPLE
    .\Scan-And-CreateAppLockerPolicy.ps1
    Scans local computer and creates Audit policy.

.EXAMPLE
    .\Scan-And-CreateAppLockerPolicy.ps1 -ComputerName "SERVER01"
    Scans remote computer SERVER01.

.EXAMPLE
    .\Scan-And-CreateAppLockerPolicy.ps1 -ComputerName "PC1","PC2","PC3" -CreatePolicy -PolicyMode Enforce
    Scans multiple computers and creates Enforce policies.

.EXAMPLE
    .\Scan-And-CreateAppLockerPolicy.ps1 -MergeWithPolicy "C:\Policies\BasePolicy.xml"
    Scans local computer and merges results with existing policy.

.EXAMPLE
    .\Scan-And-CreateAppLockerPolicy.ps1 -ApplyToLocalGPO -MergeWhenApplying
    Scans and applies policy to local GPO, merging with existing rules.

.EXAMPLE
    # Scan multiple computers and merge all into one policy:
    $policy = "C:\GA-AppLocker\Scans\MasterPolicy.xml"
    "PC1","PC2","PC3" | ForEach-Object {
        .\Scan-And-CreateAppLockerPolicy.ps1 -ComputerName $_ -MergeWithPolicy $policy
    }

.NOTES
    Output XML can be imported using:
    - AppLocker GPO Editor: Import Policy...
    - PowerShell: Set-AppLockerPolicy -XmlPolicy (Get-Content policy.xml)
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias("CN", "Name")]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [string]$OutputPath = "C:\GA-AppLocker\Scans",

    [switch]$IncludeEvents,

    [switch]$CreatePolicy,

    [ValidateSet("Audit", "Enforce")]
    [string]$PolicyMode = "Audit",

    # Merge with existing policy file instead of creating new
    [string]$MergeWithPolicy,

    # Apply directly to local GPO (requires admin)
    [switch]$ApplyToLocalGPO,

    # Merge when applying (don't replace existing rules)
    [switch]$MergeWhenApplying
)

begin {
    # Ensure output path exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $allArtifacts = @()
    $allPublishers = @{}

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " AppLocker Artifact Scanner" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Timestamp: $timestamp" -ForegroundColor White
    Write-Host "Output: $OutputPath" -ForegroundColor White
    Write-Host ""
}

process {
    foreach ($computer in $ComputerName) {
        Write-Host "--- Scanning: $computer ---" -ForegroundColor Yellow

        $isLocal = ($computer -eq $env:COMPUTERNAME) -or ($computer -eq "localhost") -or ($computer -eq ".")
        $computerFolder = Join-Path $OutputPath "${computer}_${timestamp}"

        if (-not (Test-Path $computerFolder)) {
            New-Item -ItemType Directory -Path $computerFolder -Force | Out-Null
        }

        $computerArtifacts = @()

        # ============================================
        # 1. INSTALLED SOFTWARE
        # ============================================
        Write-Host "  [1/4] Scanning installed software..." -ForegroundColor Gray
        try {
            $installedSoftware = @()

            if ($isLocal) {
                # Local scan
                $regPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )

                foreach ($regPath in $regPaths) {
                    if (Test-Path $regPath) {
                        Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName } |
                            ForEach-Object {
                                $installedSoftware += [PSCustomObject]@{
                                    Computer = $computer
                                    Name = $_.DisplayName
                                    Version = $_.DisplayVersion
                                    Publisher = $_.Publisher
                                    InstallLocation = $_.InstallLocation
                                }
                            }
                    }
                }
            } else {
                # Remote scan using registry provider
                try {
                    $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computer)
                    $uninstallKey = $remoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")

                    if ($uninstallKey) {
                        foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                            try {
                                $subKey = $uninstallKey.OpenSubKey($subKeyName)
                                $displayName = $subKey.GetValue("DisplayName")
                                if ($displayName) {
                                    $installedSoftware += [PSCustomObject]@{
                                        Computer = $computer
                                        Name = $displayName
                                        Version = $subKey.GetValue("DisplayVersion")
                                        Publisher = $subKey.GetValue("Publisher")
                                        InstallLocation = $subKey.GetValue("InstallLocation")
                                    }
                                }
                                $subKey.Close()
                            } catch { }
                        }
                        $uninstallKey.Close()
                    }
                    $remoteReg.Close()
                } catch {
                    Write-Host "    Could not access remote registry: $($_.Exception.Message)" -ForegroundColor Red
                }
            }

            $installedSoftware = $installedSoftware | Sort-Object Name -Unique
            $softwarePath = Join-Path $computerFolder "InstalledSoftware.csv"
            $installedSoftware | Export-Csv -Path $softwarePath -NoTypeInformation -Encoding UTF8
            Write-Host "    Found $($installedSoftware.Count) installed programs" -ForegroundColor Green

        } catch {
            Write-Host "    Error scanning software: $($_.Exception.Message)" -ForegroundColor Red
        }

        # ============================================
        # 2. EXECUTABLES
        # ============================================
        Write-Host "  [2/4] Scanning executables..." -ForegroundColor Gray
        try {
            $executables = @()

            $scanPaths = @(
                "Program Files",
                "Program Files (x86)"
            )

            foreach ($basePath in $scanPaths) {
                $fullPath = if ($isLocal) {
                    Join-Path $env:SystemDrive $basePath
                } else {
                    "\\$computer\C`$\$basePath"
                }

                if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $fullPath -Recurse -File -Include "*.exe" -ErrorAction SilentlyContinue |
                        Select-Object -First 500 |
                        ForEach-Object {
                            try {
                                $file = $_
                                $vInfo = $file.VersionInfo
                                $publisher = if ($vInfo.CompanyName) { $vInfo.CompanyName.Trim() } else { "Unknown" }
                                $product = if ($vInfo.ProductName) { $vInfo.ProductName.Trim() } else { "" }
                                $version = if ($vInfo.FileVersion) { $vInfo.FileVersion.Trim() } else { "" }

                                # Track publisher for policy creation
                                if ($publisher -ne "Unknown" -and -not $allPublishers.ContainsKey($publisher)) {
                                    $allPublishers[$publisher] = @{
                                        Publisher = $publisher
                                        Product = $product
                                        Count = 0
                                    }
                                }
                                if ($publisher -ne "Unknown") {
                                    $allPublishers[$publisher].Count++
                                }

                                $executables += [PSCustomObject]@{
                                    Computer = $computer
                                    FileName = $file.Name
                                    FullPath = $file.FullName
                                    Publisher = $publisher
                                    Product = $product
                                    Version = $version
                                }

                                $computerArtifacts += [PSCustomObject]@{
                                    Computer = $computer
                                    Type = "Executable"
                                    Name = $file.Name
                                    Path = $file.FullName
                                    Publisher = $publisher
                                    Product = $product
                                    Version = $version
                                }
                            } catch { }
                        }
                }
            }

            $execPath = Join-Path $computerFolder "Executables.csv"
            $executables | Export-Csv -Path $execPath -NoTypeInformation -Encoding UTF8
            Write-Host "    Found $($executables.Count) executables" -ForegroundColor Green

            $allArtifacts += $computerArtifacts

        } catch {
            Write-Host "    Error scanning executables: $($_.Exception.Message)" -ForegroundColor Red
        }

        # ============================================
        # 3. APPLOCKER EVENTS (Local Only)
        # ============================================
        if ($IncludeEvents -and $isLocal) {
            Write-Host "  [3/4] Scanning AppLocker events..." -ForegroundColor Gray
            try {
                $events = @()
                $logNames = @(
                    "Microsoft-Windows-AppLocker/EXE and DLL",
                    "Microsoft-Windows-AppLocker/MSI and Script",
                    "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                    "Microsoft-Windows-AppLocker/Packaged app-Execution"
                )

                foreach ($logName in $logNames) {
                    try {
                        Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction SilentlyContinue |
                            ForEach-Object {
                                $events += [PSCustomObject]@{
                                    Computer = $computer
                                    TimeCreated = $_.TimeCreated
                                    Id = $_.Id
                                    Level = $_.LevelDisplayName
                                    Message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
                                }
                            }
                    } catch { }
                }

                if ($events.Count -gt 0) {
                    $eventsPath = Join-Path $computerFolder "AppLockerEvents.csv"
                    $events | Export-Csv -Path $eventsPath -NoTypeInformation -Encoding UTF8
                    Write-Host "    Found $($events.Count) events" -ForegroundColor Green
                } else {
                    Write-Host "    No AppLocker events found" -ForegroundColor Gray
                }
            } catch {
                Write-Host "    Error scanning events: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  [3/4] Skipping events (local only or not requested)" -ForegroundColor Gray
        }

        # ============================================
        # 4. PUBLISHERS SUMMARY
        # ============================================
        Write-Host "  [4/4] Creating publishers list..." -ForegroundColor Gray
        $publisherList = $allPublishers.Values | ForEach-Object {
            [PSCustomObject]@{
                Publisher = $_.Publisher
                SampleProduct = $_.Product
                FileCount = $_.Count
            }
        } | Sort-Object FileCount -Descending

        $publishersPath = Join-Path $computerFolder "Publishers.csv"
        $publisherList | Export-Csv -Path $publishersPath -NoTypeInformation -Encoding UTF8
        Write-Host "    Found $($publisherList.Count) unique publishers" -ForegroundColor Green

        Write-Host "  Scan complete for $computer" -ForegroundColor Green
        Write-Host ""
    }
}

end {
    # ============================================
    # CREATE APPLOCKER POLICY
    # ============================================
    if ($CreatePolicy -or $true) {  # Always create policy
        Write-Host "--- Creating AppLocker Policy ---" -ForegroundColor Yellow

        $enforcementMode = if ($PolicyMode -eq "Enforce") { "Enabled" } else { "AuditOnly" }

        # Build AppLocker policy XML
        $policyXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$enforcementMode">
    <!-- Default rules to allow Windows and Program Files -->
    <FilePathRule Id="$(New-Guid)" Name="Allow Windows" Description="Allows execution from Windows directory" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow Program Files" Description="Allows execution from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow Program Files (x86)" Description="Allows execution from Program Files (x86)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*"/>
      </Conditions>
    </FilePathRule>
"@

        # Add publisher rules for discovered publishers
        $topPublishers = $allPublishers.Values | Sort-Object Count -Descending | Select-Object -First 20
        foreach ($pub in $topPublishers) {
            if ($pub.Publisher -and $pub.Publisher -ne "Unknown" -and $pub.Publisher.Trim() -ne "") {
                $escapedPublisher = [System.Security.SecurityElement]::Escape($pub.Publisher)
                $escapedProduct = if ($pub.Product) { [System.Security.SecurityElement]::Escape($pub.Product) } else { "*" }

                $policyXml += @"

    <FilePublisherRule Id="$(New-Guid)" Name="Allow $escapedPublisher" Description="Publisher rule for $escapedPublisher" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*$escapedPublisher*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@
            }
        }

        $policyXml += @"

  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="$enforcementMode">
    <FilePathRule Id="$(New-Guid)" Name="Allow Windows Installer" Description="Allow Windows Installer files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="$enforcementMode">
    <FilePathRule Id="$(New-Guid)" Name="Allow Windows Scripts" Description="Allow scripts from Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="$(New-Guid)" Name="Allow Program Files Scripts" Description="Allow scripts from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured"/>
</AppLockerPolicy>
"@

        # Save policy
        $policyFileName = "AppLocker-Policy-${PolicyMode}-${timestamp}.xml"
        $policyPath = Join-Path $OutputPath $policyFileName

        # Save with UTF-16 encoding (required for AppLocker)
        $policyXml | Out-File -FilePath $policyPath -Encoding Unicode

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host " SCAN COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Results saved to: $OutputPath" -ForegroundColor White
        Write-Host ""
        Write-Host "AppLocker Policy: $policyPath" -ForegroundColor Yellow
        Write-Host "Policy Mode: $PolicyMode" -ForegroundColor White
        Write-Host ""

        # If merging with existing policy
        if ($MergeWithPolicy -and (Test-Path $MergeWithPolicy)) {
            Write-Host "--- Merging with existing policy ---" -ForegroundColor Yellow
            try {
                # Load existing policy
                [xml]$existingPolicy = Get-Content $MergeWithPolicy -Encoding Unicode
                [xml]$newPolicy = Get-Content $policyPath -Encoding Unicode

                # Merge rules from new policy into existing
                foreach ($newCollection in $newPolicy.AppLockerPolicy.RuleCollection) {
                    $existingCollection = $existingPolicy.AppLockerPolicy.RuleCollection |
                        Where-Object { $_.Type -eq $newCollection.Type }

                    if ($existingCollection) {
                        # Add new rules to existing collection
                        foreach ($rule in $newCollection.ChildNodes) {
                            if ($rule.NodeType -eq 'Element') {
                                $importedRule = $existingPolicy.ImportNode($rule, $true)
                                $existingCollection.AppendChild($importedRule) | Out-Null
                            }
                        }
                    }
                }

                # Save merged policy
                $mergedPath = $policyPath -replace '\.xml$', '-MERGED.xml'
                $existingPolicy.Save($mergedPath)
                Write-Host "Merged policy saved to: $mergedPath" -ForegroundColor Green
                $policyPath = $mergedPath
            } catch {
                Write-Host "Merge failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # Apply to local GPO if requested
        if ($ApplyToLocalGPO) {
            Write-Host ""
            Write-Host "--- Applying to Local GPO ---" -ForegroundColor Yellow
            try {
                $applyParams = @{
                    XmlPolicy = $policyPath
                }
                if ($MergeWhenApplying) {
                    $applyParams["Merge"] = $true
                    Write-Host "Merging with existing local policy..." -ForegroundColor Gray
                } else {
                    Write-Host "Replacing local policy..." -ForegroundColor Gray
                }

                Set-AppLockerPolicy @applyParams -ErrorAction Stop
                Write-Host "Policy applied successfully!" -ForegroundColor Green
            } catch {
                Write-Host "Failed to apply: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Make sure you're running as Administrator." -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "TO IMPORT THIS POLICY:" -ForegroundColor Cyan
        Write-Host "  1. Open Group Policy Editor (gpedit.msc)" -ForegroundColor Gray
        Write-Host "  2. Navigate to: Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker" -ForegroundColor Gray
        Write-Host "  3. Right-click AppLocker > Import Policy..." -ForegroundColor Gray
        Write-Host "  4. Select: $policyPath" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Or use PowerShell (MERGE with existing):" -ForegroundColor Cyan
        Write-Host "  Set-AppLockerPolicy -XmlPolicy `"$policyPath`" -Merge" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Or use PowerShell (REPLACE existing):" -ForegroundColor Cyan
        Write-Host "  Set-AppLockerPolicy -XmlPolicy `"$policyPath`"" -ForegroundColor Gray
        Write-Host ""

        # Return the policy path for automation
        return @{
            Success = $true
            PolicyPath = $policyPath
            OutputFolder = $OutputPath
            ComputersScanned = $ComputerName
            ArtifactsFound = $allArtifacts.Count
            PublishersFound = $allPublishers.Count
        }
    }
}
