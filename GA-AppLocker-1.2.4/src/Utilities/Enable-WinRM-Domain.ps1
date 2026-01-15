<#
.SYNOPSIS
    Creates or removes a GPO to enable WinRM across all domain-joined computers.

.DESCRIPTION
    This script will:
    - Create: Create a new GPO to enable and configure WinRM, link it to targets,
      configure firewall exceptions, and optionally force GP refresh.
    - Remove: Find and delete the WinRM GPO and all its links.

.PARAMETER Remove
    When specified, removes the WinRM GPO instead of creating it.

.EXAMPLE
    # Create WinRM GPO (interactive)
    .\Enable-WinRM-Domain.ps1

.EXAMPLE
    # Remove WinRM GPO (interactive)
    .\Enable-WinRM-Domain.ps1 -Remove

.NOTES
    Run this script on a Domain Controller with RSAT tools installed.
    Requires Domain Admin or equivalent privileges.
#>

[CmdletBinding()]
param(
    [switch]$Remove
)

#Requires -Modules ActiveDirectory, GroupPolicy

$defaultGPOName = "Enable-WinRM"

if ($Remove) {
    # ==================== REMOVAL MODE ====================
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  WinRM GPO Removal" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # List existing GPOs that might be WinRM-related
    Write-Host "Searching for WinRM-related GPOs..." -ForegroundColor Gray
    $winrmGPOs = Get-GPO -All | Where-Object { $_.DisplayName -like "*WinRM*" }

    if ($winrmGPOs.Count -gt 0) {
        Write-Host "`nFound WinRM-related GPOs:" -ForegroundColor Yellow
        $gpoArray = @($winrmGPOs)  # Ensure it's an array
        $i = 1
        foreach ($g in $gpoArray) {
            Write-Host "  [$i] $($g.DisplayName) (Created: $($g.CreationTime))" -ForegroundColor White
            $i++
        }
        Write-Host ""
    } else {
        $gpoArray = @()
    }

    # Get GPO to remove - accept number or name
    $gpoInput = Read-Host "Enter number or GPO name (default: $defaultGPOName)"
    if ([string]::IsNullOrWhiteSpace($gpoInput)) {
        $gpoName = $defaultGPOName
    }
    elseif ($gpoInput -match "^\d+$" -and $gpoArray.Count -gt 0) {
        # User entered a number - look up from the list
        $idx = [int]$gpoInput - 1
        if ($idx -ge 0 -and $idx -lt $gpoArray.Count) {
            $gpoName = $gpoArray[$idx].DisplayName
        } else {
            Write-Host "`n[-] Invalid selection. Please enter a number between 1 and $($gpoArray.Count)." -ForegroundColor Red
            exit 1
        }
    }
    else {
        # User entered a name
        $gpoName = $gpoInput
    }

    # Check if GPO exists
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

    if ($null -eq $gpo) {
        Write-Host "`n[-] GPO '$gpoName' not found." -ForegroundColor Red
        Write-Host "    Use Get-GPO -All to list all GPOs." -ForegroundColor Gray
        exit 1
    }

    # Show GPO details
    Write-Host "`n--- GPO Details ---" -ForegroundColor Cyan
    Write-Host "Name:        $($gpo.DisplayName)" -ForegroundColor White
    Write-Host "ID:          $($gpo.Id)" -ForegroundColor Gray
    Write-Host "Created:     $($gpo.CreationTime)" -ForegroundColor Gray
    Write-Host "Modified:    $($gpo.ModificationTime)" -ForegroundColor Gray

    # Find all links
    Write-Host "`nSearching for GPO links..." -ForegroundColor Gray
    $domainDN = (Get-ADDomain).DistinguishedName

    $links = @()
    $allOUs = Get-ADOrganizationalUnit -Filter * -Properties gpLink
    foreach ($ou in $allOUs) {
        if ($ou.gpLink -like "*$($gpo.Id)*") {
            $links += $ou.DistinguishedName
        }
    }

    # Check domain root
    $domain = Get-ADDomain
    if ($domain.LinkedGroupPolicyObjects -like "*$($gpo.Id)*") {
        $links += $domainDN
    }

    if ($links.Count -gt 0) {
        Write-Host "`nGPO is linked to:" -ForegroundColor Yellow
        foreach ($link in $links) {
            Write-Host "  - $link" -ForegroundColor White
        }
    } else {
        Write-Host "`nNo links found for this GPO." -ForegroundColor Gray
    }

    # Confirmation
    Write-Host "`n--- WARNING ---" -ForegroundColor Red
    Write-Host "This will permanently delete the GPO and all its links." -ForegroundColor Red
    Write-Host "Computers will no longer receive WinRM configuration from this GPO." -ForegroundColor Yellow
    Write-Host "----------------`n" -ForegroundColor Red

    $confirm = Read-Host "Type 'DELETE' to confirm removal"
    if ($confirm -ne 'DELETE') {
        Write-Host "`nAborted. GPO was not removed." -ForegroundColor Yellow
        exit
    }

    # Remove GPO
    Write-Host "`nRemoving GPO '$gpoName'..." -ForegroundColor Cyan

    try {
        Remove-GPO -Name $gpoName -ErrorAction Stop
        Write-Host "[+] GPO '$gpoName' has been removed." -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to remove GPO: $_" -ForegroundColor Red
        exit 1
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Removal Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nNotes:" -ForegroundColor Yellow
    Write-Host "  - WinRM settings will remain until GP refresh or reconfiguration." -ForegroundColor White
    Write-Host "  - To force GP refresh: gpupdate /force" -ForegroundColor White
    Write-Host "  - To disable WinRM on a machine: Disable-PSRemoting -Force" -ForegroundColor White
    Write-Host ""

} else {
    # ==================== CREATION MODE ====================
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  WinRM Domain GPO Deployment Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Get domain info
    $currentDomain = (Get-ADDomain).DNSRoot
    $domainDN = (Get-ADDomain).DistinguishedName

    Write-Host "Detected Domain: " -NoNewline
    Write-Host "$currentDomain" -ForegroundColor Yellow
    Write-Host "Domain DN: " -NoNewline
    Write-Host "$domainDN" -ForegroundColor Yellow

    $confirmDomain = Read-Host "`nUse this domain? (Y/n)"
    if ($confirmDomain -eq 'n' -or $confirmDomain -eq 'N') {
        $customDomain = Read-Host "Enter domain FQDN (e.g., corp.contoso.com)"
        $currentDomain = $customDomain
        $domainDN = "DC=" + ($customDomain -replace '\.', ',DC=')
        Write-Host "Using: $domainDN" -ForegroundColor Yellow
    }

    # GPO Name
    $gpoName = Read-Host "`nGPO Name (default: $defaultGPOName)"
    if ([string]::IsNullOrWhiteSpace($gpoName)) { $gpoName = $defaultGPOName }

    # --- Discover Link Targets ---
    Write-Host "`n--- Discovering Link Targets ---" -ForegroundColor Cyan

    # Always include Domain Controllers OU
    $dcOU = "OU=Domain Controllers,$domainDN"
    Write-Host "  [Auto] Domain Controllers: $dcOU" -ForegroundColor Green

    # Find common OUs for servers and workstations
    $linkTargets = @()
    $linkTargets += [PSCustomObject]@{ Name = "Domain Controllers"; DN = $dcOU; Auto = $true }

    # Search for common OU names
    $commonOUNames = @("Servers", "Member Servers", "Server", "Workstations", "Computers", "Desktops", "Laptops", "Clients")
    $foundOUs = @()

    foreach ($ouName in $commonOUNames) {
        $ous = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue
        foreach ($ou in $ous) {
            if ($ou.DistinguishedName -notin $foundOUs) {
                $foundOUs += $ou.DistinguishedName
                Write-Host "  [Found] $($ou.Name): $($ou.DistinguishedName)" -ForegroundColor Yellow
            }
        }
    }

    # Also check default Computers container
    $defaultComputers = "CN=Computers,$domainDN"
    if (Get-ADObject -Identity $defaultComputers -ErrorAction SilentlyContinue) {
        Write-Host "  [Found] Default Computers Container: $defaultComputers" -ForegroundColor Yellow
        $foundOUs += $defaultComputers
    }

    # Link target selection
    Write-Host "`n--- Select Link Targets ---" -ForegroundColor Cyan
    Write-Host "  1. Domain Root (applies to ALL objects - recommended)" -ForegroundColor White
    Write-Host "  2. Select specific OUs from discovered list" -ForegroundColor White
    Write-Host "  3. Manually enter OUs" -ForegroundColor White
    $linkChoice = Read-Host "Choice (1/2/3, default: 1)"

    $selectedTargets = @()

    switch ($linkChoice) {
        '2' {
            # Build selection list
            $allTargets = @()
            $allTargets += [PSCustomObject]@{ Index = 1; Name = "Domain Controllers"; DN = $dcOU }
            $i = 2
            foreach ($ou in $foundOUs) {
                $ouObj = Get-ADObject -Identity $ou -Properties Name
                $allTargets += [PSCustomObject]@{ Index = $i; Name = $ouObj.Name; DN = $ou }
                $i++
            }

            Write-Host "`nAvailable targets:" -ForegroundColor Yellow
            foreach ($t in $allTargets) {
                Write-Host "  $($t.Index). $($t.Name) - $($t.DN)"
            }

            $selections = Read-Host "`nEnter numbers separated by commas (e.g., 1,2,3) or 'all'"

            if ($selections -eq 'all') {
                $selectedTargets = $allTargets.DN
            } else {
                $indices = $selections -split ',' | ForEach-Object { $_.Trim() }
                foreach ($idx in $indices) {
                    $target = $allTargets | Where-Object { $_.Index -eq [int]$idx }
                    if ($target) {
                        $selectedTargets += $target.DN
                    }
                }
            }
        }
        '3' {
            Write-Host "`nEnter OUs one per line. Enter blank line when done:" -ForegroundColor Yellow
            $selectedTargets += $dcOU  # Always include DCs
            Write-Host "  (Domain Controllers OU auto-added)" -ForegroundColor Gray

            while ($true) {
                $manualOU = Read-Host "  OU DN"
                if ([string]::IsNullOrWhiteSpace($manualOU)) { break }
                $selectedTargets += $manualOU
            }
        }
        default {
            # Option 1 - Domain Root (covers everything)
            $selectedTargets += $domainDN
            Write-Host "  Using Domain Root - GPO will apply to all computers" -ForegroundColor Green
        }
    }

    # If no targets selected, default to domain root
    if ($selectedTargets.Count -eq 0) {
        $selectedTargets += $domainDN
        Write-Host "  No targets selected - defaulting to Domain Root" -ForegroundColor Yellow
    }

    # IP Filter
    Write-Host "`nWinRM IP Filter (which IPs can connect):"
    Write-Host "  * = All IPs (default)" -ForegroundColor White
    Write-Host "  Or enter specific range (e.g., 192.168.1.0/24, 10.0.0.0/8)" -ForegroundColor White
    $ipFilter = Read-Host "IP Filter (default: *)"
    if ([string]::IsNullOrWhiteSpace($ipFilter)) { $ipFilter = "*" }

    # Confirmation
    Write-Host "`n--- Summary ---" -ForegroundColor Green
    Write-Host "GPO Name:    $gpoName"
    Write-Host "IP Filter:   $ipFilter"
    Write-Host "Link Targets:" -ForegroundColor White
    foreach ($target in $selectedTargets) {
        Write-Host "  - $target" -ForegroundColor Yellow
    }
    Write-Host "---------------`n" -ForegroundColor Green

    $confirm = Read-Host "Proceed? (Y/n)"
    if ($confirm -eq 'n' -or $confirm -eq 'N') {
        Write-Host "Aborted." -ForegroundColor Red
        exit
    }

    # --- Create GPO ---
    Write-Host "`n[1/6] Creating GPO..." -ForegroundColor Cyan
    try {
        $gpo = New-GPO -Name $gpoName -Comment "Enables WinRM service for remote management. Created $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Write-Host "  Created GPO: $($gpo.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to create GPO - $_" -ForegroundColor Red
        exit 1
    }

    # --- Configure WinRM Service Settings ---
    Write-Host "`n[2/6] Configuring WinRM settings..." -ForegroundColor Cyan

    # Enable WinRM Service via registry policy
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"

    # Allow remote server management
    Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "AllowAutoConfig" -Type DWord -Value 1 | Out-Null
    Write-Host "  Enabled: AllowAutoConfig" -ForegroundColor Green

    # Set IP filters
    Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "IPv4Filter" -Type String -Value $ipFilter | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "IPv6Filter" -Type String -Value $ipFilter | Out-Null
    Write-Host "  Set IP Filters: $ipFilter" -ForegroundColor Green

    # Disable unencrypted traffic on service side
    Set-GPRegistryValue -Name $gpoName -Key $regPath -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0 | Out-Null
    Write-Host "  Disabled unencrypted traffic (service)" -ForegroundColor Green

    # Enable WinRM Client settings
    $clientRegPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    Set-GPRegistryValue -Name $gpoName -Key $clientRegPath -ValueName "AllowBasic" -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $clientRegPath -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0 | Out-Null
    Write-Host "  Configured client security settings" -ForegroundColor Green

    # --- Configure WinRM Service Startup ---
    Write-Host "`n[3/6] Configuring WinRM service startup..." -ForegroundColor Cyan

    # Set WinRM service to Automatic using GPO preferences
    $gpoId = $gpo.Id.ToString()
    $gpoPath = "\\$currentDomain\SYSVOL\$currentDomain\Policies\{$gpoId}"

    # Create the GptTmpl.inf for service configuration
    $machineDir = "$gpoPath\Machine\Microsoft\Windows NT\SecEdit"
    if (!(Test-Path $machineDir)) {
        New-Item -Path $machineDir -ItemType Directory -Force | Out-Null
    }

    $gptTmplContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Service General Setting]
"WinRM",2,""
"@

    Set-Content -Path "$machineDir\GptTmpl.inf" -Value $gptTmplContent -Encoding Unicode
    Write-Host "  Set WinRM service to Automatic start" -ForegroundColor Green

    # Update GPT.ini to reflect changes
    $gptIniPath = "$gpoPath\GPT.INI"
    $machineExtensions = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"

    if (Test-Path $gptIniPath) {
        $gptContent = Get-Content $gptIniPath -Raw
        if ($gptContent -notmatch "gPCMachineExtensionNames") {
            $gptContent = $gptContent -replace "(\[General\])", "`$1`r`ngPCMachineExtensionNames=$machineExtensions"
        }
        # Increment version
        if ($gptContent -match "Version=(\d+)") {
            $newVersion = [int]$matches[1] + 1
            $gptContent = $gptContent -replace "Version=\d+", "Version=$newVersion"
        }
        Set-Content -Path $gptIniPath -Value $gptContent
    }

    # --- Configure Firewall Rules ---
    Write-Host "`n[4/6] Configuring firewall rules..." -ForegroundColor Cyan

    # Method 1: Registry-based firewall rules (for newer Windows versions)
    $fwRegPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"
    $winrmRule = "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|Name=WinRM-HTTP-In-TCP|Desc=Allow WinRM HTTP|Profile=Domain|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=WinRM|"
    Set-GPRegistryValue -Name $gpoName -Key $fwRegPath -ValueName "WinRM-HTTP-In-TCP" -Type String -Value $winrmRule | Out-Null
    Write-Host "  Added firewall rule: WinRM HTTP (5985)" -ForegroundColor Green

    $winrmRuleHttps = "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5986|Name=WinRM-HTTPS-In-TCP|Desc=Allow WinRM HTTPS|Profile=Domain|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=WinRM|"
    Set-GPRegistryValue -Name $gpoName -Key $fwRegPath -ValueName "WinRM-HTTPS-In-TCP" -Type String -Value $winrmRuleHttps | Out-Null
    Write-Host "  Added firewall rule: WinRM HTTPS (5986)" -ForegroundColor Green

    # Enable Windows Firewall domain profile (ensures rules apply)
    $fwDomainPath = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
    Set-GPRegistryValue -Name $gpoName -Key $fwDomainPath -ValueName "EnableFirewall" -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $fwDomainPath -ValueName "DefaultInboundAction" -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $fwDomainPath -ValueName "DefaultOutboundAction" -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $fwDomainPath -ValueName "DisableNotifications" -Type DWord -Value 0 | Out-Null
    Write-Host "  Configured domain firewall profile" -ForegroundColor Green

    # Method 2: Create startup script for reliable firewall rule creation
    Write-Host "`n  Creating startup script for firewall rules..." -ForegroundColor Cyan

    $scriptsDir = "$gpoPath\Machine\Scripts\Startup"
    if (!(Test-Path $scriptsDir)) {
        New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
    }

    # Create the firewall configuration script
    $firewallScript = @'
@echo off
REM WinRM Firewall Configuration Script - Created by Enable-WinRM-Domain.ps1
REM This script ensures WinRM firewall rules exist on domain computers

REM Check if rules already exist
netsh advfirewall firewall show rule name="WinRM-HTTP-In-GPO" >nul 2>&1
if %errorlevel% neq 0 (
    REM Create WinRM HTTP rule (5985)
    netsh advfirewall firewall add rule name="WinRM-HTTP-In-GPO" dir=in action=allow protocol=tcp localport=5985 profile=domain,private remoteip=localsubnet enable=yes
)

netsh advfirewall firewall show rule name="WinRM-HTTPS-In-GPO" >nul 2>&1
if %errorlevel% neq 0 (
    REM Create WinRM HTTPS rule (5986)
    netsh advfirewall firewall add rule name="WinRM-HTTPS-In-GPO" dir=in action=allow protocol=tcp localport=5986 profile=domain,private remoteip=localsubnet enable=yes
)

REM Ensure WinRM service is running
sc query WinRM | find "RUNNING" >nul 2>&1
if %errorlevel% neq 0 (
    net start WinRM
)

REM Ensure WinRM listener exists
winrm enumerate winrm/config/listener >nul 2>&1
if %errorlevel% neq 0 (
    winrm quickconfig -quiet
)
'@

    Set-Content -Path "$scriptsDir\Configure-WinRM-Firewall.cmd" -Value $firewallScript -Encoding ASCII
    Write-Host "  Created: Configure-WinRM-Firewall.cmd" -ForegroundColor Green

    # Create scripts.ini to register the startup script
    $scriptsIniDir = "$gpoPath\Machine\Scripts"
    $scriptsIniContent = @"
[Startup]
0CmdLine=Configure-WinRM-Firewall.cmd
0Parameters=
"@
    Set-Content -Path "$scriptsIniDir\scripts.ini" -Value $scriptsIniContent -Encoding Unicode
    Write-Host "  Registered startup script in GPO" -ForegroundColor Green

    # Update GPT.ini to include Scripts extension
    $scriptsExtension = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}"
    if (Test-Path $gptIniPath) {
        $gptContent = Get-Content $gptIniPath -Raw
        if ($gptContent -match "gPCMachineExtensionNames=(.*)") {
            $existingExt = $matches[1]
            if ($existingExt -notlike "*$scriptsExtension*") {
                $newExt = $existingExt + $scriptsExtension
                $gptContent = $gptContent -replace "gPCMachineExtensionNames=.*", "gPCMachineExtensionNames=$newExt"
            }
        } else {
            $gptContent = $gptContent -replace "(\[General\])", "`$1`r`ngPCMachineExtensionNames=$machineExtensions$scriptsExtension"
        }
        # Increment version again
        if ($gptContent -match "Version=(\d+)") {
            $newVersion = [int]$matches[1] + 1
            $gptContent = $gptContent -replace "Version=\d+", "Version=$newVersion"
        }
        Set-Content -Path $gptIniPath -Value $gptContent
    }
    Write-Host "  Updated GPO extensions for startup scripts" -ForegroundColor Green

    # --- Link GPO to All Targets ---
    Write-Host "`n[5/6] Linking GPO to targets..." -ForegroundColor Cyan

    $linkSuccess = 0
    $linkFailed = 0

    foreach ($target in $selectedTargets) {
        try {
            # Check if it's a container (CN=) vs OU - verify target exists
            $null = Get-ADObject -Identity $target -ErrorAction Stop

            New-GPLink -Name $gpoName -Target $target -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Host "  Linked to: $target" -ForegroundColor Green
            $linkSuccess++
        } catch {
            Write-Host "  FAILED to link to: $target" -ForegroundColor Red
            Write-Host "    Error: $_" -ForegroundColor Red
            $linkFailed++
        }
    }

    Write-Host "`n  Links created: $linkSuccess | Failed: $linkFailed" -ForegroundColor $(if ($linkFailed -eq 0) { "Green" } else { "Yellow" })

    # --- Force GP Refresh ---
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "GPO deployment complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

    $refreshChoice = Read-Host "`nForce GP refresh on all domain computers now? (Y/n)"

    if ($refreshChoice -ne 'n' -and $refreshChoice -ne 'N') {
        Write-Host "`n[6/6] Forcing Group Policy refresh across domain..." -ForegroundColor Yellow
        Write-Host "(This may take a while depending on domain size)`n" -ForegroundColor Gray

        # Get all Windows computers
        $computers = Get-ADComputer -Filter "OperatingSystem -like '*Windows*'" -Properties OperatingSystem, DistinguishedName

        # Categorize computers
        $domainControllers = $computers | Where-Object { $_.DistinguishedName -like "*OU=Domain Controllers*" }
        $memberServers = $computers | Where-Object {
            $_.OperatingSystem -like "*Server*" -and $_.DistinguishedName -notlike "*OU=Domain Controllers*"
        }
        $workstations = $computers | Where-Object { $_.OperatingSystem -notlike "*Server*" }

        Write-Host "Found:" -ForegroundColor Cyan
        Write-Host "  Domain Controllers: $($domainControllers.Count)" -ForegroundColor White
        Write-Host "  Member Servers:     $($memberServers.Count)" -ForegroundColor White
        Write-Host "  Workstations:       $($workstations.Count)" -ForegroundColor White
        Write-Host "  Total:              $($computers.Count)" -ForegroundColor Yellow

        $total = $computers.Count
        $current = 0
        $success = 0
        $failed = 0
        $offline = 0

        # Process Domain Controllers first
        Write-Host "`nRefreshing Domain Controllers..." -ForegroundColor Cyan
        foreach ($computer in $domainControllers) {
            $current++
            $pct = [math]::Round(($current / $total) * 100)
            Write-Progress -Activity "Refreshing Group Policy" -Status "DCs: $($computer.Name)" -PercentComplete $pct

            try {
                if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    Invoke-GPUpdate -Computer $computer.Name -Force -RandomDelayInMinutes 0 -ErrorAction Stop
                    $success++
                } else {
                    $offline++
                }
            } catch {
                $failed++
            }
        }

        # Process Member Servers
        Write-Host "Refreshing Member Servers..." -ForegroundColor Cyan
        foreach ($computer in $memberServers) {
            $current++
            $pct = [math]::Round(($current / $total) * 100)
            Write-Progress -Activity "Refreshing Group Policy" -Status "Servers: $($computer.Name)" -PercentComplete $pct

            try {
                if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    Invoke-GPUpdate -Computer $computer.Name -Force -RandomDelayInMinutes 0 -ErrorAction Stop
                    $success++
                } else {
                    $offline++
                }
            } catch {
                $failed++
            }
        }

        # Process Workstations
        Write-Host "Refreshing Workstations..." -ForegroundColor Cyan
        foreach ($computer in $workstations) {
            $current++
            $pct = [math]::Round(($current / $total) * 100)
            Write-Progress -Activity "Refreshing Group Policy" -Status "Workstations: $($computer.Name)" -PercentComplete $pct

            try {
                if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    Invoke-GPUpdate -Computer $computer.Name -Force -RandomDelayInMinutes 0 -ErrorAction Stop
                    $success++
                } else {
                    $offline++
                }
            } catch {
                $failed++
            }
        }

        Write-Progress -Activity "Refreshing Group Policy" -Completed

        Write-Host "`n--- GP Refresh Results ---" -ForegroundColor Green
        Write-Host "Total:     $total"
        Write-Host "Success:   $success" -ForegroundColor Green
        Write-Host "Offline:   $offline" -ForegroundColor Yellow
        Write-Host "Failed:    $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
    }

    # --- Final Summary ---
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Deployment Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nGPO '$gpoName' has been created and linked to:"
    foreach ($target in $selectedTargets) {
        Write-Host "  - $target" -ForegroundColor Yellow
    }

    Write-Host "`nTo verify on a client, run:" -ForegroundColor Yellow
    Write-Host "  gpresult /r /scope:computer" -ForegroundColor White
    Write-Host "  winrm enumerate winrm/config/listener" -ForegroundColor White
    Write-Host "  Get-Service WinRM | Select Status, StartType" -ForegroundColor White

    Write-Host "`nTo test WinRM connectivity:" -ForegroundColor Yellow
    Write-Host "  Test-WSMan -ComputerName <hostname>" -ForegroundColor White
    Write-Host "  Enter-PSSession -ComputerName <hostname>" -ForegroundColor White

    Write-Host "`nTo manually refresh GP on a single machine:" -ForegroundColor Yellow
    Write-Host "  gpupdate /force" -ForegroundColor White

    Write-Host "`nTo remove this GPO later:" -ForegroundColor Yellow
    Write-Host "  .\Enable-WinRM-Domain.ps1 -Remove" -ForegroundColor White
    Write-Host ""
}
