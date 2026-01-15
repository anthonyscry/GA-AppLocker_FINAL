<#
.SYNOPSIS
    Unified entry point for GA-AppLocker workflow.

.AUTHOR
    Tony Tran, ISSO, GA-ASI

.DESCRIPTION
    This script provides a single, simplified interface to the AppLocker policy
    generation workflow. Instead of running multiple scripts separately, use
    this unified workflow to:

    - Scan: Collect data from remote computers
    - Generate: Create AppLocker policies from scan data
    - Merge: Combine multiple policy files
    - Validate: Check policy files for issues
    - Full: Run the complete workflow (Scan -> Generate)

    Interactive mode guides you through each step with prompts.

.PARAMETER Mode
    Workflow mode to execute:
    - Scan: Run remote data collection
    - Generate: Create policy from scan data
    - Merge: Combine multiple policies
    - Validate: Validate a policy file
    - Full: Complete workflow
    - Interactive: Menu-driven mode (default)

.PARAMETER ScanPath
    Path to scan results (for Generate/Merge modes).

.PARAMETER OutputPath
    Path to save generated files.

.PARAMETER ComputerList
    Path to text file with computer names (for Scan mode).

.PARAMETER PolicyPath
    Path to policy file (for Validate mode).

.PARAMETER Simplified
    Use simplified policy generation mode.

.PARAMETER TargetType
    Target type for Build Guide mode: Workstation, Server, DomainController.

.PARAMETER DomainName
    Domain name for Build Guide mode.

.PARAMETER Phase
    Build phase (1-4) for Build Guide mode.

.EXAMPLE
    # Interactive menu mode
    .\Start-AppLockerWorkflow.ps1

.EXAMPLE
    # Quick scan
    .\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList .\ADManagement\computers.csv -OutputPath .\Scans

.EXAMPLE
    # Generate simplified policy
    .\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -Simplified

.EXAMPLE
    # Generate Build Guide policy
    .\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -TargetType Workstation -DomainName CONTOSO -Phase 1

.EXAMPLE
    # Validate existing policy
    .\Start-AppLockerWorkflow.ps1 -Mode Validate -PolicyPath .\policy.xml

.NOTES
    Part of GA-AppLocker toolkit.
    See README.md for full documentation.
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Direct')]
    [ValidateSet("Scan", "Generate", "Merge", "Validate", "Full", "Compare", "Events", "ADSetup", "ADExport", "ADImport", "Diagnostic", "Interactive")]
    [string]$Mode = "Interactive",

    [string]$ScanPath,
    [string]$OutputPath = ".\Outputs",
    [string]$ComputerList,
    [string]$PolicyPath,
    [switch]$Simplified,
    [ValidateSet("Workstation", "Server", "DomainController")]
    [string]$TargetType,
    [string]$DomainName,
    [ValidateRange(1, 4)]
    [int]$Phase = 1,
    [PSCredential]$Credential,

    # Compare mode parameters
    [string]$ReferencePath,
    [string]$ComparePath,
    [ValidateSet("Name", "NameVersion", "Hash", "Publisher")]
    [string]$CompareBy = "Name",

    # Diagnostic mode parameters
    [ValidateSet("Connectivity", "JobSession", "JobFull", "SimpleScan")]
    [string]$DiagnosticType,
    [string]$ComputerName,

    # Event collection mode parameters
    [ValidateRange(0, 365)]
    [int]$DaysBack = 14,
    [switch]$BlockedOnly,
    [switch]$IncludeAllowedEvents,

    # AD mode parameters
    [string]$ParentOU,
    [string]$GroupPrefix = "AppLocker",
    [string]$InputPath,
    [string]$SearchBase,
    [switch]$IncludeDisabled,
    [switch]$Force
)

#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
$utilitiesRoot = Join-Path (Split-Path -Parent $scriptRoot) "Utilities"

# Import utilities (includes validation functions)
$modulePath = Join-Path $utilitiesRoot "Common.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    Write-Warning "Utilities module not found at $modulePath. Some features may not work correctly."
}

#region Banner and Menu

function Show-Banner {
    Write-Host ""
    Write-Host "  GA-AppLocker - AppLocker Policy Generation Toolkit" -ForegroundColor Cyan
    Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Author: Tony Tran, ISSO, GA-ASI" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    # Show quick status counts
    $statusInfo = @()
    $scansPath = ".\Scans"
    $outputsPath = ".\Outputs"
    if (Test-Path $scansPath) {
        $scanCount = @(Get-ChildItem -Path $scansPath -Directory -ErrorAction SilentlyContinue).Count
        if ($scanCount -gt 0) { $statusInfo += "$scanCount scans" }
    }
    if (Test-Path $outputsPath) {
        $policyCount = @(Get-ChildItem -Path $outputsPath -Filter "*.xml" -File -ErrorAction SilentlyContinue).Count
        if ($policyCount -gt 0) { $statusInfo += "$policyCount policies" }
    }

    Write-Host "  Select an option:" -ForegroundColor Yellow
    if ($statusInfo.Count -gt 0) {
        Write-Host "  [$($statusInfo -join ', ') available]" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  === Collection ===" -ForegroundColor Cyan
    Write-Host "    [1] Scan       - Collect software inventory from remote computers" -ForegroundColor White
    Write-Host "    [2] Events     - Collect AppLocker audit events (8003/8004)" -ForegroundColor White
    Write-Host ""
    Write-Host "  === Analysis ===" -ForegroundColor Cyan
    Write-Host "    [3] Compare    - Compare software inventories between machines" -ForegroundColor White
    Write-Host "    [4] Validate   - Check a policy file for issues" -ForegroundColor White
    Write-Host ""
    Write-Host "  === Policy ===" -ForegroundColor Cyan
    Write-Host "    [5] Generate   - Create AppLocker policy from scan data" -ForegroundColor White
    Write-Host "    [6] Merge      - Combine multiple policy files" -ForegroundColor White
    Write-Host "    [S] Software   - Manage software lists for rule generation" -ForegroundColor White
    Write-Host ""
    Write-Host "  === Deployment ===" -ForegroundColor Cyan
    Write-Host "    [7] AD Setup   - Create AppLocker OUs and groups" -ForegroundColor White
    Write-Host "    [8] AD Export  - Export user group memberships" -ForegroundColor White
    Write-Host "    [9] AD Import  - Apply group membership changes" -ForegroundColor White
    Write-Host "    [C] Computers  - Export computer list from AD for scanning" -ForegroundColor White
    Write-Host "    [W] WinRM      - Deploy/Remove WinRM GPO" -ForegroundColor White
    Write-Host "    [D] Diagnostic - Troubleshoot remote scanning" -ForegroundColor White
    Write-Host ""
    Write-Host "  === Compliance ===" -ForegroundColor Cyan
    Write-Host "    [R] CORA       - Generate audit evidence package" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "    [F] Full       - Complete workflow (Scan + Generate)" -ForegroundColor Green
    Write-Host "    [Q] Quit" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Enter choice"
    return $choice
}

function Show-GenerateMenu {
    Write-Host ""
    Write-Host "  Main > Generate" -ForegroundColor DarkGray
    Write-Host "  Policy Generation Mode:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [1] Simplified  - Quick policy from scan data" -ForegroundColor White
    Write-Host "        Best for: Testing, small environments, quick deployments"
    Write-Host ""
    Write-Host "    [2] Build Guide - Enterprise policy with proper scoping" -ForegroundColor White
    Write-Host "        Best for: Production, large enterprises, phased rollout"
    Write-Host ""
    Write-Host "    [B] Back" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Enter choice"
    return $choice
}

#endregion

#region Workflow Functions

function Invoke-ScanWorkflow {
    param(
        [string]$ComputerListPath,
        [string]$OutputPath,
        [PSCredential]$Credential
    )

    Write-Host "`n=== Remote Scan Workflow ===" -ForegroundColor Cyan

    # Get computer list - check common locations
    if ([string]::IsNullOrWhiteSpace($ComputerListPath)) {
        # Check for common computer list files (CSV preferred)
        $defaultPath = ".\ADManagement\computers.csv"

        if (Test-Path $defaultPath -PathType Leaf) {
            $ComputerListPath = Get-ValidatedPath -Prompt "  Enter path to computer list file" `
                -DefaultValue $defaultPath `
                -MustExist -MustBeFile
        }
        else {
            $ComputerListPath = Get-ValidatedPath -Prompt "  Enter path to computer list file" `
                -DefaultValue $defaultPath `
                -MustExist -MustBeFile
        }
        if (-not $ComputerListPath) { return $null }
    }
    elseif (-not (Test-Path $ComputerListPath -PathType Leaf)) {
        Write-Host "  [-] Computer list not found or is not a file: $ComputerListPath" -ForegroundColor Red
        return $null
    }

    # Get output path - validate and set default
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Get-ValidatedPath -Prompt "  Enter output path" -DefaultValue ".\Scans"
        if (-not $OutputPath) { return $null }
    }

    # Get credentials if not provided
    if ($null -eq $Credential) {
        Write-Host "  Enter credentials for remote connections:" -ForegroundColor Yellow
        $Credential = Get-Credential -Message "Remote scan credentials (DOMAIN\username)"
    }

    # Validate we have credentials
    if ($null -eq $Credential) {
        Write-Host "  [-] Credentials are required for remote scanning" -ForegroundColor Red
        return $null
    }

    # Run scan
    $scanScript = Join-Path $scriptRoot "Invoke-RemoteScan.ps1"
    if (Test-Path $scanScript) {
        Write-Host "`n  Starting remote scan..." -ForegroundColor Cyan

        # Build parameter hashtable using helper
        $scanParams = @{}
        Add-NonEmptyParameters -Hashtable $scanParams -Parameters @{
            ComputerListPath = $ComputerListPath
            SharePath        = $OutputPath
            Credential       = $Credential
        }

        try {
            & $scanScript @scanParams
            return $OutputPath
        }
        catch {
            Write-Host "  [-] Scan failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] Scan script not found: $scanScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-GenerateWorkflow {
    param(
        [string]$ScanPath,
        [string]$OutputPath,
        [switch]$Simplified,
        [string]$TargetType,
        [string]$DomainName,
        [int]$Phase
    )

    Write-Host "`n=== Policy Generation Workflow ===" -ForegroundColor Cyan

    # Get scan path - use folder browser if not provided
    if ([string]::IsNullOrWhiteSpace($ScanPath)) {
        $ScanPath = Select-ScanDataPath -ScansPath ".\Scans"

        # Handle special return values
        if ($ScanPath -eq "RUN_SCAN") {
            Write-Host "  Redirecting to scan workflow..." -ForegroundColor Cyan
            $scanResult = Invoke-ScanWorkflow
            if ($scanResult) {
                # Find the latest scan folder
                $latestScan = Get-ChildItem -Path $scanResult -Directory -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1
                $ScanPath = if ($latestScan) { $latestScan.FullName } else { $scanResult }
            } else {
                return $null
            }
        }
        elseif (-not $ScanPath) {
            return $null
        }
    }

    if (-not (Test-Path $ScanPath)) {
        Write-Host "  [-] Scan path not found: $ScanPath" -ForegroundColor Red
        return $null
    }

    # Validate scan data
    if (Get-Command Test-ScanData -ErrorAction SilentlyContinue) {
        Write-Host "  Validating scan data..." -ForegroundColor Gray
        $validation = Test-ScanData -ScanPath $ScanPath
        if (-not $validation.IsValid) {
            Write-Host "  [-] Scan data validation failed" -ForegroundColor Red
            Show-ValidationResult -ValidationResult $validation
            return $null
        }
        Write-Host "  [+] Scan data validated: $($validation.ComputerCount) computers" -ForegroundColor Green
    }

    # Determine generation mode - only prompt if neither Simplified nor TargetType is set
    $useSimplified = $Simplified.IsPresent
    if (-not $useSimplified -and [string]::IsNullOrWhiteSpace($TargetType)) {
        $modeChoice = Show-GenerateMenu
        switch ($modeChoice) {
            "1" { $useSimplified = $true }
            "2" {
                $TargetType = Read-Host "  Enter target type (Workstation/Server/DomainController)"
                $DomainName = Read-Host "  Enter domain name (e.g., CONTOSO)"
                Write-Host ""
                Write-Host "  Deployment Phases:" -ForegroundColor Yellow
                Write-Host "    [1] EXE only           - Start here, lowest risk" -ForegroundColor White
                Write-Host "    [2] EXE + Script       - Adds .ps1, .bat, .vbs rules (highest bypass risk)" -ForegroundColor White
                Write-Host "    [3] EXE + Script + MSI - Adds installer rules (test deployments)" -ForegroundColor White
                Write-Host "    [4] All + DLL          - Full policy (audit 14+ days before enforcing!)" -ForegroundColor White
                Write-Host ""
                $phaseInput = Read-Host "  Enter phase (1-4, default: 1)"
                $Phase = if ([int]::TryParse($phaseInput, [ref]$null)) { [int]$phaseInput } else { 1 }
                if ($Phase -lt 1 -or $Phase -gt 4) { $Phase = 1 }
            }
            "B" { return $null }
            default {
                Write-Host "  Invalid choice" -ForegroundColor Red
                return $null
            }
        }
    }

    # Run generation
    $genScript = Join-Path $scriptRoot "New-AppLockerPolicyFromGuide.ps1"
    if (Test-Path $genScript) {
        Write-Host "`n  Generating policy..." -ForegroundColor Cyan

        # Build parameter hashtable carefully to avoid parameter set conflicts
        $params = @{}

        # Always add ScanPath if valid
        if (-not [string]::IsNullOrWhiteSpace($ScanPath)) {
            $params.ScanPath = $ScanPath
        }

        # Always add OutputPath if valid
        if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
            $params.OutputPath = $OutputPath
        }

        if ($useSimplified) {
            # Simplified mode - only add the switch
            $params.Simplified = $true
        }
        else {
            # Build Guide mode - validate required parameters before adding
            if ([string]::IsNullOrWhiteSpace($TargetType)) {
                Write-Host "  [-] Target type is required for Build Guide mode" -ForegroundColor Red
                return $null
            }
            if ([string]::IsNullOrWhiteSpace($DomainName)) {
                Write-Host "  [-] Domain name is required for Build Guide mode" -ForegroundColor Red
                return $null
            }

            $params.TargetType = $TargetType
            $params.DomainName = $DomainName
            if ($Phase -ge 1 -and $Phase -le 4) {
                $params.Phase = $Phase
            }
        }

        try {
            $result = & $genScript @params
            return $result
        }
        catch {
            Write-Host "  [-] Policy generation failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] Generation script not found: $genScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-MergeWorkflow {
    param(
        [string]$InputPath,
        [string]$OutputPath
    )

    Write-Host "`n=== Policy Merge Workflow ===" -ForegroundColor Cyan

    # Get input path - default to Outputs folder with option for manual entry
    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        $outputsPath = ".\Outputs"

        # Check if Outputs folder exists
        if (Test-Path $outputsPath) {
            Write-Host ""
            Write-Host "  Select source folder for policy files to merge:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    [1] Outputs folder (default)" -ForegroundColor White
            Write-Host "        $outputsPath" -ForegroundColor DarkGray
            Write-Host "    [M] Enter path manually" -ForegroundColor Gray
            Write-Host "    [C] Cancel" -ForegroundColor Gray
            Write-Host ""

            $choice = Read-Host "  Enter choice (default: 1)"

            switch ($choice.ToUpper()) {
                "C" { return $null }
                "M" {
                    $InputPath = Get-ValidatedPath -Prompt "  Enter path to folder containing policy files" -MustExist
                    if (-not $InputPath) { return $null }
                }
                default {
                    # Default to Outputs folder (including empty input or "1")
                    $InputPath = $outputsPath
                }
            }
        }
        else {
            # Outputs folder doesn't exist, prompt for manual entry
            Write-Host "  Outputs folder not found. Please specify a path." -ForegroundColor Yellow
            $InputPath = Get-ValidatedPath -Prompt "  Enter path to folder containing policy files" -MustExist
            if (-not $InputPath) { return $null }
        }
    }
    elseif (-not (Test-Path $InputPath)) {
        Write-Host "  [-] Input path not found: $InputPath" -ForegroundColor Red
        return $null
    }

    # Get output path with default to Outputs folder
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Get-ValidatedPath -Prompt "  Enter output file path" -DefaultValue ".\Outputs\MergedPolicy.xml"
        if (-not $OutputPath) { return $null }
    }

    # Run merge
    $mergeScript = Join-Path $scriptRoot "Merge-AppLockerPolicies.ps1"
    if (Test-Path $mergeScript) {
        Write-Host "`n  Merging policies..." -ForegroundColor Cyan

        $mergeParams = @{}
        Add-NonEmptyParameters -Hashtable $mergeParams -Parameters @{
            InputPath  = $InputPath
            OutputPath = $OutputPath
        }

        try {
            $result = & $mergeScript @mergeParams
            return $result
        }
        catch {
            Write-Host "  [-] Merge failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] Merge script not found: $mergeScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-ValidateWorkflow {
    param(
        [string]$PolicyPath
    )

    Write-Host "`n=== Policy Validation Workflow ===" -ForegroundColor Cyan
    Write-Host "  Validates an AppLocker policy XML file for correctness." -ForegroundColor Gray
    Write-Host ""

    # Get policy path - use GUI selection from Outputs folder by default
    if ([string]::IsNullOrWhiteSpace($PolicyPath)) {
        $outputsPath = ".\Outputs"

        # Check if Outputs folder exists and has XML files
        $xmlFiles = @()
        if (Test-Path $outputsPath) {
            $xmlFiles = @(Get-ChildItem -Path $outputsPath -Filter "*.xml" -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending)
        }

        if ($xmlFiles.Count -gt 0) {
            Write-Host "  Select a policy file to validate:" -ForegroundColor Yellow
            Write-Host "  Location: $outputsPath" -ForegroundColor DarkGray
            Write-Host ""

            # Display numbered list of XML files
            $i = 1
            foreach ($file in $xmlFiles) {
                $dateStr = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                Write-Host "    [$i] $($file.Name)" -ForegroundColor White -NoNewline
                Write-Host "  ($dateStr)" -ForegroundColor DarkGray
                $i++
            }
            Write-Host ""
            Write-Host "    [M] Enter path manually" -ForegroundColor Gray
            Write-Host "    [C] Cancel" -ForegroundColor Gray
            Write-Host ""

            $choice = Read-Host "  Enter choice"

            switch ($choice.ToUpper()) {
                "C" { return $null }
                "M" {
                    $PolicyPath = Get-ValidatedPath -Prompt "  Enter path to policy XML file" `
                        -Example ".\Outputs\AppLockerPolicy-Workstation-Phase1-AuditOnly-20260108.xml" `
                        -MustExist -MustBeFile
                    if (-not $PolicyPath) { return $null }
                }
                default {
                    if ($choice -match "^\d+$") {
                        $idx = [int]$choice - 1
                        if ($idx -ge 0 -and $idx -lt $xmlFiles.Count) {
                            $PolicyPath = $xmlFiles[$idx].FullName
                        }
                        else {
                            Write-Host "  [-] Invalid selection" -ForegroundColor Red
                            return $null
                        }
                    }
                    else {
                        Write-Host "  [-] Invalid selection" -ForegroundColor Red
                        return $null
                    }
                }
            }
        }
        else {
            # No XML files in Outputs, prompt for manual entry
            Write-Host "  No policy files found in $outputsPath" -ForegroundColor Yellow
            $PolicyPath = Get-ValidatedPath -Prompt "  Enter path to policy XML file" `
                -Example ".\Outputs\AppLockerPolicy-Workstation-Phase1-AuditOnly-20260108.xml" `
                -MustExist -MustBeFile
            if (-not $PolicyPath) { return $null }
        }
    }
    elseif (-not (Test-Path $PolicyPath -PathType Leaf)) {
        Write-Host "  [-] Policy XML file not found: $PolicyPath" -ForegroundColor Red
        return $null
    }

    # Run validation
    if (Get-Command Test-AppLockerPolicy -ErrorAction SilentlyContinue) {
        Write-Host "  Validating policy..." -ForegroundColor Gray
        try {
            $validation = Test-AppLockerPolicy -PolicyPath $PolicyPath
            Show-ValidationResult -ValidationResult $validation
            return $validation
        }
        catch {
            Write-Host "  [-] Validation failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        # Basic validation without module
        Write-Host "  Performing basic XML validation..." -ForegroundColor Gray
        try {
            [xml]$policy = Get-Content -Path $PolicyPath -Raw
            if ($null -ne $policy.AppLockerPolicy) {
                Write-Host "  [+] Policy XML is valid" -ForegroundColor Green

                $ruleCount = 0
                foreach ($coll in $policy.AppLockerPolicy.RuleCollection) {
                    $count = ($coll.FilePublisherRule | Measure-Object).Count +
                             ($coll.FilePathRule | Measure-Object).Count +
                             ($coll.FileHashRule | Measure-Object).Count
                    Write-Host "    $($coll.Type): $count rules ($($coll.EnforcementMode))" -ForegroundColor Gray
                    $ruleCount += $count
                }
                Write-Host "  Total rules: $ruleCount" -ForegroundColor Cyan

                # Return basic validation result
                return @{
                    IsValid = $true
                    RuleCount = $ruleCount
                    PolicyPath = $PolicyPath
                }
            }
            else {
                Write-Host "  [-] Missing AppLockerPolicy element" -ForegroundColor Red
                return @{
                    IsValid = $false
                    Error = "Missing AppLockerPolicy element"
                    PolicyPath = $PolicyPath
                }
            }
        }
        catch {
            Write-Host "  [-] Invalid XML: $($_.Exception.Message)" -ForegroundColor Red
            return @{
                IsValid = $false
                Error = $_.Exception.Message
                PolicyPath = $PolicyPath
            }
        }
    }
}

function Invoke-FullWorkflow {
    param(
        [string]$ComputerList,
        [string]$OutputPath,
        [PSCredential]$Credential,
        [switch]$Simplified,
        [string]$TargetType,
        [string]$DomainName,
        [int]$Phase
    )

    Write-Host "`n=== Full Workflow ===" -ForegroundColor Cyan
    Write-Host "  This will run: Scan -> Generate" -ForegroundColor Gray
    Write-Host ""

    # Step 1: Scan - pass parameters correctly
    $scanParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($ComputerList)) {
        $scanParams.ComputerListPath = $ComputerList
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $scanParams.OutputPath = $OutputPath
    }
    if ($null -ne $Credential) {
        $scanParams.Credential = $Credential
    }

    $scanOutput = Invoke-ScanWorkflow @scanParams

    if (-not $scanOutput) {
        Write-Host "  [-] Scan failed, aborting workflow" -ForegroundColor Red
        return
    }

    # Find the latest scan folder
    $latestScan = Get-ChildItem -Path $scanOutput -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latestScan) {
        $scanDataPath = $latestScan.FullName
    }
    else {
        $scanDataPath = $scanOutput
    }

    Write-Host "`n  [+] Scan complete: $scanDataPath" -ForegroundColor Green
    Write-Host ""

    # Step 2: Generate - build parameters carefully
    $genParams = @{
        ScanPath = $scanDataPath
    }
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $genParams.OutputPath = $OutputPath
    }
    if ($Simplified.IsPresent) {
        $genParams.Simplified = $true
    }
    elseif (-not [string]::IsNullOrWhiteSpace($TargetType)) {
        $genParams.TargetType = $TargetType
        if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
            $genParams.DomainName = $DomainName
        }
        if ($Phase -ge 1 -and $Phase -le 4) {
            $genParams.Phase = $Phase
        }
    }

    $policyPath = Invoke-GenerateWorkflow @genParams

    if ($policyPath) {
        Write-Host "`n  [+] Full workflow complete!" -ForegroundColor Green
        Write-Host "  Policy file: $policyPath" -ForegroundColor Cyan
    }
}

function Invoke-WinRMWorkflow {
    Write-Host "`n=== WinRM Deployment Workflow ===" -ForegroundColor Cyan
    Write-Host "  This will create a GPO to enable WinRM across domain computers." -ForegroundColor Gray
    Write-Host "  Requires: Domain Controller, RSAT tools, Domain Admin privileges." -ForegroundColor Yellow
    Write-Host ""

    $winrmScript = Join-Path $utilitiesRoot "Enable-WinRM-Domain.ps1"
    if (Test-Path $winrmScript) {
        $confirm = Read-Host "  Proceed with WinRM GPO deployment? (Y/n)"
        if ($confirm -eq 'n' -or $confirm -eq 'N') {
            Write-Host "  Aborted." -ForegroundColor Yellow
            return
        }

        try {
            & $winrmScript
        }
        catch {
            Write-Host "  [-] WinRM deployment failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [-] WinRM script not found: $winrmScript" -ForegroundColor Red
    }
}

function Invoke-RemoveWinRMWorkflow {
    Write-Host "`n=== WinRM GPO Removal Workflow ===" -ForegroundColor Cyan
    Write-Host "  This will remove the WinRM GPO from the domain." -ForegroundColor Gray
    Write-Host "  Requires: Domain Controller, RSAT tools, Domain Admin privileges." -ForegroundColor Yellow
    Write-Host ""

    $winrmScript = Join-Path $utilitiesRoot "Enable-WinRM-Domain.ps1"
    if (Test-Path $winrmScript) {
        $confirm = Read-Host "  Proceed with WinRM GPO removal? (Y/n)"
        if ($confirm -eq 'n' -or $confirm -eq 'N') {
            Write-Host "  Aborted." -ForegroundColor Yellow
            return
        }

        try {
            & $winrmScript -Remove
        }
        catch {
            Write-Host "  [-] WinRM GPO removal failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [-] WinRM script not found: $winrmScript" -ForegroundColor Red
    }
}

function Invoke-CompareWorkflow {
    param(
        [string]$RefPath,
        [string]$CompPath,
        [string]$Method = "Name",
        [string]$OutPath
    )

    Write-Host "`n=== Software Inventory Comparison ===" -ForegroundColor Cyan
    Write-Host "  Compares InstalledSoftware.csv files between machines" -ForegroundColor Gray
    Write-Host "  Identifies software differences, version drift, and unique applications" -ForegroundColor Gray
    Write-Host ""

    # Determine if we should use interactive folder browser or manual paths
    if ([string]::IsNullOrWhiteSpace($RefPath) -and [string]::IsNullOrWhiteSpace($CompPath)) {
        Write-Host "  How would you like to select files?" -ForegroundColor Yellow
        Write-Host "    [1] Browse scan folders (recommended)" -ForegroundColor White
        Write-Host "    [2] Enter paths manually" -ForegroundColor White
        Write-Host "    [C] Cancel" -ForegroundColor Gray
        Write-Host ""

        $browseChoice = Read-Host "  Enter choice"

        switch ($browseChoice.ToUpper()) {
            "1" {
                # Use interactive folder browser
                $paths = Select-ComparePaths -ScansPath ".\Scans"
                if (-not $paths) {
                    Write-Host "  Cancelled." -ForegroundColor Yellow
                    return $null
                }
                $RefPath = $paths.ReferencePath
                $CompPath = $paths.ComparePath
            }
            "2" {
                # Manual path entry
                $RefPath = Get-ValidatedPath -Prompt "  Enter path to reference/baseline CSV file" `
                    -Example ".\Scans\Scan-20260108\COMPUTER01\InstalledSoftware.csv" `
                    -MustExist -MustBeFile
                if (-not $RefPath) { return $null }

                $CompPath = Get-ValidatedPath -Prompt "  Enter path to comparison CSV file(s) (supports wildcards)" `
                    -Example ".\Scans\Scan-20260108\COMPUTER02\InstalledSoftware.csv"
                if (-not $CompPath) { return $null }
            }
            "C" { return $null }
            default {
                Write-Host "  [-] Invalid choice" -ForegroundColor Red
                return $null
            }
        }
    }
    else {
        # Validate provided paths
        if (-not [string]::IsNullOrWhiteSpace($RefPath) -and -not (Test-Path $RefPath -PathType Leaf)) {
            Write-Host "  [-] Reference CSV file not found: $RefPath" -ForegroundColor Red
            return $null
        }
    }

    # Get comparison method
    Write-Host ""
    Write-Host "  Compare by: [1] Name  [2] NameVersion  [3] Publisher" -ForegroundColor Yellow
    $methodChoice = Read-Host "  Enter choice (default: 1)"
    $Method = switch ($methodChoice) {
        "2" { "NameVersion" }
        "3" { "Publisher" }
        default { "Name" }
    }

    # Run comparison
    $compareScript = Join-Path $utilitiesRoot "Compare-SoftwareInventory.ps1"
    if (Test-Path $compareScript) {
        Write-Host "`n  Comparing inventories..." -ForegroundColor Cyan

        $compareParams = @{}
        Add-NonEmptyParameters -Hashtable $compareParams -Parameters @{
            ReferencePath = $RefPath
            ComparePath   = $CompPath
            CompareBy     = $Method
            OutputPath    = $OutPath
        }

        try {
            $result = & $compareScript @compareParams
            return $result
        }
        catch {
            Write-Host "  [-] Comparison failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] Compare script not found: $compareScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-EventCollectionWorkflow {
    param(
        [string]$ComputerListPath,
        [string]$OutPath,
        [PSCredential]$Cred,
        [int]$Days = 14,
        [switch]$Blocked,
        [switch]$IncludeAllowed
    )

    Write-Host "`n=== AppLocker Event Collection ===" -ForegroundColor Cyan
    Write-Host "  Collects audit events (8003/8004/8005/8006) from remote computers." -ForegroundColor Gray
    Write-Host "  These events show what AppLocker would have blocked/allowed in Audit mode." -ForegroundColor Gray
    Write-Host ""

    # Get computer list
    if ([string]::IsNullOrWhiteSpace($ComputerListPath)) {
        $ComputerListPath = Get-ValidatedPath -Prompt "  Enter path to computer list file" `
            -DefaultValue ".\ADManagement\computers.csv" `
            -MustExist -MustBeFile
        if (-not $ComputerListPath) { return $null }
    }
    elseif (-not (Test-Path $ComputerListPath -PathType Leaf)) {
        Write-Host "  [-] Computer list not found: $ComputerListPath" -ForegroundColor Red
        return $null
    }

    # Get output path
    if ([string]::IsNullOrWhiteSpace($OutPath)) {
        $OutPath = Get-ValidatedPath -Prompt "  Enter output path" -DefaultValue ".\Events"
        if (-not $OutPath) { return $null }
    }

    # Get credentials
    if ($null -eq $Cred) {
        Write-Host "  Enter credentials for remote connections:" -ForegroundColor Yellow
        $Cred = Get-Credential -Message "Remote connection credentials (DOMAIN\username)"
    }

    if ($null -eq $Cred) {
        Write-Host "  [-] Credentials are required" -ForegroundColor Red
        return $null
    }

    # Configure event collection options
    Write-Host ""
    Write-Host "  Event Collection Options:" -ForegroundColor Yellow

    # Days back
    if ($Days -eq 14) {
        Write-Host "  How many days of events to collect?" -ForegroundColor Gray
        Write-Host "    [1] 7 days" -ForegroundColor White
        Write-Host "    [2] 14 days (default)" -ForegroundColor White
        Write-Host "    [3] 30 days" -ForegroundColor White
        Write-Host "    [4] 90 days" -ForegroundColor White
        Write-Host "    [5] All available" -ForegroundColor White
        $daysChoice = Read-Host "  Enter choice (default: 2)"
        $Days = switch ($daysChoice) {
            "1" { 7 }
            "3" { 30 }
            "4" { 90 }
            "5" { 0 }
            default { 14 }
        }
    }

    # Event types
    if (-not $Blocked -and -not $IncludeAllowed) {
        Write-Host ""
        Write-Host "  Which events to collect?" -ForegroundColor Gray
        Write-Host "    [1] Blocked only (8004/8006/8008) - for rule creation" -ForegroundColor White
        Write-Host "    [2] All audit events (blocked + allowed)" -ForegroundColor White
        $eventChoice = Read-Host "  Enter choice (default: 1)"
        if ($eventChoice -eq "2") {
            $IncludeAllowed = $true
        } else {
            $Blocked = $true
        }
    }

    # Run collection
    $eventScript = Join-Path $scriptRoot "Invoke-RemoteEventCollection.ps1"
    if (Test-Path $eventScript) {
        Write-Host "`n  Starting event collection..." -ForegroundColor Cyan

        $eventParams = @{
            ComputerListPath = $ComputerListPath
            OutputPath       = $OutPath
            Credential       = $Cred
            DaysBack         = $Days
        }

        if ($Blocked) {
            $eventParams.BlockedOnly = $true
        }
        if ($IncludeAllowed) {
            $eventParams.IncludeAllowedEvents = $true
        }

        try {
            $result = & $eventScript @eventParams
            return $result
        }
        catch {
            Write-Host "  [-] Event collection failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] Event collection script not found: $eventScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-ADSetupWorkflow {
    param(
        [string]$Domain,
        [string]$Parent,
        [string]$Prefix,
        [switch]$NoConfirm
    )

    Write-Host "`n=== AD Structure Setup ===" -ForegroundColor Cyan
    Write-Host "  Creates AppLocker OUs and security groups in Active Directory." -ForegroundColor Gray
    Write-Host "  Requires: ActiveDirectory module, Domain Admin privileges." -ForegroundColor Yellow
    Write-Host ""

    # Get domain name
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        $Domain = Read-Host "  Enter domain name (e.g., CONTOSO)"
    }

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        Write-Host "  [-] Domain name is required" -ForegroundColor Red
        return $null
    }

    $adScript = Join-Path $utilitiesRoot "Manage-ADResources.ps1"
    if (Test-Path $adScript) {
        $adParams = @{
            Action     = "CreateStructure"
            DomainName = $Domain
        }
        if (-not [string]::IsNullOrWhiteSpace($Parent)) {
            $adParams.ParentOU = $Parent
        }
        if (-not [string]::IsNullOrWhiteSpace($Prefix)) {
            $adParams.GroupPrefix = $Prefix
        }
        if ($NoConfirm) {
            $adParams.Force = $true
        }

        try {
            $result = & $adScript @adParams
            return $result
        }
        catch {
            Write-Host "  [-] AD setup failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] AD management script not found: $adScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-ADExportWorkflow {
    param(
        [string]$Search,
        [string]$OutPath,
        [switch]$Disabled
    )

    Write-Host "`n=== AD User Export ===" -ForegroundColor Cyan
    Write-Host "  Exports users and their group memberships to CSV for editing." -ForegroundColor Gray
    Write-Host ""

    # Ensure ADManagement folder exists
    $adMgmtPath = ".\ADManagement"
    if (-not (Test-Path $adMgmtPath)) {
        New-Item -ItemType Directory -Path $adMgmtPath -Force | Out-Null
    }

    # Get output path - default to ADManagement folder
    if ([string]::IsNullOrWhiteSpace($OutPath)) {
        $defaultPath = ".\ADManagement\ADUserGroups-Export.csv"
        $OutPath = Read-Host "  Enter output path (default: $defaultPath)"
        if ([string]::IsNullOrWhiteSpace($OutPath)) {
            $OutPath = $defaultPath
        }
    }

    $adScript = Join-Path $utilitiesRoot "Manage-ADResources.ps1"
    if (Test-Path $adScript) {
        $adParams = @{
            Action     = "ExportUsers"
            OutputPath = $OutPath
        }
        if (-not [string]::IsNullOrWhiteSpace($Search)) {
            $adParams.SearchBase = $Search
        }
        if ($Disabled) {
            $adParams.IncludeDisabled = $true
        }

        try {
            $result = & $adScript @adParams
            return $result
        }
        catch {
            Write-Host "  [-] AD export failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
    else {
        Write-Host "  [-] AD management script not found: $adScript" -ForegroundColor Red
        return $null
    }
}

function Invoke-ADImportWorkflow {
    param(
        [string]$InPath,
        [switch]$Preview
    )

    Write-Host "`n=== AD User Import ===" -ForegroundColor Cyan
    Write-Host "  Applies group membership changes from CSV to Active Directory." -ForegroundColor Gray
    Write-Host ""

    # Get input path - default to ADManagement/groups.csv
    if ([string]::IsNullOrWhiteSpace($InPath)) {
        $InPath = Get-ValidatedPath -Prompt "  Enter path to CSV file with group changes" `
            -DefaultValue ".\ADManagement\groups.csv" `
            -MustExist -MustBeFile
        if (-not $InPath) { return $null }
    }
    elseif (-not (Test-Path $InPath -PathType Leaf)) {
        Write-Host "  [-] Input file not found: $InPath" -ForegroundColor Red
        return $null
    }

    # Ask about preview mode
    if (-not $Preview) {
        $previewChoice = Read-Host "  Preview changes first? (Y/n)"
        $Preview = ($previewChoice -ne 'n' -and $previewChoice -ne 'N')
    }

    $adScript = Join-Path $utilitiesRoot "Manage-ADResources.ps1"
    if (Test-Path $adScript) {
        $adParams = @{
            Action    = "ImportUsers"
            InputPath = $InPath
        }

        if ($Preview) {
            Write-Host "`n  Running in preview mode (no changes will be made)..." -ForegroundColor Yellow
            $adParams.WhatIf = $true
        }

        try {
            & $adScript @adParams
        }
        catch {
            Write-Host "  [-] AD import failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [-] AD management script not found: $adScript" -ForegroundColor Red
    }
}

function Invoke-ADComputersWorkflow {
    param(
        [string]$OutPath,
        [string]$Type,
        [string]$Search
    )

    Write-Host "`n=== Export AD Computers ===" -ForegroundColor Cyan
    Write-Host "  Exports computer names from Active Directory to a CSV file for scanning." -ForegroundColor Gray
    Write-Host ""

    # Ensure ADManagement folder exists
    $adMgmtPath = ".\ADManagement"
    if (-not (Test-Path $adMgmtPath)) {
        New-Item -ItemType Directory -Path $adMgmtPath -Force | Out-Null
    }

    # Get output path - default to ADManagement folder
    if ([string]::IsNullOrWhiteSpace($OutPath)) {
        $defaultPath = ".\ADManagement\computers.csv"
        $OutPath = Read-Host "  Enter output path (default: $defaultPath)"
        if ([string]::IsNullOrWhiteSpace($OutPath)) {
            $OutPath = $defaultPath
        }
    }

    # Get computer type
    if ([string]::IsNullOrWhiteSpace($Type)) {
        Write-Host ""
        Write-Host "  Computer Type:" -ForegroundColor Yellow
        Write-Host "    [1] All computers (default)" -ForegroundColor White
        Write-Host "    [2] Workstations only" -ForegroundColor White
        Write-Host "    [3] Servers only" -ForegroundColor White
        Write-Host "    [4] Domain Controllers only" -ForegroundColor White
        $typeChoice = Read-Host "  Enter choice (default: 1)"
        $Type = switch ($typeChoice) {
            "2" { "Workstations" }
            "3" { "Servers" }
            "4" { "DomainControllers" }
            default { "All" }
        }
    }

    $adScript = Join-Path $utilitiesRoot "Manage-ADResources.ps1"
    if (Test-Path $adScript) {
        $adParams = @{
            Action       = "ExportComputers"
            OutputPath   = $OutPath
            ComputerType = $Type
            EnabledOnly  = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($Search)) {
            $adParams.SearchBase = $Search
        }

        try {
            & $adScript @adParams
            Write-Host ""
            Write-Host "  Tip: Use this file with [1] Scan workflow:" -ForegroundColor Cyan
            Write-Host "       .\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList $OutPath" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  [-] AD export failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [-] AD management script not found: $adScript" -ForegroundColor Red
    }
}

function Invoke-DiagnosticWorkflow {
    param(
        [string]$Type,
        [string]$Computer,
        [string]$ComputerList,
        [string]$OutPath,
        [PSCredential]$Cred
    )

    Write-Host "`n=== Diagnostic Tools ===" -ForegroundColor Cyan
    Write-Host "  Troubleshoot remote scanning issues." -ForegroundColor Gray
    Write-Host ""

    # Select diagnostic type if not provided
    if ([string]::IsNullOrWhiteSpace($Type)) {
        Write-Host "  Diagnostic Types:" -ForegroundColor Yellow
        Write-Host "    [1] Connectivity - Test ping, WinRM, sessions" -ForegroundColor White
        Write-Host "    [2] JobSession   - Test PowerShell job execution" -ForegroundColor White
        Write-Host "    [3] JobFull      - Full job test with tracing" -ForegroundColor White
        Write-Host "    [4] SimpleScan   - Scan without parallel jobs" -ForegroundColor White
        Write-Host ""

        $typeChoice = Read-Host "  Enter choice"
        $Type = switch ($typeChoice) {
            "1" { "Connectivity" }
            "2" { "JobSession" }
            "3" { "JobFull" }
            "4" { "SimpleScan" }
            default { "Connectivity" }
        }
    }

    $diagScript = Join-Path $utilitiesRoot "Test-AppLockerDiagnostic.ps1"
    if (Test-Path $diagScript) {
        $diagParams = @{
            TestType = $Type
        }

        if ($Type -eq "SimpleScan") {
            # SimpleScan needs a computer list
            if ([string]::IsNullOrWhiteSpace($ComputerList)) {
                Write-Host "  Example: .\ADManagement\computers.csv" -ForegroundColor DarkGray
                $ComputerList = Read-Host "  Enter path to computer list file"
            }
            if (-not [string]::IsNullOrWhiteSpace($ComputerList)) {
                $diagParams.ComputerListPath = $ComputerList
            }
        }
        else {
            # Connectivity, JobSession, JobFull need a single computer name
            if ([string]::IsNullOrWhiteSpace($Computer)) {
                Write-Host "  Example: WORKSTATION01 or 192.168.1.100" -ForegroundColor DarkGray
                $Computer = Read-Host "  Enter target computer name"
            }
            if ([string]::IsNullOrWhiteSpace($Computer)) {
                Write-Host "  [-] Computer name is required for $Type test" -ForegroundColor Red
                return
            }
            $diagParams.ComputerName = $Computer
        }

        if (-not [string]::IsNullOrWhiteSpace($OutPath)) {
            $diagParams.OutputPath = $OutPath
        }

        if ($null -ne $Cred) {
            $diagParams.Credential = $Cred
        }

        try {
            & $diagScript @diagParams
        }
        catch {
            Write-Host "  [-] Diagnostic failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [-] Diagnostic script not found: $diagScript" -ForegroundColor Red
    }
}

function Invoke-CORAWorkflow {
    <#
    .SYNOPSIS
    Generate CORA audit evidence package.
    #>

    Write-Host "`n=== CORA Evidence Generator ===" -ForegroundColor Magenta
    Write-Host "  Generate comprehensive audit evidence for CORA assessment." -ForegroundColor Gray
    Write-Host ""

    $coraScript = Join-Path $utilitiesRoot "New-CORAEvidence.ps1"
    if (Test-Path $coraScript) {
        # Ask for options
        Write-Host "  Options:" -ForegroundColor Yellow
        $includeRaw = Read-Host "  Include raw data files? (larger package) [y/N]"
        $includeRawData = $includeRaw.ToUpper() -eq 'Y'

        Write-Host ""
        $policyPath = Read-Host "  Path to current production policy [Enter to skip]"

        $coraParams = @{}
        if ($includeRawData) {
            $coraParams['IncludeRawData'] = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($policyPath) -and (Test-Path $policyPath)) {
            $coraParams['PolicyPath'] = $policyPath
        }

        Write-Host ""
        try {
            & $coraScript @coraParams
        }
        catch {
            Write-Host "  [-] CORA evidence generation failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  [-] CORA script not found: $coraScript" -ForegroundColor Red
    }
}

function Show-WinRMMenu {
    Write-Host ""
    Write-Host "  Main > WinRM" -ForegroundColor DarkGray
    Write-Host "  WinRM GPO Options:" -ForegroundColor Yellow
    Write-Host "    [1] Deploy  - Create WinRM GPO" -ForegroundColor White
    Write-Host "    [2] Remove  - Remove WinRM GPO" -ForegroundColor White
    Write-Host "    [B] Back" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Enter choice"
    return $choice
}

function Invoke-WinRMMenuWorkflow {
    <#
    .SYNOPSIS
    Interactive workflow for WinRM GPO management.
    #>
    do {
        $winrmChoice = (Show-WinRMMenu).ToUpper()

        switch ($winrmChoice) {
            "1" { Invoke-WinRMWorkflow }
            "2" { Invoke-RemoveWinRMWorkflow }
            "B" { }
            default {
                if ($winrmChoice -ne "B") {
                    Write-Host "  Invalid option" -ForegroundColor Red
                }
            }
        }

        if ($winrmChoice -ne "B") {
            Write-Host ""
            Read-Host "  Press Enter to continue"
        }

    } while ($winrmChoice -ne "B")
}

function Show-SoftwareListMenu {
    Write-Host ""
    Write-Host "  Main > Software Lists" -ForegroundColor DarkGray
    Write-Host "  Software List Management:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [1] View       - View, search, and export lists" -ForegroundColor White
    Write-Host "    [2] Import     - Import from scan, CSV, policy, or publishers" -ForegroundColor White
    Write-Host "    [3] Approve    - Bulk approve/unapprove items" -ForegroundColor White
    Write-Host "    [G] Generate   - Generate AppLocker policy from list" -ForegroundColor White
    Write-Host ""
    Write-Host "    [B] Back" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Enter choice"
    return $choice
}

function Invoke-SoftwareListWorkflow {
    <#
    .SYNOPSIS
    Interactive workflow for managing software lists.
    #>
    Write-Host "`n=== Software List Management ===" -ForegroundColor Cyan

    # Import software list module
    $softwareListModule = Join-Path $utilitiesRoot "Manage-SoftwareLists.ps1"
    if (Test-Path $softwareListModule) {
        . $softwareListModule
    }
    else {
        Write-Host "  [-] Software list module not found: $softwareListModule" -ForegroundColor Red
        return
    }

    # Default path for software lists
    $defaultListPath = ".\SoftwareLists"
    if (-not (Test-Path $defaultListPath)) {
        New-Item -ItemType Directory -Path $defaultListPath -Force | Out-Null
    }

    # Helper function to select or create a target list
    function Select-TargetList {
        param([string]$DefaultName = "NewList", [string]$Description = "Software list")

        $lists = Get-ChildItem -Path $defaultListPath -Filter "*.json" -ErrorAction SilentlyContinue
        $targetList = $null

        if ($lists.Count -gt 0) {
            Write-Host "  Select list or create new:" -ForegroundColor Gray
            $i = 1
            foreach ($list in $lists) {
                Write-Host "    [$i] $($list.BaseName)" -ForegroundColor White
                $i++
            }
            Write-Host "    [N] Create new list" -ForegroundColor White
            $listChoice = Read-Host "  Select"

            if ($listChoice -match "^\d+$" -and [int]$listChoice -le $lists.Count -and [int]$listChoice -ge 1) {
                $targetList = $lists[[int]$listChoice - 1].FullName
            }
        }

        if (-not $targetList) {
            $newName = Read-Host "  Enter new list name (default: $DefaultName)"
            if ([string]::IsNullOrWhiteSpace($newName)) { $newName = $DefaultName }
            $targetList = Join-Path $defaultListPath "$newName.json"
            New-SoftwareList -Name $newName -Description $Description -OutputPath $defaultListPath | Out-Null
        }

        return $targetList
    }

    do {
        $slChoice = (Show-SoftwareListMenu).ToUpper()

        switch ($slChoice) {
            "1" {
                # View, search, and export lists
                Write-Host "`n  --- Software Lists ---" -ForegroundColor Cyan
                $lists = Get-ChildItem -Path $defaultListPath -Filter "*.json" -ErrorAction SilentlyContinue
                if ($lists.Count -eq 0) {
                    Write-Host "  No software lists found in $defaultListPath" -ForegroundColor Yellow
                    Write-Host "  Use [2] Import to create one." -ForegroundColor Gray
                    continue
                }

                Write-Host ""
                $i = 1
                foreach ($list in $lists) {
                    $summary = Get-SoftwareListSummary -ListPath $list.FullName
                    Write-Host "    [$i] $($summary.Name)" -ForegroundColor White
                    Write-Host "        Items: $($summary.TotalItems) | Approved: $($summary.ApprovedItems) | Publishers: $($summary.PublisherRules) | Hashes: $($summary.HashRules)" -ForegroundColor Gray
                    $i++
                }
                Write-Host ""

                $viewChoice = Read-Host "  Enter number to view (or Enter to skip)"
                if ($viewChoice -match "^\d+$") {
                    $idx = [int]$viewChoice - 1
                    if ($idx -ge 0 -and $idx -lt $lists.Count) {
                        $selectedList = $lists[$idx]
                        $items = (Get-SoftwareList -ListPath $selectedList.FullName).items
                        Write-Host "`n  Items in $($selectedList.BaseName):" -ForegroundColor Yellow
                        foreach ($item in $items | Select-Object -First 20) {
                            $status = if ($item.approved) { "[+]" } else { "[-]" }
                            $typeIcon = switch ($item.ruleType) {
                                "Publisher" { "PUB" }
                                "Hash" { "HSH" }
                                "Path" { "PTH" }
                                default { "???" }
                            }
                            Write-Host "    $status [$typeIcon] $($item.name)" -ForegroundColor $(if ($item.approved) { "Green" } else { "Gray" })
                            if ($item.publisher) {
                                Write-Host "            Publisher: $($item.publisher)" -ForegroundColor DarkGray
                            }
                        }
                        if ($items.Count -gt 20) {
                            Write-Host "    ... and $($items.Count - 20) more items" -ForegroundColor DarkGray
                        }

                        # Offer export option
                        Write-Host ""
                        $exportChoice = Read-Host "  Export to CSV? (y/N)"
                        if ($exportChoice -eq "y" -or $exportChoice -eq "Y") {
                            $csvPath = Join-Path $defaultListPath "$($selectedList.BaseName).csv"
                            Export-SoftwareListToCsv -ListPath $selectedList.FullName -OutputPath $csvPath
                        }
                    }
                }
            }
            "2" {
                # Import from various sources (sub-menu)
                Write-Host "`n  --- Import Software ---" -ForegroundColor Cyan
                Write-Host "    [1] Scan data   - From remote scan results" -ForegroundColor White
                Write-Host "    [2] CSV file    - From exported/external CSV" -ForegroundColor White
                Write-Host "    [3] Policy XML  - From existing AppLocker policy" -ForegroundColor White
                Write-Host "    [4] Publishers  - Common trusted publishers (Microsoft, Adobe, etc.)" -ForegroundColor White
                Write-Host "    [5] Executable  - Single executable file" -ForegroundColor White
                Write-Host "    [B] Back" -ForegroundColor Gray
                Write-Host ""
                $importChoice = Read-Host "  Select source"

                if ($importChoice -eq "B" -or $importChoice -eq "b") { continue }

                switch ($importChoice) {
                    "1" {
                        # Import from scan data
                        Write-Host ""
                        $targetList = Select-TargetList -DefaultName "ScanImport" -Description "Imported from scan"

                        Write-Host ""
                        Write-Host "  Select scan data:" -ForegroundColor Yellow
                        Write-Host "    [1] Browse folders" -ForegroundColor White
                        Write-Host "    [2] Enter path" -ForegroundColor Gray
                        $browseChoice = Read-Host "  Choice"

                        $scanPath = $null
                        if ($browseChoice -eq "1") {
                            $scanPath = Select-ScanPath -ScansPath ".\Scans" -Prompt "import source" -AllowRecursive
                        } else {
                            $scanPath = Read-Host "  Enter path"
                        }

                        if ($scanPath -and (Test-Path $scanPath)) {
                            Write-Host ""
                            Write-Host "  Filter:" -ForegroundColor Gray
                            Write-Host "    [1] Signed only (publisher rules)" -ForegroundColor White
                            Write-Host "    [2] Unsigned only (hash rules)" -ForegroundColor White
                            Write-Host "    [3] All software" -ForegroundColor White
                            $filterChoice = Read-Host "  Select"

                            $importParams = @{ ScanPath = $scanPath; ListPath = $targetList; Deduplicate = $true }
                            switch ($filterChoice) {
                                "1" { $importParams.SignedOnly = $true }
                                "2" { $importParams.UnsignedOnly = $true }
                            }

                            $autoApprove = Read-Host "  Auto-approve? (y/N)"
                            if ($autoApprove -eq "y" -or $autoApprove -eq "Y") { $importParams.AutoApprove = $true }

                            Import-ScanDataToSoftwareList @importParams
                        } else {
                            Write-Host "  [-] Path not found or cancelled" -ForegroundColor Red
                        }
                    }
                    "2" {
                        # Import from CSV
                        Write-Host ""
                        Write-Host "  CSV columns: name, publisher, ruleType, approved, category, hash, notes" -ForegroundColor Gray
                        $targetList = Select-TargetList -DefaultName "CSVImport" -Description "Imported from CSV"

                        $csvPath = Read-Host "  CSV file path"
                        if (-not (Test-Path $csvPath)) {
                            Write-Host "  [-] File not found" -ForegroundColor Red
                            continue
                        }

                        $totalRows = (Import-Csv -Path $csvPath | Measure-Object).Count
                        Write-Host "  Found $totalRows rows" -ForegroundColor Cyan

                        $confirm = Read-Host "  Import? (Y/n)"
                        if ($confirm -ne "n" -and $confirm -ne "N") {
                            Import-SoftwareListFromCsv -CsvPath $csvPath -ListPath $targetList
                            Write-Host "  [+] Imported!" -ForegroundColor Green
                        }
                    }
                    "3" {
                        # Import from AppLocker policy
                        Write-Host ""
                        $targetList = Select-TargetList -DefaultName "PolicyImport" -Description "Imported from policy"

                        $policyPath = Read-Host "  Policy XML path"
                        if (-not (Test-Path $policyPath)) {
                            Write-Host "  [-] File not found" -ForegroundColor Red
                            continue
                        }

                        Write-Host "  Rule types: [1] All  [2] Publisher only  [3] Hash only" -ForegroundColor Gray
                        $ruleTypeChoice = Read-Host "  Select"

                        $importParams = @{ PolicyPath = $policyPath; ListPath = $targetList; AllowOnly = $true }
                        switch ($ruleTypeChoice) {
                            "2" { $importParams.RuleTypes = "Publisher" }
                            "3" { $importParams.RuleTypes = "Hash" }
                            default { $importParams.RuleTypes = "All" }
                        }

                        $autoApprove = Read-Host "  Auto-approve? (Y/n)"
                        if ($autoApprove -ne "n" -and $autoApprove -ne "N") { $importParams.AutoApprove = $true }

                        Import-AppLockerPolicyToSoftwareList @importParams
                    }
                    "4" {
                        # Import common publishers
                        Write-Host ""
                        $targetList = Select-TargetList -DefaultName "TrustedPublishers" -Description "Common trusted publishers"

                        $categories = Get-CommonPublisherCategories
                        Write-Host "  Categories: $($categories -join ', ')" -ForegroundColor Gray
                        Write-Host "  [A] All categories" -ForegroundColor White
                        $catChoice = Read-Host "  Select category or [A]"

                        $importParams = @{ ListPath = $targetList }
                        if ($catChoice -ne "A" -and $catChoice -ne "a" -and -not [string]::IsNullOrWhiteSpace($catChoice)) {
                            $importParams.Category = $catChoice
                        }

                        $autoApprove = Read-Host "  Auto-approve? (Y/n)"
                        if ($autoApprove -ne "n" -and $autoApprove -ne "N") { $importParams.AutoApprove = $true }

                        Import-CommonPublishersToSoftwareList @importParams
                    }
                    "5" {
                        # Import single executable
                        Write-Host ""
                        $targetList = Select-TargetList -DefaultName "Imported" -Description "Imported executables"

                        $exePath = Read-Host "  Executable path"
                        if (Test-Path $exePath) {
                            $category = Read-Host "  Category (default: Imported)"
                            if ([string]::IsNullOrWhiteSpace($category)) { $category = "Imported" }
                            Import-ExecutableToSoftwareList -FilePath $exePath -ListPath $targetList -Category $category
                        } else {
                            Write-Host "  [-] File not found" -ForegroundColor Red
                        }
                    }
                    default {
                        Write-Host "  [-] Invalid choice" -ForegroundColor Red
                    }
                }
            }
            "3" {
                # Bulk approve/unapprove items
                Write-Host "`n  --- Bulk Approval ---" -ForegroundColor Cyan
                $lists = Get-ChildItem -Path $defaultListPath -Filter "*.json" -ErrorAction SilentlyContinue
                if ($lists.Count -eq 0) {
                    Write-Host "  No software lists found." -ForegroundColor Yellow
                    continue
                }

                $i = 1
                foreach ($list in $lists) {
                    $summary = Get-SoftwareListSummary -ListPath $list.FullName
                    Write-Host "    [$i] $($list.BaseName) ($($summary.ApprovedItems)/$($summary.TotalItems) approved)" -ForegroundColor White
                    $i++
                }
                $listChoice = Read-Host "  Select list"
                if (-not ($listChoice -match "^\d+$") -or [int]$listChoice -lt 1 -or [int]$listChoice -gt $lists.Count) { continue }
                $selectedListPath = $lists[[int]$listChoice - 1].FullName

                Write-Host ""
                Write-Host "    [1] Approve all    [2] Unapprove all" -ForegroundColor White
                Write-Host "    [3] By category    [4] By publisher pattern" -ForegroundColor White
                $actionChoice = Read-Host "  Action"

                $approvalParams = @{ ListPath = $selectedListPath }

                switch ($actionChoice) {
                    "1" { $approvalParams.Approved = $true; $approvalParams.All = $true }
                    "2" { $approvalParams.Approved = $false; $approvalParams.All = $true }
                    "3" {
                        $summary = Get-SoftwareListSummary -ListPath $selectedListPath
                        Write-Host "  Categories: $($summary.Categories -join ', ')" -ForegroundColor DarkGray
                        $category = Read-Host "  Category"
                        $approve = Read-Host "  Approve (Y) or Unapprove (N)?"
                        $approvalParams.Category = $category
                        $approvalParams.Approved = ($approve -eq "Y" -or $approve -eq "y")
                    }
                    "4" {
                        $publisher = Read-Host "  Publisher pattern (e.g., *MICROSOFT*)"
                        $approve = Read-Host "  Approve (Y) or Unapprove (N)?"
                        $approvalParams.Publisher = $publisher
                        $approvalParams.Approved = ($approve -eq "Y" -or $approve -eq "y")
                    }
                    default { Write-Host "  [-] Invalid choice" -ForegroundColor Red; continue }
                }

                Set-SoftwareListItemApproval @approvalParams
            }
            "G" {
                # Generate policy from software list using Build Guide mode (with AppLocker groups)
                Write-Host "`n  --- Generate Policy from Software List (Build Guide) ---" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  This uses Build Guide mode with proper AppLocker groups:" -ForegroundColor Gray
                Write-Host "    - AppLocker-Admins: Microsoft + approved vendor publishers" -ForegroundColor DarkGray
                Write-Host "    - AppLocker-StandardUsers: Path-based allows only (least privilege)" -ForegroundColor DarkGray
                Write-Host "    - AppLocker-ServiceAccounts: Vendor publishers only" -ForegroundColor DarkGray
                Write-Host "    - AppLocker-Installers: Vendor MSI access" -ForegroundColor DarkGray
                Write-Host ""

                # Select software list
                $lists = Get-ChildItem -Path $defaultListPath -Filter "*.json" -ErrorAction SilentlyContinue
                if ($lists.Count -eq 0) {
                    Write-Host "  [-] No software lists found. Create one first." -ForegroundColor Red
                    continue
                }

                Write-Host "  Select software list:" -ForegroundColor Yellow
                $i = 1
                foreach ($list in $lists) {
                    $summary = Get-SoftwareListSummary -ListPath $list.FullName
                    Write-Host "    [$i] $($list.BaseName) ($($summary.ApprovedItems) approved items)" -ForegroundColor White
                    $i++
                }
                Write-Host ""
                $listChoice = Read-Host "  Enter number (1-$($lists.Count))"
                if (-not ($listChoice -match "^\d+$") -or [int]$listChoice -lt 1 -or [int]$listChoice -gt $lists.Count) {
                    Write-Host "  [-] Invalid selection. Please enter a number between 1 and $($lists.Count)." -ForegroundColor Red
                    continue
                }
                $selectedList = $lists[[int]$listChoice - 1].FullName

                # Get domain name (required for group SID resolution)
                Write-Host ""
                Write-Host "  Domain Configuration:" -ForegroundColor Yellow
                Write-Host "    Enter the NetBIOS domain name (e.g., CONTOSO, CORP, MYDOMAIN)" -ForegroundColor Gray
                Write-Host "    This is used to resolve AppLocker group SIDs." -ForegroundColor Gray
                Write-Host ""
                $domainName = Read-Host "  Domain name"
                if ([string]::IsNullOrWhiteSpace($domainName)) {
                    Write-Host "  [-] Domain name is required for Build Guide mode." -ForegroundColor Red
                    continue
                }
                # Validate domain name format (alphanumeric, max 15 chars for NetBIOS)
                if ($domainName -notmatch "^[A-Za-z0-9\-]+$") {
                    Write-Host "  [-] Invalid domain name. Use alphanumeric characters only." -ForegroundColor Red
                    continue
                }
                $domainName = $domainName.ToUpper()

                # Get target type
                Write-Host ""
                Write-Host "  Target System Type:" -ForegroundColor Yellow
                Write-Host "    [1] Workstation   - End-user workstations (recommended for most deployments)" -ForegroundColor White
                Write-Host "    [2] Server        - Member servers" -ForegroundColor White
                Write-Host "    [3] DC            - Domain Controllers" -ForegroundColor White
                Write-Host ""
                $targetChoice = Read-Host "  Enter choice (1-3)"
                $targetType = switch ($targetChoice) {
                    "1" { "Workstation" }
                    "2" { "Server" }
                    "3" { "DomainController" }
                    default { $null }
                }
                if (-not $targetType) {
                    Write-Host "  [-] Invalid target type. Please enter 1, 2, or 3." -ForegroundColor Red
                    continue
                }

                # Get deployment phase
                Write-Host ""
                Write-Host "  Deployment Phase:" -ForegroundColor Yellow
                Write-Host "    [1] Phase 1 - EXE rules only (lowest risk, start here)" -ForegroundColor White
                Write-Host "    [2] Phase 2 - EXE + Script rules" -ForegroundColor White
                Write-Host "    [3] Phase 3 - EXE + Script + MSI/Installer rules" -ForegroundColor White
                Write-Host "    [4] Phase 4 - Full enforcement (EXE + Script + MSI + DLL)" -ForegroundColor White
                Write-Host ""
                $phaseChoice = Read-Host "  Enter phase (1-4)"
                if ($phaseChoice -notmatch "^[1-4]$") {
                    Write-Host "  [-] Invalid phase. Please enter a number between 1 and 4." -ForegroundColor Red
                    continue
                }
                $phase = [int]$phaseChoice

                # Optional: Include deny rules
                Write-Host ""
                $includeDeny = Read-Host "  Include explicit deny rules for user-writable paths? (Y/n)"
                $skipDenyRules = ($includeDeny -eq "n" -or $includeDeny -eq "N")

                # Show summary and confirm
                Write-Host ""
                Write-Host "  ================================================" -ForegroundColor Cyan
                Write-Host "  Policy Generation Summary:" -ForegroundColor Yellow
                Write-Host "    Software List: $(Split-Path -Leaf $selectedList)" -ForegroundColor White
                Write-Host "    Domain: $domainName" -ForegroundColor White
                Write-Host "    Target Type: $targetType" -ForegroundColor White
                Write-Host "    Phase: $phase" -ForegroundColor White
                Write-Host "    Deny Rules: $(if ($skipDenyRules) { 'Disabled' } else { 'Enabled' })" -ForegroundColor White
                Write-Host ""
                Write-Host "  AppLocker Groups (will be created/used):" -ForegroundColor Yellow
                Write-Host "    $domainName\AppLocker-Admins" -ForegroundColor DarkGray
                Write-Host "    $domainName\AppLocker-StandardUsers" -ForegroundColor DarkGray
                Write-Host "    $domainName\AppLocker-ServiceAccounts" -ForegroundColor DarkGray
                Write-Host "    $domainName\AppLocker-Installers" -ForegroundColor DarkGray
                Write-Host "  ================================================" -ForegroundColor Cyan
                Write-Host ""

                $confirm = Read-Host "  Proceed with policy generation? (Y/n)"
                if ($confirm -eq "n" -or $confirm -eq "N") {
                    Write-Host "  [-] Policy generation cancelled." -ForegroundColor Yellow
                    continue
                }

                Write-Host ""
                Write-Host "  Generating Build Guide policy with AppLocker groups..." -ForegroundColor Cyan
                Write-Host ""

                # Build parameters for New-AppLockerPolicyFromGuide.ps1
                $policyScript = Join-Path $PSScriptRoot "New-AppLockerPolicyFromGuide.ps1"
                $policyParams = @{
                    TargetType       = $targetType
                    DomainName       = $domainName
                    Phase            = $phase
                    SoftwareListPath = $selectedList
                    EnforcementMode  = "AuditOnly"
                }

                if ($skipDenyRules) {
                    $policyParams.SkipDenyRules = $true
                }

                & $policyScript @policyParams

                Write-Host ""
                Write-Host "  [+] Policy generation complete!" -ForegroundColor Green
                Write-Host "  [+] Policy uses least privilege with AppLocker groups." -ForegroundColor Green
            }
            "B" { }
            default {
                if ($slChoice -ne "B") {
                    Write-Host "  [-] Invalid choice" -ForegroundColor Red
                }
            }
        }

        if ($slChoice -ne "B") {
            Write-Host ""
            Read-Host "  Press Enter to continue"
        }

    } while ($slChoice -ne "B")
}

#endregion

#region Folder Browser Functions

<#
.SYNOPSIS
    Displays a list of folders and allows numbered selection.

.DESCRIPTION
    Interactive folder browser that presents folders as a numbered list
    with options to navigate back or cancel. Supports filtering.

.PARAMETER Path
    Base path to list folders from.

.PARAMETER Title
    Title to display above the list.

.PARAMETER Filter
    Optional filter pattern for folder names.

.PARAMETER AllowManualEntry
    If true, allows user to type a custom path.

.PARAMETER AllowSelectAll
    If true, shows option to select all folders for recursive import.

.PARAMETER SelectAllLabel
    Label text for the select all option. Defaults to "Import all folders recursively".

.RETURNS
    Selected folder path, $null if cancelled, "BACK" if user chose to go back, or "ALL" if select all chosen.
#>
function Show-FolderBrowser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [ValidateNotNullOrEmpty()]
        [string]$Title = "Select a folder",

        [ValidateNotNullOrEmpty()]
        [string]$Filter = "*",

        [switch]$AllowManualEntry,

        [switch]$ShowFiles,

        [ValidateNotNullOrEmpty()]
        [string]$FileFilter = "*.csv",

        [switch]$AllowSelectAll,

        [ValidateNotNullOrEmpty()]
        [string]$SelectAllLabel = "Import all folders recursively"
    )

    # Validate path exists
    if (-not (Test-Path $Path)) {
        Write-Host "  [-] Path not found: $Path" -ForegroundColor Red
        return $null
    }

    # Get folders sorted by date (newest first)
    $items = if ($ShowFiles) {
        Get-ChildItem -Path $Path -Filter $FileFilter -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
    } else {
        Get-ChildItem -Path $Path -Directory -Filter $Filter -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
    }

    if ($items.Count -eq 0) {
        $itemType = if ($ShowFiles) { "files" } else { "folders" }
        Write-Host "  [-] No $itemType found in: $Path" -ForegroundColor Yellow
        return $null
    }

    # Check if select-all option should be available
    $selectAllAvailable = $AllowSelectAll -and ($items.Count -gt 1)

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "  Location: $Path" -ForegroundColor DarkGray
    Write-Host ""

    # Display items with numbers
    $i = 1
    foreach ($item in $items) {
        $dateStr = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        $name = $item.Name
        Write-Host "    [$i] $name" -ForegroundColor White -NoNewline
        Write-Host "  ($dateStr)" -ForegroundColor DarkGray
        $i++
    }

    Write-Host ""
    if ($selectAllAvailable) {
        Write-Host "    [A] $SelectAllLabel ($($items.Count) folders)" -ForegroundColor Cyan
    }
    if ($AllowManualEntry) {
        Write-Host "    [M] Enter path manually" -ForegroundColor Gray
    }
    Write-Host "    [B] Back" -ForegroundColor Gray
    Write-Host "    [C] Cancel" -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "  Enter choice"

    # Validate input - handle null, empty, or whitespace
    if ([string]::IsNullOrWhiteSpace($choice)) {
        Write-Host "  [-] No selection made" -ForegroundColor Red
        return $null
    }

    $choice = $choice.Trim().ToUpper()

    switch ($choice) {
        "A" {
            if ($selectAllAvailable) {
                return "ALL"
            }
            Write-Host "  [-] Invalid selection" -ForegroundColor Red
            return $null
        }
        "B" { return "BACK" }
        "C" { return $null }
        "M" {
            if (-not $AllowManualEntry) {
                Write-Host "  [-] Invalid selection" -ForegroundColor Red
                return $null
            }
            $manualPath = Read-Host "  Enter path"
            if ([string]::IsNullOrWhiteSpace($manualPath)) {
                Write-Host "  [-] No path entered" -ForegroundColor Red
                return $null
            }
            $manualPath = $manualPath.Trim()
            if (Test-Path $manualPath) {
                return $manualPath
            }
            Write-Host "  [-] Path not found: $manualPath" -ForegroundColor Red
            return $null
        }
        default {
            if ($choice -match "^\d+$") {
                $idx = [int]$choice - 1
                if ($idx -ge 0 -and $idx -lt $items.Count) {
                    return $items[$idx].FullName
                }
                Write-Host "  [-] Selection out of range (1-$($items.Count))" -ForegroundColor Red
                return $null
            }
            Write-Host "  [-] Invalid selection" -ForegroundColor Red
            return $null
        }
    }
}


<#
.SYNOPSIS
    Navigates through scan folder hierarchy for Compare workflow.

.DESCRIPTION
    Multi-step folder browser specifically for scan data:
    1. Select a scan date folder (e.g., Scan-20260108-143000)
    2. Select a computer folder within that scan (or all computers if AllowRecursive)
    3. Select a CSV file (Executables.csv, Publishers.csv, etc.)

.PARAMETER ScansPath
    Base path to scans folder. Defaults to .\Scans

.PARAMETER SelectFile
    If true, navigates all the way to file selection.

.PARAMETER Prompt
    Context label shown in folder selection prompts. Defaults to "baseline".

.PARAMETER AllowRecursive
    If true, shows option to import all computer folders recursively.

.RETURNS
    Selected path or $null if cancelled.
#>
function Select-ScanPath {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$ScansPath = ".\Scans",

        [switch]$SelectFile,

        [ValidateNotNullOrEmpty()]
        [string]$Prompt = "baseline",

        [switch]$AllowRecursive
    )

    # Ensure scans folder exists
    if (-not (Test-Path $ScansPath)) {
        Write-Host "  [-] Scans folder not found: $ScansPath" -ForegroundColor Red
        Write-Host "  [-] Run a scan first to create scan data." -ForegroundColor Yellow
        return $null
    }

    # Step 1: Select scan date folder
    $scanFolder = Show-FolderBrowser -Path $ScansPath `
        -Title "Select scan date folder for $Prompt" `
        -Filter "Scan-*" `
        -AllowManualEntry

    if ($null -eq $scanFolder -or $scanFolder -eq "BACK") {
        return $null
    }

    # Validate selected folder exists (in case of manual entry)
    if (-not (Test-Path $scanFolder)) {
        Write-Host "  [-] Selected folder not found: $scanFolder" -ForegroundColor Red
        return $null
    }

    # Step 2: Select computer folder (with optional recursive import)
    $browserParams = @{
        Path             = $scanFolder
        Title            = "Select computer folder ($Prompt)"
        AllowManualEntry = $true
    }

    if ($AllowRecursive) {
        $browserParams.AllowSelectAll = $true
        $browserParams.SelectAllLabel = "Import all computers recursively"
    }

    $computerFolder = Show-FolderBrowser @browserParams

    if ($null -eq $computerFolder) {
        return $null
    }
    if ($computerFolder -eq "BACK") {
        # Go back to scan folder selection (non-recursive to avoid deep call stacks)
        return Select-ScanPath -ScansPath $ScansPath -SelectFile:$SelectFile -Prompt $Prompt -AllowRecursive:$AllowRecursive
    }
    if ($computerFolder -eq "ALL") {
        # Validate that subfolders contain scan data before returning
        $computerFolders = Get-ChildItem -Path $scanFolder -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName "*.csv") }

        if ($computerFolders.Count -eq 0) {
            Write-Host "  [-] No computer folders with scan data found in: $(Split-Path $scanFolder -Leaf)" -ForegroundColor Red
            return $null
        }

        Write-Host "  [+] Selected: All $($computerFolders.Count) computers in $(Split-Path $scanFolder -Leaf)" -ForegroundColor Green
        return $scanFolder
    }

    # Validate selected computer folder exists (in case of manual entry)
    if (-not (Test-Path $computerFolder)) {
        Write-Host "  [-] Selected folder not found: $computerFolder" -ForegroundColor Red
        return $null
    }

    # Step 3: Auto-select InstalledSoftware.csv (if file selection requested)
    if ($SelectFile) {
        $installedSoftwarePath = Join-Path $computerFolder "InstalledSoftware.csv"

        if (Test-Path $installedSoftwarePath) {
            Write-Host "  [+] Auto-selected: InstalledSoftware.csv" -ForegroundColor Green
            return $installedSoftwarePath
        }
        else {
            Write-Host "  [-] InstalledSoftware.csv not found in: $computerFolder" -ForegroundColor Red
            Write-Host "  [-] Ensure the scan collected installed software data." -ForegroundColor Yellow
            return $null
        }
    }

    return $computerFolder
}


<#
.SYNOPSIS
    Interactive compare path selector for software inventory comparison.

.DESCRIPTION
    Guides user through selecting:
    1. Baseline/reference path (workstation/server to compare from)
    2. Comparison path (computer to compare against)

.PARAMETER ScansPath
    Base path to scans folder.

.RETURNS
    Hashtable with ReferencePath and ComparePath, or $null if cancelled.
#>
function Select-ComparePaths {
    [CmdletBinding()]
    param(
        [string]$ScansPath = ".\Scans"
    )

    Write-Host ""
    Write-Host "  --- Select Paths for Comparison ---" -ForegroundColor Cyan
    Write-Host "  You will select:" -ForegroundColor Gray
    Write-Host "    1. A baseline/reference file (e.g., a golden image or standard workstation)" -ForegroundColor Gray
    Write-Host "    2. A comparison file (the machine to check against baseline)" -ForegroundColor Gray
    Write-Host ""

    # Select baseline
    Write-Host "  Step 1: Select BASELINE (reference)" -ForegroundColor Yellow
    $referencePath = Select-ScanPath -ScansPath $ScansPath -SelectFile -Prompt "BASELINE"

    if (-not $referencePath) {
        return $null
    }

    Write-Host ""
    Write-Host "  [+] Baseline: $referencePath" -ForegroundColor Green
    Write-Host ""

    # Select comparison target
    Write-Host "  Step 2: Select COMPARISON target" -ForegroundColor Yellow
    $comparePath = Select-ScanPath -ScansPath $ScansPath -SelectFile -Prompt "COMPARISON"

    if (-not $comparePath) {
        return $null
    }

    Write-Host ""
    Write-Host "  [+] Comparison: $comparePath" -ForegroundColor Green

    return @{
        ReferencePath = $referencePath
        ComparePath   = $comparePath
    }
}


<#
.SYNOPSIS
    Interactive scan folder selector for Generate workflow.

.DESCRIPTION
    Guides user through selecting scan data for policy generation.

.PARAMETER ScansPath
    Base path to scans folder.

.RETURNS
    Selected scan path or $null if cancelled.
#>
function Select-ScanDataPath {
    [CmdletBinding()]
    param(
        [string]$ScansPath = ".\Scans"
    )

    Write-Host ""
    Write-Host "  --- Select Scan Data ---" -ForegroundColor Cyan

    # Check if scans folder exists
    if (-not (Test-Path $ScansPath)) {
        Write-Host "  [-] Scans folder not found: $ScansPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor Yellow
        Write-Host "    [1] Run a scan first (recommended)" -ForegroundColor White
        Write-Host "    [M] Enter path manually" -ForegroundColor Gray
        Write-Host "    [C] Cancel" -ForegroundColor Gray
        Write-Host ""

        $choice = Read-Host "  Enter choice"
        switch ($choice.ToUpper()) {
            "1" { return "RUN_SCAN" }
            "M" {
                $manualPath = Read-Host "  Enter scan data path"
                if (Test-Path $manualPath) {
                    return $manualPath
                }
                Write-Host "  [-] Path not found" -ForegroundColor Red
                return $null
            }
            default { return $null }
        }
    }

    # Select scan date folder
    $scanFolder = Show-FolderBrowser -Path $ScansPath `
        -Title "Select scan date folder" `
        -Filter "Scan-*" `
        -AllowManualEntry

    if ($null -eq $scanFolder -or $scanFolder -eq "BACK") {
        return $null
    }

    return $scanFolder
}

#endregion

#region Helper Functions

<#
.SYNOPSIS
    Builds parameter hashtable for workflow invocation in direct mode.
#>
function Get-WorkflowParameters {
    param(
        [string]$WorkflowMode,
        [hashtable]$AllParams
    )

    $params = @{}

    switch ($WorkflowMode) {
        "Scan" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                ComputerListPath = $AllParams.ComputerList
                OutputPath       = $AllParams.OutputPath
                Credential       = $AllParams.Credential
            }
        }
        "Generate" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                ScanPath   = $AllParams.ScanPath
                OutputPath = $AllParams.OutputPath
                Simplified = $AllParams.Simplified
            }
            # Build Guide parameters
            if (-not $AllParams.Simplified -and $AllParams.TargetType) {
                Add-NonEmptyParameters -Hashtable $params -Parameters @{
                    TargetType = $AllParams.TargetType
                    DomainName = $AllParams.DomainName
                    Phase      = $AllParams.Phase
                }
            }
        }
        "Merge" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                InputPath  = $AllParams.ScanPath
                OutputPath = $AllParams.OutputPath
            }
        }
        "Validate" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                PolicyPath = $AllParams.PolicyPath
            }
        }
        "Full" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                ComputerList = $AllParams.ComputerList
                OutputPath   = $AllParams.OutputPath
                Credential   = $AllParams.Credential
                Simplified   = $AllParams.Simplified
            }
            if (-not $AllParams.Simplified -and $AllParams.TargetType) {
                Add-NonEmptyParameters -Hashtable $params -Parameters @{
                    TargetType = $AllParams.TargetType
                    DomainName = $AllParams.DomainName
                    Phase      = $AllParams.Phase
                }
            }
        }
        "Compare" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                RefPath  = $AllParams.ReferencePath
                CompPath = $AllParams.ComparePath
                Method   = $AllParams.CompareBy
                OutPath  = $AllParams.OutputPath
            }
        }
        "Events" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                ComputerListPath = $AllParams.ComputerList
                OutPath          = $AllParams.OutputPath
                Cred             = $AllParams.Credential
                Days             = $AllParams.DaysBack
                Blocked          = $AllParams.BlockedOnly
                IncludeAllowed   = $AllParams.IncludeAllowedEvents
            }
        }
        "ADSetup" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                Domain    = $AllParams.DomainName
                Parent    = $AllParams.ParentOU
                Prefix    = $AllParams.GroupPrefix
                NoConfirm = $AllParams.Force
            }
        }
        "ADExport" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                Search   = $AllParams.SearchBase
                OutPath  = $AllParams.OutputPath
                Disabled = $AllParams.IncludeDisabled
            }
        }
        "ADImport" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                InPath = $AllParams.InputPath
            }
        }
        "Diagnostic" {
            Add-NonEmptyParameters -Hashtable $params -Parameters @{
                Type         = $AllParams.DiagnosticType
                Computer     = $AllParams.ComputerName
                ComputerList = $AllParams.ComputerList
                OutPath      = $AllParams.OutputPath
                Cred         = $AllParams.Credential
            }
        }
    }

    return $params
}

#endregion

#region Main Execution

# Show banner
Show-Banner

# Handle direct mode execution
if ($Mode -ne "Interactive") {
    # Build parameter hashtable for the specified workflow
    $workflowParams = Get-WorkflowParameters -WorkflowMode $Mode -AllParams $PSBoundParameters

    # Invoke the appropriate workflow
    switch ($Mode) {
        "Scan"       { Invoke-ScanWorkflow @workflowParams }
        "Generate"   { Invoke-GenerateWorkflow @workflowParams }
        "Merge"      { Invoke-MergeWorkflow @workflowParams }
        "Validate"   { Invoke-ValidateWorkflow @workflowParams }
        "Full"       { Invoke-FullWorkflow @workflowParams }
        "Compare"    { Invoke-CompareWorkflow @workflowParams }
        "Events"     { Invoke-EventCollectionWorkflow @workflowParams }
        "ADSetup"    { Invoke-ADSetupWorkflow @workflowParams }
        "ADExport"   { Invoke-ADExportWorkflow @workflowParams }
        "ADImport"   { Invoke-ADImportWorkflow @workflowParams }
        "Diagnostic" { Invoke-DiagnosticWorkflow @workflowParams }
    }
    exit
}

# Interactive mode
do {
    $choice = (Show-Menu).ToUpper()

    switch ($choice) {
        # Collection
        "1" { Invoke-ScanWorkflow }
        "2" { Invoke-EventCollectionWorkflow }
        # Analysis
        "3" { Invoke-CompareWorkflow }
        "4" { Invoke-ValidateWorkflow }
        # Policy
        "5" { Invoke-GenerateWorkflow }
        "6" { Invoke-MergeWorkflow }
        "S" { Invoke-SoftwareListWorkflow }
        # Deployment
        "7" { Invoke-ADSetupWorkflow }
        "8" { Invoke-ADExportWorkflow }
        "9" { Invoke-ADImportWorkflow }
        "C" { Invoke-ADComputersWorkflow }
        "W" { Invoke-WinRMMenuWorkflow }
        "D" { Invoke-DiagnosticWorkflow }
        # Compliance
        "R" { Invoke-CORAWorkflow }
        # Workflows
        "F" { Invoke-FullWorkflow }
        "Q" {
            Write-Host "`n  Goodbye!" -ForegroundColor Cyan
            exit
        }
        default {
            Write-Host "  Invalid option, please try again." -ForegroundColor Red
        }
    }

    if ($choice -in @("1", "2", "3", "4", "5", "6", "7", "8", "9", "C", "F", "W", "S", "D", "R")) {
        Write-Host ""
        Read-Host "  Press Enter to continue"
        Clear-Host
        Show-Banner
    }
} while ($true)

#endregion
