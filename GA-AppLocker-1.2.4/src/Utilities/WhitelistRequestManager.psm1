<#
.SYNOPSIS
    Self-service whitelist request management for AppLocker.

.DESCRIPTION
    Provides a workflow for users to request application whitelisting:
    - Submit whitelist requests with justification
    - Admin review and approval queue
    - Automatic rule generation upon approval
    - Request tracking and audit trail
    - Email/webhook notifications

.NOTES
    Requests are stored in JSON format for easy integration with ticketing systems.
#>

#Requires -Version 5.1

$Script:RequestStorePath = $null
$Script:Config = @{
    RequireJustification = $true
    RequireManagerApproval = $false
    AutoScanOnSubmit = $true
    NotifyOnSubmit = $true
    NotifyOnApproval = $true
    ApprovalWebhook = $null
    ApprovalEmail = $null
}

#region Initialization

<#
.SYNOPSIS
    Initializes the whitelist request system.

.PARAMETER StorePath
    Path for storing request data.

.PARAMETER Config
    Optional configuration hashtable.
#>
function Initialize-WhitelistRequestStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StorePath,

        [hashtable]$Config
    )

    $Script:RequestStorePath = $StorePath

    # Merge custom config
    if ($Config) {
        foreach ($key in $Config.Keys) {
            if ($Script:Config.ContainsKey($key)) {
                $Script:Config[$key] = $Config[$key]
            }
        }
    }

    # Create store structure
    $folders = @(
        'pending',
        'approved',
        'rejected',
        'implemented',
        'archive'
    )

    foreach ($folder in $folders) {
        $path = Join-Path $StorePath $folder
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }

    # Create store metadata
    $metaPath = Join-Path $StorePath 'store.json'
    if (-not (Test-Path $metaPath)) {
        @{
            Created = Get-Date -Format 'o'
            TotalRequests = 0
            Config = $Script:Config
        } | ConvertTo-Json | Out-File $metaPath -Encoding UTF8
    }

    Write-Host "Whitelist request store initialized: $StorePath" -ForegroundColor Green
}

#endregion

#region Request Submission

<#
.SYNOPSIS
    Submits a new whitelist request.

.PARAMETER ApplicationPath
    Full path to the application executable.

.PARAMETER ApplicationName
    Friendly name for the application.

.PARAMETER Justification
    Business justification for the request.

.PARAMETER RequestedBy
    User submitting the request.

.PARAMETER Department
    Department of the requester.

.PARAMETER Priority
    Request priority: Low, Normal, High, Critical.

.PARAMETER ManagerEmail
    Manager's email for approval (if required).

.EXAMPLE
    New-WhitelistRequest -ApplicationPath "C:\Tools\app.exe" -ApplicationName "My Tool" -Justification "Needed for daily work"
#>
function New-WhitelistRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApplicationPath,

        [Parameter(Mandatory)]
        [string]$ApplicationName,

        [string]$Justification,

        [string]$RequestedBy = $env:USERNAME,

        [string]$Department,

        [ValidateSet('Low', 'Normal', 'High', 'Critical')]
        [string]$Priority = 'Normal',

        [string]$ManagerEmail,

        [string]$TicketNumber,

        [string[]]$AffectedComputers = @($env:COMPUTERNAME)
    )

    if (-not $Script:RequestStorePath) {
        throw "Request store not initialized. Call Initialize-WhitelistRequestStore first."
    }

    # Validate justification if required
    if ($Script:Config.RequireJustification -and -not $Justification) {
        throw "Justification is required for whitelist requests."
    }

    # Generate request ID
    $requestId = "WLR-$(Get-Date -Format 'yyyyMMdd')-$(Get-Random -Minimum 10000 -Maximum 99999)"

    # Scan the application if it exists and auto-scan is enabled
    $appInfo = @{
        Path = $ApplicationPath
        Exists = Test-Path $ApplicationPath
        Publisher = $null
        ProductName = $null
        FileVersion = $null
        Hash = $null
        IsSigned = $false
        SignerName = $null
    }

    if ($appInfo.Exists -and $Script:Config.AutoScanOnSubmit) {
        try {
            $file = Get-Item $ApplicationPath

            # Get file version info
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ApplicationPath)
            $appInfo.ProductName = $versionInfo.ProductName
            $appInfo.FileVersion = $versionInfo.FileVersion
            $appInfo.Publisher = $versionInfo.CompanyName

            # Get Authenticode signature
            $sig = Get-AuthenticodeSignature $ApplicationPath -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $appInfo.IsSigned = $true
                $appInfo.SignerName = $sig.SignerCertificate.Subject
            }

            # Calculate hash
            $appInfo.Hash = (Get-FileHash $ApplicationPath -Algorithm SHA256).Hash

        } catch {
            Write-Warning "Could not scan application: $_"
        }
    }

    # Create request object
    $request = @{
        RequestId = $requestId
        Status = 'Pending'
        SubmittedAt = Get-Date -Format 'o'
        SubmittedBy = $RequestedBy
        Department = $Department
        Priority = $Priority
        ManagerEmail = $ManagerEmail
        TicketNumber = $TicketNumber

        Application = @{
            Name = $ApplicationName
            Path = $ApplicationPath
            Info = $appInfo
        }

        Justification = $Justification
        AffectedComputers = $AffectedComputers

        SuggestedRuleType = if ($appInfo.IsSigned) { 'Publisher' } elseif ($appInfo.Hash) { 'Hash' } else { 'Path' }

        History = @(
            @{
                Timestamp = Get-Date -Format 'o'
                Action = 'Submitted'
                User = $RequestedBy
                Notes = 'Request submitted'
            }
        )

        Approval = @{
            ApprovedBy = $null
            ApprovedAt = $null
            Notes = $null
        }

        Implementation = @{
            ImplementedBy = $null
            ImplementedAt = $null
            RuleId = $null
            PolicyPath = $null
        }
    }

    # Save request
    $requestPath = Join-Path $Script:RequestStorePath "pending\$requestId.json"
    $request | ConvertTo-Json -Depth 10 | Out-File $requestPath -Encoding UTF8

    # Update store metadata
    $metaPath = Join-Path $Script:RequestStorePath 'store.json'
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    $meta.TotalRequests = ($meta.TotalRequests -as [int]) + 1
    $meta | ConvertTo-Json | Out-File $metaPath -Encoding UTF8

    # Send notification if configured
    if ($Script:Config.NotifyOnSubmit -and $Script:Config.ApprovalWebhook) {
        Send-RequestNotification -Request $request -Action 'Submitted'
    }

    Write-Host "Whitelist request submitted: $requestId" -ForegroundColor Green
    Write-Host "  Application: $ApplicationName" -ForegroundColor Gray
    Write-Host "  Suggested rule type: $($request.SuggestedRuleType)" -ForegroundColor Gray
    Write-Host "  Status: Pending approval" -ForegroundColor Yellow

    return [PSCustomObject]$request
}

#endregion

#region Request Management

<#
.SYNOPSIS
    Gets whitelist requests by status.

.PARAMETER Status
    Filter by status: Pending, Approved, Rejected, Implemented, All.

.PARAMETER RequestId
    Get a specific request by ID.
#>
function Get-WhitelistRequest {
    [CmdletBinding()]
    param(
        [ValidateSet('Pending', 'Approved', 'Rejected', 'Implemented', 'All')]
        [string]$Status = 'Pending',

        [string]$RequestId
    )

    if (-not $Script:RequestStorePath) {
        throw "Request store not initialized."
    }

    $requests = @()

    $folders = if ($Status -eq 'All') {
        @('pending', 'approved', 'rejected', 'implemented')
    } else {
        @($Status.ToLower())
    }

    foreach ($folder in $folders) {
        $folderPath = Join-Path $Script:RequestStorePath $folder
        if (Test-Path $folderPath) {
            Get-ChildItem $folderPath -Filter '*.json' | ForEach-Object {
                $req = Get-Content $_.FullName -Raw | ConvertFrom-Json

                if (-not $RequestId -or $req.RequestId -eq $RequestId) {
                    $requests += $req
                }
            }
        }
    }

    if ($RequestId -and $requests.Count -eq 1) {
        return $requests[0]
    }

    return $requests | Sort-Object { [datetime]$_.SubmittedAt } -Descending
}

<#
.SYNOPSIS
    Approves a whitelist request.

.PARAMETER RequestId
    The request ID to approve.

.PARAMETER ApprovedBy
    User approving the request.

.PARAMETER Notes
    Approval notes.

.PARAMETER GenerateRule
    Immediately generate the AppLocker rule.
#>
function Approve-WhitelistRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequestId,

        [string]$ApprovedBy = $env:USERNAME,

        [string]$Notes,

        [switch]$GenerateRule,

        [string]$OutputPath = '.\Outputs'
    )

    if (-not $Script:RequestStorePath) {
        throw "Request store not initialized."
    }

    # Find the request
    $pendingPath = Join-Path $Script:RequestStorePath "pending\$RequestId.json"

    if (-not (Test-Path $pendingPath)) {
        throw "Request not found or not in pending status: $RequestId"
    }

    $request = Get-Content $pendingPath -Raw | ConvertFrom-Json

    # Update request
    $request.Status = 'Approved'
    $request.Approval.ApprovedBy = $ApprovedBy
    $request.Approval.ApprovedAt = Get-Date -Format 'o'
    $request.Approval.Notes = $Notes

    $request.History += @{
        Timestamp = Get-Date -Format 'o'
        Action = 'Approved'
        User = $ApprovedBy
        Notes = $Notes
    }

    # Move to approved folder
    $approvedPath = Join-Path $Script:RequestStorePath "approved\$RequestId.json"
    $request | ConvertTo-Json -Depth 10 | Out-File $approvedPath -Encoding UTF8
    Remove-Item $pendingPath -Force

    Write-Host "Request approved: $RequestId" -ForegroundColor Green

    # Generate rule if requested
    if ($GenerateRule) {
        $ruleResult = New-RuleFromRequest -Request $request -OutputPath $OutputPath
        if ($ruleResult) {
            Write-Host "  Rule generated: $($ruleResult.RuleFile)" -ForegroundColor Gray
        }
    }

    # Send notification
    if ($Script:Config.NotifyOnApproval -and $Script:Config.ApprovalWebhook) {
        Send-RequestNotification -Request $request -Action 'Approved'
    }

    return $request
}

<#
.SYNOPSIS
    Rejects a whitelist request.

.PARAMETER RequestId
    The request ID to reject.

.PARAMETER RejectedBy
    User rejecting the request.

.PARAMETER Reason
    Rejection reason.
#>
function Deny-WhitelistRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequestId,

        [string]$RejectedBy = $env:USERNAME,

        [Parameter(Mandatory)]
        [string]$Reason
    )

    if (-not $Script:RequestStorePath) {
        throw "Request store not initialized."
    }

    $pendingPath = Join-Path $Script:RequestStorePath "pending\$RequestId.json"

    if (-not (Test-Path $pendingPath)) {
        throw "Request not found or not in pending status: $RequestId"
    }

    $request = Get-Content $pendingPath -Raw | ConvertFrom-Json

    $request.Status = 'Rejected'
    $request.History += @{
        Timestamp = Get-Date -Format 'o'
        Action = 'Rejected'
        User = $RejectedBy
        Notes = $Reason
    }

    # Move to rejected folder
    $rejectedPath = Join-Path $Script:RequestStorePath "rejected\$RequestId.json"
    $request | ConvertTo-Json -Depth 10 | Out-File $rejectedPath -Encoding UTF8
    Remove-Item $pendingPath -Force

    Write-Host "Request rejected: $RequestId" -ForegroundColor Red
    Write-Host "  Reason: $Reason" -ForegroundColor Gray

    return $request
}

#endregion

#region Rule Generation

<#
.SYNOPSIS
    Generates an AppLocker rule from an approved request.

.PARAMETER Request
    The approved request object.

.PARAMETER OutputPath
    Path to save the generated rule.
#>
function New-RuleFromRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Request,

        [string]$OutputPath = '.\Outputs',

        [ValidateSet('Publisher', 'Hash', 'Path', 'Auto')]
        [string]$RuleType = 'Auto'
    )

    if ($Request.Status -ne 'Approved') {
        throw "Cannot generate rule for non-approved request"
    }

    $appInfo = $Request.Application.Info

    # Determine rule type
    $selectedRuleType = if ($RuleType -eq 'Auto') {
        $Request.SuggestedRuleType
    } else {
        $RuleType
    }

    # Generate rule ID
    $ruleId = [guid]::NewGuid().ToString()
    $ruleName = "WLR: $($Request.Application.Name) - $($Request.RequestId)"

    # Build rule XML
    $ruleXml = switch ($selectedRuleType) {
        'Publisher' {
            if (-not $appInfo.SignerName) {
                Write-Warning "No publisher info available, falling back to hash rule"
                $selectedRuleType = 'Hash'
                continue
            }

            # Parse publisher info from signer certificate
            $publisherMatch = $appInfo.SignerName -match 'CN=([^,]+)'
            $publisherName = if ($Matches) { $Matches[1] } else { $appInfo.SignerName }

            @"
<FilePublisherRule Id="$ruleId" Name="$ruleName" Description="Auto-generated from whitelist request $($Request.RequestId)" UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions>
    <FilePublisherCondition PublisherName="$publisherName" ProductName="*" BinaryName="*">
      <BinaryVersionRange LowSection="*" HighSection="*" />
    </FilePublisherCondition>
  </Conditions>
</FilePublisherRule>
"@
        }
        'Hash' {
            if (-not $appInfo.Hash) {
                throw "No hash available for hash-based rule"
            }

            $fileName = Split-Path $appInfo.Path -Leaf

            @"
<FileHashRule Id="$ruleId" Name="$ruleName" Description="Auto-generated from whitelist request $($Request.RequestId)" UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions>
    <FileHashCondition>
      <FileHash Type="SHA256" Data="0x$($appInfo.Hash)" SourceFileName="$fileName" SourceFileLength="0" />
    </FileHashCondition>
  </Conditions>
</FileHashRule>
"@
        }
        'Path' {
            $pathEscaped = [System.Security.SecurityElement]::Escape($appInfo.Path)

            @"
<FilePathRule Id="$ruleId" Name="$ruleName" Description="Auto-generated from whitelist request $($Request.RequestId)" UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions>
    <FilePathCondition Path="$pathEscaped" />
  </Conditions>
</FilePathRule>
"@
        }
    }

    # Save rule to file
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $ruleFile = Join-Path $OutputPath "Rule-$($Request.RequestId).xml"

    # Wrap in minimal policy structure
    $policyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    $ruleXml
  </RuleCollection>
</AppLockerPolicy>
"@

    $policyXml | Out-File $ruleFile -Encoding UTF8

    return @{
        RuleId = $ruleId
        RuleType = $selectedRuleType
        RuleName = $ruleName
        RuleFile = $ruleFile
    }
}

#endregion

#region Reporting

<#
.SYNOPSIS
    Shows a summary dashboard of whitelist requests.
#>
function Show-WhitelistDashboard {
    [CmdletBinding()]
    param()

    if (-not $Script:RequestStorePath) {
        throw "Request store not initialized."
    }

    Write-Host "`n======================================" -ForegroundColor Cyan
    Write-Host "  Whitelist Request Dashboard" -ForegroundColor Cyan
    Write-Host "======================================`n" -ForegroundColor Cyan

    # Count by status
    $counts = @{
        Pending = (Get-ChildItem (Join-Path $Script:RequestStorePath 'pending') -Filter '*.json' -ErrorAction SilentlyContinue).Count
        Approved = (Get-ChildItem (Join-Path $Script:RequestStorePath 'approved') -Filter '*.json' -ErrorAction SilentlyContinue).Count
        Rejected = (Get-ChildItem (Join-Path $Script:RequestStorePath 'rejected') -Filter '*.json' -ErrorAction SilentlyContinue).Count
        Implemented = (Get-ChildItem (Join-Path $Script:RequestStorePath 'implemented') -Filter '*.json' -ErrorAction SilentlyContinue).Count
    }

    Write-Host "Request Status Summary:" -ForegroundColor Yellow
    Write-Host "  Pending:     $($counts.Pending)" -ForegroundColor $(if ($counts.Pending -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host "  Approved:    $($counts.Approved)" -ForegroundColor $(if ($counts.Approved -gt 0) { 'Green' } else { 'Gray' })
    Write-Host "  Rejected:    $($counts.Rejected)" -ForegroundColor $(if ($counts.Rejected -gt 0) { 'Red' } else { 'Gray' })
    Write-Host "  Implemented: $($counts.Implemented)" -ForegroundColor $(if ($counts.Implemented -gt 0) { 'Cyan' } else { 'Gray' })
    Write-Host ""

    # Show pending requests
    if ($counts.Pending -gt 0) {
        Write-Host "Pending Requests:" -ForegroundColor Yellow
        $pending = Get-WhitelistRequest -Status Pending

        foreach ($req in ($pending | Select-Object -First 10)) {
            $age = ((Get-Date) - [datetime]$req.SubmittedAt).Days
            $ageColor = if ($age -gt 7) { 'Red' } elseif ($age -gt 3) { 'Yellow' } else { 'Gray' }

            Write-Host "  $($req.RequestId) | " -NoNewline -ForegroundColor White
            Write-Host "$($req.Application.Name.PadRight(25)) | " -NoNewline -ForegroundColor Cyan
            Write-Host "$($req.SubmittedBy.PadRight(12)) | " -NoNewline -ForegroundColor Gray
            Write-Host "$age days old" -ForegroundColor $ageColor
        }

        if ($pending.Count -gt 10) {
            Write-Host "  ... and $($pending.Count - 10) more" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
}

#endregion

#region Notifications

function Send-RequestNotification {
    param(
        $Request,
        [string]$Action
    )

    if ($Script:Config.ApprovalWebhook) {
        try {
            $payload = @{
                '@type' = 'MessageCard'
                '@context' = 'http://schema.org/extensions'
                'themeColor' = switch ($Action) {
                    'Submitted' { '0078D4' }
                    'Approved' { '28A745' }
                    'Rejected' { 'DC3545' }
                    default { '6C757D' }
                }
                'summary' = "Whitelist Request $Action"
                'sections' = @(
                    @{
                        'activityTitle' = "Whitelist Request $Action"
                        'activitySubtitle' = $Request.RequestId
                        'facts' = @(
                            @{ 'name' = 'Application'; 'value' = $Request.Application.Name }
                            @{ 'name' = 'Requested By'; 'value' = $Request.SubmittedBy }
                            @{ 'name' = 'Priority'; 'value' = $Request.Priority }
                        )
                    }
                )
            }

            Invoke-RestMethod -Uri $Script:Config.ApprovalWebhook -Method Post -Body ($payload | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
        }
        catch {
            Write-Warning "Failed to send notification: $_"
        }
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Initialize-WhitelistRequestStore',
    'New-WhitelistRequest',
    'Get-WhitelistRequest',
    'Approve-WhitelistRequest',
    'Deny-WhitelistRequest',
    'New-RuleFromRequest',
    'Show-WhitelistDashboard'
)
