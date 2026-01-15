<#
.SYNOPSIS
    Creates an AppLocker policy from a pre-built industry template.

.DESCRIPTION
    Generates AppLocker policies based on industry-specific templates:
    - FinancialServices (Banking, Insurance, SOX/PCI-DSS)
    - Healthcare (HIPAA compliance)
    - Government (NIST/FISMA/CMMC)
    - Manufacturing (OT/ICS integration)
    - Education (K-12, Higher Ed)
    - Retail (POS, PCI-DSS)
    - SmallBusiness (Balanced productivity/security)

.PARAMETER Template
    The template to use for policy generation.

.PARAMETER OutputPath
    Directory for the generated policy.

.PARAMETER CustomPublishers
    Additional trusted publishers to include.

.PARAMETER Phase
    Deployment phase (1-4).

.PARAMETER EnforcementMode
    Override enforcement mode (AuditOnly or Enabled).

.EXAMPLE
    .\New-PolicyFromTemplate.ps1 -Template FinancialServices -OutputPath .\Policies

.EXAMPLE
    .\New-PolicyFromTemplate.ps1 -Template Healthcare -Phase 2 -EnforcementMode Enabled

.EXAMPLE
    # List available templates
    .\New-PolicyFromTemplate.ps1 -ListTemplates
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'Generate')]
    [ValidateSet('FinancialServices', 'Healthcare', 'Government', 'Manufacturing', 'Education', 'Retail', 'SmallBusiness')]
    [string]$Template,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$OutputPath = '.\Outputs',

    [Parameter(ParameterSetName = 'Generate')]
    [string[]]$CustomPublishers = @(),

    [Parameter(ParameterSetName = 'Generate')]
    [ValidateRange(1, 4)]
    [int]$Phase = 1,

    [Parameter(ParameterSetName = 'Generate')]
    [ValidateSet('AuditOnly', 'Enabled')]
    [string]$EnforcementMode,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$DomainName,

    [Parameter(ParameterSetName = 'List')]
    [switch]$ListTemplates,

    [Parameter(ParameterSetName = 'Info')]
    [string]$TemplateInfo
)

$ErrorActionPreference = 'Stop'

# Get script paths
$scriptRoot = Split-Path $PSScriptRoot -Parent

# Import common functions and error handling
Import-Module (Join-Path $scriptRoot 'utilities\Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ErrorHandling.psm1') -Force

# Load templates
$templatesPath = Join-Path $PSScriptRoot 'PolicyTemplates.psd1'
$templateData = Import-PowerShellDataFile $templatesPath

#region List Templates

if ($ListTemplates) {
    Write-SectionHeader -Title "Available Policy Templates"

    foreach ($name in $templateData.Templates.Keys | Sort-Object) {
        $tmpl = $templateData.Templates[$name]

        $riskColor = switch ($tmpl.RiskLevel) {
            'Very High' { 'Red' }
            'High' { 'DarkYellow' }
            'Medium-High' { 'Yellow' }
            'Medium' { 'White' }
            default { 'Green' }
        }

        Write-Host "$name" -ForegroundColor Yellow
        Write-Host "  $($tmpl.Description)" -ForegroundColor Gray
        Write-Host "  Risk: " -NoNewline -ForegroundColor Gray
        Write-Host $tmpl.RiskLevel -ForegroundColor $riskColor
        Write-Host "  Industries: $($tmpl.Industries -join ', ')" -ForegroundColor DarkGray
        Write-Host "  Compliance: $($tmpl.Compliance -join ', ')" -ForegroundColor DarkGray
        Write-Host ""
    }

    Write-Host "Use -Template <name> to generate a policy" -ForegroundColor Cyan
    Write-Host "Use -TemplateInfo <name> for detailed information" -ForegroundColor Cyan
    Write-Host ""
    return
}

#endregion

#region Template Info

if ($TemplateInfo) {
    if (-not $templateData.Templates.ContainsKey($TemplateInfo)) {
        Write-ErrorMessage -Message "Template not found: $TemplateInfo"
        return
    }

    $tmpl = $templateData.Templates[$TemplateInfo]

    Write-SectionHeader -Title "Template: $TemplateInfo"

    Write-Host "Name: $($tmpl.Name)" -ForegroundColor Yellow
    Write-Host "Description: $($tmpl.Description)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "Target Industries:" -ForegroundColor Yellow
    $tmpl.Industries | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    Write-Host ""

    Write-Host "Compliance Frameworks:" -ForegroundColor Yellow
    $tmpl.Compliance | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    Write-Host ""

    Write-Host "Risk Level: $($tmpl.RiskLevel)" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "Trusted Publishers ($($tmpl.TrustedPublishers.Count)):" -ForegroundColor Yellow
    $tmpl.TrustedPublishers | Select-Object -First 10 | ForEach-Object {
        Write-Host "  + $_" -ForegroundColor Green
    }
    if ($tmpl.TrustedPublishers.Count -gt 10) {
        Write-Host "  ... and $($tmpl.TrustedPublishers.Count - 10) more" -ForegroundColor DarkGray
    }
    Write-Host ""

    Write-Host "Denied Executables ($($tmpl.DeniedExecutables.Count)):" -ForegroundColor Yellow
    $tmpl.DeniedExecutables | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Red
    }
    Write-Host ""

    Write-Host "Recommended Phase Durations:" -ForegroundColor Yellow
    Write-Host "  Phase 1 (EXE only): $($tmpl.RecommendedPhases.Phase1Duration) days" -ForegroundColor Gray
    Write-Host "  Phase 2 (+Script):  $($tmpl.RecommendedPhases.Phase2Duration) days" -ForegroundColor Gray
    Write-Host "  Phase 3 (+MSI):     $($tmpl.RecommendedPhases.Phase3Duration) days" -ForegroundColor Gray
    Write-Host "  Phase 4 (+DLL):     $(if ($tmpl.RecommendedPhases.Phase4Duration -eq 0) { 'Not recommended' } else { "$($tmpl.RecommendedPhases.Phase4Duration) days" })" -ForegroundColor Gray
    Write-Host ""

    Write-Host "Notes:" -ForegroundColor Yellow
    Write-Host $tmpl.Notes -ForegroundColor Gray
    Write-Host ""

    return
}

#endregion

#region Generate Policy

if (-not $Template) {
    Write-Warning "Please specify -Template or use -ListTemplates"
    return
}

$tmpl = $templateData.Templates[$Template]

Write-SectionHeader -Title "Generating Policy from Template"

Write-Host "Template: $Template - $($tmpl.Name)" -ForegroundColor Yellow
Write-Host "Phase: $Phase" -ForegroundColor Gray
Write-Host ""

# Determine collections for this phase
$collections = switch ($Phase) {
    1 { @('Exe') }
    2 { @('Exe', 'Script') }
    3 { @('Exe', 'Script', 'Msi') }
    4 { @('Exe', 'Script', 'Msi', 'Dll') }
}

# Determine enforcement mode
$mode = if ($EnforcementMode) { $EnforcementMode } else { $tmpl.EnforcementMode }

# Start building policy XML
$policyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<!--
  AppLocker Policy generated from template: $Template
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Phase: $Phase
  Compliance: $($tmpl.Compliance -join ', ')
-->
<AppLockerPolicy Version="1">

"@

# Generate rule collections
foreach ($collection in $collections) {
    Write-Host "Generating $collection rules..." -ForegroundColor Gray

    $policyXml += @"
  <RuleCollection Type="$collection" EnforcementMode="$mode">
    <!-- Default deny implicit - only explicitly allowed items run -->

"@

    # Add publisher allow rules
    $allPublishers = $tmpl.TrustedPublishers + $CustomPublishers | Select-Object -Unique
    $ruleNum = 1

    foreach ($publisher in $allPublishers) {
        $ruleId = [guid]::NewGuid().ToString()
        $publisherEscaped = [System.Security.SecurityElement]::Escape($publisher)
        $ruleName = "$Template - Publisher $ruleNum"

        $policyXml += @"
    <FilePublisherRule Id="$ruleId" Name="$ruleName" Description="Template: $Template" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="$publisherEscaped" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

"@
        $ruleNum++
    }

    # Add path allow rules
    foreach ($path in $tmpl.AllowedPaths) {
        $ruleId = [guid]::NewGuid().ToString()
        $pathEscaped = [System.Security.SecurityElement]::Escape($path)
        $ruleName = "$Template - Path Allow $ruleNum"

        $policyXml += @"
    <FilePathRule Id="$ruleId" Name="$ruleName" Description="Template: $Template" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="$pathEscaped" />
      </Conditions>
    </FilePathRule>

"@
        $ruleNum++
    }

    # Add deny rules (for Exe collection only, unless Phase 2+ for scripts)
    $applyDenyRules = ($collection -eq 'Exe') -or ($collection -eq 'Script' -and $Phase -ge 2)

    if ($applyDenyRules) {
        # Denied paths
        foreach ($path in $tmpl.DeniedPaths) {
            $ruleId = [guid]::NewGuid().ToString()
            $pathEscaped = [System.Security.SecurityElement]::Escape($path)
            $ruleName = "$Template - Path Deny $ruleNum"

            $policyXml += @"
    <FilePathRule Id="$ruleId" Name="$ruleName" Description="Template: $Template - Deny" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="$pathEscaped" />
      </Conditions>
    </FilePathRule>

"@
            $ruleNum++
        }

        # Denied executables (LOLBins)
        foreach ($exe in $tmpl.DeniedExecutables) {
            $ruleId = [guid]::NewGuid().ToString()
            $exeEscaped = [System.Security.SecurityElement]::Escape($exe)
            $ruleName = "$Template - LOLBin Deny $ruleNum"

            $policyXml += @"
    <FilePathRule Id="$ruleId" Name="$ruleName" Description="Template: $Template - LOLBin Deny" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="$exeEscaped" />
      </Conditions>
    </FilePathRule>

"@
            $ruleNum++
        }
    }

    $policyXml += @"
  </RuleCollection>

"@
}

$policyXml += "</AppLockerPolicy>"

# Save policy using standardized path validation
$validOutputPath = Test-ValidPath -Path $OutputPath -Type Directory -CreateIfMissing
if (-not $validOutputPath) {
    Write-ErrorMessage -Message "Failed to create output directory: $OutputPath" -Throw
}

$policyFile = Join-Path $validOutputPath "AppLockerPolicy-$Template-Phase$Phase.xml"

Invoke-SafeOperation -ScriptBlock {
    $policyXml | Out-File $policyFile -Encoding UTF8
} -ErrorMessage "Failed to save policy file"

Write-Host ""
Write-SuccessMessage -Message "Policy generated successfully!"
Write-Host "  File: $policyFile" -ForegroundColor Gray
Write-Host "  Template: $Template" -ForegroundColor Gray
Write-Host "  Phase: $Phase ($($collections -join ', '))" -ForegroundColor Gray
Write-Host "  Mode: $mode" -ForegroundColor Gray
Write-Host "  Publishers: $($allPublishers.Count)" -ForegroundColor Gray
Write-Host ""

# Show recommendations
Write-Host "Recommendations:" -ForegroundColor Yellow
Write-Host "  1. Deploy in AUDIT mode for $($tmpl.RecommendedPhases."Phase${Phase}Duration") days minimum" -ForegroundColor Gray
Write-Host "  2. Collect and analyze AppLocker events (8003/8004)" -ForegroundColor Gray
Write-Host "  3. Add rules for any legitimate blocked applications" -ForegroundColor Gray
Write-Host "  4. Use Invoke-PhaseAdvancement.ps1 to check readiness for next phase" -ForegroundColor Gray
Write-Host ""

if ($tmpl.Notes) {
    Write-Host "Template Notes:" -ForegroundColor Yellow
    Write-Host $tmpl.Notes -ForegroundColor DarkGray
    Write-Host ""
}

return [PSCustomObject]@{
    Template = $Template
    Phase = $Phase
    PolicyFile = $policyFile
    EnforcementMode = $mode
    Collections = $collections
    PublisherCount = $allPublishers.Count
    RecommendedDuration = $tmpl.RecommendedPhases."Phase${Phase}Duration"
}

#endregion
