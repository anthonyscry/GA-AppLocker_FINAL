#Requires -Version 5.1
<#
.SYNOPSIS
    GA-AppLocker Policy Generation Module
.DESCRIPTION
    Functions for creating and merging AppLocker XML policies.
#>

# ============================================================
# POLICY GENERATION
# ============================================================

function New-AppLockerPolicy {
    <#
    .SYNOPSIS
        Create AppLocker policy XML from publishers.
    .PARAMETER Publishers
        Hashtable of publishers from scan.
    .PARAMETER PolicyMode
        Audit or Enforce.
    .PARAMETER MaxPublisherRules
        Maximum publisher rules to include.
    .OUTPUTS
        XML string.
    #>
    param(
        [hashtable]$Publishers = @{},
        [ValidateSet("Audit", "Enforce")]
        [string]$PolicyMode = "Audit",
        [int]$MaxPublisherRules = 20
    )

    $enforcementMode = if ($PolicyMode -eq "Enforce") { "Enabled" } else { "AuditOnly" }

    # Start building policy
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$enforcementMode">
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

    # Add publisher rules
    $topPublishers = $Publishers.Values | Sort-Object Count -Descending | Select-Object -First $MaxPublisherRules
    foreach ($pub in $topPublishers) {
        if ($pub.Publisher -and $pub.Publisher -ne "Unknown" -and $pub.Publisher.Trim() -ne "") {
            $escapedPublisher = [System.Security.SecurityElement]::Escape($pub.Publisher)
            $xml += @"

    <FilePublisherRule Id="$(New-Guid)" Name="Allow $escapedPublisher" Description="Publisher rule" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*$escapedPublisher*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@
        }
    }

    # Close Exe collection and add other rule collections
    $xml += @"

  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="$enforcementMode">
    <FilePathRule Id="$(New-Guid)" Name="Allow Windows Installer" Description="Allow MSI from Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
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

    return $xml
}

function Merge-AppLockerPolicy {
    <#
    .SYNOPSIS
        Merge new policy rules into existing policy.
    .PARAMETER BasePolicyPath
        Path to existing policy XML.
    .PARAMETER NewPolicyPath
        Path to new policy XML to merge.
    .PARAMETER OutputPath
        Path for merged policy.
    .OUTPUTS
        Path to merged policy.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BasePolicyPath,
        [Parameter(Mandatory)]
        [string]$NewPolicyPath,
        [string]$OutputPath
    )

    if (-not (Test-Path $BasePolicyPath)) {
        throw "Base policy not found: $BasePolicyPath"
    }
    if (-not (Test-Path $NewPolicyPath)) {
        throw "New policy not found: $NewPolicyPath"
    }

    # Default output path
    if (-not $OutputPath) {
        $OutputPath = $NewPolicyPath -replace '\.xml$', '-MERGED.xml'
    }

    # Load policies
    [xml]$basePolicy = Get-Content $BasePolicyPath -Encoding Unicode
    [xml]$newPolicy = Get-Content $NewPolicyPath -Encoding Unicode

    # Merge rules from new into base
    foreach ($newCollection in $newPolicy.AppLockerPolicy.RuleCollection) {
        $baseCollection = $basePolicy.AppLockerPolicy.RuleCollection |
            Where-Object { $_.Type -eq $newCollection.Type }

        if ($baseCollection) {
            foreach ($rule in $newCollection.ChildNodes) {
                if ($rule.NodeType -eq 'Element') {
                    $importedRule = $basePolicy.ImportNode($rule, $true)
                    $baseCollection.AppendChild($importedRule) | Out-Null
                }
            }
        }
    }

    # Save merged policy (UTF-16 required)
    $basePolicy.Save($OutputPath)

    return $OutputPath
}

function Save-AppLockerPolicy {
    <#
    .SYNOPSIS
        Save policy XML to file with correct encoding.
    .PARAMETER PolicyXml
        Policy XML string.
    .PARAMETER Path
        Output file path.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PolicyXml,
        [Parameter(Mandatory)]
        [string]$Path
    )

    # AppLocker requires UTF-16 encoding
    $PolicyXml | Out-File -FilePath $Path -Encoding Unicode
    return $Path
}

function Import-AppLockerPolicy {
    <#
    .SYNOPSIS
        Apply policy to local GPO.
    .PARAMETER PolicyPath
        Path to policy XML.
    .PARAMETER Merge
        Merge with existing instead of replace.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PolicyPath,
        [switch]$Merge
    )

    if (-not (Test-Path $PolicyPath)) {
        throw "Policy file not found: $PolicyPath"
    }

    $params = @{ XmlPolicy = $PolicyPath }
    if ($Merge) { $params["Merge"] = $true }

    Set-AppLockerPolicy @params -ErrorAction Stop
}

# ============================================================
# EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'New-AppLockerPolicy',
    'Merge-AppLockerPolicy',
    'Save-AppLockerPolicy',
    'Import-AppLockerPolicy'
)
