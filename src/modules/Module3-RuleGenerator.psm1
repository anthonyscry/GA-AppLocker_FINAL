# Module3-RuleGenerator.psm1
# Rule Generator module for GA-AppLocker
# Creates AppLocker rules from artifacts

<#
.SYNOPSIS
    Get Trusted Publishers
.DESCRIPTION
    Retrieves publishers from the local certificate store
#>
function Get-TrustedPublishers {
    [CmdletBinding()]
    param()

    $storePath = 'Cert:\LocalMachine\TrustedPublisher'

    if (-not (Test-Path $storePath)) {
        return @{
            success = $true
            data = @()
            message = 'TrustedPublisher store not found'
        }
    }

    try {
        $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue

        $publishers = @()
        foreach ($cert in $certs) {
            $subject = $cert.Subject
            $publisherName = $subject
            if ($subject -match 'CN=([^,]+)') {
                $publisherName = $matches[1]
            }

            $publishers += @{
                name = $publisherName
                thumbprint = $cert.Thumbprint
                expiry = $cert.NotAfter.ToString('yyyy-MM-dd')
                isValid = $cert.NotAfter -gt (Get-Date)
            }
        }

        return @{
            success = $true
            data = $publishers
            count = $publishers.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Generate Publisher Rule
.DESCRIPTION
    Creates an AppLocker rule based on digital signature/publisher
#>
function New-PublisherRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublisherName,
        [ValidateSet('Allow', 'Deny')]
        [string]$Action = 'Allow',
        [string]$Description = ''
    )

    if ([string]::IsNullOrWhiteSpace($PublisherName)) {
        return @{
            success = $false
            error = 'Publisher name is required'
        }
    }

    $ruleId = [guid]::NewGuid().ToString()
    $escapedPublisher = $PublisherName -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
    $ruleName = "$Action - $PublisherName"

    $xml = @"
<FilePublisherRule Id="$ruleId" Name="$ruleName" Description="$Description" UserOrGroupSid="S-1-1-0" Action="$Action">
  <Conditions>
    <FilePublisherCondition PublisherName="$escapedPublisher" ProductName="*" BinaryName="*">
      <BinaryVersionRange LowSection="*" HighSection="*" />
    </FilePublisherCondition>
  </Conditions>
</FilePublisherRule>
"@

    return @{
        success = $true
        id = $ruleId
        name = $ruleName
        type = 'Publisher'
        action = $Action
        publisher = $PublisherName
        xml = $xml
    }
}

<#
.SYNOPSIS
    Generate Path Rule
.DESCRIPTION
    Creates an AppLocker rule based on file path
#>
function New-PathRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [ValidateSet('Allow', 'Deny')]
        [string]$Action = 'Allow',
        [string]$Description = ''
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @{
            success = $false
            error = 'Path is required'
        }
    }

    $ruleId = [guid]::NewGuid().ToString()
    $escapedPath = $Path -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
    $fileName = Split-Path -Path $Path -Leaf
    $ruleName = "$Action - $fileName"

    $xml = @"
<FilePathRule Id="$ruleId" Name="$ruleName" Description="$Description" UserOrGroupSid="S-1-1-0" Action="$Action">
  <Conditions>
    <FilePathCondition Path="$escapedPath" />
  </Conditions>
</FilePathRule>
"@

    return @{
        success = $true
        id = $ruleId
        name = $ruleName
        type = 'Path'
        action = $Action
        path = $Path
        xml = $xml
    }
}

<#
.SYNOPSIS
    Generate Hash Rule
.DESCRIPTION
    Creates an AppLocker rule based on file hash
#>
function New-HashRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [ValidateSet('Allow', 'Deny')]
        [string]$Action = 'Allow',
        [string]$Description = ''
    )

    if (-not (Test-Path $FilePath)) {
        return @{
            success = $false
            error = "File not found: $FilePath"
        }
    }

    try {
        $hashResult = Get-FileHash -Path $FilePath -Algorithm SHA256
        $hash = $hashResult.Hash
        $fileName = Split-Path -Path $FilePath -Leaf
        $fileSize = (Get-Item $FilePath).Length
        $ruleId = [guid]::NewGuid().ToString()
        $ruleName = "$Action - $fileName (Hash)"

        $xml = @"
<FileHashRule Id="$ruleId" Name="$ruleName" Description="$Description" UserOrGroupSid="S-1-1-0" Action="$Action">
  <Conditions>
    <FileHashCondition>
      <FileHash Type="SHA256" Data="$hash" SourceFileName="$fileName" SourceFileLength="$fileSize" />
    </FileHashCondition>
  </Conditions>
</FileHashRule>
"@

        return @{
            success = $true
            id = $ruleId
            name = $ruleName
            type = 'Hash'
            action = $Action
            hash = $hash
            fileName = $fileName
            fileSize = $fileSize
            xml = $xml
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Generate Rules from Artifacts
.DESCRIPTION
    Automatically generates rules from a list of artifacts
#>
function New-RulesFromArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Artifacts,
        [ValidateSet('Publisher', 'Path', 'Hash')]
        [string]$RuleType = 'Publisher',
        [ValidateSet('Allow', 'Deny')]
        [string]$Action = 'Allow'
    )

    if (-not $Artifacts -or $Artifacts.Count -eq 0) {
        return @{
            success = $false
            error = 'No artifacts provided'
            rules = @()
        }
    }

    $rules = @()
    $publishersSeen = @{}

    foreach ($artifact in $Artifacts) {
        switch ($RuleType) {
            'Publisher' {
                $publisher = $artifact.publisher
                if ($publisher -and $publisher -ne 'Unknown' -and -not $publishersSeen.ContainsKey($publisher)) {
                    $rule = New-PublisherRule -PublisherName $publisher -Action $Action
                    if ($rule.success) {
                        $rules += $rule
                        $publishersSeen[$publisher] = $true
                    }
                }
            }
            'Path' {
                if ($artifact.path) {
                    $rule = New-PathRule -Path $artifact.path -Action $Action
                    if ($rule.success) {
                        $rules += $rule
                    }
                }
            }
            'Hash' {
                if ($artifact.path -and (Test-Path $artifact.path)) {
                    $rule = New-HashRule -FilePath $artifact.path -Action $Action
                    if ($rule.success) {
                        $rules += $rule
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
    }
}

<#
.SYNOPSIS
    Export Rules to XML File
.DESCRIPTION
    Saves generated rules to an AppLocker policy XML file
#>
function Export-RulesToXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Rules,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [ValidateSet('AuditOnly', 'Enabled', 'NotConfigured')]
        [string]$EnforcementMode = 'AuditOnly'
    )

    if (-not $Rules -or $Rules.Count -eq 0) {
        return @{
            success = $false
            error = 'No rules to export'
        }
    }

    try {
        $rulesXml = ($Rules | ForEach-Object { $_.xml }) -join "`n    "

        $policyXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="$EnforcementMode">
    $rulesXml
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured">
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured">
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured">
  </RuleCollection>
</AppLockerPolicy>
"@

        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $policyXml | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        return @{
            success = $true
            path = $OutputPath
            ruleCount = $Rules.Count
            enforcementMode = $EnforcementMode
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Import Rules from XML File
.DESCRIPTION
    Loads rules from an existing AppLocker policy XML file
#>
function Import-RulesFromXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$XmlPath
    )

    if (-not (Test-Path $XmlPath)) {
        return @{
            success = $false
            error = "File not found: $XmlPath"
            rules = @()
        }
    }

    try {
        [xml]$xml = Get-Content -Path $XmlPath -Raw

        $rules = @()

        $publisherRules = $xml.SelectNodes('//FilePublisherRule')
        foreach ($rule in $publisherRules) {
            $rules += @{
                id = $rule.Id
                name = $rule.Name
                type = 'Publisher'
                action = $rule.Action
            }
        }

        $pathRules = $xml.SelectNodes('//FilePathRule')
        foreach ($rule in $pathRules) {
            $rules += @{
                id = $rule.Id
                name = $rule.Name
                type = 'Path'
                action = $rule.Action
            }
        }

        $hashRules = $xml.SelectNodes('//FileHashRule')
        foreach ($rule in $hashRules) {
            $rules += @{
                id = $rule.Id
                name = $rule.Name
                type = 'Hash'
                action = $rule.Action
            }
        }

        return @{
            success = $true
            rules = $rules
            count = $rules.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            rules = @()
        }
    }
}

# Export functions
Export-ModuleMember -Function Get-TrustedPublishers, New-PublisherRule, New-PathRule, New-HashRule,
                              New-RulesFromArtifacts, Export-RulesToXml, Import-RulesFromXml
