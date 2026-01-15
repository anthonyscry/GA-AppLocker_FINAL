# Module3-RuleGenerator.psm1
# Rule Generator module for GA-AppLocker
# Creates AppLocker rules from artifacts
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction SilentlyContinue

# Ensure the AppLocker assembly is loaded
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

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
    Saves generated rules to an AppLocker policy XML file with proper Unicode encoding
#>
function Export-RulesToXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Rules,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [ValidateSet('AuditOnly', 'Enabled', 'NotConfigured')]
        [string]$EnforcementMode = 'AuditOnly',
        [ValidateSet('Exe', 'Dll', 'Script', 'Msi', 'Appx')]
        [string]$RuleCollectionType = 'Exe'
    )

    if (-not $Rules -or $Rules.Count -eq 0) {
        return @{
            success = $false
            error = 'No rules to export'
        }
    }

    try {
        # Use AppLockerPolicy object for proper XML structure
        $policy = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy

        # Get the rule collection
        $ruleCollection = $policy.GetRuleCollection($RuleCollectionType)
        $ruleCollection.EnforcementMode = $EnforcementMode

        # Add rules using the AppLockerPolicy object
        foreach ($ruleInfo in $Rules) {
            if ($ruleInfo.xml) {
                # Parse the XML rule and convert to proper format
                [xml]$ruleXml = $ruleInfo.xml
                $ruleNode = $ruleXml.DocumentElement

                switch ($ruleInfo.type) {
                    'Publisher' {
                        $fpr = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule
                        $fpr.Id = $ruleInfo.id
                        $fpr.Name = $ruleInfo.name
                        $fpr.Description = $ruleInfo.Description
                        $fpr.UserOrGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
                        $fpr.Action = if ($ruleInfo.action -eq 'Allow') {
                            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule+Action]::Allow
                        } else {
                            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherRule+Action]::Deny
                        }

                        # Add conditions from the parsed XML
                        if ($ruleNode.Conditions.FilePublisherCondition) {
                            $condition = $ruleNode.Conditions.FilePublisherCondition
                            $fpc = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePublisherCondition
                            $fpc.PublisherName = $condition.PublisherName
                            $fpc.ProductName = $condition.ProductName
                            $fpc.BinaryName = $condition.BinaryName
                            if ($condition.BinaryVersionRange) {
                                $fpc.VersionLow = $condition.BinaryVersionRange.LowSection
                                $fpc.VersionHigh = $condition.BinaryVersionRange.HighSection
                            }
                            $fpr.Conditions.Add($fpc)
                        }

                        $ruleCollection.Add($fpr)
                    }
                    'Path' {
                        $fpr = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule
                        $fpr.Id = $ruleInfo.id
                        $fpr.Name = $ruleInfo.name
                        $fpr.Description = $ruleInfo.Description
                        $fpr.UserOrGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
                        $fpr.Action = if ($ruleInfo.action -eq 'Allow') {
                            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule+Action]::Allow
                        } else {
                            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathRule+Action]::Deny
                        }

                        if ($ruleNode.Conditions.FilePathCondition) {
                            $fpc = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FilePathCondition
                            $fpc.Path = $ruleNode.Conditions.FilePathCondition.Path
                            $fpr.Conditions.Add($fpc)
                        }

                        $ruleCollection.Add($fpr)
                    }
                    'Hash' {
                        $fhr = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashRule
                        $fhr.Id = $ruleInfo.id
                        $fhr.Name = $ruleInfo.name
                        $fhr.Description = $ruleInfo.Description
                        $fhr.UserOrGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
                        $fhr.Action = if ($ruleInfo.action -eq 'Allow') {
                            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashRule+Action]::Allow
                        } else {
                            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashRule+Action]::Deny
                        }

                        if ($ruleNode.Conditions.FileHashCondition.FileHash) {
                            $fh = $ruleNode.Conditions.FileHashCondition.FileHash
                            $fhc = New-Object Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashCondition
                            $fhc.Type = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.FileHashType]::SHA256
                            $fhc.Data = $fh.Data
                            $fhc.SourceFileName = $fh.SourceFileName
                            $fhc.SourceFileLength = $fh.SourceFileLength
                            $fhr.Conditions.Add($fhc)
                        }

                        $ruleCollection.Add($fhr)
                    }
                }
            }
        }

        # Save using the Common library's Unicode save function
        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        Save-AppLockerPolicyAsUnicodeXml -ALPolicy $policy -xmlFilename $OutputPath

        return @{
            success = $true
            path = $OutputPath
            ruleCount = $Rules.Count
            enforcementMode = $EnforcementMode
            ruleCollectionType = $RuleCollectionType
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
    Merge AppLocker Policy Files
.DESCRIPTION
    Merges multiple AppLocker XML policy files into a single policy
.PARAMETER PolicyPaths
    Array of paths to policy XML files to merge
.PARAMETER OutputPath
    Path for the merged policy output
.PARAMETER EnforcementMode
    Enforcement mode for the merged policy
#>
function Merge-AppLockerPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$PolicyPaths,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [ValidateSet('AuditOnly', 'Enabled', 'NotConfigured')]
        [string]$EnforcementMode = 'AuditOnly'
    )

    try {
        # Create master policy from first file
        $masterPolicy = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::Load($PolicyPaths[0])

        # Merge additional policies
        for ($i = 1; $i -lt $PolicyPaths.Count; $i++) {
            $policyToMerge = [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::Load($PolicyPaths[$i])
            $masterPolicy.Merge($policyToMerge)
        }

        # Set enforcement mode
        foreach ($ruleCollection in $masterPolicy.RuleCollections) {
            $ruleCollection.EnforcementMode = $EnforcementMode
        }

        # Save merged policy
        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        Save-AppLockerPolicyAsUnicodeXml -ALPolicy $masterPolicy -xmlFilename $OutputPath

        return @{
            success = $true
            path = $OutputPath
            sources = $PolicyPaths
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
                              New-RulesFromArtifacts, Export-RulesToXml, Import-RulesFromXml,
                              Merge-AppLockerPolicies
