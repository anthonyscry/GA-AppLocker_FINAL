# Module3-RuleGenerator.psm1
# Rule Generator module for GA-AppLocker
# Creates AppLocker rules from artifacts
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction Stop

# Import Config for deny list path
Import-Module (Join-Path $PSScriptRoot '..\Config.psm1') -ErrorAction Stop

# Ensure the AppLocker assembly is loaded
[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel")

# ======================================================================
# DENY LIST - From AaronLocker pattern
# ======================================================================

<#
.SYNOPSIS
    Get Deny List File Path
.DESCRIPTION
    Returns the path to the deny list file (from AaronLocker)
.PARAMETER CustomPath
    Optional custom path to deny list file
.OUTPUTS
    Full path to deny list file
#>
function Get-DenyListPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$CustomPath
    )

    if ($CustomPath) {
        return $CustomPath
    }

    # Use Config.psm1 path or fall back to AaronLocker default location
    $denyListDir = if ($script:customizationInputsDir) {
        $script:customizationInputsDir
    } else {
        Join-Path $script:basePath "custom"
    }

    return Join-Path $denyListDir "deny-list.txt"
}

<#
.SYNOPSIS
    Get Deny List
.DESCRIPTION
    Loads the deny list from file (from AaronLocker)
.PARAMETER DenyListPath
    Path to deny list file
.OUTPUTS
    System.Collections.Hashtable with denied publishers and paths
#>
function Get-DenyList {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$DenyListPath
    )

    $denyListPath = Get-DenyListPath -CustomPath $DenyListPath

    if (-not (Test-Path $denyListPath)) {
        return @{
            success = $true
            publishers = @()
            paths = @()
            count = 0
            message = 'No deny list file found'
            path = $denyListPath
        }
    }

    try {
        $lines = Get-Content -Path $denyListPath -ErrorAction Stop

        $deniedPublishers = [System.Collections.Generic.HashSet[string]]::new()
        $deniedPaths = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($line in $lines) {
            $line = $line.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }

            # Parse publisher entries (from AaronLocker format)
            if ($line -match '^Publisher:\s*(.+)$') {
                $publisher = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($publisher)) {
                    $deniedPublishers.Add($publisher)
                }
            }
            # Parse path entries
            elseif ($line -match '^Path:\s*(.+)$') {
                $path = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($path)) {
                    $deniedPaths.Add($path)
                }
            }
            # Legacy format: just publisher name
            elseif (-not $line.Contains(':')) {
                $deniedPublishers.Add($line)
            }
        }

        return @{
            success = $true
            publishers = $deniedPublishers
            paths = $deniedPaths
            count = $deniedPublishers.Count + $deniedPaths.Count
            path = $denyListPath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            publishers = @()
            paths = @()
            count = 0
        }
    }
}

<#
.SYNOPSIS
    Test if Publisher is Denied
.DESCRIPTION
    Checks if a publisher is on the deny list (from AaronLocker)
.PARAMETER PublisherName
    The publisher name to check
.PARAMETER DenyList
    Optional pre-loaded deny list hashtable
.OUTPUTS
    True if publisher is denied, false otherwise
#>
function Test-DeniedPublisher {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublisherName,
        [hashtable]$DenyList
    )

    if ([string]::IsNullOrWhiteSpace($PublisherName)) {
        return $false
    }

    # Load deny list if not provided
    if (-not $DenyList) {
        $DenyList = Get-DenyList
        if (-not $DenyList.success) {
            return $false
        }
    }

    # Check exact match
    if ($DenyList.publishers.Contains($PublisherName)) {
        return $true
    }

    # Check partial match (e.g., "Microsoft" matches "Microsoft Corporation")
    foreach ($deniedPublisher in $DenyList.publishers) {
        if ($PublisherName -like "*$deniedPublisher*" -or $deniedPublisher -like "*$PublisherName*") {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Test if Path is Denied
.DESCRIPTION
    Checks if a file path is on the deny list (from AaronLocker)
.PARAMETER FilePath
    The file path to check
.PARAMETER DenyList
    Optional pre-loaded deny list hashtable
.OUTPUTS
    True if path is denied, false otherwise
#>
function Test-DeniedPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [hashtable]$DenyList
    )

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return $false
    }

    # Load deny list if not provided
    if (-not $DenyList) {
        $DenyList = Get-DenyList
        if (-not $DenyList.success) {
            return $false
        }
    }

    # Check exact match
    if ($DenyList.paths.Contains($FilePath)) {
        return $true
    }

    # Check partial match for directory patterns
    foreach ($deniedPath in $DenyList.paths) {
        if ($FilePath -like "$deniedPath*") {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Add Entry to Deny List
.DESCRIPTION
    Adds a publisher or path to the deny list file (from AaronLocker)
.PARAMETER Publisher
    Publisher name to deny
.PARAMETER Path
    File path pattern to deny
.PARAMETER DenyListPath
    Path to deny list file
.OUTPUTS
    System.Collections.Hashtable
#>
function Add-DenyListEntry {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$Publisher,
        [string]$Path,
        [string]$DenyListPath
    )

    $DenyListPath = Get-DenyListPath -CustomPath $DenyListPath

    # Create directory if needed
    $parentDir = Split-Path -Parent $DenyListPath
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    # Validate parameters
    if ([string]::IsNullOrWhiteSpace($Publisher) -and [string]::IsNullOrWhiteSpace($Path)) {
        return @{
            success = $false
            error = 'Either Publisher or Path must be specified'
        }
    }

    try {
        # Build new entry
        $entry = if ($Publisher) {
            "Publisher: $Publisher"
        } else {
            "Path: $Path"
        }

        # Append to file (create if doesn't exist)
        Add-Content -Path $DenyListPath -Value $entry -ErrorAction Stop

        return @{
            success = $true
            entry = $entry
            path = $DenyListPath
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
    Remove Entry from Deny List
.DESCRIPTION
    Removes a publisher or path from the deny list file (from AaronLocker)
.PARAMETER Publisher
    Publisher name to remove
.PARAMETER Path
    File path pattern to remove
.PARAMETER DenyListPath
    Path to deny list file
.OUTPUTS
    System.Collections.Hashtable
#>
function Remove-DenyListEntry {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$Publisher,
        [string]$Path,
        [string]$DenyListPath
    )

    $DenyListPath = Get-DenyListPath -CustomPath $DenyListPath

    if (-not (Test-Path $DenyListPath)) {
        return @{
            success = $false
            error = 'Deny list file not found'
        }
    }

    # Validate parameters
    if ([string]::IsNullOrWhiteSpace($Publisher) -and [string]::IsNullOrWhiteSpace($Path)) {
        return @{
            success = $false
            error = 'Either Publisher or Path must be specified'
        }
    }

    try {
        $lines = Get-Content -Path $DenyListPath -ErrorAction Stop
        $newLines = @()
        $removedCount = 0

        $targetEntry = if ($Publisher) {
            "Publisher: $Publisher"
        } else {
            "Path: $Path"
        }

        foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -eq $targetEntry) {
                $removedCount++
            }
            else {
                $newLines += $line
            }
        }

        $newLines | Set-Content -Path $DenyListPath -ErrorAction Stop

        return @{
            success = $true
            removed = $removedCount
            path = $DenyListPath
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
    Create Sample Deny List
.DESCRIPTION
    Creates a sample deny list file with common entries (from AaronLocker)
.PARAMETER DenyListPath
    Path to deny list file
.PARAMETER Force
    Overwrite existing deny list
.OUTPUTS
    System.Collections.Hashtable
#>
function New-SampleDenyList {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$DenyListPath,
        [switch]$Force
    )

    $DenyListPath = Get-DenyListPath -CustomPath $DenyListPath

    if ((Test-Path $DenyListPath) -and -not $Force) {
        return @{
            success = $false
            error = 'Deny list already exists. Use -Force to overwrite.'
            path = $DenyListPath
        }
    }

    # Create directory if needed
    $parentDir = Split-Path -Parent $DenyListPath
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    try {
        $sampleContent = @"
# AppLocker Deny List
# Lines starting with # are comments
# Use 'Publisher:' to block specific software publishers
# Use 'Path:' to block specific file paths

# Example: Block games and entertainment
# Publisher: Epic Games Inc.
# Publisher: Valve Corporation
# Publisher: Electronic Arts

# Example: Block torrent clients
# Publisher: BitTorrent Inc.
# Publisher: qBittorrent

# Example: Block risky utilities
# Publisher: NirSoft

# Example: Block specific paths
# Path: C:\Users\*\Downloads
# Path: C:\Temp\*

# Add your denied publishers below:
"@

        $sampleContent | Set-Content -Path $DenyListPath -ErrorAction Stop

        return @{
            success = $true
            path = $DenyListPath
            message = 'Sample deny list created. Edit the file to add denied publishers.'
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
    Escape XML Special Characters
.DESCRIPTION
    Escapes special characters in XML attribute values to prevent injection
.PARAMETER Value
    The value to escape
#>
function Protect-XmlAttributeValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # Escape XML special characters: & < > " '
    $escaped = $Value -replace '&', '&amp;'
    $escaped = $escaped -replace '<', '&lt;'
    $escaped = $escaped -replace '>', '&gt;'
    $escaped = $escaped -replace '"', '&quot;'
    $escaped = $escaped -replace "'", '&apos;'

    return $escaped
}

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
    Creates an AppLocker rule based on digital signature/publisher with proper validation
.PARAMETER PublisherName
    The publisher name (will be properly escaped)
.PARAMETER Action
    Allow or Deny
.PARAMETER Description
    Rule description (will be properly escaped)
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

    # Validate publisher name using Test-PublisherName from Common.psm1
    $validation = Test-PublisherName -PublisherName $PublisherName
    if (-not $validation.valid) {
        return @{
            success = $false
            error = $validation.error
        }
    }

    $ruleId = [guid]::NewGuid().ToString()
    $escapedPublisher = Protect-XmlAttributeValue -Value $PublisherName
    $escapedDescription = Protect-XmlAttributeValue -Value $Description
    $ruleName = Protect-XmlAttributeValue -Value "$Action - $PublisherName"

    $xml = @"
<FilePublisherRule Id="$ruleId" Name="$ruleName" Description="$escapedDescription" UserOrGroupSid="S-1-1-0" Action="$Action">
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
        name = "$Action - $PublisherName"
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
    Creates an AppLocker rule based on file path with proper validation
.PARAMETER Path
    The file path (will be properly escaped)
.PARAMETER Action
    Allow or Deny
.PARAMETER Description
    Rule description (will be properly escaped)
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
    $escapedPath = Protect-XmlAttributeValue -Value $Path
    $escapedDescription = Protect-XmlAttributeValue -Value $Description
    $fileName = Split-Path -Path $Path -Leaf
    $ruleName = Protect-XmlAttributeValue -Value "$Action - $fileName"

    $xml = @"
<FilePathRule Id="$ruleId" Name="$ruleName" Description="$escapedDescription" UserOrGroupSid="S-1-1-0" Action="$Action">
  <Conditions>
    <FilePathCondition Path="$escapedPath" />
  </Conditions>
</FilePathRule>
"@

    return @{
        success = $true
        id = $ruleId
        name = "$Action - $fileName"
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
    Creates an AppLocker rule based on file hash with proper validation
.PARAMETER FilePath
    The path to the file
.PARAMETER Action
    Allow or Deny
.PARAMETER Description
    Rule description (will be properly escaped)
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

    # Validate path using Test-AppLockerPath from Common.psm1
    $pathValidation = Test-AppLockerPath -Path $FilePath
    if (-not $pathValidation.valid) {
        return @{
            success = $false
            error = $pathValidation.error
        }
    }

    try {
        $hashResult = Get-FileHash -Path $pathValidation.path -Algorithm SHA256
        $hash = $hashResult.Hash
        $fileName = Split-Path -Path $FilePath -Leaf
        $fileSize = (Get-Item $pathValidation.path).Length
        $ruleId = [guid]::NewGuid().ToString()
        $ruleName = Protect-XmlAttributeValue -Value "$Action - $fileName (Hash)"
        $escapedDescription = Protect-XmlAttributeValue -Value $Description
        $escapedFileName = Protect-XmlAttributeValue -Value $fileName

        $xml = @"
<FileHashRule Id="$ruleId" Name="$ruleName" Description="$escapedDescription" UserOrGroupSid="S-1-1-0" Action="$Action">
  <Conditions>
    <FileHashCondition>
      <FileHash Type="SHA256" Data="$hash" SourceFileName="$escapedFileName" SourceFileLength="$fileSize" />
    </FileHashCondition>
  </Conditions>
</FileHashRule>
"@

        return @{
            success = $true
            id = $ruleId
            name = "$Action - $fileName (Hash)"
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
    Automatically generates rules from a list of artifacts with deny list support (from AaronLocker)
.PARAMETER Artifacts
    Array of artifact hashtables with publisher/path/hash info
.PARAMETER RuleType
    Type of rule to generate: Publisher, Path, or Hash
.PARAMETER Action
    Allow or Deny
.PARAMETER DenyListPath
    Optional path to deny list file
.PARAMETER UseDenyList
    Enable deny list filtering (default: true)
.OUTPUTS
    System.Collections.Hashtable with rules, denied count, and filtered artifacts
#>
function New-RulesFromArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Artifacts,
        [ValidateSet('Publisher', 'Path', 'Hash')]
        [string]$RuleType = 'Publisher',
        [ValidateSet('Allow', 'Deny')]
        [string]$Action = 'Allow',
        [string]$DenyListPath,
        [bool]$UseDenyList = $true
    )

    if (-not $Artifacts -or $Artifacts.Count -eq 0) {
        return @{
            success = $false
            error = 'No artifacts provided'
            rules = @()
        }
    }

    # Load deny list if enabled (from AaronLocker pattern)
    $denyList = $null
    $deniedCount = 0
    $filteredArtifacts = @()

    if ($UseDenyList) {
        $denyList = Get-DenyList -DenyListPath $DenyListPath
        if (-not $denyList.success) {
            Write-Warning "Failed to load deny list: $($denyList.error)"
            $denyList = $null
        }
    }

    $rules = @()
    $publishersSeen = @{}
    $deniedPublishers = @()
    $deniedPaths = @()

    foreach ($artifact in $Artifacts) {
        switch ($RuleType) {
            'Publisher' {
                $publisher = $artifact.publisher
                if ($publisher -and $publisher -ne 'Unknown' -and -not $publishersSeen.ContainsKey($publisher)) {
                    # Check deny list (from AaronLocker pattern)
                    if ($UseDenyList -and $denyList -and (Test-DeniedPublisher -PublisherName $publisher -DenyList $denyList)) {
                        $deniedPublishers += $publisher
                        $deniedCount++
                        continue
                    }

                    if (-not $publishersSeen.ContainsKey($publisher)) {
                        $rule = New-PublisherRule -PublisherName $publisher -Action $Action
                        if ($rule.success) {
                            $rules += $rule
                            $publishersSeen[$publisher] = $true
                            $filteredArtifacts += $artifact
                        }
                    }
                }
            }
            'Path' {
                $path = $artifact.path
                if ($path) {
                    # Check deny list
                    if ($UseDenyList -and $denyList -and (Test-DeniedPath -FilePath $path -DenyList $denyList)) {
                        $deniedPaths += $path
                        $deniedCount++
                        continue
                    }

                    $rule = New-PathRule -Path $path -Action $Action
                    if ($rule.success) {
                        $rules += $rule
                        $filteredArtifacts += $artifact
                    }
                }
            }
            'Hash' {
                $path = $artifact.path
                if ($path -and (Test-Path $path)) {
                    # Check deny list for path
                    if ($UseDenyList -and $denyList -and (Test-DeniedPath -FilePath $path -DenyList $denyList)) {
                        $deniedPaths += $path
                        $deniedCount++
                        continue
                    }

                    $rule = New-HashRule -FilePath $path -Action $Action
                    if ($rule.success) {
                        $rules += $rule
                        $filteredArtifacts += $artifact
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
        deniedCount = $deniedCount
        deniedPublishers = $deniedPublishers
        deniedPaths = $deniedPaths
        filteredArtifacts = $filteredArtifacts
        totalInput = $Artifacts.Count
    }
}

# ======================================================================
# SOFTWARE GAP ANALYSIS - Custom GA-AppLocker Feature
# ======================================================================

<#
.SYNOPSIS
    Get Baseline List Path
.DESCRIPTION
    Returns the path to the baseline list file
.PARAMETER CustomPath
    Optional custom path to baseline list file
.OUTPUTS
    Full path to baseline list file
#>
function Get-BaselineListPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$CustomPath
    )

    if ($CustomPath) {
        return $CustomPath
    }

    # Use Config.psm1 path
    $baselineDir = if ($script:customizationInputsDir) {
        $script:customizationInputsDir
    } else {
        Join-Path $script:basePath "custom"
    }

    return Join-Path $baselineDir "software-baseline.txt"
}

<#
.SYNOPSIS
    Get Software Baseline
.DESCRIPTION
    Loads the software baseline list from file (approved software list)
.PARAMETER BaselinePath
    Path to baseline file
.OUTPUTS
    System.Collections.Hashtable with baseline software entries
#>
function Get-SoftwareBaseline {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$BaselinePath
    )

    $baselinePath = Get-BaselineListPath -CustomPath $BaselinePath

    if (-not (Test-Path $baselinePath)) {
        return @{
            success = $true
            publishers = @()
            paths = @()
            names = @()
            count = 0
            message = 'No baseline file found'
            path = $baselinePath
        }
    }

    try {
        $lines = Get-Content -Path $baselinePath -ErrorAction Stop

        $baselinePublishers = [System.Collections.Generic.HashSet[string]]::new()
        $baselinePaths = [System.Collections.Generic.HashSet[string]]::new()
        $baselineNames = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($line in $lines) {
            $line = $line.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }

            # Parse publisher entries
            if ($line -match '^Publisher:\s*(.+)$') {
                $publisher = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($publisher)) {
                    $baselinePublishers.Add($publisher)
                }
            }
            # Parse path entries
            elseif ($line -match '^Path:\s*(.+)$') {
                $path = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($path)) {
                    $baselinePaths.Add($path)
                }
            }
            # Parse file name entries
            elseif ($line -match '^Name:\s*(.+)$') {
                $name = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $baselineNames.Add($name)
                }
            }
            # Legacy format: just publisher name or file name
            elseif (-not $line.Contains(':')) {
                $baselineNames.Add($line)
            }
        }

        return @{
            success = $true
            publishers = $baselinePublishers
            paths = $baselinePaths
            names = $baselineNames
            count = $baselinePublishers.Count + $baselinePaths.Count + $baselineNames.Count
            path = $baselinePath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            publishers = @()
            paths = @()
            names = @()
            count = 0
        }
    }
}

<#
.SYNOPSIS
    Compare Artifacts to Baseline
.DESCRIPTION
    Performs gap analysis between scanned artifacts and approved baseline (from AaronLocker pattern)
.PARAMETER Artifacts
    Array of scanned artifact hashtables
.PARAMETER BaselinePath
    Path to baseline file
.PARAMETER IncludeMatches
    Include items that match baseline in results
.OUTPUTS
    System.Collections.Hashtable with gap analysis results
#>
function Compare-SoftwareBaseline {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Artifacts,
        [string]$BaselinePath,
        [switch]$IncludeMatches
    )

    if (-not $Artifacts -or $Artifacts.Count -eq 0) {
        return @{
            success = $false
            error = 'No artifacts provided'
        }
    }

    # Load baseline
    $baseline = Get-SoftwareBaseline -BaselinePath $BaselinePath
    if (-not $baseline.success) {
        return @{
            success = $false
            error = "Failed to load baseline: $($baseline.error)"
        }
    }

    $missingFromBaseline = @()    # Items in artifacts but NOT in baseline (unauthorized)
    $missingFromSystem = @()       # Items in baseline but NOT in artifacts (not installed)
    $matchingItems = @()            # Items in both (authorized and installed)
    $publishersSeen = @{}

    # Check each artifact against baseline
    foreach ($artifact in $Artifacts) {
        $publisher = $artifact.publisher
        $name = $artifact.name
        $path = $artifact.path

        $isMatch = $false

        # Check publisher match
        if ($publisher -and $publisher -ne 'Unknown' -and -not $publishersSeen.ContainsKey($publisher)) {
            if ($baseline.publishers.Contains($publisher)) {
                $isMatch = $true
            }
            # Check partial match
            foreach ($baselinePublisher in $baseline.publishers) {
                if ($publisher -like "*$baselinePublisher*" -or $baselinePublisher -like "*$publisher*") {
                    $isMatch = $true
                    break
                }
            }
        }

        # Check file name match
        if (-not $isMatch -and $name) {
            if ($baseline.names.Contains($name)) {
                $isMatch = $true
            }
        }

        # Check path match
        if (-not $isMatch -and $path) {
            foreach ($baselinePath in $baseline.paths) {
                if ($path -like "$baselinePath*") {
                    $isMatch = $true
                    break
                }
            }
        }

        if ($isMatch) {
            $matchingItems += $artifact
            if ($publisher -and -not $publishersSeen.ContainsKey($publisher)) {
                $publishersSeen[$publisher] = $true
            }
        }
        else {
            $missingFromBaseline += $artifact
            if ($publisher -and -not $publishersSeen.ContainsKey($publisher)) {
                $publishersSeen[$publisher] = $true
            }
        }
    }

    # Determine what's missing from the system (baseline items not found in artifacts)
    foreach ($baselinePublisher in $baseline.publishers) {
        $found = $false
        foreach ($artifact in $Artifacts) {
            if ($artifact.publisher -and $artifact.publisher -like "*$baselinePublisher*") {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $missingFromSystem += @{
                type = 'Publisher'
                value = $baselinePublisher
            }
        }
    }

    foreach ($baselineName in $baseline.names) {
        $found = $false
        foreach ($artifact in $Artifacts) {
            if ($artifact.name -eq $baselineName) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $missingFromSystem += @{
                type = 'Name'
                value = $baselineName
            }
        }
    }

    $result = @{
        success = $true
        scannedCount = $Artifacts.Count
        baselineCount = $baseline.count
        matchingCount = $matchingItems.Count
        unauthorizedCount = $missingFromBaseline.Count
        notInstalledCount = $missingFromSystem.Count
        compliancePercent = if ($Artifacts.Count -gt 0) {
            [math]::Round(($matchingItems.Count / $Artifacts.Count) * 100, 2)
        } else { 0 }
        missingFromBaseline = $missingFromBaseline
        missingFromSystem = $missingFromSystem
        matchingItems = if ($IncludeMatches) { $matchingItems } else { @() }
        baselinePath = $baseline.path
    }

    # Assessment
    if ($missingFromBaseline.Count -eq 0) {
        $result.assessment = 'Fully Compliant - All scanned software is in baseline'
    }
    elseif ($result.compliancePercent -ge 90) {
        $result.assessment = 'Mostly Compliant - Few unauthorized items found'
    }
    elseif ($result.compliancePercent -ge 50) {
        $result.assessment = 'Partially Compliant - Significant unauthorized software present'
    }
    else {
        $result.assessment = 'Non-Compliant - Extensive unauthorized software detected'
    }

    return $result
}

<#
.SYNOPSIS
    Create Sample Baseline
.DESCRIPTION
    Creates a sample software baseline file with common entries
.PARAMETER BaselinePath
    Path to baseline file
.PARAMETER Force
    Overwrite existing baseline
.OUTPUTS
    System.Collections.Hashtable
#>
function New-SampleBaseline {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$BaselinePath,
        [switch]$Force
    )

    $baselinePath = Get-BaselineListPath -CustomPath $BaselinePath

    if ((Test-Path $baselinePath) -and -not $Force) {
        return @{
            success = $false
            error = 'Baseline already exists. Use -Force to overwrite.'
            path = $baselinePath
        }
    }

    # Create directory if needed
    $parentDir = Split-Path -Parent $baselinePath
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    try {
        $sampleContent = @"
# AppLocker Software Baseline
# Lines starting with # are comments
# Use 'Publisher:' to approve specific software publishers
# Use 'Path:' to approve specific file paths
# Use 'Name:' to approve specific file names

# Approved Publishers (examples)
Publisher: Microsoft Corporation
Publisher: Google LLC
Publisher: VMware, Inc.
Publisher: Oracle Corporation
Publisher: Adobe Inc.
Publisher: Citrix Systems, Inc.
Publisher: Cisco Systems, Inc.

# Approved File Names (examples)
Name: chrome.exe
Name: firefox.exe
Name: explorer.exe
Name: cmd.exe
Name: powershell.exe
Name: notepad.exe

# Approved Paths (examples)
# Path: C:\Program Files\Microsoft Office\*
# Path: C:\Program Files\Adobe\*

# Add your approved software below:
"@

        $sampleContent | Set-Content -Path $baselinePath -ErrorAction Stop

        return @{
            success = $true
            path = $baselinePath
            message = 'Sample baseline created. Edit the file to add your approved software.'
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
                        $fpr.Description = if ($ruleInfo.Description) { $ruleInfo.Description } else { "" }
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
                        $fpr.Description = if ($ruleInfo.Description) { $ruleInfo.Description } else { "" }
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
                        $fhr.Description = if ($ruleInfo.Description) { $ruleInfo.Description } else { "" }
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
        # Use secure XML parsing to prevent XXE attacks
        $xmlReaderSettings = New-Object System.Xml.XmlReaderSettings
        $xmlReaderSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $xmlReaderSettings.XmlResolver = $null

        $xmlReader = [System.Xml.XmlReader]::Create($XmlPath, $xmlReaderSettings)
        try {
            $xml = New-Object System.Xml.XmlDocument
            $xml.Load($xmlReader)
        }
        finally {
            $xmlReader.Close()
        }

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
# Deny List Functions (from AaronLocker)
Export-ModuleMember -Function Get-DenyListPath, Get-DenyList, Test-DeniedPublisher, Test-DeniedPath,
                              Add-DenyListEntry, Remove-DenyListEntry, New-SampleDenyList,
# Software Gap Analysis Functions (GA-AppLocker Custom)
                              Get-BaselineListPath, Get-SoftwareBaseline, Compare-SoftwareBaseline, New-SampleBaseline,
# Rule Generation Functions
                              Protect-XmlAttributeValue, Get-TrustedPublishers, New-PublisherRule, New-PathRule, New-HashRule,
                              New-RulesFromArtifacts, Export-RulesToXml, Import-RulesFromXml,
                              Merge-AppLockerPolicies
