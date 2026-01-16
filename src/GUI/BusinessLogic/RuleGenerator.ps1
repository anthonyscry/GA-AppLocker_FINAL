<#
.SYNOPSIS
    AppLocker rule generation business logic

.DESCRIPTION
    Core functions for generating Publisher, Hash, and Path rules from artifacts.
    This module provides pure business logic for AppLocker rule generation without
    any UI dependencies.

.NOTES
    Module Name: RuleGenerator
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: None (pure business logic)

.EXAMPLE
    Import-Module .\RuleGenerator.ps1

    # Generate a publisher rule
    $result = New-PublisherRule -PublisherName "Microsoft Corporation" -Action "Allow"
    if ($result.success) {
        Write-Host "Rule created: $($result.xml)"
    }

.EXAMPLE
    # Generate hash rules from artifacts
    $artifacts = @(
        @{ FullPath = "C:\Program Files\app.exe"; Publisher = "Contoso" }
    )
    $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Hash" -Action "Allow"
    Write-Host "Generated $($result.count) rules"

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# PUBLIC FUNCTIONS
# ============================================================

function New-PublisherRule {
    <#
    .SYNOPSIS
        Creates an AppLocker publisher rule

    .DESCRIPTION
        Generates an AppLocker publisher rule XML for a specific publisher.
        Returns a hashtable with rule details and XML representation.

    .PARAMETER PublisherName
        The publisher/company name to allow or deny (e.g., "Microsoft Corporation")

    .PARAMETER ProductName
        The product name pattern (default: "*" for all products)

    .PARAMETER BinaryName
        The binary name pattern (default: "*" for all binaries)

    .PARAMETER Version
        The minimum version (default: "*" for all versions)

    .PARAMETER Action
        Rule action: "Allow" or "Deny"

    .PARAMETER UserOrGroupSid
        SID for user or group (default: "S-1-1-0" for Everyone)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean indicating success/failure
        - id: GUID of the rule
        - type: "Publisher"
        - publisher: Publisher name
        - action: Allow/Deny
        - sid: User or Group SID
        - xml: Rule XML string
        - error: Error message (if failure)

    .EXAMPLE
        $rule = New-PublisherRule -PublisherName "Microsoft Corporation" -Action "Allow"
        if ($rule.success) {
            Write-Host "Created rule: $($rule.id)"
        }

    .EXAMPLE
        # Create a deny rule for a specific publisher
        $rule = New-PublisherRule -PublisherName "Bad Publisher" -Action "Deny" -UserOrGroupSid "S-1-5-21-123456789-1234567890-1234567890-1001"

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Valid publisher rule
        $result = New-PublisherRule -PublisherName "TestCorp" -Action "Allow"
        Assert ($result.success -eq $true)
        Assert ($result.type -eq "Publisher")
        Assert ($result.xml -match "TestCorp")

        # Test: Missing publisher name
        $result = New-PublisherRule -PublisherName "" -Action "Allow"
        Assert ($result.success -eq $false)
        Assert ($result.error -ne $null)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PublisherName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ProductName = "*",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$BinaryName = "*",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Version = "*",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Allow", "Deny")]
        [string]$Action = "Allow",

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^S-1-[0-59]-\d+')]
        [string]$UserOrGroupSid = "S-1-1-0"
    )

    try {
        # Validate publisher name
        if ([string]::IsNullOrWhiteSpace($PublisherName)) {
            return @{
                success = $false
                error = "Publisher name is required and cannot be empty"
            }
        }

        # Generate unique GUID for rule
        $guid = "{$([Guid]::NewGuid().ToString())}"

        # Build XML with proper escaping
        $escapedPublisher = [System.Security.SecurityElement]::Escape($PublisherName)
        $escapedProduct = [System.Security.SecurityElement]::Escape($ProductName)
        $escapedBinary = [System.Security.SecurityElement]::Escape($BinaryName)
        $escapedVersion = [System.Security.SecurityElement]::Escape($Version)

        $xml = @"
<FilePublisherRule Id="$guid" Name="$escapedPublisher" UserOrGroupSid="$UserOrGroupSid" Action="$Action">
  <Conditions>
    <FilePublisherCondition PublisherName="$escapedPublisher" ProductName="$escapedProduct" BinaryName="$escapedBinary">
      <BinaryVersionRange LowSection="$escapedVersion" HighSection="*" />
    </FilePublisherCondition>
  </Conditions>
</FilePublisherRule>
"@

        return @{
            success = $true
            id = $guid
            type = "Publisher"
            publisher = $PublisherName
            product = $ProductName
            binary = $BinaryName
            version = $Version
            action = $Action
            sid = $UserOrGroupSid
            xml = $xml
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to create publisher rule: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function New-HashRule {
    <#
    .SYNOPSIS
        Creates an AppLocker hash rule

    .DESCRIPTION
        Generates an AppLocker hash rule XML for a specific file using SHA256.
        The file must exist for the hash to be calculated.

    .PARAMETER FilePath
        Full path to the file to hash

    .PARAMETER Action
        Rule action: "Allow" or "Deny"

    .PARAMETER UserOrGroupSid
        SID for user or group (default: "S-1-1-0" for Everyone)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - id: GUID of the rule
        - type: "Hash"
        - hash: SHA256 hash value
        - fileName: Name of the file
        - filePath: Full path of the file
        - action: Allow/Deny
        - sid: User or Group SID
        - xml: Rule XML string
        - error: Error message (if failure)

    .EXAMPLE
        $rule = New-HashRule -FilePath "C:\Program Files\app.exe" -Action "Allow"
        if ($rule.success) {
            Write-Host "Hash: $($rule.hash)"
        }

    .NOTES
        Unit Test Example:
        ```powershell
        # Create a test file
        $testFile = "$env:TEMP\test.exe"
        "test" | Out-File $testFile

        # Test: Valid hash rule
        $result = New-HashRule -FilePath $testFile -Action "Allow"
        Assert ($result.success -eq $true)
        Assert ($result.hash -ne $null)
        Assert ($result.type -eq "Hash")

        # Test: Non-existent file
        $result = New-HashRule -FilePath "C:\NonExistent\file.exe" -Action "Allow"
        Assert ($result.success -eq $false)

        # Cleanup
        Remove-Item $testFile
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Allow", "Deny")]
        [string]$Action = "Allow",

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^S-1-[0-59]-\d+')]
        [string]$UserOrGroupSid = "S-1-1-0"
    )

    try {
        # Validate file exists
        if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            return @{
                success = $false
                error = "File not found: $FilePath"
            }
        }

        # Calculate SHA256 hash
        $hashObject = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        $hash = $hashObject.Hash

        # Get file information
        $fileItem = Get-Item -Path $FilePath -ErrorAction Stop
        $fileName = $fileItem.Name

        # Generate unique GUID
        $guid = "{$([Guid]::NewGuid().ToString())}"

        # Build XML with proper escaping
        $escapedFileName = [System.Security.SecurityElement]::Escape($fileName)

        $xml = @"
<FileHashRule Id="$guid" Name="$escapedFileName" UserOrGroupSid="$UserOrGroupSid" Action="$Action">
  <Conditions>
    <FileHashCondition>
      <FileHash SourceFileName="$escapedFileName" SourceFileHash="$hash" HashAlgorithm="SHA256" />
    </FileHashCondition>
  </Conditions>
</FileHashRule>
"@

        return @{
            success = $true
            id = $guid
            type = "Hash"
            hash = $hash
            fileName = $fileName
            filePath = $FilePath
            action = $Action
            sid = $UserOrGroupSid
            xml = $xml
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to create hash rule: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function New-RulesFromArtifacts {
    <#
    .SYNOPSIS
        Generates multiple AppLocker rules from artifact data

    .DESCRIPTION
        Processes an array of artifacts (scanned files) and generates appropriate
        AppLocker rules. Handles deduplication automatically.

    .PARAMETER Artifacts
        Array of artifact objects with properties: Publisher, FullPath, FileName, Name

    .PARAMETER RuleType
        Type of rules to generate: "Publisher", "Hash", or "Path"

    .PARAMETER Action
        Rule action: "Allow" or "Deny"

    .PARAMETER UserOrGroupSid
        SID for user or group (default: "S-1-1-0" for Everyone)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - rules: Array of generated rules
        - count: Number of rules generated
        - ruleType: Type of rules
        - action: Allow/Deny
        - sid: User or Group SID
        - processedCount: Number of unique items processed
        - skippedCount: Number of items skipped
        - error: Error message (if failure)

    .EXAMPLE
        $artifacts = @(
            @{ Publisher = "Microsoft Corporation"; FullPath = "C:\Program Files\app1.exe" },
            @{ Publisher = "Microsoft Corporation"; FullPath = "C:\Program Files\app2.exe" },
            @{ Publisher = "Adobe Inc."; FullPath = "C:\Program Files\Adobe\app.exe" }
        )
        $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Publisher" -Action "Allow"
        Write-Host "Generated $($result.count) rules (2 unique publishers)"

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Publisher rule deduplication
        $artifacts = @(
            @{ Publisher = "TestCorp"; FullPath = "C:\test1.exe" },
            @{ Publisher = "TestCorp"; FullPath = "C:\test2.exe" },
            @{ Publisher = "OtherCorp"; FullPath = "C:\test3.exe" }
        )
        $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Publisher"
        Assert ($result.success -eq $true)
        Assert ($result.count -eq 2) # Only 2 unique publishers
        Assert ($result.processedCount -eq 2)

        # Test: Empty artifacts
        $result = New-RulesFromArtifacts -Artifacts @() -RuleType "Publisher"
        Assert ($result.success -eq $false)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [array]$Artifacts,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Publisher", "Hash", "Path")]
        [string]$RuleType = "Publisher",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Allow", "Deny")]
        [string]$Action = "Allow",

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^S-1-[0-59]-\d+')]
        [string]$UserOrGroupSid = "S-1-1-0"
    )

    try {
        # Validate input
        if (-not $Artifacts -or $Artifacts.Count -eq 0) {
            return @{
                success = $false
                error = "No artifacts provided"
                count = 0
            }
        }

        $rules = @()
        $processed = @{}
        $skipped = 0

        foreach ($artifact in $Artifacts) {
            # Handle various property name formats from different sources
            $publisherName = $artifact.Publisher ?? $artifact.publisher ?? $artifact.CompanyName ?? $artifact.Signer ?? $null
            $filePath = $artifact.FullPath ?? $artifact.fullPath ?? $artifact.Path ?? $artifact.path ?? $artifact.FilePath ?? $null
            $fileName = $artifact.FileName ?? $artifact.Name ?? $artifact.name ?? $null

            switch ($RuleType) {
                "Publisher" {
                    # Only process if publisher is valid
                    if ([string]::IsNullOrWhiteSpace($publisherName) -or
                        $publisherName -eq "Unknown" -or
                        $publisherName -eq "N/A") {
                        $skipped++
                        continue
                    }

                    # Deduplicate by publisher name
                    $key = $publisherName.Trim().ToLowerInvariant()
                    if ($processed.ContainsKey($key)) {
                        $skipped++
                        continue
                    }

                    $processed[$key] = $true
                    $rule = New-PublisherRule -PublisherName $publisherName -Action $Action -UserOrGroupSid $UserOrGroupSid
                    if ($rule.success) {
                        $rules += $rule
                    }
                }

                "Hash" {
                    # Only process if file path is valid
                    if ([string]::IsNullOrWhiteSpace($filePath)) {
                        $skipped++
                        continue
                    }

                    if (-not (Test-Path -Path $filePath -PathType Leaf -ErrorAction SilentlyContinue)) {
                        $skipped++
                        continue
                    }

                    # Deduplicate by file path
                    $key = $filePath.Trim().ToLowerInvariant()
                    if ($processed.ContainsKey($key)) {
                        $skipped++
                        continue
                    }

                    $processed[$key] = $true
                    $rule = New-HashRule -FilePath $filePath -Action $Action -UserOrGroupSid $UserOrGroupSid
                    if ($rule.success) {
                        $rules += $rule
                    }
                }

                "Path" {
                    # Only process if file path is valid
                    if ([string]::IsNullOrWhiteSpace($filePath)) {
                        $skipped++
                        continue
                    }

                    # Create path rule for the directory
                    $directory = Split-Path -Parent $filePath -ErrorAction SilentlyContinue
                    if ([string]::IsNullOrWhiteSpace($directory)) {
                        $skipped++
                        continue
                    }

                    # Deduplicate by directory
                    $key = $directory.Trim().ToLowerInvariant()
                    if ($processed.ContainsKey($key)) {
                        $skipped++
                        continue
                    }

                    $processed[$key] = $true

                    # Generate path rule
                    $guid = "{$([Guid]::NewGuid().ToString())}"
                    $pathPattern = "$directory\*"
                    $escapedDirectory = [System.Security.SecurityElement]::Escape($directory)
                    $escapedPathPattern = [System.Security.SecurityElement]::Escape($pathPattern)

                    $xml = @"
<FilePathRule Id="$guid" Name="$escapedDirectory" UserOrGroupSid="$UserOrGroupSid" Action="$Action">
  <Conditions>
    <FilePathCondition Path="$escapedPathPattern" />
  </Conditions>
</FilePathRule>
"@

                    $rules += @{
                        success = $true
                        id = $guid
                        type = "Path"
                        publisher = $directory
                        path = $pathPattern
                        action = $Action
                        sid = $UserOrGroupSid
                        xml = $xml
                    }
                }
            }
        }

        return @{
            success = $true
            rules = $rules
            count = $rules.Count
            ruleType = $RuleType
            action = $Action
            sid = $UserOrGroupSid
            processedCount = $processed.Count
            skippedCount = $skipped
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to generate rules from artifacts: $($_.Exception.Message)"
            exception = $_.Exception
            count = 0
        }
    }
}

function New-DefaultDenyRules {
    <#
    .SYNOPSIS
        Creates default deny rules for common bypass locations

    .DESCRIPTION
        Generates AppLocker path rules to deny execution from common writable
        locations used for bypass (TEMP folders, Downloads, AppData, etc.).
        Best practice for hardening AppLocker policies.

    .PARAMETER UserOrGroupSid
        SID for user or group (default: "S-1-1-0" for Everyone)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - rules: Array of deny rules
        - count: Number of rules generated
        - ruleType: "Path"
        - action: "Deny"
        - locations: Array of blocked locations

    .EXAMPLE
        $result = New-DefaultDenyRules
        Write-Host "Created $($result.count) deny rules"
        foreach ($rule in $result.rules) {
            Write-Host "Blocking: $($rule.path)"
        }

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Default deny rules generation
        $result = New-DefaultDenyRules
        Assert ($result.success -eq $true)
        Assert ($result.count -gt 0)
        Assert ($result.action -eq "Deny")
        Assert ($result.ruleType -eq "Path")

        # Verify TEMP folder is blocked
        $tempRule = $result.rules | Where-Object { $_.path -like "*TEMP*" }
        Assert ($tempRule -ne $null)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^S-1-[0-59]-\d+')]
        [string]$UserOrGroupSid = "S-1-1-0"
    )

    try {
        $rules = @()
        $locations = @()

        # Common bypass locations to deny
        $bypassLocations = @(
            @{ Path = "%TEMP%\*"; Name = "Block TEMP folder"; Description = "Deny execution from system TEMP" }
            @{ Path = "%TMP%\*"; Name = "Block TMP folder"; Description = "Deny execution from TMP" }
            @{ Path = "%USERPROFILE%\AppData\Local\Temp\*"; Name = "Block User Temp folder"; Description = "Deny execution from user local temp" }
            @{ Path = "%LOCALAPPDATA%\Temp\*"; Name = "Block LocalAppData Temp"; Description = "Deny execution from LocalAppData Temp" }
            @{ Path = "%USERPROFILE%\Downloads\*"; Name = "Block Downloads folder"; Description = "Deny execution from user Downloads" }
            @{ Path = "C:\Users\*\Downloads\*"; Name = "Block All User Downloads"; Description = "Deny execution from all user Downloads folders" }
            @{ Path = "%APPDATA%\*"; Name = "Block AppData Roaming"; Description = "Deny execution from AppData Roaming" }
            @{ Path = "%LOCALAPPDATA%\*"; Name = "Block AppData Local"; Description = "Deny execution from AppData Local" }
            @{ Path = "C:\Windows\Temp\*"; Name = "Block Windows Temp"; Description = "Deny execution from Windows Temp" }
            @{ Path = "C:\ProgramData\*"; Name = "Block ProgramData"; Description = "Deny execution from ProgramData" }
            @{ Path = "C:\Windows\Tasks\*"; Name = "Block Tasks folder"; Description = "Deny execution from scheduled tasks folder" }
            @{ Path = "C:\Recycler\*"; Name = "Block Recycler"; Description = "Deny execution from Recycler" }
            @{ Path = "C:\$Recycle.Bin\*"; Name = "Block Recycle Bin"; Description = "Deny execution from Recycle Bin" }
        )

        foreach ($location in $bypassLocations) {
            $guid = "{$([Guid]::NewGuid().ToString())}"
            $escapedName = [System.Security.SecurityElement]::Escape($location.Name)
            $escapedPath = [System.Security.SecurityElement]::Escape($location.Path)
            $escapedDescription = [System.Security.SecurityElement]::Escape($location.Description)

            $xml = @"
<FilePathRule Id="$guid" Name="$escapedName" Description="$escapedDescription" UserOrGroupSid="$UserOrGroupSid" Action="Deny">
  <Conditions>
    <FilePathCondition Path="$escapedPath" />
  </Conditions>
</FilePathRule>
"@

            $rules += @{
                success = $true
                id = $guid
                type = "Path"
                publisher = $location.Name
                path = $location.Path
                description = $location.Description
                action = "Deny"
                sid = $UserOrGroupSid
                xml = $xml
            }

            $locations += $location.Path
        }

        return @{
            success = $true
            rules = $rules
            count = $rules.Count
            ruleType = "Path"
            action = "Deny"
            locations = $locations
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to create default deny rules: $($_.Exception.Message)"
            exception = $_.Exception
            count = 0
        }
    }
}

function New-BrowserDenyRules {
    <#
    .SYNOPSIS
        Creates deny rules for common web browsers

    .DESCRIPTION
        Generates AppLocker rules to deny execution of web browsers.
        Useful for administrative accounts that should not have internet access.

    .PARAMETER UserOrGroupSid
        SID for user or group (default: "S-1-1-0" for Everyone)

    .PARAMETER IncludeLegacyBrowsers
        Include legacy browsers like Internet Explorer

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - rules: Array of browser deny rules
        - count: Number of rules generated
        - browsers: Array of browser names blocked
        - policyXml: Complete policy XML (optional)

    .EXAMPLE
        $result = New-BrowserDenyRules -UserOrGroupSid "S-1-5-32-544"
        Write-Host "Blocked $($result.count) browser paths for Administrators"

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Browser deny rules
        $result = New-BrowserDenyRules
        Assert ($result.success -eq $true)
        Assert ($result.count -gt 0)

        # Verify Chrome is blocked
        $chromeRule = $result.browsers | Where-Object { $_ -eq "Chrome" }
        Assert ($chromeRule -ne $null)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^S-1-[0-59]-\d+')]
        [string]$UserOrGroupSid = "S-1-1-0",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeLegacyBrowsers
    )

    try {
        $rules = @()
        $browserNames = @()

        # Common browsers to deny
        $browsers = @(
            @{ Name = "Chrome"; Paths = @("C:\Program Files\Google\Chrome\Application\chrome.exe", "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") }
            @{ Name = "Firefox"; Paths = @("C:\Program Files\Mozilla Firefox\firefox.exe", "C:\Program Files (x86)\Mozilla Firefox\firefox.exe") }
            @{ Name = "Edge"; Paths = @("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "C:\Program Files\Microsoft\Edge\Application\msedge.exe") }
            @{ Name = "Opera"; Paths = @("C:\Program Files\Opera\launcher.exe", "C:\Program Files (x86)\Opera\launcher.exe") }
            @{ Name = "Brave"; Paths = @("C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", "C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe") }
            @{ Name = "Vivaldi"; Paths = @("C:\Program Files\Vivaldi\Application\vivaldi.exe", "C:\Program Files (x86)\Vivaldi\Application\vivaldi.exe") }
        )

        if ($IncludeLegacyBrowsers) {
            $browsers += @{ Name = "Internet Explorer"; Paths = @("C:\Program Files\Internet Explorer\iexplore.exe", "C:\Program Files (x86)\Internet Explorer\iexplore.exe") }
        }

        foreach ($browser in $browsers) {
            $guid = "{$([Guid]::NewGuid().ToString())}"
            $ruleName = "Deny $($browser.Name) for Admins"
            $escapedRuleName = [System.Security.SecurityElement]::Escape($ruleName)

            # Build conditions for all paths
            $conditions = ""
            foreach ($path in $browser.Paths) {
                $escapedPath = [System.Security.SecurityElement]::Escape($path)
                $conditions += "    <FilePathCondition Path=`"$escapedPath`" />`n"
            }

            $xml = @"
<FilePathRule Id="$guid" Name="$escapedRuleName" UserOrGroupSid="$UserOrGroupSid" Action="Deny">
  <Conditions>
$conditions  </Conditions>
</FilePathRule>
"@

            $rules += @{
                success = $true
                id = $guid
                type = "Path"
                browser = $browser.Name
                paths = $browser.Paths
                action = "Deny"
                sid = $UserOrGroupSid
                xml = $xml
            }

            $browserNames += $browser.Name
        }

        return @{
            success = $true
            rules = $rules
            count = $rules.Count
            browsers = $browserNames
            ruleType = "Path"
            action = "Deny"
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to create browser deny rules: $($_.Exception.Message)"
            exception = $_.Exception
            count = 0
        }
    }
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Test-RuleXml {
    <#
    .SYNOPSIS
        Validates AppLocker rule XML

    .DESCRIPTION
        Internal helper to validate XML structure

    .PARAMETER Xml
        XML string to validate

    .OUTPUTS
        Boolean indicating if XML is valid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Xml
    )

    try {
        $null = [xml]$Xml
        return $true
    }
    catch {
        return $false
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'New-PublisherRule',
    'New-HashRule',
    'New-RulesFromArtifacts',
    'New-DefaultDenyRules',
    'New-BrowserDenyRules'
)
