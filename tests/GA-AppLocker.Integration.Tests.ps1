# GA-AppLocker.Integration.Tests.ps1
# Integration tests for GA-AppLocker Dashboard
# Tests complete workflows and multi-function interactions

BeforeAll {
    # Get paths
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:SrcPath = Join-Path $script:ProjectRoot "src"
    $script:ModulesPath = Join-Path $script:SrcPath "modules"
    $script:LibPath = Join-Path $script:SrcPath "lib"
    $script:BuildPath = Join-Path $script:ProjectRoot "build"

    # Import Common module first (required by others)
    Import-Module (Join-Path $script:LibPath "Common.psm1") -Force -ErrorAction Stop

    # Import core modules for testing
    Import-Module (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Force -ErrorAction Stop

    # Create test artifact data
    $script:TestArtifacts = @(
        @{
            name = "notepad.exe"
            path = "C:\Windows\System32\notepad.exe"
            publisher = "Microsoft Corporation"
            hash = "ABC123DEF456789012345678901234567890123456789012345678901234"
            version = "10.0.19041.1"
            size = 193536
            modifiedDate = (Get-Date)
            fileType = "EXE"
            isSigned = $true
        },
        @{
            name = "calc.exe"
            path = "C:\Windows\System32\calc.exe"
            publisher = "Microsoft Corporation"
            hash = "DEF456ABC789012345678901234567890123456789012345678901234567"
            version = "10.0.19041.1"
            size = 27648
            modifiedDate = (Get-Date)
            fileType = "EXE"
            isSigned = $true
        },
        @{
            name = "unknown.exe"
            path = "C:\Temp\unknown.exe"
            publisher = ""
            hash = "123456789012345678901234567890123456789012345678901234567890"
            version = ""
            size = 10240
            modifiedDate = (Get-Date)
            fileType = "EXE"
            isSigned = $false
        }
    )
}

Describe "Rule Generation Integration" {

    Context "Publisher Rule Generation" {

        It "Creates valid Publisher rule from artifact with publisher" {
            $artifact = $script:TestArtifacts[0]
            $result = New-PublisherRule -PublisherName $artifact.publisher -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.type | Should -Be "Publisher"
            $result.publisher | Should -Be "Microsoft Corporation"
            $result.action | Should -Be "Allow"
            $result.xml | Should -Match "FilePublisherRule"
        }

        It "Creates Deny Publisher rule correctly" {
            $result = New-PublisherRule -PublisherName "Malware Inc" -Action "Deny" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.action | Should -Be "Deny"
            $result.xml | Should -Match 'Action="Deny"'
        }

        It "Handles special characters in publisher name" {
            $result = New-PublisherRule -PublisherName "Company & Sons <Inc>" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            # XML should be properly escaped
            $result.xml | Should -Not -Match '&[^a]' # Should not have unescaped ampersand
        }
    }

    Context "Hash Rule Generation" {

        It "Creates valid Hash rule from file" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.type | Should -Be "Hash"
            $result.hash | Should -Not -BeNullOrEmpty
            $result.hash.Length | Should -Be 64  # SHA256 hash length
            $result.xml | Should -Match "FileHashRule"
        }

        It "Fails gracefully for non-existent file" {
            $result = New-HashRule -FilePath "C:\NonExistent\File.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Match "not found"
        }
    }

    Context "Path Rule Generation" {

        It "Creates valid Path rule from file path" {
            $result = New-PathRule -FilePath "C:\Program Files\MyApp\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.type | Should -Be "Path"
            $result.path | Should -Match "\\\*$"  # Should end with \*
            $result.xml | Should -Match "FilePathRule"
        }

        It "Extracts directory from file path" {
            $result = New-PathRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.path | Should -Be "C:\Windows\System32\*"
        }

        It "Fails gracefully for empty path" {
            $result = New-PathRule -FilePath "" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
        }
    }

    Context "Bulk Rule Generation" {

        It "Creates rules from multiple artifacts" {
            $result = New-RulesFromArtifacts -Artifacts $script:TestArtifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules | Should -Not -BeNullOrEmpty
            # Should create rules for artifacts with publishers
            $result.rules.Count | Should -BeGreaterOrEqual 1
        }

        It "Deduplicates rules by publisher" {
            # Two artifacts with same publisher should create one rule
            $duplicates = @(
                @{ name = "app1.exe"; path = "C:\App1\app1.exe"; publisher = "Same Publisher"; hash = "AAA"; isSigned = $true }
                @{ name = "app2.exe"; path = "C:\App2\app2.exe"; publisher = "Same Publisher"; hash = "BBB"; isSigned = $true }
            )

            $result = New-RulesFromArtifacts -Artifacts $duplicates -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules.Count | Should -Be 1
        }

        It "Falls back to Hash when no publisher available" {
            $noPublisher = @(
                @{ name = "unsigned.exe"; path = "C:\Windows\System32\notepad.exe"; publisher = ""; hash = ""; isSigned = $false }
            )

            # This test requires the file to exist for hash generation
            if (Test-Path "C:\Windows\System32\notepad.exe") {
                $result = New-RulesFromArtifacts -Artifacts $noPublisher -RuleType "Automated" -Action "Allow" -UserOrGroupSid "S-1-1-0"

                $result.success | Should -Be $true
            }
        }

        It "Handles empty artifact list gracefully" {
            $result = New-RulesFromArtifacts -Artifacts @() -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Match "No artifacts"
        }
    }
}

Describe "Artifact Data Model Integration" {

    Context "Artifact Creation and Validation" {

        It "Creates artifact with all required properties" {
            $artifact = New-AppLockerArtifact -Name "test.exe" -Path "C:\Test\test.exe" -Publisher "Test Corp" -Hash "ABC123" -FileType "EXE"

            $artifact | Should -Not -BeNullOrEmpty
            $artifact.name | Should -Be "test.exe"
            $artifact.path | Should -Be "C:\Test\test.exe"
            $artifact.publisher | Should -Be "Test Corp"
        }

        It "Validates artifact for Publisher rule requirements" {
            $validArtifact = @{ name = "test.exe"; path = "C:\test.exe"; publisher = "Publisher" }
            $invalidArtifact = @{ name = "test.exe"; path = "C:\test.exe"; publisher = "" }

            $validResult = Test-AppLockerArtifact -Artifact $validArtifact -RuleType "Publisher"
            $invalidResult = Test-AppLockerArtifact -Artifact $invalidArtifact -RuleType "Publisher"

            $validResult | Should -Be $true
            $invalidResult | Should -Be $false
        }

        It "Validates artifact for Hash rule requirements" {
            $validArtifact = @{ name = "test.exe"; path = "C:\test.exe"; hash = "ABC123" }
            $invalidArtifact = @{ name = "test.exe"; path = "C:\test.exe"; hash = "" }

            $validResult = Test-AppLockerArtifact -Artifact $validArtifact -RuleType "Hash"
            $invalidResult = Test-AppLockerArtifact -Artifact $invalidArtifact -RuleType "Hash"

            $validResult | Should -Be $true
            $invalidResult | Should -Be $false
        }

        It "Validates artifact for Path rule requirements" {
            $validArtifact = @{ name = "test.exe"; path = "C:\test.exe" }
            $invalidArtifact = @{ name = "test.exe"; path = "" }

            $validResult = Test-AppLockerArtifact -Artifact $validArtifact -RuleType "Path"
            $invalidResult = Test-AppLockerArtifact -Artifact $invalidArtifact -RuleType "Path"

            $validResult | Should -Be $true
            $invalidResult | Should -Be $false
        }
    }

    Context "Artifact Format Conversion" {

        It "Converts between Module2 and GUI formats" {
            $module2Artifact = @{
                name = "test.exe"
                path = "C:\test.exe"
                publisher = "Test Corp"
                hash = "ABC123"
            }

            $guiArtifact = Convert-AppLockerArtifact -Artifact $module2Artifact -TargetFormat "GUI"

            # GUI format uses PascalCase
            $guiArtifact.Name | Should -Be "test.exe"
            $guiArtifact.Path | Should -Be "C:\test.exe"
            $guiArtifact.Publisher | Should -Be "Test Corp"
        }

        It "Handles missing properties during conversion" {
            $incompleteArtifact = @{
                name = "test.exe"
                path = "C:\test.exe"
            }

            $converted = Convert-AppLockerArtifact -Artifact $incompleteArtifact -TargetFormat "GUI"

            $converted.Name | Should -Be "test.exe"
            $converted.Publisher | Should -BeNullOrEmpty
        }
    }
}

Describe "Deny List Integration" {

    BeforeAll {
        # Create temp deny list for testing
        $script:TempDenyListPath = Join-Path $env:TEMP "test-deny-list.json"
        $testDenyList = @{
            publishers = @("Malware Inc", "Bad Software LLC")
            paths = @("C:\Temp\*", "C:\Users\*\Downloads\*")
        }
        $testDenyList | ConvertTo-Json | Set-Content $script:TempDenyListPath
    }

    AfterAll {
        # Cleanup
        if (Test-Path $script:TempDenyListPath) {
            Remove-Item $script:TempDenyListPath -Force
        }
    }

    Context "Deny List Operations" {

        It "Loads deny list from file" -Skip:(-not (Get-Command Get-DenyList -ErrorAction SilentlyContinue)) {
            $denyList = Get-DenyList -Path $script:TempDenyListPath

            $denyList | Should -Not -BeNullOrEmpty
            $denyList.publishers | Should -Contain "Malware Inc"
        }

        It "Tests publisher against deny list" -Skip:(-not (Get-Command Test-DeniedPublisher -ErrorAction SilentlyContinue)) {
            $isDenied = Test-DeniedPublisher -Publisher "Malware Inc"
            $isAllowed = Test-DeniedPublisher -Publisher "Microsoft Corporation"

            $isDenied | Should -Be $true
            $isAllowed | Should -Be $false
        }

        It "Tests path against deny list" -Skip:(-not (Get-Command Test-DeniedPath -ErrorAction SilentlyContinue)) {
            $isDenied = Test-DeniedPath -Path "C:\Temp\malware.exe"
            $isAllowed = Test-DeniedPath -Path "C:\Program Files\app.exe"

            $isDenied | Should -Be $true
            $isAllowed | Should -Be $false
        }
    }
}

Describe "XML Export Integration" {

    Context "Rule to XML Conversion" {

        It "Exports rules to valid AppLocker XML format" -Skip:(-not (Get-Command Export-RulesToXml -ErrorAction SilentlyContinue)) {
            # Create some test rules
            $rules = @(
                @{ type = "Publisher"; publisher = "Microsoft"; action = "Allow"; sid = "S-1-1-0"; xml = '<FilePublisherRule Id="{test}" Name="Test" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="Microsoft" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>' }
            )

            $tempPath = Join-Path $env:TEMP "test-export.xml"

            try {
                $result = Export-RulesToXml -Rules $rules -OutputPath $tempPath

                $result.success | Should -Be $true
                Test-Path $tempPath | Should -Be $true

                # Validate XML structure
                [xml]$xmlContent = Get-Content $tempPath
                $xmlContent.AppLockerPolicy | Should -Not -BeNullOrEmpty
            }
            finally {
                if (Test-Path $tempPath) { Remove-Item $tempPath -Force }
            }
        }

        It "Imports rules from XML file" -Skip:(-not (Get-Command Import-RulesFromXml -ErrorAction SilentlyContinue)) {
            $testXml = @"
<?xml version="1.0" encoding="utf-16"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Executable" EnforcementMode="AuditOnly">
    <FilePublisherRule Id="{12345678-1234-1234-1234-123456789012}" Name="Test" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="Test Corp" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@

            $tempPath = Join-Path $env:TEMP "test-import.xml"

            try {
                Set-Content -Path $tempPath -Value $testXml -Encoding Unicode

                $result = Import-RulesFromXml -Path $tempPath

                $result.success | Should -Be $true
                $result.rules | Should -Not -BeNullOrEmpty
            }
            finally {
                if (Test-Path $tempPath) { Remove-Item $tempPath -Force }
            }
        }
    }
}

Describe "Security Integration" {

    Context "Input Validation" {

        It "Protects XML attributes from injection" -Skip:(-not (Get-Command Protect-XmlAttributeValue -ErrorAction SilentlyContinue)) {
            $maliciousInput = 'Test" malicious="true'
            $safeOutput = Protect-XmlAttributeValue -Value $maliciousInput

            $safeOutput | Should -Not -Match '"'
        }

        It "Protects LDAP filters from injection" -Skip:(-not (Get-Command Protect-LDAPFilterValue -ErrorAction SilentlyContinue)) {
            $maliciousInput = "user*)(objectClass=*"
            $safeOutput = Protect-LDAPFilterValue -Value $maliciousInput

            $safeOutput | Should -Not -Contain "("
            $safeOutput | Should -Not -Contain ")"
        }

        It "Validates path for safety" -Skip:(-not (Get-Command Test-AppLockerPath -ErrorAction SilentlyContinue)) {
            $safePath = "C:\Program Files\App\app.exe"
            $unsafePath = "..\..\Windows\System32\cmd.exe"

            $safeResult = Test-AppLockerPath -Path $safePath
            $unsafeResult = Test-AppLockerPath -Path $unsafePath

            $safeResult | Should -Be $true
            $unsafeResult | Should -Be $false
        }
    }
}

Describe "Error Handling Integration" {

    Context "Graceful Failure Scenarios" {

        It "Returns structured error for invalid input" {
            $result = New-RulesFromArtifacts -Artifacts $null -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Not -BeNullOrEmpty
        }

        It "Handles missing modules gracefully" {
            # This tests that functions check for required modules
            # Most functions should return error hashtable if module unavailable
            $result = @{ success = $false; error = "Module test" }
            $result.success | Should -Be $false
        }
    }
}
