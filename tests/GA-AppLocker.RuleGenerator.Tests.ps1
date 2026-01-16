# GA-AppLocker.RuleGenerator.Tests.ps1
# Unit tests for Module3-RuleGenerator
# Tests all rule creation functions (Publisher, Hash, Path)

BeforeAll {
    # Get paths
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:SrcPath = Join-Path $script:ProjectRoot "src"
    $script:ModulesPath = Join-Path $script:SrcPath "modules"
    $script:LibPath = Join-Path $script:SrcPath "lib"

    # Import required modules
    Import-Module (Join-Path $script:LibPath "Common.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Force -ErrorAction Stop
}

Describe "New-PublisherRule Function" {

    Context "Basic Rule Creation" {

        It "Creates a valid Publisher rule with required parameters" {
            $result = New-PublisherRule -PublisherName "Microsoft Corporation" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result | Should -Not -BeNullOrEmpty
            $result.success | Should -Be $true
            $result.type | Should -Be "Publisher"
            $result.publisher | Should -Be "Microsoft Corporation"
            $result.action | Should -Be "Allow"
            $result.sid | Should -Be "S-1-1-0"
        }

        It "Creates unique GUIDs for each rule" {
            $rule1 = New-PublisherRule -PublisherName "Test Corp" -Action "Allow" -UserOrGroupSid "S-1-1-0"
            $rule2 = New-PublisherRule -PublisherName "Test Corp" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $rule1.id | Should -Not -Be $rule2.id
        }

        It "Includes valid XML in result" {
            $result = New-PublisherRule -PublisherName "Test Corp" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.xml | Should -Not -BeNullOrEmpty
            $result.xml | Should -Match "FilePublisherRule"
            $result.xml | Should -Match "Test Corp"
            $result.xml | Should -Match 'Action="Allow"'
            $result.xml | Should -Match 'UserOrGroupSid="S-1-1-0"'
        }
    }

    Context "Action Parameter" {

        It "Creates Allow rules correctly" {
            $result = New-PublisherRule -PublisherName "Test" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.action | Should -Be "Allow"
            $result.xml | Should -Match 'Action="Allow"'
        }

        It "Creates Deny rules correctly" {
            $result = New-PublisherRule -PublisherName "Test" -Action "Deny" -UserOrGroupSid "S-1-1-0"

            $result.action | Should -Be "Deny"
            $result.xml | Should -Match 'Action="Deny"'
        }

        It "Defaults to Allow when Action not specified" {
            $result = New-PublisherRule -PublisherName "Test" -UserOrGroupSid "S-1-1-0"

            $result.action | Should -Be "Allow"
        }
    }

    Context "SID Parameter" {

        It "Uses Everyone (S-1-1-0) as default SID" {
            $result = New-PublisherRule -PublisherName "Test"

            $result.sid | Should -Be "S-1-1-0"
            $result.xml | Should -Match 'UserOrGroupSid="S-1-1-0"'
        }

        It "Accepts custom SID" {
            $customSid = "S-1-5-21-123456789-123456789-123456789-1001"
            $result = New-PublisherRule -PublisherName "Test" -UserOrGroupSid $customSid

            $result.sid | Should -Be $customSid
            $result.xml | Should -Match $customSid
        }

        It "Accepts built-in group SIDs" {
            $adminSid = "S-1-5-32-544"
            $result = New-PublisherRule -PublisherName "Test" -UserOrGroupSid $adminSid

            $result.sid | Should -Be $adminSid
        }
    }

    Context "Input Validation" {

        It "Handles empty publisher name" {
            $result = New-PublisherRule -PublisherName "" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            # Should either fail or handle gracefully
            if ($result.success) {
                # If it succeeds, XML should still be valid
                $result.xml | Should -Not -BeNullOrEmpty
            } else {
                $result.error | Should -Not -BeNullOrEmpty
            }
        }

        It "Handles publisher name with special characters" {
            $result = New-PublisherRule -PublisherName 'Test & "Company" <Inc>' -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            # XML should be properly escaped
            { [xml]$result.xml } | Should -Not -Throw
        }
    }
}

Describe "New-HashRule Function" {

    Context "Basic Rule Creation" {

        It "Creates valid Hash rule for existing file" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result | Should -Not -BeNullOrEmpty
            $result.success | Should -Be $true
            $result.type | Should -Be "Hash"
            $result.hash | Should -Not -BeNullOrEmpty
            $result.hash.Length | Should -Be 64  # SHA256 = 64 hex chars
            $result.fileName | Should -Be "notepad.exe"
        }

        It "Includes valid XML in result" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.xml | Should -Match "FileHashRule"
            $result.xml | Should -Match "SHA256"
            $result.xml | Should -Match 'Action="Allow"'
        }

        It "Uses SHA256 algorithm" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            # SHA256 produces 64 character hex string
            $result.hash | Should -Match "^[A-Fa-f0-9]{64}$"
            $result.xml | Should -Match 'Type="SHA256"'
        }
    }

    Context "Error Handling" {

        It "Fails for non-existent file" {
            $result = New-HashRule -FilePath "C:\NonExistent\Path\file.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Match "not found|does not exist"
        }

        It "Fails for empty file path" {
            $result = New-HashRule -FilePath "" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
        }
    }

    Context "Action Parameter" {

        It "Creates Allow Hash rule" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.action | Should -Be "Allow"
            $result.xml | Should -Match 'Action="Allow"'
        }

        It "Creates Deny Hash rule" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Deny" -UserOrGroupSid "S-1-1-0"

            $result.action | Should -Be "Deny"
            $result.xml | Should -Match 'Action="Deny"'
        }
    }
}

Describe "New-PathRule Function" {

    Context "Basic Rule Creation" {

        It "Creates valid Path rule from file path" {
            $result = New-PathRule -FilePath "C:\Program Files\MyApp\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result | Should -Not -BeNullOrEmpty
            $result.success | Should -Be $true
            $result.type | Should -Be "Path"
            $result.path | Should -Not -BeNullOrEmpty
        }

        It "Extracts directory and adds wildcard" {
            $result = New-PathRule -FilePath "C:\Program Files\MyApp\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.path | Should -Be "C:\Program Files\MyApp\*"
        }

        It "Includes valid XML in result" {
            $result = New-PathRule -FilePath "C:\Test\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.xml | Should -Match "FilePathRule"
            $result.xml | Should -Match "FilePathCondition"
            $result.xml | Should -Match 'Action="Allow"'
        }
    }

    Context "Path Extraction" {

        It "Handles paths with spaces" {
            $result = New-PathRule -FilePath "C:\Program Files (x86)\My App\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.path | Should -Match "Program Files \(x86\)"
        }

        It "Handles deeply nested paths" {
            $result = New-PathRule -FilePath "C:\Level1\Level2\Level3\Level4\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.path | Should -Be "C:\Level1\Level2\Level3\Level4\*"
        }

        It "Handles root directory files" {
            $result = New-PathRule -FilePath "C:\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.path | Should -Be "C:\*"
        }
    }

    Context "Error Handling" {

        It "Fails for empty file path" {
            $result = New-PathRule -FilePath "" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Not -BeNullOrEmpty
        }

        It "Fails for null file path" {
            $result = New-PathRule -FilePath $null -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
        }
    }
}

Describe "New-RulesFromArtifacts Function" {

    Context "Publisher Rule Generation" {

        It "Generates Publisher rules from artifacts with publishers" {
            $artifacts = @(
                @{ name = "app1.exe"; path = "C:\App1\app.exe"; publisher = "Publisher 1"; hash = "AAA"; isSigned = $true }
                @{ name = "app2.exe"; path = "C:\App2\app.exe"; publisher = "Publisher 2"; hash = "BBB"; isSigned = $true }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules.Count | Should -Be 2
            $result.rules[0].type | Should -Be "Publisher"
        }

        It "Skips artifacts without publisher" {
            $artifacts = @(
                @{ name = "app1.exe"; path = "C:\App1\app.exe"; publisher = "Valid Publisher"; hash = "AAA"; isSigned = $true }
                @{ name = "app2.exe"; path = "C:\App2\app.exe"; publisher = ""; hash = "BBB"; isSigned = $false }
                @{ name = "app3.exe"; path = "C:\App3\app.exe"; publisher = "Unknown"; hash = "CCC"; isSigned = $false }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            # Only the valid publisher should have a rule
            $result.rules.Count | Should -Be 1
            $result.rules[0].publisher | Should -Be "Valid Publisher"
        }

        It "Deduplicates by publisher" {
            $artifacts = @(
                @{ name = "app1.exe"; path = "C:\App1\app.exe"; publisher = "Same Publisher"; hash = "AAA"; isSigned = $true }
                @{ name = "app2.exe"; path = "C:\App2\app.exe"; publisher = "Same Publisher"; hash = "BBB"; isSigned = $true }
                @{ name = "app3.exe"; path = "C:\App3\app.exe"; publisher = "Same Publisher"; hash = "CCC"; isSigned = $true }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules.Count | Should -Be 1
        }
    }

    Context "Hash Rule Generation" {

        It "Generates Hash rules from artifacts with file paths" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $artifacts = @(
                @{ name = "notepad.exe"; path = "C:\Windows\System32\notepad.exe"; publisher = ""; hash = ""; isSigned = $false }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Hash" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            if ($result.rules.Count -gt 0) {
                $result.rules[0].type | Should -Be "Hash"
                $result.rules[0].hash | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context "Path Rule Generation" {

        It "Generates Path rules from artifacts" {
            $artifacts = @(
                @{ name = "app1.exe"; path = "C:\Apps\App1\app.exe"; publisher = ""; hash = ""; isSigned = $false }
                @{ name = "app2.exe"; path = "C:\Apps\App2\app.exe"; publisher = ""; hash = ""; isSigned = $false }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Path" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules | Should -Not -BeNullOrEmpty
            foreach ($rule in $result.rules) {
                $rule.type | Should -Be "Path"
            }
        }
    }

    Context "Automated Rule Type Selection" {

        It "Selects Publisher for signed artifacts" {
            $artifacts = @(
                @{ name = "signed.exe"; path = "C:\App\app.exe"; publisher = "Valid Publisher"; hash = "AAA"; isSigned = $true }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Automated" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules[0].type | Should -Be "Publisher"
        }
    }

    Context "Error Handling" {

        It "Returns error for empty artifact list" {
            $result = New-RulesFromArtifacts -Artifacts @() -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Match "No artifacts"
        }

        It "Returns error for null artifact list" {
            $result = New-RulesFromArtifacts -Artifacts $null -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
        }
    }
}

Describe "XML Generation Quality" {

    Context "Valid XML Output" {

        It "Publisher rule XML is well-formed" {
            $result = New-PublisherRule -PublisherName "Test Corp" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            { [xml]$result.xml } | Should -Not -Throw
        }

        It "Hash rule XML is well-formed" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            { [xml]$result.xml } | Should -Not -Throw
        }

        It "Path rule XML is well-formed" {
            $result = New-PathRule -FilePath "C:\Test\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            { [xml]$result.xml } | Should -Not -Throw
        }
    }

    Context "Required XML Elements" {

        It "Publisher rule has all required elements" {
            $result = New-PublisherRule -PublisherName "Test" -Action "Allow" -UserOrGroupSid "S-1-1-0"
            [xml]$xml = "<Root>$($result.xml)</Root>"

            $xml.Root.FilePublisherRule | Should -Not -BeNullOrEmpty
            $xml.Root.FilePublisherRule.Id | Should -Not -BeNullOrEmpty
            $xml.Root.FilePublisherRule.Name | Should -Not -BeNullOrEmpty
            $xml.Root.FilePublisherRule.UserOrGroupSid | Should -Not -BeNullOrEmpty
            $xml.Root.FilePublisherRule.Action | Should -Not -BeNullOrEmpty
            $xml.Root.FilePublisherRule.Conditions | Should -Not -BeNullOrEmpty
        }

        It "Hash rule has all required elements" -Skip:(-not (Test-Path "C:\Windows\System32\notepad.exe")) {
            $result = New-HashRule -FilePath "C:\Windows\System32\notepad.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"
            [xml]$xml = "<Root>$($result.xml)</Root>"

            $xml.Root.FileHashRule | Should -Not -BeNullOrEmpty
            $xml.Root.FileHashRule.Id | Should -Not -BeNullOrEmpty
            $xml.Root.FileHashRule.Conditions | Should -Not -BeNullOrEmpty
            $xml.Root.FileHashRule.Conditions.FileHashCondition | Should -Not -BeNullOrEmpty
        }

        It "Path rule has all required elements" {
            $result = New-PathRule -FilePath "C:\Test\app.exe" -Action "Allow" -UserOrGroupSid "S-1-1-0"
            [xml]$xml = "<Root>$($result.xml)</Root>"

            $xml.Root.FilePathRule | Should -Not -BeNullOrEmpty
            $xml.Root.FilePathRule.Id | Should -Not -BeNullOrEmpty
            $xml.Root.FilePathRule.Conditions | Should -Not -BeNullOrEmpty
            $xml.Root.FilePathRule.Conditions.FilePathCondition | Should -Not -BeNullOrEmpty
        }
    }
}
