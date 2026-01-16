# GA-AppLocker.E2E.Tests.ps1
# End-to-End tests for GA-AppLocker Dashboard
# Tests complete workflows from start to finish

BeforeAll {
    # Get paths
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:SrcPath = Join-Path $script:ProjectRoot "src"
    $script:ModulesPath = Join-Path $script:SrcPath "modules"
    $script:LibPath = Join-Path $script:SrcPath "lib"

    # Import all required modules
    Import-Module (Join-Path $script:LibPath "Common.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Force -ErrorAction Stop

    # Test output directory
    $script:TestOutputDir = Join-Path $env:TEMP "GA-AppLocker-E2E-Tests"
    if (-not (Test-Path $script:TestOutputDir)) {
        New-Item -ItemType Directory -Path $script:TestOutputDir -Force | Out-Null
    }
}

AfterAll {
    # Cleanup test directory
    if (Test-Path $script:TestOutputDir) {
        Remove-Item $script:TestOutputDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "E2E: Artifact Scanning to Rule Generation" {

    Context "Complete Local Scanning Workflow" {

        It "Scans local directory and generates Publisher rules" -Skip:(-not (Test-Path "C:\Windows\System32")) {
            # Step 1: Simulate artifact collection (using real files)
            $testDir = "C:\Windows\System32"
            $artifacts = @()

            # Get a few real executables
            $files = Get-ChildItem -Path $testDir -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 3

            foreach ($file in $files) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                    $publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject -replace "CN=([^,]+).*", '$1' } else { "" }

                    $artifacts += @{
                        name = $file.Name
                        path = $file.FullName
                        publisher = $publisher
                        hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
                        fileType = "EXE"
                        isSigned = ($null -ne $sig.SignerCertificate)
                    }
                }
                catch {
                    # Skip files that can't be accessed
                }
            }

            $artifacts.Count | Should -BeGreaterOrEqual 1

            # Step 2: Generate rules from artifacts
            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Automated" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            $result.rules | Should -Not -BeNullOrEmpty

            # Step 3: Verify rule structure
            foreach ($rule in $result.rules) {
                $rule.type | Should -BeIn @("Publisher", "Hash", "Path")
                $rule.action | Should -Be "Allow"
                $rule.xml | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe "E2E: Rule Generation to XML Export" {

    Context "Complete Rule Export Workflow" {

        It "Generates rules and exports to valid AppLocker XML" {
            # Step 1: Create test artifacts
            $artifacts = @(
                @{
                    name = "app1.exe"
                    path = "C:\Program Files\App1\app1.exe"
                    publisher = "Contoso Ltd"
                    hash = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                    fileType = "EXE"
                    isSigned = $true
                },
                @{
                    name = "app2.exe"
                    path = "C:\Program Files\App2\app2.exe"
                    publisher = "Fabrikam Inc"
                    hash = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
                    fileType = "EXE"
                    isSigned = $true
                }
            )

            # Step 2: Generate rules
            $ruleResult = New-RulesFromArtifacts -Artifacts $artifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $ruleResult.success | Should -Be $true
            $ruleResult.rules.Count | Should -Be 2

            # Step 3: Export to XML (if function available)
            if (Get-Command Export-RulesToXml -ErrorAction SilentlyContinue) {
                $exportPath = Join-Path $script:TestOutputDir "e2e-export.xml"
                $exportResult = Export-RulesToXml -Rules $ruleResult.rules -OutputPath $exportPath

                $exportResult.success | Should -Be $true
                Test-Path $exportPath | Should -Be $true

                # Step 4: Validate XML structure
                [xml]$xmlContent = Get-Content $exportPath
                $xmlContent.AppLockerPolicy | Should -Not -BeNullOrEmpty
                $xmlContent.AppLockerPolicy.RuleCollection | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe "E2E: Policy Lifecycle" {

    Context "Rule Create -> Modify -> Export Workflow" {

        It "Creates, modifies, and exports rules through complete lifecycle" {
            # Step 1: Create initial rules
            $initialArtifacts = @(
                @{ name = "initial.exe"; path = "C:\Initial\app.exe"; publisher = "Initial Corp"; hash = "AAA"; isSigned = $true }
            )

            $initialRules = New-RulesFromArtifacts -Artifacts $initialArtifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"
            $initialRules.success | Should -Be $true

            # Step 2: Add more rules (simulating discovery of new software)
            $additionalArtifacts = @(
                @{ name = "additional.exe"; path = "C:\Additional\app.exe"; publisher = "Additional Corp"; hash = "BBB"; isSigned = $true }
            )

            $additionalRules = New-RulesFromArtifacts -Artifacts $additionalArtifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"
            $additionalRules.success | Should -Be $true

            # Step 3: Combine rules
            $allRules = @()
            $allRules += $initialRules.rules
            $allRules += $additionalRules.rules

            $allRules.Count | Should -Be 2

            # Step 4: Verify all rules have required properties
            foreach ($rule in $allRules) {
                $rule.type | Should -Not -BeNullOrEmpty
                $rule.action | Should -Be "Allow"
                $rule.xml | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe "E2E: Mixed Rule Type Generation" {

    Context "Automated Rule Type Selection" {

        It "Generates appropriate rule types based on artifact properties" {
            # Artifacts with different characteristics
            $mixedArtifacts = @(
                # Signed with publisher - should generate Publisher rule
                @{
                    name = "signed.exe"
                    path = "C:\Signed\app.exe"
                    publisher = "Trusted Publisher"
                    hash = "111222333444555666777888999000AAABBBCCCDDDEEEFFFAAA111222333"
                    isSigned = $true
                },
                # Unsigned - should generate Hash rule
                @{
                    name = "unsigned.exe"
                    path = "C:\Windows\System32\notepad.exe"  # Use real file for hash
                    publisher = ""
                    hash = ""  # Will be calculated
                    isSigned = $false
                }
            )

            $result = New-RulesFromArtifacts -Artifacts $mixedArtifacts -RuleType "Automated" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true

            # Should have Publisher rule for signed artifact
            $publisherRules = $result.rules | Where-Object { $_.type -eq "Publisher" }
            $publisherRules | Should -Not -BeNullOrEmpty

            # Verify Publisher rule has correct publisher
            ($publisherRules | Select-Object -First 1).publisher | Should -Be "Trusted Publisher"
        }
    }
}

Describe "E2E: Deny and Allow Rule Coexistence" {

    Context "Creating Both Allow and Deny Rules" {

        It "Creates valid Allow and Deny rules for same publisher category" {
            # Allow rules for trusted publishers
            $allowArtifacts = @(
                @{ name = "trusted.exe"; path = "C:\Trusted\app.exe"; publisher = "Trusted Corp"; hash = "AAA"; isSigned = $true }
            )

            $allowRules = New-RulesFromArtifacts -Artifacts $allowArtifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            # Deny rules for untrusted publishers
            $denyArtifacts = @(
                @{ name = "untrusted.exe"; path = "C:\Untrusted\app.exe"; publisher = "Untrusted Corp"; hash = "BBB"; isSigned = $true }
            )

            $denyRules = New-RulesFromArtifacts -Artifacts $denyArtifacts -RuleType "Publisher" -Action "Deny" -UserOrGroupSid "S-1-1-0"

            # Verify both succeeded
            $allowRules.success | Should -Be $true
            $denyRules.success | Should -Be $true

            # Verify actions are correct
            ($allowRules.rules | Select-Object -First 1).action | Should -Be "Allow"
            ($denyRules.rules | Select-Object -First 1).action | Should -Be "Deny"

            # Verify XML contains correct action
            ($allowRules.rules | Select-Object -First 1).xml | Should -Match 'Action="Allow"'
            ($denyRules.rules | Select-Object -First 1).xml | Should -Match 'Action="Deny"'
        }
    }
}

Describe "E2E: Large Dataset Handling" {

    Context "Performance with Many Artifacts" {

        It "Handles 100+ artifacts without timeout" {
            # Generate 100 test artifacts
            $largeArtifactSet = 1..100 | ForEach-Object {
                @{
                    name = "app$_.exe"
                    path = "C:\Apps\App$_\app$_.exe"
                    publisher = "Publisher $_"
                    hash = ("A" * 64)
                    isSigned = $true
                }
            }

            # Measure time
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            $result = New-RulesFromArtifacts -Artifacts $largeArtifactSet -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $stopwatch.Stop()

            # Should complete within reasonable time (30 seconds)
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 30000

            $result.success | Should -Be $true
            $result.rules.Count | Should -Be 100
        }

        It "Deduplicates efficiently with many duplicates" {
            # 50 unique publishers, each appearing twice = 100 artifacts, 50 rules
            $duplicateArtifactSet = 1..50 | ForEach-Object {
                $pubNum = $_
                @(
                    @{ name = "app${pubNum}a.exe"; path = "C:\Apps\a\app$pubNum.exe"; publisher = "Publisher $pubNum"; hash = "AAA$pubNum"; isSigned = $true }
                    @{ name = "app${pubNum}b.exe"; path = "C:\Apps\b\app$pubNum.exe"; publisher = "Publisher $pubNum"; hash = "BBB$pubNum"; isSigned = $true }
                )
            } | ForEach-Object { $_ }  # Flatten

            $result = New-RulesFromArtifacts -Artifacts $duplicateArtifactSet -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $true
            # Should deduplicate to 50 unique publishers
            $result.rules.Count | Should -Be 50
        }
    }
}

Describe "E2E: Group-Based Rule Assignment" {

    Context "Rules for Different User Groups" {

        It "Creates rules targeted at different security groups" {
            $artifact = @{
                name = "app.exe"
                path = "C:\App\app.exe"
                publisher = "Test Corp"
                hash = "ABC123"
                isSigned = $true
            }

            # Standard Users (Everyone)
            $everyoneRules = New-RulesFromArtifacts -Artifacts @($artifact) -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            # Administrators
            $adminRules = New-RulesFromArtifacts -Artifacts @($artifact) -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-5-32-544"

            # Custom group (example SID)
            $customRules = New-RulesFromArtifacts -Artifacts @($artifact) -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-5-21-123456789-123456789-123456789-1001"

            # All should succeed
            $everyoneRules.success | Should -Be $true
            $adminRules.success | Should -Be $true
            $customRules.success | Should -Be $true

            # Verify different SIDs in XML
            ($everyoneRules.rules | Select-Object -First 1).xml | Should -Match 'UserOrGroupSid="S-1-1-0"'
            ($adminRules.rules | Select-Object -First 1).xml | Should -Match 'UserOrGroupSid="S-1-5-32-544"'
            ($customRules.rules | Select-Object -First 1).xml | Should -Match 'UserOrGroupSid="S-1-5-21-'
        }
    }
}

Describe "E2E: Error Recovery" {

    Context "Graceful Handling of Invalid Data" {

        It "Continues processing valid artifacts when some are invalid" {
            $mixedArtifacts = @(
                @{ name = "valid.exe"; path = "C:\Valid\app.exe"; publisher = "Valid Corp"; hash = "AAA"; isSigned = $true }
                @{ name = ""; path = ""; publisher = ""; hash = "" }  # Invalid
                @{ name = "valid2.exe"; path = "C:\Valid2\app.exe"; publisher = "Valid Corp 2"; hash = "BBB"; isSigned = $true }
                $null  # Also invalid
            )

            # Should not throw, should process valid artifacts
            $result = New-RulesFromArtifacts -Artifacts $mixedArtifacts -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            # Should have processed the 2 valid artifacts
            $result.success | Should -Be $true
            $result.rules.Count | Should -BeGreaterOrEqual 2
        }

        It "Reports meaningful errors for completely invalid input" {
            $result = New-RulesFromArtifacts -Artifacts @() -RuleType "Publisher" -Action "Allow" -UserOrGroupSid "S-1-1-0"

            $result.success | Should -Be $false
            $result.error | Should -Not -BeNullOrEmpty
            $result.error | Should -Match "artifact"
        }
    }
}
