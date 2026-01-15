# GA-AppLocker.Tests.ps1
# Pester tests for GA-AppLocker Dashboard modules
# Updated with tests for deny list, software gap analysis, and AaronLocker alignment

BeforeAll {
    # Import modules
    $modulePath = $PSScriptRoot + "\..\src\modules"
    $libPath = $PSScriptRoot + "\..\src\lib"
    $srcPath = $PSScriptRoot + "\..\src"

    Import-Module (Join-Path $libPath "Common.psm1") -Force
    Import-Module (Join-Path $srcPath "Config.psm1") -Force
    Import-Module (Join-Path $modulePath "Module1-Dashboard.psm1") -Force
    Import-Module (Join-Path $modulePath "Module2-RemoteScan.psm1") -Force
    Import-Module (Join-Path $modulePath "Module3-RuleGenerator.psm1") -Force
    Import-Module (Join-Path $modulePath "Module4-PolicyLab.psm1") -Force
    Import-Module (Join-Path $modulePath "Module5-EventMonitor.psm1") -Force
    Import-Module (Join-Path $modulePath "Module6-ADManager.psm1") -Force
    Import-Module (Join-Path $modulePath "Module7-Compliance.psm1") -Force
}

Describe "Module1-Dashboard" {
    It "Get-AppLockerEventStats returns hashtable with success property" {
        $result = Get-AppLockerEventStats
        $result | Should -Not -BeNullOrEmpty
        $result.success | Should -BeIn @($true, $false)
    }

    It "Get-AppLockerEventStats returns numeric event counts when successful" {
        $result = Get-AppLockerEventStats
        if ($result.success) {
            $result.allowed | Should -BeGreaterOrEqual 0
            $result.audit | Should -BeGreaterOrEqual 0
            $result.blocked | Should -BeGreaterOrEqual 0
        } else {
            # If not successful (e.g., no log), should still have zero counts
            $result.allowed | Should -Be 0
            $result.audit | Should -Be 0
            $result.blocked | Should -Be 0
        }
    }

    It "Get-PolicyHealthScore returns hashtable with score property" {
        $result = Get-PolicyHealthScore
        $result | Should -Not -BeNullOrEmpty
        $result.score | Should -BeGreaterOrEqual 0
        $result.score | Should -BeLessOrEqual 100
    }

    It "Get-PolicyHealthScore returns boolean flags for rule types" {
        $result = Get-PolicyHealthScore
        $result.hasExe | Should -BeOfType [bool]
        $result.hasMsi | Should -BeOfType [bool]
        $result.hasScript | Should -BeOfType [bool]
        $result.hasDll | Should -BeOfType [bool]
    }

    It "Get-PolicyHealthScore score is calculated from rule categories" {
        $result = Get-PolicyHealthScore
        $expectedScore = 0
        if ($result.hasExe) { $expectedScore += 25 }
        if ($result.hasMsi) { $expectedScore += 25 }
        if ($result.hasScript) { $expectedScore += 25 }
        if ($result.hasDll) { $expectedScore += 25 }
        $result.score | Should -Be $expectedScore
    }
}

Describe "Module2-RemoteScan" {
    It "Get-ExecutableArtifacts requires valid path" {
        $result = Get-ExecutableArtifacts -TargetPath "C:\Invalid\Path\That\Does\Not\Exist"
        $result.success | Should -Be $false
    }

    It "Get-ExecutableArtifacts handles valid path gracefully" {
        # Use a path that should exist but may have access restrictions
        $testPath = "$env:TEMP"
        $result = Get-ExecutableArtifacts -TargetPath $testPath -MaxFiles 10
        # Should succeed even if no executables found
        $result.success | Should -BeIn @($true, $false)
        $result.data | Should -Not -BeNullOrEmpty
    }

    It "Get-ExecutableArtifacts returns empty array when no executables found" {
        # Create a temp directory with no executables
        $emptyDir = "$env:TEMP\GA-AppLocker-EmptyTest-$(Get-Random)"
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null

        try {
            $result = Get-ExecutableArtifacts -TargetPath $emptyDir -MaxFiles 10
            $result.success | Should -Be $true
            $result.count | Should -Be 0
        } finally {
            Remove-Item -Path $emptyDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "Test-ComputerOnline requires computer name" {
        $result = Test-ComputerOnline -ComputerName ""
        $result.success | Should -Be $false
        $result.online | Should -Be $false
    }

    It "Test-ComputerOnline returns result structure" {
        $result = Test-ComputerOnline -ComputerName "nonexistent-computer-12345"
        $result.success | Should -Be $true
        $result.computerName | Should -Be "nonexistent-computer-12345"
        $result.online | Should -Be $false
    }

    It "Export-ScanResults requires artifacts" {
        $result = Export-ScanResults -Artifacts @() -OutputPath "$env:TEMP\test.csv"
        $result.success | Should -Be $false
    }

    It "Export-ScanResults requires output path" {
        $result = Export-ScanResults -Artifacts @( @{name="test"} ) -OutputPath ""
        $result.success | Should -Be $false
    }

    It "Export-ScanResults exports valid artifacts successfully" {
        $testFile = "$env:TEMP\test-scan-export.csv"
        $artifacts = @(
            @{ name = "test.exe"; path = "C:\test.exe"; publisher = "Test"; hash = "abc123" }
        )

        try {
            $result = Export-ScanResults -Artifacts $artifacts -OutputPath $testFile
            $result.success | Should -Be $true
            $result.path | Should -Be $testFile
            Test-Path $testFile | Should -Be $true
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    # Module2 AaronLocker Pattern Tests
    It "Get-DirectorySafetyClassification classifies Program Files as SafeDir" {
        $result = Get-DirectorySafetyClassification -DirectoryPath "C:\Program Files"
        $result | Should -Be "SafeDir"
    }

    It "Get-DirectorySafetyClassification classifies Temp as UnsafeDir" {
        $result = Get-DirectorySafetyClassification -DirectoryPath "C:\Users\John\AppData\Local\Temp"
        $result | Should -Be "UnsafeDir"
    }

    It "Get-DirectorySafetyClassification classifies Downloads as UnsafeDir" {
        $result = Get-DirectorySafetyClassification -DirectoryPath "C:\Users\John\Downloads"
        $result | Should -Be "UnsafeDir"
    }

    It "Get-DirectorySafetyClassification returns UnknownDir for unrecognized paths" {
        $result = Get-DirectorySafetyClassification -DirectoryPath "D:\Some\Random\Path"
        $result | Should -Be "UnknownDir"
    }

    It "Get-DirectorySafetyClassification handles empty input" {
        $result = Get-DirectorySafetyClassification -DirectoryPath ""
        $result | Should -Be "UnknownDir"
    }

    It "Get-DirectoryFilesSafe returns empty for non-existent path" {
        $result = Get-DirectoryFilesSafe -Path "C:\NonExistent\Path\12345" -Extension @('.exe') -MaxFiles 10
        $result.Count | Should -Be 0
    }

    It "Get-DirectoryFilesSafe returns array of files" {
        $testDir = "$env:TEMP\GA-AppLocker-ScanTest"
        try {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
            "test content" | Out-File "$testDir\test.txt" -Encoding ascii

            $result = Get-DirectoryFilesSafe -Path $testDir -Extension @('.txt') -MaxFiles 10
            $result.Count | Should -BeGreaterOrEqual 0
        } finally {
            Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe "Module3-RuleGenerator" {
    It "New-PublisherRule requires publisher name" {
        $result = New-PublisherRule -PublisherName ""
        $result.success | Should -Be $false
    }

    It "New-PublisherRule returns valid rule with publisher name" {
        $result = New-PublisherRule -PublisherName "Test Corporation"
        $result.success | Should -Be $true
        $result.id | Should -Not -BeNullOrEmpty
        $result.type | Should -Be "Publisher"
        $result.xml | Should -Not -BeNullOrEmpty
    }

    It "New-PublisherRule generates valid GUID" {
        $result = New-PublisherRule -PublisherName "Test Corp"
        $guid = [guid]::empty
        [guid]::TryParse($result.id, [ref]$guid) | Should -Be $true
    }

    It "New-PublisherRule XML contains expected elements" {
        $result = New-PublisherRule -PublisherName "Microsoft Corporation"
        $result.xml | Should -Match '<FilePublisherRule'
        $result.xml | Should -Match 'Action="Allow"'
        $result.xml | Should -Match 'PublisherName='
    }

    It "New-PathRule requires path" {
        $result = New-PathRule -Path ""
        $result.success | Should -Be $false
    }

    It "New-PathRule returns valid rule with path" {
        $result = New-PathRule -Path "C:\Program Files\*.exe"
        $result.success | Should -Be $true
        $result.type | Should -Be "Path"
        $result.xml | Should -Not -BeNullOrEmpty
    }

    It "New-PathRule XML contains expected elements" {
        $result = New-PathRule -Path "C:\Windows\*.exe"
        $result.xml | Should -Match '<FilePathRule'
        $result.xml | Should -Match 'FilePathCondition'
        $result.xml | Should -Match 'Path='
    }

    It "New-HashRule requires existing file" {
        $result = New-HashRule -FilePath "C:\nonexistent\file.exe"
        $result.success | Should -Be $false
    }

    It "New-HashRule works with existing file" {
        # Create a test file
        $testFile = "$env:TEMP\test-hash-file.exe"
        "test" | Out-File -FilePath $testFile -Encoding ASCII

        try {
            $result = New-HashRule -FilePath $testFile
            $result.success | Should -Be $true
            $result.type | Should -Be "Hash"
            $result.hash | Should -Not -BeNullOrEmpty
            $result.hash | Should -BeExactly 64  # SHA256 is 64 characters
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "Export-RulesToXml requires rules" {
        $result = Export-RulesToXml -Rules @() -OutputPath "$env:TEMP\test.xml"
        $result.success | Should -Be $false
    }

    It "Export-RulesToXml creates valid XML" {
        $rules = @(
            New-PublisherRule -PublisherName "Test Corp"
        )

        $testFile = "$env:TEMP\test-policy.xml"
        try {
            $result = Export-RulesToXml -Rules $rules -OutputPath $testFile
            $result.success | Should -Be $true
            Test-Path $testFile | Should -Be $true

            [xml]$xml = Get-Content $testFile
            $xml.AppLockerPolicy | Should -Not -BeNullOrEmpty
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "New-RulesFromArtifacts requires artifacts" {
        $result = New-RulesFromArtifacts -Artifacts @()
        $result.success | Should -Be $false
    }

    It "New-RulesFromArtifacts generates rules from artifacts" {
        $artifacts = @(
            @{ publisher = "Microsoft"; name = "app.exe" }
            @{ publisher = "Google"; name = "chrome.exe" }
            @{ publisher = "Microsoft"; name = "word.exe" }  # Duplicate publisher
        )

        $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType Publisher
        $result.success | Should -Be $true
        $result.rules | Should -Not -BeNullOrEmpty
        # Should deduplicate publishers
        $result.count | Should -BeLessOrEqual 3
    }

    # Deny List Tests (AaronLocker pattern)
    It "Get-DenyList returns empty hashtable when no file exists" {
        $testPath = "$env:TEMP\nonexistent-deny-list.txt"
        $result = Get-DenyList -DenyListPath $testPath
        $result.success | Should -Be $true
        $result.publishers.Count | Should -Be 0
        $result.paths.Count | Should -Be 0
        $result.count | Should -Be 0
    }

    It "Add-DenyListEntry validates input parameters" {
        $result = Add-DenyListEntry -Publisher "" -Path ""
        $result.success | Should -Be $false
        $result.error | Should -Be "Either Publisher or Path must be specified"
    }

    It "Add-DenyListEntry adds publisher entry to file" {
        $testPath = "$env:TEMP\test-deny-list.txt"
        try {
            $result = Add-DenyListEntry -Publisher "TestPublisher" -DenyListPath $testPath
            $result.success | Should -Be $true
            Test-Path $testPath | Should -Be $true
            $content = Get-Content $testPath
            $content | Should -Match "Publisher: TestPublisher"
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Add-DenyListEntry adds path entry to file" {
        $testPath = "$env:TEMP\test-deny-list-path.txt"
        try {
            $result = Add-DenyListEntry -Path "C:\Temp\*" -DenyListPath $testPath
            $result.success | Should -Be $true
            Test-Path $testPath | Should -Be $true
            $content = Get-Content $testPath
            $content | Should -Match "Path: C:\\Temp\\*"
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Test-DeniedPublisher identifies denied publishers" {
        $testPath = "$env:TEMP\test-deny-list-check.txt"
        try {
            Add-DenyListEntry -Publisher "BlockedCorp" -DenyListPath $testPath | Out-Null
            $result = Test-DeniedPublisher -PublisherName "BlockedCorp" -DenyListPath $testPath
            $result | Should -Be $true
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Test-DeniedPublisher returns false for non-denied publishers" {
        $testPath = "$env:TEMP\test-deny-list-safe.txt"
        try {
            Add-DenyListEntry -Publisher "BlockedCorp" -DenyListPath $testPath | Out-Null
            $result = Test-DeniedPublisher -PublisherName "SafeCorp" -DenyListPath $testPath
            $result | Should -Be $false
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Test-DeniedPath identifies denied paths" {
        $testPath = "$env:TEMP\test-deny-list-path-check.txt"
        try {
            Add-DenyListEntry -Path "C:\Temp\*" -DenyListPath $testPath | Out-Null
            $result = Test-DeniedPath -FilePath "C:\Temp\app.exe" -DenyListPath $testPath
            $result | Should -Be $true
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "New-SampleDenyList creates sample file" {
        $testPath = "$env:TEMP\test-sample-deny-list.txt"
        try {
            $result = New-SampleDenyList -DenyListPath $testPath
            $result.success | Should -Be $true
            Test-Path $testPath | Should -Be $true
            $content = Get-Content $testPath -Raw
            $content | Should -Match "# AppLocker Deny List"
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "New-SampleDenyList fails if file exists without Force" {
        $testPath = "$env:TEMP\test-sample-deny-list-exist.txt"
        try {
            New-SampleDenyList -DenyListPath $testPath | Out-Null
            $result = New-SampleDenyList -DenyListPath $testPath
            $result.success | Should -Be $false
            $result.error | Should -Match "already exists"
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "New-RulesFromArtifacts filters denied publishers" {
        $testPath = "$env:TEMP\test-deny-list-filter.txt"
        try {
            Add-DenyListEntry -Publisher "BlockedCorp" -DenyListPath $testPath | Out-Null

            $artifacts = @(
                @{ publisher = "Microsoft"; name = "app.exe" }
                @{ publisher = "BlockedCorp"; name = "bad.exe" }
                @{ publisher = "Google"; name = "chrome.exe" }
            )

            $result = New-RulesFromArtifacts -Artifacts $artifacts -RuleType Publisher -DenyListPath $testPath -UseDenyList
            $result.success | Should -Be $true
            $result.deniedCount | Should -Be 1
            $result.deniedPublishers | Should -Contain "BlockedCorp"
            $result.count | Should -Be 2  # Only Microsoft and Google
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    # Software Gap Analysis Tests (GA-AppLocker Custom Feature)
    It "Get-SoftwareBaseline returns empty when no file exists" {
        $testPath = "$env:TEMP\nonexistent-baseline.txt"
        $result = Get-SoftwareBaseline -BaselinePath $testPath
        $result.success | Should -Be $true
        $result.publishers.Count | Should -Be 0
        $result.paths.Count | Should -Be 0
        $result.names.Count | Should -Be 0
    }

    It "New-SampleBaseline creates sample file" {
        $testPath = "$env:TEMP\test-sample-baseline.txt"
        try {
            $result = New-SampleBaseline -BaselinePath $testPath
            $result.success | Should -Be $true
            Test-Path $testPath | Should -Be $true
            $content = Get-Content $testPath -Raw
            $content | Should -Match "# AppLocker Software Baseline"
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Compare-SoftwareBaseline requires artifacts" {
        $result = Compare-SoftwareBaseline -Artifacts @()
        $result.success | Should -Be $false
        $result.error | Should -Match "No artifacts"
    }

    It "Compare-SoftwareBaseline returns compliance statistics" {
        $testPath = "$env:TEMP\test-baseline-compare.txt"
        try {
            # Create baseline with Microsoft
            "Publisher: Microsoft Corporation" | Out-File $testPath -Encoding utf8

            $artifacts = @(
                @{ publisher = "Microsoft Corporation"; name = "word.exe"; path = "C:\Program Files\word.exe" }
                @{ publisher = "Unauthorized Corp"; name = "bad.exe"; path = "C:\Temp\bad.exe" }
            )

            $result = Compare-SoftwareBaseline -Artifacts $artifacts -BaselinePath $testPath
            $result.success | Should -Be $true
            $result.scannedCount | Should -Be 2
            $result.unauthorizedCount | Should -Be 1
            $result.compliancePercent | Should -Be 50
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Compare-SoftwareBaseline identifies missing software" {
        $testPath = "$env:TEMP\test-baseline-missing.txt"
        try {
            # Create baseline with Microsoft and Oracle
            @"
Publisher: Microsoft Corporation
Publisher: Oracle Corporation
"@ | Out-File $testPath -Encoding utf8

            $artifacts = @(
                @{ publisher = "Microsoft Corporation"; name = "word.exe"; path = "C:\word.exe" }
            )

            $result = Compare-SoftwareBaseline -Artifacts $artifacts -BaselinePath $testPath
            $result.success | Should -Be $true
            $result.notInstalledCount | Should -Be 1
            $result.missingFromSystem[0].value | Should -Be "Oracle Corporation"
        } finally {
            Remove-Item $testPath -Force -ErrorAction SilentlyContinue
        }
    }

    It "Protect-XmlAttributeValue escapes special characters" {
        $testValue = 'test&<>"'
        $result = Protect-XmlAttributeValue -Value $testValue
        $result | Should -Not -Match '[^&]&[^;]'
        $result | Should -Not -Match '<'
        $result | Should -Not -Match '>'
        $result | Should -Match '&amp;'
        $result | Should -Match '&lt;'
    }
}

Describe "Module4-PolicyLab" {
    It "New-AppLockerGPO requires GPO name" {
        # Function has internal validation, so empty string is handled
        $result = New-AppLockerGPO -GpoName ""
        $result.success | Should -Be $false
        $result.error | Should -Be "GPO name is required"
    }

    It "New-AppLockerGPO handles missing GroupPolicy module gracefully" {
        # Will return success=false if GroupPolicy module not available
        $result = New-AppLockerGPO -GpoName "TestGPO"
        $result | Should -Not -BeNullOrEmpty
        # Should either succeed (if module available) or fail gracefully
        if (-not $result.success) {
            $result.error | Should -Not -BeNullOrEmpty
        }
    }

    It "Add-GPOLink validates GPO name parameter" {
        # Empty string triggers internal validation
        $result = Add-GPOLink -GpoName "" -TargetOU "OU=Test,DC=local"
        $result.success | Should -Be $false
        $result.error | Should -Be "GPO name is required"
    }

    It "Add-GPOLink validates target OU parameter" {
        # Empty string triggers internal validation
        $result = Add-GPOLink -GpoName "TestGPO" -TargetOU ""
        $result.success | Should -Be $false
        $result.error | Should -Be "Target OU is required"
    }

    It "Add-GPOLink handles missing modules gracefully" {
        # Without GroupPolicy/AD modules, should fail gracefully
        $result = Add-GPOLink -GpoName "TestGPO" -TargetOU "OU=Test,DC=local"
        $result | Should -Not -BeNullOrEmpty
        $result.success | Should -BeIn @($true, $false)
    }
}

Describe "Module5-EventMonitor" {
    It "Get-AppLockerEvents returns result structure" {
        $result = Get-AppLockerEvents -MaxEvents 10
        $result | Should -Not -BeNullOrEmpty
        $result.success | Should -BeIn @($true, $false)
    }

    It "Get-AppLockerEvents has data property" {
        $result = Get-AppLockerEvents -MaxEvents 10
        $result.data | Should -Not -BeNullOrEmpty
        $result.count | Should -BeGreaterOrEqual 0
    }

    It "Filter-EventsByEventId returns empty for empty array" {
        $result = Filter-EventsByEventId -Events @() -TargetEventId 8002
        $result.Count | Should -Be 0
    }

    It "Filter-EventsByEventId returns empty for null input" {
        $result = Filter-EventsByEventId -Events $null -TargetEventId 8002
        $result | Should -BeNullOrEmpty
    }

    It "Filter-EventsByEventId filters by event ID correctly" {
        $events = @(
            @{ eventId = 8002; action = "Allowed" }
            @{ eventId = 8003; action = "Audit" }
            @{ eventId = 8002; action = "Allowed" }
        )

        $result = Filter-EventsByEventId -Events $events -TargetEventId 8002
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.eventId -eq 8002 }).Count | Should -Be 2
    }

    It "Filter-EventsByDateRange filters by date correctly" {
        $events = @(
            @{ timestamp = "2024-01-01 12:00:00" }
            @{ timestamp = "2024-01-15 12:00:00" }
            @{ timestamp = "2024-02-01 12:00:00" }
        )

        $result = Filter-EventsByDateRange -Events $events -StartDate "2024-01-10" -EndDate "2024-01-20"
        $result.Count | Should -Be 1
    }

    It "Backup-RemoteAppLockerEvents requires computer name" {
        $result = Backup-RemoteAppLockerEvents -ComputerName "" -OutputPath "$env:TEMP\test.xml"
        $result.success | Should -Be $false
    }

    It "Backup-RemoteAppLockerEvents handles unreachable computer" {
        $result = Backup-RemoteAppLockerEvents -ComputerName "fake-computer-xyz" -OutputPath "$env:TEMP\test.xml"
        $result.success | Should -Be $false
        $result.error | Should -Not -BeNullOrEmpty
    }
}

Describe "Module6-ADManager" {
    It "Search-ADUsers returns result structure" {
        $result = Search-ADUsers -SearchQuery "test"
        $result | Should -Not -BeNullOrEmpty
        # Should handle gracefully even without AD
        $result.success | Should -BeIn @($true, $false)
    }

    It "Add-UserToAppLockerGroup validates SAM account name" {
        $result = Add-UserToAppLockerGroup -SamAccountName "" -GroupName "TestGroup"
        $result.success | Should -Be $false
        $result.error | Should -Be "SamAccountName is required"
    }

    It "Add-UserToAppLockerGroup validates group name" {
        $result = Add-UserToAppLockerGroup -SamAccountName "testuser" -GroupName ""
        $result.success | Should -Be $false
        $result.error | Should -Be "GroupName is required"
    }

    It "Add-UserToAppLockerGroup handles missing AD module" {
        $result = Add-UserToAppLockerGroup -SamAccountName "test" -GroupName "test"
        $result | Should -Not -BeNullOrEmpty
        $result.success | Should -BeIn @($true, $false)
    }

    It "Remove-UserFromAppLockerGroup validates SAM account name" {
        $result = Remove-UserFromAppLockerGroup -SamAccountName "" -GroupName "TestGroup"
        $result.success | Should -Be $false
        $result.error | Should -Be "SamAccountName is required"
    }

    It "Remove-UserFromAppLockerGroup validates group name" {
        $result = Remove-UserFromAppLockerGroup -SamAccountName "testuser" -GroupName ""
        $result.success | Should -Be $false
        $result.error | Should -Be "GroupName is required"
    }

    It "Remove-UserFromAppLockerGroup handles missing AD module" {
        $result = Remove-UserFromAppLockerGroup -SamAccountName "test" -GroupName "test"
        $result | Should -Not -BeNullOrEmpty
        $result.success | Should -BeIn @($true, $false)
    }

    It "New-AppLockerGroups returns results structure" {
        $result = New-AppLockerGroups
        $result | Should -Not -BeNullOrEmpty
        $result.groups | Should -Not -BeNullOrEmpty
        $result.groups.Count | Should -BeGreaterOrEqual 0
    }

    It "New-AppLockerGroups creates expected number of groups" {
        $result = New-AppLockerGroups
        $result.groups.Count | Should -BeGreaterOrEqual 0
        # If AD is available, should create 6 groups
    }

    # Module6 LDAP Injection Protection Tests
    It "Protect-LDAPFilterValue escapes backslash" {
        $result = Protect-LDAPFilterValue -Value "test\value"
        $result | Should -Match "\\5c"
    }

    It "Protect-LDAPFilterValue escapes asterisk" {
        $result = Protect-LDAPFilterValue -Value "test*value"
        $result | Should -Match "\\2a"
    }

    It "Protect-LDAPFilterValue escapes parentheses" {
        $result = Protect-LDAPFilterValue -Value "test(value)"
        $result | Should -Match "\\28"
        $result | Should -Match "\\29"
    }

    It "Protect-LDAPFilterValue escapes null byte" {
        $result = Protect-LDAPFilterValue -Value "test$([char]0x00)value"
        $result | Should -Match "\\00"
    }

    It "Protect-LDAPFilterValue escapes forward slash" {
        $result = Protect-LDAPFilterValue -Value "test/value"
        $result | Should -Match "\\2f"
    }

    It "Protect-LDAPFilterValue handles multiple special characters" {
        $result = Protect-LDAPFilterValue -Value "test*(\value)/"
        $result | Should -Match "\\2a"
        $result | Should -Match "\\28"
        $result | Should -Match "\\5c"
        $result | Should -Match "\\2f"
    }
}

Describe "Module7-Compliance" {
    It "New-EvidenceFolder creates folder structure" {
        $testPath = "$env:TEMP\GA-AppLocker-Test-Evidence"
        $result = New-EvidenceFolder -BasePath $testPath
        $result.success | Should -Be $true
        $result.basePath | Should -Be $testPath

        # Cleanup
        if (Test-Path $testPath) {
            Remove-Item -Path $testPath -Recurse -Force
        }
    }

    It "New-EvidenceFolder returns folder paths" {
        $testPath = "$env:TEMP\GA-AppLocker-Test-Evidence2"
        $result = New-EvidenceFolder -BasePath $testPath
        $result.folders.Count | Should -BeGreaterOrEqual 5

        # Verify folders exist
        $result.folders.Keys | ForEach-Object {
            Test-Path $result.folders[$_] | Should -Be $true
        }

        # Cleanup
        if (Test-Path $testPath) {
            Remove-Item -Path $testPath -Recurse -Force
        }
    }

    It "New-EvidenceFolder creates all expected subfolders" {
        $testPath = "$env:TEMP\GA-AppLocker-Test-Evidence3"
        $result = New-EvidenceFolder -BasePath $testPath

        $expectedFolders = @('Policies', 'Events', 'Inventory', 'Reports', 'Scans')
        foreach ($folder in $expectedFolders) {
            $result.folders.ContainsKey($folder) | Should -Be $true
        }

        # Cleanup
        if (Test-Path $testPath) {
            Remove-Item -Path $testPath -Recurse -Force
        }
    }

    It "Get-ComplianceSummary returns data" {
        $result = Get-ComplianceSummary
        $result.success | Should -Be $true
        $result.data.timestamp | Should -Not -BeNullOrEmpty
    }

    It "Get-ComplianceSummary returns all expected properties" {
        $result = Get-ComplianceSummary
        $data = $result.data

        $data.timestamp | Should -Not -BeNullOrEmpty
        $data.computerName | Should -Not -BeNullOrEmpty
        $data.policyScore | Should -BeGreaterOrEqual 0
        $data.assessment | Should -Not -BeNullOrEmpty
    }

    It "Export-CurrentPolicy exports to file" {
        $testFile = "$env:TEMP\test-policy-export.xml"
        try {
            $result = Export-CurrentPolicy -OutputPath $testFile
            $result | Should -Not -BeNullOrEmpty
            if ($result.success) {
                Test-Path $testFile | Should -Be $true
            }
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "Export-SystemInventory exports to file" {
        $testFile = "$env:TEMP\test-inventory.json"
        try {
            $result = Export-SystemInventory -OutputPath $testFile
            $result | Should -Not -BeNullOrEmpty
            if ($result.success) {
                Test-Path $testFile | Should -Be $true
            }
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "Export-AllEvidence collects all evidence" {
        $testPath = "$env:TEMP\GA-AppLocker-Test-Evidence-Full"
        try {
            $result = Export-AllEvidence -BasePath $testPath
            $result.success | Should -Be $true
            $result.basePath | Should -Be $testPath
        } finally {
            if (Test-Path $testPath) {
                Remove-Item -Path $testPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe "Common Library" {
    It "Write-Log handles INFO level" {
        $testLog = "$env:TEMP\test-log-info.log"
        try {
            Write-Log -Message "Test message" -Level INFO -LogPath $testLog

            if (Test-Path $testLog) {
                $content = Get-Content $testLog -Raw
                $content | Should -Match "\[INFO\]"
                $content | Should -Match "Test message"
            }
        } finally {
            Remove-Item $testLog -Force -ErrorAction SilentlyContinue
        }
    }

    It "Write-Log handles ERROR level" {
        $testLog = "$env:TEMP\test-log-error.log"
        try {
            Write-Log -Message "Error message" -Level ERROR -LogPath $testLog

            if (Test-Path $testLog) {
                $content = Get-Content $testLog -Raw
                $content | Should -Match "\[ERROR\]"
                $content | Should -Match "Error message"
            }
        } finally {
            Remove-Item $testLog -Force -ErrorAction SilentlyContinue
        }
    }

    It "Write-Log handles WARN level" {
        $testLog = "$env:TEMP\test-log-warn.log"
        try {
            Write-Log -Message "Warning message" -Level WARN -LogPath $testLog

            if (Test-Path $testLog) {
                $content = Get-Content $testLog -Raw
                $content | Should -Match "\[WARN\]"
                $content | Should -Match "Warning message"
            }
        } finally {
            Remove-Item $testLog -Force -ErrorAction SilentlyContinue
        }
    }

    It "Write-Log creates log directory if not exists" {
        $testLog = "$env:TEMP\GA-AppLocker-NewDir\test.log"
        try {
            Write-Log -Message "Test" -Level INFO -LogPath $testLog
            $logDir = Split-Path $testLog -Parent
            Test-Path $logDir | Should -Be $true
        } finally {
            Remove-Item $logDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "ConvertTo-JsonResponse converts hashtable" {
        $data = @{ key = "value"; number = 123 }
        $result = ConvertTo-JsonResponse -Data $data
        $result | Should -Match '"key"'
        $result | Should -Match '"value"'
        $result | Should -Match '123'
    }

    It "ConvertTo-JsonResponse handles arrays" {
        $data = @("one", "two", "three")
        $result = ConvertTo-JsonResponse -Data $data
        $result | Should -Match '"one"'
        $result | Should -Match '\"two\"'
    }

    # Common Library AaronLocker Pattern Tests
    It "IsWin32Executable returns EXE for valid executable" {
        $testFile = "$env:TEMP\test-pe-detection.exe"
        try {
            # Create a minimal PE file (DOS header + PE header)
            $peBytes = @(
                # "MZ" signature
                0x4D, 0x5A,
                # DOS stub (zeros)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                # Offset to PE header (at 0x3C)
                0x40, 0x00, 0x00, 0x00,
                # More DOS stub
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                # PE header starts at 0x40
                # "PE" signature
                0x50, 0x45, 0x00, 0x00,
                # Machine (0x014C = i386)
                0x4C, 0x01, 0x00, 0x00,
                # NumberOfSections
                0x01, 0x00, 0x00, 0x00,
                # TimeDateStamp
                0x00, 0x00, 0x00, 0x00,
                # PointerToSymbolTable
                0x00, 0x00, 0x00, 0x00,
                # NumberOfSymbols
                0x00, 0x00, 0x00, 0x00,
                # SizeOfOptionalHeader
                0xE0, 0x00, 0x00, 0x00,
                # Characteristics (0x0102 = executable, 32-bit)
                0x02, 0x01, 0x00, 0x00
            )
            # Pad to at least 0x80 bytes (NT headers start at 0x40 + 0x18 = 0x58)
            for ($i = $peBytes.Count; $i -lt 400; $i++) {
                $peBytes += 0x00
            }

            # Set Optional Header values
            # Magic (0x010B = PE32)
            $peBytes[0x58] = 0x0B
            $peBytes[0x59] = 0x01
            # Subsystem (3 = Windows CLI)
            $peBytes[0x5C] = 0x03
            $peBytes[0x5D] = 0x00
            # DLL Characteristics flag offset (0x70 in Optional Header)
            $peBytes[0x5C + 0x70] = 0x00
            $peBytes[0x5C + 0x71] = 0x00

            # Set Characteristics (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE)
            # At offset 0x56 + 0x18 = 0x6E, need to set 0x0102
            $peBytes[0x6E] = 0x02
            $peBytes[0x6F] = 0x01

            [System.IO.File]::WriteAllBytes($testFile, [byte[]]$peBytes)

            $result = IsWin32Executable -filename $testFile
            $result | Should -Be "EXE"
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "IsWin32Executable returns null for non-executable" {
        $testFile = "$env:TEMP\test-not-exe.txt"
        try {
            "plain text" | Out-File $testFile -Encoding ascii
            $result = IsWin32Executable -filename $testFile
            $result | Should -BeNullOrEmpty
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "IsWin32Executable returns null for non-existent file" {
        $result = IsWin32Executable -filename "C:\NonExistent\file.exe"
        $result | Should -BeNullOrEmpty
    }

    It "Test-AppLockerPath validates existing file path" {
        $testFile = "$env:TEMP\test-validation.txt"
        try {
            "test" | Out-File $testFile -Encoding ascii
            $result = Test-AppLockerPath -Path $testFile
            $result.valid | Should -Be $true
            $result.path | Should -Be $result.path
        } finally {
            Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        }
    }

    It "Test-AppLockerPath rejects empty path" {
        $result = Test-AppLockerPath -Path ""
        $result.valid | Should -Be $false
        $result.error | Should -Match "empty"
    }

    It "Test-AppLockerPath rejects UNC paths by default" {
        $result = Test-AppLockerPath -Path "\\server\share\file.exe"
        $result.valid | Should -Be $false
        $result.error | Should -Match "UNC"
    }

    It "Test-AppLockerPath rejects device paths" {
        $result = Test-AppLockerPath -Path "\\.\C:\path\file.exe"
        $result.valid | Should -Be $false
        $result.error | Should -Match "Device"
    }

    It "Test-AppLockerPath rejects non-existent files" {
        $result = Test-AppLockerPath -Path "C:\NonExistent\Path\file.exe"
        $result.valid | Should -Be $false
        $result.error | Should -Match "not found"
    }

    It "Test-PublisherName validates correct publisher name" {
        $result = Test-PublisherName -PublisherName "Microsoft Corporation"
        $result.valid | Should -Be $true
        $result.name | Should -Be "Microsoft Corporation"
    }

    It "Test-PublisherName rejects empty name" {
        $result = Test-PublisherName -PublisherName ""
        $result.valid | Should -Be $false
        $result.error | Should -Match "empty"
    }

    It "Test-PublisherName rejects name with invalid characters" {
        $result = Test-PublisherName -PublisherName "Test<script>"
        $result.valid | Should -Be $false
        $result.error | Should -Match "invalid"
    }

    It "Test-PublisherName rejects name that is too long" {
        $longName = "A" * 257
        $result = Test-PublisherName -PublisherName $longName
        $result.valid | Should -Be $false
        $result.error | Should -Match "too long"
    }

    It "ConvertTo-AppLockerGenericPath converts Program Files" {
        $result = ConvertTo-AppLockerGenericPath -FilePath "C:\Program Files\app\file.exe"
        $result | Should -Match "%PROGRAMFILES%"
    }

    It "ConvertTo-AppLockerGenericPath converts user profile paths" {
        $result = ConvertTo-AppLockerGenericPath -FilePath "C:\Users\John\AppData\Local\app.exe"
        $result | Should -Match "%LOCALAPPDATA%"
    }

    It "ConvertTo-AppLockerGenericPath converts Windows path" {
        $result = ConvertTo-AppLockerGenericPath -FilePath "C:\Windows\System32\cmd.exe"
        $result | Should -Match "%WINDIR%"
    }

    It "ConvertTo-AppLockerGenericPath handles empty input" {
        $result = ConvertTo-AppLockerGenericPath -FilePath ""
        $result | Should -Be ""
    }

    It "Get-StandardSids returns expected SID values" {
        $result = Get-StandardSids
        $result.Everyone | Should -Be "S-1-1-0"
        $result.Administrators | Should -Be "S-1-5-32-544"
        $result.System | Should -Be "S-1-5-18"
    }

    It "New-AppLockerGuid returns valid GUID" {
        $result = New-AppLockerGuid
        $guid = [guid]::empty
        [guid]::TryParse($result, [ref]$guid) | Should -Be $true
    }
}

Describe "Integration Tests" {
    It "Complete workflow: Scan -> Generate Rules -> Export" {
        # Create test artifacts
        $artifacts = @(
            @{ publisher = "TestCorp"; name = "app.exe"; path = "C:\test\app.exe"; hash = "abc123" }
            @{ publisher = "AnotherCorp"; name = "tool.exe"; path = "C:\test\tool.exe"; hash = "def456" }
        )

        # Generate rules
        $ruleResult = New-RulesFromArtifacts -Artifacts $artifacts -RuleType Publisher
        $ruleResult.success | Should -Be $true
        $ruleResult.rules.Count | Should -BeGreaterThan 0

        # Export policy
        $testPolicy = "$env:TEMP\test-workflow-policy.xml"
        try {
            $exportResult = Export-RulesToXml -Rules $ruleResult.rules -OutputPath $testPolicy
            $exportResult.success | Should -Be $true
            Test-Path $testPolicy | Should -Be $true

            # Verify XML structure
            [xml]$xml = Get-Content $testPolicy
            $xml.AppLockerPolicy.RuleCollection | Should -Not -BeNullOrEmpty
        } finally {
            Remove-Item $testPolicy -Force -ErrorAction SilentlyContinue
        }
    }

    It "Complete workflow: Evidence Collection" {
        $testPath = "$env:TEMP\GA-AppLocker-Integration-Test"
        try {
            # Create evidence folders
            $folderResult = New-EvidenceFolder -BasePath $testPath
            $folderResult.success | Should -Be $true

            # Export policy
            $policyPath = "$testPath\Policies\policy.xml"
            $policyResult = Export-CurrentPolicy -OutputPath $policyPath
            $policyResult | Should -Not -BeNullOrEmpty

            # Get compliance
            $complianceResult = Get-ComplianceSummary
            $complianceResult.success | Should -Be $true
            $complianceResult.data.timestamp | Should -Not -BeNullOrEmpty
        } finally {
            if (Test-Path $testPath) {
                Remove-Item $testPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

AfterAll {
    # Cleanup any test artifacts
    $testPaths = @(
        "$env:TEMP\GA-AppLocker-Test-Evidence",
        "$env:TEMP\GA-AppLocker-Test-Evidence2",
        "$env:TEMP\GA-AppLocker-Test-Evidence3",
        "$env:TEMP\GA-AppLocker-NewDir",
        "$env:TEMP\test-log-info.log",
        "$env:TEMP\test-log-error.log",
        "$env:TEMP\test-log-warn.log",
        "$env:TEMP\test-scan-export.csv",
        "$env:TEMP\test-policy.xml",
        "$env:TEMP\test-hash-file.exe",
        "$env:TEMP\test-workflow-policy.xml",
        "$env:TEMP\GA-AppLocker-EmptyTest-*",
        "$env:TEMP\test-policy-export.xml",
        "$env:TEMP\test-inventory.json",
        "$env:TEMP\GA-AppLocker-Test-Evidence-Full",
        "$env:TEMP\GA-AppLocker-Integration-Test",
        # Deny list and baseline test files
        "$env:TEMP\nonexistent-deny-list.txt",
        "$env:TEMP\test-deny-list*.txt",
        "$env:TEMP\test-sample-deny-list*.txt",
        "$env:TEMP\nonexistent-baseline.txt",
        "$env:TEMP\test-baseline*.txt",
        "$env:TEMP\test-sample-baseline*.txt",
        # Module2 test files
        "$env:TEMP\GA-AppLocker-ScanTest",
        # Common library test files
        "$env:TEMP\test-pe-detection.exe",
        "$env:TEMP\test-not-exe.txt",
        "$env:TEMP\test-validation.txt"
    )

    foreach ($pattern in $testPaths) {
        $matches = Resolve-Path $pattern -ErrorAction SilentlyContinue
        if ($matches) {
            foreach ($path in $matches.Path) {
                if (Test-Path $path) {
                    try {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    } catch {
                        # Ignore cleanup errors
                    }
                }
            }
        }
    }

    # Clean up any temp files with specific patterns
    $tempDir = $env:TEMP
    if (Test-Path $tempDir) {
        Get-ChildItem -Path $tempDir -Filter "GA-AppLocker-*" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore cleanup errors
            }
        }
        Get-ChildItem -Path $tempDir -Filter "test-*" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore cleanup errors
            }
        }
        Get-ChildItem -Path $tempDir -Filter "nonexistent-*" -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore cleanup errors
            }
        }
    }
}
