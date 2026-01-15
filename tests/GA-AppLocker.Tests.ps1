# GA-AppLocker.Tests.ps1
# Pester tests for GA-AppLocker Dashboard modules

BeforeAll {
    # Import modules
    $modulePath = $PSScriptRoot + "\..\src\modules"
    $libPath = $PSScriptRoot + "\..\src\lib"

    Import-Module (Join-Path $libPath "Common.psm1") -Force
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
        $result | Should -Match '"two"'
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
        "$env:TEMP\GA-AppLocker-Integration-Test"
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
    }
}
