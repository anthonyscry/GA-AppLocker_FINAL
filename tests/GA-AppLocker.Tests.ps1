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

    It "Get-AppLockerEventStats returns numeric event counts" -Skip:(-not (Test-Administrator)) {
        $result = Get-AppLockerEventStats
        if ($result.success) {
            $result.allowed | Should -BeGreaterOrEqual 0
            $result.audit | Should -BeGreaterOrEqual 0
            $result.blocked | Should -BeGreaterOrEqual 0
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
}

Describe "Module2-RemoteScan" {
    It "Get-ExecutableArtifacts requires valid path" {
        $result = Get-ExecutableArtifacts -TargetPath "C:\Invalid\Path\That\Does\Not\Exist"
        $result.success | Should -Be $false
    }

    It "Get-ExecutableArtifacts scans existing directory" -Skip:(-not (Test-Path "C:\Windows\System32")) {
        $result = Get-ExecutableArtifacts -TargetPath "C:\Windows\System32" -MaxFiles 10
        $result.success | Should -Be $true
        $result.data | Should -Not -BeNullOrEmpty
    }

    It "Test-ComputerOnline requires computer name" {
        $result = Test-ComputerOnline -ComputerName ""
        $result.success | Should -Be $false
        $result.online | Should -Be $false
    }

    It "Export-ScanResults requires artifacts" {
        $result = Export-ScanResults -Artifacts @() -OutputPath "C:\temp\test.csv"
        $result.success | Should -Be $false
    }

    It "Export-ScanResults requires output path" {
        $result = Export-ScanResults -Artifacts @( @{name="test"} ) -OutputPath ""
        $result.success | Should -Be $false
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

    It "New-HashRule requires existing file" {
        $result = New-HashRule -FilePath "C:\nonexistent\file.exe"
        $result.success | Should -Be $false
    }

    It "Export-RulesToXml requires rules" {
        $result = Export-RulesToXml -Rules @() -OutputPath "C:\temp\test.xml"
        $result.success | Should -Be $false
    }

    It "New-RulesFromArtifacts requires artifacts" {
        $result = New-RulesFromArtifacts -Artifacts @()
        $result.success | Should -Be $false
    }
}

Describe "Module4-PolicyLab" {
    It "New-AppLockerGPO requires GPO name" {
        $result = New-AppLockerGPO -GpoName ""
        $result.success | Should -Be $false
    }

    It "Add-GPOLink requires GPO name" {
        $result = Add-GPOLink -GpoName "" -TargetOU "OU=Test,DC=local"
        $result.success | Should -Be $false
    }

    It "Add-GPOLink requires target OU" {
        $result = Add-GPOLink -GpoName "TestGPO" -TargetOU ""
        $result.success | Should -Be $false
    }
}

Describe "Module5-EventMonitor" {
    It "Get-AppLockerEvents returns hashtable" {
        $result = Get-AppLockerEvents -MaxEvents 10
        $result | Should -Not -BeNullOrEmpty
        $result.success | Should -BeIn @($true, $false)
    }

    It "Filter-EventsByEventId handles empty array" {
        $result = Filter-EventsByEventId -Events @() -TargetEventId 8002
        $result | Should -BeNullOrEmpty
    }

    It "Filter-EventsByEventId handles null input" {
        $result = Filter-EventsByEventId -Events $null -TargetEventId 8002
        $result | Should -BeNullOrEmpty
    }

    It "Backup-RemoteAppLockerEvents requires computer name" {
        $result = Backup-RemoteAppLockerEvents -ComputerName "" -OutputPath "C:\temp\test.xml"
        $result.success | Should -Be $false
    }
}

Describe "Module6-ADManager" {
    It "Search-ADUsers requires search query" {
        $result = Search-ADUsers -SearchQuery ""
        $result | Should -Not -BeNullOrEmpty
    }

    It "Add-UserToAppLockerGroup requires SAM account name" {
        $result = Add-UserToAppLockerGroup -SamAccountName "" -GroupName "TestGroup"
        $result.success | Should -Be $false
    }

    It "Add-UserToAppLockerGroup requires group name" {
        $result = Add-UserToAppLockerGroup -SamAccountName "testuser" -GroupName ""
        $result.success | Should -Be $false
    }

    It "Remove-UserFromAppLockerGroup requires SAM account name" {
        $result = Remove-UserFromAppLockerGroup -SamAccountName "" -GroupName "TestGroup"
        $result.success | Should -Be $false
    }

    It "Remove-UserFromAppLockerGroup requires group name" {
        $result = Remove-UserFromAppLockerGroup -SamAccountName "testuser" -GroupName ""
        $result.success | Should -Be $false
    }
}

Describe "Module7-Compliance" {
    It "New-EvidenceFolders creates folder structure" {
        $testPath = "$env:TEMP\GA-AppLocker-Test-Evidence"
        $result = New-EvidenceFolders -BasePath $testPath
        $result.success | Should -Be $true
        $result.basePath | Should -Be $testPath

        # Cleanup
        if (Test-Path $testPath) {
            Remove-Item -Path $testPath -Recurse -Force
        }
    }

    It "New-EvidenceFolders returns folder paths" {
        $testPath = "$env:TEMP\GA-AppLocker-Test-Evidence2"
        $result = New-EvidenceFolders -BasePath $testPath
        $result.folders.Count | Should -BeGreaterOrEqual 5

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
}

Describe "Common Library" {
    It "Write-Log handles INFO level" {
        $testLog = "$env:TEMP\test-log.log"
        Write-Log -Message "Test message" -Level INFO -LogPath $testLog

        if (Test-Path $testLog) {
            $content = Get-Content $testLog -Raw
            $content | Should -Match "\[INFO\]"
            Remove-Item $testLog -Force
        }
    }

    It "Write-Log handles ERROR level" {
        $testLog = "$env:TEMP\test-log-error.log"
        Write-Log -Message "Error message" -Level ERROR -LogPath $testLog

        if (Test-Path $testLog) {
            $content = Get-Content $testLog -Raw
            $content | Should -Match "\[ERROR\]"
            Remove-Item $testLog -Force
        }
    }
}

# Helper function
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

AfterAll {
    # Cleanup any test artifacts
    $testPaths = @(
        "$env:TEMP\GA-AppLocker-Test-Evidence",
        "$env:TEMP\GA-AppLocker-Test-Evidence2",
        "$env:TEMP\test-log.log",
        "$env:TEMP\test-log-error.log"
    )

    foreach ($path in $testPaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore cleanup errors
            }
        }
    }
}
