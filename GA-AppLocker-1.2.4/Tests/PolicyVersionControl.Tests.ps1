<#
.SYNOPSIS
    Pester tests for PolicyVersionControl.psm1 module.

.DESCRIPTION
    Tests Git-like version control functionality for AppLocker policies.
#>

BeforeAll {
    # Import the module
    $modulePath = Join-Path $PSScriptRoot '..\src\Utilities\PolicyVersionControl.psm1'
    Import-Module $modulePath -Force

    # Create temp directory for tests
    $script:TestRoot = Join-Path $env:TEMP "GA-AppLocker-VersionControl-Tests-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null

    # Load fixtures path
    $script:FixturesPath = Join-Path $PSScriptRoot 'Fixtures'
}

AfterAll {
    # Cleanup
    if (Test-Path $script:TestRoot) {
        Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Initialize-PolicyRepository' {
    BeforeEach {
        $script:RepoPath = Join-Path $script:TestRoot "Repo-$(Get-Random)"
    }

    AfterEach {
        if (Test-Path $script:RepoPath) {
            Remove-Item -Path $script:RepoPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Creates repository directory structure' {
        Initialize-PolicyRepository -Path $script:RepoPath

        Test-Path $script:RepoPath | Should -BeTrue
        Test-Path (Join-Path $script:RepoPath 'versions') | Should -BeTrue
        Test-Path (Join-Path $script:RepoPath 'branches') | Should -BeTrue
        Test-Path (Join-Path $script:RepoPath 'branches\main') | Should -BeTrue
        Test-Path (Join-Path $script:RepoPath 'staging') | Should -BeTrue
        Test-Path (Join-Path $script:RepoPath 'archive') | Should -BeTrue
    }

    It 'Creates repository.json metadata file' {
        Initialize-PolicyRepository -Path $script:RepoPath

        $metaPath = Join-Path $script:RepoPath 'repository.json'
        Test-Path $metaPath | Should -BeTrue

        $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
        $meta.CurrentBranch | Should -Be 'main'
        $meta.DefaultBranch | Should -Be 'main'
        $meta.VersionCount | Should -Be 0
    }

    It 'Returns the repository path' {
        $result = Initialize-PolicyRepository -Path $script:RepoPath
        $result | Should -Be $script:RepoPath
    }
}

Describe 'Set-PolicyRepository' {
    BeforeAll {
        $script:TestRepo = Join-Path $script:TestRoot "SetRepoTest-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:TestRepo
    }

    AfterAll {
        if (Test-Path $script:TestRepo) {
            Remove-Item -Path $script:TestRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Sets the repository path without error' {
        { Set-PolicyRepository -Path $script:TestRepo } | Should -Not -Throw
    }

    It 'Throws for non-existent repository' {
        { Set-PolicyRepository -Path 'C:\NonExistent\Repo' } | Should -Throw
    }

    It 'Throws for path without repository.json' {
        $emptyDir = Join-Path $script:TestRoot "EmptyDir-$(Get-Random)"
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null

        { Set-PolicyRepository -Path $emptyDir } | Should -Throw
    }
}

Describe 'Save-PolicyVersion' {
    BeforeAll {
        $script:VersionRepo = Join-Path $script:TestRoot "VersionRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:VersionRepo
        Set-PolicyRepository -Path $script:VersionRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'
    }

    AfterAll {
        if (Test-Path $script:VersionRepo) {
            Remove-Item -Path $script:VersionRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Saves a policy version with message' {
        $result = Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Initial commit"

        $result | Should -Not -BeNullOrEmpty
        $result.VersionId | Should -Not -BeNullOrEmpty
        $result.Message | Should -Be "Initial commit"
    }

    It 'Creates version folder with policy.xml' {
        $result = Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Test version"

        $versionPath = Join-Path $script:VersionRepo "versions\$($result.VersionId)"
        Test-Path $versionPath | Should -BeTrue
        Test-Path (Join-Path $versionPath 'policy.xml') | Should -BeTrue
        Test-Path (Join-Path $versionPath 'version.json') | Should -BeTrue
    }

    It 'Includes author in metadata' {
        $result = Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Author test" -Author "TestUser"

        $result.Author | Should -Be "TestUser"
    }

    It 'Includes tags in metadata' {
        $result = Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Tags test" -Tags @('production', 'v1.0')

        $result.Tags | Should -Contain 'production'
        $result.Tags | Should -Contain 'v1.0'
    }

    It 'Throws without repository set' {
        # Create new PS session context by re-importing module
        Remove-Module PolicyVersionControl -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $PSScriptRoot '..\src\Utilities\PolicyVersionControl.psm1') -Force

        { Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Test" } | Should -Throw "*No repository*"

        # Reset repo
        Set-PolicyRepository -Path $script:VersionRepo
    }
}

Describe 'Get-PolicyHistory' {
    BeforeAll {
        $script:HistoryRepo = Join-Path $script:TestRoot "HistoryRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:HistoryRepo
        Set-PolicyRepository -Path $script:HistoryRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'

        # Create some versions
        Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Version 1"
        Start-Sleep -Milliseconds 100
        Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Version 2"
        Start-Sleep -Milliseconds 100
        Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Version 3"
    }

    AfterAll {
        if (Test-Path $script:HistoryRepo) {
            Remove-Item -Path $script:HistoryRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Returns version history' {
        $history = Get-PolicyHistory
        $history | Should -Not -BeNullOrEmpty
        $history.Count | Should -BeGreaterOrEqual 3
    }

    It 'Returns history sorted by timestamp descending' {
        $history = Get-PolicyHistory
        $history[0].Timestamp | Should -BeGreaterThan $history[1].Timestamp
    }

    It 'Limits results with -Limit parameter' {
        $history = Get-PolicyHistory -Limit 2
        $history.Count | Should -Be 2
    }

    It 'Returns versions with expected properties' {
        $history = Get-PolicyHistory -Limit 1
        $history[0].PSObject.Properties.Name | Should -Contain 'VersionId'
        $history[0].PSObject.Properties.Name | Should -Contain 'Message'
        $history[0].PSObject.Properties.Name | Should -Contain 'Author'
        $history[0].PSObject.Properties.Name | Should -Contain 'Timestamp'
    }
}

Describe 'Get-PolicyVersion' {
    BeforeAll {
        $script:GetRepo = Join-Path $script:TestRoot "GetRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:GetRepo
        Set-PolicyRepository -Path $script:GetRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'
        $script:SavedVersion = Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Test version"
    }

    AfterAll {
        if (Test-Path $script:GetRepo) {
            Remove-Item -Path $script:GetRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Retrieves a specific version' {
        $result = Get-PolicyVersion -VersionId $script:SavedVersion.VersionId
        $result | Should -Not -BeNullOrEmpty
        $result.Metadata.VersionId | Should -Be $script:SavedVersion.VersionId
    }

    It 'Returns policy XML content' {
        $result = Get-PolicyVersion -VersionId $script:SavedVersion.VersionId
        $result.PolicyXml | Should -Not -BeNullOrEmpty
        $result.PolicyXml | Should -Match 'AppLockerPolicy'
    }

    It 'Exports to file with OutputPath' {
        $outputFile = Join-Path $script:TestRoot "exported-$(Get-Random).xml"
        Get-PolicyVersion -VersionId $script:SavedVersion.VersionId -OutputPath $outputFile

        Test-Path $outputFile | Should -BeTrue
        (Get-Content $outputFile -Raw) | Should -Match 'AppLockerPolicy'
    }

    It 'Throws for non-existent version' {
        { Get-PolicyVersion -VersionId 'nonexistent-version-id' } | Should -Throw "*not found*"
    }
}

Describe 'New-PolicyBranch' {
    BeforeAll {
        $script:BranchRepo = Join-Path $script:TestRoot "BranchRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:BranchRepo
        Set-PolicyRepository -Path $script:BranchRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'
        Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Main branch version"
    }

    AfterAll {
        if (Test-Path $script:BranchRepo) {
            Remove-Item -Path $script:BranchRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Creates a new branch' {
        $branchName = "test-branch-$(Get-Random)"
        $result = New-PolicyBranch -Name $branchName

        $result | Should -Be $branchName
        $branchPath = Join-Path $script:BranchRepo "branches\$branchName"
        Test-Path $branchPath | Should -BeTrue
    }

    It 'Throws for duplicate branch name' {
        $branchName = "duplicate-$(Get-Random)"
        New-PolicyBranch -Name $branchName

        { New-PolicyBranch -Name $branchName } | Should -Throw "*already exists*"
    }
}

Describe 'Switch-PolicyBranch' {
    BeforeAll {
        $script:SwitchRepo = Join-Path $script:TestRoot "SwitchRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:SwitchRepo
        Set-PolicyRepository -Path $script:SwitchRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'
        Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Main version"
        New-PolicyBranch -Name 'feature-branch'
    }

    AfterAll {
        if (Test-Path $script:SwitchRepo) {
            Remove-Item -Path $script:SwitchRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Switches to existing branch' {
        { Switch-PolicyBranch -Name 'feature-branch' } | Should -Not -Throw
    }

    It 'Throws for non-existent branch' {
        { Switch-PolicyBranch -Name 'nonexistent-branch' } | Should -Throw "*not found*"
    }
}

Describe 'Get-PolicyBranches' {
    BeforeAll {
        $script:ListRepo = Join-Path $script:TestRoot "ListRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:ListRepo
        Set-PolicyRepository -Path $script:ListRepo

        New-PolicyBranch -Name 'branch-a'
        New-PolicyBranch -Name 'branch-b'
    }

    AfterAll {
        if (Test-Path $script:ListRepo) {
            Remove-Item -Path $script:ListRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Lists all branches' {
        $branches = Get-PolicyBranches
        $branches | Should -Not -BeNullOrEmpty
        ($branches | Where-Object { $_.Name -eq 'main' }) | Should -Not -BeNullOrEmpty
        ($branches | Where-Object { $_.Name -eq 'branch-a' }) | Should -Not -BeNullOrEmpty
        ($branches | Where-Object { $_.Name -eq 'branch-b' }) | Should -Not -BeNullOrEmpty
    }

    It 'Marks current branch' {
        $branches = Get-PolicyBranches
        $currentBranch = $branches | Where-Object { $_.IsCurrent -eq $true }
        $currentBranch | Should -Not -BeNullOrEmpty
    }
}

Describe 'Restore-PolicyVersion' {
    BeforeAll {
        $script:RestoreRepo = Join-Path $script:TestRoot "RestoreRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:RestoreRepo
        Set-PolicyRepository -Path $script:RestoreRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'
        $script:OriginalVersion = Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Original version"
    }

    AfterAll {
        if (Test-Path $script:RestoreRepo) {
            Remove-Item -Path $script:RestoreRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Restores a previous version' {
        $outputPath = Join-Path $script:TestRoot "restored-$(Get-Random).xml"

        $result = Restore-PolicyVersion -VersionId $script:OriginalVersion.VersionId -OutputPath $outputPath

        Test-Path $outputPath | Should -BeTrue
        $result | Should -Not -BeNullOrEmpty
    }

    It 'Creates a new version for the restore' {
        $outputPath = Join-Path $script:TestRoot "restored2-$(Get-Random).xml"
        $beforeCount = (Get-PolicyHistory).Count

        Restore-PolicyVersion -VersionId $script:OriginalVersion.VersionId -OutputPath $outputPath

        $afterCount = (Get-PolicyHistory).Count
        $afterCount | Should -BeGreaterThan $beforeCount
    }
}

Describe 'Show-PolicyLog' {
    BeforeAll {
        $script:LogRepo = Join-Path $script:TestRoot "LogRepo-$(Get-Random)"
        Initialize-PolicyRepository -Path $script:LogRepo
        Set-PolicyRepository -Path $script:LogRepo

        $script:TestPolicy = Join-Path $script:FixturesPath 'SamplePolicy1.xml'
        Save-PolicyVersion -PolicyPath $script:TestPolicy -Message "Log test version"
    }

    AfterAll {
        if (Test-Path $script:LogRepo) {
            Remove-Item -Path $script:LogRepo -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Runs without error' {
        { Show-PolicyLog -Limit 5 } | Should -Not -Throw
    }
}
