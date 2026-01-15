<#
.SYNOPSIS
    Pester tests for Manage-SoftwareLists.ps1.

.DESCRIPTION
    Tests software list management functions including creation, loading,
    saving, and item management.
#>

BeforeAll {
    # Import the script to get access to functions
    $scriptPath = Join-Path $PSScriptRoot '..\src\Utilities\Manage-SoftwareLists.ps1'
    . $scriptPath

    # Create temp output directory for tests
    $script:tempListsPath = Join-Path $TestDrive 'SoftwareLists'
    New-Item -ItemType Directory -Path $script:tempListsPath -Force | Out-Null
}

Describe 'CommonPublishers Variable' {
    It 'Contains Microsoft publisher' {
        $Script:CommonPublishers | Should -Not -BeNullOrEmpty
        $Script:CommonPublishers.ContainsKey('Microsoft') | Should -Be $true
    }

    It 'Contains Adobe publisher' {
        $Script:CommonPublishers.ContainsKey('Adobe') | Should -Be $true
    }

    It 'Contains Google publisher' {
        $Script:CommonPublishers.ContainsKey('Google') | Should -Be $true
    }

    It 'Contains security vendors' {
        $Script:CommonPublishers.ContainsKey('CrowdStrike') | Should -Be $true
        $Script:CommonPublishers.ContainsKey('Symantec') | Should -Be $true
    }

    It 'Has required properties for each publisher' {
        $msft = $Script:CommonPublishers['Microsoft']
        $msft.Publisher | Should -Not -BeNullOrEmpty
        $msft.Category | Should -Not -BeNullOrEmpty
        $msft.Description | Should -Not -BeNullOrEmpty
    }

    It 'Has expected categories' {
        $categories = $Script:CommonPublishers.Values | ForEach-Object { $_.Category } | Sort-Object -Unique

        $categories | Should -Contain 'Microsoft'
        $categories | Should -Contain 'Security'
        $categories | Should -Contain 'Development'
    }
}

Describe 'New-SoftwareList' {
    Context 'Creating new lists' {
        It 'Creates a new software list file' {
            $listName = "TestList-$(Get-Random)"
            $result = New-SoftwareList -Name $listName -OutputPath $script:tempListsPath

            $result | Should -Not -BeNullOrEmpty
            Test-Path $result | Should -Be $true
        }

        It 'Creates valid JSON structure' {
            $listName = "JsonTest-$(Get-Random)"
            $result = New-SoftwareList -Name $listName -Description "Test description" -OutputPath $script:tempListsPath

            { Get-Content -Path $result -Raw | ConvertFrom-Json } | Should -Not -Throw

            $content = Get-Content -Path $result -Raw | ConvertFrom-Json
            $content.metadata | Should -Not -BeNullOrEmpty
            $content.metadata.name | Should -Be $listName
            $content.metadata.description | Should -Be "Test description"
            # Items should be an array (can be empty for a new list)
            $null -ne $content.items | Should -Be $true
        }

        It 'Sets created and modified timestamps' {
            $listName = "TimestampTest-$(Get-Random)"
            $result = New-SoftwareList -Name $listName -OutputPath $script:tempListsPath

            $content = Get-Content -Path $result -Raw | ConvertFrom-Json
            $content.metadata.created | Should -Not -BeNullOrEmpty
            $content.metadata.modified | Should -Not -BeNullOrEmpty

            # Validate ISO 8601 format
            { [DateTime]::Parse($content.metadata.created) } | Should -Not -Throw
        }

        It 'Returns existing list path if list already exists' {
            $listName = "ExistingTest-$(Get-Random)"
            $firstResult = New-SoftwareList -Name $listName -OutputPath $script:tempListsPath
            $secondResult = New-SoftwareList -Name $listName -OutputPath $script:tempListsPath

            $secondResult | Should -Be $firstResult
        }

        It 'Sanitizes invalid characters in name' {
            $listName = "Test:Invalid/Name"
            $result = New-SoftwareList -Name $listName -OutputPath $script:tempListsPath

            # Should create file with sanitized name
            $result | Should -Not -BeNullOrEmpty
            # Check the filename (not full path) doesn't contain invalid chars
            $fileName = [System.IO.Path]::GetFileName($result)
            $fileName | Should -Not -Match ':'
            $fileName | Should -Not -Match '/'
            $fileName | Should -Match 'Test_Invalid_Name'
        }
    }

    Context 'Error handling' {
        It 'Creates output directory if it does not exist' {
            $newPath = Join-Path $TestDrive "NewDir-$(Get-Random)"
            $listName = "DirTest-$(Get-Random)"

            $result = New-SoftwareList -Name $listName -OutputPath $newPath

            Test-Path $newPath | Should -Be $true
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-SoftwareList' {
    BeforeAll {
        # Create a test list file
        $script:testListPath = Join-Path $script:tempListsPath 'GetTestList.json'
        $testList = @{
            metadata = @{
                name = 'GetTestList'
                description = 'Test list for Get-SoftwareList tests'
                created = (Get-Date).ToString("o")
                modified = (Get-Date).ToString("o")
                version = '1.0'
            }
            items = @(
                @{
                    id = [Guid]::NewGuid().ToString()
                    name = 'Test Software'
                    publisher = 'O=TEST CORP'
                    ruleType = 'Publisher'
                }
            )
        }
        $testList | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:testListPath -Encoding UTF8
    }

    Context 'Loading lists' {
        It 'Loads an existing software list' {
            $result = Get-SoftwareList -ListPath $script:testListPath

            $result | Should -Not -BeNullOrEmpty
            $result.metadata.name | Should -Be 'GetTestList'
        }

        It 'Returns items array' {
            $result = Get-SoftwareList -ListPath $script:testListPath

            $result.items | Should -Not -BeNullOrEmpty
            $result.items.Count | Should -Be 1
            $result.items[0].name | Should -Be 'Test Software'
        }

        It 'Returns null for non-existent file' {
            $badPath = Join-Path $TestDrive 'NonExistent.json'
            $result = Get-SoftwareList -ListPath $badPath

            $result | Should -BeNullOrEmpty
        }

        It 'Creates list when CreateIfNotExists is specified' {
            $newListPath = Join-Path $script:tempListsPath "AutoCreate-$(Get-Random).json"
            $result = Get-SoftwareList -ListPath $newListPath -CreateIfNotExists

            $result | Should -Not -BeNullOrEmpty
            Test-Path $newListPath | Should -Be $true
        }
    }

    Context 'Invalid file handling' {
        It 'Handles empty file gracefully' {
            $emptyPath = Join-Path $script:tempListsPath 'EmptyFile.json'
            '' | Out-File -FilePath $emptyPath -Encoding UTF8

            $result = Get-SoftwareList -ListPath $emptyPath

            $result | Should -BeNullOrEmpty
        }

        It 'Handles malformed JSON gracefully' {
            $badJsonPath = Join-Path $script:tempListsPath 'BadJson.json'
            'not valid json {{{' | Out-File -FilePath $badJsonPath -Encoding UTF8

            $result = Get-SoftwareList -ListPath $badJsonPath

            $result | Should -BeNullOrEmpty
        }
    }
}

Describe 'Save-SoftwareList' {
    Context 'Saving lists' {
        It 'Saves a software list to file' {
            $savePath = Join-Path $script:tempListsPath "SaveTest-$(Get-Random).json"
            $list = @{
                metadata = @{
                    name = 'SaveTest'
                    version = '1.0'
                }
                items = @()
            }

            $result = Save-SoftwareList -List $list -ListPath $savePath

            $result | Should -Be $true
            Test-Path $savePath | Should -Be $true
        }

        It 'Updates modified timestamp on save' {
            $savePath = Join-Path $script:tempListsPath "TimestampSave-$(Get-Random).json"
            $list = @{
                metadata = @{
                    name = 'TimestampTest'
                    modified = '2020-01-01T00:00:00'
                }
                items = @()
            }

            Save-SoftwareList -List $list -ListPath $savePath

            $saved = Get-Content -Path $savePath -Raw | ConvertFrom-Json
            $saved.metadata.modified | Should -Not -Be '2020-01-01T00:00:00'
        }

        It 'Creates backup when requested' {
            $savePath = Join-Path $script:tempListsPath "BackupTest-$(Get-Random).json"
            $list = @{ metadata = @{ name = 'Original' }; items = @() }

            # Create initial file
            Save-SoftwareList -List $list -ListPath $savePath

            # Save with backup
            $list.metadata.name = 'Updated'
            Save-SoftwareList -List $list -ListPath $savePath -CreateBackup

            # Check backup exists
            Test-Path "$savePath.bak" | Should -Be $true
        }

        It 'Returns false or throws when saving null list' {
            $savePath = Join-Path $script:tempListsPath "NullTest.json"

            # Passing null to the function should either:
            # 1. Return $false (function handles null gracefully)
            # 2. Throw a parameter validation error (also acceptable)
            $result = $null
            $threw = $false
            try {
                $result = Save-SoftwareList -List $null -ListPath $savePath 2>$null 3>$null
            }
            catch {
                $threw = $true
            }

            # Either it returned false or threw - both indicate proper null handling
            ($result -eq $false -or $threw) | Should -Be $true
        }
    }
}

Describe 'Software List Integration' {
    Context 'Full workflow' {
        It 'Creates, loads, and saves a list successfully' {
            $listName = "IntegrationTest-$(Get-Random)"

            # Create
            $createResult = New-SoftwareList -Name $listName -Description "Integration test" -OutputPath $script:tempListsPath
            $createResult | Should -Not -BeNullOrEmpty

            # Load
            $loadResult = Get-SoftwareList -ListPath $createResult
            $loadResult | Should -Not -BeNullOrEmpty
            $loadResult.metadata.name | Should -Be $listName

            # Modify and save
            $loadResult.metadata.description = "Modified description"
            $saveResult = Save-SoftwareList -List $loadResult -ListPath $createResult
            $saveResult | Should -Be $true

            # Verify modification persisted
            $reloadResult = Get-SoftwareList -ListPath $createResult
            $reloadResult.metadata.description | Should -Be "Modified description"
        }
    }
}

Describe 'Test Fixture Loading' {
    BeforeAll {
        $script:fixtureListPath = Join-Path $PSScriptRoot 'Fixtures\SampleSoftwareList.json'
    }

    It 'Loads the test fixture software list' {
        if (Test-Path $script:fixtureListPath) {
            $result = Get-SoftwareList -ListPath $script:fixtureListPath

            $result | Should -Not -BeNullOrEmpty
            $result.metadata.name | Should -Be 'TestSoftwareList'
        }
    }

    It 'Fixture contains expected item types' {
        if (Test-Path $script:fixtureListPath) {
            $result = Get-SoftwareList -ListPath $script:fixtureListPath

            $itemTypes = $result.items | ForEach-Object { $_.ruleType }
            $itemTypes | Should -Contain 'Publisher'
            $itemTypes | Should -Contain 'Path'
            $itemTypes | Should -Contain 'Hash'
        }
    }
}
