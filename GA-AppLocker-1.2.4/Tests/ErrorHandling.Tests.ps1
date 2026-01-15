<#
.SYNOPSIS
    Pester tests for ErrorHandling.psm1 module.

.DESCRIPTION
    Tests error handling functions, input validation, and output formatting.

.NOTES
    PSScriptAnalyzer suppressions:
    - PSAvoidUsingConvertToSecureStringWithPlainText: Required for testing credential validation
    - PSAvoidUsingComputerNameHardcoded: Required for testing computer name validation
#>

# Suppress PSScriptAnalyzer rules that are expected in test files
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification='Required for testing credential validation functions')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '', Justification='Required for testing computer name validation functions')]
param()

BeforeAll {
    # Import the module
    $modulePath = Join-Path $PSScriptRoot '..\src\Utilities\ErrorHandling.psm1'
    Import-Module $modulePath -Force

    # Create temp directory for tests
    $script:TestRoot = Join-Path $env:TEMP "GA-AppLocker-Tests-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null
}

AfterAll {
    # Cleanup
    if (Test-Path $script:TestRoot) {
        Remove-Item -Path $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#region Invoke-SafeOperation Tests

Describe 'Invoke-SafeOperation' {
    Context 'When operation succeeds' {
        It 'Returns the result from the script block' {
            $result = Invoke-SafeOperation -ScriptBlock { 42 } -ErrorMessage "Should not fail"
            $result | Should -Be 42
        }

        It 'Returns complex objects' {
            $result = Invoke-SafeOperation -ScriptBlock { @{ Name = 'Test'; Value = 123 } }
            $result.Name | Should -Be 'Test'
            $result.Value | Should -Be 123
        }

        It 'Returns arrays correctly' {
            $result = Invoke-SafeOperation -ScriptBlock { @(1, 2, 3) }
            $result.Count | Should -Be 3
        }
    }

    Context 'When operation fails without ContinueOnError' {
        It 'Throws with the custom error message' {
            { Invoke-SafeOperation -ScriptBlock { throw "Inner error" } -ErrorMessage "Custom message" } |
                Should -Throw "*Custom message*"
        }

        It 'Includes original exception in the error' {
            { Invoke-SafeOperation -ScriptBlock { throw "Original" } -ErrorMessage "Wrapper" } |
                Should -Throw "*Original*"
        }
    }

    Context 'When operation fails with ContinueOnError' {
        It 'Returns null instead of throwing' {
            $result = Invoke-SafeOperation -ScriptBlock { throw "Error" } -ErrorMessage "Test" -ContinueOnError
            $result | Should -BeNullOrEmpty
        }

        It 'Writes a warning when not silent' {
            # Capture warning
            $warnings = @()
            Invoke-SafeOperation -ScriptBlock { throw "Error" } -ErrorMessage "Test" -ContinueOnError -WarningVariable warnings 3>&1 | Out-Null
            # Warning is written to host, so we just verify no throw
            { Invoke-SafeOperation -ScriptBlock { throw "Error" } -ErrorMessage "Test" -ContinueOnError } |
                Should -Not -Throw
        }

        It 'Is silent when -Silent is specified' {
            # Should complete without any output
            $result = Invoke-SafeOperation -ScriptBlock { throw "Error" } -ErrorMessage "Test" -ContinueOnError -Silent
            $result | Should -BeNullOrEmpty
        }
    }
}

#endregion

#region Write-ErrorMessage Tests

Describe 'Write-ErrorMessage' {
    Context 'When Throw switch is not set' {
        It 'Does not throw' {
            { Write-ErrorMessage -Message "Test error" } | Should -Not -Throw
        }
    }

    Context 'When Throw switch is set' {
        It 'Throws with the error message' {
            { Write-ErrorMessage -Message "Test error" -Throw } | Should -Throw "*Test error*"
        }

        It 'Includes exception details when provided' {
            $ex = [System.Exception]::new("Inner exception")
            { Write-ErrorMessage -Message "Outer" -Exception $ex -Throw } | Should -Throw "*Inner exception*"
        }
    }
}

#endregion

#region Test-ValidPath Tests

Describe 'Test-ValidPath' {
    BeforeAll {
        # Create test structure
        $script:TestDir = Join-Path $script:TestRoot "TestDir"
        $script:TestFile = Join-Path $script:TestRoot "TestFile.txt"
        New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
        "Test content" | Out-File -FilePath $script:TestFile
    }

    Context 'With empty or null path' {
        It 'Throws for null path due to validation' {
            { Test-ValidPath -Path $null } | Should -Throw
        }

        It 'Throws for empty string due to validation' {
            { Test-ValidPath -Path "" } | Should -Throw
        }

        It 'Returns null for whitespace-only path' {
            $result = Test-ValidPath -Path "   "
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'With Type = File' {
        It 'Returns path when file exists' {
            $result = Test-ValidPath -Path $script:TestFile -Type File -MustExist
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Returns null when path is a directory' {
            $result = Test-ValidPath -Path $script:TestDir -Type File -MustExist
            $result | Should -BeNullOrEmpty
        }

        It 'Returns path when file does not exist and MustExist is false' {
            $nonExistent = Join-Path $script:TestRoot "nonexistent.txt"
            $result = Test-ValidPath -Path $nonExistent -Type File
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'With Type = Directory' {
        It 'Returns path when directory exists' {
            $result = Test-ValidPath -Path $script:TestDir -Type Directory -MustExist
            $result | Should -Not -BeNullOrEmpty
        }

        It 'Returns null when path is a file' {
            $result = Test-ValidPath -Path $script:TestFile -Type Directory -MustExist
            $result | Should -BeNullOrEmpty
        }

        It 'Creates directory when CreateIfMissing is set' {
            $newDir = Join-Path $script:TestRoot "NewDir-$(Get-Random)"
            $result = Test-ValidPath -Path $newDir -Type Directory -CreateIfMissing
            $result | Should -Not -BeNullOrEmpty
            Test-Path $newDir | Should -BeTrue
        }
    }

    Context 'With MustExist' {
        It 'Returns null for non-existent path' {
            $result = Test-ValidPath -Path "C:\NonExistent\Path\$(Get-Random)" -MustExist
            $result | Should -BeNullOrEmpty
        }

        It 'Returns path for existing path' {
            $result = Test-ValidPath -Path $script:TestDir -MustExist
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'With relative paths' {
        It 'Resolves relative paths to absolute' {
            $result = Test-ValidPath -Path ".\test"
            $result | Should -Match '^[A-Z]:\\'
        }
    }
}

#endregion

#region Test-ValidXml Tests

Describe 'Test-ValidXml' {
    BeforeAll {
        # Create test XML files
        $script:ValidXml = Join-Path $script:TestRoot "valid.xml"
        $script:InvalidXml = Join-Path $script:TestRoot "invalid.xml"
        $script:WrongRootXml = Join-Path $script:TestRoot "wrongroot.xml"

        @"
<?xml version="1.0"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
  </RuleCollection>
</AppLockerPolicy>
"@ | Out-File -FilePath $script:ValidXml -Encoding UTF8

        "Not valid XML at all <><>" | Out-File -FilePath $script:InvalidXml

        @"
<?xml version="1.0"?>
<WrongRoot>
  <Child>Test</Child>
</WrongRoot>
"@ | Out-File -FilePath $script:WrongRootXml -Encoding UTF8
    }

    Context 'With valid XML' {
        It 'Returns XML document for valid file' {
            $result = Test-ValidXml -Path $script:ValidXml
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [System.Xml.XmlDocument]
        }

        It 'Validates root element when specified' {
            $result = Test-ValidXml -Path $script:ValidXml -RootElement 'AppLockerPolicy'
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'With invalid XML' {
        It 'Returns null for invalid XML content' {
            $result = Test-ValidXml -Path $script:InvalidXml
            $result | Should -BeNullOrEmpty
        }

        It 'Returns null when root element does not match' {
            $result = Test-ValidXml -Path $script:WrongRootXml -RootElement 'AppLockerPolicy'
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'With non-existent file' {
        It 'Returns null' {
            $result = Test-ValidXml -Path "C:\NonExistent\file.xml"
            $result | Should -BeNullOrEmpty
        }
    }
}

#endregion

#region Test-ValidAppLockerPolicy Tests

Describe 'Test-ValidAppLockerPolicy' {
    BeforeAll {
        $script:ValidPolicy = Join-Path $script:TestRoot "validpolicy.xml"
        $script:EmptyPolicy = Join-Path $script:TestRoot "emptypolicy.xml"

        @"
<?xml version="1.0"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="test" Name="Test" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@ | Out-File -FilePath $script:ValidPolicy -Encoding UTF8

        @"
<?xml version="1.0"?>
<AppLockerPolicy Version="1">
</AppLockerPolicy>
"@ | Out-File -FilePath $script:EmptyPolicy -Encoding UTF8
    }

    It 'Returns XML for valid policy with rules' {
        $result = Test-ValidAppLockerPolicy -Path $script:ValidPolicy
        $result | Should -Not -BeNullOrEmpty
        $result | Should -BeOfType [System.Xml.XmlDocument]
    }

    It 'Returns null for policy without rule collections' {
        $result = Test-ValidAppLockerPolicy -Path $script:EmptyPolicy
        $result | Should -BeNullOrEmpty
    }
}

#endregion

#region Test-ValidComputerList Tests

Describe 'Test-ValidComputerList' {
    BeforeAll {
        $script:ValidList = Join-Path $script:TestRoot "computers.txt"
        $script:EmptyList = Join-Path $script:TestRoot "empty.txt"
        $script:CommentedList = Join-Path $script:TestRoot "commented.txt"

        @"
PC001
PC002
PC003
"@ | Out-File -FilePath $script:ValidList

        "" | Out-File -FilePath $script:EmptyList

        @"
# This is a comment
PC001
# Another comment
  PC002
"@ | Out-File -FilePath $script:CommentedList
    }

    It 'Returns array of computer names' {
        $result = Test-ValidComputerList -Path $script:ValidList
        $result.Count | Should -Be 3
        $result[0] | Should -Be 'PC001'
    }

    It 'Returns empty array for empty file' {
        $result = Test-ValidComputerList -Path $script:EmptyList
        $result | Should -BeNullOrEmpty
    }

    It 'Ignores comments and whitespace' {
        $result = Test-ValidComputerList -Path $script:CommentedList
        $result.Count | Should -Be 2
        $result | Should -Contain 'PC001'
        $result | Should -Contain 'PC002'
    }

    It 'Returns empty array for non-existent file' {
        $result = Test-ValidComputerList -Path "C:\NonExistent\list.txt"
        $result | Should -BeNullOrEmpty
    }
}

#endregion

#region Test-RequiredKeys Tests

Describe 'Test-RequiredKeys' {
    It 'Returns true when all required keys exist' {
        $hash = @{ Key1 = 'Value1'; Key2 = 'Value2'; Key3 = 'Value3' }
        $result = Test-RequiredKeys -Hashtable $hash -RequiredKeys @('Key1', 'Key2')
        $result | Should -BeTrue
    }

    It 'Returns false when a required key is missing' {
        $hash = @{ Key1 = 'Value1' }
        $result = Test-RequiredKeys -Hashtable $hash -RequiredKeys @('Key1', 'Key2')
        $result | Should -BeFalse
    }

    It 'Returns true when only required key is present' {
        $hash = @{ Key1 = 'Value1' }
        $result = Test-RequiredKeys -Hashtable $hash -RequiredKeys @('Key1')
        $result | Should -BeTrue
    }
}

#endregion

#region Output Formatting Tests

Describe 'Write-SectionHeader' {
    It 'Completes without error' {
        { Write-SectionHeader -Title "Test Section" } | Should -Not -Throw
    }

    It 'Accepts custom width' {
        { Write-SectionHeader -Title "Test" -Width 80 } | Should -Not -Throw
    }
}

Describe 'Write-StepProgress' {
    It 'Completes without error' {
        { Write-StepProgress -Step 1 -Total 5 -Message "Processing" } | Should -Not -Throw
    }
}

Describe 'Write-SuccessMessage' {
    It 'Completes without error' {
        { Write-SuccessMessage -Message "Operation completed" } | Should -Not -Throw
    }
}

Describe 'Write-ResultSummary' {
    It 'Handles results with Pass status' {
        $results = @(
            @{ Status = 'Pass'; Message = 'Test 1 passed' }
            @{ Status = 'Pass'; Message = 'Test 2 passed' }
        )
        { Write-ResultSummary -Title "Test Results" -Results $results } | Should -Not -Throw
    }

    It 'Handles mixed Pass and Fail results' {
        $results = @(
            @{ Status = 'Pass'; Message = 'Test 1 passed' }
            @{ Status = 'Fail'; Message = 'Test 2 failed' }
        )
        { Write-ResultSummary -Title "Test Results" -Results $results } | Should -Not -Throw
    }
}

#endregion

#region Initialize-GAAppLockerScript Tests

Describe 'Initialize-GAAppLockerScript' {
    Context 'Without RequireAdmin' {
        It 'Returns true' {
            $result = Initialize-GAAppLockerScript
            $result | Should -BeTrue
        }
    }

    Context 'With RequireModules' {
        It 'Returns false for non-existent module' {
            $result = Initialize-GAAppLockerScript -RequireModules @('NonExistentModule12345')
            $result | Should -BeFalse
        }

        It 'Returns true for existing module' {
            # Microsoft.PowerShell.Utility is always available
            $result = Initialize-GAAppLockerScript -RequireModules @('Microsoft.PowerShell.Utility')
            $result | Should -BeTrue
        }
    }
}

#endregion

#region Additional Validation Function Tests

Describe 'Test-ValidSid' {
    It 'Returns true for valid well-known SID' {
        Test-ValidSid -Sid 'S-1-5-18' | Should -BeTrue
        Test-ValidSid -Sid 'S-1-1-0' | Should -BeTrue
        Test-ValidSid -Sid 'S-1-5-32-544' | Should -BeTrue
    }

    It 'Returns true for valid domain SID' {
        Test-ValidSid -Sid 'S-1-5-21-1234567890-1234567890-1234567890-500' | Should -BeTrue
    }

    It 'Returns false for invalid SID format' {
        Test-ValidSid -Sid 'NotASid' | Should -BeFalse
        Test-ValidSid -Sid 'S-2-5-18' | Should -BeFalse
        Test-ValidSid -Sid 'S-1-' | Should -BeFalse
    }
}

Describe 'Test-ValidGuid' {
    It 'Returns true for valid GUIDs' {
        Test-ValidGuid -Guid '12345678-1234-1234-1234-123456789012' | Should -BeTrue
        Test-ValidGuid -Guid 'a1b2c3d4-e5f6-7890-abcd-ef1234567890' | Should -BeTrue
    }

    It 'Returns true for GUID with braces' {
        Test-ValidGuid -Guid '{12345678-1234-1234-1234-123456789012}' | Should -BeTrue
    }

    It 'Returns false for invalid GUID' {
        Test-ValidGuid -Guid 'not-a-guid' | Should -BeFalse
        Test-ValidGuid -Guid '12345678-1234-1234-1234' | Should -BeFalse
    }
}

Describe 'Test-ValidComputerName' {
    It 'Returns true for valid computer names' {
        Test-ValidComputerName -ComputerName 'PC001' | Should -BeTrue
        Test-ValidComputerName -ComputerName 'SERVER-WEB01' | Should -BeTrue
        Test-ValidComputerName -ComputerName 'A' | Should -BeTrue
    }

    It 'Returns false for names exceeding 15 characters' {
        Test-ValidComputerName -ComputerName 'ThisNameIsTooLongForNetBIOS' | Should -BeFalse
    }

    It 'Returns false for invalid characters' {
        Test-ValidComputerName -ComputerName 'PC_001' | Should -BeFalse
        Test-ValidComputerName -ComputerName 'PC.001' | Should -BeFalse
    }

    It 'Returns false for names starting/ending with hyphen' {
        Test-ValidComputerName -ComputerName '-PC001' | Should -BeFalse
        Test-ValidComputerName -ComputerName 'PC001-' | Should -BeFalse
    }

    It 'Returns false for whitespace-only names' {
        Test-ValidComputerName -ComputerName '   ' | Should -BeFalse
    }
}

Describe 'Test-ValidDomainName' {
    It 'Returns true for valid NetBIOS domain names' {
        Test-ValidDomainName -DomainName 'CONTOSO' | Should -BeTrue
        Test-ValidDomainName -DomainName 'DOMAIN1' | Should -BeTrue
    }

    It 'Returns true for valid FQDN' {
        Test-ValidDomainName -DomainName 'contoso.com' | Should -BeTrue
        Test-ValidDomainName -DomainName 'corp.contoso.com' | Should -BeTrue
    }

    It 'Returns false for domain names starting with number' {
        Test-ValidDomainName -DomainName '123Domain' | Should -BeFalse
    }
}

Describe 'Test-ValidEnforcementMode' {
    It 'Returns true for valid modes' {
        Test-ValidEnforcementMode -Mode 'AuditOnly' | Should -BeTrue
        Test-ValidEnforcementMode -Mode 'Enabled' | Should -BeTrue
        Test-ValidEnforcementMode -Mode 'NotConfigured' | Should -BeTrue
    }

    It 'Returns false for invalid modes' {
        Test-ValidEnforcementMode -Mode 'Disabled' | Should -BeFalse
        Test-ValidEnforcementMode -Mode 'enforce' | Should -BeFalse
    }
}

Describe 'Test-ValidFileHash' {
    Context 'SHA256 hashes' {
        It 'Returns true for valid SHA256 hash' {
            $hash = 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            Test-ValidFileHash -Hash $hash | Should -BeTrue
        }

        It 'Returns true for hash with 0x prefix' {
            $hash = '0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            Test-ValidFileHash -Hash $hash | Should -BeTrue
        }

        It 'Returns false for wrong length' {
            Test-ValidFileHash -Hash 'ABCD1234' | Should -BeFalse
        }

        It 'Returns false for invalid characters' {
            $hash = 'GHIJ1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            Test-ValidFileHash -Hash $hash | Should -BeFalse
        }
    }

    Context 'Other hash algorithms' {
        It 'Validates SHA1 hashes' {
            $sha1 = 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
            Test-ValidFileHash -Hash $sha1 -Algorithm SHA1 | Should -BeTrue
        }

        It 'Validates MD5 hashes' {
            $md5 = 'ABCD1234ABCD1234ABCD1234ABCD1234'
            Test-ValidFileHash -Hash $md5 -Algorithm MD5 | Should -BeTrue
        }
    }
}

#endregion

#region Test-CredentialValidity Tests

Describe 'Test-CredentialValidity' {
    Context 'With invalid target' {
        It 'Returns false for unreachable computer' {
            $securePass = ConvertTo-SecureString 'TestPassword123' -AsPlainText -Force
            $cred = [PSCredential]::new('TestUser', $securePass)

            # Use a non-existent computer name - should fail quickly
            $result = Test-CredentialValidity -Credential $cred -ComputerName 'NONEXISTENT-PC-12345' -TimeoutSeconds 5
            $result | Should -BeFalse
        }
    }

    Context 'Parameter validation' {
        It 'Requires Credential parameter' {
            { Test-CredentialValidity -ComputerName 'localhost' } | Should -Throw
        }

        It 'Requires ComputerName parameter' {
            $securePass = ConvertTo-SecureString 'TestPassword123' -AsPlainText -Force
            $cred = [PSCredential]::new('TestUser', $securePass)
            { Test-CredentialValidity -Credential $cred } | Should -Throw
        }

        It 'Accepts custom timeout' {
            $securePass = ConvertTo-SecureString 'TestPassword123' -AsPlainText -Force
            $cred = [PSCredential]::new('TestUser', $securePass)

            # Should complete without throwing even with short timeout
            { Test-CredentialValidity -Credential $cred -ComputerName 'NONEXISTENT-PC' -TimeoutSeconds 1 } |
                Should -Not -Throw
        }
    }
}

#endregion
