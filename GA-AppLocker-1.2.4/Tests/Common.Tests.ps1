<#
.SYNOPSIS
    Pester tests for Common.psm1 utility functions.

.DESCRIPTION
    Tests SID resolution, XML generation, and configuration functions.
#>

BeforeAll {
    # Import the module
    $modulePath = Join-Path $PSScriptRoot '..\src\Utilities\Common.psm1'
    Import-Module $modulePath -Force
}

Describe 'Resolve-AccountToSid' {
    Context 'When given a SID string' {
        It 'Returns the SID unchanged' {
            $sid = 'S-1-5-18'
            $result = Resolve-AccountToSid -Name $sid
            $result | Should -Be $sid
        }

        It 'Handles complex SIDs' {
            $sid = 'S-1-5-21-1234567890-1234567890-1234567890-500'
            $result = Resolve-AccountToSid -Name $sid
            $result | Should -Be $sid
        }
    }

    Context 'When given well-known account names' {
        It 'Resolves SYSTEM correctly' {
            $result = Resolve-AccountToSid -Name 'NT AUTHORITY\SYSTEM'
            $result | Should -Be 'S-1-5-18'
        }

        It 'Resolves Everyone correctly' {
            $result = Resolve-AccountToSid -Name 'Everyone'
            $result | Should -Be 'S-1-1-0'
        }
    }
}

Describe 'Resolve-AccountsToSids' {
    It 'Returns a hashtable with all resolved SIDs' {
        $names = @('S-1-5-18', 'Everyone')
        $result = Resolve-AccountsToSids -Names $names

        $result | Should -BeOfType [hashtable]
        $result.Keys.Count | Should -Be 2
        $result['S-1-5-18'] | Should -Be 'S-1-5-18'
        $result['Everyone'] | Should -Be 'S-1-1-0'
    }
}

Describe 'New-PathConditionXml' {
    It 'Creates valid path condition XML' {
        $result = New-PathConditionXml -Path 'C:\Windows\*'
        $result | Should -Match 'FilePathCondition'
        $result | Should -Match 'Path="C:\\Windows\\\*"'
    }

    It 'Handles paths with special characters' {
        $result = New-PathConditionXml -Path '%PROGRAMFILES%\*'
        $result | Should -Match '%PROGRAMFILES%'
    }
}

Describe 'New-PublisherConditionXml' {
    It 'Creates valid publisher condition with defaults' {
        $result = New-PublisherConditionXml -Publisher 'O=MICROSOFT CORPORATION'

        $result | Should -Match 'FilePublisherCondition'
        $result | Should -Match 'PublisherName="O=MICROSOFT CORPORATION"'
        $result | Should -Match 'ProductName="\*"'
        $result | Should -Match 'BinaryName="\*"'
    }

    It 'Creates publisher condition with specific product' {
        $result = New-PublisherConditionXml -Publisher 'O=MICROSOFT' -Product 'Windows' -Binary 'notepad.exe'

        $result | Should -Match 'ProductName="Windows"'
        $result | Should -Match 'BinaryName="notepad.exe"'
    }

    It 'Escapes special XML characters in publisher name' {
        $result = New-PublisherConditionXml -Publisher 'O=TEST & COMPANY <INC>'

        $result | Should -Match '&amp;'
        $result | Should -Match '&lt;'
        $result | Should -Match '&gt;'
    }
}

Describe 'New-HashConditionXml' {
    It 'Creates valid hash condition XML' {
        $hash = 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'
        $result = New-HashConditionXml -Hash $hash -FileName 'test.exe' -FileSize 1024

        $result | Should -Match 'FileHashCondition'
        $result | Should -Match 'Type="SHA256"'
        $result | Should -Match "Data=`"0x$hash`""
        $result | Should -Match 'SourceFileName="test.exe"'
        $result | Should -Match 'SourceFileLength="1024"'
    }

    It 'Supports custom hash types' {
        $result = New-HashConditionXml -Hash 'ABC123' -FileName 'test.exe' -FileSize 512 -HashType 'SHA1'

        $result | Should -Match 'Type="SHA1"'
    }
}

Describe 'New-AppLockerRuleXml' {
    It 'Creates valid FilePathRule XML' {
        $condition = New-PathConditionXml -Path 'C:\Test\*'
        $result = New-AppLockerRuleXml -Type 'FilePathRule' -Name 'Test Rule' -Sid 'S-1-1-0' -Action 'Allow' -Condition $condition

        $result | Should -Match '<FilePathRule'
        $result | Should -Match 'Name="Test Rule"'
        $result | Should -Match 'UserOrGroupSid="S-1-1-0"'
        $result | Should -Match 'Action="Allow"'
        $result | Should -Match '<Conditions>'
    }

    It 'Creates valid Deny rule' {
        $condition = New-PathConditionXml -Path 'C:\Temp\*'
        $result = New-AppLockerRuleXml -Type 'FilePathRule' -Name 'Deny Temp' -Sid 'S-1-1-0' -Action 'Deny' -Condition $condition

        $result | Should -Match 'Action="Deny"'
    }

    It 'Escapes special characters in rule name' {
        $condition = New-PathConditionXml -Path 'C:\Test\*'
        $result = New-AppLockerRuleXml -Type 'FilePathRule' -Name 'Test & Rule <1>' -Sid 'S-1-1-0' -Action 'Allow' -Condition $condition

        $result | Should -Match 'Test &amp; Rule &lt;1&gt;'
    }

    It 'Generates unique GUIDs' {
        $condition = New-PathConditionXml -Path 'C:\Test\*'
        $result1 = New-AppLockerRuleXml -Type 'FilePathRule' -Name 'Rule 1' -Sid 'S-1-1-0' -Action 'Allow' -Condition $condition
        $result2 = New-AppLockerRuleXml -Type 'FilePathRule' -Name 'Rule 2' -Sid 'S-1-1-0' -Action 'Allow' -Condition $condition

        # Extract GUIDs
        $guid1 = [regex]::Match($result1, 'Id="([^"]+)"').Groups[1].Value
        $guid2 = [regex]::Match($result2, 'Id="([^"]+)"').Groups[1].Value

        $guid1 | Should -Not -Be $guid2
    }
}

Describe 'New-PolicyHeaderXml' {
    It 'Creates valid policy header' {
        $result = New-PolicyHeaderXml

        $result | Should -Match '<\?xml version="1.0"'
        $result | Should -Match '<AppLockerPolicy Version="1">'
    }

    It 'Includes metadata in comments' {
        $result = New-PolicyHeaderXml -TargetType 'Workstation' -Phase '1' -Comment 'Test policy'

        $result | Should -Match 'Target: Workstation'
        $result | Should -Match 'Phase: 1'
        $result | Should -Match 'Test policy'
    }
}

Describe 'New-RuleCollectionXml' {
    It 'Creates valid Exe rule collection' {
        $result = New-RuleCollectionXml -Type 'Exe' -EnforcementMode 'AuditOnly'

        $result | Should -Match '<RuleCollection Type="Exe"'
        $result | Should -Match 'EnforcementMode="AuditOnly"'
    }

    It 'Creates enabled rule collection' {
        $result = New-RuleCollectionXml -Type 'Script' -EnforcementMode 'Enabled'

        $result | Should -Match 'Type="Script"'
        $result | Should -Match 'EnforcementMode="Enabled"'
    }

    It 'Includes rules in collection' {
        $rule = '<FilePathRule Id="test" Name="Test" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions></Conditions></FilePathRule>'
        $result = New-RuleCollectionXml -Type 'Exe' -EnforcementMode 'AuditOnly' -Rules $rule

        $result | Should -Match 'FilePathRule'
    }
}

Describe 'Get-AppLockerConfig' {
    It 'Returns a hashtable' {
        $result = Get-AppLockerConfig
        $result | Should -BeOfType [hashtable]
    }

    It 'Contains expected configuration sections' {
        $result = Get-AppLockerConfig

        $result.Keys | Should -Contain 'WellKnownSids'
        $result.Keys | Should -Contain 'LOLBins'
        $result.Keys | Should -Contain 'DefaultDenyPaths'
    }

    It 'Has well-known SIDs defined' {
        $result = Get-AppLockerConfig

        $result.WellKnownSids | Should -Not -BeNullOrEmpty
        $result.WellKnownSids['Everyone'] | Should -Be 'S-1-1-0'
    }
}

Describe 'Get-PublisherRuleKey' {
    Context 'With Publisher granularity' {
        It 'Returns publisher as key with wildcards for product and binary' {
            $result = Get-PublisherRuleKey -Publisher 'Microsoft' -Granularity 'Publisher'

            $result.Key | Should -Be 'Microsoft'
            $result.Publisher | Should -Be 'Microsoft'
            $result.Product | Should -Be '*'
            $result.Binary | Should -Be '*'
        }
    }

    Context 'With PublisherProduct granularity' {
        It 'Returns combined key with wildcard for binary' {
            $result = Get-PublisherRuleKey -Publisher 'Microsoft' -Product 'Office' -Granularity 'PublisherProduct'

            $result.Key | Should -Be 'Microsoft|Office'
            $result.Publisher | Should -Be 'Microsoft'
            $result.Product | Should -Be 'Office'
            $result.Binary | Should -Be '*'
        }
    }

    Context 'With PublisherProductBinary granularity' {
        It 'Returns fully qualified key' {
            $result = Get-PublisherRuleKey -Publisher 'Microsoft' -Product 'Office' -Binary 'excel.exe' -Granularity 'PublisherProductBinary'

            $result.Key | Should -Be 'Microsoft|Office|excel.exe'
            $result.Publisher | Should -Be 'Microsoft'
            $result.Product | Should -Be 'Office'
            $result.Binary | Should -Be 'excel.exe'
        }
    }
}

Describe 'Add-PublisherRule' {
    BeforeEach {
        $script:Rules = @{}
    }

    It 'Adds new rule and returns true' {
        $result = Add-PublisherRule -Rules $script:Rules -Publisher 'Microsoft' -Granularity 'Publisher'

        $result | Should -BeTrue
        $script:Rules.Count | Should -Be 1
        $script:Rules['Microsoft'].Publisher | Should -Be 'Microsoft'
    }

    It 'Returns false for duplicate rule' {
        Add-PublisherRule -Rules $script:Rules -Publisher 'Microsoft' -Granularity 'Publisher'
        $result = Add-PublisherRule -Rules $script:Rules -Publisher 'Microsoft' -Granularity 'Publisher'

        $result | Should -BeFalse
        $script:Rules.Count | Should -Be 1
    }

    It 'Includes source when specified' {
        Add-PublisherRule -Rules $script:Rules -Publisher 'Adobe' -Granularity 'Publisher' -Source 'ScanData'

        $script:Rules['Adobe'].Source | Should -Be 'ScanData'
    }

    It 'Handles different granularities correctly' {
        # Same publisher but different granularity should create different keys
        Add-PublisherRule -Rules $script:Rules -Publisher 'Microsoft' -Product 'Office' -Binary 'word.exe' -Granularity 'PublisherProductBinary'
        Add-PublisherRule -Rules $script:Rules -Publisher 'Microsoft' -Product 'Office' -Binary 'excel.exe' -Granularity 'PublisherProductBinary'

        $script:Rules.Count | Should -Be 2
    }
}
