# GA-AppLocker.Tests.ps1
# Simplified Pester tests for GA-AppLocker Dashboard
# Designed to run quickly in CI without hanging

BeforeAll {
    # Set timeout flag - skip tests that might hang
    $script:SkipSlowTests = $true

    # Get paths
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:SrcPath = Join-Path $script:ProjectRoot "src"
    $script:BuildPath = Join-Path $script:ProjectRoot "build"
    $script:ModulesPath = Join-Path $script:SrcPath "modules"
    $script:LibPath = Join-Path $script:SrcPath "lib"
}

Describe "Project Structure" {
    It "Has src directory" {
        Test-Path $script:SrcPath | Should -Be $true
    }

    It "Has build directory" {
        Test-Path $script:BuildPath | Should -Be $true
    }

    It "Has modules directory" {
        Test-Path $script:ModulesPath | Should -Be $true
    }

    It "Has lib directory" {
        Test-Path $script:LibPath | Should -Be $true
    }
}

Describe "Module Files Exist" {
    It "Common.psm1 exists" {
        Test-Path (Join-Path $script:LibPath "Common.psm1") | Should -Be $true
    }

    It "Config.psm1 exists" {
        Test-Path (Join-Path $script:SrcPath "Config.psm1") | Should -Be $true
    }

    It "Module1-Dashboard.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module1-Dashboard.psm1") | Should -Be $true
    }

    It "Module2-RemoteScan.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module2-RemoteScan.psm1") | Should -Be $true
    }

    It "Module3-RuleGenerator.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") | Should -Be $true
    }

    It "Module4-PolicyLab.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module4-PolicyLab.psm1") | Should -Be $true
    }

    It "Module5-EventMonitor.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module5-EventMonitor.psm1") | Should -Be $true
    }

    It "Module6-ADManager.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module6-ADManager.psm1") | Should -Be $true
    }

    It "Module7-Compliance.psm1 exists" {
        Test-Path (Join-Path $script:ModulesPath "Module7-Compliance.psm1") | Should -Be $true
    }
}

Describe "GUI Script" {
    It "GA-AppLocker-GUI-WPF.ps1 exists" {
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        Test-Path $guiPath | Should -Be $true
    }

    It "GUI script has valid PowerShell syntax" {
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "GUI script contains required WPF assemblies" {
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $content = Get-Content $guiPath -Raw
        $content | Should -Match "PresentationFramework"
        $content | Should -Match "PresentationCore"
    }

    It "GUI script contains XAML definition" {
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $content = Get-Content $guiPath -Raw
        $content | Should -Match '\$xamlString'
        $content | Should -Match '<Window'
    }
}

Describe "Module Syntax Validation" {
    It "Common.psm1 has valid syntax" {
        $path = Join-Path $script:LibPath "Common.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Config.psm1 has valid syntax" {
        $path = Join-Path $script:SrcPath "Config.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module1-Dashboard.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module1-Dashboard.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module2-RemoteScan.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module2-RemoteScan.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module3-RuleGenerator.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module4-PolicyLab.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module4-PolicyLab.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module5-EventMonitor.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module5-EventMonitor.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module6-ADManager.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module6-ADManager.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Module7-Compliance.psm1 has valid syntax" {
        $path = Join-Path $script:ModulesPath "Module7-Compliance.psm1"
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }
}

Describe "Function Definitions" {
    BeforeAll {
        # Parse GUI script to find function definitions
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $script:GuiContent = Get-Content $guiPath -Raw
    }

    It "Defines Initialize-AppLockerFolders function" {
        $script:GuiContent | Should -Match "function Initialize-AppLockerFolders"
    }

    It "Defines Get-DomainInfo function" {
        $script:GuiContent | Should -Match "function Get-DomainInfo"
    }

    It "Defines New-PublisherRule function" {
        $script:GuiContent | Should -Match "function New-PublisherRule"
    }

    It "Defines New-HashRule function" {
        $script:GuiContent | Should -Match "function New-HashRule"
    }

    It "Defines New-RulesFromArtifacts function" {
        $script:GuiContent | Should -Match "function New-RulesFromArtifacts"
    }

    It "Defines Write-Log function" {
        $script:GuiContent | Should -Match "function Write-Log"
    }
}

Describe "XAML Structure" {
    BeforeAll {
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $script:GuiContent = Get-Content $guiPath -Raw
    }

    It "Contains Window element" {
        $script:GuiContent | Should -Match '<Window'
    }

    It "Contains navigation buttons" {
        $script:GuiContent | Should -Match 'NavDashboard'
        $script:GuiContent | Should -Match 'NavRules'
        $script:GuiContent | Should -Match 'NavEvents'
    }

    It "Contains main panels" {
        $script:GuiContent | Should -Match 'PanelDashboard'
        $script:GuiContent | Should -Match 'PanelRules'
        $script:GuiContent | Should -Match 'PanelEvents'
    }

    It "Does not contain backticks in XAML Text attributes" {
        # Extract XAML section
        if ($script:GuiContent -match '\$xamlString = @"([\s\S]*?)"@') {
            $xaml = $Matches[1]
            # Check for backticks in Text attributes
            $xaml | Should -Not -Match 'Text="[^"]*`[^"]*"'
        }
    }
}

Describe "Security Features" {
    BeforeAll {
        $guiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $script:GuiContent = Get-Content $guiPath -Raw
    }

    It "Uses proper error handling" {
        $script:GuiContent | Should -Match 'try\s*{'
        $script:GuiContent | Should -Match 'catch\s*{'
    }

    It "Has rule action options (Allow/Deny)" {
        $script:GuiContent | Should -Match 'RuleActionAllow'
        $script:GuiContent | Should -Match 'RuleActionDeny'
    }

    It "Has group selection for rules" {
        $script:GuiContent | Should -Match 'RuleGroupCombo'
        $script:GuiContent | Should -Match 'UserOrGroupSid'
    }
}

AfterAll {
    # No cleanup needed for syntax-only tests
}
