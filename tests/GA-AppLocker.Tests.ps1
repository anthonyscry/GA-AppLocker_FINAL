# GA-AppLocker.Tests.ps1
# Comprehensive Pester tests for GA-AppLocker Dashboard
# Covers: Structure, Syntax, Functions, Edge Cases, Security, Input Validation

BeforeAll {
    # Test configuration
    $script:SkipSlowTests = $true
    $script:SkipNetworkTests = $true

    # Get paths
    $script:ProjectRoot = Split-Path $PSScriptRoot -Parent
    $script:SrcPath = Join-Path $script:ProjectRoot "src"
    $script:BuildPath = Join-Path $script:ProjectRoot "build"
    $script:ModulesPath = Join-Path $script:SrcPath "modules"
    $script:LibPath = Join-Path $script:SrcPath "lib"
}

# =============================================================================
# PROJECT STRUCTURE TESTS
# =============================================================================
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

    It "Has tests directory" {
        Test-Path $PSScriptRoot | Should -Be $true
    }
}

# =============================================================================
# MODULE FILES EXISTENCE TESTS
# =============================================================================
Describe "Module Files Exist" {
    It "Common.psm1 exists" {
        Test-Path (Join-Path $script:LibPath "Common.psm1") | Should -Be $true
    }

    It "Config.psm1 exists" {
        Test-Path (Join-Path $script:SrcPath "Config.psm1") | Should -Be $true
    }

    $modules = @(
        "Module1-Dashboard",
        "Module2-RemoteScan",
        "Module3-RuleGenerator",
        "Module4-PolicyLab",
        "Module5-EventMonitor",
        "Module6-ADManager",
        "Module7-Compliance"
    )

    foreach ($module in $modules) {
        It "$module.psm1 exists" {
            Test-Path (Join-Path $script:ModulesPath "$module.psm1") | Should -Be $true
        }
    }
}

# =============================================================================
# SYNTAX VALIDATION TESTS
# =============================================================================
Describe "Module Syntax Validation" {
    $allModules = @(
        @{ Name = "Common.psm1"; Path = "lib" },
        @{ Name = "Config.psm1"; Path = "" },
        @{ Name = "Module1-Dashboard.psm1"; Path = "modules" },
        @{ Name = "Module2-RemoteScan.psm1"; Path = "modules" },
        @{ Name = "Module3-RuleGenerator.psm1"; Path = "modules" },
        @{ Name = "Module4-PolicyLab.psm1"; Path = "modules" },
        @{ Name = "Module5-EventMonitor.psm1"; Path = "modules" },
        @{ Name = "Module6-ADManager.psm1"; Path = "modules" },
        @{ Name = "Module7-Compliance.psm1"; Path = "modules" }
    )

    foreach ($module in $allModules) {
        It "$($module.Name) has valid PowerShell syntax" {
            $basePath = if ($module.Path) { Join-Path $script:SrcPath $module.Path } else { $script:SrcPath }
            $filePath = Join-Path $basePath $module.Name
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($filePath, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }
}

# =============================================================================
# GUI SCRIPT TESTS
# =============================================================================
Describe "GUI Script" {
    BeforeAll {
        $script:GuiPath = Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1"
        $script:GuiContent = Get-Content $script:GuiPath -Raw
    }

    It "GA-AppLocker-GUI-WPF.ps1 exists" {
        Test-Path $script:GuiPath | Should -Be $true
    }

    It "GUI script has valid PowerShell syntax" {
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:GuiPath, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "GUI script contains required WPF assemblies" {
        $script:GuiContent | Should -Match "PresentationFramework"
        $script:GuiContent | Should -Match "PresentationCore"
    }

    It "GUI script contains XAML definition" {
        $script:GuiContent | Should -Match '\$xamlString'
        $script:GuiContent | Should -Match '<Window'
    }

    It "GUI script contains Window element" {
        $script:GuiContent | Should -Match '<Window'
    }

    It "GUI script contains navigation buttons" {
        $script:GuiContent | Should -Match 'NavDashboard'
        $script:GuiContent | Should -Match 'NavRules'
        $script:GuiContent | Should -Match 'NavEvents'
    }

    It "GUI script contains main panels" {
        $script:GuiContent | Should -Match 'PanelDashboard'
        $script:GuiContent | Should -Match 'PanelRules'
        $script:GuiContent | Should -Match 'PanelEvents'
    }

    It "Does not contain backticks in XAML Text attributes" {
        if ($script:GuiContent -match '\$xamlString = @"([\s\S]*?)"@') {
            $xaml = $Matches[1]
            $xaml | Should -Not -Match 'Text="[^"]*`[^"]*"'
        }
    }
}

# =============================================================================
# FUNCTION DEFINITION TESTS
# =============================================================================
Describe "Function Definitions" {
    BeforeAll {
        $script:GuiContent = Get-Content (Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1") -Raw
    }

    $requiredFunctions = @(
        "Initialize-AppLockerFolders",
        "Get-DomainInfo",
        "New-PublisherRule",
        "New-HashRule",
        "New-RulesFromArtifacts",
        "Write-Log"
    )

    foreach ($func in $requiredFunctions) {
        It "Defines $func function" {
            $script:GuiContent | Should -Match "function $func"
        }
    }
}

# =============================================================================
# MODULE EXPORT TESTS
# =============================================================================
Describe "Module Exports" {
    It "Common.psm1 exports functions" {
        $content = Get-Content (Join-Path $script:LibPath "Common.psm1") -Raw
        $content | Should -Match "Export-ModuleMember"
    }

    It "Module2-RemoteScan exports new event scanning functions" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module2-RemoteScan.psm1") -Raw
        $content | Should -Match "Get-RemoteAppLockerEvents"
        $content | Should -Match "Get-RemoteAppLockerEventsMultiple"
        $content | Should -Match "ConvertTo-RuleGeneratorArtifacts"
    }

    It "Module3-RuleGenerator exports rule functions" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $content | Should -Match "New-PublisherRule"
        $content | Should -Match "New-PathRule"
        $content | Should -Match "New-HashRule"
        $content | Should -Match "New-RulesFromArtifacts"
    }

    It "Module6-ADManager exports WinRM GPO function" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module6-ADManager.psm1") -Raw
        $content | Should -Match "New-WinRMGPO"
    }
}

# =============================================================================
# SECURITY VALIDATION TESTS
# =============================================================================
Describe "Security Features" {
    BeforeAll {
        $script:GuiContent = Get-Content (Join-Path $script:BuildPath "GA-AppLocker-GUI-WPF.ps1") -Raw
    }

    It "Uses proper error handling (try/catch)" {
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

Describe "Input Validation Functions" {
    It "Common.psm1 has LDAP filter protection" {
        $content = Get-Content (Join-Path $script:LibPath "Common.psm1") -Raw
        # Should have LDAP escaping or validation
        $content | Should -Match '(Protect-LDAPFilterValue|escape|sanitize)'
    }

    It "Module3-RuleGenerator has XML attribute protection" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $content | Should -Match "Protect-XmlAttributeValue"
        # Should escape XML special characters
        $content | Should -Match '&amp;|&lt;|&gt;|&quot;|&apos;'
    }

    It "Module6-ADManager has LDAP filter protection" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module6-ADManager.psm1") -Raw
        $content | Should -Match "Protect-LDAPFilterValue"
    }
}

# =============================================================================
# EDGE CASE TESTS - Empty/Null Input
# =============================================================================
Describe "Edge Cases - Empty and Null Input Handling" {
    BeforeAll {
        # Load Module3-RuleGenerator content for pattern checking
        $script:Module3Content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $script:Module2Content = Get-Content (Join-Path $script:ModulesPath "Module2-RemoteScan.psm1") -Raw
        $script:Module4Content = Get-Content (Join-Path $script:ModulesPath "Module4-PolicyLab.psm1") -Raw
        $script:Module6Content = Get-Content (Join-Path $script:ModulesPath "Module6-ADManager.psm1") -Raw
    }

    It "Module3 validates empty publisher name" {
        $script:Module3Content | Should -Match "IsNullOrWhiteSpace.*PublisherName"
    }

    It "Module3 validates empty path" {
        $script:Module3Content | Should -Match "IsNullOrWhiteSpace.*Path"
    }

    It "Module3 validates empty artifacts array" {
        $script:Module3Content | Should -Match "-not \`$Artifacts|-not\(`$Artifacts\)|Artifacts\.Count -eq 0"
    }

    It "Module2 validates empty computer name" {
        $script:Module2Content | Should -Match "IsNullOrWhiteSpace.*ComputerName"
    }

    It "Module4 validates empty GPO name" {
        $script:Module4Content | Should -Match "IsNullOrWhiteSpace.*GpoName"
    }

    It "Module4 validates empty TargetOU" {
        $script:Module4Content | Should -Match "IsNullOrWhiteSpace.*TargetOU"
    }
}

# =============================================================================
# EDGE CASE TESTS - Return Value Structure
# =============================================================================
Describe "Edge Cases - Return Value Structure" {
    $modules = @(
        @{ Name = "Module1-Dashboard.psm1"; Path = "modules" },
        @{ Name = "Module2-RemoteScan.psm1"; Path = "modules" },
        @{ Name = "Module3-RuleGenerator.psm1"; Path = "modules" },
        @{ Name = "Module4-PolicyLab.psm1"; Path = "modules" },
        @{ Name = "Module6-ADManager.psm1"; Path = "modules" },
        @{ Name = "Module7-Compliance.psm1"; Path = "modules" }
    )

    foreach ($module in $modules) {
        It "$($module.Name) returns hashtables with success key" {
            $basePath = Join-Path $script:SrcPath $module.Path
            $content = Get-Content (Join-Path $basePath $module.Name) -Raw
            # All modules should return @{ success = ... }
            $content | Should -Match "success\s*=\s*\`$true|\success\s*=\s*\`$false"
        }

        It "$($module.Name) returns error messages on failure" {
            $basePath = Join-Path $script:SrcPath $module.Path
            $content = Get-Content (Join-Path $basePath $module.Name) -Raw
            # Should include error property in failure returns
            $content | Should -Match "error\s*="
        }
    }
}

# =============================================================================
# EDGE CASE TESTS - Special Characters
# =============================================================================
Describe "Edge Cases - Special Character Handling" {
    It "XML protection escapes ampersand" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $content | Should -Match '-replace.*&.*&amp;'
    }

    It "XML protection escapes less-than" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $content | Should -Match '-replace.*<.*&lt;'
    }

    It "XML protection escapes greater-than" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $content | Should -Match '-replace.*>.*&gt;'
    }

    It "XML protection escapes double-quote" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module3-RuleGenerator.psm1") -Raw
        $content | Should -Match '-replace.*".*&quot;'
    }
}

# =============================================================================
# COMPREHENSIVE SCAN TESTS
# =============================================================================
Describe "Remote AppLocker Event Scanning" {
    BeforeAll {
        $script:Module2Content = Get-Content (Join-Path $script:ModulesPath "Module2-RemoteScan.psm1") -Raw
    }

    It "Get-RemoteAppLockerEvents collects system info" {
        $script:Module2Content | Should -Match "System\.ComputerName"
        $script:Module2Content | Should -Match "Win32_OperatingSystem"
    }

    It "Get-RemoteAppLockerEvents checks AppIDSvc status" {
        $script:Module2Content | Should -Match "AppIDSvc"
        $script:Module2Content | Should -Match "Status"
        $script:Module2Content | Should -Match "StartupType|StartMode"
    }

    It "Get-RemoteAppLockerEvents collects from all 4 log channels" {
        $script:Module2Content | Should -Match "Microsoft-Windows-AppLocker/EXE and DLL"
        $script:Module2Content | Should -Match "Microsoft-Windows-AppLocker/MSI and Script"
        $script:Module2Content | Should -Match "Microsoft-Windows-AppLocker/Packaged app-Deployment"
        $script:Module2Content | Should -Match "Microsoft-Windows-AppLocker/Packaged app-Execution"
    }

    It "Get-RemoteAppLockerEvents parses event XML" {
        $script:Module2Content | Should -Match "ToXml\(\)"
        $script:Module2Content | Should -Match "FilePath"
        $script:Module2Content | Should -Match "FileHash"
        $script:Module2Content | Should -Match "Publisher"
    }

    It "Get-RemoteAppLockerEvents classifies event types" {
        $script:Module2Content | Should -Match "8002.*Allowed"
        $script:Module2Content | Should -Match "8003.*Audit"
        $script:Module2Content | Should -Match "8004.*Blocked"
    }

    It "Get-RemoteAppLockerEvents generates artifacts for rule generator" {
        $script:Module2Content | Should -Match "Artifacts"
        $script:Module2Content | Should -Match "publisher"
        $script:Module2Content | Should -Match "path"
        $script:Module2Content | Should -Match "hash"
    }

    It "ConvertTo-RuleGeneratorArtifacts filters by event type" {
        $script:Module2Content | Should -Match "IncludeEventTypes"
        $script:Module2Content | Should -Match "Audit.*Blocked"
    }
}

# =============================================================================
# WINRM GPO TESTS
# =============================================================================
Describe "WinRM GPO Configuration" {
    BeforeAll {
        $script:Module6Content = Get-Content (Join-Path $script:ModulesPath "Module6-ADManager.psm1") -Raw
    }

    It "New-WinRMGPO uses GPO registry values (not cmdlets)" {
        $script:Module6Content | Should -Match "Set-GPRegistryValue"
        # Should NOT use Enable-PSRemoting
        $script:Module6Content | Should -Not -Match "Enable-PSRemoting"
    }

    It "New-WinRMGPO configures WinRM service path" {
        $script:Module6Content | Should -Match "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"
    }

    It "New-WinRMGPO configures WinRM client path" {
        $script:Module6Content | Should -Match "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"
    }

    It "New-WinRMGPO configures firewall rules" {
        $script:Module6Content | Should -Match "WindowsFirewall"
        $script:Module6Content | Should -Match "5985|5986"
    }

    It "New-WinRMGPO disables unencrypted traffic by default" {
        $script:Module6Content | Should -Match "AllowUnencryptedTraffic"
        $script:Module6Content | Should -Match "DisableUnencryptedTraffic.*\`$true"
    }

    It "New-WinRMGPO has ShouldProcess support" {
        $script:Module6Content | Should -Match "ShouldProcess"
    }
}

# =============================================================================
# BUG FIX VALIDATION TESTS
# =============================================================================
Describe "Bug Fix Validation" {
    It "Module4 uses correct DirectoryServices namespace" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module4-PolicyLab.psm1") -Raw
        # Should NOT have incorrect casing like "Directoryservices"
        $content | Should -Not -Match "System\.Directoryservices\.Activedirectory"
        # Should have correct casing
        $content | Should -Match "System\.DirectoryServices\.ActiveDirectory"
    }

    It "Module7 imports Module1 for event stats" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module7-Compliance.psm1") -Raw
        # Should import Module1-Dashboard, not Module5-EventMonitor for Get-AppLockerEventStats
        $content | Should -Match "Module1-Dashboard"
    }

    It "Module6 returns correct success status on link failure" {
        $content = Get-Content (Join-Path $script:ModulesPath "Module6-ADManager.psm1") -Raw
        # Should have partialSuccess pattern for GPO creation when link fails
        $content | Should -Match "partialSuccess"
    }
}

# =============================================================================
# DOCUMENTATION TESTS
# =============================================================================
Describe "Documentation" {
    It "README.md exists" {
        Test-Path (Join-Path $script:ProjectRoot "README.md") | Should -Be $true
    }

    It "claude.md exists" {
        Test-Path (Join-Path $script:ProjectRoot "claude.md") | Should -Be $true
    }

    It "claude.md documents new event scanning functions" {
        $content = Get-Content (Join-Path $script:ProjectRoot "claude.md") -Raw
        $content | Should -Match "Get-RemoteAppLockerEvents"
    }
}

AfterAll {
    # Cleanup
    Remove-Variable -Name GuiContent, Module2Content, Module3Content, Module4Content, Module6Content -Scope Script -ErrorAction SilentlyContinue
}
