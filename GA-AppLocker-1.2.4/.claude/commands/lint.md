# Run PSScriptAnalyzer and Fix Issues

Run PSScriptAnalyzer on all PowerShell files and automatically fix any issues found.

## Instructions

1. First, check if PSScriptAnalyzer is installed:
```powershell
Get-Module -ListAvailable PSScriptAnalyzer
```

2. If not installed, install it:
```powershell
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
```

3. Run the linter on the GUI folder:
```powershell
$results = Invoke-ScriptAnalyzer -Path ./GUI -Recurse -Severity Warning -Settings ./GUI/PSScriptAnalyzerSettings.psd1
$results | Format-Table -AutoSize
```

4. For each issue found:
   - **Error severity**: MUST be fixed immediately
   - **Warning severity**: Should be fixed
   - **Information severity**: Consider fixing if it improves code quality

5. Common fixes to apply:

   | Rule | Fix |
   |------|-----|
   | PSAvoidUsingWriteHost | Keep as-is for GUI (suppress with attribute) |
   | PSUseDeclaredVarsMoreThanAssignments | Remove unused variables |
   | PSAvoidUsingPlainTextForPassword | Use SecureString or PSCredential |
   | PSUseShouldProcessForStateChangingFunctions | Add SupportsShouldProcess |
   | PSAvoidUsingCmdletAliases | Replace aliases with full cmdlet names |
   | PSAvoidUsingPositionalParameters | Use named parameters |

6. After fixing, re-run the linter to verify all issues are resolved.

## Suppressing Rules

If a rule should be suppressed for a valid reason, add:
```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('RuleName', '', Justification = 'Reason')]
```

## Output

Report:
- Total issues found
- Issues by severity (Error/Warning/Information)
- Files with most issues
- All fixes applied
