# Contributing to GA-AppLocker

Thank you for your interest in contributing to GA-AppLocker! This guide will help you get set up for development.

## Development Setup

### Prerequisites

- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
- **Git** for version control
- **.NET 8 SDK** (only if building the WPF GUI)

### Required PowerShell Modules

Install these modules for development:

```powershell
# PSScriptAnalyzer - Code quality and linting
Install-Module PSScriptAnalyzer -Scope CurrentUser

# Pester - Testing framework (version 5.0+)
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force
```

### Setting Up Your Environment

1. **Clone the repository**
   ```powershell
   git clone https://github.com/anthonyscry/GA-AppLocker.git
   cd GA-AppLocker
   ```

2. **Install Git hooks**
   ```powershell
   .\.githooks\Install-Hooks.ps1
   ```
   This configures pre-commit hooks that run PSScriptAnalyzer automatically.

3. **Verify your setup**
   ```powershell
   .\scripts\Invoke-LocalValidation.ps1
   ```
   This runs all checks (linting, tests, XAML validation) locally.

## Development Workflow

### Before Making Changes

1. Create a feature branch from `main`:
   ```powershell
   git checkout -b feature/your-feature-name
   ```

2. Ensure your development environment is set up (see above)

### Making Changes

1. **Follow existing patterns** - See `CLAUDE.md` for project conventions
2. **Import Common.psm1** for shared functions
3. **Reference Config.psd1** for configurable values
4. **Use Write-Host with colors** for user feedback

### Before Committing

Run local validation to catch issues early:

```powershell
# Full validation (lint + tests + XAML)
.\scripts\Invoke-LocalValidation.ps1

# Quick lint check only
.\scripts\Invoke-LocalValidation.ps1 -SkipTests
```

The pre-commit hook will also run PSScriptAnalyzer automatically.

### Code Quality Standards

- **No PSScriptAnalyzer errors** - Warnings are acceptable but should be minimized
- **Tests must pass** - All Pester tests must succeed
- **XAML must be valid** - If modifying GUI components

## Running Tests

### Run All Tests
```powershell
Invoke-Pester -Path .\**\*.Tests.ps1
```

### Run Specific Test File
```powershell
Invoke-Pester -Path .\Tests\Common.Tests.ps1
```

### Run with Verbose Output
```powershell
Invoke-Pester -Path .\**\*.Tests.ps1 -Output Detailed
```

## Linting

### Run PSScriptAnalyzer Manually
```powershell
# Single file
Invoke-ScriptAnalyzer -Path .\Start-AppLockerWorkflow.ps1

# All files with project settings
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1
```

### Common Lint Issues

| Rule | Fix |
|------|-----|
| `PSAvoidUsingCmdletAliases` | Use full cmdlet names (`Where-Object` not `?`) |
| `PSAvoidUsingPositionalParameters` | Use named parameters (`-Path` not just the value) |
| `PSUseDeclaredVarsMoreThanAssignments` | Remove unused variables or use `$null = ...` |

## Pull Request Process

1. **Ensure all checks pass** - `.\scripts\Invoke-LocalValidation.ps1`
2. **Update documentation** if adding new features
3. **Add tests** for new functionality
4. **Create a descriptive PR** with:
   - Summary of changes
   - Any breaking changes
   - Testing performed

## Project Structure

See `CLAUDE.md` for detailed project structure and conventions.

Key directories:
- `utilities/` - Shared modules and utility scripts
- `GUI/` - WPF application components
- `Tests/` - Pester test files
- `scripts/` - Development helper scripts
- `.githooks/` - Git hook scripts

## Getting Help

- Open an issue for bugs or feature requests
- See `CLAUDE.md` for detailed project documentation
- Run `.\Start-AppLockerWorkflow.ps1` for interactive help
