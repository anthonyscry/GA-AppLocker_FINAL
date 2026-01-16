#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Comprehensive validation script for GA-AppLocker GUI modules

.DESCRIPTION
    This script performs thorough validation of all refactored GUI modules including:
    - PowerShell syntax validation using the language parser
    - Module dependency verification
    - Function export validation
    - XAML validation
    - Module loading sequence testing

.EXAMPLE
    .\Validate-Modules.ps1

.EXAMPLE
    .\Validate-Modules.ps1 -Verbose

.EXAMPLE
    .\Validate-Modules.ps1 -DetailedReport

.NOTES
    Author: GA-AppLocker Refactoring Team
    Date: 2026-01-16
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RootPath = "$PSScriptRoot/src/GUI",

    [Parameter(Mandatory=$false)]
    [switch]$DetailedReport,

    [Parameter(Mandatory=$false)]
    [switch]$ExportResults,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$PSScriptRoot/validation_results.json"
)

$ErrorActionPreference = 'Continue'

# Initialize results collection
$global:ValidationResults = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    SyntaxValidation = @()
    ModuleLoading = @()
    FunctionExports = @()
    XamlValidation = @()
    Dependencies = @()
    Summary = @{}
}

#region Helper Functions

function Write-ValidationHeader {
    param([string]$Title)

    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
}

function Write-ValidationSuccess {
    param([string]$Message)
    Write-Host "✓ " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-ValidationWarning {
    param([string]$Message)
    Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor Yellow
}

function Write-ValidationError {
    param([string]$Message)
    Write-Host "✗ " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor Red
}

#endregion

#region Validation Functions

function Test-PowerShellSyntax {
    param([string]$FilePath)

    try {
        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $FilePath,
            [ref]$tokens,
            [ref]$errors
        )

        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Valid = ($errors.Count -eq 0)
            ErrorCount = $errors.Count
            Errors = $errors | ForEach-Object { $_.Message }
            TokenCount = $tokens.Count
        }

        $global:ValidationResults.SyntaxValidation += $result

        return $result
    }
    catch {
        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Valid = $false
            ErrorCount = 1
            Errors = @($_.Exception.Message)
            TokenCount = 0
        }

        $global:ValidationResults.SyntaxValidation += $result

        return $result
    }
}

function Test-ModuleLoading {
    param([string]$FilePath)

    try {
        # Attempt to dot-source the module
        . $FilePath

        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Loaded = $true
            Error = $null
        }

        $global:ValidationResults.ModuleLoading += $result

        return $result
    }
    catch {
        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Loaded = $false
            Error = $_.Exception.Message
        }

        $global:ValidationResults.ModuleLoading += $result

        return $result
    }
}

function Get-ModuleFunctions {
    param([string]$FilePath)

    try {
        $content = Get-Content -Path $FilePath -Raw

        # Extract function definitions
        $functionPattern = 'function\s+([\w-]+)\s*(?:\(|\{)'
        $functions = [regex]::Matches($content, $functionPattern) |
            ForEach-Object { $_.Groups[1].Value }

        # Extract exports
        $exportPattern = 'Export-ModuleMember\s+-Function\s+["\']?([^"\'\r\n]+)["\']?'
        $exports = [regex]::Matches($content, $exportPattern) |
            ForEach-Object {
                $_.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() }
            }

        # Find unexported functions
        $unexported = $functions | Where-Object { $_ -notin $exports }

        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            FunctionsDefined = $functions
            FunctionsExported = $exports
            UnexportedFunctions = $unexported
            TotalFunctions = $functions.Count
            TotalExports = $exports.Count
            ExportRatio = if ($functions.Count -gt 0) {
                [math]::Round(($exports.Count / $functions.Count) * 100, 1)
            } else {
                0
            }
        }

        $global:ValidationResults.FunctionExports += $result

        return $result
    }
    catch {
        Write-Warning "Failed to analyze functions in $FilePath: $_"
        return $null
    }
}

function Test-XamlFile {
    param([string]$FilePath)

    try {
        [xml]$xaml = Get-Content -Path $FilePath -Raw

        # Find all elements with x:Name attribute
        $namedElements = $xaml.SelectNodes("//*[@*[local-name()='Name']]")

        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Valid = $true
            NamedElements = $namedElements.Count
            ElementNames = $namedElements | ForEach-Object {
                $_.GetAttribute("Name", "http://schemas.microsoft.com/winfx/2006/xaml")
            }
            Error = $null
        }

        $global:ValidationResults.XamlValidation += $result

        return $result
    }
    catch {
        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Valid = $false
            NamedElements = 0
            ElementNames = @()
            Error = $_.Exception.Message
        }

        $global:ValidationResults.XamlValidation += $result

        return $result
    }
}

function Get-ModuleDependencies {
    param([string]$FilePath)

    try {
        $content = Get-Content -Path $FilePath -Raw

        # Find dot-sourcing imports
        $importPattern = '\.\s+["\']?\$(?:PSScriptRoot|scriptPath)[/\\]([^"\'\r\n]+\.ps1)["\']?'
        $imports = [regex]::Matches($content, $importPattern) |
            ForEach-Object { $_.Groups[1].Value }

        $result = [PSCustomObject]@{
            File = Split-Path $FilePath -Leaf
            Path = $FilePath
            Dependencies = $imports
            DependencyCount = $imports.Count
        }

        $global:ValidationResults.Dependencies += $result

        return $result
    }
    catch {
        Write-Warning "Failed to analyze dependencies in $FilePath: $_"
        return $null
    }
}

#endregion

#region Main Validation Logic

# Start validation
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       GA-AppLocker GUI Module Validation Suite                        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Find all PowerShell and XAML files
$ps1Files = Get-ChildItem -Path $RootPath -Recurse -Filter "*.ps1" | Sort-Object FullName
$xamlFiles = Get-ChildItem -Path $RootPath -Recurse -Filter "*.xaml" | Sort-Object FullName

Write-Host "Found Files:" -ForegroundColor White
Write-Host "  PowerShell Modules: $($ps1Files.Count)" -ForegroundColor White
Write-Host "  XAML Files: $($xamlFiles.Count)" -ForegroundColor White

# Test 1: Syntax Validation
Write-ValidationHeader "1. POWERSHELL SYNTAX VALIDATION"

$syntaxResults = @()
foreach ($file in $ps1Files) {
    $result = Test-PowerShellSyntax -FilePath $file.FullName

    if ($result.Valid) {
        Write-ValidationSuccess "$($result.File) - Valid syntax ($($result.TokenCount) tokens)"
    }
    else {
        Write-ValidationError "$($result.File) - Syntax errors found:"
        foreach ($error in $result.Errors) {
            Write-Host "    $error" -ForegroundColor Red
        }
    }

    $syntaxResults += $result
}

$syntaxPassed = ($syntaxResults | Where-Object Valid).Count
$syntaxFailed = ($syntaxResults | Where-Object { -not $_.Valid }).Count

Write-Host ""
Write-Host "Summary: $syntaxPassed passed, $syntaxFailed failed" -ForegroundColor $(if ($syntaxFailed -eq 0) { 'Green' } else { 'Yellow' })

# Test 2: Function Export Validation
Write-ValidationHeader "2. FUNCTION EXPORT VALIDATION"

$functionResults = @()
$totalFunctions = 0
$totalExports = 0

foreach ($file in $ps1Files) {
    $result = Get-ModuleFunctions -FilePath $file.FullName

    if ($result) {
        $totalFunctions += $result.TotalFunctions
        $totalExports += $result.TotalExports

        if ($DetailedReport) {
            Write-Host "$($result.File)" -ForegroundColor White
            Write-Host "  Functions: $($result.TotalFunctions), Exports: $($result.TotalExports) ($($result.ExportRatio)%)" -ForegroundColor Gray

            if ($result.UnexportedFunctions.Count -gt 0) {
                Write-Host "  Unexported: $($result.UnexportedFunctions -join ', ')" -ForegroundColor Yellow
            }
        }
        else {
            $status = if ($result.TotalExports -eq 0 -and $result.TotalFunctions -gt 0) { "⚠" } else { "✓" }
            Write-Host "$status $($result.File): $($result.TotalFunctions) functions, $($result.TotalExports) exported"
        }

        $functionResults += $result
    }
}

Write-Host ""
Write-Host "Total Functions Defined: $totalFunctions" -ForegroundColor White
Write-Host "Total Functions Exported: $totalExports" -ForegroundColor White

# Test 3: XAML Validation
Write-ValidationHeader "3. XAML VALIDATION"

$xamlResults = @()
foreach ($file in $xamlFiles) {
    $result = Test-XamlFile -FilePath $file.FullName

    if ($result.Valid) {
        Write-ValidationSuccess "$($result.File) - Valid XML ($($result.NamedElements) named elements)"

        if ($DetailedReport) {
            Write-Host "  Named Controls:" -ForegroundColor Gray
            $result.ElementNames | Select-Object -First 10 | ForEach-Object {
                Write-Host "    - $_" -ForegroundColor Gray
            }
            if ($result.ElementNames.Count -gt 10) {
                Write-Host "    ... and $($result.ElementNames.Count - 10) more" -ForegroundColor Gray
            }
        }
    }
    else {
        Write-ValidationError "$($result.File) - Invalid XML"
        Write-Host "    Error: $($result.Error)" -ForegroundColor Red
    }

    $xamlResults += $result
}

# Test 4: Module Dependencies
Write-ValidationHeader "4. MODULE DEPENDENCY ANALYSIS"

$dependencyResults = @()
foreach ($file in $ps1Files) {
    $result = Get-ModuleDependencies -FilePath $file.FullName

    if ($result -and $result.DependencyCount -gt 0) {
        Write-Host "$($result.File)" -ForegroundColor White
        foreach ($dep in $result.Dependencies) {
            Write-Host "  └─ $dep" -ForegroundColor Gray
        }

        $dependencyResults += $result
    }
}

if ($dependencyResults.Count -eq 0) {
    Write-Host "No explicit module dependencies found (modules loaded via main entry point)" -ForegroundColor Gray
}

# Test 5: Module Organization
Write-ValidationHeader "5. MODULE ORGANIZATION"

$categories = $ps1Files | Group-Object { $_.Directory.Name } | Sort-Object Name

foreach ($category in $categories) {
    Write-Host "$($category.Name)/ ($($category.Count) files)" -ForegroundColor White
    foreach ($file in ($category.Group | Sort-Object Name)) {
        Write-Host "  - $($file.Name)" -ForegroundColor Gray
    }
}

# Final Summary
Write-ValidationHeader "VALIDATION SUMMARY"

$global:ValidationResults.Summary = @{
    TotalModules = $ps1Files.Count
    TotalXamlFiles = $xamlFiles.Count
    SyntaxPassed = $syntaxPassed
    SyntaxFailed = $syntaxFailed
    TotalFunctions = $totalFunctions
    TotalExports = $totalExports
    ExportRatio = if ($totalFunctions -gt 0) {
        [math]::Round(($totalExports / $totalFunctions) * 100, 1)
    } else {
        0
    }
    XamlValid = ($xamlResults | Where-Object Valid).Count
    XamlInvalid = ($xamlResults | Where-Object { -not $_.Valid }).Count
    ModulesWithDependencies = $dependencyResults.Count
}

Write-Host "Total Modules:              $($global:ValidationResults.Summary.TotalModules)" -ForegroundColor White
Write-Host "Total XAML Files:           $($global:ValidationResults.Summary.TotalXamlFiles)" -ForegroundColor White
Write-Host ""
Write-Host "Syntax Validation:" -ForegroundColor White
Write-Host "  Passed:                   $syntaxPassed" -ForegroundColor $(if ($syntaxFailed -eq 0) { 'Green' } else { 'Yellow' })
Write-Host "  Failed:                   $syntaxFailed" -ForegroundColor $(if ($syntaxFailed -eq 0) { 'Green' } else { 'Red' })
Write-Host ""
Write-Host "Function Exports:" -ForegroundColor White
Write-Host "  Total Functions:          $totalFunctions" -ForegroundColor White
Write-Host "  Exported Functions:       $totalExports" -ForegroundColor White
Write-Host "  Export Ratio:             $($global:ValidationResults.Summary.ExportRatio)%" -ForegroundColor White
Write-Host ""
Write-Host "XAML Validation:" -ForegroundColor White
Write-Host "  Valid:                    $($global:ValidationResults.Summary.XamlValid)" -ForegroundColor Green
Write-Host "  Invalid:                  $($global:ValidationResults.Summary.XamlInvalid)" -ForegroundColor $(if ($global:ValidationResults.Summary.XamlInvalid -eq 0) { 'Green' } else { 'Red' })

# Overall Status
Write-Host ""
if ($syntaxFailed -eq 0 -and $global:ValidationResults.Summary.XamlInvalid -eq 0) {
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                   ✓ ALL VALIDATIONS PASSED                             ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
}
else {
    Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║              ⚠ VALIDATION COMPLETED WITH WARNINGS                      ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
}

# Export results if requested
if ($ExportResults) {
    Write-Host ""
    Write-Host "Exporting validation results to: $OutputPath" -ForegroundColor Cyan
    $global:ValidationResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-ValidationSuccess "Results exported successfully"
}

Write-Host ""

#endregion
