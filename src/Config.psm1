# Config.psm1
# Configuration module for GA-AppLocker
# Based on AaronLocker Config.ps1 pattern

# ======================================================================
# CONFIGURATION - AARONLOCKER PATTERN
# ======================================================================

# Base paths (using ProgramData for proper Windows app data storage)
Set-Variable -Option Constant -Name basePath -Value "$env:ProgramData\GA-AppLocker"
Set-Variable -Option Constant -Name outputsDir -Value (Join-Path $basePath "output")
Set-Variable -Option Constant -Name scanResultsDir -Value (Join-Path $basePath "scans")
Set-Variable -Option Constant -Name supportDir -Value (Join-Path $basePath "support")
Set-Variable -Option Constant -Name customizationInputsDir -Value (Join-Path $basePath "custom")
Set-Variable -Option Constant -Name mergeRulesDynamicDir -Value (Join-Path $basePath "rules-dynamic")
Set-Variable -Option Constant -Name mergeRulesStaticDir -Value (Join-Path $basePath "rules-static")
Set-Variable -Option Constant -Name logsDir -Value (Join-Path $basePath "logs")
Set-Variable -Option Constant -Name evidenceDir -Value (Join-Path $basePath "evidence")

# Scan result files (writable directory detection)
Set-Variable -Option Constant -Name windirTxt -Value (Join-Path $scanResultsDir "writable-windir.txt")
Set-Variable -Option Constant -Name PfTxt -Value (Join-Path $scanResultsDir "writable-pf.txt")
Set-Variable -Option Constant -Name Pf86Txt -Value (Join-Path $scanResultsDir "writable-pf86.txt")

# Default policy files
Set-Variable -Option Constant -Name RulesFileAuditLatest -Value (Join-Path $outputsDir "AppLocker-Audit-Latest.xml")
Set-Variable -Option Constant -Name RulesFileEnforceLatest -Value (Join-Path $outputsDir "AppLocker-Enforce-Latest.xml")

# ======================================================================
# INITIALIZATION
# ======================================================================

function Initialize-AppLockerPaths {
    <#
    .SYNOPSIS
        Initialize AppLocker directory structure with safe defaults
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [OutputType([hashtable])]
    param(
        [string]$BasePath = $script:basePath
    )

    $paths = @{
        Base = $BasePath
        Output = $script:outputsDir
        Scans = $script:scanResultsDir
        Support = $script:supportDir
        Custom = $script:customizationInputsDir
        RulesDynamic = $script:mergeRulesDynamicDir
        RulesStatic = $script:mergeRulesStaticDir
        Logs = $script:logsDir
        Evidence = $script:evidenceDir
    }

    foreach ($key in $paths.Keys) {
        $path = $paths[$key]
        if (-not (Test-Path $path)) {
            try {
                New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
            }
            catch {
                return @{
                    success = $false
                    error = "Failed to create $key directory: $_"
                }
            }
        }
    }

    return @{
        success = $true
        paths = $paths
    }
}

function Get-AppLockerConfig {
    <#
    .SYNOPSIS
        Get all AppLocker configuration values
    .OUTPUTS
        System.Collections.Hashtable
    #>
    [OutputType([hashtable])]
    param()

    return @{
        basePath = $script:basePath
        outputsDir = $script:outputsDir
        scanResultsDir = $script:scanResultsDir
        supportDir = $script:supportDir
        customizationInputsDir = $script:customizationInputsDir
        mergeRulesDynamicDir = $script:mergeRulesDynamicDir
        mergeRulesStaticDir = $script:mergeRulesStaticDir
        logsDir = $script:logsDir
        evidenceDir = $script:evidenceDir
        windirTxt = $script:windirTxt
        PfTxt = $script:PfTxt
        Pf86Txt = $script:Pf86Txt
        RulesFileAuditLatest = $script:RulesFileAuditLatest
        RulesFileEnforceLatest = $script:RulesFileEnforceLatest
    }
}

# ======================================================================
# EXPORTS
# ======================================================================

Export-ModuleMember -Function Initialize-AppLockerPaths, Get-AppLockerConfig
Export-ModuleMember -Variable basePath, outputsDir, scanResultsDir, supportDir,
                              customizationInputsDir, mergeRulesDynamicDir, mergeRulesStaticDir, logsDir, evidenceDir,
                              windirTxt, PfTxt, Pf86Txt, RulesFileAuditLatest, RulesFileEnforceLatest
