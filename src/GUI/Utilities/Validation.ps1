<#
.SYNOPSIS
    Validation utilities for GA-AppLocker GUI

.DESCRIPTION
    Provides input validation, sanitization, and data verification
    functions with security-focused implementation.

.NOTES
    Version:        2.0
    Author:         General Atomics - ASI
    Creation Date:  2026-01-16
    Module:         Utilities\Validation
#>

function Test-AppLockerRules {
    <#
    .SYNOPSIS
        Validate AppLocker rule definitions

    .DESCRIPTION
        Validates an array of AppLocker rule hashtables for correctness,
        completeness, and security compliance.

    .PARAMETER Rules
        Array of rule hashtables to validate

    .OUTPUTS
        Hashtable with validation results including success status,
        valid rules, errors, and warnings

    .EXAMPLE
        $rules = @(
            @{ type = "Publisher"; action = "Allow"; publisher = "O=Microsoft*" }
            @{ type = "Path"; action = "Deny"; path = "C:\Temp\*" }
        )
        $validation = Test-AppLockerRules -Rules $rules
        if ($validation.success) {
            Write-Host "All rules valid: $($validation.validCount)"
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Rules
    )

    $errors = @()
    $warnings = @()
    $validRules = @()

    # Check if rules array is empty
    if ($Rules.Count -eq 0) {
        $warnings += "No rules provided for validation"
        return @{
            success      = $true
            validRules   = @()
            errorCount   = 0
            errors       = @()
            warningCount = 1
            warnings     = $warnings
            totalCount   = 0
            validCount   = 0
        }
    }

    foreach ($rule in $Rules) {
        $ruleErrors = @()

        # Check for required properties
        if (-not $rule.type) {
            $ruleErrors += "Rule missing 'type' property"
        }

        if (-not $rule.action) {
            $ruleErrors += "Rule missing 'action' property"
        }

        # Validate action values
        if ($rule.action -and $rule.action -notin @('Allow', 'Deny', 'Audit')) {
            $ruleErrors += "Invalid action value: '$($rule.action)'. Must be Allow, Deny, or Audit"
        }

        # Type-specific validation
        if ($rule.type) {
            switch ($rule.type) {
                "Publisher" {
                    if (-not $rule.publisher) {
                        $ruleErrors += "Publisher rule missing 'publisher' property"
                    }
                    elseif ([string]::IsNullOrWhiteSpace($rule.publisher)) {
                        $ruleErrors += "Publisher rule has empty 'publisher' value"
                    }
                }
                "Path" {
                    if (-not $rule.path) {
                        $ruleErrors += "Path rule missing 'path' property"
                    }
                    elseif ([string]::IsNullOrWhiteSpace($rule.path)) {
                        $ruleErrors += "Path rule has empty 'path' value"
                    }
                    # Validate path format
                    elseif (-not (Test-SafePath -Path $rule.path -AllowWildcards)) {
                        $warnings += "Path rule may contain unsafe characters: $($rule.path)"
                    }
                }
                "Hash" {
                    if (-not $rule.hash -and -not $rule.path) {
                        $ruleErrors += "Hash rule missing both 'hash' and 'path' properties"
                    }
                    if ($rule.hash -and $rule.hash -notmatch '^[0-9A-Fa-f]{64}$|^[0-9A-Fa-f]{40}$') {
                        $warnings += "Hash value may not be valid SHA256 or SHA1"
                    }
                }
                default {
                    $ruleErrors += "Unknown rule type: $($rule.type)"
                }
            }
        }

        # If rule has errors, add them to the error list
        if ($ruleErrors.Count -gt 0) {
            $errors += $ruleErrors
        }
        else {
            $validRules += $rule
        }
    }

    # Generate warnings
    if ($validRules.Count -eq 0 -and $Rules.Count -gt 0) {
        $warnings += "No valid rules found in $($Rules.Count) rules provided"
    }

    if ($validRules.Count -lt $Rules.Count) {
        $warnings += "$($Rules.Count - $validRules.Count) rule(s) were invalid and excluded"
    }

    # Check for potential security issues
    $allowAllRules = $validRules | Where-Object {
        $_.action -eq 'Allow' -and (
            ($_.type -eq 'Path' -and $_.path -in @('*', 'C:\*', '%SYSTEMDRIVE%\*')) -or
            ($_.type -eq 'Publisher' -and $_.publisher -eq '*')
        )
    }

    if ($allowAllRules) {
        $warnings += "WARNING: Rule(s) found that allow all executables - potential security risk"
    }

    return @{
        success      = ($errors.Count -eq 0)
        validRules   = $validRules
        errorCount   = $errors.Count
        errors       = $errors
        warningCount = $warnings.Count
        warnings     = $warnings
        totalCount   = $Rules.Count
        validCount   = $validRules.Count
    }
}

function Test-SafePath {
    <#
    .SYNOPSIS
        Validate if a path is safe and well-formed

    .DESCRIPTION
        Checks if a path string contains valid characters and structure

    .PARAMETER Path
        The path to validate

    .PARAMETER AllowWildcards
        Allow wildcard characters (* and ?)

    .PARAMETER AllowEnvironmentVariables
        Allow environment variable syntax (%VAR%)

    .OUTPUTS
        Boolean indicating if path is safe

    .EXAMPLE
        if (Test-SafePath -Path "C:\Program Files\App\*" -AllowWildcards) {
            Write-Host "Path is valid"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$AllowWildcards,

        [Parameter(Mandatory = $false)]
        [switch]$AllowEnvironmentVariables
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    # Check for invalid characters (excluding wildcards and env vars if allowed)
    $invalidChars = [System.IO.Path]::GetInvalidPathChars()
    $pathChars = $Path.ToCharArray()

    foreach ($char in $pathChars) {
        if ($char -in $invalidChars) {
            return $false
        }

        # Check for control characters
        if ([int]$char -lt 32) {
            return $false
        }
    }

    # If wildcards not allowed, check for them
    if (-not $AllowWildcards -and ($Path -match '[*?]')) {
        return $false
    }

    # If environment variables not allowed, check for them
    if (-not $AllowEnvironmentVariables -and ($Path -match '%\w+%')) {
        return $false
    }

    # Check for path traversal attempts
    if ($Path -match '\.\.[/\\]') {
        return $false
    }

    # Check for null bytes (potential injection)
    if ($Path -match '\x00') {
        return $false
    }

    return $true
}

function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        HTML encode a string for safe display

    .DESCRIPTION
        Escapes HTML special characters to prevent XSS attacks

    .PARAMETER Value
        The string to encode

    .OUTPUTS
        HTML-encoded string

    .EXAMPLE
        $safe = ConvertTo-HtmlEncoded -Value $userInput
        $html += "<div>$safe</div>"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Value = ""
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return ''
    }

    # Use System.Web.HttpUtility if available
    try {
        if ([System.Web.HttpUtility]) {
            return [System.Web.HttpUtility]::HtmlEncode($Value)
        }
    }
    catch {
        # System.Web not available, use manual encoding
    }

    # Fallback to manual encoding
    $encoded = $Value -replace '&', '&amp;'
    $encoded = $encoded -replace '<', '&lt;'
    $encoded = $encoded -replace '>', '&gt;'
    $encoded = $encoded -replace '"', '&quot;'
    $encoded = $encoded -replace "'", '&#39;'

    return $encoded
}

function ConvertTo-SafeString {
    <#
    .SYNOPSIS
        Sanitize user input for display

    .DESCRIPTION
        Removes or escapes potentially dangerous characters from user input
        to prevent injection attacks

    .PARAMETER InputString
        The string to sanitize

    .PARAMETER MaxLength
        Maximum allowed length (default: 1000)

    .PARAMETER RemoveControlChars
        Remove control characters (default: true)

    .PARAMETER HtmlEncode
        HTML encode the result (default: false)

    .OUTPUTS
        Sanitized string safe for display

    .EXAMPLE
        $safe = ConvertTo-SafeString -InputString $userInput -MaxLength 500
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$InputString = "",

        [Parameter(Mandatory = $false)]
        [int]$MaxLength = 1000,

        [Parameter(Mandatory = $false)]
        [bool]$RemoveControlChars = $true,

        [Parameter(Mandatory = $false)]
        [bool]$HtmlEncode = $false
    )

    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }

    # Truncate to max length
    if ($InputString.Length -gt $MaxLength) {
        $InputString = $InputString.Substring(0, $MaxLength)
    }

    $sanitized = $InputString

    # Remove control characters (except newline, tab, carriage return)
    if ($RemoveControlChars) {
        $sanitized = $sanitized -replace '[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', ''
    }

    # HTML encode if requested
    if ($HtmlEncode) {
        $sanitized = ConvertTo-HtmlEncoded -Value $sanitized
    }

    return $sanitized
}

function Test-ValidEmailAddress {
    <#
    .SYNOPSIS
        Validate email address format

    .DESCRIPTION
        Checks if a string is a valid email address format

    .PARAMETER EmailAddress
        The email address to validate

    .OUTPUTS
        Boolean indicating if email is valid

    .EXAMPLE
        if (Test-ValidEmailAddress -EmailAddress "user@domain.com") {
            Write-Host "Valid email"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$EmailAddress
    )

    if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
        return $false
    }

    # Basic email regex pattern
    $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    return $EmailAddress -match $emailPattern
}

function Test-ValidComputerName {
    <#
    .SYNOPSIS
        Validate computer/hostname format

    .DESCRIPTION
        Checks if a string is a valid Windows computer name

    .PARAMETER ComputerName
        The computer name to validate

    .OUTPUTS
        Boolean indicating if computer name is valid

    .EXAMPLE
        if (Test-ValidComputerName -ComputerName "SERVER01") {
            Write-Host "Valid computer name"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return $false
    }

    # Check length (max 15 characters for NetBIOS, 63 for DNS)
    if ($ComputerName.Length -gt 63) {
        return $false
    }

    # Valid characters: letters, numbers, hyphens (but not starting/ending with hyphen)
    $pattern = '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'

    return $ComputerName -match $pattern
}

function ConvertTo-SafeFileName {
    <#
    .SYNOPSIS
        Convert string to safe filename

    .DESCRIPTION
        Removes or replaces invalid filename characters

    .PARAMETER FileName
        The filename to sanitize

    .PARAMETER Replacement
        Character to replace invalid chars with (default: underscore)

    .OUTPUTS
        Safe filename string

    .EXAMPLE
        $safeFile = ConvertTo-SafeFileName -FileName "Report: 2024/01/15"
        # Returns: "Report_ 2024_01_15"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [string]$Replacement = "_"
    )

    if ([string]::IsNullOrWhiteSpace($FileName)) {
        return "unnamed"
    }

    # Get invalid filename characters
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()

    # Replace invalid characters
    $safe = $FileName
    foreach ($char in $invalidChars) {
        $safe = $safe -replace [regex]::Escape($char), $Replacement
    }

    # Remove leading/trailing whitespace and dots
    $safe = $safe.Trim('. ')

    # Ensure filename is not empty after sanitization
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "unnamed"
    }

    # Limit length to 200 characters (safe for Windows)
    if ($safe.Length -gt 200) {
        $safe = $safe.Substring(0, 200)
    }

    return $safe
}

# Export module members
Export-ModuleMember -Function Test-AppLockerRules, Test-SafePath, ConvertTo-HtmlEncoded, `
                              ConvertTo-SafeString, Test-ValidEmailAddress, Test-ValidComputerName, `
                              ConvertTo-SafeFileName
