<#
.SYNOPSIS
    Credential management utilities for GA-AppLocker.
.DESCRIPTION
    Provides functions for securely storing, retrieving, and managing
    credentials used for remote operations. Supports:
    - Windows Credential Manager integration
    - Encrypted file-based storage (fallback)
    - Session-based caching for performance
.NOTES
    Credentials are stored using DPAPI encryption, which ties them
    to the current user and machine.
#>

#Requires -Version 5.1

# Session-level credential cache
$Script:CredentialCache = @{}
$Script:CredentialStorePath = $null

<#
.SYNOPSIS
    Initializes the credential storage path.
.PARAMETER StorePath
    Custom path for credential storage. Defaults to user's AppData.
#>
function Initialize-CredentialStore {
    [CmdletBinding()]
    param(
        [string]$StorePath
    )

    if ($StorePath) {
        $Script:CredentialStorePath = $StorePath
    } else {
        $Script:CredentialStorePath = Join-Path $env:LOCALAPPDATA 'GA-AppLocker\Credentials'
    }

    if (-not (Test-Path $Script:CredentialStorePath)) {
        New-Item -ItemType Directory -Path $Script:CredentialStorePath -Force | Out-Null
    }
}

<#
.SYNOPSIS
    Saves a credential for later use.
.DESCRIPTION
    Stores a credential using DPAPI encryption. The credential is tied to
    the current user and machine and cannot be decrypted elsewhere.
.PARAMETER Name
    A unique name/identifier for this credential (e.g., "RemoteScan", "Domain")
.PARAMETER Credential
    The PSCredential object to store
.PARAMETER Force
    Overwrite existing credential if it exists
.EXAMPLE
    $cred = Get-Credential
    Save-StoredCredential -Name "RemoteScan" -Credential $cred
#>
function Save-StoredCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [switch]$Force
    )

    Initialize-CredentialStore

    $credPath = Join-Path $Script:CredentialStorePath "$Name.cred"

    if ((Test-Path $credPath) -and -not $Force) {
        Write-Warning "Credential '$Name' already exists. Use -Force to overwrite."
        return $false
    }

    try {
        # Export credential using DPAPI encryption (user-specific)
        $Credential | Export-Clixml -Path $credPath -Force

        # Also cache in session
        $Script:CredentialCache[$Name] = $Credential

        Write-Verbose "Credential '$Name' saved successfully."
        return $true
    }
    catch {
        Write-Error "Failed to save credential: $_"
        return $false
    }
}

<#
.SYNOPSIS
    Retrieves a stored credential.
.DESCRIPTION
    Retrieves a credential from the store or session cache.
.PARAMETER Name
    The name/identifier of the credential to retrieve
.PARAMETER PromptIfMissing
    If true, prompts the user for credentials if not found
.PARAMETER PromptMessage
    Custom message to show when prompting for credentials
.EXAMPLE
    $cred = Get-StoredCredential -Name "RemoteScan" -PromptIfMissing
#>
function Get-StoredCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$PromptIfMissing,

        [string]$PromptMessage = "Enter credentials for $Name"
    )

    # Check session cache first
    if ($Script:CredentialCache.ContainsKey($Name)) {
        Write-Verbose "Retrieved credential '$Name' from session cache."
        return $Script:CredentialCache[$Name]
    }

    Initialize-CredentialStore

    $credPath = Join-Path $Script:CredentialStorePath "$Name.cred"

    if (Test-Path $credPath) {
        try {
            $cred = Import-Clixml -Path $credPath

            # Cache in session
            $Script:CredentialCache[$Name] = $cred

            Write-Verbose "Retrieved credential '$Name' from store."
            return $cred
        }
        catch {
            Write-Warning "Failed to load credential '$Name': $_"
            # File may be corrupted or from different user
            Remove-Item $credPath -Force -ErrorAction SilentlyContinue
        }
    }

    # Prompt if requested
    if ($PromptIfMissing) {
        Write-Host ""
        Write-Host "Credential '$Name' not found in store." -ForegroundColor Yellow
        $cred = Get-Credential -Message $PromptMessage

        if ($cred) {
            # Ask if user wants to save it
            $save = Read-Host "Save this credential for future use? (y/n)"
            if ($save -eq 'y') {
                Save-StoredCredential -Name $Name -Credential $cred -Force
            } else {
                # Just cache in session
                $Script:CredentialCache[$Name] = $cred
            }
            return $cred
        }
    }

    return $null
}

<#
.SYNOPSIS
    Removes a stored credential.
.PARAMETER Name
    The name/identifier of the credential to remove
#>
function Remove-StoredCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    # Remove from session cache
    if ($Script:CredentialCache.ContainsKey($Name)) {
        $Script:CredentialCache.Remove($Name)
    }

    Initialize-CredentialStore

    $credPath = Join-Path $Script:CredentialStorePath "$Name.cred"

    if (Test-Path $credPath) {
        Remove-Item $credPath -Force
        Write-Verbose "Credential '$Name' removed."
        return $true
    }

    Write-Warning "Credential '$Name' not found."
    return $false
}

<#
.SYNOPSIS
    Lists all stored credentials.
.OUTPUTS
    Array of credential names
#>
function Get-StoredCredentialList {
    [CmdletBinding()]
    param()

    Initialize-CredentialStore

    $credentials = @()

    # Get from file store
    if (Test-Path $Script:CredentialStorePath) {
        Get-ChildItem -Path $Script:CredentialStorePath -Filter "*.cred" | ForEach-Object {
            $name = $_.BaseName
            $credentials += [PSCustomObject]@{
                Name = $name
                InCache = $Script:CredentialCache.ContainsKey($name)
                LastModified = $_.LastWriteTime
                Path = $_.FullName
            }
        }
    }

    # Add any that are only in session cache
    foreach ($name in $Script:CredentialCache.Keys) {
        if (-not ($credentials | Where-Object { $_.Name -eq $name })) {
            $credentials += [PSCustomObject]@{
                Name = $name
                InCache = $true
                LastModified = $null
                Path = "(session only)"
            }
        }
    }

    return $credentials
}

<#
.SYNOPSIS
    Clears the session credential cache.
.DESCRIPTION
    Removes all credentials from the in-memory cache.
    Does not affect stored credentials on disk.
#>
function Clear-CredentialCache {
    [CmdletBinding()]
    param()

    $count = $Script:CredentialCache.Count
    $Script:CredentialCache = @{}
    Write-Verbose "Cleared $count credentials from session cache."
}

<#
.SYNOPSIS
    Tests if a stored credential is valid.
.DESCRIPTION
    Attempts to use the credential to verify it works.
.PARAMETER Name
    The name of the stored credential to test
.PARAMETER ComputerName
    Optional computer name to test against (uses WinRM)
#>
function Test-StoredCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$ComputerName = $env:COMPUTERNAME
    )

    $cred = Get-StoredCredential -Name $Name
    if (-not $cred) {
        return [PSCustomObject]@{
            Name = $Name
            IsValid = $false
            Error = "Credential not found"
        }
    }

    try {
        # Test using WinRM
        $null = Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop

        return [PSCustomObject]@{
            Name = $Name
            IsValid = $true
            TestedAgainst = $ComputerName
            Username = $cred.UserName
        }
    }
    catch {
        return [PSCustomObject]@{
            Name = $Name
            IsValid = $false
            Error = $_.Exception.Message
            Username = $cred.UserName
        }
    }
}

<#
.SYNOPSIS
    Gets or creates a credential for use in scripts.
.DESCRIPTION
    Convenience function that combines getting stored credentials
    with prompting for new ones. Ideal for scripts that need credentials.
.PARAMETER Name
    Name/identifier for the credential
.PARAMETER Message
    Custom prompt message
.PARAMETER SaveIfNew
    Automatically save new credentials without prompting
#>
function Get-ScriptCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Message = "Enter credentials for remote operations",

        [switch]$SaveIfNew,

        [switch]$ForceNew
    )

    if ($ForceNew) {
        $cred = Get-Credential -Message $Message
        if ($cred -and $SaveIfNew) {
            Save-StoredCredential -Name $Name -Credential $cred -Force
        } elseif ($cred) {
            $Script:CredentialCache[$Name] = $cred
        }
        return $cred
    }

    # Try to get existing
    $cred = Get-StoredCredential -Name $Name
    if ($cred) {
        return $cred
    }

    # Prompt for new
    $cred = Get-Credential -Message $Message
    if ($cred) {
        if ($SaveIfNew) {
            Save-StoredCredential -Name $Name -Credential $cred -Force
        } else {
            $Script:CredentialCache[$Name] = $cred
        }
    }

    return $cred
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-CredentialStore',
    'Save-StoredCredential',
    'Get-StoredCredential',
    'Remove-StoredCredential',
    'Get-StoredCredentialList',
    'Clear-CredentialCache',
    'Test-StoredCredential',
    'Get-ScriptCredential'
)
