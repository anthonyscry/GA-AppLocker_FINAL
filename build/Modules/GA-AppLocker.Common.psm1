#Requires -Version 5.1
<#
.SYNOPSIS
    GA-AppLocker Common Utilities Module
.DESCRIPTION
    Shared functions used across GA-AppLocker scripts.
#>

# ============================================================
# CONFIGURATION
# ============================================================

$script:DefaultOutputPath = "C:\GA-AppLocker\Scans"
$script:AaronLockerPaths = @(
    "C:\GA-AppLocker\AaronLocker-main\AaronLocker",
    "$env:ProgramData\GA-AppLocker\AaronLocker-main\AaronLocker",
    "$env:USERPROFILE\GA-AppLocker\AaronLocker-main\AaronLocker"
)

# ============================================================
# FUNCTIONS
# ============================================================

function Get-Timestamp {
    <#
    .SYNOPSIS
        Get formatted timestamp for file naming.
    #>
    return Get-Date -Format "yyyyMMdd-HHmmss"
}

function Get-ScanFolderPath {
    <#
    .SYNOPSIS
        Create and return scan folder path: OutputPath/HOSTNAME_TIMESTAMP
    .PARAMETER OutputPath
        Base output path.
    .PARAMETER ComputerName
        Computer name for folder.
    #>
    param(
        [string]$OutputPath = $script:DefaultOutputPath,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $timestamp = Get-Timestamp
    $folderName = "${ComputerName}_${timestamp}"
    $folderPath = Join-Path $OutputPath $folderName

    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }

    return $folderPath
}

function Find-AaronLockerRoot {
    <#
    .SYNOPSIS
        Find AaronLocker installation path.
    .OUTPUTS
        String path or $null if not found.
    #>
    foreach ($path in $script:AaronLockerPaths) {
        $configPath = Join-Path $path "Support\Config.ps1"
        if (Test-Path $configPath) {
            return $path
        }
    }
    return $null
}

function Write-Status {
    <#
    .SYNOPSIS
        Write colored status message.
    .PARAMETER Message
        Message to display.
    .PARAMETER Type
        Message type: Info, Success, Warning, Error
    #>
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )

    $color = switch ($Type) {
        "Info"    { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
    }

    Write-Host $Message -ForegroundColor $color
}

function Test-RemoteAccess {
    <#
    .SYNOPSIS
        Test if remote computer is accessible.
    .PARAMETER ComputerName
        Computer to test.
    .OUTPUTS
        Boolean indicating accessibility.
    #>
    param([string]$ComputerName)

    if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq ".") {
        return $true
    }

    return Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
}

function Export-ToCsv {
    <#
    .SYNOPSIS
        Export data to CSV with standard settings.
    .PARAMETER Data
        Data to export.
    .PARAMETER Path
        Output file path.
    #>
    param(
        [Parameter(ValueFromPipeline)]
        $Data,
        [string]$Path
    )

    process {
        $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

function Save-XmlPolicy {
    <#
    .SYNOPSIS
        Save XML with UTF-16 encoding (required for AppLocker).
    .PARAMETER XmlContent
        XML string or document.
    .PARAMETER Path
        Output file path.
    #>
    param(
        [Parameter(Mandatory)]
        $XmlContent,
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($XmlContent -is [string]) {
        $XmlContent | Out-File -FilePath $Path -Encoding Unicode
    } else {
        $XmlContent.Save($Path)
    }
}

# ============================================================
# EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Get-Timestamp',
    'Get-ScanFolderPath',
    'Find-AaronLockerRoot',
    'Write-Status',
    'Test-RemoteAccess',
    'Export-ToCsv',
    'Save-XmlPolicy'
)
