# Module2-RemoteScan.psm1
# Remote Scan module for GA-AppLocker
# Discovers machines in AD and scans them for software artifacts

<#
.SYNOPSIS
    Get All AD Computers
.DESCRIPTION
    Retrieves all computers from Active Directory with properties
#>
function Get-AllADComputers {
    [CmdletBinding()]
    param(
        [int]$MaxResults = 500
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate, Description |
            Select-Object -First $MaxResults

        $results = @()
        foreach ($computer in $computers) {
            $dn = $computer.DistinguishedName
            $ou = ($dn -split ',', 2)[1]

            $results += @{
                hostname = $computer.Name
                os = $computer.OperatingSystem
                lastLogon = if ($computer.LastLogonDate) {
                    $computer.LastLogonDate.ToString('yyyy-MM-dd')
                } else { 'Never' }
                ou = $ou
                description = $computer.Description
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Get Computers by OU
.DESCRIPTION
    Retrieves computers from a specific Organizational Unit
#>
function Get-ComputersByOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OUPath
    )

    if ([string]::IsNullOrWhiteSpace($OUPath)) {
        return @{
            success = $false
            error = 'OU path is required'
            data = @()
        }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            success = $false
            error = 'ActiveDirectory module not available'
            data = @()
        }
    }

    try {
        $computers = Get-ADComputer -SearchBase $OUPath -SearchScope Subtree -Filter * `
            -Properties OperatingSystem, LastLogonDate

        $results = @()
        foreach ($computer in $computers) {
            $results += @{
                hostname = $computer.Name
                os = $computer.OperatingSystem
                lastLogon = if ($computer.LastLogonDate) {
                    $computer.LastLogonDate.ToString('yyyy-MM-dd')
                } else { 'Never' }
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
            ou = $OUPath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Test if Computer is Online
.DESCRIPTION
    Pings a computer to check if it's reachable
#>
function Test-ComputerOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return @{
            success = $false
            online = $false
            error = 'Computer name is required'
        }
    }

    $pingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue

    return @{
        success = $true
        computerName = $ComputerName
        online = $pingResult
    }
}

<#
.SYNOPSIS
    Scan Local Path for Executables
.DESCRIPTION
    Finds all EXE files in a folder and collects file information
#>
function Get-ExecutableArtifacts {
    [CmdletBinding()]
    param(
        [string]$TargetPath = 'C:\Program Files',
        [int]$MaxFiles = 500
    )

    if (-not (Test-Path $TargetPath)) {
        return @{
            success = $false
            error = "Path not found: $TargetPath"
            data = @()
        }
    }

    try {
        $files = Get-ChildItem -Path $TargetPath -Recurse -Include *.exe -ErrorAction SilentlyContinue |
            Select-Object -First $MaxFiles

        if (-not $files -or $files.Count -eq 0) {
            return @{
                success = $true
                data = @()
                message = "No executables found in $TargetPath"
            }
        }

        $results = @()
        foreach ($file in $files) {
            $filePath = $file.FullName
            $fileName = $file.Name

            # Get file hash
            $hashResult = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            $hash = if ($hashResult) { $hashResult.Hash } else { '' }

            # Get signature
            $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
            $publisher = 'Unknown'
            if ($signature -and $signature.SignerCertificate) {
                $subject = $signature.SignerCertificate.Subject
                if ($subject -match 'CN=([^,]+)') {
                    $publisher = $matches[1]
                }
            }

            $version = $file.VersionInfo.FileVersion

            $results += @{
                name = $fileName
                path = $filePath
                hash = $hash
                publisher = $publisher
                version = $version
                size = $file.Length
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
            scannedPath = $TargetPath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Scan Remote Computer for Artifacts
.DESCRIPTION
    Runs artifact scan on a remote computer via WinRM
#>
function Get-RemoteArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [PSCredential]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return @{
            success = $false
            error = 'Computer name is required'
            data = @()
        }
    }

    # Test WinRM
    $winrmTest = Test-WSMan -ComputerName $ComputerName -ErrorAction SilentlyContinue
    if (-not $winrmTest) {
        return @{
            success = $false
            error = "WinRM not available on '$ComputerName'"
            data = @()
        }
    }

    $scanScript = {
        $results = @()
        $paths = @('C:\Program Files', 'C:\Program Files (x86)')

        foreach ($path in $paths) {
            if (Test-Path $path) {
                $files = Get-ChildItem -Path $path -Recurse -Include *.exe -ErrorAction SilentlyContinue |
                    Select-Object -First 50

                foreach ($file in $files) {
                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                    $publisher = 'Unknown'
                    if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') {
                        $publisher = $matches[1]
                    }

                    $results += @{
                        name = $file.Name
                        path = $file.FullName
                        publisher = $publisher
                    }
                }
            }
        }

        return $results
    }

    try {
        if ($Credential) {
            $remoteResults = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scanScript -ErrorAction Stop
        }
        else {
            $remoteResults = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scanScript -ErrorAction Stop
        }

        return @{
            success = $true
            data = $remoteResults
            count = $remoteResults.Count
            computerName = $ComputerName
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

<#
.SYNOPSIS
    Export Scan Results to CSV
.DESCRIPTION
    Saves scan results to a CSV file
#>
function Export-ScanResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Artifacts,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if (-not $Artifacts -or $Artifacts.Count -eq 0) {
        return @{
            success = $false
            error = 'No artifacts to export'
        }
    }

    try {
        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $Artifacts | Export-Csv -Path $OutputPath -NoTypeInformation -Force

        return @{
            success = $true
            path = $OutputPath
            count = $Artifacts.Count
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Import Scan Results from CSV
.DESCRIPTION
    Loads previously saved scan results
#>
function Import-ScanResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path $CsvPath)) {
        return @{
            success = $false
            error = "File not found: $CsvPath"
            data = @()
        }
    }

    try {
        $data = Import-Csv -Path $CsvPath -ErrorAction Stop

        $artifacts = @()
        foreach ($row in $data) {
            $artifacts += @{
                name = $row.Name
                path = $row.Path
                publisher = $row.Publisher
                hash = $row.Hash
                version = $row.Version
            }
        }

        return @{
            success = $true
            data = $artifacts
            count = $artifacts.Count
            source = $CsvPath
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }
}

# Export functions
Export-ModuleMember -Function Get-AllADComputers, Get-ComputersByOU, Test-ComputerOnline,
                              Get-ExecutableArtifacts, Get-RemoteArtifacts,
                              Export-ScanResults, Import-ScanResults
