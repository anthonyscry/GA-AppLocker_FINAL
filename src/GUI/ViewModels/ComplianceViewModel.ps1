<#
.SYNOPSIS
    Compliance scanning and reporting ViewModel

.DESCRIPTION
    Manages compliance data including computer scan lists, evidence packages,
    and compliance status tracking for the Compliance Reporting panel.

.NOTES
    Module Name: ComplianceViewModel
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: BusinessLogic/ComplianceReporter

.EXAMPLE
    Import-Module .\ComplianceViewModel.ps1

    # Initialize and add computers
    Initialize-ComplianceData
    Add-Computer -ComputerName "PC01" -Description "Finance Department"
    $computers = Get-ComputerList

.EXAMPLE
    # Update compliance status
    Update-ComplianceStatus -ComputerName "PC01" -Status "Completed" -Score 85

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# SCRIPT-SCOPE STATE
# ============================================================

$script:ComplianceData = [hashtable]::Synchronized(@{
    ScanSessionId = ""
    ScanStartTime = $null
    ScanEndTime = $null
    ScanStatus = "NotStarted"  # NotStarted, InProgress, Completed, Failed
    OutputDirectory = ""
    TotalComputers = 0
    CompletedScans = 0
    FailedScans = 0
})

$script:ComputerList = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$script:EvidencePackages = [hashtable]::Synchronized(@{})

$script:ComplianceStatistics = [hashtable]::Synchronized(@{
    AverageComplianceScore = 0
    HighestScore = 0
    LowestScore = 0
    CompliantComputers = 0
    NonCompliantComputers = 0
    TotalArtifactsCollected = 0
    TotalEventsCollected = 0
})

# ============================================================
# PUBLIC FUNCTIONS - INITIALIZATION & DATA RETRIEVAL
# ============================================================

function Initialize-ComplianceData {
    <#
    .SYNOPSIS
        Initializes the compliance data

    .DESCRIPTION
        Resets compliance state and prepares for a new scan session

    .EXAMPLE
        Initialize-ComplianceData
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Initializing compliance data..."

        # Generate new session ID
        $script:ComplianceData.ScanSessionId = "SCAN_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $script:ComplianceData.ScanStartTime = $null
        $script:ComplianceData.ScanEndTime = $null
        $script:ComplianceData.ScanStatus = "NotStarted"
        $script:ComplianceData.OutputDirectory = ""
        $script:ComplianceData.TotalComputers = 0
        $script:ComplianceData.CompletedScans = 0
        $script:ComplianceData.FailedScans = 0

        # Clear computer list
        $script:ComputerList.Clear()

        # Clear evidence packages
        $script:EvidencePackages.Clear()

        # Reset statistics
        Update-ComplianceStatistics

        Write-Verbose "Compliance data initialized (Session: $($script:ComplianceData.ScanSessionId))"
        return @{
            success = $true
            message = "Compliance data initialized"
            sessionId = $script:ComplianceData.ScanSessionId
        }
    }
    catch {
        Write-Warning "Failed to initialize compliance data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-ComplianceData {
    <#
    .SYNOPSIS
        Gets current compliance data

    .OUTPUTS
        Hashtable containing compliance session data

    .EXAMPLE
        $data = Get-ComplianceData
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            ScanSessionId = $script:ComplianceData.ScanSessionId
            ScanStartTime = $script:ComplianceData.ScanStartTime
            ScanEndTime = $script:ComplianceData.ScanEndTime
            ScanStatus = $script:ComplianceData.ScanStatus
            OutputDirectory = $script:ComplianceData.OutputDirectory
            TotalComputers = $script:ComplianceData.TotalComputers
            CompletedScans = $script:ComplianceData.CompletedScans
            FailedScans = $script:ComplianceData.FailedScans
            Progress = if ($script:ComplianceData.TotalComputers -gt 0) {
                [math]::Round(($script:ComplianceData.CompletedScans / $script:ComplianceData.TotalComputers) * 100, 2)
            } else { 0 }
        }
    }
    catch {
        Write-Warning "Failed to get compliance data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-ComputerList {
    <#
    .SYNOPSIS
        Gets the list of computers in the scan

    .PARAMETER IncludeDetails
        Whether to include full details (default: $true)

    .OUTPUTS
        Array of computer objects

    .EXAMPLE
        $computers = Get-ComputerList
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$IncludeDetails = $true
    )

    try {
        $computers = $script:ComputerList.ToArray()

        if ($IncludeDetails) {
            return $computers | ForEach-Object {
                [PSCustomObject]@{
                    ComputerName = $_.ComputerName
                    Description = $_.Description
                    Status = $_.Status
                    ComplianceScore = $_.ComplianceScore
                    StartTime = $_.StartTime
                    EndTime = $_.EndTime
                    Duration = if ($_.StartTime -and $_.EndTime) {
                        ($_.EndTime - $_.StartTime).TotalSeconds
                    } else { 0 }
                    ArtifactsCollected = $_.ArtifactsCollected
                    EventsCollected = $_.EventsCollected
                    ErrorMessage = $_.ErrorMessage
                    EvidencePackagePath = $_.EvidencePackagePath
                }
            }
        } else {
            return $computers | Select-Object ComputerName, Status, ComplianceScore
        }
    }
    catch {
        Write-Warning "Failed to get computer list: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================
# PUBLIC FUNCTIONS - COMPUTER MANAGEMENT
# ============================================================

function Add-Computer {
    <#
    .SYNOPSIS
        Adds a computer to the scan list

    .PARAMETER ComputerName
        Name of the computer

    .PARAMETER Description
        Optional description

    .EXAMPLE
        Add-Computer -ComputerName "PC01" -Description "Finance Workstation"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [string]$Description = ""
    )

    try {
        Write-Verbose "Adding computer to scan list: $ComputerName..."

        # Check if already exists
        $existing = $script:ComputerList | Where-Object { $_.ComputerName -eq $ComputerName } | Select-Object -First 1
        if ($existing) {
            Write-Warning "Computer already in list: $ComputerName"
            return @{ success = $false; message = "Computer already exists" }
        }

        # Create computer object
        $computer = [PSCustomObject]@{
            ComputerName = $ComputerName
            Description = $Description
            Status = "Pending"  # Pending, InProgress, Completed, Failed
            ComplianceScore = 0
            StartTime = $null
            EndTime = $null
            ArtifactsCollected = 0
            EventsCollected = 0
            ErrorMessage = ""
            EvidencePackagePath = ""
            AddedDate = Get-Date
        }

        [void]$script:ComputerList.Add($computer)
        $script:ComplianceData.TotalComputers = $script:ComputerList.Count

        Write-Verbose "Computer added: $ComputerName"
        return @{ success = $true; message = "Computer added"; computer = $computer }
    }
    catch {
        Write-Warning "Failed to add computer: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Add-Computers {
    <#
    .SYNOPSIS
        Adds multiple computers to the scan list

    .PARAMETER ComputerNames
        Array of computer names

    .EXAMPLE
        Add-Computers -ComputerNames @("PC01", "PC02", "PC03")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames
    )

    try {
        Write-Verbose "Adding $($ComputerNames.Count) computers to scan list..."

        $addedCount = 0
        $skippedCount = 0

        foreach ($computerName in $ComputerNames) {
            $result = Add-Computer -ComputerName $computerName
            if ($result.success) {
                $addedCount++
            } else {
                $skippedCount++
            }
        }

        Write-Verbose "Added $addedCount computers ($skippedCount skipped)"
        return @{
            success = $true
            message = "Added $addedCount computers"
            addedCount = $addedCount
            skippedCount = $skippedCount
        }
    }
    catch {
        Write-Warning "Failed to add computers: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Remove-Computer {
    <#
    .SYNOPSIS
        Removes a computer from the scan list

    .PARAMETER ComputerName
        Name of the computer to remove

    .EXAMPLE
        Remove-Computer -ComputerName "PC01"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    try {
        Write-Verbose "Removing computer from scan list: $ComputerName..."

        $computer = $script:ComputerList | Where-Object { $_.ComputerName -eq $ComputerName } | Select-Object -First 1

        if (-not $computer) {
            throw "Computer not found: $ComputerName"
        }

        [void]$script:ComputerList.Remove($computer)
        $script:ComplianceData.TotalComputers = $script:ComputerList.Count

        Write-Verbose "Computer removed: $ComputerName"
        return @{ success = $true; message = "Computer removed" }
    }
    catch {
        Write-Warning "Failed to remove computer: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-ComplianceStatus {
    <#
    .SYNOPSIS
        Updates the compliance status for a computer

    .PARAMETER ComputerName
        Name of the computer

    .PARAMETER Status
        Status: Pending, InProgress, Completed, Failed

    .PARAMETER ComplianceScore
        Optional compliance score (0-100)

    .PARAMETER ErrorMessage
        Optional error message if failed

    .EXAMPLE
        Update-ComplianceStatus -ComputerName "PC01" -Status "Completed" -ComplianceScore 85
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateSet("Pending", "InProgress", "Completed", "Failed")]
        [string]$Status,

        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$ComplianceScore,

        [Parameter()]
        [string]$ErrorMessage = "",

        [Parameter()]
        [int]$ArtifactsCollected = 0,

        [Parameter()]
        [int]$EventsCollected = 0,

        [Parameter()]
        [string]$EvidencePackagePath = ""
    )

    try {
        Write-Verbose "Updating compliance status for $ComputerName to $Status..."

        $computer = $script:ComputerList | Where-Object { $_.ComputerName -eq $ComputerName } | Select-Object -First 1

        if (-not $computer) {
            throw "Computer not found: $ComputerName"
        }

        # Update status
        $previousStatus = $computer.Status
        $computer.Status = $Status

        if ($Status -eq "InProgress" -and $previousStatus -ne "InProgress") {
            $computer.StartTime = Get-Date
        }

        if ($Status -eq "Completed" -or $Status -eq "Failed") {
            $computer.EndTime = Get-Date

            if ($Status -eq "Completed") {
                $script:ComplianceData.CompletedScans++
            } else {
                $script:ComplianceData.FailedScans++
            }
        }

        # Update optional fields
        if ($ComplianceScore) { $computer.ComplianceScore = $ComplianceScore }
        if ($ErrorMessage) { $computer.ErrorMessage = $ErrorMessage }
        if ($ArtifactsCollected -gt 0) { $computer.ArtifactsCollected = $ArtifactsCollected }
        if ($EventsCollected -gt 0) { $computer.EventsCollected = $EventsCollected }
        if ($EvidencePackagePath) { $computer.EvidencePackagePath = $EvidencePackagePath }

        # Update statistics
        Update-ComplianceStatistics

        Write-Verbose "Compliance status updated for $ComputerName"
        return @{ success = $true; message = "Status updated"; computer = $computer }
    }
    catch {
        Write-Warning "Failed to update compliance status: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - SCAN MANAGEMENT
# ============================================================

function Start-ComplianceScan {
    <#
    .SYNOPSIS
        Marks the compliance scan as started

    .PARAMETER OutputDirectory
        Directory for scan output

    .EXAMPLE
        Start-ComplianceScan -OutputDirectory "C:\Scans\Compliance"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )

    try {
        Write-Verbose "Starting compliance scan..."

        $script:ComplianceData.ScanStatus = "InProgress"
        $script:ComplianceData.ScanStartTime = Get-Date
        $script:ComplianceData.OutputDirectory = $OutputDirectory
        $script:ComplianceData.CompletedScans = 0
        $script:ComplianceData.FailedScans = 0

        # Reset all computer statuses to Pending
        foreach ($computer in $script:ComputerList) {
            $computer.Status = "Pending"
            $computer.StartTime = $null
            $computer.EndTime = $null
            $computer.ComplianceScore = 0
            $computer.ErrorMessage = ""
        }

        Write-Verbose "Compliance scan started"
        return @{ success = $true; message = "Scan started"; sessionId = $script:ComplianceData.ScanSessionId }
    }
    catch {
        Write-Warning "Failed to start compliance scan: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Complete-ComplianceScan {
    <#
    .SYNOPSIS
        Marks the compliance scan as completed

    .EXAMPLE
        Complete-ComplianceScan
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Completing compliance scan..."

        $script:ComplianceData.ScanStatus = "Completed"
        $script:ComplianceData.ScanEndTime = Get-Date

        Update-ComplianceStatistics

        Write-Verbose "Compliance scan completed"
        return @{ success = $true; message = "Scan completed" }
    }
    catch {
        Write-Warning "Failed to complete compliance scan: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-ReportData {
    <#
    .SYNOPSIS
        Prepares data for compliance reporting

    .OUTPUTS
        Hashtable containing report data

    .EXAMPLE
        $reportData = Get-ReportData
    #>
    [CmdletBinding()]
    param()

    try {
        $computers = Get-ComputerList -IncludeDetails $true
        $stats = Get-ComplianceStatistics

        return @{
            SessionId = $script:ComplianceData.ScanSessionId
            ScanStartTime = $script:ComplianceData.ScanStartTime
            ScanEndTime = $script:ComplianceData.ScanEndTime
            TotalDuration = if ($script:ComplianceData.ScanStartTime -and $script:ComplianceData.ScanEndTime) {
                ($script:ComplianceData.ScanEndTime - $script:ComplianceData.ScanStartTime).TotalMinutes
            } else { 0 }
            Statistics = $stats
            Computers = $computers
            Summary = @{
                TotalComputers = $script:ComplianceData.TotalComputers
                CompletedScans = $script:ComplianceData.CompletedScans
                FailedScans = $script:ComplianceData.FailedScans
                SuccessRate = if ($script:ComplianceData.TotalComputers -gt 0) {
                    [math]::Round(($script:ComplianceData.CompletedScans / $script:ComplianceData.TotalComputers) * 100, 2)
                } else { 0 }
            }
        }
    }
    catch {
        Write-Warning "Failed to get report data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-ComplianceStatistics {
    <#
    .SYNOPSIS
        Gets compliance statistics

    .OUTPUTS
        Hashtable containing statistics

    .EXAMPLE
        $stats = Get-ComplianceStatistics
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            AverageComplianceScore = $script:ComplianceStatistics.AverageComplianceScore
            HighestScore = $script:ComplianceStatistics.HighestScore
            LowestScore = $script:ComplianceStatistics.LowestScore
            CompliantComputers = $script:ComplianceStatistics.CompliantComputers
            NonCompliantComputers = $script:ComplianceStatistics.NonCompliantComputers
            TotalArtifactsCollected = $script:ComplianceStatistics.TotalArtifactsCollected
            TotalEventsCollected = $script:ComplianceStatistics.TotalEventsCollected
        }
    }
    catch {
        Write-Warning "Failed to get compliance statistics: $($_.Exception.Message)"
        return @{}
    }
}

function Clear-ComplianceData {
    <#
    .SYNOPSIS
        Clears all compliance data

    .EXAMPLE
        Clear-ComplianceData
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Clearing compliance data..."
        Initialize-ComplianceData
        return @{ success = $true; message = "Compliance data cleared" }
    }
    catch {
        Write-Warning "Failed to clear compliance data: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================

function Update-ComplianceStatistics {
    [CmdletBinding()]
    param()

    try {
        $computers = $script:ComputerList | Where-Object { $_.Status -eq "Completed" }

        if ($computers.Count -eq 0) {
            $script:ComplianceStatistics.AverageComplianceScore = 0
            $script:ComplianceStatistics.HighestScore = 0
            $script:ComplianceStatistics.LowestScore = 0
            $script:ComplianceStatistics.CompliantComputers = 0
            $script:ComplianceStatistics.NonCompliantComputers = 0
            $script:ComplianceStatistics.TotalArtifactsCollected = 0
            $script:ComplianceStatistics.TotalEventsCollected = 0
            return
        }

        $scores = $computers | Select-Object -ExpandProperty ComplianceScore
        $script:ComplianceStatistics.AverageComplianceScore = [math]::Round(($scores | Measure-Object -Average).Average, 2)
        $script:ComplianceStatistics.HighestScore = ($scores | Measure-Object -Maximum).Maximum
        $script:ComplianceStatistics.LowestScore = ($scores | Measure-Object -Minimum).Minimum

        $script:ComplianceStatistics.CompliantComputers = ($computers | Where-Object { $_.ComplianceScore -ge 70 }).Count
        $script:ComplianceStatistics.NonCompliantComputers = ($computers | Where-Object { $_.ComplianceScore -lt 70 }).Count

        $script:ComplianceStatistics.TotalArtifactsCollected = ($computers | Measure-Object -Property ArtifactsCollected -Sum).Sum
        $script:ComplianceStatistics.TotalEventsCollected = ($computers | Measure-Object -Property EventsCollected -Sum).Sum
    }
    catch {
        Write-Verbose "Failed to update compliance statistics: $($_.Exception.Message)"
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Initialize-ComplianceData',
    'Get-ComplianceData',
    'Get-ComputerList',
    'Add-Computer',
    'Add-Computers',
    'Remove-Computer',
    'Update-ComplianceStatus',
    'Start-ComplianceScan',
    'Complete-ComplianceScan',
    'Get-ReportData',
    'Get-ComplianceStatistics',
    'Clear-ComplianceData'
)
