<#
.SYNOPSIS
    Policy version control and rollback management for AppLocker policies.

.DESCRIPTION
    Provides Git-like version control for AppLocker policies:
    - Automatic versioning with commit messages
    - Policy history browsing
    - Rollback to previous versions
    - Diff between versions
    - Branch support for testing variations

.NOTES
    Policies are stored with metadata in a structured repository.
#>

#Requires -Version 5.1

# Import error handling module
$errorHandlingPath = Join-Path $PSScriptRoot 'ErrorHandling.psm1'
if (Test-Path $errorHandlingPath) {
    Import-Module $errorHandlingPath -Force
}

# Repository configuration
$Script:RepositoryPath = $null
$Script:CurrentBranch = 'main'

<#
.SYNOPSIS
    Initializes a policy version control repository.

.PARAMETER Path
    Path where the repository will be created.

.EXAMPLE
    Initialize-PolicyRepository -Path "C:\AppLockerPolicies"
#>
function Initialize-PolicyRepository {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $Script:RepositoryPath = $Path

    # Create repository structure
    $folders = @(
        'versions',
        'branches',
        'branches\main',
        'staging',
        'archive'
    )

    foreach ($folder in $folders) {
        $folderPath = Join-Path $Path $folder
        if (-not (Test-Path $folderPath)) {
            New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        }
    }

    # Create repository metadata
    $repoMeta = @{
        Created = Get-Date -Format 'o'
        LastModified = Get-Date -Format 'o'
        CurrentBranch = 'main'
        DefaultBranch = 'main'
        VersionCount = 0
    }

    $metaPath = Join-Path $Path 'repository.json'
    $repoMeta | ConvertTo-Json | Out-File $metaPath -Encoding UTF8

    Write-Host "Policy repository initialized at: $Path" -ForegroundColor Green

    return $Path
}

<#
.SYNOPSIS
    Sets the active policy repository.

.PARAMETER Path
    Path to an existing repository.
#>
function Set-PolicyRepository {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path (Join-Path $_ 'repository.json') })]
        [string]$Path
    )

    $Script:RepositoryPath = $Path

    # Load repository metadata
    $metaPath = Join-Path $Path 'repository.json'
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    $Script:CurrentBranch = $meta.CurrentBranch

    Write-Verbose "Repository set to: $Path (branch: $($Script:CurrentBranch))"
}

<#
.SYNOPSIS
    Commits a policy to the repository.

.PARAMETER PolicyPath
    Path to the AppLocker policy XML file.

.PARAMETER Message
    Commit message describing the changes.

.PARAMETER Author
    Author name (defaults to current user).

.PARAMETER Tags
    Optional tags for categorization.

.EXAMPLE
    Save-PolicyVersion -PolicyPath .\policy.xml -Message "Added Chrome publisher rule"
#>
function Save-PolicyVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$PolicyPath,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Author = $env:USERNAME,

        [string[]]$Tags = @(),

        [string]$Branch
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set. Use Initialize-PolicyRepository or Set-PolicyRepository first."
    }

    $branch = if ($Branch) { $Branch } else { $Script:CurrentBranch }

    # Generate version ID
    $versionId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + (Get-Random -Minimum 1000 -Maximum 9999)

    # Read and validate policy
    [xml]$policyXml = Get-Content $PolicyPath -Raw

    # Calculate policy hash for change detection
    $policyHash = (Get-FileHash $PolicyPath -Algorithm SHA256).Hash.Substring(0, 16)

    # Count rules
    $ruleCount = @{}
    foreach ($collection in $policyXml.AppLockerPolicy.RuleCollection) {
        $count = ($collection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
        $ruleCount[$collection.Type] = $count
    }

    # Create version metadata
    $versionMeta = @{
        VersionId = $versionId
        Branch = $branch
        Timestamp = Get-Date -Format 'o'
        Author = $Author
        Message = $Message
        Tags = $Tags
        PolicyHash = $policyHash
        SourceFile = Split-Path $PolicyPath -Leaf
        RuleCounts = $ruleCount
        TotalRules = ($ruleCount.Values | Measure-Object -Sum).Sum
    }

    # Get previous version for parent reference
    $history = Get-PolicyHistory -Branch $branch -Limit 1
    if ($history) {
        $versionMeta.ParentVersion = $history[0].VersionId
    }

    # Create version folder
    $versionPath = Join-Path $Script:RepositoryPath "versions\$versionId"
    New-Item -ItemType Directory -Path $versionPath -Force | Out-Null

    # Save policy and metadata
    Copy-Item $PolicyPath -Destination (Join-Path $versionPath 'policy.xml')
    $versionMeta | ConvertTo-Json -Depth 5 | Out-File (Join-Path $versionPath 'version.json') -Encoding UTF8

    # Update branch pointer
    $branchPath = Join-Path $Script:RepositoryPath "branches\$branch"
    if (-not (Test-Path $branchPath)) {
        New-Item -ItemType Directory -Path $branchPath -Force | Out-Null
    }

    @{
        Head = $versionId
        LastModified = Get-Date -Format 'o'
    } | ConvertTo-Json | Out-File (Join-Path $branchPath 'HEAD.json') -Encoding UTF8

    # Update repository metadata
    $repoMetaPath = Join-Path $Script:RepositoryPath 'repository.json'
    $repoMeta = Get-Content $repoMetaPath -Raw | ConvertFrom-Json
    $repoMeta.LastModified = Get-Date -Format 'o'
    $repoMeta.VersionCount = ($repoMeta.VersionCount -as [int]) + 1
    $repoMeta | ConvertTo-Json | Out-File $repoMetaPath -Encoding UTF8

    Write-Host "Policy saved as version: $versionId" -ForegroundColor Green
    Write-Host "  Branch: $branch" -ForegroundColor Gray
    Write-Host "  Message: $Message" -ForegroundColor Gray
    Write-Host "  Rules: $($versionMeta.TotalRules)" -ForegroundColor Gray

    return [PSCustomObject]$versionMeta
}

<#
.SYNOPSIS
    Gets the history of policy versions.

.PARAMETER Branch
    Branch to get history from (defaults to current).

.PARAMETER Limit
    Maximum number of versions to return.

.PARAMETER IncludeAllBranches
    Include versions from all branches.
#>
function Get-PolicyHistory {
    [CmdletBinding()]
    param(
        [string]$Branch,

        [int]$Limit = 20,

        [switch]$IncludeAllBranches
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    $branch = if ($Branch) { $Branch } else { $Script:CurrentBranch }

    $versionsPath = Join-Path $Script:RepositoryPath 'versions'
    $versions = @()

    Get-ChildItem $versionsPath -Directory | ForEach-Object {
        $metaPath = Join-Path $_.FullName 'version.json'
        if (Test-Path $metaPath) {
            $meta = Get-Content $metaPath -Raw | ConvertFrom-Json

            if ($IncludeAllBranches -or $meta.Branch -eq $branch) {
                $versions += [PSCustomObject]@{
                    VersionId = $meta.VersionId
                    Branch = $meta.Branch
                    Timestamp = [datetime]$meta.Timestamp
                    Author = $meta.Author
                    Message = $meta.Message
                    Tags = $meta.Tags
                    TotalRules = $meta.TotalRules
                    PolicyHash = $meta.PolicyHash
                    Path = $_.FullName
                }
            }
        }
    }

    return $versions | Sort-Object Timestamp -Descending | Select-Object -First $Limit
}

<#
.SYNOPSIS
    Gets a specific policy version.

.PARAMETER VersionId
    The version ID to retrieve.

.PARAMETER OutputPath
    Optional path to export the policy.
#>
function Get-PolicyVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VersionId,

        [string]$OutputPath
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    $versionPath = Join-Path $Script:RepositoryPath "versions\$VersionId"

    if (-not (Test-Path $versionPath)) {
        throw "Version not found: $VersionId"
    }

    $metaPath = Join-Path $versionPath 'version.json'
    $policyPath = Join-Path $versionPath 'policy.xml'

    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    $policy = Get-Content $policyPath -Raw

    if ($OutputPath) {
        $policy | Out-File $OutputPath -Encoding UTF8
        Write-Host "Policy exported to: $OutputPath" -ForegroundColor Green
    }

    return [PSCustomObject]@{
        Metadata = $meta
        PolicyXml = $policy
        PolicyPath = $policyPath
    }
}

<#
.SYNOPSIS
    Restores a previous policy version.

.PARAMETER VersionId
    The version ID to restore.

.PARAMETER OutputPath
    Path where the restored policy will be saved.

.PARAMETER Message
    Commit message for the restore operation.

.PARAMETER Deploy
    Also deploy the restored policy locally.
#>
function Restore-PolicyVersion {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$VersionId,

        [string]$OutputPath = '.\restored-policy.xml',

        [string]$Message,

        [switch]$Deploy
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    # Get the version
    $version = Get-PolicyVersion -VersionId $VersionId

    if (-not $Message) {
        $Message = "Restored from version $VersionId"
    }

    if ($PSCmdlet.ShouldProcess($VersionId, "Restore policy version")) {
        # Export the policy
        $version.PolicyXml | Out-File $OutputPath -Encoding UTF8
        Write-Host "Policy restored to: $OutputPath" -ForegroundColor Green

        # Create a new version for the restore
        Save-PolicyVersion -PolicyPath $OutputPath -Message $Message -Tags @('restore', "from:$VersionId")

        # Deploy if requested
        if ($Deploy) {
            Write-Host "Deploying restored policy..." -ForegroundColor Yellow

            try {
                Set-AppLockerPolicy -XmlPolicy $OutputPath
                Write-Host "Policy deployed successfully!" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to deploy policy: $_"
            }
        }
    }

    return $version.Metadata
}

<#
.SYNOPSIS
    Compares two policy versions.

.PARAMETER Version1
    First version ID.

.PARAMETER Version2
    Second version ID (defaults to current HEAD).
#>
function Compare-PolicyVersions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Version1,

        [string]$Version2
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    # Get version 2 or HEAD
    if (-not $Version2) {
        $head = Get-PolicyHistory -Limit 1
        if (-not $head) {
            throw "No versions found in repository"
        }
        $Version2 = $head[0].VersionId
    }

    $v1 = Get-PolicyVersion -VersionId $Version1
    $v2 = Get-PolicyVersion -VersionId $Version2

    # Use the existing Compare-AppLockerPolicies function
    $scriptRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $scriptRoot 'utilities\Common.psm1') -Force

    $diff = Compare-AppLockerPolicies -ReferencePath $v1.PolicyPath -DifferencePath $v2.PolicyPath

    # Add version context
    $result = [PSCustomObject]@{
        Version1 = @{
            Id = $Version1
            Timestamp = $v1.Metadata.Timestamp
            Author = $v1.Metadata.Author
            Message = $v1.Metadata.Message
        }
        Version2 = @{
            Id = $Version2
            Timestamp = $v2.Metadata.Timestamp
            Author = $v2.Metadata.Author
            Message = $v2.Metadata.Message
        }
        AreIdentical = $diff.AreIdentical
        RulesAdded = $diff.RulesOnlyInDiff.Count
        RulesRemoved = $diff.RulesOnlyInRef.Count
        ModeChanges = $diff.ModeDifferences.Count
        Details = $diff
    }

    # Display summary
    Write-Host "`nPolicy Version Comparison" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Version 1: $Version1" -ForegroundColor Yellow
    Write-Host "  Date: $($v1.Metadata.Timestamp)" -ForegroundColor Gray
    Write-Host "  Author: $($v1.Metadata.Author)" -ForegroundColor Gray
    Write-Host "  Message: $($v1.Metadata.Message)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Version 2: $Version2" -ForegroundColor Yellow
    Write-Host "  Date: $($v2.Metadata.Timestamp)" -ForegroundColor Gray
    Write-Host "  Author: $($v2.Metadata.Author)" -ForegroundColor Gray
    Write-Host "  Message: $($v2.Metadata.Message)" -ForegroundColor Gray
    Write-Host ""

    if ($diff.AreIdentical) {
        Write-Host "Result: Versions are IDENTICAL" -ForegroundColor Green
    } else {
        Write-Host "Result: Versions are DIFFERENT" -ForegroundColor Yellow
        Write-Host "  Rules added: $($diff.RulesOnlyInDiff.Count)" -ForegroundColor Green
        Write-Host "  Rules removed: $($diff.RulesOnlyInRef.Count)" -ForegroundColor Red
        Write-Host "  Mode changes: $($diff.ModeDifferences.Count)" -ForegroundColor Yellow
    }

    return $result
}

<#
.SYNOPSIS
    Creates a new branch for policy testing.

.PARAMETER Name
    Branch name.

.PARAMETER FromBranch
    Source branch to copy from.
#>
function New-PolicyBranch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$FromBranch
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    $sourceBranch = if ($FromBranch) { $FromBranch } else { $Script:CurrentBranch }

    $branchPath = Join-Path $Script:RepositoryPath "branches\$Name"

    if (Test-Path $branchPath) {
        throw "Branch already exists: $Name"
    }

    # Create branch folder
    New-Item -ItemType Directory -Path $branchPath -Force | Out-Null

    # Copy HEAD from source branch
    $sourceHeadPath = Join-Path $Script:RepositoryPath "branches\$sourceBranch\HEAD.json"
    if (Test-Path $sourceHeadPath) {
        Copy-Item $sourceHeadPath -Destination (Join-Path $branchPath 'HEAD.json')
    }

    Write-Host "Created branch: $Name (from $sourceBranch)" -ForegroundColor Green

    return $Name
}

<#
.SYNOPSIS
    Switches to a different branch.

.PARAMETER Name
    Branch name to switch to.
#>
function Switch-PolicyBranch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    $branchPath = Join-Path $Script:RepositoryPath "branches\$Name"

    if (-not (Test-Path $branchPath)) {
        throw "Branch not found: $Name"
    }

    $Script:CurrentBranch = $Name

    # Update repository metadata
    $repoMetaPath = Join-Path $Script:RepositoryPath 'repository.json'
    $repoMeta = Get-Content $repoMetaPath -Raw | ConvertFrom-Json
    $repoMeta.CurrentBranch = $Name
    $repoMeta | ConvertTo-Json | Out-File $repoMetaPath -Encoding UTF8

    Write-Host "Switched to branch: $Name" -ForegroundColor Green

    # Show HEAD version
    $head = Get-PolicyHistory -Branch $Name -Limit 1
    if ($head) {
        Write-Host "  HEAD: $($head[0].VersionId) - $($head[0].Message)" -ForegroundColor Gray
    }
}

<#
.SYNOPSIS
    Lists all branches in the repository.
#>
function Get-PolicyBranches {
    [CmdletBinding()]
    param()

    if (-not $Script:RepositoryPath) {
        throw "No repository set."
    }

    $branchesPath = Join-Path $Script:RepositoryPath 'branches'

    $branches = Get-ChildItem $branchesPath -Directory | ForEach-Object {
        $headPath = Join-Path $_.FullName 'HEAD.json'
        $head = if (Test-Path $headPath) {
            Get-Content $headPath -Raw | ConvertFrom-Json
        } else {
            $null
        }

        $isCurrent = $_.Name -eq $Script:CurrentBranch

        [PSCustomObject]@{
            Name = $_.Name
            IsCurrent = $isCurrent
            HeadVersion = $head.Head
            LastModified = $head.LastModified
        }
    }

    return $branches
}

<#
.SYNOPSIS
    Shows a visual log of policy history.
#>
function Show-PolicyLog {
    [CmdletBinding()]
    param(
        [int]$Limit = 10,

        [switch]$AllBranches
    )

    $history = Get-PolicyHistory -Limit $Limit -IncludeAllBranches:$AllBranches

    Write-Host "`nPolicy History" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    Write-Host ""

    $currentBranch = $Script:CurrentBranch

    foreach ($version in $history) {
        $branchIndicator = if ($version.Branch -eq $currentBranch) { '*' } else { ' ' }
        $branchColor = if ($version.Branch -eq $currentBranch) { 'Green' } else { 'Gray' }

        Write-Host "$branchIndicator " -NoNewline -ForegroundColor $branchColor
        Write-Host "$($version.VersionId.Substring(0, 15))" -NoNewline -ForegroundColor Yellow
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($version.Branch.PadRight(10))" -NoNewline -ForegroundColor $branchColor
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($version.Author.PadRight(12))" -NoNewline -ForegroundColor Cyan
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($version.Message)" -ForegroundColor White
    }

    Write-Host ""
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-PolicyRepository',
    'Set-PolicyRepository',
    'Save-PolicyVersion',
    'Get-PolicyHistory',
    'Get-PolicyVersion',
    'Restore-PolicyVersion',
    'Compare-PolicyVersions',
    'New-PolicyBranch',
    'Switch-PolicyBranch',
    'Get-PolicyBranches',
    'Show-PolicyLog'
)
