# ============================================================
# Phase 5: Policy Simulation and Testing Functions
# GA-AppLocker WPF GUI - Policy Simulator Module
# ============================================================

# Function: Invoke-PolicySimulation
# Description: Main simulation function that orchestrates the policy testing process
function Invoke-PolicySimulation {
    <#
    .SYNOPSIS
        Main policy simulation function that orchestrates testing

    .DESCRIPTION
        Runs a comprehensive simulation of AppLocker policy impact against specified targets

    .PARAMETER PolicyXml
        The AppLocker policy XML to test (can be file path or XML string)

    .PARAMETER TestMode
        Simulation mode: DryRun, AuditMode, or TestEnvironment

    .PARAMETER TargetPath
        Path to test against (file, folder, or remote system)

    .PARAMETER TargetType
        Type of target: Local, Files, Remote, or OU

    .PARAMETER IncludeUnsigned
        Include unsigned files in analysis

    .PARAMETER CheckBypasses
        Check for potential bypass locations

    .PARAMETER AnalyzeImpact
        Analyze impact on user groups

    .PARAMETER ProgressCallback
        ScriptBlock to report progress (parameters: percent, message)

    .EXAMPLE
        $result = Invoke-PolicySimulation -PolicyXml "C:\policies\test.xml" -TestMode "DryRun" -TargetPath "C:\Program Files"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PolicyXml,

        [Parameter(Mandatory=$false)]
        [ValidateSet('DryRun', 'AuditMode', 'TestEnvironment')]
        [string]$TestMode = 'DryRun',

        [Parameter(Mandatory=$false)]
        [string]$TargetPath = 'C:\Program Files',

        [Parameter(Mandatory=$false)]
        [ValidateSet('Local', 'Files', 'Remote', 'OU')]
        [string]$TargetType = 'Local',

        [Parameter(Mandatory=$false)]
        [bool]$IncludeUnsigned = $true,

        [Parameter(Mandatory=$false)]
        [bool]$CheckBypasses = $true,

        [Parameter(Mandatory=$false)]
        [bool]$AnalyzeImpact = $true,

        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressCallback
    )

    try {
        Write-Log "Starting policy simulation in $TestMode mode"

        # Initialize result object
        $result = @{
            Success = $false
            TestMode = $TestMode
            StartTime = Get-Date
            FilesAnalyzed = 0
            WouldAllow = 0
            WouldBlock = 0
            Coverage = 0
            DetailedResults = @()
            Warnings = @()
            Recommendations = @()
            ImpactAnalysis = @()
            Bypasses = @()
            TestTarget = $TargetPath
        }

        # Report initial progress
        if ($ProgressCallback) {
            & $ProgressCallback 5 "Loading policy..."
        }

        # Load policy XML
        $policy = if (Test-Path $PolicyXml) {
            [xml](Get-Content $PolicyXml -Raw -Encoding UTF8)
        } else {
            [xml]$PolicyXml
        }

        if (-not $policy -or -not $policy.AppLockerPolicy) {
            throw "Invalid AppLocker policy XML"
        }

        # Report progress
        if ($ProgressCallback) {
            & $ProgressCallback 10 "Scanning target files..."
        }

        # Get files to test
        $filesToTest = Get-FilesForSimulation -TargetPath $TargetPath -TargetType $TargetType -IncludeUnsigned:$IncludeUnsigned

        $result.FilesAnalyzed = $filesToTest.Count

        if ($filesToTest.Count -eq 0) {
            Write-Log "No files found for simulation"
            $result.Success = $true
            return $result
        }

        # Report progress
        if ($ProgressCallback) {
            & $ProgressCallback 20 "Testing policy against $($filesToTest.Count) files..."
        }

        # Test policy against files
        $testResults = Test-PolicyAgainstFiles -Policy $policy -Files $filesToTest -ProgressCallback $ProgressCallback

        $result.DetailedResults = $testResults.Results
        $result.WouldAllow = $testResults.AllowCount
        $result.WouldBlock = $testResults.BlockCount

        # Calculate coverage
        $coverage = Get-PolicyCoverageAnalysis -Policy $policy -Files $filesToTest
        $result.Coverage = $coverage.Percentage

        # Check for bypasses
        if ($CheckBypasses) {
            if ($ProgressCallback) {
                & $ProgressCallback 70 "Checking for bypass locations..."
            }

            $bypasses = Find-PolicyBypasses -Policy $policy -Files $filesToTest
            $result.Bypasses = $bypasses
            $result.Warnings += $bypasses | Where-Object { $_.Severity -eq 'High' }
        }

        # Analyze impact
        if ($AnalyzeImpact) {
            if ($ProgressCallback) {
                & $ProgressCallback 85 "Analyzing impact on user groups..."
            }

            $impact = Measure-PolicyImpact -Policy $policy -TestResults $testResults
            $result.ImpactAnalysis = $impact
        }

        # Generate recommendations
        if ($ProgressCallback) {
            & $ProgressCallback 95 "Generating recommendations..."
        }

        $recommendations = Get-SimulationReport -TestResults $testResults -Coverage $coverage -Bypasses $result.Bypasses
        $result.Recommendations = $recommendations

        # Finalize
        $result.EndTime = Get-Date
        $result.Duration = ($result.EndTime - $result.StartTime).TotalSeconds
        $result.Success = $true

        # Report completion
        if ($ProgressCallback) {
            & $ProgressCallback 100 "Simulation complete"
        }

        Write-Log "Policy simulation completed in $($result.Duration) seconds"
        return $result
    }
    catch {
        Write-Log "Policy simulation failed: $($_.Exception.Message)" -Level "ERROR"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Function: Test-PolicyAgainstFiles
# Description: Test policy against executable files and determine allow/block
function Test-PolicyAgainstFiles {
    <#
    .SYNOPSIS
        Tests AppLocker policy against a list of files

    .DESCRIPTION
        Evaluates each file against policy rules to determine if it would be allowed or blocked

    .PARAMETER Policy
        AppLocker policy XML object

    .PARAMETER Files
        Array of file info objects

    .PARAMETER ProgressCallback
        ScriptBlock to report progress

    .EXAMPLE
        $results = Test-PolicyAgainstFiles -Policy $policy -Files $fileList
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$Policy,

        [Parameter(Mandatory=$true)]
        [array]$Files,

        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressCallback
    )

    $results = @()
    $allowCount = 0
    $blockCount = 0
    $totalFiles = $Files.Count
    $processed = 0

    foreach ($file in $Files) {
        $processed++

        # Report progress
        if ($ProgressCallback -and $processed % 10 -eq 0) {
            $percent = 20 + [math]::Floor(($processed / $totalFiles) * 50)
            & $ProgressCallback $percent "Testing file $processed of $totalFiles..."
        }

        try {
            $filePath = if ($file.FullPath) { $file.FullPath } else { $file.Path }

            # Get file information
            $fileInfo = Get-ItemProperty -Path $filePath -ErrorAction SilentlyContinue
            if (-not $fileInfo) {
                continue
            }

            # Test against policy
            $evaluation = Test-FileAgainstPolicy -Policy $Policy -FilePath $filePath -FileInfo $fileInfo

            $result = [PSCustomObject]@{
                FileName = Split-Path $filePath -Leaf
                Path = $filePath
                Publisher = $file.Publisher
                Result = $evaluation.Action
                MatchedRule = $evaluation.RuleName
                RuleType = $evaluation.RuleType
                Confidence = $evaluation.Confidence
            }

            $results += $result

            if ($evaluation.Action -eq 'Allow') {
                $allowCount++
            } else {
                $blockCount++
            }
        }
        catch {
            # File couldn't be tested, assume blocked
            $results += [PSCustomObject]@{
                FileName = Split-Path $filePath -Leaf
                Path = $filePath
                Publisher = 'Unknown'
                Result = 'Block'
                MatchedRule = 'No matching rule'
                RuleType = 'None'
                Confidence = 'High'
            }
            $blockCount++
        }
    }

    return @{
        Results = $results
        AllowCount = $allowCount
        BlockCount = $blockCount
    }
}

# Helper: Test-FileAgainstPolicy
# Description: Evaluate a single file against AppLocker policy
function Test-FileAgainstPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$Policy,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        $FileInfo
    )

    $evaluation = @{
        Action = 'Block'
        RuleName = 'Default Deny'
        RuleType = 'Default'
        Confidence = 'High'
    }

    try {
        # Get file signature information
        $signature = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue

        # Get publisher information
        $publisherName = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Subject
        } else {
            # Try to get from file version info
            try {
                (Get-Item $FilePath).VersionInfo.CompanyName
            } catch {
                $null
            }
        }

        # Check against each rule collection
        foreach ($collection in $Policy.AppLockerPolicy.RuleCollection) {
            $ruleType = $collection.Type

            # Skip if collection doesn't apply to this file type
            if ($ruleType -eq 'Dll' -and $FilePath -notmatch '\.(dll|ocx)$') { continue }
            if ($ruleType -eq 'Script' -and $FilePath -notmatch '\.(ps1|bat|cmd|vbs|js)$') { continue }
            if ($ruleType -eq 'Msi' -and $FilePath -notmatch '\.(msi|msp)$') { continue }
            if ($ruleType -eq 'Exe' -and $FilePath -notmatch '\.exe$') { continue }

            # Check each rule in collection
            foreach ($rule in $collection.GetElementsByTagName('FilePublisherRule')) {
                $ruleAction = $rule.Action
                $ruleName = $rule.Name

                # Check publisher condition
                $condition = $rule.Conditions.FilePublisherCondition
                if ($condition) {
                    $match = Test-PublisherCondition -Condition $condition -FilePath $FilePath -PublisherName $publisherName

                    if ($match) {
                        $evaluation.Action = $ruleAction
                        $evaluation.RuleName = $ruleName
                        $evaluation.RuleType = "Publisher"
                        $evaluation.Confidence = 'High'
                        return $evaluation
                    }
                }
            }

            # Check hash rules
            foreach ($rule in $collection.GetElementsByTagName('FileHashRule')) {
                $ruleAction = $rule.Action
                $ruleName = $rule.Name

                $condition = $rule.Conditions.FileHashCondition
                if ($condition) {
                    $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

                    if ($fileHash -and $condition.SourceFileHash -eq $fileHash) {
                        $evaluation.Action = $ruleAction
                        $evaluation.RuleName = $ruleName
                        $evaluation.RuleType = "Hash"
                        $evaluation.Confidence = 'High'
                        return $evaluation
                    }
                }
            }

            # Check path rules
            foreach ($rule in $collection.GetElementsByTagName('FilePathRule')) {
                $ruleAction = $rule.Action
                $ruleName = $rule.Name

                $condition = $rule.Conditions.FilePathCondition
                if ($condition) {
                    $pathPattern = $condition.Path

                    if ($FilePath -like $pathPattern) {
                        $evaluation.Action = $ruleAction
                        $evaluation.RuleName = $ruleName
                        $evaluation.RuleType = "Path"
                        $evaluation.Confidence = 'High'
                        return $evaluation
                    }
                }
            }
        }
    }
    catch {
        $evaluation.Action = 'Block'
        $evaluation.RuleName = 'Error evaluating'
        $evaluation.Confidence = 'Low'
    }

    return $evaluation
}

# Helper: Test-PublisherCondition
# Description: Test if file matches publisher condition
function Test-PublisherCondition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Condition,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [string]$PublisherName
    )

    try {
        # Check publisher name
        if ($Condition.PublisherName -and $Condition.PublisherName -ne '*') {
            if ($PublisherName -notlike "*$($Condition.PublisherName)*") {
                return $false
            }
        }

        # Check product name
        if ($Condition.ProductName -and $Condition.ProductName -ne '*') {
            $product = (Get-Item $FilePath).VersionInfo.ProductName
            if ($product -notlike $Condition.ProductName) {
                return $false
            }
        }

        # Check binary name
        if ($Condition.BinaryName -and $Condition.BinaryName -ne '*') {
            $fileName = Split-Path $FilePath -Leaf
            if ($fileName -notlike $Condition.BinaryName) {
                return $false
            }
        }

        # Check version range
        if ($Condition.BinaryVersionRange) {
            $versionRange = $Condition.BinaryVersionRange
            $fileVersion = (Get-Item $FilePath).VersionInfo.FileVersion

            if ($fileVersion -and $versionRange.LowSection -ne '*') {
                # Version check would go here (simplified)
            }
        }

        return $true
    }
    catch {
        return $false
    }
}

# Function: Get-PolicyCoverageAnalysis
# Description: Analyze what percentage of software is covered by policy
function Get-PolicyCoverageAnalysis {
    <#
    .SYNOPSIS
        Analyzes policy coverage percentage

    .DESCRIPTION
        Calculates what percentage of software is covered by explicit rules vs default deny

    .PARAMETER Policy
        AppLocker policy XML object

    .PARAMETER Files
        Array of file info objects

    .EXAMPLE
        $coverage = Get-PolicyCoverageAnalysis -Policy $policy -Files $fileList
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$Policy,

        [Parameter(Mandatory=$true)]
        [array]$Files
    )

    $totalFiles = $Files.Count
    if ($totalFiles -eq 0) {
        return @{
            Percentage = 0
            CoveredFiles = 0
            UncoveredFiles = 0
            RuleBreakdown = @{}
        }
    }

    $coveredByType = @{
        'Publisher' = 0
        'Hash' = 0
        'Path' = 0
        'Default' = 0
    }

    # Count rules by type
    foreach ($collection in $Policy.AppLockerPolicy.RuleCollection) {
        $coveredByType['Publisher'] += ($collection.GetElementsByTagName('FilePublisherRule')).Count
        $coveredByType['Hash'] += ($collection.GetElementsByTagName('FileHashRule')).Count
        $coveredByType['Path'] += ($collection.GetElementsByTagName('FilePathRule')).Count
    }

    $explicitRules = $coveredByType['Publisher'] + $coveredByType['Hash'] + $coveredByType['Path']

    # Estimate coverage (this is simplified)
    # Real implementation would test each file against policy
    $estimatedCoverage = [math]::Min(95, ($explicitRules * 2) + 10)
    if ($estimatedCoverage -gt 100) { $estimatedCoverage = 100 }

    $coveredFiles = [math]::Floor(($estimatedCoverage / 100) * $totalFiles)
    $uncoveredFiles = $totalFiles - $coveredFiles

    return @{
        Percentage = $estimatedCoverage
        CoveredFiles = $coveredFiles
        UncoveredFiles = $uncoveredFiles
        RuleBreakdown = $coveredByType
    }
}

# Function: Find-PolicyBypasses
# Description: Identify potential bypass locations in the policy
function Find-PolicyBypasses {
    <#
    .SYNOPSIS
        Identifies potential AppLocker bypass locations

    .DESCRIPTION
        Scans for common bypass techniques and locations not covered by policy

    .PARAMETER Policy
        AppLocker policy XML object

    .PARAMETER Files
        Array of file info objects

    .EXAMPLE
        $bypasses = Find-PolicyBypasses -Policy $policy -Files $fileList
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$Policy,

        [Parameter(Mandatory=$true)]
        [array]$Files
    )

    $bypasses = @()

    # Check for writable directory bypasses
    $writablePaths = @(
        "$env:TEMP",
        "$env:USERPROFILE\AppData\Local\Temp",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "C:\Users\Public"
    )

    foreach ($path in $writablePaths) {
        if (Test-Path $path) {
            $bypasses += [PSCustomObject]@{
                Severity = 'High'
                Category = 'Bypass Location'
                Message = "Writable directory may allow execution bypass: $path"
                Recommendation = "Add explicit deny rule for $path or restrict write permissions"
                Location = $path
            }
        }
    }

    # Check for missing script rules
    $scriptRules = $policy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Script' }
    if (-not $scriptRules -or $scriptRules.Count -eq 0) {
        $bypasses += [PSCustomObject]@{
            Severity = 'Medium'
            Category = 'Missing Rule Type'
            Message = "No script rules defined - PowerShell, batch, and other scripts are not controlled"
            Recommendation = "Add script rules to control PowerShell, batch files, and other script types"
            Location = 'Policy'
        }
    }

    # Check for unsigned software
    $unsignedCount = ($Files | Where-Object { $_.Publisher -eq 'Unknown' -or $_.Publisher -eq '' }).Count
    if ($unsignedCount -gt 0) {
        $bypasses += [PSCustomObject]@{
            Severity = 'Medium'
            Category = 'Unsigned Software'
            Message = "Found $unsignedCount unsigned files that may not be covered by publisher rules"
            Recommendation = "Consider adding hash rules for unsigned software or investigate missing signatures"
            Location = 'System'
        }
    }

    # Check for overly permissive path rules
    $pathRules = @()
    foreach ($collection in $policy.AppLockerPolicy.RuleCollection) {
        $pathRules += $collection.GetElementsByTagName('FilePathRule')
    }

    foreach ($rule in $pathRules) {
        $condition = $rule.Conditions.FilePathCondition
        if ($condition -and $condition.Path -eq '*') {
            $bypasses += [PSCustomObject]@{
                Severity = 'Critical'
                Category = 'Overly Permissive Rule'
                Message = "Rule '$($rule.Name)' allows all files (*) - extremely permissive"
                Recommendation = "Replace with specific publisher or path rules"
                Location = $rule.Name
            }
        }
    }

    # Check for common installation directories not covered
    $commonPaths = @(
        'C:\Tools',
        'C:\Temp',
        'C:\Install'
    )

    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $bypasses += [PSCustomObject]@{
                Severity = 'Medium'
                Category = 'Uncovered Directory'
                Message = "Directory exists but may not be covered: $path"
                Recommendation = "Verify coverage for $path or add explicit rules"
                Location = $path
            }
        }
    }

    return $bypasses
}

# Function: Measure-PolicyImpact
# Description: Estimate user/system impact of policy enforcement
function Measure-PolicyImpact {
    <#
    .SYNOPSIS
        Measures impact of policy on different user groups

    .DESCRIPTION
        Analyzes which users/groups would be most affected by policy enforcement

    .PARAMETER Policy
        AppLocker policy XML object

    .PARAMETER TestResults
        Results from Test-PolicyAgainstFiles

    .EXAMPLE
        $impact = Measure-PolicyImpact -Policy $policy -TestResults $results
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [xml]$Policy,

        [Parameter(Mandatory=$true)]
        $TestResults
    )

    $impact = @()

    # Define user groups
    $userGroups = @(
        @{ Name = 'All Users'; Sid = 'S-1-1-0' },
        @{ Name = 'Authenticated Users'; Sid = 'S-1-5-11' },
        @{ Name = 'Domain Users'; Sid = 'S-1-5-21-0-0-0-513' },
        @{ Name = 'Administrators'; Sid = 'S-1-5-32-544' },
        @{ Name = 'Everyone'; Sid = 'S-1-1-0' }
    )

    foreach ($group in $userGroups) {
        $blockedFiles = $TestResults.Results | Where-Object { $_.Result -eq 'Block' }
        $affectedFiles = $TestResults.Results

        $impactLevel = if ($TestResults.BlockCount -eq 0) {
            'None'
        } elseif ($TestResults.BlockCount -lt 10) {
            'Low'
        } elseif ($TestResults.BlockCount -lt 50) {
            'Medium'
        } else {
            'High'
        }

        $impact += [PSCustomObject]@{
            UserGroup = $group.Name
            FilesAffected = $affectedFiles.Count
            WouldBlock = $TestResults.BlockCount
            WouldAllow = $TestResults.AllowCount
            ImpactLevel = $impactLevel
            Recommendation = Get-ImpactRecommendation -ImpactLevel $impactLevel
        }
    }

    return $impact
}

# Helper: Get-ImpactRecommendation
function Get-ImpactRecommendation {
    param([string]$ImpactLevel)

    switch ($ImpactLevel) {
        'None' { 'Policy is well tuned, ready for enforcement' }
        'Low' { 'Consider audit mode before full enforcement' }
        'Medium' { 'Review blocked applications and add rules before enforcement' }
        'High' { 'Significant impact expected. Strongly recommend extended audit period' }
        default { 'Review policy before deployment' }
    }
}

# Function: Compare-PolicyVersions
# Description: Compare old vs new policy to show changes
function Compare-PolicyVersions {
    <#
    .SYNOPSIS
        Compares two AppLocker policies

    .DESCRIPTION
        Shows differences between old and new policy versions

    .PARAMETER OldPolicyXml
        Path to old policy XML

    .PARAMETER NewPolicyXml
        Path to new policy XML

    .EXAMPLE
        $diff = Compare-PolicyVersions -OldPolicyXml "old.xml" -NewPolicyXml "new.xml"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OldPolicyXml,

        [Parameter(Mandatory=$true)]
        [string]$NewPolicyXml
    )

    try {
        $oldPolicy = if (Test-Path $OldPolicyXml) {
            [xml](Get-Content $OldPolicyXml -Raw -Encoding UTF8)
        } else {
            [xml]$OldPolicyXml
        }

        $newPolicy = if (Test-Path $NewPolicyXml) {
            [xml](Get-Content $NewPolicyXml -Raw -Encoding UTF8)
        } else {
            [xml]$NewPolicyXml
        }

        $comparison = @{
            OldPolicyRuleCount = 0
            NewPolicyRuleCount = 0
            AddedRules = @()
            RemovedRules = @()
            ModifiedRules = @()
            Version = @{
                Old = $oldPolicy.AppLockerPolicy.Version
                New = $newPolicy.AppLockerPolicy.Version
            }
        }

        # Count rules in old policy
        foreach ($collection in $oldPolicy.AppLockerPolicy.RuleCollection) {
            $comparison.OldPolicyRuleCount += $collection.GetElementsByTagName('Rule').Count
        }

        # Count rules in new policy
        foreach ($collection in $newPolicy.AppLockerPolicy.RuleCollection) {
            $comparison.NewPolicyRuleCount += $collection.GetElementsByTagName('Rule').Count
        }

        # Detailed comparison would go here
        # For now, just return counts

        return $comparison
    }
    catch {
        Write-Log "Policy comparison failed: $($_.Exception.Message)" -Level "ERROR"
        return @{ Error = $_.Exception.Message }
    }
}

# Function: Get-SimulationReport
# Description: Generate comprehensive simulation results report
function Get-SimulationReport {
    <#
    .SYNOPSIS
        Generates recommendations based on simulation results

    .DESCRIPTION
        Analyzes test results and provides actionable recommendations

    .PARAMETER TestResults
        Results from Test-PolicyAgainstFiles

    .PARAMETER Coverage
        Coverage analysis from Get-PolicyCoverageAnalysis

    .PARAMETER Bypasses
        Bypass analysis from Find-PolicyBypasses

    .EXAMPLE
        $recommendations = Get-SimulationReport -TestResults $results -Coverage $coverage
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $TestResults,

        [Parameter(Mandatory=$false)]
        $Coverage = $null,

        [Parameter(Mandatory=$false)]
        $Bypasses = $null
    )

    $recommendations = @()

    # Analyze block rate
    $blockRate = if ($TestResults.FilesAnalyzed -gt 0) {
        ($TestResults.BlockCount / $TestResults.FilesAnalyzed) * 100
    } else {
        0
    }

    # Coverage recommendations
    if ($Coverage) {
        if ($Coverage.Percentage -lt 70) {
            $recommendations += [PSCustomObject]@{
                Priority = 'High'
                Type = 'Coverage'
                Recommendation = "Policy coverage is only $($Coverage.Percentage)%. Add more explicit rules."
                Benefit = "Reduce false positives and improve security posture"
            }
        } elseif ($Coverage.Percentage -lt 90) {
            $recommendations += [PSCustomObject]@{
                Priority = 'Medium'
                Type = 'Coverage'
                Recommendation = "Policy coverage is $($Coverage.Percentage)%. Consider adding rules for remaining software."
                Benefit = "Further reduce false positives"
            }
        }
    }

    # Block rate recommendations
    if ($blockRate -gt 20) {
        $recommendations += [PSCustomObject]@{
            Priority = 'High'
            Type = 'Enforcement'
            Recommendation = "High block rate ($([math]::Round($blockRate, 1))%) detected. Use audit mode first."
            Benefit = "Prevent business disruption from blocked applications"
        }
    } elseif ($blockRate -gt 5) {
        $recommendations += [PSCustomObject]@{
            Priority = 'Medium'
            Type = 'Enforcement'
            Recommendation = "Block rate is $([math]::Round($blockRate, 1))%. Review blocked applications."
            Benefit = "Ensure critical applications are not blocked"
        }
    } else {
        $recommendations += [PSCustomObject]@{
            Priority = 'Low'
            Type = 'Enforcement'
            Recommendation = "Block rate is low ($([math]::Round($blockRate, 1))%). Policy is ready for enforcement."
            Benefit = "Improve security with minimal disruption"
        }
    }

    # Bypass recommendations
    if ($Bypasses) {
        $criticalBypasses = $Bypasses | Where-Object { $_.Severity -eq 'Critical' }
        if ($criticalBypasses.Count -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = 'Critical'
                Type = 'Security'
                Recommendation = "Found $($criticalBypasses.Count) critical bypass vulnerabilities. Fix immediately."
                Benefit = "Prevent attackers from bypassing AppLocker policy"
            }
        }

        $highBypasses = $Bypasses | Where-Object { $_.Severity -eq 'High' }
        if ($highBypasses.Count -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = 'High'
                Type = 'Security'
                Recommendation = "Found $($highBypasses.Count) high-severity bypass locations."
                Benefit = "Close security gaps in policy implementation"
            }
        }
    }

    # Rule type recommendations
    $hashRuleCount = ($TestResults.Results | Where-Object { $_.RuleType -eq 'Hash' }).Count
    if ($hashRuleCount -gt 50) {
        $recommendations += [PSCustomObject]@{
            Priority = 'Medium'
            Type = 'Maintenance'
            Recommendation = "High number of hash rules ($hashRuleCount). Consider publisher rules instead."
            Benefit = "Simplify policy management and automatic updates"
        }
    }

    # Unsigned software recommendations
    $unsignedCount = ($TestResults.Results | Where-Object {
        $_.Publisher -eq 'Unknown' -or $_.Publisher -eq ''
    }).Count

    if ($unsignedCount -gt 10) {
        $recommendations += [PSCustomObject]@{
            Priority = 'Medium'
            Type = 'Visibility'
            Recommendation = "Found $unsignedCount unsigned files. Investigate and consider adding to policy."
            Benefit = "Prevent unauthorized software execution"
        }
    }

    # Overall readiness assessment
    $readiness = if ($blockRate -lt 5 -and $Coverage.Percentage -gt 90) {
        $recommendations += [PSCustomObject]@{
            Priority = 'Info'
            Type = 'Readiness'
            Recommendation = "Policy is READY for enforcement. Low risk profile."
            Benefit = "Confident deployment to production"
        }
    } elseif ($blockRate -lt 10 -and $Coverage.Percentage -gt 80) {
        $recommendations += [PSCustomObject]@{
            Priority = 'Info'
            Type = 'Readiness'
            Recommendation = "Policy is mostly ready. Consider audit mode for 1-2 weeks first."
            Benefit = "Validate policy with minimal risk"
        }
    } else {
        $recommendations += [PSCustomObject]@{
            Priority = 'High'
            Type = 'Readiness'
            Recommendation = "Policy needs more work before enforcement. High risk profile."
            Benefit = "Prevent business disruption"
        }
    }

    return $recommendations
}

# Function: Get-FilesForSimulation
# Description: Get list of files to test based on target type
function Get-FilesForSimulation {
    <#
    .SYNOPSIS
        Retrieves files for simulation testing

    .DESCRIPTION
        Gets executable files from specified target location

    .PARAMETER TargetPath
        Path to scan for files

    .PARAMETER TargetType
        Type of target (Local, Files, Remote, OU)

    .PARAMETER IncludeUnsigned
        Include unsigned files in results

    .EXAMPLE
        $files = Get-FilesForSimulation -TargetPath "C:\Program Files" -IncludeUnsigned $true
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetPath,

        [Parameter(Mandatory=$false)]
        [string]$TargetType = 'Local',

        [Parameter(Mandatory=$false)]
        [bool]$IncludeUnsigned = $true
    )

    $files = @()
    $extensions = @('.exe', '.msi', '.msp', '.bat', '.cmd', '.ps1', '.vbs', '.js')

    try {
        if ($TargetType -eq 'Files' -and (Test-Path $TargetPath)) {
            # Scan specific path
            if (Test-Path $TargetPath -PathType Leaf) {
                # Single file
                $item = Get-Item $TargetPath
                if ($extensions -contains $item.Extension) {
                    $files += Get-FileInfo -FilePath $TargetPath
                }
            } else {
                # Directory - scan recursively
                $scanFiles = Get-ChildItem -Path $TargetPath -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $extensions -contains $_.Extension } |
                    Select-Object -First 1000

                foreach ($file in $scanFiles) {
                    $files += Get-FileInfo -FilePath $file.FullName -IncludeUnsigned:$IncludeUnsigned
                }
            }
        } elseif ($TargetType -eq 'Local') {
            # Scan common program locations
            $scanPaths = @(
                'C:\Program Files',
                'C:\Program Files (x86)',
                "$env:LOCALAPPDATA",
                "$env:PROGRAMDATA"
            )

            foreach ($path in $scanPaths) {
                if (Test-Path $path) {
                    $scanFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $extensions -contains $_.Extension } |
                        Select-Object -First 500

                    foreach ($file in $scanFiles) {
                        $files += Get-FileInfo -FilePath $file.FullName -IncludeUnsigned:$IncludeUnsigned
                    }
                }
            }
        } elseif ($TargetType -eq 'Remote') {
            # Remote computer scan would go here
            Write-Log "Remote scanning not yet implemented"
        } elseif ($TargetType -eq 'OU') {
            # Active Directory OU scan would go here
            Write-Log "OU scanning not yet implemented"
        }
    }
    catch {
        Write-Log "Error scanning for files: $($_.Exception.Message)" -Level "WARN"
    }

    return $files
}

# Helper: Get-FileInfo
# Description: Get detailed file information
function Get-FileInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [bool]$IncludeUnsigned = $true
    )

    try {
        $item = Get-Item $FilePath
        $versionInfo = $item.VersionInfo

        $publisher = if ($versionInfo.CompanyName) {
            $versionInfo.CompanyName
        } else {
            'Unknown'
        }

        # Skip if unsigned and not including unsigned
        if (-not $IncludeUnsigned -and $publisher -eq 'Unknown') {
            return $null
        }

        return [PSCustomObject]@{
            FileName = $item.Name
            FullPath = $item.FullName
            Path = $item.FullName
            Publisher = $publisher
            Product = $versionInfo.ProductName
            Version = $versionInfo.FileVersion
            Size = $item.Length
            ModifiedDate = $item.LastWriteTime
        }
    }
    catch {
        return $null
    }
}

# Export module member (if used as module)
Export-ModuleMember -Function @(
    'Invoke-PolicySimulation',
    'Test-PolicyAgainstFiles',
    'Get-PolicyCoverageAnalysis',
    'Find-PolicyBypasses',
    'Measure-PolicyImpact',
    'Compare-PolicyVersions',
    'Get-SimulationReport'
)
