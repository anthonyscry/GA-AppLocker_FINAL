# Phase 5: Policy Simulation and Testing Mode - Implementation Guide

## Overview

This document describes the Policy Simulator implementation for the GA-AppLocker WPF PowerShell GUI. The Policy Simulator allows users to test AppLocker policies before deploying them to production, helping to identify potential issues and validate policy effectiveness.

## Files Created

The following files have been created as part of Phase 5 implementation:

1. **Phase5-PolicySimulator-Functions.ps1** (25 KB)
   - Core simulation functions
   - Policy testing logic
   - Coverage analysis
   - Bypass detection
   - Impact measurement

2. **Phase5-PolicySimulator-EventHandlers.ps1** (15 KB)
   - UI event handlers
   - Control initialization
   - Tab navigation
   - Report export

3. **Phase5-Integration-Script.ps1** (20 KB)
   - Automated integration script
   - Inserts panel XAML
   - Adds control references
   - Updates navigation

4. **Phase5-PolicySimulator-Panel.ps1** (2 KB)
   - Panel XAML reference
   - Export utility

5. **PolicySimulator-Panel-XAML.txt** (Generated)
   - Standalone panel XAML for reference

## Features Implemented

### 1. Policy Simulation Panel (XAML)

The panel includes:

- **Test Mode Selector**: Choose between Dry Run, Audit Mode, or Test Environment
- **Policy Selection**: Load and test policy XML files
- **Target Selection**: Test against local system, specific files/folders, remote computers, or OUs
- **Simulation Options**:
  - Include unsigned files
  - Check for bypass locations
  - Analyze user/system impact
- **Run Simulation Button**: Execute the simulation
- **Progress Indicator**: Real-time progress feedback
- **Results Tabs**:
  - Summary: High-level overview with statistics
  - Detailed Results: File-by-file analysis
  - Warnings: Policy issues and bypasses
  - Recommendations: Actionable improvements
- **Impact Analysis Grid**: User group impact assessment

### 2. Simulation Functions

#### Invoke-PolicySimulation
Main simulation orchestrator function.

**Parameters:**
- `PolicyXml`: Policy XML to test (file path or XML string)
- `TestMode`: DryRun, AuditMode, or TestEnvironment
- `TargetPath`: Path to test against
- `TargetType`: Local, Files, Remote, or OU
- `IncludeUnsigned`: Include unsigned files
- `CheckBypasses`: Check for bypass locations
- `AnalyzeImpact`: Analyze user/group impact
- `ProgressCallback`: Progress reporting callback

**Returns:**
```powershell
@{
    Success = $true/$false
    FilesAnalyzed = 1234
    WouldAllow = 1150
    WouldBlock = 84
    Coverage = 93
    DetailedResults = @(...)
    Warnings = @(...)
    Recommendations = @(...)
    ImpactAnalysis = @(...)
    Bypasses = @(...)
    Duration = 45.2
}
```

#### Test-PolicyAgainstFiles
Tests policy against executable files.

**Logic:**
1. Iterates through file list
2. Evaluates each file against policy rules
3. Checks publisher, hash, and path rules
4. Returns allow/block determination

#### Get-PolicyCoverageAnalysis
Analyzes policy coverage percentage.

**Calculates:**
- Overall coverage percentage
- Files covered vs. uncovered
- Rule type breakdown (Publisher, Hash, Path)

#### Find-PolicyBypasses
Identifies potential bypass locations.

**Checks for:**
- Writable directories (TEMP, AppData, etc.)
- Missing script rules
- Unsigned software
- Overly permissive path rules (*)
- Uncovered common directories

**Severity Levels:**
- Critical: Immediate security risk
- High: Significant vulnerability
- Medium: Potential issue
- Low: Minor concern

#### Measure-PolicyImpact
Estimates user/system impact.

**Analyzes:**
- Files affected per user group
- Block rate per group
- Impact level (None, Low, Medium, High)
- Recommendations for each group

#### Compare-PolicyVersions
Compares old vs. new policy.

**Shows:**
- Rule count changes
- Added/removed/modified rules
- Version differences

#### Get-SimulationReport
Generates recommendations based on results.

**Provides:**
- Coverage recommendations
- Enforcement readiness
- Security improvements
- Maintenance suggestions
- Overall readiness assessment

### 3. Test Mode Features

#### Dry Run Mode
- Shows what WOULD happen
- No changes made to system
- Pure analysis and prediction
- Fastest execution

#### Audit Mode
- Simulates audit-only enforcement
- Predicts what would be logged
- Helps understand event volume
- Validates logging configuration

#### Test Environment
- Deploys to test GPO
- Requires test GPO configuration
- Real-world validation
- Safe testing environment

### 4. Analysis Capabilities

#### Coverage Analysis by Software Type
- Executables (.exe)
- Installers (.msi, .msp)
- Scripts (.ps1, .bat, .cmd, .vbs, .js)
- DLLs (.dll, .ocx)

#### Impact Assessment by User Group
- All Users
- Authenticated Users
- Domain Users
- Administrators
- Everyone

#### Block/Allow Prediction
- Publisher rule matching
- Hash rule verification
- Path rule evaluation
- Default deny determination

#### Bypass Detection
Checks for:
- TEMP directory execution
- AppData bypass
- User profile execution
- Public folder execution
- Downloads folder execution
- Desktop execution

#### Missing Publisher Warnings
- Identifies unsigned software
- Flags missing signatures
- Recommends hash rules

#### Hash-Based Rule Recommendations
- Suggests hash rules for unsigned software
- Reduces publisher rule complexity
- Improves coverage

## Integration Steps

### Option 1: Automatic Integration (Recommended)

Run the integration script:

```powershell
cd C:\projects\GA-AppLocker_FINAL\build
.\Phase5-Integration-Script.ps1
```

This will:
1. Create backup of original file
2. Insert Policy Simulator panel XAML
3. Add control references
4. Add navigation event handler
5. Update Show-Panel function
6. Append simulation functions

### Option 2: Manual Integration

1. **Add Sidebar Navigation Button**

Insert into TESTING section expander in XAML (around line 2211):

```xml
<Expander x:Name="TestingSection" IsExpanded="True" Background="Transparent" BorderThickness="0" Margin="0,4,0,0">
    <Expander.Header>
        <TextBlock Text="TESTING" FontSize="10" FontWeight="Bold" Foreground="#58A6FF" VerticalAlignment="Center" Width="150"/>
    </Expander.Header>
    <StackPanel Margin="4,0,0,0">
        <Button x:Name="NavPolicySimulator" Content="Policy Simulator" Style="{StaticResource NavButton}"
                HorizontalAlignment="Stretch" Margin="10,1,5,1"/>
    </StackPanel>
</Expander>
```

2. **Insert Panel XAML**

Insert the complete panel XAML (from PolicySimulator-Panel-XAML.txt) before the closing `</Grid>` tag after PanelHelp (around line 4361).

3. **Add Control References**

Add after line 4194 (`$NavAbout = $window.FindName("NavAbout")`):

```powershell
$NavPolicySimulator = $window.FindName("NavPolicySimulator")
$TestingSection = $window.FindName("TestingSection")
# ... (all other simulator controls)
```

4. **Add Navigation Event Handler**

Add after line 7123 (after `$NavAbout.Add_Click`):

```powershell
$NavPolicySimulator.Add_Click({
    Show-Panel "PolicySimulator"
    Update-StatusBar
    Update-SimPolicySelector
})
```

5. **Update Show-Panel Function**

Add case in Show-Panel function (around line 7003):

```powershell
"PolicySimulator" { $PanelPolicySimulator.Visibility = [System.Windows.Visibility]::Visible }
```

6. **Append Simulation Functions**

Append the contents of Phase5-PolicySimulator-Functions.ps1 to the end of the main file.

7. **Add Event Handlers**

Append the event handlers from Phase5-PolicySimulator-EventHandlers.ps1 to the main file.

## Usage

### Basic Workflow

1. **Load the GUI**
   ```powershell
   .\GA-AppLocker-GUI-WPF.ps1
   ```

2. **Navigate to Policy Simulator**
   - Click "Policy Simulator" in the TESTING section

3. **Configure Simulation**
   - Select Test Mode (Dry Run recommended for first use)
   - Click "Load Policy XML" to load a policy file
   - Select target type and path
   - Configure simulation options

4. **Run Simulation**
   - Click "Run Policy Simulation"
   - Monitor progress indicator
   - Wait for completion

5. **Review Results**
   - Check Summary tab for overview
   - Review Detailed Results for file-by-file analysis
   - Check Warnings tab for issues
   - Read Recommendations tab for improvements
   - Review Impact Analysis grid

6. **Export Report**
   - Click "Export Full Report"
   - Save report for documentation

### Example Scenarios

#### Scenario 1: Test New Policy Before Deployment

```powershell
# In GUI:
1. Load new policy XML
2. Select "Dry Run" mode
3. Target: "Local System"
4. Enable all options
5. Run simulation
6. Review warnings and recommendations
7. Address critical issues before deployment
```

#### Scenario 2: Validate Policy Coverage

```powershell
# In GUI:
1. Load policy XML
2. Select "Audit Mode"
3. Target: Specific folder with common apps
4. Enable "Check for bypass locations"
5. Run simulation
6. Check coverage percentage
7. Review uncovered files
8. Add rules as needed
```

#### Scenario 3: Compare Policy Versions

```powershell
# PowerShell:
Compare-PolicyVersions -OldPolicyXml "old-policy.xml" -NewPolicyXml "new-policy.xml"
```

#### Scenario 4: Check for Bypasses

```powershell
# PowerShell:
$policy = [xml](Get-Content "policy.xml")
$files = Get-FilesForSimulation -TargetPath "C:\Program Files"
$bypasses = Find-PolicyBypasses -Policy $policy -Files $files
$bypasses | Format-Table Severity, Category, Message
```

## Troubleshooting

### Panel Not Appearing

**Check:**
1. PanelPolicySimulator control exists in XAML
2. Show-Panel function has PolicySimulator case
3. Navigation button is properly wired
4. No XAML parsing errors

**Solution:**
- Check GUI startup for errors
- Verify XAML syntax
- Check control names match

### Simulation Not Running

**Check:**
1. Policy XML is loaded
2. Target path is valid
3. Functions are sourced
4. No PowerShell errors

**Solution:**
- Load policy file first
- Verify target path exists
- Check function availability
- Review error messages

### Results Not Displaying

**Check:**
1. DataGrid.ItemsSource is set
2. Results object is not null
3. UI is on dispatcher thread
4. Proper property bindings

**Solution:**
- Verify result object structure
- Check data binding syntax
- Ensure UI updates on correct thread

## Performance Considerations

### Optimization Tips

1. **Limit File Count**
   - Use specific paths instead of entire drives
   - Start with small target areas
   - Increase scope gradually

2. **Cache Results**
   - Save simulation results
   - Compare against previous runs
   - Avoid re-scanning unchanged files

3. **Parallel Processing**
   - Use background jobs for large scans
   - Process multiple files simultaneously
   - Monitor memory usage

### Expected Performance

- Small scan (100 files): ~5-10 seconds
- Medium scan (1000 files): ~30-60 seconds
- Large scan (10000 files): ~5-10 minutes

## Security Considerations

### Best Practices

1. **Test in Isolated Environment**
   - Use test GPO before production
   - Validate in non-production environment
   - Never test directly on production systems

2. **Review Bypass Findings**
   - Address all critical bypasses
   - Document accepted risks
   - Implement compensating controls

3. **Validate Results**
   - Cross-check with manual testing
   - Verify critical applications
   - Test with different user contexts

### Limitations

1. **Simulation Accuracy**
   - Cannot predict all runtime behaviors
   - May miss environment-specific factors
   - Assumes standard AppLocker evaluation

2. **Scope Limitations**
   - Local testing only (remote not fully implemented)
   - File system scan limitations
   - Network path restrictions

## Future Enhancements

### Potential Improvements

1. **Remote Testing**
   - Full remote computer simulation
   - Batch testing across systems
   - Aggregate reporting

2. **OU-Based Testing**
   - Active Directory integration
   - GPO link validation
   - Group membership testing

3. **Advanced Analytics**
   - Machine learning predictions
   - Historical trend analysis
   - Anomaly detection

4. **Integration Features**
   - Direct GPO deployment
   - Automated rule generation
   - Continuous monitoring

## Support and Documentation

### Getting Help

1. Check this README first
2. Review inline function comments
3. Check GUI help panel
4. Review AppLocker documentation

### Reporting Issues

When reporting issues, include:
- GUI version
- Error messages
- Steps to reproduce
- Expected vs. actual behavior
- System information

## Version History

### Phase 5 (Current)
- Initial Policy Simulator implementation
- Dry Run, Audit Mode, Test Environment support
- Coverage analysis
- Bypass detection
- Impact measurement
- Comprehensive reporting

## License

Copyright 2026 GA-ASI. Internal use only.

---

**End of Phase 5 Implementation Guide**
