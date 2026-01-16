# GA-AppLocker UI Module

This directory contains extracted XAML and UI helper modules from the main GA-AppLocker GUI application.

## Contents

### MainWindow.xaml
The complete XAML definition for the GA-AppLocker Dashboard interface.

**Source:** Lines 3489-5895 from `build/GA-AppLocker-GUI-WPF.ps1`

**Key Features:**
- GitHub Dark theme styling (consistent colors and modern UI)
- Responsive grid layout with sidebar navigation
- 15+ panels for different features (Dashboard, Artifacts, Rules, Events, etc.)
- Custom styled controls (Buttons, ComboBoxes, DataGrids)
- Collapsible sidebar sections with Expanders
- Mini status bar with real-time indicators
- Chart and visualization placeholders (pie charts, gauges, bar charts)

**XAML Structure:**
```
Window (Root)
├── Window.Resources (Styles and Colors)
│   ├── Color Resources (BgDark, Blue, Green, etc.)
│   ├── Button Styles (PrimaryButton, SecondaryButton, NavButton)
│   ├── ComboBox Styles (DarkComboBoxStyle)
│   └── Expander Styles (MenuExpander)
├── Grid (Main Layout)
    ├── Header Border (Logo, Title, Mini Status Bar)
    ├── Environment Banner (Workspace controls)
    └── Main Content Grid
        ├── Sidebar (Navigation with Expanders)
        └── Content ScrollViewer (Panel Container)
            ├── PanelDashboard
            ├── PanelArtifacts
            ├── PanelRules
            ├── PanelEvents
            ├── PanelDeployment
            ├── PanelCompliance
            ├── PanelReports
            ├── PanelWinRM
            ├── PanelDiscovery
            ├── PanelGroupMgmt
            ├── PanelAppLockerSetup
            ├── PanelGapAnalysis
            ├── PanelTemplates
            ├── PanelHelp
            └── PanelAbout
```

**Editing in Visual Studio:**
1. Open MainWindow.xaml in Visual Studio (Community Edition or higher)
2. Use the XAML Designer for visual editing
3. Use IntelliSense for WPF controls and properties
4. Preview changes in the Design view
5. Theme colors are defined as StaticResources (modify in Window.Resources)

**Named Controls (x:Name attributes):**
All controls with `x:Name` can be accessed from PowerShell code using:
```powershell
$control = $window.FindName("ControlName")
```

Examples:
- `$NavDashboard` - Dashboard navigation button
- `$PanelRules` - Rules panel container
- `$StatusText` - Main status text block
- `$RulesDataGrid` - Rules data grid
- `$EventsOutput` - Events output text block

### UI-Helpers.ps1
PowerShell module containing UI utility functions.

**Extracted Functions:**

#### Show-Panel
Manages panel visibility by hiding all panels and showing the requested one.

```powershell
Show-Panel -PanelName "Dashboard"
Show-Panel -PanelName "Rules"
```

**Parameters:**
- `PanelName` - Name of the panel to show (Dashboard, Discovery, Artifacts, Rules, Deployment, Events, Compliance, Reports, WinRM, GroupMgmt, AppLockerSetup, GapAnalysis, Templates, Help, About)

#### Update-StatusBar
Updates all mini status indicators in the header.

```powershell
Update-StatusBar
```

**Updates:**
- Domain/Workgroup status
- Audit/Enforce mode indicator
- Deployment phase (P1-P4)
- Connected systems count
- Artifacts count
- Last sync time

#### Update-Badges
Updates the artifact and event count badges in the Rule Generator panel.

```powershell
Update-Badges
```

**Badge Indicators:**
- Artifact count (from `$script:CollectedArtifacts`)
- Event count (from `$script:AllEvents`)
- Color-coded based on data availability (green/blue if data present, gray if empty)

#### Get-SelectedSid
Resolves the currently selected group in the Rule Generator to its SID.

```powershell
$sid = Get-SelectedSid
```

**Returns:** String - The SID value (e.g., "S-1-5-21-...")

**Supported Groups:**
- AppLocker-Admins
- AppLocker-StandardUsers
- AppLocker-Service-Accounts
- AppLocker-Installers
- Custom SID input

#### Resolve-SidToGroupName
Converts a SID to a friendly group name.

```powershell
$groupName = Resolve-SidToGroupName -Sid "S-1-1-0"
# Returns: "Everyone"
```

**Parameters:**
- `Sid` - The SID string to resolve

**Returns:** String - Friendly name or original SID if not resolvable

**Well-Known SIDs:**
- S-1-1-0 = Everyone
- S-1-5-32-544 = Administrators
- S-1-5-32-545 = Users
- S-1-5-32-546 = Guests

#### Get-SidFromGroupName
Converts a group name to its SID.

```powershell
$sid = Get-SidFromGroupName -GroupName "Administrators"
# Returns: "S-1-5-32-544"
```

**Parameters:**
- `GroupName` - The group name to resolve

**Returns:** String - SID value, or S-1-1-0 if not resolvable

### UI-Components.ps1
PowerShell module with factory functions for creating reusable UI components.

**Factory Functions:**

#### New-StatusCard
Creates a status card with title, value, and optional subtitle.

```powershell
$xaml = New-StatusCard -Title "Total Events" -Value "1,234" -Subtitle "Last 7 days" -ValueColor "Green"
```

**Parameters:**
- `Title` (required) - Card title
- `Value` (required) - Main value to display
- `Icon` (optional) - Icon text/symbol
- `Subtitle` (optional) - Subtitle text
- `ValueColor` (optional) - Color for value (Blue, Green, Orange, Red, Purple, Text1)

#### New-FilterPanel
Creates a filter panel with multiple options (buttons or combobox).

```powershell
$xaml = New-FilterPanel -Name "Event Type" -Options @("All", "Allowed", "Blocked", "Audit") -Type "Buttons"
```

**Parameters:**
- `Name` (required) - Filter panel label
- `Options` (required) - Array of option names
- `Type` (optional) - "Buttons" or "ComboBox" (default: Buttons)

#### New-ActionButtonGroup
Creates a horizontal group of action buttons.

```powershell
$buttons = @(
    @{Name="Export"; Text="Export Rules"; Style="Primary"; Tooltip="Export to XML"},
    @{Name="Import"; Text="Import Rules"; Style="Secondary"; Tooltip="Import from XML"}
)
$xaml = New-ActionButtonGroup -Buttons $buttons
```

**Parameters:**
- `Buttons` (required) - Array of hashtables with Name, Text, Style, Tooltip

#### New-OutputLogPanel
Creates a scrollable output log panel.

```powershell
$xaml = New-OutputLogPanel -Name "DeploymentLog" -Title "Deployment Output" -DefaultText "Ready..."
```

**Parameters:**
- `Name` (required) - Control name for the TextBlock
- `Title` (optional) - Panel title
- `DefaultText` (optional) - Placeholder text
- `MinHeight` (optional) - Minimum height in pixels (default: 200)

#### New-InfoBanner
Creates an informational banner for alerts/messages.

```powershell
$xaml = New-InfoBanner -Message "Domain controllers require special consideration" -Type "Warning"
```

**Parameters:**
- `Message` (required) - Banner message text
- `Type` (optional) - Info, Warning, Error, Success (default: Info)

## Theme Colors

The UI uses a GitHub Dark theme with the following color palette:

| Color Name | Hex Code | Usage |
|------------|----------|-------|
| BgDark | #0D1117 | Main background |
| BgSidebar | #161B22 | Sidebar background |
| BgCard | #21262D | Card/panel background |
| Border | #30363D | Border colors |
| Blue | #58A6FF | Links, info |
| Green | #3FB950 | Success, allowed |
| Orange | #D29922 | Warning, audit |
| Red | #F85149 | Error, blocked |
| Purple | #8957E5 | Templates, special |
| Text1 | #E6EDF3 | Primary text |
| Text2 | #8B949E | Secondary text |
| Text3 | #6E7681 | Tertiary text |
| Hover | #30363D | Hover states |

## Usage in PowerShell Scripts

### Importing the Modules

```powershell
# Import UI helpers
Import-Module "C:\GA-AppLocker_FINAL\src\GUI\UI\UI-Helpers.ps1" -Force

# Import UI components
Import-Module "C:\GA-AppLocker_FINAL\src\GUI\UI\UI-Components.ps1" -Force
```

### Loading the XAML

```powershell
# Load XAML from file
$xamlPath = "C:\GA-AppLocker_FINAL\src\GUI\UI\MainWindow.xaml"
$xamlContent = Get-Content $xamlPath -Raw

# Parse XAML
Add-Type -AssemblyName PresentationFramework
$window = [Windows.Markup.XamlReader]::Parse($xamlContent)

# Find controls
$NavDashboard = $window.FindName("NavDashboard")
$PanelRules = $window.FindName("PanelRules")
```

### Example: Creating Dynamic UI

```powershell
# Create a new status card
$cardXaml = New-StatusCard -Title "Active Rules" -Value "247" -ValueColor "Green"

# Parse and add to existing panel
$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($cardXaml))
$card = [Windows.Markup.XamlReader]::Load($reader)

# Add to container
$container = $window.FindName("SomeStackPanel")
$container.Children.Add($card)
```

### Example: Panel Navigation

```powershell
# Switch to Rules panel
Show-Panel -PanelName "Rules"

# Update status bar after data change
Update-StatusBar

# Refresh badges
Update-Badges
```

## Best Practices

1. **XAML Editing:**
   - Use Visual Studio or VS Code with XAML extensions
   - Test XAML changes in isolation before integrating
   - Maintain consistent naming conventions (x:Name="PascalCase")

2. **Module Usage:**
   - Always import modules before using their functions
   - Use `-Force` when re-importing during development
   - Check for null controls before accessing properties

3. **Styling:**
   - Use StaticResource for colors to maintain theme consistency
   - Apply existing button styles (PrimaryButton, SecondaryButton)
   - Follow the 8px grid system for margins/padding

4. **Performance:**
   - Minimize XAML parsing operations
   - Cache FindName results for frequently accessed controls
   - Use Visibility.Collapsed instead of removing elements

## Troubleshooting

### XAML Parse Errors
- Check for unmatched tags
- Verify namespace declarations
- Ensure proper quotation marks in attribute values
- Validate color codes (must be valid hex)

### Control Not Found
```powershell
if ($null -eq $MyControl) {
    Write-Warning "Control 'MyControl' not found in XAML"
}
```

### Module Import Issues
- Ensure file paths are correct and absolute
- Check PowerShell execution policy
- Verify module has Export-ModuleMember declarations

## Integration with Main Application

These extracted modules are designed to be referenced by the main GUI application:

```powershell
# In GA-AppLocker-GUI-WPF.ps1
# Instead of inline XAML:
$xamlPath = Join-Path $PSScriptRoot "..\src\GUI\UI\MainWindow.xaml"
$xamlString = Get-Content $xamlPath -Raw

# Import helper modules
$helpersPath = Join-Path $PSScriptRoot "..\src\GUI\UI\UI-Helpers.ps1"
Import-Module $helpersPath -Force

# Helper functions are now available
Show-Panel -PanelName "Dashboard"
Update-StatusBar
```

## Future Enhancements

Potential improvements for this module:

1. **Dynamic Theme Switching** - Support light/dark theme toggle
2. **Component Templates** - Additional factory functions for common patterns
3. **Data Binding Helpers** - Simplified WPF binding from PowerShell
4. **Validation Functions** - Input validation for UI components
5. **Animation Helpers** - Smooth transitions for panel switching
6. **Accessibility** - Enhanced keyboard navigation and screen reader support

## References

- [WPF Documentation](https://docs.microsoft.com/en-us/dotnet/desktop/wpf/)
- [PowerShell WPF Guide](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-a-graphical-date-picker)
- [GitHub Primer Design System](https://primer.style/) (Color inspiration)
- [Material Design Icons](https://materialdesignicons.com/) (Icon reference)

---

**Last Updated:** 2026-01-16
**Version:** 1.2.5
**Maintainer:** GA-ASI Security Team
