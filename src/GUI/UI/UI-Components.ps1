<#
.SYNOPSIS
    Reusable UI component factory functions

.DESCRIPTION
    Provides factory functions for creating standard UI components programmatically.
    These components follow the GitHub Dark theme styling used throughout the application.

.NOTES
    This module allows dynamic creation of UI elements with consistent styling.
    Useful for templates and runtime-generated UI components.
#>

# ============================================================
# Color Theme Constants
# ============================================================

$script:Colors = @{
    BgDark = "#0D1117"
    BgSidebar = "#161B22"
    BgCard = "#21262D"
    Border = "#30363D"
    Blue = "#58A6FF"
    Green = "#3FB950"
    Orange = "#D29922"
    Red = "#F85149"
    Purple = "#8957E5"
    Text1 = "#E6EDF3"
    Text2 = "#8B949E"
    Text3 = "#6E7681"
    Hover = "#30363D"
}

# ============================================================
# Status Card Factory
# ============================================================

function New-StatusCard {
    <#
    .SYNOPSIS
        Creates a status card UI component

    .DESCRIPTION
        Generates a standard status card with title, value, and optional icon/subtitle.
        Returns XAML string that can be parsed into WPF controls.

    .PARAMETER Title
        The card title (e.g., "Total Events")

    .PARAMETER Value
        The main value to display (e.g., "1,234")

    .PARAMETER Icon
        Optional icon text or symbol

    .PARAMETER Subtitle
        Optional subtitle/description text

    .PARAMETER ValueColor
        Color for the value text (default: Blue)

    .OUTPUTS
        String - XAML markup for the status card

    .EXAMPLE
        $cardXaml = New-StatusCard -Title "Total Events" -Value "1,234" -Subtitle "Last 7 days" -ValueColor "Green"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$true)]
        [string]$Value,

        [string]$Icon = "",

        [string]$Subtitle = "",

        [ValidateSet("Blue", "Green", "Orange", "Red", "Purple", "Text1")]
        [string]$ValueColor = "Blue"
    )

    $color = $script:Colors[$ValueColor]

    $xaml = @"
<Border Background="$($script:Colors.BgCard)" BorderBrush="$($script:Colors.Border)"
        BorderThickness="1" CornerRadius="6" Padding="12" Margin="0,0,8,10">
    <StackPanel>
        <TextBlock Text="$Title" FontSize="11" Foreground="$($script:Colors.Text2)"/>
        <TextBlock Text="$Value" FontSize="26" FontWeight="Bold"
                   Foreground="$color" Margin="0,8,0,0"/>
"@

    if ($Subtitle) {
        $xaml += @"

        <TextBlock Text="$Subtitle" FontSize="10" Foreground="$($script:Colors.Text3)"/>
"@
    }

    $xaml += @"

    </StackPanel>
</Border>
"@

    return $xaml
}

# ============================================================
# Filter Panel Factory
# ============================================================

function New-FilterPanel {
    <#
    .SYNOPSIS
        Creates a filter panel with multiple options

    .DESCRIPTION
        Generates a horizontal filter panel with label and buttons/combobox options.

    .PARAMETER Name
        The filter panel name/label

    .PARAMETER Options
        Array of option names for the filter buttons

    .PARAMETER Type
        Type of filter control (Buttons or ComboBox)

    .OUTPUTS
        String - XAML markup for the filter panel

    .EXAMPLE
        $filterXaml = New-FilterPanel -Name "Event Type" -Options @("All", "Allowed", "Blocked", "Audit") -Type "Buttons"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [array]$Options,

        [ValidateSet("Buttons", "ComboBox")]
        [string]$Type = "Buttons"
    )

    $xaml = @"
<Border Background="$($script:Colors.BgDark)" BorderBrush="$($script:Colors.Border)"
        BorderThickness="1" CornerRadius="8" Padding="12" Margin="0,0,0,10">
    <Grid>
"@

    if ($Type -eq "Buttons") {
        $xaml += @"

        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="12"/>
"@

        for ($i = 0; $i -lt $Options.Count; $i++) {
            $xaml += @"

            <ColumnDefinition Width="Auto"/>
"@
            if ($i -lt $Options.Count - 1) {
                $xaml += @"

            <ColumnDefinition Width="10"/>
"@
            }
        }

        $xaml += @"

        </Grid.ColumnDefinitions>
        <TextBlock Grid.Column="0" Text="${Name}:" FontSize="11" Foreground="$($script:Colors.Text2)" VerticalAlignment="Center"/>
"@

        $col = 2
        foreach ($option in $Options) {
            $controlName = "$Name$option" -replace '\s',''
            $xaml += @"

        <Button x:Name="$controlName" Content="$option" Style="{StaticResource SecondaryButton}"
                Grid.Column="$col" Height="30" FontSize="11" Padding="14,0" MinWidth="60"/>
"@
            $col += 2
        }

    } else {
        # ComboBox
        $xaml += @"

        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="10"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBlock Grid.Column="0" Text="${Name}:" FontSize="11" Foreground="$($script:Colors.Text2)" VerticalAlignment="Center"/>
        <ComboBox x:Name="${Name}Filter" Grid.Column="2" Height="30" FontSize="11"
                  Background="$($script:Colors.BgDark)" Foreground="$($script:Colors.Text1)"
                  BorderBrush="$($script:Colors.Border)">
"@

        $first = $true
        foreach ($option in $Options) {
            $selected = if ($first) { " IsSelected=`"True`"" } else { "" }
            $xaml += @"

            <ComboBoxItem Content="$option"$selected/>
"@
            $first = $false
        }

        $xaml += @"

        </ComboBox>
"@
    }

    $xaml += @"

    </Grid>
</Border>
"@

    return $xaml
}

# ============================================================
# Action Button Group Factory
# ============================================================

function New-ActionButtonGroup {
    <#
    .SYNOPSIS
        Creates a group of action buttons in a grid layout

    .DESCRIPTION
        Generates a horizontal grid of buttons with consistent spacing.

    .PARAMETER Buttons
        Array of hashtables with button properties (Name, Text, Style, Tooltip)

    .OUTPUTS
        String - XAML markup for the button group

    .EXAMPLE
        $buttons = @(
            @{Name="Export"; Text="Export Rules"; Style="Primary"; Tooltip="Export to XML"},
            @{Name="Import"; Text="Import Rules"; Style="Secondary"; Tooltip="Import from XML"}
        )
        $buttonGroupXaml = New-ActionButtonGroup -Buttons $buttons
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Buttons
    )

    $xaml = @"
<Grid Margin="0,0,0,15">
    <Grid.ColumnDefinitions>
"@

    for ($i = 0; $i -lt $Buttons.Count; $i++) {
        $xaml += @"

        <ColumnDefinition Width="*"/>
"@
        if ($i -lt $Buttons.Count - 1) {
            $xaml += @"

        <ColumnDefinition Width="10"/>
"@
        }
    }

    $xaml += @"

    </Grid.ColumnDefinitions>
"@

    $col = 0
    foreach ($btn in $Buttons) {
        $name = $btn.Name
        $text = $btn.Text
        $style = if ($btn.Style -eq "Primary") { "PrimaryButton" } else { "SecondaryButton" }
        $tooltip = if ($btn.Tooltip) { " ToolTip=`"$($btn.Tooltip)`"" } else { "" }

        $xaml += @"

    <Button x:Name="${name}Btn" Content="$text" Style="{StaticResource $style}" Grid.Column="$col"$tooltip/>
"@
        $col += 2
    }

    $xaml += @"

</Grid>
"@

    return $xaml
}

# ============================================================
# Output Log Panel Factory
# ============================================================

function New-OutputLogPanel {
    <#
    .SYNOPSIS
        Creates a scrollable output log panel

    .DESCRIPTION
        Generates a styled output panel with scrolling support for log messages.

    .PARAMETER Name
        The control name for the TextBlock

    .PARAMETER Title
        Panel title (optional)

    .PARAMETER DefaultText
        Default placeholder text

    .PARAMETER MinHeight
        Minimum height in pixels (default: 200)

    .OUTPUTS
        String - XAML markup for the output log panel

    .EXAMPLE
        $logXaml = New-OutputLogPanel -Name "DeploymentLog" -Title "Deployment Output" -DefaultText "Ready to deploy..."
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [string]$Title = "",

        [string]$DefaultText = "Waiting for output...",

        [int]$MinHeight = 200
    )

    $xaml = @"
<Border Background="$($script:Colors.BgDark)" BorderBrush="$($script:Colors.Border)"
        BorderThickness="1" CornerRadius="8" Padding="15" MinHeight="$MinHeight">
"@

    if ($Title) {
        $xaml += @"

    <StackPanel>
        <TextBlock Text="$Title" FontSize="13" FontWeight="SemiBold"
                   Foreground="$($script:Colors.Text1)" Margin="0,0,0,8"/>
        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <TextBlock x:Name="$Name" Text="$DefaultText"
                       FontFamily="Consolas" FontSize="11" Foreground="$($script:Colors.Green)"
                       TextWrapping="Wrap"/>
        </ScrollViewer>
    </StackPanel>
"@
    } else {
        $xaml += @"

    <ScrollViewer VerticalScrollBarVisibility="Auto">
        <TextBlock x:Name="$Name" Text="$DefaultText"
                   FontFamily="Consolas" FontSize="11" Foreground="$($script:Colors.Green)"
                   TextWrapping="Wrap"/>
    </ScrollViewer>
"@
    }

    $xaml += @"

</Border>
"@

    return $xaml
}

# ============================================================
# Info Banner Factory
# ============================================================

function New-InfoBanner {
    <#
    .SYNOPSIS
        Creates an informational banner

    .DESCRIPTION
        Generates a colored banner with icon and message for alerts/info.

    .PARAMETER Message
        The banner message text

    .PARAMETER Type
        Banner type (Info, Warning, Error, Success)

    .OUTPUTS
        String - XAML markup for the info banner

    .EXAMPLE
        $bannerXaml = New-InfoBanner -Message "Domain controllers require special consideration" -Type "Warning"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Type = "Info"
    )

    $colors = @{
        Info = @{Bg = $script:Colors.BgCard; Border = $script:Colors.Blue; Text = $script:Colors.Blue}
        Warning = @{Bg = $script:Colors.BgCard; Border = $script:Colors.Orange; Text = $script:Colors.Orange}
        Error = @{Bg = $script:Colors.BgCard; Border = $script:Colors.Red; Text = $script:Colors.Red}
        Success = @{Bg = $script:Colors.BgCard; Border = $script:Colors.Green; Text = $script:Colors.Green}
    }

    $c = $colors[$Type]

    $xaml = @"
<Border Background="$($c.Bg)" BorderBrush="$($c.Border)"
        BorderThickness="1" CornerRadius="8" Padding="20" Margin="0,0,0,15">
    <StackPanel>
        <TextBlock Text="$Message" FontSize="12" Foreground="$($c.Text)" TextWrapping="Wrap"/>
    </StackPanel>
</Border>
"@

    return $xaml
}

# Export module members
Export-ModuleMember -Function New-StatusCard, New-FilterPanel, New-ActionButtonGroup, New-OutputLogPanel, New-InfoBanner
