<#
.SYNOPSIS
    GA-AppLocker Portable GUI Application
.DESCRIPTION
    A standalone, portable graphical user interface for the GA-AppLocker toolkit.
    Can be compiled to a single .exe file using PS2EXE or run directly.
.NOTES
    Author: Tony Tran
            Information Systems Security Officer
            Classified Computing, GA-ASI
            tony.tran@ga-asi.com

    Requires: PowerShell 5.1+, Windows Presentation Foundation

    To compile to EXE:
    Install-Module -Name PS2EXE -Scope CurrentUser
    Invoke-PS2EXE -InputFile .\GA-AppLocker-Portable.ps1 -OutputFile .\GA-AppLocker.exe -NoConsole -IconFile .\assets\general-atomics-logo.ico -Title "GA-AppLocker" -Version "1.0.0"
#>

#Requires -Version 5.1

param(
    [string]$ScriptsPath = ""
)

# Version constant - update this when releasing new versions
$Script:AppVersion = "1.2.4"

# Load WPF assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

#region Script Path Detection
# Detect script root - handles EXE, PS1, and ISE scenarios
$Script:AppRoot = $null

# Try multiple methods to find the app root
if ($ScriptsPath -and (Test-Path $ScriptsPath)) {
    # Explicit path provided via parameter
    $Script:AppRoot = $ScriptsPath
}
else {
    # Check if running as compiled EXE (ps2exe sets this)
    $exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($exePath -and $exePath -notmatch 'powershell\.exe$|pwsh\.exe$') {
        # Running as compiled EXE - check EXE's directory first, then parent
        $exeDir = Split-Path -Parent $exePath
        if (Test-Path (Join-Path $exeDir "Start-AppLockerWorkflow.ps1")) {
            $Script:AppRoot = $exeDir
        } elseif (Test-Path (Join-Path (Split-Path -Parent $exeDir) "Start-AppLockerWorkflow.ps1")) {
            # EXE is in dist/ subfolder, scripts are in parent
            $Script:AppRoot = Split-Path -Parent $exeDir
        } else {
            $Script:AppRoot = $exeDir
        }
    }
    elseif ($PSScriptRoot) {
        # Running as .ps1 file
        $testPath = Split-Path -Parent $PSScriptRoot
        if (Test-Path (Join-Path $testPath "Start-AppLockerWorkflow.ps1")) {
            $Script:AppRoot = $testPath
        } else {
            $Script:AppRoot = $PSScriptRoot
        }
    }
    elseif ($MyInvocation.MyCommand.Path) {
        # Running from command
        $testPath = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
        if (Test-Path (Join-Path $testPath "Start-AppLockerWorkflow.ps1")) {
            $Script:AppRoot = $testPath
        } else {
            $Script:AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
        }
    }
    else {
        # Fallback to current directory
        $Script:AppRoot = (Get-Location).Path
    }
}

# Check if running as compiled EXE
$Script:IsPortable = $true
$Script:ScriptsAvailable = Test-Path (Join-Path $Script:AppRoot "Start-AppLockerWorkflow.ps1")
#endregion

#region XAML Definition
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="GA-AppLocker Toolkit"
    Height="800"
    Width="1200"
    MinHeight="600"
    MinWidth="900"
    WindowStartupLocation="CenterScreen"
    Background="#0D1117">

    <Window.InputBindings>
        <!-- Navigation Shortcuts (matches CLI menu order) -->
        <!-- Collection -->
        <KeyBinding x:Name="KeyScan" Key="D1" Modifiers="Control" />
        <KeyBinding x:Name="KeyEvents" Key="D2" Modifiers="Control" />
        <!-- Analysis -->
        <KeyBinding x:Name="KeyCompare" Key="D3" Modifiers="Control" />
        <KeyBinding x:Name="KeyValidate" Key="D4" Modifiers="Control" />
        <!-- Policy -->
        <KeyBinding x:Name="KeyGenerate" Key="D5" Modifiers="Control" />
        <KeyBinding x:Name="KeyMerge" Key="D6" Modifiers="Control" />
        <KeyBinding x:Name="KeySoftware" Key="D7" Modifiers="Control" />
        <KeyBinding x:Name="KeyCORA" Key="D8" Modifiers="Control" />

        <!-- Quick Actions -->
        <KeyBinding x:Name="KeyQuickWorkflow" Key="Q" Modifiers="Control" />
        <KeyBinding x:Name="KeyRefresh" Key="R" Modifiers="Control" />
        <KeyBinding x:Name="KeyHelp" Key="F1" />
        <KeyBinding x:Name="KeySettings" Key="OemComma" Modifiers="Control" />
    </Window.InputBindings>

    <Window.Resources>
        <!-- Modern Color Palette -->
        <Color x:Key="BgDark">#0D1117</Color>
        <Color x:Key="BgSidebar">#161B22</Color>
        <Color x:Key="BgCard">#21262D</Color>
        <Color x:Key="BgInput">#0D1117</Color>
        <Color x:Key="BorderColor">#30363D</Color>
        <Color x:Key="AccentBlue">#58A6FF</Color>
        <Color x:Key="AccentGreen">#3FB950</Color>
        <Color x:Key="AccentOrange">#D29922</Color>
        <Color x:Key="AccentPurple">#A371F7</Color>
        <Color x:Key="AccentRed">#F85149</Color>
        <Color x:Key="TextPrimary">#E6EDF3</Color>
        <Color x:Key="TextSecondary">#A8B2BC</Color>
        <Color x:Key="TextMuted">#7D8590</Color>

        <SolidColorBrush x:Key="BgDarkBrush" Color="{StaticResource BgDark}"/>
        <SolidColorBrush x:Key="BgSidebarBrush" Color="{StaticResource BgSidebar}"/>
        <SolidColorBrush x:Key="BgCardBrush" Color="{StaticResource BgCard}"/>
        <SolidColorBrush x:Key="BgInputBrush" Color="{StaticResource BgInput}"/>
        <SolidColorBrush x:Key="BorderBrush" Color="{StaticResource BorderColor}"/>
        <SolidColorBrush x:Key="AccentBlueBrush" Color="{StaticResource AccentBlue}"/>
        <SolidColorBrush x:Key="AccentGreenBrush" Color="{StaticResource AccentGreen}"/>
        <SolidColorBrush x:Key="AccentOrangeBrush" Color="{StaticResource AccentOrange}"/>
        <SolidColorBrush x:Key="AccentPurpleBrush" Color="{StaticResource AccentPurple}"/>
        <SolidColorBrush x:Key="AccentRedBrush" Color="{StaticResource AccentRed}"/>
        <SolidColorBrush x:Key="TextPrimaryBrush" Color="{StaticResource TextPrimary}"/>
        <SolidColorBrush x:Key="TextSecondaryBrush" Color="{StaticResource TextSecondary}"/>
        <SolidColorBrush x:Key="TextMutedBrush" Color="{StaticResource TextMuted}"/>

        <!-- Primary Button Style -->
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource AccentBlueBrush}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Padding" Value="16,10"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#79C0FF"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Background" Value="#30363D"/>
                                <Setter Property="Foreground" Value="#484F58"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Secondary Button Style -->
        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource BgCardBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Padding" Value="12,8"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#30363D"/>
                                <Setter TargetName="border" Property="BorderBrush" Value="#484F58"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#484F58"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Small Button Style -->
        <Style x:Key="SmallButton" TargetType="Button" BasedOn="{StaticResource SecondaryButton}">
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontSize" Value="11"/>
        </Style>

        <!-- Navigation Button Style -->
        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
            <Setter Property="Padding" Value="14,10"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                                              VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#21262D"/>
                                <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Active Navigation Button Style -->
        <Style x:Key="NavButtonActive" TargetType="Button" BasedOn="{StaticResource NavButton}">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
        </Style>

        <!-- Modern TextBox Style -->
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{StaticResource BgInputBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,10"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="CaretBrush" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentBlueBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Modern PasswordBox Style -->
        <Style TargetType="PasswordBox">
            <Setter Property="Background" Value="{StaticResource BgInputBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,10"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="CaretBrush" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="PasswordBox">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentBlueBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Modern ComboBox Style -->
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#FFFFFF"/>
            <Setter Property="Foreground" Value="#1a1a2e"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,10"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <!-- ComboBox Item Style for readable dropdowns -->
        <Style TargetType="ComboBoxItem">
            <Setter Property="Background" Value="#FFFFFF"/>
            <Setter Property="Foreground" Value="#1a1a2e"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <!-- Modern CheckBox Style -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>

        <!-- Modern RadioButton Style -->
        <Style TargetType="RadioButton">
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>

        <!-- Modern ListBox Style -->
        <Style TargetType="ListBox">
            <Setter Property="Background" Value="{StaticResource BgInputBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="4"/>
        </Style>

        <!-- Card Styles -->
        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="{StaticResource BgCardBrush}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="6"/>
            <Setter Property="Padding" Value="16"/>
            <Setter Property="Margin" Value="0,0,0,12"/>
        </Style>

        <Style x:Key="CardDark" TargetType="Border">
            <Setter Property="Background" Value="#161B22"/>
            <Setter Property="CornerRadius" Value="6"/>
            <Setter Property="Padding" Value="10"/>
        </Style>

        <!-- Text Styles -->
        <Style x:Key="PageTitle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="22"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Margin" Value="0,0,0,4"/>
        </Style>

        <Style x:Key="PageSubtitle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
            <Setter Property="Margin" Value="0,0,0,20"/>
        </Style>

        <Style x:Key="CardTitle" TargetType="TextBlock">
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimaryBrush}"/>
            <Setter Property="Margin" Value="0,0,0,10"/>
        </Style>

        <Style x:Key="FieldLabel" TargetType="TextBlock">
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Foreground" Value="{StaticResource TextSecondaryBrush}"/>
            <Setter Property="Margin" Value="0,0,0,4"/>
        </Style>

        <Style x:Key="HintText" TargetType="TextBlock">
            <Setter Property="FontSize" Value="10"/>
            <Setter Property="Foreground" Value="{StaticResource TextMutedBrush}"/>
            <Setter Property="Margin" Value="0,6,0,0"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="220"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- Sidebar -->
        <Border Grid.Column="0" Background="{StaticResource BgSidebarBrush}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,1,0">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- Logo/Title -->
                <Border Grid.Row="0" Padding="20,24,20,20" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                            <Image x:Name="SidebarLogo" Width="32" Height="32" Margin="0,0,10,0" VerticalAlignment="Center"/>
                            <TextBlock Text="GA-AppLocker" FontSize="20" FontWeight="Bold"
                                       Foreground="{StaticResource TextPrimaryBrush}" VerticalAlignment="Center"/>
                        </StackPanel>
                        <TextBlock Text="Security Policy Toolkit" FontSize="11"
                                   Foreground="{StaticResource TextSecondaryBrush}"/>
                    </StackPanel>
                </Border>

                <!-- Navigation -->
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="6,10,6,10">
                        <TextBlock Text="COLLECTION" FontSize="10" FontWeight="Bold"
                                   Foreground="{StaticResource AccentBlueBrush}"
                                   Margin="14,6,0,6"/>

                        <Button x:Name="NavScan" Style="{StaticResource NavButtonActive}" Content="Scan Computers" ToolTip="Ctrl+1"/>
                        <Button x:Name="NavEvents" Style="{StaticResource NavButton}" Content="Collect Events" ToolTip="Ctrl+2"/>

                        <TextBlock Text="ANALYSIS" FontSize="10" FontWeight="Bold"
                                   Foreground="{StaticResource AccentBlueBrush}"
                                   Margin="14,14,0,6"/>

                        <Button x:Name="NavCompare" Style="{StaticResource NavButton}" Content="Compare Inventory" ToolTip="Ctrl+3"/>
                        <Button x:Name="NavValidate" Style="{StaticResource NavButton}" Content="Validate Policy" ToolTip="Ctrl+4"/>

                        <TextBlock Text="COMPLIANCE" FontSize="10" FontWeight="Bold"
                                   Foreground="{StaticResource AccentPurpleBrush}"
                                   Margin="14,14,0,6"/>

                        <Button x:Name="NavCORA" Style="{StaticResource NavButton}" Content="CORA Evidence" ToolTip="Ctrl+8"/>

                        <TextBlock Text="POLICY" FontSize="10" FontWeight="Bold"
                                   Foreground="{StaticResource AccentBlueBrush}"
                                   Margin="14,14,0,6"/>

                        <Button x:Name="NavGenerate" Style="{StaticResource NavButton}" Content="Generate Policy" ToolTip="Ctrl+5"/>
                        <Button x:Name="NavMerge" Style="{StaticResource NavButton}" Content="Merge Policies" ToolTip="Ctrl+6"/>
                        <Button x:Name="NavSoftware" Style="{StaticResource NavButton}" Content="Software Lists" ToolTip="Ctrl+7"/>
                        <Button x:Name="NavClone" Style="{StaticResource NavButton}" Content="Clone Rules"/>

                        <TextBlock Text="DEPLOYMENT" FontSize="10" FontWeight="Bold"
                                   Foreground="{StaticResource AccentBlueBrush}"
                                   Margin="14,14,0,6"/>

                        <Button x:Name="NavAD" Style="{StaticResource NavButton}" Content="Active Directory"/>
                        <Button x:Name="NavWinRM" Style="{StaticResource NavButton}" Content="WinRM Setup"/>
                        <Button x:Name="NavDiagnostics" Style="{StaticResource NavButton}" Content="Diagnostics"/>

                        <TextBlock Text="APPLICATION" FontSize="10" FontWeight="Bold"
                                   Foreground="{StaticResource AccentBlueBrush}"
                                   Margin="14,14,0,6"/>

                        <Button x:Name="NavSettings" Style="{StaticResource NavButton}" Content="Settings" ToolTip="Ctrl+,"/>
                        <Button x:Name="NavHelp" Style="{StaticResource NavButton}" Content="Help" ToolTip="F1"/>
                        <Button x:Name="NavAbout" Style="{StaticResource NavButton}" Content="About"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Status Bar -->
                <Border Grid.Row="2" Padding="16,12" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,1,0,0">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal">
                            <Ellipse x:Name="StatusDot" Width="8" Height="8" Fill="{StaticResource AccentGreenBrush}" Margin="0,0,8,0"/>
                            <TextBlock x:Name="StatusText" Text="Ready" FontSize="12"
                                       Foreground="{StaticResource TextSecondaryBrush}"/>
                            <Button x:Name="CancelOperation" Content="Cancel" Visibility="Collapsed"
                                    Margin="12,0,0,0" Padding="8,2" FontSize="10"
                                    Background="#F85149" Foreground="White" BorderThickness="0" Cursor="Hand"/>
                        </StackPanel>
                    </StackPanel>
                </Border>
            </Grid>
        </Border>

        <!-- Main Content Area -->
        <Grid Grid.Column="1">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- Quick Workflow Action Bar -->
            <Border Grid.Row="0" Background="#161B22" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1" Padding="24,12">
                <StackPanel>
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Grid.Column="0" Text="Quick Workflow:" FontSize="13" FontWeight="SemiBold"
                                   Foreground="{StaticResource TextSecondaryBrush}" VerticalAlignment="Center" Margin="0,0,12,0"/>

                        <ComboBox x:Name="WorkflowMode" Grid.Column="1" Width="200" VerticalAlignment="Center">
                            <ComboBoxItem Content="Create Baseline" IsSelected="True"/>
                            <ComboBoxItem Content="Assess Environment"/>
                            <ComboBoxItem Content="Update Policy"/>
                            <ComboBoxItem Content="Monitor Blocks"/>
                        </ComboBox>

                        <Button x:Name="RunWorkflow" Grid.Column="2" Content="▶ Run Workflow"
                                Style="{StaticResource PrimaryButton}" Margin="12,0,0,0" Padding="16,8"/>
                    </Grid>
                    <!-- Workflow Description -->
                    <TextBlock x:Name="WorkflowDescription" FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,8,0,0"
                               Text="Scan computers → Collect events → Generate initial policy. Best for first-time setup."
                               TextWrapping="Wrap"/>
                </StackPanel>
            </Border>

            <!-- Content Pages -->
            <Grid x:Name="ContentArea" Grid.Row="1" Margin="0">

                <!-- Scan Page -->
                <ScrollViewer x:Name="PageScan" VerticalScrollBarVisibility="Auto" Visibility="Visible">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Scan Computers" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Collect application inventory from remote computers via WinRM"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Computer List" Style="{StaticResource CardTitle}"/>

                                <!-- Export from AD Section -->
                                <Border Style="{StaticResource CardDark}" Margin="0,0,0,12">
                                    <StackPanel>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                            <TextBlock Text="&#xE716;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                                       Foreground="{StaticResource AccentGreenBrush}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <TextBlock Text="Export from Active Directory" FontSize="12" FontWeight="SemiBold"
                                                       Foreground="{StaticResource TextPrimaryBrush}"/>
                                        </StackPanel>
                                        <Grid Margin="0,0,0,8">
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Text="Type:" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}"
                                                       VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <ComboBox x:Name="ScanADComputerType" Grid.Column="1" SelectedIndex="0" Margin="0,0,8,0">
                                                <ComboBoxItem Content="All Computers"/>
                                                <ComboBoxItem Content="Workstations Only"/>
                                                <ComboBoxItem Content="Servers Only"/>
                                                <ComboBoxItem Content="Domain Controllers"/>
                                            </ComboBox>
                                            <Button x:Name="ScanExportFromAD" Grid.Column="2" Content="Export from AD"
                                                    Style="{StaticResource SecondaryButton}"/>
                                        </Grid>
                                        <CheckBox x:Name="ScanADEnabledOnly" Content="Enabled computers only" IsChecked="True" FontSize="11"/>
                                        <CheckBox x:Name="ScanADWindowsOnly" Content="Windows OS only" IsChecked="True" FontSize="11" Margin="0,4,0,0"/>
                                    </StackPanel>
                                </Border>

                                <!-- Manual file selection -->
                                <TextBlock Text="Or select existing file:" Style="{StaticResource HintText}" Margin="0,0,0,6"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="ScanComputerList" Grid.Column="0"/>
                                    <Button x:Name="BrowseScanComputerList" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="Text file with one computer per line, or CSV with ComputerName column"
                                           Style="{StaticResource HintText}"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="System Admin Credentials" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="For workstations and member servers"
                                           Style="{StaticResource HintText}" Margin="0,0,0,10"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Username (DOMAIN\user or user@domain)" Style="{StaticResource FieldLabel}"/>
                                        <TextBox x:Name="ScanUsername" />
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Password" Style="{StaticResource FieldLabel}"/>
                                        <PasswordBox x:Name="ScanPassword"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border x:Name="ScanDCCredentialsCard" Style="{StaticResource Card}" Visibility="Collapsed">
                            <StackPanel>
                                <TextBlock Text="Domain Admin Credentials" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Domain Controllers detected - separate credentials required"
                                           FontSize="10" Foreground="{StaticResource AccentOrangeBrush}" Margin="0,0,0,10"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Username (DOMAIN\user or user@domain)" Style="{StaticResource FieldLabel}"/>
                                        <TextBox x:Name="ScanDCUsername" />
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Password" Style="{StaticResource FieldLabel}"/>
                                        <PasswordBox x:Name="ScanDCPassword"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Options" Style="{StaticResource CardTitle}"/>
                                <WrapPanel>
                                    <CheckBox x:Name="ScanUserProfiles" Content="Scan User Profiles" Margin="0,0,24,8"/>
                                    <CheckBox x:Name="ScanIncludeDLLs" Content="Include DLLs" Margin="0,0,24,8"/>
                                </WrapPanel>
                                <Grid Margin="0,6,0,0">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="80"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Text="Throttle Limit:" Style="{StaticResource FieldLabel}"
                                               VerticalAlignment="Center" Margin="0,0,10,0"/>
                                    <TextBox x:Name="ScanThrottleLimit" Grid.Column="1" Text="10"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Output Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="ScanOutputPath" Grid.Column="0" Text=".\Scans"/>
                                    <Button x:Name="BrowseScanOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartScan" Content="Start Scan" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- CORA Evidence Page -->
                <ScrollViewer x:Name="PageCORA" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="CORA Evidence Package" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Generate comprehensive audit evidence for CORA assessments"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="What This Generates" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Collects and organizes all AppLocker deployment artifacts into an audit-ready package:"
                                           FontSize="11" Foreground="{StaticResource TextSecondaryBrush}" TextWrapping="Wrap" Margin="0,0,0,10"/>

                                <StackPanel Margin="6,0,0,0">
                                    <TextBlock Text="• Software Inventory Evidence (Scans folder)" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• AppLocker Event Collections (Events folder)" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• Generated Policies (Outputs folder)" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• Compliance Report with score" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• Rule Health Check results" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• Deployment Timeline" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• Control Mapping (NIST 800-53, CIS, CMMC)" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                    <TextBlock Text="• Executive Summary HTML" Foreground="{StaticResource TextSecondaryBrush}" FontSize="11"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Output Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CORAOutputPath" Grid.Column="0" Text=".\Reports"/>
                                    <Button x:Name="BrowseCORAOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="A timestamped subfolder will be created automatically"
                                           Style="{StaticResource HintText}"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Options" Style="{StaticResource CardTitle}"/>
                                <CheckBox x:Name="CORAIncludeRawData" Content="Include raw scan/event data (larger package)"
                                          IsChecked="False" Margin="0,0,0,6"/>
                                <CheckBox x:Name="CORAOpenWhenComplete" Content="Open folder when complete"
                                          IsChecked="True" Margin="0,0,0,6"/>

                                <TextBlock Text="Specific Policy (optional)" Style="{StaticResource FieldLabel}" Margin="0,10,0,4"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CORAPolicyPath" Grid.Column="0" Text=""/>
                                    <Button x:Name="BrowseCORAPolicy" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="Leave blank to include all policies from Outputs folder"
                                           Style="{StaticResource HintText}"/>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartCORA" Content="Generate CORA Evidence" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Generate Page -->
                <ScrollViewer x:Name="PageGenerate" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Generate Policy" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Create AppLocker policies from scan data"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Data Sources" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Scan Data (from Invoke-RemoteScan)" Style="{StaticResource FieldLabel}"/>
                                <Grid Margin="0,0,0,12">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="GenerateScanPath" Grid.Column="0"/>
                                    <Button x:Name="BrowseGenerateScanPath" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="Event Data (blocked apps from audit mode)" Style="{StaticResource FieldLabel}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="GenerateEventPath" Grid.Column="0"/>
                                    <Button x:Name="BrowseGenerateEventPath" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="Provide at least one data source (scan data, event data, or software list)"
                                           Style="{StaticResource HintText}"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Policy Mode" Style="{StaticResource CardTitle}"/>
                                <RadioButton x:Name="GenerateSimplified" Content="Simplified Mode" IsChecked="True" Margin="0,0,0,2"/>
                                <TextBlock Text="Quick deployment with single target user/group"
                                           Style="{StaticResource HintText}" Margin="18,0,0,12"/>
                                <RadioButton x:Name="GenerateBuildGuide" Content="Build Guide Mode" Margin="0,0,0,2"/>
                                <TextBlock Text="Enterprise deployment with proper scoping"
                                           Style="{StaticResource HintText}" Margin="18,0,0,0"/>
                            </StackPanel>
                        </Border>

                        <Border x:Name="BuildGuideOptions" Style="{StaticResource Card}" Visibility="Collapsed">
                            <StackPanel>
                                <TextBlock Text="Build Guide Options" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Target Type" Style="{StaticResource FieldLabel}"/>
                                        <ComboBox x:Name="GenerateTargetType" SelectedIndex="0">
                                            <ComboBoxItem Content="Workstation"/>
                                            <ComboBoxItem Content="Server"/>
                                            <ComboBoxItem Content="DomainController"/>
                                        </ComboBox>
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Phase" Style="{StaticResource FieldLabel}"/>
                                        <ComboBox x:Name="GeneratePhase" SelectedIndex="0">
                                            <ComboBoxItem Content="Phase 1 - EXE only"/>
                                            <ComboBoxItem Content="Phase 2 - EXE + Script"/>
                                            <ComboBoxItem Content="Phase 3 - EXE + Script + MSI"/>
                                            <ComboBoxItem Content="Phase 4 - Full"/>
                                        </ComboBox>
                                    </StackPanel>
                                </Grid>
                                <TextBlock Text="Domain Name" Style="{StaticResource FieldLabel}" Margin="0,12,0,4"/>
                                <TextBox x:Name="GenerateDomainName"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Additional Options" Style="{StaticResource CardTitle}"/>
                                <CheckBox x:Name="GenerateIncludeDenyRules" Content="Include LOLBins Deny Rules" Margin="0,0,0,8"/>
                                <StackPanel Orientation="Horizontal">
                                    <Button x:Name="SelectTrustedPublishers" Content="Select Trusted Publishers..."
                                            Style="{StaticResource SecondaryButton}" Margin="0,0,10,0"/>
                                    <TextBlock x:Name="TrustedPublishersCount" Text="0 selected" FontSize="11"
                                               Foreground="{StaticResource TextMutedBrush}" VerticalAlignment="Center"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Output Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="GenerateOutputPath" Grid.Column="0" Text=".\Outputs"/>
                                    <Button x:Name="BrowseGenerateOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartGenerate" Content="Generate Policy" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Merge Page -->
                <ScrollViewer x:Name="PageMerge" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Merge Policies" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Combine multiple AppLocker policy files"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Policy Files" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <ListBox x:Name="MergePolicyList" Grid.Column="0" Height="150"/>
                                    <StackPanel Grid.Column="1" Margin="10,0,0,0">
                                        <Button x:Name="MergeAddFile" Content="Add File" Style="{StaticResource SmallButton}" Margin="0,0,0,4"/>
                                        <Button x:Name="MergeAddFolder" Content="Add Folder" Style="{StaticResource SmallButton}" Margin="0,0,0,4"/>
                                        <Button x:Name="MergeRemoveFile" Content="Remove" Style="{StaticResource SmallButton}" Margin="0,0,0,4"/>
                                        <Button x:Name="MergeClearList" Content="Clear All" Style="{StaticResource SmallButton}"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Output Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="MergeOutputPath" Grid.Column="0" Text=".\Outputs"/>
                                    <Button x:Name="BrowseMergeOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartMerge" Content="Merge Policies" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Validate Page -->
                <ScrollViewer x:Name="PageValidate" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Validate Policy" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Check an AppLocker policy for issues"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Policy File" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="ValidatePolicyPath" Grid.Column="0"/>
                                    <Button x:Name="BrowseValidatePolicy" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border x:Name="ValidationResultsCard" Style="{StaticResource Card}" Visibility="Collapsed">
                            <StackPanel>
                                <TextBlock Text="Validation Results" Style="{StaticResource CardTitle}"/>
                                <TextBox x:Name="ValidationResults" Height="250" IsReadOnly="True"
                                         TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                                         FontFamily="Consolas" FontSize="11"/>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartValidate" Content="Validate Policy" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Clone Rules Page -->
                <ScrollViewer x:Name="PageClone" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Clone Rules" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Clone policy rules with different groups or actions"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Source Policy" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CloneSourcePolicy" Grid.Column="0"/>
                                    <Button x:Name="BrowseCloneSource" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                    <Button x:Name="LoadClonePolicy" Grid.Column="2" Content="Load"
                                            Style="{StaticResource PrimaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border x:Name="CloneOptionsCard" Style="{StaticResource Card}" Visibility="Collapsed">
                            <StackPanel>
                                <TextBlock Text="Policy Summary" Style="{StaticResource CardTitle}"/>
                                <TextBlock x:Name="ClonePolicySummary" Text="" FontSize="11"
                                           Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,12"/>

                                <TextBlock Text="Rules to Clone" Style="{StaticResource CardTitle}"/>
                                <WrapPanel Margin="0,0,0,12">
                                    <RadioButton x:Name="CloneAllRules" Content="All Rules" IsChecked="True" Margin="0,0,16,6"/>
                                    <RadioButton x:Name="ClonePublisherOnly" Content="Publisher Only" Margin="0,0,16,6"/>
                                    <RadioButton x:Name="CloneHashOnly" Content="Hash Only" Margin="0,0,16,6"/>
                                    <RadioButton x:Name="ClonePathOnly" Content="Path Only" Margin="0,0,16,6"/>
                                </WrapPanel>

                                <TextBlock Text="Filter by Current Action" Style="{StaticResource FieldLabel}" Margin="0,0,0,6"/>
                                <WrapPanel Margin="0,0,0,12">
                                    <RadioButton x:Name="CloneFilterAll" Content="All Actions" IsChecked="True" Margin="0,0,16,6"/>
                                    <RadioButton x:Name="CloneFilterAllow" Content="Allow Rules Only" Margin="0,0,16,6"/>
                                    <RadioButton x:Name="CloneFilterDeny" Content="Deny Rules Only" Margin="0,0,16,6"/>
                                </WrapPanel>

                                <Grid Margin="0,0,0,12">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>

                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="New Group/User" Style="{StaticResource CardTitle}"/>
                                        <ComboBox x:Name="CloneTargetGroup" Margin="0,0,0,6"/>
                                        <TextBox x:Name="CloneCustomGroup" Visibility="Collapsed"
                                                 Text="DOMAIN\GroupName"/>
                                    </StackPanel>

                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="New Action" Style="{StaticResource CardTitle}"/>
                                        <RadioButton x:Name="CloneActionKeep" Content="Keep Original" IsChecked="True" Margin="0,0,0,6"/>
                                        <RadioButton x:Name="CloneActionAllow" Content="Set to Allow" Margin="0,0,0,6"/>
                                        <RadioButton x:Name="CloneActionDeny" Content="Set to Deny" Margin="0,0,0,6"/>
                                    </StackPanel>
                                </Grid>

                                <TextBlock Text="Output" Style="{StaticResource CardTitle}"/>
                                <RadioButton x:Name="CloneAppendSource" Content="Append to source policy" IsChecked="True" Margin="0,0,0,6"/>
                                <RadioButton x:Name="CloneNewFile" Content="Create new policy file" Margin="0,0,0,6"/>
                                <Grid x:Name="CloneNewFileOptions" Visibility="Collapsed" Margin="18,6,0,0">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CloneOutputPath" Grid.Column="0" Text=".\Outputs\ClonedPolicy.xml"/>
                                    <Button x:Name="BrowseCloneOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border x:Name="ClonePreviewCard" Style="{StaticResource Card}" Visibility="Collapsed">
                            <StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                    <TextBlock Text="Preview" Style="{StaticResource CardTitle}" Margin="0"/>
                                    <TextBlock x:Name="ClonePreviewCount" Text=" (0 rules)" FontSize="13"
                                               Foreground="{StaticResource TextSecondaryBrush}"/>
                                </StackPanel>
                                <ListBox x:Name="ClonePreviewList" Height="160" Background="#21262D"
                                         BorderBrush="{StaticResource BorderBrush}" Foreground="{StaticResource TextPrimaryBrush}"/>
                            </StackPanel>
                        </Border>

                        <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
                            <Button x:Name="PreviewClone" Content="Preview" Style="{StaticResource SecondaryButton}"
                                    Margin="0,0,10,0" Visibility="Collapsed"/>
                            <Button x:Name="ExecuteClone" Content="Clone Rules" Style="{StaticResource PrimaryButton}"
                                    Visibility="Collapsed"/>
                        </StackPanel>
                    </StackPanel>
                </ScrollViewer>

                <!-- Events Page -->
                <ScrollViewer x:Name="PageEvents" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Collect Events" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Collect AppLocker audit events from remote computers"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Computer List" Style="{StaticResource CardTitle}"/>

                                <!-- Export from AD Section -->
                                <Border Style="{StaticResource CardDark}" Margin="0,0,0,12">
                                    <StackPanel>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                            <TextBlock Text="&#xE716;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                                       Foreground="{StaticResource AccentGreenBrush}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <TextBlock Text="Export from Active Directory" FontSize="12" FontWeight="SemiBold"
                                                       Foreground="{StaticResource TextPrimaryBrush}"/>
                                        </StackPanel>
                                        <Grid Margin="0,0,0,8">
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Text="Type:" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}"
                                                       VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <ComboBox x:Name="EventsADComputerType" Grid.Column="1" SelectedIndex="0" Margin="0,0,8,0">
                                                <ComboBoxItem Content="All Computers"/>
                                                <ComboBoxItem Content="Workstations Only"/>
                                                <ComboBoxItem Content="Servers Only"/>
                                                <ComboBoxItem Content="Domain Controllers"/>
                                            </ComboBox>
                                            <Button x:Name="EventsExportFromAD" Grid.Column="2" Content="Export from AD"
                                                    Style="{StaticResource SecondaryButton}"/>
                                        </Grid>
                                        <CheckBox x:Name="EventsADEnabledOnly" Content="Enabled computers only" IsChecked="True" FontSize="11"/>
                                        <CheckBox x:Name="EventsADWindowsOnly" Content="Windows OS only" IsChecked="True" FontSize="11" Margin="0,4,0,0"/>
                                    </StackPanel>
                                </Border>

                                <!-- Manual file selection -->
                                <TextBlock Text="Or select existing file:" Style="{StaticResource HintText}" Margin="0,0,0,6"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="EventsComputerList" Grid.Column="0"/>
                                    <Button x:Name="BrowseEventsComputerList" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="Text file with one computer per line, or CSV with ComputerName column"
                                           Style="{StaticResource HintText}"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="System Admin Credentials" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="For workstations and member servers"
                                           Style="{StaticResource HintText}" Margin="0,0,0,10"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Username (DOMAIN\user or user@domain)" Style="{StaticResource FieldLabel}"/>
                                        <TextBox x:Name="EventsUsername"/>
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Password" Style="{StaticResource FieldLabel}"/>
                                        <PasswordBox x:Name="EventsPassword"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border x:Name="EventsDCCredentialsCard" Style="{StaticResource Card}" Visibility="Collapsed">
                            <StackPanel>
                                <TextBlock Text="Domain Admin Credentials" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Domain Controllers detected - separate credentials required"
                                           FontSize="10" Foreground="{StaticResource AccentOrangeBrush}" Margin="0,0,0,10"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Username (DOMAIN\user or user@domain)" Style="{StaticResource FieldLabel}"/>
                                        <TextBox x:Name="EventsDCUsername"/>
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Password" Style="{StaticResource FieldLabel}"/>
                                        <PasswordBox x:Name="EventsDCPassword"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Event Options" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="16"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Days Back" Style="{StaticResource FieldLabel}"/>
                                        <ComboBox x:Name="EventsDaysBack" SelectedIndex="1">
                                            <ComboBoxItem Content="7 days"/>
                                            <ComboBoxItem Content="14 days"/>
                                            <ComboBoxItem Content="30 days"/>
                                            <ComboBoxItem Content="90 days"/>
                                            <ComboBoxItem Content="All available"/>
                                        </ComboBox>
                                    </StackPanel>
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Event Types" Style="{StaticResource FieldLabel}"/>
                                        <ComboBox x:Name="EventsType" SelectedIndex="0">
                                            <ComboBoxItem Content="Blocked Only (8004/8006/8008)"/>
                                            <ComboBoxItem Content="Allowed Only (8003/8005/8007)"/>
                                            <ComboBoxItem Content="All Events"/>
                                        </ComboBox>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Output Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="EventsOutputPath" Grid.Column="0" Text=".\Events"/>
                                    <Button x:Name="BrowseEventsOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartEvents" Content="Collect Events" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Compare Page -->
                <ScrollViewer x:Name="PageCompare" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Compare Inventory" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Compare software inventories between systems"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Reference (Baseline)" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CompareReferencePath" Grid.Column="0"/>
                                    <Button x:Name="BrowseCompareReference" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Target (Compare To)" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Inventory file to compare, or computer list when scanning endpoints"
                                           Style="{StaticResource HintText}" Margin="0,0,0,6"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CompareTargetPath" Grid.Column="0"/>
                                    <Button x:Name="BrowseCompareTarget" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Comparison Method" Style="{StaticResource CardTitle}"/>
                                <ComboBox x:Name="CompareMethod" SelectedIndex="0">
                                    <ComboBoxItem Content="Name - Compare by file name"/>
                                    <ComboBoxItem Content="NameVersion - Include version"/>
                                    <ComboBoxItem Content="Hash - Compare by file hash"/>
                                    <ComboBoxItem Content="Publisher - Compare by publisher"/>
                                </ComboBox>
                            </StackPanel>
                        </Border>

                        <!-- Scan Credentials Card -->
                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Scan Credentials" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Credentials for scanning remote computers"
                                           Style="{StaticResource HintText}" Margin="0,0,0,10"/>
                                <CheckBox x:Name="CompareUseLoggedInCredentials" Content="Use logged-in credentials"
                                          IsChecked="True" Margin="0,0,0,12"/>
                                <Border x:Name="CompareCustomCredentialsPanel" Visibility="Collapsed">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="16"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <StackPanel Grid.Column="0">
                                            <TextBlock Text="Username (DOMAIN\user or user@domain)" Style="{StaticResource FieldLabel}"/>
                                            <TextBox x:Name="CompareUsername" />
                                        </StackPanel>
                                        <StackPanel Grid.Column="2">
                                            <TextBlock Text="Password" Style="{StaticResource FieldLabel}"/>
                                            <PasswordBox x:Name="ComparePassword"/>
                                        </StackPanel>
                                    </Grid>
                                </Border>
                            </StackPanel>
                        </Border>

                        <!-- Scan Options Card -->
                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Options" Style="{StaticResource CardTitle}"/>
                                <CheckBox x:Name="CompareScanAllEndpoints" Content="Scan all endpoints from target list"
                                          Margin="0,0,0,8"/>
                                <TextBlock Text="When enabled, scans computers from a list file instead of comparing inventory files"
                                           Style="{StaticResource HintText}" Margin="0,0,0,0"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Output Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="CompareOutputPath" Grid.Column="0" Text=".\Outputs"/>
                                    <Button x:Name="BrowseCompareOutput" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Button x:Name="StartCompare" Content="Compare Inventories" Style="{StaticResource PrimaryButton}"
                                HorizontalAlignment="Left" Margin="0,4,0,0"/>
                    </StackPanel>
                </ScrollViewer>

                <!-- Software Page -->
                <ScrollViewer x:Name="PageSoftware" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Software Lists" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Manage curated software allowlists"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Available Lists" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <ListBox x:Name="SoftwareListBox" Grid.Column="0" Height="150"/>
                                    <StackPanel Grid.Column="1" Margin="10,0,0,0">
                                        <Button x:Name="SoftwareRefresh" Content="Refresh" Style="{StaticResource SmallButton}" Margin="0,0,0,4"/>
                                        <Button x:Name="SoftwareNew" Content="New List" Style="{StaticResource SmallButton}" Margin="0,0,0,4"/>
                                        <Button x:Name="SoftwareDelete" Content="Delete" Style="{StaticResource SmallButton}"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Generate Policy from List" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <ComboBox x:Name="SoftwareGenerateList" Grid.Column="0"/>
                                    <Button x:Name="SoftwareGeneratePolicy" Grid.Column="1" Content="Generate"
                                            Style="{StaticResource PrimaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>

                <!-- AD Page -->
                <ScrollViewer x:Name="PageAD" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Active Directory" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Manage AD resources for AppLocker deployment"
                                   Style="{StaticResource PageSubtitle}"/>

                        <!-- Two-column layout for AD Setup and Scan Users -->
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="16"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <!-- AD Setup Card -->
                            <Border Grid.Column="0" Style="{StaticResource Card}">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                        <TextBlock Text="&#xE713;" FontFamily="Segoe MDL2 Assets" FontSize="18"
                                                   Foreground="{StaticResource AccentBlueBrush}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                        <TextBlock Text="1. AD Setup" FontSize="14" FontWeight="SemiBold"
                                                   Foreground="{StaticResource TextPrimaryBrush}"/>
                                    </StackPanel>
                                    <TextBlock Text="Create AppLocker OUs and security groups in Active Directory"
                                               FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,16" TextWrapping="Wrap"/>
                                    <TextBlock Text="Domain Name" FontSize="12" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,6"/>
                                    <TextBox x:Name="ADDomainName" Margin="0,0,0,12"/>
                                    <TextBlock Text="Group Prefix" FontSize="12" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,6"/>
                                    <TextBox x:Name="ADGroupPrefix" Text="AppLocker" Margin="0,0,0,16"/>
                                    <Button x:Name="ADSetup" Content="Create OUs and Groups" Style="{StaticResource PrimaryButton}" HorizontalAlignment="Left"/>
                                </StackPanel>
                            </Border>

                            <!-- Scan Users Card -->
                            <Border Grid.Column="2" Style="{StaticResource Card}">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                        <TextBlock Text="&#xE716;" FontFamily="Segoe MDL2 Assets" FontSize="18"
                                                   Foreground="{StaticResource AccentOrangeBrush}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                        <TextBlock Text="2. Scan Users" FontSize="14" FontWeight="SemiBold"
                                                   Foreground="{StaticResource TextPrimaryBrush}"/>
                                    </StackPanel>
                                    <TextBlock Text="Export AD users and their group memberships for editing"
                                               FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,16" TextWrapping="Wrap"/>
                                    <TextBlock Text="Search Base (OU)" FontSize="12" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,6"/>
                                    <TextBox x:Name="ADUserSearchBase" Margin="0,0,0,8"/>
                                    <TextBlock Text="Leave blank to search entire domain"
                                               FontSize="10" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,12"/>
                                    <CheckBox x:Name="ADIncludeDisabled" Content="Include disabled accounts" Margin="0,0,0,12"/>
                                    <Grid Margin="0,0,0,16">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBox x:Name="ADUserExportPath" Grid.Column="0" Text=".\ADManagement\ADUserGroups-Export.csv"/>
                                        <Button x:Name="BrowseADUserExport" Grid.Column="1" Content="..."
                                                Style="{StaticResource SecondaryButton}" Margin="8,0,0,0" Padding="8,6"/>
                                    </Grid>
                                    <Button x:Name="ADScanUsers" Content="Scan Users" Style="{StaticResource PrimaryButton}" HorizontalAlignment="Left"/>
                                </StackPanel>
                            </Border>
                        </Grid>

                        <!-- Group Manager Card -->
                        <Border Style="{StaticResource Card}" Margin="0,16,0,0">
                            <StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                    <TextBlock Text="&#xE902;" FontFamily="Segoe MDL2 Assets" FontSize="18"
                                               Foreground="{StaticResource AccentGreenBrush}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                    <TextBlock Text="3. Quick Group Manager" FontSize="14" FontWeight="SemiBold"
                                               Foreground="{StaticResource TextPrimaryBrush}"/>
                                </StackPanel>
                                <TextBlock Text="Quickly add or remove users from AppLocker groups"
                                           FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,16" TextWrapping="Wrap"/>

                                <!-- Target Group Selection -->
                                <Grid Margin="0,0,0,16">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Text="Target Group:" FontSize="12" Foreground="{StaticResource TextSecondaryBrush}"
                                               VerticalAlignment="Center" Margin="0,0,12,0"/>
                                    <ComboBox x:Name="ADGroupManagerTarget" Grid.Column="1" SelectedIndex="0">
                                        <ComboBoxItem Content="AppLocker-StandardUsers"/>
                                        <ComboBoxItem Content="AppLocker-Admins"/>
                                        <ComboBoxItem Content="AppLocker-ServiceAccounts"/>
                                        <ComboBoxItem Content="AppLocker-Installers"/>
                                    </ComboBox>
                                    <Button x:Name="ADGroupManagerRefresh" Grid.Column="2" Content="Refresh"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>

                                <!-- Two-panel layout -->
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>

                                    <!-- Available Users Panel -->
                                    <StackPanel Grid.Column="0">
                                        <TextBlock Text="Available Users" FontSize="12" FontWeight="SemiBold"
                                                   Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,8"/>
                                        <Border Background="#161B22" CornerRadius="6" Padding="8">
                                            <StackPanel>
                                                <Grid Margin="0,0,0,8">
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="*"/>
                                                        <ColumnDefinition Width="Auto"/>
                                                    </Grid.ColumnDefinitions>
                                                    <TextBox x:Name="ADGroupManagerSearch" Grid.Column="0"/>
                                                    <Button x:Name="ADGroupManagerLoadUsers" Grid.Column="1" Content="Load"
                                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                                </Grid>
                                                <ComboBox x:Name="ADGroupManagerUserFilter" SelectedIndex="0" Margin="0,0,0,8">
                                                    <ComboBoxItem Content="All Users"/>
                                                    <ComboBoxItem Content="Standard Users"/>
                                                    <ComboBoxItem Content="Service Accounts"/>
                                                    <ComboBoxItem Content="Privileged Accounts"/>
                                                </ComboBox>
                                                <ListBox x:Name="ADGroupManagerAvailable" Height="200"
                                                         SelectionMode="Extended" Background="#0D1117"
                                                         Foreground="{StaticResource TextPrimaryBrush}"/>
                                                <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
                                                    <Button x:Name="ADGroupManagerSelectAll" Content="Select All"
                                                            Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                                                    <Button x:Name="ADGroupManagerSelectNone" Content="Clear"
                                                            Style="{StaticResource SmallButton}"/>
                                                </StackPanel>
                                            </StackPanel>
                                        </Border>
                                    </StackPanel>

                                    <!-- Action Buttons -->
                                    <StackPanel Grid.Column="1" VerticalAlignment="Center" Margin="16,40,16,0">
                                        <Button x:Name="ADGroupManagerAdd" Content="Add >" Style="{StaticResource PrimaryButton}"
                                                Margin="0,0,0,8" Padding="16,8"/>
                                        <Button x:Name="ADGroupManagerRemove" Content="&lt; Remove" Style="{StaticResource SecondaryButton}"
                                                Padding="16,8"/>
                                    </StackPanel>

                                    <!-- Current Members Panel -->
                                    <StackPanel Grid.Column="2">
                                        <TextBlock Text="Current Members" FontSize="12" FontWeight="SemiBold"
                                                   Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,8"/>
                                        <Border Background="#161B22" CornerRadius="6" Padding="8">
                                            <StackPanel>
                                                <TextBlock x:Name="ADGroupManagerMemberCount" Text="0 members"
                                                           FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,8"/>
                                                <ListBox x:Name="ADGroupManagerMembers" Height="248"
                                                         SelectionMode="Extended" Background="#0D1117"
                                                         Foreground="{StaticResource TextPrimaryBrush}"/>
                                            </StackPanel>
                                        </Border>
                                    </StackPanel>
                                </Grid>

                                <!-- Apply Button -->
                                <StackPanel Orientation="Horizontal" Margin="0,16,0,0">
                                    <CheckBox x:Name="ADGroupManagerPreview" Content="Preview only" IsChecked="True" Margin="0,0,16,0"
                                              VerticalAlignment="Center"/>
                                    <Button x:Name="ADGroupManagerApply" Content="Apply Changes to AD" Style="{StaticResource PrimaryButton}"/>
                                    <TextBlock x:Name="ADGroupManagerStatus" Text="" FontSize="11"
                                               Foreground="{StaticResource TextMutedBrush}" VerticalAlignment="Center" Margin="16,0,0,0"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <!-- Import Group Memberships Card -->
                        <Border Style="{StaticResource Card}" Margin="0,16,0,0">
                            <StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                                    <TextBlock Text="&#xE8FB;" FontFamily="Segoe MDL2 Assets" FontSize="18"
                                               Foreground="{StaticResource AccentPurpleBrush}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                    <TextBlock Text="4. Bulk Import Group Memberships" FontSize="14" FontWeight="SemiBold"
                                               Foreground="{StaticResource TextPrimaryBrush}"/>
                                </StackPanel>
                                <TextBlock Text="Add users to groups from CSV file (Group,Users format)"
                                           FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,16" TextWrapping="Wrap"/>
                                <TextBlock Text="Import File" FontSize="12" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,0,0,6"/>
                                <Grid Margin="0,0,0,8">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="ADImportPath" Grid.Column="0" Text=".\ADManagement\groups.csv"/>
                                    <Button x:Name="BrowseADImport" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock Text="CSV Format: Group,Users (semicolon-separated usernames)"
                                           FontSize="10" Foreground="{StaticResource TextMutedBrush}" Margin="0,0,0,12" TextWrapping="Wrap"/>
                                <CheckBox x:Name="ADImportPreview" Content="Preview only (don't apply changes)" IsChecked="True" Margin="0,0,0,16"/>
                                <StackPanel Orientation="Horizontal">
                                    <Button x:Name="ADImportUsers" Content="Import Users to Groups" Style="{StaticResource PrimaryButton}"/>
                                    <Button x:Name="ADViewImportFile" Content="View File" Style="{StaticResource SecondaryButton}" Margin="12,0,0,0"/>
                                </StackPanel>
                            </StackPanel>
                        </Border>

                        <!-- Help Section -->
                        <Border Style="{StaticResource Card}" Margin="0,16,0,0">
                            <StackPanel>
                                <TextBlock Text="Workflow Guide" FontSize="14" FontWeight="SemiBold"
                                           Foreground="{StaticResource TextPrimaryBrush}" Margin="0,0,0,12"/>
                                <TextBlock TextWrapping="Wrap" Foreground="{StaticResource TextSecondaryBrush}" FontSize="12" LineHeight="22">
                                    <Run FontWeight="SemiBold" Foreground="{StaticResource AccentBlueBrush}">1. AD Setup:</Run>
                                    <Run>Create AppLocker OUs and security groups in AD. Creates groups: Admins, StandardUsers, ServiceAccounts, Installers. Required before assigning users.</Run>
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="SemiBold" Foreground="{StaticResource AccentOrangeBrush}">2. Scan Users:</Run>
                                    <Run>Export all domain users with their current group memberships to CSV. Use for reviewing user categorization or external editing before bulk import.</Run>
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="SemiBold" Foreground="{StaticResource AccentGreenBrush}">3. Group Manager:</Run>
                                    <Run>Visual interface to add/remove users from AppLocker groups. Click 'Load' to fetch users, filter by type, select users, use Add/Remove buttons, then Apply.</Run>
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="SemiBold" Foreground="{StaticResource AccentPurpleBrush}">4. Bulk Import:</Run>
                                    <Run>Import group membership changes from CSV file. Format: Group,Users (semicolon-separated). Useful for large-scale changes or scripted workflows.</Run>
                                </TextBlock>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>

                <!-- Diagnostics Page -->
                <ScrollViewer x:Name="PageDiagnostics" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Diagnostics" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Troubleshoot connectivity issues"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Target Computer" Style="{StaticResource CardTitle}"/>
                                <TextBox x:Name="DiagnosticComputerName" Margin="0,0,0,12"/>
                                <Button x:Name="StartDiagnostic" Content="Run Diagnostic" Style="{StaticResource PrimaryButton}" HorizontalAlignment="Left"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>

                <!-- WinRM Page -->
                <ScrollViewer x:Name="PageWinRM" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="WinRM Setup" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Deploy WinRM for remote scanning"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Deploy WinRM GPO" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Creates a GPO to enable WinRM on domain computers"
                                           Style="{StaticResource HintText}" Margin="0,0,0,12"/>
                                <Button x:Name="WinRMDeploy" Content="Deploy GPO" Style="{StaticResource PrimaryButton}" HorizontalAlignment="Left"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Remove WinRM GPO" Style="{StaticResource CardTitle}"/>
                                <Button x:Name="WinRMRemove" Content="Remove GPO" Style="{StaticResource SecondaryButton}" HorizontalAlignment="Left"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>

                <!-- Settings Page -->
                <ScrollViewer x:Name="PageSettings" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="Settings" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="Configure application settings"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Scripts Location" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBox x:Name="SettingsScriptsPath" Grid.Column="0"/>
                                    <Button x:Name="BrowseScriptsPath" Grid.Column="1" Content="Browse"
                                            Style="{StaticResource SecondaryButton}" Margin="8,0,0,0"/>
                                </Grid>
                                <TextBlock x:Name="ScriptsStatusText" Text="" Style="{StaticResource HintText}"/>
                            </StackPanel>
                        </Border>

                    </StackPanel>
                </ScrollViewer>

                <!-- Help Page -->
                <Grid x:Name="PageHelp" Visibility="Collapsed">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="180"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <!-- Help Topics Navigation -->
                    <Border Grid.Column="0" Style="{StaticResource Card}" Padding="8" Margin="24,20,12,24">
                        <StackPanel>
                            <TextBlock Text="Topics" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPrimaryBrush}" Margin="8,4,0,12"/>
                            <Button x:Name="HelpGettingStarted" Style="{StaticResource NavButton}" Content="Getting Started" Padding="8,6"/>
                            <Button x:Name="HelpScanning" Style="{StaticResource NavButton}" Content="Scanning" Padding="8,6"/>
                            <Button x:Name="HelpPolicyGen" Style="{StaticResource NavButton}" Content="Policy Generation" Padding="8,6"/>
                            <Button x:Name="HelpMerging" Style="{StaticResource NavButton}" Content="Merging Policies" Padding="8,6"/>
                            <Button x:Name="HelpEvents" Style="{StaticResource NavButton}" Content="Event Collection" Padding="8,6"/>
                            <Button x:Name="HelpSoftwareLists" Style="{StaticResource NavButton}" Content="Software Lists" Padding="8,6"/>
                            <Button x:Name="HelpDeployment" Style="{StaticResource NavButton}" Content="Deployment" Padding="8,6"/>
                            <Button x:Name="HelpTroubleshooting" Style="{StaticResource NavButton}" Content="Troubleshooting" Padding="8,6"/>
                            <Button x:Name="HelpFAQ" Style="{StaticResource NavButton}" Content="FAQ" Padding="8,6"/>
                        </StackPanel>
                    </Border>

                    <!-- Help Content -->
                    <Border Grid.Column="1" Style="{StaticResource Card}" Padding="20" Margin="0,20,24,24">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <StackPanel x:Name="HelpContent">
                                <TextBlock x:Name="HelpTitle" Text="Getting Started" FontSize="20" FontWeight="Bold" Foreground="{StaticResource TextPrimaryBrush}" Margin="0,0,0,16"/>
                                <TextBlock x:Name="HelpBody" TextWrapping="Wrap" FontSize="12" Foreground="{StaticResource TextSecondaryBrush}" Text="Welcome to GA-AppLocker!"/>
                            </StackPanel>
                        </ScrollViewer>
                    </Border>
                </Grid>

                <!-- About Page -->
                <ScrollViewer x:Name="PageAbout" VerticalScrollBarVisibility="Auto" Visibility="Collapsed">
                    <StackPanel Margin="24,20,24,24">
                        <TextBlock Text="About GA-AppLocker" Style="{StaticResource PageTitle}"/>
                        <TextBlock Text="AppLocker Policy Deployment Toolkit"
                                   Style="{StaticResource PageSubtitle}"/>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>

                                    <!-- Company Logo -->
                                    <Border Grid.Column="0" Width="70" Height="70" Background="#1A3A6E" CornerRadius="6" Margin="0,0,16,0">
                                        <Image x:Name="AboutLogo" Width="56" Height="56"
                                               HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                    </Border>

                                    <StackPanel Grid.Column="1" VerticalAlignment="Center">
                                        <TextBlock Text="GA-AppLocker" FontSize="20" FontWeight="Bold"
                                                   Foreground="{StaticResource TextPrimaryBrush}"/>
                                        <TextBlock Text="Version 1.2.4" FontSize="12"
                                                   Foreground="{StaticResource TextSecondaryBrush}" Margin="0,2,0,0"/>
                                        <TextBlock Text="Windows AppLocker Policy Management Toolkit" FontSize="11"
                                                   Foreground="{StaticResource TextMutedBrush}" Margin="0,2,0,0"/>
                                    </StackPanel>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Author" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Tony Tran" FontSize="13" FontWeight="SemiBold"
                                           Foreground="{StaticResource AccentBlueBrush}"/>
                                <TextBlock Text="Information Systems Security Officer" FontSize="11"
                                           Foreground="{StaticResource TextSecondaryBrush}" Margin="0,2,0,0"/>
                                <TextBlock Text="Classified Computing, GA-ASI" FontSize="11"
                                           Foreground="{StaticResource TextSecondaryBrush}" Margin="0,2,0,0"/>
                                <TextBlock Text="tony.tran@ga-asi.com" FontSize="11"
                                           Foreground="{StaticResource AccentBlueBrush}" Margin="0,6,0,0"/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="Description" Style="{StaticResource CardTitle}"/>
                                <TextBlock TextWrapping="Wrap" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}"
                                           Text="GA-AppLocker is a comprehensive toolkit for deploying Windows AppLocker policies across enterprise environments. It simplifies the process of scanning computers for installed software, generating AppLocker policies, and managing software allowlists."/>
                                <TextBlock TextWrapping="Wrap" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,10,0,0"
                                           Text="Features include remote computer scanning via WinRM, policy generation with phased deployment support, policy merging with SID replacement, software list management, and Active Directory integration."/>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="System Requirements" Style="{StaticResource CardTitle}"/>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="130"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>

                                    <TextBlock Grid.Row="0" Grid.Column="0" Text="Operating System" FontSize="11" Foreground="{StaticResource TextMutedBrush}"/>
                                    <TextBlock Grid.Row="0" Grid.Column="1" Text="Windows 11 / Server 2019+" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}"/>

                                    <TextBlock Grid.Row="1" Grid.Column="0" Text="PowerShell" FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,3,0,0"/>
                                    <TextBlock Grid.Row="1" Grid.Column="1" Text="Version 5.1 or higher" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,3,0,0"/>

                                    <TextBlock Grid.Row="2" Grid.Column="0" Text="Remote Scans" FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,3,0,0"/>
                                    <TextBlock Grid.Row="2" Grid.Column="1" Text="WinRM enabled on targets" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,3,0,0"/>

                                    <TextBlock Grid.Row="3" Grid.Column="0" Text="AD Features" FontSize="11" Foreground="{StaticResource TextMutedBrush}" Margin="0,3,0,0"/>
                                    <TextBlock Grid.Row="3" Grid.Column="1" Text="Domain Admin credentials" FontSize="11" Foreground="{StaticResource TextSecondaryBrush}" Margin="0,3,0,0"/>
                                </Grid>
                            </StackPanel>
                        </Border>

                        <Border Style="{StaticResource Card}">
                            <StackPanel>
                                <TextBlock Text="License" Style="{StaticResource CardTitle}"/>
                                <TextBlock Text="Internal Use Only - General Atomics Aeronautical Systems, Inc." FontSize="11"
                                           Foreground="{StaticResource TextSecondaryBrush}"/>
                                <TextBlock Text="© 2026 GA-ASI. All rights reserved." FontSize="10"
                                           Foreground="{StaticResource TextMutedBrush}" Margin="0,6,0,0"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </Grid>

            <!-- Log Panel -->
            <Border x:Name="LogPanel" Grid.Row="2" Background="{StaticResource BgSidebarBrush}"
                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,1,0,0"
                    Height="150">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0" Padding="16,8" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Text="Output Log" FontSize="12" FontWeight="SemiBold"
                                       Foreground="{StaticResource TextPrimaryBrush}" VerticalAlignment="Center"/>
                            <StackPanel Grid.Column="1" Orientation="Horizontal">
                                <Button x:Name="ToggleLog" Content="Hide" Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                                <Button x:Name="ClearLog" Content="Clear" Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                                <Button x:Name="SaveLog" Content="Save" Style="{StaticResource SmallButton}"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <TextBox x:Name="LogOutput" Grid.Row="1"
                             IsReadOnly="True" TextWrapping="NoWrap"
                             VerticalScrollBarVisibility="Auto"
                             HorizontalScrollBarVisibility="Auto"
                             FontFamily="Consolas" FontSize="11"
                             Background="{StaticResource BgDarkBrush}"
                             Foreground="{StaticResource TextSecondaryBrush}"
                             BorderThickness="0" Padding="16,8"/>
                </Grid>
            </Border>
        </Grid>
    </Grid>
</Window>
"@
#endregion

#region Window Creation
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$controls = @{}
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object {
    $name = $_.Name
    if (-not $name) { $name = $_.'x:Name' }
    if ($name) { $null = $controls[$name] = $window.FindName($name) }
} | Out-Null

# Load company logo/icon
$Script:LogoPath = $null
$possibleLogoPaths = @(
    (Join-Path $Script:AppRoot "assets\general-atomics-logo.ico"),
    (Join-Path $Script:AppRoot "assets\general-atomics-large.ico"),
    (Join-Path $Script:AppRoot "assets\general-atomics.ico"),
    (Join-Path $Script:AppRoot "assets\ga-applocker.ico"),
    (Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics-logo.ico"),
    (Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics-large.ico"),
    (Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics.ico")
)

foreach ($logoPath in $possibleLogoPaths) {
    if (Test-Path $logoPath) {
        $Script:LogoPath = $logoPath
        break
    }
}

if ($Script:LogoPath) {
    try {
        # Set window icon
        $iconUri = New-Object System.Uri $Script:LogoPath
        $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create($iconUri)

        # Set sidebar logo image - use the GA logo
        if ($controls['SidebarLogo']) {
            $sidebarLogoPath = Join-Path $Script:AppRoot "assets\general-atomics-logo.ico"
            if (-not (Test-Path $sidebarLogoPath)) {
                $sidebarLogoPath = Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics-logo.ico"
            }
            if (-not (Test-Path $sidebarLogoPath)) {
                $sidebarLogoPath = Join-Path $Script:AppRoot "assets\general-atomics.ico"
            }
            if (-not (Test-Path $sidebarLogoPath)) {
                $sidebarLogoPath = Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics.ico"
            }
            if (Test-Path $sidebarLogoPath) {
                $sidebarUri = New-Object System.Uri $sidebarLogoPath
                $bitmapImage = New-Object System.Windows.Media.Imaging.BitmapImage
                $bitmapImage.BeginInit()
                $bitmapImage.UriSource = $sidebarUri
                $bitmapImage.DecodePixelWidth = 32
                $bitmapImage.EndInit()
                $controls['SidebarLogo'].Source = $bitmapImage
            }
        }

        # Set About page logo image - use the GA logo
        if ($controls['AboutLogo']) {
            $aboutLogoPath = Join-Path $Script:AppRoot "assets\general-atomics-logo.ico"
            if (-not (Test-Path $aboutLogoPath)) {
                $aboutLogoPath = Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics-logo.ico"
            }
            if (-not (Test-Path $aboutLogoPath)) {
                $aboutLogoPath = Join-Path $Script:AppRoot "assets\general-atomics-large.ico"
            }
            if (-not (Test-Path $aboutLogoPath)) {
                $aboutLogoPath = Join-Path (Split-Path -Parent $Script:AppRoot) "assets\general-atomics-large.ico"
            }
            if (Test-Path $aboutLogoPath) {
                $aboutUri = New-Object System.Uri $aboutLogoPath
                $aboutBitmap = New-Object System.Windows.Media.Imaging.BitmapImage
                $aboutBitmap.BeginInit()
                $aboutBitmap.UriSource = $aboutUri
                $aboutBitmap.DecodePixelWidth = 64
                $aboutBitmap.EndInit()
                $controls['AboutLogo'].Source = $aboutBitmap
            }
        }
    }
    catch {
        # Silently continue if logo loading fails
    }
}
#endregion

#region Helper Functions
function Write-Log {
    param([string]$Message, [ValidateSet('Info','Success','Warning','Error')][string]$Level = 'Info')
    $timestamp = Get-Date -Format "HH:mm:ss"
    $prefix = switch ($Level) { 'Success' { "[+]" } 'Warning' { "[!]" } 'Error' { "[-]" } default { "[*]" } }
    $controls['LogOutput'].Dispatcher.Invoke([Action]{
        $controls['LogOutput'].AppendText("[$timestamp] $prefix $Message`r`n")
        $controls['LogOutput'].ScrollToEnd()
    })
}

function Set-Status {
    param(
        [ValidateSet('Ready','Running','Success','Error','Cancelled')][string]$State = 'Ready',
        [switch]$ShowCancel
    )
    $controls['StatusText'].Dispatcher.Invoke([Action]{
        $controls['StatusText'].Text = switch ($State) {
            'Running' { "Running..." }
            'Success' { "Complete" }
            'Error' { "Error" }
            'Cancelled' { "Cancelled" }
            default { "Ready" }
        }
        $controls['StatusDot'].Fill = switch ($State) {
            'Running' { [System.Windows.Media.Brushes]::Orange }
            'Success' { [System.Windows.Media.Brushes]::LightGreen }
            'Error'   { [System.Windows.Media.Brushes]::Red }
            'Cancelled' { [System.Windows.Media.Brushes]::Yellow }
            default   { [System.Windows.Media.Brushes]::LightGreen }
        }
        # Show/hide cancel button based on state
        if ($controls['CancelOperation']) {
            $controls['CancelOperation'].Visibility = if ($State -eq 'Running') { 'Visible' } else { 'Collapsed' }
        }
    })
}

function Initialize-EnvironmentDetection {
    <#
    .SYNOPSIS
        Auto-detects environment settings to pre-populate GUI fields
    #>
    $Script:DetectedEnvironment = @{
        IsDomainJoined = $false
        DomainName = ""
        IsServer = $false
        IsDomainController = $false
        RecommendedTargetType = "Workstation"
        AppLockerServiceRunning = $false
        HasExistingPolicy = $false
        ExistingRuleCount = 0
        LatestScanPath = $null
        LatestEventPath = $null
        ComputerListPath = $null
        HasRecentBlocks = $false
        RecentBlockCount = 0
    }

    try {
        # Check domain membership
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($computerSystem) {
            $Script:DetectedEnvironment.IsDomainJoined = $computerSystem.PartOfDomain
            if ($computerSystem.PartOfDomain) {
                $Script:DetectedEnvironment.DomainName = $computerSystem.Domain -replace '\..*$', ''
            }

            # Detect server vs workstation
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($os) {
                $Script:DetectedEnvironment.IsServer = $os.ProductType -ne 1
            }

            # Detect domain controller
            $Script:DetectedEnvironment.IsDomainController = $computerSystem.DomainRole -in @(4, 5)
        }

        # Recommend target type
        if ($Script:DetectedEnvironment.IsDomainController) {
            $Script:DetectedEnvironment.RecommendedTargetType = "DomainController"
        } elseif ($Script:DetectedEnvironment.IsServer) {
            $Script:DetectedEnvironment.RecommendedTargetType = "Server"
        } else {
            $Script:DetectedEnvironment.RecommendedTargetType = "Workstation"
        }

        # Check AppLocker service
        $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        if ($svc) {
            $Script:DetectedEnvironment.AppLockerServiceRunning = $svc.Status -eq 'Running'
        }

        # Check for existing policy
        try {
            $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
            if ($policy -and $policy.RuleCollections) {
                $Script:DetectedEnvironment.HasExistingPolicy = $true
                $Script:DetectedEnvironment.ExistingRuleCount = ($policy.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
            }
        } catch { }

        # Check for recent blocked events (last 24 hours)
        try {
            $recentBlocks = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -eq 8004 -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
            if ($recentBlocks) {
                $Script:DetectedEnvironment.HasRecentBlocks = $true
                $Script:DetectedEnvironment.RecentBlockCount = $recentBlocks.Count
            }
        } catch { }

        # Find latest scan folder
        $scansPath = Join-Path $Script:AppRoot "Scans"
        if (Test-Path $scansPath) {
            $latestScan = Get-ChildItem -Path $scansPath -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestScan) {
                $Script:DetectedEnvironment.LatestScanPath = $latestScan.FullName
            }
        }

        # Find latest events folder
        $eventsPath = Join-Path $Script:AppRoot "Events"
        if (Test-Path $eventsPath) {
            $latestEvents = Get-ChildItem -Path $eventsPath -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestEvents) {
                $Script:DetectedEnvironment.LatestEventPath = $latestEvents.FullName
            }
        }

        # Find computer list
        $computerListPaths = @(
            (Join-Path $Script:AppRoot "ADManagement\computers.csv"),
            (Join-Path $Script:AppRoot "computers.txt"),
            (Join-Path $Script:AppRoot "computers.csv")
        )
        foreach ($p in $computerListPaths) {
            if (Test-Path $p) {
                $Script:DetectedEnvironment.ComputerListPath = $p
                break
            }
        }

    } catch {
        # Silent fail - detection is optional
    }

    return $Script:DetectedEnvironment
}

function Apply-DetectedDefaults {
    <#
    .SYNOPSIS
        Applies auto-detected values to GUI fields
    #>
    $env = $Script:DetectedEnvironment
    if (-not $env) { return }

    # Apply domain name to generate page and AD page
    if ($env.DomainName) {
        $domainUpper = $env.DomainName.ToUpper()
        if ($controls['GenerateDomainName']) {
            $controls['GenerateDomainName'].Text = $domainUpper
        }
        if ($controls['ADDomainName']) {
            $controls['ADDomainName'].Text = $domainUpper
        }
    }

    # Apply recommended target type
    if ($controls['GenerateTargetType'] -and $env.RecommendedTargetType) {
        $targetIndex = switch ($env.RecommendedTargetType) {
            "Workstation" { 0 }
            "Server" { 1 }
            "DomainController" { 2 }
            default { 0 }
        }
        $controls['GenerateTargetType'].SelectedIndex = $targetIndex
    }

    # Apply latest scan path
    if ($env.LatestScanPath -and $controls['GenerateScanPath']) {
        $controls['GenerateScanPath'].Text = $env.LatestScanPath
    }

    # Apply computer list path
    if ($env.ComputerListPath -and $controls['ScanComputerList']) {
        $controls['ScanComputerList'].Text = $env.ComputerListPath
    }

    # Log detected environment
    Write-Log "=== Environment Auto-Detection ===" -Level Info
    if ($env.IsDomainJoined) {
        Write-Log "Domain: $($env.DomainName)" -Level Info
    } else {
        Write-Log "Workgroup computer (not domain-joined)" -Level Info
    }
    Write-Log "Detected type: $($env.RecommendedTargetType)" -Level Info

    if ($env.AppLockerServiceRunning) {
        Write-Log "AppLocker service: Running" -Level Success
    } else {
        Write-Log "AppLocker service: Not running (start before deploying)" -Level Warning
    }

    if ($env.HasExistingPolicy) {
        Write-Log "Existing policy: $($env.ExistingRuleCount) rules active" -Level Info
    }

    if ($env.HasRecentBlocks) {
        Write-Log "Recent blocks: $($env.RecentBlockCount) in last 24 hours" -Level Warning
    }

    if ($env.LatestScanPath) {
        Write-Log "Latest scan data found: $(Split-Path $env.LatestScanPath -Leaf)" -Level Info
    }

    if ($env.ComputerListPath) {
        Write-Log "Computer list found: $(Split-Path $env.ComputerListPath -Leaf)" -Level Info
    }
}

function Get-OpenFileDialog {
    param([string]$Title = "Select File", [string]$Filter = "All Files (*.*)|*.*")
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Title = $Title; $dialog.Filter = $Filter
    if ($dialog.ShowDialog() -eq $true) { return $dialog.FileName }
    return $null
}

function Get-FolderDialog {
    param([string]$Description = "Select Folder")
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    if ($dialog.ShowDialog() -eq 'OK') { return $dialog.SelectedPath }
    return $null
}

function Get-SaveFileDialog {
    param([string]$Title = "Save File", [string]$Filter = "All Files (*.*)|*.*", [string]$DefaultExt = "")
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Title = $Title; $dialog.Filter = $Filter; $dialog.DefaultExt = $DefaultExt
    if ($dialog.ShowDialog() -eq $true) { return $dialog.FileName }
    return $null
}

#region Helper Functions for Event Handlers

function New-BrowseHandler {
    <#
    .SYNOPSIS
    Factory function to create browse button handlers
    #>
    param(
        [string]$TargetControl,
        [ValidateSet('Folder', 'File', 'XML', 'CSV')]
        [string]$DialogType = 'Folder',
        [string]$Title = $null
    )

    $handler = {
        param($ctl, $dtype, $ttl)
        $path = switch ($dtype) {
            'Folder' { Get-FolderDialog -Description $(if ($ttl) { $ttl } else { "Select Folder" }) }
            'File'   { Get-OpenFileDialog -Title $(if ($ttl) { $ttl } else { "Select File" }) }
            'XML'    { Get-OpenFileDialog -Title $(if ($ttl) { $ttl } else { "Select XML File" }) -Filter "XML Files (*.xml)|*.xml|All Files (*.*)|*.*" }
            'CSV'    { Get-OpenFileDialog -Title $(if ($ttl) { $ttl } else { "Select CSV File" }) -Filter "CSV/Text Files (*.csv;*.txt)|*.csv;*.txt|All Files (*.*)|*.*" }
        }
        if ($path) { $controls[$ctl].Text = $path }
    }.GetNewClosure()

    return { & $handler $TargetControl $DialogType $Title }.GetNewClosure()
}

function Add-CredentialParams {
    <#
    .SYNOPSIS
    Adds credential parameters to a hashtable from UI controls
    #>
    param(
        [hashtable]$Params,
        [string]$PagePrefix
    )

    $username = $controls["${PagePrefix}Username"].Text
    $password = $controls["${PagePrefix}Password"].SecurePassword
    if ($username -and $password.Length -gt 0) {
        $Params['Credential'] = [System.Management.Automation.PSCredential]::new($username, $password)
    }

    # Add DC credentials if available
    if ($controls["${PagePrefix}DCUsername"]) {
        $dcUser = $controls["${PagePrefix}DCUsername"].Text
        $dcPass = $controls["${PagePrefix}DCPassword"].SecurePassword
        if ($dcUser -and $dcPass.Length -gt 0) {
            $Params['DCCredential'] = [System.Management.Automation.PSCredential]::new($dcUser, $dcPass)
        }
    }

    return $Params
}

function Invoke-ADComputerExport {
    <#
    .SYNOPSIS
    Exports computers from Active Directory for Scan or Events pages
    #>
    param([string]$PagePrefix)

    $computerType = switch ($controls["${PagePrefix}ADComputerType"].SelectedIndex) {
        0 { "All" }
        1 { "Workstation" }
        2 { "Server" }
        3 { "DC" }
        default { "All" }
    }

    $outputPath = Join-Path $Script:AppRoot "ADManagement"
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }
    $outputFile = Join-Path $outputPath "computers.csv"

    $adParams = @{
        OutputPath = $outputFile
        ComputerType = $computerType
        EnabledOnly = $controls["${PagePrefix}ADEnabledOnly"].IsChecked
        WindowsOnly = $controls["${PagePrefix}ADWindowsOnly"].IsChecked
    }

    Write-Log "Exporting $computerType computers from AD..." -Level Info

    try {
        $scriptPath = Join-Path $Script:AppRoot "src\Utilities\Manage-ADResources.ps1"
        if (Test-Path $scriptPath) {
            & $scriptPath -Mode ExportComputers @adParams
            if (Test-Path $outputFile) {
                $controls["${PagePrefix}ComputerList"].Text = $outputFile
                Test-ComputerListForDCs -ComputerListPath $outputFile -DCCardName "${PagePrefix}DCCredentialsCard"
                Write-Log "Exported to: $outputFile" -Level Success
            }
        } else {
            Write-Log "AD export script not found" -Level Error
        }
    } catch {
        Write-Log "AD export failed: $_" -Level Error
    }
}

#endregion

function Test-ComputerListForDCs {
    <#
    .SYNOPSIS
    Checks if a computer list contains Domain Controllers and updates UI visibility
    #>
    param(
        [string]$ComputerListPath,
        [string]$DCCardName  # 'ScanDCCredentialsCard' or 'EventsDCCredentialsCard'
    )

    $hasDCs = $false

    if ($ComputerListPath -and (Test-Path $ComputerListPath)) {
        try {
            # Get list of Domain Controllers from AD if available
            $domainControllers = @()
            if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
                $domainControllers = @((Get-ADDomainController -Filter * -ErrorAction SilentlyContinue).Name)
            }

            if ($domainControllers.Count -gt 0) {
                # Read computer list
                $computers = @()
                $extension = [System.IO.Path]::GetExtension($ComputerListPath).ToLower()
                if ($extension -eq '.csv') {
                    $csvData = Import-Csv -Path $ComputerListPath -ErrorAction SilentlyContinue
                    if ($csvData) {
                        $computers = @($csvData | ForEach-Object {
                            if ($_.ComputerName) { $_.ComputerName }
                            elseif ($_.Name) { $_.Name }
                            elseif ($_.Computer) { $_.Computer }
                        } | Where-Object { $_ })
                    }
                } else {
                    $computers = @(Get-Content $ComputerListPath -ErrorAction SilentlyContinue |
                        Where-Object { $_ -and $_.Trim() -and -not $_.StartsWith('#') } |
                        ForEach-Object { $_.Trim() })
                }

                # Check if any computer in the list is a DC
                foreach ($computer in $computers) {
                    $computerName = $computer.Split('.')[0]  # Get hostname without domain
                    if ($domainControllers -contains $computerName) {
                        $hasDCs = $true
                        break
                    }
                }
            }
        }
        catch {
            # If we can't check, assume no DCs (card stays hidden)
        }
    }

    # Update UI visibility
    if ($controls[$DCCardName]) {
        $controls[$DCCardName].Visibility = if ($hasDCs) { 'Visible' } else { 'Collapsed' }
    }

    return $hasDCs
}

# Track operation state for button management
$Script:OperationRunning = $false
$Script:CancellationRequested = $false
$Script:OperationButtons = @('StartScan', 'StartEvents', 'StartGenerate', 'StartMerge', 'StartCompare', 'StartValidate', 'StartCORA', 'StartDiagnostic', 'RunWorkflow')

function Set-OperationButtonsEnabled {
    param([bool]$Enabled)
    foreach ($btnName in $Script:OperationButtons) {
        if ($controls[$btnName]) {
            $controls[$btnName].Dispatcher.Invoke([Action]{
                $controls[$btnName].IsEnabled = $Enabled
                if (-not $Enabled) {
                    $controls[$btnName].Content = $controls[$btnName].Content -replace ' \(Running\.\.\.\)$', ''
                }
            })
        }
    }
}

function Invoke-Script {
    param([string]$ScriptName, [hashtable]$Parameters = @{}, [string]$CallerButton = "")

    if ($Script:OperationRunning) {
        Write-Log "An operation is already running. Please wait." -Level Warning
        return
    }

    if (-not $Script:ScriptsAvailable) {
        Write-Log "Scripts not found. Please configure Scripts Location in Settings." -Level Error
        return
    }

    $scriptPath = Join-Path $Script:AppRoot $ScriptName
    if (-not (Test-Path $scriptPath)) {
        Write-Log "Script not found: $scriptPath" -Level Error
        return
    }

    # Disable operation buttons during execution
    $Script:OperationRunning = $true
    $Script:CancellationRequested = $false
    Set-OperationButtonsEnabled -Enabled $false

    # Reset cancel button state
    $controls['CancelOperation'].Dispatcher.Invoke([Action]{
        $controls['CancelOperation'].IsEnabled = $true
        $controls['CancelOperation'].Content = "Cancel"
    })

    Set-Status -State 'Running'
    try {
        & $scriptPath @Parameters 2>&1 | ForEach-Object {
            Write-Log $_.ToString()
            # Check for cancellation (note: this only works between output lines)
            if ($Script:CancellationRequested) {
                throw "Operation cancelled by user"
            }
        }
        if ($Script:CancellationRequested) {
            Set-Status -State 'Cancelled'
            Write-Log "Operation was cancelled." -Level Warning
        } else {
            Set-Status -State 'Success'
        }
    } catch {
        if ($_.Exception.Message -eq "Operation cancelled by user") {
            Set-Status -State 'Cancelled'
            Write-Log "Operation cancelled by user." -Level Warning
        } else {
            Write-Log "Error: $_" -Level Error
            Set-Status -State 'Error'
        }
    } finally {
        # Re-enable operation buttons
        $Script:OperationRunning = $false
        $Script:CancellationRequested = $false
        Set-OperationButtonsEnabled -Enabled $true
    }
}

# Navigation
$Script:Pages = @("Scan","Generate","Merge","Validate","Clone","Events","Compare","Software","CORA","AD","Diagnostics","WinRM","Settings","Help","About")

function Switch-Page {
    param([string]$PageName)
    foreach ($page in $Script:Pages) { $controls["Page$page"].Visibility = 'Collapsed' }
    $controls["Page$PageName"].Visibility = 'Visible'
    foreach ($page in $Script:Pages) {
        $nav = $controls["Nav$page"]
        if ($nav) { $nav.Style = $window.FindResource($(if ($page -eq $PageName) { "NavButtonActive" } else { "NavButton" })) }
    }
}

function Set-WorkflowStatus {
    param([ValidateSet('Ready','Running','Success','Error')][string]$State = 'Ready', [string]$Message = "")
    # Use the sidebar status controls
    $controls['StatusText'].Dispatcher.Invoke([Action]{
        $controls['StatusText'].Text = if ($Message) { $Message } else {
            switch ($State) { 'Running' { "Running..." } 'Success' { "Complete" } 'Error' { "Error" } default { "Ready" } }
        }
        $controls['StatusDot'].Fill = switch ($State) {
            'Running' { [System.Windows.Media.Brushes]::Orange }
            'Success' { [System.Windows.Media.Brushes]::LightGreen }
            'Error'   { [System.Windows.Media.Brushes]::Red }
            default   { [System.Windows.Media.Brushes]::LightGreen }
        }
    })
}

function Show-WorkflowDialog {
    param([string]$WorkflowType)

    $dialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$WorkflowType" Height="500" Width="550"
        WindowStartupLocation="CenterOwner" Background="#0D1117"
        ResizeMode="NoResize">
    <Window.Resources>
        <SolidColorBrush x:Key="TextPrimary" Color="#E6EDF3"/>
        <SolidColorBrush x:Key="TextSecondary" Color="#8B949E"/>
        <SolidColorBrush x:Key="AccentBlue" Color="#58A6FF"/>
        <SolidColorBrush x:Key="AccentGreen" Color="#3FB950"/>
        <SolidColorBrush x:Key="BgCard" Color="#161B22"/>
        <SolidColorBrush x:Key="Border" Color="#30363D"/>
    </Window.Resources>
    <Grid Margin="24">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,20">
            <TextBlock x:Name="DialogTitle" Text="$WorkflowType" FontSize="22" FontWeight="Bold" Foreground="{StaticResource TextPrimary}"/>
            <TextBlock x:Name="DialogSubtitle" Text="" FontSize="13" Foreground="{StaticResource TextSecondary}" Margin="0,4,0,0" TextWrapping="Wrap"/>
        </StackPanel>

        <!-- Content Area -->
        <Border Grid.Row="1" Background="{StaticResource BgCard}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="20">
            <StackPanel x:Name="DialogContent">
                <!-- Target Selection -->
                <TextBlock Text="Target" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPrimary}" Margin="0,0,0,12"/>
                <RadioButton x:Name="TargetLocal" Content="This computer only" IsChecked="True" Foreground="{StaticResource TextPrimary}" Margin="0,0,0,8"/>
                <RadioButton x:Name="TargetMultiple" Content="Multiple computers (from list)" Foreground="{StaticResource TextPrimary}" Margin="0,0,0,16"/>

                <StackPanel x:Name="ComputerListPanel" Visibility="Collapsed">
                    <TextBlock Text="Computer List" FontSize="12" Foreground="{StaticResource TextSecondary}" Margin="0,0,0,6"/>
                    <Grid Margin="0,0,0,16">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox x:Name="ComputerListPath" Grid.Column="0" Background="#21262D" Foreground="{StaticResource TextPrimary}" BorderBrush="{StaticResource Border}" Padding="8,6"/>
                        <Button x:Name="BrowseComputerList" Grid.Column="1" Content="Browse" Background="#21262D" Foreground="{StaticResource TextPrimary}" BorderBrush="{StaticResource Border}" Padding="12,6" Margin="8,0,0,0"/>
                    </Grid>
                </StackPanel>

                <!-- Output Folder -->
                <TextBlock Text="Output Folder" FontSize="12" Foreground="{StaticResource TextSecondary}" Margin="0,0,0,6"/>
                <Grid Margin="0,0,0,16">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="OutputPath" Grid.Column="0" Text=".\Outputs" Background="#21262D" Foreground="{StaticResource TextPrimary}" BorderBrush="{StaticResource Border}" Padding="8,6"/>
                    <Button x:Name="BrowseOutput" Grid.Column="1" Content="Browse" Background="#21262D" Foreground="{StaticResource TextPrimary}" BorderBrush="{StaticResource Border}" Padding="12,6" Margin="8,0,0,0"/>
                </Grid>

                <!-- Options -->
                <TextBlock Text="Options" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextPrimary}" Margin="0,8,0,12"/>
                <CheckBox x:Name="IncludeDenyRules" Content="Include LOLBins Deny Rules" Foreground="{StaticResource TextPrimary}" Margin="0,0,0,8"/>
                <CheckBox x:Name="IncludeHashRules" Content="Include Hash Rules (unsigned apps)" Foreground="{StaticResource TextPrimary}" Margin="0,0,0,8"/>
                <CheckBox x:Name="CollectEvents" Content="Collect audit events (if available)" IsChecked="True" Foreground="{StaticResource TextPrimary}" Margin="0,0,0,8"/>

                <!-- Progress -->
                <StackPanel x:Name="ProgressPanel" Visibility="Collapsed" Margin="0,16,0,0">
                    <TextBlock x:Name="ProgressText" Text="Initializing..." FontSize="12" Foreground="{StaticResource AccentBlue}" Margin="0,0,0,8"/>
                    <ProgressBar x:Name="ProgressBar" Height="6" IsIndeterminate="True" Background="#21262D" Foreground="{StaticResource AccentBlue}"/>
                </StackPanel>
            </StackPanel>
        </Border>

        <!-- Buttons -->
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,20,0,0">
            <Button x:Name="CancelButton" Content="Cancel" Background="#21262D" Foreground="{StaticResource TextPrimary}" BorderBrush="{StaticResource Border}" Padding="20,10" Margin="0,0,12,0"/>
            <Button x:Name="StartButton" Content="Start Workflow" Background="{StaticResource AccentBlue}" Foreground="White" BorderThickness="0" Padding="20,10"/>
        </StackPanel>
    </Grid>
</Window>
"@

    $dialogReader = New-Object System.Xml.XmlNodeReader ([xml]$dialogXaml)
    $dialog = [Windows.Markup.XamlReader]::Load($dialogReader)
    $dialog.Owner = $window

    # Get dialog controls
    $dlgControls = @{}
    @('DialogTitle','DialogSubtitle','TargetLocal','TargetMultiple','ComputerListPanel','ComputerListPath',
      'BrowseComputerList','OutputPath','BrowseOutput','IncludeDenyRules','IncludeHashRules','CollectEvents',
      'ProgressPanel','ProgressText','ProgressBar','CancelButton','StartButton') | ForEach-Object {
        $dlgControls[$_] = $dialog.FindName($_)
    }

    # Set workflow-specific content
    switch ($WorkflowType) {
        "Create Baseline" {
            $dlgControls['DialogSubtitle'].Text = "Scan computers, collect events, and generate a baseline AppLocker policy."
        }
        "Assess Environment" {
            $dlgControls['DialogSubtitle'].Text = "Analyze what would be blocked without making any changes. Generates a report."
            $dlgControls['StartButton'].Content = "Start Assessment"
        }
        "Update Policy" {
            $dlgControls['DialogSubtitle'].Text = "Collect recent blocked events and generate rules to add to your existing policy."
            $dlgControls['CollectEvents'].IsChecked = $true
            $dlgControls['CollectEvents'].IsEnabled = $false
            $dlgControls['StartButton'].Content = "Collect & Generate"
        }
        "Monitor Blocks" {
            $dlgControls['DialogSubtitle'].Text = "Check what applications are being blocked in your environment."
            $dlgControls['IncludeDenyRules'].Visibility = 'Collapsed'
            $dlgControls['IncludeHashRules'].Visibility = 'Collapsed'
            $dlgControls['StartButton'].Content = "Start Monitoring"
        }
    }

    # Event handlers
    $dlgControls['TargetMultiple'].Add_Checked({ $dlgControls['ComputerListPanel'].Visibility = 'Visible' })
    $dlgControls['TargetLocal'].Add_Checked({ $dlgControls['ComputerListPanel'].Visibility = 'Collapsed' })

    $dlgControls['BrowseComputerList'].Add_Click({
        $f = Get-OpenFileDialog -Title "Select Computer List" -Filter "Text/CSV (*.txt;*.csv)|*.txt;*.csv"
        if ($f) { $dlgControls['ComputerListPath'].Text = $f }
    })

    $dlgControls['BrowseOutput'].Add_Click({
        $f = Get-FolderDialog -Description "Select Output Folder"
        if ($f) { $dlgControls['OutputPath'].Text = $f }
    })

    $dlgControls['CancelButton'].Add_Click({ $dialog.DialogResult = $false; $dialog.Close() })

    $Script:WorkflowResult = $null
    $dlgControls['StartButton'].Add_Click({
        # Collect settings
        $Script:WorkflowResult = @{
            WorkflowType = $WorkflowType
            TargetLocal = $dlgControls['TargetLocal'].IsChecked
            ComputerListPath = $dlgControls['ComputerListPath'].Text
            OutputPath = $dlgControls['OutputPath'].Text
            IncludeDenyRules = $dlgControls['IncludeDenyRules'].IsChecked
            IncludeHashRules = $dlgControls['IncludeHashRules'].IsChecked
            CollectEvents = $dlgControls['CollectEvents'].IsChecked
        }
        $dialog.DialogResult = $true
        $dialog.Close()
    })

    $result = $dialog.ShowDialog()
    if ($result -eq $true) { return $Script:WorkflowResult }
    return $null
}

function Start-Workflow {
    param([hashtable]$Settings)

    if (-not $Settings) { return }

    $workflowType = $Settings.WorkflowType
    $outputPath = $Settings.OutputPath
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # Error tracking for better user feedback
    $Script:WorkflowErrors = [System.Collections.Generic.List[string]]::new()
    $Script:WorkflowWarnings = [System.Collections.Generic.List[string]]::new()

    Set-WorkflowStatus -State 'Running' -Message "Starting $workflowType..."
    Write-Log "=== Starting $workflowType Workflow ===" -Level Info

    # Ensure output path exists
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    try {
        switch ($workflowType) {
            "Create Baseline" {
                # Step 1: Scan
                Set-WorkflowStatus -State 'Running' -Message "Step 1/3: Scanning..."
                Write-Log "Step 1: Scanning for installed applications..." -Level Info

                $scanOutput = Join-Path $outputPath "Scans-$timestamp"
                if ($Settings.TargetLocal) {
                    # Local scan - create local inventory
                    Write-Log "Scanning local computer..." -Level Info
                    New-Item -ItemType Directory -Path $scanOutput -Force | Out-Null
                    $localFolder = Join-Path $scanOutput $env:COMPUTERNAME
                    New-Item -ItemType Directory -Path $localFolder -Force | Out-Null

                    # Get executables from Program Files with error tracking
                    $exes = @()
                    $scanErrors = 0
                    $paths = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:SystemRoot")
                    foreach ($p in $paths) {
                        if (Test-Path $p) {
                            Write-Log "  Scanning: $p" -Level Info
                            try {
                                $filesScanned = 0
                                Get-ChildItem -Path $p -Recurse -Include "*.exe" -ErrorAction Stop | Select-Object -First 500 | ForEach-Object {
                                    $filesScanned++
                                    try {
                                        $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                                        $hash = $null
                                        try { $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $scanErrors++ }
                                        $exes += [PSCustomObject]@{
                                            Name = $_.Name
                                            Path = $_.FullName
                                            Extension = $_.Extension
                                            IsSigned = ($sig.Status -eq 'Valid')
                                            Publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject -replace '^CN=|,.*$','' } else { "" }
                                            Hash = $hash
                                            Size = $_.Length
                                        }
                                    } catch {
                                        $scanErrors++
                                    }
                                }
                                Write-Log "    Scanned $filesScanned files from $p" -Level Info
                            } catch {
                                $Script:WorkflowWarnings.Add("Could not scan $p : $($_.Exception.Message)")
                                Write-Log "  Warning: Could not fully scan $p - $($_.Exception.Message)" -Level Warning
                            }
                        } else {
                            Write-Log "  Path not found, skipping: $p" -Level Warning
                        }
                    }

                    if ($scanErrors -gt 0) {
                        $Script:WorkflowWarnings.Add("$scanErrors files could not be fully processed (access denied or in use)")
                        Write-Log "  Warning: $scanErrors files had errors during scan" -Level Warning
                    }

                    $exes | Export-Csv -Path (Join-Path $localFolder "Executables.csv") -NoTypeInformation
                    Write-Log "  Found $($exes.Count) executables" -Level Info
                } else {
                    # Remote scan
                    if (-not $Settings.ComputerListPath -or -not (Test-Path $Settings.ComputerListPath)) {
                        Write-Log "Computer list not found!" -Level Error
                        throw "Computer list required for multi-computer scan"
                    }
                    Invoke-Script -ScriptName "Invoke-RemoteScan.ps1" -Parameters @{
                        ComputerListPath = $Settings.ComputerListPath
                        OutputPath = $scanOutput
                    }
                }

                # Step 2: Collect Events (if enabled)
                $eventOutput = $null
                if ($Settings.CollectEvents) {
                    Set-WorkflowStatus -State 'Running' -Message "Step 2/3: Collecting events..."
                    Write-Log "Step 2: Collecting audit events..." -Level Info

                    $eventOutput = Join-Path $outputPath "Events-$timestamp"
                    if ($Settings.TargetLocal) {
                        # Local event collection
                        New-Item -ItemType Directory -Path $eventOutput -Force | Out-Null
                        $blockedEvents = @()
                        try {
                            $events = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 1000 -ErrorAction SilentlyContinue |
                                Where-Object { $_.Id -in @(8004, 8006, 8008) }
                            foreach ($evt in $events) {
                                $xml = [xml]$evt.ToXml()
                                $data = $xml.Event.EventData.Data
                                $blockedEvents += [PSCustomObject]@{
                                    FilePath = ($data | Where-Object { $_.Name -eq 'FilePath' }).'#text'
                                    FileName = Split-Path (($data | Where-Object { $_.Name -eq 'FilePath' }).'#text') -Leaf
                                    FileHash = ($data | Where-Object { $_.Name -eq 'FileHash' }).'#text'
                                    Publisher = ""
                                    ProductName = ""
                                }
                            }
                        } catch { Write-Log "No AppLocker events found (policy may not be active)" -Level Warning }

                        if ($blockedEvents.Count -gt 0) {
                            $blockedEvents | Select-Object -Unique FilePath | Export-Csv -Path (Join-Path $eventOutput "UniqueBlockedApps.csv") -NoTypeInformation
                            Write-Log "  Found $($blockedEvents.Count) blocked events" -Level Info
                        } else {
                            Write-Log "  No blocked events found" -Level Info
                        }
                    } else {
                        Invoke-Script -ScriptName "Invoke-RemoteEventCollection.ps1" -Parameters @{
                            ComputerListPath = $Settings.ComputerListPath
                            OutputPath = $eventOutput
                            BlockedOnly = $true
                        }
                    }
                }

                # Step 3: Generate Policy
                Set-WorkflowStatus -State 'Running' -Message "Step 3/3: Generating policy..."
                Write-Log "Step 3: Generating baseline policy..." -Level Info

                $genParams = @{
                    Simplified = $true
                    OutputPath = $outputPath
                }
                if (Test-Path $scanOutput) { $genParams['ScanPath'] = $scanOutput }
                if ($eventOutput -and (Test-Path $eventOutput)) { $genParams['EventPath'] = $eventOutput }
                if ($Settings.IncludeDenyRules) { $genParams['IncludeDenyRules'] = $true }
                if ($Settings.IncludeHashRules) { $genParams['IncludeHashRules'] = $true }

                Invoke-Script -ScriptName "New-AppLockerPolicyFromGuide.ps1" -Parameters $genParams

                Set-WorkflowStatus -State 'Success' -Message "Baseline created!"
                Write-Log "=== Baseline Policy Created Successfully ===" -Level Success
                Write-Log "Output folder: $outputPath" -Level Info

                # Build completion message with warnings if any
                $completionMsg = "Baseline policy created successfully!`n`nOutput: $outputPath"

                if ($Script:WorkflowWarnings.Count -gt 0) {
                    $completionMsg += "`n`n⚠ Warnings ($($Script:WorkflowWarnings.Count)):`n"
                    $Script:WorkflowWarnings | Select-Object -First 5 | ForEach-Object {
                        $completionMsg += "• $_`n"
                    }
                    if ($Script:WorkflowWarnings.Count -gt 5) {
                        $completionMsg += "... and $($Script:WorkflowWarnings.Count - 5) more (see log for details)"
                    }
                }

                $completionMsg += "`n`nNext steps:`n1. Review the generated policy`n2. Apply in Audit mode first`n3. Monitor for blocks before enforcing"

                # Show completion dialog with appropriate icon
                $msgIcon = if ($Script:WorkflowWarnings.Count -gt 0) {
                    [System.Windows.MessageBoxImage]::Warning
                } else {
                    [System.Windows.MessageBoxImage]::Information
                }

                [System.Windows.MessageBox]::Show(
                    $completionMsg,
                    "Workflow Complete",
                    [System.Windows.MessageBoxButton]::OK,
                    $msgIcon
                )
            }

            "Assess Environment" {
                Set-WorkflowStatus -State 'Running' -Message "Assessing environment..."
                Write-Log "Assessing environment (no changes will be made)..." -Level Info

                $scanOutput = Join-Path $outputPath "Assessment-$timestamp"
                New-Item -ItemType Directory -Path $scanOutput -Force | Out-Null

                if ($Settings.TargetLocal) {
                    # Quick local assessment
                    $results = @()
                    $results += "=== AppLocker Environment Assessment ==="
                    $results += "Date: $(Get-Date)"
                    $results += "Computer: $env:COMPUTERNAME"
                    $results += ""

                    # Check AppLocker service
                    $svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
                    $results += "AppLocker Service: $($svc.Status)"

                    # Check current policy
                    try {
                        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
                        $ruleCount = ($policy.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
                        $results += "Active Rules: $ruleCount"
                    } catch { $results += "Active Rules: None (no policy)" }

                    # Check recent blocks
                    $blockCount = 0
                    try {
                        $blockCount = (Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 100 -ErrorAction SilentlyContinue |
                            Where-Object { $_.Id -eq 8004 }).Count
                    } catch {}
                    $results += "Recent Blocks (last 100 events): $blockCount"
                    $results += ""

                    # Scan for unsigned apps
                    $results += "=== Unsigned Applications in User-Writable Paths ==="
                    $userPaths = @("$env:APPDATA", "$env:LOCALAPPDATA", "$env:TEMP")
                    $unsignedCount = 0
                    foreach ($p in $userPaths) {
                        if (Test-Path $p) {
                            Get-ChildItem -Path $p -Recurse -Include "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 50 | ForEach-Object {
                                $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
                                if ($sig.Status -ne 'Valid') {
                                    $results += "  [UNSIGNED] $($_.FullName)"
                                    $unsignedCount++
                                }
                            }
                        }
                    }
                    if ($unsignedCount -eq 0) { $results += "  None found" }
                    $results += ""
                    $results += "Total unsigned executables: $unsignedCount"

                    $reportPath = Join-Path $scanOutput "Assessment-Report.txt"
                    $results | Out-File -FilePath $reportPath -Encoding UTF8
                    Write-Log "Assessment complete. Report: $reportPath" -Level Success
                }

                Set-WorkflowStatus -State 'Success' -Message "Assessment complete!"
                [System.Windows.MessageBox]::Show("Assessment complete!`n`nReport saved to:`n$scanOutput", "Assessment Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }

            "Update Policy" {
                Set-WorkflowStatus -State 'Running' -Message "Collecting blocked events..."
                Write-Log "Collecting recent blocked events for policy update..." -Level Info

                $eventOutput = Join-Path $outputPath "Events-$timestamp"
                if ($Settings.TargetLocal) {
                    New-Item -ItemType Directory -Path $eventOutput -Force | Out-Null
                    # Same local collection as Create Baseline
                    $blockedEvents = @()
                    try {
                        $events = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 500 -ErrorAction SilentlyContinue |
                            Where-Object { $_.Id -in @(8004, 8006, 8008) }
                        foreach ($evt in $events) {
                            $xml = [xml]$evt.ToXml()
                            $data = $xml.Event.EventData.Data
                            $fqbn = ($data | Where-Object { $_.Name -eq 'Fqbn' }).'#text'
                            $publisher = ""
                            if ($fqbn -and $fqbn -match "^O=([^\\,]+)") { $publisher = $matches[1].Trim('"') }
                            $blockedEvents += [PSCustomObject]@{
                                FilePath = ($data | Where-Object { $_.Name -eq 'FilePath' }).'#text'
                                FileName = Split-Path (($data | Where-Object { $_.Name -eq 'FilePath' }).'#text') -Leaf
                                FileHash = ($data | Where-Object { $_.Name -eq 'FileHash' }).'#text'
                                Publisher = $publisher
                                ProductName = ""
                            }
                        }
                    } catch { }

                    if ($blockedEvents.Count -gt 0) {
                        $blockedEvents | Group-Object FilePath | ForEach-Object { $_.Group[0] } | Export-Csv -Path (Join-Path $eventOutput "UniqueBlockedApps.csv") -NoTypeInformation
                        Write-Log "Found $($blockedEvents.Count) blocked events" -Level Info

                        Set-WorkflowStatus -State 'Running' -Message "Generating update rules..."
                        $genParams = @{ Simplified = $true; EventPath = $eventOutput; OutputPath = $outputPath }
                        if ($Settings.IncludeHashRules) { $genParams['IncludeHashRules'] = $true }
                        Invoke-Script -ScriptName "New-AppLockerPolicyFromGuide.ps1" -Parameters $genParams
                    } else {
                        Write-Log "No blocked events found. Policy is up to date!" -Level Info
                    }
                }

                Set-WorkflowStatus -State 'Success' -Message "Update complete!"
                [System.Windows.MessageBox]::Show("Policy update generated!`n`nMerge the new rules with your existing policy using the Merge Policies tool.", "Update Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }

            "Monitor Blocks" {
                Set-WorkflowStatus -State 'Running' -Message "Collecting block data..."
                Write-Log "Monitoring blocked applications..." -Level Info

                $monitorOutput = Join-Path $outputPath "Monitor-$timestamp"
                New-Item -ItemType Directory -Path $monitorOutput -Force | Out-Null

                if ($Settings.TargetLocal) {
                    $blockedApps = @()
                    try {
                        $events = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 1000 -ErrorAction SilentlyContinue |
                            Where-Object { $_.Id -eq 8004 }
                        foreach ($evt in $events) {
                            $xml = [xml]$evt.ToXml()
                            $data = $xml.Event.EventData.Data
                            $blockedApps += [PSCustomObject]@{
                                TimeCreated = $evt.TimeCreated
                                FilePath = ($data | Where-Object { $_.Name -eq 'FilePath' }).'#text'
                                FileName = Split-Path (($data | Where-Object { $_.Name -eq 'FilePath' }).'#text') -Leaf
                                User = ($data | Where-Object { $_.Name -eq 'TargetUser' }).'#text'
                            }
                        }
                    } catch { }

                    if ($blockedApps.Count -gt 0) {
                        $blockedApps | Export-Csv -Path (Join-Path $monitorOutput "BlockedApps.csv") -NoTypeInformation
                        $summary = $blockedApps | Group-Object FileName | Sort-Object Count -Descending | Select-Object -First 10
                        Write-Log "=== Top 10 Blocked Applications ===" -Level Info
                        foreach ($app in $summary) { Write-Log "  $($app.Count)x - $($app.Name)" -Level Info }
                    } else {
                        Write-Log "No blocked applications found!" -Level Success
                    }
                }

                Set-WorkflowStatus -State 'Success' -Message "Monitoring complete!"
                [System.Windows.MessageBox]::Show("Block monitoring complete!`n`nResults saved to:`n$monitorOutput", "Monitoring Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    } catch {
        Set-WorkflowStatus -State 'Error' -Message "Workflow failed"
        Write-Log "Workflow error: $_" -Level Error
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error

        # Build detailed error message
        $errorMsg = "Workflow failed:`n`n$($_.Exception.Message)"

        if ($Script:WorkflowWarnings.Count -gt 0) {
            $errorMsg += "`n`nWarnings before failure:`n"
            $Script:WorkflowWarnings | Select-Object -First 3 | ForEach-Object {
                $errorMsg += "• $_`n"
            }
        }

        $errorMsg += "`n`nCheck the log panel for more details."

        [System.Windows.MessageBox]::Show($errorMsg, "Workflow Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}
#endregion

#region Event Handlers
# Navigation
$controls['NavScan'].Add_Click({ Switch-Page "Scan" })
$controls['NavGenerate'].Add_Click({ Switch-Page "Generate" })
$controls['NavMerge'].Add_Click({ Switch-Page "Merge" })
$controls['NavValidate'].Add_Click({ Switch-Page "Validate" })
$controls['NavClone'].Add_Click({ Switch-Page "Clone" })
$controls['NavEvents'].Add_Click({ Switch-Page "Events" })
$controls['NavCompare'].Add_Click({ Switch-Page "Compare" })
$controls['NavSoftware'].Add_Click({ Switch-Page "Software" })
$controls['NavCORA'].Add_Click({ Switch-Page "CORA" })
$controls['NavAD'].Add_Click({ Switch-Page "AD" })
$controls['NavDiagnostics'].Add_Click({ Switch-Page "Diagnostics" })
$controls['NavWinRM'].Add_Click({ Switch-Page "WinRM" })
$controls['NavSettings'].Add_Click({ Switch-Page "Settings" })
$controls['NavHelp'].Add_Click({ Switch-Page "Help"; Show-HelpTopic "GettingStarted" })
$controls['NavAbout'].Add_Click({ Switch-Page "About" })

# Cancel operation button
$controls['CancelOperation'].Add_Click({
    if ($Script:OperationRunning) {
        $Script:CancellationRequested = $true
        Write-Log "Cancellation requested... Please wait for current operation to complete." -Level Warning
        $controls['CancelOperation'].IsEnabled = $false
        $controls['CancelOperation'].Content = "Cancelling..."
    }
})

# Quick Workflow mode selection - update description
$controls['WorkflowMode'].Add_SelectionChanged({
    $selected = $controls['WorkflowMode'].SelectedItem.Content
    $controls['WorkflowDescription'].Text = switch ($selected) {
        "Create Baseline" {
            "Scan computers → Collect events → Generate initial policy. Best for first-time AppLocker setup."
        }
        "Assess Environment" {
            "Scan computers only to assess software inventory. No policy changes. Use for planning."
        }
        "Update Policy" {
            "Collect new events → Merge with existing policy. Use after baseline to add missing rules."
        }
        "Monitor Blocks" {
            "Collect and analyze block events only. Use to monitor policy effectiveness and find gaps."
        }
        default {
            "Select a workflow mode to see its description."
        }
    }
})

# Quick Workflow button
$controls['RunWorkflow'].Add_Click({
    $selectedMode = $controls['WorkflowMode'].SelectedItem.Content
    $settings = Show-WorkflowDialog -WorkflowType $selectedMode
    if ($settings) { Start-Workflow -Settings $settings }
})

# Build Guide toggle
$controls['GenerateBuildGuide'].Add_Checked({ $controls['BuildGuideOptions'].Visibility = 'Visible' })
$controls['GenerateSimplified'].Add_Checked({ $controls['BuildGuideOptions'].Visibility = 'Collapsed' })

# Trusted Publishers Selection - Organized by category
$Script:TrustedPublishers = [ordered]@{
    # === Operating System / Core ===
    'Microsoft' = @{ Selected = $false; Description = 'Microsoft Corporation'; Category = 'Core' }
    'Apple' = @{ Selected = $false; Description = 'Apple Inc.'; Category = 'Core' }

    # === Hardware Vendors ===
    'Intel' = @{ Selected = $false; Description = 'Intel Corporation'; Category = 'Hardware' }
    'AMD' = @{ Selected = $false; Description = 'Advanced Micro Devices'; Category = 'Hardware' }
    'NVIDIA' = @{ Selected = $false; Description = 'NVIDIA Corporation'; Category = 'Hardware' }
    'Dell' = @{ Selected = $false; Description = 'Dell Technologies'; Category = 'Hardware' }
    'HP' = @{ Selected = $false; Description = 'HP Inc.'; Category = 'Hardware' }
    'Lenovo' = @{ Selected = $false; Description = 'Lenovo Group'; Category = 'Hardware' }
    'Logitech' = @{ Selected = $false; Description = 'Logitech International'; Category = 'Hardware' }
    'Realtek' = @{ Selected = $false; Description = 'Realtek Semiconductor'; Category = 'Hardware' }
    'Broadcom' = @{ Selected = $false; Description = 'Broadcom Inc.'; Category = 'Hardware' }

    # === Defense / DOD / Aerospace ===
    'Lockheed Martin' = @{ Selected = $false; Description = 'Lockheed Martin Corporation'; Category = 'Defense' }
    'Raytheon' = @{ Selected = $false; Description = 'Raytheon Technologies'; Category = 'Defense' }
    'Northrop Grumman' = @{ Selected = $false; Description = 'Northrop Grumman Corporation'; Category = 'Defense' }
    'General Dynamics' = @{ Selected = $false; Description = 'General Dynamics Corporation'; Category = 'Defense' }
    'BAE Systems' = @{ Selected = $false; Description = 'BAE Systems plc'; Category = 'Defense' }
    'L3Harris' = @{ Selected = $false; Description = 'L3Harris Technologies'; Category = 'Defense' }
    'Leidos' = @{ Selected = $false; Description = 'Leidos Holdings'; Category = 'Defense' }
    'SAIC' = @{ Selected = $false; Description = 'Science Applications International'; Category = 'Defense' }
    'Booz Allen Hamilton' = @{ Selected = $false; Description = 'Booz Allen Hamilton'; Category = 'Defense' }
    'ManTech' = @{ Selected = $false; Description = 'ManTech International'; Category = 'Defense' }
    'Parsons' = @{ Selected = $false; Description = 'Parsons Corporation'; Category = 'Defense' }
    'CACI' = @{ Selected = $false; Description = 'CACI International'; Category = 'Defense' }
    'Peraton' = @{ Selected = $false; Description = 'Peraton Inc.'; Category = 'Defense' }
    'General Atomics' = @{ Selected = $false; Description = 'General Atomics'; Category = 'Defense' }
    'Boeing' = @{ Selected = $false; Description = 'The Boeing Company'; Category = 'Defense' }
    'Honeywell' = @{ Selected = $false; Description = 'Honeywell International'; Category = 'Defense' }
    'Collins Aerospace' = @{ Selected = $false; Description = 'Collins Aerospace (RTX)'; Category = 'Defense' }
    'Kratos' = @{ Selected = $false; Description = 'Kratos Defense'; Category = 'Defense' }
    'Sierra Nevada' = @{ Selected = $false; Description = 'Sierra Nevada Corporation'; Category = 'Defense' }

    # === CAD / Engineering / Design ===
    'Autodesk' = @{ Selected = $false; Description = 'Autodesk (AutoCAD, Revit, Inventor)'; Category = 'CAD' }
    'Dassault Systemes' = @{ Selected = $false; Description = 'Dassault (SOLIDWORKS, CATIA)'; Category = 'CAD' }
    'PTC' = @{ Selected = $false; Description = 'PTC Inc. (Creo, Windchill)'; Category = 'CAD' }
    'Siemens PLM' = @{ Selected = $false; Description = 'Siemens (NX, Solid Edge, Teamcenter)'; Category = 'CAD' }
    'ANSYS' = @{ Selected = $false; Description = 'ANSYS Inc. (Simulation)'; Category = 'CAD' }
    'MathWorks' = @{ Selected = $false; Description = 'MathWorks (MATLAB, Simulink)'; Category = 'CAD' }
    'Bentley Systems' = @{ Selected = $false; Description = 'Bentley Systems (MicroStation)'; Category = 'CAD' }
    'Altium' = @{ Selected = $false; Description = 'Altium (PCB Design)'; Category = 'CAD' }
    'Cadence' = @{ Selected = $false; Description = 'Cadence Design Systems'; Category = 'CAD' }
    'Synopsys' = @{ Selected = $false; Description = 'Synopsys Inc.'; Category = 'CAD' }
    'National Instruments' = @{ Selected = $false; Description = 'NI (LabVIEW, TestStand)'; Category = 'CAD' }
    'Hexagon' = @{ Selected = $false; Description = 'Hexagon AB (MSC Software)'; Category = 'CAD' }
    'Trimble' = @{ Selected = $false; Description = 'Trimble Inc.'; Category = 'CAD' }
    'ESRI' = @{ Selected = $false; Description = 'ESRI (ArcGIS)'; Category = 'CAD' }
    'Bluebeam' = @{ Selected = $false; Description = 'Bluebeam (Revu)'; Category = 'CAD' }

    # === Development Tools ===
    'JetBrains' = @{ Selected = $false; Description = 'JetBrains (IntelliJ, PyCharm)'; Category = 'Development' }
    'GitHub' = @{ Selected = $false; Description = 'GitHub Inc.'; Category = 'Development' }
    'Atlassian' = @{ Selected = $false; Description = 'Atlassian (Jira, Confluence)'; Category = 'Development' }
    'Git' = @{ Selected = $false; Description = 'Software Freedom Conservancy'; Category = 'Development' }
    'Python' = @{ Selected = $false; Description = 'Python Software Foundation'; Category = 'Development' }
    'Node.js' = @{ Selected = $false; Description = 'OpenJS Foundation'; Category = 'Development' }
    'Docker' = @{ Selected = $false; Description = 'Docker Inc.'; Category = 'Development' }
    'Postman' = @{ Selected = $false; Description = 'Postman Inc.'; Category = 'Development' }
    'Sublime HQ' = @{ Selected = $false; Description = 'Sublime HQ (Sublime Text)'; Category = 'Development' }
    'Notepad++' = @{ Selected = $false; Description = 'Notepad++ Team'; Category = 'Development' }
    'WinSCP' = @{ Selected = $false; Description = 'Martin Prikryl (WinSCP)'; Category = 'Development' }
    'PuTTY' = @{ Selected = $false; Description = 'Simon Tatham (PuTTY)'; Category = 'Development' }
    'VS Code' = @{ Selected = $false; Description = 'Microsoft (Visual Studio Code)'; Category = 'Development' }
    'Beyond Compare' = @{ Selected = $false; Description = 'Scooter Software'; Category = 'Development' }

    # === Virtualization / Infrastructure ===
    'VMware' = @{ Selected = $false; Description = 'VMware Inc.'; Category = 'Virtualization' }
    'Citrix' = @{ Selected = $false; Description = 'Citrix Systems'; Category = 'Virtualization' }
    'Parallels' = @{ Selected = $false; Description = 'Parallels International'; Category = 'Virtualization' }
    'Red Hat' = @{ Selected = $false; Description = 'Red Hat Inc.'; Category = 'Virtualization' }
    'Nutanix' = @{ Selected = $false; Description = 'Nutanix Inc.'; Category = 'Virtualization' }

    # === Security ===
    'Symantec' = @{ Selected = $false; Description = 'Symantec Corporation'; Category = 'Security' }
    'McAfee' = @{ Selected = $false; Description = 'McAfee Corp.'; Category = 'Security' }
    'CrowdStrike' = @{ Selected = $false; Description = 'CrowdStrike Holdings'; Category = 'Security' }
    'Carbon Black' = @{ Selected = $false; Description = 'VMware Carbon Black'; Category = 'Security' }
    'Palo Alto Networks' = @{ Selected = $false; Description = 'Palo Alto Networks'; Category = 'Security' }
    'Fortinet' = @{ Selected = $false; Description = 'Fortinet Inc.'; Category = 'Security' }
    'Trend Micro' = @{ Selected = $false; Description = 'Trend Micro Inc.'; Category = 'Security' }
    'ESET' = @{ Selected = $false; Description = 'ESET LLC'; Category = 'Security' }
    'Ivanti' = @{ Selected = $false; Description = 'Ivanti Inc.'; Category = 'Security' }
    'Tenable' = @{ Selected = $false; Description = 'Tenable (Nessus)'; Category = 'Security' }
    'Rapid7' = @{ Selected = $false; Description = 'Rapid7 Inc.'; Category = 'Security' }
    'SolarWinds' = @{ Selected = $false; Description = 'SolarWinds Corporation'; Category = 'Security' }
    'BeyondTrust' = @{ Selected = $false; Description = 'BeyondTrust Corporation'; Category = 'Security' }
    'CyberArk' = @{ Selected = $false; Description = 'CyberArk Software'; Category = 'Security' }
    'Thycotic' = @{ Selected = $false; Description = 'Thycotic (Delinea)'; Category = 'Security' }
    'SafeNet' = @{ Selected = $false; Description = 'SafeNet (Thales)'; Category = 'Security' }
    'RSA' = @{ Selected = $false; Description = 'RSA Security'; Category = 'Security' }
    'Duo' = @{ Selected = $false; Description = 'Duo Security (Cisco)'; Category = 'Security' }
    'Yubico' = @{ Selected = $false; Description = 'Yubico (YubiKey)'; Category = 'Security' }
    'Forescout' = @{ Selected = $false; Description = 'Forescout Technologies'; Category = 'Security' }
    'Tanium' = @{ Selected = $false; Description = 'Tanium Inc.'; Category = 'Security' }
    'Splunk' = @{ Selected = $false; Description = 'Splunk Inc.'; Category = 'Security' }
    'LogRhythm' = @{ Selected = $false; Description = 'LogRhythm Inc.'; Category = 'Security' }
    'Elastic' = @{ Selected = $false; Description = 'Elastic (ELK Stack)'; Category = 'Security' }
    'Varonis' = @{ Selected = $false; Description = 'Varonis Systems'; Category = 'Security' }
    'Qualys' = @{ Selected = $false; Description = 'Qualys Inc.'; Category = 'Security' }
    'Proofpoint' = @{ Selected = $false; Description = 'Proofpoint Inc.'; Category = 'Security' }
    'Mimecast' = @{ Selected = $false; Description = 'Mimecast'; Category = 'Security' }
    'Zscaler' = @{ Selected = $false; Description = 'Zscaler Inc.'; Category = 'Security' }
    'Netskope' = @{ Selected = $false; Description = 'Netskope Inc.'; Category = 'Security' }
    'SentinelOne' = @{ Selected = $false; Description = 'SentinelOne Inc.'; Category = 'Security' }
    'Cybereason' = @{ Selected = $false; Description = 'Cybereason Inc.'; Category = 'Security' }
    'Sophos' = @{ Selected = $false; Description = 'Sophos Ltd.'; Category = 'Security' }
    'Kaspersky' = @{ Selected = $false; Description = 'Kaspersky Lab'; Category = 'Security' }
    'Bitdefender' = @{ Selected = $false; Description = 'Bitdefender'; Category = 'Security' }
    'Malwarebytes' = @{ Selected = $false; Description = 'Malwarebytes Inc.'; Category = 'Security' }
    'Absolute' = @{ Selected = $false; Description = 'Absolute Software'; Category = 'Security' }
    'Imperva' = @{ Selected = $false; Description = 'Imperva Inc.'; Category = 'Security' }
    'F5 Networks' = @{ Selected = $false; Description = 'F5 Networks'; Category = 'Security' }
    'Akamai' = @{ Selected = $false; Description = 'Akamai Technologies'; Category = 'Security' }
    'Okta' = @{ Selected = $false; Description = 'Okta Inc.'; Category = 'Security' }
    'Ping Identity' = @{ Selected = $false; Description = 'Ping Identity'; Category = 'Security' }
    'SailPoint' = @{ Selected = $false; Description = 'SailPoint Technologies'; Category = 'Security' }
    'Saviynt' = @{ Selected = $false; Description = 'Saviynt Inc.'; Category = 'Security' }
    'Venafi' = @{ Selected = $false; Description = 'Venafi Inc.'; Category = 'Security' }
    'Entrust' = @{ Selected = $false; Description = 'Entrust Corporation'; Category = 'Security' }
    'DigiCert' = @{ Selected = $false; Description = 'DigiCert Inc.'; Category = 'Security' }
    'Forcepoint' = @{ Selected = $false; Description = 'Forcepoint LLC'; Category = 'Security' }
    'Digital Guardian' = @{ Selected = $false; Description = 'Digital Guardian'; Category = 'Security' }
    'Code42' = @{ Selected = $false; Description = 'Code42 Software'; Category = 'Security' }
    'Acronis' = @{ Selected = $false; Description = 'Acronis International'; Category = 'Security' }
    'Commvault' = @{ Selected = $false; Description = 'Commvault Systems'; Category = 'Security' }
    'Veritas' = @{ Selected = $false; Description = 'Veritas Technologies'; Category = 'Security' }
    'Veeam' = @{ Selected = $false; Description = 'Veeam Software'; Category = 'Security' }

    # === DOD / Government Security ===
    'DISA' = @{ Selected = $false; Description = 'Defense Information Systems Agency'; Category = 'DOD' }
    'Telos' = @{ Selected = $false; Description = 'Telos Corporation'; Category = 'DOD' }
    'Assured Compliance' = @{ Selected = $false; Description = 'ACAS/Nessus DOD'; Category = 'DOD' }
    'BigFix' = @{ Selected = $false; Description = 'HCL BigFix (DOD Patching)'; Category = 'DOD' }
    'SCAP' = @{ Selected = $false; Description = 'SCAP Compliance Checker'; Category = 'DOD' }
    'Axonius' = @{ Selected = $false; Description = 'Axonius Inc.'; Category = 'DOD' }
    'Swimlane' = @{ Selected = $false; Description = 'Swimlane Inc.'; Category = 'DOD' }
    'Demisto' = @{ Selected = $false; Description = 'Palo Alto (Demisto/XSOAR)'; Category = 'DOD' }
    'ServiceNow' = @{ Selected = $false; Description = 'ServiceNow Inc.'; Category = 'DOD' }
    'Remedy' = @{ Selected = $false; Description = 'BMC Remedy'; Category = 'DOD' }
    'ManageEngine' = @{ Selected = $false; Description = 'ManageEngine (Zoho)'; Category = 'DOD' }
    'Quest' = @{ Selected = $false; Description = 'Quest Software'; Category = 'DOD' }
    'Netwrix' = @{ Selected = $false; Description = 'Netwrix Corporation'; Category = 'DOD' }
    'Stealthbits' = @{ Selected = $false; Description = 'Stealthbits (Netwrix)'; Category = 'DOD' }
    'Spirion' = @{ Selected = $false; Description = 'Spirion (Data Discovery)'; Category = 'DOD' }
    'PKWARE' = @{ Selected = $false; Description = 'PKWARE Inc.'; Category = 'DOD' }
    'WinMagic' = @{ Selected = $false; Description = 'WinMagic (SecureDoc)'; Category = 'DOD' }
    'Sophos SafeGuard' = @{ Selected = $false; Description = 'Sophos SafeGuard Encryption'; Category = 'DOD' }
    'McAfee DLP' = @{ Selected = $false; Description = 'McAfee DLP/ePO'; Category = 'DOD' }
    'Symantec DLP' = @{ Selected = $false; Description = 'Symantec Data Loss Prevention'; Category = 'DOD' }
    'Vormetric' = @{ Selected = $false; Description = 'Thales Vormetric'; Category = 'DOD' }
    'Voltage' = @{ Selected = $false; Description = 'Micro Focus Voltage'; Category = 'DOD' }

    # === Networking ===
    'Cisco' = @{ Selected = $false; Description = 'Cisco Systems'; Category = 'Networking' }
    'Juniper' = @{ Selected = $false; Description = 'Juniper Networks'; Category = 'Networking' }
    'Wireshark' = @{ Selected = $false; Description = 'Wireshark Foundation'; Category = 'Networking' }
    'NetScout' = @{ Selected = $false; Description = 'NetScout Systems'; Category = 'Networking' }

    # === Productivity / Office ===
    'Adobe' = @{ Selected = $false; Description = 'Adobe Inc.'; Category = 'Productivity' }
    'Google' = @{ Selected = $false; Description = 'Google LLC'; Category = 'Productivity' }
    'Zoom' = @{ Selected = $false; Description = 'Zoom Video Communications'; Category = 'Productivity' }
    'Slack' = @{ Selected = $false; Description = 'Slack Technologies'; Category = 'Productivity' }
    'Webex' = @{ Selected = $false; Description = 'Cisco Webex'; Category = 'Productivity' }
    'Dropbox' = @{ Selected = $false; Description = 'Dropbox Inc.'; Category = 'Productivity' }
    'Box' = @{ Selected = $false; Description = 'Box Inc.'; Category = 'Productivity' }
    'Mozilla' = @{ Selected = $false; Description = 'Mozilla Corporation'; Category = 'Productivity' }
    'Oracle' = @{ Selected = $false; Description = 'Oracle Corporation'; Category = 'Productivity' }
    '7-Zip' = @{ Selected = $false; Description = 'Igor Pavlov'; Category = 'Productivity' }
    'WinZip' = @{ Selected = $false; Description = 'Corel (WinZip)'; Category = 'Productivity' }
    'WinRAR' = @{ Selected = $false; Description = 'win.rar GmbH'; Category = 'Productivity' }
    'Foxit' = @{ Selected = $false; Description = 'Foxit Software (PDF)'; Category = 'Productivity' }
    'Nitro' = @{ Selected = $false; Description = 'Nitro Software (PDF)'; Category = 'Productivity' }
    'Snagit' = @{ Selected = $false; Description = 'TechSmith (Snagit, Camtasia)'; Category = 'Productivity' }
    'Greenshot' = @{ Selected = $false; Description = 'Greenshot'; Category = 'Productivity' }
    'Corel' = @{ Selected = $false; Description = 'Corel Corporation (CorelDRAW, PaintShop)'; Category = 'Productivity' }

    # === Data Transfer / Media ===
    'SafeMedia' = @{ Selected = $false; Description = 'SafeMedia (Data Transfer)'; Category = 'DataTransfer' }
    'Virtru' = @{ Selected = $false; Description = 'Virtru (Encryption)'; Category = 'DataTransfer' }
    'Globalscape' = @{ Selected = $false; Description = 'Globalscape (EFT)'; Category = 'DataTransfer' }
    'Axway' = @{ Selected = $false; Description = 'Axway (SecureTransport)'; Category = 'DataTransfer' }
    'FileZilla' = @{ Selected = $false; Description = 'FileZilla Project'; Category = 'DataTransfer' }

    # === Database ===
    'PostgreSQL' = @{ Selected = $false; Description = 'PostgreSQL Global Dev'; Category = 'Database' }
    'MySQL' = @{ Selected = $false; Description = 'Oracle (MySQL)'; Category = 'Database' }
    'MongoDB' = @{ Selected = $false; Description = 'MongoDB Inc.'; Category = 'Database' }
    'DBeaver' = @{ Selected = $false; Description = 'DBeaver Corp'; Category = 'Database' }

    # === Remote Access ===
    'TeamViewer' = @{ Selected = $false; Description = 'TeamViewer Germany'; Category = 'Remote' }
    'AnyDesk' = @{ Selected = $false; Description = 'AnyDesk Software'; Category = 'Remote' }
    'Bomgar' = @{ Selected = $false; Description = 'BeyondTrust (Bomgar)'; Category = 'Remote' }
    'LogMeIn' = @{ Selected = $false; Description = 'LogMeIn Inc.'; Category = 'Remote' }
}

# Help Topics Content
$Script:HelpTopics = @{
    "GettingStarted" = @{
        Title = "Getting Started"
        Content = @"
Welcome to GA-AppLocker - your comprehensive AppLocker deployment toolkit for Windows environments.

QUICK START GUIDE

1. Prerequisites
   - Windows 11 / Server 2019+
   - PowerShell 5.1 or higher
   - Administrator privileges
   - WinRM enabled on target computers (for remote scans)

2. Recommended Workflow
   Step 1: Scan computers to collect software inventory
   Step 2: Generate an AppLocker policy from scan data
   Step 3: Deploy policy in Audit mode for 14+ days
   Step 4: Collect AppLocker events to find blocked apps
   Step 5: Update policy with legitimate blocked software
   Step 6: Advance through deployment phases

3. Folder Structure
   - Scans are saved to: .\Scans\
   - Events are saved to: .\Events\
   - Policies are saved to: .\Outputs\
   - Software lists: .\SoftwareLists\

KEYBOARD SHORTCUTS
   Ctrl+1-6    Navigate to main pages
   Ctrl+L      Toggle log panel
   Ctrl+,      Open Settings
   F1          Open Help

QUICK WORKFLOW
   Use the Quick Workflow bar at the top for guided workflows:
   - Create Baseline: First-time AppLocker setup
   - Assess Environment: Inventory only, no policy changes
   - Update Policy: Add rules for blocked applications
   - Monitor Blocks: Collect and analyze block events
"@
    }
    "Scanning" = @{
        Title = "Scanning Computers"
        Content = @"
REMOTE COMPUTER SCANNING

Scan computers to collect installed software inventory via WinRM.

PREREQUISITES

1. WinRM must be enabled on target computers
   - Use the WinRM page to deploy GPO settings
   - Or manually: winrm quickconfig

2. Firewall must allow:
   - TCP 5985 (WinRM HTTP)
   - TCP 5986 (WinRM HTTPS)

3. Administrator credentials required

SCAN PROCESS

Step 1: Load Computer List
   - Browse to a CSV file with 'ComputerName' column
   - Or use 'Scan AD' to query Active Directory

Step 2: Enter Credentials
   - Provide domain admin credentials
   - Credentials are used for WinRM connections

Step 3: Configure Options
   - Throttle Limit: Concurrent connections (default: 10)
   - Scan User Profiles: Include AppData locations

Step 4: Start Scan
   - Progress shown in log panel
   - Results saved per-computer as CSV files

SCAN OUTPUT

Each computer folder contains:
- InstalledSoftware.csv: All detected applications
- RunningProcesses.csv: Active processes at scan time
- Services.csv: Windows services
- ScheduledTasks.csv: Scheduled tasks

TROUBLESHOOTING

- WinRM errors: Run Test-WSMan <computer>
- Access denied: Verify credentials and permissions
- Timeout: Increase throttle limit or check network
"@
    }
    "PolicyGen" = @{
        Title = "Policy Generation"
        Content = @"
APPLOCKER POLICY GENERATION

Generate AppLocker policies from scan data or software lists.

TWO GENERATION MODES

1. Build Guide Mode (Enterprise)
   - Target-specific: Workstation, Server, Domain Controller
   - Custom AD group scoping
   - Phased deployment (Phase 1-4)
   - Proper principal scoping

2. Simplified Mode (Quick Setup)
   - Single target user/group
   - Good for labs or standalone machines

DEPLOYMENT PHASES

Phase 1 - EXE Only (Lowest Risk)
   - Executable rules only
   - Best for initial deployment

Phase 2 - EXE + Scripts
   - Adds PowerShell, BAT, CMD rules

Phase 3 - EXE + Scripts + MSI
   - Adds installer rules

Phase 4 - Full (EXE + Scripts + MSI + DLL)
   - Complete protection
   - Highest security, requires careful testing

RULE TYPES

Publisher Rules (Recommended)
   - Based on digital signatures
   - Survives software updates

Path Rules
   - Based on file location
   - Use for unsigned software

Hash Rules
   - Based on file hash
   - Must update after every change

OPTIONS EXPLAINED

- Include Deny Rules: Block LOLBins (mshta, wscript, etc.)
- Include Vendor Publishers: Trust publishers from scan data
- Software List: Use curated allowlist for rules
- Target Group: AD group for rule scoping

OUTPUT

Policies saved as XML to .\Outputs\
Deploy via GPO, PowerShell, or SCCM/Intune
"@
    }
    "Merging" = @{
        Title = "Merging Policies"
        Content = @"
POLICY MERGING

Combine multiple AppLocker policies into a single unified policy.

WHEN TO MERGE

- Combining department-specific policies
- Merging baseline with custom rules
- Consolidating policies from multiple sources
- Removing duplicate rules

MERGE PROCESS

Step 1: Select Policies
   - Click 'Browse' to select multiple XML files
   - Or select a folder containing policies

Step 2: Configure Options
   - Remove Default Rules: Filter out standard defaults
   - Target Group: Replace Everyone SID with specific group
   - Replace Mode: Everyone, All, or None

Step 3: Merge
   - Output saved to .\Outputs\MergedPolicy.xml

MERGE OPTIONS

Remove Default Rules
   - Filters out AppLocker default rules
   - Useful when merging custom policies

Target Group Replacement
   - Replaces generic SIDs with specific AD groups
   - Everyone: Only replace Everyone (S-1-1-0)
   - All: Replace all generic SIDs
   - None: Keep original SIDs

DEDUPLICATION

The merge process automatically:
- Removes exact duplicate rules
- Preserves unique rules from each source
- Maintains rule conditions and exceptions

VALIDATION

After merging:
- Use Validate page to check the merged policy
- Review rule counts and types
- Test in Audit mode before enforcement
"@
    }
    "Events" = @{
        Title = "Event Collection"
        Content = @"
APPLOCKER EVENT COLLECTION

Collect AppLocker audit events from remote computers to identify blocked applications.

EVENT TYPES

Event 8003: Would have been allowed (EXE/DLL)
Event 8004: Would have been blocked (EXE/DLL) - Most useful
Event 8005/8006: MSI and Script events
Event 8007/8008: Packaged app events

COLLECTION PROCESS

Step 1: Load Computer List
   - Same list used for scanning
   - Or use 'Scan AD' to discover computers

Step 2: Configure Options
   - Days Back: How many days of events (default: 14)
   - Blocked Only: Only collect 8004 events
   - Since Last Run: Incremental collection

Step 3: Collect Events
   - Progress shown in log panel
   - Results saved to .\Events\

OUTPUT FILES

Per-Computer Files:
- BlockedApps.csv: All blocked events for that computer

Summary Files:
- UniqueBlockedApps.csv: Deduplicated list with counts
- AllBlockedEvents.csv: Consolidated view

USING EVENT DATA

1. Review UniqueBlockedApps.csv
2. Identify legitimate software being blocked
3. Create rules for legitimate apps:
   - Use Software Lists to build allowlists
   - Generate new policy with allowed apps
   - Merge with existing policy

INCREMENTAL COLLECTION

Use 'Since Last Run' option to:
- Only collect new events since last run
- Faster collection for regular monitoring
- Track timestamps per computer
"@
    }
    "SoftwareLists" = @{
        Title = "Software Lists"
        Content = @"
SOFTWARE LIST MANAGEMENT

Create and manage curated software allowlists for policy generation.

WHAT ARE SOFTWARE LISTS?

JSON files containing:
- Publisher names for publisher rules
- File paths for path rules
- File hashes for hash rules

Stored in: .\SoftwareLists\

IMPORT METHODS

1. From Scan Data
   - Import software from scan CSV files
   - Select specific applications to include

2. From Common Publishers
   - Pre-defined trusted publishers
   - Categories: Microsoft, Adobe, Security vendors, etc.

3. From AppLocker Policy
   - Extract rules from existing policy XML
   - Useful for policy migration

4. From Folder Scan
   - Scan local folders for executables
   - Collect publisher info from signatures

PUBLISHER CATEGORIES

Core: Microsoft, Apple
Hardware: Intel, AMD, NVIDIA, Dell, HP
Defense: Lockheed Martin, Boeing, General Atomics
Security: CrowdStrike, Symantec, McAfee
Productivity: Adobe, Google, Mozilla
And many more...

USING SOFTWARE LISTS

1. Create or select a software list
2. On Generate page, select 'Use Software List'
3. Browse to your JSON file
4. Policy rules created from list entries

MANAGING LISTS

- View: See all entries in a list
- Add: Manually add publishers/paths
- Remove: Delete individual entries
- Export: Save list as JSON
- Compare: Diff two lists
"@
    }
    "Deployment" = @{
        Title = "Deployment Guide"
        Content = @"
APPLOCKER DEPLOYMENT STRATEGY

Recommended approach for enterprise AppLocker deployment.

PHASED DEPLOYMENT

Week 1-2: Assessment
- Scan 14+ representative machines
- Collect software inventory
- Identify common applications

Week 3-4: Initial Policy
- Generate Phase 1 policy (EXE only)
- Deploy via GPO in Audit mode
- Monitor for 14+ days

Week 5-6: Refinement
- Collect AppLocker events
- Review blocked applications
- Add rules for legitimate software

Week 7+: Enforcement
- Switch from Audit to Enforce mode
- Continue monitoring
- Advance through phases gradually

DEPLOYMENT METHODS

1. Group Policy (Recommended)
   - Computer Configuration > Windows Settings
   - Security Settings > Application Control Policies
   - Import XML policy

2. PowerShell
   Set-AppLockerPolicy -XmlPolicy policy.xml

3. SCCM/Intune
   - Use Export feature for deployment packages
   - Deploy as configuration baseline

GPO CONFIGURATION

1. Create new GPO or edit existing
2. Navigate to AppLocker settings
3. Import your policy XML
4. Configure enforcement mode:
   - Audit Only: Log without blocking
   - Enforce Rules: Block and log
5. Link GPO to target OUs

TESTING RECOMMENDATIONS

- Always test in Audit mode first
- Monitor for at least 14 days
- Review all blocked events
- Test with representative users
- Have rollback plan ready
"@
    }
    "Troubleshooting" = @{
        Title = "Troubleshooting"
        Content = @"
COMMON ISSUES AND SOLUTIONS

WINRM CONNECTION ISSUES

Error: WinRM cannot complete the operation
Solutions:
- Verify WinRM is enabled: winrm quickconfig
- Check firewall: TCP 5985, 5986
- Verify credentials have admin rights
- Test: Test-WSMan <computername>

Error: Access is denied
Solutions:
- Use domain admin credentials
- Verify computer is domain-joined
- Check local admin group membership

SCAN FAILURES

Error: RPC server unavailable
Solutions:
- Computer may be offline
- Check network connectivity: ping <computer>
- Verify computer name is correct

Error: Timeout expired
Solutions:
- Reduce throttle limit
- Check target computer performance
- Increase timeout in settings

POLICY GENERATION ISSUES

Error: No software data found
Solutions:
- Verify scan completed successfully
- Check scan folder contains CSV files
- Ensure InstalledSoftware.csv exists

Error: Invalid XML
Solutions:
- Use Validate page to check policy
- Review for special characters
- Check file encoding (UTF-8)

EVENT COLLECTION ISSUES

Error: No events found
Solutions:
- Verify AppLocker is configured
- Check policy is in Audit mode
- Ensure event log is not cleared
- Increase 'Days Back' setting

APPLOCKER NOT WORKING

Policy not applying:
- Verify Application Identity service running
- Check GPO is linked correctly
- Run: gpupdate /force
- Review Event Viewer > AppLocker logs

Applications blocked unexpectedly:
- Check policy mode (Audit vs Enforce)
- Review Event ID 8004 details
- Verify rule conditions

LOGS AND DIAGNOSTICS

Use the Diagnostics page to:
- Test AppLocker service status
- Verify policy application
- Check event log access
- Test WinRM connectivity
"@
    }
    "FAQ" = @{
        Title = "Frequently Asked Questions"
        Content = @"
FREQUENTLY ASKED QUESTIONS

Q: What is AppLocker?
A: Windows application control feature that lets admins specify which users/groups can run particular applications based on file attributes.

Q: What's the difference between Audit and Enforce mode?
A: Audit mode logs what would be blocked without actually blocking. Enforce mode both logs and blocks. Always start with Audit mode.

Q: Why use publisher rules over hash rules?
A: Publisher rules survive software updates because they're based on digital signatures. Hash rules must be updated after every software change.

Q: What are LOLBins?
A: Living-off-the-land binaries - legitimate Windows tools often abused by attackers (mshta.exe, wscript.exe, powershell.exe, etc.). Consider blocking in high-security environments.

Q: How many computers should I scan?
A: At least 14 representative machines covering all departments and user types. More is better for comprehensive coverage.

Q: How long should I run in Audit mode?
A: Minimum 14 days to capture regular business activities, monthly processes, and various user workflows.

Q: Can I deploy without Active Directory?
A: Yes, use local policy or PowerShell deployment for standalone machines.

Q: What if I block something critical?
A: In Audit mode, nothing is blocked. In Enforce mode, use GPO to quickly switch back to Audit or disable the policy.

Q: Does AppLocker affect administrators?
A: By default, local administrators can bypass AppLocker. Use explicit deny rules to include admins.

Q: What about unsigned applications?
A: Use path rules or hash rules for unsigned software. Consider getting software signed or using a controlled folder.

Q: How do I handle software updates?
A: Publisher rules automatically allow updates if signed by same publisher. Path rules don't need updates. Hash rules must be regenerated.

Q: What's the performance impact?
A: Minimal on modern hardware. DLL rules have highest overhead - only enable if needed.

Q: Can I export policies for SCCM/Intune?
A: Yes, use the Export feature to generate deployment packages for various platforms.
"@
    }
}

# Help topic navigation click handlers
$controls['HelpGettingStarted'].Add_Click({ Show-HelpTopic "GettingStarted" })
$controls['HelpScanning'].Add_Click({ Show-HelpTopic "Scanning" })
$controls['HelpPolicyGen'].Add_Click({ Show-HelpTopic "PolicyGen" })
$controls['HelpMerging'].Add_Click({ Show-HelpTopic "Merging" })
$controls['HelpEvents'].Add_Click({ Show-HelpTopic "Events" })
$controls['HelpSoftwareLists'].Add_Click({ Show-HelpTopic "SoftwareLists" })
$controls['HelpDeployment'].Add_Click({ Show-HelpTopic "Deployment" })
$controls['HelpTroubleshooting'].Add_Click({ Show-HelpTopic "Troubleshooting" })
$controls['HelpFAQ'].Add_Click({ Show-HelpTopic "FAQ" })

function Show-HelpTopic {
    param([string]$TopicName)
    if ($Script:HelpTopics.ContainsKey($TopicName)) {
        $topic = $Script:HelpTopics[$TopicName]
        $controls['HelpTitle'].Text = $topic.Title
        $controls['HelpBody'].Text = $topic.Content
    }
}

$controls['SelectTrustedPublishers'].Add_Click({
    # Create selection window
    $pubWindow = New-Object System.Windows.Window
    $pubWindow.Title = "Select Trusted Publishers"
    $pubWindow.Width = 650
    $pubWindow.Height = 700
    $pubWindow.WindowStartupLocation = 'CenterOwner'
    $pubWindow.Owner = $window
    $pubWindow.Background = [System.Windows.Media.Brushes]::White

    $mainPanel = New-Object System.Windows.Controls.StackPanel
    $mainPanel.Margin = "20"

    # Header
    $header = New-Object System.Windows.Controls.TextBlock
    $header.Text = "Select publishers to trust:"
    $header.FontSize = 14
    $header.FontWeight = "SemiBold"
    $header.Margin = "0,0,0,10"
    $null = $mainPanel.Children.Add($header)

    # Get unique categories
    $categories = @('All') + ($Script:TrustedPublishers.Values | ForEach-Object { $_.Category } | Sort-Object -Unique)

    # Category filter dropdown
    $filterPanel = New-Object System.Windows.Controls.StackPanel
    $filterPanel.Orientation = "Horizontal"
    $filterPanel.Margin = "0,0,0,10"

    $filterLabel = New-Object System.Windows.Controls.TextBlock
    $filterLabel.Text = "Filter by Category:"
    $filterLabel.VerticalAlignment = "Center"
    $filterLabel.Margin = "0,0,10,0"
    $null = $filterPanel.Children.Add($filterLabel)

    $categoryCombo = New-Object System.Windows.Controls.ComboBox
    $categoryCombo.Width = 200
    foreach ($cat in $categories) { $null = $categoryCombo.Items.Add($cat) }
    $categoryCombo.SelectedIndex = 0
    $null = $filterPanel.Children.Add($categoryCombo)

    $null = $mainPanel.Children.Add($filterPanel)

    # Select All / None buttons
    $buttonPanel = New-Object System.Windows.Controls.StackPanel
    $buttonPanel.Orientation = "Horizontal"
    $buttonPanel.Margin = "0,0,0,10"

    $selectAllBtn = New-Object System.Windows.Controls.Button
    $selectAllBtn.Content = "Select All Visible"
    $selectAllBtn.Padding = "12,5"
    $selectAllBtn.Margin = "0,0,8,0"

    $selectNoneBtn = New-Object System.Windows.Controls.Button
    $selectNoneBtn.Content = "Deselect All Visible"
    $selectNoneBtn.Padding = "12,5"
    $selectNoneBtn.Margin = "0,0,8,0"

    $selectCatBtn = New-Object System.Windows.Controls.Button
    $selectCatBtn.Content = "Select Category"
    $selectCatBtn.Padding = "12,5"

    $null = $buttonPanel.Children.Add($selectAllBtn)
    $null = $buttonPanel.Children.Add($selectNoneBtn)
    $null = $buttonPanel.Children.Add($selectCatBtn)
    $null = $mainPanel.Children.Add($buttonPanel)

    # ScrollViewer with checkboxes
    $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
    $scrollViewer.Height = 420
    $scrollViewer.VerticalScrollBarVisibility = "Auto"

    $checkPanel = New-Object System.Windows.Controls.StackPanel
    $checkboxes = @{}
    $checkboxPanels = @{}

    foreach ($pub in ($Script:TrustedPublishers.Keys | Sort-Object)) {
        $pubData = $Script:TrustedPublishers[$pub]
        $itemPanel = New-Object System.Windows.Controls.StackPanel
        $itemPanel.Orientation = "Horizontal"
        $itemPanel.Margin = "0,3,0,3"
        $itemPanel.Tag = $pubData.Category

        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.IsChecked = $pubData.Selected
        $cb.VerticalAlignment = "Center"
        $cb.Tag = $pub

        $catLabel = New-Object System.Windows.Controls.TextBlock
        $catLabel.Text = "[$($pubData.Category)]"
        $catLabel.Width = 90
        $catLabel.FontSize = 10
        $catLabel.Foreground = [System.Windows.Media.Brushes]::Gray
        $catLabel.VerticalAlignment = "Center"
        $catLabel.Margin = "5,0,5,0"

        $nameLabel = New-Object System.Windows.Controls.TextBlock
        $nameLabel.Text = "$pub - $($pubData.Description)"
        $nameLabel.FontSize = 12
        $nameLabel.VerticalAlignment = "Center"

        $null = $itemPanel.Children.Add($cb)
        $null = $itemPanel.Children.Add($catLabel)
        $null = $itemPanel.Children.Add($nameLabel)

        $checkboxes[$pub] = $cb
        $checkboxPanels[$pub] = $itemPanel
        $null = $checkPanel.Children.Add($itemPanel)
    }

    $scrollViewer.Content = $checkPanel
    $null = $mainPanel.Children.Add($scrollViewer)

    # Selected count label
    $countLabel = New-Object System.Windows.Controls.TextBlock
    $countLabel.Text = "0 selected"
    $countLabel.FontSize = 11
    $countLabel.Foreground = [System.Windows.Media.Brushes]::Gray
    $countLabel.Margin = "0,10,0,0"
    $null = $mainPanel.Children.Add($countLabel)

    # Update count function
    $updateCount = {
        $selected = ($checkboxes.Values | Where-Object { $_.IsChecked }).Count
        $countLabel.Text = "$selected selected"
    }

    # OK/Cancel buttons
    $okCancelPanel = New-Object System.Windows.Controls.StackPanel
    $okCancelPanel.Orientation = "Horizontal"
    $okCancelPanel.HorizontalAlignment = "Right"
    $okCancelPanel.Margin = "0,10,0,0"

    $okBtn = New-Object System.Windows.Controls.Button
    $okBtn.Content = "OK"
    $okBtn.Width = 80
    $okBtn.Padding = "10,8"
    $okBtn.Margin = "0,0,10,0"
    $okBtn.IsDefault = $true

    $cancelBtn = New-Object System.Windows.Controls.Button
    $cancelBtn.Content = "Cancel"
    $cancelBtn.Width = 80
    $cancelBtn.Padding = "10,8"
    $cancelBtn.IsCancel = $true

    $null = $okCancelPanel.Children.Add($okBtn)
    $null = $okCancelPanel.Children.Add($cancelBtn)
    $null = $mainPanel.Children.Add($okCancelPanel)

    $pubWindow.Content = $mainPanel

    # Category filter handler
    $categoryCombo.Add_SelectionChanged({
        $selectedCat = $categoryCombo.SelectedItem
        foreach ($pub in $checkboxPanels.Keys) {
            $panel = $checkboxPanels[$pub]
            if ($selectedCat -eq 'All' -or $panel.Tag -eq $selectedCat) {
                $panel.Visibility = 'Visible'
            } else {
                $panel.Visibility = 'Collapsed'
            }
        }
    })

    # Select/Deselect handlers
    $selectAllBtn.Add_Click({
        foreach ($pub in $checkboxPanels.Keys) {
            if ($checkboxPanels[$pub].Visibility -eq 'Visible') {
                $checkboxes[$pub].IsChecked = $true
            }
        }
        & $updateCount
    })

    $selectNoneBtn.Add_Click({
        foreach ($pub in $checkboxPanels.Keys) {
            if ($checkboxPanels[$pub].Visibility -eq 'Visible') {
                $checkboxes[$pub].IsChecked = $false
            }
        }
        & $updateCount
    })

    $selectCatBtn.Add_Click({
        $selectedCat = $categoryCombo.SelectedItem
        if ($selectedCat -ne 'All') {
            foreach ($pub in $checkboxPanels.Keys) {
                if ($checkboxPanels[$pub].Tag -eq $selectedCat) {
                    $checkboxes[$pub].IsChecked = $true
                }
            }
            & $updateCount
        }
    })

    # Checkbox change handlers
    foreach ($cb in $checkboxes.Values) {
        $cb.Add_Checked($updateCount)
        $cb.Add_Unchecked($updateCount)
    }

    # Initial count
    & $updateCount

    $okBtn.Add_Click({
        foreach ($pub in $checkboxes.Keys) {
            $Script:TrustedPublishers[$pub].Selected = $checkboxes[$pub].IsChecked
        }
        $count = ($Script:TrustedPublishers.Values | Where-Object { $_.Selected }).Count
        $controls['TrustedPublishersCount'].Text = "$count selected"
        $pubWindow.DialogResult = $true
        $pubWindow.Close()
    })

    $null = $pubWindow.ShowDialog()
})

# Log panel toggle
$Script:LogExpanded = $true
$controls['ToggleLog'].Add_Click({
    if ($Script:LogExpanded) { $controls['LogPanel'].Height = 36; $controls['ToggleLog'].Content = "Show"; $Script:LogExpanded = $false }
    else { $controls['LogPanel'].Height = 180; $controls['ToggleLog'].Content = "Hide"; $Script:LogExpanded = $true }
})

$controls['ClearLog'].Add_Click({ $controls['LogOutput'].Clear() })
$controls['SaveLog'].Add_Click({
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Filter = "Text Files (*.txt)|*.txt"; $dialog.FileName = "AppLocker-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    if ($dialog.ShowDialog() -eq $true) { $controls['LogOutput'].Text | Out-File $dialog.FileName -Encoding UTF8; Write-Log "Log saved." -Level Success }
})

#region Browse Button Handlers
$controls['BrowseScanComputerList'].Add_Click({
    $f = Get-OpenFileDialog -Title "Select Computer List" -Filter "Text/CSV (*.txt;*.csv)|*.txt;*.csv"
    if ($f) {
        $controls['ScanComputerList'].Text = $f
        Test-ComputerListForDCs -ComputerListPath $f -DCCardName 'ScanDCCredentialsCard'
    }
})
$controls['BrowseScanOutput'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['ScanOutputPath'].Text = $f } })
$controls['BrowseGenerateScanPath'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['GenerateScanPath'].Text = $f } })
$controls['BrowseGenerateEventPath'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['GenerateEventPath'].Text = $f } })
$controls['BrowseGenerateOutput'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['GenerateOutputPath'].Text = $f } })
$controls['BrowseMergeOutput'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['MergeOutputPath'].Text = $f } })
$controls['BrowseValidatePolicy'].Add_Click({ $f = Get-OpenFileDialog -Title "Select Policy" -Filter "XML (*.xml)|*.xml"; if ($f) { $controls['ValidatePolicyPath'].Text = $f } })
$controls['BrowseCloneSource'].Add_Click({ $f = Get-OpenFileDialog -Title "Select Policy" -Filter "XML (*.xml)|*.xml"; if ($f) { $controls['CloneSourcePolicy'].Text = $f } })
$controls['BrowseCloneOutput'].Add_Click({ $f = Get-SaveFileDialog -Title "Save Cloned Policy" -Filter "XML (*.xml)|*.xml" -DefaultExt ".xml"; if ($f) { $controls['CloneOutputPath'].Text = $f } })
$controls['BrowseEventsComputerList'].Add_Click({
    $f = Get-OpenFileDialog -Filter "Text/CSV (*.txt;*.csv)|*.txt;*.csv"
    if ($f) {
        $controls['EventsComputerList'].Text = $f
        Test-ComputerListForDCs -ComputerListPath $f -DCCardName 'EventsDCCredentialsCard'
    }
})
$controls['BrowseEventsOutput'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['EventsOutputPath'].Text = $f } })
$controls['BrowseCompareReference'].Add_Click({ $f = Get-OpenFileDialog -Filter "CSV (*.csv)|*.csv"; if ($f) { $controls['CompareReferencePath'].Text = $f } })
$controls['BrowseCompareTarget'].Add_Click({ $f = Get-OpenFileDialog -Filter "CSV (*.csv)|*.csv"; if ($f) { $controls['CompareTargetPath'].Text = $f } })
$controls['BrowseCompareOutput'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['CompareOutputPath'].Text = $f } })
$controls['BrowseCORAOutput'].Add_Click({ $f = Get-FolderDialog; if ($f) { $controls['CORAOutputPath'].Text = $f } })
$controls['BrowseCORAPolicy'].Add_Click({ $f = Get-OpenFileDialog -Title "Select Policy" -Filter "XML (*.xml)|*.xml"; if ($f) { $controls['CORAPolicyPath'].Text = $f } })
$controls['BrowseScriptsPath'].Add_Click({ $f = Get-FolderDialog -Description "Select GA-AppLocker folder"; if ($f) { $controls['SettingsScriptsPath'].Text = $f; $Script:AppRoot = $f; $Script:ScriptsAvailable = Test-Path (Join-Path $f "Start-AppLockerWorkflow.ps1"); $controls['ScriptsStatusText'].Text = if ($Script:ScriptsAvailable) { "Scripts found!" } else { "Scripts not found" } } })
#endregion

#region AD Export Handlers
# Export Computers from AD (on Scan page)
$controls['ScanExportFromAD'].Add_Click({
    $computerType = switch ($controls['ScanADComputerType'].SelectedIndex) {
        0 { "All" }
        1 { "Workstations" }
        2 { "Servers" }
        3 { "DomainControllers" }
        default { "All" }
    }
    $enabledOnly = $controls['ScanADEnabledOnly'].IsChecked
    $windowsOnly = $controls['ScanADWindowsOnly'].IsChecked

    # Ensure output directory exists
    $outputDir = Join-Path $Script:AppRoot "ADManagement"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    $outputPath = Join-Path $outputDir "computers.csv"

    Write-Log "Exporting $computerType computers from AD (Windows: $windowsOnly)..." -Level Info
    $params = @{
        Action = 'ExportComputers'
        ComputerType = $computerType
        EnabledOnly = $enabledOnly
        WindowsOnly = $windowsOnly
        OutputPath = $outputPath
    }
    Invoke-Script -ScriptName "utilities\Manage-ADResources.ps1" -Parameters $params

    # Auto-populate the computer list field and check for DCs
    if (Test-Path $outputPath) {
        $controls['ScanComputerList'].Text = $outputPath
        Write-Log "Exported to: $outputPath" -Level Success
        Write-Log "Computer list field auto-populated." -Level Info

        # Check if DCs are in the list and show credential card if needed
        $hasDCs = Test-ComputerListForDCs -ComputerListPath $outputPath -DCCardName 'ScanDCCredentialsCard'
        if ($hasDCs) {
            Write-Log "Domain Controllers detected - please provide Domain Admin credentials" -Level Warning
        }
    }
})

# Export Computers from AD (on Events page)
$controls['EventsExportFromAD'].Add_Click({
    $computerType = switch ($controls['EventsADComputerType'].SelectedIndex) {
        0 { "All" }
        1 { "Workstations" }
        2 { "Servers" }
        3 { "DomainControllers" }
        default { "All" }
    }
    $enabledOnly = $controls['EventsADEnabledOnly'].IsChecked
    $windowsOnly = $controls['EventsADWindowsOnly'].IsChecked

    # Ensure output directory exists
    $outputDir = Join-Path $Script:AppRoot "ADManagement"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    $outputPath = Join-Path $outputDir "computers.csv"

    Write-Log "Exporting $computerType computers from AD (Windows: $windowsOnly)..." -Level Info
    $params = @{
        Action = 'ExportComputers'
        ComputerType = $computerType
        EnabledOnly = $enabledOnly
        WindowsOnly = $windowsOnly
        OutputPath = $outputPath
    }
    Invoke-Script -ScriptName "utilities\Manage-ADResources.ps1" -Parameters $params

    # Auto-populate the computer list field and check for DCs
    if (Test-Path $outputPath) {
        $controls['EventsComputerList'].Text = $outputPath
        Write-Log "Exported to: $outputPath" -Level Success
        Write-Log "Computer list field auto-populated." -Level Info

        # Check if DCs are in the list and show credential card if needed
        $hasDCs = Test-ComputerListForDCs -ComputerListPath $outputPath -DCCardName 'EventsDCCredentialsCard'
        if ($hasDCs) {
            Write-Log "Domain Controllers detected - please provide Domain Admin credentials" -Level Warning
        }
    }
})

#endregion

#region Merge and Clone Handlers
# Merge list management
$controls['MergeAddFile'].Add_Click({ $f = Get-OpenFileDialog -Filter "XML (*.xml)|*.xml"; if ($f) { $null = $controls['MergePolicyList'].Items.Add($f) } })
$controls['MergeAddFolder'].Add_Click({ $f = Get-FolderDialog; if ($f) { Get-ChildItem $f -Filter "*.xml" | ForEach-Object { $null = $controls['MergePolicyList'].Items.Add($_.FullName) } } })
$controls['MergeRemoveFile'].Add_Click({ if ($controls['MergePolicyList'].SelectedItem) { $controls['MergePolicyList'].Items.Remove($controls['MergePolicyList'].SelectedItem) } })
$controls['MergeClearList'].Add_Click({ $controls['MergePolicyList'].Items.Clear() })

# Clone Rules - stored policy data
$Script:ClonePolicy = $null
$Script:CloneRules = @()

# Clone Rules UI toggles
$controls['CloneTargetGroup'].Add_SelectionChanged({
    $item = $controls['CloneTargetGroup'].SelectedItem
    if ($item -and $item.Content) {
        $selected = $item.Content.ToString()
        $controls['CloneCustomGroup'].Visibility = if ($selected -eq "Custom...") { 'Visible' } else { 'Collapsed' }
    }
})

$controls['CloneNewFile'].Add_Checked({ $controls['CloneNewFileOptions'].Visibility = 'Visible' })
$controls['CloneAppendSource'].Add_Checked({ $controls['CloneNewFileOptions'].Visibility = 'Collapsed' })

# Load Clone Policy
$controls['LoadClonePolicy'].Add_Click({
    $path = $controls['CloneSourcePolicy'].Text
    if (-not $path -or -not (Test-Path $path)) {
        Write-Log "Please select a valid policy file." -Level Error
        return
    }

    try {
        [xml]$Script:ClonePolicy = Get-Content $path -Raw
        if ($Script:ClonePolicy.DocumentElement.Name -ne 'AppLockerPolicy') {
            Write-Log "Invalid AppLocker policy file." -Level Error
            return
        }

        # Count rules by type
        $Script:CloneRules = @()
        $summary = @()
        foreach ($collection in $Script:ClonePolicy.AppLockerPolicy.RuleCollection) {
            $type = $collection.Type
            $rules = $collection.ChildNodes | Where-Object { $_.LocalName -match 'Rule$' }
            foreach ($rule in $rules) {
                $Script:CloneRules += [PSCustomObject]@{
                    Type = $type
                    RuleType = $rule.LocalName -replace 'File|Rule',''
                    Name = $rule.Name
                    Action = $rule.Action
                    UserOrGroupSid = $rule.UserOrGroupSid
                    Node = $rule
                    Collection = $collection
                }
            }
            $allowCount = ($rules | Where-Object { $_.Action -eq 'Allow' }).Count
            $denyCount = ($rules | Where-Object { $_.Action -eq 'Deny' }).Count
            if ($rules.Count -gt 0) {
                $summary += "$type : $($rules.Count) rules ($allowCount allow, $denyCount deny)"
            }
        }

        $controls['ClonePolicySummary'].Text = $summary -join "`n"
        $controls['CloneOptionsCard'].Visibility = 'Visible'
        $controls['PreviewClone'].Visibility = 'Visible'
        $controls['ExecuteClone'].Visibility = 'Visible'

        Write-Log "Loaded policy: $($Script:CloneRules.Count) total rules" -Level Success
    } catch {
        Write-Log "Error loading policy: $_" -Level Error
    }
})

# Preview Clone
$controls['PreviewClone'].Add_Click({
    if (-not $Script:ClonePolicy) {
        Write-Log "Please load a policy first." -Level Error
        return
    }

    # Filter rules based on selections
    $filtered = $Script:CloneRules

    # Filter by rule type
    if ($controls['ClonePublisherOnly'].IsChecked) { $filtered = $filtered | Where-Object { $_.RuleType -eq 'Publisher' } }
    elseif ($controls['CloneHashOnly'].IsChecked) { $filtered = $filtered | Where-Object { $_.RuleType -eq 'Hash' } }
    elseif ($controls['ClonePathOnly'].IsChecked) { $filtered = $filtered | Where-Object { $_.RuleType -eq 'Path' } }

    # Filter by action
    if ($controls['CloneFilterAllow'].IsChecked) { $filtered = $filtered | Where-Object { $_.Action -eq 'Allow' } }
    elseif ($controls['CloneFilterDeny'].IsChecked) { $filtered = $filtered | Where-Object { $_.Action -eq 'Deny' } }

    # Determine new action
    $newAction = "Keep"
    if ($controls['CloneActionAllow'].IsChecked) { $newAction = "Allow" }
    elseif ($controls['CloneActionDeny'].IsChecked) { $newAction = "Deny" }

    # Determine new group
    $newGroup = $controls['CloneTargetGroup'].SelectedItem.Content
    if ($newGroup -eq "Custom...") { $newGroup = $controls['CloneCustomGroup'].Text }

    # Build preview
    $controls['ClonePreviewList'].Items.Clear()
    foreach ($rule in $filtered) {
        $actionDisplay = if ($newAction -eq "Keep") { $rule.Action } else { $newAction }
        $preview = "[$($rule.Type)] $($rule.Name) -> $newGroup ($actionDisplay)"
        $null = $controls['ClonePreviewList'].Items.Add($preview)
    }

    $controls['ClonePreviewCount'].Text = " ($($filtered.Count) rules)"
    $controls['ClonePreviewCard'].Visibility = 'Visible'

    Write-Log "Preview: $($filtered.Count) rules will be cloned" -Level Info
})

# Execute Clone
$controls['ExecuteClone'].Add_Click({
    if (-not $Script:ClonePolicy) {
        Write-Log "Please load a policy first." -Level Error
        return
    }

    # Filter rules based on selections
    $filtered = $Script:CloneRules

    if ($controls['ClonePublisherOnly'].IsChecked) { $filtered = $filtered | Where-Object { $_.RuleType -eq 'Publisher' } }
    elseif ($controls['CloneHashOnly'].IsChecked) { $filtered = $filtered | Where-Object { $_.RuleType -eq 'Hash' } }
    elseif ($controls['ClonePathOnly'].IsChecked) { $filtered = $filtered | Where-Object { $_.RuleType -eq 'Path' } }

    if ($controls['CloneFilterAllow'].IsChecked) { $filtered = $filtered | Where-Object { $_.Action -eq 'Allow' } }
    elseif ($controls['CloneFilterDeny'].IsChecked) { $filtered = $filtered | Where-Object { $_.Action -eq 'Deny' } }

    if ($filtered.Count -eq 0) {
        Write-Log "No rules match the selected filters." -Level Warning
        return
    }

    # Determine new action
    $newAction = $null
    if ($controls['CloneActionAllow'].IsChecked) { $newAction = "Allow" }
    elseif ($controls['CloneActionDeny'].IsChecked) { $newAction = "Deny" }

    # Determine new group and resolve SID
    $newGroup = $controls['CloneTargetGroup'].SelectedItem.Content
    if ($newGroup -eq "Custom...") { $newGroup = $controls['CloneCustomGroup'].Text }

    # Resolve SID for new group
    $newSid = switch ($newGroup) {
        "BUILTIN\Administrators" { "S-1-5-32-544" }
        "BUILTIN\Users" { "S-1-5-32-545" }
        "Everyone" { "S-1-1-0" }
        "NT AUTHORITY\SYSTEM" { "S-1-5-18" }
        "NT AUTHORITY\LOCAL SERVICE" { "S-1-5-19" }
        "NT AUTHORITY\NETWORK SERVICE" { "S-1-5-20" }
        default {
            try {
                $account = New-Object System.Security.Principal.NTAccount($newGroup)
                $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                Write-Log "Could not resolve SID for $newGroup - using name" -Level Warning
                $newGroup
            }
        }
    }

    Write-Log "Cloning $($filtered.Count) rules to $newGroup ($newSid)..." -Level Info

    # Clone the rules
    $clonedCount = 0
    foreach ($rule in $filtered) {
        # Clone the XML node
        $clonedNode = $rule.Node.CloneNode($true)

        # Generate new GUID for the rule
        $clonedNode.Id = [guid]::NewGuid().ToString()

        # Update the name to indicate it's cloned
        $originalName = $clonedNode.Name
        $clonedNode.Name = "(Cloned) $originalName"

        # Update the SID
        $clonedNode.UserOrGroupSid = $newSid

        # Update action if specified
        if ($newAction) { $clonedNode.Action = $newAction }

        # Find the correct RuleCollection and append
        $targetCollection = $Script:ClonePolicy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $rule.Type }
        if ($targetCollection) {
            $null = $targetCollection.AppendChild($clonedNode)
            $clonedCount++
        }
    }

    # Save the policy
    $outputPath = if ($controls['CloneAppendSource'].IsChecked) {
        $controls['CloneSourcePolicy'].Text
    } else {
        $controls['CloneOutputPath'].Text
    }

    # Ensure output directory exists
    $outputDir = Split-Path $outputPath -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $Script:ClonePolicy.Save($outputPath)

    Write-Log "Successfully cloned $clonedCount rules to: $outputPath" -Level Success
    [System.Windows.MessageBox]::Show(
        "Successfully cloned $clonedCount rules!`n`nSaved to: $outputPath",
        "Clone Complete",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information
    )
})
#endregion

#region Main Operation Handlers
$controls['StartScan'].Add_Click({
    $list = $controls['ScanComputerList'].Text
    if (-not $list -or -not (Test-Path $list)) { Write-Log "Please select a valid computer list." -Level Error; return }
    $params = @{ ComputerList = $list; OutputPath = $controls['ScanOutputPath'].Text; ThrottleLimit = [int]$controls['ScanThrottleLimit'].Text }
    if ($controls['ScanUserProfiles'].IsChecked) { $params['ScanUserProfiles'] = $true }

    # Build credential if provided
    $username = $controls['ScanUsername'].Text
    $password = $controls['ScanPassword'].SecurePassword
    if ($username -and $password.Length -gt 0) {
        $params['Credential'] = New-Object System.Management.Automation.PSCredential($username, $password)
        Write-Log "Using credentials for: $username" -Level Info
    }

    # Check for DC credentials
    $dcUsername = $controls['ScanDCUsername'].Text
    $dcPassword = $controls['ScanDCPassword'].SecurePassword
    if ($dcUsername -and $dcPassword.Length -gt 0) {
        $params['DCCredential'] = New-Object System.Management.Automation.PSCredential($dcUsername, $dcPassword)
        Write-Log "DC credentials provided for: $dcUsername (will be used for Domain Controllers)" -Level Info
    }

    Write-Log "Starting scan..." -Level Info
    Invoke-Script -ScriptName "Invoke-RemoteScan.ps1" -Parameters $params
    Write-Log "Scan completed." -Level Success
})

$controls['StartGenerate'].Add_Click({
    $scanPath = $controls['GenerateScanPath'].Text
    $eventPath = $controls['GenerateEventPath'].Text
    $hasScan = $scanPath -and (Test-Path $scanPath)
    $hasEvent = $eventPath -and (Test-Path $eventPath)
    if (-not $hasScan -and -not $hasEvent) { Write-Log "Please select a valid scan folder or event folder." -Level Error; return }
    $params = @{ OutputPath = $controls['GenerateOutputPath'].Text }
    if ($hasScan) { $params['ScanPath'] = $scanPath }
    if ($hasEvent) { $params['EventPath'] = $eventPath }
    if ($controls['GenerateSimplified'].IsChecked) { $params['Simplified'] = $true }
    else {
        $domain = $controls['GenerateDomainName'].Text
        if (-not $domain) { Write-Log "Domain name required for Build Guide mode." -Level Error; return }
        $params['DomainName'] = $domain; $params['Phase'] = $controls['GeneratePhase'].SelectedIndex + 1
    }
    if ($controls['GenerateIncludeDenyRules'].IsChecked) { $params['IncludeDenyRules'] = $true }
    Write-Log "Generating policy..." -Level Info
    Invoke-Script -ScriptName "New-AppLockerPolicyFromGuide.ps1" -Parameters $params
    Write-Log "Generation completed." -Level Success
})

$controls['StartMerge'].Add_Click({
    $files = @($controls['MergePolicyList'].Items)
    if ($files.Count -lt 2) { Write-Log "Add at least 2 policy files." -Level Error; return }
    Write-Log "Merging $($files.Count) policies..." -Level Info
    Invoke-Script -ScriptName "Merge-AppLockerPolicies.ps1" -Parameters @{ PolicyPaths = $files; OutputPath = $controls['MergeOutputPath'].Text }
    Write-Log "Merge completed." -Level Success
})

$controls['StartValidate'].Add_Click({
    $path = $controls['ValidatePolicyPath'].Text
    if (-not $path -or -not (Test-Path $path)) { Write-Log "Please select a valid policy file." -Level Error; return }
    Write-Log "Validating policy..." -Level Info
    Set-Status -State 'Running'
    try {
        [xml]$policy = Get-Content $path -Raw
        $results = @("Policy Validation Results", "=" * 40, "")
        if ($policy.DocumentElement.Name -eq 'AppLockerPolicy') { $results += "[+] Valid AppLocker structure" }
        else { $results += "[-] Invalid structure" }
        $results += ""; $results += "Rule Collections:"
        foreach ($c in $policy.AppLockerPolicy.RuleCollection) {
            $count = ($c.ChildNodes | Where-Object { $_.LocalName -match 'Rule$' }).Count
            $results += "  - $($c.Type): $count rules ($($c.EnforcementMode))"
        }
        $everyone = $policy.SelectNodes("//*[contains(@UserOrGroupSid, 'S-1-1-0')]")
        $results += ""; $results += "Security:"
        if ($everyone.Count -gt 0) { $results += "[!] $($everyone.Count) Everyone rules" }
        else { $results += "[+] No Everyone rules" }
        $controls['ValidationResultsCard'].Visibility = 'Visible'
        $controls['ValidationResults'].Text = $results -join "`r`n"
        Set-Status -State 'Success'; Write-Log "Validation completed." -Level Success
    } catch { Write-Log "Error: $_" -Level Error; Set-Status -State 'Error' }
})

$controls['StartEvents'].Add_Click({
    $list = $controls['EventsComputerList'].Text
    if (-not $list -or -not (Test-Path $list)) { Write-Log "Please select a valid computer list." -Level Error; return }
    $days = switch ($controls['EventsDaysBack'].SelectedIndex) { 0 { 7 } 1 { 14 } 2 { 30 } 3 { 90 } 4 { 0 } default { 14 } }
    $params = @{ ComputerList = $list; OutputPath = $controls['EventsOutputPath'].Text; DaysBack = $days }

    # Build credential if provided
    $username = $controls['EventsUsername'].Text
    $password = $controls['EventsPassword'].SecurePassword
    if ($username -and $password.Length -gt 0) {
        $params['Credential'] = New-Object System.Management.Automation.PSCredential($username, $password)
        Write-Log "Using credentials for: $username" -Level Info
    }

    # Check for DC credentials
    $dcUsername = $controls['EventsDCUsername'].Text
    $dcPassword = $controls['EventsDCPassword'].SecurePassword
    if ($dcUsername -and $dcPassword.Length -gt 0) {
        $params['DCCredential'] = New-Object System.Management.Automation.PSCredential($dcUsername, $dcPassword)
        Write-Log "DC credentials provided for: $dcUsername" -Level Info
    }

    # 0 = Blocked Only, 1 = Allowed Only, 2 = All Events
    switch ($controls['EventsType'].SelectedIndex) {
        0 { $params['BlockedOnly'] = $true }
        1 { $params['AllowedOnly'] = $true }
        2 { $params['IncludeAllowedEvents'] = $true }
    }
    Write-Log "Collecting events..." -Level Info
    Invoke-Script -ScriptName "Invoke-RemoteEventCollection.ps1" -Parameters $params
    Write-Log "Collection completed." -Level Success
})

# Compare Inventory - Credentials toggle
$controls['CompareUseLoggedInCredentials'].Add_Checked({ $controls['CompareCustomCredentialsPanel'].Visibility = 'Collapsed' })
$controls['CompareUseLoggedInCredentials'].Add_Unchecked({ $controls['CompareCustomCredentialsPanel'].Visibility = 'Visible' })

$controls['StartCompare'].Add_Click({
    $ref = $controls['CompareReferencePath'].Text
    $target = $controls['CompareTargetPath'].Text
    $outputPath = $controls['CompareOutputPath'].Text
    $method = switch ($controls['CompareMethod'].SelectedIndex) { 0 { "Name" } 1 { "NameVersion" } 2 { "Hash" } 3 { "Publisher" } default { "Name" } }

    # Check if scanning endpoints with credentials
    if ($controls['CompareScanAllEndpoints'].IsChecked) {
        # Target path should be a computer list file
        if (-not $target -or -not (Test-Path $target)) {
            Write-Log "Please select a valid computer list file for endpoint scanning." -Level Error
            return
        }

        # Build scan parameters
        $scanParams = @{
            ComputerList = $target
            OutputPath = $outputPath
        }

        # Build credential if custom credentials are specified
        if (-not $controls['CompareUseLoggedInCredentials'].IsChecked) {
            $username = $controls['CompareUsername'].Text
            $password = $controls['ComparePassword'].SecurePassword
            if ($username -and $password.Length -gt 0) {
                $scanParams['Credential'] = New-Object System.Management.Automation.PSCredential($username, $password)
                Write-Log "Using custom credentials for: $username" -Level Info
            } else {
                Write-Log "Custom credentials selected but username or password is empty." -Level Error
                return
            }
        } else {
            Write-Log "Using logged-in credentials for remote scanning." -Level Info
        }

        Write-Log "Scanning endpoints from computer list..." -Level Info
        Invoke-Script -ScriptName "Invoke-RemoteScan.ps1" -Parameters $scanParams

        # After scan, compare with reference if provided
        if ($ref -and (Test-Path $ref)) {
            Write-Log "Scan complete. Comparing scanned inventory with baseline..." -Level Info
            # Find latest scan output
            $latestScan = Get-ChildItem -Path $outputPath -Directory -Filter "Scan-*" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestScan) {
                $scanInventory = Join-Path $latestScan.FullName "Executables.csv"
                if (Test-Path $scanInventory) {
                    Invoke-Script -ScriptName "utilities\Compare-SoftwareInventory.ps1" -Parameters @{
                        ReferencePath = $ref
                        ComparePath = $scanInventory
                        CompareBy = $method
                        OutputPath = $outputPath
                    }
                }
            }
        }
        Write-Log "Endpoint scan and comparison completed." -Level Success
    } else {
        # Standard file-to-file comparison
        if (-not $ref -or -not $target -or -not (Test-Path $ref) -or -not (Test-Path $target)) {
            Write-Log "Select valid reference and target files." -Level Error
            return
        }
        Write-Log "Comparing inventories..." -Level Info
        Invoke-Script -ScriptName "utilities\Compare-SoftwareInventory.ps1" -Parameters @{
            ReferencePath = $ref
            ComparePath = $target
            CompareBy = $method
            OutputPath = $outputPath
        }
        Write-Log "Comparison completed." -Level Success
    }
})
#endregion

#region CORA and Diagnostic Handlers
$controls['StartCORA'].Add_Click({
    $outputPath = $controls['CORAOutputPath'].Text
    if (-not $outputPath) { Write-Log "Please specify an output path." -Level Error; return }

    $params = @{ OutputPath = $outputPath }

    # Check for specific policy
    $policyPath = $controls['CORAPolicyPath'].Text
    if ($policyPath -and (Test-Path $policyPath)) {
        $params['PolicyPath'] = $policyPath
    }

    # Check options
    if ($controls['CORAIncludeRawData'].IsChecked) {
        $params['IncludeRawData'] = $true
    }

    Write-Log "Generating CORA Evidence Package..." -Level Info
    Invoke-Script -ScriptName "utilities\New-CORAEvidence.ps1" -Parameters $params

    # Open folder if requested
    if ($controls['CORAOpenWhenComplete'].IsChecked) {
        $latestFolder = Get-ChildItem -Path $outputPath -Directory -Filter "CORA-*" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestFolder) {
            Start-Process "explorer.exe" -ArgumentList $latestFolder.FullName
        }
    }

    Write-Log "CORA Evidence Package generated." -Level Success
})

$controls['StartDiagnostic'].Add_Click({
    $computer = $controls['DiagnosticComputerName'].Text
    if (-not $computer) { Write-Log "Enter a computer name." -Level Error; return }
    Write-Log "Running diagnostic on $computer..." -Level Info
    Invoke-Script -ScriptName "utilities\Test-AppLockerDiagnostic.ps1" -Parameters @{ ComputerName = $computer }
    Write-Log "Diagnostic completed." -Level Success
})
#endregion

#region AD Management Handlers
# AD Setup - Create OUs and Groups
$controls['ADSetup'].Add_Click({
    $domain = $controls['ADDomainName'].Text.Trim()
    $prefix = $controls['ADGroupPrefix'].Text.Trim()

    # Input validation
    if (-not $domain) {
        Write-Log "Domain name is required. Enter the domain name (e.g., CONTOSO or contoso.com)." -Level Error
        return
    }

    if (-not $prefix) {
        $prefix = "AppLocker"
        $controls['ADGroupPrefix'].Text = $prefix
        Write-Log "Using default group prefix: AppLocker" -Level Warning
    }

    # Validate domain format
    if ($domain -match '[<>:"/\\|?*]') {
        Write-Log "Domain name contains invalid characters." -Level Error
        return
    }

    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory PowerShell module is not installed. Install RSAT tools or run on a domain controller." -Level Error
        return
    }

    try {
        Write-Log "Creating AD resources for $domain..." -Level Info
        Write-Log "  Groups: ${prefix}-Admins, ${prefix}-StandardUsers, ${prefix}-ServiceAccounts, ${prefix}-Installers" -Level Info

        $params = @{
            Action = 'CreateStructure'
            DomainName = $domain
            GroupPrefix = $prefix
            Force = $true
        }
        Invoke-Script -ScriptName "utilities\Manage-ADResources.ps1" -Parameters $params
        Write-Log "AD setup completed successfully!" -Level Success
    }
    catch {
        Write-Log "AD setup failed: $_" -Level Error
    }
})


# AD Scan Users - Export users and group memberships
$controls['ADScanUsers'].Add_Click({
    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory PowerShell module is not installed. Install RSAT tools or run on a domain controller." -Level Error
        return
    }

    $outputPath = $controls['ADUserExportPath'].Text.Trim()
    if (-not $outputPath) {
        $outputPath = ".\ADManagement\ADUserGroups-Export.csv"
        $controls['ADUserExportPath'].Text = $outputPath
    }

    # Validate output path
    if ($outputPath -match '[<>:"|?*]' -and $outputPath -notmatch '^[A-Z]:') {
        Write-Log "Output path contains invalid characters." -Level Error
        return
    }

    # Validate search base if provided
    $searchBase = $controls['ADUserSearchBase'].Text.Trim()
    if ($searchBase) {
        # Basic LDAP DN validation
        if ($searchBase -notmatch '^(OU|CN|DC)=') {
            Write-Log "Search base should be a valid LDAP path (e.g., OU=Users,DC=contoso,DC=com). Leave blank for entire domain." -Level Warning
        }
    }

    try {
        # Ensure output directory exists
        $outputDir = Split-Path $outputPath -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            Write-Log "Created output directory: $outputDir" -Level Info
        }

        Write-Log "Scanning AD users..." -Level Info
        if ($searchBase) {
            Write-Log "  Search Base: $searchBase" -Level Info
        } else {
            Write-Log "  Search Base: Entire domain" -Level Info
        }

        $params = @{
            Action = 'ExportUsers'
            OutputPath = $outputPath
        }

        if ($searchBase) { $params['SearchBase'] = $searchBase }
        if ($controls['ADIncludeDisabled'].IsChecked) { $params['IncludeDisabled'] = $true }

        Invoke-Script -ScriptName "utilities\Manage-ADResources.ps1" -Parameters $params

        if (Test-Path $outputPath) {
            $count = (Import-Csv $outputPath -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Log "User export completed! $count users exported to $outputPath" -Level Success
            Write-Log "Also created: groups.csv (for bulk import) and users.csv" -Level Info
        } else {
            Write-Log "Export completed but output file not found. Check logs for errors." -Level Warning
        }
    }
    catch {
        Write-Log "User scan failed: $_" -Level Error
    }
})

# Browse for user export path
$controls['BrowseADUserExport'].Add_Click({
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Filter = "CSV Files (*.csv)|*.csv"
    $dialog.FileName = "ADUserGroups-Export.csv"
    $dialog.InitialDirectory = Join-Path $Script:AppRoot "ADManagement"
    if ($dialog.ShowDialog()) { $controls['ADUserExportPath'].Text = $dialog.FileName }
})

# AD Import Users - Add users to groups from CSV
$controls['ADImportUsers'].Add_Click({
    $importPath = $controls['ADImportPath'].Text
    if (-not $importPath -or -not (Test-Path $importPath)) {
        Write-Log "Import file not found: $importPath" -Level Error
        return
    }

    $previewOnly = $controls['ADImportPreview'].IsChecked

    if ($previewOnly) {
        Write-Log "Preview mode - analyzing changes (no changes will be made)..." -Level Info
    } else {
        Write-Log "Importing group memberships from $importPath..." -Level Warning
    }

    $params = @{
        Action = 'ImportUsers'
        InputPath = $importPath
    }

    if ($previewOnly) {
        # Use WhatIf for preview mode
        $params['WhatIf'] = $true
    }

    Invoke-Script -ScriptName "utilities\Manage-ADResources.ps1" -Parameters $params

    if ($previewOnly) {
        Write-Log "Preview completed. Uncheck 'Preview only' to apply changes." -Level Info
    } else {
        Write-Log "Import completed. Check log for details." -Level Success
    }
})

# Browse for import file
$controls['BrowseADImport'].Add_Click({
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Filter = "CSV Files (*.csv)|*.csv"
    $dialog.InitialDirectory = Join-Path $Script:AppRoot "ADManagement"
    if ($dialog.ShowDialog()) { $controls['ADImportPath'].Text = $dialog.FileName }
})

# View import file in default editor
$controls['ADViewImportFile'].Add_Click({
    $importPath = $controls['ADImportPath'].Text
    if (-not $importPath) {
        Write-Log "No import file specified." -Level Error
        return
    }
    if (-not (Test-Path $importPath)) {
        Write-Log "File not found: $importPath" -Level Error
        return
    }
    Write-Log "Opening $importPath..." -Level Info
    Start-Process $importPath
})

#region Quick Group Manager Handlers
# Store pending changes for the group manager
$Script:GroupManagerPendingAdd = @()
$Script:GroupManagerPendingRemove = @()
$Script:GroupManagerAllUsers = @()

# Helper function to update status text
function Update-GroupManagerStatus {
    param([string]$Message, [string]$Color = "#A8B2BC")
    $controls['ADGroupManagerStatus'].Text = $Message
    $controls['ADGroupManagerStatus'].Foreground = $Color
}

# Load users from AD
$controls['ADGroupManagerLoadUsers'].Add_Click({
    try {
        Write-Log "Loading users from Active Directory..." -Level Info
        Update-GroupManagerStatus "Loading users..." "#FFCC00"

        # Check if AD module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Log "ActiveDirectory module not available." -Level Error
            Update-GroupManagerStatus "AD module not available" "#FF6B6B"
            return
        }

        Import-Module ActiveDirectory -ErrorAction Stop

        # Get all users with relevant properties
        $users = Get-ADUser -Filter * -Properties DisplayName, SamAccountName, Enabled, DistinguishedName,
            AdminCount, ServicePrincipalName, MemberOf, Description |
            Where-Object { $_.Enabled -eq $true } |
            Select-Object @{N='Display';E={
                $name = if ($_.DisplayName) { $_.DisplayName } else { $_.SamAccountName }
                # Extract OU for sorting
                $ou = ($_.DistinguishedName -split ',OU=' | Select-Object -Skip 1 | Select-Object -First 1)
                if (-not $ou) { $ou = "Users" }
                $name
            }},
            @{N='SamAccountName';E={$_.SamAccountName}},
            @{N='OU';E={
                $parts = $_.DistinguishedName -split ',OU='
                if ($parts.Count -gt 1) { $parts[1] -replace ',.*$','' } else { "Users" }
            }},
            @{N='Category';E={
                # Categorize user
                if ($_.AdminCount -eq 1) { "Privileged" }
                elseif ($_.ServicePrincipalName) { "Service" }
                elseif ($_.SamAccountName -match '^(svc|service|app|sql|iis)') { "Service" }
                elseif ($_.MemberOf -match 'Admin|Privileged|IT-') { "Privileged" }
                else { "Standard" }
            }},
            @{N='DN';E={$_.DistinguishedName}}

        # Store all users for filtering
        $Script:GroupManagerAllUsers = $users | Sort-Object OU, Display

        # Populate the available users listbox
        $controls['ADGroupManagerAvailable'].Items.Clear()
        foreach ($user in $Script:GroupManagerAllUsers) {
            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = "$($user.Display) ($($user.SamAccountName))"
            $item.Tag = $user.SamAccountName
            $item.ToolTip = "OU: $($user.OU) | Category: $($user.Category)"
            $controls['ADGroupManagerAvailable'].Items.Add($item) | Out-Null
        }

        $count = $Script:GroupManagerAllUsers.Count
        Write-Log "Loaded $count users from Active Directory." -Level Success
        Update-GroupManagerStatus "$count users loaded" "#58A6FF"

        # Also refresh the current group members
        $controls['ADGroupManagerRefresh'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))

    } catch {
        Write-Log "Failed to load users: $_" -Level Error
        Update-GroupManagerStatus "Failed to load users" "#FF6B6B"
    }
})

# Filter users based on category selection
$controls['ADGroupManagerUserFilter'].Add_SelectionChanged({
    if ($Script:GroupManagerAllUsers.Count -eq 0) { return }

    $filter = $controls['ADGroupManagerUserFilter'].SelectedItem.Content
    $searchText = $controls['ADGroupManagerSearch'].Text.ToLower()

    $controls['ADGroupManagerAvailable'].Items.Clear()

    $filteredUsers = $Script:GroupManagerAllUsers | Where-Object {
        $matchFilter = switch ($filter) {
            "All Users" { $true }
            "Standard Users" { $_.Category -eq "Standard" }
            "Service Accounts" { $_.Category -eq "Service" }
            "Privileged Accounts" { $_.Category -eq "Privileged" }
            default { $true }
        }
        $matchSearch = if ($searchText) {
            $_.Display -like "*$searchText*" -or $_.SamAccountName -like "*$searchText*" -or $_.OU -like "*$searchText*"
        } else { $true }
        $matchFilter -and $matchSearch
    }

    foreach ($user in $filteredUsers) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = "$($user.Display) ($($user.SamAccountName))"
        $item.Tag = $user.SamAccountName
        $item.ToolTip = "OU: $($user.OU) | Category: $($user.Category)"
        $controls['ADGroupManagerAvailable'].Items.Add($item) | Out-Null
    }

    Update-GroupManagerStatus "$($filteredUsers.Count) users shown" "#A8B2BC"
})

# Search box handler
$controls['ADGroupManagerSearch'].Add_TextChanged({
    # Trigger filter update
    $controls['ADGroupManagerUserFilter'].RaiseEvent((New-Object System.Windows.Controls.SelectionChangedEventArgs(
        [System.Windows.Controls.ComboBox]::SelectionChangedEvent, @(), @())))
})

# Refresh current group members
$controls['ADGroupManagerRefresh'].Add_Click({
    try {
        $targetGroup = $controls['ADGroupManagerTarget'].SelectedItem.Content
        if (-not $targetGroup) { return }

        Write-Log "Refreshing members for $targetGroup..." -Level Info

        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Log "ActiveDirectory module not available." -Level Error
            return
        }

        Import-Module ActiveDirectory -ErrorAction Stop

        $controls['ADGroupManagerMembers'].Items.Clear()

        # Try to get group members
        try {
            $groupName = $targetGroup -replace "^.*\\", ""  # Remove domain prefix
            $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop |
                Where-Object { $_.objectClass -eq 'user' } |
                ForEach-Object {
                    $user = Get-ADUser $_.SamAccountName -Properties DisplayName
                    [PSCustomObject]@{
                        Display = if ($user.DisplayName) { $user.DisplayName } else { $user.SamAccountName }
                        SamAccountName = $user.SamAccountName
                    }
                } | Sort-Object Display

            foreach ($member in $members) {
                $item = New-Object System.Windows.Controls.ListBoxItem
                $item.Content = "$($member.Display) ($($member.SamAccountName))"
                $item.Tag = $member.SamAccountName
                $controls['ADGroupManagerMembers'].Items.Add($item) | Out-Null
            }

            $count = $members.Count
            $controls['ADGroupManagerMemberCount'].Text = "$count members"
            Write-Log "Group $targetGroup has $count members." -Level Info

        } catch {
            if ($_.Exception.Message -match "Cannot find") {
                $controls['ADGroupManagerMemberCount'].Text = "Group not found"
                Write-Log "Group $targetGroup not found in AD. It may need to be created first." -Level Warning
            } else {
                throw
            }
        }

        # Clear pending changes when refreshing
        $Script:GroupManagerPendingAdd = @()
        $Script:GroupManagerPendingRemove = @()
        Update-GroupManagerStatus "Members refreshed" "#58A6FF"

    } catch {
        Write-Log "Failed to refresh members: $_" -Level Error
        Update-GroupManagerStatus "Refresh failed" "#FF6B6B"
    }
})

# Target group selection changed - refresh members
$controls['ADGroupManagerTarget'].Add_SelectionChanged({
    if ($controls['ADGroupManagerTarget'].SelectedItem) {
        $controls['ADGroupManagerRefresh'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
    }
})

# Select All button
$controls['ADGroupManagerSelectAll'].Add_Click({
    $controls['ADGroupManagerAvailable'].SelectAll()
    $count = $controls['ADGroupManagerAvailable'].SelectedItems.Count
    Update-GroupManagerStatus "$count users selected" "#A8B2BC"
})

# Clear selection button
$controls['ADGroupManagerSelectNone'].Add_Click({
    $controls['ADGroupManagerAvailable'].UnselectAll()
    Update-GroupManagerStatus "Selection cleared" "#A8B2BC"
})

# Add selected users to pending additions
$controls['ADGroupManagerAdd'].Add_Click({
    $selected = $controls['ADGroupManagerAvailable'].SelectedItems
    if ($selected.Count -eq 0) {
        Write-Log "No users selected to add." -Level Warning
        return
    }

    $addCount = 0
    foreach ($item in $selected) {
        $sam = $item.Tag
        # Check if already a member
        $alreadyMember = $controls['ADGroupManagerMembers'].Items | Where-Object { $_.Tag -eq $sam }
        if (-not $alreadyMember -and $sam -notin $Script:GroupManagerPendingAdd) {
            $Script:GroupManagerPendingAdd += $sam

            # Add to members list with pending indicator
            $newItem = New-Object System.Windows.Controls.ListBoxItem
            $newItem.Content = "$($item.Content) [+]"
            $newItem.Tag = $sam
            $newItem.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#58A6FF")  # Blue to indicate pending add
            $controls['ADGroupManagerMembers'].Items.Add($newItem) | Out-Null
            $addCount++
        }
    }

    if ($addCount -gt 0) {
        Write-Log "Marked $addCount users for addition (pending)." -Level Info
        $totalPending = $Script:GroupManagerPendingAdd.Count + $Script:GroupManagerPendingRemove.Count
        Update-GroupManagerStatus "$totalPending pending changes" "#FFCC00"
    }

    # Update member count
    $controls['ADGroupManagerMemberCount'].Text = "$($controls['ADGroupManagerMembers'].Items.Count) members"
})

# Remove selected members (mark for removal)
$controls['ADGroupManagerRemove'].Add_Click({
    $selected = @($controls['ADGroupManagerMembers'].SelectedItems)
    if ($selected.Count -eq 0) {
        Write-Log "No members selected to remove." -Level Warning
        return
    }

    $removeCount = 0
    foreach ($item in $selected) {
        $sam = $item.Tag

        # If it was a pending add, just remove it
        if ($sam -in $Script:GroupManagerPendingAdd) {
            $Script:GroupManagerPendingAdd = $Script:GroupManagerPendingAdd | Where-Object { $_ -ne $sam }
            $controls['ADGroupManagerMembers'].Items.Remove($item)
        } else {
            # Mark for removal
            if ($sam -notin $Script:GroupManagerPendingRemove) {
                $Script:GroupManagerPendingRemove += $sam
                $item.Content = $item.Content -replace ' \[\+\]$',''
                $item.Content = "$($item.Content) [-]"
                $item.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FF6B6B")  # Red to indicate pending removal
                $removeCount++
            }
        }
    }

    if ($removeCount -gt 0) {
        Write-Log "Marked $removeCount members for removal (pending)." -Level Info
    }

    $totalPending = $Script:GroupManagerPendingAdd.Count + $Script:GroupManagerPendingRemove.Count
    if ($totalPending -gt 0) {
        Update-GroupManagerStatus "$totalPending pending changes" "#FFCC00"
    } else {
        Update-GroupManagerStatus "" "#A8B2BC"
    }

    # Update member count
    $controls['ADGroupManagerMemberCount'].Text = "$($controls['ADGroupManagerMembers'].Items.Count) members"
})

# Apply changes to AD
$controls['ADGroupManagerApply'].Add_Click({
    $targetGroup = $controls['ADGroupManagerTarget'].SelectedItem.Content
    if (-not $targetGroup) {
        Write-Log "No target group selected." -Level Error
        return
    }

    $groupName = $targetGroup -replace "^.*\\", ""  # Remove domain prefix
    $previewOnly = $controls['ADGroupManagerPreview'].IsChecked

    if ($Script:GroupManagerPendingAdd.Count -eq 0 -and $Script:GroupManagerPendingRemove.Count -eq 0) {
        Write-Log "No pending changes to apply." -Level Warning
        Update-GroupManagerStatus "No changes to apply" "#A8B2BC"
        return
    }

    $addList = $Script:GroupManagerPendingAdd -join ','
    $removeList = $Script:GroupManagerPendingRemove -join ','

    if ($previewOnly) {
        Write-Log "=== PREVIEW MODE ===" -Level Info
        Write-Log "Target Group: $groupName" -Level Info
        if ($Script:GroupManagerPendingAdd.Count -gt 0) {
            Write-Log "Would ADD $($Script:GroupManagerPendingAdd.Count) users: $addList" -Level Info
        }
        if ($Script:GroupManagerPendingRemove.Count -gt 0) {
            Write-Log "Would REMOVE $($Script:GroupManagerPendingRemove.Count) users: $removeList" -Level Warning
        }
        Write-Log "Uncheck 'Preview only' and click Apply to make changes." -Level Info
        Update-GroupManagerStatus "Preview complete" "#58A6FF"
        return
    }

    # Apply changes using Manage-ADResources.ps1
    try {
        Write-Log "Applying changes to $groupName..." -Level Warning

        $params = @{
            Action = 'UpdateGroupMembership'
            GroupName = $groupName
        }

        if ($Script:GroupManagerPendingAdd.Count -gt 0) {
            $params['AddMembers'] = $Script:GroupManagerPendingAdd
        }
        if ($Script:GroupManagerPendingRemove.Count -gt 0) {
            $params['RemoveMembers'] = $Script:GroupManagerPendingRemove
        }

        Invoke-Script -ScriptName "utilities\Manage-ADResources.ps1" -Parameters $params

        Write-Log "Changes applied successfully!" -Level Success
        Update-GroupManagerStatus "Changes applied!" "#3FB950"

        # Clear pending changes and refresh
        $Script:GroupManagerPendingAdd = @()
        $Script:GroupManagerPendingRemove = @()

        # Refresh the members list
        Start-Sleep -Milliseconds 500
        $controls['ADGroupManagerRefresh'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))

    } catch {
        Write-Log "Failed to apply changes: $_" -Level Error
        Update-GroupManagerStatus "Apply failed" "#FF6B6B"
    }
})
#endregion AD Management Handlers

#region WinRM Handlers
$controls['WinRMDeploy'].Add_Click({
    Write-Log "Deploying WinRM GPO..." -Level Info
    Invoke-Script -ScriptName "utilities\Enable-WinRM-Domain.ps1" -Parameters @{ Action = 'Deploy' }
    Write-Log "Deployment completed." -Level Success
})

$controls['WinRMRemove'].Add_Click({
    Write-Log "Removing WinRM GPO..." -Level Info
    Invoke-Script -ScriptName "utilities\Enable-WinRM-Domain.ps1" -Parameters @{ Action = 'Remove' }
    Write-Log "Removal completed." -Level Success
})
#endregion

#region Software List Handlers
function Update-SoftwareLists {
    $controls['SoftwareListBox'].Items.Clear()
    $controls['SoftwareGenerateList'].Items.Clear()
    $listsPath = Join-Path $Script:AppRoot "SoftwareLists"
    if (Test-Path $listsPath) {
        Get-ChildItem $listsPath -Filter "*.json" | ForEach-Object {
            $null = $controls['SoftwareListBox'].Items.Add($_.BaseName)
            $null = $controls['SoftwareGenerateList'].Items.Add($_.BaseName)
        }
    }
    if ($controls['SoftwareGenerateList'].Items.Count -gt 0) { $controls['SoftwareGenerateList'].SelectedIndex = 0 }
}

$controls['SoftwareRefresh'].Add_Click({ Update-SoftwareLists; Write-Log "Lists refreshed." -Level Info })

$controls['SoftwareNew'].Add_Click({
    $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter list name:", "New Software List", "")
    if ($name) {
        $listsPath = Join-Path $Script:AppRoot "SoftwareLists"
        if (-not (Test-Path $listsPath)) { New-Item $listsPath -ItemType Directory -Force | Out-Null }
        @{ name = $name; items = @() } | ConvertTo-Json | Out-File (Join-Path $listsPath "$name.json") -Encoding UTF8
        Update-SoftwareLists; Write-Log "Created list: $name" -Level Success
    }
})

$controls['SoftwareDelete'].Add_Click({
    $sel = $controls['SoftwareListBox'].SelectedItem
    if ($sel) {
        $result = [System.Windows.MessageBox]::Show("Delete '$sel'?", "Confirm", "YesNo", "Warning")
        if ($result -eq 'Yes') {
            Remove-Item (Join-Path $Script:AppRoot "SoftwareLists\$sel.json") -Force
            Update-SoftwareLists; Write-Log "Deleted: $sel" -Level Success
        }
    }
})

$controls['SoftwareGeneratePolicy'].Add_Click({
    $sel = $controls['SoftwareGenerateList'].SelectedItem
    if (-not $sel) { Write-Log "Select a list." -Level Error; return }
    $listPath = Join-Path $Script:AppRoot "SoftwareLists\$sel.json"
    Write-Log "Generating from $sel..." -Level Info
    Invoke-Script -ScriptName "New-AppLockerPolicyFromGuide.ps1" -Parameters @{ SoftwareListPath = $listPath; OutputPath = ".\Outputs"; Simplified = $true }
    Write-Log "Generation completed." -Level Success
})
#endregion

#region Initialization
# Add Microsoft.VisualBasic for InputBox
Add-Type -AssemblyName Microsoft.VisualBasic

Write-Log "GA-AppLocker Portable GUI v$Script:AppVersion started." -Level Info
Write-Log "App Root: $Script:AppRoot" -Level Info
Write-Log "Scripts Available: $Script:ScriptsAvailable" -Level Info

# Update window title with version
$window.Title = "GA-AppLocker Toolkit v$Script:AppVersion"

# Set paths
$controls['SettingsScriptsPath'].Text = $Script:AppRoot
$controls['ScriptsStatusText'].Text = if ($Script:ScriptsAvailable) { "Scripts found!" } else { "Scripts not found - configure path in Settings" }
$controls['ScanOutputPath'].Text = Join-Path $Script:AppRoot "Scans"
$controls['GenerateOutputPath'].Text = Join-Path $Script:AppRoot "Outputs"
$controls['MergeOutputPath'].Text = Join-Path $Script:AppRoot "Outputs"
$controls['EventsOutputPath'].Text = Join-Path $Script:AppRoot "Events"
$controls['CompareOutputPath'].Text = Join-Path $Script:AppRoot "Outputs"

Update-SoftwareLists

# Populate Clone Target Group dropdown with auto-detected domain
$Script:DetectedDomain = try { $env:USERDNSDOMAIN } catch { $null }
if (-not $Script:DetectedDomain) { $Script:DetectedDomain = try { (Get-WmiObject Win32_ComputerSystem).Domain } catch { $null } }
if (-not $Script:DetectedDomain) { $Script:DetectedDomain = "DOMAIN" }

$cloneGroups = @(
    "BUILTIN\Administrators",
    "BUILTIN\Users",
    "Everyone",
    "NT AUTHORITY\SYSTEM",
    "NT AUTHORITY\LOCAL SERVICE",
    "NT AUTHORITY\NETWORK SERVICE",
    "---",  # Separator marker
    "$Script:DetectedDomain\AppLocker-Admins",
    "$Script:DetectedDomain\AppLocker-StandardUsers",
    "$Script:DetectedDomain\AppLocker-ServiceAccounts",
    "$Script:DetectedDomain\AppLocker-Installers",
    "---",  # Separator marker
    "Custom..."
)

foreach ($group in $cloneGroups) {
    if ($group -eq "---") {
        $null = $controls['CloneTargetGroup'].Items.Add((New-Object System.Windows.Controls.Separator))
    } else {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $group
        $null = $controls['CloneTargetGroup'].Items.Add($item)
    }
}
$controls['CloneTargetGroup'].SelectedIndex = 0

if (-not $Script:ScriptsAvailable) {
    Write-Log "To use all features, configure the scripts location in Settings." -Level Warning
}

# Run auto-detection on startup
Initialize-EnvironmentDetection | Out-Null
Apply-DetectedDefaults

# Keyboard shortcut handlers
$window.Add_KeyDown({
    param($sender, $e)

    # Check for Ctrl modifier
    $ctrlPressed = [System.Windows.Input.Keyboard]::Modifiers -eq [System.Windows.Input.ModifierKeys]::Control

    if ($ctrlPressed) {
        switch ($e.Key) {
            # Navigation matches sidebar order and tooltips
            'D1' { Switch-Page -PageName 'Scan'; $e.Handled = $true }      # Collection
            'D2' { Switch-Page -PageName 'Events'; $e.Handled = $true }    # Collection
            'D3' { Switch-Page -PageName 'Compare'; $e.Handled = $true }   # Analysis
            'D4' { Switch-Page -PageName 'Validate'; $e.Handled = $true }  # Analysis
            'D5' { Switch-Page -PageName 'Generate'; $e.Handled = $true }  # Policy
            'D6' { Switch-Page -PageName 'Merge'; $e.Handled = $true }     # Policy
            'D7' { Switch-Page -PageName 'Software'; $e.Handled = $true }  # Policy
            'D8' { Switch-Page -PageName 'CORA'; $e.Handled = $true }      # Compliance
            'Q' {
                # Quick workflow - show workflow dialog
                $result = Show-WorkflowDialog -WorkflowType "Create Baseline"
                if ($result) { Start-Workflow -Settings $result }
                $e.Handled = $true
            }
            'R' {
                # Refresh - re-run auto-detection
                Write-Log "Refreshing environment detection..." -Level Info
                Initialize-EnvironmentDetection | Out-Null
                Apply-DetectedDefaults
                Write-Log "Refresh complete." -Level Success
                $e.Handled = $true
            }
            'OemComma' {
                # Settings (Ctrl+,)
                Switch-Page -PageName 'Settings'
                $e.Handled = $true
            }
        }
    } else {
        switch ($e.Key) {
            'F1' {
                # Help - show keyboard shortcuts
                $helpText = @"
Keyboard Shortcuts
==================

Navigation (matches sidebar order):
  Ctrl+1    Scan Computers
  Ctrl+2    Collect Events
  Ctrl+3    Compare Inventory
  Ctrl+4    Validate Policy
  Ctrl+5    Generate Policy
  Ctrl+6    Merge Policies
  Ctrl+7    Software Lists
  Ctrl+8    CORA Evidence
  Ctrl+,    Settings

Quick Actions:
  Ctrl+Q    Quick Workflow (Create Baseline)
  Ctrl+R    Refresh Environment Detection
  F1        Show this help

Tips:
  - Use Tab to navigate between fields
  - Press Enter to activate focused buttons
  - Shortcuts match the tooltips on sidebar buttons
"@
                [System.Windows.MessageBox]::Show($helpText, "Keyboard Shortcuts", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $e.Handled = $true
            }
        }
    }
})

Write-Log "Keyboard shortcuts enabled (Press F1 for help)" -Level Info
#endregion

$window.ShowDialog() | Out-Null
