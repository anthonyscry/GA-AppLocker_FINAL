#Requires -Version 5.1

<#
.SYNOPSIS
    Standalone AaronLocker GUI - GUI wrapper for AaronLocker scripts
.DESCRIPTION
    A lightweight WPF GUI that provides easy access to AaronLocker scripts
    with proper parameter input dialogs for each tool.
.NOTES
    Based on AaronLocker by Aaron Margosis
    GUI wrapper by GA-AppLocker project
#>

# Required assemblies for WPF
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
} catch {
    $msg = "ERROR: Failed to load WPF assemblies.`n`nThis application requires .NET Framework 4.5 or later.`n`nError: $($_.Exception.Message)"
    Write-Host $msg -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ============================================================
# Find AaronLocker Root
# ============================================================
$script:AaronLockerRoot = $null
$aaronLockerSearchPaths = @(
    # Relative to script location (for portable deployment)
    (Join-Path $PSScriptRoot "AaronLocker-main\AaronLocker"),
    (Join-Path $PSScriptRoot "..\AaronLocker-main\AaronLocker"),
    # Standard install locations
    "C:\GA-AppLocker\AaronLocker-main\AaronLocker",
    (Join-Path $env:ProgramData "GA-AppLocker\AaronLocker-main\AaronLocker"),
    (Join-Path $env:USERPROFILE "GA-AppLocker\AaronLocker-main\AaronLocker")
)

foreach ($searchPath in $aaronLockerSearchPaths) {
    $configPath = Join-Path $searchPath "Support\Config.ps1"
    if (Test-Path $configPath) {
        $script:AaronLockerRoot = $searchPath
        break
    }
}

if (-not $script:AaronLockerRoot) {
    $script:AaronLockerRoot = "C:\GA-AppLocker\AaronLocker-main\AaronLocker"
}

# ============================================================
# XAML Definition
# ============================================================
$xamlString = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AaronLocker Tools" Height="800" Width="1000"
        WindowStartupLocation="CenterScreen"
        Background="#0D1117">
    <Window.Resources>
        <!-- GitHub Dark Theme Styles -->
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="#238636"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#2EA043"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#238636"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="#C9D1D9"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#30363D"/>
                                <Setter Property="BorderBrush" Value="#8B949E"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="DangerButton" TargetType="Button">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="#F85149"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#490202"/>
                                <Setter Property="BorderBrush" Value="#F85149"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="SmallButton" TargetType="Button">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="#8B949E"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,4"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#30363D"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#C9D1D9"/>
            <Setter Property="Margin" Value="0,4"/>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <StackPanel Grid.Row="0" Margin="0,0,0,20">
            <TextBlock Text="AaronLocker Tools" FontSize="28" FontWeight="Bold" Foreground="#F0883E"/>
            <TextBlock Text="Original AaronLocker scripts by Aaron Margosis - GUI wrapper for easy access"
                       FontSize="12" Foreground="#8B949E" Margin="0,4,0,0"/>
            <TextBlock x:Name="RootPathText" FontSize="11" Foreground="#6E7681" Margin="0,4,0,0"/>
        </StackPanel>

        <!-- Main Content -->
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <StackPanel>
                <!-- STEP 1: Customization Inputs -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                            <TextBlock Text="1" FontSize="14" FontWeight="Bold" Foreground="#0D1117" Background="#8B949E" Padding="6,2" Margin="0,0,8,0"/>
                            <TextBlock Text="Configure Inputs" FontSize="16" FontWeight="Bold" Foreground="#8B949E"/>
                        </StackPanel>
                        <TextBlock Text="Edit these files BEFORE scanning/creating policies:" FontSize="11" Foreground="#6E7681" Margin="0,0,0,12"/>
                        <WrapPanel>
                            <Button x:Name="BtnEditTrustedSigners" Content="Trusted Signers" Style="{StaticResource SmallButton}" Margin="0,0,8,8" ToolTip="Publishers to allow"/>
                            <Button x:Name="BtnEditSafePaths" Content="Safe Paths" Style="{StaticResource SmallButton}" Margin="0,0,8,8" ToolTip="Paths to whitelist"/>
                            <Button x:Name="BtnEditUnsafePaths" Content="Unsafe Paths" Style="{StaticResource SmallButton}" Margin="0,0,8,8" ToolTip="User-writable paths needing rules"/>
                            <Button x:Name="BtnEditDenyList" Content="Deny List" Style="{StaticResource SmallButton}" Margin="0,0,8,8" ToolTip="Executables to block"/>
                            <Button x:Name="BtnEditHashRules" Content="Hash Rules" Style="{StaticResource SmallButton}" Margin="0,0,8,8" ToolTip="Specific file hashes"/>
                            <Button x:Name="BtnEditKnownAdmins" Content="Known Admins" Style="{StaticResource SmallButton}" Margin="0,0,8,8" ToolTip="Admin accounts to exempt"/>
                        </WrapPanel>
                    </StackPanel>
                </Border>

                <!-- STEP 2: Scan -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="2" FontSize="14" FontWeight="Bold" Foreground="#0D1117" Background="#58A6FF" Padding="6,2" Margin="0,0,8,0"/>
                            <TextBlock Text="Scan System" FontSize="16" FontWeight="Bold" Foreground="#58A6FF"/>
                        </StackPanel>
                        <Border Background="#21262D" CornerRadius="6" Padding="12">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <StackPanel Grid.Column="0">
                                    <TextBlock Text="Scan for files that need AppLocker rules" FontSize="11" Foreground="#8B949E" Margin="0,0,0,8"/>
                                    <WrapPanel>
                                        <CheckBox x:Name="ScanUserProfile" Content="User Profile" IsChecked="True" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanAllProfiles" Content="All Profiles" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanProgramData" Content="ProgramData" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanWritableWindir" Content="Writable Windir" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanWritablePF" Content="Writable ProgramFiles" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanNonDefaultRoot" Content="Non-Default Root" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanExcel" Content="Excel" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="ScanGridView" Content="GridView"/>
                                    </WrapPanel>
                                </StackPanel>
                                <Button x:Name="BtnScanDirectories" Content="Scan" Style="{StaticResource PrimaryButton}"
                                        Grid.Column="1" VerticalAlignment="Center" MinWidth="80"/>
                            </Grid>
                        </Border>
                    </StackPanel>
                </Border>

                <!-- STEP 3: Create Policies -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="3" FontSize="14" FontWeight="Bold" Foreground="#0D1117" Background="#3FB950" Padding="6,2" Margin="0,0,8,0"/>
                            <TextBlock Text="Create Policies" FontSize="16" FontWeight="Bold" Foreground="#3FB950"/>
                        </StackPanel>
                        <Border Background="#21262D" CornerRadius="6" Padding="12">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <StackPanel Grid.Column="0">
                                    <TextBlock Text="Generate policies from scan results and customization inputs" FontSize="11" Foreground="#8B949E" Margin="0,0,0,8"/>
                                    <WrapPanel>
                                        <TextBlock Text="Type:" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,6,4"/>
                                        <ComboBox x:Name="PolicyType" Width="100" SelectedIndex="0" Margin="0,0,12,4">
                                            <ComboBoxItem Content="Both"/>
                                            <ComboBoxItem Content="AppLocker"/>
                                            <ComboBoxItem Content="WDAC"/>
                                        </ComboBox>
                                        <CheckBox x:Name="PolicyRescan" Content="Rescan" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="PolicyExcel" Content="Excel" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="PolicyWDACManagedInstallers" Content="WDAC: Managed Installers" IsChecked="True" Margin="0,0,12,4"/>
                                        <CheckBox x:Name="PolicyWDACISG" Content="WDAC: ISG"/>
                                    </WrapPanel>
                                </StackPanel>
                                <Button x:Name="BtnCreatePolicies" Content="Create" Style="{StaticResource PrimaryButton}"
                                        Grid.Column="1" VerticalAlignment="Center" MinWidth="80"/>
                            </Grid>
                        </Border>
                    </StackPanel>
                </Border>

                <!-- STEP 4: Deploy -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                            <TextBlock Text="4" FontSize="14" FontWeight="Bold" Foreground="#0D1117" Background="#F0883E" Padding="6,2" Margin="0,0,8,0"/>
                            <TextBlock Text="Deploy Policies" FontSize="16" FontWeight="Bold" Foreground="#F0883E"/>
                        </StackPanel>
                        <WrapPanel>
                            <Button x:Name="BtnApplyToLocalGPO" Content="Apply to Local GPO" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                            <Button x:Name="BtnSetGPOPolicy" Content="Set Domain GPO" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                        </WrapPanel>
                    </StackPanel>
                </Border>

                <!-- Tools & Utilities -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
                    <StackPanel>
                        <TextBlock Text="Tools &amp; Utilities" FontSize="14" FontWeight="Bold" Foreground="#A371F7" Margin="0,0,0,12"/>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <TextBlock Text="Analysis" FontSize="11" Foreground="#6E7681" Margin="0,0,0,6"/>
                                <WrapPanel>
                                    <Button x:Name="BtnGetEvents" Content="Get Events" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                                    <Button x:Name="BtnComparePolicies" Content="Compare Policies" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                                </WrapPanel>
                                <WrapPanel Margin="0,4,0,0">
                                    <CheckBox x:Name="EventsAll" Content="All" IsChecked="True" Margin="0,0,8,0"/>
                                    <CheckBox x:Name="EventsWarningOnly" Content="Warn" Margin="0,0,8,0"/>
                                    <CheckBox x:Name="EventsErrorOnly" Content="Error" Margin="0,0,8,0"/>
                                    <CheckBox x:Name="EventsAllowedOnly" Content="Allowed" Margin="0,0,8,0"/>
                                    <CheckBox x:Name="EventsExcel" Content="Excel" Margin="0,0,8,0"/>
                                    <CheckBox x:Name="EventsGridView" Content="Grid"/>
                                </WrapPanel>
                            </StackPanel>
                            <StackPanel Grid.Column="1">
                                <TextBlock Text="Export" FontSize="11" Foreground="#6E7681" Margin="0,0,0,6"/>
                                <WrapPanel>
                                    <Button x:Name="BtnExportToExcel" Content="Policy to Excel" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                                    <Button x:Name="BtnGenerateEventWorkbook" Content="Event Workbook" Style="{StaticResource SecondaryButton}" Margin="0,0,8,8"/>
                                </WrapPanel>
                            </StackPanel>
                        </Grid>
                    </StackPanel>
                </Border>

                <!-- Folders & Maintenance -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16" Margin="0,0,0,16">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Grid.Column="0">
                            <TextBlock Text="Folders" FontSize="11" Foreground="#6E7681" Margin="0,0,0,6"/>
                            <WrapPanel>
                                <Button x:Name="BtnOpenOutputs" Content="Outputs" Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                                <Button x:Name="BtnOpenScanResults" Content="ScanResults" Style="{StaticResource SmallButton}" Margin="0,0,8,0"/>
                                <Button x:Name="BtnOpenAaronLocker" Content="AaronLocker" Style="{StaticResource SmallButton}"/>
                            </WrapPanel>
                        </StackPanel>
                        <StackPanel Grid.Column="1">
                            <TextBlock Text="Maintenance" FontSize="11" Foreground="#6E7681" Margin="0,0,0,6"/>
                            <WrapPanel>
                                <Button x:Name="BtnClearLocalPolicy" Content="Clear Policy" Style="{StaticResource DangerButton}" Margin="0,0,8,0"/>
                                <Button x:Name="BtnClearLogs" Content="Clear Logs" Style="{StaticResource DangerButton}"/>
                            </WrapPanel>
                        </StackPanel>
                    </Grid>
                </Border>

                <!-- Output Console -->
                <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="8" Padding="16">
                    <StackPanel>
                        <Grid Margin="0,0,0,8">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <TextBlock Text="Output Console" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3"/>
                            <Button x:Name="BtnClearConsole" Content="Clear" Style="{StaticResource SmallButton}" Grid.Column="1"/>
                        </Grid>
                        <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1" CornerRadius="4" Padding="8">
                            <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="200">
                                <TextBox x:Name="OutputConsole" Text="AaronLocker output will appear here..."
                                         Background="Transparent" Foreground="#8B949E" BorderThickness="0"
                                         IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11"
                                         AcceptsReturn="True" VerticalScrollBarVisibility="Auto"/>
                            </ScrollViewer>
                        </Border>
                    </StackPanel>
                </Border>
            </StackPanel>
        </ScrollViewer>

        <!-- Footer -->
        <Border Grid.Row="2" Margin="0,16,0,0">
            <TextBlock Text="AaronLocker - Application Whitelisting Made Easy | GUI by GA-AppLocker Project"
                       FontSize="11" Foreground="#6E7681" HorizontalAlignment="Center"/>
        </Border>
    </Grid>
</Window>
"@

# ============================================================
# Create Window
# ============================================================
try {
    $window = [Windows.Markup.XamlReader]::Parse($xamlString)
} catch {
    $errorMsg = "Failed to load GUI: $($_.Exception.Message)"
    [System.Windows.MessageBox]::Show($errorMsg, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    exit 1
}

# Find controls
$RootPathText = $window.FindName("RootPathText")
$OutputConsole = $window.FindName("OutputConsole")
$BtnClearConsole = $window.FindName("BtnClearConsole")

# Scan Directories controls
$ScanWritableWindir = $window.FindName("ScanWritableWindir")
$ScanWritablePF = $window.FindName("ScanWritablePF")
$ScanProgramData = $window.FindName("ScanProgramData")
$ScanUserProfile = $window.FindName("ScanUserProfile")
$ScanAllProfiles = $window.FindName("ScanAllProfiles")
$ScanNonDefaultRoot = $window.FindName("ScanNonDefaultRoot")
$ScanExcel = $window.FindName("ScanExcel")
$ScanGridView = $window.FindName("ScanGridView")
$BtnScanDirectories = $window.FindName("BtnScanDirectories")

# Get Events controls
$EventsWarningOnly = $window.FindName("EventsWarningOnly")
$EventsErrorOnly = $window.FindName("EventsErrorOnly")
$EventsAllowedOnly = $window.FindName("EventsAllowedOnly")
$EventsAll = $window.FindName("EventsAll")
$EventsExcel = $window.FindName("EventsExcel")
$EventsGridView = $window.FindName("EventsGridView")
$BtnGetEvents = $window.FindName("BtnGetEvents")

# Compare Policies
$BtnComparePolicies = $window.FindName("BtnComparePolicies")

# Create Policies controls
$PolicyType = $window.FindName("PolicyType")
$PolicyRescan = $window.FindName("PolicyRescan")
$PolicyExcel = $window.FindName("PolicyExcel")
$PolicyWDACManagedInstallers = $window.FindName("PolicyWDACManagedInstallers")
$PolicyWDACISG = $window.FindName("PolicyWDACISG")
$BtnCreatePolicies = $window.FindName("BtnCreatePolicies")

# Export buttons
$BtnExportToExcel = $window.FindName("BtnExportToExcel")
$BtnGenerateEventWorkbook = $window.FindName("BtnGenerateEventWorkbook")

# Local Config buttons
$BtnApplyToLocalGPO = $window.FindName("BtnApplyToLocalGPO")
$BtnSetGPOPolicy = $window.FindName("BtnSetGPOPolicy")
$BtnClearLocalPolicy = $window.FindName("BtnClearLocalPolicy")
$BtnClearLogs = $window.FindName("BtnClearLogs")

# Customization buttons
$BtnEditTrustedSigners = $window.FindName("BtnEditTrustedSigners")
$BtnEditSafePaths = $window.FindName("BtnEditSafePaths")
$BtnEditUnsafePaths = $window.FindName("BtnEditUnsafePaths")
$BtnEditDenyList = $window.FindName("BtnEditDenyList")
$BtnEditHashRules = $window.FindName("BtnEditHashRules")
$BtnEditKnownAdmins = $window.FindName("BtnEditKnownAdmins")
$BtnOpenOutputs = $window.FindName("BtnOpenOutputs")
$BtnOpenScanResults = $window.FindName("BtnOpenScanResults")
$BtnOpenAaronLocker = $window.FindName("BtnOpenAaronLocker")

# ============================================================
# Helper Functions
# ============================================================
function Write-Console {
    param([string]$Text, [switch]$Append)
    if ($Append) {
        $OutputConsole.Text += "`n$Text"
    } else {
        $OutputConsole.Text = $Text
    }
    $OutputConsole.ScrollToEnd()
}

function Test-AaronLockerExists {
    if (-not (Test-Path $script:AaronLockerRoot)) {
        Write-Console "ERROR: AaronLocker not found at:`n$script:AaronLockerRoot`n`nPlease ensure AaronLocker is installed."
        return $false
    }
    return $true
}

# Launch script in its own visible console window
# Uses Windows PowerShell 5.1 explicitly (required for AaronLocker compatibility)
function Invoke-AaronLockerScript {
    param(
        [string]$ScriptName,
        [string]$ScriptPath,
        [string]$Parameters = ""
    )

    if (-not (Test-AaronLockerExists)) { return }

    if (-not (Test-Path $ScriptPath)) {
        Write-Console "ERROR: Script not found:`n$ScriptPath"
        return
    }

    Write-Console "Launching: $ScriptName`n`nScript: $ScriptPath`nParameters: $Parameters`n`nA new Windows PowerShell window will open..."

    # Use Windows PowerShell 5.1 explicitly (AaronLocker requires it for -Encoding Byte support)
    $windowsPowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

    # Build the command to run in the new window
    $cmd = "Set-Location '$($script:AaronLockerRoot)'; Write-Host '=== $ScriptName ===' -ForegroundColor Cyan; Write-Host ''; . '$ScriptPath' $Parameters; Write-Host ''; Write-Host '=== COMPLETE ===' -ForegroundColor Green; Write-Host 'Press any key to close...'; `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')"

    # Launch in a new visible console window using Windows PowerShell 5.1
    Start-Process $windowsPowerShell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", $cmd
}

# ============================================================
# Event Handlers
# ============================================================

# Set root path display
$RootPathText.Text = "AaronLocker Path: $script:AaronLockerRoot"

# Clear Console
$BtnClearConsole.Add_Click({
    $OutputConsole.Text = "AaronLocker output will appear here..."
})

# === SCANNING ===

# Scan Directories
$BtnScanDirectories.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Scan-Directories.ps1"
    $params = @()

    if ($ScanWritableWindir.IsChecked) { $params += "-WritableWindir" }
    if ($ScanWritablePF.IsChecked) { $params += "-WritablePF" }
    if ($ScanProgramData.IsChecked) { $params += "-SearchProgramData" }
    if ($ScanUserProfile.IsChecked) { $params += "-SearchOneUserProfile" }
    if ($ScanAllProfiles.IsChecked) { $params += "-SearchAllUserProfiles" }
    if ($ScanNonDefaultRoot.IsChecked) { $params += "-SearchNonDefaultRootDirs" }
    if ($ScanExcel.IsChecked) { $params += "-Excel" }
    if ($ScanGridView.IsChecked) { $params += "-GridView" }

    # Need at least one scan option
    if ($params.Count -eq 0 -or ($params.Count -eq 1 -and ($params[0] -eq "-Excel" -or $params[0] -eq "-GridView"))) {
        Write-Console "Please select at least one directory to scan."
        return
    }

    Invoke-AaronLockerScript -ScriptName "Scan Directories" -ScriptPath $scriptPath -Parameters ($params -join " ")
})

# Get AppLocker Events
$BtnGetEvents.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Get-AppLockerEvents.ps1"
    $params = @()

    if ($EventsWarningOnly.IsChecked) { $params += "-WarningOnly" }
    elseif ($EventsErrorOnly.IsChecked) { $params += "-ErrorOnly" }
    elseif ($EventsAllowedOnly.IsChecked) { $params += "-AllowedOnly" }
    elseif ($EventsAll.IsChecked) { $params += "-AllEvents" }

    if ($EventsExcel.IsChecked) { $params += "-Excel" }
    if ($EventsGridView.IsChecked) { $params += "-GridView" }

    Invoke-AaronLockerScript -ScriptName "Get AppLocker Events" -ScriptPath $scriptPath -Parameters ($params -join " ")
})

# Compare Policies
$BtnComparePolicies.Add_Click({
    Write-Console "Select two policy files to compare..."

    $openDialog1 = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog1.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog1.Title = "Select FIRST AppLocker Policy File"
    $openDialog1.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog1.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $policy1 = $openDialog1.FileName

        $openDialog2 = New-Object System.Windows.Forms.OpenFileDialog
        $openDialog2.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
        $openDialog2.Title = "Select SECOND AppLocker Policy File"
        $openDialog2.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

        if ($openDialog2.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $policy2 = $openDialog2.FileName
            $scriptPath = Join-Path $script:AaronLockerRoot "Compare-Policies.ps1"

            Invoke-AaronLockerScript -ScriptName "Compare Policies" -ScriptPath $scriptPath -Parameters "-Policy1Path `"$policy1`" -Policy2Path `"$policy2`""
        }
    }
})

# === POLICY CREATION ===

$BtnCreatePolicies.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Create-Policies.ps1"
    $params = @()

    # Policy type
    $selectedType = $PolicyType.SelectedItem.Content
    if ($selectedType -ne "Both") {
        $params += "-AppLockerOrWDAC $selectedType"
    }

    if ($PolicyRescan.IsChecked) { $params += "-Rescan" }
    if ($PolicyExcel.IsChecked) { $params += "-Excel" }
    if ($PolicyWDACManagedInstallers.IsChecked) { $params += "-WDACTrustManagedInstallers" }
    if ($PolicyWDACISG.IsChecked) { $params += "-WDACTrustISG" }

    Invoke-AaronLockerScript -ScriptName "Create Policies" -ScriptPath $scriptPath -Parameters ($params -join " ")
})

# === EXPORT ===

$BtnExportToExcel.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml"
    $openDialog.Title = "Select AppLocker Policy XML to Export"
    $openDialog.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $scriptPath = Join-Path $script:AaronLockerRoot "ExportPolicy-ToExcel.ps1"
        Invoke-AaronLockerScript -ScriptName "Export to Excel" -ScriptPath $scriptPath -Parameters "-AppLockerXML `"$($openDialog.FileName)`""
    }
})

$BtnGenerateEventWorkbook.Add_Click({
    $scriptPath = Join-Path $script:AaronLockerRoot "Generate-EventWorkbook.ps1"
    Invoke-AaronLockerScript -ScriptName "Generate Event Workbook" -ScriptPath $scriptPath
})

# === LOCAL CONFIGURATION ===

$BtnApplyToLocalGPO.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml"
    $openDialog.Title = "Select AppLocker Policy to Apply to Local GPO"
    $openDialog.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $result = [System.Windows.MessageBox]::Show(
            "Apply this policy to LOCAL GPO?`n`nPolicy: $($openDialog.FileName)`n`nThis will modify the local Group Policy.",
            "Confirm Apply to Local GPO",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )

        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ApplyPolicyToLocalGPO.ps1"
            Invoke-AaronLockerScript -ScriptName "Apply to Local GPO" -ScriptPath $scriptPath -Parameters "-PolicyPath `"$($openDialog.FileName)`""
        }
    }
})

$BtnSetGPOPolicy.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml"
    $openDialog.Title = "Select AppLocker Policy to Set on Domain GPO"
    $openDialog.InitialDirectory = Join-Path $script:AaronLockerRoot "Outputs"

    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $gpoName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the GPO name:", "Set GPO AppLocker Policy", "AppLocker Policy")
        if ($gpoName) {
            $scriptPath = Join-Path $script:AaronLockerRoot "GPOConfiguration\Set-GPOAppLockerPolicy.ps1"
            Invoke-AaronLockerScript -ScriptName "Set GPO Policy" -ScriptPath $scriptPath -Parameters "-GpoName `"$gpoName`" -AppLockerXml `"$($openDialog.FileName)`""
        }
    }
})

$BtnClearLocalPolicy.Add_Click({
    $result = [System.Windows.MessageBox]::Show(
        "Are you sure you want to CLEAR the local AppLocker policy?`n`nThis action cannot be undone!",
        "Confirm Clear Local Policy",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ClearLocalAppLockerPolicy.ps1"
        Invoke-AaronLockerScript -ScriptName "Clear Local Policy" -ScriptPath $scriptPath
    }
})

$BtnClearLogs.Add_Click({
    $result = [System.Windows.MessageBox]::Show(
        "Are you sure you want to CLEAR all AppLocker event logs?`n`nThis action cannot be undone!",
        "Confirm Clear Logs",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        $scriptPath = Join-Path $script:AaronLockerRoot "LocalConfiguration\ClearApplockerLogs.ps1"
        Invoke-AaronLockerScript -ScriptName "Clear AppLocker Logs" -ScriptPath $scriptPath
    }
})

# === CUSTOMIZATION INPUTS ===

$BtnEditTrustedSigners.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\TrustedSigners.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        Write-Console "Opened TrustedSigners.ps1`n`nDefines publishers whose software should be allowed."
    } else {
        Write-Console "File not found: $filePath"
    }
})

$BtnEditSafePaths.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\GetSafePathsToAllow.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        Write-Console "Opened GetSafePathsToAllow.ps1`n`nDefines additional paths to whitelist."
    } else {
        Write-Console "File not found: $filePath"
    }
})

$BtnEditUnsafePaths.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\UnsafePathsToBuildRulesFor.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        Write-Console "Opened UnsafePathsToBuildRulesFor.ps1`n`nDefines user-writable paths needing specific rules."
    } else {
        Write-Console "File not found: $filePath"
    }
})

$BtnEditDenyList.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\GetExeFilesToDenyList.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        Write-Console "Opened GetExeFilesToDenyList.ps1`n`nDefines executables to explicitly block."
    } else {
        Write-Console "File not found: $filePath"
    }
})

$BtnEditHashRules.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\HashRuleData.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        Write-Console "Opened HashRuleData.ps1`n`nDefines specific file hashes to allow/deny."
    } else {
        Write-Console "File not found: $filePath"
    }
})

$BtnEditKnownAdmins.Add_Click({
    $filePath = Join-Path $script:AaronLockerRoot "CustomizationInputs\KnownAdmins.ps1"
    if (Test-Path $filePath) {
        Start-Process notepad.exe -ArgumentList $filePath
        Write-Console "Opened KnownAdmins.ps1`n`nDefines admin accounts to exempt from certain rules."
    } else {
        Write-Console "File not found: $filePath"
    }
})

$BtnOpenOutputs.Add_Click({
    $folderPath = Join-Path $script:AaronLockerRoot "Outputs"
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }
    Start-Process explorer.exe -ArgumentList $folderPath
    Write-Console "Opened Outputs folder`n`nPath: $folderPath"
})

$BtnOpenScanResults.Add_Click({
    $folderPath = Join-Path $script:AaronLockerRoot "ScanResults"
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }
    Start-Process explorer.exe -ArgumentList $folderPath
    Write-Console "Opened ScanResults folder`n`nPath: $folderPath"
})

$BtnOpenAaronLocker.Add_Click({
    if (Test-Path $script:AaronLockerRoot) {
        Start-Process explorer.exe -ArgumentList $script:AaronLockerRoot
        Write-Console "Opened AaronLocker folder`n`nPath: $script:AaronLockerRoot"
    } else {
        Write-Console "AaronLocker folder not found: $script:AaronLockerRoot"
    }
})

# ============================================================
# Show Window
# ============================================================
$window.ShowDialog() | Out-Null
