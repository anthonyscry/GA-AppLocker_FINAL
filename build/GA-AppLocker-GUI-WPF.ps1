# GA-AppLocker Dashboard - Modern WPF GUI
# GitHub-style dark theme based on ExampleGUI design
# Self-contained with embedded module functions

# Required assemblies for WPF
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
} catch {
    Write-Host "ERROR: Failed to load WPF assemblies. This application requires .NET Framework 4.5 or later." -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# ============================================================
# EMBEDDED: All Module Functions
# ============================================================

# Module 1: Dashboard Functions
function Get-AppLockerEventStats {
    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    try {
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $logExists) {
            return @{ success = $true; allowed = 0; audit = 0; blocked = 0; total = 0; message = 'AppLocker log not found' }
        }
    } catch {
        return @{ success = $true; allowed = 0; audit = 0; blocked = 0; total = 0; message = 'AppLocker log not available' }
    }
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction Stop
        $allowed = ($events | Where-Object { $_.Id -eq 8002 }).Count
        $audit = ($events | Where-Object { $_.Id -eq 8003 }).Count
        $blocked = ($events | Where-Object { $_.Id -eq 8004 }).Count
        return @{ success = $true; allowed = $allowed; audit = $audit; blocked = $blocked; total = $events.Count }
    } catch {
        return @{ success = $true; allowed = 0; audit = 0; blocked = 0; total = 0; message = 'No events found' }
    }
}

function Get-PolicyHealthScore {
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    } catch {
        return @{ success = $true; score = 0; hasPolicy = $false; hasExe = $false; hasMsi = $false; hasScript = $false; hasDll = $false }
    }
    if ($null -eq $policy) {
        return @{ success = $true; score = 0; hasPolicy = $false; hasExe = $false; hasMsi = $false; hasScript = $false; hasDll = $false }
    }
    $hasExe = $false; $hasMsi = $false; $hasScript = $false; $hasDll = $false
    foreach ($collection in $policy.RuleCollections) {
        switch ($collection.RuleCollectionType) {
            'Exe'     { if ($collection.Count -gt 0) { $hasExe = $true } }
            'Msi'     { if ($collection.Count -gt 0) { $hasMsi = $true } }
            'Script'  { if ($collection.Count -gt 0) { $hasScript = $true } }
            'Dll'     { if ($collection.Count -gt 0) { $hasDll = $true } }
        }
    }
    $score = 0
    if ($hasExe)     { $score += 25 }
    if ($hasMsi)     { $score += 25 }
    if ($hasScript)  { $score += 25 }
    if ($hasDll)     { $score += 25 }
    return @{ success = $true; score = $score; hasPolicy = $true; hasExe = $hasExe; hasMsi = $hasMsi; hasScript = $hasScript; hasDll = $hasDll }
}

function Get-DashboardSummary {
    $events = Get-AppLockerEventStats
    $health = Get-PolicyHealthScore
    return @{ success = $true; timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; events = $events; policyHealth = $health }
}

# Module 2: Scan Functions
function Get-LocalExecutableArtifacts {
    param(
        [string[]]$Paths = @("C:\Program Files", "C:\Program Files (x86)", "$env:LOCALAPPDATA", "$env:PROGRAMDATA"),
        [int]$MaxFiles = 1000
    )
    $artifacts = @()
    $extensions = @(".exe", ".msi", ".bat", ".cmd", ".ps1")
    foreach ($basePath in $Paths) {
        if (-not (Test-Path $basePath)) { continue }
        try {
            $files = Get-ChildItem -Path $basePath -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $extensions -contains $_.Extension } |
                     Select-Object -First $MaxFiles
            foreach ($file in $files) {
                try {
                    $versionInfo = $file.VersionInfo
                    $publisher = if ($versionInfo.CompanyName) { $versionInfo.CompanyName } else { "Unknown" }
                    if ($file.FullName -like "*Windows\*") { continue }
                    $artifacts += @{
                        name = $file.Name; publisher = $publisher; path = $file.FullName
                        hash = "N/A"; version = if ($versionInfo.FileVersion) { $versionInfo.FileVersion } else { "Unknown" }
                        size = $file.Length; modifiedDate = $file.LastWriteTime
                    }
                    if ($artifacts.Count -ge $MaxFiles) { break }
                } catch { continue }
            }
        } catch { }
        if ($artifacts.Count -ge $MaxFiles) { break }
    }
    return @{ success = $true; artifacts = $artifacts; count = $artifacts.Count }
}

# Module 3: Rule Generator Functions
function New-PublisherRule {
    param([string]$PublisherName, [string]$ProductName = "*", [string]$BinaryName = "*", [string]$Version = "*")
    if (-not $PublisherName) { return @{ success = $false; error = "Publisher name is required" } }
    $guid = "{" + (New-Guid).ToString() + "}"
    $xml = "<FilePublisherRule Id=`"$guid`" Name=`"$PublisherName`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FilePublisherCondition PublisherName=`"$PublisherName`" ProductName=`"$ProductName`" BinaryName=`"$BinaryName`"><BinaryVersionRange LowSection=`"$Version`" HighSection=`"*`" /></FilePublisherCondition></Conditions></FilePublisherRule>"
    return @{ success = $true; id = $guid; type = "Publisher"; publisher = $PublisherName; xml = $xml }
}

function New-HashRule {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return @{ success = $false; error = "File not found" } }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    $fileName = (Get-Item $FilePath).Name
    $guid = "{" + (New-Guid).ToString() + "}"
    $xml = "<FileHashRule Id=`"$guid`" Name=`"$fileName`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FileHashCondition SourceFileName=`"$fileName`" SourceFileHash=`"$hash`" Type=`"SHA256`" /></Conditions></FileHashRule>"
    return @{ success = $true; id = $guid; type = "Hash"; hash = $hash; fileName = $fileName; xml = $xml }
}

function New-RulesFromArtifacts {
    param([array]$Artifacts, [string]$RuleType = "Publisher")
    if (-not $Artifacts -or $Artifacts.Count -eq 0) { return @{ success = $false; error = "No artifacts provided" } }
    $rules = @()
    $publishers = @{}
    foreach ($artifact in $Artifacts) {
        if ($RuleType -eq "Publisher" -and $artifact.publisher) {
            if (-not $publishers.ContainsKey($artifact.publisher)) {
                $publishers[$artifact.publisher] = $true
                $rule = New-PublisherRule -PublisherName $artifact.publisher
                if ($rule.success) { $rules += $rule }
            }
        }
    }
    return @{ success = $true; rules = $rules; count = $rules.Count; ruleType = $RuleType }
}

# Module 4: Domain Detection
function Get-ADDomain {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isWorkgroup = $computerSystem -and ($computerSystem.Workgroup -eq "WORKGROUP" -or $null -eq $computerSystem.PartOfDomain)
    if ($isWorkgroup) {
        return @{ success = $true; isWorkgroup = $true; dnsRoot = "WORKGROUP"; netBIOSName = $computerSystem.Name; message = "WORKGROUP - AD/GPO disabled" }
    }
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $domain = Get-ADDomain -ErrorAction Stop
        return @{ success = $true; isWorkgroup = $false; dnsRoot = $domain.DNSRoot; netBIOSName = $domain.NetBIOSName; message = "Domain: $($domain.DNSRoot)" }
    } catch {
        $dnsDomain = $env:USERDNSDOMAIN
        if ([string]::IsNullOrEmpty($dnsDomain)) {
            return @{ success = $true; isWorkgroup = $true; dnsRoot = "WORKGROUP"; netBIOSName = $env:COMPUTERNAME; message = "WORKGROUP - AD/GPO disabled" }
        }
        return @{ success = $true; isWorkgroup = $false; dnsRoot = $dnsDomain; netBIOSName = $env:USERDOMAIN; message = "Domain detected" }
    }
}

# Module 5: Event Monitor
function Get-AppLockerEvents {
    param([int]$MaxEvents = 100)
    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop
        $data = $events | ForEach-Object @{
            eventId = $_.Id; time = $_.TimeCreated; message = $_.Message -replace "`n", " " -replace "`r", ""
        }
        return @{ success = $true; data = $data; count = $data.Count }
    } catch {
        return @{ success = $true; data = @(); count = 0; message = "No events found" }
    }
}

# Module 6: Compliance
function New-EvidenceFolder {
    param([string]$BasePath)
    if (-not $BasePath) { $BasePath = "C:\GA-AppLocker" }
    try {
        $folders = @{}
        $subfolders = @("Policies", "Events", "Inventory", "Reports", "Scans")
        foreach ($sub in $subfolders) {
            $path = Join-Path $BasePath $sub
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            $folders[$sub] = $path
        }
        return @{ success = $true; basePath = $BasePath; folders = $folders }
    } catch {
        return @{ success = $false; error = "Failed to create evidence folder" }
    }
}

# Module 7: WinRM GPO Functions
function New-WinRMGpo {
    param(
        [string]$GpoName = "Enable WinRM",
        [string]$OU = $null
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop

        # Detect current domain if OU not specified
        if (-not $OU) {
            $domain = Get-ADDomain
            $OU = "DC=$($domain.DNSRoot -replace '\.', ',DC=')"
        }

        Write-Log "Creating WinRM GPO: $GpoName"

        # 1. Create and link the GPO
        $gpo = New-GPO -Name $GpoName -ErrorAction Stop
        Write-Log "GPO created: $($gpo.Id)"

        $link = New-GPLink -Name $GpoName -Target $OU -LinkEnabled Yes -ErrorAction Stop
        Write-Log "GPO linked to: $OU"

        # 2. Enable WinRM service via policy (XML-backed registry policy)
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Type DWord -Value 1 -ErrorAction Stop
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0 -ErrorAction Stop
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv4Filter" -Type String -Value "*" -ErrorAction Stop
        Write-Log "WinRM service policies configured"

        # 3. Ensure WinRM service starts automatically
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "Start" -Type DWord -Value 2 -ErrorAction Stop
        Write-Log "WinRM service startup type set to Automatic"

        # 4. Enable Windows Firewall rules for WinRM
        Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\WinRM" -ValueName "Enabled" -Type DWord -Value 1 -ErrorAction Stop
        Write-Log "WinRM firewall rules configured"

        return @{
            success = $true
            gpoName = $GpoName
            gpoId = $gpo.Id
            linkedTo = $OU
            message = "WinRM GPO created and linked successfully"
        }
    }
    catch {
        Write-Log "Failed to create WinRM GPO: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

function Set-WinRMGpoLink {
    param(
        [string]$GpoName = "Enable WinRM",
        [string]$Target,
        [bool]$Enabled = $true
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop

        if ($Enabled) {
            $link = Set-GPLink -Name $GpoName -Target $Target -LinkEnabled Yes -ErrorAction Stop
            Write-Log "GPO link enabled: $GpoName -> $Target"
        } else {
            $link = Set-GPLink -Name $GpoName -Target $Target -LinkEnabled No -ErrorAction Stop
            Write-Log "GPO link disabled: $GpoName -> $Target"
        }

        return @{
            success = $true
            message = "GPO link updated successfully"
        }
    }
    catch {
        Write-Log "Failed to set GPO link: $($_.Exception.Message)" -Level "ERROR"
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

# ============================================================
# WPF XAML - Modern GitHub Dark Theme
# ============================================================

$xamlString = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="GA-AppLocker Dashboard" Height="720" Width="1280" MinHeight="600" MinWidth="1000"
        WindowStartupLocation="CenterScreen" Background="#0D1117">
    <Window.Resources>
        <!-- GitHub Dark Theme Colors -->
        <SolidColorBrush x:Key="BgDark" Color="#0D1117"/>
        <SolidColorBrush x:Key="BgSidebar" Color="#161B22"/>
        <SolidColorBrush x:Key="BgCard" Color="#21262D"/>
        <SolidColorBrush x:Key="Border" Color="#30363D"/>
        <SolidColorBrush x:Key="Blue" Color="#58A6FF"/>
        <SolidColorBrush x:Key="Green" Color="#3FB950"/>
        <SolidColorBrush x:Key="Orange" Color="#D29922"/>
        <SolidColorBrush x:Key="Red" Color="#F85149"/>
        <SolidColorBrush x:Key="Purple" Color="#8957E5"/>
        <SolidColorBrush x:Key="Text1" Color="#E6EDF3"/>
        <SolidColorBrush x:Key="Text2" Color="#8B949E"/>
        <SolidColorBrush x:Key="Text3" Color="#6E7681"/>
        <SolidColorBrush x:Key="Hover" Color="#30363D"/>

        <!-- Button Styles -->
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="#238636"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderThickness="0"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#2ea043"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#30363D"/>
                    <Setter Property="Foreground" Value="#6E7681"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="#21262D"/>
            <Setter Property="Foreground" Value="#E6EDF3"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="#30363D"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="1"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#30363D"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid>
        <!-- Header -->
        <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Height="60" VerticalAlignment="Top">
            <Grid Margin="20,0">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="GA-AppLocker Dashboard" FontSize="18" FontWeight="Bold"
                               Foreground="#E6EDF3" VerticalAlignment="Center"/>
                    <TextBlock Text="v1.0" FontSize="12" Foreground="#6E7681"
                               VerticalAlignment="Center" Margin="10,0,0,0"/>
                </StackPanel>
                <TextBlock x:Name="StatusText" Text="Initializing..." FontSize="12"
                           Foreground="#6E7681" VerticalAlignment="Center" HorizontalAlignment="Right"/>
            </Grid>
        </Border>

        <!-- Environment Status Banner -->
        <Border x:Name="EnvironmentBanner" Background="#21262D" BorderBrush="#30363D"
                BorderThickness="0,0,0,1" Height="40" VerticalAlignment="Top" Margin="0,60,0,0">
            <TextBlock x:Name="EnvironmentText" Text="" FontSize="12"
                       Foreground="#8B949E" VerticalAlignment="Center" Margin="20,0"/>
        </Border>

        <!-- Main Content Area -->
        <Grid Margin="0,104,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="200"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Sidebar Navigation -->
            <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Grid.Column="0">
                <StackPanel Margin="0,10,0,10">
                    <!-- Dashboard Button -->
                    <Button x:Name="NavDashboard" Content="Dashboard" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- AD Discovery Button -->
                    <Button x:Name="NavDiscovery" Content="AD Discovery" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- Artifacts Button -->
                    <Button x:Name="NavArtifacts" Content="Artifacts" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- Rules Button -->
                    <Button x:Name="NavRules" Content="Rule Generator" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- Deployment Button -->
                    <Button x:Name="NavDeployment" Content="Deployment" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- Events Button -->
                    <Button x:Name="NavEvents" Content="Events" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- Compliance Button -->
                    <Button x:Name="NavCompliance" Content="Compliance" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>

                    <!-- WinRM Button -->
                    <Button x:Name="NavWinRM" Content="WinRM Setup" Style="{StaticResource SecondaryButton}"
                            HorizontalAlignment="Stretch" Margin="10,5"/>
                </StackPanel>
            </Border>

            <!-- Content Panel -->
            <Grid Grid.Column="1" Margin="0,10,10,10">
                <!-- Dashboard Panel -->
                <StackPanel x:Name="PanelDashboard" Visibility="Collapsed">
                    <TextBlock Text="Dashboard" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Stats Cards -->
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <!-- Policy Health Card -->
                        <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,10,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Policy Health" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="HealthScore" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,10,0,0"/>
                                <TextBlock x:Name="HealthStatus" Text="Loading..." FontSize="11" Foreground="#6E7681"/>
                            </StackPanel>
                        </Border>

                        <!-- Events Card -->
                        <Border Grid.Column="1" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,10,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Total Events" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="TotalEvents" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#58A6FF" Margin="0,10,0,0"/>
                                <TextBlock x:Name="EventsStatus" Text="Loading..." FontSize="11" Foreground="#6E7681"/>
                            </StackPanel>
                        </Border>

                        <!-- Allowed Card -->
                        <Border Grid.Column="2" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,10,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Allowed" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="AllowedEvents" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#3FB950" Margin="0,10,0,0"/>
                                <TextBlock FontSize="11" Foreground="#6E7681">Event ID 8002</TextBlock>
                            </StackPanel>
                        </Border>

                        <!-- Blocked Card -->
                        <Border Grid.Column="3" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                CornerRadius="8" Margin="0,0,0,10" Padding="20">
                            <StackPanel>
                                <TextBlock Text="Blocked" FontSize="12" Foreground="#8B949E"/>
                                <TextBlock x:Name="BlockedEvents" Text="--" FontSize="32" FontWeight="Bold"
                                           Foreground="#F85149" Margin="0,10,0,0"/>
                                <TextBlock FontSize="11" Foreground="#6E7681">Event ID 8004</TextBlock>
                            </StackPanel>
                        </Border>
                    </Grid>

                    <!-- Refresh Button -->
                    <Button x:Name="RefreshDashboardBtn" Content="Refresh Dashboard"
                            Style="{StaticResource PrimaryButton}" Width="180" HorizontalAlignment="Left"
                            Margin="0,20,0,0"/>

                    <!-- Output Area -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,10,0,0" Padding="15" Height="300">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="DashboardOutput" Text="Loading dashboard..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Artifacts Panel -->
                <StackPanel x:Name="PanelArtifacts" Visibility="Collapsed">
                    <TextBlock Text="Artifact Collection" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="120"/>
                            <ColumnDefinition Width="120"/>
                        </Grid.ColumnDefinitions>

                        <StackPanel Grid.Column="0" Orientation="Horizontal">
                            <TextBlock Text="Max Files:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                            <TextBox x:Name="MaxFilesText" Text="1000" Width="80" Height="32"
                                     Background="#0D1117" Foreground="#E6EDF3" BorderBrush="#30363D"
                                     BorderThickness="1" FontSize="13" Padding="5"/>
                        </StackPanel>

                        <Button x:Name="ExportArtifactsBtn" Content="Export CSV"
                                Style="{StaticResource SecondaryButton}" Grid.Column="1" Margin="0,0,5,0"/>
                        <Button x:Name="ScanLocalBtn" Content="Scan Localhost"
                                Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Artifacts List -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Margin="0,0,0,0" Padding="15" Height="380">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Discovered Artifacts" FontSize="13" FontWeight="Bold"
                                       Foreground="#8B949E" Margin="0,0,0,10"/>

                            <ListBox x:Name="ArtifactsList" Grid.Row="1" Background="#0D1117"
                                     Foreground="#E6EDF3" BorderThickness="0" FontFamily="Consolas" FontSize="11"/>
                        </Grid>
                    </Border>
                </StackPanel>

                <!-- Rules Panel -->
                <StackPanel x:Name="PanelRules" Visibility="Collapsed">
                    <TextBlock Text="Rule Generator" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Grid Margin="0,0,0,15">
                        <TextBlock Text="Rule Type (Best Practice Order):" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center"/>
                        <ComboBox x:Name="RuleTypeCombo" Width="250" Height="32" HorizontalAlignment="Left" Margin="10,5,0,0"
                                  Background="#21262D" Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="13">
                            <ComboBoxItem Content="Publisher (Preferred)" Background="#21262D" Foreground="#E6EDF3"/>
                            <ComboBoxItem Content="Hash (Fallback)" Background="#21262D" Foreground="#E6EDF3"/>
                            <ComboBoxItem Content="Path (Exceptions Only)" Background="#21262D" Foreground="#E6EDF3"/>
                        </ComboBox>
                    </Grid>

                    <Grid Margin="0,10,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="ImportArtifactsBtn" Content="Import Artifacts"
                                Style="{StaticResource SecondaryButton}"/>

                        <Button x:Name="GenerateRulesBtn" Content="Generate Rules"
                                Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <!-- Rules Output -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="320">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="RulesOutput" Text="Import artifacts or generate rules to see results here..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Events Panel -->
                <StackPanel x:Name="PanelEvents" Visibility="Collapsed">
                    <TextBlock Text="Event Monitor" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Event Filters and Export -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="100"/>
                            <ColumnDefinition Width="120"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock Grid.Column="0" Text="Filter by event type:" FontSize="13" Foreground="#8B949E" VerticalAlignment="Center"/>

                        <Button x:Name="FilterAllBtn" Content="All" Style="{StaticResource SecondaryButton}" Grid.Column="1" Margin="5,0"/>
                        <Button x:Name="FilterAllowedBtn" Content="Allowed" Style="{StaticResource SecondaryButton}" Grid.Column="2" Margin="5,0"/>
                        <Button x:Name="FilterBlockedBtn" Content="Blocked" Style="{StaticResource SecondaryButton}" Grid.Column="3" Margin="5,0"/>
                        <Button x:Name="FilterAuditBtn" Content="Audit" Style="{StaticResource SecondaryButton}" Grid.Column="4" Margin="5,0"/>
                        <Button x:Name="RefreshEventsBtn" Content="Refresh" Style="{StaticResource PrimaryButton}" Grid.Column="5" Margin="5,0"/>
                        <Button x:Name="ExportEventsBtn" Content="Export" Style="{StaticResource PrimaryButton}" Grid.Column="6" Margin="5,0,0,0"/>
                    </Grid>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="440">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="EventsOutput" Text="Click refresh to load events..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Deployment Panel -->
                <StackPanel x:Name="PanelDeployment" Visibility="Collapsed">
                    <TextBlock Text="Deployment" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Deployment Buttons (disabled in workgroup mode) -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="CreateGP0Btn" Content="Create GPO" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="LinkGP0Btn" Content="Link GPO to Domain" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Deployment Status" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock x:Name="DeploymentStatus" Text="Ready to deploy policies..."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="370">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock FontFamily="Consolas" FontSize="12" Foreground="#8B949E">
                                <Run Text="Deployment Workflow:" Foreground="#E6EDF3"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="1. Discover AD computers"/>
                                <LineBreak/>
                                <Run Text="2. Collect artifacts"/>
                                <LineBreak/>
                                <Run Text="3. Generate rules (Publisher first)"/>
                                <LineBreak/>
                                <Run Text="4. Create GPO in Audit mode"/>
                                <LineBreak/>
                                <Run Text="5. Monitor for X days"/>
                                <LineBreak/>
                                <Run Text="6. Switch to Enforce mode"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="Best Practices:" Foreground="#E6EDF3"/>
                                <LineBreak/>
                                <Run Text="• Use Publisher rules first"/>
                                <LineBreak/>
                                <Run Text="• Use Hash rules for unsigned files"/>
                                <LineBreak/>
                                <Run Text="• Avoid Path rules when possible"/>
                                <LineBreak/>
                                <Run Text="• Always start in Audit mode"/>
                                <LineBreak/>
                                <Run Text="• Use role-based groups"/>
                            </TextBlock>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- Compliance Panel -->
                <StackPanel x:Name="PanelCompliance" Visibility="Collapsed">
                    <TextBlock Text="Compliance" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Button x:Name="GenerateEvidenceBtn" Content="Generate Evidence Package"
                            Style="{StaticResource PrimaryButton}" Width="220" HorizontalAlignment="Left"
                            Margin="0,0,0,15"/>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="440">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="ComplianceOutput" Text="Click 'Generate Evidence Package' to create compliance artifacts..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- WinRM Panel -->
                <StackPanel x:Name="PanelWinRM" Visibility="Collapsed">
                    <TextBlock Text="WinRM Setup" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="WinRM (Windows Remote Management)" FontSize="14" FontWeight="Bold"
                                       Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="WinRM is required for remote PowerShell and AppLocker scanning."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <!-- WinRM Buttons (disabled when not on DC) -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>

                        <Button x:Name="CreateWinRMGpoBtn" Content="Create WinRM GPO" Style="{StaticResource PrimaryButton}" Grid.Column="0"/>
                        <Button x:Name="FullWorkflowBtn" Content="Full Workflow" Style="{StaticResource PrimaryButton}" Grid.Column="2"/>
                    </Grid>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="380">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock x:Name="WinRMOutput" Text="Click 'Full Workflow' to set up WinRM..."
                                       FontFamily="Consolas" FontSize="12" Foreground="#3FB950"
                                       TextWrapping="Wrap"/>
                        </ScrollViewer>
                    </Border>
                </StackPanel>

                <!-- AD Discovery Panel -->
                <StackPanel x:Name="PanelDiscovery" Visibility="Collapsed">
                    <TextBlock Text="AD Discovery" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock x:Name="DiscoveryStatus" Text="Active Directory Discovery" FontSize="14"
                                       FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Discover computers in Active Directory by OU or search criteria."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Height="420">
                        <ScrollViewer VerticalScrollBarVisibility="Auto">
                            <TextBlock FontFamily="Consolas" FontSize="12" Foreground="#8B949E">
                                <Run Text="AD Discovery Features:" Foreground="#E6EDF3"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="• Search computers by OU path"/>
                                <LineBreak/>
                                <Run Text="• Test connectivity to discovered hosts"/>
                                <LineBreak/>
                                <Run Text="• Select hosts for artifact scanning"/>
                                <LineBreak/>
                                <LineBreak/>
                                <Run Text="Note: In workgroup mode, AD features are disabled."/>
                                <Run Text=" Use 'Scan Localhost' in the Artifacts tab instead." Foreground="#D29922"/>
                            </TextBlock>
                        </ScrollViewer>
                    </Border>
                </StackPanel>
            </Grid>
        </Grid>
    </Grid>
</Window>
"@

# ============================================================
# WPF Window Creation and Event Handlers
# ============================================================

try {
    $window = [Windows.Markup.XamlReader]::Parse($xamlString)
} catch {
    Write-Host "ERROR: Failed to load WPF GUI: $_" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Find controls
$NavDashboard = $window.FindName("NavDashboard")
$NavDiscovery = $window.FindName("NavDiscovery")
$NavArtifacts = $window.FindName("NavArtifacts")
$NavRules = $window.FindName("NavRules")
$NavDeployment = $window.FindName("NavDeployment")
$NavEvents = $window.FindName("NavEvents")
$NavCompliance = $window.FindName("NavCompliance")
$NavWinRM = $window.FindName("NavWinRM")

$StatusText = $window.FindName("StatusText")
$EnvironmentText = $window.FindName("EnvironmentText")
$EnvironmentBanner = $window.FindName("EnvironmentBanner")

$PanelDashboard = $window.FindName("PanelDashboard")
$PanelDiscovery = $window.FindName("PanelDiscovery")
$PanelArtifacts = $window.FindName("PanelArtifacts")
$PanelRules = $window.FindName("PanelRules")
$PanelDeployment = $window.FindName("PanelDeployment")
$PanelEvents = $window.FindName("PanelEvents")
$PanelCompliance = $window.FindName("PanelCompliance")
$PanelWinRM = $window.FindName("PanelWinRM")

# Dashboard controls
$HealthScore = $window.FindName("HealthScore")
$HealthStatus = $window.FindName("HealthStatus")
$TotalEvents = $window.FindName("TotalEvents")
$EventsStatus = $window.FindName("EventsStatus")
$AllowedEvents = $window.FindName("AllowedEvents")
$BlockedEvents = $window.FindName("BlockedEvents")
$RefreshDashboardBtn = $window.FindName("RefreshDashboardBtn")
$DashboardOutput = $window.FindName("DashboardOutput")

# Other controls
$MaxFilesText = $window.FindName("MaxFilesText")
$ScanLocalBtn = $window.FindName("ScanLocalBtn")
$ExportArtifactsBtn = $window.FindName("ExportArtifactsBtn")
$ArtifactsList = $window.FindName("ArtifactsList")
$RuleTypeCombo = $window.FindName("RuleTypeCombo")
$ImportArtifactsBtn = $window.FindName("ImportArtifactsBtn")
$GenerateRulesBtn = $window.FindName("GenerateRulesBtn")
$RulesOutput = $window.FindName("RulesOutput")
$FilterAllBtn = $window.FindName("FilterAllBtn")
$FilterAllowedBtn = $window.FindName("FilterAllowedBtn")
$FilterBlockedBtn = $window.FindName("FilterBlockedBtn")
$FilterAuditBtn = $window.FindName("FilterAuditBtn")
$RefreshEventsBtn = $window.FindName("RefreshEventsBtn")
$ExportEventsBtn = $window.FindName("ExportEventsBtn")
$EventsOutput = $window.FindName("EventsOutput")
$CreateGP0Btn = $window.FindName("CreateGP0Btn")
$LinkGP0Btn = $window.FindName("LinkGP0Btn")
$DeploymentStatus = $window.FindName("DeploymentStatus")
$GenerateEvidenceBtn = $window.FindName("GenerateEvidenceBtn")
$ComplianceOutput = $window.FindName("ComplianceOutput")
$CreateWinRMGpoBtn = $window.FindName("CreateWinRMGpoBtn")
$FullWorkflowBtn = $window.FindName("FullWorkflowBtn")
$WinRMOutput = $window.FindName("WinRMOutput")

# Global variables
$script:CollectedArtifacts = @()
$script:IsWorkgroup = $false
$script:DomainInfo = $null
$script:EventFilter = "All"  # All, Allowed, Blocked, Audit
$script:AllEvents = @()

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $logDir = ".\Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $logDir "GA-AppLocker-$(Get-Date -Format 'yyyy-MM-dd').log"
    $logEntry = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    } catch {
        # Silently fail if logging fails
    }
}

# Helper function to show panel
function Show-Panel {
    param([string]$PanelName)

    $PanelDashboard.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelDiscovery.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelArtifacts.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelRules.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelDeployment.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelEvents.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelCompliance.Visibility = [System.Windows.Visibility]::Collapsed
    $PanelWinRM.Visibility = [System.Windows.Visibility]::Collapsed

    switch ($PanelName) {
        "Dashboard" { $PanelDashboard.Visibility = [System.Windows.Visibility]::Visible }
        "Discovery" { $PanelDiscovery.Visibility = [System.Windows.Visibility]::Visible }
        "Artifacts" { $PanelArtifacts.Visibility = [System.Windows.Visibility]::Visible }
        "Rules" { $PanelRules.Visibility = [System.Windows.Visibility]::Visible }
        "Deployment" { $PanelDeployment.Visibility = [System.Windows.Visibility]::Visible }
        "Events" { $PanelEvents.Visibility = [System.Windows.Visibility]::Visible }
        "Compliance" { $PanelCompliance.Visibility = [System.Windows.Visibility]::Visible }
        "WinRM" { $PanelWinRM.Visibility = [System.Windows.Visibility]::Visible }
    }
}

# Navigation event handlers
$NavDashboard.Add_Click({
    Show-Panel "Dashboard"
    Update-StatusBar
})

$NavDiscovery.Add_Click({
    Show-Panel "Discovery"
    Update-StatusBar
})

$NavArtifacts.Add_Click({
    Show-Panel "Artifacts"
    Update-StatusBar
})

$NavRules.Add_Click({
    Show-Panel "Rules"
    Update-StatusBar
})

$NavDeployment.Add_Click({
    Show-Panel "Deployment"
    Update-StatusBar
})

$NavEvents.Add_Click({
    Show-Panel "Events"
    Update-StatusBar
})

$NavCompliance.Add_Click({
    Show-Panel "Compliance"
    Update-StatusBar
})

$NavWinRM.Add_Click({
    Show-Panel "WinRM"
    Update-StatusBar
})

# Dashboard events
function Refresh-Data {
    $summary = Get-DashboardSummary
    $HealthScore.Text = $summary.policyHealth.score
    $HealthStatus.Text = if ($summary.policyHealth.score -eq 100) { "All categories enabled" } else { "Score: $($summary.policyHealth.score)/100" }
    $TotalEvents.Text = $summary.events.total
    $EventsStatus.Text = if ($summary.events.total -gt 0) { "Events found" } else { "No events" }
    $AllowedEvents.Text = $summary.events.allowed
    $BlockedEvents.Text = $summary.events.blocked
}

$RefreshDashboardBtn.Add_Click({
    Refresh-Data
    $DashboardOutput.Text = "Dashboard refreshed at $(Get-Date -Format 'HH:mm:ss')"
})

# Artifacts events
$ExportArtifactsBtn.Add_Click({
    if ($script:CollectedArtifacts.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No artifacts to export. Run a scan first.", "No Data", "OK", "Information")
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json"
    $saveDialog.Title = "Export Artifacts"
    $saveDialog.FileName = "Artifacts-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker"

    if ($saveDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName)
        if ($ext -eq ".csv") {
            $script:CollectedArtifacts | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        } else {
            $script:CollectedArtifacts | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Exported $($script:CollectedArtifacts.Count) artifacts to $($saveDialog.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:CollectedArtifacts.Count) artifacts to $($saveDialog.FileName)", "Export Complete", "OK", "Information")
    }
})

$ScanLocalBtn.Add_Click({
    Write-Log "Starting localhost scan with max files: $($MaxFilesText.Text)"
    $ArtifactsList.Items.Clear()
    $RulesOutput.Text = "Scanning localhost for executables...`n`nThis may take a few minutes..."
    [System.Windows.Forms.Application]::DoEvents()

    $max = [int]$MaxFilesText.Text
    $result = Get-LocalExecutableArtifacts -MaxFiles $max
    $script:CollectedArtifacts = $result.artifacts

    foreach ($art in $result.artifacts) {
        $ArtifactsList.Items.Add("$($art.name) | $($art.publisher)")
    }

    $RulesOutput.Text = "Scan complete! Found $($result.count) artifacts.`n`nNow go to Rule Generator to create AppLocker rules."
    Write-Log "Localhost scan complete: $($result.count) artifacts found"
})

# Rules events
$ImportArtifactsBtn.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $openDialog.Title = "Import Scan Artifacts"
    if ($openDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($openDialog.FileName)
        if ($ext -eq ".csv") {
            $script:CollectedArtifacts = Import-Csv -Path $openDialog.FileName
        } else {
            $script:CollectedArtifacts = Get-Content -Path $openDialog.FileName | ConvertFrom-Json
        }
        $RulesOutput.Text = "Imported $($script:CollectedArtifacts.Count) artifacts. Select rule type and click Generate Rules."
    }
})

$GenerateRulesBtn.Add_Click({
    if ($script:CollectedArtifacts.Count -eq 0) {
        $RulesOutput.Text = "ERROR: No artifacts imported. Use Import Artifacts first."
        return
    }

    $ruleType = switch ($RuleTypeCombo.SelectedIndex) {
        0 { "Publisher" }
        1 { "Hash" }
        2 { "Path" }
    }

    $result = New-RulesFromArtifacts -Artifacts $script:CollectedArtifacts -RuleType $ruleType

    $output = "Generated $($result.count) $ruleType rules:`n`n"
    foreach ($rule in $result.rules) {
        $output += "[$($rule.type)] $($rule.publisher)`n"
    }
    $RulesOutput.Text = $output
})

# Events events
$FilterAllBtn.Add_Click({
    $script:EventFilter = "All"
    Write-Log "Event filter set to: All"
    $EventsOutput.Text = "Filter set to All. Click Refresh to load events."
})

$FilterAllowedBtn.Add_Click({
    $script:EventFilter = "Allowed"
    Write-Log "Event filter set to: Allowed"
    $EventsOutput.Text = "Filter set to Allowed (ID 8002). Click Refresh to load events."
})

$FilterBlockedBtn.Add_Click({
    $script:EventFilter = "Blocked"
    Write-Log "Event filter set to: Blocked"
    $EventsOutput.Text = "Filter set to Blocked (ID 8004). Click Refresh to load events."
})

$FilterAuditBtn.Add_Click({
    $script:EventFilter = "Audit"
    Write-Log "Event filter set to: Audit"
    $EventsOutput.Text = "Filter set to Audit (ID 8003). Click Refresh to load events."
})

$ExportEventsBtn.Add_Click({
    if ($script:AllEvents.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No events to export. Click Refresh first.", "No Data", "OK", "Information")
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|Text Files (*.txt)|*.txt"
    $saveDialog.Title = "Export Events"
    $saveDialog.FileName = "AppLockerEvents-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $saveDialog.InitialDirectory = "C:\GA-AppLocker\Scans"

    if ($saveDialog.ShowDialog() -eq "OK") {
        $ext = [System.IO.Path]::GetExtension($saveDialog.FileName)
        if ($ext -eq ".csv") {
            $script:AllEvents | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
        } elseif ($ext -eq ".json") {
            $script:AllEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        } else {
            $script:AllEvents | ForEach-Object { "[$($_.time)] [$($_.type)] $($_.message)" } | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
        }
        Write-Log "Exported $($script:AllEvents.Count) events to $($saveDialog.FileName)"
        [System.Windows.MessageBox]::Show("Exported $($script:AllEvents.Count) events to $($saveDialog.FileName)", "Export Complete", "OK", "Information")
    }
})

$RefreshEventsBtn.Add_Click({
    Write-Log "Refreshing events with filter: $($script:EventFilter)"
    $result = Get-AppLockerEvents -MaxEvents 1000
    $script:AllEvents = $result.data

    # Filter events based on selection
    $filteredEvents = switch ($script:EventFilter) {
        "Allowed" { $result.data | Where-Object { $_.eventId -eq 8002 } }
        "Blocked" { $result.data | Where-Object { $_.eventId -eq 8004 } }
        "Audit"   { $result.data | Where-Object { $_.eventId -eq 8003 } }
        default   { $result.data }
    }

    $output = "=== APPLOCKER EVENTS (Filter: $($script:EventFilter)) ===`n`nShowing $($filteredEvents.Count) of $($result.count) total events`n`n"
    foreach ($evt in $filteredEvents) {
        $type = switch ($evt.eventId) {
            8002 { "ALLOWED" }
            8003 { "AUDIT" }
            8004 { "BLOCKED" }
            default { "UNKNOWN" }
        }
        $output += "[$($evt.time)] [$type] $($evt.message)`n`n"
    }
    $EventsOutput.Text = $output
    Write-Log "Events refreshed: $($filteredEvents.Count) events displayed"
})

# Compliance events
$GenerateEvidenceBtn.Add_Click({
    Write-Log "Generating evidence package"
    $result = New-EvidenceFolder
    if ($result.success) {
        $ComplianceOutput.Text = "Evidence package created at:`n$($result.basePath)`n`nSub-folders:`n"
        foreach ($folder in $result.folders.GetEnumerator()) {
            $ComplianceOutput.Text += "  - $($folder.Key): $($folder.Value)`n"
        }
        Write-Log "Evidence package created at: $($result.basePath)"
    } else {
        $ComplianceOutput.Text = "ERROR: $($result.error)"
        Write-Log "Failed to create evidence package: $($result.error)" -Level "ERROR"
    }
})

# Deployment events
$CreateGP0Btn.Add_Click({
    Write-Log "Create GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }
    $DeploymentStatus.Text = "GPO creation requires Domain Admin privileges. In production, this would create a new GPO in the domain."
    Write-Log "GPO creation initiated (domain mode)"
})

$LinkGP0Btn.Add_Click({
    Write-Log "Link GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("GPO linking requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }
    $DeploymentStatus.Text = "GPO linking requires Domain Admin privileges. In production, this would link the GPO to an OU."
    Write-Log "GPO linking initiated (domain mode)"
})

# WinRM events
$CreateWinRMGpoBtn.Add_Click({
    Write-Log "Create WinRM GPO button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO creation requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        return
    }

    $WinRMOutput.Text = "=== WINRM GPO CREATION ===`n`nCreating WinRM GPO...`n`nThis will:`n  • Create 'Enable WinRM' GPO`n  • Link to domain root`n  • Configure WinRM service settings`n  • Enable firewall rules`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $WinRMOutput.Text = "=== WINRM GPO CREATED ===`n`nSUCCESS: GPO created and linked`n`nGPO Name: $($result.gpoName)`n`nGPO ID: $($result.gpoId)`n`nLinked to: $($result.linkedTo)`n`nConfigured Settings:`n  • WinRM service: Auto-config enabled`n  • Unencrypted traffic: Disabled`n  • IPv4 filter: * (all addresses)`n  • Service startup: Automatic`n  • Firewall rules: Enabled`n`n`nThe GPO will be applied during the next Group Policy refresh (typically every 90 minutes).`n`nTo force immediate update: gpupdate /force"
        Write-Log "WinRM GPO created successfully: $($result.gpoName)"
        [System.Windows.MessageBox]::Show("WinRM GPO created successfully!`n`nGPO: $($result.gpoName)`n`nLinked to: $($result.linkedTo)", "Success", "OK", "Information")
    } else {
        $WinRMOutput.Text = "=== WINRM GPO CREATION FAILED ===`n`nERROR: $($result.error)`n`n`nPossible causes:`n  • Not running as Domain Admin`n  • Group Policy module not available`n  • Insufficient permissions`n`n`nPlease run as Domain Administrator and try again."
        Write-Log "Failed to create WinRM GPO: $($result.error)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to create WinRM GPO:`n$($result.error)", "Error", "OK", "Error")
    }
})

# WinRM events
$FullWorkflowBtn.Add_Click({
    Write-Log "Full WinRM workflow button clicked"
    if ($script:IsWorkgroup) {
        [System.Windows.MessageBox]::Show("WinRM GPO deployment requires Domain Controller access. This feature is disabled in workgroup mode.", "Workgroup Mode", "OK", "Information")
        $WinRMOutput.Text = "=== WINRM SETUP (WORKGROUP MODE) ===`n`nWinRM GPO deployment is only available in domain mode.`n`nIn workgroup mode, you can:`n  • Manually enable WinRM on each machine`n  • Use: `Enable-PSRemoting -Force` in PowerShell`n  • Configure firewall rules manually"
        return
    }

    $WinRMOutput.Text = "=== WINRM FULL WORKFLOW ===`n`nStep 1: Creating and linking WinRM GPO...`n`nPlease wait..."
    [System.Windows.Forms.Application]::DoEvents()

    $result = New-WinRMGpo

    if ($result.success) {
        $WinRMOutput.Text = "=== WINRM SETUP COMPLETE ===`n`nSUCCESS: WinRM GPO deployed!`n`nWhat was done:`n`n1. Created GPO: $($result.gpoName)`n`n2. Linked to: $($result.linkedTo)`n`n3. Configured registry policies:`n   • WinRM Auto-Config: Enabled`n   • Unencrypted Traffic: Disabled`n   • IPv4 Filter: * (all)`n`n4. Service startup: Automatic`n`n5. Firewall rules: Enabled (Domain profile)`n`n`n=== NEXT STEPS ===`n`n1. Wait for Group Policy refresh (up to 90 min)`n   Or run: gpupdate /force`n`n2. Test WinRM: Test-WsMan -ComputerName <target>`n`n3. Enter-PSSession to test remote access`n`n`nGPO will apply to all computers in the domain."
        Write-Log "Full WinRM workflow completed successfully"
        [System.Windows.MessageBox]::Show("WinRM GPO deployed successfully!`n`nGPO: $($result.gpoName)`n`nThe GPO will apply during the next Group Policy refresh.", "Success", "OK", "Information")
    } else {
        $WinRMOutput.Text = "=== WINRM SETUP FAILED ===`n`nERROR: $($result.error)`n`n`nPlease ensure you are running as Domain Administrator."
        Write-Log "Full WinRM workflow failed: $($result.error)" -Level "ERROR"
        [System.Windows.MessageBox]::Show("Failed to deploy WinRM GPO:`n$($result.error)", "Error", "OK", "Error")
    }
})

# Other events
function Update-StatusBar {
    if ($script:IsWorkgroup) {
        $StatusText.Text = "WORKGROUP MODE - Local scanning available"
    } else {
        $StatusText.Text = "$($script:DomainInfo.dnsRoot) - Full features available"
    }
}

# Initialize on load
$window.add_Loaded({
    # Detect domain/workgroup
    $script:DomainInfo = Get-ADDomain
    $script:IsWorkgroup = $script:DomainInfo.isWorkgroup

    Write-Log "Application started - Mode: $($script:DomainInfo.message)"

    # Update environment banner
    if ($script:IsWorkgroup) {
        $EnvironmentText.Text = "WORKGROUP MODE - Localhost scanning available | AD/GPO features disabled"
        $EnvironmentBanner.Background = "#21262D" # BgCard

        # Disable AD/GPO related buttons in workgroup mode
        $CreateGP0Btn.IsEnabled = $false
        $LinkGP0Btn.IsEnabled = $false
        $CreateWinRMGpoBtn.IsEnabled = $false
        $FullWorkflowBtn.IsEnabled = $false

        Write-Log "Workgroup mode: Deployment and WinRM buttons disabled"
    } else {
        $EnvironmentText.Text = "DOMAIN: $($script:DomainInfo.dnsRoot) | Full features available"
        $EnvironmentBanner.Background = "#238636" # Green

        # Enable all buttons in domain mode
        $CreateGP0Btn.IsEnabled = $true
        $LinkGP0Btn.IsEnabled = $true
        $CreateWinRMGpoBtn.IsEnabled = $true
        $FullWorkflowBtn.IsEnabled = $true

        Write-Log "Domain mode: All features enabled"
    }

    # Load dashboard
    Show-Panel "Dashboard"
    Refresh-Data
    Update-StatusBar

    # Load initial message
    $DashboardOutput.Text = "=== GA-APPLOCKER DASHBOARD ===`n`nAaronLocker-aligned AppLocker Policy Management`n`nEnvironment: $($script:DomainInfo.message)`n`nReady to begin. Select a tab to start."
})

# Show window
$window.ShowDialog() | Out-Null
