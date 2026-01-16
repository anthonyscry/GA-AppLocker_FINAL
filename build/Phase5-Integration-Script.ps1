# ============================================================
# Phase 5 Integration Script
# GA-AppLocker WPF GUI - Policy Simulator Integration
# ============================================================
# This script integrates the Policy Simulator panel and functions
# into the main GA-AppLocker-GUI-WPF.ps1 file
# ============================================================

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Phase 5: Policy Simulator Integration" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$mainFile = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1"
$backupFile = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1.backup"
$functionsFile = "C:\projects\GA-AppLocker_FINAL\build\Phase5-PolicySimulator-Functions.ps1"
$eventHandlersFile = "C:\projects\GA-AppLocker_FINAL\build\Phase5-PolicySimulator-EventHandlers.ps1"

# Step 1: Backup original file
Write-Host "[1/6] Creating backup..." -ForegroundColor Yellow
if (Test-Path $backupFile) {
    Write-Host "  Backup already exists: $backupFile" -ForegroundColor Green
} else {
    Copy-Item -Path $mainFile -Destination $backupFile -Force
    Write-Host "  Backup created: $backupFile" -ForegroundColor Green
}
Write-Host ""

# Step 2: Insert Policy Simulator Panel XAML
Write-Host "[2/6] Inserting Policy Simulator Panel XAML..." -ForegroundColor Yellow

# Read the main file
$content = Get-Content $mainFile -Raw -Encoding UTF8

# Define the panel XAML to insert (before the closing Grid tags after PanelHelp)
$panelXAML = @'

                <!-- Policy Simulator Panel -->
                <StackPanel x:Name="PanelPolicySimulator" Visibility="Collapsed">
                    <TextBlock Text="Policy Simulator" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Simulation Configuration -->
                    <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <!-- Test Mode Selection -->
                            <StackPanel Grid.Column="0" Grid.Row="0" Margin="0,0,12,0">
                                <TextBlock Text="Test Mode" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <ComboBox x:Name="SimTestMode" SelectedIndex="0" Height="32">
                                    <ComboBoxItem Content="Dry Run - Show what would happen"/>
                                    <ComboBoxItem Content="Audit Mode - Simulate audit-only enforcement"/>
                                    <ComboBoxItem Content="Test Environment - Deploy to test GPO"/>
                                </ComboBox>
                                <TextBlock TextWrapping="Wrap" FontSize="11" Foreground="#6E7681" Margin="0,6,0,0">
                                    <Run Text="Dry Run: No changes made. Analyzes policy impact only."/>
                                </TextBlock>
                            </StackPanel>

                            <!-- Policy Selection -->
                            <StackPanel Grid.Column="1" Grid.Row="0">
                                <TextBlock Text="Policy to Test" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <ComboBox x:Name="SimPolicySelector" Height="32"/>
                                <Button x:Name="SimLoadPolicyBtn" Content="Load Policy XML" Style="{StaticResource SecondaryButton}"
                                        HorizontalAlignment="Left" Margin="0,6,0,0" Padding="12,4"/>
                            </StackPanel>

                            <!-- Target Selection -->
                            <StackPanel Grid.Column="0" Grid.Row="1" Margin="0,12,12,0">
                                <TextBlock Text="Test Target" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <ComboBox x:Name="SimTargetType" SelectedIndex="0" Height="32">
                                    <ComboBoxItem Content="Local System"/>
                                    <ComboBoxItem Content="Specific Files/Folders"/>
                                    <ComboBoxItem Content="Remote Computer"/>
                                    <ComboBoxItem Content="Test OU (Active Directory)"/>
                                </ComboBox>
                                <TextBox x:Name="SimTargetPath" Text="C:\Program Files" Margin="0,6,0,0" Height="32"
                                         FontSize="12" Padding="8,6" Background="#161B22" Foreground="#E6EDF3"
                                         BorderBrush="#30363D" BorderThickness="1"/>
                            </StackPanel>

                            <!-- Simulation Options -->
                            <StackPanel Grid.Column="1" Grid.Row="1" Margin="0,12,0,0">
                                <TextBlock Text="Simulation Options" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <CheckBox x:Name="SimIncludeUnsigned" Content="Include unsigned files" IsChecked="true"
                                          Foreground="#E6EDF3" Margin="0,4,0,0"/>
                                <CheckBox x:Name="SimCheckBypasses" Content="Check for bypass locations" IsChecked="true"
                                          Foreground="#E6EDF3" Margin="0,8,0,0"/>
                                <CheckBox x:Name="SimAnalyzeImpact" Content="Analyze user/system impact" IsChecked="true"
                                          Foreground="#E6EDF3" Margin="0,8,0,0"/>
                            </StackPanel>

                            <!-- Run Simulation Button -->
                            <StackPanel Grid.Column="0" Grid.ColumnSpan="2" Grid.Row="2" Margin="0,12,0,0">
                                <Button x:Name="SimRunBtn" Content="Run Policy Simulation" Style="{StaticResource PrimaryButton}"
                                        HorizontalAlignment="Left" Padding="16,8" FontSize="14"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <!-- Progress Indicator -->
                    <Border x:Name="SimProgressPanel" Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12" Visibility="Collapsed">
                        <StackPanel>
                            <TextBlock Text="Simulation Progress" FontSize="13" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                            <ProgressBar x:Name="SimProgressBar" Height="8" Minimum="0" Maximum="100" Value="0"
                                         Background="#161B22" Foreground="#58A6FF"/>
                            <TextBlock x:Name="SimProgressText" Text="Initializing..." FontSize="11" Foreground="#8B949E" Margin="0,6,0,0"/>
                        </StackPanel>
                    </Border>

                    <!-- Results Tabs -->
                    <Border Background="#21262D" CornerRadius="8" Padding="0" Margin="0,0,0,12">
                        <Grid>
                            <!-- Tab Headers -->
                            <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="0,0,0,1" Padding="12,8">
                                <StackPanel Orientation="Horizontal">
                                    <Button x:Name="SimTabSummary" Content="Summary" Style="{StaticResource SecondaryButton}"
                                            Margin="0,0,4,0" Padding="16,6"/>
                                    <Button x:Name="SimTabDetailed" Content="Detailed Results" Style="{StaticResource SecondaryButton}"
                                            Margin="0,0,4,0" Padding="16,6"/>
                                    <Button x:Name="SimTabWarnings" Content="Warnings" Style="{StaticResource SecondaryButton}"
                                            Margin="0,0,4,0" Padding="16,6"/>
                                    <Button x:Name="SimTabRecommendations" Content="Recommendations" Style="{StaticResource SecondaryButton}"
                                            Padding="16,6"/>
                                </StackPanel>
                            </Border>

                            <!-- Tab Content -->
                            <StackPanel Margin="20,50,20,20">
                                <!-- Summary Tab -->
                                <StackPanel x:Name="SimSummaryPanel" Visibility="Visible">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>

                                        <Border Grid.Column="0" Background="#161B22" BorderBrush="#30363D" BorderThickness="1"
                                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                                            <StackPanel>
                                                <TextBlock Text="Files Analyzed" FontSize="11" Foreground="#8B949E"/>
                                                <TextBlock x:Name="SimFilesAnalyzed" Text="--" FontSize="20" FontWeight="Bold"
                                                           Foreground="#58A6FF" Margin="0,4,0,0"/>
                                            </StackPanel>
                                        </Border>

                                        <Border Grid.Column="1" Background="#161B22" BorderBrush="#30363D" BorderThickness="1"
                                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                                            <StackPanel>
                                                <TextBlock Text="Would Allow" FontSize="11" Foreground="#8B949E"/>
                                                <TextBlock x:Name="SimWouldAllow" Text="--" FontSize="20" FontWeight="Bold"
                                                           Foreground="#3FB950" Margin="0,4,0,0"/>
                                            </StackPanel>
                                        </Border>

                                        <Border Grid.Column="2" Background="#161B22" BorderBrush="#30363D" BorderThickness="1"
                                                CornerRadius="6" Margin="0,0,8,10" Padding="12">
                                            <StackPanel>
                                                <TextBlock Text="Would Block" FontSize="11" Foreground="#8B949E"/>
                                                <TextBlock x:Name="SimWouldBlock" Text="--" FontSize="20" FontWeight="Bold"
                                                           Foreground="#F85149" Margin="0,4,0,0"/>
                                            </StackPanel>
                                        </Border>

                                        <Border Grid.Column="3" Background="#161B22" BorderBrush="#30363D" BorderThickness="1"
                                                CornerRadius="6" Margin="0,0,0,10" Padding="12">
                                            <StackPanel>
                                                <TextBlock Text="Coverage" FontSize="11" Foreground="#8B949E"/>
                                                <TextBlock x:Name="SimCoverage" Text="--" FontSize="20" FontWeight="Bold"
                                                           Foreground="#D29922" Margin="0,4,0,0"/>
                                            </StackPanel>
                                        </Border>
                                    </Grid>

                                    <Border Background="#161B22" BorderBrush="#30363D" BorderThickness="1" CornerRadius="6" Padding="16" Margin="0,0,0,12">
                                        <TextBlock x:Name="SimOverallStatus" TextWrapping="Wrap" FontSize="13" Foreground="#E6EDF3">
                                            <Run Text="Run a simulation to see policy impact analysis."/>
                                        </TextBlock>
                                    </Border>

                                    <Button x:Name="SimExportBtn" Content="Export Full Report" Style="{StaticResource SecondaryButton}"
                                            HorizontalAlignment="Left" Padding="12,6"/>
                                </StackPanel>

                                <!-- Detailed Results Tab -->
                                <StackPanel x:Name="SimDetailedPanel" Visibility="Collapsed">
                                    <TextBlock Text="File-Level Results" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                    <DataGrid x:Name="SimResultsGrid" Height="400" AutoGenerateColumns="False"
                                              Background="#161B22" Foreground="#E6EDF3" GridLinesVisibility="Horizontal"
                                              HeadersVisibility="Column" BorderBrush="#30363D" BorderThickness="1"
                                              RowBackground="#161B22" AlternatingRowBackground="#21262D">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="File Name" Binding="{Binding FileName}" Width="*"/>
                                            <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="2*"/>
                                            <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="*"/>
                                            <DataGridTextColumn Header="Result" Binding="{Binding Result}" Width="100"/>
                                            <DataGridTextColumn Header="Matched Rule" Binding="{Binding MatchedRule}" Width="*"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </StackPanel>

                                <!-- Warnings Tab -->
                                <StackPanel x:Name="SimWarningsPanel" Visibility="Collapsed">
                                    <TextBlock Text="Policy Warnings and Issues" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                    <DataGrid x:Name="SimWarningsGrid" Height="400" AutoGenerateColumns="False"
                                              Background="#161B22" Foreground="#E6EDF3" GridLinesVisibility="Horizontal"
                                              HeadersVisibility="Column" BorderBrush="#30363D" BorderThickness="1"
                                              RowBackground="#161B22" AlternatingRowBackground="#21262D">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="100"/>
                                            <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="150"/>
                                            <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                                            <DataGridTextColumn Header="Recommendation" Binding="{Binding Recommendation}" Width="*"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </StackPanel>

                                <!-- Recommendations Tab -->
                                <StackPanel x:Name="SimRecommendationsPanel" Visibility="Collapsed">
                                    <TextBlock Text="Policy Improvement Recommendations" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                                    <DataGrid x:Name="SimRecommendationsGrid" Height="400" AutoGenerateColumns="False"
                                              Background="#161B22" Foreground="#E6EDF3" GridLinesVisibility="Horizontal"
                                              HeadersVisibility="Column" BorderBrush="#30363D" BorderThickness="1"
                                              RowBackground="#161B22" AlternatingRowBackground="#21262D">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Priority" Binding="{Binding Priority}" Width="100"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="150"/>
                                            <DataGridTextColumn Header="Recommendation" Binding="{Binding Recommendation}" Width="*"/>
                                            <DataGridTextColumn Header="Benefit" Binding="{Binding Benefit}" Width="*"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </StackPanel>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <!-- Impact Analysis -->
                    <Border Background="#21262D" CornerRadius="8" Padding="20" Margin="0,0,0,12">
                        <StackPanel>
                            <TextBlock Text="Impact Analysis by User Group" FontSize="14" FontWeight="SemiBold" Foreground="#E6EDF3" Margin="0,0,0,12"/>
                            <DataGrid x:Name="SimImpactGrid" Height="200" AutoGenerateColumns="False"
                                      Background="#161B22" Foreground="#E6EDF3" GridLinesVisibility="Horizontal"
                                      HeadersVisibility="Column" BorderBrush="#30363D" BorderThickness="1"
                                      RowBackground="#161B22" AlternatingRowBackground="#21262D">
                                <DataGrid.Columns>
                                    <DataGridTextColumn Header="User Group" Binding="{Binding UserGroup}" Width="*"/>
                                    <DataGridTextColumn Header="Files Affected" Binding="{Binding FilesAffected}" Width="100"/>
                                    <DataGridTextColumn Header="Would Block" Binding="{Binding WouldBlock}" Width="100"/>
                                    <DataGridTextColumn Header="Impact Level" Binding="{Binding ImpactLevel}" Width="120"/>
                                </DataGrid.Columns>
                            </DataGrid>
                        </StackPanel>
                    </Border>
                </StackPanel>
'@

# Insert the panel before the closing Grid tag after PanelHelp
$insertPattern = '(</ScrollViewer>\s+</Grid>\s+</ScrollViewer>\s+</Grid>\s+</Grid>\s+</Window>\s+"@)'

# Check if PanelPolicySimulator already exists
if ($content -match 'PanelPolicySimulator') {
    Write-Host "  Policy Simulator panel already exists in file. Skipping XAML insertion." -ForegroundColor Yellow
} else {
    # Find the location to insert (before the closing tags after PanelHelp)
    $insertLocation = $content.LastIndexOf('                </ScrollViewer>')
    if ($insertLocation -gt 0) {
        $beforeInsert = $content.Substring(0, $insertLocation + 31)
        $afterInsert = $content.Substring($insertLocation + 31)

        $newContent = $beforeInsert + $panelXAML + $afterInsert

        Set-Content -Path $mainFile -Value $newContent -Encoding UTF8 -NoNewline
        Write-Host "  Policy Simulator panel XAML inserted successfully" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Could not find insertion point for panel XAML" -ForegroundColor Red
    }
}
Write-Host ""

# Step 3: Insert control references
Write-Host "[3/6] Adding control references..." -ForegroundColor Yellow

$controlReferences = @'

$NavPolicySimulator = $window.FindName("NavPolicySimulator")
$TestingSection = $window.FindName("TestingSection")
$SimTestMode = $window.FindName("SimTestMode")
$SimPolicySelector = $window.FindName("SimPolicySelector")
$SimLoadPolicyBtn = $window.FindName("SimLoadPolicyBtn")
$SimTargetType = $window.FindName("SimTargetType")
$SimTargetPath = $window.FindName("SimTargetPath")
$SimIncludeUnsigned = $window.FindName("SimIncludeUnsigned")
$SimCheckBypasses = $window.FindName("SimCheckBypasses")
$SimAnalyzeImpact = $window.FindName("SimAnalyzeImpact")
$SimRunBtn = $window.FindName("SimRunBtn")
$SimProgressPanel = $window.FindName("SimProgressPanel")
$SimProgressBar = $window.FindName("SimProgressBar")
$SimProgressText = $window.FindName("SimProgressText")
$SimFilesAnalyzed = $window.FindName("SimFilesAnalyzed")
$SimWouldAllow = $window.FindName("SimWouldAllow")
$SimWouldBlock = $window.FindName("SimWouldBlock")
$SimCoverage = $window.FindName("SimCoverage")
$SimOverallStatus = $window.FindName("SimOverallStatus")
$SimExportBtn = $window.FindName("SimExportBtn")
$SimTabSummary = $window.FindName("SimTabSummary")
$SimTabDetailed = $window.FindName("SimTabDetailed")
$SimTabWarnings = $window.FindName("SimTabWarnings")
$SimTabRecommendations = $window.FindName("SimTabRecommendations")
$SimSummaryPanel = $window.FindName("SimSummaryPanel")
$SimDetailedPanel = $window.FindName("SimDetailedPanel")
$SimWarningsPanel = $window.FindName("SimWarningsPanel")
$SimRecommendationsPanel = $window.FindName("SimRecommendationsPanel")
$SimResultsGrid = $window.FindName("SimResultsGrid")
$SimWarningsGrid = $window.FindName("SimWarningsGrid")
$SimRecommendationsGrid = $window.FindName("SimRecommendationsGrid")
$SimImpactGrid = $window.FindName("SimImpactGrid")
'@

$content = Get-Content $mainFile -Raw -Encoding UTF8

# Find the location after existing control references
$pattern = '\$NavAbout = \$window\.FindName\("NavAbout"\)'

if ($content -match $pattern) {
    $insertLocation = $content.LastIndexOf($NavAbout)
    $beforeInsert = $content.Substring(0, $insertLocation)
    $afterInsert = $content.Substring($insertLocation)

    $newContent = $beforeInsert + "`n" + $controlReferences + $afterInsert

    Set-Content -Path $mainFile -Value $newContent -Encoding UTF8 -NoNewline
    Write-Host "  Control references added successfully" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Could not find insertion point for control references" -ForegroundColor Yellow
}
Write-Host ""

# Step 4: Insert navigation event handler
Write-Host "[4/6] Adding navigation event handler..." -ForegroundColor Yellow

$navEventHandler = @'

$NavPolicySimulator.Add_Click({
    Show-Panel "PolicySimulator"
    Update-StatusBar
    Update-SimPolicySelector
})
'@

$content = Get-Content $mainFile -Raw -Encoding UTF8

# Find the location after $NavAbout.Add_Click
$pattern = '\$NavAbout\.Add_Click\(\{[^}]+\}\)'

if ($content -match $pattern) {
    $lastMatch = $matches[0]
    $insertLocation = $content.LastIndexOf($lastMatch) + $lastMatch.Length
    $beforeInsert = $content.Substring(0, $insertLocation)
    $afterInsert = $content.Substring($insertLocation)

    $newContent = $beforeInsert + "`n" + $navEventHandler + $afterInsert

    Set-Content -Path $mainFile -Value $newContent -Encoding UTF8 -NoNewline
    Write-Host "  Navigation event handler added successfully" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Could not find insertion point for navigation handler" -ForegroundColor Yellow
}
Write-Host ""

# Step 5: Update Show-Panel function
Write-Host "[5/6] Updating Show-Panel function..." -ForegroundColor Yellow

$content = Get-Content $mainFile -Raw -Encoding UTF8

# Find and update the Show-Panel function
$showPanelPattern = 'function Show-Panel \{[^}]+"About"[^}]+\}[^}]+\}'

if ($content -match $showPanelPattern) {
    # Add PolicySimulator case before the closing brace
    $updatedShowPanel = $content -replace '( "About" \{ \$PanelAbout\.Visibility = \[System\.Windows\.Visibility\]::Visible \}\s*\})', '$1
    "PolicySimulator" { $PanelPolicySimulator.Visibility = [System.Windows.Visibility]::Visible }'

    Set-Content -Path $mainFile -Value $updatedShowPanel -Encoding UTF8 -NoNewline
    Write-Host "  Show-Panel function updated successfully" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Could not find Show-Panel function" -ForegroundColor Yellow
}
Write-Host ""

# Step 6: Append simulation functions and event handlers
Write-Host "[6/6] Appending simulation functions and event handlers..." -ForegroundColor Yellow

# Read the functions and event handlers
$functionsContent = Get-Content $functionsFile -Raw -Encoding UTF8

# Append to main file
Add-Content -Path $mainFile -Value "`n# ============================================================`n# Phase 5: Policy Simulation and Testing Functions`n# ============================================================`n" -Encoding UTF8
Add-Content -Path $mainFile -Value $functionsContent -Encoding UTF8

Write-Host "  Simulation functions appended successfully" -ForegroundColor Green

# Create a separate file for event handlers (to be sourced)
Write-Host ""
Write-Host "Integration complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review the changes in: $mainFile" -ForegroundColor White
Write-Host "2. Test the GUI to ensure the Policy Simulator panel appears" -ForegroundColor White
Write-Host "3. The event handlers file is at: $eventHandlersFile" -ForegroundColor White
Write-Host "4. Add event handlers manually or integrate them into the main file" -ForegroundColor White
Write-Host ""
Write-Host "Backup saved to: $backupFile" -ForegroundColor Yellow
Write-Host ""
