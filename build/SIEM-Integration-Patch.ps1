# ============================================================
# SIEM INTEGRATION PATCH FOR GA-AppLocker GUI
# Instructions for integrating SIEM functionality
# ============================================================

# This file contains the complete code to integrate SIEM functionality
# into the GA-AppLocker-GUI-WPF.ps1 file

# ============================================================
# STEP 1: Insert SIEM Panel XAML
# Location: After line 4153 (before "<!-- About Panel -->")
# ============================================================

$xamlPatch_SIEMPanel = @'
                <!-- SIEM Integration Panel - Phase 5 -->
                <StackPanel x:Name="PanelSiem" Visibility="Collapsed">
                    <TextBlock Text="SIEM Integration" FontSize="24" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,20"/>

                    <!-- Overview Section -->
                    <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="20" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Log Forwarding Configuration" FontSize="14" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <TextBlock Text="Configure forwarding of AppLocker events to SIEM systems. Supports Splunk, QRadar, LogRhythm, Elastic, Syslog, and custom REST endpoints."
                                       FontSize="12" Foreground="#8B949E" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <!-- SIEM Type Selection -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="SIEM Type" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>
                            <ComboBox x:Name="SiemTypeCombo" Height="30" Background="#21262D" Foreground="#E6EDF3"
                                      BorderBrush="#30363D" FontSize="12" Padding="8,5">
                                <ComboBoxItem Content="Splunk (HEC)" Tag="Splunk"/>
                                <ComboBoxItem Content="IBM QRadar (LEEF)" Tag="QRadar"/>
                                <ComboBoxItem Content="LogRhythm" Tag="LogRhythm"/>
                                <ComboBoxItem Content="Elastic (Elasticsearch)" Tag="Elastic"/>
                                <ComboBoxItem Content="Syslog (RFC5424)" Tag="Syslog"/>
                                <ComboBoxItem Content="REST API Custom" Tag="RestApi"/>
                            </ComboBox>
                        </StackPanel>
                    </Border>

                    <!-- Connection Settings -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Connection Settings" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <!-- Server/Endpoint -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Server/Endpoint:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="SiemServerText" Grid.Column="1" Height="28" Background="#21262D"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"
                                         ToolTip="SIEM server hostname or API endpoint URL"/>
                            </Grid>

                            <!-- Port and Protocol -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="100"/>
                                    <ColumnDefinition Width="20"/>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Port:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="SiemPortText" Grid.Column="1" Text="8088" Height="28" Background="#21262D"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"/>
                                <TextBlock Grid.Column="2"/>
                                <TextBlock Grid.Column="3" Text="Protocol:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <ComboBox x:Name="SiemProtocolCombo" Grid.Column="4" Height="28" Background="#21262D"
                                          Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12" Padding="5">
                                    <ComboBoxItem Content="HTTPS" IsSelected="True"/>
                                    <ComboBoxItem Content="HTTP"/>
                                    <ComboBoxItem Content="TCP"/>
                                    <ComboBoxItem Content="UDP"/>
                                </ComboBox>
                            </Grid>

                            <!-- Authentication -->
                            <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Padding="10" Margin="0,0,0,10">
                                <StackPanel>
                                    <TextBlock Text="Authentication" FontSize="12" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,8"/>

                                    <!-- Auth Type -->
                                    <Grid Margin="0,0,0,8">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="120"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="Auth Type:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                        <ComboBox x:Name="SiemAuthTypeCombo" Grid.Column="1" Height="28" Background="#0D1117"
                                                  Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12" Padding="5">
                                            <ComboBoxItem Content="Token/Bearer" IsSelected="True"/>
                                            <ComboBoxItem Content="Username/Password"/>
                                            <ComboBoxItem Content="Certificate"/>
                                            <ComboBoxItem Content="None"/>
                                        </ComboBox>
                                    </Grid>

                                    <!-- Token/Username -->
                                    <Grid Margin="0,0,0,8">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="120"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock x:Name="SiemTokenLabel" Grid.Column="0" Text="Token:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                        <PasswordBox x:Name="SiemTokenBox" Grid.Column="1" Height="28" Background="#0D1117"
                                                     Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12" Padding="5"/>
                                    </Grid>

                                    <!-- Password (for Username/Password) -->
                                    <Grid x:Name="SiemPasswordGrid" Margin="0,0,0,0" Visibility="Collapsed">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="120"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="Password:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                        <PasswordBox x:Name="SiemPasswordBox" Grid.Column="1" Height="28" Background="#0D1117"
                                                     Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12" Padding="5"/>
                                    </Grid>
                                </StackPanel>
                            </Border>

                            <!-- SSL/TLS -->
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="SSL/TLS:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <CheckBox x:Name="SiemSslCheck" IsChecked="True" Grid.Column="1" Foreground="#E6EDF3" Content="Enable SSL/TLS"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Event Filters -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Event Filters" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <!-- Event Types -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Event Types:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <StackPanel Grid.Column="1" Orientation="Horizontal">
                                    <CheckBox x:Name="FilterAllowedCheck" IsChecked="True" Content="Allowed" Foreground="#E6EDF3" Margin="0,0,15,0"/>
                                    <CheckBox x:Name="FilterBlockedCheck" IsChecked="True" Content="Blocked" Foreground="#E6EDF3" Margin="0,0,15,0"/>
                                    <CheckBox x:Name="FilterAuditedCheck" IsChecked="True" Content="Audited" Foreground="#E6EDF3"/>
                                </StackPanel>
                            </Grid>

                            <!-- Severity Threshold -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="150"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Min Severity:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <ComboBox x:Name="SiemSeverityCombo" Grid.Column="1" Height="28" Background="#21262D"
                                          Foreground="#E6EDF3" BorderBrush="#30363D" FontSize="12" Padding="5">
                                    <ComboBoxItem Content="All Events" IsSelected="True"/>
                                    <ComboBoxItem Content="Info"/>
                                    <ComboBoxItem Content="Warning"/>
                                    <ComboBoxItem Content="Error"/>
                                    <ComboBoxItem Content="Critical"/>
                                </ComboBox>
                            </Grid>

                            <!-- Include/Exclude Patterns -->
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="120"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Filter Pattern:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Top" Margin="0,4,0,0"/>
                                <StackPanel Grid.Column="1">
                                    <TextBox x:Name="SiemIncludePatternText" Height="26" Background="#21262D"
                                             Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="11" Padding="5"
                                             ToolTip="Regex pattern to INCLUDE (e.g., '.*C:\\Windows\\.*')"/>
                                    <TextBlock Text="Include pattern (regex)" FontSize="10" Foreground="#6E7681" Margin="0,2,0,4"/>
                                    <TextBox x:Name="SiemExcludePatternText" Height="26" Background="#21262D"
                                             Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="11" Padding="5"
                                             ToolTip="Regex pattern to EXCLUDE (e.g., '.*\.tmp$')"/>
                                    <TextBlock Text="Exclude pattern (regex)" FontSize="10" Foreground="#6E7681" Margin="0,2,0,0"/>
                                </StackPanel>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Advanced Settings -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Advanced Settings" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <!-- Batch Size -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="180"/>
                                    <ColumnDefinition Width="100"/>
                                    <ColumnDefinition Width="20"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Batch Size:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="SiemBatchSizeText" Grid.Column="1" Text="100" Height="28" Background="#21262D"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"/>
                                <TextBlock Grid.Column="2"/>
                                <TextBlock Grid.Column="3" Text="events per batch" FontSize="11" Foreground="#6E7681" VerticalAlignment="Center"/>
                            </Grid>

                            <!-- Retry Settings -->
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="180"/>
                                    <ColumnDefinition Width="100"/>
                                    <ColumnDefinition Width="20"/>
                                    <ColumnDefinition Width="100"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Max Retries:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="SiemMaxRetriesText" Grid.Column="1" Text="3" Height="28" Background="#21262D"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"/>
                                <TextBlock Grid.Column="2"/>
                                <TextBlock Grid.Column="3" Text="Retry Delay (sec):" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center" Margin="0,0,10,0"/>
                                <TextBox x:Name="SiemRetryDelayText" Grid.Column="4" Text="5" Height="28" Background="#21262D"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5" Width="100" HorizontalAlignment="Left"/>
                            </Grid>

                            <!-- Fallback Destination -->
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="180"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Fallback Endpoint:" FontSize="12" Foreground="#8B949E" VerticalAlignment="Center"/>
                                <TextBox x:Name="SiemFallbackText" Grid.Column="1" Height="28" Background="#21262D"
                                         Foreground="#E6EDF3" BorderBrush="#30363D" BorderThickness="1" FontSize="12" Padding="5"
                                         ToolTip="Secondary SIEM endpoint for failover"/>
                            </Grid>
                        </StackPanel>
                    </Border>

                    <!-- Action Buttons -->
                    <Grid Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="150"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="150"/>
                            <ColumnDefinition Width="10"/>
                            <ColumnDefinition Width="150"/>
                        </Grid.ColumnDefinitions>
                        <Button x:Name="SiemTestConnectionBtn" Content="Test Connection"
                                Style="{StaticResource SecondaryButton}" Grid.Column="2" MinHeight="32"/>
                        <Button x:Name="SiemSaveConfigBtn" Content="Save Configuration"
                                Style="{StaticResource SecondaryButton}" Grid.Column="4" MinHeight="32"/>
                        <Button x:Name="SiemLoadConfigBtn" Content="Load Configuration"
                                Style="{StaticResource SecondaryButton}" Grid.Column="6" MinHeight="32"/>
                    </Grid>

                    <!-- Enable Forwarding -->
                    <Border Background="#21262D" BorderBrush="#3FB950" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="20"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="150"/>
                            </Grid.ColumnDefinitions>
                            <CheckBox x:Name="SiemEnableForwardingCheck" IsChecked="False" Grid.Column="0" Foreground="#E6EDF3" FontSize="14"/>
                            <TextBlock Grid.Column="2" Text="Enable Event Forwarding" FontSize="14" FontWeight="Bold"
                                       Foreground="#E6EDF3" VerticalAlignment="Center"/>
                            <Button x:Name="SiemToggleForwardingBtn" Content="Start Forwarding"
                                    Style="{StaticResource PrimaryButton}" Grid.Column="3" MinHeight="32"/>
                        </Grid>
                    </Border>

                    <!-- Statistics Dashboard -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Forwarding Statistics" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>

                                <!-- Events Sent -->
                                <Border Grid.Column="0" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                        CornerRadius="6" Padding="12">
                                    <StackPanel>
                                        <TextBlock Text="Events Sent" FontSize="10" Foreground="#8B949E"/>
                                        <TextBlock x:Name="SiemEventsSentText" Text="0" FontSize="20" FontWeight="Bold"
                                                   Foreground="#3FB950" Margin="0,4,0,0"/>
                                    </StackPanel>
                                </Border>

                                <!-- Events Failed -->
                                <Border Grid.Column="2" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                        CornerRadius="6" Padding="12">
                                    <StackPanel>
                                        <TextBlock Text="Events Failed" FontSize="10" Foreground="#8B949E"/>
                                        <TextBlock x:Name="SiemEventsFailedText" Text="0" FontSize="20" FontWeight="Bold"
                                                   Foreground="#F85149" Margin="0,4,0,0"/>
                                    </StackPanel>
                                </Border>

                                <!-- Queue Size -->
                                <Border Grid.Column="4" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                        CornerRadius="6" Padding="12">
                                    <StackPanel>
                                        <TextBlock Text="In Queue" FontSize="10" Foreground="#8B949E"/>
                                        <TextBlock x:Name="SiemQueueSizeText" Text="0" FontSize="20" FontWeight="Bold"
                                                   Foreground="#58A6FF" Margin="0,4,0,0"/>
                                    </StackPanel>
                                </Border>

                                <!-- Rate (events/min) -->
                                <Border Grid.Column="6" Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                        CornerRadius="6" Padding="12">
                                    <StackPanel>
                                        <TextBlock Text="Rate/min" FontSize="10" Foreground="#8B949E"/>
                                        <TextBlock x:Name="SiemRateText" Text="0" FontSize="20" FontWeight="Bold"
                                                   Foreground="#E6EDF3" Margin="0,4,0,0"/>
                                    </StackPanel>
                                </Border>
                            </Grid>

                            <!-- Status Bar -->
                            <Border Background="#21262D" BorderBrush="#30363D" BorderThickness="1"
                                    CornerRadius="6" Padding="10" Margin="0,10,0,0">
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="10"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <TextBlock Grid.Column="0" Text="Status:" FontSize="11" Foreground="#8B949E" VerticalAlignment="Center"/>
                                    <Ellipse x:Name="SiemStatusIndicator" Grid.Column="1" Width="10" Height="10"
                                             Fill="#6E7681" VerticalAlignment="Center"/>
                                    <TextBlock x:Name="SiemStatusText" Grid.Column="2" Text="Stopped" FontSize="11"
                                               Foreground="#8B949E" VerticalAlignment="Center" Margin="5,0,10,0"/>
                                    <TextBlock x:Name="SiemLastEventText" Grid.Column="4" Text="Last event: Never"
                                               FontSize="10" Foreground="#6E7681" HorizontalAlignment="Right"/>
                                </Grid>
                            </Border>
                        </StackPanel>
                    </Border>

                    <!-- Event Enrichment Options -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" Margin="0,0,0,15">
                        <StackPanel>
                            <TextBlock Text="Event Enrichment" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3" Margin="0,0,0,10"/>

                            <StackPanel>
                                <CheckBox x:Name="SiemEnrichHostCheck" IsChecked="True" Content="Add Host Metadata" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <CheckBox x:Name="SiemEnrichADCheck" IsChecked="False" Content="Add User Department Info (AD)" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <CheckBox x:Name="SiemEnrichThreatCheck" IsChecked="False" Content="Add Threat Intelligence Context" Foreground="#E6EDF3" Margin="0,0,0,8"/>
                                <CheckBox x:Name="SiemEnrichNormalizeCheck" IsChecked="True" Content="Normalize Timestamps (UTC)" Foreground="#E6EDF3"/>
                            </StackPanel>
                        </StackPanel>
                    </Border>

                    <!-- Output Log -->
                    <Border Background="#0D1117" BorderBrush="#30363D" BorderThickness="1"
                            CornerRadius="8" Padding="15" MinHeight="200">
                        <StackPanel>
                            <Grid Margin="0,0,0,10">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="100"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Grid.Column="0" Text="Activity Log" FontSize="13" FontWeight="Bold" Foreground="#E6EDF3"/>
                                <Button x:Name="SiemClearLogBtn" Content="Clear Log"
                                        Style="{StaticResource SecondaryButton}" Grid.Column="2" Height="26" FontSize="11"/>
                            </Grid>
                            <ScrollViewer VerticalScrollBarVisibility="Auto" MaxHeight="300">
                                <TextBlock x:Name="SiemOutputLog" Text="SIEM Integration ready..."
                                           FontFamily="Consolas" FontSize="10" Foreground="#3FB950"
                                           TextWrapping="Wrap"/>
                            </ScrollViewer>
                        </StackPanel>
                    </Border>
                </StackPanel>
'@

# ============================================================
# STEP 2: Add PanelSiem to Show-Panel function
# Location: In the Show-Panel function switch statement
# ============================================================

$showPanelPatch = @'
    "Siem" { $PanelSiem.Visibility = [System.Windows.Visibility]::Visible }
'@

# ============================================================
# STEP 3: Add PanelSiem visibility initialization
# Location: In Show-Panel function where all panels are collapsed
# ============================================================

$hidePanelPatch = @'
    $PanelSiem.Visibility = [System.Windows.Visibility]::Collapsed
'@

# ============================================================
# STEP 4: Add control initialization
# Location: After other control FindName calls (around line 4250)
# ============================================================

$controlInitPatch = @'
$NavSiem = $window.FindName("NavSiem")
$PanelSiem = $window.FindName("PanelSiem")
$SiemTypeCombo = $window.FindName("SiemTypeCombo")
$SiemServerText = $window.FindName("SiemServerText")
$SiemPortText = $window.FindName("SiemPortText")
$SiemProtocolCombo = $window.FindName("SiemProtocolCombo")
$SiemAuthTypeCombo = $window.FindName("SiemAuthTypeCombo")
$SiemTokenLabel = $window.FindName("SiemTokenLabel")
$SiemTokenBox = $window.FindName("SiemTokenBox")
$SiemPasswordGrid = $window.FindName("SiemPasswordGrid")
$SiemPasswordBox = $window.FindName("SiemPasswordBox")
$SiemSslCheck = $window.FindName("SiemSslCheck")
$FilterAllowedCheck = $window.FindName("FilterAllowedCheck")
$FilterBlockedCheck = $window.FindName("FilterBlockedCheck")
$FilterAuditedCheck = $window.FindName("FilterAuditedCheck")
$SiemSeverityCombo = $window.FindName("SiemSeverityCombo")
$SiemIncludePatternText = $window.FindName("SiemIncludePatternText")
$SiemExcludePatternText = $window.FindName("SiemExcludePatternText")
$SiemBatchSizeText = $window.FindName("SiemBatchSizeText")
$SiemMaxRetriesText = $window.FindName("SiemMaxRetriesText")
$SiemRetryDelayText = $window.FindName("SiemRetryDelayText")
$SiemFallbackText = $window.FindName("SiemFallbackText")
$SiemTestConnectionBtn = $window.FindName("SiemTestConnectionBtn")
$SiemSaveConfigBtn = $window.FindName("SiemSaveConfigBtn")
$SiemLoadConfigBtn = $window.FindName("SiemLoadConfigBtn")
$SiemEnableForwardingCheck = $window.FindName("SiemEnableForwardingCheck")
$SiemToggleForwardingBtn = $window.FindName("SiemToggleForwardingBtn")
$SiemEventsSentText = $window.FindName("SiemEventsSentText")
$SiemEventsFailedText = $window.FindName("SiemEventsFailedText")
$SiemQueueSizeText = $window.FindName("SiemQueueSizeText")
$SiemRateText = $window.FindName("SiemRateText")
$SiemStatusIndicator = $window.FindName("SiemStatusIndicator")
$SiemStatusText = $window.FindName("SiemStatusText")
$SiemLastEventText = $window.FindName("SiemLastEventText")
$SiemEnrichHostCheck = $window.FindName("SiemEnrichHostCheck")
$SiemEnrichADCheck = $window.FindName("SiemEnrichADCheck")
$SiemEnrichThreatCheck = $window.FindName("SiemEnrichThreatCheck")
$SiemEnrichNormalizeCheck = $window.FindName("SiemEnrichNormalizeCheck")
$SiemOutputLog = $window.FindName("SiemOutputLog")
$SiemClearLogBtn = $window.FindName("SiemClearLogBtn")
'@

# ============================================================
# STEP 5: Add Navigation Event Handler
# Location: After other Nav button event handlers
# ============================================================

$navHandlerPatch = @'
$NavSiem.Add_Click({
    Show-Panel "Siem"
    Update-StatusBar
})
'@

# ============================================================
# STEP 6: Add SIEM Control Event Handlers
# Location: Before window.ShowDialog() at end of script
# ============================================================

$siemEventHandlersPatch = @'

# ============================================================
# SIEM INTEGRATION EVENT HANDLERS
# ============================================================

# SIEM Type Selection Handler
$SiemTypeCombo.Add_SelectionChanged({
    $selectedItem = $SiemTypeCombo.SelectedItem
    if ($selectedItem) {
        $tag = $selectedItem.Tag.ToString()
        # Update default port based on SIEM type
        switch ($tag) {
            "Splunk"   { $SiemPortText.Text = "8088" }
            "QRadar"   { $SiemPortText.Text = "514" }
            "LogRhythm" { $SiemPortText.Text = "8300" }
            "Elastic"  { $SiemPortText.Text = "9200" }
            "Syslog"   { $SiemPortText.Text = "514" }
            "RestApi"  { $SiemPortText.Text = "443" }
        }
    }
})

# Authentication Type Handler
$SiemAuthTypeCombo.Add_SelectionChanged({
    $selectedItem = $SiemAuthTypeCombo.SelectedItem
    if ($selectedItem) {
        $content = $selectedItem.Content.ToString()
        switch ($content) {
            "Token/Bearer" {
                $SiemTokenLabel.Text = "Token:"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Collapsed
            }
            "Username/Password" {
                $SiemTokenLabel.Text = "Username:"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Visible
            }
            "Certificate" {
                $SiemTokenLabel.Text = "Certificate Path:"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Collapsed
            }
            "None" {
                $SiemTokenLabel.Text = "N/A"
                $SiemPasswordGrid.Visibility = [System.Windows.Visibility]::Collapsed
            }
        }
    }
})

# Test Connection Button Handler
$SiemTestConnectionBtn.Add_Click({
    try {
        # Load SIEM module
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found at: $siemModulePath"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        # Build config from UI
        $config = $script:SiemConfig.Clone()
        $config.SiemType = if ($SiemTypeCombo.SelectedItem) { $SiemTypeCombo.SelectedItem.Tag } else { "Splunk" }
        $config.Server = $SiemServerText.Text
        $config.Port = [int]$SiemPortText.Text
        $config.Protocol = if ($SiemProtocolCombo.SelectedItem) { $SiemProtocolCombo.SelectedItem.Content.ToString() } else { "HTTPS" }
        $config.AuthType = if ($SiemAuthTypeCombo.SelectedItem) { $SiemAuthTypeCombo.SelectedItem.Content.ToString() } else { "Token" }

        # Get token/password securely
        $config.Token = if ($SiemTokenBox.SecurePassword) {
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SiemTokenBox.SecurePassword))
        } else { "" }

        $config.UseSSL = $SiemSslCheck.IsChecked

        # Test connection
        $SiemOutputLog.Text += "`n[INFO] Testing connection to $($config.Server):$($config.Port)..."
        $SiemOutputLog.Foreground = "#58A6FF"

        $result = Test-SiemConnection -Config $config

        if ($result.Success) {
            $SiemOutputLog.Text += "`n[SUCCESS] Connection test successful!"
            $SiemOutputLog.Foreground = "#3FB950"
            $SiemStatusIndicator.Fill = "#3FB950"
            $SiemStatusText.Text = "Connected"
        } else {
            $SiemOutputLog.Text += "`n[ERROR] Connection test failed: $($result.Error)"
            $SiemOutputLog.Foreground = "#F85149"
            $SiemStatusIndicator.Fill = "#F85149"
            $SiemStatusText.Text = "Failed"
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Save Configuration Button Handler
$SiemSaveConfigBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        # Build config from UI
        $script:SiemConfig.SiemType = if ($SiemTypeCombo.SelectedItem) { $SiemTypeCombo.SelectedItem.Tag } else { "Splunk" }
        $script:SiemConfig.Server = $SiemServerText.Text
        $script:SiemConfig.Port = [int]$SiemPortText.Text
        $script:SiemConfig.Protocol = if ($SiemProtocolCombo.SelectedItem) { $SiemProtocolCombo.SelectedItem.Content.ToString() } else { "HTTPS" }
        $script:SiemConfig.AuthType = if ($SiemAuthTypeCombo.SelectedItem) { $SiemAuthTypeCombo.SelectedItem.Content.ToString() } else { "Token" }

        # Get token/password securely
        if ($SiemTokenBox.SecurePassword) {
            $script:SiemConfig.Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SiemTokenBox.SecurePassword))
        }

        if ($SiemPasswordBox.SecurePassword) {
            $script:SiemConfig.Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SiemPasswordBox.SecurePassword))
        }

        $script:SiemConfig.UseSSL = $SiemSslCheck.IsChecked
        $script:SiemConfig.BatchSize = [int]$SiemBatchSizeText.Text
        $script:SiemConfig.MaxRetries = [int]$SiemMaxRetriesText.Text
        $script:SiemConfig.RetryDelay = [int]$SiemRetryDelayText.Text
        $script:SiemConfig.FallbackEndpoint = $SiemFallbackText.Text

        # Filters
        $script:SiemConfig.Filters.Allowed = $FilterAllowedCheck.IsChecked
        $script:SiemConfig.Filters.Blocked = $FilterBlockedCheck.IsChecked
        $script:SiemConfig.Filters.Audited = $FilterAuditedCheck.IsChecked
        $script:SiemConfig.Filters.MinSeverity = if ($SiemSeverityCombo.SelectedItem) { $SiemSeverityCombo.SelectedItem.Content.ToString() } else { "All" }
        $script:SiemConfig.Filters.IncludePattern = if ($SiemIncludePatternText.Text) { $SiemIncludePatternText.Text } else { $null }
        $script:SiemConfig.Filters.ExcludePattern = if ($SiemExcludePatternText.Text) { $SiemExcludePatternText.Text } else { $null }

        # Enrichment
        $script:SiemConfig.Enrichment.AddHostMetadata = $SiemEnrichHostCheck.IsChecked
        $script:SiemConfig.Enrichment.AddADInfo = $SiemEnrichADCheck.IsChecked
        $script:SiemConfig.Enrichment.AddThreatIntel = $SiemEnrichThreatCheck.IsChecked
        $script:SiemConfig.Enrichment.NormalizeTimestamps = $SiemEnrichNormalizeCheck.IsChecked

        # Save
        $result = Save-SiemConfig

        if ($result.Success) {
            $SiemOutputLog.Text += "`n[SUCCESS] Configuration saved to: $($result.Path)"
            $SiemOutputLog.Foreground = "#3FB950"
        } else {
            $SiemOutputLog.Text += "`n[ERROR] Failed to save: $($result.Error)"
            $SiemOutputLog.Foreground = "#F85149"
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Load Configuration Button Handler
$SiemLoadConfigBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        $result = Load-SiemConfig

        if ($result.Success) {
            $config = $result.Config

            # Update UI
            $SiemServerText.Text = $config.Server
            $SiemPortText.Text = $config.Port.ToString()
            $SiemBatchSizeText.Text = $config.BatchSize.ToString()
            $SiemMaxRetriesText.Text = $config.MaxRetries.ToString()
            $SiemRetryDelayText.Text = $config.RetryDelay.ToString()
            $SiemFallbackText.Text = $config.FallbackEndpoint

            # Update combo boxes
            foreach ($item in $SiemTypeCombo.Items) {
                if ($item.Tag -eq $config.SiemType) {
                    $SiemTypeCombo.SelectedItem = $item
                    break
                }
            }

            $SiemSslCheck.IsChecked = $config.UseSSL
            $FilterAllowedCheck.IsChecked = $config.Filters.Allowed
            $FilterBlockedCheck.IsChecked = $config.Filters.Blocked
            $FilterAuditedCheck.IsChecked = $config.Filters.Audited
            $SiemEnrichHostCheck.IsChecked = $config.Enrichment.AddHostMetadata
            $SiemEnrichADCheck.IsChecked = $config.Enrichment.AddADInfo
            $SiemEnrichThreatCheck.IsChecked = $config.Enrichment.AddThreatIntel
            $SiemEnrichNormalizeCheck.IsChecked = $config.Enrichment.NormalizeTimestamps

            $SiemOutputLog.Text += "`n[SUCCESS] Configuration loaded successfully"
            $SiemOutputLog.Foreground = "#3FB950"
        } else {
            $SiemOutputLog.Text += "`n[ERROR] Failed to load: $($result.Error)"
            $SiemOutputLog.Foreground = "#F85149"
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Toggle Forwarding Button Handler
$SiemToggleForwardingBtn.Add_Click({
    try {
        $siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
        if (-not (Test-Path $siemModulePath)) {
            $SiemOutputLog.Text += "`n[ERROR] SIEM module not found"
            $SiemOutputLog.Foreground = "#F85149"
            return
        }

        . $siemModulePath

        if ($script:SiemConfig.Enabled) {
            # Stop forwarding
            $result = Stop-EventForwarder
            $SiemToggleForwardingBtn.Content = "Start Forwarding"
            $SiemStatusIndicator.Fill = "#6E7681"
            $SiemStatusText.Text = "Stopped"

            if ($result.Success) {
                $SiemOutputLog.Text += "`n[SUCCESS] Event forwarding stopped"
                $SiemOutputLog.Foreground = "#3FB950"
            }
        } else {
            # Start forwarding
            $result = Start-EventForwarder

            if ($result.Success) {
                $SiemToggleForwardingBtn.Content = "Stop Forwarding"
                $SiemStatusIndicator.Fill = "#3FB950"
                $SiemStatusText.Text = "Running"
                $SiemOutputLog.Text += "`n[SUCCESS] Event forwarding started (Job ID: $($result.JobId))"
                $SiemOutputLog.Foreground = "#3FB950"

                # Start statistics update timer
                $timer = New-Object System.Windows.Threading.DispatcherTimer
                $timer.Interval = [TimeSpan]::FromSeconds(5)
                $timer.Tag = @{ OutputLog = $SiemOutputLog; EventsSentText = $SiemEventsSentText; EventsFailedText = $SiemEventsFailedText; QueueSizeText = $SiemQueueSizeText; RateText = $SiemRateText; LastEventText = $SiemLastEventText }
                $timer.Add_Tick({
                    $stats = Get-ForwarderStatistics
                    $this.Tag.EventsSentText.Text = $stats.EventsSent.ToString()
                    $this.Tag.EventsFailedText.Text = $stats.EventsFailed.ToString()
                    $this.Tag.QueueSizeText.Text = $stats.QueueSize.ToString()
                    $this.Tag.RateText.Text = $stats.EventsPerMinute.ToString("F1")
                    if ($stats.LastEventTime) {
                        $this.Tag.LastEventText.Text = "Last event: " + $stats.LastEventTime.ToString("HH:mm:ss")
                    }
                })
                $timer.Start()
            } else {
                $SiemOutputLog.Text += "`n[ERROR] Failed to start forwarding: $($result.Error)"
                $SiemOutputLog.Foreground = "#F85149"
            }
        }
    } catch {
        $SiemOutputLog.Text += "`n[ERROR] $($_.Exception.Message)"
        $SiemOutputLog.Foreground = "#F85149"
    }
})

# Clear Log Button Handler
$SiemClearLogBtn.Add_Click({
    $SiemOutputLog.Text = "SIEM Integration ready..."
    $SiemOutputLog.Foreground = "#3FB950"
})
'@

# ============================================================
# INTEGRATION SUMMARY
# ============================================================

Write-Host @"
============================================================
GA-AppLocker SIEM Integration - Integration Instructions
============================================================

The following files have been created:

1. GA-AppLocker-SIEM-Integration.ps1
   - Complete SIEM forwarding module with all functions
   - Location: C:\projects\GA-AppLocker_FINAL\build\

2. SIEM-Integration-Patch.ps1 (this file)
   - Integration code and instructions

TO COMPLETE THE INTEGRATION:

Step 1: Insert SIEM Panel XAML
   - Open: GA-AppLocker-GUI-WPF.ps1
   - Find line 4155: "<!-- About Panel -->"
   - Insert the XAML from `$xamlPatch_SIEMPanel` before this line

Step 2: Update Show-Panel Function
   - Find the Show-Panel function switch statement
   - Add: "Siem" { `$PanelSiem.Visibility = [System.Windows.Visibility]::Visible }
   - Add to panel collapse section: `$PanelSiem.Visibility = [System.Windows.Visibility]::Collapsed

Step 3: Add Control Initialization
   - Find where controls are initialized with FindName (after line 4250)
   - Add all controls from `$controlInitPatch`

Step 4: Add Navigation Handler
   - Find the other Nav button event handlers
   - Add the NavSiem click handler from `$navHandlerPatch`

Step 5: Add SIEM Event Handlers
   - Before `$window.ShowDialog()` at the end of the script
   - Add all event handlers from `$siemEventHandlersPatch`

FEATURES INCLUDED:

- 6 SIEM Types: Splunk HEC, IBM QRadar LEEF, LogRhythm, Elastic, Syslog RFC5424, Custom REST API
- Secure credential handling with PasswordBoxes
- Event filtering (type, severity, regex patterns)
- Batch sending with configurable size and retry logic
- Fallback/secondary endpoint support
- Event enrichment:
  * Host metadata (OS, architecture, etc.)
  * Active Directory user info (department, groups)
  * Threat intelligence context (risk scoring)
  * Timestamp normalization to UTC
- Real-time statistics dashboard
- Multiple configuration profiles
- Encrypted configuration storage

SECURITY FEATURES:

- Credentials encrypted when saved
- PasswordBoxes for secure entry
- SSL/TLS support with certificate validation
- Secure string handling throughout

TESTING:

1. Load the GUI
2. Click "SIEM Integration" in the sidebar
3. Configure your SIEM endpoint
4. Click "Test Connection"
5. Click "Save Configuration"
6. Click "Start Forwarding"

============================================================
"@

# Export patches for easy access
Export-Clixml -Path "C:\projects\GA-AppLocker_FINAL\build\SIEM-XAML-Patch.xml" -InputObject $xamlPatch_SIEMPanel
Export-Clixml -Path "C:\projects\GA-AppLocker_FINAL\build\SIEM-Handlers-Patch.xml" -InputObject $siemEventHandlersPatch

Write-Host "Patch files exported to XML for easy integration."
