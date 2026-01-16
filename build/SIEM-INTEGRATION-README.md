# GA-AppLocker SIEM Integration - Complete Documentation

## Overview

The GA-AppLocker SIEM Integration module provides comprehensive log forwarding capabilities for AppLocker events to enterprise SIEM systems. This Phase 5 implementation supports multiple SIEM platforms, event enrichment, and secure credential management.

## Files Created

1. **GA-AppLocker-SIEM-Integration.ps1** (Main Module)
   - Complete SIEM forwarding engine
   - All formatting functions for different SIEM types
   - Event enrichment capabilities
   - Configuration management

2. **SIEM-Integration-Patch.ps1** (Integration Helper)
   - XAML for SIEM panel
   - Event handlers for GUI integration
   - Integration instructions

3. **SIEM-INTEGRATION-README.md** (This File)
   - Complete documentation
   - Usage examples
   - API reference

## Supported SIEM Platforms

### 1. Splunk (HTTP Event Collector - HEC)
- **Port**: 8088 (default)
- **Protocol**: HTTPS
- **Format**: JSON with HEC metadata
- **Auth**: Bearer token (Splunk token)

### 2. IBM QRadar (Log Event Extension Format - LEEF)
- **Port**: 514 (default)
- **Protocol**: TCP/UDP/HTTPS
- **Format**: LEEF 1.0
- **Auth**: Token or None

### 3. LogRhythm
- **Port**: 8300 (default)
- **Protocol**: HTTPS
- **Format**: REST API JSON
- **Auth**: API token

### 4. Elastic / Elasticsearch
- **Port**: 9200 (default)
- **Protocol**: HTTPS
- **Format**: ECS (Elastic Common Schema) JSON
- **Auth**: Bearer token or Basic auth

### 5. Syslog (RFC5424)
- **Port**: 514 (default)
- **Protocol**: TCP/UDP
- **Format**: RFC5424 structured syslog
- **Auth**: None

### 6. Custom REST API
- **Port**: 443 (default)
- **Protocol**: HTTPS
- **Format**: Custom JSON schema
- **Auth**: Bearer token, Basic auth, or None

## Features

### Event Forwarding

#### Send-SiemEvent
Send a single event to the configured SIEM:

```powershell
$result = Send-SiemEvent -Event $appLockerEvent
```

#### Send-BatchEvents
Send multiple events efficiently:

```powershell
$events = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 100
$result = Send-BatchEvents -Events $events
```

### Event Formatting

#### Format-EventForSplunk
Convert AppLocker event to Splunk HEC format:

```powershell
$splunkEvent = Format-EventForSplunk -Event $appLockerEvent
```

Output format:
```json
{
  "time": "2026-01-15T10:30:00Z",
  "host": "WORKSTATION01",
  "source": "AppLocker",
  "sourcetype": "WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL",
  "event": {
    "EventId": 8004,
    "Level": "Error",
    "Message": "...",
    "Severity": "Critical",
    "FilePath": "C:\\Temp\\suspicious.exe",
    "FileHash": "ABC123...",
    "PublisherName": "Unknown"
  }
}
```

#### Format-EventForQradar
Convert to IBM QRadar LEEF format:

```powershell
$leefEvent = Format-EventForQradar -Event $appLockerEvent
```

Output format:
```
LEEF:1.0|Microsoft|AppLocker|1.0|8004|devTime=20260115103000Z devTimeFormat=yyyy-MM-ddTHH:mm:ss.fffZ src=WORKSTATION01 usrName=JDOE eventId=8004 severity=10 filePath=C:\Temp\suspicious.exe publisher=Unknown
```

#### Format-EventForSyslog
Convert to RFC5424 syslog format:

```powershell
$syslogEvent = Format-EventForSyslog -Event $appLockerEvent
```

Output format:
```
<134>1 2026-01-15T10:30:00.123Z WORKSTATION01 AppLocker 1234 - - [AppLockerEvents@WORKSTATION01 eventId="8004" userName="JDOE" filePath="C:\Temp\suspicious.exe" publisher="Unknown"] AppLocker blocked execution...
```

#### Format-EventForElastic
Convert to ECS (Elastic Common Schema) format:

```powershell
$elasticEvent = Format-EventForElastic -Event $appLockerEvent
```

Output format:
```json
{
  "@timestamp": "2026-01-15T10:30:00.0000000Z",
  "event": {
    "module": "applocker",
    "dataset": "applocker.events",
    "category": "host",
    "type": "info"
  },
  "host": {
    "name": "WORKSTATION01",
    "os": {
      "family": "windows",
      "version": "10.0.19044"
    }
  },
  "user": {
    "name": "JDOE",
    "id": "S-1-5-21-..."
  },
  "process": {
    "pid": 1234,
    "executable": "C:\\Temp\\suspicious.exe"
  },
  "file": {
    "path": "C:\\Temp\\suspicious.exe",
    "hash": "ABC123..."
  }
}
```

### Connection Management

#### Test-SiemConnection
Test connectivity to SIEM endpoint:

```powershell
$result = Test-SiemConnection
if ($result.Success) {
    Write-Host "Connection successful!"
}
```

#### Start-EventForwarder
Start background event forwarding:

```powershell
$result = Start-EventForwarder
# Returns: Job ID for tracking
```

Features:
- Real-time event subscription
- Automatic batching
- Background job execution
- Automatic retry on failure

#### Stop-EventForwarder
Stop event forwarding:

```powershell
$result = Stop-EventForwarder
```

### Event Enrichment

#### Add-EventEnrichment
Enrich events with additional metadata:

```powershell
$enrichedEvent = Add-EventEnrichment -Event $appLockerEvent -Config $config
```

Enrichment options:

1. **Host Metadata**
   - Computer name
   - OS version and architecture
   - Domain information

2. **Active Directory Information**
   - User department
   - Title/role
   - Group memberships
   - Manager information

3. **Threat Intelligence**
   - Risk scoring based on:
     * Execution location (Temp, Downloads, etc.)
     * Publisher trust level
     * File characteristics
   - Risk levels: None, Low, Medium, High, Critical

4. **Timestamp Normalization**
   - Convert to UTC
   - ISO 8601 formatting

### Event Filtering

#### Test-EventFilter
Filter events based on criteria:

```powershell
$shouldForward = Test-EventFilter -Event $appLockerEvent -Config $config
```

Filter options:
- Event type: Allowed, Blocked, Audited
- Severity threshold: All, Info, Warning, Error, Critical
- Include pattern: Regex for matching file paths
- Exclude pattern: Regex for excluding file paths

### Configuration Management

#### Save-SiemConfig
Save encrypted configuration:

```powershell
$result = Save-SiemConfig
# Saved to: $env:LOCALAPPDATA\GA-AppLocker\SIEM-Config.xml
```

Security features:
- Credentials encrypted using Windows DPAPI
- Secure string handling
- Protected storage location

#### Load-SiemConfig
Load saved configuration:

```powershell
$result = Load-SiemConfig
```

#### Save-SiemProfile
Save named configuration profile:

```powershell
$result = Save-SiemProfile -ProfileName "Production-Splunk"
```

Use cases:
- Multiple environments (dev, test, prod)
- Different SIEM endpoints
- Team-specific configurations

#### Get-SiemProfiles
List available profiles:

```powershell
$profiles = Get-SiemProfiles
foreach ($profile in $profiles) {
    Write-Host "$($profile.Name) - Created: $($profile.Created)"
}
```

## Configuration Schema

```powershell
$script:SiemConfig = @{
    # Connection Settings
    Enabled = $false
    SiemType = "Splunk"  # Splunk, QRadar, LogRhythm, Elastic, Syslog, RestApi
    Server = "splunk.example.com"
    Port = 8088
    Protocol = "HTTPS"   # HTTPS, HTTP, TCP, UDP
    AuthType = "Token"   # Token, Username, Certificate, None
    Token = "your-token-here"
    UseSSL = $true

    # Advanced Settings
    BatchSize = 100      # Events per batch
    MaxRetries = 3       # Retry attempts
    RetryDelay = 5       # Seconds between retries
    FallbackEndpoint = ""  # Secondary SIEM endpoint

    # Event Filters
    Filters = @{
        Allowed = $true
        Blocked = $true
        Audited = $true
        MinSeverity = "All"
        IncludePattern = $null
        ExcludePattern = $null
    }

    # Event Enrichment
    Enrichment = @{
        AddHostMetadata = $true
        AddADInfo = $false
        AddThreatIntel = $false
        NormalizeTimestamps = $true
    }
}
```

## Statistics and Monitoring

#### Get-ForwarderStatistics
Get current forwarding statistics:

```powershell
$stats = Get-ForwarderStatistics
Write-Host "Events Sent: $($stats.EventsSent)"
Write-Host "Events Failed: $($stats.EventsFailed)"
Write-Host "Queue Size: $($stats.QueueSize)"
Write-Host "Events/min: $($stats.EventsPerMinute)"
Write-Host "Status: $($stats.Status)"
```

## GUI Integration

### Panel Features

The SIEM Integration panel includes:

1. **SIEM Type Selection**
   - Dropdown with 6 supported SIEM types
   - Auto-sets default port for each type

2. **Connection Settings**
   - Server/endpoint URL
   - Port configuration
   - Protocol selection (HTTPS, HTTP, TCP, UDP)
   - Authentication configuration
   - SSL/TLS toggle

3. **Event Filters**
   - Event type checkboxes (Allowed, Blocked, Audited)
   - Severity threshold dropdown
   - Include/exclude regex patterns

4. **Advanced Settings**
   - Batch size configuration
   - Retry settings (max retries, delay)
   - Fallback endpoint

5. **Action Buttons**
   - Test Connection
   - Save Configuration
   - Load Configuration

6. **Enable Forwarding**
   - Enable checkbox
   - Start/Stop button
   - Real-time status indicator

7. **Statistics Dashboard**
   - Events sent counter
   - Events failed counter
   - Queue size indicator
   - Events/minute rate
   - Status bar with indicator
   - Last event timestamp

8. **Event Enrichment**
   - Host metadata checkbox
   - AD info checkbox
   - Threat intel checkbox
   - Timestamp normalization checkbox

9. **Activity Log**
   - Real-time log display
   - Color-coded messages (Info, Success, Error)
   - Clear log button

## Integration Steps

### Step 1: Insert XAML Panel

In `GA-AppLocker-GUI-WPF.ps1` at line 4155 (before `<!-- About Panel -->`):

```powershell
# Insert the complete SIEM panel XAML from:
# C:\projects\GA-AppLocker_FINAL\build\SIEM-XAML-Patch.xml
```

### Step 2: Update Show-Panel Function

Add to switch statement:

```powershell
"Siem" { $PanelSiem.Visibility = [System.Windows.Visibility]::Visible }
```

Add to panel collapse section:

```powershell
$PanelSiem.Visibility = [System.Windows.Visibility]::Collapsed
```

### Step 3: Initialize Controls

After existing control FindName calls:

```powershell
$NavSiem = $window.FindName("NavSiem")
$PanelSiem = $window.FindName("PanelSiem")
$SiemTypeCombo = $window.FindName("SiemTypeCombo")
# ... (all other SIEM controls)
```

### Step 4: Add Navigation Handler

After other Nav button handlers:

```powershell
$NavSiem.Add_Click({
    Show-Panel "Siem"
    Update-StatusBar
})
```

### Step 5: Add Event Handlers

Before `$window.ShowDialog()`:

```powershell
# Import SIEM module
$siemModulePath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1"
if (Test-Path $siemModulePath) {
    . $siemModulePath
}

# Add all SIEM event handlers (see SIEM-Integration-Patch.ps1)
```

## Usage Examples

### Example 1: Forward to Splunk

```powershell
# Configure
$script:SiemConfig.SiemType = "Splunk"
$script:SiemConfig.Server = "splunk.example.com"
$script:SiemConfig.Port = 8088
$script:SiemConfig.Protocol = "HTTPS"
$script:SiemConfig.AuthType = "Token"
$script:SiemConfig.Token = "your-splunk-hec-token"

# Test connection
Test-SiemConnection

# Start forwarding
Start-EventForwarder

# Monitor statistics
while ($true) {
    $stats = Get-ForwarderStatistics
    Write-Host "Sent: $($stats.EventsSent), Failed: $($stats.EventsFailed), Rate: $($stats.EventsPerMinute)/min"
    Start-Sleep -Seconds 10
}
```

### Example 2: Forward to QRadar with Enrichment

```powershell
# Configure
$script:SiemConfig.SiemType = "QRadar"
$script:SiemConfig.Server = "qradar.example.com"
$script:SiemConfig.Port = 514
$script:SiemConfig.Protocol = "TCP"

# Enable enrichment
$script:SiemConfig.Enrichment.AddHostMetadata = $true
$script:SiemConfig.Enrichment.AddADInfo = $true
$script:SiemConfig.Enrichment.AddThreatIntel = $true
$script:SiemConfig.Enrichment.NormalizeTimestamps = $true

# Save configuration
Save-SiemProfile -ProfileName "QRadar-Prod"

# Start forwarding
Start-EventForwarder
```

### Example 3: Batch Forward Historical Events

```powershell
# Get last 1000 AppLocker events
$events = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 1000

# Filter to only blocked events
$blockedEvents = $events | Where-Object { $_.Id -eq 8004 }

# Forward in batch
$result = Send-BatchEvents -Events $blockedEvents

Write-Host "Sent: $($result.Sent), Failed: $($result.Failed)"
```

### Example 4: Custom REST API

```powershell
# Configure for custom endpoint
$script:SiemConfig.SiemType = "RestApi"
$script:SiemConfig.Server = "api.example.com"
$script:SiemConfig.Port = 443
$script:SiemConfig.Protocol = "HTTPS"
$script:SiemConfig.AuthType = "Token"
$script:SiemConfig.Token = "your-api-token"

# Set custom endpoint path (modify in Send-HttpEvent function)
# Default: /api/events

# Test and start
Test-SiemConnection
Start-EventForwarder
```

## Security Considerations

### Credential Protection

1. **Storage**: Credentials encrypted using Windows DPAPI
2. **Transmission**: Always use HTTPS/TLS when available
3. **Memory**: Secure strings used for password handling
4. **Logging**: No credentials written to logs

### Network Security

1. **SSL/TLS Verification**: Enabled by default
2. **Certificate Validation**: Performed automatically
3. **Fallback**: Secondary endpoint for high availability
4. **Retry Logic**: Exponential backoff on failures

### Access Control

1. **Configuration Files**: Stored in user profile (ACL protected)
2. **Event Filters**: Prevent sensitive data exposure
3. **AD Integration**: Respect existing AD permissions

## Troubleshooting

### Connection Failures

**Problem**: Test connection fails

**Solutions**:
1. Verify server name and port
2. Check firewall rules
3. Verify credentials
4. Test with: `Test-NetConnection -ComputerName $server -Port $port`

### Event Forwarding Not Working

**Problem**: No events being sent

**Solutions**:
1. Check event filters - may be too restrictive
2. Verify AppLocker log exists: `Get-WinEvent -ListLog 'Microsoft-Windows-AppLocker/EXE and DLL'`
3. Check statistics: `Get-ForwarderStatistics`
4. Review activity log for errors

### High Failure Rate

**Problem**: Many events failing to send

**Solutions**:
1. Reduce batch size
2. Increase retry delay
3. Check network stability
4. Verify SIEM endpoint capacity
5. Review SIEM logs for errors

### AD Lookup Failing

**Problem**: User enrichment not working

**Solutions**:
1. Verify machine is domain-joined
2. Check: `Test-ComputerSecureChannel`
3. Verify ActiveDirectory module available
4. Check user has permissions for AD queries

## Performance Tuning

### Batch Size

- **Small (10-50)**: Better for real-time, higher overhead
- **Medium (100-500)**: Balanced (default)
- **Large (1000+)**: Better throughput, higher memory use

### Retry Settings

- **Max Retries**: 0-3 for fast-fail, 5+ for reliability
- **Retry Delay**: 1-5 seconds for normal, 10+ for unstable networks

### Memory Management

The event queue uses a `ConcurrentQueue` with these characteristics:
- Thread-safe operations
- Bounded only by available memory
- Monitor queue size via statistics

## API Reference

### Functions

| Function | Parameters | Returns | Description |
|----------|-----------|---------|-------------|
| Send-SiemEvent | Event, Config | Hashtable | Send single event |
| Send-BatchEvents | Events, Config | Hashtable | Send batch of events |
| Format-EventForSplunk | Event, Config | Hashtable | Format for Splunk HEC |
| Format-EventForQradar | Event, Config | Hashtable | Format for QRadar LEEF |
| Format-EventForSyslog | Event, Config | Hashtable | Format for Syslog RFC5424 |
| Format-EventForElastic | Event, Config | Hashtable | Format for Elastic ECS |
| Format-EventForRestApi | Event, Config | Hashtable | Format for REST API |
| Test-SiemConnection | Config | Hashtable | Test connectivity |
| Start-EventForwarder | Config | Hashtable | Start forwarding job |
| Stop-EventForwarder | - | Hashtable | Stop forwarding job |
| Get-ForwarderStatistics | - | Hashtable | Get statistics |
| Save-SiemConfig | ConfigPath, Config | Hashtable | Save configuration |
| Load-SiemConfig | ConfigPath | Hashtable | Load configuration |
| Save-SiemProfile | ProfileName, Config | Hashtable | Save named profile |
| Load-SiemProfile | ProfileName | Hashtable | Load named profile |
| Get-SiemProfiles | - | Array | List profiles |
| Remove-SiemProfile | ProfileName | Hashtable | Delete profile |
| Write-SiemLog | Message, Level | - | Write to log |

### Global Variables

| Variable | Type | Description |
|----------|------|-------------|
| $script:SiemConfig | Hashtable | Current configuration |
| $script:SiemStatistics | Hashtable | Forwarding statistics |
| $script:SiemEventQueue | ConcurrentQueue | Event queue |
| $script:SiemForwarderJob | Job | Background job object |
| $script:SiemConfigPath | String | Config file path |
| $script:SiemLogBuffer | List | In-memory log buffer |

## Best Practices

1. **Always test connection** before enabling forwarding
2. **Start with small batch sizes** and monitor performance
3. **Use event filters** to reduce noise and focus on important events
4. **Enable enrichment** selectively based on SIEM capabilities
5. **Save multiple profiles** for different environments
6. **Monitor statistics** regularly to ensure health
7. **Use HTTPS/TLS** for all production deployments
8. **Configure fallback** endpoint for high availability
9. **Review logs** when troubleshooting issues
10. **Secure credentials** using encrypted storage

## Support

For issues or questions:
1. Review this documentation
2. Check activity log in GUI
3. Review SIEM endpoint logs
4. Test with simple example first
5. Verify network connectivity
6. Check PowerShell version (requires 5.1+)

## Version History

- **v1.0.0** (2026-01-15): Initial release
  - Splunk HEC support
  - QRadar LEEF support
  - Elastic ECS support
  - Syslog RFC5424 support
  - REST API support
  - Event enrichment
  - Configuration profiles
  - GUI integration

## License

© 2026 GA-ASI. Internal use only.

---

**End of Documentation**
