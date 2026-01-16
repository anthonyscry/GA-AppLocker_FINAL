# SIEM Integration - Quick Start Guide

## 5-Minute Setup

### Step 1: Install the Integration (1 minute)

```powershell
cd C:\projects\GA-AppLocker_FINAL\build
.\Install-SIEM-Integration.ps1
```

### Step 2: Launch the GUI (30 seconds)

```powershell
.\GA-AppLocker-GUI-WPF.ps1
```

### Step 3: Configure Your SIEM (2 minutes)

1. Click **"SIEM Integration"** in the sidebar
2. Select your **SIEM Type** from dropdown
3. Enter **Server/Endpoint** hostname
4. Configure **Port** (auto-fills based on SIEM type)
5. Select **Protocol** (HTTPS recommended)
6. Choose **Auth Type** and enter credentials
7. Enable **SSL/TLS** (recommended)

### Step 4: Test Connection (30 seconds)

Click **"Test Connection"** button

- ✅ Green = Success
- ❌ Red = Check your settings

### Step 5: Save Configuration (30 seconds)

Click **"Save Configuration"** button

Configuration saved encrypted to:
`$env:LOCALAPPDATA\GA-AppLocker\SIEM-Config.xml`

### Step 6: Start Forwarding (30 seconds)

1. Check **"Enable Event Forwarding"** checkbox
2. Click **"Start Forwarding"** button
3. Watch statistics update in real-time!

---

## Configuration Templates

### Splunk
```
SIEM Type:    Splunk (HEC)
Server:       splunk.example.com
Port:         8088
Protocol:     HTTPS
Auth Type:    Token/Bearer
Token:        your-splunk-hec-token
SSL/TLS:      ✅ Enabled
```

### IBM QRadar
```
SIEM Type:    IBM QRadar (LEEF)
Server:       qradar.example.com
Port:         514
Protocol:     TCP
Auth Type:    Token/Bearer
Token:        your-qradar-token
SSL/TLS:      ⚪ Optional
```

### Elastic
```
SIEM Type:    Elastic (Elasticsearch)
Server:       elastic.example.com
Port:         9200
Protocol:     HTTPS
Auth Type:    Token/Bearer
Token:        your-elastic-api-key
SSL/TLS:      ✅ Enabled
```

### Syslog
```
SIEM Type:    Syslog (RFC5424)
Server:       syslog.example.com
Port:         514
Protocol:     TCP or UDP
Auth Type:    None
SSL/TLS:      ⚪ Optional
```

---

## Common Commands

### Test Manually (PowerShell)
```powershell
# Load module
. C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1

# Test connection
Test-SiemConnection

# Get statistics
Get-ForwarderStatistics

# Start forwarding
Start-EventForwarder

# Stop forwarding
Stop-EventForwarder
```

### Send Historical Events
```powershell
# Load module
. C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1

# Get events
$events = Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 100

# Send batch
Send-BatchEvents -Events $events
```

---

## Troubleshooting

### Connection Fails
- ✅ Check server name and port
- ✅ Verify firewall allows connection
- ✅ Confirm credentials are correct
- ✅ Try: `Test-NetConnection server -Port port`

### No Events Sent
- ✅ Check event filters (may be too restrictive)
- ✅ Verify AppLocker log exists
- ✅ Review activity log for errors

### High Failure Rate
- ✅ Reduce batch size (try 50)
- ✅ Increase retry delay (try 10 seconds)
- ✅ Check network stability

---

## File Locations

```
Main Module:     C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-SIEM-Integration.ps1
Config File:     $env:LOCALAPPDATA\GA-AppLocker\SIEM-Config.xml
Profiles:        $env:LOCALAPPDATA\GA-AppLocker\SIEM-Profiles\
Log File:        $env:LOCALAPPDATA\GA-AppLocker\SIEM-Integration.log
```

---

## Quick Reference

| What | Where |
|------|-------|
| GUI Panel | Click "SIEM Integration" in sidebar |
| Test Connection | Click "Test Connection" button |
| Save Config | Click "Save Configuration" button |
| Load Config | Click "Load Configuration" button |
| Start/Stop | Click "Start Forwarding" button |
| View Stats | Statistics dashboard (auto-updates) |
| View Log | Activity log at bottom of panel |

---

## Keyboard Shortcuts (In GUI)

| Action | Shortcut |
|--------|----------|
| Navigate to SIEM | Click "SIEM Integration" button |
| Test connection | Alt+T (when panel has focus) |
| Save config | Alt+S (when panel has focus) |
| Start forwarding | Alt+F (when panel has focus) |

---

## Tips

💡 **Save Multiple Profiles**
- Create different configs for Dev, Test, Production
- Use "Save Configuration" → Enter profile name
- Load with "Load Configuration" dropdown

💡 **Optimize Performance**
- Start with batch size of 100
- Increase if network is stable
- Decrease if experiencing failures

💡 **Use Event Filters**
- Only forward what you need
- Set severity threshold to reduce noise
- Use exclude patterns for known safe apps

💡 **Enable Enrichment**
- Host metadata: Always safe, low overhead
- AD info: Useful for user context
- Threat intel: Adds security value

---

## Need Help?

📖 **Full Documentation**: `SIEM-INTEGRATION-README.md`
📊 **Implementation Details**: `SIEM-IMPLEMENTATION-SUMMARY.md`
🔧 **Troubleshooting**: See SIEM-INTEGRATION-README.md section

---

## Status Indicators

| Color | Meaning |
|-------|---------|
| 🟢 Green | Running/Connected |
| ⚪ Gray | Stopped |
| 🔴 Red | Error/Failed |

---

## Event Types

| ID | Type | Description |
|----|------|-------------|
| 8002 | Allowed | Application allowed to run |
| 8003 | Audited | Application audited (would be allowed/blocked) |
| 8004 | Blocked | Application blocked from running |

---

## Severity Levels

| Level | Description |
|-------|-------------|
| All | Forward all events |
| Critical | Only blocked events |
| Error | Blocked and audited events |
| Warning | Audited and allowed events |
| Info | All events |

---

**You're ready to forward AppLocker events to your SIEM! 🚀**
