# WinRM Setup Guide

WinRM (Windows Remote Management) is required for remote scanning and event collection.

## Domain Environments (Recommended)

Use the integrated WinRM GPO deployment:

```powershell
# Via GUI: Select WinRM → Deploy
# Or via script:
.\src\Utilities\Enable-WinRM-Domain.ps1
```

This creates a GPO named "Enable-WinRM" that configures:
- WinRM service settings (AllowAutoConfig, IP filters)
- WinRM service set to Automatic startup
- Windows Firewall rules for ports 5985 (HTTP) and 5986 (HTTPS)
- Startup script that ensures firewall rules are applied

### GPO Firewall Configuration

The GPO includes firewall rules via two methods for maximum compatibility:

1. **Registry-based rules** - Applied via Group Policy registry settings
2. **Startup script** - Creates firewall rules using `netsh advfirewall` on each boot

The startup script (`Configure-WinRM-Firewall.cmd`) automatically:
- Creates inbound rules for WinRM HTTP (5985) and HTTPS (5986)
- Starts the WinRM service if not running
- Runs `winrm quickconfig` if no listener exists

### After GPO Deployment

After creating the GPO and running `gpupdate /force`, verify on clients:

```powershell
# Check firewall rules
netsh advfirewall firewall show rule name="WinRM-HTTP-In-GPO"
netsh advfirewall firewall show rule name="WinRM-HTTPS-In-GPO"

# Check WinRM service
Get-Service WinRM | Select Status, StartType

# Check WinRM listener
winrm enumerate winrm/config/listener
```

## Individual Machines

```powershell
Enable-PSRemoting -Force
```

## Workgroup/Non-Domain

```powershell
# Trust specific machines
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "PC01,PC02"

# Test connectivity
Test-WSMan -ComputerName "TARGET-PC"
```

## Troubleshooting

### Test Connectivity

```powershell
# Test WinRM
Test-WSMan -ComputerName "TARGET-PC"

# Test PowerShell remoting
Enter-PSSession -ComputerName "TARGET-PC"
```

### Manual Firewall Fix

If firewall rules aren't applying via GPO, run on the target machine:

```powershell
# Create firewall rules manually
netsh advfirewall firewall add rule name="WinRM-HTTP-In" dir=in action=allow protocol=tcp localport=5985 profile=domain,private enable=yes
netsh advfirewall firewall add rule name="WinRM-HTTPS-In" dir=in action=allow protocol=tcp localport=5986 profile=domain,private enable=yes

# Restart WinRM
Restart-Service WinRM

# Or run full quickconfig
winrm quickconfig -force
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Access denied | Ensure admin credentials and WinRM access |
| WinRM connection failed | Run `Enable-PSRemoting -Force` on target |
| Firewall blocking | Run `netsh advfirewall firewall add rule` commands above |
| Certificate issues | Check HTTPS configuration or use HTTP |
| Listener not created | Run `winrm quickconfig -force` on target |
| GPO firewall rules not applying | Reboot target machine to trigger startup script |

### Use the Diagnostic Tool

```powershell
.\src\Utilities\Test-AppLockerDiagnostic.ps1 -ComputerName "TARGET-PC"
```

This checks:
- Network connectivity
- WinRM service status
- Authentication
- AppLocker service status
- Event log access
