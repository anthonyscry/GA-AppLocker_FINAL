# WinRM Setup Guide

WinRM (Windows Remote Management) is required for remote scanning and event collection.

## Domain Environments (Recommended)

Use the integrated WinRM GPO deployment:

```powershell
# Via GUI: Select WinRM → Deploy
# Or via script:
.\src\Utilities\Enable-WinRM-Domain.ps1
```

This creates a GPO named "Enable-WinRM" that configures WinRM and firewall rules domain-wide.

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

### Common Issues

| Issue | Solution |
|-------|----------|
| Access denied | Ensure admin credentials and WinRM access |
| WinRM connection failed | Run `Enable-PSRemoting -Force` on target |
| Firewall blocking | Enable Windows Remote Management rule |
| Certificate issues | Check HTTPS configuration or use HTTP |

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
