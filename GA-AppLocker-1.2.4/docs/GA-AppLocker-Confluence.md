# GA-AppLocker - AppLocker Policy Deployment Toolkit

{toc:printable=true|style=square|minLevel=1|maxLevel=3}

---

## Overview

**GA-AppLocker** is an internal toolkit for deploying Windows AppLocker policies across the enterprise. It simplifies the process of scanning computers, generating policies, and managing software allowlists.

| | |
|---|---|
| **Author** | Tony Tran, ISSO |
| **Department** | Information Security |
| **Version** | 1.2.3 |
| **Last Updated** | January 2026 |

---

## Download

{info:title=Download Link}
**📦 Bundle Package:** [GA-AppLocker Bundle](<!-- INSERT_BUNDLE_LINK_HERE -->)

_(Update this link with the actual bundle package location)_
{info}

The bundle package includes:
- `GA-AppLocker.exe` - Standalone GUI executable
- All PowerShell scripts and modules
- Documentation and templates
- Test fixtures and examples

---

## Quick Start

{info:title=Recommended Method}
Download and run the **GA-AppLocker.exe** GUI application. No installation or setup required.
{info}

### Option 1: GUI Application (Recommended)

1. Download the bundle package from the link above
2. Extract to a folder (e.g., `C:\GA-AppLocker`)
3. Double-click `GA-AppLocker.exe` to launch

The GUI provides point-and-click access to all features.

### Option 2: PowerShell Scripts

For automation or advanced users:

```powershell
.\Start-AppLockerWorkflow.ps1
```

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | Windows 11 / Windows Server 2019+ |
| PowerShell | Version 5.1 or higher |
| Network | WinRM enabled on target computers (for remote scans) |
| Permissions | Local admin on scanning computer; domain admin for AD features |

---

## Features

### Core Workflow

| Feature | Description |
|---------|-------------|
| **Scan** | Collect software inventory from remote computers via WinRM |
| **Generate** | Create AppLocker policies from scan data |
| **Merge** | Combine multiple policy files with SID replacement |
| **Validate** | Check policies for errors before deployment |

### Analysis Tools

| Feature | Description |
|---------|-------------|
| **Compare** | Compare software inventories between systems to identify drift |
| **Events** | Collect AppLocker audit events (Event IDs 8003/8004) with incremental collection support |

### Compliance & Audit

| Feature | Description |
|---------|-------------|
| **CORA Evidence** | Generate audit-ready evidence packages for compliance reviews (NIST, HIPAA, PCI-DSS) |
| **Compliance Reports** | Consolidated documentation package for auditors and inspectors |

### Management

| Feature | Description |
|---------|-------------|
| **Software Lists** | Create and manage curated software allowlists |
| **AD Integration** | Create AppLocker OUs, security groups, and deploy WinRM GPO |

### GUI Features (v1.2.0+)

| Feature | Description |
|---------|-------------|
| **Keyboard Shortcuts** | Ctrl+1-8 for navigation, Ctrl+Q quick workflow, Ctrl+R refresh, F1 for help |
| **Operation Cancellation** | Cancel button for long-running operations |
| **Progress Indicators** | Visual feedback during XML validation and file processing |
| **Button State Management** | Prevents conflicts during operations |
| **CORA Evidence Page** | Generate compliance packages directly from the GUI (Ctrl+8) |
| **Compact UI** | Streamlined layout with consistent styling and reduced spacing |

### Advanced Features (v1.1.0+)

| Feature | Description |
|---------|-------------|
| **Policy Version Control** | Git-like versioning with branch support |
| **Industry Templates** | Pre-built policies for Healthcare, Financial, Government, etc. |
| **Phase Advancement** | Automatic readiness checking for next deployment phase |
| **Rule Health Checking** | Detect broken paths, expired certificates, unused rules |
| **Whitelist Requests** | Self-service request workflow with approvals |
| **Continuous Monitoring** | Scheduled event collection with webhook alerts |
| **GPO Export** | Export to GPO, SCCM, Intune, or registry formats |
| **Impact Analysis** | Pre-deployment risk assessment |

---

## Deployment Workflow

{panel:title=Enterprise Deployment Steps|borderStyle=solid}

### Phase 1: Preparation

1. **Enable WinRM** on target computers
   - Use the built-in GPO deployment: GUI → WinRM → Deploy
   - Or manually: `Enable-PSRemoting -Force`

2. **Create computer list**
   - Export from AD or create CSV with `ComputerName` column

### Phase 2: Scanning

1. Launch GA-AppLocker GUI or run:
   ```powershell
   .\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList .\computers.csv
   ```

2. Review scan results in `.\Scans\` folder

### Phase 3: Policy Generation

1. Generate policy in **Audit mode**:
   ```powershell
   .\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -Phase 1
   ```

2. Start with Phase 1 (EXE rules only)

### Phase 4: GPO Deployment

1. Open Group Policy Management Console
2. Create new GPO or edit existing
3. Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Application Control Policies → AppLocker
4. Import the generated XML policy
5. Set enforcement to **Audit only**
6. Link GPO to pilot OU

### Phase 5: Monitoring

{warning:title=Critical}
Monitor audit events for **minimum 14 days** before enforcing!
{warning}

- **Event ID 8003**: Application allowed
- **Event ID 8004**: Application would have been blocked

Collect events using:
```powershell
# Standard collection
.\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\computers.csv

# Incremental collection (only new events since last run)
.\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\computers.csv -SinceLastRun
```

### Phase 5b: Generate CORA Evidence (for audits)

{tip:title=Audit Preparation}
Use the CORA Evidence Generator to create audit-ready documentation packages:
```powershell
.\src\Utilities\New-CORAEvidence.ps1 -OutputPath .\CORA-Evidence
```

Or via GUI: Navigate to **CORA Evidence** (Ctrl+8) and click Generate.
{tip}

The CORA package includes:
- Executive summary
- Policy inventory
- Rule analysis
- Compliance assessment
- System configuration details

### Phase 6: Enforcement

After confirming no critical applications are blocked:

1. Update GPO enforcement mode from "Audit only" to "Enforce rules"
2. Progress through phases:
   - Phase 2: Add Script rules
   - Phase 3: Add MSI rules
   - Phase 4: Add DLL rules (audit 14+ days first!)

{panel}

---

## WinRM Configuration

### Domain Environment (GPO Method)

The toolkit can deploy WinRM configuration via GPO:

1. Run GA-AppLocker as Domain Admin on a Domain Controller
2. Select **WinRM → Deploy**
3. GPO "Enable-WinRM" will be created and linked

**GPO Settings Applied:**
- WinRM service set to Automatic
- WinRM listener on port 5985
- Firewall rules for WinRM

### Standalone Machines

```powershell
Enable-PSRemoting -Force
```

### Workgroup Environments

On the scanning computer, trust target machines:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "PC01,PC02,PC03"
```

---

## Troubleshooting

### Connection Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Access denied" | Insufficient permissions | Use domain admin credentials |
| "WinRM cannot complete" | WinRM not enabled | Run `Enable-PSRemoting -Force` on target |
| "Cannot find computer" | DNS/network issue | Verify computer name and connectivity |

### Diagnostic Tool

Use the built-in diagnostic:

```powershell
.\utilities\Test-AppLockerDiagnostic.ps1 -ComputerName "TARGET-PC"
```

This tests:
- Ping connectivity
- DNS resolution
- WinRM connectivity
- Remote command execution

---

## Best Practices

{tip:title=Recommended Practices}
1. **Always start in Audit mode** - Never deploy in Enforce mode initially
2. **Monitor for 14+ days** - Collect sufficient event data
3. **Phase deployment** - Start with EXE rules, then add Script, MSI, DLL
4. **Pilot first** - Test on a small group before enterprise rollout
5. **Document exceptions** - Track all software additions and approvals
6. **Have rollback plan** - Maintain a GPO to disable AppLocker if needed
{tip}

---

## File Locations

| Path | Description |
|------|-------------|
| `.\Scans\` | Remote scan output data |
| `.\Outputs\` | Generated policies |
| `.\Events\` | Collected AppLocker events |
| `.\SoftwareLists\` | Curated software allowlists |
| `.\ADManagement\` | Computer lists and AD exports |
| `.\CORA-Evidence\` | Generated CORA compliance packages |

---

## Support

| Resource | Location |
|----------|----------|
| Source Code | Internal Git repository |
| Issues | Contact Information Security team |
| Author | Tony Tran, ISSO |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.2.3 | January 2026 | GUI cleanup: consolidated XAML styles, compact UI with reduced margins/spacing, code organization improvements |
| 1.2.2 | January 2026 | Bug fixes for test compatibility (PowerShell 5.1), build script improvements, download bundle placeholder |
| 1.2.1 | January 2026 | CORA Evidence Generator for compliance audits, incremental event collection (-SinceLastRun), GUI CORA page with Ctrl+8 shortcut |
| 1.2.0 | January 2026 | Policy version control, industry templates, phase advancement, rule health checking, whitelist request workflow, GUI improvements (keyboard shortcuts, cancellation, progress indicators) |
| 1.1.0 | January 2026 | Continuous monitoring, GPO export formats, impact analysis, credential caching |
| 1.0.0 | January 2026 | Initial release with GUI |

---

{note:title=Document Classification}
**INTERNAL USE ONLY** - This document contains internal operational procedures.
{note}
