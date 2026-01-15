# GA-AppLocker

**Author:** Tony Tran, ISSO, GA-ASI
**Version:** 1.2.4

Simplified AppLocker deployment toolkit for Windows 11/Server 2019+. No external dependencies required.

---

## Download

> **📦 Download the latest release package:**
> **[GA-AppLocker Bundle Package](<!-- INSERT_BUNDLE_LINK_HERE -->)**
>
> _(Update this link with the actual bundle package location)_

The bundle includes:
- `GA-AppLocker.exe` - Standalone GUI executable
- All PowerShell scripts and modules
- Documentation and templates
- Test fixtures and examples

---

## Quick Start (Primary Method)

### Run the Portable Executable

The **recommended way** to use GA-AppLocker is the standalone portable executable in the root folder:

```
GA-AppLocker.exe    <-- Just double-click this!
```

**That's it!** The GUI provides access to all features with no setup required.

> **Note:** The EXE automatically detects scripts in the `src/` directory. For full functionality, keep the folder structure intact.

---

<details>
<summary><strong>Features</strong></summary>

### Core Workflow
- **Scan** - Collect software inventory from remote computers via WinRM
- **Generate** - Create AppLocker policies from scan data
- **Merge** - Combine multiple policy files with SID replacement and deduplication
- **Validate** - Check policies for issues before deployment

### Analysis
- **Compare** - Compare software inventories between systems
- **Events** - Collect AppLocker audit events (8003/8004) with incremental collection
- **Impact Analysis** - Pre-deployment risk assessment
- **Rule Health** - Detect broken, unused, or conflicting rules

### Compliance & Audit
- **CORA Evidence** - Generate audit-ready evidence packages for compliance reviews
- **Compliance Reports** - Documentation for inspectors (NIST, HIPAA, PCI-DSS)

### Policy Lifecycle (v1.2.0)
- **Version Control** - Git-like policy versioning with rollback
- **Industry Templates** - Pre-built compliance templates (NIST, HIPAA, PCI-DSS)
- **Phase Advancement** - Automated readiness assessment for phase progression

### Software Lists
- Create and manage curated software allowlists
- Import from scans, policies, or folders
- Add trusted publishers (Microsoft, Adobe, Google, 19+ vendors)
- Self-service whitelist request workflow

### AD Management
- Create AppLocker OUs and security groups
- Export/import group memberships
- Export computer lists from AD
- Deploy WinRM via GPO

### GUI Features
- **Embedded Help System** - Comprehensive in-app documentation (F1)
- **Keyboard shortcuts** - Ctrl+1-8 for navigation, Ctrl+Q quick workflow, Ctrl+R refresh, F1 for help
- **Operation cancellation** - Cancel long-running operations
- **Button state management** - Prevents conflicts during operations
- **Progress indicators** - Visual feedback during file processing
- **CORA Evidence page** - Generate compliance packages directly from GUI

</details>

---

<details>
<summary><strong>Common Workflows</strong></summary>

### Enterprise Deployment (Build Guide Mode)

**Step 1: Scan target computers**
```powershell
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList .\ADManagement\computers.csv
```

**Step 2: Generate Phase 1 policy**
```powershell
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate `
    -ScanPath .\Scans\Scan-20260109 `
    -TargetType Workstation -DomainName CONTOSO -Phase 1
```

**Step 3: Deploy via GPO**
1. Open Group Policy Management
2. Create/link GPO to target OUs
3. Import generated XML under Application Control Policies
4. Keep in **Audit mode** initially

**Step 4: Monitor Events (14+ days)**
```powershell
# Collect AppLocker audit events
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv

# Incremental collection (only new events since last run)
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Events -ComputerList .\ADManagement\computers.csv -SinceLastRun
```
- Event ID 8003: Allowed
- Event ID 8004: Would have been blocked

**Step 5: Generate CORA Evidence (for audits)**
```powershell
.\src\Utilities\New-CORAEvidence.ps1 -OutputPath .\CORA-Evidence
```

**Step 6: Advance through phases**
```powershell
-Phase 2  # EXE + Script
-Phase 3  # EXE + Script + MSI
-Phase 4  # All including DLL
```

### Quick Deployment (Simplified Mode)

For testing, labs, or standalone machines:

```powershell
# Generate simple policy
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -Simplified

# Apply locally
Set-AppLockerPolicy -XmlPolicy .\Outputs\AppLockerPolicy-Simplified.xml
```

</details>

---

<details>
<summary><strong>Policy Deployment Best Practices</strong></summary>

### Pre-Deployment

| Practice | Why It Matters |
|----------|----------------|
| **Inventory first** | Scan 10-20 representative machines before creating policies |
| **Include edge cases** | Scan developer workstations, kiosks, and specialty systems |
| **Document exceptions** | Track which apps need special rules and why |
| **Baseline your environment** | Export current software inventory for comparison |

### Deployment Strategy

| Practice | Why It Matters |
|----------|----------------|
| **Always start in Audit mode** | Never enforce without 14+ days of event data |
| **Phase deployment** | Start with EXE only (Phase 1), add Script/MSI/DLL progressively |
| **Pilot group first** | Test on 5-10 machines before wider rollout |
| **Separate GPOs by phase** | Easier rollback if issues arise |
| **Have a kill switch** | Keep an emergency GPO that disables AppLocker entirely |

### Rule Design

| Practice | Why It Matters |
|----------|----------------|
| **Prefer publisher rules** | More resilient to updates than hash rules |
| **Avoid overly broad wildcards** | `O=*` trusts everyone - be specific |
| **Deny user-writable paths** | Block %TEMP%, Downloads, AppData explicitly |
| **Block LOLBins** | Deny mshta.exe, wscript.exe, cscript.exe, etc. |
| **Use proper principal scoping** | Don't use "Everyone" for publisher rules |

### Monitoring & Maintenance

| Practice | Why It Matters |
|----------|----------------|
| **Collect events regularly** | Run event collection weekly during rollout |
| **Review UniqueBlockedApps.csv** | Identify legitimate apps being blocked |
| **Update policies for new software** | Add rules before deploying new apps |
| **Test updates in audit mode** | Policy changes can break things |
| **Document all policy changes** | Use version control for policies |

### Common Mistakes to Avoid

| Mistake | Impact |
|---------|--------|
| Enforcing without audit period | Users locked out, helpdesk flooded |
| Starting with DLL rules | High chance of breaking applications |
| No rollback plan | Extended outages when issues occur |
| Trusting all signed code | Malware can be signed too |
| Ignoring script rules | PowerShell/VBScript bypass risk |

</details>

---

<details>
<summary><strong>Directory Structure</strong></summary>

```
GA-AppLocker/
├── GA-AppLocker.exe              # Standalone executable (RECOMMENDED)
├── GA-AppLocker.psd1             # PowerShell module manifest (v1.2.0)
├── GA-AppLocker.psm1             # Root module
├── README.md
├── LICENSE
├── build/                        # Build scripts
│   ├── Build-AppLocker.ps1       # Full build orchestrator
│   ├── Build-Executable.ps1      # CLI executable compilation
│   ├── Build-GUI.ps1             # GUI executable compilation
│   └── Publish-ToGallery.ps1     # PowerShell Gallery publishing
├── src/
│   ├── Core/                     # Core workflow scripts (6 scripts)
│   ├── GUI/                      # WPF GUI application
│   └── Utilities/                # 12 utility scripts + 5 modules
├── Tests/                        # Pester tests (7 test files)
├── ADManagement/                 # AD-related files (computers.csv, users.csv)
├── assets/                       # Icons and images
└── docs/                         # Additional documentation
```

</details>

---

<details>
<summary><strong>Requirements</strong></summary>

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 11 / Server 2019+ |
| **PowerShell** | 5.1+ |
| **For Remote Scans** | WinRM enabled on target computers |
| **For AD Features** | Domain Admin credentials |

</details>

---

<details>
<summary><strong>Alternative: PowerShell Scripts (Backup Method)</strong></summary>

If you prefer command-line, need to customize behavior, or the EXE doesn't work, use the PowerShell scripts directly from the `src/Core/` folder.

### First-Time Setup

```powershell
# Set execution policy (allows local scripts)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Unblock downloaded files
Get-ChildItem -Path "C:\GA-AppLocker" -Recurse -Include *.ps1,*.psm1 | Unblock-File
```

### Interactive Mode

```powershell
.\src\Core\Start-AppLockerWorkflow.ps1
```

### Direct Mode Examples

```powershell
# Scan remote computers
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Scan -ComputerList .\ADManagement\computers.csv

# Generate policy from scan data
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Generate -ScanPath .\Scans -Simplified

# Validate a policy file
.\src\Core\Start-AppLockerWorkflow.ps1 -Mode Validate -PolicyPath .\policy.xml
```

</details>

---

<details>
<summary><strong>WinRM Setup (Required for Remote Scans)</strong></summary>

### Domain Environments (Recommended)

Use the integrated WinRM GPO deployment:

```powershell
# Via GUI: Select WinRM → Deploy
# Or via script:
.\src\Utilities\Enable-WinRM-Domain.ps1
```

This creates a GPO named "Enable-WinRM" that configures WinRM and firewall rules domain-wide.

### Individual Machines

```powershell
Enable-PSRemoting -Force
```

### Workgroup/Non-Domain

```powershell
# Trust specific machines
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "PC01,PC02"

# Test connectivity
Test-WSMan -ComputerName "TARGET-PC"
```

</details>

---

<details>
<summary><strong>Building the EXE</strong></summary>

To rebuild the standalone executable:

```powershell
# Full build with validation, tests, and packaging
.\build\Build-AppLocker.ps1

# Build just the GUI executable
.\build\Build-GUI.ps1

# Build the CLI executable (embeds all scripts)
.\build\Build-Executable.ps1

# Run validation only (lint + tests)
.\build\Invoke-LocalValidation.ps1
```

</details>

---

<details>
<summary><strong>Troubleshooting</strong></summary>

### Remote Scan Failures

Use the diagnostic tool:
```powershell
.\src\Core\Start-AppLockerWorkflow.ps1
# Select [D] Diagnostic → [1] Connectivity
```

Or directly:
```powershell
.\src\Utilities\Test-AppLockerDiagnostic.ps1 -ComputerName "TARGET-PC"
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Access denied | Ensure admin credentials and WinRM access |
| WinRM connection failed | Run `Enable-PSRemoting -Force` on target |
| Scripts blocked | Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| EXE shows "Scripts not found" | Place EXE in same folder as PowerShell scripts |

</details>

---

## Documentation

Detailed documentation is available in the `docs/` folder:

| Document | Description |
|----------|-------------|
| [Rule Generation](docs/Rule-Generation.md) | How policies are built (Simplified vs Build Guide mode) |
| [PowerShell Usage](docs/PowerShell-Usage.md) | Command-line reference and examples |
| [WinRM Setup](docs/WinRM-Setup.md) | Remote management configuration |
| [Advanced Features](docs/Advanced-Features.md) | Monitoring, templates, version control |
| [Codebase Best Practices](docs/Codebase-Best-Practices.md) | Security patterns and coding standards |

---

## Support

- **Issues:** [GitHub Issues](../../issues)
- **Development Notes:** See `CLAUDE.md`

---

## Official AppLocker Documentation

- [AppLocker Overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview)
- [AppLocker Technical Reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-technical-reference)
- [AppLocker Policy Design Guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-policies-design-guide)
- [AppLocker Deployment Guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-policies-deployment-guide)
- [Understanding AppLocker Rule Behavior](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/understanding-applocker-rule-behavior)
- [AppLocker Event Log Reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations)

---

## License

Internal use only - GA-ASI
