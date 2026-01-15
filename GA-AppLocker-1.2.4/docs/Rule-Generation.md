# Rule Generation Logic

The policy generator has two modes with fundamentally different approaches.

## Simplified Mode

**Purpose:** Quick deployment for testing, labs, or small environments.

**Data Sources** (can combine multiple):
- **Scan Data** - Executables.csv from remote scans
- **Software Lists** - Curated JSON allowlists
- **Event Data** - UniqueBlockedApps.csv from audit mode

### Rule Generation Flow

```
1. LOAD DATA
   ├── Scan Data → Extract signed executables + writable directories
   ├── Software List → Load approved items
   └── Event Data → Load blocked apps from audit mode

2. BUILD PUBLISHER RULES (deduplicated)
   ├── From scan: signed executables → extract publisher info
   └── From events: blocked apps with publisher info

   Granularity options (-RuleGranularity):
   ├── Publisher:              O=ACME CORP*           (broadest)
   ├── PublisherProduct:       O=ACME* + ProductName
   └── PublisherProductBinary: O=ACME* + Product + Binary.exe (most specific)

3. BUILD HASH RULES (if -IncludeHashRules)
   ├── Unsigned files in writable directories
   └── Unsigned blocked events

4. BUILD DENY RULES (if -IncludeDenyRules)
   └── LOLBins: mshta, wscript, cscript, MSBuild, etc.

5. GENERATE XML
   ├── Admin full access (path: *)
   ├── Default paths: %WINDIR%\*, %PROGRAMFILES%\*
   ├── Publisher rules for target user
   ├── Hash rules for target user
   └── Deny rules for target user
```

### Default Rules Created

| Rule | Target | Action |
|------|--------|--------|
| `*` (all files) | Administrators | Allow |
| `%WINDIR%\*` | Target User | Allow |
| `%PROGRAMFILES%\*` | Target User | Allow |
| Publisher rules | Target User | Allow |
| Hash rules | Target User | Allow |
| LOLBins | Target User | Deny |

---

## Build Guide Mode (Enterprise)

**Purpose:** Production deployments with proper principal scoping.

**Core Principle:**
> *"Allow who may run trusted code, deny where code can never run"*

### Principal Hierarchy

```
MANDATORY PRINCIPALS (Windows accounts):
├── NT AUTHORITY\SYSTEM
├── NT AUTHORITY\LOCAL SERVICE
├── NT AUTHORITY\NETWORK SERVICE
└── BUILTIN\Administrators

CUSTOM AD GROUPS (created by AD Setup):
├── DOMAIN\AppLocker-Admins        → Full vendor access
├── DOMAIN\AppLocker-StandardUsers → Path-based only
├── DOMAIN\AppLocker-ServiceAccounts → Vendor publisher only
└── DOMAIN\AppLocker-Installers    → MSI access
```

### Phased Deployment

| Phase | Rule Collections | Risk Level |
|-------|-----------------|------------|
| 1 | EXE only | Lowest - start here |
| 2 | EXE + Script | High bypass risk |
| 3 | EXE + Script + MSI | Test deployments |
| 4 | All + DLL | Audit 14+ days first! |

### Phase 1 EXE Rules

```
Microsoft Publisher → Allow for:
  SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Administrators
  (NOT Everyone - key security principle)

AppLocker-Admins:
  ├── Microsoft Publisher → Allow
  └── Vendor Publishers → Allow

AppLocker-ServiceAccounts:
  └── Vendor Publishers → Allow (no path rules)

AppLocker-StandardUsers:
  ├── %WINDIR%\* → Allow
  └── %PROGRAMFILES%\* → Allow
  (No vendor publisher - must use approved paths)

DENY (Everyone):
  ├── %USERPROFILE%\Downloads\*
  ├── %APPDATA%\*
  ├── %LOCALAPPDATA%\Temp\*
  ├── %TEMP%\*
  └── %USERPROFILE%\Desktop\*
```

### Phase 2+ Script Rules

Scripts are the highest bypass risk - very restricted:
- SYSTEM/Services → Microsoft-signed only
- Admins → Microsoft-signed only
- ServiceAccounts → Vendor-signed only
- StandardUsers → **NO script access**

### Phase 3+ MSI Rules

- SYSTEM/Admins → Microsoft installers
- AppLocker-Installers → Microsoft + Vendors
- Windows Installer cache allowed

### Phase 4 DLL Rules

Most restrictive - can break applications if not thoroughly tested. Only enabled if `-DLLEnforcement` is set to `AuditOnly` or `Enabled`.

---

## Rule Processing Priority

AppLocker processes rules in this order:
1. **Deny rules** (highest priority - evaluated first)
2. **Allow rules** (only if not denied)

This is why deny rules for Downloads/Temp work even when path allows exist - deny always wins.
