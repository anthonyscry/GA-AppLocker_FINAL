# GA-AppLocker Artifact Data Model Documentation

This document describes the standardized data structures used throughout the GA-AppLocker application for artifacts and rules.

---

## Artifact Data Structure

Artifacts represent executable files discovered during scanning. They contain metadata about the file including publisher, path, hash, and other properties.

### Standard Artifact Properties (Lowercase)

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `name` | string | Recommended | File name | `"notepad.exe"` |
| `path` | string | **Required** | Full file path | `"C:\Windows\System32\notepad.exe"` |
| `publisher` | string | Recommended | Publisher name from digital signature | `"Microsoft Corporation"` |
| `hash` | string | Optional | SHA256 hash of the file | `"A1B2C3D4..."` |
| `version` | string | Optional | File version | `"10.0.19041.1"` |
| `size` | long | Optional | File size in bytes | `215040` |
| `modifiedDate` | DateTime | Optional | Last modified date | `2023-01-15 10:30:00` |
| `fileType` | string | Optional | File type: EXE, DLL, MSI, Script, Unknown | `"EXE"` |

### Artifact Creation

```powershell
# Create a new artifact
$artifact = New-AppLockerArtifact -Name "app.exe" -Path "C:\Apps\app.exe" -Publisher "Contoso Inc."

# Result:
@{
    name      = "app.exe"
    path      = "C:\Apps\app.exe"
    publisher = "Contoso Inc."
    hash         = ""
    version      = ""
    size         = 0
    modifiedDate = <current datetime>
    fileType     = "Unknown"
    source       = "New-AppLockerArtifact"
    created      = <current datetime>
}
```

---

## Property Name Mapping

Different parts of the application use different property naming conventions. The `Convert-AppLockerArtifact` function handles conversion between these formats.

### Path Property Mappings

| Source Format | Property Names | Mapped To |
|---------------|----------------|------------|
| Module2 (RemoteScan) | `path` | `path` |
| GUI (WPF) | `FullPath`, `Path` | `path` |
| CSV Import | `FilePath`, `Path` | `path` |
| Standard | `path` | `path` |

### Name Property Mappings

| Source Format | Property Names | Mapped To |
|---------------|----------------|------------|
| Module2 (RemoteScan) | `name` | `name` |
| GUI (WPF) | `FileName`, `Name` | `name` |
| CSV Import | `FileName`, `Name` | `name` |
| Standard | `name` | `name` |

### Publisher Property Mappings

| Source Format | Property Names | Mapped To |
|---------------|----------------|------------|
| Module2 (RemoteScan) | `publisher` | `publisher` |
| GUI (WPF) | `Publisher`, `Vendor`, `Company`, `Signer` | `publisher` |
| CSV Import | `Publisher`, `PublisherName` | `publisher` |
| Standard | `publisher` | `publisher` |

### Hash Property Mappings

| Source Format | Property Names | Mapped To |
|---------------|----------------|------------|
| Module2 (RemoteScan) | `hash` | `hash` |
| GUI (WPF) | `Hash`, `SHA256` | `hash` |
| CSV Import | `Hash`, `SHA256` | `hash` |
| Standard | `hash` | `hash` |

---

## Rule Data Structure

Rules are generated from artifacts and define AppLocker policy rules.

### Rule Properties

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `type` | string | **Required** | Rule type: Publisher, Path, Hash, Imported | `"Publisher"` |
| `action` | string | **Required** | Action: Allow, Deny | `"Allow"` |
| `publisher` | string | For Publisher rules | Publisher name | `"Microsoft Corporation"` |
| `path` | string | For Path/Hash rules | File path or directory path | `"C:\Program Files\*"` |
| `fileName` | string | Optional | File name | `"notepad.exe"` |
| `hash` | string | For Hash rules | SHA256 hash | `"ABC123..."` |
| `xml` | string | For Imported rules | OuterXml from imported rule | `"<FilePublisherRule...>"` |

### Rule Creation Example

```powershell
# Publisher rule
$rule = New-PublisherRule -PublisherName "Microsoft" -Action "Allow" -UserOrGroupSid "S-1-1-0"

# Result:
@{
    type      = "Publisher"
    action    = "Allow"
    publisher = "Microsoft"
    userSid    = "S-1-1-0"
    xml       = "<FilePublisherRule...>"
}
```

---

## Module-Specific Artifact Formats

### Module2 (RemoteScan) Format

```powershell
@{
    name     = "app.exe"
    path     = "C:\Apps\app.exe"
    publisher = "Contoso Inc."
}
```

### GUI (WPF) Format

```powershell
[PSCustomObject]@{
    FileName = "app.exe"
    FullPath = "C:\Apps\app.exe"
    Publisher = "Contoso Inc."
    Hash = "ABC123..."
    Version = "1.0.0.0"
}
```

### CSV Import Format

```powershell
[PSCustomObject]@{
    FilePath = "C:\Apps\app.exe"
    Publisher = "Contoso Inc."
    SHA256 = "ABC123..."
}
```

---

## Artifact Conversion

The `Convert-AppLockerArtifact` function automatically handles property name mapping:

```powershell
# Convert from GUI format to Standard
$guiArtifact = [PSCustomObject]@{
    FileName = "app.exe"
    FullPath = "C:\Apps\app.exe"
    Publisher = "Contoso Inc."
}

$standardArtifact = Convert-AppLockerArtifact -Artifact $guiArtifact

# Result:
@{
    name      = "app.exe"
    path      = "C:\Apps\app.exe"
    publisher = "Contoso Inc."
    hash         = ""
    version      = ""
    size         = 0
    modifiedDate = <current datetime>
    fileType     = "Unknown"
    source       = "New-AppLockerArtifact"
    created      = <current datetime>
}
```

---

## Artifact Validation

The `Test-AppLockerArtifact` function validates artifacts before rule generation:

```powershell
# Validate artifact for Publisher rule
$validation = Test-AppLockerArtifact -Artifact $artifact -RuleType "Publisher"

# Result:
@{
    success               = $true  # Overall validation result
    valid                 = $true  # Same as success
    errors                = @()   # Array of error messages
    warnings              = @()   # Array of warning messages
    canCreatePublisherRule = $true  # Can create Publisher rule
    canCreatePathRule     = $true  # Can create Path rule
    canCreateHashRule     = $true  # Can create Hash rule
}
```

---

## Rule Validation

The `Test-AppLockerRules` function validates rules before export:

```powershell
# Validate rules for export
$validation = Test-AppLockerRules -Rules $rules

# Result:
@{
    success     = $true  # All rules are valid
    validRules  = @(...)  # Array of valid rules
    errorCount  = 0      # Number of errors found
    errors      = @()    # Array of error messages
    warningCount = 2      # Number of warnings
    warnings    = @("2 rules were invalid and excluded")
    totalCount  = 10     # Total number of rules
    validCount  = 8      # Number of valid rules
}
```

---

## UTF-16 Encoding Requirement

**IMPORTANT:** AppLocker policy XML files MUST be UTF-16 encoded (Unicode) to be accepted by Windows.

```powershell
# Correct: UTF-16 encoding
$xmlDoc = [xml]$xmlContent
$xws = [System.Xml.XmlWriterSettings]::new()
$xws.Encoding = [System.Text.Encoding]::Unicode
$xw = [System.Xml.XmlWriter]::Create($filePath, $xws)
$xmlDoc.Save($xw)
$xw.Close()

# Incorrect: UTF-8 encoding (will fail!)
$xmlContent | Out-File -FilePath $filePath -Encoding UTF8
```

---

## Quick Reference

### Creating Artifacts

```powershell
# From scratch
$artifact = New-AppLockerArtifact -Name "app.exe" -Path "C:\Apps\app.exe" -Publisher "Contoso"

# Converting from other format
$standard = Convert-AppLockerArtifact -Artifact $guiArtifact
```

### Validating Artifacts

```powershell
$validation = Test-AppLockerArtifact -Artifact $artifact -RuleType "Publisher"
if ($validation.success) {
    # Artifact is valid
}
```

### Validating Rules

```powershell
$validation = Test-AppLockerRules -Rules $rules
if ($validation.success) {
    # Export rules
}
```

---

## Functions Reference

| Function | Location | Description |
|----------|----------|-------------|
| `New-AppLockerArtifact` | Common.psm1 | Creates standardized artifact |
| `Convert-AppLockerArtifact` | Common.psm1 | Converts between formats |
| `Test-AppLockerArtifact` | Common.psm1 | Validates artifact properties |
| `Test-AppLockerRules` | GUI | Validates rules before export |
| `New-PublisherRule` | Module3 | Creates Publisher rule |
| `New-PathRule` | Module3 | Creates Path rule |
| `New-HashRule` | Module3 | Creates Hash rule |

---

## Best Practices

1. **Always use `Convert-AppLockerArtifact`** when importing artifacts from external sources
2. **Validate artifacts before rule generation** using `Test-AppLockerArtifact`
3. **Validate rules before export** using `Test-AppLockerRules`
4. **Use UTF-16 encoding** for all AppLocker XML exports
5. **Use lowercase property names** (`name`, `path`, `publisher`) for new code
6. **Handle the "Unknown" publisher** - many legitimate files are unsigned

---

## Changelog

- **v1.2.5** - Added standardized artifact data model
- **v1.2.5** - Added artifact conversion functions
- **v1.2.5** - Added validation functions for artifacts and rules
- **v1.2.5** - Fixed UTF-8 to UTF-16 encoding issue in GUI export
