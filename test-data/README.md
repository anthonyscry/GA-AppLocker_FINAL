# Test Data for GA-AppLocker

This folder contains mock artifact data for testing the GA-AppLocker application.

## Contents

### /scans
Contains simulated artifact scan results from 3 different computer types:

1. **DC01_Scan_2024-01-15_09-30-00.csv** - Domain Controller
   - Windows system tools
   - Active Directory management tools
   - Group Policy management console
   - 7 artifacts

2. **SERVER01_Scan_2024-01-15_10-15-00.csv** - Member Server
   - SQL Server components
   - IIS/Web server tools
   - Common server utilities (7-Zip, Notepad++)
   - 8 artifacts

3. **WORKSTATION01_Scan_2024-01-15_11-00-00.csv** - End User Workstation
   - Web browsers (Chrome, Edge, Firefox)
   - Microsoft Office applications
   - Collaboration tools (Teams, Slack, Zoom, OneDrive)
   - 11 artifacts

**Total: 26 artifacts across 3 assets**

## CSV Format

Each scan file contains the following columns:
- **Name**: Executable filename
- **Path**: Full file path
- **Publisher**: Code signing certificate information
- **Hash**: SHA256 file hash
- **Version**: File version
- **Size**: File size in bytes
- **ModifiedDate**: Last modified timestamp
- **FileType**: EXE, MSI, MSC, etc.

## Usage

1. Copy scan files to `C:\GA-AppLocker\Scans\` on your test system
2. Use the Rule Generator to import these artifacts
3. Generate AppLocker rules from the imported data
4. Test export/import to GPO functionality

## Notes

- Hash values are simulated and not real file hashes
- Publisher information matches typical Microsoft and third-party signing certificates
- File sizes are approximate based on real-world values
