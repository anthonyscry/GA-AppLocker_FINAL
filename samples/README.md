# GA-AppLocker Sample Artifacts

This folder contains sample artifact files for testing the Rule Generator import functionality.

## Files

### artifacts-sample.csv
CSV format with columns: `name`, `publisher`, `path`, `hash`

Contains 20 sample executable entries including:
- Browsers (Chrome, Firefox, Edge)
- Development tools (VS Code, Python, Node.js, Docker)
- Office applications (Word, Excel, Outlook)
- System utilities (explorer.exe, cmd.exe, powershell.exe)
- Media tools (VLC)
- Compression (7-Zip)

### artifacts-sample.json
JSON format with extended fields: `name`, `publisher`, `path`, `hash`, `version`, `category`

Same 20 entries as the CSV file, plus additional metadata.

## How to Use

### Option 1: Import via Rule Generator Tab
1. Open the GA-AppLocker Dashboard
2. Go to **Rule Generator** tab
3. Click **Import Artifacts** button
4. Select either `artifacts-sample.csv` or `artifacts-sample.json`
5. Select rule type (Publisher recommended)
6. Click **Generate Rules**

### Option 2: Import via Artifact Collection Tab
1. Open the GA-AppLocker Dashboard
2. Go to **Artifact Collection** tab
3. Click **Import Artifacts** button
4. Select either file
5. Switch to Rule Generator tab to create rules

## Expected Output

When you import and generate rules:

| Rule Type | Expected Rules Generated |
|-----------|------------------------|
| Publisher | ~15 rules (one per unique publisher) |
| Hash | 20 rules (one per file) |
| Path | 20 rules (one per path) |

**Publisher rules are recommended** as they:
- Survive application updates
- Provide good security coverage
- Are the AppLocker best practice

## Real-World Usage

In production, you would generate artifact files by:
1. Running the **AD Discovery** tab to find computers
2. Running **Artifact Collection** scans on discovered computers
3. Exporting scan results to CSV/JSON
4. Importing into **Rule Generator** to create AppLocker policies

## Categories in Sample Data

| Category | Examples |
|----------|----------|
| Browser | chrome.exe, firefox.exe, msedge.exe |
| Development | Code.exe, python.exe, node.exe, java.exe |
| Productivity | winword.exe, excel.exe, outlook.exe |
| System | explorer.exe, cmd.exe, powershell.exe |
| Media | vlc.exe |
| Utility | 7zFM.exe |
| Communication | Teams.exe |
