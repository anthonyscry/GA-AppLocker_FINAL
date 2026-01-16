# Alternative Download Methods for GA-AppLocker Dashboard

If your work computer's security software is blocking GitHub downloads, try these alternative methods:

## Method 1: Git Clone (Often Less Restricted)

Many corporate environments allow Git operations even when direct downloads are blocked:

```powershell
# Using Git for Windows
git clone https://github.com/anthonyscry/GA-AppLocker_FINAL.git C:\Dev\GA-AppLocker

# Or if SSH is allowed
git clone git@github.com:anthonyscry/GA-AppLocker_FINAL.git C:\Dev\GA-AppLocker
```

**Why this works:** Git traffic is often whitelisted for development purposes.

---

## Method 2: Download as Email Attachment

1. On your personal computer/phone:
   - Go to: https://github.com/anthonyscry/GA-AppLocker_FINAL
   - Click "Code" → "Download ZIP"
   - Email the ZIP to your work email

2. On your work computer:
   - Download from email (usually trusted)
   - Extract to `C:\Dev\GA-AppLocker`

**Why this works:** Email attachments often bypass web filters.

---

## Method 3: OneDrive/SharePoint Transfer

1. Upload to personal OneDrive/SharePoint:
   - Download ZIP from GitHub
   - Upload to OneDrive/SharePoint

2. Access from work computer:
   - Download from OneDrive/SharePoint (typically trusted)
   - Extract files

**Why this works:** Corporate cloud storage is usually trusted.

---

## Method 4: Compress with Different Extension

Sometimes the `.zip` extension triggers blocks. Try:

```powershell
# On source computer
Compress-Archive -Path .\GA-AppLocker_FINAL -DestinationPath GA-AppLocker.dat

# Transfer the .dat file (looks like data, not code)

# On work computer
Rename-Item GA-AppLocker.dat GA-AppLocker.zip
Expand-Archive -Path GA-AppLocker.zip -DestinationPath C:\Dev\
```

**Why this works:** AV often relies on file extensions for scanning.

---

## Method 5: Use PowerShell WebClient (Bypass Browser)

If your browser blocks but PowerShell doesn't:

```powershell
# Download directly via PowerShell
$url = "https://github.com/anthonyscry/GA-AppLocker_FINAL/archive/refs/heads/main.zip"
$output = "$env:TEMP\GA-AppLocker.zip"

# Method A: WebClient
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $output)

# Method B: Invoke-WebRequest (PS 3.0+)
Invoke-WebRequest -Uri $url -OutFile $output

# Extract
Expand-Archive -Path $output -DestinationPath C:\Dev\GA-AppLocker
```

**Why this works:** PowerShell may have different security policies than browsers.

---

## Method 6: Network Share

If you have access to a network share:

1. Copy files from personal computer to network share
2. Access from work computer via UNC path:
   ```powershell
   Copy-Item -Path "\\server\share\GA-AppLocker" -Destination C:\Dev\ -Recurse
   ```

**Why this works:** Internal file shares are typically trusted.

---

## Method 7: VPN/Remote Desktop

If you have VPN or RDP access to a less-restricted machine:

1. RDP/VPN to development server
2. Download there
3. Copy back to your workstation via network share

**Why this works:** Dev servers often have relaxed policies.

---

## Method 8: Request IT Assistance

Create a ticket with your IT department:

**Subject:** Request to download GA-AppLocker Dashboard v2.0

**Body:**
```
I need to download the GA-AppLocker Dashboard tool for AppLocker policy management.

Repository: https://github.com/anthonyscry/GA-AppLocker_FINAL
Purpose: Enterprise AppLocker deployment and compliance management
Risk Level: Low (internal administrative tool)

The download is being blocked by [antivirus/web filter/SmartScreen].
Can you either:
1. Whitelist the GitHub repository, or
2. Download and scan the files for me, or
3. Add an exception for my development folder

Justification: Required for security policy deployment project.

Thank you!
```

Attach: `SECURITY_JUSTIFICATION.md` (see below)

---

## Method 9: Bypass SmartScreen (If Downloaded Successfully)

If the file downloads but won't run:

```powershell
# Unblock all files
Get-ChildItem -Path C:\Dev\GA-AppLocker -Recurse | Unblock-File

# Or unblock the ZIP before extraction
Unblock-File -Path .\GA-AppLocker.zip
```

**Why this works:** Files from internet get "Mark of the Web" which SmartScreen blocks.

---

## Method 10: Build from Source on Trusted Machine

If all else fails:

1. Review source code on GitHub (verify it's safe)
2. Manually copy/paste code into files on work computer
3. Build locally

**Why this works:** Typing code yourself bypasses download restrictions.

---

## Still Blocked? Check These Settings

### PowerShell Execution Policy
```powershell
# Check current policy
Get-ExecutionPolicy -List

# If Restricted, request change to RemoteSigned
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Windows Defender Application Control (WDAC)
```powershell
# Check if WDAC is blocking
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# If CodeIntegrityPolicyEnforcementStatus = 1, you need IT to whitelist
```

### AppLocker Itself
```powershell
# Check AppLocker policy
Get-AppLockerPolicy -Effective -Xml | Out-File AppLockerPolicy.xml
# Review policy - you may be blocked by your own tool!
```

---

## Recommended Approach

**Try in this order:**

1. ✅ **Git Clone** (fastest, often works)
2. ✅ **Email Attachment** (easy workaround)
3. ✅ **OneDrive Transfer** (usually trusted)
4. ✅ **PowerShell WebClient** (bypasses browser filters)
5. ✅ **Request IT Assistance** (official route)

**For long-term solution:**
- Get code signing certificate
- Run `Sign-Code.ps1` to sign all files
- Request permanent whitelist from IT

---

## Questions?

If all methods fail, contact your IT security team with the `SECURITY_JUSTIFICATION.md` document.
