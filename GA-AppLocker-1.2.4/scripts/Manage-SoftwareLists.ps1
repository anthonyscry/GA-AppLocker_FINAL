<#
.SYNOPSIS
Manages software lists for AppLocker rule generation.

.DESCRIPTION
Part of GA-AppLocker toolkit. Provides functions to create, manage, and use
software lists (whitelists/allowlists) for generating AppLocker rules.

Software lists contain predefined approved software with:
- Publisher/Signature information (for publisher rules)
- SHA256 hashes (for hash rules)
- Path information (for path rules)
- Metadata (category, notes, approval status)

This enables rule generation from curated lists rather than just scan data.

.EXAMPLE
# Create a new software list
New-SoftwareList -Name "BusinessApps" -Description "Standard business applications"

.EXAMPLE
# Add software to a list
Add-SoftwareListItem -ListPath .\SoftwareLists\BusinessApps.json -Name "Adobe Reader" `
    -Publisher "ADOBE INC." -ProductName "Adobe Acrobat Reader" -Category "PDF"

.EXAMPLE
# Generate rules from a software list
$rules = Get-SoftwareListRules -ListPath .\SoftwareLists\BusinessApps.json -RuleType Publisher

.EXAMPLE
# Import software from scan data into a list
Import-ScanDataToSoftwareList -ScanPath .\Scans -ListPath .\SoftwareLists\Discovered.json
#>

#Requires -Version 5.1

# Import common utilities if available
$modulePath = Join-Path $PSScriptRoot "Common.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force -ErrorAction SilentlyContinue
}

# =============================================================================
# Common Publisher List - Pre-populated trusted software publishers
# =============================================================================
# This can be used to quickly add commonly trusted publishers to software lists

$Script:CommonPublishers = @{
    # Microsoft Publishers
    "Microsoft" = @{
        Publisher   = "O=MICROSOFT CORPORATION*"
        ProductName = "*"
        Description = "Microsoft Corporation - All Products"
        Category    = "Microsoft"
    }
    "Microsoft-Windows" = @{
        Publisher   = "O=MICROSOFT WINDOWS*"
        ProductName = "*"
        Description = "Microsoft Windows - OS Components"
        Category    = "Microsoft"
    }

    # Adobe Products
    "Adobe" = @{
        Publisher   = "O=ADOBE INC.*"
        ProductName = "*"
        Description = "Adobe Inc. - All Products"
        Category    = "Productivity"
    }
    "Adobe-Systems" = @{
        Publisher   = "O=ADOBE SYSTEMS*"
        ProductName = "*"
        Description = "Adobe Systems - Legacy Products"
        Category    = "Productivity"
    }

    # Google Products
    "Google" = @{
        Publisher   = "O=GOOGLE LLC*"
        ProductName = "*"
        Description = "Google LLC - All Products"
        Category    = "Browser/Cloud"
    }
    "Google-Inc" = @{
        Publisher   = "O=GOOGLE INC*"
        ProductName = "*"
        Description = "Google Inc - Legacy Products"
        Category    = "Browser/Cloud"
    }

    # Development Tools
    "JetBrains" = @{
        Publisher   = "O=JETBRAINS*"
        ProductName = "*"
        Description = "JetBrains - Development IDEs"
        Category    = "Development"
    }
    "GitHub" = @{
        Publisher   = "O=GITHUB*"
        ProductName = "*"
        Description = "GitHub - Development Tools"
        Category    = "Development"
    }
    "Git" = @{
        Publisher   = "O=THE GIT DEVELOPMENT COMMUNITY*"
        ProductName = "*"
        Description = "Git SCM"
        Category    = "Development"
    }
    "Node.js" = @{
        Publisher   = "O=NODE.JS FOUNDATION*"
        ProductName = "*"
        Description = "Node.js Runtime"
        Category    = "Development"
    }
    "Python" = @{
        Publisher   = "O=PYTHON SOFTWARE FOUNDATION*"
        ProductName = "*"
        Description = "Python Runtime"
        Category    = "Development"
    }
    "MathWorks" = @{
        Publisher   = "O=THE MATHWORKS*"
        ProductName = "*"
        Description = "MathWorks - MATLAB and Simulink"
        Category    = "Development"
    }
    "VSCode" = @{
        Publisher   = "O=MICROSOFT CORPORATION*"
        ProductName = "Microsoft Visual Studio Code"
        Description = "Visual Studio Code"
        Category    = "Development"
    }

    # Security Software
    "Symantec" = @{
        Publisher   = "O=SYMANTEC CORPORATION*"
        ProductName = "*"
        Description = "Symantec - Security Products"
        Category    = "Security"
    }
    "McAfee" = @{
        Publisher   = "O=MCAFEE*"
        ProductName = "*"
        Description = "McAfee - Security Products"
        Category    = "Security"
    }
    "CrowdStrike" = @{
        Publisher   = "O=CROWDSTRIKE*"
        ProductName = "*"
        Description = "CrowdStrike - Endpoint Security"
        Category    = "Security"
    }
    "CarbonBlack" = @{
        Publisher   = "O=CARBON BLACK*"
        ProductName = "*"
        Description = "Carbon Black - Endpoint Protection"
        Category    = "Security"
    }
    "Trend-Micro" = @{
        Publisher   = "O=TREND MICRO*"
        ProductName = "*"
        Description = "Trend Micro - Security Products"
        Category    = "Security"
    }
    "SentinelOne" = @{
        Publisher   = "O=SENTINELONE*"
        ProductName = "*"
        Description = "SentinelOne - EDR"
        Category    = "Security"
    }
    "Trellix" = @{
        Publisher   = "O=TRELLIX*"
        ProductName = "*"
        Description = "Trellix - Enterprise Security (formerly McAfee/FireEye)"
        Category    = "Security"
    }
    "Splunk" = @{
        Publisher   = "O=SPLUNK*"
        ProductName = "*"
        Description = "Splunk - SIEM and Log Analytics"
        Category    = "Security"
    }
    "Forescout" = @{
        Publisher   = "O=FORESCOUT*"
        ProductName = "*"
        Description = "Forescout - Network Access Control"
        Category    = "Security"
    }

    # Collaboration & Communication
    "Zoom" = @{
        Publisher   = "O=ZOOM VIDEO COMMUNICATIONS*"
        ProductName = "*"
        Description = "Zoom Video Conferencing"
        Category    = "Communication"
    }
    "Slack" = @{
        Publisher   = "O=SLACK TECHNOLOGIES*"
        ProductName = "*"
        Description = "Slack Communication"
        Category    = "Communication"
    }
    "Cisco-WebEx" = @{
        Publisher   = "O=CISCO*"
        ProductName = "*WEBEX*"
        Description = "Cisco WebEx"
        Category    = "Communication"
    }
    "Microsoft-Teams" = @{
        Publisher   = "O=MICROSOFT CORPORATION*"
        ProductName = "Microsoft Teams*"
        Description = "Microsoft Teams"
        Category    = "Communication"
    }

    # Remote Access / VPN
    "Citrix" = @{
        Publisher   = "O=CITRIX*"
        ProductName = "*"
        Description = "Citrix - Remote Access"
        Category    = "Remote Access"
    }
    "VMware" = @{
        Publisher   = "O=VMWARE*"
        ProductName = "*"
        Description = "VMware - Virtualization"
        Category    = "Remote Access"
    }
    "PaloAlto-GlobalProtect" = @{
        Publisher   = "O=PALO ALTO NETWORKS*"
        ProductName = "GlobalProtect*"
        Description = "Palo Alto GlobalProtect VPN"
        Category    = "Remote Access"
    }
    "Cisco-AnyConnect" = @{
        Publisher   = "O=CISCO*"
        ProductName = "*ANYCONNECT*"
        Description = "Cisco AnyConnect VPN"
        Category    = "Remote Access"
    }
    "Cisco" = @{
        Publisher   = "O=CISCO*"
        ProductName = "*"
        Description = "Cisco Systems - All Products"
        Category    = "Remote Access"
    }
    "Fortinet" = @{
        Publisher   = "O=FORTINET*"
        ProductName = "*"
        Description = "Fortinet - VPN and Security"
        Category    = "Remote Access"
    }
    "Zscaler" = @{
        Publisher   = "O=ZSCALER*"
        ProductName = "*"
        Description = "Zscaler - Cloud Security"
        Category    = "Remote Access"
    }
    "Ivanti" = @{
        Publisher   = "O=IVANTI*"
        ProductName = "*"
        Description = "Ivanti - Endpoint Management"
        Category    = "Remote Access"
    }
    "BeyondTrust" = @{
        Publisher   = "O=BEYONDTRUST*"
        ProductName = "*"
        Description = "BeyondTrust - Privileged Access"
        Category    = "Remote Access"
    }
    "TeamViewer" = @{
        Publisher   = "O=TEAMVIEWER*"
        ProductName = "*"
        Description = "TeamViewer - Remote Support"
        Category    = "Remote Access"
    }

    # Browsers
    "Mozilla" = @{
        Publisher   = "O=MOZILLA CORPORATION*"
        ProductName = "*"
        Description = "Mozilla - Firefox Browser"
        Category    = "Browser"
    }
    "Brave" = @{
        Publisher   = "O=BRAVE SOFTWARE*"
        ProductName = "*"
        Description = "Brave Browser"
        Category    = "Browser"
    }
    "Opera" = @{
        Publisher   = "O=OPERA*"
        ProductName = "*"
        Description = "Opera Browser"
        Category    = "Browser"
    }

    # Productivity & Office
    "Autodesk" = @{
        Publisher   = "O=AUTODESK*"
        ProductName = "*"
        Description = "Autodesk - CAD/3D Software"
        Category    = "Productivity"
    }
    "Corel" = @{
        Publisher   = "O=COREL*"
        ProductName = "*"
        Description = "Corel - Graphics Software"
        Category    = "Productivity"
    }
    "Foxit" = @{
        Publisher   = "O=FOXIT*"
        ProductName = "*"
        Description = "Foxit - PDF Software"
        Category    = "Productivity"
    }
    "Nitro" = @{
        Publisher   = "O=NITRO*"
        ProductName = "*"
        Description = "Nitro - PDF Software"
        Category    = "Productivity"
    }
    "DocuSign" = @{
        Publisher   = "O=DOCUSIGN*"
        ProductName = "*"
        Description = "DocuSign - Electronic Signatures"
        Category    = "Productivity"
    }
    "Nuance" = @{
        Publisher   = "O=NUANCE*"
        ProductName = "*"
        Description = "Nuance - Dragon/PDF Software"
        Category    = "Productivity"
    }
    "SAP" = @{
        Publisher   = "O=SAP*"
        ProductName = "*"
        Description = "SAP - Enterprise Software"
        Category    = "Productivity"
    }
    "Oracle" = @{
        Publisher   = "O=ORACLE*"
        ProductName = "*"
        Description = "Oracle - Database and Enterprise"
        Category    = "Productivity"
    }
    "Salesforce" = @{
        Publisher   = "O=SALESFORCE*"
        ProductName = "*"
        Description = "Salesforce - CRM Software"
        Category    = "Productivity"
    }
    "Atlassian" = @{
        Publisher   = "O=ATLASSIAN*"
        ProductName = "*"
        Description = "Atlassian - Jira, Confluence"
        Category    = "Productivity"
    }
    "1Password" = @{
        Publisher   = "O=AGILEBITS*"
        ProductName = "*"
        Description = "1Password - Password Manager"
        Category    = "Productivity"
    }
    "LastPass" = @{
        Publisher   = "O=LASTPASS*"
        ProductName = "*"
        Description = "LastPass - Password Manager"
        Category    = "Productivity"
    }
    "Bitwarden" = @{
        Publisher   = "O=BITWARDEN*"
        ProductName = "*"
        Description = "Bitwarden - Password Manager"
        Category    = "Productivity"
    }

    # Development Tools (additional)
    "Docker" = @{
        Publisher   = "O=DOCKER*"
        ProductName = "*"
        Description = "Docker - Container Platform"
        Category    = "Development"
    }
    "Postman" = @{
        Publisher   = "O=POSTMAN*"
        ProductName = "*"
        Description = "Postman - API Development"
        Category    = "Development"
    }
    "Sublime" = @{
        Publisher   = "O=SUBLIME*"
        ProductName = "*"
        Description = "Sublime Text Editor"
        Category    = "Development"
    }
    "Notepad++" = @{
        Publisher   = "O=NOTEPAD++*"
        ProductName = "*"
        Description = "Notepad++ Text Editor"
        Category    = "Development"
    }
    "WinSCP" = @{
        Publisher   = "O=MARTIN PRIKRYL*"
        ProductName = "*"
        Description = "WinSCP - SFTP Client"
        Category    = "Development"
    }
    "PuTTY" = @{
        Publisher   = "O=SIMON TATHAM*"
        ProductName = "*"
        Description = "PuTTY - SSH Client"
        Category    = "Development"
    }
    "FileZilla" = @{
        Publisher   = "O=FILEZILLA*"
        ProductName = "*"
        Description = "FileZilla - FTP Client"
        Category    = "Development"
    }
    "GitLab" = @{
        Publisher   = "O=GITLAB*"
        ProductName = "*"
        Description = "GitLab - DevOps Platform"
        Category    = "Development"
    }
    "Perforce" = @{
        Publisher   = "O=PERFORCE*"
        ProductName = "*"
        Description = "Perforce - Version Control"
        Category    = "Development"
    }
    "Unity" = @{
        Publisher   = "O=UNITY*"
        ProductName = "*"
        Description = "Unity - Game Engine"
        Category    = "Development"
    }
    "Epic-Games" = @{
        Publisher   = "O=EPIC GAMES*"
        ProductName = "*"
        Description = "Epic Games - Unreal Engine"
        Category    = "Development"
    }

    # Security (additional)
    "Kaspersky" = @{
        Publisher   = "O=KASPERSKY*"
        ProductName = "*"
        Description = "Kaspersky - Antivirus"
        Category    = "Security"
    }
    "ESET" = @{
        Publisher   = "O=ESET*"
        ProductName = "*"
        Description = "ESET - Antivirus"
        Category    = "Security"
    }
    "Bitdefender" = @{
        Publisher   = "O=BITDEFENDER*"
        ProductName = "*"
        Description = "Bitdefender - Antivirus"
        Category    = "Security"
    }
    "Sophos" = @{
        Publisher   = "O=SOPHOS*"
        ProductName = "*"
        Description = "Sophos - Endpoint Security"
        Category    = "Security"
    }
    "Webroot" = @{
        Publisher   = "O=WEBROOT*"
        ProductName = "*"
        Description = "Webroot - Cloud Security"
        Category    = "Security"
    }
    "Malwarebytes" = @{
        Publisher   = "O=MALWAREBYTES*"
        ProductName = "*"
        Description = "Malwarebytes - Anti-Malware"
        Category    = "Security"
    }
    "Avast" = @{
        Publisher   = "O=AVAST*"
        ProductName = "*"
        Description = "Avast - Antivirus"
        Category    = "Security"
    }
    "AVG" = @{
        Publisher   = "O=AVG*"
        ProductName = "*"
        Description = "AVG - Antivirus"
        Category    = "Security"
    }
    "NortonLifeLock" = @{
        Publisher   = "O=NORTONLIFELOCK*"
        ProductName = "*"
        Description = "Norton - Security Products"
        Category    = "Security"
    }
    "Qualys" = @{
        Publisher   = "O=QUALYS*"
        ProductName = "*"
        Description = "Qualys - Vulnerability Management"
        Category    = "Security"
    }
    "Tenable" = @{
        Publisher   = "O=TENABLE*"
        ProductName = "*"
        Description = "Tenable - Nessus Vulnerability Scanner"
        Category    = "Security"
    }
    "Rapid7" = @{
        Publisher   = "O=RAPID7*"
        ProductName = "*"
        Description = "Rapid7 - Security Analytics"
        Category    = "Security"
    }
    "Tanium" = @{
        Publisher   = "O=TANIUM*"
        ProductName = "*"
        Description = "Tanium - Endpoint Management"
        Category    = "Security"
    }
    "Cybereason" = @{
        Publisher   = "O=CYBEREASON*"
        ProductName = "*"
        Description = "Cybereason - EDR"
        Category    = "Security"
    }
    "Palo-Alto" = @{
        Publisher   = "O=PALO ALTO NETWORKS*"
        ProductName = "*"
        Description = "Palo Alto Networks - All Products"
        Category    = "Security"
    }
    "CheckPoint" = @{
        Publisher   = "O=CHECK POINT*"
        ProductName = "*"
        Description = "Check Point - Security"
        Category    = "Security"
    }
    "Proofpoint" = @{
        Publisher   = "O=PROOFPOINT*"
        ProductName = "*"
        Description = "Proofpoint - Email Security"
        Category    = "Security"
    }
    "Mimecast" = @{
        Publisher   = "O=MIMECAST*"
        ProductName = "*"
        Description = "Mimecast - Email Security"
        Category    = "Security"
    }
    "CyberArk" = @{
        Publisher   = "O=CYBERARK*"
        ProductName = "*"
        Description = "CyberArk - Privileged Access"
        Category    = "Security"
    }
    "Thycotic" = @{
        Publisher   = "O=THYCOTIC*"
        ProductName = "*"
        Description = "Thycotic - Secret Server"
        Category    = "Security"
    }
    "Delinea" = @{
        Publisher   = "O=DELINEA*"
        ProductName = "*"
        Description = "Delinea - PAM (formerly Thycotic)"
        Category    = "Security"
    }

    # Backup & Storage
    "Veeam" = @{
        Publisher   = "O=VEEAM*"
        ProductName = "*"
        Description = "Veeam - Backup Solutions"
        Category    = "Backup"
    }
    "Veritas" = @{
        Publisher   = "O=VERITAS*"
        ProductName = "*"
        Description = "Veritas - Backup Exec"
        Category    = "Backup"
    }
    "Acronis" = @{
        Publisher   = "O=ACRONIS*"
        ProductName = "*"
        Description = "Acronis - Backup and Recovery"
        Category    = "Backup"
    }
    "Commvault" = @{
        Publisher   = "O=COMMVAULT*"
        ProductName = "*"
        Description = "Commvault - Data Management"
        Category    = "Backup"
    }
    "Carbonite" = @{
        Publisher   = "O=CARBONITE*"
        ProductName = "*"
        Description = "Carbonite - Cloud Backup"
        Category    = "Backup"
    }
    "Druva" = @{
        Publisher   = "O=DRUVA*"
        ProductName = "*"
        Description = "Druva - SaaS Data Protection"
        Category    = "Backup"
    }
    "Dropbox" = @{
        Publisher   = "O=DROPBOX*"
        ProductName = "*"
        Description = "Dropbox - Cloud Storage"
        Category    = "Backup"
    }
    "Box" = @{
        Publisher   = "O=BOX*"
        ProductName = "*"
        Description = "Box - Cloud Storage"
        Category    = "Backup"
    }

    # Utilities
    "7-Zip" = @{
        Publisher   = "O=IGOR PAVLOV*"
        ProductName = "*"
        Description = "7-Zip - Archive Utility"
        Category    = "Utilities"
    }
    "WinZip" = @{
        Publisher   = "O=WINZIP*"
        ProductName = "*"
        Description = "WinZip - Archive Utility"
        Category    = "Utilities"
    }
    "WinRAR" = @{
        Publisher   = "O=WIN.RAR*"
        ProductName = "*"
        Description = "WinRAR - Archive Utility"
        Category    = "Utilities"
    }
    "CCleaner" = @{
        Publisher   = "O=PIRIFORM*"
        ProductName = "*"
        Description = "CCleaner - System Utility"
        Category    = "Utilities"
    }
    "TeamViewer-QuickSupport" = @{
        Publisher   = "O=TEAMVIEWER*"
        ProductName = "TeamViewer QuickSupport"
        Description = "TeamViewer QuickSupport"
        Category    = "Utilities"
    }
    "VLC" = @{
        Publisher   = "O=VIDEOLAN*"
        ProductName = "*"
        Description = "VLC Media Player"
        Category    = "Utilities"
    }
    "Audacity" = @{
        Publisher   = "O=AUDACITY*"
        ProductName = "*"
        Description = "Audacity - Audio Editor"
        Category    = "Utilities"
    }
    "Greenshot" = @{
        Publisher   = "O=GREENSHOT*"
        ProductName = "*"
        Description = "Greenshot - Screenshot Tool"
        Category    = "Utilities"
    }
    "Snagit" = @{
        Publisher   = "O=TECHSMITH*"
        ProductName = "*SNAGIT*"
        Description = "Snagit - Screen Capture"
        Category    = "Utilities"
    }
    "TechSmith" = @{
        Publisher   = "O=TECHSMITH*"
        ProductName = "*"
        Description = "TechSmith - Camtasia/Snagit"
        Category    = "Utilities"
    }
    "PDF24" = @{
        Publisher   = "O=PDF24*"
        ProductName = "*"
        Description = "PDF24 - PDF Tools"
        Category    = "Utilities"
    }
    "HandBrake" = @{
        Publisher   = "O=HANDBRAKE*"
        ProductName = "*"
        Description = "HandBrake - Video Converter"
        Category    = "Utilities"
    }
    "OBS" = @{
        Publisher   = "O=OBS*"
        ProductName = "*"
        Description = "OBS Studio - Streaming"
        Category    = "Utilities"
    }
    "Logitech" = @{
        Publisher   = "O=LOGITECH*"
        ProductName = "*"
        Description = "Logitech - Peripheral Software"
        Category    = "Utilities"
    }
    "Lenovo" = @{
        Publisher   = "O=LENOVO*"
        ProductName = "*"
        Description = "Lenovo - System Software"
        Category    = "Utilities"
    }
    "Dell" = @{
        Publisher   = "O=DELL*"
        ProductName = "*"
        Description = "Dell - System Software"
        Category    = "Utilities"
    }
    "HP" = @{
        Publisher   = "O=HP*"
        ProductName = "*"
        Description = "HP - System Software"
        Category    = "Utilities"
    }
    "Intel" = @{
        Publisher   = "O=INTEL*"
        ProductName = "*"
        Description = "Intel - Drivers and Tools"
        Category    = "Utilities"
    }
    "AMD" = @{
        Publisher   = "O=ADVANCED MICRO DEVICES*"
        ProductName = "*"
        Description = "AMD - Drivers and Tools"
        Category    = "Utilities"
    }
    "NVIDIA" = @{
        Publisher   = "O=NVIDIA*"
        ProductName = "*"
        Description = "NVIDIA - Graphics Drivers"
        Category    = "Utilities"
    }
    "Realtek" = @{
        Publisher   = "O=REALTEK*"
        ProductName = "*"
        Description = "Realtek - Audio/Network Drivers"
        Category    = "Utilities"
    }

    # Communication (additional)
    "RingCentral" = @{
        Publisher   = "O=RINGCENTRAL*"
        ProductName = "*"
        Description = "RingCentral - VoIP"
        Category    = "Communication"
    }
    "Webex" = @{
        Publisher   = "O=CISCO WEBEX*"
        ProductName = "*"
        Description = "Webex - Video Conferencing"
        Category    = "Communication"
    }
    "GoTo" = @{
        Publisher   = "O=GOTO*"
        ProductName = "*"
        Description = "GoTo - Meeting/Webinar"
        Category    = "Communication"
    }
    "LogMeIn" = @{
        Publisher   = "O=LOGMEIN*"
        ProductName = "*"
        Description = "LogMeIn - Remote Access"
        Category    = "Communication"
    }
    "BlueJeans" = @{
        Publisher   = "O=BLUEJEANS*"
        ProductName = "*"
        Description = "BlueJeans - Video Conferencing"
        Category    = "Communication"
    }
    "Discord" = @{
        Publisher   = "O=DISCORD*"
        ProductName = "*"
        Description = "Discord - Communication"
        Category    = "Communication"
    }
    "Signal" = @{
        Publisher   = "O=SIGNAL*"
        ProductName = "*"
        Description = "Signal - Secure Messaging"
        Category    = "Communication"
    }

    # Cloud/SaaS Agents
    "Okta" = @{
        Publisher   = "O=OKTA*"
        ProductName = "*"
        Description = "Okta - Identity Management"
        Category    = "Cloud"
    }
    "Duo" = @{
        Publisher   = "O=DUO*"
        ProductName = "*"
        Description = "Duo Security - MFA"
        Category    = "Cloud"
    }
    "Ping" = @{
        Publisher   = "O=PING IDENTITY*"
        ProductName = "*"
        Description = "Ping Identity - IAM"
        Category    = "Cloud"
    }
    "AWS" = @{
        Publisher   = "O=AMAZON*"
        ProductName = "*"
        Description = "Amazon Web Services - Tools"
        Category    = "Cloud"
    }
    "Snowflake" = @{
        Publisher   = "O=SNOWFLAKE*"
        ProductName = "*"
        Description = "Snowflake - Data Cloud"
        Category    = "Cloud"
    }
    "ServiceNow" = @{
        Publisher   = "O=SERVICENOW*"
        ProductName = "*"
        Description = "ServiceNow - ITSM"
        Category    = "Cloud"
    }
    "Workday" = @{
        Publisher   = "O=WORKDAY*"
        ProductName = "*"
        Description = "Workday - HR/Finance"
        Category    = "Cloud"
    }

    # Endpoint Management
    "SCCM" = @{
        Publisher   = "O=MICROSOFT CORPORATION*"
        ProductName = "*Configuration Manager*"
        Description = "Microsoft SCCM/MECM"
        Category    = "Management"
    }
    "Intune" = @{
        Publisher   = "O=MICROSOFT CORPORATION*"
        ProductName = "*Intune*"
        Description = "Microsoft Intune"
        Category    = "Management"
    }
    "ManageEngine" = @{
        Publisher   = "O=ZOHO*"
        ProductName = "*"
        Description = "ManageEngine/Zoho - IT Management"
        Category    = "Management"
    }
    "PDQ" = @{
        Publisher   = "O=PDQ*"
        ProductName = "*"
        Description = "PDQ Deploy/Inventory"
        Category    = "Management"
    }
    "SolarWinds" = @{
        Publisher   = "O=SOLARWINDS*"
        ProductName = "*"
        Description = "SolarWinds - IT Management"
        Category    = "Management"
    }
    "ConnectWise" = @{
        Publisher   = "O=CONNECTWISE*"
        ProductName = "*"
        Description = "ConnectWise - RMM/PSA"
        Category    = "Management"
    }
    "Datto" = @{
        Publisher   = "O=DATTO*"
        ProductName = "*"
        Description = "Datto - RMM/Backup"
        Category    = "Management"
    }
    "NinjaRMM" = @{
        Publisher   = "O=NINJARMM*"
        ProductName = "*"
        Description = "NinjaRMM - Remote Monitoring"
        Category    = "Management"
    }
    "Kaseya" = @{
        Publisher   = "O=KASEYA*"
        ProductName = "*"
        Description = "Kaseya - IT Management"
        Category    = "Management"
    }
    "Jamf" = @{
        Publisher   = "O=JAMF*"
        ProductName = "*"
        Description = "Jamf - Apple Device Management"
        Category    = "Management"
    }
    "Quest" = @{
        Publisher   = "O=QUEST*"
        ProductName = "*"
        Description = "Quest - AD/System Management"
        Category    = "Management"
    }

    # Printing & Scanning
    "Canon" = @{
        Publisher   = "O=CANON*"
        ProductName = "*"
        Description = "Canon - Printer Drivers"
        Category    = "Printing"
    }
    "Xerox" = @{
        Publisher   = "O=XEROX*"
        ProductName = "*"
        Description = "Xerox - Printer Drivers"
        Category    = "Printing"
    }
    "Ricoh" = @{
        Publisher   = "O=RICOH*"
        ProductName = "*"
        Description = "Ricoh - Printer Drivers"
        Category    = "Printing"
    }
    "Konica" = @{
        Publisher   = "O=KONICA MINOLTA*"
        ProductName = "*"
        Description = "Konica Minolta - Printers"
        Category    = "Printing"
    }
    "Brother" = @{
        Publisher   = "O=BROTHER*"
        ProductName = "*"
        Description = "Brother - Printer Drivers"
        Category    = "Printing"
    }
    "Epson" = @{
        Publisher   = "O=SEIKO EPSON*"
        ProductName = "*"
        Description = "Epson - Printer Drivers"
        Category    = "Printing"
    }
    "Lexmark" = @{
        Publisher   = "O=LEXMARK*"
        ProductName = "*"
        Description = "Lexmark - Printer Drivers"
        Category    = "Printing"
    }
    "PaperCut" = @{
        Publisher   = "O=PAPERCUT*"
        ProductName = "*"
        Description = "PaperCut - Print Management"
        Category    = "Printing"
    }
}

# =============================================================================
# Software List Schema Definition
# =============================================================================
<#
Software List JSON Schema:
{
    "metadata": {
        "name": "List Name",
        "description": "Description",
        "created": "ISO 8601 timestamp",
        "modified": "ISO 8601 timestamp",
        "version": "1.0"
    },
    "items": [
        {
            "id": "GUID",
            "name": "Software Display Name",
            "publisher": "O=PUBLISHER NAME",
            "productName": "Product Name (for publisher rules)",
            "binaryName": "*.exe or specific.exe",
            "minVersion": "0.0.0.0",
            "maxVersion": "*",
            "hash": "SHA256 hash (for hash rules)",
            "hashSourceFile": "original filename",
            "hashSourceSize": file size in bytes,
            "path": "Path pattern (for path rules)",
            "category": "Category/Tag",
            "notes": "Additional notes",
            "approved": true/false,
            "ruleType": "Publisher|Hash|Path",
            "added": "ISO 8601 timestamp",
            "addedBy": "Username"
        }
    ]
}
#>

# =============================================================================
# Software List Management Functions
# =============================================================================

function New-SoftwareList {
    <#
    .SYNOPSIS
    Creates a new software list file.

    .PARAMETER Name
    Name of the software list.

    .PARAMETER Description
    Description of what this list contains.

    .PARAMETER OutputPath
    Directory to save the list file. Defaults to .\SoftwareLists

    .EXAMPLE
    New-SoftwareList -Name "ApprovedSoftware" -Description "Corporate approved applications"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string]$Description = "",

        [string]$OutputPath = ".\SoftwareLists"
    )

    # Defensive check: sanitize name for filesystem
    $sanitizedName = $Name -replace '[\\/:*?"<>|]', '_'
    if ($sanitizedName -ne $Name) {
        Write-Warning "Name contained invalid characters. Using: $sanitizedName"
        $Name = $sanitizedName
    }

    try {
        # Create output directory if needed
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created directory: $OutputPath"
        }

        $listFile = Join-Path $OutputPath "$Name.json"

        if (Test-Path $listFile) {
            Write-Warning "Software list '$Name' already exists at: $listFile"
            return $listFile
        }

        $softwareList = @{
            metadata = @{
                name        = $Name
                description = if ($Description) { $Description } else { "" }
                created     = (Get-Date).ToString("o")
                modified    = (Get-Date).ToString("o")
                version     = "1.0"
            }
            items    = @()
        }

        $softwareList | ConvertTo-Json -Depth 10 | Out-File -FilePath $listFile -Encoding UTF8 -ErrorAction Stop

        Write-Host "Created software list: $listFile" -ForegroundColor Green
        return $listFile
    }
    catch {
        Write-Host "[-] Failed to create software list: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Get-SoftwareList {
    <#
    .SYNOPSIS
    Loads a software list from file.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER CreateIfNotExists
    If true, creates an empty list if the file doesn't exist.

    .EXAMPLE
    $list = Get-SoftwareList -ListPath .\SoftwareLists\ApprovedSoftware.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [switch]$CreateIfNotExists
    )

    # Defensive check: validate path
    if (-not (Test-Path $ListPath)) {
        if ($CreateIfNotExists) {
            $listDir = Split-Path -Parent $ListPath
            $listName = [System.IO.Path]::GetFileNameWithoutExtension($ListPath)
            $result = New-SoftwareList -Name $listName -OutputPath $listDir
            if ($result) {
                return Get-SoftwareList -ListPath $ListPath
            }
        }
        Write-Host "[-] Software list not found: $ListPath" -ForegroundColor Red
        return $null
    }

    try {
        $content = Get-Content -Path $ListPath -Raw -ErrorAction Stop

        # Defensive check: empty file
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Host "[-] Software list file is empty: $ListPath" -ForegroundColor Red
            return $null
        }

        $list = $content | ConvertFrom-Json -ErrorAction Stop

        # Defensive check: validate structure
        if ($null -eq $list.metadata) {
            Write-Warning "Software list missing metadata - may be corrupted: $ListPath"
            # Add minimal metadata
            $list | Add-Member -NotePropertyName "metadata" -NotePropertyValue @{
                name     = [System.IO.Path]::GetFileNameWithoutExtension($ListPath)
                modified = (Get-Date).ToString("o")
                version  = "1.0"
            } -Force
        }

        if ($null -eq $list.items) {
            Write-Warning "Software list missing items array - initializing empty array"
            $list | Add-Member -NotePropertyName "items" -NotePropertyValue @() -Force
        }

        return $list
    }
    catch {
        Write-Host "[-] Failed to load software list: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Save-SoftwareList {
    <#
    .SYNOPSIS
    Saves a software list object to file.

    .PARAMETER List
    The software list object to save.

    .PARAMETER ListPath
    Path to save the JSON file.

    .PARAMETER CreateBackup
    If true, creates a backup before saving.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$List,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [switch]$CreateBackup
    )

    # Defensive check: validate list object
    if ($null -eq $List) {
        Write-Host "[-] Cannot save null software list" -ForegroundColor Red
        return $false
    }

    try {
        # Create backup if requested and file exists
        if ($CreateBackup -and (Test-Path $ListPath)) {
            $backupPath = "$ListPath.bak"
            Copy-Item -Path $ListPath -Destination $backupPath -Force -ErrorAction SilentlyContinue
            Write-Verbose "Created backup: $backupPath"
        }

        # Ensure metadata exists
        if ($null -eq $List.metadata) {
            $List | Add-Member -NotePropertyName "metadata" -NotePropertyValue @{} -Force
        }

        # Update modified timestamp
        if ($List.metadata -is [hashtable]) {
            $List.metadata.modified = (Get-Date).ToString("o")
        }
        else {
            $List.metadata | Add-Member -NotePropertyName "modified" -NotePropertyValue (Get-Date).ToString("o") -Force
        }

        # Ensure items is an array
        if ($null -eq $List.items) {
            $List | Add-Member -NotePropertyName "items" -NotePropertyValue @() -Force
        }

        # Ensure output directory exists
        $outputDir = Split-Path -Parent $ListPath
        if (-not [string]::IsNullOrWhiteSpace($outputDir) -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        $List | ConvertTo-Json -Depth 10 | Out-File -FilePath $ListPath -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Saved software list to: $ListPath"
        return $true
    }
    catch {
        Write-Host "[-] Failed to save software list: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}


function Add-SoftwareListItem {
    <#
    .SYNOPSIS
    Adds a software item to a software list.

    .DESCRIPTION
    Adds software with publisher signature, hash, or path information
    for AppLocker rule generation.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Name
    Display name of the software.

    .PARAMETER Publisher
    Publisher/Organization name from certificate (e.g., "ADOBE INC.")

    .PARAMETER ProductName
    Product name for publisher rules. Use "*" for all products from publisher.

    .PARAMETER BinaryName
    Binary name for publisher rules. Use "*" for all binaries.

    .PARAMETER MinVersion
    Minimum version to allow. Default: "*" (any version)

    .PARAMETER MaxVersion
    Maximum version to allow. Default: "*" (any version)

    .PARAMETER Hash
    SHA256 hash for hash-based rules.

    .PARAMETER HashSourceFile
    Original filename for the hash.

    .PARAMETER HashSourceSize
    File size in bytes for the hash.

    .PARAMETER Path
    Path pattern for path-based rules.

    .PARAMETER Category
    Category/tag for organizing software (e.g., "Productivity", "Security")

    .PARAMETER Notes
    Additional notes about this software.

    .PARAMETER RuleType
    Type of rule to generate: Publisher, Hash, or Path

    .PARAMETER Approved
    Whether this software is approved. Default: $true

    .PARAMETER SkipDuplicateCheck
    If true, skips checking for duplicate entries.

    .EXAMPLE
    # Add publisher-based software
    Add-SoftwareListItem -ListPath .\list.json -Name "Adobe Reader" `
        -Publisher "ADOBE INC." -ProductName "Adobe Acrobat Reader" `
        -Category "PDF" -RuleType Publisher

    .EXAMPLE
    # Add hash-based software
    Add-SoftwareListItem -ListPath .\list.json -Name "Custom Tool" `
        -Hash "A1B2C3D4..." -HashSourceFile "tool.exe" -HashSourceSize 12345 `
        -Category "Internal" -RuleType Hash
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string]$Publisher,
        [string]$ProductName = "*",
        [string]$BinaryName = "*",
        [string]$MinVersion = "*",
        [string]$MaxVersion = "*",

        [string]$Hash,
        [string]$HashSourceFile,
        [int64]$HashSourceSize,

        [string]$Path,

        [string]$Category = "Uncategorized",
        [string]$Notes = "",

        [ValidateSet("Publisher", "Hash", "Path")]
        [string]$RuleType = "Publisher",

        [bool]$Approved = $true,

        [switch]$SkipDuplicateCheck
    )

    try {
        # Defensive check: ensure list exists or create it
        if (-not (Test-Path $ListPath)) {
            Write-Warning "Software list not found, creating: $ListPath"
            $listDir = Split-Path -Parent $ListPath
            if ([string]::IsNullOrWhiteSpace($listDir)) { $listDir = "." }
            $listName = [System.IO.Path]::GetFileNameWithoutExtension($ListPath)
            New-SoftwareList -Name $listName -OutputPath $listDir | Out-Null
        }

        $list = Get-SoftwareList -ListPath $ListPath
        if ($null -eq $list) {
            Write-Host "[-] Failed to load software list" -ForegroundColor Red
            return $null
        }

        # Validate required fields based on rule type
        switch ($RuleType) {
            "Publisher" {
                if ([string]::IsNullOrWhiteSpace($Publisher)) {
                    Write-Host "[-] Publisher is required for Publisher rule type" -ForegroundColor Red
                    return $null
                }
                # Normalize publisher format
                if ($Publisher -notmatch "^O=") {
                    $Publisher = "O=$Publisher"
                }
            }
            "Hash" {
                if ([string]::IsNullOrWhiteSpace($Hash)) {
                    Write-Host "[-] Hash is required for Hash rule type" -ForegroundColor Red
                    return $null
                }
                # Normalize hash format (remove 0x prefix if present)
                $Hash = $Hash -replace "^0x", ""
            }
            "Path" {
                if ([string]::IsNullOrWhiteSpace($Path)) {
                    Write-Host "[-] Path is required for Path rule type" -ForegroundColor Red
                    return $null
                }
            }
        }

        # Check for duplicates unless skipped
        if (-not $SkipDuplicateCheck -and $null -ne $list.items -and $list.items.Count -gt 0) {
            $existingItem = $list.items | Where-Object {
                ($RuleType -eq "Publisher" -and $_.publisher -eq $Publisher -and $_.productName -eq $ProductName -and $_.binaryName -eq $BinaryName) -or
                ($RuleType -eq "Hash" -and $_.hash -eq $Hash -and -not [string]::IsNullOrWhiteSpace($Hash)) -or
                ($RuleType -eq "Path" -and $_.path -eq $Path -and -not [string]::IsNullOrWhiteSpace($Path))
            }

            if ($existingItem) {
                Write-Warning "Similar item already exists in list: $($existingItem.name)"
                return $existingItem
            }
        }

        $newItem = [PSCustomObject]@{
            id             = [guid]::NewGuid().ToString()
            name           = $Name.Trim()
            publisher      = if ($Publisher) { $Publisher.Trim() } else { $null }
            productName    = if ($ProductName) { $ProductName.Trim() } else { "*" }
            binaryName     = if ($BinaryName) { $BinaryName.Trim() } else { "*" }
            minVersion     = if ($MinVersion) { $MinVersion.Trim() } else { "*" }
            maxVersion     = if ($MaxVersion) { $MaxVersion.Trim() } else { "*" }
            hash           = if ($Hash) { $Hash.Trim() } else { $null }
            hashSourceFile = if ($HashSourceFile) { $HashSourceFile.Trim() } else { $null }
            hashSourceSize = $HashSourceSize
            path           = if ($Path) { $Path.Trim() } else { $null }
            category       = if ($Category) { $Category.Trim() } else { "Uncategorized" }
            notes          = if ($Notes) { $Notes.Trim() } else { "" }
            approved       = $Approved
            ruleType       = $RuleType
            added          = (Get-Date).ToString("o")
            addedBy        = if ($env:USERNAME) { $env:USERNAME } else { "Unknown" }
        }

        # Convert items to array if needed and add new item
        $items = @($list.items)
        $items += $newItem
        $list.items = $items

        $saveResult = Save-SoftwareList -List $list -ListPath $ListPath
        if (-not $saveResult) {
            Write-Host "[-] Failed to save software list" -ForegroundColor Red
            return $null
        }

        Write-Host "[+] Added: $Name ($RuleType rule)" -ForegroundColor Green
        return $newItem
    }
    catch {
        Write-Host "[-] Failed to add software list item: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Remove-SoftwareListItem {
    <#
    .SYNOPSIS
    Removes an item from a software list.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Id
    ID of the item to remove.

    .PARAMETER Name
    Name of the item to remove (if ID not specified).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ListPath,

        [string]$Id,
        [string]$Name
    )

    if (-not $Id -and -not $Name) {
        throw "Either -Id or -Name must be specified"
    }

    $list = Get-SoftwareList -ListPath $ListPath

    $itemToRemove = if ($Id) {
        $list.items | Where-Object { $_.id -eq $Id }
    }
    else {
        $list.items | Where-Object { $_.name -eq $Name }
    }

    if (-not $itemToRemove) {
        Write-Warning "Item not found in list"
        return
    }

    $list.items = @($list.items | Where-Object { $_.id -ne $itemToRemove.id })

    Save-SoftwareList -List $list -ListPath $ListPath
    Write-Host "Removed: $($itemToRemove.name)" -ForegroundColor Yellow
}


function Update-SoftwareListItem {
    <#
    .SYNOPSIS
    Updates an existing item in a software list.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Id
    ID of the item to update.

    .PARAMETER Properties
    Hashtable of properties to update.

    .EXAMPLE
    Update-SoftwareListItem -ListPath .\list.json -Id "guid" -Properties @{approved=$true; notes="Tested OK"}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ListPath,

        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [hashtable]$Properties
    )

    $list = Get-SoftwareList -ListPath $ListPath

    $item = $list.items | Where-Object { $_.id -eq $Id }
    if (-not $item) {
        throw "Item with ID '$Id' not found"
    }

    foreach ($key in $Properties.Keys) {
        if ($item.PSObject.Properties.Name -contains $key) {
            $item.$key = $Properties[$key]
        }
    }

    Save-SoftwareList -List $list -ListPath $ListPath
    Write-Host "Updated: $($item.name)" -ForegroundColor Cyan
    return $item
}


# =============================================================================
# Import Functions - Convert scan data to software list
# =============================================================================

function Import-ScanDataToSoftwareList {
    <#
    .SYNOPSIS
    Imports software discovered during scans into a software list.

    .DESCRIPTION
    Reads Executables.csv and Publishers.csv from scan data and creates
    software list entries with publisher and hash information.

    .PARAMETER ScanPath
    Path to scan results from Invoke-RemoteScan.ps1

    .PARAMETER ListPath
    Path to the software list to import into. Creates if doesn't exist.

    .PARAMETER Category
    Category to assign to imported items.

    .PARAMETER SignedOnly
    Only import signed executables (with publisher info).

    .PARAMETER UnsignedOnly
    Only import unsigned executables (hash-based rules).

    .PARAMETER AutoApprove
    Automatically mark imported items as approved.

    .PARAMETER Deduplicate
    Deduplicate by publisher (imports unique publishers only).

    .EXAMPLE
    Import-ScanDataToSoftwareList -ScanPath .\Scans -ListPath .\SoftwareLists\Discovered.json -SignedOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ScanPath,

        [Parameter(Mandatory = $true)]
        [string]$ListPath,

        [string]$Category = "Discovered",

        [switch]$SignedOnly,
        [switch]$UnsignedOnly,
        [switch]$AutoApprove,
        [switch]$Deduplicate
    )

    # Create list if doesn't exist
    if (-not (Test-Path $ListPath)) {
        $listDir = Split-Path -Parent $ListPath
        $listName = [System.IO.Path]::GetFileNameWithoutExtension($ListPath)
        New-SoftwareList -Name $listName -Description "Imported from scan data" -OutputPath $listDir | Out-Null
    }

    $list = Get-SoftwareList -ListPath $ListPath

    # Find all scan data - check if CSVs exist directly in the given path first
    $directCsvPath = Join-Path $ScanPath "Executables.csv"
    $computerFolders = @()

    if (Test-Path $directCsvPath) {
        # CSV files are directly in the given path (user selected a computer folder)
        $computerFolders = @([PSCustomObject]@{ FullName = $ScanPath; Name = (Split-Path $ScanPath -Leaf) })
        Write-Host "Loading scan data from: $(Split-Path $ScanPath -Leaf)..." -ForegroundColor Cyan
    }
    else {
        # Look for subfolders containing CSVs (user selected a scan date folder)
        $computerFolders = Get-ChildItem -Path $ScanPath -Directory |
            Where-Object { Test-Path (Join-Path $_.FullName "*.csv") }

        if ($computerFolders.Count -eq 0) {
            throw "No scan data found in $ScanPath. Ensure the folder contains Executables.csv or subfolders with CSV files."
        }
        Write-Host "Loading scan data from $($computerFolders.Count) computers..." -ForegroundColor Cyan
    }

    $allExecutables = @()
    foreach ($folder in $computerFolders) {
        $exePath = Join-Path $folder.FullName "Executables.csv"
        if (Test-Path $exePath) {
            $allExecutables += Import-Csv -Path $exePath
        }
    }

    Write-Host "  Found $($allExecutables.Count) total executables" -ForegroundColor Gray

    # Filter based on switches
    $toImport = $allExecutables
    if ($SignedOnly) {
        $toImport = $toImport | Where-Object { $_.IsSigned -eq "True" -and $_.Publisher }
    }
    if ($UnsignedOnly) {
        $toImport = $toImport | Where-Object { $_.IsSigned -ne "True" -and $_.Hash }
    }

    # Track what we've added for deduplication
    $addedPublishers = @{}
    $addedHashes = @{}
    $importCount = 0

    foreach ($exe in $toImport) {
        $ruleType = if ($exe.IsSigned -eq "True" -and $exe.Publisher) { "Publisher" } else { "Hash" }

        # Deduplicate if requested
        if ($Deduplicate -and $ruleType -eq "Publisher") {
            if ($addedPublishers.ContainsKey($exe.Publisher)) { continue }
            $addedPublishers[$exe.Publisher] = $true
        }
        if ($Deduplicate -and $ruleType -eq "Hash") {
            if ($addedHashes.ContainsKey($exe.Hash)) { continue }
            $addedHashes[$exe.Hash] = $true
        }

        # Check if already in list
        $exists = $list.items | Where-Object {
            ($_.publisher -eq $exe.Publisher -and $exe.Publisher) -or
            ($_.hash -eq $exe.Hash -and $exe.Hash)
        }
        if ($exists) { continue }

        # Extract product name from path
        $productName = if ($exe.Path -match "\\([^\\]+)\\[^\\]+$") { $matches[1] } else { "*" }

        $newItem = [PSCustomObject]@{
            id             = [guid]::NewGuid().ToString()
            name           = $exe.Name
            publisher      = $exe.Publisher
            productName    = $productName
            binaryName     = $exe.Name
            minVersion     = "*"
            maxVersion     = "*"
            hash           = $exe.Hash
            hashSourceFile = $exe.Name
            hashSourceSize = [int64]$exe.Size
            path           = $exe.Path
            category       = $Category
            notes          = "Imported from scan: $($folder.Name)"
            approved       = [bool]$AutoApprove
            ruleType       = $ruleType
            added          = (Get-Date).ToString("o")
            addedBy        = $env:USERNAME
        }

        $items = @($list.items)
        $items += $newItem
        $list.items = $items
        $importCount++
    }

    Save-SoftwareList -List $list -ListPath $ListPath

    Write-Host "Imported $importCount items to software list" -ForegroundColor Green
    Write-Host "  Publisher-based: $($addedPublishers.Count)" -ForegroundColor Gray
    Write-Host "  Hash-based: $($addedHashes.Count)" -ForegroundColor Gray

    return $list
}


function Import-ExecutableToSoftwareList {
    <#
    .SYNOPSIS
    Imports a specific executable file into a software list.

    .DESCRIPTION
    Reads signature and hash information from an executable and adds it
    to a software list for rule generation.

    .PARAMETER FilePath
    Path to the executable file.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Category
    Category to assign.

    .PARAMETER Notes
    Notes to add.

    .PARAMETER PreferHash
    Use hash rule even if file is signed.

    .EXAMPLE
    Import-ExecutableToSoftwareList -FilePath "C:\Tools\app.exe" -ListPath .\list.json -Category "Internal Tools"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ListPath,

        [string]$Category = "Imported",
        [string]$Notes = "",
        [switch]$PreferHash
    )

    $file = Get-Item $FilePath
    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

    $isSigned = $sig -and $sig.Status -eq "Valid"
    $publisher = $null

    if ($isSigned -and $sig.SignerCertificate) {
        if ($sig.SignerCertificate.Subject -match "O=([^,]+)") {
            $publisher = $matches[1].Trim('"')
        }
    }

    $ruleType = if ($isSigned -and $publisher -and -not $PreferHash) { "Publisher" } else { "Hash" }

    $params = @{
        ListPath = $ListPath
        Name     = $file.Name
        Category = $Category
        Notes    = $Notes
        RuleType = $ruleType
        Approved = $true
    }

    if ($ruleType -eq "Publisher") {
        $params.Publisher = $publisher
        $params.ProductName = "*"
        $params.BinaryName = $file.Name
    }
    else {
        $params.Hash = $hash
        $params.HashSourceFile = $file.Name
        $params.HashSourceSize = $file.Length
    }

    Add-SoftwareListItem @params
}


# =============================================================================
# Advanced Import Functions
# =============================================================================

function Get-CommonPublishers {
    <#
    .SYNOPSIS
    Returns the list of common trusted publishers.

    .DESCRIPTION
    Returns the pre-defined list of commonly trusted software publishers
    that can be added to software lists for rule generation.

    .PARAMETER Category
    Filter publishers by category.

    .EXAMPLE
    Get-CommonPublishers
    Get-CommonPublishers -Category "Security"
    #>
    [CmdletBinding()]
    param(
        [string]$Category
    )

    $publishers = $Script:CommonPublishers

    if (-not [string]::IsNullOrWhiteSpace($Category)) {
        $filtered = @{}
        foreach ($key in $publishers.Keys) {
            if ($publishers[$key].Category -eq $Category) {
                $filtered[$key] = $publishers[$key]
            }
        }
        return $filtered
    }

    return $publishers
}


function Get-CommonPublisherCategories {
    <#
    .SYNOPSIS
    Returns available categories of common publishers.
    #>
    [CmdletBinding()]
    param()

    $categories = @()
    foreach ($key in $Script:CommonPublishers.Keys) {
        $cat = $Script:CommonPublishers[$key].Category
        if ($cat -notin $categories) {
            $categories += $cat
        }
    }
    return $categories | Sort-Object
}


function Import-CommonPublishersToSoftwareList {
    <#
    .SYNOPSIS
    Imports common trusted publishers to a software list.

    .DESCRIPTION
    Adds pre-defined common publishers (Microsoft, Adobe, Google, etc.)
    to a software list for quick policy generation.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Publishers
    Array of publisher keys to import. Use Get-CommonPublishers to see available options.
    If not specified, shows interactive selection.

    .PARAMETER Category
    Filter available publishers by category (e.g., "Microsoft", "Security", "Development").

    .PARAMETER All
    Import all common publishers.

    .PARAMETER AutoApprove
    Automatically mark imported items as approved.

    .EXAMPLE
    Import-CommonPublishersToSoftwareList -ListPath .\list.json -Publishers "Microsoft", "Adobe"

    .EXAMPLE
    Import-CommonPublishersToSoftwareList -ListPath .\list.json -Category "Security" -All
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [string[]]$Publishers,

        [string]$Category,

        [switch]$All,

        [switch]$AutoApprove
    )

    try {
        # Get available publishers
        $availablePublishers = if ($Category) {
            Get-CommonPublishers -Category $Category
        }
        else {
            Get-CommonPublishers
        }

        if ($availablePublishers.Count -eq 0) {
            Write-Host "[-] No publishers found" -ForegroundColor Red
            return $null
        }

        # Determine which publishers to import
        $toImport = @()
        if ($All) {
            $toImport = $availablePublishers.Keys
        }
        elseif ($Publishers -and $Publishers.Count -gt 0) {
            $toImport = $Publishers | Where-Object { $availablePublishers.ContainsKey($_) }
            $invalid = $Publishers | Where-Object { -not $availablePublishers.ContainsKey($_) }
            if ($invalid) {
                Write-Warning "Unknown publishers (skipped): $($invalid -join ', ')"
            }
        }
        else {
            # Interactive selection
            Write-Host "`n  Available Common Publishers:" -ForegroundColor Cyan
            Write-Host "  (Select by number, comma-separated for multiple)" -ForegroundColor Gray
            Write-Host ""

            # Show "All" option first
            Write-Host "    [A] " -ForegroundColor Green -NoNewline
            Write-Host "ALL PUBLISHERS" -ForegroundColor White -NoNewline
            Write-Host " - Import all $($availablePublishers.Count) publishers at once" -ForegroundColor Gray
            Write-Host ""

            $i = 1
            $indexMap = @{}
            $sortedKeys = $availablePublishers.Keys | Sort-Object
            foreach ($key in $sortedKeys) {
                $pub = $availablePublishers[$key]
                Write-Host "    [$i] " -ForegroundColor Yellow -NoNewline
                Write-Host "$key" -ForegroundColor White -NoNewline
                Write-Host " - $($pub.Description)" -ForegroundColor Gray
                $indexMap[$i] = $key
                $i++
            }

            Write-Host ""
            $selection = Read-Host "  Enter selection (e.g., 1,2,3 or A for all)"

            if ($selection -eq "all" -or $selection -eq "a" -or $selection -eq "A") {
                $toImport = $availablePublishers.Keys
            }
            elseif ($selection -match "^\d+(,\s*\d+)*$") {
                $indices = $selection -split "," | ForEach-Object { [int]$_.Trim() }
                $toImport = $indices | ForEach-Object {
                    if ($indexMap.ContainsKey($_)) { $indexMap[$_] }
                } | Where-Object { $_ }
            }
            else {
                Write-Host "[-] Invalid selection" -ForegroundColor Red
                return $null
            }
        }

        if ($toImport.Count -eq 0) {
            Write-Host "[-] No publishers selected" -ForegroundColor Yellow
            return $null
        }

        # Import selected publishers
        $importCount = 0
        foreach ($key in $toImport) {
            $pub = $availablePublishers[$key]

            $params = @{
                ListPath    = $ListPath
                Name        = $pub.Description
                Publisher   = $pub.Publisher
                ProductName = $pub.ProductName
                BinaryName  = "*"
                Category    = $pub.Category
                Notes       = "Common publisher: $key"
                RuleType    = "Publisher"
                Approved    = [bool]$AutoApprove
            }

            $result = Add-SoftwareListItem @params
            if ($result) {
                $importCount++
            }
        }

        Write-Host ""
        Write-Host "[+] Imported $importCount common publishers" -ForegroundColor Green
        return $importCount
    }
    catch {
        Write-Host "[-] Failed to import common publishers: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Import-AppLockerPolicyToSoftwareList {
    <#
    .SYNOPSIS
    Imports rules from an existing AppLocker policy XML into a software list.

    .DESCRIPTION
    Reads an AppLocker policy XML file and extracts publisher, hash, and path
    rules to add to a software list.

    .PARAMETER PolicyPath
    Path to the AppLocker policy XML file.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER RuleTypes
    Types of rules to import: Publisher, Hash, Path, or All.

    .PARAMETER AllowOnly
    Only import Allow rules (skip Deny rules).

    .PARAMETER Collections
    Rule collections to import from: Exe, Msi, Script, Dll, or All.

    .PARAMETER AutoApprove
    Automatically mark imported items as approved.

    .EXAMPLE
    Import-AppLockerPolicyToSoftwareList -PolicyPath .\policy.xml -ListPath .\list.json

    .EXAMPLE
    Import-AppLockerPolicyToSoftwareList -PolicyPath .\policy.xml -ListPath .\list.json -RuleTypes Publisher -AllowOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [ValidateSet("Publisher", "Hash", "Path", "All")]
        [string]$RuleTypes = "All",

        [switch]$AllowOnly,

        [ValidateSet("Exe", "Msi", "Script", "Dll", "Appx", "All")]
        [string]$Collections = "All",

        [switch]$AutoApprove
    )

    try {
        # Validate policy file
        if (-not (Test-Path $PolicyPath)) {
            Write-Host "[-] Policy file not found: $PolicyPath" -ForegroundColor Red
            return $null
        }

        Write-Host "  Loading AppLocker policy..." -ForegroundColor Cyan

        [xml]$policy = Get-Content -Path $PolicyPath -Raw -ErrorAction Stop

        if ($null -eq $policy.AppLockerPolicy) {
            Write-Host "[-] Invalid AppLocker policy: missing AppLockerPolicy element" -ForegroundColor Red
            return $null
        }

        $importCount = 0
        $skippedCount = 0

        foreach ($collection in $policy.AppLockerPolicy.RuleCollection) {
            $collectionType = $collection.Type

            # Filter by collection type
            if ($Collections -ne "All" -and $collectionType -ne $Collections) {
                continue
            }

            # Import Publisher rules
            if ($RuleTypes -eq "All" -or $RuleTypes -eq "Publisher") {
                foreach ($rule in $collection.FilePublisherRule) {
                    # Skip deny rules if AllowOnly
                    if ($AllowOnly -and $rule.Action -ne "Allow") {
                        $skippedCount++
                        continue
                    }

                    $condition = $rule.Conditions.FilePublisherCondition
                    if ($null -eq $condition) { continue }

                    $params = @{
                        ListPath    = $ListPath
                        Name        = $rule.Name
                        Publisher   = $condition.PublisherName
                        ProductName = $condition.ProductName
                        BinaryName  = $condition.BinaryName
                        MinVersion  = $condition.BinaryVersionRange.LowSection
                        MaxVersion  = $condition.BinaryVersionRange.HighSection
                        Category    = "Imported-$collectionType"
                        Notes       = "Imported from policy: $($rule.Description)"
                        RuleType    = "Publisher"
                        Approved    = [bool]$AutoApprove
                    }

                    $result = Add-SoftwareListItem @params -SkipDuplicateCheck:$false
                    if ($result) { $importCount++ }
                }
            }

            # Import Hash rules
            if ($RuleTypes -eq "All" -or $RuleTypes -eq "Hash") {
                foreach ($rule in $collection.FileHashRule) {
                    if ($AllowOnly -and $rule.Action -ne "Allow") {
                        $skippedCount++
                        continue
                    }

                    $hashCondition = $rule.Conditions.FileHashCondition
                    if ($null -eq $hashCondition) { continue }

                    foreach ($fileHash in $hashCondition.FileHash) {
                        $hashValue = $fileHash.Data -replace "^0x", ""

                        $params = @{
                            ListPath       = $ListPath
                            Name           = if ($fileHash.SourceFileName) { $fileHash.SourceFileName } else { $rule.Name }
                            Hash           = $hashValue
                            HashSourceFile = $fileHash.SourceFileName
                            HashSourceSize = [int64]$fileHash.SourceFileLength
                            Category       = "Imported-$collectionType"
                            Notes          = "Imported from policy: $($rule.Description)"
                            RuleType       = "Hash"
                            Approved       = [bool]$AutoApprove
                        }

                        $result = Add-SoftwareListItem @params -SkipDuplicateCheck:$false
                        if ($result) { $importCount++ }
                    }
                }
            }

            # Import Path rules
            if ($RuleTypes -eq "All" -or $RuleTypes -eq "Path") {
                foreach ($rule in $collection.FilePathRule) {
                    if ($AllowOnly -and $rule.Action -ne "Allow") {
                        $skippedCount++
                        continue
                    }

                    $pathCondition = $rule.Conditions.FilePathCondition
                    if ($null -eq $pathCondition) { continue }

                    $params = @{
                        ListPath = $ListPath
                        Name     = $rule.Name
                        Path     = $pathCondition.Path
                        Category = "Imported-$collectionType"
                        Notes    = "Imported from policy: $($rule.Description)"
                        RuleType = "Path"
                        Approved = [bool]$AutoApprove
                    }

                    $result = Add-SoftwareListItem @params -SkipDuplicateCheck:$false
                    if ($result) { $importCount++ }
                }
            }
        }

        Write-Host ""
        Write-Host "[+] Imported $importCount rules from policy" -ForegroundColor Green
        if ($skippedCount -gt 0) {
            Write-Host "    Skipped $skippedCount deny rules" -ForegroundColor Gray
        }

        return $importCount
    }
    catch {
        Write-Host "[-] Failed to import from policy: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Import-FolderToSoftwareList {
    <#
    .SYNOPSIS
    Scans a folder for executables and imports them to a software list.

    .DESCRIPTION
    Recursively scans a folder for executable files, extracts signature
    and hash information, and adds them to a software list.

    .PARAMETER FolderPath
    Path to the folder to scan.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Extensions
    File extensions to include. Default: exe, dll, msi, ps1, bat, cmd, vbs, js

    .PARAMETER Recurse
    Scan subfolders recursively.

    .PARAMETER SignedOnly
    Only import signed files.

    .PARAMETER Category
    Category to assign to imported items.

    .PARAMETER AutoApprove
    Automatically mark imported items as approved.

    .PARAMETER MaxFiles
    Maximum number of files to process. Default: 1000

    .EXAMPLE
    Import-FolderToSoftwareList -FolderPath "C:\Program Files\MyApp" -ListPath .\list.json -Recurse
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [string[]]$Extensions = @("exe", "dll", "msi", "ps1", "bat", "cmd", "vbs", "js"),

        [switch]$Recurse,

        [switch]$SignedOnly,

        [string]$Category = "Folder Import",

        [switch]$AutoApprove,

        [int]$MaxFiles = 1000
    )

    try {
        if (-not (Test-Path $FolderPath)) {
            Write-Host "[-] Folder not found: $FolderPath" -ForegroundColor Red
            return $null
        }

        Write-Host "  Scanning folder: $FolderPath" -ForegroundColor Cyan

        # Build filter pattern
        $includePatterns = $Extensions | ForEach-Object { "*.$_" }

        # Find files
        $searchParams = @{
            Path    = $FolderPath
            Include = $includePatterns
            File    = $true
        }
        if ($Recurse) {
            $searchParams.Recurse = $true
        }

        $files = Get-ChildItem @searchParams -ErrorAction SilentlyContinue |
            Select-Object -First $MaxFiles

        if ($files.Count -eq 0) {
            Write-Host "[-] No matching files found" -ForegroundColor Yellow
            return 0
        }

        Write-Host "  Found $($files.Count) files to process..." -ForegroundColor Gray

        $importCount = 0
        $signedCount = 0
        $unsignedCount = 0

        foreach ($file in $files) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                $isSigned = $sig -and $sig.Status -eq "Valid"

                if ($SignedOnly -and -not $isSigned) {
                    continue
                }

                $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

                $publisher = $null
                if ($isSigned -and $sig.SignerCertificate) {
                    if ($sig.SignerCertificate.Subject -match "O=([^,]+)") {
                        $publisher = $matches[1].Trim('"')
                    }
                }

                $ruleType = if ($isSigned -and $publisher) { "Publisher" } else { "Hash" }

                $params = @{
                    ListPath = $ListPath
                    Name     = $file.Name
                    Category = $Category
                    Notes    = "Imported from: $($file.DirectoryName)"
                    RuleType = $ruleType
                    Approved = [bool]$AutoApprove
                }

                if ($ruleType -eq "Publisher") {
                    $params.Publisher = $publisher
                    $params.ProductName = "*"
                    $params.BinaryName = $file.Name
                    $signedCount++
                }
                else {
                    $params.Hash = $hash
                    $params.HashSourceFile = $file.Name
                    $params.HashSourceSize = $file.Length
                    $unsignedCount++
                }

                $result = Add-SoftwareListItem @params -SkipDuplicateCheck:$false
                if ($result) {
                    $importCount++
                }
            }
            catch {
                Write-Verbose "Failed to process $($file.Name): $_"
            }
        }

        Write-Host ""
        Write-Host "[+] Imported $importCount files from folder" -ForegroundColor Green
        Write-Host "    Publisher rules: $signedCount" -ForegroundColor Gray
        Write-Host "    Hash rules: $unsignedCount" -ForegroundColor Gray

        return $importCount
    }
    catch {
        Write-Host "[-] Failed to import from folder: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Import-CertificateStoreToSoftwareList {
    <#
    .SYNOPSIS
    Imports trusted publishers from Windows Certificate Store.

    .DESCRIPTION
    Reads certificates from the TrustedPublisher certificate store and
    creates publisher rules in a software list.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER StoreLocation
    Certificate store location: CurrentUser or LocalMachine. Default: LocalMachine

    .PARAMETER AutoApprove
    Automatically mark imported items as approved.

    .EXAMPLE
    Import-CertificateStoreToSoftwareList -ListPath .\list.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [ValidateSet("CurrentUser", "LocalMachine")]
        [string]$StoreLocation = "LocalMachine",

        [switch]$AutoApprove
    )

    try {
        Write-Host "  Reading TrustedPublisher certificates from $StoreLocation store..." -ForegroundColor Cyan

        # Access the TrustedPublisher store
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            "TrustedPublisher",
            [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        $certs = $store.Certificates

        if ($certs.Count -eq 0) {
            Write-Host "[-] No certificates found in TrustedPublisher store" -ForegroundColor Yellow
            $store.Close()
            return 0
        }

        Write-Host "  Found $($certs.Count) trusted publisher certificates" -ForegroundColor Gray

        $importCount = 0

        foreach ($cert in $certs) {
            try {
                # Extract organization from subject
                $publisher = $null
                if ($cert.Subject -match "O=([^,]+)") {
                    $publisher = $matches[1].Trim('"')
                }

                if ([string]::IsNullOrWhiteSpace($publisher)) {
                    # Fallback to CN
                    if ($cert.Subject -match "CN=([^,]+)") {
                        $publisher = $matches[1].Trim('"')
                    }
                }

                if ([string]::IsNullOrWhiteSpace($publisher)) {
                    continue
                }

                $params = @{
                    ListPath    = $ListPath
                    Name        = "Trusted: $publisher"
                    Publisher   = $publisher
                    ProductName = "*"
                    BinaryName  = "*"
                    Category    = "Certificate Store"
                    Notes       = "Imported from $StoreLocation TrustedPublisher store. Thumbprint: $($cert.Thumbprint)"
                    RuleType    = "Publisher"
                    Approved    = [bool]$AutoApprove
                }

                $result = Add-SoftwareListItem @params -SkipDuplicateCheck:$false
                if ($result) {
                    $importCount++
                }
            }
            catch {
                Write-Verbose "Failed to process certificate: $_"
            }
        }

        $store.Close()

        Write-Host ""
        Write-Host "[+] Imported $importCount publishers from certificate store" -ForegroundColor Green

        return $importCount
    }
    catch {
        Write-Host "[-] Failed to import from certificate store: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Set-SoftwareListItemApproval {
    <#
    .SYNOPSIS
    Sets approval status for items in a software list.

    .DESCRIPTION
    Bulk update approval status for items matching specified criteria.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Approved
    New approval status.

    .PARAMETER Category
    Filter by category.

    .PARAMETER RuleType
    Filter by rule type.

    .PARAMETER Publisher
    Filter by publisher (supports wildcards).

    .PARAMETER All
    Apply to all items.

    .EXAMPLE
    Set-SoftwareListItemApproval -ListPath .\list.json -Approved $true -Category "Microsoft"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ListPath,

        [Parameter(Mandatory = $true)]
        [bool]$Approved,

        [string]$Category,

        [ValidateSet("Publisher", "Hash", "Path")]
        [string]$RuleType,

        [string]$Publisher,

        [switch]$All
    )

    try {
        $list = Get-SoftwareList -ListPath $ListPath
        if ($null -eq $list) {
            return $null
        }

        $items = $list.items
        if ($null -eq $items -or $items.Count -eq 0) {
            Write-Host "[-] No items in software list" -ForegroundColor Yellow
            return 0
        }

        # Apply filters
        $matchingItems = $items
        if (-not $All) {
            if ($Category) {
                $matchingItems = $matchingItems | Where-Object { $_.category -eq $Category }
            }
            if ($RuleType) {
                $matchingItems = $matchingItems | Where-Object { $_.ruleType -eq $RuleType }
            }
            if ($Publisher) {
                $matchingItems = $matchingItems | Where-Object { $_.publisher -like $Publisher }
            }
        }

        $updateCount = 0
        foreach ($item in $matchingItems) {
            if ($item.approved -ne $Approved) {
                $item.approved = $Approved
                $updateCount++
            }
        }

        if ($updateCount -gt 0) {
            Save-SoftwareList -List $list -ListPath $ListPath
        }

        $status = if ($Approved) { "approved" } else { "unapproved" }
        Write-Host "[+] Marked $updateCount items as $status" -ForegroundColor Green

        return $updateCount
    }
    catch {
        Write-Host "[-] Failed to update approval status: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


# =============================================================================
# Rule Generation Functions
# =============================================================================

function Get-SoftwareListRules {
    <#
    .SYNOPSIS
    Generates AppLocker rule XML from a software list.

    .DESCRIPTION
    Converts software list items into AppLocker rule XML that can be
    incorporated into a policy.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER RuleType
    Filter by rule type: Publisher, Hash, Path, or All

    .PARAMETER ApprovedOnly
    Only generate rules for approved items.

    .PARAMETER Category
    Filter by category.

    .PARAMETER UserOrGroupSid
    SID to apply rules to. Default: S-1-1-0 (Everyone)

    .PARAMETER Action
    Rule action: Allow or Deny

    .EXAMPLE
    $rules = Get-SoftwareListRules -ListPath .\list.json -RuleType Publisher -ApprovedOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ListPath,

        [ValidateSet("Publisher", "Hash", "Path", "All")]
        [string]$RuleType = "All",

        [switch]$ApprovedOnly,

        [string]$Category,

        [string]$UserOrGroupSid = "S-1-1-0",

        [ValidateSet("Allow", "Deny")]
        [string]$Action = "Allow"
    )

    $list = Get-SoftwareList -ListPath $ListPath

    $items = $list.items

    # Filter by approval status
    if ($ApprovedOnly) {
        $items = $items | Where-Object { $_.approved -eq $true }
    }

    # Filter by category
    if ($Category) {
        $items = $items | Where-Object { $_.category -eq $Category }
    }

    # Filter by rule type
    if ($RuleType -ne "All") {
        $items = $items | Where-Object { $_.ruleType -eq $RuleType }
    }

    $rules = @()

    foreach ($item in $items) {
        switch ($item.ruleType) {
            "Publisher" {
                $rule = New-PublisherRuleFromListItem -Item $item -Sid $UserOrGroupSid -Action $Action
            }
            "Hash" {
                $rule = New-HashRuleFromListItem -Item $item -Sid $UserOrGroupSid -Action $Action
            }
            "Path" {
                $rule = New-PathRuleFromListItem -Item $item -Sid $UserOrGroupSid -Action $Action
            }
        }

        if ($rule) {
            $rules += $rule
        }
    }

    return $rules
}


function New-PublisherRuleFromListItem {
    <#
    .SYNOPSIS
    Creates a publisher rule XML from a software list item.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Item,

        [string]$Sid = "S-1-1-0",
        [string]$Action = "Allow"
    )

    $pubXml = [System.Security.SecurityElement]::Escape($Item.publisher)
    $prodXml = [System.Security.SecurityElement]::Escape($Item.productName)
    $binXml = [System.Security.SecurityElement]::Escape($Item.binaryName)
    $nameXml = [System.Security.SecurityElement]::Escape($Item.name)

    $lowVersion = if ($Item.minVersion -and $Item.minVersion -ne "*") { $Item.minVersion } else { "*" }
    $highVersion = if ($Item.maxVersion -and $Item.maxVersion -ne "*") { $Item.maxVersion } else { "*" }

    $ruleXml = @"
    <FilePublisherRule Id="$(New-Guid)" Name="$nameXml" Description="From Software List: $($Item.category)" UserOrGroupSid="$Sid" Action="$Action">
      <Conditions>
        <FilePublisherCondition PublisherName="O=$pubXml*" ProductName="$prodXml" BinaryName="$binXml">
          <BinaryVersionRange LowSection="$lowVersion" HighSection="$highVersion"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
"@

    return [PSCustomObject]@{
        Type     = "Publisher"
        Name     = $Item.name
        Category = $Item.category
        Xml      = $ruleXml
        Item     = $Item
    }
}


function New-HashRuleFromListItem {
    <#
    .SYNOPSIS
    Creates a hash rule XML from a software list item.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Item,

        [string]$Sid = "S-1-1-0",
        [string]$Action = "Allow"
    )

    if (-not $Item.hash) {
        Write-Warning "No hash available for: $($Item.name)"
        return $null
    }

    $nameXml = [System.Security.SecurityElement]::Escape($Item.name)
    $sourceFile = [System.Security.SecurityElement]::Escape($Item.hashSourceFile)
    $hashValue = if ($Item.hash -notmatch "^0x") { "0x$($Item.hash)" } else { $Item.hash }

    $ruleXml = @"
    <FileHashRule Id="$(New-Guid)" Name="Hash: $nameXml" Description="From Software List: $($Item.category)" UserOrGroupSid="$Sid" Action="$Action">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="SHA256" Data="$hashValue" SourceFileName="$sourceFile" SourceFileLength="$($Item.hashSourceSize)"/>
        </FileHashCondition>
      </Conditions>
    </FileHashRule>
"@

    return [PSCustomObject]@{
        Type     = "Hash"
        Name     = $Item.name
        Category = $Item.category
        Xml      = $ruleXml
        Item     = $Item
    }
}


function New-PathRuleFromListItem {
    <#
    .SYNOPSIS
    Creates a path rule XML from a software list item.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Item,

        [string]$Sid = "S-1-1-0",
        [string]$Action = "Allow"
    )

    if (-not $Item.path) {
        Write-Warning "No path available for: $($Item.name)"
        return $null
    }

    $nameXml = [System.Security.SecurityElement]::Escape($Item.name)
    $pathXml = [System.Security.SecurityElement]::Escape($Item.path)

    $ruleXml = @"
    <FilePathRule Id="$(New-Guid)" Name="Path: $nameXml" Description="From Software List: $($Item.category)" UserOrGroupSid="$Sid" Action="$Action">
      <Conditions>
        <FilePathCondition Path="$pathXml"/>
      </Conditions>
    </FilePathRule>
"@

    return [PSCustomObject]@{
        Type     = "Path"
        Name     = $Item.name
        Category = $Item.category
        Xml      = $ruleXml
        Item     = $Item
    }
}


# =============================================================================
# Query and Report Functions
# =============================================================================

function Get-SoftwareListSummary {
    <#
    .SYNOPSIS
    Gets a summary of a software list.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .EXAMPLE
    Get-SoftwareListSummary -ListPath .\SoftwareLists\BusinessApps.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ListPath
    )

    $list = Get-SoftwareList -ListPath $ListPath

    $summary = [PSCustomObject]@{
        Name             = $list.metadata.name
        Description      = $list.metadata.description
        Version          = $list.metadata.version
        Created          = $list.metadata.created
        Modified         = $list.metadata.modified
        TotalItems       = $list.items.Count
        ApprovedItems    = ($list.items | Where-Object { $_.approved -eq $true }).Count
        PendingItems     = ($list.items | Where-Object { $_.approved -ne $true }).Count
        PublisherRules   = ($list.items | Where-Object { $_.ruleType -eq "Publisher" }).Count
        HashRules        = ($list.items | Where-Object { $_.ruleType -eq "Hash" }).Count
        PathRules        = ($list.items | Where-Object { $_.ruleType -eq "Path" }).Count
        Categories       = ($list.items | Select-Object -ExpandProperty category -Unique)
        UniquePublishers = ($list.items | Where-Object { $_.publisher } | Select-Object -ExpandProperty publisher -Unique).Count
    }

    return $summary
}


function Find-SoftwareListItem {
    <#
    .SYNOPSIS
    Searches for items in a software list.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER Name
    Search by name (supports wildcards).

    .PARAMETER Publisher
    Search by publisher (supports wildcards).

    .PARAMETER Category
    Filter by category.

    .PARAMETER RuleType
    Filter by rule type.

    .EXAMPLE
    Find-SoftwareListItem -ListPath .\list.json -Publisher "*ADOBE*"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ListPath,

        [string]$Name,
        [string]$Publisher,
        [string]$Category,

        [ValidateSet("Publisher", "Hash", "Path")]
        [string]$RuleType
    )

    $list = Get-SoftwareList -ListPath $ListPath
    $items = $list.items

    if ($Name) {
        $items = $items | Where-Object { $_.name -like $Name }
    }
    if ($Publisher) {
        $items = $items | Where-Object { $_.publisher -like $Publisher }
    }
    if ($Category) {
        $items = $items | Where-Object { $_.category -eq $Category }
    }
    if ($RuleType) {
        $items = $items | Where-Object { $_.ruleType -eq $RuleType }
    }

    return $items
}


function Export-SoftwareListToCsv {
    <#
    .SYNOPSIS
    Exports a software list to CSV format for easy editing.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .PARAMETER OutputPath
    Path for the CSV output file.

    .EXAMPLE
    Export-SoftwareListToCsv -ListPath .\list.json -OutputPath .\list.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ListPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $list = Get-SoftwareList -ListPath $ListPath

    $list.items | Select-Object name, publisher, productName, binaryName, hash, path, category, approved, ruleType, notes |
    Export-Csv -Path $OutputPath -NoTypeInformation

    Write-Host "Exported $($list.items.Count) items to: $OutputPath" -ForegroundColor Green
}


function Import-SoftwareListFromCsv {
    <#
    .SYNOPSIS
    Imports items from a CSV file into a software list.

    .DESCRIPTION
    CSV should have columns: name, publisher, productName, binaryName, hash, path, category, approved, ruleType, notes

    .PARAMETER CsvPath
    Path to the CSV file.

    .PARAMETER ListPath
    Path to the software list JSON file.

    .EXAMPLE
    Import-SoftwareListFromCsv -CsvPath .\items.csv -ListPath .\SoftwareLists\MyList.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$CsvPath,

        [Parameter(Mandatory = $true)]
        [string]$ListPath
    )

    # Create list if doesn't exist
    if (-not (Test-Path $ListPath)) {
        $listDir = Split-Path -Parent $ListPath
        $listName = [System.IO.Path]::GetFileNameWithoutExtension($ListPath)
        New-SoftwareList -Name $listName -Description "Imported from CSV" -OutputPath $listDir | Out-Null
    }

    $csvItems = Import-Csv -Path $CsvPath
    $importCount = 0

    foreach ($csvItem in $csvItems) {
        # Determine rule type from CSV or infer from available data
        $ruleType = if ($csvItem.ruleType) {
            $csvItem.ruleType
        }
        elseif ($csvItem.hash) {
            "Hash"
        }
        elseif ($csvItem.publisher) {
            "Publisher"
        }
        else {
            "Path"
        }

        $params = @{
            ListPath    = $ListPath
            Name        = $csvItem.name
            Category    = if ($csvItem.category) { $csvItem.category } else { "Imported" }
            Notes       = $csvItem.notes
            RuleType    = $ruleType
            Approved    = [bool]($csvItem.approved -eq "True" -or $csvItem.approved -eq $true)
        }

        switch ($ruleType) {
            "Publisher" {
                $params.Publisher = $csvItem.publisher
                $params.ProductName = if ($csvItem.productName) { $csvItem.productName } else { "*" }
                $params.BinaryName = if ($csvItem.binaryName) { $csvItem.binaryName } else { "*" }
            }
            "Hash" {
                $params.Hash = $csvItem.hash
                $params.HashSourceFile = $csvItem.name
            }
            "Path" {
                $params.Path = $csvItem.path
            }
        }

        try {
            Add-SoftwareListItem @params -ErrorAction SilentlyContinue | Out-Null
            $importCount++
        }
        catch {
            Write-Warning "Failed to import: $($csvItem.name) - $_"
        }
    }

    Write-Host "Imported $importCount items from CSV" -ForegroundColor Green
}


# =============================================================================
# Export Module Members (only when loaded as a module)
# =============================================================================

# Only export if being loaded as a module (not dot-sourced)
if ($MyInvocation.Line -notmatch '^\.\s') {
    try {
        Export-ModuleMember -Function @(
            # List Management
            'New-SoftwareList',
            'Get-SoftwareList',
            'Save-SoftwareList',
            'Add-SoftwareListItem',
            'Remove-SoftwareListItem',
            'Update-SoftwareListItem',

            # Basic Import Functions
            'Import-ScanDataToSoftwareList',
            'Import-ExecutableToSoftwareList',

            # Advanced Import Functions
            'Get-CommonPublishers',
            'Get-CommonPublisherCategories',
            'Import-CommonPublishersToSoftwareList',
            'Import-AppLockerPolicyToSoftwareList',
            'Import-FolderToSoftwareList',
            'Import-CertificateStoreToSoftwareList',

            # Bulk Operations
            'Set-SoftwareListItemApproval',

            # Rule Generation
            'Get-SoftwareListRules',
            'New-PublisherRuleFromListItem',
            'New-HashRuleFromListItem',
            'New-PathRuleFromListItem',

            # Query and Export
            'Get-SoftwareListSummary',
            'Find-SoftwareListItem',
            'Export-SoftwareListToCsv',
            'Import-SoftwareListFromCsv'
        ) -ErrorAction SilentlyContinue
    }
    catch {
        # Expected when file is dot-sourced instead of loaded as module
        Write-Verbose "Module export skipped: $_"
    }
}
