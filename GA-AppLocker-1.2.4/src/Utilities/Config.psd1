@{
    # ==========================================================================
    # GA-AppLocker Central Configuration
    # ==========================================================================
    # Edit this file to customize AppLocker policy generation for your environment.
    # All scripts reference this single configuration file.
    # ==========================================================================

    # --------------------------------------------------------------------------
    # Well-Known Security Identifiers (SIDs)
    # --------------------------------------------------------------------------
    # These are standard Windows SIDs that don't require AD lookup.
    # Do not modify unless you know what you're doing.

    WellKnownSids = @{
        "NT AUTHORITY\SYSTEM"              = "S-1-5-18"
        "NT AUTHORITY\LOCAL SERVICE"       = "S-1-5-19"
        "NT AUTHORITY\NETWORK SERVICE"     = "S-1-5-20"
        "BUILTIN\Administrators"           = "S-1-5-32-544"
        "BUILTIN\Users"                    = "S-1-5-32-545"
        "BUILTIN\Power Users"              = "S-1-5-32-547"
        "Everyone"                         = "S-1-1-0"
        "NT AUTHORITY\Authenticated Users" = "S-1-5-11"
        "NT AUTHORITY\INTERACTIVE"         = "S-1-5-4"
        "NT AUTHORITY\SERVICE"             = "S-1-5-6"
    }

    # --------------------------------------------------------------------------
    # AppLocker AD Group Configuration
    # --------------------------------------------------------------------------
    # Standardized group names for AppLocker deployment.
    # These names MUST match what Manage-ADResources.ps1 creates.
    # All policy generation scripts should reference these values.

    AppLockerGroups = @{
        # Group name prefix (default: "AppLocker")
        Prefix = "AppLocker"

        # Group suffixes (appended to prefix with hyphen)
        # Example: With prefix "AppLocker", creates "AppLocker-Admins"
        Suffixes = @{
            Admins          = "Admins"           # Full: AppLocker-Admins
            StandardUsers   = "StandardUsers"   # Full: AppLocker-StandardUsers
            ServiceAccounts = "ServiceAccounts" # Full: AppLocker-ServiceAccounts (NO hyphen in "ServiceAccounts")
            Installers      = "Installers"      # Full: AppLocker-Installers
        }

        # Group descriptions for AD creation
        Descriptions = @{
            Admins          = "Administrative users - full system access"
            StandardUsers   = "Standard users with restricted application access"
            ServiceAccounts = "Service accounts that need specific application access"
            Installers      = "Users authorized to install software"
        }
    }

    # --------------------------------------------------------------------------
    # LOLBins (Living Off The Land Binaries)
    # --------------------------------------------------------------------------
    # These are legitimate Windows binaries commonly abused by attackers.
    # Deny rules are created for these in simplified mode with -IncludeDenyRules.
    # Add or remove entries based on your security requirements.

    LOLBins = @(
        @{ Name = "mshta.exe"; Description = "HTML Application Host - executes .hta files" }
        @{ Name = "PresentationHost.exe"; Description = "XAML Browser Applications host" }
        @{ Name = "InstallUtil.exe"; Description = ".NET Installation Utility - code execution" }
        @{ Name = "RegAsm.exe"; Description = ".NET Assembly Registration - code execution" }
        @{ Name = "RegSvcs.exe"; Description = ".NET Component Services - code execution" }
        @{ Name = "MSBuild.exe"; Description = "Microsoft Build Engine - code execution" }
        @{ Name = "cscript.exe"; Description = "Console Script Host - runs VBScript/JScript" }
        @{ Name = "wscript.exe"; Description = "Windows Script Host - runs VBScript/JScript" }
        @{ Name = "msiexec.exe"; Description = "Windows Installer - can download and execute" }
        @{ Name = "certutil.exe"; Description = "Certificate utility - can download files" }
        @{ Name = "bitsadmin.exe"; Description = "BITS Admin - can download files" }
        @{ Name = "rundll32.exe"; Description = "Run DLL - executes DLL exports" }
        @{ Name = "regsvr32.exe"; Description = "Register Server - can execute remote scripts" }
        @{ Name = "hh.exe"; Description = "HTML Help - can execute scripts" }
        @{ Name = "mmc.exe"; Description = "Microsoft Management Console - snap-in execution" }
        @{ Name = "control.exe"; Description = "Control Panel - can load arbitrary CPL files" }
        @{ Name = "pcalua.exe"; Description = "Program Compatibility Assistant - bypass" }
        @{ Name = "SyncAppvPublishingServer.exe"; Description = "App-V Publishing - PowerShell execution" }
    )

    # --------------------------------------------------------------------------
    # Default Deny Paths
    # --------------------------------------------------------------------------
    # User-writable locations where code execution should be blocked.
    # These apply to ALL users including administrators in strict mode.

    DefaultDenyPaths = @(
        @{ Path = "%USERPROFILE%\Downloads\*"; Description = "User Downloads folder" }
        @{ Path = "%USERPROFILE%\Desktop\*"; Description = "User Desktop" }
        @{ Path = "%APPDATA%\*"; Description = "Roaming AppData" }
        @{ Path = "%LOCALAPPDATA%\*"; Description = "Local AppData" }
        @{ Path = "%LOCALAPPDATA%\Temp\*"; Description = "Local Temp folder" }
        @{ Path = "%TEMP%\*"; Description = "System Temp folder" }
        @{ Path = "%TMP%\*"; Description = "TMP folder" }
    )

    # Additional deny paths for servers
    ServerDenyPaths = @(
        @{ Path = "C:\inetpub\wwwroot\*"; Description = "IIS Web Root" }
        @{ Path = "%SYSTEMDRIVE%\Temp\*"; Description = "System Drive Temp" }
        @{ Path = "C:\PerfLogs\*"; Description = "Performance Logs folder" }
    )

    # --------------------------------------------------------------------------
    # Default Safe Paths (Allow Rules)
    # --------------------------------------------------------------------------
    # Standard Windows paths that are protected by NTFS permissions.
    # Code execution is generally safe from these locations.

    DefaultAllowPaths = @(
        @{ Path = "%WINDIR%\*"; Description = "Windows Directory" }
        @{ Path = "%PROGRAMFILES%\*"; Description = "Program Files" }
        @{ Path = "%PROGRAMFILES(X86)%\*"; Description = "Program Files (x86)" }
    )

    # --------------------------------------------------------------------------
    # Trusted Microsoft Publishers
    # --------------------------------------------------------------------------
    # Microsoft certificate subjects for publisher rules.

    MicrosoftPublishers = @(
        "O=MICROSOFT CORPORATION*"
        "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
    )

    # --------------------------------------------------------------------------
    # Default Scan Paths
    # --------------------------------------------------------------------------
    # Paths scanned by Invoke-RemoteScan.ps1 for executables.

    DefaultScanPaths = @(
        "%ProgramFiles%"
        "%ProgramFiles(x86)%"
        "%SystemRoot%\System32"
        "%SystemRoot%\SysWOW64"
    )

    # User profile paths (optional, use -ScanUserProfiles)
    UserProfileScanPaths = @(
        "%SystemDrive%\Users\*\AppData\Local\Programs"
        "%SystemDrive%\Users\*\AppData\Local\Microsoft"
        "%SystemDrive%\Users\*\Desktop"
        "%SystemDrive%\Users\*\Downloads"
    )

    # --------------------------------------------------------------------------
    # File Extensions
    # --------------------------------------------------------------------------
    # Extensions to scan and categorize.

    ExecutableExtensions = @(".exe", ".com", ".scr")
    DllExtensions        = @(".dll", ".ocx")
    ScriptExtensions     = @(".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".wsh")
    InstallerExtensions  = @(".msi", ".msp", ".mst")

    # All scannable extensions
    AllScanExtensions = @(
        "*.exe", "*.dll", "*.msi", "*.ps1", "*.bat", "*.cmd",
        "*.vbs", "*.js", "*.wsf", "*.com", "*.scr", "*.ocx"
    )

    # --------------------------------------------------------------------------
    # Policy Generation Defaults
    # --------------------------------------------------------------------------

    DefaultEnforcementMode = "AuditOnly"  # AuditOnly, Enabled, NotConfigured
    DefaultOutputPath      = ".\Outputs"
    DefaultRuleGranularity = "PublisherProductBinary"  # Publisher, PublisherProduct, PublisherProductBinary

    # --------------------------------------------------------------------------
    # Remote Scan Defaults
    # --------------------------------------------------------------------------

    DefaultThrottleLimit   = 10           # Max concurrent remote connections
    MaxFilesPerPath        = 5000         # Limit files scanned per path (timeout prevention)
    MaxDirectoriesPerPath  = 2000         # Limit directories for writable scan
    ScanTimeout            = 300          # Seconds per computer

    # --------------------------------------------------------------------------
    # Event Collection Defaults
    # --------------------------------------------------------------------------

    MaxEventsPerComputer   = 5000         # Limit events collected per computer
    DefaultEventDaysBack   = 14           # Default days of events to collect (0 = all)

    # --------------------------------------------------------------------------
    # Build Guide Phase Descriptions
    # --------------------------------------------------------------------------
    # Reference information for the phased deployment approach.

    Phases = @{
        1 = @{
            Name        = "EXE Rules"
            Description = "Executable control - foundation of AppLocker"
            Collections = @("Exe")
        }
        2 = @{
            Name        = "Script Rules"
            Description = "Script control - highest security risk"
            Collections = @("Exe", "Script")
        }
        3 = @{
            Name        = "MSI/Installer Rules"
            Description = "Installer control - software deployment"
            Collections = @("Exe", "Script", "Msi")
        }
        4 = @{
            Name        = "DLL Rules"
            Description = "DLL control - most comprehensive, enable last"
            Collections = @("Exe", "Script", "Msi", "Dll")
        }
    }

    # --------------------------------------------------------------------------
    # Workflow Mode Descriptions
    # --------------------------------------------------------------------------

    WorkflowModes = @{
        Scan     = "Collect data from remote computers"
        Generate = "Create AppLocker policy from scan data"
        Merge    = "Combine multiple policy files"
        Full     = "Complete workflow: Scan -> Generate -> Merge"
        Validate = "Validate an existing policy file"
        Software = "Manage software lists for rule generation"
    }

    # --------------------------------------------------------------------------
    # Software List Settings
    # --------------------------------------------------------------------------
    # Configuration for software list management and rule generation

    SoftwareListSettings = @{
        DefaultPath       = ".\SoftwareLists"
        DefaultListName   = "ApprovedSoftware"
        AutoApproveScans  = $false
        DeduplicateOnImport = $true
    }

    # --------------------------------------------------------------------------
    # Common Software Publishers (for quick adding)
    # --------------------------------------------------------------------------
    # Pre-defined publishers that can be quickly added to software lists

    CommonPublishers = @(
        @{ Name = "Microsoft"; Publisher = "MICROSOFT CORPORATION"; Category = "System" }
        @{ Name = "Adobe"; Publisher = "ADOBE INC."; Category = "Productivity" }
        @{ Name = "Google"; Publisher = "GOOGLE LLC"; Category = "Web" }
        @{ Name = "Mozilla"; Publisher = "MOZILLA CORPORATION"; Category = "Web" }
        @{ Name = "Oracle"; Publisher = "ORACLE AMERICA, INC."; Category = "Development" }
        @{ Name = "Citrix"; Publisher = "CITRIX SYSTEMS, INC."; Category = "Virtualization" }
        @{ Name = "VMware"; Publisher = "VMWARE, INC."; Category = "Virtualization" }
        @{ Name = "Dell"; Publisher = "DELL INC."; Category = "Hardware" }
        @{ Name = "HP"; Publisher = "HP INC."; Category = "Hardware" }
        @{ Name = "Lenovo"; Publisher = "LENOVO"; Category = "Hardware" }
        @{ Name = "Intel"; Publisher = "INTEL CORPORATION"; Category = "Hardware" }
        @{ Name = "NVIDIA"; Publisher = "NVIDIA CORPORATION"; Category = "Hardware" }
        @{ Name = "AMD"; Publisher = "ADVANCED MICRO DEVICES, INC."; Category = "Hardware" }
        @{ Name = "Zoom"; Publisher = "ZOOM VIDEO COMMUNICATIONS, INC."; Category = "Communication" }
        @{ Name = "Slack"; Publisher = "SLACK TECHNOLOGIES, LLC"; Category = "Communication" }
        @{ Name = "Atlassian"; Publisher = "ATLASSIAN PTY LTD"; Category = "Development" }
        @{ Name = "JetBrains"; Publisher = "JETBRAINS S.R.O."; Category = "Development" }
        @{ Name = "7-Zip"; Publisher = "IGOR PAVLOV"; Category = "Utilities" }
        @{ Name = "Notepad++"; Publisher = "NOTEPAD++"; Category = "Utilities" }
        @{ Name = "WinRAR"; Publisher = "ALEXANDER ROSHAL"; Category = "Utilities" }
    )

    # --------------------------------------------------------------------------
    # Software Categories
    # --------------------------------------------------------------------------
    # Standard categories for organizing software lists

    SoftwareCategories = @(
        "System"
        "Productivity"
        "Communication"
        "Development"
        "Security"
        "Utilities"
        "Web"
        "Virtualization"
        "Hardware"
        "Database"
        "Media"
        "Internal"
        "Discovered"
        "Uncategorized"
    )

    # --------------------------------------------------------------------------
    # Remote Scan Limits
    # --------------------------------------------------------------------------
    # Performance limits for remote scanning to prevent timeouts and
    # overwhelming target systems. Adjust based on your environment.

    ScanLimits = @{
        # Maximum files to scan per path (prevents timeout on large folders)
        MaxFilesPerPath = 5000

        # Maximum directories to check for writable permissions per base path
        MaxDirectoriesPerPath = 2000

        # Default throttle limit for concurrent remote connections
        DefaultThrottleLimit = 10

        # Maximum throttle limit allowed
        MaxThrottleLimit = 100

        # Minimum throttle limit
        MinThrottleLimit = 1
    }

    # --------------------------------------------------------------------------
    # Event Collection Settings
    # --------------------------------------------------------------------------
    # Settings for AppLocker audit event collection

    EventCollection = @{
        # Default number of days to look back for events
        DefaultDaysBack = 14

        # Maximum days to look back (0 = unlimited)
        MaxDaysBack = 365

        # Event IDs to collect
        BlockedEventIds = @(8003, 8004, 8006, 8007)  # "Would have been blocked"
        AllowedEventIds = @(8002, 8005)               # "Would have been allowed"
    }

    # --------------------------------------------------------------------------
    # Health Check Thresholds
    # --------------------------------------------------------------------------
    # Thresholds for rule health checking

    HealthCheck = @{
        # Points deducted per issue severity
        CriticalDeduction = 20
        WarningDeduction = 5
        InfoDeduction = 1

        # Minimum health score to pass
        MinimumPassScore = 50

        # Maximum rules before warning about policy size
        MaxRulesWarning = 500
    }
}
