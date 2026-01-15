@{
    # Script module or binary module file associated with this manifest
    RootModule = 'GA-AppLocker.psm1'

    # Version number of this module
    ModuleVersion = '1.2.4'

    # ID used to uniquely identify this module
    GUID = 'f8d4a7c2-9e3b-4f6a-8d1c-5b2e9f0a3c7d'

    # Author of this module
    Author = 'Tony Tran'

    # Company or vendor of this module
    CompanyName = 'GA-ASI'

    # Copyright statement for this module
    Copyright = '(c) 2024-2026 GA-ASI. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'GA-AppLocker is a simplified AppLocker deployment toolkit for Windows security administrators. It automates creating and managing Windows AppLocker policies through inventory collection, audit event analysis, and policy generation.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'src\Utilities\Common.psm1',
        'src\Utilities\ErrorHandling.psm1'
    )

    # Functions to export from this module
    FunctionsToExport = @(
        # Main workflow
        'Start-AppLockerWorkflow',

        # Scanning
        'Invoke-RemoteScan',

        # Event Collection
        'Invoke-RemoteEventCollection',

        # Policy Generation
        'New-AppLockerPolicyFromGuide',

        # Policy Management
        'Merge-AppLockerPolicies',

        # Validation
        'Test-AppLockerPolicy',
        'Test-ScanData',
        'Compare-AppLockerPolicies',

        # SID Resolution (from Common.psm1)
        'Resolve-AccountToSid',
        'Resolve-AccountsToSids',
        'Get-StandardPrincipalSids',
        'Clear-SidCache',
        'Get-SidCacheStats',

        # Configuration
        'Get-AppLockerConfig',

        # Logging
        'Start-Logging',
        'Write-Log',
        'Stop-Logging',

        # Utilities
        'Get-ComputerList',
        'Confirm-Directory',

        # Error Handling (from ErrorHandling.psm1)
        'Invoke-SafeOperation',
        'Write-ErrorMessage',
        'Test-ValidPath',
        'Test-ValidXml',
        'Test-ValidAppLockerPolicy',
        'Test-ValidComputerList',
        'Test-RequiredKeys',
        'Write-SectionHeader',
        'Write-StepProgress',
        'Write-SuccessMessage',
        'Write-ResultSummary',
        'Initialize-GAAppLockerScript',
        'Test-CredentialValidity'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @(
        'gaapp'
    )

    # List of all files packaged with this module
    FileList = @(
        'GA-AppLocker.psd1',
        'GA-AppLocker.psm1',
        'GA-AppLocker.exe',
        'build\Build-AppLocker.ps1',
        'build\Build-Executable.ps1',
        'build\Build-GUI.ps1',
        'build\Invoke-LocalValidation.ps1',
        'build\Publish-ToGallery.ps1',
        'src\Core\Start-AppLockerWorkflow.ps1',
        'src\Core\Start-GUI.ps1',
        'src\Core\Invoke-RemoteScan.ps1',
        'src\Core\Invoke-RemoteEventCollection.ps1',
        'src\Core\New-AppLockerPolicyFromGuide.ps1',
        'src\Core\Merge-AppLockerPolicies.ps1',
        'src\Utilities\Common.psm1',
        'src\Utilities\Config.psd1',
        'src\Utilities\ErrorHandling.psm1',
        'src\Utilities\CredentialManager.psm1',
        'src\Utilities\Manage-SoftwareLists.ps1',
        'src\Utilities\Compare-SoftwareInventory.ps1',
        'src\Utilities\Test-AppLockerDiagnostic.ps1',
        'src\Utilities\Enable-WinRM-Domain.ps1',
        'src\Utilities\Manage-ADResources.ps1',
        'src\Utilities\Start-AppLockerMonitor.ps1',
        'src\Utilities\Export-AppLockerGPO.ps1',
        'src\Utilities\Get-RuleImpactAnalysis.ps1',
        'src\Utilities\PolicyVersionControl.psm1',
        'src\Utilities\Invoke-PhaseAdvancement.ps1',
        'src\Utilities\WhitelistRequestManager.psm1',
        'src\Utilities\PolicyTemplates.psd1',
        'src\Utilities\New-PolicyFromTemplate.ps1',
        'src\Utilities\Test-RuleHealth.ps1',
        'src\GUI\GA-AppLocker-Portable.ps1',
        'src\GUI\AsyncHelpers.psm1'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for online gallery discovery
            Tags = @(
                'AppLocker',
                'Security',
                'Windows',
                'Policy',
                'ApplicationControl',
                'Whitelisting',
                'NIST',
                'CIS',
                'Compliance',
                'EnterpriseManagement'
            )

            # A URL to the license for this module
            LicenseUri = 'https://github.com/anthonyscry/GA-AppLocker/blob/main/LICENSE'

            # A URL to the main website for this project
            ProjectUri = 'https://github.com/anthonyscry/GA-AppLocker'

            # A URL to an icon representing this module
            IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
## Version 1.2.4
- Added embedded Help system with comprehensive in-app documentation
- Help page with 9 topics: Getting Started, Scanning, Policy Generation, Merging, Events, Software Lists, Deployment, Troubleshooting, FAQ
- Fixed duplicate status indicator in GUI (removed redundant workflow status)
- Updated icon to use general-atomics-logo.ico across all build scripts

## Version 1.2.3
- GUI cleanup: Consolidated XAML styles (PageTitle, PageSubtitle, CardTitle, FieldLabel, HintText)
- Compact UI: Reduced margins, padding, and spacing throughout
- Sidebar width reduced from 240 to 220 pixels
- Log panel height reduced from 180 to 150 pixels
- Code organization: Added region markers for event handlers
- Updated keyboard shortcut documentation

## Version 1.2.0
- Policy version control with Git-like versioning and rollback (PolicyVersionControl.psm1)
- Automatic phase advancement based on event analysis (Invoke-PhaseAdvancement.ps1)
- Self-service whitelist request workflow with approvals (WhitelistRequestManager.psm1)
- Pre-built industry policy templates: Financial, Healthcare, Government, etc. (New-PolicyFromTemplate.ps1)
- Rule health checking to detect broken/unused rules (Test-RuleHealth.ps1)

## Version 1.1.0
- PowerShell Gallery publication support (Publish-ToGallery.ps1)
- Scheduled monitoring mode with alerts (Start-AppLockerMonitor.ps1)
- GPO export formats: PowerShell, Registry, SCCM, Intune (Export-AppLockerGPO.ps1)
- Rule impact analysis with risk assessment (Get-RuleImpactAnalysis.ps1)
- Credential caching with DPAPI encryption (CredentialManager.psm1)
- Policy diff visualization (Show-PolicyDiff)
- Keyboard shortcuts in GUI (Ctrl+1-6, F1 help)
- Auto-detection on GUI startup

## Version 1.0.0
- Initial public release
- Remote computer scanning via WinRM
- AppLocker audit event collection (8003/8004)
- Policy generation in Build Guide and Simplified modes
- Policy merge and deduplication
- Software list management with publisher categories
- Policy validation and comparison
- Interactive CLI and portable GUI
- SID resolution caching for performance
- WhatIf support for policy generation
'@

            # Prerelease string of this module
            Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @()
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/anthonyscry/GA-AppLocker/wiki'

    # Default prefix for commands exported from this module
    DefaultCommandPrefix = ''
}
