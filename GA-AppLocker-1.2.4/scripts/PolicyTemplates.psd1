@{
    # Pre-built industry-specific AppLocker policy templates
    # These provide starting points for different organizational contexts

    Templates = @{

        #region Financial Services
        FinancialServices = @{
            Name = 'Financial Services Baseline'
            Description = 'Strict policy for financial institutions with regulatory compliance focus (SOX, PCI-DSS)'
            RiskLevel = 'High'
            Industries = @('Banking', 'Insurance', 'Investment', 'Fintech')
            Compliance = @('SOX', 'PCI-DSS', 'GLBA', 'FFIEC')

            EnforcementMode = 'AuditOnly'  # Start in audit

            # Trusted publishers for financial sector
            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=ADOBE INC.*',
                'O=BLOOMBERG L.P.*',
                'O=THOMSON REUTERS*',
                'O=INTUIT INC.*',
                'O=ORACLE*',
                'O=SAP SE*',
                'O=CITRIX*',
                'O=SYMANTEC*',
                'O=MCAFEE*',
                'O=CROWDSTRIKE*'
            )

            # Strict path rules
            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%WINDIR%\*'
            )

            # Financial services typically deny user-writable locations
            DeniedPaths = @(
                '%USERPROFILE%\Downloads\*',
                '%USERPROFILE%\Desktop\*.exe',
                '%APPDATA%\*.exe',
                '%LOCALAPPDATA%\*.exe',
                '%TEMP%\*'
            )

            # LOLBins to deny in financial environments
            DeniedExecutables = @(
                '*\mshta.exe',
                '*\wscript.exe',
                '*\cscript.exe',
                '*\powershell.exe',  # Often restricted to admins only
                '*\cmd.exe',
                '*\certutil.exe',
                '*\bitsadmin.exe',
                '*\regsvr32.exe'
            )

            # Phase recommendations
            RecommendedPhases = @{
                Phase1Duration = 30  # days
                Phase2Duration = 30
                Phase3Duration = 21
                Phase4Duration = 14
            }

            Notes = @'
Financial services require strict application control due to regulatory requirements.
- Deploy Phase 1 for minimum 30 days in audit mode
- Collect and analyze all blocked events before proceeding
- PowerShell execution should be restricted to IT/Admin groups
- Consider additional DLL rules for high-value systems
'@
        }
        #endregion

        #region Healthcare
        Healthcare = @{
            Name = 'Healthcare / HIPAA Baseline'
            Description = 'Policy template for healthcare organizations with HIPAA compliance requirements'
            RiskLevel = 'High'
            Industries = @('Hospital', 'Clinic', 'Pharmacy', 'Medical Device', 'Health Insurance')
            Compliance = @('HIPAA', 'HITECH', 'FDA 21 CFR Part 11')

            EnforcementMode = 'AuditOnly'

            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=EPIC SYSTEMS CORPORATION*',
                'O=CERNER CORPORATION*',
                'O=ALLSCRIPTS*',
                'O=MCKESSON*',
                'O=MEDITECH*',
                'O=CITRIX*',
                'O=VMWARE*',
                'O=ADOBE INC.*',
                'O=PHILIPS*',
                'O=GE HEALTHCARE*',
                'O=SIEMENS*'
            )

            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%PROGRAMFILES(X86)%\*',
                '%WINDIR%\*',
                # Common EMR installation paths
                'C:\Epic\*',
                'C:\Cerner\*'
            )

            DeniedPaths = @(
                '%USERPROFILE%\Downloads\*',
                '%TEMP%\*.exe',
                '%APPDATA%\*.exe'
            )

            DeniedExecutables = @(
                '*\mshta.exe',
                '*\wscript.exe',
                '*\cscript.exe',
                '*\certutil.exe'
            )

            RecommendedPhases = @{
                Phase1Duration = 21
                Phase2Duration = 21
                Phase3Duration = 14
                Phase4Duration = 14
            }

            Notes = @'
Healthcare environments require balancing security with clinical workflow needs.
- EMR/EHR applications are critical - ensure proper rules before enforcement
- Medical devices may require special path rules
- Consider separate policies for clinical vs administrative workstations
- HIPAA requires audit trails - keep audit mode data
'@
        }
        #endregion

        #region Government
        Government = @{
            Name = 'Government / NIST Baseline'
            Description = 'Hardened policy for government agencies following NIST guidelines'
            RiskLevel = 'Very High'
            Industries = @('Federal', 'State', 'Local', 'Defense', 'Intelligence')
            Compliance = @('NIST 800-53', 'FISMA', 'FedRAMP', 'CMMC', 'STIG')

            EnforcementMode = 'AuditOnly'

            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=ADOBE INC.*',
                'O=ORACLE*',
                'O=VMWARE*',
                'O=CITRIX*',
                # Security vendors
                'O=CROWDSTRIKE*',
                'O=CARBON BLACK*',
                'O=MCAFEE*',
                'O=SYMANTEC*',
                'O=TENABLE*'
            )

            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%WINDIR%\*'
                # Very restrictive - only system paths
            )

            DeniedPaths = @(
                '%USERPROFILE%\*\*.exe',
                '%APPDATA%\*',
                '%LOCALAPPDATA%\*',
                '%TEMP%\*',
                # USB and removable media
                'D:\*',
                'E:\*',
                'F:\*'
            )

            DeniedExecutables = @(
                '*\mshta.exe',
                '*\wscript.exe',
                '*\cscript.exe',
                '*\powershell.exe',
                '*\powershell_ise.exe',
                '*\cmd.exe',
                '*\certutil.exe',
                '*\bitsadmin.exe',
                '*\regsvr32.exe',
                '*\msiexec.exe',  # Restrict to admins
                '*\rundll32.exe',
                '*\regasm.exe',
                '*\regsvcs.exe',
                '*\msbuild.exe',
                '*\installutil.exe'
            )

            RecommendedPhases = @{
                Phase1Duration = 45
                Phase2Duration = 30
                Phase3Duration = 30
                Phase4Duration = 21
            }

            Notes = @'
Government systems require maximum security posture.
- Follow DISA STIGs for AppLocker configuration
- Deny all LOLBins for standard users
- Consider application-level allowlisting (not just publisher)
- DLL rules recommended for high-impact systems
- Maintain detailed audit logs for compliance
'@
        }
        #endregion

        #region Manufacturing
        Manufacturing = @{
            Name = 'Manufacturing / OT Baseline'
            Description = 'Balanced policy for manufacturing with OT/ICS integration considerations'
            RiskLevel = 'Medium-High'
            Industries = @('Manufacturing', 'Automotive', 'Aerospace', 'Industrial')
            Compliance = @('IEC 62443', 'NIST CSF', 'CIS Controls')

            EnforcementMode = 'AuditOnly'

            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=SIEMENS*',
                'O=ROCKWELL AUTOMATION*',
                'O=SCHNEIDER ELECTRIC*',
                'O=ABB*',
                'O=HONEYWELL*',
                'O=EMERSON*',
                'O=GE*',
                'O=AUTODESK*',
                'O=DASSAULT*',
                'O=PTC*'
            )

            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%PROGRAMFILES(X86)%\*',
                '%WINDIR%\*',
                # Common SCADA/HMI paths
                'C:\Siemens\*',
                'C:\Rockwell\*',
                'C:\FactoryTalk\*'
            )

            DeniedPaths = @(
                '%USERPROFILE%\Downloads\*.exe',
                '%TEMP%\*.exe'
            )

            DeniedExecutables = @(
                '*\mshta.exe',
                '*\wscript.exe',
                '*\cscript.exe'
            )

            RecommendedPhases = @{
                Phase1Duration = 30
                Phase2Duration = 21
                Phase3Duration = 21
                Phase4Duration = 0  # DLL rules often problematic with ICS
            }

            Notes = @'
Manufacturing environments must balance security with operational continuity.
- OT/ICS systems may require special exceptions
- Test thoroughly before enforcement - downtime can be costly
- HMI and SCADA applications are critical
- Consider separate policies for IT vs OT networks
- Phase 4 (DLL) rules may not be suitable for legacy ICS systems
'@
        }
        #endregion

        #region Education
        Education = @{
            Name = 'Education Baseline'
            Description = 'Flexible policy for educational institutions with diverse user needs'
            RiskLevel = 'Medium'
            Industries = @('K-12', 'Higher Education', 'Research', 'Library')
            Compliance = @('FERPA', 'COPPA', 'CIPA')

            EnforcementMode = 'AuditOnly'

            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=GOOGLE*',
                'O=APPLE*',
                'O=ADOBE INC.*',
                'O=ZOOM*',
                'O=CISCO*',
                'O=BLACKBOARD*',
                'O=CANVAS*',
                'O=PEARSON*',
                'O=MCGRAW-HILL*',
                'O=AUTODESK*',  # Student software
                'O=JETBRAINS*'
            )

            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%PROGRAMFILES(X86)%\*',
                '%WINDIR%\*',
                # Allow some user-installed apps for labs
                '%LOCALAPPDATA%\Programs\*'
            )

            DeniedPaths = @(
                '%USERPROFILE%\Downloads\*.exe',
                '%TEMP%\*.exe'
            )

            DeniedExecutables = @(
                '*\mshta.exe',
                '*\wscript.exe'
            )

            RecommendedPhases = @{
                Phase1Duration = 21
                Phase2Duration = 14
                Phase3Duration = 14
                Phase4Duration = 0  # DLL rules typically too restrictive
            }

            Notes = @'
Educational environments need flexibility for diverse learning activities.
- Student devices may need more permissive policies
- Faculty/staff devices can be more restrictive
- Computer labs often need different policies than offices
- Consider time-based rules for after-hours lockdown
- Research environments may need exceptions for custom software
'@
        }
        #endregion

        #region Retail
        Retail = @{
            Name = 'Retail / POS Baseline'
            Description = 'Locked-down policy for retail environments with POS systems'
            RiskLevel = 'High'
            Industries = @('Retail', 'Hospitality', 'Restaurant', 'Entertainment')
            Compliance = @('PCI-DSS', 'PA-DSS')

            EnforcementMode = 'AuditOnly'

            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=ORACLE*',  # MICROS
                'O=NCR*',
                'O=VERIFONE*',
                'O=INGENICO*',
                'O=SQUARE*',
                'O=TOAST*',
                'O=LIGHTSPEED*'
            )

            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%WINDIR%\*',
                # POS specific paths
                'C:\POS\*',
                'C:\MICROS\*'
            )

            DeniedPaths = @(
                '%USERPROFILE%\*',
                '%APPDATA%\*',
                '%LOCALAPPDATA%\*',
                '%TEMP%\*'
            )

            DeniedExecutables = @(
                '*\mshta.exe',
                '*\wscript.exe',
                '*\cscript.exe',
                '*\powershell.exe',
                '*\cmd.exe',
                '*\certutil.exe',
                '*\bitsadmin.exe'
            )

            RecommendedPhases = @{
                Phase1Duration = 14
                Phase2Duration = 14
                Phase3Duration = 7
                Phase4Duration = 7
            }

            Notes = @'
Retail/POS systems require tight security for payment card compliance.
- POS terminals should be extremely locked down
- Back-office systems can have slightly more flexibility
- PCI-DSS requires strong application controls
- Consider kiosk mode for customer-facing systems
- Deny all browser and email on POS terminals
'@
        }
        #endregion

        #region Startup / Small Business
        SmallBusiness = @{
            Name = 'Small Business / Startup'
            Description = 'Balanced policy for small businesses prioritizing productivity with reasonable security'
            RiskLevel = 'Medium-Low'
            Industries = @('Startup', 'SMB', 'Professional Services', 'Consulting')
            Compliance = @('General Best Practices', 'CIS Controls Lite')

            EnforcementMode = 'AuditOnly'

            TrustedPublishers = @(
                'O=MICROSOFT CORPORATION*',
                'O=GOOGLE*',
                'O=APPLE*',
                'O=ADOBE INC.*',
                'O=ZOOM*',
                'O=SLACK*',
                'O=ATLASSIAN*',
                'O=DROPBOX*',
                'O=SALESFORCE*',
                'O=HUBSPOT*',
                'O=JETBRAINS*',
                'O=GITHUB*'
            )

            AllowedPaths = @(
                '%PROGRAMFILES%\*',
                '%PROGRAMFILES(X86)%\*',
                '%WINDIR%\*',
                '%LOCALAPPDATA%\Programs\*',  # Allow user-installed apps
                '%LOCALAPPDATA%\Microsoft\Teams\*'
            )

            DeniedPaths = @(
                '%TEMP%\*.exe'
            )

            DeniedExecutables = @(
                '*\mshta.exe'
            )

            RecommendedPhases = @{
                Phase1Duration = 14
                Phase2Duration = 7
                Phase3Duration = 7
                Phase4Duration = 0  # Often skipped for productivity
            }

            Notes = @'
Small businesses need to balance security with agility.
- Start with minimal restrictions
- Allow common productivity tools
- Focus on blocking obvious malware vectors
- Phase 4 (DLL) typically not needed
- Can tighten over time as security matures
'@
        }
        #endregion
    }

    # Common publisher lists for reference
    CommonPublishers = @{
        Microsoft = @(
            'O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'
        )
        Security = @(
            'O=CROWDSTRIKE*',
            'O=CARBON BLACK*',
            'O=MCAFEE*',
            'O=SYMANTEC*',
            'O=NORTON*',
            'O=TREND MICRO*',
            'O=KASPERSKY*',
            'O=ESET*',
            'O=SOPHOS*',
            'O=MALWAREBYTES*'
        )
        Productivity = @(
            'O=ADOBE INC.*',
            'O=GOOGLE*',
            'O=SLACK*',
            'O=ZOOM*',
            'O=ATLASSIAN*',
            'O=NOTION*',
            'O=ASANA*'
        )
        Development = @(
            'O=JETBRAINS*',
            'O=GITHUB*',
            'O=DOCKER*',
            'O=NODEJS*',
            'O=PYTHON*',
            'O=ORACLE*'  # Java
        )
    }
}
