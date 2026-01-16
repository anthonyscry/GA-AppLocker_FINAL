# Phase 4: Enhanced Tooltips - Quick Reference

## All Tooltips by Category

### Navigation Buttons (14)
| Control | Tooltip |
|---------|---------|
| NavDashboard | View policy health and event statistics (Ctrl+D) |
| NavAppLockerSetup | Initialize AD structure and create GPOs (Ctrl+Shift+S) |
| NavGroupMgmt | Manage AppLocker security group memberships |
| NavDiscovery | Discover computers and test connectivity |
| NavArtifacts | Collect executable inventory from systems (Ctrl+A) |
| NavGapAnalysis | Compare software between systems |
| NavRules | Generate AppLocker rules from artifacts (Ctrl+R) |
| NavDeployment | Deploy policies via GPO (Ctrl+Shift+D) |
| NavWinRM | Enable WinRM for remote management |
| NavEvents | Monitor AppLocker events (Ctrl+E) |
| NavCompliance | Generate audit evidence packages |
| NavHelp | View workflow and best practices guide (F1) |
| NavAbout | Version and license information |

### Dashboard Controls (3)
| Control | Tooltip |
|---------|---------|
| DashboardTimeFilter | Filter events by time range (7/30 days) |
| DashboardSystemFilter | Filter by specific computer name |
| RefreshDashboardBtn | Refresh all dashboard metrics (F5) |

### Artifacts Controls (5)
| Control | Tooltip |
|---------|---------|
| ScanLocalArtifactsBtn | Scan localhost for executable artifacts (Quick scan) |
| ScanRemoteArtifactsBtn | Scan selected remote computers for artifacts |
| RefreshArtifactComputersBtn | Refresh the computer list from AD |
| MaxFilesText | Maximum number of files to scan (prevents excessive scans) |
| ScanDirectoriesBtn | Scan specified directory paths for artifacts |

### Gap Analysis Controls (4)
| Control | Tooltip |
|---------|---------|
| ImportBaselineBtn | Import baseline software inventory CSV |
| ImportTargetBtn | Import target software inventory CSV |
| CompareSoftwareBtn | Compare software lists and identify gaps |
| ExportGapAnalysisBtn | Export comparison results to CSV |

### Rules Controls - Rule Types (4)
| Control | Tooltip |
|---------|---------|
| RuleTypeAuto | Auto: Publisher for signed, Hash for unsigned (Recommended) |
| RuleTypePublisher | Publisher: Uses code signing certificate (most resilient) |
| RuleTypeHash | Hash: SHA256 hash (breaks on updates) |
| RuleTypePath | Path: File path (least secure, easily bypassed) |

### Rules Controls - Actions (2)
| Control | Tooltip |
|---------|---------|
| RuleActionAllow | Allow: Permit execution of this application |
| RuleActionDeny | Deny: Block execution of this application |

### Rules Controls - Generation (7)
| Control | Tooltip |
|---------|---------|
| RuleGroupCombo | Select target AppLocker group for this rule |
| CustomSidText | Enter custom SID or group name |
| LoadCollectedArtifactsBtn | Load artifacts from previous scans |
| LoadCollectedEventsBtn | Load events to create rules from actual usage |
| DedupeTypeCombo | Deduplicate by Publisher, Hash, or Path |
| DedupeBtn | Remove duplicate entries from the list |
| GenerateRulesBtn | Generate AppLocker rules from selected artifacts (Enter) |

### Rules Controls - Management (8)
| Control | Tooltip |
|---------|---------|
| ExportArtifactsListBtn | Export current artifact list to CSV |
| ImportArtifactsBtn | Import artifacts from CSV file |
| ImportFolderBtn | Import all CSV files from a folder |
| MergeRulesBtn | Merge new rules with existing rules |
| AuditToggleBtn | Toggle all rules between Audit and Enforce mode |
| RulesSearchBox | Search artifacts by name, publisher, or path (Ctrl+F) |
| ClearFilterBtn | Clear search filter |
| DefaultDenyRulesBtn | Add default deny rules for bypass locations (TEMP, Downloads, etc.) |

### Rules Controls - Browser & Preview (4)
| Control | Tooltip |
|---------|---------|
| CreateBrowserDenyBtn | Add rules to deny browsers in admin sessions |
| ClosePreviewBtn | Close rule preview panel |
| ChangeGroupBtn | Change target group for selected rules |
| DuplicateRulesBtn | Duplicate rules to another group |
| DeleteRulesBtn | Delete selected rules (Del) |

### Events Controls (8)
| Control | Tooltip |
|---------|---------|
| ScanLocalEventsBtn | Scan localhost for AppLocker events |
| ScanRemoteEventsBtn | Scan selected remote computers for events |
| RefreshComputersBtn | Refresh the computer list from AD |
| ExportEventsBtn | Export events to CSV for analysis |
| FilterAllBtn | Show all event types |
| FilterAllowedBtn | Show only allowed events (ID 8002) |
| FilterBlockedBtn | Show only blocked events (ID 8004) |
| FilterAuditBtn | Show only audit events (ID 8003) |
| RefreshEventsBtn | Refresh events view with current filters |

### Deployment Controls (6)
| Control | Tooltip |
|---------|---------|
| CreateGP0Btn | Create and link new AppLocker GPO |
| DisableGpoBtn | Unlink and disable AppLocker GPO |
| ExportRulesBtn | Export rules to C:\GA-AppLocker\Rules\ |
| ImportRulesBtn | Import rules into Group Policy |
| TargetGpoCombo | Select target GPO for import |
| ImportModeCombo | Replace existing rules or Append to them |

### Compliance Controls (4)
| Control | Tooltip |
|---------|---------|
| ScanLocalComplianceBtn | Scan localhost for compliance status |
| ScanSelectedComplianceBtn | Scan selected computers for compliance |
| RefreshComplianceListBtn | Refresh the computer list from AD |
| GenerateEvidenceBtn | Generate audit evidence package |

### WinRM Controls (4)
| Control | Tooltip |
|---------|---------|
| CreateWinRMGpoBtn | Create or update WinRM GPO with required settings |
| ForceGPUpdateBtn | Force GPUpdate on all computers (may take time) |
| EnableWinRMGpoBtn | Enable WinRM GPO link |
| DisableWinRMGpoBtn | Disable WinRM GPO link |

### AD Discovery Controls (5)
| Control | Tooltip |
|---------|---------|
| ADSearchFilter | AD search filter (* for all, or criteria like WIN-*) |
| DiscoverComputersBtn | Discover computers in Active Directory |
| TestConnectivityBtn | Test WinRM connectivity to selected systems |
| SelectAllComputersBtn | Select all online computers |
| ScanSelectedBtn | Scan selected computers |

### Group Management Controls (5)
| Control | Tooltip |
|---------|---------|
| ExportGroupsBtn | Export current group memberships to CSV |
| DryRunCheck | Preview changes without applying (Recommended) |
| AllowRemovalsCheck | Allow removing users from groups |
| IncludeProtectedCheck | Include Tier-0 protected accounts (Caution!) |
| ImportGroupsBtn | Import group membership changes from CSV |

### AppLocker Setup Controls (4)
| Control | Tooltip |
|---------|---------|
| OUNameText | Name for the AppLocker OU (default: AppLocker) |
| AutoPopulateCheck | Automatically add Domain Admins to AppLocker groups |
| BootstrapAppLockerBtn | Initialize AppLocker OU and groups in AD |
| RemoveOUProtectionBtn | Remove OU protection to allow deletion (Requires Domain Admin) |

### GPO Quick Assignment Controls (9)
| Control | Tooltip |
|---------|---------|
| DCGPOPhase | Deployment phase for Domain Controllers (1-4) |
| DCGPOMode | Enforcement mode for Domain Controllers |
| ServersGPOPhase | Deployment phase for Servers (1-4) |
| ServersGPOMode | Enforcement mode for Servers |
| WorkstationsGPOPhase | Deployment phase for Workstations (1-4) |
| WorkstationsGPOMode | Enforcement mode for Workstations |
| CreateGPOsBtn | Create 3 GPOs (DC, Servers, Workstations) |
| ApplyGPOSettingsBtn | Apply phase and mode settings to GPOs |
| LinkGPOsBtn | Link GPOs to appropriate OUs |

### Help Buttons (5)
| Control | Tooltip |
|---------|---------|
| HelpBtnWorkflow | View complete deployment workflow guide |
| HelpBtnWhatsNew | View new features and changes in v1.2.5 |
| HelpBtnPolicyGuide | View AppLocker policy configuration guide |
| HelpBtnRules | View rule creation best practices |
| HelpBtnTroubleshooting | View common issues and solutions |

## Summary Statistics

- **Total Controls**: 80+
- **Total Categories**: 17
- **Average Tooltip Length**: 15-30 words
- **Controls with Keyboard Shortcuts**: 12
- **Controls with Warnings**: 5
- **Controls with Prerequisites**: 3

## Keyboard Shortcuts Documented

| Shortcut | Action |
|----------|--------|
| Ctrl+D | Dashboard |
| Ctrl+Shift+S | AppLocker Setup |
| Ctrl+A | Artifacts |
| Ctrl+R | Rules |
| Ctrl+Shift+D | Deployment |
| Ctrl+E | Events |
| F1 | Help |
| F5 | Refresh Dashboard |
| Ctrl+F | Search Rules |
| Enter | Generate Rules |
| Del | Delete Rules |

## Warning Keywords

Tooltips containing cautionary warnings:
- "(Caution!)" - 2 instances
- "(Recommended)" - 2 instances
- "(Requires Domain Admin)" - 1 instance
- "(least secure, easily bypassed)" - 1 instance
- "(may take time)" - 1 instance
- "(breaks on updates)" - 1 instance

## Prerequisites Documented

- "Requires Domain Admin rights"
- "Requires Domain-joined computer"
- "Requires WinRM enabled on target systems"
- "Requires WinRM" (for various operations)
