# GA-AppLocker Development Changelog

This file tracks significant changes made during Claude Code sessions.

---

## 2026-01-16 - Session: fix-workflow-scroll-3R17m (Continued)

### New Features (v1.2.6)
- **Template Manager** - Unified tabbed interface combining Browse, Create, and Import
  - Browse Templates tab: Search, filter, preview, apply templates
  - Create Template tab: Build from rules, artifacts, or empty
  - Import Template tab: Import from JSON or AppLocker XML
- **Enhanced Help Panel** - Completely revamped with:
  - Visual Quick Start Guide (4-step workflow)
  - Organized documentation topics with styled buttons
  - New Keyboard Shortcuts reference section
  - Quick Links section for common file locations
- **Event Handlers** - Added for all new Template Manager controls

### Test Coverage
- Created GA-AppLocker.Integration.Tests.ps1 (60+ tests)
- Created GA-AppLocker.E2E.Tests.ps1 (40+ tests)
- Created GA-AppLocker.RuleGenerator.Tests.ps1 (50+ tests)

### Critical Bug Fixes
- **New-PathRule function added** - Path rule generation was completely missing
- **GPO import parameter fixed** - Changed `-PolicyXml` to `-PolicyXmlPath`, now saves to temp file
- **Convert-RulesToAppLockerXml implemented** - Was placeholder returning empty template
- **Property name mismatches fixed** - `publisherName`/`publisher`, `FileHash`/`hash`
- **Admin elevation check** - Added to `New-WinRMGpo` function
- **Null safety** - Added checks to `Show-Panel` (15 cases), `Update-StatusBar`

### Code Quality
- Fixed artifact scanning property normalization (handles both cases)
- Removed orphaned `ScanDirectoriesBtn` references
- Fixed button enable/disable synchronization
- Added FindName bindings for 22 new Template Manager controls

### Documentation
- Added Session Context Management to claude.md
- Added Test Coverage Requirements to claude.md
- Created `.context/` directory structure for session continuity
- Updated What's New help content for v1.2.6

### UI Changes
- Template navigation: Consolidated 3 buttons into 1 "Template Manager" button
- Template Manager panel: New TabControl with styled tabs
- Help panel: Complete redesign with Quick Start Guide
- Deployment Workflow box: scrollable with MaxHeight=300
- Available Templates list: reduced height to 350px (inside tab)
- Discovered Artifacts: scrollable with MaxHeight=350
- Export Events button: moved next to Refresh Events
- WIP panels greyed out: Compliance Reports, SIEM Integration, Policy Simulator

---

## Previous Changes (Pre-Session Logging)

### v1.2.5 Features
- Search/Filter for artifacts and rules
- Audit Toggle for deployment
- Rule Preview before generation
- Mini Status Bar
- Bulk Confirmation dialogs
- Quick Date Presets for events

### Known Technical Debt
- Module4-PolicyLab.psm1:259 - Namespace typo
- Module7-Compliance.psm1:219 - Wrong module import
- Module6-ADManager.psm1:528 - Return value logic error
- ActiveDirectory module imported per-function (performance)
- No caching for expensive AD queries
