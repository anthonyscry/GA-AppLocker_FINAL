# GA-AppLocker Development Changelog

This file tracks significant changes made during Claude Code sessions.

---

## 2026-01-16 - Session: fix-workflow-scroll-3R17m

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

### Documentation
- Added Session Context Management to claude.md
- Added Test Coverage Requirements to claude.md
- Created `.context/` directory structure for session continuity

### UI Changes
- Deployment Workflow box: scrollable with MaxHeight=300
- Available Templates: reduced height to 300px
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
