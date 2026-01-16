# Quick Fix Guide - Control Initialization Errors

## The Problem
Error: "The property 'Text' cannot be found on this object"

**Cause:** Controls weren't being created as script-level variables, only stored in hashtable.

---

## The Solution (Already Applied)

The main GUI file has been updated with the fix. The key change is in `Initialize-UiControls`:

```powershell
# ✓ NOW DOES THIS (FIXED):
foreach ($name in $controlNames) {
    $control = $script:Window.FindName($name)
    if ($null -ne $control) {
        # Store in hashtable
        $script:Controls[$name] = $control

        # CREATE SCRIPT VARIABLE (the fix!)
        Set-Variable -Name $name -Value $control -Scope Script
    }
}
```

---

## How to Use Controls Safely

### Option 1: Direct Access (Now Works!)
```powershell
if ($null -ne $StatusText) {
    $StatusText.Text = "Ready"
}
```

### Option 2: Hashtable Access
```powershell
if ($script:Controls.ContainsKey("StatusText") -and $null -ne $script:Controls["StatusText"]) {
    $script:Controls["StatusText"].Text = "Ready"
}
```

### Option 3: Safe Helper (Best Practice)
```powershell
Set-ControlProperty "StatusText" "Text" "Ready"
```

---

## Testing the Fix

Run the diagnostic test:
```powershell
.\Test-ControlInitialization.ps1 -Verbose
```

This will:
- Show which controls are found
- List any missing controls
- Verify critical controls exist
- Generate a detailed report

---

## Files Modified

1. `/src/GUI/Main/GA-AppLocker-GUI.ps1` - Main fix applied
2. `/src/GUI/Core/Control-Initialization-Fix.ps1` - Helper functions (NEW)
3. `/Test-ControlInitialization.ps1` - Test script (NEW)

---

## Critical Controls to Verify

Make sure these exist:
- StatusText
- HeaderVersion
- PanelDashboard
- PanelRules
- PanelEvents
- NavDashboard
- NavRules
- NavEvents

---

## Next Steps

1. Test the GUI startup
2. Run the diagnostic script
3. Review any missing controls
4. Update UI-Helpers.ps1 if needed (add null checks)

---

## Need Help?

See the full report: `CONTROL_INITIALIZATION_FIX_REPORT.md`
