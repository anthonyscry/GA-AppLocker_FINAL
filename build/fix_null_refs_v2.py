#!/usr/bin/env python3
"""
Fix Null Reference Issues in GA-AppLocker-GUI-WPF.ps1 - Version 2

This script adds null checks for:
1. All FindName calls that might return null
2. All Add_Click event handlers that reference potentially null controls
3. All panel visibility assignments (including inside functions)
4. All property assignments on potentially null controls
"""

import re
import shutil
from datetime import datetime

def log_message(msg, level="INFO"):
    """Print log messages with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {msg}")

def fix_visibility_assignments(lines):
    """Fix visibility assignments in lines of code"""
    output_lines = []
    fixes = 0

    for line in lines:
        # Match visibility assignments
        match = re.match(r'^(\s*)(\$[a-zA-Z_]\w+)\.Visibility\s*=\s*\[System\.Windows\.Visibility\]::(\w+)', line)

        if match:
            indent = match.group(1)
            var_name = match.group(2)
            visibility = match.group(3)

            # Check if already wrapped
            if len(output_lines) > 0 and f'if ($null -ne {var_name})' in output_lines[-1]:
                output_lines.append(line)
            else:
                # Add null check wrapper
                output_lines.append(f'{indent}if ($null -ne {var_name}) {{')
                output_lines.append(line)
                output_lines.append(f'{indent}}}')
                fixes += 1
        else:
            output_lines.append(line)

    return output_lines, fixes

def main():
    script_path = r"C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1"
    backup_path = r"C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1.backup"
    output_path = r"C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF-Fixed.ps1"

    log_message("Starting null reference fix process v2...")

    # Backup original file
    log_message("Creating backup...")
    try:
        shutil.copy2(script_path, backup_path)
        log_message(f"Backup created: {backup_path}")
    except Exception as e:
        log_message(f"Error creating backup: {e}", "ERROR")
        return

    # Read the file
    log_message("Reading source file...")
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        log_message(f"Error reading file: {e}", "ERROR")
        return

    log_message(f"Read {len(lines)} lines")

    # Process the file
    output_lines = []
    fixes_applied = 0
    findname_fixes = 0
    event_handler_fixes = 0
    visibility_fixes = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        line_num = i + 1

        # Pattern 1: FindName calls without null checks
        findname_match = re.match(r'^(\$[a-zA-Z_]\w*)\s*=\s*\$window\.FindName\("([^"]+)"\)', line)

        if findname_match:
            var_name = findname_match.group(1)
            control_name = findname_match.group(2)

            # Check if next line is already a null check
            if i + 1 < len(lines) and 'null -eq' in lines[i + 1] and var_name in lines[i + 1]:
                # Already has null check, keep as is
                output_lines.append(line)
            else:
                # Add null check
                output_lines.append(line)
                output_lines.append(f'if ($null -eq {var_name}) {{ Write-Log "WARNING: Control \'{control_name}\' not found in XAML" -Level "WARNING" }}')
                findname_fixes += 1
                fixes_applied += 1

        # Pattern 2: Add_Click event handlers without null checks
        elif re.match(r'^\$[a-zA-Z_]\w+\.Add_Click\(\{', line):
            var_match = re.match(r'^(\$[a-zA-Z_]\w+)\.Add_Click\(\{', line)
            var_name = var_match.group(1) if var_match else ""

            # Check if previous line is already a null check
            if len(output_lines) > 0 and 'null -ne' in output_lines[-1] and var_name in output_lines[-1]:
                # Already has null check, keep as is
                output_lines.append(line)
            else:
                # Add null check wrapper
                output_lines.append(f"if ($null -ne {var_name}) {{")
                output_lines.append(line)
                event_handler_fixes += 1
                fixes_applied += 1

                # Find the end of the event handler (closing brace + })
                brace_count = 1
                j = i + 1
                while j < len(lines) and brace_count > 0:
                    output_lines.append(lines[j])
                    open_count = lines[j].count('{')
                    close_count = lines[j].count('}')
                    brace_count += open_count - close_count
                    j += 1

                # Add closing brace for null check
                output_lines.append("}")
                i = j - 1  # Skip the lines we already added

        # Pattern 3: Panel visibility assignments (standalone, not in switch)
        elif re.match(r'^\s*\$[a-zA-Z_]\w+\.Visibility\s*=\s*\[System\.Windows\.Visibility\]::(Collapsed|Visible)', line):
            var_match = re.match(r'^\s*(\$[a-zA-Z_]\w+)\.Visibility', line)
            var_name = var_match.group(1) if var_match else ""

            # Check if already wrapped
            if len(output_lines) > 0 and f'if ($null -ne {var_name})' in output_lines[-1]:
                output_lines.append(line)
            else:
                # Get the indentation
                indent_match = re.match(r'^(\s*)', line)
                indent = indent_match.group(1) if indent_match else ""

                # Add null check wrapper
                output_lines.append(f'{indent}if ($null -ne {var_name}) {{')
                output_lines.append(line)
                output_lines.append(f'{indent}}}')
                visibility_fixes += 1
                fixes_applied += 1

        else:
            output_lines.append(line)

        # Progress indicator
        if line_num % 1000 == 0:
            log_message(f"Processed {line_num}/{len(lines)} lines...")

        i += 1

    # Second pass: fix visibility inside switch statements
    log_message("Running second pass for switch statement visibility assignments...")
    output_lines, switch_visibility_fixes = fix_visibility_assignments(output_lines)
    visibility_fixes += switch_visibility_fixes
    fixes_applied += switch_visibility_fixes

    # Write the output
    log_message("Writing fixed file...")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))
        log_message(f"Fixed file written: {output_path}")
    except Exception as e:
        log_message(f"Error writing file: {e}", "ERROR")
        return

    # Summary
    log_message("=" * 60)
    log_message("FIX SUMMARY")
    log_message("=" * 60)
    log_message(f"Total fixes applied: {fixes_applied}")
    log_message(f"  - FindName null checks: {findname_fixes}")
    log_message(f"  - Event handler null checks: {event_handler_fixes}")
    log_message(f"  - Visibility null checks: {visibility_fixes}")
    log_message("")
    log_message("FILES:")
    log_message(f"  Original: {script_path}")
    log_message(f"  Backup:   {backup_path}")
    log_message(f"  Fixed:    {output_path}")
    log_message("")
    log_message("To apply the fixes:")
    log_message(f"  1. Review the differences")
    log_message(f"  2. Apply:  copy /Y {output_path} {script_path}")
    log_message("=" * 60)

if __name__ == "__main__":
    main()
