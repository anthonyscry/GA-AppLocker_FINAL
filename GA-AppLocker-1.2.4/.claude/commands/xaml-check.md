# Validate XAML Files

Validate that all XAML content in the project loads correctly without runtime errors.

## Instructions

1. Find all PowerShell files that contain embedded XAML:
```powershell
Get-ChildItem -Path ./GUI -Filter "*.ps1" -Recurse |
    Select-String -Pattern '\[xml\]\$\w+\s*=\s*@"' -List
```

2. For each file with embedded XAML, run the validation script:
```powershell
./GUI/Scripts/Test-XamlValidation.ps1
```

3. If the validation script doesn't exist, create it and run validation manually:

```powershell
# Extract and validate XAML from GA-AppLocker-Portable.ps1
$content = Get-Content -Path ./GUI/GA-AppLocker-Portable.ps1 -Raw

# Find XAML here-string
if ($content -match '(?s)\[xml\]\$xaml\s*=\s*@"(.+?)"@') {
    $xamlContent = $matches[1]
    try {
        [xml]$testXaml = $xamlContent
        Write-Host "[PASS] XAML is valid XML" -ForegroundColor Green

        # Check for required namespaces
        $root = $testXaml.DocumentElement
        if ($root.NamespaceURI -eq 'http://schemas.microsoft.com/winfx/2006/xaml/presentation') {
            Write-Host "[PASS] WPF namespace is correct" -ForegroundColor Green
        }

        # Check for x:Name attributes
        $namedElements = $testXaml.SelectNodes("//*[@*[local-name()='Name']]")
        Write-Host "[INFO] Found $($namedElements.Count) named elements" -ForegroundColor Cyan

    } catch {
        Write-Host "[FAIL] XAML parsing error: $_" -ForegroundColor Red
    }
}
```

4. Common XAML issues to check:
   - **Missing closing tags**: Ensure all elements are properly closed
   - **Invalid attribute values**: Check Color, Thickness, Margin values
   - **Duplicate x:Name**: Each name must be unique
   - **Missing xmlns declarations**: Ensure all namespaces are declared
   - **Invalid resource references**: Check StaticResource/DynamicResource keys

5. If XAML fails to load:
   - Identify the exact line/element causing the error
   - Check for typos in element names or attributes
   - Verify resource keys exist in Window.Resources
   - Check for unsupported WPF features in the target .NET version

## Validation Checklist

- [ ] XAML parses as valid XML
- [ ] All x:Name attributes are unique
- [ ] All StaticResource references have matching keys
- [ ] All event handler names follow naming conventions
- [ ] No deprecated WPF properties used
- [ ] Proper namespace prefixes (x:, local:, etc.)

## Output

Report for each XAML block:
- File location
- Validation status (PASS/FAIL)
- Named elements count
- Any warnings or errors
- Suggested fixes for failures
