$guiPath = "C:\projects\GA-AppLocker_FINAL\build\GA-AppLocker-GUI-WPF.ps1"
Write-Host "Checking: $guiPath"
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$errors)
Write-Host "Errors found: $($errors.Count)"
if ($errors) {
    $errors | Select-Object -First 10 | ForEach-Object {
        Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)"
    }
}
