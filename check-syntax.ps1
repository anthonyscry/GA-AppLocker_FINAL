$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile('C:\projects\GA-AppLocker_FINAL\src\lib\Common.psm1', [ref]$null, [ref]$errors)
Write-Host "Errors: $($errors.Count)"
if ($errors) {
    $errors | Select-Object -First 10 | ForEach-Object {
        Write-Host "Line $($_.Extent.StartLineNumber): $($_.Message)"
    }
}
