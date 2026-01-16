<#
.SYNOPSIS
    Code signing script for GA-AppLocker Dashboard v2.0
.DESCRIPTION
    Signs all PowerShell scripts with a code signing certificate to prevent
    false positives from antivirus/EDR software.
.NOTES
    Author: GA-ASI
    Version: 1.0.0
    Requires: Code signing certificate in CurrentUser\My store
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory=$false)]
    [string]$TimestampServer = "http://timestamp.digicert.com",

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  GA-AppLocker Code Signing Utility" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Step 1: Find code signing certificate
Write-Host "[1/4] Locating code signing certificate..." -ForegroundColor Yellow

if ($CertificateThumbprint) {
    $cert = Get-ChildItem Cert:\CurrentUser\My\$CertificateThumbprint -ErrorAction SilentlyContinue
    if (-not $cert) {
        Write-Error "Certificate with thumbprint $CertificateThumbprint not found"
    }
} else {
    # Find all code signing certs
    $certs = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert

    if ($certs.Count -eq 0) {
        Write-Host ""
        Write-Host "ERROR: No code signing certificates found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "To obtain a code signing certificate:" -ForegroundColor Yellow
        Write-Host "  1. Request from your corporate Certificate Authority (CA)" -ForegroundColor White
        Write-Host "  2. Or use makecert.exe for testing (NOT for production):" -ForegroundColor White
        Write-Host ""
        Write-Host '     makecert -n "CN=GA-AppLocker Dev" -r -sv DevCert.pvk DevCert.cer' -ForegroundColor Gray
        Write-Host '     pvk2pfx -pvk DevCert.pvk -spc DevCert.cer -pfx DevCert.pfx' -ForegroundColor Gray
        Write-Host '     Import-PfxCertificate -FilePath DevCert.pfx -CertStoreLocation Cert:\CurrentUser\My' -ForegroundColor Gray
        Write-Host ""
        exit 1
    }

    if ($certs.Count -eq 1) {
        $cert = $certs[0]
        Write-Host "  Found certificate: $($cert.Subject)" -ForegroundColor Green
    } else {
        Write-Host "  Multiple certificates found. Please choose:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $certs.Count; $i++) {
            Write-Host "    [$i] $($certs[$i].Subject) (Expires: $($certs[$i].NotAfter))" -ForegroundColor White
        }
        $selection = Read-Host "  Enter number"
        $cert = $certs[$selection]
    }
}

Write-Host "  Using: $($cert.Subject)" -ForegroundColor Green
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
Write-Host "  Expires: $($cert.NotAfter)" -ForegroundColor Gray
Write-Host ""

# Step 2: Find all PowerShell files
Write-Host "[2/4] Scanning for PowerShell files..." -ForegroundColor Yellow

$files = @(
    Get-ChildItem -Path "$PSScriptRoot\src" -Recurse -Filter "*.ps1" -File
    Get-ChildItem -Path "$PSScriptRoot\build" -Filter "*.ps1" -File
    Get-ChildItem -Path "$PSScriptRoot" -Filter "*.ps1" -File -Depth 1
)

Write-Host "  Found $($files.Count) PowerShell files to sign" -ForegroundColor Green
Write-Host ""

# Step 3: Sign files
Write-Host "[3/4] Signing files..." -ForegroundColor Yellow

$signed = 0
$failed = 0
$skipped = 0

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace($PSScriptRoot, ".")

    # Check if already signed
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName
    if ($signature.Status -eq "Valid" -and $signature.SignerCertificate.Thumbprint -eq $cert.Thumbprint) {
        Write-Host "  [SKIP] $relativePath (already signed)" -ForegroundColor Gray
        $skipped++
        continue
    }

    if ($WhatIf) {
        Write-Host "  [WHAT-IF] Would sign: $relativePath" -ForegroundColor Cyan
        continue
    }

    try {
        $result = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -TimestampServer $TimestampServer -ErrorAction Stop

        if ($result.Status -eq "Valid") {
            Write-Host "  [OK] $relativePath" -ForegroundColor Green
            $signed++
        } else {
            Write-Host "  [FAIL] $relativePath - Status: $($result.Status)" -ForegroundColor Red
            $failed++
        }
    }
    catch {
        Write-Host "  [ERROR] $relativePath - $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""

# Step 4: Summary
Write-Host "[4/4] Summary" -ForegroundColor Yellow
Write-Host "  Total files: $($files.Count)" -ForegroundColor White
Write-Host "  Signed: $signed" -ForegroundColor Green
Write-Host "  Skipped (already signed): $skipped" -ForegroundColor Gray
Write-Host "  Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "White" })
Write-Host ""

if ($WhatIf) {
    Write-Host "This was a dry run. Remove -WhatIf to actually sign files." -ForegroundColor Cyan
    Write-Host ""
}

if ($failed -eq 0 -and -not $WhatIf) {
    Write-Host "SUCCESS: All files signed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your PowerShell scripts are now digitally signed and should be" -ForegroundColor White
    Write-Host "trusted by Windows SmartScreen and most antivirus software." -ForegroundColor White
    Write-Host ""
} elseif ($failed -gt 0) {
    Write-Host "WARNING: $failed files failed to sign. Check errors above." -ForegroundColor Red
    exit 1
}
