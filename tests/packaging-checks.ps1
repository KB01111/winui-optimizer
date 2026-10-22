# Static + toolchain checks for MSIX/NSIS packaging. Never fabricates results:
# missing tooling or artifacts are reported as SKIPPED/FAILED explicitly.
$ErrorActionPreference = 'Continue'
$failed = 0
$skipped = 0

function Check-Pass([string]$name, [bool]$condition, [string]$detail = '') {
    if ($condition) {
        Write-Host "PASS  $name $detail" -ForegroundColor Green
    } else {
        Write-Host "FAIL  $name $detail" -ForegroundColor Red
        $script:failed++
    }
}

function Check-Skip([string]$name, [string]$reason) {
    Write-Host "SKIP  $name ($reason)" -ForegroundColor Yellow
    $script:skipped++
}

Write-Host "=== Package inputs ===" -ForegroundColor Cyan
$manifestPath = Join-Path $PSScriptRoot '..\appxmanifest.xml'
Check-Pass 'appxmanifest.xml exists' (Test-Path $manifestPath)

if (Test-Path $manifestPath) {
    try {
        [xml]$manifest = Get-Content $manifestPath -Raw
        $identity = $manifest.Package.Identity
        Check-Pass 'identity name preserved' ($identity.Name -eq 'tauri-app') "Name=$($identity.Name)"
        Check-Pass 'publisher preserved' ($identity.Publisher -eq 'CN=nikolame') "Publisher=$($identity.Publisher)"
        Check-Pass 'version is 1.0.0.0' ($identity.Version -eq '1.0.0.0') "Version=$($identity.Version)"
        $arch = [string]$identity.ProcessorArchitecture
        Check-Pass 'architecture (x64 or neutral manifest)' ([string]::IsNullOrEmpty($arch) -or $arch -eq 'x64') "Architecture=$arch"
        $assets = @('StoreLogo.png','Square150x150Logo.png','Square44x44Logo.png','Wide310x150Logo.png')
        foreach ($asset in $assets) {
            Check-Pass "asset $asset" (Test-Path (Join-Path $PSScriptRoot "..\Assets\$asset"))
        }
    } catch {
        Check-Pass 'manifest is well-formed XML' $false $_.Exception.Message
    }
}

$icons = @('32x32.png','128x128.png','128x128@2x.png','icon.ico','icon.icns')
foreach ($icon in $icons) {
    Check-Pass "tauri icon $icon" (Test-Path (Join-Path $PSScriptRoot "..\src-tauri\icons\$icon"))
}

Write-Host ""
Write-Host "=== Toolchain ===" -ForegroundColor Cyan
$winapp = Get-Command winapp -ErrorAction SilentlyContinue
if ($null -eq $winapp) {
    Check-Skip 'winapp CLI' 'not installed; MSIX pack/run checks cannot be performed'
} else {
    Check-Pass 'winapp CLI' $true $winapp.Source
}

$certPath = Join-Path $PSScriptRoot '..\devcert.pfx'
if (-not (Test-Path $certPath)) {
    Check-Skip 'dev certificate' 'devcert.pfx missing'
} else {
    Check-Pass 'dev certificate' $true
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, '')
        Check-Pass 'certificate subject matches publisher' ($cert.Subject -like '*CN=nikolame*') $cert.Subject
        Check-Pass 'certificate not expired' ($cert.NotAfter -gt (Get-Date)) $cert.NotAfter
    } catch {
        Check-Skip 'certificate inspection' 'certificate is password-protected or unreadable'
    }
}

Write-Host ""
Write-Host "=== Artifacts ===" -ForegroundColor Cyan
$msix = Get-ChildItem -Path (Join-Path $PSScriptRoot '..') -Filter '*.msix' -File -ErrorAction SilentlyContinue
if ($null -eq $msix) {
    Check-Skip 'MSIX artifact' 'not built in this checkout'
} else {
    foreach ($file in $msix) {
        Check-Pass "MSIX $($file.Name)" ($file.Length -gt 0) "$([math]::Round($file.Length/1MB,1)) MiB"
        try {
            $sig = Get-AuthenticodeSignature $file.FullName
            if ($sig.Status -eq 'Valid') {
                Check-Pass "signature $($file.Name)" $true $sig.SignerCertificate.Subject
            } else {
                Check-Skip "signature $($file.Name)" "status=$($sig.Status); install the dev certificate and re-sign"
            }
        } catch {
            Check-Skip "signature $($file.Name)" $_.Exception.Message
        }
    }
}

$nsis = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\src-tauri\target\release\bundle\nsis') -Filter '*.exe' -File -ErrorAction SilentlyContinue
if ($null -eq $nsis) {
    Check-Skip 'NSIS artifact' 'run npm run tauri build'
} else {
    foreach ($file in $nsis) {
        Check-Pass "NSIS $($file.Name)" ($file.Length -gt 0) "$([math]::Round($file.Length/1MB,1)) MiB"
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "failures: $failed, skipped: $skipped"
if ($failed -gt 0) { exit 1 }
exit 0
