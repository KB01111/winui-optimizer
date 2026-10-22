# Runs the full local verification sequence. Reports the real exit code of
# every step; never turns a failure into a pass. Run from the repository root.
$ErrorActionPreference = 'Continue'
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    & $Action
    $code = $LASTEXITCODE
    $results.Add([pscustomobject]@{ Step = $Name; ExitCode = $code; Passed = ($code -eq 0) })
    return $code
}

$env:CARGO_TERM_COLOR = 'never'

Invoke-Step 'cargo fmt --check' { cargo fmt --all -- --check | Out-Host }
Invoke-Step 'cargo clippy' { cargo clippy --workspace --all-targets -- -D warnings | Out-Host }
Invoke-Step 'cargo test' { cargo test --workspace | Out-Host }
Invoke-Step 'frontend typecheck' { npm run typecheck | Out-Host }
Invoke-Step 'frontend lint' { npm run lint | Out-Host }
Invoke-Step 'frontend tests' { npm test | Out-Host }
Invoke-Step 'frontend build' { npm run build | Out-Host }

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-Host
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) step(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host "All automated steps passed." -ForegroundColor Green
exit 0
