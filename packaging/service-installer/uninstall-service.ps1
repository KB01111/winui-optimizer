#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the AI Antivirus Security Engine service.

.DESCRIPTION
    Stops the service if needed and deletes its Service Control Manager entry.
    The database, logs and quarantine vault in %ProgramData%\AiAntivirus are
    preserved by default. Pass -PurgeData to delete them as well.

.PARAMETER DataDirectory
    Data root that -PurgeData removes. Defaults to %ProgramData%\AiAntivirus.

.PARAMETER PurgeData
    Delete the data directory (database, logs and quarantined files). This is
    irreversible. Without this switch the vault and database are preserved.

.EXAMPLE
    .\uninstall-service.ps1

.EXAMPLE
    .\uninstall-service.ps1 -PurgeData
#>
[CmdletBinding()]
param(
    [string]$DataDirectory = (Join-Path $env:ProgramData 'AiAntivirus'),
    [switch]$PurgeData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'AiAntivirusSecurityService'

function Wait-ForServiceDeletion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [TimeSpan]$Timeout = [TimeSpan]::FromSeconds(15)
    )

    $deadline = (Get-Date) + $Timeout
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "Service $ServiceName is not installed."
} else {
    if ($existing.Status -ne 'Stopped') {
        Write-Host "Stopping $ServiceName"
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    Write-Host "Deleting $ServiceName"
    $output = & sc.exe delete $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("sc.exe delete $ServiceName failed with exit code {0}:`n{1}" -f `
            $LASTEXITCODE, ($output -join [Environment]::NewLine))
    }

    # Windows marks a service for deletion; it disappears once the last handle
    # is closed. Retry briefly so a follow-up install does not race it.
    if (-not (Wait-ForServiceDeletion -Name $ServiceName)) {
        Write-Warning "$ServiceName is still marked for deletion; retry the install after a few seconds."
    } else {
        Write-Host "$ServiceName removed."
    }
}

$fullData = [System.IO.Path]::GetFullPath($DataDirectory)
if ($PurgeData) {
    $root = [System.IO.Path]::GetPathRoot($fullData)
    if ([string]::IsNullOrWhiteSpace($fullData) -or
        $fullData.TrimEnd('\') -eq $root.TrimEnd('\')) {
        throw "Refusing to purge a drive root: $fullData"
    }

    if (Test-Path -LiteralPath $fullData) {
        Write-Host "Purging data directory $fullData"
        Remove-Item -LiteralPath $fullData -Recurse -Force
        Write-Host 'Database, logs and quarantine vault removed.'
    } else {
        Write-Host "Data directory $fullData does not exist; nothing to purge."
    }
} else {
    Write-Host ''
    Write-Host "Data preserved at $fullData"
    Write-Host 'The quarantine vault and database were intentionally kept.'
    Write-Host 'Use -PurgeData to remove them (irreversible).'
}
