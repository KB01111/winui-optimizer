#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the AI Antivirus Security Engine as a least-privilege Windows
    service.

.DESCRIPTION
    Creates the service with New-Service, switches it to the built-in
    NT AUTHORITY\LocalService account, configures recovery actions, applies
    restrictive ACLs to the data directory and starts the service.

    The service is registered with Manual startup so that an endpoint agent or
    the desktop app controls when the engine runs. The script starts it once at
    the end unless -NoStart is supplied.

.PARAMETER BinaryPath
    Path to security-service.exe. Defaults to a copy next to this script, then
    to target\release and target\debug in the repository.

.PARAMETER DataDirectory
    Data root. Defaults to %ProgramData%\AiAntivirus (database, logs and the
    quarantine vault live below it).

.PARAMETER NoStart
    Register the service but do not start it.

.PARAMETER SkipAcl
    Do not rewrite the data-directory ACL. Only use this when the ACL was
    already hardened by another deployment mechanism.

.EXAMPLE
    .\install-service.ps1 -BinaryPath 'C:\Program Files\AI Antivirus\security-service.exe'

.EXAMPLE
    .\install-service.ps1 -NoStart
#>
[CmdletBinding()]
param(
    [string]$BinaryPath,
    [string]$DataDirectory = (Join-Path $env:ProgramData 'AiAntivirus'),
    [switch]$NoStart,
    [switch]$SkipAcl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'AiAntivirusSecurityService'
$DisplayName = 'AI Antivirus Security Engine'
$Description = 'Deterministic local security telemetry, scanning and quarantine engine for AI Antivirus.'
$ServiceAccount = 'NT AUTHORITY\LocalService'
$PipePath = '\\.\pipe\ai-antivirus-security'
$FailureResetSeconds = 86400

function Invoke-Sc {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ScArguments
    )

    $output = & sc.exe @ScArguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("sc.exe {0} failed with exit code {1}:`n{2}" -f `
            ($ScArguments -join ' '), $LASTEXITCODE, ($output -join [Environment]::NewLine))
    }
    return $output
}

function Resolve-ServiceBinary {
    param([string]$RequestedPath)

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($RequestedPath) {
        $candidates.Add($RequestedPath)
    } else {
        $scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $candidates.Add((Join-Path $scriptDirectory 'security-service.exe'))
        $candidates.Add((Join-Path $scriptDirectory '..\..\target\release\security-service.exe'))
        $candidates.Add((Join-Path $scriptDirectory '..\..\target\debug\security-service.exe'))
    }

    foreach ($candidate in $candidates) {
        $fullPath = [System.IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            return $fullPath
        }
    }

    throw ("security-service.exe was not found. Pass -BinaryPath with the full path to the " +
        "service executable.")
}

Write-Host "Installing $DisplayName ($ServiceName)"

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service $ServiceName is already installed. Run .\uninstall-service.ps1 first."
}

$resolvedBinary = Resolve-ServiceBinary -RequestedPath $BinaryPath
$dataRoot = [System.IO.Path]::GetFullPath($DataDirectory)
$vaultDirectory = Join-Path $dataRoot 'quarantine'
$logDirectory = Join-Path $dataRoot 'logs'

foreach ($directory in @($dataRoot, $vaultDirectory, $logDirectory)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}

if (-not $SkipAcl) {
    Write-Host "Hardening ACLs below $dataRoot"
    # ProgramData is readable by every interactive user by default. The engine
    # database contains process/file telemetry, so remove inherited ACEs and
    # grant only SYSTEM/Administrators (full) and LocalService (modify).
    $aclOutput = & icacls.exe $dataRoot `
        /inheritance:r `
        /grant:r '*S-1-5-18:(OI)(CI)F' `
        /grant:r '*S-1-5-32-544:(OI)(CI)F' `
        /grant:r '*S-1-5-19:(OI)(CI)M' `
        /T 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("icacls failed with exit code {0}:`n{1}" -f $LASTEXITCODE, ($aclOutput -join [Environment]::NewLine))
    }
    if ($aclOutput) {
        $aclOutput | Out-Host
    }
} else {
    Write-Warning 'Skipping ACL hardening (-SkipAcl); make sure LocalService can write to the data directory.'
}

Write-Host "Registering $ServiceName"
$quotedBinary = '"{0}"' -f $resolvedBinary
New-Service `
    -Name $ServiceName `
    -BinaryPathName $quotedBinary `
    -DisplayName $DisplayName `
    -StartupType Manual | Out-Null

# New-Service always creates the service as LocalSystem. Switch to the
# least-privilege built-in LocalService account (no password) and make the
# description explicit for older PowerShell versions.
Invoke-Sc @('config', $ServiceName, 'obj=', $ServiceAccount, 'password=', '') | Out-Null
Invoke-Sc @('description', $ServiceName, $Description) | Out-Null

Write-Host 'Configuring recovery actions (restart after 5s, 10s and 30s)'
Invoke-Sc @(
    'failure', $ServiceName,
    'reset=', $FailureResetSeconds.ToString(),
    'actions=', 'restart/5000/restart/10000/restart/30000'
) | Out-Null

if ($NoStart) {
    Write-Host "$ServiceName registered. Start it with: Start-Service $ServiceName"
    return
}

Write-Host "Starting $ServiceName"
Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

# Give the engine a moment to create the pipe, then report readiness.
$pipeReady = $false
$deadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $PipePath) {
        $pipeReady = $true
        break
    }
    Start-Sleep -Milliseconds 200
}

if ($pipeReady) {
    Write-Host "$DisplayName is running and listening on $PipePath"
} else {
    Write-Warning ("$ServiceName is running but $PipePath is not available yet. " +
        "Check $logDirectory\security-service.log.")
}

Write-Host ''
Write-Host 'Data directory : ' $dataRoot
Write-Host 'Quarantine     : ' $vaultDirectory
Write-Host 'Logs           : ' $logDirectory
Write-Host 'Account        : ' $ServiceAccount
