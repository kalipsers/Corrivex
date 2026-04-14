# Corrivex Server — Windows installer
#
# Run as Administrator. Supply the URLs to your release artifacts:
#
#   .\install-server.ps1 `
#       -ServerExeUrl 'https://releases.example.com/corrivex-server.exe' `
#       -AgentExeUrl  'https://releases.example.com/corrivex-agent.exe'
#
# Optional flags:
#   -Listen ':8484'                            # listen address
#   -DBPath 'C:\ProgramData\Corrivex\server\corrivex.db'
#   -TLSCert 'C:\path\srv.pem' -TLSKey 'C:\path\srv.key'   # enable HTTPS
#   -APISecret '...'                           # optional shared secret

[CmdletBinding()]
param(
    # URLs to fetch the binaries. No defaults — supply your release host.
    [Parameter(Mandatory = $true)] [string]$ServerExeUrl,
    [Parameter(Mandatory = $true)] [string]$AgentExeUrl,

    # Server runtime settings
    [string]$Listen    = ':8484',
    [string]$DBPath    = 'C:\ProgramData\Corrivex\server\corrivex.db',
    [string]$TLSCert   = '',
    [string]$TLSKey    = '',
    [string]$APISecret = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([System.Security.Principal.WindowsPrincipal]$id).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    throw 'This installer must be run as Administrator.'
}

$Dir = 'C:\ProgramData\Corrivex\server'
if (-not (Test-Path $Dir)) {
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
}

$ServerExe = Join-Path $Dir 'corrivex-server.exe'
$AgentExe  = Join-Path $Dir 'corrivex-agent.exe'

# If the existing service is running we must stop it before overwriting.
$svc = Get-Service -Name 'CorrivexServer' -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host 'Stopping existing CorrivexServer service ...'
    try { Stop-Service -Name 'CorrivexServer' -Force -ErrorAction Stop } catch {}
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $h = [System.IO.File]::Open($ServerExe, 'Open', 'ReadWrite', 'None')
            $h.Close(); break
        } catch { Start-Sleep -Milliseconds 500 }
    }
}

Write-Host "Downloading server binary from $ServerExeUrl ..."
Invoke-WebRequest -Uri $ServerExeUrl -OutFile $ServerExe -UseBasicParsing
Write-Host "Downloading agent binary from $AgentExeUrl ..."
Invoke-WebRequest -Uri $AgentExeUrl  -OutFile $AgentExe  -UseBasicParsing

# Build install args.
$installArgs = @(
    'install',
    "--addr=$Listen",
    '--db-driver=sqlite',
    "--db-path=$DBPath"
)
if ($TLSCert) { $installArgs += "--tls-cert=$TLSCert" }
if ($TLSKey)  { $installArgs += "--tls-key=$TLSKey"   }
if ($APISecret) { $installArgs += "--api-secret=$APISecret" }

Write-Host "Installing CorrivexServer service ..."
& $ServerExe @installArgs
if ($LASTEXITCODE -ne 0) {
    throw "Install failed (exit $LASTEXITCODE)."
}

$scheme = if ($TLSCert -and $TLSKey) { 'https' } else { 'http' }
$port = ($Listen -split ':')[-1]
if (-not $port) { $port = '8484' }
Write-Host ""
Write-Host "Corrivex server is running."
Write-Host "Open the dashboard:  $scheme`://$($env:COMPUTERNAME):$port/"
Write-Host "Logs:                Get-EventLog Application -Source CorrivexServer -Newest 20"
Write-Host "Service control:     'sc.exe stop CorrivexServer' / 'sc.exe start CorrivexServer'"
