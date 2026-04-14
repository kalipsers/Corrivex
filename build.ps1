# Corrivex build script — Windows PowerShell entry point.
#
# Equivalent to the Makefile for admins working on Windows without `make`.
#
# Usage:
#   .\build.ps1                    # all targets
#   .\build.ps1 -Target server-linux
#   .\build.ps1 -Target server-windows
#   .\build.ps1 -Target agent-windows
#   .\build.ps1 -Release           # produces dist\corrivex-windows-X.Y.Z.zip
#   .\build.ps1 -Clean             # remove .\bin and .\dist
#   .\build.ps1 -Tidy              # go mod tidy

[CmdletBinding()]
param(
    [ValidateSet('all','server-linux','server-windows','agent-windows','release-windows')]
    [string]$Target = 'all',

    [switch]$Release,
    [switch]$Clean,
    [switch]$Tidy,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Root

$BinDir  = Join-Path $Root 'bin'
$DistDir = Join-Path $Root 'dist'

# Read the canonical version from internal/version/version.go.
$verLine = Get-Content (Join-Path $Root 'internal\version\version.go') |
           Where-Object { $_ -match '^var Version\s*=\s*"([^"]+)"' } |
           Select-Object -First 1
if (-not $verLine) { throw 'Could not find Version constant in internal/version/version.go' }
$null = $verLine -match '"([^"]+)"'
$Version = $Matches[1]
Write-Host "Building Corrivex v$Version`n"

$LDFlags = "-s -w -X github.com/markov/corrivex/internal/version.Version=$Version"
$GoFlags = @('-trimpath','-ldflags',$LDFlags)
$GoVersionInfo = 'github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1'

function Need-Go {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'go is not on PATH. Install Go 1.23+ and reopen the shell.'
    }
}

function New-BinDir { if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir | Out-Null } }

function Make-Syso([string]$cmdName) {
    Push-Location (Join-Path $Root "cmd\$cmdName")
    try {
        Write-Host "Generating Windows file-properties .syso for $cmdName ..."
        # goversioninfo runs on the host — clear cross-compile vars first.
        $env:GOOS=''; $env:GOARCH=''
        & go run $GoVersionInfo -64 -o resource_amd64.syso versioninfo.json
        if ($LASTEXITCODE) { throw "goversioninfo failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
}

function Build-ServerLinux {
    Need-Go; New-BinDir
    Write-Host 'Building corrivex-server (linux/amd64)...'
    $env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    & go build @GoFlags -o (Join-Path $BinDir 'corrivex-server') ./cmd/server
    if ($LASTEXITCODE) { throw "go build failed ($LASTEXITCODE)" }
}

function Build-ServerWindows {
    Need-Go; New-BinDir
    Make-Syso 'server'
    Write-Host 'Building corrivex-server.exe (windows/amd64)...'
    $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    & go build @GoFlags -o (Join-Path $BinDir 'corrivex-server.exe') ./cmd/server
    if ($LASTEXITCODE) { throw "go build failed ($LASTEXITCODE)" }
}

function Build-AgentWindows {
    Need-Go; New-BinDir
    Make-Syso 'agent'
    Write-Host 'Building corrivex-agent.exe (windows/amd64)...'
    $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    & go build @GoFlags -o (Join-Path $BinDir 'corrivex-agent.exe') ./cmd/agent
    if ($LASTEXITCODE) { throw "go build failed ($LASTEXITCODE)" }
}

function Build-Release {
    Build-ServerWindows
    Build-AgentWindows
    if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir | Out-Null }
    $stage = Join-Path $DistDir '_stage'
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage | Out-Null

    Copy-Item (Join-Path $BinDir 'corrivex-server.exe') $stage
    Copy-Item (Join-Path $BinDir 'corrivex-agent.exe')  $stage
    Copy-Item (Join-Path $Root 'deploy\install-server.ps1') $stage
    Copy-Item (Join-Path $Root 'README.md') $stage
    Copy-Item (Join-Path $Root 'versioning.md') $stage

    $zip = Join-Path $DistDir "corrivex-windows-$Version.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    Remove-Item $stage -Recurse -Force
    Write-Host ''
    Write-Host "  → $zip"
    Get-Item $zip | Format-Table Name, Length, LastWriteTime
}

function Build-All {
    Build-ServerLinux
    Build-ServerWindows
    Build-AgentWindows
}

if ($Clean) {
    foreach ($d in @($BinDir,$DistDir)) {
        if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    }
    Remove-Item (Join-Path $Root 'cmd\server\resource_amd64.syso') -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root 'cmd\agent\resource_amd64.syso')  -Force -ErrorAction SilentlyContinue
    Write-Host 'Cleaned bin\, dist\, and generated .syso files.'
    return
}

if ($Tidy) { Need-Go; & go mod tidy; return }
if ($Test) { Need-Go; & go test ./...; return }

if ($Release -or $Target -eq 'release-windows') {
    Build-Release
    return
}

switch ($Target) {
    'server-linux'    { Build-ServerLinux }
    'server-windows'  { Build-ServerWindows }
    'agent-windows'   { Build-AgentWindows }
    default           { Build-All }
}
