<#
.SYNOPSIS
    Authenticode-signs Audere's built executables.

.DESCRIPTION
    Signing is what stops Windows SmartScreen and heuristic scanners from
    treating the build as unknown software. Point this at a certificate,
    either one installed in the certificate store (by thumbprint) or a .pfx
    file, and it signs and verifies every binary it is given.

    The timestamp is not optional: without one the signature stops being
    trusted the day the certificate expires. With one, builds signed while the
    certificate was valid stay valid forever.

.EXAMPLE
    # Certificate already in the Windows certificate store (typical for the
    # hardware tokens that code-signing certificates now ship on)
    .\scripts\sign.ps1 -Thumbprint 1A2B3C...

.EXAMPLE
    # Certificate as a .pfx file
    .\scripts\sign.ps1 -PfxPath .\audere.pfx -PfxPassword (Read-Host -AsSecureString)

.EXAMPLE
    # Values kept in the environment instead of the command line
    $env:AUDERE_SIGN_THUMBPRINT = '1A2B3C...'
    .\scripts\sign.ps1
#>

[CmdletBinding()]
param(
    [string] $Thumbprint = $env:AUDERE_SIGN_THUMBPRINT,
    [string] $PfxPath = $env:AUDERE_SIGN_PFX,
    [System.Security.SecureString] $PfxPassword,

    # Any RFC 3161 timestamp server. Free ones are offered by the CAs.
    [string] $TimestampUrl = 'http://timestamp.sectigo.com',

    # Defaults to the release builds of both binaries.
    [string[]] $Files
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not $Files -or $Files.Count -eq 0) {
    $Files = @(
        Join-Path $root 'client\src-tauri\target\release\concord.exe'
        Join-Path $root 'server\target\release\concord-server.exe'
    ) | Where-Object { Test-Path $_ }
}

if ($Files.Count -eq 0) {
    throw 'Nothing to sign. Build with `cargo build --release` first.'
}

# signtool ships with the Windows SDK; take the newest x64 copy.
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like '*x64*' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1

if (-not $signtool) {
    throw 'signtool.exe not found. Install the Windows SDK (Signing Tools component).'
}

$common = @('sign', '/fd', 'sha256', '/tr', $TimestampUrl, '/td', 'sha256', '/v')

if ($Thumbprint) {
    $args = $common + @('/sha1', $Thumbprint)
} elseif ($PfxPath) {
    if (-not (Test-Path $PfxPath)) { throw "Certificate not found: $PfxPath" }
    $args = $common + @('/f', $PfxPath)
    if ($PfxPassword) {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
        $args += @('/p', $plain)
    }
} else {
    throw 'Provide -Thumbprint or -PfxPath (or set AUDERE_SIGN_THUMBPRINT / AUDERE_SIGN_PFX).'
}

foreach ($file in $Files) {
    Write-Host "Signing $file"
    & $signtool.FullName @args $file
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $file" }

    # /pa checks it against the rules Windows itself applies to a downloaded
    # program, which is the thing that actually matters here.
    & $signtool.FullName verify /pa /v $file
    if ($LASTEXITCODE -ne 0) { throw "Verification failed for $file" }
}

Write-Host "`nSigned $($Files.Count) file(s)." -ForegroundColor Green
