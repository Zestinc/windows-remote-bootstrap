#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot 'install.ps1'
$text = Get-Content -LiteralPath $installer -Raw

$required = @(
    "PasswordAuthentication no",
    "AuthenticationMethods publickey",
    "AllowTcpForwarding no",
    "AllowAgentForwarding no",
    "OpenSSH.Server~~~~0.0.1.0",
    "TypeOfAdminApprovalMode",
    "OpenSSH-Server-In-TCP",
    "RemoteAddress"
)
foreach ($needle in $required) {
    if (-not $text.Contains($needle)) {
        throw "Missing required security control: $needle"
    }
}

$forbidden = @(
    'LocalAccountTokenFilterPolicy',
    'administrators_authorized_keys',
    'PasswordAuthentication yes',
    '-RemoteAddress Any'
)
foreach ($needle in $forbidden) {
    if ($text.Contains($needle)) {
        throw "Forbidden security pattern found: $needle"
    }
}

Write-Output 'Static security tests passed.'
