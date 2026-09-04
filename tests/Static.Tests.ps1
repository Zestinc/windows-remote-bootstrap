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
    "RemoteAddress",
    "transaction.json",
    "Test-EffectiveSshPolicy",
    "managedConfigSha256",
    "hostKeyFingerprint",
    "Set-ExactAcl",
    "AllowBypass",
    "Language.NullString]::Value"
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
    '-RemoteAddress Any',
    'Invoke-SelfElevation',
    "'/grant:r'"
)
foreach ($needle in $forbidden) {
    if ($text.Contains($needle)) {
        throw "Forbidden security pattern found: $needle"
    }
}

if ($text -match '(?m)\[IO\.File\]::Replace\([^\r\n]*,\s*\$null\s*\)') {
    throw 'File.Replace must use AutomationNull, not a PowerShell null argument.'
}
if ($text -match '(?m)\(Get-OptionalPropertyValues[^\r\n]*\)\.Count') {
    throw 'Optional property values must be array-wrapped before reading Count in PowerShell 5.1.'
}

Write-Output 'Static security tests passed.'
