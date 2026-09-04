#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot 'install.ps1'
$text = Get-Content -LiteralPath $installer -Raw
$winctlText = Get-Content -LiteralPath (Join-Path $repoRoot 'winctl') -Raw

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
    "WINDOWS_REMOTE_BOOTSTRAP_RECEIPT_JSON=",
    '$keygen -y -f $path',
    "Set-ExactAcl",
    "QueryServiceObjectSecurity",
    '$keygen -A',
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
    'PublicReceiptPath',
    'SpecialFolder]::CommonDocuments',
    'Write-JsonFile',
    "'/grant:r'"
)
foreach ($needle in $forbidden) {
    if ($text.Contains($needle)) {
        throw "Forbidden security pattern found: $needle"
    }
}

foreach ($strictSetting in @('-o StrictHostKeyChecking=ask', '-o StrictHostKeyChecking=yes')) {
    if ([regex]::Matches($winctlText, [regex]::Escape($strictSetting)).Count -ne 1) {
        throw "macOS control helper must select exactly one '$strictSetting' branch."
    }
}

if ($text -match '(?m)\[IO\.File\]::Replace\([^\r\n]*,\s*\$null\s*\)') {
    throw 'File.Replace must use AutomationNull, not a PowerShell null argument.'
}
if ($text -match '(?m)(?<!@)\(Get-OptionalPropertyValues[^\r\n]*\)\.Count') {
    throw 'Optional property values must be array-wrapped before reading Count in PowerShell 5.1.'
}

foreach ($needle in @(
        '-o BatchMode=no',
        '-o StrictHostKeyChecking=ask',
        '$values[$values.Count - 2]',
        '$values[$values.Count - 1]',
        'ConvertTo-Json -Depth 4 -Compress',
        'powercfg update did not converge to the requested values'
    )) {
    if (-not $winctlText.Contains($needle)) {
        throw "macOS control helper is missing a required safety check: $needle"
    }
}
if ($winctlText.Contains('-o BatchMode=yes')) {
    throw 'macOS control helper must permit first-connection host-key confirmation.'
}

Write-Output 'Static security tests passed.'
