# Windows Remote Bootstrap

A dependency-free Windows PowerShell 5.1 bootstrapper for secure administration
from macOS. It installs the in-box Windows OpenSSH Server when needed, creates
one dedicated local administrator, accepts only the supplied public keys, and
limits the SSH firewall rule to the supplied source addresses.

It does **not** install a custom daemon, enable WinRM, disable UAC, expose a
router port, store private keys, use Windows'
`administrators_authorized_keys`, or bypass WDAC, AppLocker, Constrained
Language Mode, or other system policy.

## Requirements

- Windows 10 build 1809 or newer, or Windows 11.
- An account that can approve one UAC prompt.
- Elevated 64-bit Windows PowerShell 5.1.
- Internet access to Windows Update if OpenSSH Server is not already installed.
- Windows 11 Administrator Protection must not be enabled. The installer stops
  instead of weakening that protection.

## Install on Windows

Open **64-bit Windows PowerShell as Administrator** and paste this complete
block. It launches a separate Windows PowerShell process, downloads the
versioned asset once as bytes, hashes those exact bytes, decodes them as strict
UTF-8, and executes only the verified script in memory.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run 64-bit Windows PowerShell as Administrator.'
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Use System32 Windows PowerShell, not SysWOW64 Windows PowerShell.'
    }

    $loader = @'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$uri = 'https://github.com/Zestinc/windows-remote-bootstrap/releases/download/v1.0.0/install.ps1'
$expected = '4d282c9eb8cc4a9b857aa43bb819165e412eca710e0a8d688968b9957f49b41f'
$keys = @(
    'c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUdSVTVWWi9nalJhZUpyNnRlNzlseEhPM3lzeWFaWDVDcUZkZ3EybEI1Zk0gbWFjbWluaS0yMDI2',
    'c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUVJZWMrRTlSazRqSzd2KytTUGR1QVF6Y296cGh5bnI5eGRwUjNFRGRkdDUgbWJwLTIwMjY='
)
$client = New-Object System.Net.WebClient
try {
    $client.Headers['User-Agent'] = 'WindowsRemoteBootstrap/1.0.0'
    [byte[]]$bytes = $client.DownloadData($uri)
} finally {
    $client.Dispose()
}
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}
if (-not [string]::Equals($actual, $expected, [StringComparison]::Ordinal)) {
    throw "SHA-256 mismatch: $actual"
}
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$source = $utf8.GetString($bytes)
& ([ScriptBlock]::Create($source)) `
    -Mode Install `
    -AuthorizedKeyBase64 $keys `
    -AccountName 'macremote' `
    -Port 22 `
    -AllowedRemoteAddress @('LocalSubnet')
'@

    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loader))
    $system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $windowsPowerShell = Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
    & $windowsPowerShell -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded
    $code = $LASTEXITCODE
    if ($code -eq 3) {
        Write-Warning 'Restart Windows, then rerun this exact complete block.'
    } elseif ($code -ne 0) {
        throw "Windows Remote Bootstrap failed with exit code $code. Read its receipt above."
    }
}
```

The only machine-readable result line starts exactly with
`WINDOWS_REMOTE_BOOTSTRAP_RECEIPT_JSON=`. Keep the JSON after that prefix. A
successful install reports `status: "installed"`, the Windows LAN addresses in
`ipv4`, and the server fingerprint in `ssh.hostKeyFingerprint`. Exit code `3`
means Windows must be restarted; after restart, rerun the exact complete block.
The installer is idempotent.

On the first SSH connection, accept the key **only if** the ED25519 fingerprint
shown by `ssh` is byte-for-byte identical to `ssh.hostKeyFingerprint` in that
receipt. Do not accept a merely similar fingerprint.

If OpenSSH Server was already configured by something else, installation stops
instead of replacing its policy. Deliberate takeover requires the explicit
`-TakeOverExistingSshd` switch and preserves the prior configuration for
rollback.

## What gets changed

- Windows optional capability: `OpenSSH.Server~~~~0.0.1.0`, only when missing.
- Local account: `macremote`, with an undisclosed random password.
- SSH: public-key only, one dedicated account, no agent or TCP forwarding.
- Key file: `%ProgramData%\WindowsRemoteBootstrap\authorized_keys`, protected
  so only trusted system principals can modify it.
- Firewall: one program-owned inbound TCP/22 rule limited to `LocalSubnet`; the
  default broad OpenSSH rule is disabled.
- State and rollback data: `%ProgramData%\WindowsRemoteBootstrap`.

## Audit and uninstall

Use the same versioned, SHA-256-verified, strict-UTF-8 in-memory launcher, but
invoke the verified script with `-Mode Audit` or `-Mode Uninstall`. Audit exits
`0` only for a compliant state and `2` for drift. Uninstall automatically
removes OpenSSH Server only when the protected receipt proves this tool
installed it; a capability that existed before installation is retained.

## Install and use `winctl` on macOS

`winctl` requires only `/bin/sh`, `ssh`, `iconv`, `base64`, and `tr` at runtime.
It deliberately keeps first-connection host-key verification enabled.

```bash
(
  set -eu
  wrb_tmp=$(mktemp -d)
  trap 'rm -rf "$wrb_tmp"' 0 1 2 15
  curl --fail --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    -o "$wrb_tmp/winctl" \
    https://github.com/Zestinc/windows-remote-bootstrap/releases/download/v1.0.0/winctl
  printf '%s  %s\n' '8af8e301b44aec7f45629b4f020ffd89fd31e36835422d478df969330eaf2ba4' "$wrb_tmp/winctl" | shasum -a 256 -c -
  mkdir -p "$HOME/.local/bin"
  install -m 700 "$wrb_tmp/winctl" "$HOME/.local/bin/winctl"
)
```

After making the exact first-connection fingerprint comparison described above:

```bash
$HOME/.local/bin/winctl --identity "$HOME/.ssh/id_ed25519" <WINDOWS_LAN_IP> status
$HOME/.local/bin/winctl --identity "$HOME/.ssh/id_ed25519" <WINDOWS_LAN_IP> display 15 5
$HOME/.local/bin/winctl --identity "$HOME/.ssh/id_ed25519" <WINDOWS_LAN_IP> sleep 60 30
```

Display and sleep values are AC and battery minutes; if the second value is
omitted it equals the first. `0` means never. The helper reads settings back and
fails if Windows did not apply the requested values.

## Verification boundary

CI validates Windows PowerShell 5.1 parsing, a real OpenSSH installation,
key-only localhost login, an elevated remote token, `powercfg`, idempotency,
audit, rollback, and uninstall on Windows Server runners. The receipt verifies
the effective SSH policy, service, listener, firewall, and host key. Actual LAN
reachability is verified by the first authorized Mac connection.

## License

MIT
