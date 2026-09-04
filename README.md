# Windows Remote Bootstrap

A dependency-free Windows PowerShell 5.1 bootstrapper for secure administration
from macOS. It installs the Windows OpenSSH optional capability, creates one
dedicated local administrator, accepts only explicitly supplied public keys,
and limits the SSH firewall rule to explicitly supplied source addresses.

It does **not** install a custom daemon, enable WinRM, disable UAC, expose a
router port, store private keys, or use Windows' shared
`administrators_authorized_keys` file.

## Requirements

- Windows 10 build 1809 or newer, or Windows 11.
- An account that can approve one UAC prompt.
- Windows PowerShell 5.1 and internet access to Windows Update for the OpenSSH
  optional capability when it is not already installed.
- Windows 11 Administrator Protection must not be enabled. The installer checks
  this and stops instead of weakening that protection.

## Installation

Use a versioned GitHub Release asset and verify its documented SHA-256 before
execution. Pass each macOS public key as Base64-encoded UTF-8 and set the exact
LAN, host IPs, or `LocalSubnet` that may connect.

Example (replace the placeholder with a Base64-encoded public key):

```powershell
$url = 'https://github.com/Zestinc/windows-remote-bootstrap/releases/download/v1.0.0/install.ps1'
$path = Join-Path $env:TEMP 'windows-remote-bootstrap-v1.0.0.ps1'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $path
$actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
$expected = '3623989524e1a48cc87f7083eb2a0daf221c63f18f9e3100a19315f4d3c10aa6'
if ($actual -ne $expected) { Remove-Item $path -Force; throw "SHA-256 mismatch: $actual" }
& $path -AuthorizedKeyBase64 '<BASE64_PUBLIC_KEY>' -AllowedRemoteAddress 'LocalSubnet'
```

The installer is idempotent. If OpenSSH Server was already configured by
something else, it refuses to replace that access policy unless
`-TakeOverExistingSshd` is explicitly present. The previous configuration is
backed up for uninstall and rollback.

## What gets changed

- Windows optional capability: `OpenSSH.Server~~~~0.0.1.0` when missing.
- Local account: `macremote` by default, with an undisclosed random password.
- SSH: public-key only, only the dedicated account, no agent or TCP forwarding.
- Key file: `%ProgramData%\WindowsRemoteBootstrap\authorized_keys`, protected
  so only SYSTEM and local Administrators can modify it.
- Firewall: one program-owned inbound rule; the default broad OpenSSH rule is
  disabled.
- State and rollback data: `%ProgramData%\WindowsRemoteBootstrap`.
- Shareable receipt: `%PUBLIC%\Documents\WindowsRemoteBootstrap-receipt.json`.

## Audit and uninstall

Run the downloaded, hash-verified script from an elevated Windows PowerShell:

```powershell
.\install.ps1 -Mode Audit
.\install.ps1 -Mode Uninstall
```

OpenSSH itself is retained by default. Add `-RemoveOpenSshCapability` to
uninstall only when the receipt proves this tool installed it.

## macOS control helper

`winctl` uses only utilities included with macOS (`ssh`, `iconv`, and `base64`).
It never suppresses first-connection host-key verification.

```bash
./winctl 192.168.1.50 status
./winctl 192.168.1.50 display 15 5
./winctl 192.168.1.50 sleep 60 30
```

The two display values are AC and battery minutes. `0` means never. Display
timeout and system sleep are separate settings.

## Verification boundary

CI validates PowerShell 5.1 parsing, a real OpenSSH installation, a key-only
localhost login, an elevated remote token, `powercfg`, idempotency, audit, and
uninstall on Windows Server runners. The receipt verifies service, effective
sshd policy, listener, firewall, and host-key fingerprint. Actual LAN
reachability still must be verified from an authorized Mac after installation.

## License

MIT
