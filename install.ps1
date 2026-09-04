#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Audit', 'Uninstall')]
    [string]$Mode = 'Install',

    [string[]]$AuthorizedKeyBase64 = @(),

    [ValidatePattern('^[a-z][a-z0-9_-]{0,19}$')]
    [string]$AccountName = 'macremote',

    [ValidateRange(1, 65535)]
    [int]$Port = 22,

    [string[]]$AllowedRemoteAddress = @('LocalSubnet'),

    [switch]$TakeOverExistingSshd,

    [switch]$RemoveOpenSshCapability,

    # Internal: the unelevated parent serializes parameters here before UAC.
    [string]$ElevatedConfigPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ProgramName = 'WindowsRemoteBootstrap'
$script:InstallerVersion = '1.0.0'
$script:CapabilityName = 'OpenSSH.Server~~~~0.0.1.0'
$script:FirewallRuleName = 'WindowsRemoteBootstrap-SSH-In'
$script:RootPath = Join-Path $env:ProgramData $script:ProgramName
$script:StatePath = Join-Path $script:RootPath 'state.json'
$script:KeyPath = Join-Path $script:RootPath 'authorized_keys'
$script:SshPath = Join-Path $env:ProgramData 'ssh'
$script:SshConfigPath = Join-Path $script:SshPath 'sshd_config'
$script:PublicReceiptPath = Join-Path $env:PUBLIC 'Documents\WindowsRemoteBootstrap-receipt.json'
$script:GlobalBegin = '# BEGIN WINDOWS-REMOTE-BOOTSTRAP GLOBAL'
$script:GlobalEnd = '# END WINDOWS-REMOTE-BOOTSTRAP GLOBAL'
$script:UserBegin = '# BEGIN WINDOWS-REMOTE-BOOTSTRAP USER'
$script:UserEnd = '# END WINDOWS-REMOTE-BOOTSTRAP USER'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = $Value | ConvertTo-Json -Depth 10
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        [void](New-Item -Path $directory -ItemType Directory -Force)
    }
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporaryPath, $json, $script:Utf8NoBom)
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Write-PublicReceipt {
    param([Parameter(Mandatory = $true)]$Receipt)

    Write-JsonFile -Value $Receipt -Path $script:PublicReceiptPath
    Write-Output '=== WINDOWS_REMOTE_BOOTSTRAP_RECEIPT ==='
    Write-Output ($Receipt | ConvertTo-Json -Depth 10)
    Write-Output "Receipt: $script:PublicReceiptPath"
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-Icacls {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    & "$env:SystemRoot\System32\icacls.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE"
    }
}

function Protect-ProgramDirectory {
    if (-not (Test-Path -LiteralPath $script:RootPath)) {
        [void](New-Item -Path $script:RootPath -ItemType Directory -Force)
    }

    Invoke-Icacls $script:RootPath '/inheritance:r' '/grant:r' `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
}

function Protect-ManagedFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    Invoke-Icacls $Path '/inheritance:r' '/grant:r' `
        '*S-1-5-18:F' '*S-1-5-32-544:F'
}

function Test-ManagedFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        return $false
    }
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in $acl.Access) {
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $false
        }
        if (($allowed -notcontains $sid) -or ([string]$rule.AccessControlType -ne 'Allow')) {
            return $false
        }
    }
    $actual = @($acl.Access | ForEach-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } | Sort-Object -Unique)
    return (($actual -join ',') -eq (($allowed | Sort-Object) -join ','))
}

function Get-SavedState {
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return $null
    }
    return (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json)
}

function Assert-SupportedEnvironment {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This installer only supports Windows.'
    }
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
        throw 'Windows PowerShell 5.1 or later is required.'
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run the 64-bit Windows PowerShell from System32, not the 32-bit SysWOW64 host.'
    }

    $version = [Environment]::OSVersion.Version
    if (($version.Major -lt 10) -or (($version.Major -eq 10) -and ($version.Build -lt 17763))) {
        throw "Windows 10 build 17763 (1809) or later is required; found $version."
    }

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uac = Get-ItemProperty -LiteralPath $uacPath -Name TypeOfAdminApprovalMode -ErrorAction SilentlyContinue
    if (($null -ne $uac) -and ([int]$uac.TypeOfAdminApprovalMode -eq 2)) {
        throw 'Windows Administrator Protection is enabled. It requires interactive Windows Hello elevation and is intentionally not disabled by this installer.'
    }
}

function Assert-AccountName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $reserved = @(
        'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount',
        'system', 'localservice', 'networkservice'
    )
    if ($reserved -contains $Name.ToLowerInvariant()) {
        throw "The account name '$Name' is reserved."
    }
}

function Test-RemoteAddressValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -eq 'LocalSubnet') {
        return $true
    }
    if ($Value -in @('Any', '*', 'Internet', 'IntranetRemoteAccess')) {
        return $false
    }

    $addressText = $Value
    $prefixText = $null
    if ($Value.Contains('/')) {
        $parts = $Value.Split('/')
        if ($parts.Count -ne 2) {
            return $false
        }
        $addressText = $parts[0]
        $prefixText = $parts[1]
    }

    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse($addressText, [ref]$parsedAddress)) {
        return $false
    }

    if ($null -ne $prefixText) {
        $prefix = 0
        if (-not [int]::TryParse($prefixText, [ref]$prefix)) {
            return $false
        }
        $maximum = if ($parsedAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if (($prefix -lt 0) -or ($prefix -gt $maximum)) {
            return $false
        }
    }
    return $true
}

function Assert-AllowedRemoteAddress {
    param([Parameter(Mandatory = $true)][string[]]$Values)

    if ($Values.Count -eq 0) {
        throw 'At least one allowed remote address is required.'
    }
    foreach ($value in $Values) {
        if (-not (Test-RemoteAddressValue -Value $value)) {
            throw "Unsafe or invalid remote address: '$value'. Use LocalSubnet, a single IP, or a CIDR."
        }
    }
}

function Convert-AuthorizedKeys {
    param([Parameter(Mandatory = $true)][string[]]$EncodedKeys)

    if ($EncodedKeys.Count -eq 0) {
        throw 'Install mode requires at least one -AuthorizedKeyBase64 value.'
    }

    $acceptedAlgorithms = @(
        'ssh-ed25519',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'sk-ssh-ed25519@openssh.com',
        'sk-ecdsa-sha2-nistp256@openssh.com',
        'ssh-rsa'
    )
    $keysByIdentity = @{}
    foreach ($encoded in $EncodedKeys) {
        try {
            $bytes = [Convert]::FromBase64String($encoded)
            $line = [Text.Encoding]::UTF8.GetString($bytes).Trim()
        } catch {
            throw 'An authorized key is not valid Base64-encoded UTF-8.'
        }

        if (($line.Length -gt 8192) -or $line.Contains("`r") -or $line.Contains("`n")) {
            throw 'Each authorized key must be exactly one line and at most 8192 characters.'
        }
        $parts = $line -split '\s+', 3
        if (($parts.Count -lt 2) -or ($acceptedAlgorithms -notcontains $parts[0])) {
            throw 'An authorized key uses an unsupported algorithm or contains authorized_keys options.'
        }

        try {
            [void][Convert]::FromBase64String($parts[1])
        } catch {
            throw 'An authorized key contains an invalid key blob.'
        }

        $identity = "$($parts[0]) $($parts[1])"
        $comment = if ($parts.Count -eq 3) { ($parts[2] -replace '[^A-Za-z0-9_.@+-]', '_') } else { '' }
        $keysByIdentity[$identity] = if ($comment) { "$identity $comment" } else { $identity }
    }
    return @($keysByIdentity.Keys | Sort-Object | ForEach-Object { $keysByIdentity[$_] })
}

function New-RandomPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([Convert]::ToBase64String($bytes) + '!aA1')
}

function Ensure-LocalAccount {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        $SavedState
    )

    $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        if ($null -eq $SavedState) {
            throw "Local account '$Name' already exists and is not owned by this installer."
        }
        if ([string]$existing.SID.Value -ne [string]$SavedState.accountSid) {
            throw "Local account '$Name' has a different SID from the saved installer state."
        }
        if (-not $existing.Enabled) {
            Enable-LocalUser -Name $Name
        }
        $created = $false
    } else {
        if ($null -ne $SavedState) {
            throw "Saved installer state exists, but its local account '$Name' is missing. Uninstall or repair manually before reinstalling."
        }
        $plainPassword = New-RandomPassword
        try {
            $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
            $existing = New-LocalUser -Name $Name -Password $securePassword `
                -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword `
                -Description 'Key-only SSH account'
        } finally {
            $plainPassword = $null
            $securePassword = $null
        }
        $created = $true
    }

    $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
    $isMember = Get-LocalGroupMember -Group $administrators -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.SID.Value -eq [string]$existing.SID.Value }
    if ($null -eq $isMember) {
        Add-LocalGroupMember -Group $administrators -Member $existing
    }

    return [pscustomobject]@{
        user = $existing
        created = $created
    }
}

function Remove-ManagedBlocks {
    param([Parameter(Mandatory = $true)][string]$Text)

    $pairs = @(
        @($script:GlobalBegin, $script:GlobalEnd),
        @($script:UserBegin, $script:UserEnd)
    )
    $result = $Text
    foreach ($pair in $pairs) {
        $beginCount = ([regex]::Matches($result, [regex]::Escape($pair[0]))).Count
        $endCount = ([regex]::Matches($result, [regex]::Escape($pair[1]))).Count
        if ($beginCount -ne $endCount) {
            throw "Corrupt managed markers in sshd_config: $($pair[0])"
        }
        if ($beginCount -gt 1) {
            throw "Duplicate managed markers in sshd_config: $($pair[0])"
        }
        if ($beginCount -eq 1) {
            $pattern = '(?ms)^' + [regex]::Escape($pair[0]) + '.*?^' + [regex]::Escape($pair[1]) + '\s*\r?\n?'
            $result = [regex]::Replace($result, $pattern, '')
        }
    }
    return $result
}

function New-ManagedSshConfig {
    param(
        [Parameter(Mandatory = $true)][string]$OriginalText,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort
    )

    $clean = Remove-ManagedBlocks -Text $OriginalText
    $globalBlock = @"
$script:GlobalBegin
Port $SshPort
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
AllowUsers $Name
MaxAuthTries 3
$script:GlobalEnd

"@
    $userBlock = @"
$script:UserBegin
Match User $Name
    AuthorizedKeysFile __PROGRAMDATA__/$script:ProgramName/authorized_keys
    PasswordAuthentication no
    AuthenticationMethods publickey
    AllowAgentForwarding no
    AllowTcpForwarding no
$script:UserEnd

"@

    $firstMatch = [regex]::Match($clean, '(?im)^\s*Match\s+')
    if ($firstMatch.Success) {
        return $globalBlock + $clean.Substring(0, $firstMatch.Index) + $userBlock + $clean.Substring($firstMatch.Index)
    }
    return $globalBlock + $clean.TrimEnd() + "`r`n`r`n" + $userBlock
}

function Test-ManagedPolicyText {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort
    )

    $globalPattern = '(?ms)^' + [regex]::Escape($script:GlobalBegin) + '(.*?)^' + [regex]::Escape($script:GlobalEnd)
    $userPattern = '(?ms)^' + [regex]::Escape($script:UserBegin) + '(.*?)^' + [regex]::Escape($script:UserEnd)
    $globalMatch = [regex]::Match($Text, $globalPattern)
    $userMatch = [regex]::Match($Text, $userPattern)
    if (-not $globalMatch.Success -or -not $userMatch.Success) {
        return $false
    }
    if ($globalMatch.Index -ne 0 -or $userMatch.Index -le $globalMatch.Index) {
        return $false
    }

    $global = $globalMatch.Groups[1].Value.ToLowerInvariant()
    $user = $userMatch.Groups[1].Value.ToLowerInvariant()
    $requiredGlobal = @(
        "port $SshPort",
        'pubkeyauthentication yes',
        'passwordauthentication no',
        'authenticationmethods publickey',
        'permitemptypasswords no',
        "allowusers $Name",
        'maxauthtries 3'
    )
    $requiredUser = @(
        "match user $Name",
        "authorizedkeysfile __programdata__/$($script:ProgramName.ToLowerInvariant())/authorized_keys",
        'passwordauthentication no',
        'authenticationmethods publickey',
        'allowagentforwarding no',
        'allowtcpforwarding no'
    )
    foreach ($required in $requiredGlobal) {
        if (-not $global.Contains($required.ToLowerInvariant())) {
            return $false
        }
    }
    foreach ($required in $requiredUser) {
        if (-not $user.Contains($required.ToLowerInvariant())) {
            return $false
        }
    }

    # The dedicated user Match must be the first active Match block. OpenSSH uses
    # the first matching value, so the later Windows administrator-group default
    # cannot redirect this account to Windows' shared administrator key file.
    $firstMatch = [regex]::Match($Text, '(?im)^\s*Match\s+')
    return $firstMatch.Success -and ($firstMatch.Index -ge $userMatch.Index) -and ($firstMatch.Index -lt ($userMatch.Index + $userMatch.Length))
}

function Get-SshdExecutable {
    $candidate = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "OpenSSH Server executable was not found at $candidate."
    }
    return $candidate
}

function Get-SshKeygenExecutable {
    $candidate = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "OpenSSH key utility was not found at $candidate."
    }
    return $candidate
}

function Assert-OpenSshHostKeysProtected {
    $privateHostKeys = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
    if ($privateHostKeys.Count -eq 0) {
        throw 'OpenSSH did not generate any private host keys.'
    }
    foreach ($hostKey in $privateHostKeys) {
        # The Windows sshd service creates its private host keys with a
        # protected SYSTEM/Administrators ACL. Do not rewrite those
        # service-owned files; fail closed if their ACL is unexpectedly broad.
        if (-not (Test-ManagedFileAcl -Path $hostKey.FullName)) {
            throw "OpenSSH private host key has an unexpected ACL: $($hostKey.FullName)"
        }
    }
}

function Test-SshConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )

    $output = & $SshdExe -t -f $Path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sshd_config validation failed: $($output -join ' ')"
    }
}

function Get-KeyFingerprints {
    param([Parameter(Mandatory = $true)][string]$Path)

    $keygen = Get-SshKeygenExecutable
    $output = & $keygen -l -E sha256 -f $Path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ssh-keygen rejected the authorized key file: $($output -join ' ')"
    }
    return @($output | ForEach-Object { [string]$_ })
}

function Get-ActiveIPv4Addresses {
    $addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -ne '127.0.0.1' -and
            -not $_.IPAddress.StartsWith('169.254.') -and
            $_.AddressState -eq 'Preferred'
        } |
        Select-Object -ExpandProperty IPAddress -Unique
    return @($addresses)
}

function Get-HostKeyFingerprint {
    $path = Join-Path $script:SshPath 'ssh_host_ed25519_key.pub'
    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }
    $keygen = Get-SshKeygenExecutable
    $output = & $keygen -l -E sha256 -f $path 2>&1
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return ([string]($output | Select-Object -First 1))
}

function Disable-DefaultOpenSshFirewallRule {
    $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    if ($null -ne $rule) {
        Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' | Out-Null
    }
}

function Assert-NoCompetingSshFirewallRule {
    param([Parameter(Mandatory = $true)][int]$SshPort)

    $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $script:FirewallRuleName }
    foreach ($rule in $rules) {
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if (($null -eq $portFilter) -or ([string]$portFilter.Protocol -ne 'TCP')) {
            continue
        }
        if ([string]$portFilter.LocalPort -ne [string]$SshPort) {
            continue
        }
        $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        if (($null -ne $addressFilter) -and (@($addressFilter.RemoteAddress) -contains 'Any')) {
            throw "Enabled firewall rule '$($rule.DisplayName)' already exposes TCP/$SshPort to Any. Disable or narrow it before installing."
        }
    }
}

function Set-ManagedFirewallRule {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )

    Get-NetFirewallRule -Name $script:FirewallRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $script:FirewallRuleName `
        -DisplayName 'Windows Remote Bootstrap - SSH (restricted)' `
        -Description 'Managed by WindowsRemoteBootstrap; key-only SSH.' `
        -Enabled True -Profile Any -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $SshPort -RemoteAddress $RemoteAddress `
        -Program $SshdExe | Out-Null
}

function Install-WindowsRemoteBootstrap {
    param(
        [Parameter(Mandatory = $true)][string[]]$EncodedKeys,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][bool]$MayTakeOver
    )

    Assert-AccountName -Name $Name
    Assert-AllowedRemoteAddress -Values $RemoteAddress
    $keys = Convert-AuthorizedKeys -EncodedKeys $EncodedKeys
    $savedState = Get-SavedState

    if (($null -ne $savedState) -and ([string]$savedState.accountName -ne $Name)) {
        throw "This machine is already managed for account '$($savedState.accountName)'. Uninstall it before changing account names."
    }
    if (($null -ne $savedState) -and
        ([string]::IsNullOrWhiteSpace([string]$savedState.configBackup) -or
         -not (Test-Path -LiteralPath ([string]$savedState.configBackup)))) {
        throw 'Saved installer state has lost its original sshd_config backup. Refusing to overwrite recovery data.'
    }

    $preCapability = Get-WindowsCapability -Online -Name $script:CapabilityName
    $preService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $preConfigExists = Test-Path -LiteralPath $script:SshConfigPath
    $defaultFirewall = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    $defaultFirewallWasEnabled = ($null -ne $defaultFirewall) -and ([string]$defaultFirewall.Enabled -eq 'True')

    $hasExistingSshd = ($preCapability.State -eq 'Installed') -or ($null -ne $preService) -or $preConfigExists
    if ($hasExistingSshd -and ($null -eq $savedState) -and (-not $MayTakeOver)) {
        throw 'OpenSSH Server already exists. Rerun with -TakeOverExistingSshd only if replacing its access policy is intended.'
    }

    $rollback = [ordered]@{
        capabilityInstalled = $false
        accountCreated = $false
        configBackup = $null
        keyBackup = $null
        originalKeyExisted = (Test-Path -LiteralPath $script:KeyPath)
        originalConfigExisted = $preConfigExists
        configReplaced = $false
        ownFirewallCreated = $false
        defaultFirewallWasEnabled = $defaultFirewallWasEnabled
        serviceWasRunning = ($null -ne $preService) -and ($preService.Status -eq 'Running')
    }

    try {
        if ($preCapability.State -ne 'Installed') {
            $result = Add-WindowsCapability -Online -Name $script:CapabilityName
            if ($result.RestartNeeded) {
                throw 'Windows installed OpenSSH Server but requires a restart. Restart Windows, then run the same installer command again.'
            }
            $rollback.capabilityInstalled = $true
        }

        Disable-DefaultOpenSshFirewallRule
        Assert-NoCompetingSshFirewallRule -SshPort $SshPort

        Protect-ProgramDirectory
        $accountResult = Ensure-LocalAccount -Name $Name -SavedState $savedState
        $rollback.accountCreated = $accountResult.created
        $accountSid = [string]$accountResult.user.SID.Value

        if ($rollback.originalKeyExisted) {
            $rollback.keyBackup = Join-Path $script:RootPath ("authorized_keys-$([Guid]::NewGuid().ToString('N')).rollback")
            Copy-Item -LiteralPath $script:KeyPath -Destination $rollback.keyBackup -Force
            Protect-ManagedFile -Path $rollback.keyBackup
        }
        [IO.File]::WriteAllLines($script:KeyPath, $keys, [Text.Encoding]::ASCII)
        Protect-ManagedFile -Path $script:KeyPath
        $fingerprints = Get-KeyFingerprints -Path $script:KeyPath

        $sshdExe = Get-SshdExecutable
        if (-not (Test-Path -LiteralPath $script:SshPath)) {
            [void](New-Item -Path $script:SshPath -ItemType Directory -Force)
        }

        $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            throw 'OpenSSH capability reports installed, but the sshd service does not exist.'
        }

        if (-not (Test-Path -LiteralPath $script:SshConfigPath)) {
            $defaultConfig = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd_config_default'
            if (-not (Test-Path -LiteralPath $defaultConfig)) {
                throw "OpenSSH default configuration was not found at $defaultConfig."
            }
            Copy-Item -LiteralPath $defaultConfig -Destination $script:SshConfigPath -Force
        }
        if (-not (Test-Path -LiteralPath $script:SshConfigPath)) {
            throw 'OpenSSH did not create sshd_config.'
        }

        $privateHostKeys = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
        if ($privateHostKeys.Count -eq 0) {
            Set-Service -Name sshd -StartupType Automatic
            Start-Service -Name sshd
            $hostKeyDeadline = (Get-Date).AddSeconds(15)
            do {
                Start-Sleep -Milliseconds 250
                $privateHostKeys = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
            } while (($privateHostKeys.Count -eq 0) -and ((Get-Date) -lt $hostKeyDeadline))
            Stop-Service -Name sshd -Force
        }
        Assert-OpenSshHostKeysProtected

        $backupDirectory = Join-Path $script:RootPath 'backup'
        [void](New-Item -Path $backupDirectory -ItemType Directory -Force)
        $currentBackupPath = Join-Path $backupDirectory ("sshd_config-{0}-{1}.rollback" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N'))
        Copy-Item -LiteralPath $script:SshConfigPath -Destination $currentBackupPath -Force
        Protect-ManagedFile -Path $currentBackupPath
        $rollback.configBackup = $currentBackupPath
        $backupPath = if ($null -ne $savedState) { [string]$savedState.configBackup } else { $currentBackupPath }

        $originalConfig = Get-Content -LiteralPath $script:SshConfigPath -Raw
        $managedConfig = New-ManagedSshConfig -OriginalText $originalConfig -Name $Name -SshPort $SshPort
        $candidatePath = Join-Path $script:SshPath ("sshd_config.$([Guid]::NewGuid().ToString('N')).candidate")
        [IO.File]::WriteAllText($candidatePath, $managedConfig, [Text.Encoding]::ASCII)
        try {
            Copy-Item -LiteralPath $script:SshConfigPath -Destination "$candidatePath.acl" -Force
            $candidateAcl = Get-Acl -LiteralPath "$candidatePath.acl"
            Set-Acl -LiteralPath $candidatePath -AclObject $candidateAcl
            Remove-Item -LiteralPath "$candidatePath.acl" -Force
            Test-SshConfig -Path $candidatePath -SshdExe $sshdExe
            Move-Item -LiteralPath $candidatePath -Destination $script:SshConfigPath -Force
            $rollback.configReplaced = $true
        } finally {
            Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "$candidatePath.acl" -Force -ErrorAction SilentlyContinue
        }

        Set-Service -Name sshd -StartupType Automatic
        Restart-Service -Name sshd -Force
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 250
            $service = Get-Service -Name sshd
        } while (($service.Status -ne 'Running') -and ((Get-Date) -lt $deadline))
        if ($service.Status -ne 'Running') {
            throw 'sshd did not reach the Running state.'
        }

        Set-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe
        $rollback.ownFirewallCreated = $true

        $listenDeadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 250
            $listener = Get-NetTCPConnection -State Listen -LocalPort $SshPort -ErrorAction SilentlyContinue
        } while (($null -eq $listener) -and ((Get-Date) -lt $listenDeadline))
        if ($null -eq $listener) {
            throw "sshd is running but TCP/$SshPort is not listening."
        }

        $activeConfigText = Get-Content -LiteralPath $script:SshConfigPath -Raw
        if (-not (Test-ManagedPolicyText -Text $activeConfigText -Name $Name -SshPort $SshPort)) {
            throw 'Managed sshd policy is missing or is ordered after another Match block.'
        }

        $state = [ordered]@{
            schemaVersion = 1
            installerVersion = $script:InstallerVersion
            installedAt = if ($null -ne $savedState) { [string]$savedState.installedAt } else { (Get-Date).ToUniversalTime().ToString('o') }
            updatedAt = (Get-Date).ToUniversalTime().ToString('o')
            computerName = $env:COMPUTERNAME
            accountName = $Name
            accountSid = $accountSid
            port = $SshPort
            allowedRemoteAddress = @($RemoteAddress)
            keyFingerprints = @($fingerprints)
            openSshInstalledByTool = if ($null -ne $savedState) { [bool]$savedState.openSshInstalledByTool } else { [bool]$rollback.capabilityInstalled }
            existingSshdTakenOver = if ($null -ne $savedState) { [bool]$savedState.existingSshdTakenOver } else { [bool]$hasExistingSshd }
            defaultFirewallWasEnabled = if ($null -ne $savedState) { [bool]$savedState.defaultFirewallWasEnabled } else { [bool]$defaultFirewallWasEnabled }
            serviceWasRunning = if ($null -ne $savedState) { [bool]$savedState.serviceWasRunning } else { [bool]$rollback.serviceWasRunning }
            originalConfigExisted = if ($null -ne $savedState) { [bool]$savedState.originalConfigExisted } else { [bool]$preConfigExists }
            configBackup = $backupPath
            managedConfigSha256 = Get-FileSha256 -Path $script:SshConfigPath
            hostKeyFingerprint = Get-HostKeyFingerprint
        }
        Write-JsonFile -Value $state -Path $script:StatePath
        Protect-ManagedFile -Path $script:StatePath
        if (($null -ne $savedState) -and ($currentBackupPath -ne $backupPath)) {
            Remove-Item -LiteralPath $currentBackupPath -Force -ErrorAction SilentlyContinue
        }
        if ($rollback.keyBackup) {
            Remove-Item -LiteralPath $rollback.keyBackup -Force -ErrorAction SilentlyContinue
        }

        return [ordered]@{
            status = 'installed'
            installerVersion = $script:InstallerVersion
            computerName = $env:COMPUTERNAME
            ipv4 = @(Get-ActiveIPv4Addresses)
            ssh = [ordered]@{
                user = $Name
                port = $SshPort
                allowedRemoteAddress = @($RemoteAddress)
                hostKeyFingerprint = $state.hostKeyFingerprint
                authorizedKeyFingerprints = @($fingerprints)
            }
            verification = [ordered]@{
                openSshCapability = 'Installed'
                sshdConfigSyntax = 'valid'
                sshdPolicyOrder = 'key-only/dedicated-user-keyfile/first-match'
                sshdService = 'Running/Automatic'
                tcpListener = "TCP/$SshPort"
                firewall = 'enabled/restricted'
                endToEndMacSsh = 'pending'
            }
        }
    } catch {
        $failure = $_
        try {
            if ($rollback.ownFirewallCreated) {
                Get-NetFirewallRule -Name $script:FirewallRuleName -ErrorAction SilentlyContinue |
                    Remove-NetFirewallRule -ErrorAction SilentlyContinue
            }
            if ($rollback.configReplaced -and $rollback.configBackup -and (Test-Path -LiteralPath $rollback.configBackup)) {
                Copy-Item -LiteralPath $rollback.configBackup -Destination $script:SshConfigPath -Force
                Restart-Service -Name sshd -Force -ErrorAction SilentlyContinue
            }
            if ($rollback.originalKeyExisted -and $rollback.keyBackup -and (Test-Path -LiteralPath $rollback.keyBackup)) {
                Copy-Item -LiteralPath $rollback.keyBackup -Destination $script:KeyPath -Force
            } elseif (-not $rollback.originalKeyExisted) {
                Remove-Item -LiteralPath $script:KeyPath -Force -ErrorAction SilentlyContinue
            }
            if ($rollback.defaultFirewallWasEnabled) {
                Enable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Out-Null
            }
            if ($rollback.accountCreated) {
                Remove-LocalUser -Name $Name -ErrorAction SilentlyContinue
            }
            if ($rollback.capabilityInstalled) {
                Remove-WindowsCapability -Online -Name $script:CapabilityName -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # The original exception remains authoritative; rollback is best effort.
        }
        throw $failure
    }
}

function Invoke-WindowsRemoteBootstrapAudit {
    $state = Get-SavedState
    $checks = New-Object System.Collections.ArrayList

    function Add-AuditCheck {
        param([string]$Name, [bool]$Ok, [string]$Detail)
        [void]$checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
    }

    if ($null -eq $state) {
        Add-AuditCheck 'state' $false 'Managed state file is missing.'
        return [ordered]@{ status = 'drift'; computerName = $env:COMPUTERNAME; checks = @($checks) }
    }

    $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
    Add-AuditCheck 'openssh-capability' ($capability.State -eq 'Installed') ([string]$capability.State)

    $user = Get-LocalUser -Name ([string]$state.accountName) -ErrorAction SilentlyContinue
    $userOk = ($null -ne $user) -and ([string]$user.SID.Value -eq [string]$state.accountSid) -and $user.Enabled
    Add-AuditCheck 'account' $userOk $(if ($null -eq $user) { 'missing' } else { "SID=$($user.SID.Value); enabled=$($user.Enabled)" })

    $adminOk = $false
    if ($null -ne $user) {
        $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
        $adminOk = $null -ne (Get-LocalGroupMember -Group $administrators -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.SID.Value -eq [string]$user.SID.Value })
    }
    Add-AuditCheck 'administrator-membership' $adminOk ([string]$adminOk)

    $keyOk = Test-Path -LiteralPath $script:KeyPath
    $fingerprints = @()
    if ($keyOk) {
        try {
            $fingerprints = @(Get-KeyFingerprints -Path $script:KeyPath)
            $expected = @($state.keyFingerprints | Sort-Object)
            $actual = @($fingerprints | Sort-Object)
            $keyOk = (($expected -join "`n") -eq ($actual -join "`n"))
        } catch {
            $keyOk = $false
        }
    }
    Add-AuditCheck 'authorized-keys' $keyOk (($fingerprints -join '; '))
    Add-AuditCheck 'authorized-keys-acl' (Test-ManagedFileAcl -Path $script:KeyPath) 'SYSTEM and Administrators only'
    Add-AuditCheck 'state-acl' (Test-ManagedFileAcl -Path $script:StatePath) 'SYSTEM and Administrators only'

    $hostKeysOk = $true
    try {
        Assert-OpenSshHostKeysProtected
    } catch {
        $hostKeysOk = $false
    }
    Add-AuditCheck 'ssh-host-key-acls' $hostKeysOk 'private host keys: SYSTEM and Administrators only'

    $configOk = $false
    $policyOk = $false
    if (Test-Path -LiteralPath $script:SshConfigPath) {
        try {
            $sshdExe = Get-SshdExecutable
            Test-SshConfig -Path $script:SshConfigPath -SshdExe $sshdExe
            $configOk = $true
            $activeConfigText = Get-Content -LiteralPath $script:SshConfigPath -Raw
            $policyOk = Test-ManagedPolicyText -Text $activeConfigText -Name ([string]$state.accountName) -SshPort ([int]$state.port)
        } catch {
            $configOk = $false
        }
    }
    Add-AuditCheck 'sshd-config-syntax' $configOk ([string]$configOk)
    Add-AuditCheck 'sshd-policy-order' $policyOk ([string]$policyOk)

    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $serviceOk = ($null -ne $service) -and ($service.Status -eq 'Running')
    Add-AuditCheck 'sshd-service' $serviceOk $(if ($null -eq $service) { 'missing' } else { [string]$service.Status })

    $listener = Get-NetTCPConnection -State Listen -LocalPort ([int]$state.port) -ErrorAction SilentlyContinue
    Add-AuditCheck 'tcp-listener' ($null -ne $listener) "TCP/$($state.port)"

    $firewall = Get-NetFirewallRule -Name $script:FirewallRuleName -ErrorAction SilentlyContinue
    $firewallOk = ($null -ne $firewall) -and ([string]$firewall.Enabled -eq 'True') -and ([string]$firewall.Action -eq 'Allow')
    if ($firewallOk) {
        $filter = $firewall | Get-NetFirewallAddressFilter
        $expectedAddresses = @($state.allowedRemoteAddress | Sort-Object)
        $actualAddresses = @($filter.RemoteAddress | Sort-Object)
        $firewallOk = (($expectedAddresses -join ',') -eq ($actualAddresses -join ','))
    }
    Add-AuditCheck 'firewall' $firewallOk $(if ($null -eq $firewall) { 'missing' } else { [string]$firewall.Enabled })

    $defaultRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    $defaultRuleOk = ($null -eq $defaultRule) -or ([string]$defaultRule.Enabled -ne 'True')
    Add-AuditCheck 'default-wide-firewall-disabled' $defaultRuleOk $(if ($null -eq $defaultRule) { 'absent' } else { [string]$defaultRule.Enabled })

    $allOk = @($checks | Where-Object { -not $_.ok }).Count -eq 0
    return [ordered]@{
        status = if ($allOk) { 'compliant' } else { 'drift' }
        installerVersion = $script:InstallerVersion
        computerName = $env:COMPUTERNAME
        ipv4 = @(Get-ActiveIPv4Addresses)
        hostKeyFingerprint = Get-HostKeyFingerprint
        checks = @($checks)
    }
}

function Uninstall-WindowsRemoteBootstrap {
    $state = Get-SavedState
    if ($null -eq $state) {
        throw 'Managed state file is missing; refusing to remove unowned Windows configuration.'
    }

    Get-NetFirewallRule -Name $script:FirewallRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $script:SshConfigPath) {
        $currentHash = Get-FileSha256 -Path $script:SshConfigPath
        if (($currentHash -eq [string]$state.managedConfigSha256) -and
            $state.configBackup -and (Test-Path -LiteralPath ([string]$state.configBackup))) {
            Copy-Item -LiteralPath ([string]$state.configBackup) -Destination $script:SshConfigPath -Force
        } else {
            $currentText = Get-Content -LiteralPath $script:SshConfigPath -Raw
            $cleanText = Remove-ManagedBlocks -Text $currentText
            $candidate = "$script:SshConfigPath.uninstall-candidate"
            [IO.File]::WriteAllText($candidate, $cleanText, [Text.Encoding]::ASCII)
            try {
                Test-SshConfig -Path $candidate -SshdExe (Get-SshdExecutable)
                Move-Item -LiteralPath $candidate -Destination $script:SshConfigPath -Force
            } finally {
                Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
            }
        }
        Restart-Service -Name sshd -Force -ErrorAction SilentlyContinue
    }

    if ([bool]$state.defaultFirewallWasEnabled) {
        Enable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Out-Null
    }

    $user = Get-LocalUser -Name ([string]$state.accountName) -ErrorAction SilentlyContinue
    if (($null -ne $user) -and ([string]$user.SID.Value -eq [string]$state.accountSid)) {
        Remove-LocalUser -Name ([string]$state.accountName)
    }

    if ($RemoveOpenSshCapability -and [bool]$state.openSshInstalledByTool) {
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Remove-WindowsCapability -Online -Name $script:CapabilityName | Out-Null
    }

    $receipt = [ordered]@{
        status = 'uninstalled'
        installerVersion = $script:InstallerVersion
        computerName = $env:COMPUTERNAME
        openSshCapabilityRemoved = [bool]($RemoveOpenSshCapability -and [bool]$state.openSshInstalledByTool)
    }
    Remove-Item -LiteralPath $script:RootPath -Recurse -Force
    return $receipt
}

function Invoke-SelfElevation {
    if (Test-IsAdministrator) {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Save install.ps1 to disk before running it so the installer can request UAC elevation.'
    }

    $payloadPath = Join-Path $env:TEMP ("WindowsRemoteBootstrap-$([Guid]::NewGuid().ToString('N')).json")
    $payload = [ordered]@{
        Mode = $Mode
        AuthorizedKeyBase64 = @($AuthorizedKeyBase64)
        AccountName = $AccountName
        Port = $Port
        AllowedRemoteAddress = @($AllowedRemoteAddress)
        TakeOverExistingSshd = [bool]$TakeOverExistingSshd
        RemoveOpenSshCapability = [bool]$RemoveOpenSshCapability
    }
    Write-JsonFile -Value $payload -Path $payloadPath
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Invoke-Icacls $payloadPath '/inheritance:r' '/grant:r' `
        "*${currentSid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F'

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -ElevatedConfigPath "{1}"' -f $PSCommandPath, $payloadPath
    try {
        $process = Start-Process -FilePath $powershell -Verb RunAs -Wait -PassThru -ArgumentList $arguments
        if (Test-Path -LiteralPath $script:PublicReceiptPath) {
            Write-Output (Get-Content -LiteralPath $script:PublicReceiptPath -Raw)
            Write-Output "Receipt: $script:PublicReceiptPath"
        }
        exit $process.ExitCode
    } finally {
        Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
    }
}

if (-not [string]::IsNullOrWhiteSpace($ElevatedConfigPath)) {
    $elevatedPayload = Get-Content -LiteralPath $ElevatedConfigPath -Raw | ConvertFrom-Json
    $Mode = [string]$elevatedPayload.Mode
    $AuthorizedKeyBase64 = @($elevatedPayload.AuthorizedKeyBase64)
    $AccountName = [string]$elevatedPayload.AccountName
    $Port = [int]$elevatedPayload.Port
    $AllowedRemoteAddress = @($elevatedPayload.AllowedRemoteAddress)
    $TakeOverExistingSshd = [bool]$elevatedPayload.TakeOverExistingSshd
    $RemoveOpenSshCapability = [bool]$elevatedPayload.RemoveOpenSshCapability
    Remove-Item -LiteralPath $ElevatedConfigPath -Force -ErrorAction SilentlyContinue
}

$exitCode = 0
$mutex = $null
$mutexAcquired = $false
try {
    Assert-SupportedEnvironment
    if (-not (Test-IsAdministrator)) {
        [void](Invoke-SelfElevation)
    }

    $mutex = New-Object Threading.Mutex($false, 'Global\WindowsRemoteBootstrap.Setup')
    $mutexAcquired = $mutex.WaitOne(0)
    if (-not $mutexAcquired) {
        throw 'Another WindowsRemoteBootstrap operation is already running.'
    }

    switch ($Mode) {
        'Install' {
            $receipt = Install-WindowsRemoteBootstrap `
                -EncodedKeys $AuthorizedKeyBase64 `
                -Name $AccountName `
                -SshPort $Port `
                -RemoteAddress $AllowedRemoteAddress `
                -MayTakeOver ([bool]$TakeOverExistingSshd)
            Write-PublicReceipt -Receipt $receipt
        }
        'Audit' {
            $receipt = Invoke-WindowsRemoteBootstrapAudit
            Write-PublicReceipt -Receipt $receipt
            if ($receipt.status -ne 'compliant') {
                $exitCode = 2
            }
        }
        'Uninstall' {
            $receipt = Uninstall-WindowsRemoteBootstrap
            Write-PublicReceipt -Receipt $receipt
        }
    }
} catch {
    $exitCode = 1
    $failureReceipt = [ordered]@{
        status = 'failed'
        installerVersion = $script:InstallerVersion
        mode = $Mode
        computerName = $env:COMPUTERNAME
        error = $_.Exception.Message
    }
    try {
        Write-PublicReceipt -Receipt $failureReceipt
    } catch {
        Write-Error $failureReceipt.error
    }
} finally {
    if ($mutexAcquired -and ($null -ne $mutex)) {
        [void]$mutex.ReleaseMutex()
    }
    if ($null -ne $mutex) {
        $mutex.Dispose()
    }
}

exit $exitCode
