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

    [switch]$RemoveOpenSshCapability
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ProgramName = 'WindowsRemoteBootstrap'
$script:InstallerVersion = '1.0.0'
$script:CapabilityName = 'OpenSSH.Server~~~~0.0.1.0'
$script:FirewallRuleName = 'WindowsRemoteBootstrap-SSH-In'
$script:RootPath = Join-Path $env:ProgramData $script:ProgramName
$script:StatePath = Join-Path $script:RootPath 'state.json'
$script:TransactionPath = Join-Path $script:RootPath 'transaction.json'
$script:KeyPath = Join-Path $script:RootPath 'authorized_keys'
$script:SshPath = Join-Path $env:ProgramData 'ssh'
$script:SshConfigPath = Join-Path $script:SshPath 'sshd_config'
$script:PublicReceiptPath = Join-Path $env:PUBLIC 'Documents\WindowsRemoteBootstrap-receipt.json'
$script:GlobalBegin = '# BEGIN WINDOWS-REMOTE-BOOTSTRAP MANAGED CONFIG'
$script:GlobalEnd = '# END WINDOWS-REMOTE-BOOTSTRAP MANAGED CONFIG'
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

function Write-ProtectedJsonFile {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = $Value | ConvertTo-Json -Depth 12
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Protected state directory is missing: $directory"
    }
    $temporaryPath = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporaryPath, $json, $script:Utf8NoBom)
        Protect-ManagedFile -Path $temporaryPath
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
        if (-not (Test-ManagedFileAcl -Path $Path)) {
            throw "Protected state ACL verification failed: $Path"
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Write-PublicReceipt {
    param([Parameter(Mandatory = $true)]$Receipt)

    Write-Output '=== WINDOWS_REMOTE_BOOTSTRAP_RECEIPT ==='
    Write-Output ($Receipt | ConvertTo-Json -Depth 10)
    try {
        Write-JsonFile -Value $Receipt -Path $script:PublicReceiptPath
        Write-Output "Receipt: $script:PublicReceiptPath"
    } catch {
        Write-Warning "The operation committed, but the public receipt file could not be written: $($_.Exception.Message)"
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Set-ExactAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedSids,
        [Parameter(Mandatory = $true)][bool]$Directory,
        [bool]$InheritToChildren = $true,
        [string]$OwnerSid = 'S-1-5-32-544'
    )

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $inheritance = if ($Directory -and $InheritToChildren) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    foreach ($sidText in @($AllowedSids | Sort-Object -Unique)) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $accessRule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($accessRule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($OwnerSid)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-ExactAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedSids,
        [Parameter(Mandatory = $true)][bool]$Directory,
        [bool]$InheritToChildren = $true,
        [string[]]$AllowedOwnerSids = @('S-1-5-18', 'S-1-5-32-544')
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        return $false
    }
    try {
        $ownerSid = $acl.Owner
        if (-not $ownerSid.StartsWith('S-1-')) {
            $ownerSid = (New-Object Security.Principal.NTAccount($ownerSid)).Translate([Security.Principal.SecurityIdentifier]).Value
        }
    } catch {
        return $false
    }
    if ($AllowedOwnerSids -notcontains $ownerSid) {
        return $false
    }

    $expectedInheritance = if ($Directory -and $InheritToChildren) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $rules = @($acl.Access)
    if ($rules.Count -ne @($AllowedSids | Sort-Object -Unique).Count) {
        return $false
    }
    foreach ($rule in $rules) {
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $false
        }
        if (($AllowedSids -notcontains $sid) -or
            ([string]$rule.AccessControlType -ne 'Allow') -or
            $rule.IsInherited -or
            ($rule.InheritanceFlags -ne $expectedInheritance) -or
            ($rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) -or
            (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl)) {
            return $false
        }
    }
    $actual = @($rules | ForEach-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } | Sort-Object -Unique)
    return (($actual -join ',') -eq ((@($AllowedSids | Sort-Object -Unique)) -join ','))
}

function Protect-ProgramDirectory {
    if (-not (Test-Path -LiteralPath $script:RootPath)) {
        [void](New-Item -Path $script:RootPath -ItemType Directory)
    }
    Set-ExactAcl -Path $script:RootPath -AllowedSids @('S-1-5-18', 'S-1-5-32-544') -Directory $true
    if (-not (Test-ManagedDirectoryAcl -Path $script:RootPath)) {
        throw 'Program directory ACL did not converge to SYSTEM and Administrators only.'
    }
}

function Protect-ManagedFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    Set-ExactAcl -Path $Path -AllowedSids @('S-1-5-18', 'S-1-5-32-544') -Directory $false
    if (-not (Test-ManagedFileAcl -Path $Path)) {
        throw "Managed file ACL did not converge: $Path"
    }
}

function Test-ManagedFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Test-ExactAcl -Path $Path -AllowedSids @('S-1-5-18', 'S-1-5-32-544') -Directory $false
}

function Test-ManagedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Test-ExactAcl -Path $Path -AllowedSids @('S-1-5-18', 'S-1-5-32-544') -Directory $true
}

function Get-SshDirectorySnapshot {
    if (-not (Test-Path -LiteralPath $script:SshPath)) {
        return [ordered]@{ existed = $false; sddl = $null; attributes = $null }
    }
    if ((-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) -or
        (Test-ReparsePoint -Path $script:SshPath)) {
        throw "OpenSSH data path must be a real directory: $script:SshPath"
    }
    $item = Get-Item -LiteralPath $script:SshPath -Force
    return [ordered]@{
        existed = $true
        sddl = (Get-Acl -LiteralPath $script:SshPath).Sddl
        attributes = [int]$item.Attributes
    }
}

function Protect-SshDirectory {
    if (-not (Test-Path -LiteralPath $script:SshPath)) {
        [void](New-Item -Path $script:SshPath -ItemType Directory)
    }
    if ((-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) -or
        (Test-ReparsePoint -Path $script:SshPath)) {
        throw "OpenSSH data path must be a real directory: $script:SshPath"
    }
    # Do not propagate a replacement ACL onto unrelated existing SSH files.
    # The parent itself is protected so unprivileged users cannot replace its
    # children; every file this installer relies on is protected separately.
    Set-ExactAcl -Path $script:SshPath -AllowedSids @('S-1-5-18', 'S-1-5-32-544') `
        -Directory $true -InheritToChildren $false
    if (-not (Test-SshDirectoryAcl)) {
        throw 'OpenSSH data directory ACL did not converge.'
    }
}

function Test-SshDirectoryAcl {
    return (Test-Path -LiteralPath $script:SshPath -PathType Container) -and
        (-not (Test-ReparsePoint -Path $script:SshPath)) -and
        (Test-ExactAcl -Path $script:SshPath -AllowedSids @('S-1-5-18', 'S-1-5-32-544') `
            -Directory $true -InheritToChildren $false)
}

function Set-SecurityDescriptorFromSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Snapshot
    )

    if ((Test-ReparsePoint -Path $Path) -or (-not (Test-Path -LiteralPath $Path))) {
        throw "Cannot restore security on a missing or reparse-point path: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm([string]$Snapshot.sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
    [IO.File]::SetAttributes($Path, [IO.FileAttributes][int]$Snapshot.attributes)
    $restoredAcl = Get-Acl -LiteralPath $Path
    $restoredItem = Get-Item -LiteralPath $Path -Force
    if (($restoredAcl.Sddl -ne [string]$Snapshot.sddl) -or
        ([int]$restoredItem.Attributes -ne [int]$Snapshot.attributes)) {
        throw "Security descriptor or attributes were not restored exactly: $Path"
    }
}

function Get-SavedState {
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return $null
    }
    Assert-TrustedProgramPath -Path $script:StatePath -Directory $false
    $state = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
    if (($null -eq $state) -or ([int]$state.schemaVersion -ne 2) -or
        ([string]$state.status -notin @('installed', 'uninstalling', 'uninstall-restart-required'))) {
        throw 'Managed state has an unsupported schema or status.'
    }
    return $state
}

function Get-InstallTransaction {
    if (-not (Test-Path -LiteralPath $script:TransactionPath)) {
        return $null
    }
    Assert-TrustedProgramPath -Path $script:TransactionPath -Directory $false
    $transaction = Get-Content -LiteralPath $script:TransactionPath -Raw | ConvertFrom-Json
    if (($null -eq $transaction) -or ([int]$transaction.schemaVersion -ne 2) -or
        ([string]$transaction.status -notin @('installing', 'restart-required', 'rollback-restart-required'))) {
        throw 'Install transaction has an unsupported schema or status.'
    }
    return $transaction
}

function Test-ReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-TrustedProgramPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    if (-not (Test-Path -LiteralPath $script:RootPath -PathType Container)) {
        throw 'Managed program directory is missing.'
    }
    if ((Test-ReparsePoint -Path $script:RootPath) -or (Test-ReparsePoint -Path $Path)) {
        throw 'Managed state must not use a reparse point.'
    }
    if (-not (Test-ManagedDirectoryAcl -Path $script:RootPath)) {
        throw 'Managed program directory ACL or owner is not trusted.'
    }
    $aclOk = if ($Directory) {
        Test-ManagedDirectoryAcl -Path $Path
    } else {
        Test-ManagedFileAcl -Path $Path
    }
    if (-not $aclOk) {
        throw "Managed path ACL or owner is not trusted: $Path"
    }
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

    if ($Value -ceq 'LocalSubnet') {
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
        if (($prefix -le 0) -or ($prefix -gt $maximum)) {
            return $false
        }
    }
    if ($parsedAddress.Equals([Net.IPAddress]::Any) -or
        $parsedAddress.Equals([Net.IPAddress]::IPv6Any)) {
        return $false
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
    $expandedKeys = @($EncodedKeys | ForEach-Object { @([string]$_ -split ',') })
    foreach ($encoded in $expandedKeys) {
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

function Ensure-TransactionAccount {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Transaction
    )

    $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $hasRecordedSid = -not [string]::IsNullOrWhiteSpace([string]$Transaction.accountSid)
        $ownedBySid = $hasRecordedSid -and ([string]$existing.SID.Value -eq [string]$Transaction.accountSid)
        $ownedByMarker = ([string]$existing.Description -eq [string]$Transaction.accountMarker)
        if (($hasRecordedSid -and (-not ($ownedBySid -and $ownedByMarker))) -or
            ((-not $hasRecordedSid) -and (-not $ownedByMarker))) {
            throw "Local account '$Name' exists but is not owned by the active install transaction."
        }
    } else {
        $plainPassword = New-RandomPassword
        try {
            $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
            $existing = New-LocalUser -Name $Name -Password $securePassword `
                -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword `
                -Description ([string]$Transaction.accountMarker)
        } finally {
            $plainPassword = $null
            $securePassword = $null
        }
    }

    if (-not $existing.Enabled) {
        Enable-LocalUser -Name $Name
    }

    $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
    $isMember = Get-LocalGroupMember -Group $administrators -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.SID.Value -eq [string]$existing.SID.Value }
    if ($null -eq $isMember) {
        Add-LocalGroupMember -Group $administrators -Member $existing
    }

    return $existing
}

function New-ManagedSshConfig {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort
    )

    return @"
$script:GlobalBegin
Port $SshPort
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
AuthorizedKeysFile __PROGRAMDATA__/$script:ProgramName/authorized_keys
AllowUsers $Name
MaxAuthTries 3
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
$script:GlobalEnd
"@
}

function Test-EffectiveSshPolicy {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SshdExe,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort
    )

    $output = @(& $SshdExe -T -f $Path -C "user=$Name,host=localhost,addr=127.0.0.1" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    $lines = @($output | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $required = @(
        "port $SshPort",
        'addressfamily any',
        "listenaddress 0.0.0.0:$SshPort",
        "listenaddress [::]:$SshPort",
        'hostkey __programdata__/ssh/ssh_host_ed25519_key',
        'pubkeyauthentication yes',
        'passwordauthentication no',
        'authenticationmethods publickey',
        'permitemptypasswords no',
        "authorizedkeysfile __programdata__/$($script:ProgramName.ToLowerInvariant())/authorized_keys",
        "allowusers $($Name.ToLowerInvariant())",
        'maxauthtries 3',
        'allowagentforwarding no',
        'allowtcpforwarding no',
        'gatewayports no',
        'permittunnel no',
        'permituserenvironment no'
    )
    foreach ($item in $required) {
        if ($lines -notcontains $item) {
            return $false
        }
    }
    return (@($lines | Where-Object { $_ -like 'port *' }).Count -eq 1) -and
        (@($lines | Where-Object { $_ -like 'hostkey *' }).Count -eq 1) -and
        (@($lines | Where-Object { $_ -like 'allowusers *' }).Count -eq 1) -and
        (@($lines | Where-Object { $_ -like 'authorizedkeysfile *' }).Count -eq 1)
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

function Protect-OpenSshHostKeys {
    $privateHostKeys = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
    if ($privateHostKeys.Count -eq 0) {
        throw 'OpenSSH did not generate any private host keys.'
    }
    foreach ($hostKey in $privateHostKeys) {
        if (Test-ReparsePoint -Path $hostKey.FullName) {
            throw "OpenSSH private host key is a reparse point: $($hostKey.FullName)"
        }
        Protect-ManagedFile -Path $hostKey.FullName
    }
}

function Assert-OpenSshHostKeysProtected {
    $privateHostKeys = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
    if ($privateHostKeys.Count -eq 0) {
        throw 'OpenSSH did not generate any private host keys.'
    }
    foreach ($hostKey in $privateHostKeys) {
        if ((Test-ReparsePoint -Path $hostKey.FullName) -or
            (-not (Test-ManagedFileAcl -Path $hostKey.FullName))) {
            throw "OpenSSH private host key has an unexpected ACL or type: $($hostKey.FullName)"
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
    $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if ($null -ne $rule) {
        $rule | Disable-NetFirewallRule | Out-Null
    }
}

function Test-PortFilterIncludes {
    param($LocalPort, [Parameter(Mandatory = $true)][int]$SshPort)

    foreach ($entry in @($LocalPort)) {
        foreach ($part in @(([string]$entry) -split ',')) {
            $value = $part.Trim()
            if ($value -eq 'Any') { return $true }
            if ($value -match '^(\d+)-(\d+)$') {
                if (($SshPort -ge [int]$Matches[1]) -and ($SshPort -le [int]$Matches[2])) { return $true }
            } elseif ($value -match '^\d+$') {
                if ([int]$value -eq $SshPort) { return $true }
            }
        }
    }
    return $false
}

function Get-CompetingSshFirewallRules {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )

    $targetProgram = [IO.Path]::GetFullPath($SshdExe).TrimEnd('\').ToLowerInvariant()
    $competing = New-Object System.Collections.ArrayList
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @($script:FirewallRuleName, 'OpenSSH-Server-In-TCP') })
    foreach ($rule in $rules) {
        $enforcement = @($rule.EnforcementStatus | ForEach-Object { [string]$_ })
        # ActiveStore can retain packaged-app capability rules whose hidden app
        # identity currently cannot resolve. Such a rule cannot match sshd.exe.
        if (($enforcement -contains 'ApplicationResolutionEmpty') -or ($enforcement -contains '11')) {
            continue
        }
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if ($null -eq $portFilter) {
            continue
        }
        $protocol = [string]$portFilter.Protocol
        if ($protocol -notin @('TCP', '6', 'Any', '256')) {
            continue
        }
        if (-not (Test-PortFilterIncludes -LocalPort $portFilter.LocalPort -SshPort $SshPort)) {
            continue
        }

        $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $program = if ($null -eq $applicationFilter) { 'Any' } else { [string]$applicationFilter.Program }
        $package = if ($null -eq $applicationFilter) { 'Any' } else { [string]$applicationFilter.Package }
        $programExpanded = [Environment]::ExpandEnvironmentVariables($program).TrimEnd('\').ToLowerInvariant()
        $programApplies = ($program -eq 'Any') -or ($programExpanded -eq $targetProgram)
        # Packaged-app rules cannot authorize an unpackaged sshd.exe, even when
        # their Program filter is reported as Any.
        $packageApplies = [string]::IsNullOrWhiteSpace($package) -or ($package -eq 'Any')

        $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
        $serviceName = if ($null -eq $serviceFilter) { 'Any' } else { [string]$serviceFilter.Service }
        $serviceApplies = ($serviceName -eq 'Any') -or ($serviceName -eq 'sshd')
        if ($programApplies -and $packageApplies -and $serviceApplies) {
            [void]$competing.Add("$([string]$rule.Name) [owner=$([string]$rule.Owner); package=$package; program=$program; service=$serviceName; enforcement=$($enforcement -join ','); source=$([string]$rule.PolicyStoreSourceType)]")
        }
    }
    return @($competing)
}

function Assert-FirewallPreconditions {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )

    $disabledProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { [string]$_.Enabled -ne 'True' })
    if ($disabledProfiles.Count -gt 0) {
        throw "Windows Firewall must be enabled for every profile; disabled: $((@($disabledProfiles.Name)) -join ', ')."
    }
    $competing = @(Get-CompetingSshFirewallRules -SshPort $SshPort -SshdExe $SshdExe)
    if ($competing.Count -gt 0) {
        throw "Other enabled inbound allow rules can reach sshd on TCP/${SshPort}: $($competing -join ', '). Disable or narrow them before installing."
    }
}

function Test-ManagedFirewallRule {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$SshdExe,
        [ValidateSet('ActiveStore', 'PersistentStore')][string]$PolicyStore = 'ActiveStore'
    )

    $rules = @(Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore $PolicyStore -ErrorAction SilentlyContinue)
    if ($rules.Count -ne 1) { return $false }
    $rule = $rules[0]
    if (([string]$rule.Enabled -ne 'True') -or
        ([string]$rule.Direction -ne 'Inbound') -or
        ([string]$rule.Action -ne 'Allow') -or
        ([string]$rule.Profile -ne 'Any')) {
        return $false
    }
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    if (($null -eq $portFilter) -or ([string]$portFilter.Protocol -notin @('TCP', '6')) -or
        ([string]$portFilter.LocalPort -ne [string]$SshPort)) {
        return $false
    }
    $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    if ($null -eq $applicationFilter) { return $false }
    $package = [string]$applicationFilter.Package
    if (-not ([string]::IsNullOrWhiteSpace($package) -or ($package -eq 'Any'))) { return $false }
    $actualProgram = [Environment]::ExpandEnvironmentVariables([string]$applicationFilter.Program)
    if ([IO.Path]::GetFullPath($actualProgram).TrimEnd('\') -ine [IO.Path]::GetFullPath($SshdExe).TrimEnd('\')) {
        return $false
    }
    $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
    if (($null -ne $serviceFilter) -and ([string]$serviceFilter.Service -ne 'Any')) { return $false }
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    if ($null -eq $addressFilter) { return $false }
    $expectedAddresses = @($RemoteAddress | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $actualAddresses = @($addressFilter.RemoteAddress | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    return (($expectedAddresses -join ',') -eq ($actualAddresses -join ','))
}

function New-ManagedFirewallRule {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )

    if ($null -ne (Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) {
        throw "Firewall rule '$script:FirewallRuleName' already exists without finalized ownership state."
    }
    New-NetFirewallRule -Name $script:FirewallRuleName `
        -DisplayName 'Windows Remote Bootstrap - SSH (restricted)' `
        -Description 'Managed by WindowsRemoteBootstrap; key-only SSH.' `
        -Enabled True -Profile Any -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $SshPort -RemoteAddress $RemoteAddress `
        -Program $SshdExe | Out-Null
    if ((-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $SshdExe -PolicyStore PersistentStore)) -or
        (-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $SshdExe -PolicyStore ActiveStore))) {
        throw 'The managed firewall rule failed exact filter verification.'
    }
}

function Test-DefaultOpenSshFirewallClosed {
    $rules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    return @($rules | Where-Object { [string]$_.Enabled -eq 'True' }).Count -eq 0
}

function Invoke-TestHook {
    param([Parameter(Mandatory = $true)][string]$Stage)

    if ([string]$env:GITHUB_ACTIONS -ne 'true') { return }
    if ([string]$env:WRB_TEST_THROW_AFTER -eq $Stage) {
        throw "Injected CI failure after $Stage"
    }
    if ([string]$env:WRB_TEST_CRASH_AFTER -eq $Stage) {
        Stop-Process -Id $PID -Force
    }
}

function Get-HostKeyFileRecords {
    if (-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) { return @() }
    if (Test-ReparsePoint -Path $script:SshPath) {
        throw 'OpenSSH host-key directory is a reparse point.'
    }
    return @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*' -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object {
            if (([IO.Path]::GetFileName($_.Name) -ne $_.Name) -or
                ($_.Name -notmatch '^ssh_host_[A-Za-z0-9._-]+$') -or
                (Test-ReparsePoint -Path $_.FullName)) {
                throw "Unsafe OpenSSH host-key path: $($_.FullName)"
            }
            [ordered]@{
                name = $_.Name
                sha256 = (Get-FileSha256 -Path $_.FullName)
                sddl = (Get-Acl -LiteralPath $_.FullName).Sddl
                attributes = [int]$_.Attributes
            }
        })
}

function Get-ServiceSnapshot {
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return [ordered]@{ existed = $false; status = $null; startType = $null; startName = $null; pathName = $null }
    }
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    return [ordered]@{
        existed = $true
        status = [string]$service.Status
        startType = [string]$service.StartType
        startName = [string]$cim.StartName
        pathName = [string]$cim.PathName
    }
}

function Test-SshdServiceIdentity {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if ($null -eq $service) { return $false }
    if ([string]$service.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) { return $false }
    $rawPath = [Environment]::ExpandEnvironmentVariables([string]$service.PathName).Trim()
    if ($rawPath.StartsWith('"') -and $rawPath.EndsWith('"')) {
        $rawPath = $rawPath.Substring(1, $rawPath.Length - 2)
    }
    try {
        $actual = [IO.Path]::GetFullPath($rawPath).TrimEnd('\')
        $expected = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe')).TrimEnd('\')
        return $actual -ieq $expected
    } catch {
        return $false
    }
}

function Restore-ServiceSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not [bool]$Snapshot.existed) {
        if ($null -ne $service) {
            Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
            Set-Service -Name sshd -StartupType Manual
        }
        return
    }
    if ($null -eq $service) {
        throw 'Cannot restore the original sshd service because it is missing.'
    }
    $targetType = [string]$Snapshot.startType
    if ($targetType -eq 'Disabled') {
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Set-Service -Name sshd -StartupType Disabled
        return
    }
    Set-Service -Name sshd -StartupType $targetType
    if ([string]$Snapshot.status -eq 'Running') {
        Start-Service -Name sshd
    } else {
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    }
}

function Get-ConfigSnapshot {
    if (-not (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf)) {
        return [ordered]@{
            existed = $false
            bytesBase64 = $null
            sha256 = $null
            sddl = $null
            attributes = $null
        }
    }
    if (Test-ReparsePoint -Path $script:SshConfigPath) {
        throw 'Existing sshd_config is a reparse point; refusing to replace it.'
    }
    $item = Get-Item -LiteralPath $script:SshConfigPath -Force
    return [ordered]@{
        existed = $true
        bytesBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:SshConfigPath))
        sha256 = Get-FileSha256 -Path $script:SshConfigPath
        sddl = (Get-Acl -LiteralPath $script:SshConfigPath).Sddl
        attributes = [int]$item.Attributes
    }
}

function Restore-ConfigSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    if (-not [bool]$Snapshot.existed) {
        if (Test-Path -LiteralPath $script:SshConfigPath) {
            if (Test-ReparsePoint -Path $script:SshConfigPath) {
                throw 'Refusing to remove a reparse-point sshd_config during recovery.'
            }
            Remove-Item -LiteralPath $script:SshConfigPath -Force
        }
        return
    }
    if (-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) {
        [void](New-Item -Path $script:SshPath -ItemType Directory -Force)
    }
    $temporaryPath = Join-Path $script:SshPath ("sshd_config.restore.$([Guid]::NewGuid().ToString('N'))")
    try {
        [IO.File]::WriteAllBytes($temporaryPath, [Convert]::FromBase64String([string]$Snapshot.bytesBase64))
        Protect-ManagedFile -Path $temporaryPath
        if ((Test-Path -LiteralPath $script:SshConfigPath) -and
            (Test-ReparsePoint -Path $script:SshConfigPath)) {
            throw 'Refusing to replace a reparse-point sshd_config during recovery.'
        }
        Move-Item -LiteralPath $temporaryPath -Destination $script:SshConfigPath -Force
        Set-SecurityDescriptorFromSnapshot -Path $script:SshConfigPath -Snapshot $Snapshot
        if ((Get-FileSha256 -Path $script:SshConfigPath) -ne [string]$Snapshot.sha256) {
            throw 'Original sshd_config byte restoration failed hash verification.'
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Restore-SshDirectorySnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [bool]$RemoveIfOriginallyAbsent = $false
    )

    if ([bool]$Snapshot.existed) {
        if (-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) {
            throw 'Cannot restore the original OpenSSH directory because it is missing.'
        }
        Set-SecurityDescriptorFromSnapshot -Path $script:SshPath -Snapshot $Snapshot
    } elseif ($RemoveIfOriginallyAbsent -and (Test-Path -LiteralPath $script:SshPath)) {
        if ((Test-ReparsePoint -Path $script:SshPath) -or
            (-not (Test-Path -LiteralPath $script:SshPath -PathType Container))) {
            throw 'Refusing to remove an unexpected OpenSSH data path.'
        }
        if (@(Get-ChildItem -LiteralPath $script:SshPath -Force).Count -ne 0) {
            throw 'The newly created OpenSSH data directory contains unowned files; refusing to remove it.'
        }
        Remove-Item -LiteralPath $script:SshPath -Force
    }
}

function Restore-DefaultFirewallSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    $rules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    if ([bool]$Snapshot.existed) {
        if ($rules.Count -ne 1) {
            throw 'Cannot restore the original OpenSSH firewall rule because its identity changed.'
        }
        if ([bool]$Snapshot.enabled) {
            $rules[0] | Enable-NetFirewallRule | Out-Null
        } else {
            $rules[0] | Disable-NetFirewallRule | Out-Null
        }
    } elseif ($rules.Count -gt 0) {
        $rules | Remove-NetFirewallRule
    }
}

function Assert-ValidSecurityDescriptor {
    param([Parameter(Mandatory = $true)][string]$Sddl)
    if ([string]::IsNullOrWhiteSpace($Sddl)) { throw 'A required security descriptor is missing.' }
    try {
        [void](New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList (,$Sddl))
    } catch {
        throw 'A recorded security descriptor is invalid.'
    }
}

function Assert-HostKeyRecordsShape {
    param([Parameter(Mandatory = $true)]$Records)

    $seen = @{}
    foreach ($record in @($Records)) {
        $name = [string]$record.name
        if (([IO.Path]::GetFileName($name) -ne $name) -or
            ($name -notmatch '^ssh_host_[A-Za-z0-9._-]+$')) {
            throw "Unsafe recorded host-key filename: '$name'."
        }
        if ($seen.ContainsKey($name.ToLowerInvariant())) { throw "Duplicate recorded host-key filename: '$name'." }
        $seen[$name.ToLowerInvariant()] = $true
        if ([string]$record.sha256 -notmatch '^[0-9a-f]{64}$') { throw "Invalid host-key hash: '$name'." }
        Assert-ValidSecurityDescriptor -Sddl ([string]$record.sddl)
        try { [void][int]$record.attributes } catch { throw "Invalid host-key attributes: '$name'." }
    }
}

function Assert-SnapshotShape {
    param([Parameter(Mandatory = $true)]$Original)

    foreach ($value in @($Original.capabilityInstalled, $Original.sshDirectory.existed,
            $Original.config.existed, $Original.service.existed, $Original.defaultFirewall.existed,
            $Original.defaultFirewall.enabled)) {
        if ($value -isnot [bool]) { throw 'A recorded baseline boolean is invalid.' }
    }
    if ([bool]$Original.sshDirectory.existed) {
        Assert-ValidSecurityDescriptor -Sddl ([string]$Original.sshDirectory.sddl)
        try { [void][int]$Original.sshDirectory.attributes } catch { throw 'Invalid OpenSSH directory attributes.' }
    }
    if ([bool]$Original.config.existed) {
        $bytes = [Convert]::FromBase64String([string]$Original.config.bytesBase64)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $embeddedHash = (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
        } finally {
            $sha.Dispose()
        }
        if (($embeddedHash -ne [string]$Original.config.sha256) -or
            ([string]$Original.config.sha256 -notmatch '^[0-9a-f]{64}$')) {
            throw 'Original config bytes do not match their recorded hash.'
        }
        Assert-ValidSecurityDescriptor -Sddl ([string]$Original.config.sddl)
        try { [void][int]$Original.config.attributes } catch { throw 'Invalid original config attributes.' }
    }
    Assert-HostKeyRecordsShape -Records @($Original.hostKeyFiles)
    if ([string]$Original.service.status -notin @('', 'Running', 'Stopped', 'Paused', 'StartPending', 'StopPending', 'ContinuePending', 'PausePending')) {
        throw 'Invalid original sshd service status.'
    }
    if ([string]$Original.service.startType -notin @('', 'Automatic', 'Manual', 'Disabled')) {
        throw 'Invalid original sshd service startup type.'
    }
    if ([bool]$Original.service.existed -and
        ([string]::IsNullOrWhiteSpace([string]$Original.service.startName) -or
            [string]::IsNullOrWhiteSpace([string]$Original.service.pathName))) {
        throw 'Original sshd service identity is incomplete.'
    }
}

function Assert-TransactionShape {
    param([Parameter(Mandatory = $true)]$Transaction)

    if ([string]$Transaction.transactionId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid install transaction ID.' }
    if ([string]$Transaction.accountMarker -ne "WRB:$($Transaction.transactionId)") { throw 'Invalid transaction account marker.' }
    Assert-AccountName -Name ([string]$Transaction.accountName)
    Assert-AllowedRemoteAddress -Values @($Transaction.allowedRemoteAddress)
    if (([int]$Transaction.port -lt 1) -or ([int]$Transaction.port -gt 65535)) { throw 'Invalid transaction SSH port.' }
    if ([string]$Transaction.authorizedKeysCanonicalSha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid transaction key hash.' }
    if ([string]$Transaction.phase -notin @('created', 'capability', 'ssh-directory', 'account', 'host-keys', 'config', 'firewall', 'service', 'state-commit')) {
        throw 'Invalid install transaction phase.'
    }
    if ($null -ne $Transaction.accountSid -and
        -not [string]::IsNullOrWhiteSpace([string]$Transaction.accountSid) -and
        [string]$Transaction.accountSid -notmatch '^S-1-5-21-') {
        throw 'Invalid transaction account SID.'
    }
    Assert-SnapshotShape -Original $Transaction.original
    Assert-HostKeyRecordsShape -Records @($Transaction.generatedHostKeyFiles)
    Assert-HostKeyRecordsShape -Records @(@($Transaction.original.hostKeyFiles) + @($Transaction.generatedHostKeyFiles))
}

function Assert-StateShape {
    param([Parameter(Mandatory = $true)]$State)

    if ([string]$State.transactionId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid managed install ID.' }
    if ([string]$State.accountMarker -ne "WRB:$($State.transactionId)") { throw 'Invalid managed account marker.' }
    Assert-AccountName -Name ([string]$State.accountName)
    Assert-AllowedRemoteAddress -Values @($State.allowedRemoteAddress)
    if (([int]$State.port -lt 1) -or ([int]$State.port -gt 65535)) { throw 'Invalid managed SSH port.' }
    foreach ($hash in @([string]$State.authorizedKeysCanonicalSha256, [string]$State.authorizedKeysFileSha256, [string]$State.managedConfigSha256)) {
        if ($hash -notmatch '^[0-9a-f]{64}$') { throw 'Managed state contains an invalid SHA-256.' }
    }
    if ([string]$State.accountSid -notmatch '^S-1-5-21-') { throw 'Invalid managed account SID.' }
    if ([string]$State.firewallRuleName -ne $script:FirewallRuleName) { throw 'Invalid managed firewall rule identity.' }
    if ($State.uninstallRemoveCapability -isnot [bool]) { throw 'Invalid uninstall capability choice in managed state.' }
    Assert-SnapshotShape -Original $State.original
    Assert-HostKeyRecordsShape -Records @($State.generatedHostKeyFiles)
    Assert-HostKeyRecordsShape -Records @(@($State.original.hostKeyFiles) + @($State.generatedHostKeyFiles))
}

function New-InstallTransaction {
    param(
        [Parameter(Mandatory = $true)][string[]]$Keys,
        [Parameter(Mandatory = $true)][string]$KeysCanonicalSha256,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][bool]$MayTakeOver
    )

    if (Test-Path -LiteralPath $script:RootPath) {
        throw "'$script:RootPath' already exists without trusted state; refusing to claim or delete it."
    }
    if ($null -ne (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Local account '$Name' already exists without trusted state."
    }
    if ($null -ne (Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) {
        throw "Firewall rule '$script:FirewallRuleName' already exists without trusted state."
    }
    if ($null -ne (Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
        throw "An effective firewall policy already uses reserved rule name '$script:FirewallRuleName'."
    }

    $sshDirectorySnapshot = Get-SshDirectorySnapshot
    $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
    $serviceSnapshot = Get-ServiceSnapshot
    $configSnapshot = Get-ConfigSnapshot
    $hostKeySnapshot = @(Get-HostKeyFileRecords)
    if (($capability.State -ne 'Installed') -and
        ([bool]$serviceSnapshot.existed -or [bool]$configSnapshot.existed -or
            [bool]$sshDirectorySnapshot.existed -or $hostKeySnapshot.Count -gt 0)) {
        throw 'OpenSSH files or service exist while the Windows capability is absent; refusing an ambiguous takeover.'
    }
    $hasExistingSshd = ($capability.State -eq 'Installed') -or [bool]$serviceSnapshot.existed -or [bool]$configSnapshot.existed
    if ($hasExistingSshd -and (-not $MayTakeOver)) {
        throw 'OpenSSH Server already exists. Rerun with -TakeOverExistingSshd only if replacing its entire access policy is intended.'
    }

    $defaultRules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    if ($defaultRules.Count -gt 1) { throw 'More than one default OpenSSH firewall rule exists; refusing ambiguous takeover.' }
    $defaultFirewall = [ordered]@{
        existed = ($defaultRules.Count -eq 1)
        enabled = ($defaultRules.Count -eq 1) -and ([string]$defaultRules[0].Enabled -eq 'True')
    }
    $sshdPath = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    Assert-FirewallPreconditions -SshPort $SshPort -SshdExe $sshdPath

    $transactionId = [Guid]::NewGuid().ToString('N')
    $transaction = [ordered]@{
        schemaVersion = 2
        installerVersion = $script:InstallerVersion
        status = 'installing'
        phase = 'created'
        transactionId = $transactionId
        createdAt = (Get-Date).ToUniversalTime().ToString('o')
        accountName = $Name
        accountMarker = "WRB:$transactionId"
        accountSid = $null
        port = $SshPort
        allowedRemoteAddress = @($RemoteAddress | Sort-Object -Unique)
        authorizedKeys = @($Keys)
        authorizedKeysCanonicalSha256 = $KeysCanonicalSha256
        takeOverExistingSshd = $MayTakeOver
        capabilityInstalledByTool = ($capability.State -ne 'Installed')
        generatedHostKeyFiles = @()
        original = [ordered]@{
            capabilityInstalled = ($capability.State -eq 'Installed')
            service = $serviceSnapshot
            sshDirectory = $sshDirectorySnapshot
            config = $configSnapshot
            defaultFirewall = $defaultFirewall
            hostKeyFiles = $hostKeySnapshot
        }
    }

    $stagingRoot = Join-Path $env:ProgramData (".$($script:ProgramName)-$transactionId")
    try {
        [void](New-Item -Path $stagingRoot -ItemType Directory)
        Set-ExactAcl -Path $stagingRoot -AllowedSids @('S-1-5-18', 'S-1-5-32-544') -Directory $true
        if ((Test-ReparsePoint -Path $stagingRoot) -or
            -not (Test-ManagedDirectoryAcl -Path $stagingRoot)) {
            throw 'Secure transaction staging directory validation failed.'
        }
        $stagedTransaction = Join-Path $stagingRoot 'transaction.json'
        Write-ProtectedJsonFile -Value $transaction -Path $stagedTransaction
        Move-Item -LiteralPath $stagingRoot -Destination $script:RootPath
    } finally {
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
    }
    $persisted = Get-InstallTransaction
    Assert-TransactionShape -Transaction $persisted
    return $persisted
}

function Update-InstallTransaction {
    param([Parameter(Mandatory = $true)]$Transaction)
    Write-ProtectedJsonFile -Value $Transaction -Path $script:TransactionPath
}

function Assert-RequestedInstallMatches {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$KeysCanonicalSha256,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress
    )

    $expectedAddresses = @($Record.allowedRemoteAddress | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $requestedAddresses = @($RemoteAddress | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    if (([string]$Record.accountName -ne $Name) -or
        ([int]$Record.port -ne $SshPort) -or
        ([string]$Record.authorizedKeysCanonicalSha256 -ne $KeysCanonicalSha256) -or
        (($expectedAddresses -join ',') -ne ($requestedAddresses -join ','))) {
        throw 'Requested settings differ from the owned install/transaction. Uninstall before changing account, keys, port, or firewall sources.'
    }
}

function Assert-OriginalHostKeysUnchanged {
    param([Parameter(Mandatory = $true)]$Records)

    foreach ($record in @($Records)) {
        $path = Join-Path $script:SshPath ([string]$record.name)
        if ((-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
            (Test-ReparsePoint -Path $path) -or
            ((Get-FileSha256 -Path $path) -ne [string]$record.sha256)) {
            throw "An original OpenSSH host-key file changed during the transaction: $path"
        }
    }
}

function Get-GeneratedHostKeyRecords {
    param([Parameter(Mandatory = $true)]$OriginalRecords)

    $originalNames = @($OriginalRecords | ForEach-Object { ([string]$_.name).ToLowerInvariant() })
    return @(Get-HostKeyFileRecords | Where-Object {
        $originalNames -notcontains ([string]$_.name).ToLowerInvariant()
    })
}

function Restore-OriginalHostKeySecurity {
    param([Parameter(Mandatory = $true)]$Records)

    Assert-OriginalHostKeysUnchanged -Records $Records
    foreach ($record in @($Records)) {
        $path = Join-Path $script:SshPath ([string]$record.name)
        Set-SecurityDescriptorFromSnapshot -Path $path -Snapshot $record
    }
}

function Remove-GeneratedHostKeys {
    param([Parameter(Mandatory = $true)]$Records)

    foreach ($record in @($Records)) {
        $path = Join-Path $script:SshPath ([string]$record.name)
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            if ((Get-FileSha256 -Path $path) -ne [string]$record.sha256) {
                throw "Generated host key changed after installation; refusing to delete it: $path"
            }
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Undo-InstallTransaction {
    param([Parameter(Mandatory = $true)]$Transaction)

    Assert-TransactionShape -Transaction $Transaction
    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop

    $account = Get-LocalUser -Name ([string]$Transaction.accountName) -ErrorAction SilentlyContinue
    if ($null -ne $account) {
        if ([string]::IsNullOrWhiteSpace([string]$Transaction.accountSid) -and
            ([string]$account.Description -eq [string]$Transaction.accountMarker)) {
            # A hard stop can happen after New-LocalUser succeeds but before the
            # SID is journaled. The unguessable marker safely reconnects it.
            $Transaction.accountSid = [string]$account.SID.Value
            Update-InstallTransaction -Transaction $Transaction
        }
        $sidMatches = -not [string]::IsNullOrWhiteSpace([string]$Transaction.accountSid) -and
            ([string]$account.SID.Value -eq [string]$Transaction.accountSid)
        if ($sidMatches -and ([string]$account.Description -eq [string]$Transaction.accountMarker)) {
            Remove-LocalUser -Name ([string]$Transaction.accountName)
        } else {
            throw 'Transaction account identity changed; refusing to delete it during recovery.'
        }
    }

    $restartRequired = $false
    if (-not [bool]$Transaction.original.capabilityInstalled) {
        $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
        if ($capability.State -eq 'Installed') {
            $removeResult = Remove-WindowsCapability -Online -Name $script:CapabilityName
            if ($removeResult.RestartNeeded) {
                $restartRequired = $true
            }
        }
    }

    $generatedNow = @()
    if (Test-Path -LiteralPath $script:SshPath -PathType Container) {
        $generatedNow = @(Get-GeneratedHostKeyRecords -OriginalRecords @($Transaction.original.hostKeyFiles))
        $recordedByName = @{}
        foreach ($record in @($Transaction.generatedHostKeyFiles)) {
            $recordedByName[([string]$record.name).ToLowerInvariant()] = $record
        }
        foreach ($record in $generatedNow) {
            $key = ([string]$record.name).ToLowerInvariant()
            if ($recordedByName.ContainsKey($key) -and
                ([string]$recordedByName[$key].sha256 -ne [string]$record.sha256)) {
                throw "A generated host-key file changed before recovery: $($record.name)"
            }
        }
        Remove-GeneratedHostKeys -Records $generatedNow
    }

    Restore-ConfigSnapshot -Snapshot $Transaction.original.config
    Restore-DefaultFirewallSnapshot -Snapshot $Transaction.original.defaultFirewall
    Restore-SshDirectorySnapshot -Snapshot $Transaction.original.sshDirectory `
        -RemoveIfOriginallyAbsent ((-not [bool]$Transaction.original.capabilityInstalled) -and (-not $restartRequired))
    if ([bool]$Transaction.original.sshDirectory.existed) {
        if ([bool]$Transaction.original.config.existed) {
            Set-SecurityDescriptorFromSnapshot -Path $script:SshConfigPath -Snapshot $Transaction.original.config
        }
        Restore-OriginalHostKeySecurity -Records @($Transaction.original.hostKeyFiles)
    }
    Restore-ServiceSnapshot -Snapshot $Transaction.original.service
    Remove-Item -LiteralPath $script:KeyPath -Force -ErrorAction SilentlyContinue
    if ($restartRequired) {
        $Transaction.status = 'rollback-restart-required'
        Update-InstallTransaction -Transaction $Transaction
        throw 'Rollback restored managed configuration but Windows capability removal requires a restart. Restart, then run the same installer command again.'
    }
    Remove-Item -LiteralPath $script:TransactionPath -Force
    if ((Test-Path -LiteralPath $script:RootPath) -and
        @(Get-ChildItem -LiteralPath $script:RootPath -Force).Count -eq 0) {
        Remove-Item -LiteralPath $script:RootPath -Force
    }
}

function Test-SshdListenerExact {
    param([Parameter(Mandatory = $true)][int]$SshPort)

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if (($null -eq $service) -or ([uint32]$service.ProcessId -eq 0)) { return $false }
    $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess ([uint32]$service.ProcessId) -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) { return $false }
    $ports = @($listeners | Select-Object -ExpandProperty LocalPort -Unique)
    return ($ports.Count -eq 1) -and ([int]$ports[0] -eq $SshPort)
}

function New-InstalledReceipt {
    param([Parameter(Mandatory = $true)]$State, [bool]$Idempotent = $false)

    return [ordered]@{
        status = 'installed'
        idempotent = $Idempotent
        installerVersion = $script:InstallerVersion
        computerName = $env:COMPUTERNAME
        ipv4 = @(Get-ActiveIPv4Addresses)
        ssh = [ordered]@{
            user = [string]$State.accountName
            port = [int]$State.port
            allowedRemoteAddress = @($State.allowedRemoteAddress)
            hostKeyFingerprint = [string]$State.hostKeyFingerprint
            authorizedKeyFingerprints = @($State.keyFingerprints)
        }
        verification = [ordered]@{
            openSshCapability = 'Installed'
            effectiveSshdPolicy = 'exact/key-only/single-user/single-port'
            sshdService = 'Running/Automatic'
            tcpListener = "sshd-only TCP/$($State.port)"
            firewall = 'exact/restricted/no-competing-rule'
            endToEndMacSsh = 'pending'
        }
    }
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
    $keys = @(Convert-AuthorizedKeys -EncodedKeys $EncodedKeys)
    $canonicalKeyHash = Get-TextSha256 -Text ($keys -join "`n")
    $savedState = Get-SavedState
    $transaction = Get-InstallTransaction

    if ($null -ne $savedState) {
        Assert-StateShape -State $savedState
        Assert-RequestedInstallMatches -Record $savedState -KeysCanonicalSha256 $canonicalKeyHash `
            -Name $Name -SshPort $SshPort -RemoteAddress $RemoteAddress
        if ([string]$savedState.status -ne 'installed') {
            throw "Managed installation is in '$($savedState.status)' state; finish Uninstall before installing."
        }
        if ($null -ne $transaction) {
            Assert-TransactionShape -Transaction $transaction
            if ([string]$transaction.transactionId -ne [string]$savedState.transactionId) {
                throw 'Installed state and transaction IDs disagree.'
            }
        }
        $audit = Invoke-WindowsRemoteBootstrapAudit
        if ([string]$audit.status -ne 'compliant') {
            if ($null -ne $transaction) {
                Remove-Item -LiteralPath $script:StatePath -Force
                Undo-InstallTransaction -Transaction $transaction
                throw 'The interrupted state commit failed strong audit and was rolled back.'
            }
            throw 'Existing managed installation has security drift. Run -Mode Audit; reinstall will not overwrite drift.'
        }
        if ($null -ne $transaction) {
            Remove-Item -LiteralPath $script:TransactionPath -Force
        }
        return New-InstalledReceipt -State $savedState -Idempotent $true
    }

    if ($null -ne $transaction) {
        Assert-TransactionShape -Transaction $transaction
        Assert-RequestedInstallMatches -Record $transaction -KeysCanonicalSha256 $canonicalKeyHash `
            -Name $Name -SshPort $SshPort -RemoteAddress $RemoteAddress
        if ([string]$transaction.status -eq 'rollback-restart-required') {
            Undo-InstallTransaction -Transaction $transaction
            $transaction = $null
        }
    }
    if ($null -eq $transaction) {
        $transaction = New-InstallTransaction -Keys $keys -KeysCanonicalSha256 $canonicalKeyHash `
            -Name $Name -SshPort $SshPort -RemoteAddress $RemoteAddress -MayTakeOver $MayTakeOver
    }

    try {
        $transaction.phase = 'capability'
        Update-InstallTransaction -Transaction $transaction
        $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
        if ($capability.State -ne 'Installed') {
            $capabilityResult = Add-WindowsCapability -Online -Name $script:CapabilityName
            if ($capabilityResult.RestartNeeded) {
                $transaction.status = 'restart-required'
                Update-InstallTransaction -Transaction $transaction
                return [ordered]@{
                    status = 'restart-required'
                    installerVersion = $script:InstallerVersion
                    computerName = $env:COMPUTERNAME
                    nextStep = 'Restart Windows, then run the exact same installation command.'
                }
            }
        }
        $transaction.status = 'installing'
        Update-InstallTransaction -Transaction $transaction

        $sshdExe = Get-SshdExecutable
        Assert-FirewallPreconditions -SshPort $SshPort -SshdExe $sshdExe
        $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
        if ($null -eq $service) { throw 'OpenSSH capability is installed, but the sshd service is missing.' }
        if (-not (Test-SshdServiceIdentity)) {
            throw 'The sshd service must run the in-box System32 OpenSSH binary as LocalSystem.'
        }
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        Disable-DefaultOpenSshFirewallRule
        if (-not (Test-DefaultOpenSshFirewallClosed)) {
            throw 'The effective default OpenSSH firewall rule remains enabled (possibly by Group Policy).'
        }

        $transaction.phase = 'ssh-directory'
        Update-InstallTransaction -Transaction $transaction
        Protect-SshDirectory
        if ([bool]$transaction.original.config.existed -and
            ((Get-FileSha256 -Path $script:SshConfigPath) -ne [string]$transaction.original.config.sha256)) {
            throw 'The original sshd_config changed before the protected takeover boundary was established.'
        }
        Assert-OriginalHostKeysUnchanged -Records @($transaction.original.hostKeyFiles)

        $transaction.phase = 'account'
        Update-InstallTransaction -Transaction $transaction
        $account = Ensure-TransactionAccount -Name $Name -Transaction $transaction
        Invoke-TestHook -Stage 'account-before-sid-journal'
        $transaction.accountSid = [string]$account.SID.Value
        Update-InstallTransaction -Transaction $transaction
        Invoke-TestHook -Stage 'account'

        $keyCandidate = Join-Path $script:RootPath ("authorized_keys.$([Guid]::NewGuid().ToString('N')).tmp")
        try {
            [IO.File]::WriteAllLines($keyCandidate, $keys, [Text.Encoding]::ASCII)
            Protect-ManagedFile -Path $keyCandidate
            Move-Item -LiteralPath $keyCandidate -Destination $script:KeyPath -Force
        } finally {
            Remove-Item -LiteralPath $keyCandidate -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-ManagedFileAcl -Path $script:KeyPath)) { throw 'Authorized key ACL verification failed.' }
        $fingerprints = @(Get-KeyFingerprints -Path $script:KeyPath)

        $transaction.phase = 'host-keys'
        Update-InstallTransaction -Transaction $transaction
        $keygen = Get-SshKeygenExecutable
        $keygenOutput = @(& $keygen -A 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "OpenSSH host key generation failed: $($keygenOutput -join ' ')" }
        Invoke-TestHook -Stage 'hostkeys-before-journal'
        Protect-OpenSshHostKeys
        $transaction.generatedHostKeyFiles = @(Get-GeneratedHostKeyRecords -OriginalRecords @($transaction.original.hostKeyFiles))
        Update-InstallTransaction -Transaction $transaction
        Assert-OpenSshHostKeysProtected

        $transaction.phase = 'config'
        Update-InstallTransaction -Transaction $transaction
        $managedConfig = New-ManagedSshConfig -Name $Name -SshPort $SshPort
        $candidatePath = Join-Path $script:SshPath ("sshd_config.$([Guid]::NewGuid().ToString('N')).candidate")
        try {
            [IO.File]::WriteAllText($candidatePath, $managedConfig, [Text.Encoding]::ASCII)
            Protect-ManagedFile -Path $candidatePath
            Test-SshConfig -Path $candidatePath -SshdExe $sshdExe
            if (-not (Test-EffectiveSshPolicy -Path $candidatePath -SshdExe $sshdExe -Name $Name -SshPort $SshPort)) {
                throw 'Candidate effective sshd policy failed exact verification.'
            }
            Move-Item -LiteralPath $candidatePath -Destination $script:SshConfigPath -Force
        } finally {
            Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-ManagedFileAcl -Path $script:SshConfigPath)) { throw 'Active sshd_config ACL verification failed.' }
        Invoke-TestHook -Stage 'config'

        $transaction.phase = 'firewall'
        Update-InstallTransaction -Transaction $transaction
        $existingOwnRule = Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue
        if ($null -ne $existingOwnRule) {
            if ((-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe -PolicyStore PersistentStore)) -or
                (-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe -PolicyStore ActiveStore))) {
                $existingOwnRule | Remove-NetFirewallRule
                New-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe
            }
        } else {
            New-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe
        }
        Invoke-TestHook -Stage 'firewall'

        $transaction.phase = 'service'
        Update-InstallTransaction -Transaction $transaction
        Set-Service -Name sshd -StartupType Automatic
        Start-Service -Name sshd
        $deadline = (Get-Date).AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 250
            $service = Get-Service -Name sshd
        } while (($service.Status -ne 'Running') -and ((Get-Date) -lt $deadline))
        if (($service.Status -ne 'Running') -or (-not (Test-SshdListenerExact -SshPort $SshPort))) {
            throw 'sshd did not reach the exact expected running/listener state.'
        }
        Invoke-TestHook -Stage 'service'

        $transaction.phase = 'state-commit'
        Update-InstallTransaction -Transaction $transaction
        $state = [ordered]@{
            schemaVersion = 2
            installerVersion = $script:InstallerVersion
            status = 'installed'
            transactionId = [string]$transaction.transactionId
            installedAt = (Get-Date).ToUniversalTime().ToString('o')
            computerName = $env:COMPUTERNAME
            accountName = $Name
            accountMarker = [string]$transaction.accountMarker
            accountSid = [string]$transaction.accountSid
            port = $SshPort
            allowedRemoteAddress = @($RemoteAddress | Sort-Object -Unique)
            authorizedKeysCanonicalSha256 = $canonicalKeyHash
            authorizedKeysFileSha256 = Get-FileSha256 -Path $script:KeyPath
            keyFingerprints = @($fingerprints)
            firewallRuleName = $script:FirewallRuleName
            managedConfigSha256 = Get-FileSha256 -Path $script:SshConfigPath
            hostKeyFingerprint = Get-HostKeyFingerprint
            openSshInstalledByTool = [bool]$transaction.capabilityInstalledByTool
            existingSshdTakenOver = [bool]$transaction.takeOverExistingSshd
            uninstallRemoveCapability = $false
            generatedHostKeyFiles = @($transaction.generatedHostKeyFiles)
            original = $transaction.original
        }
        Write-ProtectedJsonFile -Value $state -Path $script:StatePath
        Invoke-TestHook -Stage 'state-commit'
        $audit = Invoke-WindowsRemoteBootstrapAudit
        if ([string]$audit.status -ne 'compliant') {
            Remove-Item -LiteralPath $script:StatePath -Force
            throw 'Final strong audit did not prove the installed security state.'
        }
        Remove-Item -LiteralPath $script:TransactionPath -Force
        return New-InstalledReceipt -State $state
    } catch {
        $failure = $_
        $committedState = $null
        try { $committedState = Get-SavedState } catch { $committedState = $null }
        if (($null -ne $committedState) -and
            ([string]$committedState.transactionId -eq [string]$transaction.transactionId)) {
            try {
                $committedAudit = Invoke-WindowsRemoteBootstrapAudit
                if ([string]$committedAudit.status -eq 'compliant') {
                    Remove-Item -LiteralPath $script:TransactionPath -Force -ErrorAction SilentlyContinue
                    return New-InstalledReceipt -State $committedState
                }
            } catch { }
            Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue
        }
        try {
            Undo-InstallTransaction -Transaction $transaction
        } catch {
            throw "$($failure.Exception.Message) Rollback also failed and the protected transaction was retained: $($_.Exception.Message)"
        }
        throw $failure
    }
}

function Invoke-WindowsRemoteBootstrapAudit {
    $checks = New-Object System.Collections.ArrayList

    function Add-AuditCheck {
        param([string]$Name, [bool]$Ok, [string]$Detail)
        [void]$checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
    }

    $state = $null
    try {
        $state = Get-SavedState
        if ($null -ne $state) { Assert-StateShape -State $state }
        Add-AuditCheck 'trusted-state' ($null -ne $state) $(if ($null -eq $state) { 'missing' } else { 'schema/owner/exact ACL valid' })
    } catch {
        Add-AuditCheck 'trusted-state' $false $_.Exception.Message
        return [ordered]@{ status = 'drift'; computerName = $env:COMPUTERNAME; checks = @($checks) }
    }
    if ($null -eq $state) {
        return [ordered]@{ status = 'drift'; computerName = $env:COMPUTERNAME; checks = @($checks) }
    }
    Add-AuditCheck 'install-status' ([string]$state.status -eq 'installed') ([string]$state.status)
    Add-AuditCheck 'program-root-acl' (Test-ManagedDirectoryAcl -Path $script:RootPath) 'SYSTEM/Administrators exact FullControl'
    Add-AuditCheck 'state-acl' (Test-ManagedFileAcl -Path $script:StatePath) 'SYSTEM/Administrators exact FullControl'

    $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
    Add-AuditCheck 'openssh-capability' ($capability.State -eq 'Installed') ([string]$capability.State)

    $user = Get-LocalUser -Name ([string]$state.accountName) -ErrorAction SilentlyContinue
    $userOk = ($null -ne $user) -and
        ([string]$user.SID.Value -eq [string]$state.accountSid) -and
        ([string]$user.Description -eq [string]$state.accountMarker) -and
        $user.Enabled
    Add-AuditCheck 'account' $userOk $(if ($null -eq $user) { 'missing' } else { "SID=$($user.SID.Value); enabled=$($user.Enabled); marker=$($user.Description)" })

    $adminOk = $false
    if ($null -ne $user) {
        $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
        $adminOk = $null -ne (Get-LocalGroupMember -Group $administrators -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.SID.Value -eq [string]$user.SID.Value })
    }
    Add-AuditCheck 'administrator-membership' $adminOk ([string]$adminOk)

    $keyOk = (Test-Path -LiteralPath $script:KeyPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $script:KeyPath)) -and
        ((Get-FileSha256 -Path $script:KeyPath) -eq [string]$state.authorizedKeysFileSha256)
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
    Add-AuditCheck 'openssh-directory-acl' (Test-SshDirectoryAcl) 'real directory; SYSTEM/Administrators exact FullControl'

    $hostKeysOk = $true
    try {
        Assert-OpenSshHostKeysProtected
    } catch {
        $hostKeysOk = $false
    }
    Add-AuditCheck 'ssh-host-key-acls' $hostKeysOk 'private host keys: SYSTEM and Administrators only'
    $hostKeySetOk = $true
    try {
        $expectedRecords = @(@($state.original.hostKeyFiles) + @($state.generatedHostKeyFiles) |
            Sort-Object { ([string]$_.name).ToLowerInvariant() })
        $currentRecords = @(Get-HostKeyFileRecords | Sort-Object { ([string]$_.name).ToLowerInvariant() })
        if ($expectedRecords.Count -ne $currentRecords.Count) {
            $hostKeySetOk = $false
        } else {
            for ($index = 0; $index -lt $expectedRecords.Count; $index++) {
                if (([string]$expectedRecords[$index].name -ine [string]$currentRecords[$index].name) -or
                    ([string]$expectedRecords[$index].sha256 -ne [string]$currentRecords[$index].sha256)) {
                    $hostKeySetOk = $false
                }
            }
        }
    } catch {
        $hostKeySetOk = $false
    }
    Add-AuditCheck 'host-key-file-set-and-hashes' $hostKeySetOk 'original plus generated host-key files exactly unchanged'
    $currentHostFingerprint = Get-HostKeyFingerprint
    Add-AuditCheck 'host-key-fingerprint' `
        ([string]$currentHostFingerprint -eq [string]$state.hostKeyFingerprint) ([string]$currentHostFingerprint)

    $configOk = $false
    $policyOk = $false
    $configAclOk = $false
    if ((Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $script:SshConfigPath))) {
        try {
            $sshdExe = Get-SshdExecutable
            Test-SshConfig -Path $script:SshConfigPath -SshdExe $sshdExe
            $configOk = (Get-FileSha256 -Path $script:SshConfigPath) -eq [string]$state.managedConfigSha256
            $configAclOk = Test-ManagedFileAcl -Path $script:SshConfigPath
            $policyOk = Test-EffectiveSshPolicy -Path $script:SshConfigPath -SshdExe $sshdExe `
                -Name ([string]$state.accountName) -SshPort ([int]$state.port)
        } catch {
            $configOk = $false
        }
    }
    Add-AuditCheck 'sshd-config-hash-and-syntax' $configOk ([string]$configOk)
    Add-AuditCheck 'sshd-config-acl' $configAclOk 'SYSTEM/Administrators exact FullControl'
    Add-AuditCheck 'effective-sshd-policy' $policyOk 'single user, key file, and port; forwarding disabled'

    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $serviceOk = ($null -ne $service) -and ($service.Status -eq 'Running') -and ([string]$service.StartType -eq 'Automatic')
    Add-AuditCheck 'sshd-service' $serviceOk $(if ($null -eq $service) { 'missing' } else { "$($service.Status)/$($service.StartType)" })
    Add-AuditCheck 'sshd-service-identity' (Test-SshdServiceIdentity) 'System32 OpenSSH sshd.exe as LocalSystem'

    $listenerOk = Test-SshdListenerExact -SshPort ([int]$state.port)
    Add-AuditCheck 'sshd-listeners' $listenerOk "sshd PID only TCP/$($state.port)"

    $sshdPath = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $firewallOk = Test-ManagedFirewallRule -SshPort ([int]$state.port) `
        -RemoteAddress @($state.allowedRemoteAddress) -SshdExe $sshdPath
    Add-AuditCheck 'firewall-exact-filters' $firewallOk ([string]$firewallOk)
    $profilesOk = $true
    $competing = @()
    try {
        $profilesOk = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0
        $competing = @(Get-CompetingSshFirewallRules -SshPort ([int]$state.port) -SshdExe $sshdPath)
    } catch {
        $profilesOk = $false
    }
    Add-AuditCheck 'firewall-profiles-enabled' $profilesOk ([string]$profilesOk)
    Add-AuditCheck 'no-competing-firewall-rule' ($competing.Count -eq 0) ($competing -join ', ')

    $defaultRules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    $enabledDefaultRules = @($defaultRules | Where-Object { [string]$_.Enabled -eq 'True' })
    $defaultRuleOk = $enabledDefaultRules.Count -eq 0
    Add-AuditCheck 'default-wide-firewall-disabled' $defaultRuleOk $(if ($defaultRules.Count -eq 0) { 'absent' } else { (@($defaultRules.Enabled) -join ',') })

    $originalConfigOk = $true
    if ([bool]$state.original.config.existed) {
        try {
            $bytes = [Convert]::FromBase64String([string]$state.original.config.bytesBase64)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $embeddedHash = (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
            } finally {
                $sha.Dispose()
            }
            $originalConfigOk = $embeddedHash -eq [string]$state.original.config.sha256
        } catch {
            $originalConfigOk = $false
        }
    }
    Add-AuditCheck 'embedded-original-config' $originalConfigOk 'rollback bytes match recorded hash'

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
        $transaction = Get-InstallTransaction
        if ($null -eq $transaction) {
            throw 'Managed state is missing; refusing to remove unowned Windows configuration.'
        }
        Undo-InstallTransaction -Transaction $transaction
        return [ordered]@{
            status = 'rolled-back-incomplete-install'
            installerVersion = $script:InstallerVersion
            computerName = $env:COMPUTERNAME
        }
    }
    Assert-StateShape -State $state

    if ([string]$state.status -eq 'installed') {
        $audit = Invoke-WindowsRemoteBootstrapAudit
        if ([string]$audit.status -ne 'compliant') {
            throw 'Uninstall refused before mutation because the managed security state has drifted. Run -Mode Audit and repair the reported drift.'
        }
        $state.status = 'uninstalling'
        $state.uninstallRemoveCapability = [bool]$RemoveOpenSshCapability
        Write-ProtectedJsonFile -Value $state -Path $script:StatePath
    } else {
        if ([bool]$state.uninstallRemoveCapability -ne [bool]$RemoveOpenSshCapability) {
            throw 'Resume Uninstall with the same -RemoveOpenSshCapability choice used when it started.'
        }
    }

    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name $script:FirewallRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
    Invoke-TestHook -Stage 'uninstall-firewall'

    $user = Get-LocalUser -Name ([string]$state.accountName) -ErrorAction SilentlyContinue
    if ($null -ne $user) {
        if (([string]$user.SID.Value -ne [string]$state.accountSid) -or
            ([string]$user.Description -ne [string]$state.accountMarker)) {
            throw 'Managed account identity changed; refusing to delete it.'
        }
        Remove-LocalUser -Name ([string]$state.accountName)
    }
    Invoke-TestHook -Stage 'uninstall-account'

    $removeCapability = [bool]$state.uninstallRemoveCapability -and [bool]$state.openSshInstalledByTool
    if ([bool]$state.original.capabilityInstalled -or $removeCapability) {
        Remove-GeneratedHostKeys -Records @($state.generatedHostKeyFiles)
    }

    $restartRequired = $false
    if ($removeCapability) {
        $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
        if ($capability.State -eq 'Installed') {
            $removeResult = Remove-WindowsCapability -Online -Name $script:CapabilityName
            if ($removeResult.RestartNeeded) {
                $restartRequired = $true
            }
        }
    }

    Restore-ConfigSnapshot -Snapshot $state.original.config
    Invoke-TestHook -Stage 'uninstall-config'
    Restore-DefaultFirewallSnapshot -Snapshot $state.original.defaultFirewall
    $removeSshDirectory = (-not [bool]$state.original.sshDirectory.existed) -and
        ([bool]$state.original.capabilityInstalled -or ($removeCapability -and (-not $restartRequired)))
    Restore-SshDirectorySnapshot -Snapshot $state.original.sshDirectory `
        -RemoveIfOriginallyAbsent $removeSshDirectory
    if ([bool]$state.original.sshDirectory.existed) {
        if ([bool]$state.original.config.existed) {
            Set-SecurityDescriptorFromSnapshot -Path $script:SshConfigPath -Snapshot $state.original.config
        }
        Restore-OriginalHostKeySecurity -Records @($state.original.hostKeyFiles)
    }

    if ([bool]$state.original.capabilityInstalled) {
        Restore-ServiceSnapshot -Snapshot $state.original.service
    } else {
        Restore-ServiceSnapshot -Snapshot ([ordered]@{ existed = $false; status = $null; startType = $null })
    }

    if ($restartRequired) {
        $state.status = 'uninstall-restart-required'
        Write-ProtectedJsonFile -Value $state -Path $script:StatePath
        return [ordered]@{
            status = 'uninstall-restart-required'
            installerVersion = $script:InstallerVersion
            computerName = $env:COMPUTERNAME
            nextStep = 'Restart Windows, then run the exact same uninstall command.'
        }
    }

    Remove-Item -LiteralPath $script:KeyPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:TransactionPath -Force -ErrorAction SilentlyContinue
    $receipt = [ordered]@{
        status = 'uninstalled'
        installerVersion = $script:InstallerVersion
        computerName = $env:COMPUTERNAME
        openSshCapabilityRemoved = $removeCapability
    }
    Remove-Item -LiteralPath $script:StatePath -Force
    if ((Test-Path -LiteralPath $script:RootPath) -and
        @(Get-ChildItem -LiteralPath $script:RootPath -Force).Count -eq 0) {
        Remove-Item -LiteralPath $script:RootPath -Force
    }
    return $receipt
}

$exitCode = 0
$mutex = $null
$mutexAcquired = $false
try {
    Assert-SupportedEnvironment
    if (-not (Test-IsAdministrator)) {
        throw 'Run this installer from an elevated 64-bit Windows PowerShell process.'
    }

    $mutex = New-Object Threading.Mutex($false, 'Global\WindowsRemoteBootstrap.Setup')
    try {
        $mutexAcquired = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        # WaitOne grants ownership before reporting that the previous process
        # died. Treat it as acquired so recovery can proceed and finally can
        # release it normally.
        $mutexAcquired = $true
    }
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
            if ([string]$receipt.status -eq 'restart-required') {
                $exitCode = 3
            }
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
            if ([string]$receipt.status -eq 'uninstall-restart-required') {
                $exitCode = 3
            }
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
