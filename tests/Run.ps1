#Requires -Version 5.1

param(
    [ValidateSet('smoke', 'recovery')]
    [string]$Suite = 'smoke'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot 'install.ps1'
$winctl = Join-Path $repoRoot 'winctl'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sshRoot = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $sshRoot 'sshd_config'
$managedRoot = Join-Path $env:ProgramData 'WindowsRemoteBootstrap'
$cleanupRoot = Join-Path $env:ProgramData '.WindowsRemoteBootstrap.cleanup'
$receiptPath = Join-Path $env:PUBLIC 'Documents\WindowsRemoteBootstrap-receipt.json'
$managedRuleName = 'WindowsRemoteBootstrap-SSH-In'
$testRoot = Join-Path $env:TEMP ("WindowsRemoteBootstrapTests-$([Guid]::NewGuid().ToString('N'))")
$clientKey = Join-Path $testRoot 'id_ed25519'
$unauthorizedKey = Join-Path $testRoot 'id_unauthorized'
$knownHosts = Join-Path $testRoot 'known_hosts'
$testPort = 22991

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ([string]$Expected -ne [string]$Actual) {
        throw "ASSERTION FAILED: $Message`nEXPECTED: $Expected`nACTUAL: $Actual"
    }
}

function Set-TestExactAcl {
    param([string]$Path, [bool]$Directory = $false)

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    try {
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        & "$env:SystemRoot\System32\takeown.exe" /F $Path /A | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "takeown failed for $Path" }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

function Set-PathSnapshot {
    param([string]$Path, $Snapshot)

    if (-not [bool]$Snapshot.existed) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        return
    }
    [IO.File]::WriteAllBytes($Path, [Convert]::FromBase64String([string]$Snapshot.bytesBase64))
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm([string]$Snapshot.sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
    [IO.File]::SetAttributes($Path, [IO.FileAttributes][int]$Snapshot.attributes)
}

function Get-PathSnapshot {
    param([string]$Path, [bool]$Directory = $false)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ existed = $false; sddl = $null; attributes = $null; bytesBase64 = $null; sha256 = $null }
    }
    $item = Get-Item -LiteralPath $Path -Force
    $bytes = if ($Directory) { $null } else { [IO.File]::ReadAllBytes($Path) }
    return [ordered]@{
        existed = $true
        sddl = (Get-Acl -LiteralPath $Path).Sddl
        attributes = [int]$item.Attributes
        bytesBase64 = if ($Directory) { $null } else { [Convert]::ToBase64String($bytes) }
        sha256 = if ($Directory) { $null } else { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
}

function Get-HostKeySnapshots {
    if (-not (Test-Path -LiteralPath $sshRoot -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $sshRoot -Filter 'ssh_host_*' -Force -ErrorAction Stop |
        Sort-Object Name | ForEach-Object {
            if ($_.PSIsContainer) { throw "Unexpected host-key directory: $($_.FullName)" }
            [ordered]@{
                name = $_.Name
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                sddl = (Get-Acl -LiteralPath $_.FullName).Sddl
                attributes = [int]$_.Attributes
            }
        })
}

function Get-ServiceTestSnapshot {
    $cimServices = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
    if ($cimServices.Count -eq 0) {
        return [ordered]@{
            existed = $false
            status = $null
            startType = $null
            startName = $null
            pathName = $null
        }
    }
    Assert-True ($cimServices.Count -eq 1) 'test fixture found an ambiguous sshd service'
    $service = Get-Service -Name sshd -ErrorAction Stop
    $cim = $cimServices[0]
    return [ordered]@{
        existed = $true
        status = [string]$service.Status
        startType = [string]$service.StartType
        startName = [string]$cim.StartName
        pathName = [string]$cim.PathName
    }
}

function Canonical-Values {
    param($Value)
    return (@($Value | ForEach-Object { [string]$_ } | Sort-Object -Unique) -join ',')
}

function Get-DefaultFirewallSnapshot {
    $rules = @(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) { return [ordered]@{ existed = $false } }
    Assert-True ($rules.Count -eq 1) 'default firewall fixture must be unambiguous'
    $rule = $rules[0]
    $port = $rule | Get-NetFirewallPortFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $app = $rule | Get-NetFirewallApplicationFilter
    $service = $rule | Get-NetFirewallServiceFilter
    return [ordered]@{
        existed = $true
        enabled = [string]$rule.Enabled
        direction = [string]$rule.Direction
        action = [string]$rule.Action
        profile = [string]$rule.Profile
        displayName = [string]$rule.DisplayName
        description = [string]$rule.Description
        protocol = Canonical-Values $port.Protocol
        localPort = Canonical-Values $port.LocalPort
        remotePort = Canonical-Values $port.RemotePort
        localAddress = Canonical-Values $address.LocalAddress
        remoteAddress = Canonical-Values $address.RemoteAddress
        program = Canonical-Values $app.Program
        package = Canonical-Values $app.Package
        service = Canonical-Values $service.Service
    }
}

function Get-Baseline {
    return [ordered]@{
        capability = [string](Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0').State
        sshDirectory = Get-PathSnapshot -Path $sshRoot -Directory $true
        config = Get-PathSnapshot -Path $configPath
        hostKeys = @(Get-HostKeySnapshots)
        service = Get-ServiceTestSnapshot
        defaultFirewall = Get-DefaultFirewallSnapshot
    }
}

function Assert-BaselineExact {
    param($Expected, [string]$Context)
    $actual = Get-Baseline
    Assert-Equal ($Expected | ConvertTo-Json -Depth 10 -Compress) `
        ($actual | ConvertTo-Json -Depth 10 -Compress) "$Context did not restore the exact baseline"
    Assert-True ($null -eq (Get-LocalUser -Name macremote -ErrorAction SilentlyContinue)) "$Context left the managed account"
    Assert-True ($null -eq (Get-NetFirewallRule -Name $managedRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) "$Context left the managed firewall rule"
    $rootDiagnostic = if (Test-Path -LiteralPath $managedRoot) {
        @((Get-ChildItem -LiteralPath $managedRoot -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ',')
    } else { @() }
    Assert-True (-not (Test-Path -LiteralPath $managedRoot)) `
        "$Context left the managed root; children=$($rootDiagnostic -join ',')"
    Assert-True (-not (Test-Path -LiteralPath $cleanupRoot)) `
        "$Context left the protected cleanup root"
}

function Invoke-InstallerRaw {
    param(
        [string[]]$Arguments,
        [string]$ThrowAfter = '',
        [string]$CrashAfter = ''
    )

    Remove-Item -LiteralPath $receiptPath -Force -ErrorAction SilentlyContinue
    $oldThrow = [string]$env:WRB_TEST_THROW_AFTER
    $oldCrash = [string]$env:WRB_TEST_CRASH_AFTER
    try {
        $env:WRB_TEST_THROW_AFTER = $ThrowAfter
        $env:WRB_TEST_CRASH_AFTER = $CrashAfter
        $output = @(& $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $installer @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally {
        $env:WRB_TEST_THROW_AFTER = $oldThrow
        $env:WRB_TEST_CRASH_AFTER = $oldCrash
    }
    $receipt = $null
    if (Test-Path -LiteralPath $receiptPath) {
        try { $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json } catch { $receipt = $null }
    }
    return [pscustomobject]@{
        ExitCode = $code
        Output = @($output | ForEach-Object { [string]$_ })
        ReceiptExists = Test-Path -LiteralPath $receiptPath
        Receipt = $receipt
    }
}

function Assert-Result {
    param($Result, [int]$ExitCode, [string]$Status, [string]$Context)
    $diagnostic = "$Context exit code; output=$($Result.Output -join ' | '); receipt=$($Result.Receipt | ConvertTo-Json -Depth 8 -Compress)"
    Assert-Equal $ExitCode $Result.ExitCode $diagnostic
    Assert-True ($null -ne $Result.Receipt) "$Context did not produce a parseable receipt: $($Result.Output -join ' ')"
    Assert-Equal $Status ([string]$Result.Receipt.status) "$Context receipt status"
}

function Assert-AuditCheck {
    param($Receipt, [string]$Name, [bool]$Expected)
    $check = @($Receipt.checks | Where-Object { [string]$_.name -eq $Name })
    Assert-True ($check.Count -eq 1) "Audit check '$Name' is missing or duplicated"
    Assert-Equal $Expected ([bool]$check[0].ok) "Audit check '$Name'"
}

function ConvertTo-MsysPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Cannot convert a non-drive path for Git Bash: $fullPath"
    }
    return "/$(([string]$Matches[1]).ToLowerInvariant())/$(([string]$Matches[2]).Replace('\', '/'))"
}

function Write-TestKnownHosts {
    $publicHostKey = Get-Content -LiteralPath (Join-Path $sshRoot 'ssh_host_ed25519_key.pub') -Raw
    $parts = @($publicHostKey.Trim() -split '\s+')
    Assert-True ($parts.Count -ge 2) 'managed host public key is malformed'
    [IO.File]::WriteAllText(
        $knownHosts,
        "[127.0.0.1]:$testPort $($parts[0]) $($parts[1])`n",
        (New-Object Text.UTF8Encoding($false))
    )
}

function Get-TestPowerValue {
    param([string]$SubGroup, [string]$Setting)
    $text = (& powercfg.exe /query SCHEME_CURRENT $SubGroup $Setting 2>&1 | Out-String)
    Assert-True ($LASTEXITCODE -eq 0) "powercfg query failed: $text"
    $values = @([regex]::Matches($text, '0x([0-9a-fA-F]{8})') | ForEach-Object {
            [Convert]::ToInt64($_.Groups[1].Value, 16)
        })
    Assert-True ($values.Count -ge 2) 'powercfg query did not expose current AC/DC values'
    return [pscustomobject]@{
        AcSeconds = [int64]$values[$values.Count - 2]
        DcSeconds = [int64]$values[$values.Count - 1]
    }
}

function Test-WinctlPowerControl {
    $bash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
    Assert-True (Test-Path -LiteralPath $bash -PathType Leaf) 'Git Bash is unavailable for the macOS helper test'
    $before = Get-TestPowerValue -SubGroup 'SUB_VIDEO' -Setting 'VIDEOIDLE'
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $bash (ConvertTo-MsysPath -Path $winctl) `
                    '--identity' (ConvertTo-MsysPath -Path $clientKey) `
                    '--known-hosts' (ConvertTo-MsysPath -Path $knownHosts) `
                    '--port' ([string]$testPort) '127.0.0.1' 'display' '17' '19' 2>&1)
            $winctlExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        Assert-True ($winctlExitCode -eq 0) "winctl failed: $($output -join ' ')"
        $receipt = ($output -join "`n") | ConvertFrom-Json
        Assert-Equal 'updated' ([string]$receipt.status) 'winctl update status'
        Assert-Equal 1020 ([int64]$receipt.effective.acSeconds) 'winctl AC display readback'
        Assert-Equal 1140 ([int64]$receipt.effective.dcSeconds) 'winctl DC display readback'
        $actual = Get-TestPowerValue -SubGroup 'SUB_VIDEO' -Setting 'VIDEOIDLE'
        Assert-Equal 1020 $actual.AcSeconds 'system AC display setting after winctl'
        Assert-Equal 1140 $actual.DcSeconds 'system DC display setting after winctl'
    } finally {
        & powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE ([string]$before.AcSeconds) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to restore the AC display timeout after winctl test' }
        & powercfg.exe /setdcvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE ([string]$before.DcSeconds) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to restore the DC display timeout after winctl test' }
        & powercfg.exe /setactive SCHEME_CURRENT | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to reactivate the original power scheme after winctl test' }
    }
}

function Test-SshSession {
    Write-TestKnownHosts
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $arguments = @(
        '-p', [string]$testPort, '-i', $clientKey,
        '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
        '-o', 'IdentitiesOnly=yes', '-o', 'LogLevel=ERROR',
        '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$knownHosts",
        'macremote@127.0.0.1'
    )
    $identity = @(& $ssh @arguments 'whoami.exe' 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) "authorized SSH failed: $($identity -join ' ')"
    Assert-True ((($identity -join ' ').ToLowerInvariant()).Contains('\macremote')) 'SSH used the wrong account'
    $adminCommand = 'powershell.exe -NoProfile -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"'
    $isAdmin = @(& $ssh @arguments $adminCommand 2>&1)
    Assert-True (($LASTEXITCODE -eq 0) -and ((($isAdmin -join ' ').Trim()) -eq 'True')) 'SSH session is not elevated'
    [void](& $ssh @arguments 'powercfg.exe /getactivescheme' 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) 'remote powercfg failed'

    $badArguments = @($arguments)
    $identityIndex = [Array]::IndexOf($badArguments, $clientKey)
    $badArguments[$identityIndex] = $unauthorizedKey
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 turns a native process' expected stderr into a
        # NativeCommandError when the suite runs with Stop.  This connection is
        # intentionally rejected, so capture only its process exit status.
        $ErrorActionPreference = 'Continue'
        [void](& $ssh @badArguments 'whoami.exe' 2>&1)
        $badKeyExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-True ($badKeyExitCode -ne 0) 'an unauthorized SSH key was accepted'
}

function Initialize-Fixture {
    [void](New-Item -Path $testRoot -ItemType Directory -Force)
    $server = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($server.State -ne 'Installed') {
        $result = Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        Assert-True (-not $result.RestartNeeded) 'OpenSSH fixture setup unexpectedly requires restart'
    }
    $keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    foreach ($path in @($clientKey, $unauthorizedKey)) {
        & $keygen -q -t ed25519 -N '""' -C 'wrb-ci' -f $path
        Assert-True ($LASTEXITCODE -eq 0) "failed to generate test key $path"
    }

    Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType Manual
    if (-not (Test-Path -LiteralPath $sshRoot -PathType Container)) {
        [void](New-Item -Path $sshRoot -ItemType Directory)
    }
    & $keygen -A | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'failed to generate baseline OpenSSH keys'
    foreach ($keyFile in @(Get-ChildItem -LiteralPath $sshRoot -Filter 'ssh_host_*' -File -Force)) {
        Set-TestExactAcl -Path $keyFile.FullName
    }
    foreach ($name in @('ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub')) {
        $path = Join-Path $sshRoot $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    $fixtureConfig = @"
Port 2222
AllowUsers legacy-user
Include __PROGRAMDATA__/ssh/sshd_config.d/*.conf
Match User legacy-user
    PasswordAuthentication yes
"@
    if (-not (Test-Path -LiteralPath $configPath)) { [IO.File]::WriteAllText($configPath, '', [Text.Encoding]::ASCII) }
    Set-TestExactAcl -Path $configPath
    [IO.File]::WriteAllText($configPath, $fixtureConfig, [Text.Encoding]::ASCII)

    $defaultRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if ($null -eq $defaultRule) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server (sshd)' `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    } else {
        $defaultRule | Enable-NetFirewallRule | Out-Null
    }
    Assert-True ($null -eq (Get-LocalUser -Name macremote -ErrorAction SilentlyContinue)) 'fixture started with macremote account'
    Assert-True ($null -eq (Get-NetFirewallRule -Name $managedRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) 'fixture started with managed rule'
    Assert-True (-not (Test-Path -LiteralPath $managedRoot)) 'fixture started with managed state'
    Assert-True (-not (Test-Path -LiteralPath $cleanupRoot)) 'fixture started with managed cleanup state'
}

[void](New-Item -Path $testRoot -ItemType Directory -Force)
try {
    Initialize-Fixture
    $baseline = Get-Baseline
    $publicKey = (Get-Content -LiteralPath "$clientKey.pub" -Raw).Trim()
    $encodedKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($publicKey))
    $installArguments = @(
        '-Mode', 'Install', '-AuthorizedKeyBase64', $encodedKey,
        '-AccountName', 'macremote', '-Port', [string]$testPort,
        '-AllowedRemoteAddress', '127.0.0.1', '-TakeOverExistingSshd'
    )

    if ($Suite -eq 'smoke') {
        $first = Invoke-InstallerRaw -Arguments $installArguments
        Assert-Result $first 0 'installed' 'first install'
        $second = Invoke-InstallerRaw -Arguments $installArguments
        Assert-Result $second 0 'installed' 'idempotent install'
        Assert-True ([bool]$second.Receipt.idempotent) 'second install did not report idempotent=true'

        $config = Get-Content -LiteralPath $configPath -Raw
        Assert-True (([regex]::Matches($config, '# BEGIN WINDOWS-REMOTE-BOOTSTRAP MANAGED CONFIG')).Count -eq 1) 'managed config marker is not unique'
        Assert-True (-not $config.Contains('Match ')) 'managed config preserved a Match block'
        Assert-True (-not $config.Contains('Include ')) 'managed config preserved an Include directive'
        Test-SshSession
        Test-WinctlPowerControl

        $audit = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
        Assert-Result $audit 0 'compliant' 'smoke audit'
        Assert-True (@($audit.Receipt.checks | Where-Object { -not $_.ok }).Count -eq 0) 'a smoke audit check failed'
        $uninstall = Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')
        Assert-Result $uninstall 0 'uninstalled' 'smoke uninstall'
        Assert-BaselineExact -Expected $baseline -Context 'smoke uninstall'
    } else {
        foreach ($stage in @('account-before-sid-journal', 'service')) {
            $failed = Invoke-InstallerRaw -Arguments $installArguments -ThrowAfter $stage
            Assert-Result $failed 1 'failed' "throw recovery $stage"
            Write-Output "throw recovery $stage reported: $([string]$failed.Receipt.error)"
            Assert-BaselineExact -Expected $baseline -Context "throw recovery $stage"
        }

        foreach ($retirementStage in @(
                'cleanup-root-after-freeze',
                'cleanup-root-after-commit',
                'cleanup-tombstone-partial'
            )) {
            # Combine a normal injected forward failure with a hard kill during
            # rollback. The next process must recognize either the frozen root
            # or committed tombstone and finish cleanup without guessing.
            $crashedRetirement = Invoke-InstallerRaw -Arguments $installArguments `
                -ThrowAfter 'account-before-sid-journal' -CrashAfter $retirementStage
            Assert-True (($crashedRetirement.ExitCode -ne 0) -and
                (-not $crashedRetirement.ReceiptExists)) `
                "$retirementStage hard crash did not terminate cleanup"
            $retirementRetry = Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')
            Assert-Result $retirementRetry 0 'already-uninstalled' "$retirementStage retry"
            Assert-BaselineExact -Expected $baseline -Context "$retirementStage recovery"
        }

        $crashedAccount = Invoke-InstallerRaw -Arguments $installArguments -CrashAfter 'account-before-sid-journal'
        Assert-True ($crashedAccount.ExitCode -ne 0) 'account hard crash unexpectedly succeeded'
        Assert-True (-not $crashedAccount.ReceiptExists) 'account hard crash wrote a receipt'
        Assert-True (Test-Path -LiteralPath (Join-Path $managedRoot 'transaction.json')) 'account hard crash lost its transaction'
        [IO.File]::AppendAllText($configPath, "# post-crash sentinel`r`n", [Text.Encoding]::ASCII)
        $sentinelHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
        New-NetFirewallRule -Name $managedRuleName -DisplayName 'post-crash sentinel' `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort 65530 -RemoteAddress 127.0.0.1 | Out-Null
        $rolledBack = Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')
        Assert-Result $rolledBack 0 'rolled-back-incomplete-install' 'phase-bounded rollback'
        Assert-Equal $sentinelHash (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash 'rollback overwrote a post-crash config'
        Assert-True ($null -ne (Get-NetFirewallRule -Name $managedRuleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) 'rollback deleted a post-crash firewall rule'
        Get-NetFirewallRule -Name $managedRuleName -PolicyStore PersistentStore | Remove-NetFirewallRule
        Set-PathSnapshot -Path $configPath -Snapshot $baseline.config
        Assert-BaselineExact -Expected $baseline -Context 'phase-bounded rollback cleanup'

        $crashedService = Invoke-InstallerRaw -Arguments $installArguments -CrashAfter 'service'
        Assert-True (($crashedService.ExitCode -ne 0) -and (-not $crashedService.ReceiptExists)) 'service hard crash did not terminate cleanly'
        $retryService = Invoke-InstallerRaw -Arguments $installArguments
        Assert-Result $retryService 0 'installed' 'service-crash retry'
        Test-SshSession
        Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')) 0 'compliant' 'service-crash audit'
        Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) 0 'uninstalled' 'service-crash uninstall'
        Assert-BaselineExact -Expected $baseline -Context 'service-crash recovery'

        $crashedCommit = Invoke-InstallerRaw -Arguments $installArguments -CrashAfter 'state-commit'
        Assert-True (($crashedCommit.ExitCode -ne 0) -and (-not $crashedCommit.ReceiptExists)) 'state commit hard crash did not terminate cleanly'
        Assert-True ((Test-Path -LiteralPath (Join-Path $managedRoot 'state.json')) -and
            (Test-Path -LiteralPath (Join-Path $managedRoot 'transaction.json'))) 'state commit crash did not preserve both records'
        $retryCommit = Invoke-InstallerRaw -Arguments $installArguments
        Assert-Result $retryCommit 0 'installed' 'state-commit retry'
        Assert-True ([bool]$retryCommit.Receipt.idempotent) 'state-commit retry was not recognized as committed'

        $configSnapshot = Get-PathSnapshot -Path $configPath
        [IO.File]::AppendAllText($configPath, "# audit drift`r`n", [Text.Encoding]::ASCII)
        $configDrift = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
        Assert-Result $configDrift 2 'drift' 'config tamper audit'
        Assert-AuditCheck $configDrift.Receipt 'sshd-config-hash-and-syntax' $false
        Assert-Result (Invoke-InstallerRaw -Arguments $installArguments) 1 'failed' 'install over config drift'
        Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) 1 'failed' 'uninstall over config drift'
        Set-PathSnapshot -Path $configPath -Snapshot $configSnapshot

        $state = Get-Content -LiteralPath (Join-Path $managedRoot 'state.json') -Raw | ConvertFrom-Json
        $privateHostKey = Join-Path $sshRoot 'ssh_host_ed25519_key'
        $privateAcl = Get-Acl -LiteralPath $privateHostKey
        $usersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $readRule = New-Object Security.AccessControl.FileSystemAccessRule($usersSid, 'Read', 'Allow')
        [void]$privateAcl.AddAccessRule($readRule)
        Set-Acl -LiteralPath $privateHostKey -AclObject $privateAcl
        $aclDrift = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
        Assert-Result $aclDrift 2 'drift' 'host-key ACL tamper audit'
        Assert-AuditCheck $aclDrift.Receipt 'ssh-host-key-security' $false
        $expectedKey = @($state.generatedHostKeyFiles | Where-Object { [string]$_.name -eq 'ssh_host_ed25519_key' })[0]
        $restoreAcl = Get-Acl -LiteralPath $privateHostKey
        $restoreAcl.SetSecurityDescriptorSddlForm([string]$expectedKey.sddl)
        Set-Acl -LiteralPath $privateHostKey -AclObject $restoreAcl

        Set-NetFirewallRule -Name $managedRuleName -PolicyStore PersistentStore -RemoteAddress Any
        $firewallDrift = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
        Assert-Result $firewallDrift 2 'drift' 'firewall tamper audit'
        Assert-AuditCheck $firewallDrift.Receipt 'firewall-exact-filters' $false
        Set-NetFirewallRule -Name $managedRuleName -PolicyStore PersistentStore -RemoteAddress 127.0.0.1

        $hostKeyBytes = [IO.File]::ReadAllBytes($privateHostKey)
        $alternateKey = Join-Path $testRoot 'alternate-host-key'
        & (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe') -q -t ed25519 -N '""' -f $alternateKey
        Assert-True ($LASTEXITCODE -eq 0) 'failed to generate alternate host key'
        [IO.File]::WriteAllBytes($privateHostKey, [IO.File]::ReadAllBytes($alternateKey))
        $fingerprintDrift = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
        Assert-Result $fingerprintDrift 2 'drift' 'host-key fingerprint tamper audit'
        Assert-AuditCheck $fingerprintDrift.Receipt 'host-key-fingerprint' $false
        [IO.File]::WriteAllBytes($privateHostKey, $hostKeyBytes)

        $finalAudit = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
        Assert-Result $finalAudit 0 'compliant' 'post-tamper repaired audit'
        Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) 0 'uninstalled' 'recovery-suite uninstall'
        Assert-BaselineExact -Expected $baseline -Context 'recovery suite'

        # Exercise the stronger ownership contract used when ProgramData\ssh did
        # not exist before installation. Moving the fixture within the same
        # volume preserves its complete NTFS metadata for exact restoration.
        $sshFixtureBackup = Join-Path $testRoot 'ssh-existing-fixture'
        $sshTestLeftover = Join-Path $testRoot 'ssh-test-leftover'
        $unknownChild = Join-Path $sshRoot 'operator-data.txt'
        Assert-True (Test-Path -LiteralPath $sshRoot -PathType Container) `
            'the existing SSH fixture is missing before absent-directory tests'
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        [IO.Directory]::Move($sshRoot, $sshFixtureBackup)
        $absentSshBaseline = Get-Baseline
        Assert-True (-not [bool]$absentSshBaseline.sshDirectory.existed) `
            'the absent-directory fixture still has ProgramData\ssh'
        try {
            $freshInstall = Invoke-InstallerRaw -Arguments $installArguments
            Assert-Result $freshInstall 0 'installed' 'absent-directory install'
            Test-SshSession
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')) `
                0 'compliant' 'absent-directory audit'
            $newDirectoryRetirement = Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall') `
                -CrashAfter 'cleanup-root-after-freeze'
            Assert-True (($newDirectoryRetirement.ExitCode -ne 0) -and
                (-not $newDirectoryRetirement.ReceiptExists)) `
                'new-directory cleanup freeze did not hard crash'
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) `
                0 'already-uninstalled' 'new-directory frozen cleanup retry'
            Assert-BaselineExact -Expected $absentSshBaseline -Context 'absent-directory uninstall'

            # This hook is intentionally inside Establish-SshDirectoryBoundary,
            # after the protected candidate exists and immediately before its
            # atomic publication as ProgramData\ssh.
            $crashedBeforeRetry = Invoke-InstallerRaw -Arguments $installArguments `
                -CrashAfter 'ssh-directory-before-publish'
            Assert-True (($crashedBeforeRetry.ExitCode -ne 0) -and
                (-not $crashedBeforeRetry.ReceiptExists)) `
                'pre-publish directory hard crash did not terminate cleanly'
            $crashTransactionPath = Join-Path $managedRoot 'transaction.json'
            Assert-True (Test-Path -LiteralPath $crashTransactionPath -PathType Leaf) `
                'pre-publish directory hard crash lost its transaction'
            $crashTransaction = Get-Content -LiteralPath $crashTransactionPath -Raw | ConvertFrom-Json
            Assert-Equal 'ssh-directory' ([string]$crashTransaction.phase) `
                'pre-publish directory crash transaction phase'
            $directoryCandidate = Join-Path $managedRoot `
                "ssh-directory.$([string]$crashTransaction.transactionId).tmp"
            Assert-True (Test-Path -LiteralPath $directoryCandidate -PathType Container) `
                'pre-publish directory crash did not preserve the protected candidate'
            Assert-True (-not (Test-Path -LiteralPath $sshRoot)) `
                'pre-publish directory crash published ProgramData\ssh prematurely'

            $retryAfterDirectoryCrash = Invoke-InstallerRaw -Arguments $installArguments
            Assert-Result $retryAfterDirectoryCrash 0 'installed' 'pre-publish directory crash retry'
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')) `
                0 'compliant' 'pre-publish directory crash retry audit'
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) `
                0 'uninstalled' 'pre-publish directory crash retry uninstall'
            Assert-BaselineExact -Expected $absentSshBaseline `
                -Context 'pre-publish directory crash retry cleanup'

            $crashedBeforeUninstall = Invoke-InstallerRaw -Arguments $installArguments `
                -CrashAfter 'ssh-directory-before-publish'
            Assert-True (($crashedBeforeUninstall.ExitCode -ne 0) -and
                (-not $crashedBeforeUninstall.ReceiptExists)) `
                'second pre-publish directory hard crash did not terminate cleanly'
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) `
                0 'rolled-back-incomplete-install' 'pre-publish directory crash direct uninstall'
            Assert-BaselineExact -Expected $absentSshBaseline `
                -Context 'pre-publish directory crash direct cleanup'

            Assert-Result (Invoke-InstallerRaw -Arguments $installArguments) `
                0 'installed' 'new-directory ownership install'
            [IO.File]::WriteAllText($unknownChild, 'operator-owned sentinel', [Text.Encoding]::UTF8)
            $unknownChildHash = (Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash

            $unknownAudit = Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')
            Assert-Result $unknownAudit 2 'drift' 'unknown SSH child audit'
            Assert-True (Test-Path -LiteralPath $unknownChild -PathType Leaf) `
                'audit deleted an unknown SSH child'
            Assert-Equal $unknownChildHash `
                (Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash `
                'audit changed an unknown SSH child'

            $unknownUninstall = Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')
            Assert-Result $unknownUninstall 1 'failed' 'uninstall with unknown SSH child'
            Assert-True (Test-Path -LiteralPath $unknownChild -PathType Leaf) `
                'refused uninstall deleted or relocated an unknown SSH child'
            Assert-Equal $unknownChildHash `
                (Get-FileHash -LiteralPath $unknownChild -Algorithm SHA256).Hash `
                'refused uninstall changed an unknown SSH child'

            Remove-Item -LiteralPath $unknownChild -Force
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')) `
                0 'compliant' 'unknown SSH child repair audit'
            Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) `
                0 'uninstalled' 'unknown SSH child repair uninstall'
            Assert-BaselineExact -Expected $absentSshBaseline `
                -Context 'new-directory ownership cleanup'
        } finally {
            # Preserve runner hygiene even when an assertion exposes a recovery
            # bug: remove only our sentinel, ask the installer to clean its own
            # state, then put the untouched original fixture back in place.
            Remove-Item -LiteralPath $unknownChild -Force -ErrorAction SilentlyContinue
            try {
                if ((Test-Path -LiteralPath (Join-Path $managedRoot 'state.json')) -or
                    (Test-Path -LiteralPath (Join-Path $managedRoot 'transaction.json'))) {
                    [void](Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall'))
                }
            } catch {
                Write-Warning "Absent-directory managed cleanup failed: $($_.Exception.Message)"
            }
            Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $sshRoot) {
                Assert-True (-not (Test-Path -LiteralPath $sshTestLeftover)) `
                    'the absent-directory cleanup quarantine path already exists'
                [IO.Directory]::Move($sshRoot, $sshTestLeftover)
            }
            Assert-True (Test-Path -LiteralPath $sshFixtureBackup -PathType Container) `
                'the saved existing SSH fixture disappeared'
            [IO.Directory]::Move($sshFixtureBackup, $sshRoot)
            Set-Service -Name sshd -StartupType ([string]$baseline.service.startType)
            if ([string]$baseline.service.status -eq 'Running') {
                Start-Service -Name sshd
            } else {
                Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
            }
        }
        Assert-BaselineExact -Expected $baseline -Context 'restored existing SSH fixture'

        # Last, turn the ephemeral runner into a genuinely dependency-free
        # baseline. This proves the installer—not the fixture—adds OpenSSH, and
        # that exact uninstall removes only the capability it claimed.
        Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
        $removeCapability = Remove-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        $removedCapability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        Assert-True ((-not $removeCapability.RestartNeeded) -and
            ([string]$removedCapability.State -eq 'NotPresent')) `
            "runner could not reach a restart-free NotPresent dependency baseline: $($removedCapability.State)"
        Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore `
            -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
        if (Test-Path -LiteralPath $sshRoot) {
            $dependencySshBackup = Join-Path $testRoot 'dependency-ssh-leftover'
            [IO.Directory]::Move($sshRoot, $dependencySshBackup)
        }
        $dependencyBaseline = Get-Baseline
        Assert-Equal 'NotPresent' ([string]$dependencyBaseline.capability) 'dependency baseline capability'
        Assert-True (-not [bool]$dependencyBaseline.service.existed) 'dependency baseline still has sshd'
        Assert-True (-not [bool]$dependencyBaseline.sshDirectory.existed) 'dependency baseline still has ProgramData\ssh'

        $dependencyInstall = Invoke-InstallerRaw -Arguments $installArguments
        Assert-Result $dependencyInstall 0 'installed' 'automatic OpenSSH dependency install'
        Assert-True ([bool]$dependencyInstall.Receipt.openSsh.installedByThisTool) `
            'automatic dependency install was not recorded as installer-owned'
        Test-SshSession
        Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Audit')) `
            0 'compliant' 'automatic dependency audit'
        Assert-Result (Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall')) `
            0 'uninstalled' 'automatic dependency uninstall'
        Assert-BaselineExact -Expected $dependencyBaseline -Context 'automatic dependency uninstall'
    }

    Write-Output "Windows $Suite tests passed."
} finally {
    try {
        if ((Test-Path -LiteralPath (Join-Path $managedRoot 'state.json')) -or
            (Test-Path -LiteralPath (Join-Path $managedRoot 'transaction.json'))) {
            [void](Invoke-InstallerRaw -Arguments @('-Mode', 'Uninstall'))
        }
    } catch {
        Write-Warning "Test cleanup could not run the managed uninstall: $($_.Exception.Message)"
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
