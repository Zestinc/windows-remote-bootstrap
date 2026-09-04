#Requires -Version 5.1

param(
    [ValidateSet('smoke', 'recovery')]
    [string]$Suite = 'smoke'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot 'install.ps1'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sshRoot = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $sshRoot 'sshd_config'
$managedRoot = Join-Path $env:ProgramData 'WindowsRemoteBootstrap'
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
    return @(Get-ChildItem -LiteralPath $sshRoot -Filter 'ssh_host_*' -Force -ErrorAction SilentlyContinue |
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
    $service = Get-Service -Name sshd
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'"
    return [ordered]@{
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

function Test-SshSession {
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $arguments = @(
        '-p', [string]$testPort, '-i', $clientKey,
        '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
        '-o', 'IdentitiesOnly=yes', '-o', 'LogLevel=ERROR',
        '-o', 'StrictHostKeyChecking=no', '-o', "UserKnownHostsFile=$knownHosts",
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
    [void](& $ssh @badArguments 'whoami.exe' 2>&1)
    Assert-True ($LASTEXITCODE -ne 0) 'an unauthorized SSH key was accepted'
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
