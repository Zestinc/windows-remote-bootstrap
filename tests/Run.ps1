#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repoRoot 'install.ps1'
$testRoot = Join-Path $env:TEMP ("WindowsRemoteBootstrapTests-$([Guid]::NewGuid().ToString('N'))")
$keyPath = Join-Path $testRoot 'id_ed25519'
$knownHosts = Join-Path $testRoot 'known_hosts'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Invoke-Installer {
    param([string[]]$Arguments)
    & $installer @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Installer failed with exit code $LASTEXITCODE"
    }
}

[void](New-Item -Path $testRoot -ItemType Directory -Force)
try {
    $sshKeygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    if (-not (Test-Path -LiteralPath $sshKeygen)) {
        $client = Get-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0'
        if ($client.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0' | Out-Null
        }
    }
    & $sshKeygen -q -t ed25519 -N '' -C 'ci-test' -f $keyPath
    if ($LASTEXITCODE -ne 0) { throw 'Unable to generate CI SSH key.' }

    $publicKey = (Get-Content -LiteralPath "$keyPath.pub" -Raw).Trim()
    $encodedKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($publicKey))
    $installArguments = @(
        '-Mode', 'Install',
        '-AuthorizedKeyBase64', $encodedKey,
        '-AccountName', 'macremote',
        '-AllowedRemoteAddress', '127.0.0.1',
        '-TakeOverExistingSshd'
    )

    Invoke-Installer -Arguments $installArguments
    Invoke-Installer -Arguments $installArguments

    $config = Get-Content -LiteralPath "$env:ProgramData\ssh\sshd_config" -Raw
    Assert-True (([regex]::Matches($config, '# BEGIN WINDOWS-REMOTE-BOOTSTRAP GLOBAL')).Count -eq 1) 'global marker must be unique after a second install'
    Assert-True (([regex]::Matches($config, '# BEGIN WINDOWS-REMOTE-BOOTSTRAP USER')).Count -eq 1) 'user marker must be unique after a second install'

    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $sshArguments = @(
        '-p', '22',
        '-i', $keyPath,
        '-o', 'BatchMode=yes',
        '-o', 'PasswordAuthentication=no',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=no',
        '-o', "UserKnownHostsFile=$knownHosts",
        'macremote@127.0.0.1'
    )
    $identity = & $ssh @sshArguments 'whoami.exe' 2>&1
    Assert-True ($LASTEXITCODE -eq 0) "key-only localhost SSH failed: $($identity -join ' ')"
    Assert-True ((($identity -join ' ').ToLowerInvariant()).Contains('\macremote')) 'SSH session used the wrong account'

    $isAdminCommand = 'powershell.exe -NoProfile -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"'
    $isAdmin = & $ssh @sshArguments $isAdminCommand 2>&1
    Assert-True ($LASTEXITCODE -eq 0) "remote administrator check failed: $($isAdmin -join ' ')"
    Assert-True ((($isAdmin -join ' ').Trim()) -eq 'True') 'SSH account did not receive an elevated administrator token'

    $power = & $ssh @sshArguments 'powercfg.exe /getactivescheme' 2>&1
    Assert-True ($LASTEXITCODE -eq 0) "remote powercfg failed: $($power -join ' ')"

    & $installer -Mode Audit
    Assert-True ($LASTEXITCODE -eq 0) 'audit did not report compliant after install'

    & $installer -Mode Uninstall
    Assert-True ($LASTEXITCODE -eq 0) 'uninstall failed'
    Assert-True ($null -eq (Get-LocalUser -Name macremote -ErrorAction SilentlyContinue)) 'managed account remains after uninstall'
    Assert-True ($null -eq (Get-NetFirewallRule -Name 'WindowsRemoteBootstrap-SSH-In' -ErrorAction SilentlyContinue)) 'managed firewall rule remains after uninstall'

    Write-Output 'All native Windows tests passed.'
} finally {
    if (Test-Path -LiteralPath 'C:\ProgramData\WindowsRemoteBootstrap\state.json') {
        & $installer -Mode Uninstall -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
