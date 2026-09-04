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

    [switch]$TakeOverExistingSshd
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ProgramName = 'WindowsRemoteBootstrap'
$script:InstallerVersion = '1.0.0'
$script:CapabilityName = 'OpenSSH.Server~~~~0.0.1.0'
$script:FirewallRuleName = 'WindowsRemoteBootstrap-SSH-In'
$script:ProgramDataPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$script:SystemPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$script:RootPath = Join-Path $script:ProgramDataPath $script:ProgramName
$script:CleanupRootPath = Join-Path $script:ProgramDataPath (".$($script:ProgramName).cleanup")
$script:StatePath = Join-Path $script:RootPath 'state.json'
$script:TransactionPath = Join-Path $script:RootPath 'transaction.json'
$script:KeyPath = Join-Path $script:RootPath 'authorized_keys'
$script:SshPath = Join-Path $script:ProgramDataPath 'ssh'
$script:SshConfigPath = Join-Path $script:SshPath 'sshd_config'
$script:SshLogsPath = Join-Path $script:SshPath 'logs'
$script:SshOwnershipMarkerName = '.WindowsRemoteBootstrap.owner'
$script:GlobalBegin = '# BEGIN WINDOWS-REMOTE-BOOTSTRAP MANAGED CONFIG'
$script:GlobalEnd = '# END WINDOWS-REMOTE-BOOTSTRAP MANAGED CONFIG'
$script:ManagedHostKeyTypes = @('dsa', 'rsa', 'ecdsa', 'ed25519')
$script:LastSecurityBoundaryError = ''
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:InstallPhases = @(
    'created',
    'ssh-directory',
    'capability',
    'service-stop',
    'default-firewall',
    'account',
    'authorized-keys',
    'host-key-staging',
    'host-keys',
    'config',
    'firewall',
    'service',
    'state-commit'
)
$script:CleanupPhases = @(
    'none',
    'service-stop',
    'firewall',
    'account',
    'capability',
    'ssh-boundary',
    'config',
    'host-keys',
    'default-firewall',
    'service-restore',
    'root-retire'
)

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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
    # A deterministic sibling is safe to recover: callers do not mutate the
    # machine until this atomic write returns, so an orphaned .next file can
    # always be discarded while the previous committed record remains truth.
    $temporaryPath = "$Path.next"
    if (Test-Path -LiteralPath $temporaryPath) {
        if ((-not (Test-Path -LiteralPath $temporaryPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $temporaryPath) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $temporaryPath))) {
            throw "Protected JSON staging path is not owned by this installer: $temporaryPath"
        }
        Remove-Item -LiteralPath $temporaryPath -Force
    }
    try {
        [IO.File]::WriteAllText($temporaryPath, $json, $script:Utf8NoBom)
        Protect-ManagedFile -Path $temporaryPath
        if (Test-Path -LiteralPath $Path) {
            if ((-not (Test-Path -LiteralPath $Path -PathType Leaf)) -or
                (Test-ReparsePoint -Path $Path) -or
                (-not (Test-ManagedFileAcl -Path $Path))) {
                throw "Protected JSON destination changed identity: $Path"
            }
            # PowerShell converts a bare $null passed to a .NET string
            # parameter into String.Empty. File.Replace then rejects that as
            # an illegal backup path. NullString.Value preserves a real CLR
            # null, which the File.Replace contract explicitly supports.
            [IO.File]::Replace(
                $temporaryPath,
                $Path,
                [System.Management.Automation.Language.NullString]::Value
            )
        } else {
            [IO.File]::Move($temporaryPath, $Path)
        }
        if (-not (Test-ManagedFileAcl -Path $Path)) {
            throw "Protected state ACL verification failed: $Path"
        }
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Remove-OrphanedProtectedJsonStaging {
    if (-not (Test-Path -LiteralPath $script:RootPath)) { return }
    Assert-TrustedProgramPath -Path $script:RootPath -Directory $true
    foreach ($path in @("$($script:StatePath).next", "$($script:TransactionPath).next")) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if ((-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
            (Test-ReparsePoint -Path $path) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $path))) {
            throw "An orphaned protected JSON staging path changed identity: $path"
        }
        Remove-Item -LiteralPath $path -Force
    }
}

function Write-PublicReceipt {
    param([Parameter(Mandatory = $true)]$Receipt)

    # An elevated process must not write a fixed path in a user-writable
    # namespace. Emit one prefixed record for launchers and tests to capture.
    Write-Output ('WINDOWS_REMOTE_BOOTSTRAP_RECEIPT_JSON=' +
        ($Receipt | ConvertTo-Json -Depth 10 -Compress))
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

    function New-ExactAclObject {
        param([Parameter(Mandatory = $true)][string]$TargetPath)

        $result = Get-Acl -LiteralPath $TargetPath
        $result.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($result.Access)) {
            [void]$result.RemoveAccessRuleSpecific($rule)
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
            [void]$result.AddAccessRule($accessRule)
        }
        $result.SetOwner((New-Object Security.Principal.SecurityIdentifier($OwnerSid)))
        return $result
    }

    $acl = New-ExactAclObject -TargetPath $Path
    try {
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        # Some in-box OpenSSH files are readable by Administrators but reserve
        # WRITE_DAC for SYSTEM. The already-elevated installer takes ownership
        # explicitly, then replaces the complete DACL from scratch.
        $takeown = Join-Path $script:SystemPath 'takeown.exe'
        $takeownOutput = @(& $takeown /F $Path /A 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to take administrative ownership of '$Path': $($takeownOutput -join ' ')"
        }
        $acl = New-ExactAclObject -TargetPath $Path
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
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

function New-ManagedDirectoryProtectedAtCreation {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        throw "Refusing to claim an existing managed directory: $Path"
    }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    $security.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    [void][IO.Directory]::CreateDirectory($Path, $security)
    if ((-not (Test-Path -LiteralPath $Path -PathType Container)) -or
        (Test-ReparsePoint -Path $Path) -or
        (-not (Test-ManagedDirectoryAcl -Path $Path))) {
        throw "A newly created managed directory failed its exact ACL/type check: $Path"
    }
}

function Assert-ManagedCleanupRoot {
    param([bool]$RequireEmpty = $false)

    if ((-not (Test-Path -LiteralPath $script:CleanupRootPath -PathType Container)) -or
        (Test-ReparsePoint -Path $script:CleanupRootPath) -or
        (-not (Test-ManagedDirectoryAcl -Path $script:CleanupRootPath)) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:CleanupRootPath))) {
        throw 'The protected cleanup directory changed identity or ACL.'
    }
    if ($RequireEmpty -and
        (@(Get-ChildItem -LiteralPath $script:CleanupRootPath -Force -ErrorAction Stop).Count -ne 0)) {
        throw 'The protected cleanup directory is not empty.'
    }
}

function Initialize-ManagedCleanupRoot {
    if (Test-Path -LiteralPath $script:CleanupRootPath) {
        Assert-ManagedCleanupRoot -RequireEmpty $true
        return
    }
    New-ManagedDirectoryProtectedAtCreation -Path $script:CleanupRootPath
    Assert-ManagedCleanupRoot -RequireEmpty $true
}

function Remove-UnjournaledInstallScaffolding {
    if (-not (Test-Path -LiteralPath $script:RootPath)) { return $false }

    Assert-TrustedProgramPath -Path $script:RootPath -Directory $true
    $children = @(Get-ChildItem -LiteralPath $script:RootPath -Force -ErrorAction Stop)
    if ($children.Count -ne 0) {
        throw "The managed root contains data without a trusted state or transaction; refusing to delete it."
    }
    Assert-ManagedCleanupRoot -RequireEmpty $true

    # Both deletes are deliberately non-recursive. These exact, empty,
    # administrator-only directories are the only possible artifacts between
    # publishing the root boundary and publishing the first transaction.
    [IO.Directory]::Delete($script:RootPath, $false)
    Assert-ManagedCleanupRoot -RequireEmpty $true
    [IO.Directory]::Delete($script:CleanupRootPath, $false)
    return $true
}

function ConvertTo-SidValue {
    param([Parameter(Mandatory = $true)]$IdentityReference)

    try {
        if ($IdentityReference -is [Security.Principal.SecurityIdentifier]) {
            return [string]$IdentityReference.Value
        }
        $identityText = [string]$IdentityReference
        if ($identityText.StartsWith('S-1-')) { return $identityText }
        $account = New-Object Security.Principal.NTAccount($identityText)
        return [string]$account.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Test-TrustedAdministrativeSid {
    param([Parameter(Mandatory = $true)][string]$Sid)

    $alwaysTrusted = @(
        'S-1-5-18',       # LocalSystem
        'S-1-5-32-544',   # Builtin Administrators
        # NT SERVICE\TrustedInstaller
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    if ($alwaysTrusted -contains $Sid) { return $true }

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($Sid -eq $currentSid) { return $true }

    try {
        $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
        return $null -ne (Get-LocalGroupMember -Group $administrators -ErrorAction Stop |
            Where-Object { [string]$_.SID.Value -eq $Sid } |
            Select-Object -First 1)
    } catch {
        return $false
    }
}

function Test-FixedTrustedSystemSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    return $Sid -in @(
        'S-1-5-18',       # LocalSystem
        'S-1-5-32-544',   # Builtin Administrators
        # NT SERVICE\TrustedInstaller
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
}

function Test-TrustedSidForSecurityBoundary {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [bool]$FixedTrustedOnly = $false
    )

    if ($FixedTrustedOnly) {
        return Test-FixedTrustedSystemSid -Sid $Sid
    }
    return Test-TrustedAdministrativeSid -Sid $Sid
}

function ConvertTo-UnsignedAccessMask {
    param([Parameter(Mandatory = $true)][int]$AccessMask)

    # AccessMask is exposed as a signed Int32 in Windows PowerShell 5.1.
    # Promote first, then add 2^32 for a negative value. This preserves its
    # raw bits without relying on PowerShell 5.1's ambiguous BitConverter
    # overload binding.
    $result = [int64]$AccessMask
    if ($result -lt 0) { $result += [int64]4294967296 }
    return $result
}

function Test-RawFileSystemAllowAces {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][int64]$UnsafeMask,
        [bool]$FixedTrustedOnly = $false
    )

    if (($Descriptor.ControlFlags -band
            [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or
        ($null -eq $Descriptor.DiscretionaryAcl)) {
        $script:LastSecurityBoundaryError = 'security descriptor has no present, non-null DACL'
        return $false
    }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if (($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -ne 0) {
            continue
        }
        if (($ace -isnot [Security.AccessControl.CommonAce]) -or $ace.IsCallback) {
            $script:LastSecurityBoundaryError = "unsupported or callback ACE: $($ace.GetType().FullName)"
            return $false
        }
        if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) {
            continue
        }
        if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) {
            $script:LastSecurityBoundaryError = "unsupported ACE qualifier: $($ace.AceQualifier)"
            return $false
        }
        $sid = $null
        try { $sid = [string]$ace.SecurityIdentifier.Value } catch {
            $script:LastSecurityBoundaryError = 'an ACE has no parseable SID'
            return $false
        }
        if ([string]::IsNullOrWhiteSpace($sid)) {
            $script:LastSecurityBoundaryError = 'an ACE has an empty SID'
            return $false
        }
        if (Test-TrustedSidForSecurityBoundary -Sid $sid -FixedTrustedOnly $FixedTrustedOnly) {
            continue
        }
        $mask = ConvertTo-UnsignedAccessMask -AccessMask ([int]$ace.AccessMask)
        if (($mask -band $UnsafeMask) -ne 0) {
            $script:LastSecurityBoundaryError = ('untrusted allow ACE SID={0} mask=0x{1:x8}' -f $sid, $mask)
            return $false
        }
    }
    return $true
}

function Test-PathProtectedFromUntrustedMutation {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$DenyUntrustedRead = $false,
        [bool]$FixedTrustedOnly = $false
    )

    if ((-not (Test-Path -LiteralPath $Path)) -or (Test-ReparsePoint -Path $Path)) {
        return $false
    }
    try {
        $script:LastSecurityBoundaryError = ''
        $acl = Get-Acl -LiteralPath $Path
        $raw = New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList (,$acl.Sddl)
        $ownerSid = ConvertTo-SidValue -IdentityReference $acl.Owner
        if ([string]::IsNullOrWhiteSpace($ownerSid) -or
            (-not (Test-TrustedSidForSecurityBoundary -Sid $ownerSid `
                    -FixedTrustedOnly $FixedTrustedOnly))) {
            $script:LastSecurityBoundaryError = "untrusted or unreadable owner SID on '$Path': '$ownerSid'"
            return $false
        }

        # Untrusted principals may read/execute ordinary protected inputs, but
        # every write/delete/security/future bit is rejected. Private host
        # keys additionally reject ReadData and GENERIC_READ.
        $unsafeMask = if ($DenyUntrustedRead) {
            [int64]3756916567 # 0xdfedff57 = ~0x201200a8
        } else {
            [int64]1609432918 # 0x5fedff56 = ~0xa01200a9
        }
        return Test-RawFileSystemAllowAces -Descriptor $raw -UnsafeMask $unsafeMask `
            -FixedTrustedOnly $FixedTrustedOnly
    } catch {
        $script:LastSecurityBoundaryError = "ACL query failed for '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Test-ParentProtectsChildFromUntrustedReplacement {
    param(
        [Parameter(Mandatory = $true)][string]$ChildPath,
        [bool]$FixedTrustedOnly = $false
    )

    $parent = Split-Path -Parent $ChildPath
    if ((-not (Test-Path -LiteralPath $parent -PathType Container)) -or
        (Test-ReparsePoint -Path $parent)) {
        return $false
    }
    try {
        $script:LastSecurityBoundaryError = ''
        $acl = Get-Acl -LiteralPath $parent
        $raw = New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList (,$acl.Sddl)
        $ownerSid = ConvertTo-SidValue -IdentityReference $acl.Owner
        if ([string]::IsNullOrWhiteSpace($ownerSid) -or
            (-not (Test-TrustedSidForSecurityBoundary -Sid $ownerSid `
                    -FixedTrustedOnly $FixedTrustedOnly))) {
            $script:LastSecurityBoundaryError = "untrusted or unreadable owner SID on '$parent': '$ownerSid'"
            return $false
        }
        # A parent may allow an untrusted user to create unrelated siblings;
        # it must not allow deleting/replacing this child or rewriting the
        # parent's security. Include generic write/all explicitly.
        $unsafeReplacementMask = [int64]1343029312 # 0x500d0040
        return Test-RawFileSystemAllowAces -Descriptor $raw `
            -UnsafeMask $unsafeReplacementMask -FixedTrustedOnly $FixedTrustedOnly
    } catch {
        $script:LastSecurityBoundaryError = "ACL query failed for '$parent': $($_.Exception.Message)"
        return $false
    }
}

function Test-ProtectedPathIdentityChain {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        while ($null -ne $current.Parent) {
            $acl = Get-Acl -LiteralPath $current.FullName -ErrorAction Stop
            $raw = New-Object -TypeName Security.AccessControl.RawSecurityDescriptor `
                -ArgumentList (,$acl.Sddl)
            $ownerSid = ConvertTo-SidValue -IdentityReference $acl.Owner
            if ([string]::IsNullOrWhiteSpace($ownerSid) -or
                (-not (Test-FixedTrustedSystemSid -Sid $ownerSid))) {
                return $false
            }
            # The object itself cannot be deleted or have ownership/DACL
            # rewritten; generic write/all also fail closed.
            if (-not (Test-RawFileSystemAllowAces -Descriptor $raw `
                    -UnsafeMask ([int64]1343029248) -FixedTrustedOnly $true)) { # 0x500d0000
                return $false
            }
            if (-not (Test-ParentProtectsChildFromUntrustedReplacement `
                    -ChildPath $current.FullName -FixedTrustedOnly $true)) {
                return $false
            }
            $current = $current.Parent
        }
        return $true
    } catch {
        return $false
    }
}

function Test-SshLogsDirectoryProtected {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [bool]$RequireEmpty = $false,
        [bool]$ManagedExact = $false
    )

    if ((-not (Test-Path -LiteralPath $Path -PathType Container)) -or
        (Test-ReparsePoint -Path $Path) -or
        (-not (Test-PathProtectedFromUntrustedMutation -Path $Path)) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $Path))) {
        return $false
    }
    if ($ManagedExact -and (-not (Test-ManagedDirectoryAcl -Path $Path))) { return $false }
    if ($RequireEmpty) {
        try {
            return @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop).Count -eq 0
        } catch {
            return $false
        }
    }
    return $true
}

function Assert-SafeExistingSshBaseline {
    if (-not (Test-Path -LiteralPath $script:SshPath)) { return }
    if ((-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) -or
        (Test-ReparsePoint -Path $script:SshPath) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:SshPath)) -or
        (-not (Test-PathProtectedFromUntrustedMutation -Path $script:SshPath))) {
        throw 'The existing OpenSSH data directory is writable or owned by an untrusted principal.'
    }
    $markerPath = Join-Path $script:SshPath $script:SshOwnershipMarkerName
    if (Test-Path -LiteralPath $markerPath) {
        throw 'The reserved OpenSSH ownership marker already exists without trusted installer state.'
    }
    if (-not (Test-SshLogsDirectoryProtected -Path $script:SshLogsPath)) {
        throw 'The existing OpenSSH logs directory is missing, writable, or not a regular protected directory.'
    }
    $protectedInputs = @()
    if (Test-Path -LiteralPath $script:SshConfigPath) {
        if ((-not (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $script:SshConfigPath)) {
            throw 'The existing sshd_config is not a regular file.'
        }
        $protectedInputs += Get-Item -LiteralPath $script:SshConfigPath -Force
    }
    $hostKeyInputs = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*' -Force -ErrorAction Stop)
    foreach ($hostKeyInput in $hostKeyInputs) {
        if ($hostKeyInput.PSIsContainer) {
            throw "An OpenSSH host-key-shaped path is not a regular file: $($hostKeyInput.FullName)"
        }
    }
    $protectedInputs += $hostKeyInputs
    foreach ($item in $protectedInputs) {
        $privateHostKey = ([string]$item.Name -match '^ssh_host_[A-Za-z0-9._-]+_key$')
        if ($privateHostKey -and ([int64]$item.Length -le 0)) {
            throw "An existing private host key is empty and would be replaced by ssh-keygen -A: $($item.FullName)"
        }
        if ((Test-ReparsePoint -Path $item.FullName) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $item.FullName -DenyUntrustedRead $privateHostKey))) {
            throw "An existing OpenSSH security input is writable or owned by an untrusted principal: $($item.FullName)"
        }
    }
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

function Get-SshOwnershipMarkerPath {
    return Join-Path $script:SshPath $script:SshOwnershipMarkerName
}

function Test-SshOwnershipMarker {
    param([Parameter(Mandatory = $true)]$Record)

    $markerPath = Get-SshOwnershipMarkerPath
    return (Test-Path -LiteralPath $markerPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $markerPath)) -and
        (Test-ManagedFileAcl -Path $markerPath) -and
        ((Get-FileSha256 -Path $markerPath) -eq [string]$Record.sshDirectoryMarkerSha256)
}

function Test-SshDirectoryBoundary {
    param([Parameter(Mandatory = $true)]$Record)

    if ((-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) -or
        (Test-ReparsePoint -Path $script:SshPath) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:SshPath)) -or
        (-not (Test-SshOwnershipMarker -Record $Record)) -or
        (-not (Test-SshLogsDirectoryProtected -Path $script:SshLogsPath `
                -RequireEmpty (-not [bool]$Record.original.sshDirectory.existed) `
                -ManagedExact (-not [bool]$Record.original.sshDirectory.existed)))) {
        return $false
    }
    if ([bool]$Record.original.sshDirectory.existed) {
        try {
            $directory = Get-Item -LiteralPath $script:SshPath -Force
            return (Test-PathProtectedFromUntrustedMutation -Path $script:SshPath) -and
                ((Get-Acl -LiteralPath $script:SshPath).Sddl -eq [string]$Record.original.sshDirectory.sddl) -and
                ([int]$directory.Attributes -eq [int]$Record.original.sshDirectory.attributes)
        } catch {
            return $false
        }
    }
    return Test-ManagedDirectoryAcl -Path $script:SshPath
}

function Assert-OriginalSshBaselineUnchanged {
    param([Parameter(Mandatory = $true)]$Original)

    if ([bool]$Original.config.existed) {
        if ((-not (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $script:SshConfigPath) -or
            ((Get-FileSha256 -Path $script:SshConfigPath) -ne [string]$Original.config.sha256) -or
            ((Get-Acl -LiteralPath $script:SshConfigPath).Sddl -ne [string]$Original.config.sddl) -or
            ([int](Get-Item -LiteralPath $script:SshConfigPath -Force).Attributes -ne [int]$Original.config.attributes)) {
            throw 'The original sshd_config changed before the protected takeover boundary was established.'
        }
    } elseif (Test-Path -LiteralPath $script:SshConfigPath) {
        throw 'An sshd_config appeared before the protected takeover boundary was established.'
    }

    $expected = @($Original.hostKeyFiles | Sort-Object { ([string]$_.name).ToLowerInvariant() })
    $current = @(Get-HostKeyFileRecords | Sort-Object { ([string]$_.name).ToLowerInvariant() })
    if ($expected.Count -ne $current.Count) {
        throw 'The OpenSSH host-key file set changed before the protected takeover boundary was established.'
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if (([string]$expected[$index].name -ine [string]$current[$index].name) -or
            ([string]$expected[$index].sha256 -ne [string]$current[$index].sha256) -or
            ([string]$expected[$index].sddl -ne [string]$current[$index].sddl) -or
            ([int]$expected[$index].attributes -ne [int]$current[$index].attributes)) {
            throw 'An OpenSSH host-key file changed before the protected takeover boundary was established.'
        }
    }
}

function Establish-SshDirectoryBoundary {
    param([Parameter(Mandatory = $true)]$Transaction)

    if ([bool]$Transaction.original.sshDirectory.existed) {
        Assert-OriginalSshBaselineUnchanged -Original $Transaction.original
        $markerCandidate = Join-Path $script:RootPath ("ssh-marker.$($Transaction.transactionId).tmp")
        try {
            [IO.File]::WriteAllText($markerCandidate, [string]$Transaction.accountMarker, $script:Utf8NoBom)
            Protect-ManagedFile -Path $markerCandidate
            [IO.File]::Move($markerCandidate, (Get-SshOwnershipMarkerPath))
        } finally {
            Remove-Item -LiteralPath $markerCandidate -Force -ErrorAction SilentlyContinue
        }
        Assert-OriginalSshBaselineUnchanged -Original $Transaction.original
        if (-not (Test-SshOwnershipMarker -Record $Transaction)) {
            throw 'The OpenSSH ownership marker failed validation.'
        }
        return
    }

    if (Test-Path -LiteralPath $script:SshPath) {
        throw 'The OpenSSH data path appeared after preflight; refusing to claim it.'
    }
    $candidatePath = Join-Path $script:RootPath ("ssh-directory.$($Transaction.transactionId).tmp")
    if (Test-Path -LiteralPath $candidatePath) {
        throw 'The protected OpenSSH directory candidate already exists.'
    }
    try {
        [void](New-Item -Path $candidatePath -ItemType Directory)
        Set-ExactAcl -Path $candidatePath -AllowedSids @('S-1-5-18', 'S-1-5-32-544') -Directory $true
        $candidateMarker = Join-Path $candidatePath $script:SshOwnershipMarkerName
        $candidateLogs = Join-Path $candidatePath 'logs'
        New-ManagedDirectoryProtectedAtCreation -Path $candidateLogs
        [IO.File]::WriteAllText($candidateMarker, [string]$Transaction.accountMarker, $script:Utf8NoBom)
        Protect-ManagedFile -Path $candidateMarker
        if ((-not (Test-ManagedDirectoryAcl -Path $candidatePath)) -or
            (-not (Test-SshLogsDirectoryProtected -Path $candidateLogs -RequireEmpty $true -ManagedExact $true)) -or
            ((Get-FileSha256 -Path $candidateMarker) -ne [string]$Transaction.sshDirectoryMarkerSha256)) {
            throw 'The protected OpenSSH directory candidate failed validation.'
        }
        Invoke-TestHook -Stage 'ssh-directory-before-publish'
        [IO.Directory]::Move($candidatePath, $script:SshPath)
    } finally {
        if ((Test-Path -LiteralPath $candidatePath -PathType Container) -and
            (-not (Test-ReparsePoint -Path $candidatePath)) -and
            (Test-ManagedDirectoryAcl -Path $candidatePath)) {
            $candidateMarker = Join-Path $candidatePath $script:SshOwnershipMarkerName
            $candidateLogs = Join-Path $candidatePath 'logs'
            if ((Test-Path -LiteralPath $candidateMarker -PathType Leaf) -and
                ((Get-FileSha256 -Path $candidateMarker) -eq [string]$Transaction.sshDirectoryMarkerSha256) -and
                (Test-SshLogsDirectoryProtected -Path $candidateLogs -RequireEmpty $true -ManagedExact $true) -and
                (@(Get-ChildItem -LiteralPath $candidatePath -Force).Count -eq 2)) {
                Remove-Item -LiteralPath $candidateMarker -Force
                [IO.Directory]::Delete($candidateLogs, $false)
                Remove-Item -LiteralPath $candidatePath -Force
            }
        }
    }
    if ((-not (Test-ManagedDirectoryAcl -Path $script:SshPath)) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:SshPath)) -or
        (-not (Test-SshOwnershipMarker -Record $Transaction))) {
        throw 'The OpenSSH data directory ownership boundary failed validation.'
    }
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
        ([string]$transaction.status -notin @('installing', 'restart-required', 'rolling-back', 'rollback-restart-required'))) {
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

function Assert-NoReparseAncestors {
    param([Parameter(Mandatory = $true)][string]$Path)

    $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A canonical Windows path traverses a reparse point: $($current.FullName)"
        }
        $current = $current.Parent
    }
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
    if (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:RootPath)) {
        throw 'The managed program directory can be replaced by an untrusted principal.'
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
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This installer only supports Windows.'
    }
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
        throw 'Windows PowerShell 5.1 or later is required.'
    }
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run the 64-bit Windows PowerShell from System32, not the 32-bit SysWOW64 host.'
    }
    foreach ($knownFolder in @($script:ProgramDataPath, $script:SystemPath)) {
        if ([string]::IsNullOrWhiteSpace([string]$knownFolder) -or
            (-not [IO.Path]::IsPathRooted([string]$knownFolder))) {
            throw 'Windows returned an invalid canonical known-folder path.'
        }
    }
    foreach ($securityRoot in @($script:ProgramDataPath, $script:SystemPath)) {
        if (-not (Test-Path -LiteralPath $securityRoot -PathType Container)) {
            throw "A canonical Windows security root is missing: $securityRoot"
        }
        Assert-NoReparseAncestors -Path $securityRoot
    }
    foreach ($managedChild in @($script:RootPath, $script:CleanupRootPath, $script:SshPath)) {
        if (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $managedChild)) {
            throw "The canonical parent can expose a managed path to untrusted replacement: $managedChild; $script:LastSecurityBoundaryError"
        }
    }

    $version = [Environment]::OSVersion.Version
    if (($version.Major -lt 10) -or (($version.Major -eq 10) -and ($version.Build -lt 17763))) {
        throw "Windows 10 build 17763 (1809) or later is required; found $version."
    }

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uac = Get-ItemProperty -LiteralPath $uacPath -ErrorAction Stop
    $approvalMode = $uac.PSObject.Properties['TypeOfAdminApprovalMode']
    if (($null -ne $approvalMode) -and ([int]$approvalMode.Value -eq 2)) {
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

function Get-LocalUserOrNull {
    param([Parameter(Mandatory = $true)][string]$Name)

    $matches = @(Get-LocalUser -ErrorAction Stop |
        Where-Object { [string]$_.Name -ieq $Name })
    if ($matches.Count -eq 0) { return $null }
    if ($matches.Count -ne 1) { throw "Local account identity is ambiguous: $Name" }
    return $matches[0]
}

function Ensure-TransactionAccount {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Transaction
    )

    $existing = Get-LocalUserOrNull -Name $Name
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
    $members = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop |
        Where-Object { [string]$_.SID.Value -eq [string]$existing.SID.Value })
    if ($members.Count -eq 0) {
        Add-LocalGroupMember -Group $administrators -Member $existing
    } elseif ($members.Count -ne 1) {
        throw 'The managed account has ambiguous Administrators membership.'
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

function Test-ProtectedSystemExecutable {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $actual = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $systemRoot = [IO.Path]::GetFullPath($script:SystemPath).TrimEnd('\') + '\'
        if (-not $actual.StartsWith($systemRoot, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        if ((-not (Test-Path -LiteralPath $actual -PathType Leaf)) -or
            (Test-ReparsePoint -Path $actual)) { return $false }
        Assert-NoReparseAncestors -Path $actual
        if (-not (Test-ProtectedPathIdentityChain -Path $actual)) { return $false }

        $directory = Split-Path -Parent $actual
        $windowsDirectory = Split-Path -Parent $script:SystemPath
        if ((-not (Test-Path -LiteralPath $directory -PathType Container)) -or
            (Test-ReparsePoint -Path $directory) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $directory -FixedTrustedOnly $true)) -or
            (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $directory -FixedTrustedOnly $true)) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $actual -FixedTrustedOnly $true)) -or
            (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $actual -FixedTrustedOnly $true)) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $script:SystemPath -FixedTrustedOnly $true)) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $windowsDirectory -FixedTrustedOnly $true))) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

function Get-SshdExecutable {
    $candidate = Join-Path $script:SystemPath 'OpenSSH\sshd.exe'
    if (-not (Test-ProtectedSystemExecutable -Path $candidate)) {
        throw "OpenSSH Server executable is missing or has an unsafe path/ACL: $candidate"
    }
    return $candidate
}

function Get-SshKeygenExecutable {
    $candidate = Join-Path $script:SystemPath 'OpenSSH\ssh-keygen.exe'
    if (-not (Test-ProtectedSystemExecutable -Path $candidate)) {
        throw "OpenSSH key utility is missing or has an unsafe path/ACL: $candidate"
    }
    return $candidate
}

function Get-ManagedHostKeyNames {
    return @($script:ManagedHostKeyTypes | ForEach-Object {
            "ssh_host_$($_)_key"
            "ssh_host_$($_)_key.pub"
        })
}

function Get-PlannedHostKeyStagePath {
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $allowedNames = @(Get-ManagedHostKeyNames)
    if ($Name -notin $allowedNames) {
        throw "Unexpected planned host-key filename: $Name"
    }
    $privateName = if ($Name.EndsWith('.pub', [StringComparison]::Ordinal)) {
        $Name.Substring(0, $Name.Length - 4)
    } else { $Name }
    $suffix = if ($Name.EndsWith('.pub', [StringComparison]::Ordinal)) {
        "$privateName.staged.pub"
    } else { "$privateName.staged" }
    return Join-Path $script:RootPath ("host-key.$($Transaction.transactionId).$suffix")
}

function Get-HostKeyProbeRootPath {
    param([Parameter(Mandatory = $true)]$Transaction)
    return Join-Path $script:RootPath ("host-key-probe.$($Transaction.transactionId)")
}

function Get-HostKeyProbeLayout {
    param([Parameter(Mandatory = $true)]$Transaction)

    $root = Get-HostKeyProbeRootPath -Transaction $Transaction
    $prefix = Join-Path $root 'prefix.'
    $prefixedProgramData = "${prefix}__PROGRAMDATA__"
    $fallbackProgramData = Join-Path $root 'fallback'
    return [pscustomobject]@{
        Root = $root
        Prefix = $prefix
        PrefixedProgramData = $prefixedProgramData
        PrefixedSsh = Join-Path $prefixedProgramData 'ssh'
        FallbackProgramData = $fallbackProgramData
        FallbackSsh = Join-Path $fallbackProgramData 'ssh'
    }
}

function Assert-HostKeyProbeTreeProtected {
    param([Parameter(Mandatory = $true)]$Transaction)

    $layout = Get-HostKeyProbeLayout -Transaction $Transaction
    if (-not (Test-Path -LiteralPath $layout.Root)) { return }
    if ((-not (Test-Path -LiteralPath $layout.Root -PathType Container)) -or
        (Test-ReparsePoint -Path $layout.Root) -or
        (-not (Test-ManagedDirectoryAcl -Path $layout.Root)) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $layout.Root))) {
        throw 'The protected host-key probe root changed identity.'
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $layout.Root -Recurse -Force -ErrorAction Stop)) {
        if (Test-ReparsePoint -Path $item.FullName) {
            throw "The host-key probe contains a reparse point: $($item.FullName)"
        }
        if ($item.PSIsContainer) {
            if (-not (Test-ManagedDirectoryAcl -Path $item.FullName)) {
                throw "The host-key probe contains an unprotected directory: $($item.FullName)"
            }
        } else {
            $publicOnly = [string]$item.Name -match '\.pub(?:\.[A-Za-z0-9]+)?$'
            if (Test-PathProtectedFromUntrustedMutation -Path $item.FullName `
                    -DenyUntrustedRead (-not $publicOnly)) { continue }
            # An interrupted ssh-keygen may leave a randomly suffixed private
            # temporary file. Treat everything except public-key forms as
            # confidential.
            throw "The host-key probe contains an unprotected file: $($item.FullName)"
        }
    }
}

function Remove-HostKeyProbeTree {
    param([Parameter(Mandatory = $true)]$Transaction)

    $root = Get-HostKeyProbeRootPath -Transaction $Transaction
    if (-not (Test-Path -LiteralPath $root)) { return }
    Assert-HostKeyProbeTreeProtected -Transaction $Transaction
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}

function Get-ProbeHostKeyRecords {
    param([Parameter(Mandatory = $true)][string]$Path)

    $records = New-Object System.Collections.ArrayList
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Sort-Object Name)) {
        $nameMatch = [regex]::Match([string]$item.Name,
            '^ssh_host_([a-z0-9][a-z0-9_-]{0,31})_key(?:\.pub)?$',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if ($item.PSIsContainer -or (Test-ReparsePoint -Path $item.FullName) -or
            (-not $nameMatch.Success) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $item.FullName `
                    -DenyUntrustedRead (-not ([string]$item.Name).EndsWith('.pub', [StringComparison]::Ordinal)))) -or
            ([int64]$item.Length -le 0)) {
            throw "The host-key probe produced an unsafe or unexpected path: $($item.FullName)"
        }
        [void]$records.Add([ordered]@{
                name = [string]$item.Name
                type = [string]$nameMatch.Groups[1].Value
                sha256 = Get-FileSha256 -Path $item.FullName
                path = [string]$item.FullName
            })
    }
    return @($records)
}

function Test-ProbeHostKeyPair {
    param(
        [Parameter(Mandatory = $true)][string]$PrivatePath,
        [Parameter(Mandatory = $true)][string]$PublicPath,
        [Parameter(Mandatory = $true)][string]$SshKeygen
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $derivedOutput = @(& $SshKeygen -y -f $PrivatePath 2>&1)
        $derivedExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($derivedExit -ne 0) { return $false }
    $derivedLines = @($derivedOutput | ForEach-Object { ([string]$_).Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $publicLines = @(Get-Content -LiteralPath $PublicPath -ErrorAction Stop |
        ForEach-Object { ([string]$_).Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (($derivedLines.Count -ne 1) -or ($publicLines.Count -ne 1)) { return $false }
    $derivedParts = @($derivedLines[0] -split '\s+', 3)
    $publicParts = @($publicLines[0] -split '\s+', 3)
    return ($derivedParts.Count -ge 2) -and ($publicParts.Count -ge 2) -and
        ([string]$derivedParts[0] -ceq [string]$publicParts[0]) -and
        ([string]$derivedParts[1] -ceq [string]$publicParts[1])
}

function Get-AuthorizedKeysStagePath {
    param([Parameter(Mandatory = $true)]$Transaction)
    return Join-Path $script:RootPath ("authorized-keys.$($Transaction.transactionId).staged")
}

function Get-ManagedConfigStagePath {
    param([Parameter(Mandatory = $true)]$Transaction)
    return Join-Path $script:RootPath ("sshd-config.$($Transaction.transactionId).staged")
}

function Remove-ProtectedStageFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ExpectedSha256
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ((-not (Test-Path -LiteralPath $Path -PathType Leaf)) -or
        (Test-ReparsePoint -Path $Path) -or
        (-not (Test-PathProtectedFromUntrustedMutation -Path $Path))) {
        throw "A protected staging path changed identity; refusing to remove it: $Path"
    }
    if ((-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) -and
        ((Get-FileSha256 -Path $Path) -ne $ExpectedSha256)) {
        throw "A protected staging file changed content; refusing to remove it: $Path"
    }
    Remove-Item -LiteralPath $Path -Force
}

function Get-ProtectedFileRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ((-not (Test-Path -LiteralPath $Path -PathType Leaf)) -or
        (Test-ReparsePoint -Path $Path) -or
        (-not (Test-ManagedFileAcl -Path $Path))) {
        throw "A planned protected file failed validation: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [ordered]@{
        name = $Name
        sha256 = Get-FileSha256 -Path $Path
        sddl = (Get-Acl -LiteralPath $Path).Sddl
        attributes = [int]$item.Attributes
    }
}

function Prepare-PlannedHostKeyFiles {
    param([Parameter(Mandatory = $true)]$Transaction)

    Assert-OriginalHostKeysUnchanged -Records @($Transaction.original.hostKeyFiles)
    $layout = Get-HostKeyProbeLayout -Transaction $Transaction
    if (Test-Path -LiteralPath $layout.Root) {
        throw 'The deterministic host-key probe path already exists.'
    }

    New-ManagedDirectoryProtectedAtCreation -Path $layout.Root
    New-ManagedDirectoryProtectedAtCreation -Path $layout.PrefixedProgramData
    New-ManagedDirectoryProtectedAtCreation -Path $layout.PrefixedSsh
    New-ManagedDirectoryProtectedAtCreation -Path $layout.FallbackProgramData
    New-ManagedDirectoryProtectedAtCreation -Path $layout.FallbackSsh
    Assert-HostKeyProbeTreeProtected -Transaction $Transaction

    $keygen = Get-SshKeygenExecutable
    $savedProgramData = [Environment]::GetEnvironmentVariable('ProgramData', 'Process')
    try {
        # -f is the documented ssh-keygen -A prefix. The process-only
        # ProgramData override is a second containment boundary for older
        # Windows builds that might ignore the prefix.
        [Environment]::SetEnvironmentVariable('ProgramData', $layout.FallbackProgramData, 'Process')
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $firstOutput = @(& $keygen -A -f $layout.Prefix 2>&1)
            $firstExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousPreference
        }
        if ($firstExit -ne 0) {
            throw "OpenSSH default host-key generation failed: $($firstOutput -join ' ')"
        }
        Assert-OriginalHostKeysUnchanged -Records @($Transaction.original.hostKeyFiles)
        Assert-HostKeyProbeTreeProtected -Transaction $Transaction
        Invoke-TestHook -Stage 'host-key-probe'

        $prefixedCount = @(Get-ChildItem -LiteralPath $layout.PrefixedSsh -Force -ErrorAction Stop).Count
        $fallbackCount = @(Get-ChildItem -LiteralPath $layout.FallbackSsh -Force -ErrorAction Stop).Count
        if (([int]($prefixedCount -gt 0) + [int]($fallbackCount -gt 0)) -ne 1) {
            throw 'ssh-keygen did not produce one unambiguous protected default-key set.'
        }
        $sourcePath = if ($prefixedCount -gt 0) { $layout.PrefixedSsh } else { $layout.FallbackSsh }
        $firstRecords = @(Get-ProbeHostKeyRecords -Path $sourcePath)

        # A second run must be silent and byte-stable. ssh-keygen -A may
        # return success even when one key type failed, but it always emits
        # output while retrying a missing default key.
        try {
            $ErrorActionPreference = 'Continue'
            $secondOutput = @(& $keygen -A -f $layout.Prefix 2>&1)
            $secondExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousPreference
        }
        $nonEmptySecondOutput = @($secondOutput | Where-Object {
                -not [string]::IsNullOrWhiteSpace(([string]$_).Trim())
            })
        $prefixedCountAfter = @(Get-ChildItem -LiteralPath $layout.PrefixedSsh -Force -ErrorAction Stop).Count
        $fallbackCountAfter = @(Get-ChildItem -LiteralPath $layout.FallbackSsh -Force -ErrorAction Stop).Count
        $secondRecords = @(Get-ProbeHostKeyRecords -Path $sourcePath)
        if (($secondExit -ne 0) -or ($nonEmptySecondOutput.Count -ne 0) -or
            ($prefixedCountAfter -ne $prefixedCount) -or
            ($fallbackCountAfter -ne $fallbackCount) -or
            (($firstRecords | ConvertTo-Json -Depth 4 -Compress) -ne
                ($secondRecords | ConvertTo-Json -Depth 4 -Compress))) {
            throw 'OpenSSH default host-key generation did not converge to a silent, byte-stable set.'
        }
        Assert-OriginalHostKeysUnchanged -Records @($Transaction.original.hostKeyFiles)
    } finally {
        [Environment]::SetEnvironmentVariable('ProgramData', $savedProgramData, 'Process')
    }

    $records = @(Get-ProbeHostKeyRecords -Path $sourcePath)
    $types = @($records | ForEach-Object { [string]$_.type } | Sort-Object -Unique)
    $typeSet = $types -join ','
    if ($typeSet -notin @('ecdsa,ed25519,rsa', 'dsa,ecdsa,ed25519,rsa')) {
        throw "OpenSSH produced an unsupported default host-key set: $typeSet"
    }
    foreach ($type in $types) {
        $privateName = "ssh_host_$($type)_key"
        $publicName = "$privateName.pub"
        $private = @($records | Where-Object { [string]$_.name -ceq $privateName })
        $public = @($records | Where-Object { [string]$_.name -ceq $publicName })
        if (($private.Count -ne 1) -or ($public.Count -ne 1) -or
            (-not (Test-ProbeHostKeyPair -PrivatePath ([string]$private[0].path) `
                    -PublicPath ([string]$public[0].path) -SshKeygen $keygen))) {
            throw "OpenSSH produced an incomplete or mismatched $type host-key pair."
        }
    }

    $originalNames = @($Transaction.original.hostKeyFiles | ForEach-Object {
            ([string]$_.name).ToLowerInvariant()
        })
    foreach ($record in @($Transaction.original.hostKeyFiles)) {
        $name = ([string]$record.name).ToLowerInvariant()
        if (($name -match '^ssh_host_[a-z0-9][a-z0-9_-]{0,31}_key$') -and
            ([int64](Get-Item -LiteralPath (Join-Path $script:SshPath $name) -Force).Length -le 0)) {
            throw "An existing zero-length private host key would be replaced by ssh-keygen -A: $name"
        }
    }

    $planned = New-Object System.Collections.ArrayList
    foreach ($type in $types) {
        $privateName = "ssh_host_$($type)_key"
        $publicName = "$privateName.pub"
        if ($originalNames -contains $privateName) { continue }
        if ($originalNames -contains $publicName) {
            throw "An orphaned original $type public host key exists without its private key."
        }
        foreach ($name in @($privateName, $publicName)) {
            $destination = Join-Path $script:SshPath $name
            $stage = Get-PlannedHostKeyStagePath -Transaction $Transaction -Name $name
            if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $stage)) {
                throw "A host-key destination or staging path appeared unexpectedly: $name"
            }
            $source = Join-Path $sourcePath $name
            [IO.File]::Move($source, $stage)
            Protect-ManagedFile -Path $stage
            [void]$planned.Add((Get-ProtectedFileRecord -Path $stage -Name $name))
        }
    }
    Invoke-TestHook -Stage 'hostkeys-before-journal'
    $Transaction.plannedHostKeyFiles = @($planned)
    Update-InstallTransaction -Transaction $Transaction
    Remove-HostKeyProbeTree -Transaction $Transaction
}

function Publish-PlannedHostKeyFiles {
    param([Parameter(Mandatory = $true)]$Transaction)

    foreach ($record in @($Transaction.plannedHostKeyFiles)) {
        $stage = Get-PlannedHostKeyStagePath -Transaction $Transaction -Name ([string]$record.name)
        $destination = Join-Path $script:SshPath ([string]$record.name)
        if (Test-Path -LiteralPath $destination) {
            throw "A planned host-key destination already exists: $destination"
        }
        if ((-not (Test-Path -LiteralPath $stage -PathType Leaf)) -or
            (Test-ReparsePoint -Path $stage) -or
            ((Get-FileSha256 -Path $stage) -ne [string]$record.sha256) -or
            (-not (Test-ManagedFileAcl -Path $stage))) {
            throw "A planned host-key staging file changed before publication: $stage"
        }
        [IO.File]::Move($stage, $destination)
    }
    $Transaction.generatedHostKeyFiles = @($Transaction.plannedHostKeyFiles)
    Update-InstallTransaction -Transaction $Transaction
}

function Remove-PlannedHostKeyStagingFiles {
    param([Parameter(Mandatory = $true)]$Transaction)

    $names = @(Get-ManagedHostKeyNames)
    foreach ($name in $names) {
        $stage = Get-PlannedHostKeyStagePath -Transaction $Transaction -Name $name
        if (-not (Test-Path -LiteralPath $stage)) { continue }
        if ((Test-ReparsePoint -Path $stage) -or
            (-not (Test-Path -LiteralPath $stage -PathType Leaf)) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $stage `
                    -DenyUntrustedRead ($name -match '_key$')))) {
            throw "A host-key staging file changed identity; refusing to remove it: $stage"
        }
        $planned = @($Transaction.plannedHostKeyFiles | Where-Object { [string]$_.name -eq $name })
        if (($planned.Count -gt 0) -and ((Get-FileSha256 -Path $stage) -ne [string]$planned[0].sha256)) {
            throw "A host-key staging file changed content; refusing to remove it: $stage"
        }
        Remove-Item -LiteralPath $stage -Force
    }
    Remove-HostKeyProbeTree -Transaction $Transaction
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
    $path = Join-Path $script:SshPath 'ssh_host_ed25519_key'
    if ((-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
        (Test-ReparsePoint -Path $path)) {
        throw 'The managed Ed25519 host key is missing or is not a regular file.'
    }
    $keygen = Get-SshKeygenExecutable
    # ssh-keygen -l may prefer a same-name .pub companion and therefore report
    # a key sshd is not actually using. Derive the public blob from the private
    # key, then calculate the OpenSSH SHA256 fingerprint directly.
    $output = & $keygen -y -f $path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "ssh-keygen could not derive the managed host public key: $($output -join ' ')"
    }
    $publicKeyLines = @($output | ForEach-Object { ([string]$_).Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($publicKeyLines.Count -ne 1) {
        throw "ssh-keygen returned an ambiguous public key: $($output -join ' | ')"
    }
    # Windows OpenSSH preserves the private key's optional comment. It is not
    # part of the key blob or fingerprint, so parse at most three fields.
    $parts = @($publicKeyLines[0] -split '\s+', 3)
    if (($parts.Count -lt 2) -or
        ([string]$parts[0] -cne 'ssh-ed25519') -or
        ([string]$parts[1] -notmatch '^[A-Za-z0-9+/]+={0,2}$')) {
        throw 'ssh-keygen returned an unrecognized Ed25519 public key.'
    }
    try {
        $blob = [Convert]::FromBase64String([string]$parts[1])
    } catch {
        throw 'ssh-keygen returned an invalid Ed25519 public-key blob.'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($blob)
    } finally {
        $sha.Dispose()
    }
    return 'SHA256:' + ([Convert]::ToBase64String($digest).TrimEnd('='))
}

function ConvertTo-CanonicalStringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { [string]$_ } | Sort-Object -Unique)
}

function Get-OptionalPropertyText {
    param($Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return '' }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return '' }
    return [string]$property.Value
}

function Get-OptionalPropertyValues {
    param($Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return @() }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return @() }
    return @(ConvertTo-CanonicalStringArray $property.Value)
}

function Test-ActiveFirewallEnforcementStatus {
    param([Parameter(Mandatory = $true)]$Rule)

    # NetSecurity's PowerShell adapter uses friendly names (Enforced and
    # ProfileInactive), while the underlying WMI schema documents the same
    # values as Full/1 and InactiveProfile/5. A Profile=Any rule normally has
    # inactive-profile entries beside the enforced active profile. Accept only
    # those benign representations and require at least one enforced profile.
    $values = @(Get-OptionalPropertyValues -Object $Rule -Name 'EnforcementStatus' |
        ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    if ($values.Count -eq 0) { return $false }
    $allowed = @('enforced', 'full', '1', 'profileinactive', 'inactiveprofile', '5')
    if (@($values | Where-Object { $_ -notin $allowed }).Count -gt 0) { return $false }
    return @($values | Where-Object { $_ -in @('enforced', 'full', '1') }).Count -gt 0
}

function Get-FirewallRuleSemanticSha256 {
    param([Parameter(Mandatory = $true)]$Rule)

    $port = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $application = $Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $service = $Rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    $interface = $Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
    $interfaceType = $Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    $security = $Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
    $record = [ordered]@{
        name = [string]$Rule.Name
        displayName = [string]$Rule.DisplayName
        description = [string]$Rule.Description
        ruleGroup = Get-OptionalPropertyText -Object $Rule -Name 'RuleGroup'
        direction = [string]$Rule.Direction
        action = [string]$Rule.Action
        profile = [string]$Rule.Profile
        edgeTraversalPolicy = Get-OptionalPropertyText -Object $Rule -Name 'EdgeTraversalPolicy'
        looseSourceMapping = Get-OptionalPropertyText -Object $Rule -Name 'LooseSourceMapping'
        localOnlyMapping = Get-OptionalPropertyText -Object $Rule -Name 'LocalOnlyMapping'
        owner = Get-OptionalPropertyText -Object $Rule -Name 'Owner'
        packageFamilyName = Get-OptionalPropertyText -Object $Rule -Name 'PackageFamilyName'
        platforms = Get-OptionalPropertyValues -Object $Rule -Name 'Platforms'
        policyAppId = Get-OptionalPropertyValues -Object $Rule -Name 'PolicyAppId'
        remoteDynamicKeywordAddresses = Get-OptionalPropertyValues -Object $Rule -Name 'RemoteDynamicKeywordAddresses'
        port = [ordered]@{
            protocol = ConvertTo-CanonicalStringArray $port.Protocol
            localPort = ConvertTo-CanonicalStringArray $port.LocalPort
            remotePort = ConvertTo-CanonicalStringArray $port.RemotePort
            icmpType = ConvertTo-CanonicalStringArray $port.IcmpType
            dynamicTarget = ConvertTo-CanonicalStringArray $port.DynamicTarget
        }
        address = [ordered]@{
            localAddress = ConvertTo-CanonicalStringArray $address.LocalAddress
            remoteAddress = ConvertTo-CanonicalStringArray $address.RemoteAddress
        }
        application = [ordered]@{
            program = ConvertTo-CanonicalStringArray $application.Program
            package = ConvertTo-CanonicalStringArray $application.Package
        }
        service = ConvertTo-CanonicalStringArray $service.Service
        interfaceAlias = ConvertTo-CanonicalStringArray $interface.InterfaceAlias
        interfaceType = ConvertTo-CanonicalStringArray $interfaceType.InterfaceType
        security = [ordered]@{
            authentication = ConvertTo-CanonicalStringArray $security.Authentication
            encryption = ConvertTo-CanonicalStringArray $security.Encryption
            overrideBlockRules = ConvertTo-CanonicalStringArray $security.OverrideBlockRules
            localUser = ConvertTo-CanonicalStringArray $security.LocalUser
            remoteUser = ConvertTo-CanonicalStringArray $security.RemoteUser
            remoteMachine = ConvertTo-CanonicalStringArray $security.RemoteMachine
        }
    }
    return Get-TextSha256 -Text ($record | ConvertTo-Json -Depth 8 -Compress)
}

function Get-FirewallRulesByNameSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet('ActiveStore', 'PersistentStore')][string]$PolicyStore
    )

    $rules = @(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop)
    return @($rules | Where-Object { [string]$_.Name -eq $Name })
}

function Test-FirewallProfilesSecure {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -eq 0) { return $false }
    foreach ($profile in $profiles) {
        $disabledAliases = @($profile.DisabledInterfaceAliases | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            })
        if (([string]$profile.Enabled -ne 'True') -or
            ([string]$profile.DefaultInboundAction -notin @('Block', '4')) -or
            ($disabledAliases.Count -gt 0)) {
            return $false
        }
    }
    return $true
}

function Disable-DefaultOpenSshFirewallRule {
    $rules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore)
    if ($rules.Count -gt 1) { throw 'More than one default OpenSSH firewall rule exists.' }
    if ($rules.Count -eq 1) {
        $rules[0] | Disable-NetFirewallRule -ErrorAction Stop | Out-Null
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
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object {
            ([string]$_.Enabled -eq 'True') -and
            ([string]$_.Direction -eq 'Inbound') -and
            ([string]$_.Action -in @('Allow', 'AllowBypass', 'Block', '2', '3', '4')) -and
            ($_.Name -notin @($script:FirewallRuleName, 'OpenSSH-Server-In-TCP'))
        })
    foreach ($rule in $rules) {
        $enforcement = @($rule.EnforcementStatus | ForEach-Object { [string]$_ })
        $packageFamilyProperty = $rule.PSObject.Properties['PackageFamilyName']
        $packageFamilyName = if ($null -eq $packageFamilyProperty) { '' } else { [string]$packageFamilyProperty.Value }
        if (-not [string]::IsNullOrWhiteSpace($packageFamilyName)) {
            continue
        }
        # ActiveStore can retain packaged-app capability rules whose hidden app
        # identity currently cannot resolve. Such a rule cannot match sshd.exe.
        if (($enforcement -contains 'ApplicationResolutionEmpty') -or ($enforcement -contains '11')) {
            continue
        }
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        if ($null -eq $portFilter) { throw "Firewall rule '$($rule.Name)' has no readable port filter." }
        $protocol = [string]$portFilter.Protocol
        if ($protocol -notin @('TCP', '6', 'Any', '256')) {
            continue
        }
        if (-not (Test-PortFilterIncludes -LocalPort $portFilter.LocalPort -SshPort $SshPort)) {
            continue
        }

        $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        if ($null -eq $applicationFilter) { throw "Firewall rule '$($rule.Name)' has no readable application filter." }
        $program = [string]$applicationFilter.Program
        $package = [string]$applicationFilter.Package
        $programExpanded = [Environment]::ExpandEnvironmentVariables($program).TrimEnd('\').ToLowerInvariant()
        $programApplies = ($program -eq 'Any') -or ($programExpanded -eq $targetProgram)
        # Packaged-app rules cannot authorize an unpackaged sshd.exe, even when
        # their Program filter is reported as Any.
        $packageApplies = [string]::IsNullOrWhiteSpace($package) -or ($package -eq 'Any')

        $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
        if ($null -eq $serviceFilter) { throw "Firewall rule '$($rule.Name)' has no readable service filter." }
        $serviceName = [string]$serviceFilter.Service
        $serviceApplies = ($serviceName -eq 'Any') -or ($serviceName -eq 'sshd')
        if ($programApplies -and $packageApplies -and $serviceApplies) {
            [void]$competing.Add("$([string]$rule.Name) [action=$([string]$rule.Action); owner=$([string]$rule.Owner); package=$package; program=$program; service=$serviceName; enforcement=$($enforcement -join ','); source=$([string]$rule.PolicyStoreSourceType)]")
        }
    }
    return @($competing)
}

function Assert-FirewallPreconditions {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string]$SshdExe
    )

    if (-not (Test-FirewallProfilesSecure)) {
        throw 'Every Windows Firewall profile must be enabled, default-deny inbound traffic, and have no excluded interface.'
    }
    $competing = @(Get-CompetingSshFirewallRules -SshPort $SshPort -SshdExe $SshdExe)
    if ($competing.Count -gt 0) {
        throw "Other enabled inbound allow/block rules apply to sshd on TCP/${SshPort}: $($competing -join ', '). Disable or narrow them before installing."
    }
}

function Test-ManagedFirewallRule {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$SshdExe,
        [Parameter(Mandatory = $true)][string]$Marker,
        [ValidateSet('ActiveStore', 'PersistentStore')][string]$PolicyStore = 'ActiveStore'
    )

    $rules = @(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore $PolicyStore)
    if ($rules.Count -ne 1) { return $false }
    $rule = $rules[0]
    if (([string]$rule.Enabled -ne 'True') -or
        ([string]$rule.Direction -ne 'Inbound') -or
        ([string]$rule.Action -ne 'Allow') -or
        ([string]$rule.Profile -ne 'Any') -or
        ([string]$rule.EdgeTraversalPolicy -notin @('Block', '0')) -or
        ([string]$rule.LooseSourceMapping -notin @('False', '0')) -or
        ([string]$rule.LocalOnlyMapping -notin @('False', '0')) -or
        ([string]$rule.DisplayName -ne 'Windows Remote Bootstrap - SSH (restricted)') -or
        ([string]$rule.Description -ne "Managed by WindowsRemoteBootstrap; $Marker") -or
        (-not [string]::IsNullOrWhiteSpace((Get-OptionalPropertyText -Object $rule -Name 'RuleGroup'))) -or
        (-not [string]::IsNullOrWhiteSpace((Get-OptionalPropertyText -Object $rule -Name 'Owner'))) -or
        (-not [string]::IsNullOrWhiteSpace((Get-OptionalPropertyText -Object $rule -Name 'PackageFamilyName'))) -or
        (@(Get-OptionalPropertyValues -Object $rule -Name 'Platforms').Count -gt 0) -or
        (@(Get-OptionalPropertyValues -Object $rule -Name 'PolicyAppId').Count -gt 0) -or
        (@(Get-OptionalPropertyValues -Object $rule -Name 'RemoteDynamicKeywordAddresses').Count -gt 0)) {
        return $false
    }
    if ($PolicyStore -eq 'ActiveStore') {
        if ((-not (Test-ActiveFirewallEnforcementStatus -Rule $rule)) -or
            ([string]$rule.PolicyStoreSourceType -notin @('Local', '1'))) {
            return $false
        }
    }
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    if (($null -eq $portFilter) -or ([string]$portFilter.Protocol -notin @('TCP', '6')) -or
        ([string]$portFilter.LocalPort -ne [string]$SshPort) -or
        ([string]$portFilter.RemotePort -ne 'Any') -or
        ([string]$portFilter.IcmpType -notin @('', 'Any')) -or
        ([string]$portFilter.DynamicTarget -notin @('', 'Any', '0'))) {
        return $false
    }
    $applicationFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    if ($null -eq $applicationFilter) { return $false }
    $package = [string]$applicationFilter.Package
    if (-not ([string]::IsNullOrWhiteSpace($package) -or ($package -eq 'Any'))) { return $false }
    $actualProgram = [Environment]::ExpandEnvironmentVariables([string]$applicationFilter.Program)
    if ([IO.Path]::GetFullPath($actualProgram).TrimEnd('\') -ine [IO.Path]::GetFullPath($SshdExe).TrimEnd('\')) {
        return $false
    }
    $serviceFilter = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    if (($null -eq $serviceFilter) -or ([string]$serviceFilter.Service -ne 'Any')) { return $false }
    $interfaceFilter = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
    if (($null -eq $interfaceFilter) -or ([string]$interfaceFilter.InterfaceAlias -ne 'Any')) { return $false }
    $interfaceTypeFilter = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    if (($null -eq $interfaceTypeFilter) -or ([string]$interfaceTypeFilter.InterfaceType -ne 'Any')) { return $false }
    $securityFilter = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
    if (($null -eq $securityFilter) -or
        ([string]$securityFilter.Authentication -ne 'NotRequired') -or
        ([string]$securityFilter.Encryption -ne 'NotRequired') -or
        ([string]$securityFilter.OverrideBlockRules -notin @('False', '0')) -or
        ([string]$securityFilter.LocalUser -ne 'Any') -or
        ([string]$securityFilter.RemoteUser -ne 'Any') -or
        ([string]$securityFilter.RemoteMachine -ne 'Any')) {
        return $false
    }
    $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    if ($null -eq $addressFilter) { return $false }
    if ([string]$addressFilter.LocalAddress -ne 'Any') { return $false }
    $expectedAddresses = @($RemoteAddress | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $actualAddresses = @($addressFilter.RemoteAddress | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    return (($expectedAddresses -join ',') -eq ($actualAddresses -join ','))
}

function New-ManagedFirewallRule {
    param(
        [Parameter(Mandatory = $true)][int]$SshPort,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$SshdExe,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    if (@(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore PersistentStore).Count -gt 0) {
        throw "Firewall rule '$script:FirewallRuleName' already exists without finalized ownership state."
    }
    New-NetFirewallRule -Name $script:FirewallRuleName `
        -DisplayName 'Windows Remote Bootstrap - SSH (restricted)' `
        -Description "Managed by WindowsRemoteBootstrap; $Marker" `
        -Enabled True -Profile Any -Direction Inbound -Action Allow `
        -EdgeTraversalPolicy Block -LooseSourceMapping $false -LocalOnlyMapping $false `
        -Protocol TCP -LocalPort $SshPort -RemotePort Any `
        -LocalAddress Any -RemoteAddress $RemoteAddress `
        -Program $SshdExe -Service Any -InterfaceAlias Any -InterfaceType Any `
        -Authentication NotRequired -Encryption NotRequired -OverrideBlockRules $false | Out-Null
    if ((-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $SshdExe -Marker $Marker -PolicyStore PersistentStore)) -or
        (-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $SshdExe -Marker $Marker -PolicyStore ActiveStore))) {
        throw 'The managed firewall rule failed exact filter verification.'
    }
}

function Test-DefaultOpenSshFirewallClosed {
    $rules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore ActiveStore)
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
    $items = @(Get-ChildItem -LiteralPath $script:SshPath -Filter 'ssh_host_*' -Force -ErrorAction Stop)
    return @($items | Sort-Object Name | ForEach-Object {
            if (([IO.Path]::GetFileName($_.Name) -ne $_.Name) -or
                ($_.Name -notmatch '^ssh_host_[A-Za-z0-9._-]+$') -or
                $_.PSIsContainer -or
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

function Get-SshdServiceOrNull {
    $cimServices = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
    if ($cimServices.Count -eq 0) { return $null }
    if ($cimServices.Count -ne 1) { throw 'The sshd service identity is ambiguous.' }
    $controller = Get-Service -Name sshd -ErrorAction Stop
    return [pscustomobject]@{
        Controller = $controller
        Cim = $cimServices[0]
    }
}

function Get-ServiceSecurityDescriptor {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq ('WindowsRemoteBootstrap.NativeServiceSecurity' -as [type])) {
        $source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WindowsRemoteBootstrap
{
    public static class NativeServiceSecurity
    {
        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint READ_CONTROL = 0x00020000;
        private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(
            IntPtr serviceManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceObjectSecurity(
            IntPtr service,
            uint securityInformation,
            byte[] securityDescriptor,
            uint bufferSize,
            out uint bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        public static byte[] QueryOwnerAndDacl(string serviceName)
        {
            IntPtr manager = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            try
            {
                manager = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                if (manager == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
                service = OpenService(manager, serviceName, READ_CONTROL);
                if (service == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");

                uint needed;
                bool first = QueryServiceObjectSecurity(
                    service,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    null,
                    0,
                    out needed);
                int firstError = Marshal.GetLastWin32Error();
                if (first || needed == 0 || firstError != ERROR_INSUFFICIENT_BUFFER)
                    throw new Win32Exception(firstError, "QueryServiceObjectSecurity sizing failed");

                byte[] descriptor = new byte[needed];
                if (!QueryServiceObjectSecurity(
                    service,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    descriptor,
                    (uint)descriptor.Length,
                    out needed))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceObjectSecurity failed");
                return descriptor;
            }
            finally
            {
                if (service != IntPtr.Zero) CloseServiceHandle(service);
                if (manager != IntPtr.Zero) CloseServiceHandle(manager);
            }
        }
    }
}
'@
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
    }
    return [WindowsRemoteBootstrap.NativeServiceSecurity]::QueryOwnerAndDacl($Name)
}

function Test-SshdServiceObjectSecurity {
    try {
        [byte[]]$bytes = Get-ServiceSecurityDescriptor -Name 'sshd'
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
        if (($null -eq $descriptor.Owner) -or
            (-not (Test-FixedTrustedSystemSid -Sid ([string]$descriptor.Owner.Value))) -or
            (($descriptor.ControlFlags -band
                    [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) -or
            ($null -eq $descriptor.DiscretionaryAcl)) {
            return $false
        }

        # Non-administrative principals may query status/configuration and
        # read the descriptor. Every mutation/control/future bit fails closed.
        $unsafeForUntrusted = [int64]2147352178 # 0x7ffDFE72
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if (($ace -isnot [Security.AccessControl.CommonAce]) -or
                $ace.IsCallback -or
                ($ace.AceFlags -ne [Security.AccessControl.AceFlags]::None)) {
                return $false
            }
            if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) { continue }
            if ($ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) { return $false }
            $sid = [string]$ace.SecurityIdentifier.Value
            if (Test-FixedTrustedSystemSid -Sid $sid) { continue }
            $mask = [int64][BitConverter]::ToUInt32(
                [BitConverter]::GetBytes([int]$ace.AccessMask), 0)
            if (($mask -band $unsafeForUntrusted) -ne 0) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-SshdServiceSecurityBoundary {
    try {
        if ($null -eq (Get-SshdServiceOrNull)) { return $false }
        [void](Get-SshdExecutable)
        [void](Get-SshKeygenExecutable)
        return Test-SshdServiceObjectSecurity
    } catch {
        return $false
    }
}

function Get-ServiceSnapshot {
    $record = Get-SshdServiceOrNull
    if ($null -eq $record) {
        return [ordered]@{ existed = $false; status = $null; startType = $null; startName = $null; pathName = $null; processId = 0 }
    }
    $service = $record.Controller
    $deadline = (Get-Date).AddSeconds(15)
    while (([string]$service.Status -notin @('Running', 'Stopped')) -and ((Get-Date) -lt $deadline)) {
        Start-Sleep -Milliseconds 250
        $service.Refresh()
    }
    if ([string]$service.Status -notin @('Running', 'Stopped')) {
        throw "The existing sshd service is not in a stable Running/Stopped state: $($service.Status)"
    }
    $cim = $record.Cim
    return [ordered]@{
        existed = $true
        status = [string]$service.Status
        startType = [string]$service.StartType
        startName = [string]$cim.StartName
        pathName = [string]$cim.PathName
        processId = [uint32]$cim.ProcessId
    }
}

function Stop-SshdAndWait {
    $record = Get-SshdServiceOrNull
    if ($null -eq $record) { return }
    $service = $record.Controller
    if ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary))) {
        throw 'Refusing to stop sshd because its identity, service DACL, or binary boundary is unsafe.'
    }
    if ([string]$service.Status -ne 'Stopped') {
        Stop-Service -Name sshd -Force -ErrorAction Stop
        $service = Get-Service -Name sshd -ErrorAction Stop
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
    }
    $service.Refresh()
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if (([string]$service.Status -ne 'Stopped') -or ([uint32]$cim.ProcessId -ne 0)) {
        throw 'sshd did not reach a proven stopped state.'
    }
}

function Test-SshdServiceIdentity {
    try {
        $record = Get-SshdServiceOrNull
    } catch {
        return $false
    }
    if ($null -eq $record) { return $false }
    if ([string]$record.Cim.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) { return $false }
    $rawPath = [Environment]::ExpandEnvironmentVariables([string]$record.Cim.PathName).Trim()
    if ($rawPath.StartsWith('"') -and $rawPath.EndsWith('"')) {
        $rawPath = $rawPath.Substring(1, $rawPath.Length - 2)
    }
    try {
        $actual = [IO.Path]::GetFullPath($rawPath).TrimEnd('\')
        $expected = [IO.Path]::GetFullPath((Join-Path $script:SystemPath 'OpenSSH\sshd.exe')).TrimEnd('\')
        return $actual -ieq $expected
    } catch {
        return $false
    }
}

function Restore-ServiceSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    $record = Get-SshdServiceOrNull
    $service = if ($null -eq $record) { $null } else { $record.Controller }
    if (-not [bool]$Snapshot.existed) {
        if ($null -ne $service) {
            throw 'The sshd service still exists although the original baseline had no service.'
        }
        return
    }
    if ($null -eq $service) {
        throw 'Cannot restore the original sshd service because it is missing.'
    }
    if ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary))) {
        throw 'Cannot restore sshd because its identity, service DACL, or binary boundary changed.'
    }
    $targetType = [string]$Snapshot.startType
    if ($targetType -eq 'Disabled') {
        Stop-SshdAndWait
        Set-Service -Name sshd -StartupType Disabled
        return
    }
    Set-Service -Name sshd -StartupType $targetType
    if ([string]$Snapshot.status -eq 'Running') {
        Start-Service -Name sshd -ErrorAction Stop
        $service = Get-Service -Name sshd -ErrorAction Stop
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
    } else {
        Stop-SshdAndWait
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

function Get-ConfigRestoreStagePath {
    param([Parameter(Mandatory = $true)]$Record)
    return Join-Path $script:RootPath ("config-restore.$($Record.transactionId).next")
}

function Test-ConfigHasSnapshotContent {
    param([Parameter(Mandatory = $true)]$Snapshot)

    return [bool]$Snapshot.existed -and
        (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $script:SshConfigPath)) -and
        ((Get-FileSha256 -Path $script:SshConfigPath) -eq [string]$Snapshot.sha256) -and
        (Test-PathProtectedFromUntrustedMutation -Path $script:SshConfigPath)
}

function Restore-ConfigSnapshot {
    param([Parameter(Mandatory = $true)]$Record)

    $snapshot = $Record.original.config
    $temporaryPath = Get-ConfigRestoreStagePath -Record $Record
    if (-not [bool]$snapshot.existed) {
        if (Test-Path -LiteralPath $script:SshConfigPath) {
            $owned = (Test-ManagedConfigContentProtected -Record $Record)
            if (($null -ne $Record.PSObject.Properties['preManagedConfig']) -and
                ($null -ne $Record.preManagedConfig)) {
                $owned = $owned -or (Test-ConfigMatchesSnapshot -Snapshot $Record.preManagedConfig)
            }
            if (-not $owned) {
                throw 'Refusing to remove an sshd_config that is not an exact transaction-owned version.'
            }
            [IO.File]::Delete($script:SshConfigPath)
        }
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-ProtectedStageFile -Path $temporaryPath
        }
        return
    }

    if (Test-ConfigHasSnapshotContent -Snapshot $snapshot) {
        Set-SecurityDescriptorFromSnapshot -Path $script:SshConfigPath -Snapshot $snapshot
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-ProtectedStageFile -Path $temporaryPath -ExpectedSha256 ([string]$snapshot.sha256)
        }
        return
    }

    if (Test-Path -LiteralPath $script:SshConfigPath) {
        $ownedCurrent = Test-ManagedConfigContentProtected -Record $Record
        if (($null -ne $Record.PSObject.Properties['preManagedConfig']) -and
            ($null -ne $Record.preManagedConfig)) {
            $ownedCurrent = $ownedCurrent -or (Test-ConfigMatchesSnapshot -Snapshot $Record.preManagedConfig)
        }
        if (-not $ownedCurrent) {
            throw 'Refusing to overwrite an sshd_config that is neither managed nor the recorded original.'
        }
    }

    if (Test-Path -LiteralPath $temporaryPath) {
        if ((-not (Test-Path -LiteralPath $temporaryPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $temporaryPath) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $temporaryPath))) {
            throw 'The deterministic config restoration stage changed identity.'
        }
        # A hard stop can interrupt WriteAllBytes before the stage is complete.
        # The protected journal remains authoritative, so discard only this
        # safely contained partial stage and deterministically rebuild it.
        if ((Get-FileSha256 -Path $temporaryPath) -ne [string]$snapshot.sha256) {
            [IO.File]::Delete($temporaryPath)
        } elseif (-not (Test-ManagedFileAcl -Path $temporaryPath)) {
            Protect-ManagedFile -Path $temporaryPath
        }
    }
    if (-not (Test-Path -LiteralPath $temporaryPath)) {
        [IO.File]::WriteAllBytes($temporaryPath, [Convert]::FromBase64String([string]$snapshot.bytesBase64))
        Protect-ManagedFile -Path $temporaryPath
        if ((Get-FileSha256 -Path $temporaryPath) -ne [string]$snapshot.sha256) {
            throw 'The deterministic config restoration stage failed hash verification.'
        }
    }
    if (Test-Path -LiteralPath $script:SshConfigPath) {
        if ((-not (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $script:SshConfigPath)) {
            throw 'Refusing to replace an unsafe sshd_config during recovery.'
        }
        [IO.File]::Replace(
            $temporaryPath,
            $script:SshConfigPath,
            [System.Management.Automation.Language.NullString]::Value
        )
    } else {
        [IO.File]::Move($temporaryPath, $script:SshConfigPath)
    }
    Set-SecurityDescriptorFromSnapshot -Path $script:SshConfigPath -Snapshot $snapshot
    if (-not (Test-ConfigMatchesSnapshot -Snapshot $snapshot)) {
        throw 'Original sshd_config restoration did not converge exactly.'
    }
}

function Test-ConfigMatchesSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    if (-not [bool]$Snapshot.existed) {
        return -not (Test-Path -LiteralPath $script:SshConfigPath)
    }
    if ((-not (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf)) -or
        (Test-ReparsePoint -Path $script:SshConfigPath)) {
        return $false
    }
    try {
        $item = Get-Item -LiteralPath $script:SshConfigPath -Force
        return ((Get-FileSha256 -Path $script:SshConfigPath) -eq [string]$Snapshot.sha256) -and
            ((Get-Acl -LiteralPath $script:SshConfigPath).Sddl -eq [string]$Snapshot.sddl) -and
            ([int]$item.Attributes -eq [int]$Snapshot.attributes)
    } catch {
        return $false
    }
}

function Test-ManagedConfigCurrent {
    param([Parameter(Mandatory = $true)]$Record)

    return (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $script:SshConfigPath)) -and
        ((Get-FileSha256 -Path $script:SshConfigPath) -eq [string]$Record.managedConfigSha256) -and
        (Test-ManagedFileAcl -Path $script:SshConfigPath) -and
        ([int](Get-Item -LiteralPath $script:SshConfigPath -Force).Attributes -eq
            [int][IO.FileAttributes]::Normal)
}

function Test-ManagedConfigContentProtected {
    param([Parameter(Mandatory = $true)]$Record)

    return (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $script:SshConfigPath)) -and
        ((Get-FileSha256 -Path $script:SshConfigPath) -eq [string]$Record.managedConfigSha256) -and
        (Test-PathProtectedFromUntrustedMutation -Path $script:SshConfigPath)
}

function Remove-SshOwnershipMarker {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [bool]$AllowMissing = $false
    )

    $markerPath = Get-SshOwnershipMarkerPath
    if (-not (Test-Path -LiteralPath $markerPath)) {
        if ($AllowMissing) { return }
        throw 'The OpenSSH ownership marker is missing.'
    }
    if (-not (Test-SshOwnershipMarker -Record $Record)) {
        throw 'The OpenSSH ownership marker changed; refusing to remove it.'
    }
    Remove-Item -LiteralPath $markerPath -Force
}

function Restore-DefaultFirewallSnapshot {
    param([Parameter(Mandatory = $true)]$Record)

    $rules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore)
    $snapshot = $Record.original.defaultFirewall
    if ([bool]$snapshot.existed) {
        if ($rules.Count -ne 1) {
            throw 'Cannot restore the original OpenSSH firewall rule because its identity changed.'
        }
        if ((Get-FirewallRuleSemanticSha256 -Rule $rules[0]) -ne [string]$snapshot.semanticSha256) {
            throw 'Cannot restore the original OpenSSH firewall rule because its filters changed.'
        }
        if ([bool]$snapshot.enabled) {
            $rules[0] | Enable-NetFirewallRule | Out-Null
        } else {
            $rules[0] | Disable-NetFirewallRule | Out-Null
        }
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$Record.createdDefaultFirewallSemanticSha256)) {
        if ($rules.Count -gt 1) {
            throw 'Cannot remove the transaction-created OpenSSH firewall rule because its identity is ambiguous.'
        }
        if ($rules.Count -eq 1) {
            if ((Get-FirewallRuleSemanticSha256 -Rule $rules[0]) -ne [string]$Record.createdDefaultFirewallSemanticSha256) {
                throw 'Cannot remove the transaction-created OpenSSH firewall rule because its filters changed.'
            }
            $rules[0] | Remove-NetFirewallRule
        }
    } elseif ($rules.Count -gt 0) {
        throw 'An unowned default OpenSSH firewall rule appeared during the transaction.'
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

function Assert-GeneratedHostKeyRecordPairs {
    param([Parameter(Mandatory = $true)]$Records)

    $names = @($Records | ForEach-Object { ([string]$_.name).ToLowerInvariant() })
    $allowedNames = @(Get-ManagedHostKeyNames)
    foreach ($name in $names) {
        if ($name -notin $allowedNames) {
            throw "A generated host-key record has an unsupported name: '$name'."
        }
    }
    foreach ($type in $script:ManagedHostKeyTypes) {
        $privatePresent = $names -contains "ssh_host_$($type)_key"
        $publicPresent = $names -contains "ssh_host_$($type)_key.pub"
        if ($privatePresent -ne $publicPresent) {
            throw "A generated $type host-key record is missing its pair."
        }
    }
}

function Assert-SnapshotShape {
    param([Parameter(Mandatory = $true)]$Original)

    foreach ($value in @($Original.capabilityInstalled, $Original.sshDirectory.existed,
            $Original.config.existed, $Original.service.existed, $Original.defaultFirewall.existed,
            $Original.defaultFirewall.enabled)) {
        if ($value -isnot [bool]) { throw 'A recorded baseline boolean is invalid.' }
    }
    if ([string]$Original.capabilityState -notin @('Installed', 'NotPresent')) {
        throw 'The original OpenSSH capability state is not stable or supported.'
    }
    if ([bool]$Original.capabilityInstalled -ne
        ([string]$Original.capabilityState -eq 'Installed')) {
        throw 'The original OpenSSH capability ownership fields disagree.'
    }
    if ([bool]$Original.sshDirectory.existed) {
        Assert-ValidSecurityDescriptor -Sddl ([string]$Original.sshDirectory.sddl)
        try { [void][int]$Original.sshDirectory.attributes } catch { throw 'Invalid OpenSSH directory attributes.' }
    } elseif ([bool]$Original.config.existed -or (@($Original.hostKeyFiles).Count -ne 0)) {
        throw 'An absent OpenSSH directory baseline cannot contain config or host-key files.'
    }
    if ([bool]$Original.defaultFirewall.existed -and
        ([string]$Original.defaultFirewall.semanticSha256 -notmatch '^[0-9a-f]{64}$')) {
        throw 'Invalid original OpenSSH firewall semantic hash.'
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
    if ([string]$Original.service.status -notin @('', 'Running', 'Stopped')) {
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
    try { [void][uint32]$Original.service.processId } catch { throw 'Invalid original sshd process ID.' }
}

function Assert-ConfigSnapshotShape {
    param([Parameter(Mandatory = $true)]$Snapshot)

    if ($Snapshot.existed -isnot [bool]) { throw 'A recorded config existence flag is invalid.' }
    if ([bool]$Snapshot.existed) {
        $bytes = [Convert]::FromBase64String([string]$Snapshot.bytesBase64)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $embeddedHash = (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
        } finally {
            $sha.Dispose()
        }
        if (($embeddedHash -ne [string]$Snapshot.sha256) -or
            ([string]$Snapshot.sha256 -notmatch '^[0-9a-f]{64}$')) {
            throw 'Recorded config bytes do not match their hash.'
        }
        Assert-ValidSecurityDescriptor -Sddl ([string]$Snapshot.sddl)
        try { [void][int]$Snapshot.attributes } catch { throw 'Invalid recorded config attributes.' }
    }
}

function Assert-TransactionShape {
    param([Parameter(Mandatory = $true)]$Transaction)

    if ([string]$Transaction.transactionId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid install transaction ID.' }
    if ([string]$Transaction.accountMarker -ne "WRB:$($Transaction.transactionId)") { throw 'Invalid transaction account marker.' }
    Assert-AccountName -Name ([string]$Transaction.accountName)
    Assert-AllowedRemoteAddress -Values @($Transaction.allowedRemoteAddress)
    if (([int]$Transaction.port -lt 1) -or ([int]$Transaction.port -gt 65535)) { throw 'Invalid transaction SSH port.' }
    foreach ($hash in @([string]$Transaction.authorizedKeysCanonicalSha256,
            [string]$Transaction.managedConfigSha256, [string]$Transaction.sshDirectoryMarkerSha256)) {
        if ($hash -notmatch '^[0-9a-f]{64}$') { throw 'Invalid transaction SHA-256.' }
    }
    if ((-not [string]::IsNullOrWhiteSpace([string]$Transaction.authorizedKeysFileSha256)) -and
        ([string]$Transaction.authorizedKeysFileSha256 -notmatch '^[0-9a-f]{64}$')) {
        throw 'Invalid transaction authorized_keys hash.'
    }
    if ((Test-InstallPhaseReached -Transaction $Transaction -Phase 'host-key-staging') -and
        ([string]$Transaction.authorizedKeysFileSha256 -notmatch '^[0-9a-f]{64}$')) {
        throw 'The authorized_keys hash was not journaled before the next transaction phase.'
    }
    if (($Transaction.capabilityInstalledByTool -isnot [bool]) -or
        ($Transaction.takeOverExistingSshd -isnot [bool])) {
        throw 'Invalid transaction ownership flags.'
    }
    if (([string]$Transaction.cleanupKind -notin @('', 'rollback')) -or
        ((Get-CleanupPhaseIndex -Phase ([string]$Transaction.cleanupPhase)) -lt 0) -or
        ($Transaction.cleanupRemoveCapability -isnot [bool])) {
        throw 'Invalid install cleanup journal.'
    }
    try { [void][uint32]$Transaction.sshdProcessIdBeforeStop } catch { throw 'Invalid transaction sshd process ID.' }
    if (-not [string]::IsNullOrWhiteSpace([string]$Transaction.createdDefaultFirewallSemanticSha256) -and
        ([string]$Transaction.createdDefaultFirewallSemanticSha256 -notmatch '^[0-9a-f]{64}$')) {
        throw 'Invalid transaction-created OpenSSH firewall semantic hash.'
    }
    if ((Get-InstallPhaseIndex -Phase ([string]$Transaction.phase)) -lt 0) {
        throw 'Invalid install transaction phase.'
    }
    if ($null -ne $Transaction.accountSid -and
        -not [string]::IsNullOrWhiteSpace([string]$Transaction.accountSid) -and
        [string]$Transaction.accountSid -notmatch '^S-1-5-21-') {
        throw 'Invalid transaction account SID.'
    }
    Assert-SnapshotShape -Original $Transaction.original
    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'config') {
        if ($null -eq $Transaction.preManagedConfig) { throw 'The pre-managed config snapshot is missing.' }
        Assert-ConfigSnapshotShape -Snapshot $Transaction.preManagedConfig
    }
    Assert-HostKeyRecordsShape -Records @($Transaction.plannedHostKeyFiles)
    Assert-HostKeyRecordsShape -Records @($Transaction.generatedHostKeyFiles)
    Assert-GeneratedHostKeyRecordPairs -Records @($Transaction.plannedHostKeyFiles)
    Assert-GeneratedHostKeyRecordPairs -Records @($Transaction.generatedHostKeyFiles)
    Assert-HostKeyRecordsShape -Records @(@($Transaction.original.hostKeyFiles) + @($Transaction.generatedHostKeyFiles))
}

function Assert-StateShape {
    param([Parameter(Mandatory = $true)]$State)

    if ([string]$State.transactionId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid managed install ID.' }
    if ([string]$State.accountMarker -ne "WRB:$($State.transactionId)") { throw 'Invalid managed account marker.' }
    Assert-AccountName -Name ([string]$State.accountName)
    Assert-AllowedRemoteAddress -Values @($State.allowedRemoteAddress)
    if (([int]$State.port -lt 1) -or ([int]$State.port -gt 65535)) { throw 'Invalid managed SSH port.' }
    foreach ($hash in @([string]$State.authorizedKeysCanonicalSha256, [string]$State.authorizedKeysFileSha256,
            [string]$State.managedConfigSha256, [string]$State.sshDirectoryMarkerSha256)) {
        if ($hash -notmatch '^[0-9a-f]{64}$') { throw 'Managed state contains an invalid SHA-256.' }
    }
    if ([string]$State.hostKeyFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}={0,2}$') {
        throw 'Managed state contains an invalid host-key fingerprint.'
    }
    if ([string]$State.accountSid -notmatch '^S-1-5-21-') { throw 'Invalid managed account SID.' }
    if ([string]$State.firewallRuleName -ne $script:FirewallRuleName) { throw 'Invalid managed firewall rule identity.' }
    if (($State.openSshInstalledByTool -isnot [bool]) -or ($State.existingSshdTakenOver -isnot [bool])) {
        throw 'Invalid managed OpenSSH ownership flags.'
    }
    if (([string]$State.cleanupKind -notin @('', 'uninstall')) -or
        ((Get-CleanupPhaseIndex -Phase ([string]$State.cleanupPhase)) -lt 0) -or
        ($State.cleanupRemoveCapability -isnot [bool])) {
        throw 'Invalid uninstall cleanup journal.'
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$State.createdDefaultFirewallSemanticSha256) -and
        ([string]$State.createdDefaultFirewallSemanticSha256 -notmatch '^[0-9a-f]{64}$')) {
        throw 'Invalid managed default firewall semantic hash.'
    }
    Assert-SnapshotShape -Original $State.original
    Assert-HostKeyRecordsShape -Records @($State.generatedHostKeyFiles)
    Assert-GeneratedHostKeyRecordPairs -Records @($State.generatedHostKeyFiles)
    Assert-HostKeyRecordsShape -Records @(@($State.original.hostKeyFiles) + @($State.generatedHostKeyFiles))
    $hostKeyNames = @(@($State.original.hostKeyFiles) + @($State.generatedHostKeyFiles) |
        ForEach-Object { ([string]$_.name).ToLowerInvariant() })
    if ($hostKeyNames -notcontains 'ssh_host_ed25519_key') {
        throw 'Managed state does not contain the Ed25519 host key required by sshd_config.'
    }
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

    $reuseProtectedRoot = $false
    if (Test-Path -LiteralPath $script:RootPath) {
        Assert-TrustedProgramPath -Path $script:RootPath -Directory $true
        $unexpectedChildren = @(Get-ChildItem -LiteralPath $script:RootPath -Force)
        if ($unexpectedChildren.Count -gt 0) {
            throw "'$script:RootPath' contains data without trusted state; refusing to claim or delete it."
        }
        # A crash after deleting the final state record but before removing the
        # exact protected root leaves this one benign completion marker.
        $reuseProtectedRoot = $true
    }
    if ($null -ne (Get-LocalUserOrNull -Name $Name)) {
        throw "Local account '$Name' already exists without trusted state."
    }
    if (@(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore PersistentStore).Count -gt 0) {
        throw "Firewall rule '$script:FirewallRuleName' already exists without trusted state."
    }
    if (@(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore ActiveStore).Count -gt 0) {
        throw "An effective firewall policy already uses reserved rule name '$script:FirewallRuleName'."
    }

    $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
    if ([string]$capability.State -notin @('Installed', 'NotPresent')) {
        throw "OpenSSH capability servicing is not in a stable state ($($capability.State)). Finish Windows servicing or restart, then retry."
    }
    $serviceSnapshot = Get-ServiceSnapshot
    if ([bool]$serviceSnapshot.existed -and
        ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary)))) {
        throw 'The existing sshd service identity, DACL, or System32 OpenSSH binary boundary is unsafe.'
    }
    Assert-SafeExistingSshBaseline
    $sshDirectorySnapshot = Get-SshDirectorySnapshot
    $configSnapshot = Get-ConfigSnapshot
    $hostKeySnapshot = @(Get-HostKeyFileRecords)
    $sshdPath = Join-Path $script:SystemPath 'OpenSSH\sshd.exe'
    $existingWithoutCapability = ($capability.State -ne 'Installed') -and [bool]$serviceSnapshot.existed
    if (($capability.State -ne 'Installed') -and (-not [bool]$serviceSnapshot.existed) -and
        [bool]$sshDirectorySnapshot.existed) {
        throw 'OpenSSH capability is absent but an orphaned ProgramData\ssh directory exists. Move or remove that unowned directory before installing.'
    }
    if ($existingWithoutCapability -and (-not (Test-Path -LiteralPath $sshdPath -PathType Leaf))) {
        throw 'An existing sshd service does not use the supported in-box System32 location.'
    }
    $hasExistingSshd = ($capability.State -eq 'Installed') -or [bool]$serviceSnapshot.existed -or
        [bool]$sshDirectorySnapshot.existed -or [bool]$configSnapshot.existed -or ($hostKeySnapshot.Count -gt 0)
    if ($hasExistingSshd -and (-not $MayTakeOver)) {
        throw 'OpenSSH Server already exists. Rerun with -TakeOverExistingSshd only if replacing its entire access policy is intended.'
    }

    $defaultRules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore)
    if ($defaultRules.Count -gt 1) { throw 'More than one default OpenSSH firewall rule exists; refusing ambiguous takeover.' }
    $defaultFirewall = [ordered]@{
        existed = ($defaultRules.Count -eq 1)
        enabled = ($defaultRules.Count -eq 1) -and ([string]$defaultRules[0].Enabled -eq 'True')
        semanticSha256 = if ($defaultRules.Count -eq 1) { Get-FirewallRuleSemanticSha256 -Rule $defaultRules[0] } else { $null }
    }
    Assert-FirewallPreconditions -SshPort $SshPort -SshdExe $sshdPath

    $transactionId = [Guid]::NewGuid().ToString('N')
    $accountMarker = "WRB:$transactionId"
    $managedConfig = New-ManagedSshConfig -Name $Name -SshPort $SshPort
    $transaction = [ordered]@{
        schemaVersion = 2
        installerVersion = $script:InstallerVersion
        status = 'installing'
        phase = 'created'
        cleanupKind = ''
        cleanupPhase = 'none'
        cleanupRemoveCapability = $false
        transactionId = $transactionId
        createdAt = (Get-Date).ToUniversalTime().ToString('o')
        accountName = $Name
        accountMarker = $accountMarker
        accountSid = $null
        sshdProcessIdBeforeStop = 0
        port = $SshPort
        allowedRemoteAddress = @($RemoteAddress | Sort-Object -Unique)
        authorizedKeys = @($Keys)
        authorizedKeysCanonicalSha256 = $KeysCanonicalSha256
        authorizedKeysFileSha256 = $null
        managedConfigSha256 = Get-TextSha256 -Text $managedConfig
        sshDirectoryMarkerSha256 = Get-TextSha256 -Text $accountMarker
        takeOverExistingSshd = $hasExistingSshd
        capabilityInstalledByTool = ($capability.State -ne 'Installed') -and (-not $existingWithoutCapability)
        createdDefaultFirewallSemanticSha256 = $null
        plannedHostKeyFiles = @()
        generatedHostKeyFiles = @()
        preManagedConfig = $null
        original = [ordered]@{
            capabilityInstalled = ($capability.State -eq 'Installed')
            capabilityState = [string]$capability.State
            service = $serviceSnapshot
            sshDirectory = $sshDirectorySnapshot
            config = $configSnapshot
            defaultFirewall = $defaultFirewall
            hostKeyFiles = $hostKeySnapshot
        }
    }

    Initialize-ManagedCleanupRoot
    if (-not $reuseProtectedRoot) {
        New-ManagedDirectoryProtectedAtCreation -Path $script:RootPath
        Invoke-TestHook -Stage 'root-before-transaction'
    }
    Write-ProtectedJsonFile -Value $transaction -Path $script:TransactionPath
    $persisted = Get-InstallTransaction
    Assert-TransactionShape -Transaction $persisted
    return $persisted
}

function Update-InstallTransaction {
    param([Parameter(Mandatory = $true)]$Transaction)
    Write-ProtectedJsonFile -Value $Transaction -Path $script:TransactionPath
}

function Get-InstallPhaseIndex {
    param([Parameter(Mandatory = $true)][string]$Phase)

    for ($index = 0; $index -lt $script:InstallPhases.Count; $index++) {
        if ([string]$script:InstallPhases[$index] -eq $Phase) { return $index }
    }
    return -1
}

function Test-InstallPhaseReached {
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)][string]$Phase
    )

    return (Get-InstallPhaseIndex -Phase ([string]$Transaction.phase)) -ge
        (Get-InstallPhaseIndex -Phase $Phase)
}

function Enter-InstallPhase {
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)][string]$Phase
    )

    $currentIndex = Get-InstallPhaseIndex -Phase ([string]$Transaction.phase)
    $newIndex = Get-InstallPhaseIndex -Phase $Phase
    if (($currentIndex -lt 0) -or ($newIndex -lt 0)) { throw 'Unknown install transaction phase.' }
    if ($newIndex -lt $currentIndex) { throw 'Install transaction phase regression refused.' }
    if ($newIndex -gt ($currentIndex + 1)) { throw 'Install transaction phase skip refused.' }
    if ($newIndex -eq $currentIndex) { return }

    $Transaction.phase = $Phase
    Update-InstallTransaction -Transaction $Transaction
    $persisted = Get-InstallTransaction
    Assert-TransactionShape -Transaction $persisted
    if (([string]$persisted.transactionId -ne [string]$Transaction.transactionId) -or
        ([string]$persisted.phase -ne $Phase)) {
        throw 'Install transaction phase did not persist exactly.'
    }
}

function Get-CleanupPhaseIndex {
    param([Parameter(Mandatory = $true)][string]$Phase)

    for ($index = 0; $index -lt $script:CleanupPhases.Count; $index++) {
        if ([string]$script:CleanupPhases[$index] -eq $Phase) { return $index }
    }
    return -1
}

function Save-CleanupRecord {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind
    )

    if ($Kind -eq 'rollback') {
        Update-InstallTransaction -Transaction $Record
    } else {
        Write-ProtectedJsonFile -Value $Record -Path $script:StatePath
    }
}

function Initialize-CleanupRecord {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind,
        [Parameter(Mandatory = $true)][bool]$RemoveCapability
    )

    if ([string]::IsNullOrWhiteSpace([string]$Record.cleanupKind)) {
        $Record.cleanupKind = $Kind
        $Record.cleanupPhase = 'none'
        $Record.cleanupRemoveCapability = $RemoveCapability
        if ($Kind -eq 'rollback') { $Record.status = 'rolling-back' } else { $Record.status = 'uninstalling' }
        Save-CleanupRecord -Record $Record -Kind $Kind
    }
    if (([string]$Record.cleanupKind -ne $Kind) -or
        ([bool]$Record.cleanupRemoveCapability -ne $RemoveCapability) -or
        ((Get-CleanupPhaseIndex -Phase ([string]$Record.cleanupPhase)) -lt 0)) {
        throw 'The persisted cleanup ownership decision is invalid.'
    }
}

function Enter-CleanupPhase {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Phase
    )

    $currentIndex = Get-CleanupPhaseIndex -Phase ([string]$Record.cleanupPhase)
    $newIndex = Get-CleanupPhaseIndex -Phase $Phase
    if (($currentIndex -lt 0) -or ($newIndex -lt 0)) { throw 'Unknown cleanup journal phase.' }
    if ($newIndex -lt $currentIndex) { return }
    if ($newIndex -gt ($currentIndex + 1)) { throw 'Cleanup journal phase skip refused.' }
    if ($newIndex -eq $currentIndex) { return }
    $Record.cleanupPhase = $Phase
    Save-CleanupRecord -Record $Record -Kind $Kind
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

    $expectedRecords = @($Records | Sort-Object { ([string]$_.name).ToLowerInvariant() })
    $currentRecords = @(Get-HostKeyFileRecords | Sort-Object { ([string]$_.name).ToLowerInvariant() })
    if ($expectedRecords.Count -ne $currentRecords.Count) {
        throw 'The OpenSSH host-key file set changed during the transaction.'
    }
    for ($index = 0; $index -lt $expectedRecords.Count; $index++) {
        $record = $expectedRecords[$index]
        $current = $currentRecords[$index]
        $path = Join-Path $script:SshPath ([string]$record.name)
        if (([string]$record.name -ine [string]$current.name) -or
            ([string]$record.sha256 -ne [string]$current.sha256)) {
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
        if (Test-Path -LiteralPath $path) {
            if ((-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
                (Test-ReparsePoint -Path $path) -or
                ((Get-FileSha256 -Path $path) -ne [string]$record.sha256) -or
                ((Get-Acl -LiteralPath $path).Sddl -ne [string]$record.sddl) -or
                ([int](Get-Item -LiteralPath $path -Force).Attributes -ne [int]$record.attributes)) {
                throw "Generated host key changed after installation; refusing to delete it: $path"
            }
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Assert-HostKeySetSafeForRollback {
    param([Parameter(Mandatory = $true)]$Transaction)

    $allowed = @{}
    foreach ($record in @($Transaction.original.hostKeyFiles)) {
        $allowed[([string]$record.name).ToLowerInvariant()] = [ordered]@{ record = $record; original = $true }
    }
    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'host-keys') {
        foreach ($record in @($Transaction.plannedHostKeyFiles)) {
            $allowed[([string]$record.name).ToLowerInvariant()] = [ordered]@{ record = $record; original = $false }
        }
    }
    foreach ($current in @(Get-HostKeyFileRecords)) {
        $key = ([string]$current.name).ToLowerInvariant()
        if (-not $allowed.ContainsKey($key)) {
            throw "An unowned host-key-shaped file appeared during the transaction: $($current.name)"
        }
        $expected = $allowed[$key].record
        if (([string]$current.sha256 -ne [string]$expected.sha256) -or
            ([string]$current.sddl -ne [string]$expected.sddl) -or
            ([int]$current.attributes -ne [int]$expected.attributes)) {
            throw "A host key changed during the transaction: $($current.name)"
        }
    }
    foreach ($record in @($Transaction.original.hostKeyFiles)) {
        $path = Join-Path $script:SshPath ([string]$record.name)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "An original host key disappeared during the transaction: $($record.name)"
        }
    }
}

function Assert-InstallTransactionRollbackSafe {
    param([Parameter(Mandatory = $true)]$Transaction)

    Assert-TransactionShape -Transaction $Transaction
    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'ssh-directory') {
        if ([bool]$Transaction.original.sshDirectory.existed) {
            Assert-ExistingSshDirectoryUnchanged -Record $Transaction
        }
        $boundaryRetired = (Get-CleanupPhaseIndex -Phase ([string]$Transaction.cleanupPhase)) -ge
            (Get-CleanupPhaseIndex -Phase 'ssh-boundary')
        if ($boundaryRetired) {
            if ([bool]$Transaction.original.sshDirectory.existed) {
                Assert-ExistingSshDirectoryUnchanged -Record $Transaction
                $activeMarker = Get-SshOwnershipMarkerPath
                $retiredMarker = Get-RetiredSshMarkerPath
                $unpublished = ([string]$Transaction.phase -eq 'ssh-directory') -and
                    (-not (Test-Path -LiteralPath $activeMarker)) -and
                    (-not (Test-Path -LiteralPath $retiredMarker))
                if (-not $unpublished) {
                    if ((Test-Path -LiteralPath $activeMarker) -or
                        (-not (Test-OwnedMarkerAtPath -Path $retiredMarker -Record $Transaction))) {
                        throw 'The retired OpenSSH marker boundary changed during rollback.'
                    }
                }
            } else {
                $retired = Get-RetiredSshDirectoryPath
                $unpublished = ([string]$Transaction.phase -eq 'ssh-directory') -and
                    (-not (Test-Path -LiteralPath $script:SshPath)) -and
                    (-not (Test-Path -LiteralPath $retired))
                if (-not $unpublished) {
                    if ((Test-Path -LiteralPath $script:SshPath) -or
                        (-not (Test-Path -LiteralPath $retired -PathType Container))) {
                        throw 'The retired OpenSSH directory boundary changed during rollback.'
                    }
                    Assert-NewSshTreeOwned -Path $retired -Record $Transaction -Kind rollback
                }
            }
        } elseif (Test-Path -LiteralPath $script:SshPath) {
            if ((-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) -or
                (Test-ReparsePoint -Path $script:SshPath) -or
                (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:SshPath))) {
                throw 'The OpenSSH directory boundary changed during the transaction.'
            }
            $markerExists = Test-Path -LiteralPath (Get-SshOwnershipMarkerPath)
            if ($markerExists -and (-not (Test-SshOwnershipMarker -Record $Transaction))) {
                throw 'The OpenSSH ownership marker changed during the transaction.'
            }
            if ((-not $markerExists) -and ([string]$Transaction.phase -ne 'ssh-directory') -and
                ([string]$Transaction.status -ne 'rollback-restart-required')) {
                throw 'The OpenSSH ownership marker disappeared during the transaction.'
            }
            if ($markerExists -and (-not (Test-SshDirectoryBoundary -Record $Transaction))) {
                throw 'The OpenSSH directory security boundary drifted during the transaction.'
            }
        } elseif ([string]$Transaction.phase -ne 'ssh-directory') {
            throw 'The OpenSSH directory disappeared during the transaction.'
        }
    }

    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'capability') {
        $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
        if ([bool]$Transaction.capabilityInstalledByTool) {
            if ([string]$capability.State -notin @([string]$Transaction.original.capabilityState, 'Installed', 'InstallPending', 'UninstallPending')) {
                throw "The OpenSSH capability entered an unexpected state: $($capability.State)"
            }
        } elseif ([string]$capability.State -ne [string]$Transaction.original.capabilityState) {
            throw 'The externally owned OpenSSH capability state changed during the transaction.'
        }
    }

    $rollbackService = Get-SshdServiceOrNull
    if ((Test-InstallPhaseReached -Transaction $Transaction -Phase 'service-stop') -and
        ($null -ne $rollbackService) -and
        ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary)))) {
        throw 'The sshd service identity, DACL, or binary boundary changed during the transaction.'
    }

    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'default-firewall') {
        $defaultRules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore)
        if ([bool]$Transaction.original.defaultFirewall.existed) {
            if (($defaultRules.Count -ne 1) -or
                ((Get-FirewallRuleSemanticSha256 -Rule $defaultRules[0]) -ne
                    [string]$Transaction.original.defaultFirewall.semanticSha256)) {
                throw 'The original OpenSSH firewall rule changed during the transaction.'
            }
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$Transaction.createdDefaultFirewallSemanticSha256)) {
            if (($defaultRules.Count -gt 1) -or
                (($defaultRules.Count -eq 1) -and
                    ((Get-FirewallRuleSemanticSha256 -Rule $defaultRules[0]) -ne
                        [string]$Transaction.createdDefaultFirewallSemanticSha256))) {
                throw 'The transaction-created OpenSSH firewall rule changed.'
            }
        } elseif ($defaultRules.Count -gt 0) {
            throw 'An unowned default OpenSSH firewall rule appeared during the transaction.'
        }
    }

    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'account') {
        $account = Get-LocalUserOrNull -Name ([string]$Transaction.accountName)
        if ($null -ne $account) {
            $markerMatches = [string]$account.Description -eq [string]$Transaction.accountMarker
            $sidMatches = [string]::IsNullOrWhiteSpace([string]$Transaction.accountSid) -or
                ([string]$account.SID.Value -eq [string]$Transaction.accountSid)
            if (-not ($markerMatches -and $sidMatches)) {
                throw 'The transaction account identity changed during recovery.'
            }
        }
    }

    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'authorized-keys') {
        $keyStage = Get-AuthorizedKeysStagePath -Transaction $Transaction
        foreach ($path in @($keyStage, $script:KeyPath)) {
            if (-not (Test-Path -LiteralPath $path)) { continue }
            if ((-not (Test-Path -LiteralPath $path -PathType Leaf)) -or
                (Test-ReparsePoint -Path $path) -or
                (-not (Test-PathProtectedFromUntrustedMutation -Path $path))) {
                throw "An authorized_keys path changed identity: $path"
            }
            if ($path -eq $script:KeyPath) {
                if ([string]::IsNullOrWhiteSpace([string]$Transaction.authorizedKeysFileSha256) -or
                    ((Get-FileSha256 -Path $path) -ne [string]$Transaction.authorizedKeysFileSha256) -or
                    (-not (Test-ManagedFileAcl -Path $path))) {
                    throw 'The transaction-owned authorized_keys file changed.'
                }
            } elseif ((-not [string]::IsNullOrWhiteSpace([string]$Transaction.authorizedKeysFileSha256)) -and
                ((Get-FileSha256 -Path $path) -ne [string]$Transaction.authorizedKeysFileSha256)) {
                throw 'The authorized_keys staging file changed.'
            }
        }
    }

    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'host-key-staging') {
        Assert-HostKeySetSafeForRollback -Transaction $Transaction
        foreach ($name in @(Get-ManagedHostKeyNames)) {
            $stage = Get-PlannedHostKeyStagePath -Transaction $Transaction -Name $name
            if (-not (Test-Path -LiteralPath $stage)) { continue }
            if ((-not (Test-Path -LiteralPath $stage -PathType Leaf)) -or
                (Test-ReparsePoint -Path $stage) -or
                (-not (Test-PathProtectedFromUntrustedMutation -Path $stage `
                        -DenyUntrustedRead ($name -match '_key$')))) {
                throw "A host-key staging path changed identity: $stage"
            }
            $planned = @($Transaction.plannedHostKeyFiles | Where-Object { [string]$_.name -eq $name })
            if (($planned.Count -gt 0) -and ((Get-FileSha256 -Path $stage) -ne [string]$planned[0].sha256)) {
                throw "A host-key staging file changed content: $stage"
            }
        }
        Assert-HostKeyProbeTreeProtected -Transaction $Transaction
    }

    $configStage = Get-ManagedConfigStagePath -Transaction $Transaction
    if (Test-Path -LiteralPath $configStage) {
        if ((-not (Test-Path -LiteralPath $configStage -PathType Leaf)) -or
            (Test-ReparsePoint -Path $configStage) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $configStage))) {
            throw 'The managed sshd_config staging file changed.'
        }
        if ((Test-InstallPhaseReached -Transaction $Transaction -Phase 'config') -and
            (((Get-FileSha256 -Path $configStage) -ne [string]$Transaction.managedConfigSha256) -or
                (-not (Test-ManagedFileAcl -Path $configStage)))) {
            throw 'The committed managed sshd_config staging file changed.'
        }
    }
    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'config') {
        $configAllowed = (Test-ConfigMatchesSnapshot -Snapshot $Transaction.original.config) -or
            (Test-ManagedConfigCurrent -Record $Transaction) -or
            (Test-ManagedConfigContentProtected -Record $Transaction) -or
            (Test-ConfigMatchesSnapshot -Snapshot $Transaction.preManagedConfig) -or
            (Test-ConfigHasSnapshotContent -Snapshot $Transaction.original.config)
        if (-not (Test-Path -LiteralPath $script:SshConfigPath)) {
            $managedStageExact = (Test-Path -LiteralPath $configStage -PathType Leaf) -and
                (-not (Test-ReparsePoint -Path $configStage)) -and
                (Test-ManagedFileAcl -Path $configStage) -and
                ((Get-FileSha256 -Path $configStage) -eq [string]$Transaction.managedConfigSha256)
            $cleanupMayRestore = (Get-CleanupPhaseIndex -Phase ([string]$Transaction.cleanupPhase)) -ge
                (Get-CleanupPhaseIndex -Phase 'config')
            $configAllowed = $configAllowed -or $managedStageExact -or $cleanupMayRestore
        }
        if (-not $configAllowed) {
            throw 'The active sshd_config is neither the baseline nor a transaction-owned version.'
        }
    }

    if (Test-InstallPhaseReached -Transaction $Transaction -Phase 'firewall') {
        $ownedRules = @(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore PersistentStore)
        if (($ownedRules.Count -gt 1) -or
            (($ownedRules.Count -eq 1) -and
                (-not (Test-ManagedFirewallRule -SshPort ([int]$Transaction.port) `
                    -RemoteAddress @($Transaction.allowedRemoteAddress) `
                    -SshdExe (Join-Path $script:SystemPath 'OpenSSH\sshd.exe') `
                    -Marker ([string]$Transaction.accountMarker) -PolicyStore PersistentStore)))) {
            throw 'The transaction-owned firewall rule changed.'
        }
    }
}

function Remove-SshBoundaryStaging {
    param([Parameter(Mandatory = $true)]$Transaction)

    $markerStage = Join-Path $script:RootPath ("ssh-marker.$($Transaction.transactionId).tmp")
    if (Test-Path -LiteralPath $markerStage) {
        Remove-ProtectedStageFile -Path $markerStage
    }

    $directoryStage = Join-Path $script:RootPath ("ssh-directory.$($Transaction.transactionId).tmp")
    if (-not (Test-Path -LiteralPath $directoryStage)) { return }
    if ((-not (Test-Path -LiteralPath $directoryStage -PathType Container)) -or
        (Test-ReparsePoint -Path $directoryStage) -or
        (-not (Test-PathProtectedFromUntrustedMutation -Path $directoryStage))) {
        throw 'The OpenSSH directory staging path changed identity.'
    }
    $children = @(Get-ChildItem -LiteralPath $directoryStage -Force)
    foreach ($child in $children) {
        if ([string]$child.Name -eq 'logs') {
            if (-not (Test-SshLogsDirectoryProtected -Path $child.FullName -RequireEmpty $true -ManagedExact $true)) {
                throw 'The OpenSSH directory staging path contains an unsafe logs directory.'
            }
            [IO.Directory]::Delete($child.FullName, $false)
            continue
        }
        if (($child.Name -ne $script:SshOwnershipMarkerName) -or $child.PSIsContainer -or
            (Test-ReparsePoint -Path $child.FullName) -or
            (-not (Test-PathProtectedFromUntrustedMutation -Path $child.FullName))) {
            throw 'The OpenSSH directory staging path contains an unowned child.'
        }
        Remove-Item -LiteralPath $child.FullName -Force
    }
    Remove-Item -LiteralPath $directoryStage -Force
}

function Get-RetiredSshMarkerPath {
    return Join-Path $script:RootPath 'ssh-marker.retired'
}

function Get-RetiredSshDirectoryPath {
    return Join-Path $script:RootPath 'ssh-directory.retired'
}

function Test-OwnedMarkerAtPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Record
    )
    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $Path)) -and
        (Test-ManagedFileAcl -Path $Path) -and
        ((Get-FileSha256 -Path $Path) -eq [string]$Record.sshDirectoryMarkerSha256)
}

function Assert-ExistingSshDirectoryUnchanged {
    param([Parameter(Mandatory = $true)]$Record)

    if (-not [bool]$Record.original.sshDirectory.existed) {
        throw 'An existing-directory comparison was requested for an absent baseline.'
    }
    if ((-not (Test-Path -LiteralPath $script:SshPath -PathType Container)) -or
        (Test-ReparsePoint -Path $script:SshPath) -or
        (-not (Test-ParentProtectsChildFromUntrustedReplacement -ChildPath $script:SshPath)) -or
        (-not (Test-PathProtectedFromUntrustedMutation -Path $script:SshPath)) -or
        (-not (Test-SshLogsDirectoryProtected -Path $script:SshLogsPath)) -or
        ((Get-Acl -LiteralPath $script:SshPath).Sddl -ne [string]$Record.original.sshDirectory.sddl) -or
        ([int](Get-Item -LiteralPath $script:SshPath -Force).Attributes -ne
            [int]$Record.original.sshDirectory.attributes)) {
        throw 'The pre-existing OpenSSH directory metadata changed; refusing to overwrite it.'
    }
}

function Test-FileMatchesSnapshotAtPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Snapshot
    )

    if (-not [bool]$Snapshot.existed) { return -not (Test-Path -LiteralPath $Path) }
    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $Path)) -and
        ((Get-FileSha256 -Path $Path) -eq [string]$Snapshot.sha256) -and
        ((Get-Acl -LiteralPath $Path).Sddl -eq [string]$Snapshot.sddl) -and
        ([int](Get-Item -LiteralPath $Path -Force).Attributes -eq [int]$Snapshot.attributes)
}

function Test-ProtectedFileRecordAtPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Record
    )

    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $Path)) -and
        ((Get-FileSha256 -Path $Path) -eq [string]$Record.sha256) -and
        ((Get-Acl -LiteralPath $Path).Sddl -eq [string]$Record.sddl) -and
        ([int](Get-Item -LiteralPath $Path -Force).Attributes -eq [int]$Record.attributes)
}

function Assert-NewSshTreeOwned {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall', 'audit')][string]$Kind
    )

    if ([bool]$Record.original.sshDirectory.existed) {
        throw 'A newly-created-directory proof was requested for an existing baseline.'
    }
    if ((-not (Test-Path -LiteralPath $Path -PathType Container)) -or
        (Test-ReparsePoint -Path $Path) -or
        (-not (Test-ManagedDirectoryAcl -Path $Path))) {
        throw "The transaction-created OpenSSH directory changed identity: $Path"
    }

    $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
    $logsCount = 0
    foreach ($child in $children) {
        if (Test-ReparsePoint -Path $child.FullName) {
            throw "The transaction-created OpenSSH directory contains a reparse point: $($child.FullName)"
        }
        if ($child.PSIsContainer) {
            if (([string]$child.Name -ine 'logs') -or
                (-not (Test-SshLogsDirectoryProtected -Path $child.FullName -RequireEmpty $true -ManagedExact $true))) {
                throw "The transaction-created OpenSSH directory contains an unowned directory: $($child.FullName)"
            }
            $logsCount++
        }
    }
    if ($logsCount -ne 1) {
        throw 'The transaction-created OpenSSH directory must contain one exact, empty logs directory.'
    }

    $markerName = $script:SshOwnershipMarkerName.ToLowerInvariant()
    $configName = 'sshd_config'
    $markerCount = 0
    $configCount = 0
    $hostChildren = New-Object System.Collections.ArrayList
    foreach ($child in $children) {
        if ($child.PSIsContainer) { continue }
        $name = ([string]$child.Name).ToLowerInvariant()
        if ($name -eq $markerName) {
            $markerCount++
            if (-not (Test-OwnedMarkerAtPath -Path $child.FullName -Record $Record)) {
                throw 'The transaction-created OpenSSH directory marker changed.'
            }
        } elseif ($name -eq $configName) {
            $configCount++
        } elseif ($name -match '^ssh_host_[a-z0-9._-]+$') {
            [void]$hostChildren.Add($child)
        } else {
            throw "The transaction-created OpenSSH directory contains an unowned file: $($child.FullName)"
        }
    }
    if ($markerCount -ne 1) { throw 'The transaction-created OpenSSH directory must contain exactly one ownership marker.' }
    if ($configCount -gt 1) { throw 'The transaction-created OpenSSH directory contains an ambiguous sshd_config.' }

    $configPath = Join-Path $Path 'sshd_config'
    $preManaged = $null
    if (($null -ne $Record.PSObject.Properties['preManagedConfig']) -and ($null -ne $Record.preManagedConfig)) {
        $preManaged = $Record.preManagedConfig
    }
    $managedExact = (Test-Path -LiteralPath $configPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $configPath)) -and
        ((Get-FileSha256 -Path $configPath) -eq [string]$Record.managedConfigSha256) -and
        (Test-ManagedFileAcl -Path $configPath) -and
        ([int](Get-Item -LiteralPath $configPath -Force).Attributes -eq [int][IO.FileAttributes]::Normal)
    $managedProtected = (Test-Path -LiteralPath $configPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $configPath)) -and
        ((Get-FileSha256 -Path $configPath) -eq [string]$Record.managedConfigSha256) -and
        (Test-PathProtectedFromUntrustedMutation -Path $configPath)
    $preManagedExact = ($null -ne $preManaged) -and [bool]$preManaged.existed -and
        (Test-FileMatchesSnapshotAtPath -Path $configPath -Snapshot $preManaged)

    if ($Kind -in @('uninstall', 'audit')) {
        if (($configCount -ne 1) -or (-not $managedExact)) {
            throw 'The installed sshd_config is not the exact transaction-owned file.'
        }
    } else {
        $phaseIndex = Get-InstallPhaseIndex -Phase ([string]$Record.phase)
        $configPhase = Get-InstallPhaseIndex -Phase 'config'
        if ($phaseIndex -lt $configPhase) {
            if (($null -ne $preManaged) -and [bool]$preManaged.existed) {
                if (($configCount -ne 1) -or (-not $preManagedExact)) {
                    throw 'The pre-managed sshd_config changed before rollback.'
                }
            } elseif ($configCount -ne 0) {
                throw 'An unowned sshd_config appeared before the config phase.'
            }
        } elseif ($phaseIndex -eq $configPhase) {
            if (($configCount -eq 1) -and (-not ($managedProtected -or $preManagedExact))) {
                throw 'The interrupted sshd_config publication is not a recorded transaction state.'
            }
        } elseif (($configCount -ne 1) -or (-not $managedExact)) {
            throw 'The committed managed sshd_config changed before rollback.'
        }
    }

    $expectedRecords = @()
    $requireAllHostKeys = $false
    if ($Kind -in @('uninstall', 'audit')) {
        $expectedRecords = @($Record.generatedHostKeyFiles)
        $requireAllHostKeys = $true
    } else {
        $hostPhase = Get-InstallPhaseIndex -Phase 'host-keys'
        $phaseIndex = Get-InstallPhaseIndex -Phase ([string]$Record.phase)
        if ($phaseIndex -lt $hostPhase) {
            if ($hostChildren.Count -ne 0) { throw 'A host key appeared before the host-key publication phase.' }
            return
        }
        $expectedRecords = @($Record.plannedHostKeyFiles)
        $requireAllHostKeys = $phaseIndex -gt $hostPhase
    }
    $expectedByName = @{}
    foreach ($expected in $expectedRecords) {
        $expectedByName[([string]$expected.name).ToLowerInvariant()] = $expected
    }
    foreach ($child in @($hostChildren)) {
        $key = ([string]$child.Name).ToLowerInvariant()
        if (-not $expectedByName.ContainsKey($key)) {
            throw "An unrecorded host key appeared in the transaction-created OpenSSH directory: $($child.Name)"
        }
        if (-not (Test-ProtectedFileRecordAtPath -Path $child.FullName -Record $expectedByName[$key])) {
            throw "A transaction-owned host key changed: $($child.Name)"
        }
    }
    if ($requireAllHostKeys -and ($hostChildren.Count -ne $expectedRecords.Count)) {
        throw 'The transaction-owned host-key set is incomplete.'
    }
}

function Assert-OwnedTreeSafeToDelete {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ((-not (Test-Path -LiteralPath $Path -PathType Container)) -or
        (Test-ReparsePoint -Path $Path) -or
        (-not (Test-ManagedDirectoryAcl -Path $Path))) {
        throw "Owned cleanup root changed identity: $Path"
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)) {
        if (Test-ReparsePoint -Path $item.FullName) {
            throw "Owned cleanup tree contains a reparse point: $($item.FullName)"
        }
        $denyRead = (-not $item.PSIsContainer) -and ([string]$item.Name -match '^ssh_host_[A-Za-z0-9._-]+_key$')
        if (-not (Test-PathProtectedFromUntrustedMutation -Path $item.FullName -DenyUntrustedRead $denyRead)) {
            throw "Owned cleanup tree contains an unprotected path: $($item.FullName)"
        }
    }
}

function Retire-SshDirectoryBoundary {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind
    )

    $retiredMarker = Get-RetiredSshMarkerPath
    $retiredDirectory = Get-RetiredSshDirectoryPath
    if ((Test-Path -LiteralPath $retiredMarker) -and (Test-Path -LiteralPath $retiredDirectory)) {
        throw 'Both forms of retired OpenSSH ownership evidence exist.'
    }

    if ([bool]$Record.original.sshDirectory.existed) {
        Assert-ExistingSshDirectoryUnchanged -Record $Record
        if (Test-Path -LiteralPath $retiredDirectory) {
            throw 'An unexpected retired OpenSSH directory exists for an existing-directory baseline.'
        }
        if (Test-Path -LiteralPath $retiredMarker) {
            if (-not (Test-OwnedMarkerAtPath -Path $retiredMarker -Record $Record)) {
                throw 'The retired OpenSSH marker changed.'
            }
            if (Test-Path -LiteralPath (Get-SshOwnershipMarkerPath)) {
                throw 'Both active and retired OpenSSH markers exist.'
            }
            Assert-ExistingSshDirectoryUnchanged -Record $Record
            return
        }
        $sourceMarker = Get-SshOwnershipMarkerPath
        if (Test-Path -LiteralPath $sourceMarker) {
            if (-not (Test-OwnedMarkerAtPath -Path $sourceMarker -Record $Record)) {
                throw 'The active OpenSSH marker changed before retirement.'
            }
            [IO.File]::Move($sourceMarker, $retiredMarker)
            return
        }
        if (($Kind -eq 'rollback') -and ([string]$Record.phase -eq 'ssh-directory')) {
            # The write-ahead phase can persist before marker publication. The
            # original directory is not ours in that state and is left intact.
            return
        }
        throw 'OpenSSH marker ownership evidence disappeared before retirement.'
    }

    if (Test-Path -LiteralPath $retiredMarker) {
        throw 'An unexpected marker-only retirement exists for a new-directory baseline.'
    }
    if (Test-Path -LiteralPath $retiredDirectory) {
        if (Test-Path -LiteralPath $script:SshPath) {
            throw 'Both active and retired OpenSSH directories exist.'
        }
        Assert-NewSshTreeOwned -Path $retiredDirectory -Record $Record -Kind $Kind
        $marker = Join-Path $retiredDirectory $script:SshOwnershipMarkerName
        if (-not (Test-OwnedMarkerAtPath -Path $marker -Record $Record)) {
            throw 'The retired OpenSSH directory lost its ownership marker.'
        }
        return
    }
    if (-not (Test-Path -LiteralPath $script:SshPath)) {
        if (($Kind -eq 'rollback') -and ([string]$Record.phase -eq 'ssh-directory')) { return }
        throw 'The transaction-owned OpenSSH directory disappeared before retirement.'
    }
    if (-not (Test-SshDirectoryBoundary -Record $Record)) {
        if (($Kind -eq 'rollback') -and ([string]$Record.phase -eq 'ssh-directory') -and
            (-not (Test-Path -LiteralPath (Get-SshOwnershipMarkerPath)))) {
            throw 'An unowned OpenSSH path raced with directory publication; it was preserved for manual review.'
        }
        throw 'The active OpenSSH directory boundary changed before retirement.'
    }
    Assert-NewSshTreeOwned -Path $script:SshPath -Record $Record -Kind $Kind
    [IO.Directory]::Move($script:SshPath, $retiredDirectory)
    Assert-NewSshTreeOwned -Path $retiredDirectory -Record $Record -Kind $Kind
}

function Get-CleanupTombstonePath {
    param([Parameter(Mandatory = $true)][string]$TransactionId)
    if ($TransactionId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid cleanup tombstone transaction ID.' }
    return Join-Path $script:CleanupRootPath ("retired.$TransactionId")
}

function Get-CleanupRetiringPath {
    param([Parameter(Mandatory = $true)][string]$TransactionId)
    if ($TransactionId -notmatch '^[0-9a-f]{32}$') { throw 'Invalid cleanup retiring transaction ID.' }
    return Join-Path $script:CleanupRootPath ("retiring.$TransactionId")
}

function Get-CleanupAllowedRootNames {
    param([Parameter(Mandatory = $true)][string]$TransactionId)
    $names = New-Object System.Collections.ArrayList
    foreach ($name in @(
        'state.json', 'transaction.json', 'authorized_keys',
        'ssh-marker.retired', 'ssh-directory.retired',
        "ssh-marker.$TransactionId.tmp", "ssh-directory.$TransactionId.tmp",
        "authorized-keys.$TransactionId.staged", "sshd-config.$TransactionId.staged",
        "host-key-probe.$TransactionId",
        "config-restore.$TransactionId.next"
    )) { [void]$names.Add($name) }
    foreach ($hostKeyName in @(Get-ManagedHostKeyNames)) {
        $privateName = if ($hostKeyName.EndsWith('.pub', [StringComparison]::Ordinal)) {
            $hostKeyName.Substring(0, $hostKeyName.Length - 4)
        } else { $hostKeyName }
        $suffix = if ($hostKeyName.EndsWith('.pub', [StringComparison]::Ordinal)) {
            "$privateName.staged.pub"
        } else { "$privateName.staged" }
        [void]$names.Add("host-key.$TransactionId.$suffix")
    }
    return @($names)
}

function Get-CleanupRecordFromFrozenRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedId
    )

    $records = New-Object System.Collections.ArrayList
    foreach ($entry in @(
            [ordered]@{ name = 'state.json'; kind = 'state' },
            [ordered]@{ name = 'transaction.json'; kind = 'transaction' }
        )) {
        $recordPath = Join-Path $Path ([string]$entry.name)
        if (-not (Test-Path -LiteralPath $recordPath)) { continue }
        if ((-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $recordPath) -or
            (-not (Test-ManagedFileAcl -Path $recordPath))) {
            throw "A frozen cleanup journal changed identity: $recordPath"
        }
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        if ([string]$entry.kind -eq 'state') {
            Assert-StateShape -State $record
        } else {
            Assert-TransactionShape -Transaction $record
        }
        if ([string]$record.transactionId -ne $ExpectedId) {
            throw 'A frozen cleanup journal belongs to a different transaction.'
        }
        [void]$records.Add($record)
    }
    if ($records.Count -eq 0) { throw 'The frozen cleanup root has no trusted journal.' }
    $cleanupRecords = @($records | Where-Object {
            ([string]$_.cleanupPhase -eq 'root-retire') -and
            ([string]$_.cleanupKind -in @('rollback', 'uninstall'))
        })
    if ($cleanupRecords.Count -ne 1) {
        throw 'The frozen cleanup root does not contain one authoritative root-retire journal.'
    }
    return $cleanupRecords[0]
}

function Assert-CleanupRootReadyForRetirement {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Record
    )

    Assert-OwnedTreeSafeToDelete -Path $Path
    $id = [string]$Record.transactionId
    if ($id -notmatch '^[0-9a-f]{32}$') { throw 'The cleanup record has an invalid transaction ID.' }
    $allowedNames = @(Get-CleanupAllowedRootNames -TransactionId $id)
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) {
        if ([string]$child.Name -notin $allowedNames) {
            throw "Protected cleanup root contains an unowned child: $($child.FullName)"
        }
    }

    $keyPath = Join-Path $Path 'authorized_keys'
    if (Test-Path -LiteralPath $keyPath) {
        if ([string]$Record.authorizedKeysFileSha256 -notmatch '^[0-9a-f]{64}$' -or
            (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) -or
            (Test-ReparsePoint -Path $keyPath) -or
            (-not (Test-ManagedFileAcl -Path $keyPath)) -or
            ((Get-FileSha256 -Path $keyPath) -ne [string]$Record.authorizedKeysFileSha256)) {
            throw 'The protected cleanup root contains an invalid authorized_keys file.'
        }
    }

    $retiredMarker = Join-Path $Path 'ssh-marker.retired'
    $retiredDirectory = Join-Path $Path 'ssh-directory.retired'
    if ([bool]$Record.original.sshDirectory.existed) {
        if (Test-Path -LiteralPath $retiredDirectory) {
            throw 'An existing-directory cleanup unexpectedly contains a retired SSH tree.'
        }
        $boundaryWasOwned = ([string]$Record.cleanupKind -eq 'uninstall') -or
            (Test-InstallPhaseReached -Transaction $Record -Phase 'ssh-directory')
        $unpublished = ([string]$Record.cleanupKind -eq 'rollback') -and
            ([string]$Record.phase -eq 'ssh-directory') -and
            (-not (Test-Path -LiteralPath $retiredMarker))
        if ($boundaryWasOwned -and (-not $unpublished) -and
            (-not (Test-OwnedMarkerAtPath -Path $retiredMarker -Record $Record))) {
            throw 'The frozen cleanup root lost its retired SSH marker.'
        }
    } else {
        if (Test-Path -LiteralPath $retiredMarker) {
            throw 'A new-directory cleanup unexpectedly contains a marker-only retirement.'
        }
        $unpublished = ([string]$Record.cleanupKind -eq 'rollback') -and
            ([string]$Record.phase -eq 'ssh-directory') -and
            (-not (Test-Path -LiteralPath $retiredDirectory))
        if (-not $unpublished) {
            Assert-NewSshTreeOwned -Path $retiredDirectory -Record $Record -Kind ([string]$Record.cleanupKind)
        }
    }
}

function Remove-CleanupTombstone {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-OwnedTreeSafeToDelete -Path $Path
    if (([string]$env:GITHUB_ACTIONS -eq 'true') -and
        ([string]$env:WRB_TEST_CRASH_AFTER -eq 'cleanup-tombstone-partial')) {
        # Delete the authoritative journal first. Recovery from a committed
        # retired.* tombstone must never depend on a record that recursive
        # deletion may already have removed before a power loss.
        $journalChild = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop |
            Where-Object { [string]$_.Name -in @('state.json', 'transaction.json') } |
            Sort-Object Name | Select-Object -First 1
        if ($null -eq $journalChild) {
            throw 'The partial-tombstone test hook found no cleanup journal to delete.'
        }
        Remove-Item -LiteralPath $journalChild.FullName -Force -ErrorAction Stop
        Invoke-TestHook -Stage 'cleanup-tombstone-partial'
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}

function Remove-StaleCleanupTombstones {
    if (-not (Test-Path -LiteralPath $script:CleanupRootPath)) { return }
    Assert-ManagedCleanupRoot
    $allChildren = @(Get-ChildItem -LiteralPath $script:CleanupRootPath -Force -ErrorAction Stop)
    if ($allChildren.Count -gt 1) {
        throw 'The protected cleanup directory contains more than one recovery object.'
    }
    if ((Test-Path -LiteralPath $script:RootPath) -and ($allChildren.Count -gt 0)) {
        throw 'Active state and a frozen cleanup object unexpectedly coexist.'
    }

    foreach ($item in @($allChildren | Where-Object { [string]$_.Name -like 'retiring.*' })) {
        if ((-not $item.PSIsContainer) -or
            ([string]$item.Name -notmatch '^retiring\.([0-9a-f]{32})$')) {
            throw "An invalid retiring cleanup root blocks safe recovery: $($item.FullName)"
        }
        $id = [string]$Matches[1]
        if (Test-Path -LiteralPath (Get-CleanupTombstonePath -TransactionId $id)) {
            throw 'Both retiring and retired cleanup roots exist for one transaction.'
        }
        $record = Get-CleanupRecordFromFrozenRoot -Path $item.FullName -ExpectedId $id
        Assert-CleanupRootReadyForRetirement -Path $item.FullName -Record $record
        [IO.Directory]::Move($item.FullName, (Get-CleanupTombstonePath -TransactionId $id))
    }

    $retiredChildren = @(Get-ChildItem -LiteralPath $script:CleanupRootPath -Force -ErrorAction Stop)
    foreach ($item in @($retiredChildren | Where-Object { [string]$_.Name -like 'retired.*' })) {
        if ((-not $item.PSIsContainer) -or
            ([string]$item.Name -notmatch '^retired\.[0-9a-f]{32}$')) {
            throw "An invalid cleanup tombstone blocks safe recovery: $($item.FullName)"
        }
        Remove-CleanupTombstone -Path $item.FullName
    }

    $remaining = @(Get-ChildItem -LiteralPath $script:CleanupRootPath -Force -ErrorAction Stop)
    if ($remaining.Count -gt 0) {
        throw "The protected cleanup directory contains an unknown object: $($remaining[0].FullName)"
    }
    if (-not (Test-Path -LiteralPath $script:RootPath)) {
        Assert-ManagedCleanupRoot -RequireEmpty $true
        [IO.Directory]::Delete($script:CleanupRootPath, $false)
    }
}

function Complete-RootRetirement {
    param([Parameter(Mandatory = $true)]$Record)

    $id = [string]$Record.transactionId
    Assert-ManagedCleanupRoot -RequireEmpty $true
    Assert-CleanupRootReadyForRetirement -Path $script:RootPath -Record $Record
    $savedState = Get-SavedState
    if (($null -ne $savedState) -and ([string]$savedState.transactionId -ne $id)) {
        throw 'Cleanup state belongs to a different transaction.'
    }
    $savedTransaction = Get-InstallTransaction
    if (($null -ne $savedTransaction) -and ([string]$savedTransaction.transactionId -ne $id)) {
        throw 'Cleanup transaction belongs to a different install.'
    }
    $retiring = Get-CleanupRetiringPath -TransactionId $id
    $tombstone = Get-CleanupTombstonePath -TransactionId $id
    if ((Test-Path -LiteralPath $retiring) -or (Test-Path -LiteralPath $tombstone)) {
        throw 'A cleanup retirement path already exists for this transaction.'
    }
    [IO.Directory]::Move($script:RootPath, $retiring)
    Invoke-TestHook -Stage 'cleanup-root-after-freeze'
    $frozenRecord = Get-CleanupRecordFromFrozenRoot -Path $retiring -ExpectedId $id
    Assert-CleanupRootReadyForRetirement -Path $retiring -Record $frozenRecord
    [IO.Directory]::Move($retiring, $tombstone)
    Invoke-TestHook -Stage 'cleanup-root-after-commit'
    Remove-CleanupTombstone -Path $tombstone
    Assert-ManagedCleanupRoot -RequireEmpty $true
    [IO.Directory]::Delete($script:CleanupRootPath, $false)
}

function Test-ServiceMatchesSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)
    try {
        $current = Get-ServiceSnapshot
        if ([bool]$current.existed -ne [bool]$Snapshot.existed) { return $false }
        if (-not [bool]$Snapshot.existed) { return $true }
        if ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary))) { return $false }
        return ([string]$current.status -eq [string]$Snapshot.status) -and
            ([string]$current.startType -eq [string]$Snapshot.startType) -and
            ([string]$current.startName -eq [string]$Snapshot.startName) -and
            ([string]$current.pathName -eq [string]$Snapshot.pathName)
    } catch { return $false }
}

function Test-ServiceSafeForRestore {
    param([Parameter(Mandatory = $true)]$Snapshot)
    if (Test-ServiceMatchesSnapshot -Snapshot $Snapshot) { return $true }
    if (-not [bool]$Snapshot.existed) {
        try { return $null -eq (Get-SshdServiceOrNull) } catch { return $false }
    }
    if ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary))) { return $false }
    try {
        $current = Get-ServiceSnapshot
        return ([string]$current.status -in @('Running', 'Stopped')) -and
            ([string]$current.startType -in @('Automatic', [string]$Snapshot.startType)) -and
            ([string]$current.startName -eq [string]$Snapshot.startName) -and
            ([string]$current.pathName -eq [string]$Snapshot.pathName)
    } catch { return $false }
}

function Test-HostKeysMatchSnapshot {
    param([Parameter(Mandatory = $true)]$Records)
    try {
        $expected = @($Records | Sort-Object { ([string]$_.name).ToLowerInvariant() })
        $actual = @(Get-HostKeyFileRecords | Sort-Object { ([string]$_.name).ToLowerInvariant() })
        if ($expected.Count -ne $actual.Count) { return $false }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if (([string]$expected[$index].name -ine [string]$actual[$index].name) -or
                ([string]$expected[$index].sha256 -ne [string]$actual[$index].sha256) -or
                ([string]$expected[$index].sddl -ne [string]$actual[$index].sddl) -or
                ([int]$expected[$index].attributes -ne [int]$actual[$index].attributes)) {
                return $false
            }
        }
        return $true
    } catch { return $false }
}

function Test-DefaultFirewallMatchesSnapshot {
    param([Parameter(Mandatory = $true)]$Record)
    try {
        $rules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore)
        $snapshot = $Record.original.defaultFirewall
        if (-not [bool]$snapshot.existed) { return $rules.Count -eq 0 }
        return ($rules.Count -eq 1) -and
            ((Get-FirewallRuleSemanticSha256 -Rule $rules[0]) -eq [string]$snapshot.semanticSha256) -and
            (([string]$rules[0].Enabled -eq 'True') -eq [bool]$snapshot.enabled)
    } catch { return $false }
}

function Invoke-CapabilityCleanup {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind
    )

    $originalState = [string]$Record.original.capabilityState
    $current = Get-WindowsCapability -Online -Name $script:CapabilityName
    if (-not [bool]$Record.cleanupRemoveCapability) {
        if ([string]$current.State -ne $originalState) {
            throw 'The externally owned OpenSSH capability changed during cleanup.'
        }
        return $false
    }
    if ([string]$current.State -eq $originalState) { return $false }
    if ([string]$current.State -in @('InstallPending', 'UninstallPending')) {
        $Record.status = if ($Kind -eq 'rollback') { 'rollback-restart-required' } else { 'uninstall-restart-required' }
        Save-CleanupRecord -Record $Record -Kind $Kind
        return $true
    }
    if ([string]$current.State -ne 'Installed') {
        throw "OpenSSH capability entered an unexpected cleanup state: $($current.State)"
    }
    $removeResult = Remove-WindowsCapability -Online -Name $script:CapabilityName
    $after = Get-WindowsCapability -Online -Name $script:CapabilityName
    if ($removeResult.RestartNeeded -or ([string]$after.State -in @('InstallPending', 'UninstallPending', 'Installed'))) {
        $Record.status = if ($Kind -eq 'rollback') { 'rollback-restart-required' } else { 'uninstall-restart-required' }
        Save-CleanupRecord -Record $Record -Kind $Kind
        return $true
    }
    if ([string]$after.State -ne $originalState) {
        throw "OpenSSH capability removal did not restore '$originalState': $($after.State)"
    }
    return $false
}

function Assert-CleanupBaselineConverged {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind
    )

    $accountWasOwned = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'account')
    if ($accountWasOwned -and
        ($null -ne (Get-LocalUserOrNull -Name ([string]$Record.accountName)))) {
        throw 'The managed local account remains after cleanup.'
    }
    $authorizedKeyRelevant = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'authorized-keys')
    if ($authorizedKeyRelevant -and (Test-Path -LiteralPath $script:KeyPath)) {
        if ((-not (Test-ManagedFileAcl -Path $script:KeyPath)) -or
            ([string]::IsNullOrWhiteSpace([string]$Record.authorizedKeysFileSha256) -or
            ((Get-FileSha256 -Path $script:KeyPath) -ne [string]$Record.authorizedKeysFileSha256))) {
            throw 'The managed authorized_keys file changed during cleanup.'
        }
    } elseif (($Kind -eq 'uninstall') -and (-not (Test-Path -LiteralPath $script:KeyPath))) {
        throw 'The managed authorized_keys file disappeared during cleanup.'
    }
    $firewallWasOwned = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'firewall')
    if ($firewallWasOwned -and
        (@(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore PersistentStore).Count -ne 0 -or
        @(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore ActiveStore).Count -ne 0)) {
        throw 'The managed firewall rule remains after cleanup.'
    }
    $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
    $capabilityWasTouched = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'capability')
    if ($capabilityWasTouched -and ([string]$capability.State -ne [string]$Record.original.capabilityState)) {
        throw 'The OpenSSH capability did not return to its baseline state.'
    }
    $defaultFirewallWasTouched = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'default-firewall')
    if ($defaultFirewallWasTouched -and (-not (Test-DefaultFirewallMatchesSnapshot -Record $Record))) {
        throw 'The default OpenSSH firewall rule did not return to its baseline state.'
    }
    $serviceWasTouched = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'service-stop')
    if ($serviceWasTouched -and (-not (Test-ServiceMatchesSnapshot -Snapshot $Record.original.service))) {
        throw 'The sshd service did not return to its baseline state.'
    }

    $boundaryWasOwned = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'ssh-directory')
    if ([bool]$Record.original.sshDirectory.existed) {
        $configWasTouched = ($Kind -eq 'uninstall') -or
            (Test-InstallPhaseReached -Transaction $Record -Phase 'config')
        $hostKeysWereTouched = ($Kind -eq 'uninstall') -or
            (Test-InstallPhaseReached -Transaction $Record -Phase 'host-keys')
        Assert-ExistingSshDirectoryUnchanged -Record $Record
        if ($configWasTouched -and (-not (Test-ConfigMatchesSnapshot -Snapshot $Record.original.config))) {
            throw 'The original sshd_config did not return to its exact baseline.'
        }
        if ($hostKeysWereTouched -and
            (-not (Test-HostKeysMatchSnapshot -Records @($Record.original.hostKeyFiles)))) {
            throw 'The original host keys did not return to their exact baseline.'
        }
        if ((-not $configWasTouched) -or (-not $hostKeysWereTouched)) {
            Assert-SafeExistingSshBaseline
        }
        if ($boundaryWasOwned -and
            (-not (Test-OwnedMarkerAtPath -Path (Get-RetiredSshMarkerPath) -Record $Record))) {
            if (-not (($Kind -eq 'rollback') -and ([string]$Record.phase -eq 'ssh-directory'))) {
                throw 'Retired OpenSSH marker evidence is missing.'
            }
        }
        if ($boundaryWasOwned -and (Test-Path -LiteralPath (Get-SshOwnershipMarkerPath))) {
            throw 'The active OpenSSH ownership marker remains after retirement.'
        }
    } else {
        if (-not $boundaryWasOwned) {
            if (Test-Path -LiteralPath $script:SshPath) {
                throw 'An OpenSSH data path appeared before the installer claimed it.'
            }
            return
        }
        $retiredDirectory = Get-RetiredSshDirectoryPath
        $unpublished = ($Kind -eq 'rollback') -and ([string]$Record.phase -eq 'ssh-directory') -and
            (-not (Test-Path -LiteralPath $script:SshPath)) -and
            (-not (Test-Path -LiteralPath $retiredDirectory))
        if (-not $unpublished) {
            if (Test-Path -LiteralPath $script:SshPath) {
                throw 'The transaction-created OpenSSH data directory remains after cleanup.'
            }
            if (-not (Test-Path -LiteralPath $retiredDirectory -PathType Container)) {
                throw 'Retired OpenSSH directory evidence is missing.'
            }
            Assert-NewSshTreeOwned -Path $retiredDirectory -Record $Record -Kind $Kind
        }
    }
}

function Invoke-OwnedCleanup {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [ValidateSet('rollback', 'uninstall')][string]$Kind
    )

    # This fixed, protected parent is the only namespace into which destructive
    # cleanup may freeze the managed root. Prove it before the first mutation.
    Assert-ManagedCleanupRoot -RequireEmpty $true

    $removeCapability = if ($Kind -eq 'rollback') {
        [bool]$Record.capabilityInstalledByTool -and
            (Test-InstallPhaseReached -Transaction $Record -Phase 'capability')
    } else {
        [bool]$Record.openSshInstalledByTool
    }
    Initialize-CleanupRecord -Record $Record -Kind $Kind -RemoveCapability $removeCapability

    $forwardStopped = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'service-stop')
    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'service-stop'
    # The forward install sets sshd to Automatic. If Windows restarts during a
    # later cleanup phase, SCM can start it again. Re-establish the stopped
    # invariant on every cleanup entry before touching policy, keys, or config.
    $cleanupCanStillTouchSshInputs = (Get-CleanupPhaseIndex -Phase ([string]$Record.cleanupPhase)) -le
        (Get-CleanupPhaseIndex -Phase 'service-restore')
    $cleanupService = Get-SshdServiceOrNull
    if ($forwardStopped -and $cleanupCanStillTouchSshInputs -and
        ($null -ne $cleanupService)) {
        Stop-SshdAndWait
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'firewall'
    $forwardFirewall = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'firewall')
    if (([string]$Record.cleanupPhase -eq 'firewall') -and $forwardFirewall) {
        $rules = @(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore PersistentStore)
        if ($rules.Count -gt 1) { throw 'The managed firewall rule identity is ambiguous during cleanup.' }
        if ($rules.Count -eq 1) {
            if ((-not (Test-ManagedFirewallRule -SshPort ([int]$Record.port) `
                    -RemoteAddress @($Record.allowedRemoteAddress) `
                    -SshdExe (Join-Path $script:SystemPath 'OpenSSH\sshd.exe') `
                    -Marker ([string]$Record.accountMarker) -PolicyStore PersistentStore)) -or
                (-not (Test-ManagedFirewallRule -SshPort ([int]$Record.port) `
                    -RemoteAddress @($Record.allowedRemoteAddress) `
                    -SshdExe (Join-Path $script:SystemPath 'OpenSSH\sshd.exe') `
                    -Marker ([string]$Record.accountMarker) -PolicyStore ActiveStore))) {
                throw 'The managed firewall rule changed during cleanup.'
            }
            $rules[0] | Remove-NetFirewallRule -ErrorAction Stop
        }
        if (@(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore ActiveStore).Count -ne 0) {
            throw 'An effective policy still defines the managed firewall rule after local removal.'
        }
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'account'
    $forwardAccount = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'account')
    if (([string]$Record.cleanupPhase -eq 'account') -and $forwardAccount) {
        $account = Get-LocalUserOrNull -Name ([string]$Record.accountName)
        if ($null -ne $account) {
            if ([string]$account.Description -ne [string]$Record.accountMarker) {
                throw 'The managed account marker changed during cleanup.'
            }
            if ([string]::IsNullOrWhiteSpace([string]$Record.accountSid)) {
                $Record.accountSid = [string]$account.SID.Value
                Save-CleanupRecord -Record $Record -Kind $Kind
            } elseif ([string]$account.SID.Value -ne [string]$Record.accountSid) {
                throw 'The managed account SID changed during cleanup.'
            }
            Remove-LocalUser -Name ([string]$Record.accountName)
        }
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'capability'
    if ([string]$Record.cleanupPhase -eq 'capability') {
        $forwardCapability = ($Kind -eq 'uninstall') -or
            (Test-InstallPhaseReached -Transaction $Record -Phase 'capability')
        if ($forwardCapability) {
            if (Invoke-CapabilityCleanup -Record $Record -Kind $Kind) {
                return [ordered]@{ restartRequired = $true }
            }
        }
        $Record.status = if ($Kind -eq 'rollback') { 'rolling-back' } else { 'uninstalling' }
        Save-CleanupRecord -Record $Record -Kind $Kind
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'ssh-boundary'
    $forwardBoundary = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'ssh-directory')
    if (([string]$Record.cleanupPhase -eq 'ssh-boundary') -and $forwardBoundary) {
        Retire-SshDirectoryBoundary -Record $Record -Kind $Kind
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'config'
    $forwardConfig = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'config')
    if (([string]$Record.cleanupPhase -eq 'config') -and
        ($forwardConfig -or ((-not [bool]$Record.original.config.existed) -and $removeCapability))) {
        if (-not (Test-Path -LiteralPath (Get-RetiredSshDirectoryPath))) {
            if ([bool]$Record.original.sshDirectory.existed) {
                Assert-ExistingSshDirectoryUnchanged -Record $Record
            }
            Restore-ConfigSnapshot -Record $Record
        }
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'host-keys'
    $forwardHostKeys = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'host-keys')
    if (([string]$Record.cleanupPhase -eq 'host-keys') -and $forwardHostKeys -and
        (-not (Test-Path -LiteralPath (Get-RetiredSshDirectoryPath)))) {
        if ([bool]$Record.original.sshDirectory.existed) {
            Assert-ExistingSshDirectoryUnchanged -Record $Record
        }
        $generated = if ($Kind -eq 'rollback') { @($Record.plannedHostKeyFiles) } else { @($Record.generatedHostKeyFiles) }
        Remove-GeneratedHostKeys -Records $generated
        if (-not (Test-HostKeysMatchSnapshot -Records @($Record.original.hostKeyFiles))) {
            throw 'The original OpenSSH host keys changed during cleanup.'
        }
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'default-firewall'
    $forwardDefaultFirewall = ($Kind -eq 'uninstall') -or
        (Test-InstallPhaseReached -Transaction $Record -Phase 'default-firewall')
    if (([string]$Record.cleanupPhase -eq 'default-firewall') -and $forwardDefaultFirewall) {
        Restore-DefaultFirewallSnapshot -Record $Record
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'service-restore'
    if (([string]$Record.cleanupPhase -eq 'service-restore') -and $forwardStopped) {
        if ([bool]$Record.original.sshDirectory.existed) {
            Assert-ExistingSshDirectoryUnchanged -Record $Record
        }
        if (-not (Test-ServiceSafeForRestore -Snapshot $Record.original.service)) {
            throw 'The sshd service changed after cleanup began; refusing to overwrite it.'
        }
        if (-not (Test-ServiceMatchesSnapshot -Snapshot $Record.original.service)) {
            Restore-ServiceSnapshot -Snapshot $Record.original.service
        }
    }

    Enter-CleanupPhase -Record $Record -Kind $Kind -Phase 'root-retire'
    if ([string]$Record.cleanupPhase -eq 'root-retire') {
        if ([bool]$Record.original.sshDirectory.existed) {
            Assert-ExistingSshDirectoryUnchanged -Record $Record
        }
        if ($forwardStopped -and (-not (Test-ServiceMatchesSnapshot -Snapshot $Record.original.service))) {
            if (-not (Test-ServiceSafeForRestore -Snapshot $Record.original.service)) {
                throw 'The sshd service changed after service restoration; refusing to overwrite it.'
            }
            Restore-ServiceSnapshot -Snapshot $Record.original.service
        }
        Remove-PlannedHostKeyStagingFiles -Transaction $Record
        Remove-SshBoundaryStaging -Transaction $Record
        Assert-CleanupBaselineConverged -Record $Record -Kind $Kind
        Complete-RootRetirement -Record $Record
    }
    return [ordered]@{ restartRequired = $false }
}

function Undo-InstallTransaction {
    param([Parameter(Mandatory = $true)]$Transaction)

    Assert-InstallTransactionRollbackSafe -Transaction $Transaction
    $result = Invoke-OwnedCleanup -Record $Transaction -Kind rollback
    if ([bool]$result.restartRequired) {
        throw 'Rollback requires a Windows restart. Restart, then run the exact same installer command again.'
    }
}

function Test-SshdListenerExact {
    param([Parameter(Mandatory = $true)][int]$SshPort)

    try {
        $services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
        if (($services.Count -ne 1) -or ([uint32]$services[0].ProcessId -eq 0)) { return $false }
        $listeners = @(Get-NetTCPConnection -State Listen `
                -OwningProcess ([uint32]$services[0].ProcessId) -ErrorAction Stop)
        if ($listeners.Count -eq 0) { return $false }
        $ports = @($listeners | Select-Object -ExpandProperty LocalPort -Unique)
        return ($ports.Count -eq 1) -and ([int]$ports[0] -eq $SshPort)
    } catch {
        return $false
    }
}

function New-InstalledReceipt {
    param([Parameter(Mandatory = $true)]$State, [bool]$Idempotent = $false)

    return [ordered]@{
        status = 'installed'
        idempotent = $Idempotent
        installerVersion = $script:InstallerVersion
        computerName = $env:COMPUTERNAME
        ipv4 = @(Get-ActiveIPv4Addresses)
        openSsh = [ordered]@{
            capabilityState = 'Installed'
            installedByThisTool = [bool]$State.openSshInstalledByTool
        }
        ssh = [ordered]@{
            user = [string]$State.accountName
            port = [int]$State.port
            allowedRemoteAddress = @($State.allowedRemoteAddress)
            hostKeyFingerprint = [string]$State.hostKeyFingerprint
            authorizedKeyFingerprints = @($State.keyFingerprints)
        }
        verification = [ordered]@{
            openSsh = $(if ([bool]$State.openSshInstalledByTool -or [bool]$State.original.capabilityInstalled) {
                'Windows capability/Installed'
            } else {
                'Existing in-box System32 service'
            })
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
        if ([string]$transaction.status -eq 'restart-required') {
            $capabilityAfterRestart = Get-WindowsCapability -Online -Name $script:CapabilityName
            if ([string]$capabilityAfterRestart.State -ne 'Installed') {
                return [ordered]@{
                    status = 'restart-required'
                    installerVersion = $script:InstallerVersion
                    computerName = $env:COMPUTERNAME
                    nextStep = 'Restart Windows, then run the exact same installation command.'
                }
            }
            $transaction.status = 'installing'
            Update-InstallTransaction -Transaction $transaction
        } else {
            # An installing transaction without committed state represents an
            # interrupted run. Safely restore its baseline, then start afresh.
            Undo-InstallTransaction -Transaction $transaction
            $transaction = $null
        }
    }
    if ($null -eq $transaction) {
        $transaction = New-InstallTransaction -Keys $keys -KeysCanonicalSha256 $canonicalKeyHash `
            -Name $Name -SshPort $SshPort -RemoteAddress $RemoteAddress -MayTakeOver $MayTakeOver
    }

    try {
        if ([string]$transaction.phase -eq 'created') {
            Enter-InstallPhase -Transaction $transaction -Phase 'ssh-directory'
            Establish-SshDirectoryBoundary -Transaction $transaction
            Invoke-TestHook -Stage 'ssh-directory'
        }
        if (-not (Test-SshDirectoryBoundary -Record $transaction)) {
            throw 'The protected OpenSSH directory boundary is not intact.'
        }
        if (-not [bool]$transaction.original.sshDirectory.existed) {
            Assert-NewSshTreeOwned -Path $script:SshPath -Record $transaction -Kind rollback
        }

        if ([string]$transaction.phase -eq 'ssh-directory') {
            Enter-InstallPhase -Transaction $transaction -Phase 'capability'
        }
        $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
        if (($capability.State -ne 'Installed') -and [bool]$transaction.capabilityInstalledByTool) {
            $capabilityResult = Add-WindowsCapability -Online -Name $script:CapabilityName
            $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
            if ($capabilityResult.RestartNeeded -or
                ([string]$capability.State -in @('InstallPending', 'UninstallPending'))) {
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
        if ([string]$capability.State -ne 'Installed') {
            throw "OpenSSH capability installation did not converge to Installed: $($capability.State)"
        }
        $transaction.status = 'installing'
        Update-InstallTransaction -Transaction $transaction
        Invoke-TestHook -Stage 'capability'

        if (-not (Test-SshDirectoryBoundary -Record $transaction)) {
            throw 'OpenSSH capability setup changed the protected data-directory boundary.'
        }
        if (-not [bool]$transaction.original.sshDirectory.existed) {
            Assert-NewSshTreeOwned -Path $script:SshPath -Record $transaction -Kind rollback
        }

        $sshdExe = Get-SshdExecutable
        Assert-FirewallPreconditions -SshPort $SshPort -SshdExe $sshdExe
        $serviceRecord = Get-SshdServiceOrNull
        if ($null -eq $serviceRecord) { throw 'OpenSSH capability is installed, but the sshd service is missing.' }
        $service = $serviceRecord.Controller
        if ((-not (Test-SshdServiceIdentity)) -or (-not (Test-SshdServiceSecurityBoundary))) {
            throw 'The sshd service identity, DACL, or System32 OpenSSH binary boundary is unsafe.'
        }
        if ([string]$transaction.phase -eq 'capability') {
            $serviceBeforeStop = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
            $transaction.sshdProcessIdBeforeStop = [uint32]$serviceBeforeStop.ProcessId
            Update-InstallTransaction -Transaction $transaction
        }
        Enter-InstallPhase -Transaction $transaction -Phase 'service-stop'
        Stop-SshdAndWait
        Invoke-TestHook -Stage 'service-stop'

        $currentDefaultRules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore PersistentStore)
        if ([bool]$transaction.original.defaultFirewall.existed) {
            if (($currentDefaultRules.Count -ne 1) -or
                ((Get-FirewallRuleSemanticSha256 -Rule $currentDefaultRules[0]) -ne
                    [string]$transaction.original.defaultFirewall.semanticSha256)) {
                throw 'The original OpenSSH firewall rule changed before it could be disabled.'
            }
        } elseif ($currentDefaultRules.Count -gt 0) {
            if ((-not [bool]$transaction.capabilityInstalledByTool) -or ($currentDefaultRules.Count -ne 1)) {
                throw 'An unowned default OpenSSH firewall rule appeared during installation.'
            }
            $transaction.createdDefaultFirewallSemanticSha256 = Get-FirewallRuleSemanticSha256 -Rule $currentDefaultRules[0]
            Update-InstallTransaction -Transaction $transaction
        }
        Enter-InstallPhase -Transaction $transaction -Phase 'default-firewall'
        Disable-DefaultOpenSshFirewallRule
        if (-not (Test-DefaultOpenSshFirewallClosed)) {
            throw 'The effective default OpenSSH firewall rule remains enabled (possibly by Group Policy).'
        }
        Invoke-TestHook -Stage 'default-firewall'

        Enter-InstallPhase -Transaction $transaction -Phase 'account'
        $account = Ensure-TransactionAccount -Name $Name -Transaction $transaction
        Invoke-TestHook -Stage 'account-before-sid-journal'
        $transaction.accountSid = [string]$account.SID.Value
        Update-InstallTransaction -Transaction $transaction
        Invoke-TestHook -Stage 'account'

        Enter-InstallPhase -Transaction $transaction -Phase 'authorized-keys'
        $keyCandidate = Get-AuthorizedKeysStagePath -Transaction $transaction
        try {
            if (Test-Path -LiteralPath $keyCandidate) { throw 'The authorized_keys staging path already exists.' }
            [IO.File]::WriteAllLines($keyCandidate, $keys, [Text.Encoding]::ASCII)
            Protect-ManagedFile -Path $keyCandidate
            $transaction.authorizedKeysFileSha256 = Get-FileSha256 -Path $keyCandidate
            Update-InstallTransaction -Transaction $transaction
            if (Test-Path -LiteralPath $script:KeyPath) { throw 'The managed authorized_keys destination already exists.' }
            [IO.File]::Move($keyCandidate, $script:KeyPath)
        } finally {
            if (Test-Path -LiteralPath $keyCandidate) {
                Remove-ProtectedStageFile -Path $keyCandidate -ExpectedSha256 ([string]$transaction.authorizedKeysFileSha256)
            }
        }
        if ((-not (Test-ManagedFileAcl -Path $script:KeyPath)) -or
            ((Get-FileSha256 -Path $script:KeyPath) -ne [string]$transaction.authorizedKeysFileSha256)) {
            throw 'Authorized key content or ACL verification failed.'
        }
        $fingerprints = @(Get-KeyFingerprints -Path $script:KeyPath)

        Enter-InstallPhase -Transaction $transaction -Phase 'host-key-staging'
        Prepare-PlannedHostKeyFiles -Transaction $transaction
        Enter-InstallPhase -Transaction $transaction -Phase 'host-keys'
        Publish-PlannedHostKeyFiles -Transaction $transaction

        $managedConfig = New-ManagedSshConfig -Name $Name -SshPort $SshPort
        if ((Get-TextSha256 -Text $managedConfig) -ne [string]$transaction.managedConfigSha256) {
            throw 'The planned managed sshd_config hash changed unexpectedly.'
        }
        $candidatePath = Get-ManagedConfigStagePath -Transaction $transaction
        try {
            if (Test-Path -LiteralPath $candidatePath) { throw 'The sshd_config staging path already exists.' }
            [IO.File]::WriteAllText($candidatePath, $managedConfig, [Text.Encoding]::ASCII)
            Protect-ManagedFile -Path $candidatePath
            Test-SshConfig -Path $candidatePath -SshdExe $sshdExe
            if (-not (Test-EffectiveSshPolicy -Path $candidatePath -SshdExe $sshdExe -Name $Name -SshPort $SshPort)) {
                throw 'Candidate effective sshd policy failed exact verification.'
            }
            $transaction.preManagedConfig = Get-ConfigSnapshot
            if ([bool]$transaction.original.config.existed) {
                if (-not (Test-ConfigMatchesSnapshot -Snapshot $transaction.original.config)) {
                    throw 'The original sshd_config changed before managed replacement.'
                }
            } elseif ([bool]$transaction.preManagedConfig.existed -and
                (-not [bool]$transaction.capabilityInstalledByTool)) {
                throw 'An unowned sshd_config appeared during installation.'
            }
            Update-InstallTransaction -Transaction $transaction
            Enter-InstallPhase -Transaction $transaction -Phase 'config'
            if ([bool]$transaction.original.config.existed) {
                if (-not (Test-ConfigMatchesSnapshot -Snapshot $transaction.original.config)) {
                    throw 'The original sshd_config changed before managed replacement.'
                }
            } elseif (Test-Path -LiteralPath $script:SshConfigPath) {
                if ((Test-ReparsePoint -Path $script:SshConfigPath) -or
                    (-not (Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf))) {
                    throw 'The capability-created sshd_config has an unsafe path type.'
                }
            }
            if (Test-Path -LiteralPath $script:SshConfigPath) {
                [IO.File]::Replace(
                    $candidatePath,
                    $script:SshConfigPath,
                    [System.Management.Automation.Language.NullString]::Value
                )
            } else {
                [IO.File]::Move($candidatePath, $script:SshConfigPath)
            }
            Protect-ManagedFile -Path $script:SshConfigPath
            [IO.File]::SetAttributes($script:SshConfigPath, [IO.FileAttributes]::Normal)
        } finally {
            if (Test-Path -LiteralPath $candidatePath) {
                $replacementInterrupted = (Test-InstallPhaseReached -Transaction $transaction -Phase 'config') -and
                    (-not (Test-Path -LiteralPath $script:SshConfigPath))
                if (-not $replacementInterrupted) {
                    Remove-ProtectedStageFile -Path $candidatePath -ExpectedSha256 ([string]$transaction.managedConfigSha256)
                }
            }
        }
        if (-not (Test-ManagedConfigCurrent -Record $transaction)) { throw 'Active sshd_config verification failed.' }
        Invoke-TestHook -Stage 'config'

        Enter-InstallPhase -Transaction $transaction -Phase 'firewall'
        $existingOwnRules = @(Get-FirewallRulesByNameSafe -Name $script:FirewallRuleName -PolicyStore PersistentStore)
        if ($existingOwnRules.Count -gt 0) {
            if ((-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe -Marker ([string]$transaction.accountMarker) -PolicyStore PersistentStore)) -or
                (-not (Test-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe -Marker ([string]$transaction.accountMarker) -PolicyStore ActiveStore))) {
                throw 'The transaction-owned firewall rule changed; refusing to replace it.'
            }
        } else {
            New-ManagedFirewallRule -SshPort $SshPort -RemoteAddress $RemoteAddress -SshdExe $sshdExe `
                -Marker ([string]$transaction.accountMarker)
        }
        Invoke-TestHook -Stage 'firewall'

        Enter-InstallPhase -Transaction $transaction -Phase 'service'
        Set-Service -Name sshd -StartupType Automatic
        Start-Service -Name sshd
        $deadline = (Get-Date).AddSeconds(30)
        $serviceReady = $false
        do {
            Start-Sleep -Milliseconds 250
            $runningRecord = Get-SshdServiceOrNull
            if ($null -ne $runningRecord) {
                $runningService = $runningRecord.Cim
                $restartedGeneration = ([uint32]$runningService.ProcessId -ne 0) -and
                    (([uint32]$transaction.sshdProcessIdBeforeStop -eq 0) -or
                        ([uint32]$runningService.ProcessId -ne [uint32]$transaction.sshdProcessIdBeforeStop))
                $serviceReady = ([string]$runningRecord.Controller.Status -eq 'Running') -and
                    $restartedGeneration -and (Test-SshdListenerExact -SshPort $SshPort)
            }
        } while ((-not $serviceReady) -and ((Get-Date) -lt $deadline))
        if (-not $serviceReady) {
            throw 'sshd did not reach the exact expected running/listener state.'
        }
        Invoke-TestHook -Stage 'service'

        Enter-InstallPhase -Transaction $transaction -Phase 'state-commit'
        $state = [ordered]@{
            schemaVersion = 2
            installerVersion = $script:InstallerVersion
            status = 'installed'
            cleanupKind = ''
            cleanupPhase = 'none'
            cleanupRemoveCapability = $false
            transactionId = [string]$transaction.transactionId
            installedAt = (Get-Date).ToUniversalTime().ToString('o')
            computerName = $env:COMPUTERNAME
            accountName = $Name
            accountMarker = [string]$transaction.accountMarker
            accountSid = [string]$transaction.accountSid
            port = $SshPort
            allowedRemoteAddress = @($RemoteAddress | Sort-Object -Unique)
            authorizedKeysCanonicalSha256 = $canonicalKeyHash
            authorizedKeysFileSha256 = [string]$transaction.authorizedKeysFileSha256
            keyFingerprints = @($fingerprints)
            firewallRuleName = $script:FirewallRuleName
            managedConfigSha256 = [string]$transaction.managedConfigSha256
            sshDirectoryMarkerSha256 = [string]$transaction.sshDirectoryMarkerSha256
            hostKeyFingerprint = Get-HostKeyFingerprint
            openSshInstalledByTool = [bool]$transaction.capabilityInstalledByTool
            existingSshdTakenOver = [bool]$transaction.takeOverExistingSshd
            createdDefaultFirewallSemanticSha256 = [string]$transaction.createdDefaultFirewallSemanticSha256
            generatedHostKeyFiles = @($transaction.generatedHostKeyFiles)
            original = $transaction.original
        }
        Write-ProtectedJsonFile -Value $state -Path $script:StatePath
        Invoke-TestHook -Stage 'state-commit'
        $audit = Invoke-WindowsRemoteBootstrapAudit
        if ([string]$audit.status -ne 'compliant') {
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
    $cleanupRootOk = $false
    try {
        Assert-ManagedCleanupRoot -RequireEmpty $true
        $cleanupRootOk = $true
    } catch { }
    Add-AuditCheck 'cleanup-root-boundary' $cleanupRootOk 'empty; SYSTEM/Administrators exact FullControl'

    $capability = Get-WindowsCapability -Online -Name $script:CapabilityName
    $expectedCapabilityState = if ([bool]$state.openSshInstalledByTool) { 'Installed' } else { [string]$state.original.capabilityState }
    Add-AuditCheck 'openssh-capability-state' ([string]$capability.State -eq $expectedCapabilityState) ([string]$capability.State)

    $user = $null
    $userQueryOk = $true
    try { $user = Get-LocalUserOrNull -Name ([string]$state.accountName) } catch { $userQueryOk = $false }
    $userOk = ($null -ne $user) -and
        $userQueryOk -and
        ([string]$user.SID.Value -eq [string]$state.accountSid) -and
        ([string]$user.Description -eq [string]$state.accountMarker) -and
        $user.Enabled
    Add-AuditCheck 'account' $userOk $(if ($null -eq $user) { 'missing' } else { "SID=$($user.SID.Value); enabled=$($user.Enabled); marker=$($user.Description)" })

    $adminOk = $false
    if ($null -ne $user) {
        try {
            $administrators = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
            $adminMatches = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop |
                Where-Object { [string]$_.SID.Value -eq [string]$user.SID.Value })
            $adminOk = $adminMatches.Count -eq 1
        } catch { $adminOk = $false }
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
    Add-AuditCheck 'openssh-directory-boundary' (Test-SshDirectoryBoundary -Record $state) `
        'real directory; parent replacement blocked; marker and baseline/exact ACL intact'
    $createdSshTreeOk = $true
    if (-not [bool]$state.original.sshDirectory.existed) {
        try {
            Assert-NewSshTreeOwned -Path $script:SshPath -Record $state -Kind audit
        } catch {
            $createdSshTreeOk = $false
        }
    }
    Add-AuditCheck 'created-ssh-directory-owned-set' $createdSshTreeOk `
        'new directory contains only the recorded marker, config, and host keys'

    $hostKeysOk = $true
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
                    ([string]$expectedRecords[$index].sha256 -ne [string]$currentRecords[$index].sha256) -or
                    ([string]$expectedRecords[$index].sddl -ne [string]$currentRecords[$index].sddl) -or
                    ([int]$expectedRecords[$index].attributes -ne [int]$currentRecords[$index].attributes)) {
                    $hostKeySetOk = $false
                }
                if ([string]$currentRecords[$index].name -match '^ssh_host_[A-Za-z0-9._-]+_key$') {
                    $path = Join-Path $script:SshPath ([string]$currentRecords[$index].name)
                    $isGenerated = $null -ne (@($state.generatedHostKeyFiles | Where-Object {
                        [string]$_.name -ieq [string]$currentRecords[$index].name
                    }) | Select-Object -First 1)
                    if (($isGenerated -and (-not (Test-ManagedFileAcl -Path $path))) -or
                        ((-not $isGenerated) -and
                            (-not (Test-PathProtectedFromUntrustedMutation -Path $path -DenyUntrustedRead $true)))) {
                        $hostKeysOk = $false
                    }
                }
            }
        }
    } catch {
        $hostKeySetOk = $false
    }
    Add-AuditCheck 'ssh-host-key-security' $hostKeysOk 'private host keys remain confidential and immutable'
    Add-AuditCheck 'host-key-file-set-and-hashes' $hostKeySetOk 'original plus generated host-key files exactly unchanged'
    $currentHostFingerprint = $null
    $hostFingerprintDetail = 'missing'
    $hostFingerprintOk = $false
    try {
        $currentHostFingerprint = Get-HostKeyFingerprint
        $hostFingerprintOk = [string]$currentHostFingerprint -eq [string]$state.hostKeyFingerprint
        $hostFingerprintDetail = [string]$currentHostFingerprint
    } catch {
        $hostFingerprintDetail = "query failed: $($_.Exception.Message)"
    }
    Add-AuditCheck 'host-key-fingerprint' `
        $hostFingerprintOk $hostFingerprintDetail

    $configOk = $false
    $policyOk = $false
    $configAclOk = $false
    if ((Test-Path -LiteralPath $script:SshConfigPath -PathType Leaf) -and
        (-not (Test-ReparsePoint -Path $script:SshConfigPath))) {
        try {
            $sshdExe = Get-SshdExecutable
            Test-SshConfig -Path $script:SshConfigPath -SshdExe $sshdExe
            $configOk = Test-ManagedConfigCurrent -Record $state
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

    $service = $null
    $serviceDetail = 'missing'
    try {
        $serviceRecord = Get-SshdServiceOrNull
        if ($null -ne $serviceRecord) {
            $service = $serviceRecord.Controller
            $serviceDetail = "$($service.Status)/$($service.StartType)"
        }
    } catch {
        $serviceDetail = "query failed: $($_.Exception.Message)"
    }
    $serviceOk = ($null -ne $service) -and ($service.Status -eq 'Running') -and ([string]$service.StartType -eq 'Automatic')
    Add-AuditCheck 'sshd-service' $serviceOk $serviceDetail
    Add-AuditCheck 'sshd-service-identity' (Test-SshdServiceIdentity) 'System32 OpenSSH sshd.exe as LocalSystem'
    Add-AuditCheck 'sshd-service-security' (Test-SshdServiceSecurityBoundary) `
        'service DACL/owner and sshd/ssh-keygen binary boundaries deny untrusted mutation'

    $listenerOk = Test-SshdListenerExact -SshPort ([int]$state.port)
    Add-AuditCheck 'sshd-listeners' $listenerOk "sshd PID only TCP/$($state.port)"

    $sshdPath = Join-Path $script:SystemPath 'OpenSSH\sshd.exe'
    $firewallOk = $false
    try {
        $firewallOk = (Test-ManagedFirewallRule -SshPort ([int]$state.port) `
                -RemoteAddress @($state.allowedRemoteAddress) -SshdExe $sshdPath `
                -Marker ([string]$state.accountMarker) -PolicyStore PersistentStore) -and
            (Test-ManagedFirewallRule -SshPort ([int]$state.port) `
                -RemoteAddress @($state.allowedRemoteAddress) -SshdExe $sshdPath `
                -Marker ([string]$state.accountMarker) -PolicyStore ActiveStore)
    } catch { $firewallOk = $false }
    Add-AuditCheck 'firewall-exact-filters' $firewallOk ([string]$firewallOk)
    $profilesOk = $false
    $competingQueryOk = $false
    $competing = @()
    try {
        $profilesOk = Test-FirewallProfilesSecure
        $competing = @(Get-CompetingSshFirewallRules -SshPort ([int]$state.port) -SshdExe $sshdPath)
        $competingQueryOk = $true
    } catch { }
    Add-AuditCheck 'firewall-profiles-enabled' $profilesOk 'enabled; default inbound Block; no excluded interface'
    Add-AuditCheck 'no-competing-firewall-rule' ($competingQueryOk -and ($competing.Count -eq 0)) `
        $(if (-not $competingQueryOk) { 'firewall policy query failed' } else { $competing -join ', ' })

    $defaultRuleOk = $false
    $defaultRuleDetail = 'firewall policy query failed'
    try {
        $defaultRules = @(Get-FirewallRulesByNameSafe -Name 'OpenSSH-Server-In-TCP' -PolicyStore ActiveStore)
        $enabledDefaultRules = @($defaultRules | Where-Object { [string]$_.Enabled -eq 'True' })
        $defaultRuleOk = $enabledDefaultRules.Count -eq 0
        $defaultRuleDetail = if ($defaultRules.Count -eq 0) { 'absent' } else { (@($defaultRules.Enabled) -join ',') }
    } catch { }
    Add-AuditCheck 'default-wide-firewall-disabled' $defaultRuleOk $defaultRuleDetail

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
        hostKeyFingerprint = $currentHostFingerprint
        checks = @($checks)
    }
}

function Uninstall-WindowsRemoteBootstrap {
    $state = Get-SavedState
    if ($null -eq $state) {
        $transaction = Get-InstallTransaction
        if ($null -eq $transaction) {
            [void](Remove-UnjournaledInstallScaffolding)
            return [ordered]@{
                status = 'already-uninstalled'
                installerVersion = $script:InstallerVersion
                computerName = $env:COMPUTERNAME
            }
        }
        Assert-TransactionShape -Transaction $transaction
        Assert-InstallTransactionRollbackSafe -Transaction $transaction
        $rollback = Invoke-OwnedCleanup -Record $transaction -Kind rollback
        if ([bool]$rollback.restartRequired) {
            return [ordered]@{
                status = 'rollback-restart-required'
                installerVersion = $script:InstallerVersion
                computerName = $env:COMPUTERNAME
                nextStep = 'Restart Windows, then run the exact same uninstall command.'
            }
        }
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
    }
    $result = Invoke-OwnedCleanup -Record $state -Kind uninstall
    if ([bool]$result.restartRequired) {
        return [ordered]@{
            status = 'uninstall-restart-required'
            installerVersion = $script:InstallerVersion
            computerName = $env:COMPUTERNAME
            nextStep = 'Restart Windows, then run the exact same uninstall command.'
        }
    }
    return [ordered]@{
        status = 'uninstalled'
        installerVersion = $script:InstallerVersion
        computerName = $env:COMPUTERNAME
        openSshCapabilityRemoved = [bool]$state.openSshInstalledByTool
    }
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

    Remove-StaleCleanupTombstones
    Remove-OrphanedProtectedJsonStaging

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
            if ([string]$receipt.status -in @('uninstall-restart-required', 'rollback-restart-required')) {
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
