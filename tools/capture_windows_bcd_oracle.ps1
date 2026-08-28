# SPDX-License-Identifier: AGPL-3.0-or-later
#requires -Version 7.4
#requires -RunAsAdministrator

<#
.SYNOPSIS
Collects non-authorizing Windows BCD evidence on disposable fixed VHD files.

.DESCRIPTION
This maintainer-only collector never accepts a disk, device, drive letter, or
virtual-disk path.  It creates all writable media beneath an ACL-private work
directory, detaches the fixed parent before making sequential full clones, and
patches only detached raw GPT metadata.  The output still requires independent
Linux hivex parsing and differential validation; successful collection is not
runtime or boot certification.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $IsoPath,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 128)]
    [int] $ImageIndex,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$Schema = 'io.github.codebooker.isopropyl/windows-bcd-raw-capture/v1'
$Variants = @('baseline', 'disk-guid', 'esp-guid', 'windows-guid')
$DiskSizeBytes = [UInt64]68719476736
$SectorBytes = [UInt64]512
$EspOffsetBytes = [UInt64]1048576
$EspSizeBytes = [UInt64]272629760
$MsrOffsetBytes = [UInt64]273678336
$MsrSizeBytes = [UInt64]134217728
$WindowsOffsetBytes = [UInt64]407896064
$WindowsSizeBytes = [UInt64]68310532096
$EspType = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
$MsrType = 'e3c9e316-0b5c-4db8-817d-f92df00215ae'
$WindowsType = 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
$MaximumCommandBytes = 65536
$MaximumHiveBytes = 16777216
$MaximumTemplateBytes = 16777216

if ($PSVersionTable.PSEdition -ne 'Core' -or
    $PSVersionTable.PSVersion.Major -ne 7 -or
    $PSVersionTable.PSVersion.Minor -ne 4 -or
    -not [Environment]::Is64BitProcess -or
    -not [Environment]::Is64BitOperatingSystem) {
    throw 'This frozen collector requires 64-bit PowerShell Core 7.4 on 64-bit Windows.'
}
if (-not $IsWindows) {
    throw 'This collector runs only on Windows.'
}

function Assert-NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string] $LiteralPath,
        [Parameter(Mandatory = $true)][bool] $LeafMustExist
    )
    $full = [IO.Path]::GetFullPath($LiteralPath)
    if (-not [IO.Path]::IsPathFullyQualified($full)) {
        throw "Path is not fully qualified: $LiteralPath"
    }
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root) -or $root.StartsWith('\\')) {
        throw "Only local drive paths are accepted: $LiteralPath"
    }
    $drive = [IO.DriveInfo]::new($root)
    if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed -or
        $drive.DriveFormat -ne 'NTFS') {
        throw "Path must reside on a ready local NTFS fixed drive: $LiteralPath"
    }
    $current = $root
    $relative = $full.Substring($root.Length)
    $parts = $relative.Split('\', [StringSplitOptions]::RemoveEmptyEntries)
    for ($index = 0; $index -lt $parts.Length; $index++) {
        $current = [IO.Path]::Combine($current, $parts[$index])
        $exists = [IO.File]::Exists($current) -or [IO.Directory]::Exists($current)
        if (-not $exists) {
            if ($index -lt ($parts.Length - 1) -or $LeafMustExist) {
                throw "A required path component does not exist: $current"
            }
            break
        }
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are outside the collector profile: $current"
        }
    }
    return $full
}

function New-PrivateDirectory {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    [void][IO.Directory]::CreateDirectory($LiteralPath)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($sid in @(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        $administrators
    )) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, $rights, $inheritance, $propagation,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner($administrators)
    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $LiteralPath -AclObject $acl
    Assert-PrivateDirectoryAcl -LiteralPath $LiteralPath
}

function Assert-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $LiteralPath
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $acl.AreAccessRulesProtected -or $owner -ne $administrators) {
        throw "Directory owner or DACL protection is outside policy: $LiteralPath"
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 2) {
        throw "Directory DACL is not the exact Administrators/SYSTEM policy: $LiteralPath"
    }
    $seen = [Collections.Generic.HashSet[string]]::new()
    foreach ($rule in $rules) {
        $sid = [Security.Principal.SecurityIdentifier]$rule.IdentityReference
        if ($sid -notin @($administrators, $system) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            $rule.IsInherited) {
            throw "Directory DACL rule is outside policy: $LiteralPath"
        }
        if (-not $seen.Add($sid.Value)) {
            throw "Directory DACL repeats an identity: $LiteralPath"
        }
    }
    if (-not $seen.Contains($administrators.Value) -or -not $seen.Contains($system.Value)) {
        throw "Directory DACL omits Administrators or SYSTEM: $LiteralPath"
    }
}

function Get-ArtifactClaim {
    param(
        [Parameter(Mandatory = $true)][string] $LiteralPath,
        [Parameter(Mandatory = $true)][UInt64] $MaximumBytes
    )
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force
    if ($item.PSIsContainer -or $item.Length -lt 1 -or $item.Length -gt $MaximumBytes -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Artifact is not a bounded ordinary file: $LiteralPath"
    }
    $digest = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
    return [ordered]@{ size = [UInt64]$item.Length; sha256 = $digest }
}

function Get-FourPartVersion {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($LiteralPath)
    return '{0}.{1}.{2}.{3}' -f @(
        $version.FileMajorPart,
        $version.FileMinorPart,
        $version.FileBuildPart,
        $version.FilePrivatePart
    )
}

function Get-TrustedMicrosoftExecutableClaim {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    $full = Assert-NoReparsePath -LiteralPath $LiteralPath -LeafMustExist $true
    if ([IO.Path]::GetDirectoryName($full) -ne $SystemDirectory) {
        throw "Executable is outside the trusted Windows system directory: $LiteralPath"
    }
    $artifact = Get-ArtifactClaim -LiteralPath $full -MaximumBytes 67108864
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $full
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(?:^|, )O=Microsoft Corporation(?:,|$)') {
        throw "Executable does not have a valid Microsoft Authenticode signature: $LiteralPath"
    }
    return [ordered]@{
        path = $full
        version = Get-FourPartVersion -LiteralPath $full
        executable_sha256 = $artifact.sha256
    }
}

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

public sealed class IsopropylCommandResult {
    public int ExitCode { get; init; }
    public byte[] Stdout { get; init; } = Array.Empty<byte>();
    public byte[] Stderr { get; init; } = Array.Empty<byte>();
}

public static class IsopropylBoundedCommand {
    private static async Task<byte[]> Pump(Stream source, int maximum, CancellationToken token, Process process) {
        using var output = new MemoryStream();
        byte[] buffer = new byte[4096];
        while (true) {
            int count = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
            if (count == 0) break;
            if (output.Length + count > maximum) {
                try { if (!process.HasExited) process.Kill(true); } catch { }
                throw new InvalidDataException("Native command output exceeded its byte limit");
            }
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    public static IsopropylCommandResult Run(
        string executable,
        string[] arguments,
        string workingDirectory,
        int maximum,
        int timeoutSeconds,
        string systemRoot,
        string temporaryDirectory
    ) {
        if (!Path.IsPathFullyQualified(executable))
            throw new ArgumentException("The executable path must be absolute");
        var info = new ProcessStartInfo {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string argument in arguments) info.ArgumentList.Add(argument);
        info.Environment.Clear();
        info.Environment["SystemRoot"] = systemRoot;
        info.Environment["WINDIR"] = systemRoot;
        info.Environment["TEMP"] = temporaryDirectory;
        info.Environment["TMP"] = temporaryDirectory;

        using var process = new Process { StartInfo = info };
        if (!process.Start()) throw new InvalidOperationException("Native command did not start");
        process.StandardInput.Close();
        using var cancellation = new CancellationTokenSource();
        Task<byte[]> stdout = Pump(process.StandardOutput.BaseStream, maximum, cancellation.Token, process);
        Task<byte[]> stderr = Pump(process.StandardError.BaseStream, maximum, cancellation.Token, process);
        Task exited = process.WaitForExitAsync(cancellation.Token);
        Task complete = Task.WhenAll(exited, stdout, stderr);
        Task deadline = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds));
        try {
            Task winner = Task.WhenAny(complete, deadline).GetAwaiter().GetResult();
            if (winner == deadline)
                throw new TimeoutException("Native command exceeded its deadline");
            complete.GetAwaiter().GetResult();
        } catch {
            cancellation.Cancel();
            try { if (!process.HasExited) process.Kill(true); } catch { }
            try { process.WaitForExit(5000); } catch { }
            throw;
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException("Native command returned exit code " + process.ExitCode);
        return new IsopropylCommandResult {
            ExitCode = process.ExitCode,
            Stdout = stdout.GetAwaiter().GetResult(),
            Stderr = stderr.GetAwaiter().GetResult()
        };
    }
}
'@
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $nativeSource -Language CSharp

$gptSource = @'
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

public sealed class IsopropylGptIdentity {
    public Guid DiskGuid { get; init; }
    public Guid EspGuid { get; init; }
    public Guid MsrGuid { get; init; }
    public Guid WindowsGuid { get; init; }
}

public static class IsopropylFixedVhdGpt {
    const long DiskBytes = 68719476736L;
    const int Sector = 512;
    const ulong TotalLbas = 134217728UL;
    const ulong LastLba = TotalLbas - 1;
    const ulong FirstUsable = 34;
    const ulong LastUsable = 134217694;
    const ulong EspFirst = 2048;
    const ulong EspLast = 534527;
    const ulong MsrFirst = 534528;
    const ulong MsrLast = 796671;
    const ulong WindowsFirst = 796672;
    const ulong WindowsLast = 134215679;
    const int Entries = 128;
    const int EntryBytes = 128;
    const int ArrayBytes = Entries * EntryBytes;

    static readonly Guid EspType = new Guid("c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    static readonly Guid MsrType = new Guid("e3c9e316-0b5c-4db8-817d-f92df00215ae");
    static readonly Guid WindowsType = new Guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");

    static uint Crc32(ReadOnlySpan<byte> bytes) {
        uint crc = 0xffffffffU;
        foreach (byte value in bytes) {
            crc ^= value;
            for (int bit = 0; bit < 8; bit++)
                crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0U : 0xedb88320U);
        }
        return ~crc;
    }

    static byte[] ReadExact(FileStream stream, long offset, int count) {
        byte[] data = new byte[count];
        stream.Position = offset;
        int done = 0;
        while (done < count) {
            int read = stream.Read(data, done, count - done);
            if (read == 0) throw new InvalidDataException("Detached VHD ended unexpectedly");
            done += read;
        }
        return data;
    }

    static void WriteExact(FileStream stream, long offset, byte[] data) {
        stream.Position = offset;
        stream.Write(data, 0, data.Length);
    }

    static ulong U64(byte[] data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));
    static uint U32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
    static uint U32BE(byte[] data, int offset) => BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
    static ulong U64BE(byte[] data, int offset) => BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(offset, 8));
    static Guid GuidAt(byte[] data, int offset) => new Guid(data.AsSpan(offset, 16));
    static void PutGuid(byte[] data, int offset, Guid value) => value.TryWriteBytes(data.AsSpan(offset, 16));

    static void ValidateFooter(byte[] footer) {
        if (!footer.AsSpan(0, 8).SequenceEqual(Encoding.ASCII.GetBytes("conectix")) ||
            U64BE(footer, 16) != ulong.MaxValue || U64BE(footer, 40) != (ulong)DiskBytes ||
            U64BE(footer, 48) != (ulong)DiskBytes || U32BE(footer, 60) != 2)
            throw new InvalidDataException("File is not the frozen fixed VHD profile");
        uint stored = U32BE(footer, 64);
        byte[] copy = (byte[])footer.Clone();
        Array.Clear(copy, 64, 4);
        uint sum = 0;
        foreach (byte value in copy) sum += value;
        if (stored != ~sum) throw new InvalidDataException("Fixed VHD footer checksum is invalid");
    }

    static void ValidateHeader(byte[] header, ulong here, ulong other, ulong entriesLba, uint arrayCrc, Guid diskGuid) {
        if (!header.AsSpan(0, 8).SequenceEqual(Encoding.ASCII.GetBytes("EFI PART")) ||
            U32(header, 8) != 0x00010000U || U32(header, 12) != 92U ||
            U64(header, 24) != here || U64(header, 32) != other ||
            U64(header, 40) != FirstUsable || U64(header, 48) != LastUsable ||
            GuidAt(header, 56) != diskGuid || U64(header, 72) != entriesLba ||
            U32(header, 80) != Entries || U32(header, 84) != EntryBytes ||
            U32(header, 88) != arrayCrc)
            throw new InvalidDataException("GPT header is outside the frozen profile");
        uint stored = U32(header, 16);
        byte[] copy = header.AsSpan(0, 92).ToArray();
        Array.Clear(copy, 16, 4);
        if (stored != Crc32(copy)) throw new InvalidDataException("GPT header CRC is invalid");
        if (header.AsSpan(92).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("GPT reserved header bytes are nonzero");
    }

    static Guid ValidateEntry(byte[] entries, int index, Guid type, ulong first, ulong last) {
        int offset = index * EntryBytes;
        if (GuidAt(entries, offset) != type || U64(entries, offset + 32) != first ||
            U64(entries, offset + 40) != last || U64(entries, offset + 48) != 0)
            throw new InvalidDataException("GPT partition entry is outside the frozen profile");
        Guid unique = GuidAt(entries, offset + 16);
        if (unique == Guid.Empty) throw new InvalidDataException("GPT unique GUID is empty");
        return unique;
    }

    static IsopropylGptIdentity Validate(FileStream stream, out byte[] primary, out byte[] backup,
        out byte[] entries, out byte[] backupEntries) {
        if (stream.Length != DiskBytes + Sector)
            throw new InvalidDataException("Fixed VHD length is outside the frozen profile");
        ValidateFooter(ReadExact(stream, DiskBytes, Sector));
        byte[] mbr = ReadExact(stream, 0, Sector);
        if (mbr[510] != 0x55 || mbr[511] != 0xaa || mbr[450] != 0xee || U32(mbr, 454) != 1)
            throw new InvalidDataException("Protective MBR is invalid");
        primary = ReadExact(stream, Sector, Sector);
        backup = ReadExact(stream, (long)LastLba * Sector, Sector);
        entries = ReadExact(stream, 2L * Sector, ArrayBytes);
        backupEntries = ReadExact(stream, (long)(LastLba - 32) * Sector, ArrayBytes);
        if (!entries.SequenceEqual(backupEntries))
            throw new InvalidDataException("Primary and backup GPT arrays differ");
        uint arrayCrc = Crc32(entries);
        if (U32(primary, 88) != arrayCrc || U32(backup, 88) != arrayCrc)
            throw new InvalidDataException("GPT array CRC is invalid");
        Guid diskGuid = GuidAt(primary, 56);
        if (diskGuid == Guid.Empty) throw new InvalidDataException("GPT disk GUID is empty");
        ValidateHeader(primary, 1, LastLba, 2, arrayCrc, diskGuid);
        ValidateHeader(backup, LastLba, 1, LastLba - 32, arrayCrc, diskGuid);
        Guid esp = ValidateEntry(entries, 0, EspType, EspFirst, EspLast);
        Guid msr = ValidateEntry(entries, 1, MsrType, MsrFirst, MsrLast);
        Guid windows = ValidateEntry(entries, 2, WindowsType, WindowsFirst, WindowsLast);
        if (new[] { diskGuid, esp, msr, windows }.Distinct().Count() != 4)
            throw new InvalidDataException("GPT GUID identities collide");
        if (entries.AsSpan(3 * EntryBytes).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Unexpected GPT partition entries are present");
        return new IsopropylGptIdentity { DiskGuid = diskGuid, EspGuid = esp, MsrGuid = msr, WindowsGuid = windows };
    }

    static void RefreshHeaderCrc(byte[] header) {
        Array.Clear(header, 16, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16, 4), Crc32(header.AsSpan(0, 92)));
    }

    public static IsopropylGptIdentity ValidateAndPatch(string path, string variant, Guid replacement) {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 4096,
            FileOptions.RandomAccess | FileOptions.WriteThrough);
        IsopropylGptIdentity before = Validate(stream, out byte[] primary, out byte[] backup,
            out byte[] entries, out byte[] backupEntries);
        if (variant == "baseline") {
            if (replacement != Guid.Empty) throw new ArgumentException("Baseline replacement must be empty");
            return before;
        }
        if (replacement == Guid.Empty || replacement == before.DiskGuid || replacement == before.EspGuid ||
            replacement == before.MsrGuid || replacement == before.WindowsGuid)
            throw new ArgumentException("Replacement GUID is empty or collides");

        if (variant == "disk-guid") {
            PutGuid(primary, 56, replacement);
            PutGuid(backup, 56, replacement);
        } else if (variant == "esp-guid" || variant == "windows-guid") {
            int entry = variant == "esp-guid" ? 0 : 2;
            PutGuid(entries, entry * EntryBytes + 16, replacement);
            PutGuid(backupEntries, entry * EntryBytes + 16, replacement);
            uint crc = Crc32(entries);
            BinaryPrimitives.WriteUInt32LittleEndian(primary.AsSpan(88, 4), crc);
            BinaryPrimitives.WriteUInt32LittleEndian(backup.AsSpan(88, 4), crc);
        } else {
            throw new ArgumentException("Unknown GPT variant");
        }
        RefreshHeaderCrc(primary);
        RefreshHeaderCrc(backup);
        WriteExact(stream, Sector, primary);
        WriteExact(stream, (long)LastLba * Sector, backup);
        if (variant != "disk-guid") {
            WriteExact(stream, 2L * Sector, entries);
            WriteExact(stream, (long)(LastLba - 32) * Sector, backupEntries);
        }
        stream.Flush(true);
        IsopropylGptIdentity after = Validate(stream, out _, out _, out _, out _);
        if ((variant == "disk-guid" && (after.DiskGuid != replacement || after.EspGuid != before.EspGuid ||
                after.MsrGuid != before.MsrGuid || after.WindowsGuid != before.WindowsGuid)) ||
            (variant == "esp-guid" && (after.DiskGuid != before.DiskGuid || after.EspGuid != replacement ||
                after.MsrGuid != before.MsrGuid || after.WindowsGuid != before.WindowsGuid)) ||
            (variant == "windows-guid" && (after.DiskGuid != before.DiskGuid || after.EspGuid != before.EspGuid ||
                after.MsrGuid != before.MsrGuid || after.WindowsGuid != replacement)))
            throw new InvalidDataException("GPT mutation exceeded its one-GUID allowlist");
        return after;
    }
}
'@
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $gptSource -Language CSharp

function Resolve-BoundDisk {
    param([Parameter(Mandatory = $true)][string] $GeneratedVhdPath)
    $vhd = Hyper-V\Get-VHD -Path $GeneratedVhdPath
    if (-not $vhd.Attached -or $vhd.Path -ne $GeneratedVhdPath) {
        throw 'Generated VHD is not attached through its exact path.'
    }
    $disks = @($vhd | Storage\Get-Disk)
    if ($disks.Count -ne 1) {
        throw 'Generated VHD did not resolve to exactly one disk.'
    }
    $disk = $disks[0]
    if ([UInt64]$disk.Size -ne $DiskSizeBytes -or [UInt64]$disk.LogicalSectorSize -ne $SectorBytes -or
        $disk.IsBoot -or $disk.IsSystem) {
        throw 'Path-bound generated disk is outside the frozen disposable profile.'
    }
    return $disk
}

function Assert-PartitionLayout {
    param(
        [Parameter(Mandatory = $true)] $Disk,
        [Parameter(Mandatory = $true)] $ExpectedIdentity
    )
    $parts = @(Storage\Get-Partition -InputObject $Disk | Microsoft.PowerShell.Utility\Sort-Object -Property Offset)
    if ($parts.Count -ne 3) { throw 'Generated disk must contain exactly three partitions.' }
    $expected = @(
        @([UInt32]1, $EspOffsetBytes, $EspSizeBytes, $EspType, $ExpectedIdentity.EspGuid),
        @([UInt32]2, $MsrOffsetBytes, $MsrSizeBytes, $MsrType, $ExpectedIdentity.MsrGuid),
        @([UInt32]3, $WindowsOffsetBytes, $WindowsSizeBytes, $WindowsType, $ExpectedIdentity.WindowsGuid)
    )
    for ($i = 0; $i -lt 3; $i++) {
        $part = $parts[$i]
        $want = $expected[$i]
        if ([UInt32]$part.PartitionNumber -ne $want[0] -or [UInt64]$part.Offset -ne $want[1] -or
            [UInt64]$part.Size -ne $want[2] -or
            ([Guid]$part.GptType).ToString() -ne $want[3] -or
            ([Guid]$part.Guid) -ne [Guid]$want[4]) {
            throw 'Attached partition layout contradicts detached GPT validation.'
        }
    }
    if (([Guid]$Disk.Guid) -ne [Guid]$ExpectedIdentity.DiskGuid) {
        throw 'Attached disk GUID contradicts detached GPT validation.'
    }
    return $parts
}

function Set-VerifiedLetters {
    param(
        [Parameter(Mandatory = $true)] $Disk,
        [Parameter(Mandatory = $true)] $Partitions
    )
    $expectedNumbers = @{ S = 1; W = 3 }
    foreach ($letter in @('S', 'W')) {
        $existing = @(Storage\Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and (
            $existing[0].DiskPath -ne $Disk.Path -or
            $existing[0].PartitionNumber -ne $expectedNumbers[$letter]
        ))) {
            throw "Required private drive letter $letter is not exclusively bound to the generated VHD."
        }
    }
    if ($Partitions[0].DriveLetter -ne 'S') {
        Storage\Set-Partition -InputObject $Partitions[0] -NewDriveLetter S
    }
    if ($Partitions[2].DriveLetter -ne 'W') {
        Storage\Set-Partition -InputObject $Partitions[2] -NewDriveLetter W
    }
    Assert-VerifiedLetters -Disk $Disk
}

function Assert-VerifiedLetters {
    param([Parameter(Mandatory = $true)] $Disk)
    $esp = @(Storage\Get-Partition -DriveLetter S -ErrorAction Stop)
    $windows = @(Storage\Get-Partition -DriveLetter W -ErrorAction Stop)
    if ($esp.Count -ne 1 -or $windows.Count -ne 1 -or
        $esp[0].DiskPath -ne $Disk.Path -or $windows[0].DiskPath -ne $Disk.Path -or
        $esp[0].PartitionNumber -ne 1 -or $windows[0].PartitionNumber -ne 3 -or
        $esp[0].Guid -eq $windows[0].Guid) {
        throw 'Private drive letters are not bound to the generated VHD.'
    }
}

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)][string] $Executable,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][int] $DeadlineSeconds,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory
    )
    $result = [IsopropylBoundedCommand]::Run(
        $Executable, $Arguments, $WorkingDirectory, $MaximumCommandBytes,
        $DeadlineSeconds, $WindowsRoot, $WorkingDirectory
    )
    return [ordered]@{
        argv = @($Executable) + @($Arguments)
        exit_code = [int]$result.ExitCode
        stdout_base64 = [Convert]::ToBase64String($result.Stdout)
        stderr_base64 = [Convert]::ToBase64String($result.Stderr)
    }
}

function Copy-StableArtifact {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination,
        [Parameter(Mandatory = $true)][UInt64] $MaximumBytes
    )
    $before = Get-ArtifactClaim -LiteralPath $Source -MaximumBytes $MaximumBytes
    [IO.File]::Copy($Source, $Destination, $false)
    $after = Get-ArtifactClaim -LiteralPath $Source -MaximumBytes $MaximumBytes
    $copy = Get-ArtifactClaim -LiteralPath $Destination -MaximumBytes $MaximumBytes
    if ($before.size -ne $after.size -or $before.sha256 -ne $after.sha256 -or
        $before.size -ne $copy.size -or $before.sha256 -ne $copy.sha256) {
        throw 'Artifact changed while it was copied.'
    }
    return $copy
}

function Assert-EvidenceTree {
    param(
        [Parameter(Mandatory = $true)][string] $LiteralPath,
        [Parameter(Mandatory = $true)] $ExpectedClaims
    )
    $observed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($LiteralPath)) {
        $name = [IO.Path]::GetFileName($entry)
        if (-not $ExpectedClaims.Contains($name) -or -not $observed.Add($name)) {
            throw "Evidence directory inventory is not exact: $LiteralPath"
        }
        $claim = Get-ArtifactClaim -LiteralPath $entry -MaximumBytes 16777216
        $expected = $ExpectedClaims[$name]
        if ($claim.size -ne $expected.size -or $claim.sha256 -ne $expected.sha256) {
            throw "Evidence artifact changed before publication: $name"
        }
    }
    if ($observed.Count -ne $ExpectedClaims.Count) {
        throw "Evidence directory inventory is incomplete: $LiteralPath"
    }
}

function Dismount-ExactVhd {
    param([Parameter(Mandatory = $true)][string] $GeneratedVhdPath)
    $vhd = Hyper-V\Get-VHD -Path $GeneratedVhdPath -ErrorAction SilentlyContinue
    if ($null -ne $vhd -and $vhd.Attached) {
        Hyper-V\Dismount-VHD -Path $GeneratedVhdPath
    }
    $after = Hyper-V\Get-VHD -Path $GeneratedVhdPath
    if ($after.Attached) { throw 'Generated VHD remained attached during cleanup.' }
}

# Resolve inputs before creating or attaching anything.
if (-not [IO.Path]::IsPathFullyQualified($IsoPath) -or
    -not [IO.Path]::IsPathFullyQualified($OutputDirectory)) {
    throw 'IsoPath and OutputDirectory must be absolute paths.'
}
$IsoPath = Assert-NoReparsePath -LiteralPath $IsoPath -LeafMustExist $true
if ([IO.Path]::GetExtension($IsoPath).ToLowerInvariant() -ne '.iso') {
    throw 'IsoPath must identify an ISO file.'
}
$isoItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath $IsoPath -Force
if ($isoItem.PSIsContainer -or $isoItem.Length -lt 1) { throw 'IsoPath is not a non-empty file.' }

$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if ([IO.Directory]::Exists($OutputDirectory) -or [IO.File]::Exists($OutputDirectory)) {
    throw 'OutputDirectory must not already exist.'
}
$outputParent = Assert-NoReparsePath -LiteralPath ([IO.Path]::GetDirectoryName($OutputDirectory)) -LeafMustExist $true
Assert-PrivateDirectoryAcl -LiteralPath $outputParent

$SystemDirectory = Assert-NoReparsePath -LiteralPath ([Environment]::SystemDirectory) -LeafMustExist $true
$WindowsRoot = Assert-NoReparsePath -LiteralPath ([IO.Directory]::GetParent($SystemDirectory).FullName) -LeafMustExist $true
$trustedModuleRoot = Assert-NoReparsePath -LiteralPath (
    [IO.Path]::Combine($SystemDirectory, 'WindowsPowerShell', 'v1.0', 'Modules')
) -LeafMustExist $true
$requiredModules = [ordered]@{
    'Storage' = @('Get-Disk', 'Get-Partition', 'Set-Partition', 'Initialize-Disk',
        'New-Partition', 'Format-Volume', 'Mount-DiskImage', 'Dismount-DiskImage',
        'Get-DiskImage', 'Get-Volume')
    'Dism' = @('Expand-WindowsImage', 'Get-WindowsImage')
    'Hyper-V' = @('New-VHD', 'Mount-VHD', 'Get-VHD', 'Dismount-VHD')
}
foreach ($moduleName in $requiredModules.Keys) {
    $manifest = Assert-NoReparsePath -LiteralPath (
        [IO.Path]::Combine($trustedModuleRoot, $moduleName, "$moduleName.psd1")
    ) -LeafMustExist $true
    foreach ($loaded in @(Microsoft.PowerShell.Core\Get-Module -Name $moduleName -All)) {
        if ([IO.Path]::GetFullPath($loaded.Path) -ne $manifest) {
            throw "An untrusted $moduleName module is already loaded. Start PowerShell with -NoProfile."
        }
    }
    $imported = @(Microsoft.PowerShell.Core\Import-Module -Name $manifest -Force -PassThru -SkipEditionCheck)
    if ($imported.Count -ne 1 -or [IO.Path]::GetFullPath($imported[0].Path) -ne $manifest) {
        throw "The trusted $moduleName module could not be pinned."
    }
    foreach ($commandName in $requiredModules[$moduleName]) {
        $resolved = @(Microsoft.PowerShell.Core\Get-Command "$moduleName\$commandName" -CommandType Cmdlet, Function -ErrorAction Stop)
        if ($resolved.Count -ne 1 -or
            $resolved[0].CommandType -notin @(
                [System.Management.Automation.CommandTypes]::Cmdlet,
                [System.Management.Automation.CommandTypes]::Function
            ) -or
            [IO.Path]::GetFullPath($resolved[0].Module.Path) -ne $manifest) {
            throw "Required command did not resolve from the pinned module: $moduleName\$commandName"
        }
    }
}

foreach ($letter in @('S', 'W')) {
    if (@(Storage\Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue).Count -ne 0) {
        throw "Drive letter $letter must be unused before collection."
    }
}

$hostBuild = [int](Microsoft.PowerShell.Management\Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuildNumber)
if ($hostBuild -lt 26100) { throw 'Host Windows build is too old for the frozen offline profile.' }
$bcdbootPath = [IO.Path]::Combine($WindowsRoot, 'System32', 'bcdboot.exe')
$bcdeditPath = [IO.Path]::Combine($WindowsRoot, 'System32', 'bcdedit.exe')
$bcdbootClaim = Get-TrustedMicrosoftExecutableClaim -LiteralPath $bcdbootPath
$bcdeditClaim = Get-TrustedMicrosoftExecutableClaim -LiteralPath $bcdeditPath
if ([Version]$bcdbootClaim.version -lt [Version]'10.0.26100.8037') {
    throw 'BCDBoot is too old for /offline non-bootex capture.'
}

$runId = [Guid]::NewGuid().ToString('N')
$work = [IO.Path]::Combine($outputParent, ".isopropyl-bcd-work-$runId")
$stage = [IO.Path]::Combine($outputParent, ".isopropyl-bcd-$runId.tmp")
if ([IO.Directory]::Exists($work) -or [IO.Directory]::Exists($stage)) {
    throw 'Generated private path unexpectedly exists.'
}
$scratch = [IO.Path]::Combine($work, 'scratch')
$isoCopy = [IO.Path]::Combine($work, 'source.iso')
$parentVhd = [IO.Path]::Combine($work, 'parent.vhd')
$cloneVhd = [IO.Path]::Combine($work, 'variant.vhd')
$templateOutput = [IO.Path]::Combine($stage, 'BCD-Template')
$collectorOutput = [IO.Path]::Combine($stage, 'collector.ps1')
$rawOutput = [IO.Path]::Combine($stage, 'capture.raw.json')

$isoMountAttempted = $false
$attachedVhd = $null
$published = $false
$outputMoved = $false
$cleanupFailure = $null
$captures = [Collections.Generic.List[object]]::new()

try {
    New-PrivateDirectory -LiteralPath $work
    New-PrivateDirectory -LiteralPath $stage
    New-PrivateDirectory -LiteralPath $scratch
    $collectorClaim = Copy-StableArtifact -Source $PSCommandPath -Destination $collectorOutput -MaximumBytes 1048576
    $isoBefore = Get-ArtifactClaim -LiteralPath $IsoPath -MaximumBytes ([UInt64]::MaxValue)
    $isoCopyClaim = Copy-StableArtifact -Source $IsoPath -Destination $isoCopy -MaximumBytes ([UInt64]::MaxValue)
    if ($isoBefore.size -ne $isoCopyClaim.size -or $isoBefore.sha256 -ne $isoCopyClaim.sha256) {
        throw 'The protected ISO copy contradicts its source.'
    }
    $copyAttachment = @(Storage\Get-DiskImage -ImagePath $isoCopy -ErrorAction SilentlyContinue)
    if ($copyAttachment.Count -gt 1 -or
        ($copyAttachment.Count -eq 1 -and $copyAttachment[0].Attached)) {
        throw 'The protected ISO copy is unexpectedly attached.'
    }
    $isoMountAttempted = $true
    $isoImage = Storage\Mount-DiskImage -ImagePath $isoCopy -StorageType ISO -Access ReadOnly -NoDriveLetter -PassThru
    $isoVolumes = @($isoImage | Storage\Get-Volume)
    if ($isoVolumes.Count -ne 1 -or $isoVolumes[0].FileSystemType -notin @('UDF', 'CDFS')) {
        throw 'ISO must expose exactly one read-only optical volume.'
    }
    $isoRoot = $isoVolumes[0].Path
    $installWim = [IO.Path]::Combine($isoRoot, 'sources', 'install.wim')
    if (-not [IO.File]::Exists($installWim)) { throw 'The frozen profile requires sources\install.wim.' }
    $wimClaim = Get-ArtifactClaim -LiteralPath $installWim -MaximumBytes ([UInt64]::MaxValue)
    $image = Dism\Get-WindowsImage -ImagePath $installWim -Index $ImageIndex -ScratchDirectory $scratch
    if ($image.Architecture -notin @('x64', 'amd64', 9)) { throw 'Selected Windows image is not amd64.' }
    $sourceVersion = [Version]([string]$image.Version)
    $sourceEdition = [string]$image.ImageName
    if ([string]::IsNullOrWhiteSpace($sourceEdition) -or $sourceEdition.Length -gt 256) {
        throw 'Selected Windows edition name is invalid.'
    }

    Hyper-V\New-VHD -Path $parentVhd -Fixed -SizeBytes $DiskSizeBytes -LogicalSectorSizeBytes 512 | Microsoft.PowerShell.Core\Out-Null
    $attachedVhd = $parentVhd
    Hyper-V\Mount-VHD -Path $parentVhd -PassThru | Microsoft.PowerShell.Core\Out-Null
    $disk = Resolve-BoundDisk -GeneratedVhdPath $parentVhd
    if ($disk.PartitionStyle -ne 'RAW') { throw 'New fixed VHD was not empty.' }
    $disk = Storage\Initialize-Disk -InputObject $disk -PartitionStyle GPT -PassThru
    $esp = Storage\New-Partition -InputObject $disk -Offset $EspOffsetBytes -Size $EspSizeBytes -GptType $EspType
    $msr = Storage\New-Partition -InputObject $disk -Offset $MsrOffsetBytes -Size $MsrSizeBytes -GptType $MsrType
    $windows = Storage\New-Partition -InputObject $disk -Offset $WindowsOffsetBytes -Size $WindowsSizeBytes -GptType $WindowsType
    Storage\Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel 'ISOPROPYL-ESP' -Force -Confirm:$false | Microsoft.PowerShell.Core\Out-Null
    Storage\Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'ISOPROPYL-WIN' -Force -Confirm:$false | Microsoft.PowerShell.Core\Out-Null
    $liveDisk = Resolve-BoundDisk -GeneratedVhdPath $parentVhd
    $liveParts = @(Storage\Get-Partition -InputObject $liveDisk | Microsoft.PowerShell.Utility\Sort-Object -Property Offset)
    if ($liveParts.Count -ne 3) { throw 'Generated parent did not expose three partitions.' }
    $liveIdentity = [PSCustomObject]@{
        DiskGuid = [Guid]$liveDisk.Guid
        EspGuid = [Guid]$liveParts[0].Guid
        MsrGuid = [Guid]$liveParts[1].Guid
        WindowsGuid = [Guid]$liveParts[2].Guid
    }
    $parts = Assert-PartitionLayout -Disk $liveDisk -ExpectedIdentity $liveIdentity
    Set-VerifiedLetters -Disk $liveDisk -Partitions $parts
    $dismLog = [IO.Path]::Combine($work, 'dism-parent.log')
    Dism\Expand-WindowsImage -ImagePath $installWim -Index $ImageIndex -ApplyPath 'W:\' -CheckIntegrity -Verify -ScratchDirectory $scratch -LogPath $dismLog | Microsoft.PowerShell.Core\Out-Null
    $templateSource = 'W:\Windows\System32\Config\BCD-Template'
    $templateClaim = Copy-StableArtifact -Source $templateSource -Destination $templateOutput -MaximumBytes $MaximumTemplateBytes
    Dismount-ExactVhd -GeneratedVhdPath $parentVhd
    $attachedVhd = $null
    $baselineIdentity = [IsopropylFixedVhdGpt]::ValidateAndPatch($parentVhd, 'baseline', [Guid]::Empty)
    if ($baselineIdentity.DiskGuid -ne $liveIdentity.DiskGuid -or
        $baselineIdentity.EspGuid -ne $liveIdentity.EspGuid -or
        $baselineIdentity.MsrGuid -ne $liveIdentity.MsrGuid -or
        $baselineIdentity.WindowsGuid -ne $liveIdentity.WindowsGuid) {
        throw 'Detached GPT identity contradicted the path-bound Storage observations.'
    }

    foreach ($variant in $Variants) {
        if ([IO.File]::Exists($cloneVhd)) { throw 'Previous clone was not cleaned up.' }
        [IO.File]::Copy($parentVhd, $cloneVhd, $false)
        $replacement = if ($variant -eq 'baseline') { [Guid]::Empty } else { [Guid]::NewGuid() }
        while ($replacement -ne [Guid]::Empty -and $replacement -in @(
            $baselineIdentity.DiskGuid, $baselineIdentity.EspGuid,
            $baselineIdentity.MsrGuid, $baselineIdentity.WindowsGuid
        )) { $replacement = [Guid]::NewGuid() }
        $variantIdentity = [IsopropylFixedVhdGpt]::ValidateAndPatch($cloneVhd, $variant, $replacement)
        $attachedVhd = $cloneVhd
        Hyper-V\Mount-VHD -Path $cloneVhd -PassThru | Microsoft.PowerShell.Core\Out-Null
        $variantDisk = Resolve-BoundDisk -GeneratedVhdPath $cloneVhd
        $variantParts = Assert-PartitionLayout -Disk $variantDisk -ExpectedIdentity $variantIdentity
        Set-VerifiedLetters -Disk $variantDisk -Partitions $variantParts

        $storeSource = 'S:\EFI\Microsoft\Boot\BCD'
        if ([IO.File]::Exists($storeSource)) { throw 'BCD store was not fresh before BCDBoot.' }
        [void][IO.Directory]::CreateDirectory('S:\EFI\Microsoft\Boot')
        Assert-VerifiedLetters -Disk $variantDisk
        $bcdboot = Invoke-CapturedCommand -Executable $bcdbootPath -Arguments @(
            'W:\Windows', '/v', '/offline', '/f', 'UEFI', '/s', 'S:'
        ) -DeadlineSeconds 120 -WorkingDirectory $scratch
        Assert-VerifiedLetters -Disk $variantDisk
        $recovery = Invoke-CapturedCommand -Executable $bcdeditPath -Arguments @(
            '/store', 'S:\EFI\Microsoft\Boot\BCD', '/set', '{default}', 'recoveryenabled', 'no'
        ) -DeadlineSeconds 30 -WorkingDirectory $scratch
        Assert-VerifiedLetters -Disk $variantDisk
        $enumeration = Invoke-CapturedCommand -Executable $bcdeditPath -Arguments @(
            '/store', 'S:\EFI\Microsoft\Boot\BCD', '/enum', 'all', '/v'
        ) -DeadlineSeconds 30 -WorkingDirectory $scratch
        if ([string]::IsNullOrEmpty($enumeration.stdout_base64)) {
            throw 'BCDEdit enumeration produced no stdout evidence.'
        }
        $storeOutput = [IO.Path]::Combine($stage, "$variant.BCD")
        $storeClaim = Copy-StableArtifact -Source $storeSource -Destination $storeOutput -MaximumBytes $MaximumHiveBytes
        $signature = [IO.File]::ReadAllBytes($storeOutput)[0..3]
        if ([Text.Encoding]::ASCII.GetString($signature) -ne 'regf') {
            throw 'Captured BCD does not have a registry-hive signature.'
        }
        [void]$captures.Add([ordered]@{
            variant = $variant
            disk_guid = $variantIdentity.DiskGuid.ToString()
            esp_partition_guid = $variantIdentity.EspGuid.ToString()
            windows_partition_guid = $variantIdentity.WindowsGuid.ToString()
            store = $storeClaim
            commands = [ordered]@{
                bcdboot = $bcdboot
                bcdedit_set_recovery = $recovery
                bcdedit_enum = $enumeration
            }
        })

        Dismount-ExactVhd -GeneratedVhdPath $cloneVhd
        $attachedVhd = $null
        [IO.File]::Delete($cloneVhd)
    }

    $raw = [ordered]@{
        schema = $Schema
        profile = [ordered]@{
            host_windows_build = $hostBuild
            source_windows_build = [int]$sourceVersion.Build
            source_iso_sha256 = $isoBefore.sha256
            source_wim_sha256 = $wimClaim.sha256
            source_wim_index = $ImageIndex
            source_edition = $sourceEdition
            disk_size_bytes = $DiskSizeBytes
            msr_partition_guid = $baselineIdentity.MsrGuid.ToString()
            bcdboot = $bcdbootClaim
            bcdedit = $bcdeditClaim
            template = $templateClaim
            collector = $collectorClaim
        }
        captures = @($captures)
    }
    $json = $raw | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4194304) {
        throw 'RAW capture JSON exceeds the importer limit.'
    }
    [IO.File]::WriteAllText($rawOutput, $json + "`n", [Text.UTF8Encoding]::new($false))
    $rawClaim = Get-ArtifactClaim -LiteralPath $rawOutput -MaximumBytes 4194304
    $expectedOutputClaims = [ordered]@{
        'capture.raw.json' = $rawClaim
        'collector.ps1' = $collectorClaim
        'BCD-Template' = $templateClaim
    }
    foreach ($capture in $captures) {
        $expectedOutputClaims["$($capture.variant).BCD"] = $capture.store
    }
    Assert-EvidenceTree -LiteralPath $stage -ExpectedClaims $expectedOutputClaims

    Storage\Dismount-DiskImage -ImagePath $isoCopy
    $isoMountAttempted = $false
    $isoAfter = Get-ArtifactClaim -LiteralPath $IsoPath -MaximumBytes ([UInt64]::MaxValue)
    if ($isoBefore.size -ne $isoAfter.size -or $isoBefore.sha256 -ne $isoAfter.sha256) {
        throw 'Source ISO changed during collection.'
    }
    foreach ($toolClaim in @($bcdbootClaim, $bcdeditClaim)) {
        $current = Get-TrustedMicrosoftExecutableClaim -LiteralPath $toolClaim.path
        if ($current.version -ne $toolClaim.version -or
            $current.executable_sha256 -ne $toolClaim.executable_sha256) {
            throw 'A pinned Windows tool changed during collection.'
        }
    }
    foreach ($claim in @(
        @($collectorOutput, $collectorClaim.sha256),
        @($templateOutput, $templateClaim.sha256)
    )) {
        if ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $claim[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $claim[1]) {
            throw 'A pinned evidence artifact changed during collection.'
        }
    }
    [IO.Directory]::Delete($work, $true)
    $work = $null
    [IO.Directory]::Move($stage, $OutputDirectory)
    $outputMoved = $true
    Assert-EvidenceTree -LiteralPath $OutputDirectory -ExpectedClaims $expectedOutputClaims
    $published = $true
    $outputMoved = $false
    $stage = $null
    Microsoft.PowerShell.Utility\Write-Output "RAW BCD evidence collected at $OutputDirectory"
}
finally {
    try {
        if ($null -ne $attachedVhd) {
            Dismount-ExactVhd -GeneratedVhdPath $attachedVhd
            $attachedVhd = $null
        }
        if ($isoMountAttempted -and $null -ne $isoCopy) {
            $copyAttachment = @(Storage\Get-DiskImage -ImagePath $isoCopy -ErrorAction SilentlyContinue)
            if ($copyAttachment.Count -eq 1 -and $copyAttachment[0].Attached) {
                Storage\Dismount-DiskImage -ImagePath $isoCopy
            }
            $isoMountAttempted = $false
        }
    }
    catch {
        $cleanupFailure = $_
    }
    if (-not $published -and $null -ne $stage -and [IO.Directory]::Exists($stage)) {
        try { [IO.Directory]::Delete($stage, $true) } catch { if ($null -eq $cleanupFailure) { $cleanupFailure = $_ } }
    }
    if ($outputMoved -and -not $published -and [IO.Directory]::Exists($OutputDirectory)) {
        try { [IO.Directory]::Delete($OutputDirectory, $true) } catch { if ($null -eq $cleanupFailure) { $cleanupFailure = $_ } }
    }
    if ($null -ne $work -and [IO.Directory]::Exists($work) -and $null -eq $cleanupFailure) {
        try { [IO.Directory]::Delete($work, $true) } catch { $cleanupFailure = $_ }
    }
    if ($null -ne $cleanupFailure) {
        throw "Collector cleanup did not complete; inspect the ACL-private work directory before retrying: $cleanupFailure"
    }
}
