using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Emulation.OS.Linux.Files;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Linux
{
    public delegate long SpecialPathHandlerDelegate(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write);

    internal enum SpecialPathKind
    {
        CharacterDevice,
        Directory,
        RegularFile
    }

    internal sealed class SpecialPathEntry
    {
        public string Path { get; set; } = string.Empty;
        public SpecialPathKind Kind { get; set; }
        public SpecialPathHandlerDelegate? Handler { get; set; }
    }

    public class SpecialPathsHandlers
    {
        private const int X_OK = 1;
        private const int O_ACCMODE = 0x3;
        private const int O_WRONLY = 0x1;
        private const int O_RDWR = 0x2;
        private const int O_DIRECTORY = 0x10000;
        private const long PROCFS_MEMTOTAL_KB = 1048576;
        private const long PROCFS_SWAPTOTAL_KB = 2097152;
        private const long PROCFS_SWAPUSED_KB = 65536;

        private readonly Dictionary<string, SpecialPathEntry> Entries;

        public SpecialPathsHandlers()
        {
            Entries = new Dictionary<string, SpecialPathEntry>(StringComparer.Ordinal);

            RegisterDirectory("/dev");
            RegisterDirectory("/dev/fd");
            RegisterDirectory("/proc");
            RegisterDirectory("/proc/self");
            RegisterDirectory("/proc/self/fd");
            RegisterDirectory("/proc/self/task");
            RegisterDirectory("/proc/sys");
            RegisterDirectory("/proc/sys/kernel");
            RegisterDirectory("/sys");
            RegisterDirectory("/sys/class");
            RegisterDirectory("/sys/devices");
            RegisterDirectory("/sys/devices/system");
            RegisterDirectory("/sys/devices/system/cpu");
            RegisterDirectory("/sys/class/drm");
            RegisterDirectory("/sys/class/drm/card0");
            RegisterDirectory("/sys/class/drm/card0/device");
            RegisterDirectory("/sys/class/drm/card0/device/power");
            RegisterDirectory("/sys/class/drm/card0-eDP-1");
            RegisterDirectory("/sys/class/power_supply");
            RegisterDirectory("/sys/class/power_supply/AC");
            RegisterDirectory("/sys/class/power_supply/ADP1");
            RegisterDirectory("/sys/class/power_supply/BAT0");

            RegisterCharacterDevice("/dev/null", DevNull);
            RegisterCharacterDevice("/dev/zero", DevZero);
            RegisterCharacterDevice("/dev/random", DevRandom);
            RegisterCharacterDevice("/dev/urandom", DevURandom);
            RegisterCharacterDevice("/dev/stdin", DevStdIn);
            RegisterCharacterDevice("/dev/stdout", DevStdOut);
            RegisterCharacterDevice("/dev/stderr", DevStdErr);
            RegisterCharacterDevice("/dev/tty", DevTty);

            RegisterRegularFile("/proc/cpuinfo", ProcCpuInfo);
            RegisterRegularFile("/proc/filesystems", ProcFileSystems);
            RegisterRegularFile("/proc/meminfo", ProcMemInfo);
            RegisterRegularFile("/proc/mounts", ProcMounts);
            RegisterRegularFile("/proc/stat", GeneratedFile);
            RegisterRegularFile("/proc/swaps", GeneratedFile);
            RegisterRegularFile("/proc/uptime", ProcUptime);
            RegisterRegularFile("/proc/version", ProcVersion);
            RegisterRegularFile("/proc/self/cmdline", ProcSelfCmdline);
            RegisterRegularFile("/proc/self/comm", ProcSelfComm);
            RegisterRegularFile("/proc/self/maps", ProcSelfMaps);
            RegisterRegularFile("/proc/self/mounts", ProcMounts);
            RegisterRegularFile("/proc/self/statm", ProcSelfStatm);
            RegisterRegularFile("/proc/self/status", ProcSelfStatus);
            RegisterRegularFile("/proc/sys/kernel/hostname", ProcKernelHostname);
            RegisterRegularFile("/proc/sys/kernel/osrelease", ProcKernelOsRelease);
            RegisterRegularFile("/proc/sys/kernel/ostype", ProcKernelOsType);
            RegisterRegularFile("/proc/sys/kernel/version", ProcKernelVersion);

            RegisterRegularFile("/sys/class/drm/card0/device/power/runtime_status", GeneratedFile);
            RegisterRegularFile("/sys/class/drm/card0-eDP-1/connector_id", GeneratedFile);
            RegisterRegularFile("/sys/class/drm/card0-eDP-1/dpms", GeneratedFile);
            RegisterRegularFile("/sys/class/drm/card0-eDP-1/edid", GeneratedFile);
            RegisterRegularFile("/sys/class/drm/card0-eDP-1/enabled", GeneratedFile);
            RegisterRegularFile("/sys/class/drm/card0-eDP-1/modes", GeneratedFile);
            RegisterRegularFile("/sys/class/drm/card0-eDP-1/status", GeneratedFile);
            RegisterRegularFile("/sys/devices/system/cpu/kernel_max", GeneratedFile);
            RegisterRegularFile("/sys/devices/system/cpu/offline", GeneratedFile);
            RegisterRegularFile("/sys/devices/system/cpu/online", GeneratedFile);
            RegisterRegularFile("/sys/devices/system/cpu/possible", GeneratedFile);
            RegisterRegularFile("/sys/devices/system/cpu/present", GeneratedFile);

            RegisterPowerSupplyFile("/sys/class/power_supply/AC/online");
            RegisterPowerSupplyFile("/sys/class/power_supply/AC/type");
            RegisterPowerSupplyFile("/sys/class/power_supply/AC/uevent");
            RegisterPowerSupplyFile("/sys/class/power_supply/ADP1/online");
            RegisterPowerSupplyFile("/sys/class/power_supply/ADP1/type");
            RegisterPowerSupplyFile("/sys/class/power_supply/ADP1/uevent");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/capacity");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/capacity_level");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/charge_full");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/charge_full_design");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/charge_now");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/current_now");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/cycle_count");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/manufacturer");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/model_name");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/online");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/present");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/scope");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/serial_number");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/status");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/technology");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/temp");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/type");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/uevent");
            RegisterPowerSupplyFile("/sys/class/power_supply/BAT0/voltage_now");
        }

        private void RegisterCharacterDevice(string PathValue, SpecialPathHandlerDelegate Handler)
        {
            string NormalizedPath = NormalizePath(PathValue);
            Entries[NormalizedPath] = new SpecialPathEntry
            {
                Path = NormalizedPath,
                Kind = SpecialPathKind.CharacterDevice,
                Handler = Handler
            };
        }

        private void RegisterRegularFile(string PathValue, SpecialPathHandlerDelegate Handler)
        {
            string NormalizedPath = NormalizePath(PathValue);
            Entries[NormalizedPath] = new SpecialPathEntry
            {
                Path = NormalizedPath,
                Kind = SpecialPathKind.RegularFile,
                Handler = Handler
            };
        }

        private void RegisterPowerSupplyFile(string PathValue)
        {
            RegisterRegularFile(PathValue, GeneratedFile);
        }

        private void RegisterDirectory(string PathValue)
        {
            string NormalizedPath = NormalizePath(PathValue);
            Entries[NormalizedPath] = new SpecialPathEntry
            {
                Path = NormalizedPath,
                Kind = SpecialPathKind.Directory
            };
        }

        public bool TryHandle(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write, out long Result)
        {
            Result = 0;
            if (File == null || string.IsNullOrWhiteSpace(File.Path))
                return false;

            if (File.IsDirectory)
            {
                Result = -(long)LinuxErrno.EISDIR;
                return true;
            }

            string PathValue = ResolveSpecialPath(Helper, File.Path);
            if (IsDynamicGeneratedPath(PathValue))
            {
                Result = ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, PathValue);
                return true;
            }

            if (!Entries.TryGetValue(PathValue, out SpecialPathEntry? Entry) || Entry.Handler == null)
                return false;

            Result = Entry.Handler(Instance, Helper, File, BufferAddress, Length, Write);
            return true;
        }

        public bool TryOpenPath(LinuxSyscallsHelper Helper, string PathValue, int Flags, bool CloseOnExec, ulong DescriptorLimit, out long Result)
        {
            Result = 0;
            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return false;

            if (string.Equals(NormalizedPath, "/dev/stdin", StringComparison.Ordinal))
                return TryDuplicateExistingDescriptor(Helper, 0, CloseOnExec, DescriptorLimit, out Result);

            if (string.Equals(NormalizedPath, "/dev/stdout", StringComparison.Ordinal))
                return TryDuplicateExistingDescriptor(Helper, 1, CloseOnExec, DescriptorLimit, out Result);

            if (string.Equals(NormalizedPath, "/dev/stderr", StringComparison.Ordinal))
                return TryDuplicateExistingDescriptor(Helper, 2, CloseOnExec, DescriptorLimit, out Result);

            if (string.Equals(NormalizedPath, "/dev/tty", StringComparison.Ordinal))
            {
                if ((Flags & O_DIRECTORY) != 0)
                {
                    Result = -(long)LinuxErrno.ENOTDIR;
                    return true;
                }

                FileObject TerminalObject = new FileObject
                {
                    Path = NormalizedPath,
                    HostPath = NormalizedPath,
                    StatusFlags = O_RDWR,
                    IsSpecialPath = true,
                    IsDirectory = false,
                    TerminalState = Helper.TerminalState
                };

                if (!Helper.DescriptorTable.TryAddHandle(TerminalObject, CloseOnExec, DescriptorLimit, out ulong TerminalDescriptor))
                {
                    Result = -(long)LinuxErrno.EMFILE;
                    return true;
                }

                Result = (long)TerminalDescriptor;
                return true;
            }


            if (TryGetExistingDescriptor(Helper, NormalizedPath, out ulong ExistingDescriptor, out bool IsDescriptorAlias))
            {
                if (!IsDescriptorAlias)
                    return false;

                return TryDuplicateExistingDescriptor(Helper, ExistingDescriptor, CloseOnExec, DescriptorLimit, out Result);
            }

            if (IsDynamicDirectoryPath(NormalizedPath))
            {
                if ((Flags & O_ACCMODE) != 0)
                {
                    Result = -(long)LinuxErrno.EISDIR;
                    return true;
                }

                FileObject DirectoryObject = new FileObject
                {
                    Path = NormalizedPath,
                    HostPath = NormalizedPath,
                    StatusFlags = Flags,
                    IsSpecialPath = true,
                    IsDirectory = true
                };

                if (!Helper.DescriptorTable.TryAddHandle(DirectoryObject, CloseOnExec, DescriptorLimit, out ulong DirectoryDescriptor))
                {
                    Result = -(long)LinuxErrno.EMFILE;
                    return true;
                }

                Result = (long)DirectoryDescriptor;
                return true;
            }

            if (IsDynamicGeneratedPath(NormalizedPath))
            {
                if ((Flags & O_DIRECTORY) != 0)
                {
                    Result = -(long)LinuxErrno.ENOTDIR;
                    return true;
                }

                FileObject SpecialObject2 = new FileObject
                {
                    Path = NormalizedPath,
                    HostPath = NormalizedPath,
                    StatusFlags = Flags,
                    IsSpecialPath = true,
                    IsDirectory = false
                };

                if (!Helper.DescriptorTable.TryAddHandle(SpecialObject2, CloseOnExec, DescriptorLimit, out ulong SpecialDescriptor2))
                {
                    Result = -(long)LinuxErrno.EMFILE;
                    return true;
                }

                Result = (long)SpecialDescriptor2;
                return true;
            }

            if (!Entries.TryGetValue(NormalizedPath, out SpecialPathEntry? Entry))
                return false;

            if (Entry.Kind == SpecialPathKind.Directory)
            {
                if ((Flags & O_ACCMODE) != 0)
                {
                    Result = -(long)LinuxErrno.EISDIR;
                    return true;
                }

                FileObject DirectoryObject = new FileObject
                {
                    Path = NormalizedPath,
                    HostPath = NormalizedPath,
                    StatusFlags = Flags,
                    IsSpecialPath = true,
                    IsDirectory = true
                };

                if (!Helper.DescriptorTable.TryAddHandle(DirectoryObject, CloseOnExec, DescriptorLimit, out ulong DirectoryDescriptor))
                {
                    Result = -(long)LinuxErrno.EMFILE;
                    return true;
                }

                Result = (long)DirectoryDescriptor;
                return true;
            }

            if ((Flags & O_DIRECTORY) != 0)
            {
                Result = -(long)LinuxErrno.ENOTDIR;
                return true;
            }

            FileObject SpecialObject = new FileObject
            {
                Path = NormalizedPath,
                HostPath = NormalizedPath,
                StatusFlags = Flags,
                IsSpecialPath = true,
                IsDirectory = false
            };

            if (!Helper.DescriptorTable.TryAddHandle(SpecialObject, CloseOnExec, DescriptorLimit, out ulong SpecialDescriptor))
            {
                Result = -(long)LinuxErrno.EMFILE;
                return true;
            }

            Result = (long)SpecialDescriptor;
            return true;
        }

        public bool TryAccess(LinuxSyscallsHelper Helper, string PathValue, int Mode, out long Result)
        {
            Result = 0;
            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return false;

            if (TryGetExistingDescriptor(Helper, NormalizedPath, out ulong ExistingDescriptor, out bool IsDescriptorAlias) && IsDescriptorAlias)
            {
                Result = Helper.DescriptorTable.ContainsHandle(ExistingDescriptor) ? 0 : -(long)LinuxErrno.ENOENT;
                return true;
            }

            if (IsDynamicDirectoryPath(NormalizedPath) || IsDynamicGeneratedPath(NormalizedPath))
            {
                if ((Mode & X_OK) != 0 && !IsDynamicDirectoryPath(NormalizedPath))
                {
                    Result = -(long)LinuxErrno.EACCES;
                    return true;
                }

                Result = 0;
                return true;
            }

            if (!Entries.TryGetValue(NormalizedPath, out SpecialPathEntry? Entry))
                return false;

            if ((Mode & X_OK) != 0 && Entry.Kind != SpecialPathKind.Directory)
            {
                Result = -(long)LinuxErrno.EACCES;
                return true;
            }

            Result = 0;
            return true;
        }

        public bool TryCreateSpecialFileObject(LinuxSyscallsHelper Helper, string PathValue, out FileObject File)
        {
            File = null;
            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return false;

            if (TryGetExistingDescriptor(Helper, NormalizedPath, out _, out bool IsDescriptorAlias) && IsDescriptorAlias)
            {
                File = new FileObject
                {
                    Path = NormalizedPath,
                    HostPath = NormalizedPath,
                    IsSpecialPath = true,
                    IsDirectory = false
                };

                return true;
            }

            if (IsDynamicDirectoryPath(NormalizedPath) || IsDynamicGeneratedPath(NormalizedPath))
            {
                File = new FileObject
                {
                    Path = NormalizedPath,
                    HostPath = NormalizedPath,
                    IsSpecialPath = true,
                    IsDirectory = IsDynamicDirectoryPath(NormalizedPath)
                };

                return true;
            }

            if (!Entries.TryGetValue(NormalizedPath, out SpecialPathEntry? Entry))
                return false;

            File = new FileObject
            {
                Path = NormalizedPath,
                HostPath = NormalizedPath,
                IsSpecialPath = true,
                IsDirectory = Entry.Kind == SpecialPathKind.Directory
            };

            return true;
        }

        public bool TryCreateSpecialStatData(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, out LinuxStatData Data)
        {
            Data = default;
            if (File == null || string.IsNullOrWhiteSpace(File.Path))
                return false;

            string NormalizedPath = ResolveSpecialPath(Helper, File.Path);
            ulong StableId = LinuxStatHelper.ComputeStableId(NormalizedPath);
            LinuxTimespec64 Now = LinuxStatHelper.ToTimespec64(DateTimeOffset.UtcNow);

            if (TryGetExistingDescriptor(Helper, NormalizedPath, out ulong Descriptor, out bool IsDescriptorAlias) && IsDescriptorAlias)
            {
                Data = new LinuxStatData
                {
                    Device = StableId,
                    Inode = LinuxStatHelper.ComputeStableId(NormalizedPath + ":" + Descriptor.ToString()),
                    NLink = 1,
                    Mode = 0xA000 | 0x1FF,
                    Uid = Helper.Credentials.RealUserId,
                    Gid = Helper.Credentials.RealGroupId,
                    RDev = StableId,
                    Size = NormalizedPath.Length,
                    BlockSize = 4096,
                    Blocks = LinuxStatHelper.GetBlockCount(NormalizedPath.Length),
                    AccessTime = Now,
                    ModifyTime = Now,
                    ChangeTime = Now,
                    Kind = LinuxStatFileKind.SymbolicLink
                };

                return true;
            }

            if (IsDynamicDirectoryPath(NormalizedPath) || IsDynamicGeneratedPath(NormalizedPath))
            {
                long DynamicSize = IsDynamicGeneratedPath(NormalizedPath) ? BuildContent(Instance, Helper, NormalizedPath).Length : 4096;
                Data = new LinuxStatData
                {
                    Device = StableId,
                    Inode = StableId,
                    NLink = IsDynamicDirectoryPath(NormalizedPath) ? 2UL : 1UL,
                    Mode = IsDynamicDirectoryPath(NormalizedPath) ? 0x4000U | 0x1EDU : 0x8000U | 0x1A4U,
                    Uid = Helper.Credentials.RealUserId,
                    Gid = Helper.Credentials.RealGroupId,
                    RDev = 0,
                    Size = DynamicSize,
                    BlockSize = 4096,
                    Blocks = LinuxStatHelper.GetBlockCount(DynamicSize),
                    AccessTime = Now,
                    ModifyTime = Now,
                    ChangeTime = Now,
                    Kind = IsDynamicDirectoryPath(NormalizedPath) ? LinuxStatFileKind.Directory : LinuxStatFileKind.RegularFile
                };

                return true;
            }

            if (!Entries.TryGetValue(NormalizedPath, out SpecialPathEntry? Entry))
                return false;

            long Size = 0;
            uint Mode = Entry.Kind switch
            {
                SpecialPathKind.Directory => 0x4000 | 0x1ED,
                SpecialPathKind.RegularFile => 0x8000 | 0x1A4,
                _ => 0x2000 | 0x1B6
            };

            ulong NLink = Entry.Kind == SpecialPathKind.Directory ? 2UL : 1UL;
            ulong RDev = Entry.Kind == SpecialPathKind.CharacterDevice ? StableId : 0;
            LinuxStatFileKind Kind = Entry.Kind switch
            {
                SpecialPathKind.Directory => LinuxStatFileKind.Directory,
                SpecialPathKind.RegularFile => LinuxStatFileKind.RegularFile,
                _ => LinuxStatFileKind.CharacterDevice
            };

            if (Entry.Kind == SpecialPathKind.RegularFile && Entry.Handler != null)
                Size = BuildContent(Instance, Helper, NormalizedPath).Length;
            else if (Entry.Kind == SpecialPathKind.Directory)
                Size = 4096;

            Data = new LinuxStatData
            {
                Device = StableId,
                Inode = StableId,
                NLink = NLink,
                Mode = Mode,
                Uid = Helper.Credentials.RealUserId,
                Gid = Helper.Credentials.RealGroupId,
                RDev = RDev,
                Size = Size,
                BlockSize = 4096,
                Blocks = LinuxStatHelper.GetBlockCount(Size),
                AccessTime = Now,
                ModifyTime = Now,
                ChangeTime = Now,
                Kind = Kind
            };

            return true;
        }

        public bool TryResolveHostBackedPath(LinuxSyscallsHelper Helper, string PathValue, out string HostPath)
        {
            HostPath = null;
            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            if (string.Equals(NormalizedPath, "/etc/localtime", StringComparison.Ordinal))
            {
                if (OperatingSystem.IsLinux() && File.Exists("/etc/localtime"))
                {
                    HostPath = "/etc/localtime";
                    return true;
                }

                if (TryResolveZoneInfoPath(Helper, GetHostTimeZoneId(), out HostPath))
                    return true;

                if (TryResolveZoneInfoPath(Helper, "Etc/UTC", out HostPath))
                    return true;

                HostPath = null;
                return false;
            }

            if (string.Equals(NormalizedPath, "/proc/self/exe", StringComparison.Ordinal))
            {
                if (string.IsNullOrWhiteSpace(Helper.ProcessExecutablePath))
                    return false;

                string ResolvedHostPath = Helper.ResolveHostPath(Helper.ProcessExecutablePath);
                if (!string.IsNullOrWhiteSpace(ResolvedHostPath) && (File.Exists(ResolvedHostPath) || Directory.Exists(ResolvedHostPath)))
                {
                    HostPath = ResolvedHostPath;
                    return true;
                }
            }

            if (TryParseDynamicProcessPath(NormalizedPath, out int ProcessId, out string Leaf)
                && string.Equals(Leaf, "exe", StringComparison.Ordinal)
                && Helper.TryGetProcessInfo(ProcessId, out LinuxProcessInfo Process)
                && !string.IsNullOrWhiteSpace(Process.ExecutablePath))
            {
                string ResolvedHostPath = Helper.ResolveHostPath(Process.ExecutablePath);
                if (!string.IsNullOrWhiteSpace(ResolvedHostPath) && (File.Exists(ResolvedHostPath) || Directory.Exists(ResolvedHostPath)))
                {
                    HostPath = ResolvedHostPath;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Builds synthesized directory entries for a special Linux path.
        /// </summary>
        internal bool TryEnumerateDirectory(LinuxSyscallsHelper Helper, string PathValue, out List<LinuxDirectoryEntry> DirectoryEntries)
        {
            DirectoryEntries = null;
            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return false;

            List<LinuxDirectoryEntry> Result = new List<LinuxDirectoryEntry>();

            if (TryParseDynamicCpuPath(NormalizedPath, out _, out string CpuLeaf) && string.IsNullOrEmpty(CpuLeaf))
            {
                DirectoryEntries = Result;
                return true;
            }

            switch (NormalizedPath)
            {
                case "/dev":
                    {
                        AddEntry(Result, "/dev/fd", "fd", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/dev/null", "null", LinuxDirectoryEntryType.CharacterDevice);
                        AddEntry(Result, "/dev/random", "random", LinuxDirectoryEntryType.CharacterDevice);
                        AddEntry(Result, "/dev/stderr", "stderr", LinuxDirectoryEntryType.SymbolicLink);
                        AddEntry(Result, "/dev/stdin", "stdin", LinuxDirectoryEntryType.SymbolicLink);
                        AddEntry(Result, "/dev/stdout", "stdout", LinuxDirectoryEntryType.SymbolicLink);
                        AddEntry(Result, "/dev/tty", "tty", LinuxDirectoryEntryType.CharacterDevice);
                        AddEntry(Result, "/dev/urandom", "urandom", LinuxDirectoryEntryType.CharacterDevice);
                        AddEntry(Result, "/dev/zero", "zero", LinuxDirectoryEntryType.CharacterDevice);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/dev/fd":
                    {
                        AddDescriptorEntries(Helper, Result);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/proc":
                    {
                        AddEntry(Result, "/proc/cpuinfo", "cpuinfo", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/filesystems", "filesystems", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/meminfo", "meminfo", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/mounts", "mounts", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/stat", "stat", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/self", "self", LinuxDirectoryEntryType.SymbolicLink);
                        AddEntry(Result, "/proc/swaps", "swaps", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/thread-self", "thread-self", LinuxDirectoryEntryType.SymbolicLink);
                        AddEntry(Result, "/proc/sys", "sys", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/proc/uptime", "uptime", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/version", "version", LinuxDirectoryEntryType.RegularFile);
                        foreach (LinuxProcessInfo ProcessLinux in Helper.EnumerateProcesses())
                            AddEntry(Result, "/proc/" + ProcessLinux.ProcessId.ToString(), ProcessLinux.ProcessId.ToString(), LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/proc/sys":
                    {
                        AddEntry(Result, "/proc/sys/kernel", "kernel", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/proc/sys/kernel":
                    {
                        AddEntry(Result, "/proc/sys/kernel/hostname", "hostname", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/sys/kernel/osrelease", "osrelease", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/sys/kernel/ostype", "ostype", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/proc/sys/kernel/version", "version", LinuxDirectoryEntryType.RegularFile);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys":
                    {
                        AddEntry(Result, "/sys/class", "class", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/sys/devices", "devices", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/devices":
                    {
                        AddEntry(Result, "/sys/devices/system", "system", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/devices/system":
                    {
                        AddEntry(Result, "/sys/devices/system/cpu", "cpu", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/devices/system/cpu":
                    {
                        int CpuCount = Helper.SystemIdentity.GetCpuCount();
                        for (int Index = 0; Index < CpuCount; Index++)
                            AddEntry(Result, "/sys/devices/system/cpu/cpu" + Index.ToString(), "cpu" + Index.ToString(), LinuxDirectoryEntryType.Directory);

                        AddEntry(Result, "/sys/devices/system/cpu/kernel_max", "kernel_max", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/devices/system/cpu/offline", "offline", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/devices/system/cpu/online", "online", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/devices/system/cpu/possible", "possible", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/devices/system/cpu/present", "present", LinuxDirectoryEntryType.RegularFile);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class":
                    {
                        AddEntry(Result, "/sys/class/drm", "drm", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/sys/class/power_supply", "power_supply", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/power_supply":
                    {
                        AddEntry(Result, "/sys/class/power_supply/AC", "AC", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/sys/class/power_supply/ADP1", "ADP1", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/sys/class/power_supply/BAT0", "BAT0", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/power_supply/AC":
                    {
                        AddPowerSupplyEntries(Result, "/sys/class/power_supply/AC", "online", "type", "uevent");
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/power_supply/ADP1":
                    {
                        AddPowerSupplyEntries(Result, "/sys/class/power_supply/ADP1", "online", "type", "uevent");
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/power_supply/BAT0":
                    {
                        AddPowerSupplyEntries(Result, "/sys/class/power_supply/BAT0", "capacity", "capacity_level", "charge_full", "charge_full_design", "charge_now", "current_now", "cycle_count", "manufacturer", "model_name", "online", "present", "scope", "serial_number", "status", "technology", "temp", "type", "uevent", "voltage_now");
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/drm":
                    {
                        AddEntry(Result, "/sys/class/drm/card0", "card0", LinuxDirectoryEntryType.Directory);
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1", "card0-eDP-1", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/drm/card0":
                    {
                        AddEntry(Result, "/sys/class/drm/card0/device", "device", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/drm/card0/device":
                    {
                        AddEntry(Result, "/sys/class/drm/card0/device/power", "power", LinuxDirectoryEntryType.Directory);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/drm/card0/device/power":
                    {
                        AddEntry(Result, "/sys/class/drm/card0/device/power/runtime_status", "runtime_status", LinuxDirectoryEntryType.RegularFile);
                        DirectoryEntries = Result;
                        return true;
                    }
                case "/sys/class/drm/card0-eDP-1":
                    {
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1/connector_id", "connector_id", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1/dpms", "dpms", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1/edid", "edid", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1/enabled", "enabled", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1/modes", "modes", LinuxDirectoryEntryType.RegularFile);
                        AddEntry(Result, "/sys/class/drm/card0-eDP-1/status", "status", LinuxDirectoryEntryType.RegularFile);
                        DirectoryEntries = Result;
                        return true;
                    }
            }

            if (TryParseDynamicProcessPath(NormalizedPath, out int ProcessId, out string ProcessLeaf) && Helper.TryGetProcessInfo(ProcessId, out LinuxProcessInfo Process))
            {
                if (string.IsNullOrEmpty(ProcessLeaf))
                {
                    AddEntry(Result, $"/proc/{ProcessId}/cmdline", "cmdline", LinuxDirectoryEntryType.RegularFile);
                    AddEntry(Result, $"/proc/{ProcessId}/comm", "comm", LinuxDirectoryEntryType.RegularFile);
                    AddEntry(Result, $"/proc/{ProcessId}/exe", "exe", LinuxDirectoryEntryType.SymbolicLink);
                    AddEntry(Result, $"/proc/{ProcessId}/fd", "fd", LinuxDirectoryEntryType.Directory);
                    AddEntry(Result, $"/proc/{ProcessId}/maps", "maps", LinuxDirectoryEntryType.RegularFile);
                    AddEntry(Result, $"/proc/{ProcessId}/mounts", "mounts", LinuxDirectoryEntryType.RegularFile);
                    AddEntry(Result, $"/proc/{ProcessId}/statm", "statm", LinuxDirectoryEntryType.RegularFile);
                    AddEntry(Result, $"/proc/{ProcessId}/status", "status", LinuxDirectoryEntryType.RegularFile);
                    AddEntry(Result, $"/proc/{ProcessId}/task", "task", LinuxDirectoryEntryType.Directory);
                    DirectoryEntries = Result;
                    return true;
                }

                if (string.Equals(ProcessLeaf, "fd", StringComparison.Ordinal))
                {
                    if (ProcessId == Helper.PID)
                        AddDescriptorEntries(Helper, Result);

                    DirectoryEntries = Result;
                    return true;
                }

                if (string.Equals(ProcessLeaf, "task", StringComparison.Ordinal))
                {
                    foreach (LinuxTaskInfo Task in Process.Threads.Values.OrderBy(Task => Task.ThreadId))
                        AddEntry(Result, $"/proc/{ProcessId}/task/{Task.ThreadId}", Task.ThreadId.ToString(), LinuxDirectoryEntryType.Directory);

                    DirectoryEntries = Result;
                    return true;
                }
            }

            if (TryParseDynamicTaskPath(NormalizedPath, out int TaskProcessId, out uint ThreadId, out string TaskLeaf)
                && string.IsNullOrEmpty(TaskLeaf)
                && Helper.TryGetThreadInfo(TaskProcessId, ThreadId, out _))
            {
                AddEntry(Result, $"/proc/{TaskProcessId}/task/{ThreadId}/comm", "comm", LinuxDirectoryEntryType.RegularFile);
                AddEntry(Result, $"/proc/{TaskProcessId}/task/{ThreadId}/fd", "fd", LinuxDirectoryEntryType.Directory);
                AddEntry(Result, $"/proc/{TaskProcessId}/task/{ThreadId}/status", "status", LinuxDirectoryEntryType.RegularFile);
                DirectoryEntries = Result;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Adds file descriptor symlink entries to a synthesized directory listing.
        /// </summary>
        private static void AddDescriptorEntries(LinuxSyscallsHelper Helper, List<LinuxDirectoryEntry> DirectoryEntries)
        {
            foreach (ulong Descriptor in Helper.DescriptorTable.EnumerateDescriptors())
            {
                string Name = Descriptor.ToString();
                AddEntry(DirectoryEntries, "/proc/self/fd/" + Name, Name, LinuxDirectoryEntryType.SymbolicLink);
            }
        }

        /// <summary>
        /// Adds synthesized sysfs power_supply file entries.
        /// </summary>
        private static void AddPowerSupplyEntries(List<LinuxDirectoryEntry> DirectoryEntries, string BasePath, params string[] Names)
        {
            foreach (string Name in Names)
                AddEntry(DirectoryEntries, BasePath + "/" + Name, Name, LinuxDirectoryEntryType.RegularFile);
        }

        /// <summary>
        /// Adds a synthesized special-path directory entry with a stable inode value.
        /// </summary>
        private static void AddEntry(List<LinuxDirectoryEntry> DirectoryEntries, string PathValue, string Name, LinuxDirectoryEntryType Type)
        {
            DirectoryEntries.Add(new LinuxDirectoryEntry
            {
                Name = Name,
                Inode = LinuxStatHelper.ComputeStableId(PathValue),
                Type = Type
            });
        }

        public bool IsSpecialPath(LinuxSyscallsHelper Helper, string PathValue)
        {
            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return false;

            return Entries.ContainsKey(NormalizedPath) || IsDescriptorAliasPath(Helper, NormalizedPath) || IsDynamicDirectoryPath(NormalizedPath) || IsDynamicGeneratedPath(NormalizedPath);
        }

        private static string NormalizePath(string Path) => (Path ?? string.Empty).Replace('\\', '/');

        private static string ResolveSpecialPath(LinuxSyscallsHelper Helper, string PathValue)
        {
            string NormalizedPath = NormalizePath(PathValue);
            if (string.IsNullOrEmpty(NormalizedPath))
                return NormalizedPath;

            if (TryResolveProcessPath(Helper, NormalizedPath, out string ResolvedPath))
                return ResolvedPath;

            return NormalizedPath;
        }

        private static bool TryResolveProcessPath(LinuxSyscallsHelper Helper, string NormalizedPath, out string ResolvedPath)
        {
            ResolvedPath = null;
            string[] Segments = NormalizedPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (Segments.Length < 2 || !string.Equals(Segments[0], "proc", StringComparison.Ordinal))
                return false;

            if (string.Equals(Segments[1], "thread-self", StringComparison.Ordinal))
                return TryResolveThreadSelfPath(Helper, Segments, out ResolvedPath);

            LinuxProcessInfo Process;
            if (string.Equals(Segments[1], "self", StringComparison.Ordinal))
            {
                Helper.SyncCurrentProcessMetadata();
                Process = Helper.CurrentProcess;
            }
            else
            {
                if (!int.TryParse(Segments[1], out int ProcessId) || !Helper.TryGetProcessInfo(ProcessId, out Process))
                    return false;
            }

            if (Segments.Length == 2)
            {
                ResolvedPath = $"/proc/@pid/{Process.ProcessId}";
                return true;
            }

            switch (Segments[2])
            {
                case "cmdline":
                case "comm":
                case "maps":
                case "mounts":
                case "statm":
                case "status":
                case "exe":
                    if (Segments.Length == 3)
                    {
                        ResolvedPath = $"/proc/@pid/{Process.ProcessId}/{Segments[2]}";
                        return true;
                    }

                    return false;
                case "fd":
                    if (Segments.Length == 3)
                    {
                        ResolvedPath = $"/proc/@pid/{Process.ProcessId}/fd";
                        return true;
                    }

                    if (Segments.Length == 4)
                    {
                        if (Process.ProcessId == Helper.PID)
                            ResolvedPath = "/proc/self/fd/" + Segments[3];
                        else
                            ResolvedPath = $"/proc/@pid/{Process.ProcessId}/fd/{Segments[3]}";
                        return true;
                    }

                    return false;
                case "task":
                    return TryResolveTaskPath(Helper, Process.ProcessId, Segments, out ResolvedPath);
                default:
                    return false;
            }
        }

        private static bool TryResolveThreadSelfPath(LinuxSyscallsHelper Helper, string[] Segments, out string ResolvedPath)
        {
            ResolvedPath = null;
            if (Helper.CurrentThreadId == 0 || !Helper.TryGetThreadInfo(Helper.PID, (uint)Helper.CurrentThreadId, out _))
                return false;

            if (Segments.Length == 2)
            {
                ResolvedPath = $"/proc/@task/{Helper.PID}/{Helper.CurrentThreadId}";
                return true;
            }

            if (string.Equals(Segments[2], "fd", StringComparison.Ordinal))
            {
                if (Segments.Length == 3)
                {
                    ResolvedPath = "/proc/self/fd";
                    return true;
                }

                if (Segments.Length == 4)
                {
                    ResolvedPath = "/proc/self/fd/" + Segments[3];
                    return true;
                }

                return false;
            }

            if (Segments.Length == 3 && (string.Equals(Segments[2], "comm", StringComparison.Ordinal) || string.Equals(Segments[2], "status", StringComparison.Ordinal)))
            {
                ResolvedPath = $"/proc/@task/{Helper.PID}/{Helper.CurrentThreadId}/{Segments[2]}";
                return true;
            }

            return false;
        }

        private static bool TryResolveTaskPath(LinuxSyscallsHelper Helper, int ProcessId, string[] Segments, out string ResolvedPath)
        {
            ResolvedPath = null;
            if (Segments.Length == 3)
            {
                ResolvedPath = $"/proc/@pid/{ProcessId}/task";
                return true;
            }

            if (!uint.TryParse(Segments[3], out uint ThreadId) || !Helper.TryGetThreadInfo(ProcessId, ThreadId, out _))
                return false;

            if (Segments.Length == 4)
            {
                ResolvedPath = $"/proc/@task/{ProcessId}/{ThreadId}";
                return true;
            }

            if (Segments.Length >= 5 && string.Equals(Segments[4], "fd", StringComparison.Ordinal))
            {
                if (Segments.Length == 5)
                {
                    ResolvedPath = $"/proc/@pid/{ProcessId}/fd";
                    return true;
                }

                if (Segments.Length == 6)
                {
                    if (ProcessId == Helper.PID)
                        ResolvedPath = "/proc/self/fd/" + Segments[5];
                    else
                        ResolvedPath = $"/proc/@pid/{ProcessId}/fd/{Segments[5]}";
                    return true;
                }

                return false;
            }

            if (Segments.Length == 5 && (string.Equals(Segments[4], "comm", StringComparison.Ordinal) || string.Equals(Segments[4], "status", StringComparison.Ordinal)))
            {
                ResolvedPath = $"/proc/@task/{ProcessId}/{ThreadId}/{Segments[4]}";
                return true;
            }

            return false;
        }

        private static bool IsDynamicDirectoryPath(string PathValue)
        {
            return TryParseDynamicProcessPath(PathValue, out _, out string ProcessLeaf)
                && (string.IsNullOrEmpty(ProcessLeaf) || string.Equals(ProcessLeaf, "fd", StringComparison.Ordinal) || string.Equals(ProcessLeaf, "task", StringComparison.Ordinal))
                || TryParseDynamicTaskPath(PathValue, out _, out _, out string TaskLeaf) && string.IsNullOrEmpty(TaskLeaf)
                || TryParseDynamicCpuPath(PathValue, out _, out string CpuLeaf) && string.IsNullOrEmpty(CpuLeaf);
        }

        private static bool IsDynamicGeneratedPath(string PathValue)
        {
            if (TryParseDynamicProcessPath(PathValue, out _, out string ProcessLeaf))
            {
                return string.Equals(ProcessLeaf, "cmdline", StringComparison.Ordinal)
                    || string.Equals(ProcessLeaf, "comm", StringComparison.Ordinal)
                    || string.Equals(ProcessLeaf, "maps", StringComparison.Ordinal)
                    || string.Equals(ProcessLeaf, "mounts", StringComparison.Ordinal)
                    || string.Equals(ProcessLeaf, "statm", StringComparison.Ordinal)
                    || string.Equals(ProcessLeaf, "status", StringComparison.Ordinal)
                    || string.Equals(ProcessLeaf, "exe", StringComparison.Ordinal);
            }

            return TryParseDynamicTaskPath(PathValue, out _, out _, out string TaskLeaf)
                && (string.Equals(TaskLeaf, "comm", StringComparison.Ordinal) || string.Equals(TaskLeaf, "status", StringComparison.Ordinal));
        }

        private static bool TryParseDynamicCpuPath(string PathValue, out int CpuIndex, out string Leaf)
        {
            CpuIndex = 0;
            Leaf = string.Empty;

            const string Prefix = "/sys/devices/system/cpu/cpu";
            if (!PathValue.StartsWith(Prefix, StringComparison.Ordinal))
                return false;

            string Rest = PathValue.Substring(Prefix.Length);
            int Slash = Rest.IndexOf('/');
            string CpuIndexText = Slash >= 0 ? Rest.Substring(0, Slash) : Rest;
            if (CpuIndexText.Length == 0 || !int.TryParse(CpuIndexText, out CpuIndex) || CpuIndex < 0)
                return false;

            Leaf = Slash >= 0 ? Rest.Substring(Slash + 1) : string.Empty;
            return true;
        }

        private static bool TryParseDynamicProcessPath(string PathValue, out int ProcessId, out string Leaf)
        {
            ProcessId = 0;
            Leaf = null;
            const string Prefix = "/proc/@pid/";
            if (!PathValue.StartsWith(Prefix, StringComparison.Ordinal))
                return false;

            string Remainder = PathValue.Substring(Prefix.Length);
            int Slash = Remainder.IndexOf('/');
            if (Slash < 0)
                return int.TryParse(Remainder, out ProcessId);

            if (!int.TryParse(Remainder.Substring(0, Slash), out ProcessId))
                return false;

            Leaf = Remainder.Substring(Slash + 1);
            return true;
        }

        private static bool TryParseDynamicTaskPath(string PathValue, out int ProcessId, out uint ThreadId, out string Leaf)
        {
            ProcessId = 0;
            ThreadId = 0;
            Leaf = null;
            const string Prefix = "/proc/@task/";
            if (!PathValue.StartsWith(Prefix, StringComparison.Ordinal))
                return false;

            string Remainder = PathValue.Substring(Prefix.Length);
            string[] Segments = Remainder.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (Segments.Length < 2 || !int.TryParse(Segments[0], out ProcessId) || !uint.TryParse(Segments[1], out ThreadId))
                return false;

            if (Segments.Length >= 3)
                Leaf = Segments[2];

            return true;
        }

        private static bool TryGetExistingDescriptor(LinuxSyscallsHelper Helper, string PathValue, out ulong Descriptor, out bool IsDescriptorAlias)
        {
            Descriptor = 0;
            IsDescriptorAlias = false;

            string NormalizedPath = ResolveSpecialPath(Helper, PathValue);
            switch (NormalizedPath)
            {
                case "/proc/self/fd/0":
                case "/dev/fd/0":
                    Descriptor = 0;
                    IsDescriptorAlias = true;
                    return true;
                case "/proc/self/fd/1":
                case "/dev/fd/1":
                    Descriptor = 1;
                    IsDescriptorAlias = true;
                    return true;
                case "/proc/self/fd/2":
                case "/dev/fd/2":
                    Descriptor = 2;
                    IsDescriptorAlias = true;
                    return true;
            }

            if (NormalizedPath.StartsWith("/proc/self/fd/", StringComparison.Ordinal))
            {
                IsDescriptorAlias = true;
                return ulong.TryParse(NormalizedPath.Substring("/proc/self/fd/".Length), out Descriptor);
            }

            if (NormalizedPath.StartsWith("/dev/fd/", StringComparison.Ordinal))
            {
                IsDescriptorAlias = true;
                return ulong.TryParse(NormalizedPath.Substring("/dev/fd/".Length), out Descriptor);
            }

            if (TryParseDynamicProcessPath(NormalizedPath, out int ProcessId, out string Leaf)
                && ProcessId == Helper.PID
                && !string.IsNullOrEmpty(Leaf)
                && Leaf.StartsWith("fd/", StringComparison.Ordinal))
            {
                IsDescriptorAlias = true;
                return ulong.TryParse(Leaf.Substring(3), out Descriptor);
            }

            return false;
        }

        private static bool IsDescriptorAliasPath(LinuxSyscallsHelper Helper, string PathValue)
        {
            return TryGetExistingDescriptor(Helper, PathValue, out _, out bool IsDescriptorAlias) && IsDescriptorAlias;
        }

        private static bool TryDuplicateExistingDescriptor(LinuxSyscallsHelper Helper, ulong SourceDescriptor, bool CloseOnExec, ulong DescriptorLimit, out long Result)
        {
            Result = 0;
            FileDescriptorEntry Entry = Helper.DescriptorTable.GetEntry(SourceDescriptor);
            if (Entry == null)
            {
                Result = -(long)LinuxErrno.ENOENT;
                return true;
            }

            if (!Helper.DescriptorTable.TryAddHandle(Entry.Object, CloseOnExec, DescriptorLimit, out ulong NewDescriptor))
            {
                Result = -(long)LinuxErrno.EMFILE;
                return true;
            }

            Result = (long)NewDescriptor;
            return true;
        }

        private static bool TryResolveZoneInfoPath(LinuxSyscallsHelper Helper, string TimeZoneId, out string HostPath)
        {
            HostPath = null;
            if (string.IsNullOrWhiteSpace(TimeZoneId))
                return false;

            string ZoneInfoGuestPath = "/usr/share/zoneinfo/" + TimeZoneId.Replace('\\', '/').TrimStart('/');
            string ResolvedHostPath = Helper.ResolveHostPath(ZoneInfoGuestPath);
            if (string.IsNullOrWhiteSpace(ResolvedHostPath) || !File.Exists(ResolvedHostPath))
                return false;

            HostPath = ResolvedHostPath;
            return true;
        }

        private static string GetHostTimeZoneId()
        {
            try
            {
                string LocalId = TimeZoneInfo.Local.Id;
                if (string.IsNullOrWhiteSpace(LocalId))
                    return null;

                if (LocalId.IndexOf('/') >= 0)
                    return LocalId;

                if (TimeZoneInfo.TryConvertWindowsIdToIanaId(LocalId, out string IanaId) && !string.IsNullOrWhiteSpace(IanaId))
                    return IanaId;

                return LocalId;
            }
            catch
            {
                return null;
            }
        }

        public long DevNull(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            return Write ? (long)ClampTransferCount(Length) : 0;
        }

        public long DevZero(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (Write)
                return (long)ClampTransferCount(Length);

            if (Length == 0)
                return 0;

            if (!Instance.IsRegionMapped(BufferAddress, Length))
                return -(long)LinuxErrno.EFAULT;

            ulong TransferLength = ClampTransferCount((ulong)Math.Min(Length, (ulong)int.MaxValue));
            if (TransferLength == 0)
                return 0;

            Span<byte> Buffer = Helper.Shared.GetSpan(TransferLength);
            Buffer.Clear();

            if (!Instance.WriteMemory(BufferAddress, Buffer.Slice(0, (int)TransferLength)))
                return -(long)LinuxErrno.EFAULT;

            return (long)TransferLength;
        }

        public long DevRandom(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (Write)
                return (long)ClampTransferCount(Length);

            return FillRandomBuffer(Instance, Helper, BufferAddress, Length);
        }

        public long DevURandom(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (Write)
                return (long)ClampTransferCount(Length);

            return FillRandomBuffer(Instance, Helper, BufferAddress, Length);
        }

        public long DevStdIn(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (Write)
                return -(long)LinuxErrno.EBADF;

            if (Length == 0)
                return 0;

            if (!Instance.IsRegionMapped(BufferAddress, Length))
                return -(long)LinuxErrno.EFAULT;

            string? Input = Console.ReadLine();
            if (Input == null)
                return 0;

            ulong TransferLength = ClampTransferCount(Length);
            byte[] Data = Encoding.ASCII.GetBytes(Input);
            if ((ulong)Data.Length > TransferLength)
                Array.Resize(ref Data, (int)TransferLength);

            if (Data.Length == 0)
                return 0;

            if (!Instance._emulator.WriteMemory(BufferAddress, Data))
                return -(long)LinuxErrno.EFAULT;

            return Data.Length;
        }

        public long DevStdOut(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (!Write)
                return -(long)LinuxErrno.EBADF;

            return WriteConsole(Instance, Helper, BufferAddress, Length, Console.OpenStandardOutput());
        }

        public long DevStdErr(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (!Write)
                return -(long)LinuxErrno.EBADF;

            return WriteConsole(Instance, Helper, BufferAddress, Length, Console.OpenStandardError());
        }

        public long DevTty(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
        {
            if (Write)
                return WriteConsole(Instance, Helper, BufferAddress, Length, Console.OpenStandardOutput());

            if (Length == 0)
                return 0;

            if (!Instance.IsRegionMapped(BufferAddress, Length))
                return -(long)LinuxErrno.EFAULT;

            string? Input = Console.ReadLine();
            if (Input == null)
                return 0;

            ulong TransferLength = ClampTransferCount(Length);
            byte[] Data = Encoding.ASCII.GetBytes(Input);
            if ((ulong)Data.Length > TransferLength)
                Array.Resize(ref Data, (int)TransferLength);

            if (Data.Length == 0)
                return 0;

            if (!Instance._emulator.WriteMemory(BufferAddress, Data))
                return -(long)LinuxErrno.EFAULT;

            return Data.Length;
        }

        public long GeneratedFile(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, ResolveSpecialPath(Helper, File.Path));

        public long ProcCpuInfo(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/cpuinfo");

        public long ProcFileSystems(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/filesystems");

        public long ProcMemInfo(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/meminfo");

        public long ProcMounts(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/mounts");

        public long ProcUptime(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/uptime");

        public long ProcVersion(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/version");

        public long ProcSelfCmdline(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/self/cmdline");

        public long ProcSelfComm(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/self/comm");

        public long ProcSelfMaps(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/self/maps");

        public long ProcSelfStatm(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/self/statm");

        public long ProcSelfStatus(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/self/status");

        public long ProcKernelHostname(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/sys/kernel/hostname");

        public long ProcKernelOsRelease(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/sys/kernel/osrelease");

        public long ProcKernelOsType(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/sys/kernel/ostype");

        public long ProcKernelVersion(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write = false)
            => ReadGeneratedContent(Instance, Helper, File, BufferAddress, Length, Write, "/proc/sys/kernel/version");

        private static long ReadGeneratedContent(BinaryEmulator Instance, LinuxSyscallsHelper Helper, FileObject File, ulong BufferAddress, ulong Length, bool Write, string PathValue)
        {
            if (Write)
                return -(long)LinuxErrno.EBADF;

            if (Length == 0)
                return 0;

            if (!Instance.IsRegionMapped(BufferAddress, Length))
                return -(long)LinuxErrno.EFAULT;

            byte[] Content = BuildContent(Instance, Helper, PathValue);
            if ((ulong)Content.Length <= File.Offset)
                return 0;

            ulong Remaining = (ulong)Content.Length - File.Offset;
            ulong TransferLength = Math.Min(ClampTransferCount(Length), Remaining);
            if (TransferLength == 0)
                return 0;

            if (!Instance._emulator.WriteMemory(BufferAddress, Content, (int)File.Offset, (int)TransferLength))
                return -(long)LinuxErrno.EFAULT;

            File.Offset += TransferLength;
            return (long)TransferLength;
        }

        private static byte[] BuildContent(BinaryEmulator Instance, LinuxSyscallsHelper Helper, string PathValue)
        {
            if (TryParseDynamicProcessPath(PathValue, out int ProcessId, out string ProcessLeaf) && Helper.TryGetProcessInfo(ProcessId, out LinuxProcessInfo Process))
            {
                string ProcessText = ProcessLeaf switch
                {
                    "cmdline" => BuildCmdline(Process),
                    "comm" => Process.CommandName + "\n",
                    "maps" => BuildMaps(Instance, Helper, Process),
                    "mounts" => BuildMounts(Helper),
                    "statm" => BuildStatm(Instance, Process),
                    "status" => BuildStatus(Instance, Helper, Process),
                    "exe" => Process.ExecutablePath + "\n",
                    _ => string.Empty
                };

                return Encoding.ASCII.GetBytes(ProcessText);
            }

            if (TryParseDynamicTaskPath(PathValue, out int TaskProcessId, out uint ThreadId, out string Leaf)
                && Helper.TryGetProcessInfo(TaskProcessId, out LinuxProcessInfo TaskProcess)
                && Helper.TryGetThreadInfo(TaskProcessId, ThreadId, out LinuxTaskInfo Task))
            {
                string TaskText = Leaf switch
                {
                    "comm" => Task.Name + "\n",
                    "status" => BuildStatus(Instance, Helper, TaskProcess, Task),
                    _ => string.Empty
                };

                return Encoding.ASCII.GetBytes(TaskText);
            }

            if (TryBuildPowerSupplyContent(PathValue, out string PowerSupplyText))
                return Encoding.ASCII.GetBytes(PowerSupplyText);

            string Text = PathValue switch
            {
                "/proc/cpuinfo" => BuildCpuInfo(Instance, Helper),
                "/proc/filesystems" => BuildFileSystems(),
                "/proc/meminfo" => BuildMemInfo(Instance),
                "/proc/mounts" => BuildMounts(Helper),
                "/proc/stat" => BuildProcStat(Helper),
                "/proc/swaps" => BuildSwaps(),
                "/proc/self/mounts" => BuildMounts(Helper),
                "/proc/self/cmdline" => BuildCmdline(Helper),
                "/proc/self/comm" => BuildCommandName(Helper) + "\n",
                "/proc/self/maps" => BuildMaps(Instance, Helper),
                "/proc/self/statm" => BuildStatm(Instance),
                "/proc/self/status" => BuildStatus(Instance, Helper),
                "/proc/sys/kernel/hostname" => Helper.GetHostName() + "\n",
                "/proc/sys/kernel/osrelease" => Helper.GetKernelRelease() + "\n",
                "/proc/sys/kernel/ostype" => Helper.GetSystemName() + "\n",
                "/proc/sys/kernel/version" => Helper.GetKernelVersion() + "\n",
                "/proc/uptime" => BuildUptime(Helper),
                "/proc/version" => BuildVersion(Helper),
                "/sys/class/drm/card0/device/power/runtime_status" => "active\n",
                "/sys/class/drm/card0-eDP-1/connector_id" => "32\n",
                "/sys/class/drm/card0-eDP-1/dpms" => "On\n",
                "/sys/class/drm/card0-eDP-1/edid" => string.Empty,
                "/sys/class/drm/card0-eDP-1/enabled" => "enabled\n",
                "/sys/class/drm/card0-eDP-1/modes" => "1920x1080\n",
                "/sys/class/drm/card0-eDP-1/status" => "connected\n",
                "/sys/devices/system/cpu/kernel_max" => (Helper.SystemIdentity.GetCpuCount() - 1).ToString() + "\n",
                "/sys/devices/system/cpu/offline" => "\n",
                "/sys/devices/system/cpu/online" => Helper.SystemIdentity.GetCpuListString() + "\n",
                "/sys/devices/system/cpu/possible" => Helper.SystemIdentity.GetCpuListString() + "\n",
                "/sys/devices/system/cpu/present" => Helper.SystemIdentity.GetCpuListString() + "\n",
                _ => string.Empty
            };

            return Encoding.ASCII.GetBytes(Text);
        }

        private static string BuildCmdline(LinuxSyscallsHelper Helper)
        {
            return BuildCmdline(Helper.CurrentProcess);
        }

        private static string BuildCmdline(LinuxProcessInfo Process)
        {
            if (Process == null || Process.Arguments == null || Process.Arguments.Length == 0)
                return string.Empty;

            return string.Join("\0", Process.Arguments) + "\0";
        }

        private static string BuildCommandName(LinuxSyscallsHelper Helper)
        {
            return BuildCommandName(Helper.CurrentProcess);
        }

        private static string BuildCommandName(LinuxProcessInfo Process)
        {
            if (Process == null || string.IsNullOrWhiteSpace(Process.CommandName))
                return "program";

            return Process.CommandName;
        }

        private static string BuildStatus(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxTaskInfo Task = null)
        {
            return BuildStatus(Instance, Helper, Helper.CurrentProcess, Task);
        }

        private static string BuildStatus(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxProcessInfo Process, LinuxTaskInfo Task = null)
        {
            GetMemoryUsage(Instance, out long TotalBytes, out long ResidentBytes, out long TextBytes, out long DataBytes);
            long VmSizeKb = Math.Max(0, TotalBytes / 1024);
            long VmRssKb = Math.Max(0, ResidentBytes / 1024);
            long VmExeKb = Math.Max(0, TextBytes / 1024);
            long VmDataKb = Math.Max(0, DataBytes / 1024);
            long VmStkKb = 8192;
            ulong FdSize = Helper.ResourceLimits.TryGetValue(SocketHelpers.RLIMIT_NOFILE, out LinuxResourceLimit Limit) && Limit.Current != 0 ? Limit.Current : 1024UL;
            uint ReportedPid = Task?.ThreadId ?? (uint)(Process?.ProcessId ?? Helper.PID);
            string ReportedName = Task?.Name ?? BuildCommandName(Process);
            uint RealUserId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.UserId : Helper.Credentials.RealUserId;
            uint EffectiveUserId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.UserId : Helper.Credentials.EffectiveUserId;
            uint SavedUserId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.UserId : Helper.Credentials.SavedUserId;
            uint FileSystemUserId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.UserId : Helper.Credentials.FileSystemUserId;
            uint RealGroupId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.GroupId : Helper.Credentials.RealGroupId;
            uint EffectiveGroupId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.GroupId : Helper.Credentials.EffectiveGroupId;
            uint SavedGroupId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.GroupId : Helper.Credentials.SavedGroupId;
            uint FileSystemGroupId = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess) ? Process.GroupId : Helper.Credentials.FileSystemGroupId;
            string SupplementaryGroups = Process != null && !ReferenceEquals(Process, Helper.CurrentProcess)
                ? (Process.GroupId == 0 ? string.Empty : Process.GroupId.ToString())
                : (Helper.Credentials.SupplementaryGroups.Count != 0 ? string.Join(" ", Helper.Credentials.SupplementaryGroups) : string.Empty);

            StringBuilder Builder = new StringBuilder();
            Builder.Append("Name:\t").Append(ReportedName).Append('\n');
            Builder.Append("Umask:\t").Append(Convert.ToString(Helper.Credentials.Umask, 8).PadLeft(4, '0')).Append('\n');
            Builder.Append("State:\tR (running)\n");
            Builder.Append("Tgid:\t").Append(Process?.ProcessId ?? Helper.PID).Append('\n');
            Builder.Append("Ngid:\t0\n");
            Builder.Append("Pid:\t").Append(ReportedPid).Append('\n');
            Builder.Append("PPid:\t").Append(Process?.ParentProcessId ?? Helper.ParentPid).Append('\n');
            Builder.Append("TracerPid:\t0\n");
            Builder.Append("Uid:\t").Append(RealUserId).Append('\t').Append(EffectiveUserId).Append('\t').Append(SavedUserId).Append('\t').Append(FileSystemUserId).Append('\n');
            Builder.Append("Gid:\t").Append(RealGroupId).Append('\t').Append(EffectiveGroupId).Append('\t').Append(SavedGroupId).Append('\t').Append(FileSystemGroupId).Append('\n');
            Builder.Append("FDSize:\t").Append(FdSize).Append('\n');
            Builder.Append("Groups:\t");
            if (!string.IsNullOrEmpty(SupplementaryGroups))
                Builder.Append(SupplementaryGroups);
            Builder.Append('\n');
            Builder.Append("Threads:\t").Append(Math.Max(1, Process?.Threads.Count ?? Helper.CurrentProcess?.Threads.Count ?? 0)).Append('\n');
            Builder.Append("VmPeak:\t").Append(VmSizeKb).Append(" kB\n");
            Builder.Append("VmSize:\t").Append(VmSizeKb).Append(" kB\n");
            Builder.Append("VmRSS:\t").Append(VmRssKb).Append(" kB\n");
            Builder.Append("VmData:\t").Append(VmDataKb).Append(" kB\n");
            Builder.Append("VmStk:\t").Append(VmStkKb).Append(" kB\n");
            Builder.Append("VmExe:\t").Append(VmExeKb).Append(" kB\n");
            Builder.Append("VmLib:\t0 kB\n");
            Builder.Append("SigQ:\t0/0\n");
            Builder.Append("CapInh:\t0000000000000000\n");
            Builder.Append("CapPrm:\t0000000000000000\n");
            Builder.Append("CapEff:\t0000000000000000\n");
            Builder.Append("CapBnd:\t0000000000000000\n");
            Builder.Append("CapAmb:\t0000000000000000\n");
            Builder.Append("NoNewPrivs:\t0\n");
            Builder.Append("Seccomp:\t0\n");
            Builder.Append("Cpus_allowed:\t1\n");
            Builder.Append("Cpus_allowed_list:\t0\n");
            Builder.Append("Mems_allowed:\t1\n");
            Builder.Append("Mems_allowed_list:\t0\n");
            return Builder.ToString();
        }

        private static string BuildStatm(BinaryEmulator Instance)
        {
            return BuildStatm(Instance, null);
        }

        private static string BuildStatm(BinaryEmulator Instance, LinuxProcessInfo Process)
        {
            LinuxGuest Current = Instance.GetGuest<LinuxGuest>();
            if (Process != null && Process.ProcessId != 0 && Process.ProcessId != Current.Helper.PID)
                return "1 1 0 0 0 0 0\n";

            GetMemoryUsage(Instance, out long TotalBytes, out long ResidentBytes, out long TextBytes, out long DataBytes);
            long PageSize = 4096;
            long TotalPages = Math.Max(1, (TotalBytes + (PageSize - 1)) / PageSize);
            long ResidentPages = Math.Max(1, (ResidentBytes + (PageSize - 1)) / PageSize);
            long SharedPages = 0;
            long TextPages = Math.Max(0, (TextBytes + (PageSize - 1)) / PageSize);
            long LibPages = 0;
            long DataPages = Math.Max(0, (DataBytes + (PageSize - 1)) / PageSize);
            return $"{TotalPages} {ResidentPages} {SharedPages} {TextPages} {LibPages} {DataPages} 0\n";
        }

        private static string BuildMaps(BinaryEmulator Instance, LinuxSyscallsHelper Helper)
        {
            return BuildMaps(Instance, Helper, Helper.CurrentProcess);
        }

        private static string BuildMaps(BinaryEmulator Instance, LinuxSyscallsHelper Helper, LinuxProcessInfo Process)
        {
            if (Process != null && Process.ProcessId != 0 && Process.ProcessId != Helper.PID)
                return string.Empty;

            StringBuilder Builder = new StringBuilder();
            ulong StackPointer = Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_RSP) : Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            bool NamedImageRegion = false;

            foreach (MemoryRegion Region in Instance.EnumerateMemoryRegionsByBase())
            {
                ulong Start = Region.BaseAddress;
                ulong End = Region.BaseAddress + Region.Size;
                string Permissions = BuildMapsPermissions(Region.Protections);
                string PathLabel = string.Empty;

                if (StackPointer >= Start && StackPointer < End)
                {
                    PathLabel = "[stack]";
                }
                else if (!NamedImageRegion && (Region.Flags & AllocationType.Image) != 0 && !string.IsNullOrWhiteSpace(Process?.ExecutablePath ?? Helper.ProcessExecutablePath))
                {
                    PathLabel = Process?.ExecutablePath ?? Helper.ProcessExecutablePath;
                    NamedImageRegion = true;
                }
                else
                {
                    PathLabel = "[anon]";
                }

                Builder.AppendFormat("{0:x}-{1:x} {2} 00000000 00:00 0", Start, End, Permissions);
                if (!string.IsNullOrEmpty(PathLabel))
                    Builder.Append(' ').Append(PathLabel);
                Builder.Append('\n');
            }

            return Builder.ToString();
        }

        private static string BuildMapsPermissions(MemoryProtection Protection)
        {
            char Read = (Protection & MemoryProtection.Read) != 0 ? 'r' : '-';
            char Write = (Protection & MemoryProtection.Write) != 0 ? 'w' : '-';
            char Execute = (Protection & MemoryProtection.Execute) != 0 ? 'x' : '-';
            return string.Concat(Read, Write, Execute, 'p');
        }

        private static void GetMemoryUsage(BinaryEmulator Instance, out long TotalBytes, out long ResidentBytes, out long TextBytes, out long DataBytes)
        {
            TotalBytes = 0;
            ResidentBytes = 0;
            TextBytes = 0;
            DataBytes = 0;

            foreach (MemoryRegion Region in Instance._memory)
            {
                long RegionSize = unchecked((long)Math.Min(Region.Size, (ulong)long.MaxValue));
                if (RegionSize <= 0)
                    continue;

                TotalBytes += RegionSize;
                ResidentBytes += RegionSize;

                if ((Region.Protections & MemoryProtection.Execute) != 0)
                    TextBytes += RegionSize;
                else
                    DataBytes += RegionSize;
            }
        }

        private static string BuildMemInfo(BinaryEmulator Instance)
        {
            GetMemoryUsage(Instance, out long TotalBytes, out _, out _, out _);
            long UsedKb = Math.Max(0, TotalBytes / 1024);
            long TotalKb = PROCFS_MEMTOTAL_KB;
            long FreeKb = Math.Max(0, TotalKb - UsedKb);
            long AvailableKb = FreeKb;
            long SwapFreeKb = Math.Max(0, PROCFS_SWAPTOTAL_KB - PROCFS_SWAPUSED_KB);

            StringBuilder Builder = new StringBuilder();
            Builder.Append("MemTotal:       ").Append(TotalKb.ToString().PadLeft(8)).Append(" kB\n");
            Builder.Append("MemFree:        ").Append(FreeKb.ToString().PadLeft(8)).Append(" kB\n");
            Builder.Append("MemAvailable:   ").Append(AvailableKb.ToString().PadLeft(8)).Append(" kB\n");
            Builder.Append("Buffers:               0 kB\n");
            Builder.Append("Cached:                0 kB\n");
            Builder.Append("SwapCached:            0 kB\n");
            Builder.Append("SwapTotal:      ").Append(PROCFS_SWAPTOTAL_KB.ToString().PadLeft(8)).Append(" kB\n");
            Builder.Append("SwapFree:       ").Append(SwapFreeKb.ToString().PadLeft(8)).Append(" kB\n");
            return Builder.ToString();
        }

        private static string BuildSwaps()
        {
            return "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
                + "/swapfile\t\t\t\tfile\t\t" + PROCFS_SWAPTOTAL_KB.ToString() + "\t\t" + PROCFS_SWAPUSED_KB.ToString() + "\t\t-2\n";
        }

        private static bool TryBuildPowerSupplyContent(string PathValue, out string Text)
        {
            Text = PathValue switch
            {
                "/sys/class/power_supply/AC/online" => "1\n",
                "/sys/class/power_supply/AC/type" => "Mains\n",
                "/sys/class/power_supply/AC/uevent" => "POWER_SUPPLY_NAME=AC\nPOWER_SUPPLY_TYPE=Mains\nPOWER_SUPPLY_ONLINE=1\n",
                "/sys/class/power_supply/ADP1/online" => "1\n",
                "/sys/class/power_supply/ADP1/type" => "Mains\n",
                "/sys/class/power_supply/ADP1/uevent" => "POWER_SUPPLY_NAME=ADP1\nPOWER_SUPPLY_TYPE=Mains\nPOWER_SUPPLY_ONLINE=1\n",
                "/sys/class/power_supply/BAT0/capacity" => "100\n",
                "/sys/class/power_supply/BAT0/capacity_level" => "Full\n",
                "/sys/class/power_supply/BAT0/charge_full" => "5000000\n",
                "/sys/class/power_supply/BAT0/charge_full_design" => "5000000\n",
                "/sys/class/power_supply/BAT0/charge_now" => "5000000\n",
                "/sys/class/power_supply/BAT0/current_now" => "0\n",
                "/sys/class/power_supply/BAT0/cycle_count" => "42\n",
                "/sys/class/power_supply/BAT0/manufacturer" => "Brovan\n",
                "/sys/class/power_supply/BAT0/model_name" => "Virtual Battery\n",
                "/sys/class/power_supply/BAT0/online" => "1\n",
                "/sys/class/power_supply/BAT0/present" => "1\n",
                "/sys/class/power_supply/BAT0/scope" => "System\n",
                "/sys/class/power_supply/BAT0/serial_number" => "0000\n",
                "/sys/class/power_supply/BAT0/status" => "Full\n",
                "/sys/class/power_supply/BAT0/technology" => "Li-ion\n",
                "/sys/class/power_supply/BAT0/temp" => "300\n",
                "/sys/class/power_supply/BAT0/type" => "Battery\n",
                "/sys/class/power_supply/BAT0/uevent" => BuildBatteryUevent(),
                "/sys/class/power_supply/BAT0/voltage_now" => "12000000\n",
                _ => null
            };

            return Text != null;
        }

        private static string BuildBatteryUevent()
        {
            return "POWER_SUPPLY_NAME=BAT0\n"
                + "POWER_SUPPLY_TYPE=Battery\n"
                + "POWER_SUPPLY_STATUS=Full\n"
                + "POWER_SUPPLY_PRESENT=1\n"
                + "POWER_SUPPLY_TECHNOLOGY=Li-ion\n"
                + "POWER_SUPPLY_VOLTAGE_NOW=12000000\n"
                + "POWER_SUPPLY_CHARGE_FULL_DESIGN=5000000\n"
                + "POWER_SUPPLY_CHARGE_FULL=5000000\n"
                + "POWER_SUPPLY_CHARGE_NOW=5000000\n"
                + "POWER_SUPPLY_CAPACITY=100\n"
                + "POWER_SUPPLY_CAPACITY_LEVEL=Full\n"
                + "POWER_SUPPLY_MODEL_NAME=Virtual Battery\n"
                + "POWER_SUPPLY_MANUFACTURER=Brovan\n"
                + "POWER_SUPPLY_SERIAL_NUMBER=0000\n";
        }

        private static string BuildCpuInfo(BinaryEmulator Instance, LinuxSyscallsHelper Helper)
        {
            LinuxX86CpuIdentity CpuIdentity = Helper.SystemIdentity.X86Cpu;
            int CpuCount = Helper.SystemIdentity.GetCpuCount();
            string Machine = Helper.GetMachineName(Instance.IsX64Guest);
            string Flags = CpuIdentity.BuildProcCpuInfoFlags(Instance.IsX64Guest);
            StringBuilder Builder = new StringBuilder();
            for (int Index = 0; Index < CpuCount; Index++)
            {
                Builder.Append("processor\t: ").Append(Index).Append('\n');
                Builder.Append("vendor_id\t: ").Append(CpuIdentity.VendorId).Append('\n');
                Builder.Append("cpu family\t: ").Append(CpuIdentity.GetDisplayFamily()).Append('\n');
                Builder.Append("model\t\t: ").Append(CpuIdentity.GetDisplayModel()).Append('\n');
                Builder.Append("model name\t: ").Append(CpuIdentity.GetModelName()).Append('\n');
                Builder.Append("stepping\t: ").Append(CpuIdentity.GetDisplayStepping()).Append('\n');
                Builder.Append("microcode\t: 0x1\n");
                Builder.Append("cpu MHz\t\t: 2400.000\n");
                Builder.Append("cache size\t: 4096 KB\n");
                Builder.Append("physical id\t: 0\n");
                Builder.Append("siblings\t: ").Append(CpuCount).Append('\n');
                Builder.Append("core id\t\t: ").Append(Index).Append('\n');
                Builder.Append("cpu cores\t: ").Append(CpuCount).Append('\n');
                Builder.Append("apicid\t\t: ").Append(Index).Append('\n');
                Builder.Append("initial apicid\t: ").Append(Index).Append('\n');
                Builder.Append("fpu\t\t: yes\n");
                Builder.Append("fpu_exception\t: yes\n");
                Builder.Append("cpuid level\t: ").Append(CpuIdentity.MaxBasicLeaf).Append('\n');
                Builder.Append("wp\t\t: yes\n");
                Builder.Append("flags\t\t: ").Append(Flags).Append('\n');
                Builder.Append("bugs\t\t:\n");
                Builder.Append("bogomips\t: 4800.00\n");
                Builder.Append("clflush size\t: 64\n");
                Builder.Append("cache_alignment\t: 64\n");
                Builder.Append("address sizes\t: ").Append(CpuIdentity.GetPhysicalAddressBits()).Append(" bits physical, ").Append(CpuIdentity.GetVirtualAddressBits()).Append(" bits virtual\n");
                Builder.Append("architecture\t: ").Append(Machine).Append("\n\n");
            }

            return Builder.ToString();
        }

        private static string BuildProcStat(LinuxSyscallsHelper Helper)
        {
            int CpuCount = Helper.SystemIdentity.GetCpuCount();
            StringBuilder Builder = new StringBuilder();
            Builder.Append("cpu  ");
            Builder.Append(100UL * (ulong)CpuCount).Append(" 0 ");
            Builder.Append(50UL * (ulong)CpuCount).Append(" ");
            Builder.Append(10000UL * (ulong)CpuCount).Append(" 0 0 0 0 0 0\n");

            for (int Index = 0; Index < CpuCount; Index++)
                Builder.Append("cpu").Append(Index).Append(" 100 0 50 10000 0 0 0 0 0 0\n");

            Builder.Append("intr 0\n");
            Builder.Append("ctxt 0\n");
            Builder.Append("btime ").Append(Helper.RealtimeClockBaseUtc.ToUnixTimeSeconds() - (long)Helper.GetSystemUptime().TotalSeconds).Append('\n');
            Builder.Append("processes 1\n");
            Builder.Append("procs_running 1\n");
            Builder.Append("procs_blocked 0\n");
            return Builder.ToString();
        }

        private static string BuildFileSystems()
        {
            return "nodev\tproc\nnodev\tsysfs\nnodev\ttmpfs\next4\n";
        }

        private static string BuildMounts(LinuxSyscallsHelper Helper)
        {
            StringBuilder Builder = new StringBuilder();
            Builder.Append("proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
            Builder.Append("sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n");
            foreach (LinuxMountEntry Entry in Helper.MountTable.Values.OrderBy(Entry => Entry.GuestPath, StringComparer.Ordinal))
            {
                string Source = string.IsNullOrWhiteSpace(Entry.HostPath) ? Entry.GuestPath : Entry.HostPath.Replace(' ', '_');
                string FsType = string.IsNullOrWhiteSpace(Entry.FileSystemType) ? "hostfs" : Entry.FileSystemType;
                string Options = Entry.ReadOnly ? "ro,relatime" : "rw,relatime";
                Builder.Append(Source).Append(' ').Append(Entry.GuestPath).Append(' ').Append(FsType).Append(' ').Append(Options).Append(" 0 0\n");
            }

            return Builder.ToString();
        }

        private static string BuildUptime(LinuxSyscallsHelper Helper)
        {
            double UptimeSeconds = Helper.GetSystemUptime().TotalSeconds;
            double IdleSeconds = UptimeSeconds * Helper.SystemIdentity.GetCpuCount();
            return $"{UptimeSeconds:0.00} {IdleSeconds:0.00}\n";
        }

        private static string BuildVersion(LinuxSyscallsHelper Helper)
        {
            return Helper.SystemIdentity.BuildVersionString() + "\n";
        }
        private static long FillRandomBuffer(BinaryEmulator Instance, LinuxSyscallsHelper Helper, ulong BufferAddress, ulong Length)
        {
            if (Length == 0)
                return 0;

            if (!Instance.IsRegionMapped(BufferAddress, Length))
                return -(long)LinuxErrno.EFAULT;

            ulong TransferLength = ClampTransferCount((ulong)Math.Min(Length, (ulong)int.MaxValue));
            if (TransferLength == 0)
                return 0;

            Span<byte> Buffer = Helper.Shared.GetSpan(TransferLength);
            Buffer.Clear();
            RandomNumberGenerator.Fill(Buffer);

            if (!Instance.WriteMemory(BufferAddress, Buffer.Slice(0, (int)TransferLength)))
                return -(long)LinuxErrno.EFAULT;

            return (long)TransferLength;
        }

        private static long WriteConsole(BinaryEmulator Instance, LinuxSyscallsHelper Helper, ulong BufferAddress, ulong Length, Stream Output)
        {
            if (Length == 0)
                return 0;

            ulong TransferLength = ClampTransferCount(Length);
            if (!Instance.IsRegionMapped(BufferAddress, TransferLength))
                return -(long)LinuxErrno.EFAULT;

            Span<byte> Transfer = Helper.Shared.GetSpan(TransferLength);
            if (!Instance.ReadMemory(BufferAddress, Transfer))
                return -(long)LinuxErrno.EFAULT;

            GeneralHelper.ConsoleWrite(Transfer, Output, Instance.Settings.ConsoleOutputMode);
            return (long)TransferLength;
        }

        private static ulong ClampTransferCount(ulong Length)
        {
            return Math.Min(Length, 0x7ffff000UL);
        }
    }
}
