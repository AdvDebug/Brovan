using System.Buffers.Binary;
using System.IO;
using System.Reflection;
using System.Text;
using Brovan.Core.Emulation.OS.Linux;
using Brovan.Core.Emulation.OS.Linux.Files;
using Brovan.Core.Emulation.OS.Linux.Events;
using Brovan.Core.Emulation.OS.Linux.Misc;
using Brovan.Core.Emulation.OS.Linux.Process;
using Brovan.Core.Emulation.OS.Linux.network;
using Brovan.Core.Emulation.OS.Linux.Signals;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.Guests
{
    public struct LinuxSyscallEntry
    {
        public string Name;
        public int Number;
        public SyscallAbi ABI;
        public ILinuxSyscall Handler;
    }

    public struct ElfLoadRegion
    {
        public ulong VirtualAddress;
        public ulong FileOffset;
        public ulong FileSize;
        public ulong MemorySize;
        public uint Flags;
    }

    public class BlobData
    {
        public ulong LoadAddress;
        public ulong EntryAddress;
        public ulong StackSize;
        public ulong MappedBase;
        public ulong StackBase;
    }

    public struct LinuxModuleRange
    {
        public ulong Start;
        public ulong End;
    }

    public sealed class LinuxLoadedModule
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Role { get; set; }
        public ulong MappedBase { get; set; }
        public ulong Size { get; set; }
        public ulong EntryPoint { get; set; }
        public ulong OriginalEntryPoint { get; set; }
        public List<LinuxModuleRange> Ranges { get; } = new List<LinuxModuleRange>();

        public bool ContainsAddress(ulong Address)
        {
            if (Ranges.Count != 0)
            {
                for (int i = 0; i < Ranges.Count; i++)
                {
                    LinuxModuleRange Range = Ranges[i];
                    if (Address >= Range.Start && Address < Range.End)
                        return true;
                }

                return false;
            }

            return Address >= MappedBase && Address < AddWithClamp(MappedBase, Size);
        }

        public void AddRange(ulong Start, ulong RangeSize)
        {
            if (Start == 0 || RangeSize == 0)
                return;

            ulong End = AddWithClamp(Start, RangeSize);
            LinuxModuleRange NewRange = new LinuxModuleRange()
            {
                Start = Start,
                End = End,
            };

            for (int i = 0; i < Ranges.Count; i++)
            {
                LinuxModuleRange Existing = Ranges[i];
                if (NewRange.Start > Existing.End || NewRange.End < Existing.Start)
                    continue;

                if (Existing.Start < NewRange.Start)
                    NewRange.Start = Existing.Start;

                if (Existing.End > NewRange.End)
                    NewRange.End = Existing.End;

                Ranges.RemoveAt(i);
                i--;
            }

            Ranges.Add(NewRange);

            ulong ExistingEnd = AddWithClamp(MappedBase, Size);
            if (MappedBase == 0 || Size == 0)
            {
                MappedBase = NewRange.Start;
                Size = NewRange.End - NewRange.Start;
                return;
            }

            ulong NewBase = Math.Min(MappedBase, NewRange.Start);
            ulong NewEnd = Math.Max(ExistingEnd, NewRange.End);
            MappedBase = NewBase;
            Size = NewEnd - NewBase;
        }

        private static ulong AddWithClamp(ulong Left, ulong Right)
        {
            ulong Result = Left + Right;
            if (Result < Left)
                return ulong.MaxValue;
            return Result;
        }
    }

    internal struct LinuxSignalStack
    {
        public ulong StackPointer;
        public int Flags;
        public ulong Size;
    }

    internal struct LinuxPendingSignal
    {
        public int Signal;
        public int Code;
        public ulong FaultAddress;
        public MemoryType MemoryAccess;
    }

    internal sealed class LinuxThreadState
    {
        public const int SignalCount = 65;
        public const int SignalSetSize = 8;

        public ulong FsBase;
        public ulong GsBase;
        public ulong TIDPtr;
        public ulong RobustListHead;
        public ulong RobustListLength;
        public ulong RseqPointer;
        public uint RseqLength;
        public uint RseqSignature;
        public int NiceValue;
        public bool CpuidEnabled = true;
        public bool FutexWaitActive;
        public bool FutexWaitCompleted;
        public long FutexWaitResult;
        public ulong FutexAddress;
        public uint FutexBitset;
        public ulong FutexWaitResumeRIP;
        public bool EpollWaitActive;
        public ulong EpollWaitDescriptor;
        public ulong EpollWaitEventsAddress;
        public int EpollWaitMaxEvents;
        public ulong EpollWaitReturnRIP;
        public byte[] EpollWaitSavedSignalMask;
        public bool SigsuspendActive;
        public ulong SigsuspendReturnRIP;
        public byte[] SigsuspendSavedSignalMask;
        public byte[] SignalMask = new byte[SignalSetSize];
        public List<LinuxPendingSignal> PendingSignals = new List<LinuxPendingSignal>();
        public LinuxSignalStack AlternateSignalStack;
        public bool SignalStackActive;
        public bool DispatchSignal;
        public bool SignalReturnCompleted;
        public bool IsHandlingSignal;
        public int SignalNesting;
        public LinuxPendingSignal PendingSignal;

        public void EnsureSignalState()
        {
            if (SignalMask == null || SignalMask.Length != SignalSetSize)
                SignalMask = new byte[SignalSetSize];
        }
    }

    internal class LinuxGuest : IGuestEnvironment
    {
        private const uint PT_LOAD = 1;
        private const uint PT_INTERP = 3;
        private const uint PF_X = 1;
        private const uint PF_W = 2;
        private const uint PF_R = 4;
        private const ulong PageMask = ~0xFFFUL;
        internal const uint RseqCpuIdUninitialized = 0xFFFFFFFF;
        internal const uint RseqOriginalSize = 32;
        internal const uint RseqMinimumFeatureSize = 28;
        internal const ulong RseqAlignment = 32;
        internal const ulong RseqCpuIdStartOffset = 0;
        internal const ulong RseqCpuIdOffset = 4;
        internal const ulong RseqCsOffset = 8;
        internal const ulong RseqNodeIdOffset = 20;
        internal const ulong RseqMmCidOffset = 24;

        public GuestOsKind Os => GuestOsKind.Linux;

        private BlobData _blob;
        private ulong _initialStackBase;
        private ulong _initialStackSize;
        private ulong _defaultThreadStackSize;
        private ulong _signalRestorer64;
        private ulong _signalRestorer32;

        internal LinuxSyscallsHelper Helper { get; private set; }
        internal Dictionary<int, LinuxSyscallEntry> X64Dictionary { get; private set; }
        internal Dictionary<int, LinuxSyscallEntry> X86Dictionary { get; private set; }

        /// <summary>
        /// Indicates whether the emulator will treat the data as a binary or as raw data.
        /// </summary>
        internal bool IsBlob { get; set; }

        internal ulong BlobMappedBase => _blob?.MappedBase ?? 0;
        internal List<LinuxLoadedModule> LoadedModules { get; } = new List<LinuxLoadedModule>();
        internal LinuxLoadedModule MainModule => LoadedModules.FirstOrDefault(Module => string.Equals(Module.Role, "main", StringComparison.OrdinalIgnoreCase));
        internal ulong MainModuleBase => MainModule?.MappedBase ?? BlobMappedBase;

        private static List<string> GetInitialProgramArguments(BinaryEmulator Instance)
        {
            List<string> Arguments = new List<string>();
            string Arg0 = !string.IsNullOrEmpty(Instance._binary.Location) ? Path.GetFileName(Instance._binary.Location) : "program";
            Arguments.Add(Arg0);

            if (Instance.ProgramArguments.Length != 0)
                Arguments.AddRange(Instance.ProgramArguments);

            return Arguments;
        }

        private static string NormalizeProcessExecutablePath(string PathValue)
        {
            if (string.IsNullOrWhiteSpace(PathValue))
                return "/program";

            string Normalized = PathValue.Replace('\\', '/');
            if (!Normalized.StartsWith("/", StringComparison.Ordinal))
                Normalized = "/" + Path.GetFileName(Normalized);

            while (Normalized.Contains("//"))
                Normalized = Normalized.Replace("//", "/");

            return Normalized;
        }

        public LinuxGuest(BlobData Blob = null)
        {
            if (Blob != null)
            {
                this.IsBlob = true;
                _blob = Blob;
            }

            Helper = new LinuxSyscallsHelper();
            X64Dictionary = new Dictionary<int, LinuxSyscallEntry>();
            X86Dictionary = new Dictionary<int, LinuxSyscallEntry>();
            RegisterSyscalls();
#if DEBUG
            var SyscallTypes = Assembly.GetExecutingAssembly().GetTypes().Where(T =>
                    T.IsClass &&
                    !T.IsAbstract &&
                    typeof(ILinuxSyscall).IsAssignableFrom(T) && T.Namespace != null &&
                    T.Namespace.StartsWith("Brovan.Core.Emulation.OS.Linux"));

            foreach (var T in SyscallTypes)
            {
                bool Set = false;
                foreach (LinuxSyscallEntry SysEntry in X64Dictionary.Values)
                {
                    if (T.Name == SysEntry.Handler.GetType().Name || SysEntry.Number == -1)
                    {
                        Set = true;
                        break;
                    }
                }

                foreach(LinuxSyscallEntry SysEntry in X86Dictionary.Values)
                {
                    if (T.Name == SysEntry.Handler.GetType().Name || SysEntry.Number == -1)
                    {
                        Set = true;
                        break;
                    }
                }

                if (!Set)
                {
                    Console.WriteLine($"Syscall {T.Name} is not set!");
                }
            }
#endif
        }

        public void Initialize(BinaryEmulator Instance, BinaryFile Binary)
        {
            if (!Instance.IsArchX86Guest)
                throw new Exception("Linux guest supports only x86/x64.");

            LoadedModules.Clear();

            ReadOnlySpan<byte> Data = Binary.GetBinaryData();
            ulong HighestAddress = 0;
            ulong GuestEntry = Binary.EntryPoint;
            ulong StartupEntry = GuestEntry;
            ulong ProgramHeaderAddress = 0;
            ulong ProgramHeaderEntrySize = 0;
            ulong ProgramHeaderCount = 0;
            ulong InterpreterBase = 0;
            ulong ProgramBreakAddress = 0;
            ulong StackSize = Binary.Architecture == BinaryArchitecture.x64 ? 0x200000UL : 0x100000UL;

            if (IsBlob)
            {
                InitializeBlob(Instance, Binary, Data, ref HighestAddress, ref StackSize, out GuestEntry);
                StartupEntry = GuestEntry;
                ProgramBreakAddress = HighestAddress;
            }
            else if (Binary.FileFormat == BinaryFormat.ELF)
            {
                ulong MainModuleAddress;
                ulong MainModuleSize;
                LoadElfBinary(Instance, Binary, Data, ref HighestAddress, out GuestEntry, out ProgramHeaderAddress, out ProgramHeaderEntrySize, out ProgramHeaderCount, out MainModuleAddress, out MainModuleSize, Binary.Location, "main");
                StartupEntry = GuestEntry;
                ProgramBreakAddress = HighestAddress;

                if (TryReadElfInterpreterPath(Binary, Data, out string InterpreterPath))
                {
                    if (!TryLoadElfInterpreter(Instance, Binary, InterpreterPath, ref HighestAddress, out StartupEntry, out InterpreterBase))
                    {
                        bool RetriedWithUbuntuRootfs = false;

                        if (!GeneralHelper.IsLinux && Binary.Architecture == BinaryArchitecture.x64)
                        {
                            Utils.PrintHighlight($"[-] The ELF interpreter '{InterpreterPath}' is missing.", true, false, true);
                            Utils.PrintHighlight("[!] Download and extract Ubuntu Base 26.04 rootfs now? [y/N] ", true, false, true);
                            string Response = Console.ReadLine();
                            if (!string.IsNullOrWhiteSpace(Response) && (string.Equals(Response.Trim(), "y", StringComparison.OrdinalIgnoreCase) || string.Equals(Response.Trim(), "yes", StringComparison.OrdinalIgnoreCase)))
                                RetriedWithUbuntuRootfs = GeneralHelper.IO.EnsureUbuntuBaseRootfs(Binary.Architecture);
                        }

                        if (RetriedWithUbuntuRootfs)
                            RetriedWithUbuntuRootfs = TryLoadElfInterpreter(Instance, Binary, InterpreterPath, ref HighestAddress, out StartupEntry, out InterpreterBase);

                        if (!RetriedWithUbuntuRootfs)
                            throw new InvalidOperationException($"Failed to load the ELF interpreter '{InterpreterPath}'.");
                    }
                }
            }
            else
            {
                return;
            }

            ulong ProgramBreakSource = ProgramBreakAddress != 0 ? ProgramBreakAddress : HighestAddress;
            Helper.ProgramBreakBase = Instance.AlignToPageSize(ProgramBreakSource);
            Helper.ProgramBreak = Helper.ProgramBreakBase;
            Helper.ProcessExecutablePath = NormalizeProcessExecutablePath(Binary?.Location);
            Helper.ProcessArguments = GetInitialProgramArguments(Instance).ToArray();
            Helper.SyncCurrentProcessMetadata();

            if (GuestEntry <= uint.MaxValue)
                Binary.EntryPoint = (uint)GuestEntry;

            ulong AlignedStackSize = Instance.AlignToPageSize(StackSize == 0 ? (Instance.IsX64Guest ? 0x200000UL : 0x100000UL) : StackSize);
            ulong Stack = Instance.MapUniqueAddress(AlignedStackSize, MemoryProtection.ReadWrite);
            if (Stack == 0)
                throw new InvalidOperationException("Failed to map the Linux guest stack.");

            _initialStackBase = Stack;
            _initialStackSize = AlignedStackSize;
            _defaultThreadStackSize = AlignedStackSize;

            if (_blob != null)
                _blob.StackBase = Stack;

            if (Instance.IsX64Guest)
            {
                ulong InitialRSP = Stack + AlignedStackSize;
                Instance.WriteRegister(Registers.UC_X86_REG_RSP, InitialRSP);
                BuildInitialStack64(Instance, StartupEntry, GuestEntry, ProgramHeaderAddress, ProgramHeaderEntrySize, ProgramHeaderCount, InterpreterBase);
            }
            else if (Instance.IsX86Guest)
            {
                ulong InitialESP = Stack + AlignedStackSize;
                Instance.WriteRegister(Registers.UC_X86_REG_ESP, InitialESP);
                BuildInitialStack32(Instance, (uint)StartupEntry, (uint)GuestEntry, (uint)ProgramHeaderAddress, (uint)ProgramHeaderEntrySize, (uint)ProgramHeaderCount, (uint)InterpreterBase);
            }
        }

        public MemoryProtection TranslateMemoryProtection(ElfSectionCharacteristics Characteristics)
        {
            MemoryProtection Protections = MemoryProtection.None;
            if ((Characteristics & ElfSectionCharacteristics.Write) == 0)
            {
                Protections |= MemoryProtection.Write;
            }

            if ((Characteristics & ElfSectionCharacteristics.Alloc) == 0)
            {
                Protections |= MemoryProtection.Read;
            }

            if ((Characteristics & ElfSectionCharacteristics.ExecInstr) == 0)
            {
                Protections |= MemoryProtection.Execute;
            }

            return Protections;
        }

        public bool TryHandleSyscall(BinaryEmulator Instance)
        {
            try
            {
                int syscall = unchecked((int)Instance.ReadRegister(Registers.UC_X86_REG_RAX));
                ulong Rip = Instance.ReadRegister(Instance.IPRegister);
                if (X64Dictionary.TryGetValue(syscall, out LinuxSyscallEntry Entry))
                {
                    LinuxSyscallContext Context = new LinuxSyscallContext();
                    Context.Abi = SyscallAbi.X64;
                    Context.Arg0 = Instance.ReadRegister(Registers.UC_X86_REG_RDI);
                    Context.Arg1 = Instance.ReadRegister(Registers.UC_X86_REG_RSI);
                    Context.Arg2 = Instance.ReadRegister(Registers.UC_X86_REG_RDX);
                    Context.Arg3 = Instance.ReadRegister(Registers.UC_X86_REG_R10);
                    Context.Arg4 = Instance.ReadRegister(Registers.UC_X86_REG_R8);
                    Context.Arg5 = Instance.ReadRegister(Registers.UC_X86_REG_R9);
                    Entry.Handler.Handle(Instance, Helper, Context);
                    ulong ReturnValue = Instance.ReadRegister(Registers.UC_X86_REG_RAX);
                    if (Instance.Syscalls?.TraceEnabled == true)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Linux, Context.Abi, unchecked((uint)syscall), Entry.Name, GetLinuxSyscallArguments(Context), ReturnValue, Rip, true);
                    Instance.TriggerEventMessage($"[+] Syscall {Entry.Name} (0x{syscall:X}) has been executed, returned 0x{ReturnValue:X}.", LogFlags.Issues);
                }
                else
                {
                    if (Instance.Syscalls?.TraceEnabled == true)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Linux, SyscallAbi.X64, unchecked((uint)syscall), null, ReadLinuxSyscallArguments64(Instance), Instance.ReadRegister(Registers.UC_X86_REG_RAX), Rip, false);
                    Instance.TriggerEventMessage($"[!] Unknown linux syscall with the number 0x{syscall:X} has been executed.", LogFlags.Issues);
                }
            }
            catch (Exception ex)
            {
                Utils.LogError($"[Linux Syscall Handler] Failed to run syscall: {ex.Message}");
            }
            return false;
        }

        private static ulong[] GetLinuxSyscallArguments(LinuxSyscallContext Context)
        {
            return new[] { Context.Arg0, Context.Arg1, Context.Arg2, Context.Arg3, Context.Arg4, Context.Arg5 };
        }

        private static ulong[] ReadLinuxSyscallArguments64(BinaryEmulator Instance)
        {
            return new[]
            {
                Instance.ReadRegister(Registers.UC_X86_REG_RDI),
                Instance.ReadRegister(Registers.UC_X86_REG_RSI),
                Instance.ReadRegister(Registers.UC_X86_REG_RDX),
                Instance.ReadRegister(Registers.UC_X86_REG_R10),
                Instance.ReadRegister(Registers.UC_X86_REG_R8),
                Instance.ReadRegister(Registers.UC_X86_REG_R9)
            };
        }

        private static ulong[] ReadLinuxSyscallArguments32(BinaryEmulator Instance)
        {
            return new[]
            {
                (ulong)Instance.ReadRegister32(Registers.UC_X86_REG_EBX),
                (ulong)Instance.ReadRegister32(Registers.UC_X86_REG_ECX),
                (ulong)Instance.ReadRegister32(Registers.UC_X86_REG_EDX),
                (ulong)Instance.ReadRegister32(Registers.UC_X86_REG_ESI),
                (ulong)Instance.ReadRegister32(Registers.UC_X86_REG_EDI),
                (ulong)Instance.ReadRegister32(Registers.UC_X86_REG_EBP)
            };
        }

        public bool TryHandleInterrupt(BinaryEmulator Instance, uint InterruptNumber)
        {
            if (InterruptNumber == 0x80)
            {
                try
                {
                    int syscall = unchecked((int)Instance.ReadRegister32(Registers.UC_X86_REG_EAX));
                    ulong Rip = Instance.ReadRegister(Instance.IPRegister);
                    if (X86Dictionary.TryGetValue(syscall, out LinuxSyscallEntry Entry))
                    {
                        Helper.SyncEmulatedClock(Instance);
                        LinuxSyscallContext Context = new LinuxSyscallContext();
                        Context.Abi = SyscallAbi.X86;
                        Context.Arg0 = Instance.ReadRegister32(Registers.UC_X86_REG_EBX);
                        Context.Arg1 = Instance.ReadRegister32(Registers.UC_X86_REG_ECX);
                        Context.Arg2 = Instance.ReadRegister32(Registers.UC_X86_REG_EDX);
                        Context.Arg3 = Instance.ReadRegister32(Registers.UC_X86_REG_ESI);
                        Context.Arg4 = Instance.ReadRegister32(Registers.UC_X86_REG_EDI);
                        Context.Arg5 = Instance.ReadRegister32(Registers.UC_X86_REG_EBP);
                        Entry.Handler.Handle(Instance, Helper, Context);
                        ulong ReturnValue = Instance.ReadRegister32(Registers.UC_X86_REG_EAX);
                        if (Instance.Syscalls?.TraceEnabled == true)
                            Instance.Syscalls.RecordSyscall(GuestOsKind.Linux, Context.Abi, unchecked((uint)syscall), Entry.Name, GetLinuxSyscallArguments(Context), ReturnValue, Rip, true);
                        Instance.TriggerEventMessage($"[+] Interrupt Syscall {Entry.Name} (0x{syscall:X}) has been executed, returned 0x{ReturnValue:X}.", LogFlags.Issues);
                    }
                    else
                    {
                        if (Instance.Syscalls?.TraceEnabled == true)
                            Instance.Syscalls.RecordSyscall(GuestOsKind.Linux, SyscallAbi.X86, unchecked((uint)syscall), null, ReadLinuxSyscallArguments32(Instance), Instance.ReadRegister32(Registers.UC_X86_REG_EAX), Rip, false);
                        Instance.TriggerEventMessage($"[!] Unknown linux syscall interrupt with the number 0x{syscall:X} has been executed.", LogFlags.Issues);
                    }
                    return true;
                }
                catch (Exception ex)
                {
                    Utils.LogError($"[Linux Interrupt Handler] Failed to run syscall: {ex.Message}");
                }
            }
            return false;
        }

        public void HandlePrivilegedInstruction(BinaryEmulator Instance)
        {
            QueueSynchronousSignal(Instance, LinuxSignalHelpers.SIGILL, LinuxSignalHelpers.ILL_PRVOPC, Instance.ReadRegister(Instance.IPRegister), default);
        }

        public void HandleInvalidInstruction(BinaryEmulator Instance)
        {
            QueueSynchronousSignal(Instance, LinuxSignalHelpers.SIGILL, LinuxSignalHelpers.ILL_ILLOPN, Instance.ReadRegister(Instance.IPRegister), default);
        }

        public bool HandleInvalidMemory(BinaryEmulator Instance, MemoryType Type, ulong Address, uint Size, ulong Value)
        {
            int Code = LinuxSignalHelpers.IsProtectionFault(Type) ? LinuxSignalHelpers.SEGV_ACCERR : LinuxSignalHelpers.SEGV_MAPERR;
            QueueSynchronousSignal(Instance, LinuxSignalHelpers.SIGSEGV, Code, Address, Type);
            return false;
        }

        internal ulong GetOrCreateSignalRestorer(BinaryEmulator Instance)
        {
            if (Instance.IsX64Guest)
            {
                if (_signalRestorer64 != 0)
                    return _signalRestorer64;

                byte[] Code = new byte[]
                {
                    0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00,
                    0x0F, 0x05,
                    0xF4
                };

                ulong Address = Instance.MapUniqueAddress(0x1000, MemoryProtection.All);
                if (Address == 0 || !Instance.WriteMemory(Address, Code))
                    return 0;

                _signalRestorer64 = Address;
                return _signalRestorer64;
            }

            if (_signalRestorer32 != 0)
                return _signalRestorer32;

            byte[] Code32 = new byte[]
            {
                0xB8, 0x77, 0x00, 0x00, 0x00,
                0xCD, 0x80,
                0xF4
            };

            ulong Address32 = Instance.MapUniqueAddress(0x1000, MemoryProtection.All);
            if (Address32 == 0 || !Instance.WriteMemory(Address32, Code32))
                return 0;

            _signalRestorer32 = Address32;
            return _signalRestorer32;
        }

        private void QueueSynchronousSignal(BinaryEmulator Instance, int Signal, int Code, ulong FaultAddress, MemoryType Access)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
            {
                Instance.StopEmulation();
                return;
            }

            LinuxSignalHelpers.QueueSignal(Instance, Helper, Thread, new LinuxPendingSignal
            {
                Signal = Signal,
                Code = Code,
                FaultAddress = FaultAddress,
                MemoryAccess = Access
            }, true);

            Thread.State = EmulatedThreadState.Exception;
            Instance._emulator.StopEmulation();
        }


        internal static ulong GetCurrentSyscallInstructionAddress(BinaryEmulator Instance, LinuxSyscallContext Context)
        {
            ulong Rip = Instance.ReadRegister(Instance.IPRegister);
            if (IsLinuxSyscallInstructionAt(Instance, Context, Rip))
                return Rip;

            if (Rip >= 2 && IsLinuxSyscallInstructionAt(Instance, Context, Rip - 2))
                return Rip - 2;

            return Rip;
        }

        internal static ulong GetCurrentSyscallReturnAddress(BinaryEmulator Instance, LinuxSyscallContext Context)
        {
            ulong Rip = Instance.ReadRegister(Instance.IPRegister);
            if (IsLinuxSyscallInstructionAt(Instance, Context, Rip))
                return Rip + 2;

            if (Rip >= 2 && IsLinuxSyscallInstructionAt(Instance, Context, Rip - 2))
                return Rip;

            return Rip;
        }

        private static bool IsLinuxSyscallInstructionAt(BinaryEmulator Instance, LinuxSyscallContext Context, ulong Address)
        {
            if (!Instance.IsRegionMapped(Address, 2))
                return false;

            byte[] Bytes = Instance.ReadMemory(Address, 2);
            if (Context.Abi == SyscallAbi.X64)
                return Bytes[0] == 0x0F && Bytes[1] == 0x05;

            return Bytes[0] == 0xCD && Bytes[1] == 0x80;
        }

        public ulong CreateInitialThread(BinaryEmulator Instance)
        {
            if (Instance.Threads.Count > 0)
            {
                if (Instance.CurrentThreadId != -1)
                    return (ulong)(uint)Instance.CurrentThreadId;

                int ExistingThreadId = (int)Instance.Threads.Keys.First();
                Instance.CurrentThreadId = ExistingThreadId;
                return (ulong)(uint)ExistingThreadId;
            }

            ulong StackPointer = Instance.ReadRegister(Instance.IsX64Guest ? Registers.UC_X86_REG_RSP : Registers.UC_X86_REG_ESP);
            LinuxThreadState State = new LinuxThreadState
            {
                CpuidEnabled = Helper.CpuidEnabled
            };

            if (Instance.IsX64Guest)
            {
                State.FsBase = Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE);
                State.GsBase = Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE);
            }

            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = (uint)Instance.NextThreadId++,
                Name = "InitialThread",
                State = EmulatedThreadState.Ready,
                BasePriority = 8,
                DynamicBoost = 0,
                QueueLevel = 0,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = Instance.ReadRegister(Instance.IPRegister),
                Parameter = 0,
                StackAddress = _initialStackBase,
                StackSize = _initialStackSize != 0 ? _initialStackSize : (StackPointer >= 0x100000 ? 0x100000UL : Instance.AlignToPageSize(StackPointer + 0x1000)),
                GuestState = State
            };

            Instance.SaveContext(Thread);
            Helper.RegisterThread(Thread);
            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread.ThreadId;
        }

        public EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name = null, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8)
        {
            ulong ThreadStackSize = StackSizeOverride ?? (_defaultThreadStackSize != 0 ? _defaultThreadStackSize : (Instance.IsX64Guest ? 0x200000UL : 0x100000UL));
            ThreadStackSize = Instance.AlignToPageSize(ThreadStackSize);
            ulong ThreadStackBase = Instance.AllocateThreadStack(ThreadStackSize);
            if (ThreadStackBase == 0)
                return null;

            LinuxThreadState CurrentState = Instance.CurrentThread?.GuestState as LinuxThreadState;
            LinuxThreadState ThreadState = new LinuxThreadState
            {
                CpuidEnabled = CurrentState?.CpuidEnabled ?? Helper.CpuidEnabled,
                FsBase = CurrentState?.FsBase ?? (Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE) : 0),
                GsBase = CurrentState?.GsBase ?? (Instance.IsX64Guest ? Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE) : 0)
            };

            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = (uint)Instance.NextThreadId++,
                Name = Name,
                State = EmulatedThreadState.Ready,
                BasePriority = BasePriority,
                DynamicBoost = 0,
                QueueLevel = 0,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = StartAddress,
                Parameter = Parameter,
                StackAddress = ThreadStackBase,
                StackSize = ThreadStackSize,
                GuestState = ThreadState
            };

            Thread.Name ??= $"LinuxThread_{Thread.ThreadId}";
            Thread.Context.RIP = StartAddress;
            Thread.Context.RFLAGS = 0x202;
            Thread.Context.RBP = 0;

            if (Instance.IsX64Guest)
            {
                ulong InitialRsp = (ThreadStackBase + ThreadStackSize) & ~0xFUL;
                InitialRsp -= 8;
                Instance.WriteMemory(InitialRsp, BitConverter.GetBytes(0UL));
                Thread.Context.RSP = InitialRsp;
                Thread.Context.RDI = Parameter;
            }
            else
            {
                ulong InitialEsp = (ThreadStackBase + ThreadStackSize) & ~0xFUL;
                InitialEsp -= 4;
                Instance.WriteMemory(InitialEsp, BitConverter.GetBytes((uint)Parameter));
                InitialEsp -= 4;
                Instance.WriteMemory(InitialEsp, BitConverter.GetBytes(0U));
                Thread.Context.RSP = InitialEsp;
            }

            Helper.RegisterThread(Thread);
            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }

        public void OnThreadContextLoaded(BinaryEmulator Instance, EmulatedThread Thread)
        {
            LinuxThreadState State = Thread?.GuestState as LinuxThreadState;
            if (State == null)
                return;

            Helper.CurrentThreadId = (int)Thread.ThreadId;
            Helper.RegisterThread(Thread);
            Helper.CpuidEnabled = State.CpuidEnabled;
            if (Instance.IsX64Guest)
            {
                Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_FS_BASE, State.FsBase);
                Instance._emulator.WriteRegister((int)Registers.UC_X86_REG_GS_BASE, State.GsBase);
            }

            TryWriteRegisteredRseq(Instance, Thread, State);
        }

        public bool HasPendingGuestWork(BinaryEmulator Instance, EmulatedThread Thread)
        {
            LinuxThreadState State = Thread?.GuestState as LinuxThreadState;
            if (State == null)
                return false;

            if (State.DispatchSignal)
                return true;

            return LinuxSignalHelpers.TryActivatePendingSignal(State);
        }

        public bool IsHandleSignaled(BinaryEmulator Instance, ulong Handle)
        {
            Helper.SyncEmulatedClock(Instance);
            FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(Handle);
            return Entry?.Object is EpollObject Epoll && LinuxEventHelpers.HasReadyEpollEvents(Instance, Helper, Epoll);
        }

        public bool ExecuteThreadSlice(BinaryEmulator Instance, EmulatedThread Thread, uint QuantumInstructions, out bool State)
        {
            State = false;
            if (Thread == null)
                return false;

            LinuxThreadState ThreadState = Thread.GuestState as LinuxThreadState;
            if (ThreadState != null && ThreadState.DispatchSignal)
            {
                if (!LinuxSignalHelpers.DeliverPendingSignal(Instance, this, Helper, Thread, ThreadState))
                {
                    State = false;
                    return true;
                }
            }

            State = Instance._emulator.Emulate(Thread.Context.RIP, 0, 0, QuantumInstructions);

            ThreadState = Thread.GuestState as LinuxThreadState;
            if (ThreadState != null)
            {
                ThreadState.CpuidEnabled = Helper.CpuidEnabled;
                if (Instance.IsX64Guest)
                {
                    ThreadState.FsBase = Instance.ReadRegister(Registers.UC_X86_REG_FS_BASE);
                    ThreadState.GsBase = Instance.ReadRegister(Registers.UC_X86_REG_GS_BASE);
                }

                if (ThreadState.SignalReturnCompleted)
                {
                    ThreadState.SignalReturnCompleted = false;
                    State = true;
                }

                if (ThreadState.DispatchSignal)
                    State = true;

                ulong CurrentIp = Instance.ReadRegister(Instance.IPRegister);
                if ((!State || CurrentIp == 0) && !ThreadState.DispatchSignal)
                    CleanupExitedThread(Instance, Thread);
            }

            return true;
        }

        /// <summary>
        /// Clean up a thread after exiting (clearing the Clear TID pointer, handling futex, etc)
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Thread">Thread to be cleaned.</param>
        internal static void CleanupExitedThread(BinaryEmulator Instance, EmulatedThread Thread)
        {
            LinuxThreadState State = Thread?.GuestState as LinuxThreadState;
            if (State == null)
                return;

            if (State.TIDPtr != 0)
            {
                if (Instance.IsRegionMapped(State.TIDPtr, 4))
                    Instance.WriteMemory(State.TIDPtr, BitConverter.GetBytes(0U));

                State.TIDPtr = 0;
            }

            if (State.RobustListHead != 0)
            {
                ulong WordSize = Instance.IsX64Guest ? 8UL : 4UL;
                ulong ExpectedHeadSize = WordSize * 3;
                const uint FUTEX_WAITERS = 0x80000000;
                const uint FUTEX_OWNER_DIED = 0x40000000;
                const uint FUTEX_TID_MASK = 0x3FFFFFFF;
                const int ROBUST_LIST_LIMIT = 2048;

                if (State.RobustListLength == ExpectedHeadSize && Instance.IsRegionMapped(State.RobustListHead, ExpectedHeadSize))
                {
                    byte[] HeadBytes = Instance._emulator.ReadMemory(State.RobustListHead, ExpectedHeadSize);
                    ulong Next = WordSize == 8 ? BitConverter.ToUInt64(HeadBytes, 0) : BitConverter.ToUInt32(HeadBytes, 0);
                    long Offset = WordSize == 8 ? BitConverter.ToInt64(HeadBytes, 8) : BitConverter.ToInt32(HeadBytes, 4);
                    ulong Pending = WordSize == 8 ? BitConverter.ToUInt64(HeadBytes, 16) : BitConverter.ToUInt32(HeadBytes, 8);
                    HashSet<ulong> Seen = new HashSet<ulong>();
                    uint ThreadId = Thread.ThreadId & FUTEX_TID_MASK;
                    bool Continue = true;

                    void HandleEntry(ulong EntryAddress)
                    {
                        if (!Continue || EntryAddress == 0 || !Seen.Add(EntryAddress))
                            return;

                        ulong FutexAddress;
                        if (Offset >= 0)
                        {
                            ulong PositiveOffset = (ulong)Offset;
                            if (EntryAddress > ulong.MaxValue - PositiveOffset)
                            {
                                Continue = false;
                                return;
                            }

                            FutexAddress = EntryAddress + PositiveOffset;
                        }
                        else
                        {
                            ulong NegativeOffset = (ulong)(-Offset);
                            if (EntryAddress < NegativeOffset)
                            {
                                Continue = false;
                                return;
                            }

                            FutexAddress = EntryAddress - NegativeOffset;
                        }

                        if (!Instance.IsRegionMapped(FutexAddress, 4))
                        {
                            Continue = false;
                            return;
                        }

                        uint LockWord = BitConverter.ToUInt32(Instance.ReadMemory(FutexAddress, 4), 0);
                        if ((LockWord & FUTEX_TID_MASK) == ThreadId)
                        {
                            uint NewValue = (LockWord & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
                            Instance.WriteMemory(FutexAddress, BitConverter.GetBytes(NewValue));
                        }
                    }

                    HandleEntry(Pending);
                    for (int i = 0; Continue && i < ROBUST_LIST_LIMIT && Next != State.RobustListHead; i++)
                    {
                        if (!Instance.IsRegionMapped(Next, WordSize))
                            break;

                        ulong EntryAddress = Next;
                        byte[] EntryBytes = Instance._emulator.ReadMemory(EntryAddress, WordSize);
                        Next = WordSize == 8 ? BitConverter.ToUInt64(EntryBytes, 0) : BitConverter.ToUInt32(EntryBytes, 0);
                        HandleEntry(EntryAddress);
                    }
                }

                State.RobustListHead = 0;
                State.RobustListLength = 0;
            }

            LinuxGuest Guest = Instance.GetGuest<LinuxGuest>();
            Guest?.Helper?.UnregisterThread(Thread.ThreadId);
        }

        public void OnThreadWaitSatisfied(BinaryEmulator Instance, EmulatedThread Thread)
        {
            LinuxThreadState State = Thread?.GuestState as LinuxThreadState;
            if (State == null)
                return;

            if (State.FutexWaitActive)
            {
                Helper.RemoveFutexWaiter(State.FutexAddress, Thread);
                State.FutexWaitResult = Thread.WaitTimedOut ? -(long)LinuxErrno.ETIMEDOUT : 0L;
                Helper?.SetThreadReturnValue(Instance, Thread, State.FutexWaitResult);
                State.FutexWaitCompleted = Thread.Context != null && Thread.Context.RIP == State.FutexWaitResumeRIP;
                if (!State.FutexWaitCompleted)
                    State.FutexWaitResumeRIP = 0;

                State.FutexWaitActive = false;
                State.FutexAddress = 0;
                State.FutexBitset = 0;
                return;
            }

            if (State.EpollWaitActive)
            {
                CompleteEpollWait(Instance, Thread, State);
                return;
            }
        }


        private void CompleteEpollWait(BinaryEmulator Instance, EmulatedThread Thread, LinuxThreadState State)
        {
            long Result = 0;
            if (!Thread.WaitTimedOut)
            {
                FileDescriptorEntry? Entry = Helper.DescriptorTable.GetEntry(State.EpollWaitDescriptor);
                if (Entry == null)
                {
                    Result = -(long)LinuxErrno.EBADF;
                }
                else if (Entry.Object is not EpollObject Epoll)
                {
                    Result = -(long)LinuxErrno.EINVAL;
                }
                else
                {
                    Result = LinuxEventHelpers.WriteReadyEvents(Instance, Helper, Epoll, State.EpollWaitEventsAddress, State.EpollWaitMaxEvents);
                    if (Result < 0)
                        Result = -(long)LinuxErrno.EFAULT;
                }
            }

            LinuxSignalHelpers.RestoreEpollWaitSignalMask(State);
            Helper.SetThreadReturnValue(Instance, Thread, Result);
            LinuxSignalHelpers.ClearEpollWait(State);
        }

        public void Start(BinaryEmulator Instance)
        {
            ulong ThreadId = CreateInitialThread(Instance);
            if (!Instance.Threads.TryGetValue((uint)ThreadId, out EmulatedThread Thread) || Thread == null)
                return;

            Instance.LoadContext(Thread);
            Instance.RunMlfqScheduler();
        }

        /// <summary>
        /// Register a syscall and add it to the dictionary list.
        /// </summary>
        /// <param name="Name">Name of the syscall.</param>
        /// <param name="SysNumber64">Syscall number for x64 version.</param>
        /// <param name="SysNumber32">Syscall number for x86 version.</param>
        /// <param name="SyscallFunc">Syscall handler.</param>
        /// <remarks>
        /// Putting -1 in either <paramref name="SysNumber64"/> or <paramref name="SysNumber32"/> will cause it not to be added to its respective dictionary.
        /// </remarks>
        public void RegisterSyscall(string Name, int SysNumber64, int SysNumber32, ILinuxSyscall SyscallFunc)
        {
            if (SysNumber64 != -1)
            {
                LinuxSyscallEntry Entry64 = new LinuxSyscallEntry() { Name = Name, Number = SysNumber64, ABI = SyscallAbi.X64, Handler = SyscallFunc };
                X64Dictionary.TryAdd(SysNumber64, Entry64);
            }

            if (SysNumber32 != -1)
            {
                LinuxSyscallEntry Entry86 = new LinuxSyscallEntry() { Name = Name, Number = SysNumber32, ABI = SyscallAbi.X86, Handler = SyscallFunc };
                X86Dictionary.TryAdd(SysNumber32, Entry86);
            }
        }

        /// <summary>
        /// Register all implemented linux syscalls.
        /// </summary>
        public void RegisterSyscalls()
        {
            // File syscalls
            RegisterSyscall("read", 0, 3, new Read());
            RegisterSyscall("write", 1, 4, new Write());
            RegisterSyscall("writev", 20, 146, new Writev());
            RegisterSyscall("lseek", 8, 19, new Lseek());
            RegisterSyscall("_llseek", -1, 140, new Llseek());
            RegisterSyscall("getdents", 78, 141, new Getdents());
            RegisterSyscall("getdents64", 217, 220, new Getdents(true));
            RegisterSyscall("open", 2, 5, new Open());
            RegisterSyscall("access", 21, 33, new Access());
            RegisterSyscall("mount", 165, 21, new Mount());
            RegisterSyscall("openat", 257, 295, new Openat());
            RegisterSyscall("newfstatat", 262, 300, new Newfstatat());
            RegisterSyscall("pread64", 17, 180, new Pread64());
            RegisterSyscall("fcntl", 72, 55, new Fcntl());
            RegisterSyscall("fcntl64", -1, 221, new Fcntl());
            RegisterSyscall("stat", 4, 106, new Stat());
            RegisterSyscall("lstat", 6, 107, new Lstat());
            RegisterSyscall("fstat", 5, 108, new Fstat());
            RegisterSyscall("stat64", -1, 195, new Stat(true));
            RegisterSyscall("lstat64", -1, 196, new Lstat(true));
            RegisterSyscall("fstat64", -1, 197, new Fstat(true));
            RegisterSyscall("fadvise64", 221, 250, new Fadvise64());
            RegisterSyscall("statfs", 137, 99, new Statfs());
            RegisterSyscall("ioctl", 16, 54, new Ioctl());

            // Process syscalls
            RegisterSyscall("exit", 60, 1, new Exit());
            RegisterSyscall("exit_group", 231, 252, new Exit_group());
            RegisterSyscall("mmap", 9, 90, new Mmap());
            RegisterSyscall("mprotect", 10, 125, new Mprotect());
            RegisterSyscall("munmap", 11, 91, new Munmap());
            RegisterSyscall("mremap", 25, 163, new Mremap());
            RegisterSyscall("brk", 12, 45, new Brk());
            RegisterSyscall("arch_prctl", 158, 384, new Arch_prctl());
            RegisterSyscall("set_tid_address", 218, 258, new Set_tid_address());
            RegisterSyscall("set_robust_list", 273, 311, new Set_robust_list());
            RegisterSyscall("get_robust_list", 274, 312, new Get_robust_list());
            RegisterSyscall("gettid", 186, 224, new Gettid());
            RegisterSyscall("getpid", 39, 20, new Getpid());
            RegisterSyscall("getppid", 110, 64, new Getppid());
            RegisterSyscall("umask", 95, 60, new Umask());
            RegisterSyscall("getuid", 102, 24, new Getuid());
            RegisterSyscall("getgid", 104, 47, new Getgid());
            RegisterSyscall("geteuid", 107, 49, new Geteuid());
            RegisterSyscall("getegid", 108, 50, new Getegid());
            RegisterSyscall("nice", -1, 34, new Nice());
            RegisterSyscall("rseq", 334, 386, new Rseq());
            RegisterSyscall("prlimit64", 302, 340, new Prlimit64());
            RegisterSyscall("sched_getaffinity", 204, 242, new Sched_getaffinity());
            RegisterSyscall("clone", 56, 120, new Clone());
            RegisterSyscall("prctl", 157, 172, new Prctl());

            // Misc syscalls
            RegisterSyscall("close", 3, 6, new Close());
            RegisterSyscall("uname", 63, 122, new Uname());
            RegisterSyscall("clock_gettime", 228, 265, new Clock_gettime());
            RegisterSyscall("clock_gettime64", -1, 403, new Clock_gettime(true));
            RegisterSyscall("getrandom", 318, 355, new Getrandom());
            RegisterSyscall("poll", 7, 168, new Poll());
            RegisterSyscall("pselect6", 270, 308, new Pselect6());
            RegisterSyscall("futex", 202, 240, new Futex());
            RegisterSyscall("futex_time64", -1, 422, new Futex(true));
            RegisterSyscall("rt_sigaction", 13, 174, new Rt_sigaction());
            RegisterSyscall("rt_sigprocmask", 14, 175, new Rt_sigprocmask());
            RegisterSyscall("rt_sigreturn", 15, 173, new Rt_sigreturn());
            RegisterSyscall("rt_sigpending", 127, 176, new Rt_sigpending());
            RegisterSyscall("rt_sigsuspend", 130, 179, new Rt_sigsuspend());
            RegisterSyscall("sigaltstack", 131, 186, new Sigaltstack());
            RegisterSyscall("kill", 62, 37, new Kill());
            RegisterSyscall("tkill", 200, 238, new Tkill());
            RegisterSyscall("tgkill", 234, 270, new Tgkill());
            RegisterSyscall("epoll_wait", 232, 256, new Epoll_wait());
            RegisterSyscall("epoll_ctl", 233, 255, new Epoll_ctl());
            RegisterSyscall("epoll_pwait", 281, 319, new Epoll_wait(true));
            RegisterSyscall("timerfd_create", 283, 322, new Timerfd_create());
            RegisterSyscall("timerfd_settime", 286, 325, new Timerfd_settime());
            RegisterSyscall("timerfd_gettime", 287, 326, new Timerfd_gettime());
            RegisterSyscall("eventfd2", 290, 328, new Eventfd2());
            RegisterSyscall("epoll_create1", 291, 329, new Epoll_create1());
            RegisterSyscall("timerfd_settime64", -1, 411, new Timerfd_settime(true));
            RegisterSyscall("timerfd_gettime64", -1, 410, new Timerfd_gettime(true));

            // Network syscalls
            RegisterSyscall("socket", 41, 359, new Socket());
            RegisterSyscall("connect", 42, 362, new Connect());
            RegisterSyscall("accept", 43, -1, new Accept());
            RegisterSyscall("sendto", 44, 369, new Sendto());
            RegisterSyscall("recvfrom", 45, 371, new Recvfrom());
            RegisterSyscall("shutdown", 48, 373, new Shutdown());
            RegisterSyscall("bind", 49, 361, new Bind());
            RegisterSyscall("listen", 50, 363, new Listen());
            RegisterSyscall("getsockname", 51, 367, new Getsockname());
            RegisterSyscall("setsockopt", 54, 366, new Setsockopt());
            RegisterSyscall("getsockopt", 55, 365, new Getsockopt());
            RegisterSyscall("accept4", 288, 364, new Accept(true));
            RegisterSyscall("socketcall", -1, 102, new Socketcall());
        }

        private static bool WriteRseqUInt32(BinaryEmulator Instance, ulong Address, uint Value)
        {
            return Instance.WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        private static bool WriteRseqUInt64(BinaryEmulator Instance, ulong Address, ulong Value)
        {
            return Instance.WriteMemory(Address, BitConverter.GetBytes(Value));
        }

        internal static bool TryWriteRegisteredRseq(BinaryEmulator Instance, EmulatedThread Thread, LinuxThreadState State, bool ClearRseqCs = false)
        {
            if (State == null || State.RseqPointer == 0 || State.RseqLength == 0)
                return true;

            if (!Instance.IsRegionMapped(State.RseqPointer, State.RseqLength))
                return false;

            uint MmCid = Thread?.ThreadId ?? (uint)Math.Max(Instance.CurrentThreadId, 0);
            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqCpuIdStartOffset, 0))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqCpuIdOffset, 0))
                return false;

            if (ClearRseqCs && !WriteRseqUInt64(Instance, State.RseqPointer + RseqCsOffset, 0))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqNodeIdOffset, 0))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqMmCidOffset, MmCid))
                return false;

            return true;
        }

        internal static bool TryResetRegisteredRseq(BinaryEmulator Instance, LinuxThreadState State, bool ClearRseqCs = false)
        {
            if (State == null || State.RseqPointer == 0 || State.RseqLength == 0)
                return true;

            if (!Instance.IsRegionMapped(State.RseqPointer, State.RseqLength))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqCpuIdStartOffset, RseqCpuIdUninitialized))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqCpuIdOffset, RseqCpuIdUninitialized))
                return false;

            if (ClearRseqCs && !WriteRseqUInt64(Instance, State.RseqPointer + RseqCsOffset, 0))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqNodeIdOffset, 0))
                return false;

            if (!WriteRseqUInt32(Instance, State.RseqPointer + RseqMmCidOffset, 0))
                return false;

            return true;
        }

        /// <summary>
        /// Initialize the raw data blob with the linux guest.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Binary">BinaryFile class which was tried to be initialized with the blob.</param>
        /// <param name="Data">Raw Data.</param>
        /// <param name="HighestAddress">Highest address to be set.</param>
        /// <param name="StackSize">Stack size to be initialized.</param>
        /// <param name="GuestEntry">Entry address after mapping.</param>
        /// <exception cref="InvalidOperationException"></exception>
        private void InitializeBlob(BinaryEmulator Instance, BinaryFile Binary, ReadOnlySpan<byte> Data, ref ulong HighestAddress, ref ulong StackSize, out ulong GuestEntry)
        {
            ulong BlobSize = Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 1));
            ulong RequestedBase = _blob?.LoadAddress ?? 0;
            ulong MappedBase;
            if (RequestedBase == 0 || Instance.IsRegionMapped(RequestedBase, BlobSize))
                MappedBase = Instance.MapUniqueAddress(BlobSize, MemoryProtection.All);
            else
                MappedBase = Instance.MapMemoryRegion(RequestedBase, BlobSize, MemoryProtection.All);

            if (MappedBase == 0)
                throw new InvalidOperationException("Failed to map the Linux blob image.");

            if (Data.Length != 0)
                Instance._emulator.WriteMemory(MappedBase, Data);

            if (_blob != null)
                _blob.MappedBase = MappedBase;

            HighestAddress = MappedBase + BlobSize;
            StackSize = (_blob?.StackSize).GetValueOrDefault();

            if (_blob == null || _blob.EntryAddress == 0)
            {
                GuestEntry = MappedBase;
            }
            else
            {
                ulong EntryAddress = _blob.EntryAddress;
                if (_blob.LoadAddress != 0 && EntryAddress >= _blob.LoadAddress && EntryAddress < _blob.LoadAddress + BlobSize)
                    GuestEntry = MappedBase + (EntryAddress - _blob.LoadAddress);
                else
                    GuestEntry = EntryAddress;
            }

            RegisterLoadedModule(Binary, Binary?.Location, "main", MappedBase, BlobSize, GuestEntry, 0);
        }

        private void RegisterLoadedModule(BinaryFile Binary, string ModulePath, string Role, ulong MappedBase, ulong Size, ulong EntryPoint, ulong OriginalEntryPoint)
        {
            if (MappedBase == 0 || Size == 0)
                return;

            string PathValue = ModulePath ?? Binary?.Location ?? string.Empty;
            string Name = GetModuleDisplayName(PathValue, Role);
            LinuxLoadedModule Existing = FindLoadedModule(PathValue, Role, MappedBase);

            if (Existing != null)
            {
                Existing.Name = Name;
                Existing.Path = PathValue;
                Existing.Role = Role;
                if (EntryPoint != 0)
                    Existing.EntryPoint = EntryPoint;
                if (OriginalEntryPoint != 0)
                    Existing.OriginalEntryPoint = OriginalEntryPoint;
                Existing.AddRange(MappedBase, Size);
                if (Existing.Size < Size)
                    Existing.Size = Size;
                return;
            }

            LinuxLoadedModule Module = new LinuxLoadedModule
            {
                Name = Name,
                Path = PathValue,
                Role = Role,
                EntryPoint = EntryPoint,
                OriginalEntryPoint = OriginalEntryPoint
            };
            Module.AddRange(MappedBase, Size);
            LoadedModules.Add(Module);
        }

        private LinuxLoadedModule FindLoadedModule(string ModulePath, string Role, ulong MappedBase)
        {
            for (int i = 0; i < LoadedModules.Count; i++)
            {
                LinuxLoadedModule Existing = LoadedModules[i];
                if (!string.IsNullOrWhiteSpace(ModulePath) && !string.IsNullOrWhiteSpace(Existing.Path) && string.Equals(Existing.Path, ModulePath, StringComparison.OrdinalIgnoreCase))
                    return Existing;

                if (MappedBase != 0 && Existing.MappedBase == MappedBase)
                    return Existing;

                if (!string.IsNullOrWhiteSpace(Role) && string.Equals(Existing.Role, Role, StringComparison.OrdinalIgnoreCase) && (string.Equals(Role, "main", StringComparison.OrdinalIgnoreCase) || string.Equals(Role, "interpreter", StringComparison.OrdinalIgnoreCase)))
                    return Existing;
            }

            return null;
        }

        private static string GetModuleDisplayName(string PathValue, string Role)
        {
            string Name = Path.GetFileName(PathValue);
            if (!string.IsNullOrWhiteSpace(Name))
                return Name;

            if (string.Equals(Role, "interpreter", StringComparison.OrdinalIgnoreCase))
                return "interpreter";

            if (string.Equals(Role, "main", StringComparison.OrdinalIgnoreCase))
                return "main";

            return "module";
        }

        internal void RegisterMappedFileModule(string ModulePath, string HostPath, ulong MappedAddress, ulong MappingSize, ulong FileOffset)
        {
            if (MappedAddress == 0 || MappingSize == 0 || string.IsNullOrWhiteSpace(HostPath) || !File.Exists(HostPath))
                return;

            try
            {
                using BinaryFile ModuleBinary = new BinaryFile(HostPath, true);
                if (ModuleBinary.FileFormat != BinaryFormat.ELF)
                    return;

                ReadOnlySpan<byte> Data = ModuleBinary.GetBinaryData();
                ulong ModuleBase = MappedAddress;
                ulong ModuleSize = MappingSize;
                ulong EntryPoint = 0;
                if (!TryResolveMappedElfModuleLayout(ModuleBinary, Data, MappedAddress, FileOffset, out ModuleBase, out ModuleSize, out EntryPoint))
                    EntryPoint = (ulong)ModuleBinary.EntryPoint;

                string PathValue = !string.IsNullOrWhiteSpace(ModulePath) ? ModulePath : HostPath;
                string Role = "module";
                LinuxLoadedModule Existing = FindLoadedModule(PathValue, null, 0);
                if (Existing != null && !string.IsNullOrWhiteSpace(Existing.Role))
                    Role = Existing.Role;

                RegisterLoadedModule(ModuleBinary, PathValue, Role, ModuleBase, ModuleSize, EntryPoint, (ulong)ModuleBinary.EntryPoint);
                LinuxLoadedModule Registered = FindLoadedModule(PathValue, Role, ModuleBase);
                if (Registered != null)
                {
                    ulong ModuleEnd = ModuleBase + ModuleSize;
                    if (ModuleEnd < ModuleBase)
                        ModuleEnd = ulong.MaxValue;

                    if (Registered.Ranges.Count == 1 && Registered.Ranges[0].Start == ModuleBase && Registered.Ranges[0].End == ModuleEnd && (ModuleBase != MappedAddress || ModuleSize != MappingSize))
                        Registered.Ranges.Clear();

                    Registered.AddRange(MappedAddress, MappingSize);
                }
            }
            catch
            {
            }
        }

        private bool TryResolveMappedElfModuleLayout(BinaryFile Binary, ReadOnlySpan<byte> Data, ulong MappedAddress, ulong FileOffset, out ulong ModuleBase, out ulong ModuleSize, out ulong EntryPoint)
        {
            ModuleBase = MappedAddress;
            ModuleSize = 0;
            EntryPoint = (ulong)Binary.EntryPoint;

            if (!TryCollectElfLoadRegions(Binary, Data, out List<ElfLoadRegion> Regions, out ulong MinAddress, out ulong MaxAddress))
                return false;

            ModuleSize = MaxAddress - MinAddress;
            for (int i = 0; i < Regions.Count; i++)
            {
                ElfLoadRegion Region = Regions[i];
                ulong RegionOffset = AlignDown(Region.FileOffset);
                if (RegionOffset != FileOffset)
                    continue;

                ulong RegionBaseOffset = AlignDown(Region.VirtualAddress) - MinAddress;
                if (MappedAddress < RegionBaseOffset)
                    continue;

                ModuleBase = MappedAddress - RegionBaseOffset;
                if ((ulong)Binary.EntryPoint >= MinAddress)
                    EntryPoint = ModuleBase + ((ulong)Binary.EntryPoint - MinAddress);
                else
                    EntryPoint = ModuleBase + (ulong)Binary.EntryPoint;
                return true;
            }

            return false;
        }

        private bool TryCollectElfLoadRegions(BinaryFile Binary, ReadOnlySpan<byte> Data, out List<ElfLoadRegion> Regions, out ulong MinAddress, out ulong MaxAddress)
        {
            Regions = new List<ElfLoadRegion>();
            MinAddress = ulong.MaxValue;
            MaxAddress = 0;

            if (Binary.Architecture == BinaryArchitecture.x64)
            {
                if (Data.Length < sizeof(ulong) * 6)
                    return false;

                ELF64_HEADER Header = Binary.ReadStruct<ELF64_HEADER>(Data, 0);
                if (Header.e_phoff == 0 || Header.e_phentsize == 0 || Header.e_phnum == 0)
                    return false;

                for (int i = 0; i < Header.e_phnum; i++)
                {
                    long HeaderOffset = (long)Header.e_phoff + (long)(i * Header.e_phentsize);
                    if (HeaderOffset < 0 || HeaderOffset + Header.e_phentsize > Data.Length)
                        return false;

                    ELF64_PROGRAM_HEADER ProgramHeader = Binary.ReadStruct<ELF64_PROGRAM_HEADER>(Data, (int)HeaderOffset);
                    if (ProgramHeader.p_type != PT_LOAD || ProgramHeader.p_memsz == 0)
                        continue;

                    Regions.Add(new ElfLoadRegion
                    {
                        VirtualAddress = ProgramHeader.p_vaddr,
                        FileOffset = ProgramHeader.p_offset,
                        FileSize = ProgramHeader.p_filesz,
                        MemorySize = ProgramHeader.p_memsz,
                        Flags = ProgramHeader.p_flags
                    });
                }
            }
            else
            {
                if (Data.Length < sizeof(uint) * 6)
                    return false;

                ELF32_HEADER Header = Binary.ReadStruct<ELF32_HEADER>(Data, 0);
                if (Header.e_phoff == 0 || Header.e_phentsize == 0 || Header.e_phnum == 0)
                    return false;

                for (int i = 0; i < Header.e_phnum; i++)
                {
                    long HeaderOffset = (long)Header.e_phoff + (long)(i * Header.e_phentsize);
                    if (HeaderOffset < 0 || HeaderOffset + Header.e_phentsize > Data.Length)
                        return false;

                    ELF32_PROGRAM_HEADER ProgramHeader = Binary.ReadStruct<ELF32_PROGRAM_HEADER>(Data, (int)HeaderOffset);
                    if (ProgramHeader.p_type != PT_LOAD || ProgramHeader.p_memsz == 0)
                        continue;

                    Regions.Add(new ElfLoadRegion
                    {
                        VirtualAddress = ProgramHeader.p_vaddr,
                        FileOffset = ProgramHeader.p_offset,
                        FileSize = ProgramHeader.p_filesz,
                        MemorySize = ProgramHeader.p_memsz,
                        Flags = ProgramHeader.p_flags
                    });
                }
            }

            if (Regions.Count == 0)
                return false;

            for (int i = 0; i < Regions.Count; i++)
            {
                ulong RegionBase = AlignDown(Regions[i].VirtualAddress);
                ulong RegionEnd = (Regions[i].VirtualAddress + Regions[i].MemorySize + 0xFFFUL) & ~0xFFFUL;
                if (RegionBase < MinAddress)
                    MinAddress = RegionBase;
                if (RegionEnd > MaxAddress)
                    MaxAddress = RegionEnd;
            }

            return MinAddress < MaxAddress;
        }

        private void LoadElfBinary(BinaryEmulator Instance, BinaryFile Binary, ReadOnlySpan<byte> Data, ref ulong HighestAddress, out ulong GuestEntry, out ulong ProgramHeaderAddress, out ulong ProgramHeaderEntrySize, out ulong ProgramHeaderCount, out ulong ModuleBase, out ulong ModuleSize, string ModulePath, string Role)
        {
            if (!TryLoadElfSegments(Instance, Binary, Data, ref HighestAddress, out GuestEntry, out ProgramHeaderAddress, out ProgramHeaderEntrySize, out ProgramHeaderCount, out ModuleBase, out ModuleSize))
            {
                ProgramHeaderAddress = 0;
                ProgramHeaderEntrySize = 0;
                ProgramHeaderCount = 0;
                LoadElfSections(Instance, Binary, Data, ref HighestAddress, out GuestEntry, out ModuleBase, out ModuleSize);
            }

            RegisterLoadedModule(Binary, ModulePath, Role, ModuleBase, ModuleSize, GuestEntry, (ulong)Binary.EntryPoint);
        }

        private bool TryReadElfInterpreterPath(BinaryFile Binary, ReadOnlySpan<byte> Data, out string InterpreterPath)
        {
            InterpreterPath = null;

            if (Binary.Architecture == BinaryArchitecture.x64)
            {
                if (Data.Length < sizeof(ulong) * 6)
                    return false;

                ELF64_HEADER Header = Binary.ReadStruct<ELF64_HEADER>(Data, 0);
                if (Header.e_phoff == 0 || Header.e_phentsize == 0 || Header.e_phnum == 0)
                    return false;

                for (int i = 0; i < Header.e_phnum; i++)
                {
                    long HeaderOffset = (long)Header.e_phoff + (long)(i * Header.e_phentsize);
                    if (HeaderOffset < 0 || HeaderOffset + Header.e_phentsize > Data.Length)
                        return false;

                    ELF64_PROGRAM_HEADER ProgramHeader = Binary.ReadStruct<ELF64_PROGRAM_HEADER>(Data, (int)HeaderOffset);
                    if (ProgramHeader.p_type != PT_INTERP || ProgramHeader.p_filesz == 0)
                        continue;

                    if (!TryReadElfInterpreterString(Data, ProgramHeader.p_offset, ProgramHeader.p_filesz, out InterpreterPath))
                        return false;

                    return !string.IsNullOrWhiteSpace(InterpreterPath);
                }
            }
            else
            {
                if (Data.Length < sizeof(uint) * 6)
                    return false;

                ELF32_HEADER Header = Binary.ReadStruct<ELF32_HEADER>(Data, 0);
                if (Header.e_phoff == 0 || Header.e_phentsize == 0 || Header.e_phnum == 0)
                    return false;

                for (int i = 0; i < Header.e_phnum; i++)
                {
                    long HeaderOffset = (long)Header.e_phoff + (long)(i * Header.e_phentsize);
                    if (HeaderOffset < 0 || HeaderOffset + Header.e_phentsize > Data.Length)
                        return false;

                    ELF32_PROGRAM_HEADER ProgramHeader = Binary.ReadStruct<ELF32_PROGRAM_HEADER>(Data, (int)HeaderOffset);
                    if (ProgramHeader.p_type != PT_INTERP || ProgramHeader.p_filesz == 0)
                        continue;

                    if (!TryReadElfInterpreterString(Data, ProgramHeader.p_offset, ProgramHeader.p_filesz, out InterpreterPath))
                        return false;

                    return !string.IsNullOrWhiteSpace(InterpreterPath);
                }
            }

            return false;
        }

        private bool TryReadElfInterpreterString(ReadOnlySpan<byte> Data, ulong Offset, ulong Size, out string InterpreterPath)
        {
            InterpreterPath = null;
            if (Size == 0 || Offset >= (ulong)Data.Length)
                return false;

            int ByteCount = (int)Math.Min(Size, (ulong)Data.Length - Offset);
            if (ByteCount <= 0)
                return false;

            ReadOnlySpan<byte> PathBytes = Data.Slice((int)Offset, ByteCount);
            int TerminatorIndex = PathBytes.IndexOf((byte)0);
            if (TerminatorIndex >= 0)
                PathBytes = PathBytes.Slice(0, TerminatorIndex);

            InterpreterPath = Encoding.ASCII.GetString(PathBytes).Trim();
            return !string.IsNullOrWhiteSpace(InterpreterPath);
        }

        private bool TryLoadElfInterpreter(BinaryEmulator Instance, BinaryFile Binary, string InterpreterPath, ref ulong HighestAddress, out ulong InterpreterEntry, out ulong InterpreterBase)
        {
            InterpreterEntry = 0;
            InterpreterBase = 0;

            string InterpreterHostPath = GeneralHelper.IO.ResolveHostPath(InterpreterPath, BinaryFormat.ELF);
            if (string.IsNullOrWhiteSpace(InterpreterHostPath) || !File.Exists(InterpreterHostPath))
                return false;

            using BinaryFile InterpreterBinary = new BinaryFile(InterpreterHostPath, true);
            if (InterpreterBinary.FileFormat != BinaryFormat.ELF || InterpreterBinary.Architecture != Binary.Architecture)
                return false;

            ReadOnlySpan<byte> InterpreterData = InterpreterBinary.GetBinaryData();
            ulong InterpreterHighestAddress = HighestAddress;
            ulong InterpreterProgramHeaderAddress;
            ulong InterpreterProgramHeaderEntrySize;
            ulong InterpreterProgramHeaderCount;
            ulong InterpreterModuleBase;
            ulong InterpreterModuleSize;
            LoadElfBinary(Instance, InterpreterBinary, InterpreterData, ref InterpreterHighestAddress, out InterpreterEntry, out InterpreterProgramHeaderAddress, out InterpreterProgramHeaderEntrySize, out InterpreterProgramHeaderCount, out InterpreterModuleBase, out InterpreterModuleSize, InterpreterPath, "interpreter");
            HighestAddress = Math.Max(HighestAddress, InterpreterHighestAddress);

            ulong OriginalInterpreterEntry = (ulong)InterpreterBinary.EntryPoint;
            if (InterpreterEntry >= OriginalInterpreterEntry)
                InterpreterBase = InterpreterEntry - OriginalInterpreterEntry;

            return InterpreterEntry != 0;
        }

        private bool TryLoadElfSegments(BinaryEmulator Instance, BinaryFile Binary, ReadOnlySpan<byte> Data, ref ulong HighestAddress, out ulong GuestEntry, out ulong ProgramHeaderAddress, out ulong ProgramHeaderEntrySize, out ulong ProgramHeaderCount, out ulong ModuleBase, out ulong ModuleSize)
        {
            GuestEntry = Binary.EntryPoint;
            ProgramHeaderAddress = 0;
            ProgramHeaderEntrySize = 0;
            ProgramHeaderCount = 0;
            ModuleBase = 0;
            ModuleSize = 0;

            List<ElfLoadRegion> Regions = new List<ElfLoadRegion>();
            ulong EntryAddress;
            ulong ProgramHeaderOffset;
            ushort ProgramHeaderSize;
            ushort ProgramHeaderEntries;

            if (Binary.Architecture == BinaryArchitecture.x64)
            {
                if (Data.Length < sizeof(ulong) * 6)
                    return false;

                ELF64_HEADER Header = Binary.ReadStruct<ELF64_HEADER>(Data, 0);
                EntryAddress = Header.e_entry;
                ProgramHeaderOffset = Header.e_phoff;
                ProgramHeaderSize = Header.e_phentsize;
                ProgramHeaderEntries = Header.e_phnum;

                if (ProgramHeaderOffset == 0 || ProgramHeaderSize == 0 || ProgramHeaderEntries == 0)
                    return false;

                for (int i = 0; i < ProgramHeaderEntries; i++)
                {
                    long HeaderOffset = (long)ProgramHeaderOffset + (long)(i * ProgramHeaderSize);
                    if (HeaderOffset < 0 || HeaderOffset + ProgramHeaderSize > Data.Length)
                        return false;

                    ELF64_PROGRAM_HEADER ProgramHeader = Binary.ReadStruct<ELF64_PROGRAM_HEADER>(Data, (int)HeaderOffset);
                    if (ProgramHeader.p_type != PT_LOAD || ProgramHeader.p_memsz == 0)
                        continue;

                    Regions.Add(new ElfLoadRegion
                    {
                        VirtualAddress = ProgramHeader.p_vaddr,
                        FileOffset = ProgramHeader.p_offset,
                        FileSize = ProgramHeader.p_filesz,
                        MemorySize = ProgramHeader.p_memsz,
                        Flags = ProgramHeader.p_flags
                    });
                }
            }
            else
            {
                if (Data.Length < sizeof(uint) * 6)
                    return false;

                ELF32_HEADER Header = Binary.ReadStruct<ELF32_HEADER>(Data, 0);
                EntryAddress = Header.e_entry;
                ProgramHeaderOffset = Header.e_phoff;
                ProgramHeaderSize = Header.e_phentsize;
                ProgramHeaderEntries = Header.e_phnum;

                if (ProgramHeaderOffset == 0 || ProgramHeaderSize == 0 || ProgramHeaderEntries == 0)
                    return false;

                for (int i = 0; i < ProgramHeaderEntries; i++)
                {
                    long HeaderOffset = (long)ProgramHeaderOffset + (long)(i * ProgramHeaderSize);
                    if (HeaderOffset < 0 || HeaderOffset + ProgramHeaderSize > Data.Length)
                        return false;

                    ELF32_PROGRAM_HEADER ProgramHeader = Binary.ReadStruct<ELF32_PROGRAM_HEADER>(Data, (int)HeaderOffset);
                    if (ProgramHeader.p_type != PT_LOAD || ProgramHeader.p_memsz == 0)
                        continue;

                    Regions.Add(new ElfLoadRegion
                    {
                        VirtualAddress = ProgramHeader.p_vaddr,
                        FileOffset = ProgramHeader.p_offset,
                        FileSize = ProgramHeader.p_filesz,
                        MemorySize = ProgramHeader.p_memsz,
                        Flags = ProgramHeader.p_flags
                    });
                }
            }

            if (Regions.Count == 0)
                return false;

            ulong MinAddress = ulong.MaxValue;
            ulong MaxAddress = 0;
            for (int i = 0; i < Regions.Count; i++)
            {
                ulong RegionBase = AlignDown(Regions[i].VirtualAddress);
                ulong RegionEnd = Instance.AlignToPageSize(Regions[i].VirtualAddress + Regions[i].MemorySize);
                if (RegionBase < MinAddress)
                    MinAddress = RegionBase;
                if (RegionEnd > MaxAddress)
                    MaxAddress = RegionEnd;
            }

            ulong ImageSize = MaxAddress - MinAddress;
            ulong ReservedBase;
            if (MinAddress != 0 && !Instance.IsRegionMapped(MinAddress, ImageSize))
                ReservedBase = Instance.MapMemoryRegion(MinAddress, ImageSize, MemoryProtection.All);
            else
                ReservedBase = Instance.MapUniqueAddress(ImageSize, MemoryProtection.All);

            if (ReservedBase == 0)
                throw new InvalidOperationException("Failed to map the ELF image.");

            ulong LoadBias = ReservedBase - MinAddress;
            ModuleBase = ReservedBase;
            ModuleSize = ImageSize;
            List<ProtectionRange> ProtectionRanges = new List<ProtectionRange>();

            for (int i = 0; i < Regions.Count; i++)
            {
                ElfLoadRegion Region = Regions[i];
                ulong RegionAddress = Region.VirtualAddress + LoadBias;
                MemoryProtection Protection = TranslateProgramHeaderProtection(Region.Flags);
                AddProtectionRange(ProtectionRanges, AlignDown(RegionAddress), Instance.AlignToPageSize((RegionAddress - AlignDown(RegionAddress)) + Region.MemorySize), Protection);

                if (Region.FileSize == 0)
                    continue;

                if (Region.FileOffset >= (ulong)Data.Length)
                    continue;

                int BytesToWrite = (int)Math.Min(Region.FileSize, (ulong)Data.Length - Region.FileOffset);
                if (BytesToWrite <= 0)
                    continue;

                Instance._emulator.WriteMemory(RegionAddress, Data.Slice((int)Region.FileOffset, BytesToWrite));
            }

            ApplyProtectionRanges(Instance, ProtectionRanges);

            HighestAddress = MaxAddress + LoadBias;
            GuestEntry = EntryAddress + LoadBias;
            ProgramHeaderEntrySize = ProgramHeaderSize;
            ProgramHeaderCount = ProgramHeaderEntries;

            ulong ProgramHeaderTableSize = ProgramHeaderEntrySize * ProgramHeaderCount;
            for (int i = 0; i < Regions.Count; i++)
            {
                ElfLoadRegion Region = Regions[i];
                if (ProgramHeaderOffset < Region.FileOffset || ProgramHeaderOffset + ProgramHeaderTableSize > Region.FileOffset + Region.FileSize)
                    continue;

                ProgramHeaderAddress = Region.VirtualAddress + LoadBias + (ProgramHeaderOffset - Region.FileOffset);
                break;
            }

            return true;
        }

        private void LoadElfSections(BinaryEmulator Instance, BinaryFile Binary, ReadOnlySpan<byte> Data, ref ulong HighestAddress, out ulong GuestEntry, out ulong ModuleBase, out ulong ModuleSize)
        {
            GuestEntry = Binary.EntryPoint;
            ModuleBase = 0;
            ModuleSize = 0;

            List<ElfBinarySection> Sections = new List<ElfBinarySection>();
            ulong MinAddress = ulong.MaxValue;
            ulong MaxAddress = 0;

            foreach (ElfBinarySection Section in Binary.ELF.Sections)
            {
                ulong SectionSpan = Math.Max(Section.VirtualSize, Section.RawSize);
                if (SectionSpan == 0)
                    continue;

                Sections.Add(Section);
                ulong SectionBase = AlignDown(Section.VirtualAddress);
                ulong SectionEnd = Instance.AlignToPageSize(Section.VirtualAddress + SectionSpan);
                if (SectionBase < MinAddress)
                    MinAddress = SectionBase;
                if (SectionEnd > MaxAddress)
                    MaxAddress = SectionEnd;
            }

            if (Sections.Count == 0)
                return;

            ulong ImageSize = MaxAddress - MinAddress;
            ulong ReservedBase;
            if (MinAddress != 0 && !Instance.IsRegionMapped(MinAddress, ImageSize))
                ReservedBase = Instance.MapMemoryRegion(MinAddress, ImageSize, MemoryProtection.All);
            else
                ReservedBase = Instance.MapUniqueAddress(ImageSize, MemoryProtection.All);

            if (ReservedBase == 0)
                throw new InvalidOperationException("Failed to map the ELF image.");

            ulong LoadBias = ReservedBase - MinAddress;
            ModuleBase = ReservedBase;
            ModuleSize = ImageSize;
            List<ProtectionRange> ProtectionRanges = new List<ProtectionRange>();

            foreach (ElfBinarySection Section in Sections)
            {
                ulong SectionSpan = Math.Max(Section.VirtualSize, Section.RawSize);
                ulong SectionAddress = Section.VirtualAddress + LoadBias;
                MemoryProtection Protection = Instance.GetMemoryProtection(Section.Characteristics);
                AddProtectionRange(ProtectionRanges, AlignDown(SectionAddress), Instance.AlignToPageSize((SectionAddress - AlignDown(SectionAddress)) + SectionSpan), Protection);

                if (Section.RawSize == 0 || Section.RawOffset >= (uint)Data.Length)
                    continue;

                int BytesToWrite = (int)Math.Min(Section.RawSize, (uint)Data.Length - Section.RawOffset);
                if (BytesToWrite <= 0)
                    continue;

                Instance._emulator.WriteMemory(SectionAddress, Data.Slice((int)Section.RawOffset, BytesToWrite));
            }

            ApplyProtectionRanges(Instance, ProtectionRanges);

            HighestAddress = MaxAddress + LoadBias;
            GuestEntry = Binary.EntryPoint + LoadBias;
        }

        private MemoryProtection TranslateProgramHeaderProtection(uint Flags)
        {
            MemoryProtection Protection = MemoryProtection.None;

            if ((Flags & PF_R) != 0)
                Protection |= MemoryProtection.Read;

            if ((Flags & PF_W) != 0)
                Protection |= MemoryProtection.Write;

            if ((Flags & PF_X) != 0)
                Protection |= MemoryProtection.Execute;

            return Protection != MemoryProtection.None ? Protection : MemoryProtection.All;
        }

        private static ulong AlignDown(ulong Value)
        {
            return Value & PageMask;
        }

        private struct ProtectionRange
        {
            public ulong Start;
            public ulong End;
            public MemoryProtection Protection;
        }

        private void AddProtectionRange(List<ProtectionRange> Protections, ulong BaseAddress, ulong Size, MemoryProtection Protection)
        {
            if (Size == 0)
                return;

            ulong End = BaseAddress + Size;
            if (End <= BaseAddress)
                return;

            Protections.Add(new ProtectionRange()
            {
                Start = BaseAddress,
                End = End,
                Protection = Protection,
            });
        }

        private void ApplyProtectionRanges(BinaryEmulator Instance, List<ProtectionRange> Protections)
        {
            if (Protections.Count == 0)
                return;

            List<ulong> Boundaries = new List<ulong>(Protections.Count * 2);
            for (int i = 0; i < Protections.Count; i++)
            {
                Boundaries.Add(Protections[i].Start);
                Boundaries.Add(Protections[i].End);
            }

            Boundaries.Sort();
            int BoundaryCount = 0;
            for (int i = 0; i < Boundaries.Count; i++)
            {
                if (BoundaryCount == 0 || Boundaries[i] != Boundaries[BoundaryCount - 1])
                    Boundaries[BoundaryCount++] = Boundaries[i];
            }

            ulong PendingStart = 0;
            ulong PendingEnd = 0;
            MemoryProtection PendingProtection = MemoryProtection.None;
            bool HasPendingRange = false;

            for (int i = 0; i + 1 < BoundaryCount; i++)
            {
                ulong Start = Boundaries[i];
                ulong End = Boundaries[i + 1];
                if (End <= Start)
                    continue;

                MemoryProtection Protection = MemoryProtection.None;
                bool IsCovered = false;
                for (int j = 0; j < Protections.Count; j++)
                {
                    ProtectionRange Range = Protections[j];
                    if (Range.Start <= Start && Range.End >= End)
                    {
                        Protection |= Range.Protection;
                        IsCovered = true;
                    }
                }

                if (!IsCovered)
                    continue;

                if (HasPendingRange && PendingEnd == Start && PendingProtection == Protection)
                {
                    PendingEnd = End;
                    continue;
                }

                if (HasPendingRange)
                    Instance._emulator.SetMemoryProtection(PendingStart, PendingEnd - PendingStart, PendingProtection);

                PendingStart = Start;
                PendingEnd = End;
                PendingProtection = Protection;
                HasPendingRange = true;
            }

            if (HasPendingRange)
                Instance._emulator.SetMemoryProtection(PendingStart, PendingEnd - PendingStart, PendingProtection);
        }

        private void BuildInitialStack64(BinaryEmulator Instance, ulong StartupEntry, ulong ProgramEntry, ulong ProgramHeaderAddress, ulong ProgramHeaderEntrySize, ulong ProgramHeaderCount, ulong InterpreterBase)
        {
            ulong StackTop = Instance.ReadRegister(Registers.UC_X86_REG_RSP) & ~0xFUL;

            byte[] RandomBytes = new byte[16];
            Random.Shared.NextBytes(RandomBytes);
            ulong RandomAddress = Instance.MapUniqueAddress(Instance.AlignToPageSize((uint)RandomBytes.Length), MemoryProtection.ReadWrite);
            if (RandomAddress != 0)
                Instance.WriteMemory(RandomAddress, RandomBytes);

            string ExecFn = !string.IsNullOrEmpty(Instance._binary.Location) ? Instance._binary.Location : "program";
            byte[] ExecFnBytes = Encoding.ASCII.GetBytes(ExecFn + "\0");
            ulong ExecFnAddress = Instance.MapUniqueAddress(Instance.AlignToPageSize((uint)ExecFnBytes.Length), MemoryProtection.ReadWrite);
            if (ExecFnAddress != 0)
                Instance.WriteMemory(ExecFnAddress, ExecFnBytes);

            byte[] PlatformBytes = Encoding.ASCII.GetBytes("x86_64\0");
            ulong PlatformAddress = Instance.MapUniqueAddress(Instance.AlignToPageSize((uint)PlatformBytes.Length), MemoryProtection.ReadWrite);
            if (PlatformAddress != 0)
                Instance.WriteMemory(PlatformAddress, PlatformBytes);

            List<string> Arguments = GetInitialProgramArguments(Instance);
            ulong[] ArgumentPointers = new ulong[Arguments.Count];
            for (int i = Arguments.Count - 1; i >= 0; i--)
            {
                byte[] ArgumentBytes = Encoding.ASCII.GetBytes(Arguments[i] + "\0");
                StackTop -= (ulong)ArgumentBytes.Length;
                Instance.WriteMemory(StackTop, ArgumentBytes);
                ArgumentPointers[i] = StackTop;
            }
            StackTop &= ~0xFUL;

            List<ulong> Entries = new List<ulong>
            {
                (ulong)ArgumentPointers.Length,
            };
            Entries.AddRange(ArgumentPointers);
            Entries.Add(0);
            Entries.Add(0);
            Entries.AddRange(new ulong[]
            {
                3, // AT_PHDR
                ProgramHeaderAddress,
                4, // AT_PHENT
                ProgramHeaderEntrySize,
                5, // AT_PHNUM
                ProgramHeaderCount,
                6, // AT_PAGESZ
                0x1000,
                7, // AT_BASE
                InterpreterBase,
                9, // AT_ENTRY
                ProgramEntry,
                11, // AT_UID
                1000,
                12, // AT_EUID
                1000,
                13, // AT_GID
                1000,
                14, // AT_EGID
                1000,
                15, // AT_PLATFORM
                PlatformAddress,
                16, // AT_HWCAP
                2,
                17, // AT_CLKTCK
                100,
                23, // AT_SECURE
                0,
                25, // AT_RANDOM
                RandomAddress,
                26, // AT_HWCAP2
                0,
                27, // AT_RSEQ_FEATURE_SIZE
                RseqMinimumFeatureSize,
                28, // AT_RSEQ_ALIGN
                RseqAlignment,
                31, // AT_EXECFN
                ExecFnAddress,
                0, // AT_NULL
                0
            });

            int AuxvStartIndex = 1 + ArgumentPointers.Length + 2;
            byte[] AuxvBytes = new byte[(Entries.Count - AuxvStartIndex) * sizeof(ulong)];
            for (int i = AuxvStartIndex; i < Entries.Count; i++)
                Buffer.BlockCopy(BitConverter.GetBytes(Entries[i]), 0, AuxvBytes, (i - AuxvStartIndex) * sizeof(ulong), sizeof(ulong));

            Helper.AuxiliaryVector = AuxvBytes;

            ulong EntryBytes = (ulong)(Entries.Count * sizeof(ulong));
            StackTop -= EntryBytes;
            StackTop &= ~0xFUL;

            byte[] StackData = new byte[EntryBytes];
            for (int i = 0; i < Entries.Count; i++)
                Buffer.BlockCopy(BitConverter.GetBytes(Entries[i]), 0, StackData, i * sizeof(ulong), sizeof(ulong));

            Instance.WriteMemory(StackTop, StackData);

            Instance.WriteRegister(Registers.UC_X86_REG_RIP, StartupEntry);
            Instance.WriteRegister(Registers.UC_X86_REG_RSP, StackTop);
            Instance.WriteRegister(Registers.UC_X86_REG_RBP, 0);
            Instance.WriteRegister(Registers.UC_X86_REG_RFLAGS, 0x202);
        }

        private void BuildInitialStack32(BinaryEmulator Instance, uint StartupEntry, uint ProgramEntry, uint ProgramHeaderAddress, uint ProgramHeaderEntrySize, uint ProgramHeaderCount, uint InterpreterBase)
        {
            ulong StackTop = Instance.ReadRegister32(Registers.UC_X86_REG_ESP) & ~0xFUL;

            byte[] RandomBytes = new byte[16];
            Random.Shared.NextBytes(RandomBytes);
            ulong MappedRandomAddress = Instance.MapUniqueAddress(Instance.AlignToPageSize((uint)RandomBytes.Length), MemoryProtection.ReadWrite);
            uint RandomAddress = 0;
            if (MappedRandomAddress != 0)
            {
                Instance.WriteMemory(MappedRandomAddress, RandomBytes);
                RandomAddress = (uint)MappedRandomAddress;
            }

            string ExecFn = !string.IsNullOrEmpty(Instance._binary.Location) ? Instance._binary.Location : "program";
            byte[] ExecFnBytes = Encoding.ASCII.GetBytes(ExecFn + "\0");
            ulong MappedExecFnAddress = Instance.MapUniqueAddress(Instance.AlignToPageSize((uint)ExecFnBytes.Length), MemoryProtection.ReadWrite);
            uint ExecFnAddress = 0;
            if (MappedExecFnAddress != 0)
            {
                Instance.WriteMemory(MappedExecFnAddress, ExecFnBytes);
                ExecFnAddress = (uint)MappedExecFnAddress;
            }

            List<string> Arguments = GetInitialProgramArguments(Instance);
            uint[] ArgumentPointers = new uint[Arguments.Count];
            for (int i = Arguments.Count - 1; i >= 0; i--)
            {
                byte[] ArgumentBytes = Encoding.ASCII.GetBytes(Arguments[i] + "\0");
                StackTop -= (ulong)ArgumentBytes.Length;
                Instance.WriteMemory(StackTop, ArgumentBytes);
                ArgumentPointers[i] = (uint)StackTop;
            }
            StackTop &= ~0xFUL;

            List<uint> Entries = new List<uint>
            {
                (uint)ArgumentPointers.Length,
            };
            Entries.AddRange(ArgumentPointers);
            Entries.Add(0);
            Entries.Add(0);
            Entries.AddRange(new uint[]
            {
                3, // AT_PHDR
                ProgramHeaderAddress,
                4, // AT_PHENT
                ProgramHeaderEntrySize,
                5, // AT_PHNUM
                ProgramHeaderCount,
                6, // AT_PAGESZ
                0x1000,
                7, // AT_BASE
                InterpreterBase,
                9, // AT_ENTRY
                ProgramEntry,
                11, // AT_UID
                1000,
                12, // AT_EUID
                1000,
                13, // AT_GID
                1000,
                14, // AT_EGID
                1000,
                23, // AT_SECURE
                0,
                25, // AT_RANDOM
                RandomAddress,
                31, // AT_EXECFN
                ExecFnAddress,
                0, // AT_NULL
                0
            });

            int AuxvStartIndex = 1 + ArgumentPointers.Length + 2;
            byte[] AuxvBytes = new byte[(Entries.Count - AuxvStartIndex) * sizeof(uint)];
            for (int i = AuxvStartIndex; i < Entries.Count; i++)
                Buffer.BlockCopy(BitConverter.GetBytes(Entries[i]), 0, AuxvBytes, (i - AuxvStartIndex) * sizeof(uint), sizeof(uint));

            Helper.AuxiliaryVector = AuxvBytes;

            ulong EntryBytes = (ulong)(Entries.Count * sizeof(uint));
            StackTop -= EntryBytes;
            StackTop &= ~0xFUL;

            byte[] StackData = new byte[EntryBytes];
            for (int i = 0; i < Entries.Count; i++)
                Buffer.BlockCopy(BitConverter.GetBytes(Entries[i]), 0, StackData, i * sizeof(uint), sizeof(uint));

            Instance.WriteMemory(StackTop, StackData);

            Instance.WriteRegister(Registers.UC_X86_REG_EIP, StartupEntry);
            Instance.WriteRegister(Registers.UC_X86_REG_ESP, (uint)StackTop);
            Instance.WriteRegister(Registers.UC_X86_REG_EBP, 0);
            Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, 0x202);
        }
    }
}