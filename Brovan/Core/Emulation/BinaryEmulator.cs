using System.Runtime.InteropServices;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Net;
using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Helpers;
using Brovan.Core.Emulation.Guests;
using System.Security.Cryptography;
using static Brovan.Core.Emulation.BinaryEmulator;
using System.Buffers.Binary;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Log flags for the emulator.
    /// </summary>
    [Flags]
    public enum LogFlags
    {
        /// <summary>
        /// General logs such as libraries being mapped, etc.
        /// </summary>
        General = 1 << 0,

        /// <summary>
        /// Log emulation issues (invalid read, writes, etc).
        /// </summary>
        Issues = 1 << 1,

        /// <summary>
        /// Syscall log.
        /// </summary>
        Syscall = 1 << 2,

        /// <summary>
        /// CPUID Instruction log.
        /// </summary>
        CPUID = 1 << 3,

        /// <summary>
        /// RDTSC Instruction log.
        /// </summary>
        RDTSC = 1 << 4,

        /// <summary>
        /// RDTSCP Instruction log.
        /// </summary>
        RDTSCP = 1 << 5,

        /// <summary>
        /// Suspicious behavior log.
        /// </summary>
        Suspicious = 1 << 6,

        /// <summary>
        /// Important emulator event log.
        /// </summary>
        Important = 1 << 7,

        /// <summary>
        /// All flags.
        /// </summary>
        All = General | Issues | Syscall | CPUID | RDTSC | RDTSCP | Suspicious | Important,
    }

    /// <summary>
    /// Controls how guest console output is written to the host console.
    /// </summary>
    public enum GuestConsoleOutputMode
    {
        /// <summary>
        /// No console output at all.
        /// </summary>
        Suppressed,

        /// <summary>
        /// Allow some safe virtual terminal styling while escaping dangerous terminal actions.
        /// </summary>
        LightEscaped,

        /// <summary>
        /// Escape characters before printing.
        /// </summary>
        Escaped,

        /// <summary>
        /// Write the raw characters to the console directly.
        /// </summary>
        Raw
    }

    /// <summary>
    /// Network access mode for host-backed guest networking.
    /// </summary>
    public enum NetworkAccessMode
    {
        /// <summary>
        /// Block host-backed guest networking.
        /// </summary>
        None,

        /// <summary>
        /// Only allow loopback endpoints and explicitly allowed addresses.
        /// </summary>
        Loopback,

        /// <summary>
        /// Allow all host-backed network endpoints.
        /// </summary>
        Full
    }

    /// <summary>
    /// Host-backed guest networking policy to enforce security rules on guest socket.
    /// </summary>
    public sealed class NetworkAccessPolicy
    {
        private readonly HashSet<IPAddress> AllowedAddresses = new HashSet<IPAddress>();

        /// <summary>
        /// Base network access mode.
        /// </summary>
        public NetworkAccessMode Mode { get; set; }

        /// <summary>
        /// Addresses allowed in addition to the base mode.
        /// </summary>
        public IReadOnlyCollection<IPAddress> Allowed => AllowedAddresses;

        public NetworkAccessPolicy(NetworkAccessMode Mode = NetworkAccessMode.None)
        {
            this.Mode = Mode;
        }

        /// <summary>
        /// Creates a policy that allows all endpoints.
        /// </summary>
        public static NetworkAccessPolicy Full()
        {
            return new NetworkAccessPolicy(NetworkAccessMode.Full);
        }

        /// <summary>
        /// Creates a policy that blocks all endpoints unless addresses are explicitly added.
        /// </summary>
        public static NetworkAccessPolicy None()
        {
            return new NetworkAccessPolicy(NetworkAccessMode.None);
        }

        /// <summary>
        /// Adds an address to the explicit allow list.
        /// </summary>
        public void AddAllowedAddress(IPAddress Address)
        {
            if (Address == null)
                return;

            AllowedAddresses.Add(NormalizeAddress(Address));
        }

        /// <summary>
        /// Returns true if this policy allows any host-backed network access.
        /// </summary>
        public bool HasAnyAccess()
        {
            return Mode != NetworkAccessMode.None || AllowedAddresses.Count != 0;
        }

        /// <summary>
        /// Returns true if the address is allowed by the current policy.
        /// </summary>
        public bool IsAddressAllowed(IPAddress Address)
        {
            if (Address == null)
                return false;

            if (Mode == NetworkAccessMode.Full)
                return true;

            IPAddress Normalized = NormalizeAddress(Address);

            if (AllowedAddresses.Contains(Normalized))
                return true;

            return Mode == NetworkAccessMode.Loopback && IPAddress.IsLoopback(Normalized);
        }

        /// <summary>
        /// Returns true if the endpoint is allowed by the current policy.
        /// </summary>
        public bool IsEndpointAllowed(EndPoint EndPointValue)
        {
            if (EndPointValue is IPEndPoint IpEndPoint)
                return IsAddressAllowed(IpEndPoint.Address);

            return Mode == NetworkAccessMode.Full;
        }

        public bool IsLocalBindAllowed(EndPoint EndPointValue)
        {
            if (!HasAnyAccess())
                return false;

            if (EndPointValue is IPEndPoint IpEndPoint && (IpEndPoint.Address.Equals(IPAddress.Any) || IpEndPoint.Address.Equals(IPAddress.IPv6Any)))
                return true;

            return IsEndpointAllowed(EndPointValue);
        }

        private static IPAddress NormalizeAddress(IPAddress Address)
        {
            if (Address.IsIPv4MappedToIPv6)
                return Address.MapToIPv4();

            return Address;
        }
    }

    public struct BinaryEmulatorSettings
    {
        /// <summary>
        /// Enables host-backed networking for the emulated program.
        /// </summary>
        public bool EmulateNetworking;

        /// <summary>
        /// Host-backed guest networking policy. When null, <see cref="EmulateNetworking"/> is used for compatibility.
        /// </summary>
        public NetworkAccessPolicy NetworkPolicy;

        /// <summary>
        /// Causes unimplemented syscalls to return STATUS_SUCCESS instead of STATUS_NOT_SUPPORTED.
        /// </summary>
        public bool FakeUnimplementedSyscalls;

        /// <summary>
        /// Log flags (have the <see cref="LogFlags.General"/> by default).
        /// </summary>
        public LogFlags Flags;

        /// <summary>
        /// Holds every guest thread suspended until another session member resumes the process.
        /// </summary>
        public bool StartSuspended;

        /// <summary>
        /// Split the stack to support individual function emulation (on by default).
        /// </summary>
        public bool SplitStack;

        /// <summary>
        /// Handle invalid memory operations by the emulator, if there's no handler the execution will silently fail (on by default).
        /// </summary>
        public bool HandleInvalidOperations;

        /// <summary>
        /// Specifies a callback used to decide whether invalid memory or instruction operations should stop emulation.
        /// </summary>
        public InvalidOperationHandler InvalidOperationsCallback;

        /// <summary>
        /// Specifies a function that can get a notification when a syscall is executed. when this is set, the syscall handler itself won't emit event messages.
        /// </summary>
        public SyscallNotificationDelegate SyscallNotificationCallback;

        /// <summary>
        /// Logs event handler. can be set up after the binary initialization.
        /// </summary>
        public MessageHandler OnMessageHandler;

        /// <summary>
        /// Raw command line passed to the emulated process, excluding argv[0].
        /// </summary>
        public string RawProgramArguments;

        public string WorkingDirectory;

        /// <summary>
        /// Parsed arguments passed to the emulated process, excluding argv[0].
        /// </summary>
        public string[] ProgramArguments;

        /// <summary>
        /// Console output mode used for guest writes to standard output and standard error.
        /// </summary>
        public GuestConsoleOutputMode ConsoleOutputMode;

        /// <summary>
        /// Enables internal emulator debug diagnostics.
        /// </summary>
        public bool Debug;

        /// <summary>
        /// Sets a unicorn flag to tell the binding to not add any hooks (except instructions hooks like syscalls).
        /// </summary>
        public bool NoHooks;

        /// <summary>Backend implementation to use. Defaults to Unicorn.</summary>
        public EmulationBackendKind BackendKind;

#pragma warning disable
        public BinaryEmulatorSettings()
        {
            SplitStack = true;
            Flags = LogFlags.General;
            HandleInvalidOperations = true;
            OnMessageHandler = null;
            InvalidOperationsCallback = null;
            SyscallNotificationCallback = null;
            RawProgramArguments = null;
            ProgramArguments = Array.Empty<string>();
            ConsoleOutputMode = GuestConsoleOutputMode.LightEscaped;
            EmulateNetworking = false;
            NetworkPolicy = null;
            Debug = false;
            BackendKind = EmulationBackendKind.Unicorn;
#pragma warning restore
        }

        /// <summary>
        /// Gets the effective network policy for this settings instance.
        /// </summary>
        public NetworkAccessPolicy GetNetworkPolicy()
        {
            if (NetworkPolicy != null)
                return NetworkPolicy;

            return EmulateNetworking ? NetworkAccessPolicy.Full() : NetworkAccessPolicy.None();
        }
    }

    /// <summary>
    /// Binary emulator class which is a high-level wrapper for the unicorn emulator to emulate binaries.
    /// </summary>
    public partial class BinaryEmulator : IDisposable
    {
        internal BinaryFile _binary;

        internal IEmulationBackend _emulator;

        internal List<MemoryRegion> _memory = new();
        internal List<MemoryRegion> _freedmemory = new();
        private readonly Queue<int>[] MlfqReadyQueues = new Queue<int>[32];
        private readonly HashSet<int> MlfqQueuedThreads = new();
        private readonly uint[] MlfqQuanta = new uint[32];
        private readonly int[] MlfqLevelSkips = new int[32];
        private int MlfqLevels;
        internal readonly WakeSignal WakeSignal = CreateWakeSignal();
        private long LastScannedWakeEpoch = -1;

        // HostEventQueue is process wide already, and it has to reach the signal from the GUI thread.
        private static WakeSignal CreateWakeSignal()
        {
            WakeSignal Signal = new WakeSignal();
            OS.SharedHelpers.HostEventQueue.WakeSignal = Signal;
            return Signal;
        }
        
        private long MlfqSchedulerTick;
        private long EarliestWaitDeadline = long.MaxValue;
        private long LastFullWakeupScanTick;
        private uint SlicesSinceFullWakeupScan;
        private bool _freedMemorySorted = true;

        private static readonly MemoryRegionBaseComparer _memoryRegionBaseComparer = new();

        private sealed class MemoryRegionBaseComparer : IComparer<MemoryRegion>
        {
            public int Compare(MemoryRegion x, MemoryRegion y)
            {
                if (x.BaseAddress < y.BaseAddress) return -1;
                if (x.BaseAddress > y.BaseAddress) return 1;
                return 0;
            }
        }

        private const int GprBatchCount = 18;
        private const int GprBatchCount32 = 10;
        private int[] _gprBatchRegs;
        private ulong[] _gprBatchScratch;
        internal BinaryEmulatorSettings Settings;
        private InstructionHookCallback Syscall;
        private InstructionHookCallback Privileged;
        private InterruptHookCallback Interrupt;
        private InstructionBoolHookCallback CPUID;
        private InstructionBoolHookCallback RDTSC;
        private InstructionBoolHookCallback RDTSCP;
        private MemoryHookCallback InvalidMemory;
        private InstructionHookCallback InvalidInstruction;
        private MemoryHookCallback SnapMonitor;
        public delegate void MessageHandler(string Message, LogFlags Flags);
        public delegate bool InvalidOperationHandler(BackendMemoryAccessType Type, ulong Address, uint Size, ulong value);
        public delegate void SyscallNotificationDelegate(ulong Address, ulong Syscall, string Name, ulong ReturnValue);
        public SyscallManager Syscalls;
        internal IGuestEnvironment Guest { get; }
        private bool Disposed = false;
        public bool IsDisposed { get { return Disposed; } }

        /// <summary>
        /// Enables internal emulator debug diagnostics.
        /// </summary>
        public bool Debug { get; set; }

        public string RawProgramArguments { get; }
        public string WorkingDirectory { get; }
        public string[] ProgramArguments { get; }

        /// <summary>
        /// Path of the emulated image as the guest sees it, which is not the host path when the host is not Windows.
        /// </summary>
        public string GuestImagePath { get; }

        public int IPRegister { get; private set; }
        public Arch BackendArch { get; private set; }
        public Mode BackendMode { get; private set; }
        public bool IsX86Guest => BackendArch == Arch.X86 && BackendMode == Mode.MODE_32;
        public bool IsArmGuest => BackendArch == Arch.ARM;
        public bool IsX64Guest => BackendArch == Arch.X86 && BackendMode == Mode.MODE_64;
        public bool IsArchX86Guest => BackendArch == Arch.X86;
        public readonly ulong BaseAddress = 0x10000000UL; // Base Start

        public ulong MaxAddress
        {
            get
            {
                ulong Limit = IsArchX86Guest && _binary.FileFormat == BinaryFormat.PE
                    ? (IsX86Guest
                        ? (_binary.PE.Characteristics.HasFlag(System.Reflection.PortableExecutable.Characteristics.LargeAddressAware) ? 0xBFFF0000UL : 0x7FFF0000UL)
                        : 0x7FFFFFFEFFFFUL)
                    : 0x7FFFFFFFFUL;

                ulong Mappable = _emulator != null ? _emulator.MaxMappableAddress : ulong.MaxValue;
                return Limit < Mappable ? Limit : Mappable;
            }
        }
        /// <summary>
        /// How long the scheduler blocks in one go when no guest thread can run.
        /// </summary>
        private const int IdleWaitSliceMs = 5;

        private const ulong TscCyclesPerMillisecond = 3_000_000UL;

        internal const ulong TscTicksPerQpcTick =
            TscCyclesPerMillisecond / (ulong)(OS.Windows.KuserSharedDataManager.QpcFrequency / 1000);

        private readonly long EmulatedSystemTimeBaseFileTimeUtc = DateTime.UtcNow.ToFileTimeUtc();

        private readonly System.Diagnostics.Stopwatch _wallClock = System.Diagnostics.Stopwatch.StartNew();
        private long _emulatedTimeSkewMilliseconds;

        /// <summary>
        /// Current guest tick count in milliseconds.
        /// </summary>
        internal long EmulatedTickCount64
        {
            get
            {
                long elapsed = _wallClock.ElapsedMilliseconds;
                long skew = Volatile.Read(ref _emulatedTimeSkewMilliseconds);
                if (elapsed > long.MaxValue - skew)
                    return long.MaxValue;
                return elapsed + skew;
            }
        }

        /// <summary>
        /// Returns the current deterministic guest system time as a Windows file time.
        /// </summary>
        internal long GetEmulatedSystemTimeFileTimeUtc()
        {
            if (EmulatedTickCount64 > (long.MaxValue - EmulatedSystemTimeBaseFileTimeUtc) / 10000)
                return long.MaxValue;

            return EmulatedSystemTimeBaseFileTimeUtc + (EmulatedTickCount64 * 10000);
        }

        /// <summary>
        /// Creates a deadline using the deterministic guest tick count.
        /// </summary>
        internal long CreateEmulatedDeadlineMilliseconds(long Milliseconds)
        {
            if (Milliseconds <= 0)
                return EmulatedTickCount64;

            if (Milliseconds == long.MaxValue || EmulatedTickCount64 > long.MaxValue - Milliseconds)
                return long.MaxValue;

            return EmulatedTickCount64 + Milliseconds;
        }

        /// <summary>
        /// Returns true when a deterministic guest deadline has elapsed.
        /// </summary>
        internal bool IsEmulatedDeadlineExpired(long Deadline)
        {
            return Deadline != -1 && EmulatedTickCount64 >= Deadline;
        }

        /// <summary>
        /// The performance counter, on the same timebase as <see cref="EmulatedTickCount64"/> and at finer
        /// resolution than it.
        /// </summary>
        internal ulong GetEmulatedPerformanceCounter()
        {
            const long QpcFrequency = OS.Windows.KuserSharedDataManager.QpcFrequency;

            long HostTicks = _wallClock.ElapsedTicks;
            long HostFrequency = System.Diagnostics.Stopwatch.Frequency;
            long Elapsed = HostFrequency == QpcFrequency
                ? HostTicks
                : (long)((decimal)HostTicks * QpcFrequency / HostFrequency);

            long Skew = Volatile.Read(ref _emulatedTimeSkewMilliseconds);
            long SkewCounts = Skew > long.MaxValue / (QpcFrequency / 1000) ? long.MaxValue : Skew * (QpcFrequency / 1000);

            return unchecked((ulong)(Elapsed > long.MaxValue - SkewCounts ? long.MaxValue : Elapsed + SkewCounts));
        }

        // Only a hook-free run takes it. With hooks on, the RDTSC handler has to see every execution.
        private void PublishTimestampCounterSource()
        {
            if (!Settings.NoHooks)
                return;

            const long QpcFrequency = OS.Windows.KuserSharedDataManager.QpcFrequency;
            long HostStart = System.Diagnostics.Stopwatch.GetTimestamp() - _wallClock.ElapsedTicks;
            long SkewCounts = Volatile.Read(ref _emulatedTimeSkewMilliseconds) * (QpcFrequency / 1000);
            _emulator.ConfigureEmulatedTimestampCounter(HostStart, System.Diagnostics.Stopwatch.Frequency, QpcFrequency, TscTicksPerQpcTick, SkewCounts);
        }

        /// <summary>
        /// Advances guest time for a wait that was not served in real time.
        /// </summary>
        internal void AdvanceEmulatedTimeMilliseconds(long Milliseconds)
        {
            if (Milliseconds <= 0)
                return;

            long Skew = Volatile.Read(ref _emulatedTimeSkewMilliseconds);
            long AppliedMilliseconds = Skew > long.MaxValue - Milliseconds ? long.MaxValue - Skew : Milliseconds;
            if (AppliedMilliseconds <= 0)
                return;

            Interlocked.Add(ref _emulatedTimeSkewMilliseconds, AppliedMilliseconds);
            PublishTimestampCounterSource();

            // A skew jump has no producer of its own: it can bring every timed wait due at once.
            WakeSignal.Bump();

            // A skew jump is the one moment the page is guaranteed stale, and the guest usually reads it
            // immediately afterwards: the wait it was serving has just come due.
            WinHelper?.KuserSharedData?.RefreshIfUnhooked();
        }

        /// <summary>
        /// <see cref="Delegate"/> Callback for emulation logs.
        /// </summary>
        public event MessageHandler OnMessage;

        internal readonly Dictionary<uint, EmulatedThread> Threads = new();

        private bool StartSuspendedApplied;

        private bool StartSuspendedReleased;
        internal readonly List<int> ThreadOrder = new();
        internal int CurrentThreadId = -1;
        internal int NextThreadId = 1;
        private bool SchedulerRefreshRequested;
        internal bool EscapeScheduler;
        private int TerminationRequested;

        // Threads keeps terminated entries so thread-id lookups stay valid, so it grows with every thread the guest
        // has ever created. ThreadOrder is the live set.
        internal LiveThreadCollection LiveThreads => new LiveThreadCollection(this);

        internal readonly struct LiveThreadCollection
        {
            private readonly BinaryEmulator Owner;

            internal LiveThreadCollection(BinaryEmulator Owner)
            {
                this.Owner = Owner;
            }

            public Enumerator GetEnumerator() => new Enumerator(Owner);

            internal struct Enumerator
            {
                private readonly BinaryEmulator Owner;
                private int Index;

                internal Enumerator(BinaryEmulator Owner)
                {
                    this.Owner = Owner;
                    Index = -1;
                    Current = null;
                }

                public EmulatedThread Current { get; private set; }

                public bool MoveNext()
                {
                    List<int> Order = Owner.ThreadOrder;
                    while (++Index < Order.Count)
                    {
                        if (Owner.Threads.TryGetValue((uint)Order[Index], out EmulatedThread Thread) && Thread != null)
                        {
                            Current = Thread;
                            return true;
                        }
                    }

                    Current = null;
                    return false;
                }
            }
        }

        private EmulatedThread _currentThreadCache;

        internal EmulatedThread CurrentThread
        {
            get
            {
                int tid = CurrentThreadId;
                if (tid == -1) return null;
                if (_currentThreadCache != null && (int)_currentThreadCache.ThreadId == tid)
                    return _currentThreadCache;
                if (Threads.TryGetValue((uint)tid, out EmulatedThread t))
                { _currentThreadCache = t; return t; }
                _currentThreadCache = null;
                return null;
            }
        }

        internal TGuest GetGuest<TGuest>() where TGuest : class, IGuestEnvironment
        {
            return Guest as TGuest;
        }

        /// <summary>
        /// Initialize the binary with the emulator.
        /// </summary>
        /// <param name="Binary">Binary to be emulated.</param>
        /// <param name="Settings">Emulation settings.</param>
        /// <exception cref="NullReferenceException"></exception>
        /// <exception cref="UnicornException"></exception>
        public BinaryEmulator(BinaryFile Binary, BinaryEmulatorSettings Settings)
        {
            if (Binary == null || Binary.Location == null)
                throw new NullReferenceException("The binary cannot be null.");

            if (Binary.FileFormat == BinaryFormat.Unknown)
                throw new BadImageFormatException("Unknown file format used.");

            if (Binary.Architecture == BinaryArchitecture.Unknown)
                throw new BadImageFormatException("Unsupported binary architecture.");

            _binary = Binary;
            BackendArch = Arch.X86;
            BackendMode = Binary.Architecture == BinaryArchitecture.x64 ? Mode.MODE_64 : Mode.MODE_32;
            GeneralHelper.IO.Wow64FileRedirect = Binary.FileFormat == BinaryFormat.PE && Binary.Architecture == BinaryArchitecture.x86;
            GuestImagePath = ResolveGuestImagePath(Binary);
            _emulator = BackendFactory.Create(Settings.BackendKind, BackendArch, BackendMode, Settings.NoHooks, GuestImagePath, Binary.Location);
            _emulator.NoHooks = Settings.NoHooks;
            this.Settings = Settings;
            Debug = Settings.Debug;
            RawProgramArguments = Settings.RawProgramArguments ?? string.Empty;
            WorkingDirectory = Settings.WorkingDirectory;
            ProgramArguments = Settings.ProgramArguments?.ToArray() ?? Array.Empty<string>();

            if (_binary.Architecture == BinaryArchitecture.x64)
                IPRegister = (int)Registers.UC_X86_REG_RIP;
            else if (_binary.Architecture == BinaryArchitecture.x86)
                IPRegister = (int)Registers.UC_X86_REG_EIP;

            this.Syscalls = new SyscallManager(this);
            Guest = GuestFactory.Create(Binary);

            if (Settings.OnMessageHandler != null)
                OnMessage += Settings.OnMessageHandler;

            InitializeEmulationEnvironment(this.Settings);
        }

        /// <summary>
        /// Initializes the emulator with a raw blob and an explicit guest environment.
        /// </summary>
        /// <param name="Guest">Guest to initialize the data with.</param>
        /// <param name="Settings">Emulation settings.</param>
        /// <param name="mode">Emulation mode.</param>
        /// <param name="arch">Architecture to initialize the emulator with.</param>
        /// <param name="Data">Data to be emulated based on the architecture and mode.</param>
        /// <exception cref="NullReferenceException"></exception>
        /// <exception cref="UnicornException"></exception>
        public BinaryEmulator(IGuestEnvironment Guest, BinaryEmulatorSettings Settings, Mode mode, Arch arch, ReadOnlySpan<byte> Data, BinaryFile Binary = null!)
        {
            if (Data == null || Data.Length == 0)
                throw new NullReferenceException(nameof(Data));

            _binary = Binary ?? new BinaryFile(Data, true);
            BackendArch = arch;
            BackendMode = mode;
            GeneralHelper.IO.Wow64FileRedirect = Binary?.FileFormat == BinaryFormat.PE && Binary?.Architecture == BinaryArchitecture.x86;
            GuestImagePath = ResolveGuestImagePath(_binary, Guest);
            _emulator = BackendFactory.Create(Settings.BackendKind, arch, mode, Settings.NoHooks, GuestImagePath, _binary?.Location);
            this.Settings = Settings;
            Debug = Settings.Debug;
            RawProgramArguments = Settings.RawProgramArguments ?? string.Empty;
            WorkingDirectory = Settings.WorkingDirectory;
            ProgramArguments = Settings.ProgramArguments?.ToArray() ?? Array.Empty<string>();

            if (Guest is GenericGuest Generic)
            {
                IPRegister = Generic.ProgramCounterRegister;
            }
            else if (arch == Arch.X86)
            {
                IPRegister = mode == Mode.MODE_64 ? (int)Registers.UC_X86_REG_RIP : (int)Registers.UC_X86_REG_EIP;
            }

            this.Syscalls = new SyscallManager(this);
            this.Guest = Guest;

            if (Settings.OnMessageHandler != null)
                OnMessage += Settings.OnMessageHandler;

            InitializeEmulationEnvironment(this.Settings);
        }

        /// <summary>
        /// Dumps the emulator state.
        /// </summary>
        /// <returns>Returns the full state of the emulator as a string.</returns>
        public string GetDump()
        {
            if (Disposed || _emulator.Disposed)
                return string.Empty;

            if (Guest is GenericGuest Generic && Generic.IsArm)
                return Generic.GetRegisterDump(this);

            StringBuilder Builder = new StringBuilder();

            if (_binary.Architecture == BinaryArchitecture.x64)
            {
                Builder.AppendLine("Registers:");
                Builder.AppendLine($"RAX: 0x{ReadRegister(Registers.UC_X86_REG_RAX):X16}");
                Builder.AppendLine($"RBX: 0x{ReadRegister(Registers.UC_X86_REG_RBX):X16}");
                Builder.AppendLine($"RCX: 0x{ReadRegister(Registers.UC_X86_REG_RCX):X16}");
                Builder.AppendLine($"RDX: 0x{ReadRegister(Registers.UC_X86_REG_RDX):X16}");
                Builder.AppendLine($"RSI: 0x{ReadRegister(Registers.UC_X86_REG_RSI):X16}");
                Builder.AppendLine($"RDI: 0x{ReadRegister(Registers.UC_X86_REG_RDI):X16}");
                Builder.AppendLine($"RBP: 0x{ReadRegister(Registers.UC_X86_REG_RBP):X16}");
                Builder.AppendLine($"RSP: 0x{ReadRegister(Registers.UC_X86_REG_RSP):X16}");
                Builder.AppendLine($"R8:  0x{ReadRegister(Registers.UC_X86_REG_R8):X16}");
                Builder.AppendLine($"R9:  0x{ReadRegister(Registers.UC_X86_REG_R9):X16}");
                Builder.AppendLine($"R10: 0x{ReadRegister(Registers.UC_X86_REG_R10):X16}");
                Builder.AppendLine($"R11: 0x{ReadRegister(Registers.UC_X86_REG_R11):X16}");
                Builder.AppendLine($"R12: 0x{ReadRegister(Registers.UC_X86_REG_R12):X16}");
                Builder.AppendLine($"R13: 0x{ReadRegister(Registers.UC_X86_REG_R13):X16}");
                Builder.AppendLine($"R14: 0x{ReadRegister(Registers.UC_X86_REG_R14):X16}");
                Builder.AppendLine($"R15: 0x{ReadRegister(Registers.UC_X86_REG_R15):X16}");
                Builder.AppendLine($"RIP: 0x{ReadRegister(Registers.UC_X86_REG_RIP):X16}");
                Builder.AppendLine($"EFLAGS: 0x{ReadRegister(Registers.UC_X86_REG_RFLAGS):X8}");
                Builder.AppendLine($"MXCSR: 0x{ReadRegister(Registers.UC_X86_REG_MXCSR):X8}");
                Builder.AppendLine($"FPCW: 0x{ReadRegister(Registers.UC_X86_REG_FPCW):X4}");
                Builder.AppendLine($"FPSW: 0x{ReadRegister(Registers.UC_X86_REG_FPSW):X4}");
            }
            else if (_binary.Architecture == BinaryArchitecture.x86)
            {
                Builder.AppendLine("Registers:");
                Builder.AppendLine($"EAX: 0x{ReadRegister(Registers.UC_X86_REG_EAX):X8}");
                Builder.AppendLine($"EBX: 0x{ReadRegister(Registers.UC_X86_REG_EBX):X8}");
                Builder.AppendLine($"ECX: 0x{ReadRegister(Registers.UC_X86_REG_ECX):X8}");
                Builder.AppendLine($"EDX: 0x{ReadRegister(Registers.UC_X86_REG_EDX):X8}");
                Builder.AppendLine($"ESI: 0x{ReadRegister(Registers.UC_X86_REG_ESI):X8}");
                Builder.AppendLine($"EDI: 0x{ReadRegister(Registers.UC_X86_REG_EDI):X8}");
                Builder.AppendLine($"EBP: 0x{ReadRegister(Registers.UC_X86_REG_EBP):X8}");
                Builder.AppendLine($"ESP: 0x{ReadRegister(Registers.UC_X86_REG_ESP):X8}");
                Builder.AppendLine($"EIP: 0x{ReadRegister(Registers.UC_X86_REG_EIP):X8}");
                Builder.AppendLine($"EFLAGS: 0x{ReadRegister(Registers.UC_X86_REG_EFLAGS):X8}");
            }

            return Builder.ToString();
        }

        /// <summary>
        /// Send a message to the message event handler.
        /// </summary>
        /// <param name="Message">Message to send.</param>
        /// <param name="FlagType">Log flag type.</param>
        public void TriggerEventMessage(string Message, LogFlags FlagType)
        {
            if ((Settings.Flags & FlagType) != 0)
                OnMessage?.Invoke(Message, FlagType);
        }

        public void TriggerEventMessage(Func<string> MessageFactory, LogFlags FlagType)
        {
            if ((Settings.Flags & FlagType) == 0 || MessageFactory == null)
                return;

            try { OnMessage?.Invoke(MessageFactory(), FlagType); }
            catch (Exception ex) { OnMessage?.Invoke($"[event] msg factory failed: {ex.GetType().Name}: {ex.Message}", FlagType); }
        }

        /// <summary>
        /// Emits an internal emulator debug diagnostic when debug mode is enabled.
        /// </summary>
        internal void TriggerDebugMessage(string Message)
        {
            if (Debug && (Settings.Flags & LogFlags.General) != 0)
                TriggerEventMessage($"[DBG] {Message}", LogFlags.General);
        }

        /// <summary>
        /// Emits an internal emulator debug diagnostic when debug mode is enabled and the message is expensive to build.
        /// </summary>
        internal void TriggerDebugMessage(Func<string> MessageFactory)
        {
            if (!Debug || MessageFactory == null)
                return;

            try
            {
                if ((Settings.Flags & LogFlags.General) != 0)
                    TriggerEventMessage($"[DBG] {MessageFactory()}", LogFlags.General);
            }
            catch (Exception ex)
            {
                if ((Settings.Flags & LogFlags.General) != 0)
                    TriggerEventMessage($"[DBG] debug message failed: {ex.GetType().Name}: {ex.Message}", LogFlags.General);
            }
        }

        private const ulong PageSize = 0x1000;

        /// <summary>
        /// Aligns <paramref name="Value"/> up to the next multiple of <paramref name="Align"/>.
        /// </summary>
        public static ulong AlignUp(ulong Value, ulong Align)
        {
            return (Value + Align - 1) & ~(Align - 1);
        }

        /// <summary>
        /// Returns true if the two [Base, Base+Size) ranges overlap.
        /// </summary>
        private static bool RegionsOverlap(ulong ABase, ulong ASize, ulong BBase, ulong BSize)
        {
            ulong AEnd = GetRangeEnd(ABase, ASize);
            ulong BEnd = GetRangeEnd(BBase, BSize);
            return ABase < BEnd && AEnd > BBase;
        }

        /// <summary>
        /// Removes the specified mapped range from the freed-region list.
        /// </summary>
        private void ConsumeFreedMemoryRange(ulong Address, ulong Size)
        {
            if (Size == 0 || _freedmemory.Count == 0)
                return;

            EnsureFreedMemorySorted();

            ulong End = GetRangeEnd(Address, Size);

            int lo = 0, hi = _freedmemory.Count - 1, firstCandidate = -1;
            while (lo <= hi)
            {
                int mid = lo + ((hi - lo) >> 1);
                ulong midEnd = GetRangeEnd(_freedmemory[mid].BaseAddress, _freedmemory[mid].Size);
                if (midEnd > Address)
                {
                    firstCandidate = mid;
                    hi = mid - 1;
                }
                else
                {
                    lo = mid + 1;
                }
            }

            if (firstCandidate < 0)
                return;

            for (int i = firstCandidate; i < _freedmemory.Count; i++)
            {
                MemoryRegion FreedMemory = _freedmemory[i];
                ulong FreedStart = FreedMemory.BaseAddress;
                ulong FreedEnd = GetRangeEnd(FreedMemory.BaseAddress, FreedMemory.Size);

                if (FreedStart >= End)
                    break;

                if (!RegionsOverlap(Address, Size, FreedStart, FreedMemory.Size))
                    continue;

                if (Address <= FreedStart && End >= FreedEnd)
                {
                    _freedmemory.RemoveAt(i);
                    i--;
                    continue;
                }

                if (Address <= FreedStart)
                {
                    FreedMemory.BaseAddress = End;
                    FreedMemory.Size = FreedEnd > End ? FreedEnd - End : 0;
                    FreedMemory.RequestedSize = FreedMemory.Size;

                    if (FreedMemory.Size == 0)
                    {
                        _freedmemory.RemoveAt(i);
                        i--;
                    }
                    else
                    {
                        _freedmemory[i] = FreedMemory;
                    }

                    continue;
                }

                if (End >= FreedEnd)
                {
                    FreedMemory.Size = Address - FreedStart;
                    FreedMemory.RequestedSize = FreedMemory.Size;

                    if (FreedMemory.Size == 0)
                    {
                        _freedmemory.RemoveAt(i);
                        i--;
                    }
                    else
                    {
                        _freedmemory[i] = FreedMemory;
                    }

                    continue;
                }

                MemoryRegion Right = FreedMemory;
                Right.BaseAddress = End;
                Right.Size = FreedEnd - End;
                Right.RequestedSize = Right.Size;

                FreedMemory.Size = Address - FreedStart;
                FreedMemory.RequestedSize = FreedMemory.Size;

                _freedmemory[i] = FreedMemory;
                _freedmemory.Insert(i + 1, Right);
                i++;
            }
        }

        /// <summary>
        /// Adds a mapped memory region, keeping the list ordered by base address.
        /// </summary>
        internal void AddMemoryRegion(MemoryRegion Region)
        {
            int idx = _memory.BinarySearch(Region, _memoryRegionBaseComparer);
            if (idx < 0) idx = ~idx;
            _memory.Insert(idx, Region);
        }

        /// <summary>
        /// Removes a mapped memory region.
        /// </summary>
        internal bool RemoveMemoryRegion(MemoryRegion Region)
        {
            int Index = _memory.BinarySearch(Region, _memoryRegionBaseComparer);
            if (Index < 0)
                return false;

            int First = Index;
            while (First > 0 && _memory[First - 1].BaseAddress == Region.BaseAddress)
                First--;

            for (int i = First; i < _memory.Count && _memory[i].BaseAddress == Region.BaseAddress; i++)
            {
                if (!_memory[i].Equals(Region))
                    continue;

                _memory.RemoveAt(i);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Removes a mapped memory region by index.
        /// </summary>
        internal void RemoveMemoryRegionAt(int Index)
        {
            _memory.RemoveAt(Index);
        }

        /// <summary>
        /// Removes all mapped memory regions matching a predicate.
        /// </summary>
        internal int RemoveMemoryRegions(Predicate<MemoryRegion> Match)
        {
            return _memory.RemoveAll(Match);
        }

        /// <summary>
        /// Replaces a mapped memory region by index, restoring base-address order when it moved.
        /// </summary>
        internal void SetMemoryRegion(int Index, MemoryRegion Region)
        {
            if (Index < 0 || Index >= _memory.Count)
                return;

            ulong OldBase = _memory[Index].BaseAddress;
            _memory[Index] = Region;

            if (Region.BaseAddress != OldBase)
                _memory.Sort(_memoryRegionBaseComparer);
        }

        /// <summary>
        /// Replaces the mapped memory region list and restores base-address order.
        /// </summary>
        internal void ReplaceMemoryRegions(List<MemoryRegion> Regions)
        {
            _memory = Regions ?? new List<MemoryRegion>();
            _memory.Sort(_memoryRegionBaseComparer);
        }

        /// <summary>
        /// Returns true if an address belongs to a mapped memory region.
        /// </summary>
        internal bool TryFindMemoryRegion(ulong Address, out MemoryRegion Region)
        {
            if (TryFindMemoryRegionIndex(Address, out int Index))
            {
                Region = _memory[Index];
                return true;
            }

            Region = default;
            return false;
        }

        /// <summary>
        /// Returns true if an address belongs to a mapped memory region and returns its main memory-list index.
        /// </summary>
        internal bool TryFindMemoryRegionIndex(ulong Address, out int Index)
        {
            Index = -1;

            int Left = 0;
            int Right = _memory.Count - 1;
            int Candidate = -1;

            while (Left <= Right)
            {
                int Middle = Left + ((Right - Left) >> 1);
                MemoryRegion Region = _memory[Middle];

                if (Region.BaseAddress <= Address)
                {
                    Candidate = Middle;
                    Left = Middle + 1;
                }
                else
                {
                    Right = Middle - 1;
                }
            }

            if (Candidate < 0)
                return false;

            Index = Candidate;
            MemoryRegion Found = _memory[Index];
            ulong End = GetRangeEnd(Found.BaseAddress, Found.Size);
            if (Address >= Found.BaseAddress && Address < End)
                return true;

            Index = -1;
            return false;
        }

        /// <summary>
        /// Returns true if a mapped memory region starts at the specified base address.
        /// </summary>
        internal bool TryFindMemoryRegionByBase(ulong BaseAddress, out int Index, out MemoryRegion Region)
        {
            int Left = 0;
            int Right = _memory.Count - 1;

            while (Left <= Right)
            {
                int Middle = Left + ((Right - Left) >> 1);
                MemoryRegion Candidate = _memory[Middle];

                if (Candidate.BaseAddress == BaseAddress)
                {
                    Index = Middle;
                    Region = Candidate;
                    return true;
                }

                if (Candidate.BaseAddress < BaseAddress)
                    Left = Middle + 1;
                else
                    Right = Middle - 1;
            }

            Index = -1;
            Region = default;
            return false;
        }

        /// <summary>
        /// Returns true if any mapped memory region overlaps the specified range.
        /// </summary>
        internal bool TryFindOverlappingMemoryRegion(ulong Address, ulong Size, out MemoryRegion Region)
        {
            Region = default;

            if (Size == 0 || _memory.Count == 0)
                return false;

            ulong End = GetRangeEnd(Address, Size);
            int Start = FindFirstRegionStartingBefore(End);
            if (Start < 0)
                return false;

            for (int i = Start; i >= 0; i--)
            {
                MemoryRegion Candidate = _memory[i];
                ulong CandidateEnd = GetRangeEnd(Candidate.BaseAddress, Candidate.Size);

                if (CandidateEnd <= Address)
                    break;

                if (Address < CandidateEnd && End > Candidate.BaseAddress)
                {
                    Region = Candidate;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Adds mapped memory regions overlapping the specified range to the destination list.
        /// </summary>
        internal void AddOverlappingMemoryRegions(ulong Address, ulong Size, List<MemoryRegion> Destination)
        {
            if (Destination == null || Size == 0)
                return;

            if (_memory.Count == 0)
                return;

            ulong End = GetRangeEnd(Address, Size);
            int Start = FindFirstRegionStartingBefore(End);
            if (Start < 0)
                return;

            for (int i = Start; i >= 0; i--)
            {
                MemoryRegion Region = _memory[i];
                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);

                if (RegionEnd <= Address)
                    break;

                if (Address < RegionEnd && End > Region.BaseAddress)
                    Destination.Add(Region);
            }
        }

        /// <summary>
        /// Returns true if the whole address range is covered by mapped memory regions.
        /// </summary>
        internal bool IsMemoryRangeMapped(ulong Address, ulong Size)
        {
            if (Size == 0)
                return true;

            ulong End = GetRangeEnd(Address, Size);
            ulong Current = Address;

            while (Current < End)
            {
                if (!TryFindMemoryRegion(Current, out MemoryRegion Region))
                    return false;

                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);
                if (RegionEnd <= Current)
                    return false;

                Current = RegionEnd;
            }

            return true;
        }

        /// <summary>
        /// Returns true if there is a mapped memory region after the specified address.
        /// </summary>
        internal bool TryFindNextMemoryRegionBase(ulong Address, out ulong BaseAddress)
        {
            int Left = 0;
            int Right = _memory.Count - 1;
            int Candidate = -1;

            while (Left <= Right)
            {
                int Middle = Left + ((Right - Left) >> 1);
                MemoryRegion Region = _memory[Middle];

                if (Region.BaseAddress > Address)
                {
                    Candidate = Middle;
                    Right = Middle - 1;
                }
                else
                {
                    Left = Middle + 1;
                }
            }

            if (Candidate >= 0)
            {
                BaseAddress = _memory[Candidate].BaseAddress;
                return true;
            }

            BaseAddress = 0;
            return false;
        }

        /// <summary>
        /// Enumerates mapped memory regions in base-address order. <see cref="_memory"/> is kept sorted
        /// by every mutator, so this is a plain walk.
        /// </summary>
        internal IEnumerable<MemoryRegion> EnumerateMemoryRegionsByBase()
        {
            for (int i = 0; i < _memory.Count; i++)
                yield return _memory[i];
        }

        private int FindFirstRegionStartingBefore(ulong Address)
        {
            int Left = 0;
            int Right = _memory.Count - 1;
            int Candidate = -1;

            while (Left <= Right)
            {
                int Middle = Left + ((Right - Left) >> 1);
                MemoryRegion Region = _memory[Middle];

                if (Region.BaseAddress < Address)
                {
                    Candidate = Middle;
                    Left = Middle + 1;
                }
                else
                {
                    Right = Middle - 1;
                }
            }

            return Candidate;
        }

        private static ulong GetRangeEnd(ulong Address, ulong Size)
        {
            return Address > ulong.MaxValue - Size ? ulong.MaxValue : Address + Size;
        }

        /// <summary>
        /// Returns true if any existing region overlaps the requested address range.
        /// This is an "address space in use" check (reserve collision semantics), not a commit check.
        /// </summary>
        public bool IsRegionInUse(ulong Address, ulong Size)
        {
            return TryFindOverlappingMemoryRegion(Address, Size, out _);
        }

        /// <summary>
        /// Walks the sorted memory-region index and returns the first
        /// <paramref name="Alignment"/>-aligned gap of at least <paramref name="Size"/>
        /// bytes between <paramref name="MinAddress"/> and <paramref name="MaxAddress"/>.
        /// </summary>
        internal bool TryFindFreeBaseAddress(ulong Size, ulong Alignment, ulong MinAddress, ulong MaxAddress, out ulong Result)
        {
            Result = 0;
            if (Size == 0 || Alignment == 0)
                return false;

            ulong Candidate = AlignUp(MinAddress, Alignment);
            if (Candidate < MinAddress || Candidate >= MaxAddress)
                return false;

            int Count = _memory.Count;
            for (int i = 0; i < Count; i++)
            {
                MemoryRegion Region = _memory[i];

                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);
                if (RegionEnd <= Candidate)
                    continue;

                if (Region.BaseAddress <= Candidate)
                {
                    ulong Next = AlignUp(RegionEnd, Alignment);
                    if (Next < RegionEnd || Next >= MaxAddress)
                        return false;

                    Candidate = Next;
                    continue;
                }

                ulong Available = Region.BaseAddress - Candidate;
                if (Available >= Size)
                {
                    Result = Candidate;
                    return true;
                }

                ulong After = AlignUp(RegionEnd, Alignment);
                if (After < RegionEnd || After >= MaxAddress)
                    return false;

                Candidate = After;
            }

            if (MaxAddress - Candidate >= Size)
            {
                Result = Candidate;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Returns true if the entire [Address, Address+Size) range is covered by committed regions.
        /// This is used for validating reads/writes (commit semantics).
        /// </summary>
        public bool IsRegionCommitted(ulong Address, ulong Size)
        {
            if (Size == 0)
                return true;

            ulong End = Address + Size;
            ulong Current = Address;

            while (Current < End)
            {
                if (!TryFindMemoryRegion(Current, out MemoryRegion Region) || !Region.IsCommitted)
                    return false;

                Current = Region.BaseAddress + Region.Size;
            }

            return true;
        }

        /// <summary>
        /// Map a memory region for emulation.
        /// if Address is 0, automatically finds a free memory region.
        /// </summary>
        /// <param name="Address">Address to map memory at, or 0 for auto-allocation.</param>
        /// <param name="Size">Size of memory region.</param>
        /// <param name="Protection">Memory protection flags.</param>
        /// <returns>Returns the mapped address if succeeded, otherwise 0.</returns>
        public ulong MapMemoryRegion(ulong Address, ulong Size, MemoryProtection Protection)
        {
            ulong AlignedSize = AlignToPageSize(Size);
            if (Address != 0)
            {
                ulong AlignedAddress = Address & ~0xFFFUL;
                if (_emulator.MapMemory(AlignedAddress, AlignedSize, Protection))
                {
                    ConsumeFreedMemoryRange(AlignedAddress, AlignedSize);

                    MemoryRegion Region = new MemoryRegion()
                    {
                        BaseAddress = AlignedAddress,
                        Size = Size,
                        InitialProtections = Protection,
                        Protections = Protection,
                    };

                    if (Size < AlignedSize)
                    {
                        Region.PoisonedMemory = (AlignedAddress + Size, AlignedAddress + AlignedSize);
                    }

                    AddMemoryRegion(Region);
                    TriggerDebugMessage(() => $"memory: mapped base=0x{AlignedAddress:X} size=0x{Size:X} aligned=0x{AlignedSize:X} prot={Protection}");
                    return AlignedAddress;
                }

                TriggerDebugMessage(() => $"memory: map failed base=0x{AlignedAddress:X} size=0x{AlignedSize:X} prot={Protection} error={GetLastError()}");
                return 0;
            }
            else
            {
                return MapUniqueAddress(Size, Protection);
            }
        }

        /// <summary>
        /// Map a unique memory address.
        /// </summary>
        /// <param name="Size">Size of the memory.</param>
        /// <param name="Protection">Protection of the memory.</param>
        /// <returns>The base address of the emulated memory.</returns>
        public ulong MapUniqueAddress(ulong Size, MemoryProtection Protection)
        {
            ulong CurrentAddress = BaseAddress;
            ulong AlignedSize = AlignToPageSize(Size);
            while (CurrentAddress + AlignedSize < MaxAddress)
            {
                if (TryFindOverlappingMemoryRegion(CurrentAddress, AlignedSize, out MemoryRegion Occupied))
                {
                    ulong NextAddress = AlignToPageSize(GetRangeEnd(Occupied.BaseAddress, Occupied.Size));
                    CurrentAddress = NextAddress > CurrentAddress ? NextAddress : CurrentAddress + 0x1000;
                    continue;
                }

                if (_emulator.MapMemory(CurrentAddress, AlignedSize, Protection))
                {
                    ConsumeFreedMemoryRange(CurrentAddress, AlignedSize);

                    MemoryRegion Region = new MemoryRegion()
                    {
                        BaseAddress = CurrentAddress,
                        Size = Size,
                        AllocationBase = CurrentAddress,
                        InitialProtections = Protection,
                        Protections = Protection,
                    };

                    if (Size < AlignedSize)
                    {
                        Region.PoisonedMemory = (CurrentAddress + Size, CurrentAddress + AlignedSize);
                    }

                    AddMemoryRegion(Region);
                    TriggerDebugMessage(() => $"memory: mapped unique base=0x{CurrentAddress:X} size=0x{Size:X} aligned=0x{AlignedSize:X} prot={Protection}");
                    return CurrentAddress;
                }

                CurrentAddress += AlignedSize;
            }

            TriggerDebugMessage(() => $"memory: unique map failed size=0x{AlignedSize:X} prot={Protection}");
            return 0;
        }

        /// <summary>
        /// Checks if the specified memory region overlaps any mapped regions.
        /// </summary>
        /// <param name="Address">Start address of the region.</param>
        /// <param name="Size">Size of the region.</param>
        /// <returns>returns true if overlapping, otherwise false.</returns>
        public bool IsRegionMapped(ulong Address, ulong Size)
        {
            return TryFindOverlappingMemoryRegion(Address, Size, out _);
        }

        public IntPtr GetHostPointer(ulong Address, ulong Size)
        {
            return _emulator.GetHostPointer(Address, Size);
        }

        /// <summary>
        /// Checks if the specified memory region is freed.
        /// </summary>
        /// <param name="BaseAddress">Base address of the region.</param>
        /// <param name="WholeMemory">Indicates that the whole region of that base address should be scanned.</param>
        /// <returns>returns true if freed, otherwise false.</returns>
        public bool IsRegionFreed(ulong BaseAddress, bool WholeMemory)
        {
            if (_freedmemory.Count == 0)
                return false;

            EnsureFreedMemorySorted();

            if (WholeMemory)
            {
                int lo = 0, hi = _freedmemory.Count - 1, cand = -1;
                while (lo <= hi)
                {
                    int mid = lo + ((hi - lo) >> 1);
                    if (_freedmemory[mid].BaseAddress <= BaseAddress) { cand = mid; lo = mid + 1; }
                    else hi = mid - 1;
                }
                if (cand < 0) return false;
                MemoryRegion r = _freedmemory[cand];
                return BaseAddress >= r.BaseAddress && BaseAddress < r.BaseAddress + r.Size;
            }
            else
            {
                int lo = 0, hi = _freedmemory.Count - 1;
                while (lo <= hi)
                {
                    int mid = lo + ((hi - lo) >> 1);
                    ulong mb = _freedmemory[mid].BaseAddress;
                    if (mb == BaseAddress) return true;
                    if (mb < BaseAddress) lo = mid + 1;
                    else hi = mid - 1;
                }
                return false;
            }
        }

        private void EnsureFreedMemorySorted()
        {
            if (_freedMemorySorted)
                return;
            _freedmemory.Sort(_memoryRegionBaseComparer);
            _freedMemorySorted = true;
        }

        /// <summary>
        /// Unmaps a memory region.
        /// </summary>
        /// <param name="Address">Base Address to unmap.</param>
        /// <param name="UnmapImage">Unmap the region even if it belongs to an Image.</param>
        /// <returns>returns true if successfully unmapped, otherwise false.</returns>
        public bool UnmapMemoryRegion(ulong Address, bool UnmapImage = false)
        {
            if (Address == 0)
                return false;

            if (!TryFindMemoryRegion(Address, out MemoryRegion Region) || Region.BaseAddress != Address)
            {
                TriggerDebugMessage(() => $"memory: unmap failed, base not found 0x{Address:X}");
                return false;
            }

            if (!UnmapImage && Region.Flags.HasFlag(AllocationType.Image))
            {
                TriggerDebugMessage(() => $"memory: unmap denied image base=0x{Address:X} size=0x{Region.Size:X}");
                return false;
            }

            if (_emulator.UnmapMemory(Address, Region.Size))
            {
                RemoveMemoryRegion(Region);
                _freedmemory.Add(Region);
                _freedMemorySorted = false;
                TriggerDebugMessage(() => $"memory: unmapped base=0x{Address:X} size=0x{Region.Size:X}");
                return true;
            }

            TriggerDebugMessage(() => $"memory: unmap failed base=0x{Address:X} size=0x{Region.Size:X} error={GetLastError()}");
            return false;
        }

        public void AddFreedRegion(ulong BaseAddress, ulong Size)
        {
            if (BaseAddress == 0 || Size == 0)
                return;

            EnsureFreedMemorySorted();

            ulong Start = BaseAddress;
            ulong End = BaseAddress + Size;

            int lo = 0, hi = _freedmemory.Count - 1, firstOverlap = -1;
            while (lo <= hi)
            {
                int mid = lo + ((hi - lo) >> 1);
                ulong midEnd = _freedmemory[mid].BaseAddress + _freedmemory[mid].Size;
                if (midEnd >= Start)
                {
                    firstOverlap = mid;
                    hi = mid - 1;
                }
                else
                {
                    lo = mid + 1;
                }
            }

            int insertIdx = firstOverlap < 0 ? _freedmemory.Count : firstOverlap;

            if (firstOverlap >= 0)
            {
                for (int i = firstOverlap; i < _freedmemory.Count; i++)
                {
                    MemoryRegion Region = _freedmemory[i];
                    ulong RegionStart = Region.BaseAddress;
                    ulong RegionEnd = Region.BaseAddress + Region.Size;

                    if (End < RegionStart)
                        break;

                    Start = Math.Min(Start, RegionStart);
                    End = Math.Max(End, RegionEnd);
                    _freedmemory.RemoveAt(i);
                    i--;
                    insertIdx = i + 1;
                }
            }

            _freedmemory.Insert(insertIdx < 0 ? 0 : insertIdx, new MemoryRegion
            {
                BaseAddress = Start,
                Size = End - Start,
                RequestedSize = End - Start
            });
        }

        /// <summary>
        /// Get a suitable base address with a specific size. (won't map)
        /// </summary>
        /// <param name="Size">Size of the address to get.</param>
        /// <returns>Returns the suitable base address to be used.</returns>
        public ulong GetSuitableBaseAddress(ulong Size)
        {
            ulong AlignedSize = AlignToPageSize(Size);
            ulong CurrentAddress = BaseAddress;

            while (CurrentAddress + AlignedSize < MaxAddress)
            {
                if (TryFindOverlappingMemoryRegion(CurrentAddress, AlignedSize, out MemoryRegion Region))
                {
                    ulong NextAddress = AlignToPageSize(GetRangeEnd(Region.BaseAddress, Region.Size));
                    CurrentAddress = NextAddress > CurrentAddress ? NextAddress : CurrentAddress + 0x1000;
                    continue;
                }

                if (IsRegionFreed(CurrentAddress, WholeMemory: false))
                {
                    CurrentAddress += 0x1000;
                    continue;
                }

                return CurrentAddress;
            }

            return 0;
        }


        /// <summary>
        /// Privileged instruction handler.
        /// </summary>
        private void PrivilegedInstructionHandler()
        {
            SchedulerRefreshRequested = true;
            TriggerDebugMessage(() => $"cpu: privileged instruction at 0x{ReadRegister(IPRegister):X}");
            Guest.HandlePrivilegedInstruction(this);
        }


        /// <summary>
        /// Invalid instruction handler.
        /// </summary>
        private void InvalidInstructionHandler()
        {
            SchedulerRefreshRequested = true;
            TriggerDebugMessage(() => $"cpu: invalid instruction at 0x{ReadRegister(IPRegister):X}");
            Guest.HandleInvalidInstruction(this);
        }


        /// <summary>
        /// Windows interrupt handling method.
        /// </summary>
        private void InterruptHandler(uint interrupt_number)
        {
            SchedulerRefreshRequested = true;
            TriggerDebugMessage(() => $"cpu: interrupt 0x{interrupt_number:X} at 0x{ReadRegister(IPRegister):X}");
            try
            {
                // An unhandled vector leaves IP on the faulting instruction, which re-faults forever.
                if (!Guest.TryHandleInterrupt(this, interrupt_number) && (Settings.Flags & LogFlags.Issues) != 0)
                    TriggerEventMessage($"[-] Unhandled CPU interrupt 0x{interrupt_number:X} at 0x{ReadRegister(IPRegister):X}.", LogFlags.Issues);
            }
            catch (Exception ex)
            {
                Utils.LogError($"[GuestInterrupt] Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Makes the thread the running thread just woke runnable. A wake only unblocks the target, and real
        /// hardware runs it on another core at once. A waker whose slice can be capped keeps running, since it
        /// usually wakes several threads or blocks within microseconds; otherwise its slice ends here rather
        /// than holding the target for the rest of the quantum.
        /// </summary>
        internal void YieldSliceAfterWake(EmulatedThread WokenThread)
        {
            if (WokenThread != null && MlfqLevels > 0)
                EnqueueMlfqThread(WokenThread, MlfqReadyQueues, MlfqQueuedThreads, MlfqLevels, MlfqSchedulerTick);
            else
                SchedulerRefreshRequested = true;

            if (_emulator.TryLimitSlice(WakeSliceLimitMicroseconds))
                return;

            if (CurrentThread != null && CurrentThread.State == EmulatedThreadState.Running)
                CurrentThread.State = EmulatedThreadState.Ready;

            _emulator.StopEmulation();
        }

        private const int WakeSliceLimitMicroseconds = 500;

        private void StopAfterSyntheticInstruction(ulong NextIp)
        {
            SchedulerRefreshRequested = true;
            TriggerDebugMessage(() => $"cpu: synthetic instruction stop nextIp=0x{NextIp:X}");
            WriteRegister(IPRegister, NextIp);
            _emulator.StopEmulation();
        }

        private const string ProcessorBrandString = "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz";

        private static void ReadProcessorBrandLeaf(uint Leaf, out uint Eax, out uint Ebx, out uint Ecx, out uint Edx)
        {
            Span<byte> Chunk = stackalloc byte[16];
            int BaseOffset = (int)(Leaf - 0x80000002u) * 16;
            for (int Index = 0; Index < Chunk.Length; Index++)
            {
                int StringIndex = BaseOffset + Index;
                Chunk[Index] = StringIndex < ProcessorBrandString.Length ? (byte)ProcessorBrandString[StringIndex] : (byte)0;
            }

            Eax = BinaryPrimitives.ReadUInt32LittleEndian(Chunk);
            Ebx = BinaryPrimitives.ReadUInt32LittleEndian(Chunk.Slice(4));
            Ecx = BinaryPrimitives.ReadUInt32LittleEndian(Chunk.Slice(8));
            Edx = BinaryPrimitives.ReadUInt32LittleEndian(Chunk.Slice(12));
        }

        /// <summary>
        /// CPUID Handler.
        /// </summary>
        private bool CPUID_Handler()
        {
            bool Is64BitGuest = _binary.Architecture == BinaryArchitecture.x64;
            uint Leaf = Is64BitGuest ? (uint)ReadRegister(Registers.UC_X86_REG_RAX) : ReadRegister32(Registers.UC_X86_REG_EAX);
            uint SubLeaf = Is64BitGuest ? (uint)ReadRegister(Registers.UC_X86_REG_RCX) : ReadRegister32(Registers.UC_X86_REG_ECX);
            ulong IP = ReadRegister(IPRegister);
            LinuxGuest Linux = GetGuest<LinuxGuest>();
            if (Linux != null && !Linux.Helper.CpuidEnabled)
            {
                if ((Settings.Flags & (LogFlags.CPUID | LogFlags.Issues)) != 0)
                    TriggerEventMessage($"[!] CPUID instruction was blocked by arch_prctl at 0x{IP:X}.", LogFlags.CPUID | LogFlags.Issues);
                return true;
            }

            void WriteCpuidOutputs(uint Eax, uint Ebx, uint Ecx, uint Edx)
            {
                if (Is64BitGuest)
                {
                    WriteRegister(Registers.UC_X86_REG_RAX, Eax);
                    WriteRegister(Registers.UC_X86_REG_RBX, Ebx);
                    WriteRegister(Registers.UC_X86_REG_RCX, Ecx);
                    WriteRegister(Registers.UC_X86_REG_RDX, Edx);
                    return;
                }

                WriteRegister32(Registers.UC_X86_REG_EAX, Eax);
                WriteRegister32(Registers.UC_X86_REG_EBX, Ebx);
                WriteRegister32(Registers.UC_X86_REG_ECX, Ecx);
                WriteRegister32(Registers.UC_X86_REG_EDX, Edx);
            }

            uint ReadVisibleEax()
            {
                return Is64BitGuest ? (uint)ReadRegister(Registers.UC_X86_REG_RAX) : ReadRegister32(Registers.UC_X86_REG_EAX);
            }

            uint ReadVisibleEbx()
            {
                return Is64BitGuest ? (uint)ReadRegister(Registers.UC_X86_REG_RBX) : ReadRegister32(Registers.UC_X86_REG_EBX);
            }

            uint ReadVisibleEcx()
            {
                return Is64BitGuest ? (uint)ReadRegister(Registers.UC_X86_REG_RCX) : ReadRegister32(Registers.UC_X86_REG_ECX);
            }

            uint ReadVisibleEdx()
            {
                return Is64BitGuest ? (uint)ReadRegister(Registers.UC_X86_REG_RDX) : ReadRegister32(Registers.UC_X86_REG_EDX);
            }

            try
            {
                uint out_eax = 0;
                uint out_ebx = 0;
                uint out_ecx = 0;
                uint out_edx = 0;
                switch (Leaf)
                {
                    case 0:
                        out_eax = 0x00000019;
                        out_ebx = 0x756E6547;
                        out_edx = 0x49656E69;
                        out_ecx = 0x6C65746E;
                        break;

                    case 1:
                        out_eax = 0x000106A5;
                        out_ebx = (8u << 8) | (1u << 16);
                        out_ecx =
                            (1u << 0) |
                            (1u << 9) |
                            (1u << 13) |
                            (1u << 19) |
                            (1u << 20) |
                            (1u << 23);
                        out_edx =
                            (1u << 0) |
                            (1u << 4) |
                            (1u << 5) |
                            (1u << 8) |
                            (1u << 15) |
                            (1u << 19) |
                            (1u << 23) |
                            (1u << 24) |
                            (1u << 25) |
                            (1u << 26);
                        break;

                    case 7:
                        if (SubLeaf == 0)
                            out_eax = 0;
                        break;

                    case 0xD:
                        break;

                    case 0x14:
                        break;

                    case 0x19:
                        break;

                    case 0x80000000:
                        out_eax = 0x80000008;
                        break;

                    case 0x80000001:
                        out_ecx = 1u << 0;
                        out_edx = (1u << 11) | (1u << 20) | (1u << 27);
                        if (Is64BitGuest)
                            out_edx |= 1u << 29;
                        break;

                    case 0x80000002:
                    case 0x80000003:
                    case 0x80000004:
                        ReadProcessorBrandLeaf(Leaf, out out_eax, out out_ebx, out out_ecx, out out_edx);
                        break;

                    case 0x80000007:
                        out_edx = 1u << 8;
                        break;

                    case 0x80000008:
                        out_eax = 0x00003030;
                        break;
                }

                WriteCpuidOutputs(out_eax, out_ebx, out_ecx, out_edx);
                uint visibleEax = ReadVisibleEax();
                uint visibleEbx = ReadVisibleEbx();
                uint visibleEcx = ReadVisibleEcx();
                uint visibleEdx = ReadVisibleEdx();
                if ((Settings.Flags & LogFlags.CPUID) != 0)
                    TriggerEventMessage($"[+] CPUID instruction was executed with the leaf 0x{Leaf:X}, subleaf 0x{SubLeaf:X} at 0x{IP:X}. => EAX=0x{visibleEax:X} EBX=0x{visibleEbx:X} ECX=0x{visibleEcx:X} EDX=0x{visibleEdx:X}", LogFlags.CPUID);
                return true;
            }
            catch
            {
                WriteCpuidOutputs(0, 0, 0, 0);
                uint visibleEax = ReadVisibleEax();
                uint visibleEbx = ReadVisibleEbx();
                uint visibleEcx = ReadVisibleEcx();
                uint visibleEdx = ReadVisibleEdx();
                return true;
            }
        }

        internal ulong GetEmulatedTimestampCounter()
        {
            ulong Counter = GetEmulatedPerformanceCounter();
            return Counter > ulong.MaxValue / TscTicksPerQpcTick ? ulong.MaxValue : Counter * TscTicksPerQpcTick;
        }

        private bool RDTSC_Handler()
        {
            ulong IP = ReadRegister(IPRegister);
            ulong ticks = GetEmulatedTimestampCounter();

            if (_binary.Architecture == BinaryArchitecture.x64)
            {
                WriteRegister(Registers.UC_X86_REG_RAX, (uint)ticks);
                WriteRegister(Registers.UC_X86_REG_RDX, (uint)(ticks >> 32));
            }
            else
            {
                WriteRegister32(Registers.UC_X86_REG_EAX, (uint)ticks);
                WriteRegister32(Registers.UC_X86_REG_EDX, (uint)(ticks >> 32));
            }

            if ((Settings.Flags & LogFlags.RDTSC) != 0)
                TriggerEventMessage($"[+] RDTSC Instruction Executed at 0x{IP:X}.", LogFlags.RDTSC);

            return true;
        }

        private bool RDTSCP_Handler()
        {
            ulong IP = ReadRegister(IPRegister);
            ulong ticks = GetEmulatedTimestampCounter();

            if (_binary.Architecture == BinaryArchitecture.x64)
            {
                WriteRegister(Registers.UC_X86_REG_RAX, (uint)ticks);
                WriteRegister(Registers.UC_X86_REG_RDX, (uint)(ticks >> 32));
                WriteRegister(Registers.UC_X86_REG_RCX, (uint)CurrentThreadId);
            }
            else
            {
                WriteRegister32(Registers.UC_X86_REG_EAX, (uint)ticks);
                WriteRegister32(Registers.UC_X86_REG_EDX, (uint)(ticks >> 32));
                WriteRegister32(Registers.UC_X86_REG_ECX, (uint)CurrentThreadId);
            }

            if ((Settings.Flags & LogFlags.RDTSCP) != 0)
                TriggerEventMessage($"[+] RDTSCP Instruction Executed at 0x{IP:X}.", LogFlags.RDTSCP);

            return true;
        }

        internal ulong AllocateThreadStack(ulong StackSize)
        {
            return MapUniqueAddress(StackSize, MemoryProtection.ReadWrite);
        }

        internal ulong BuildInitialContext(ulong RIP, ulong RSP, ulong RCX = 0, ulong RDX = 0, uint Flags = 0x00100000 | 0x00000001 | 0x00000002)
        {
            const ulong ContextSize = 0x500;
            ulong ContextAddress = MapUniqueAddress(ContextSize, MemoryProtection.ReadWrite);

            Span<byte> Buf = stackalloc byte[(int)ContextSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x30, 4), Flags);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x44, 4), 0x202u);
            BinaryPrimitives.WriteUInt64LittleEndian(Buf.Slice(0x80, 8), RCX);
            BinaryPrimitives.WriteUInt64LittleEndian(Buf.Slice(0x88, 8), RDX);
            BinaryPrimitives.WriteUInt64LittleEndian(Buf.Slice(0x98, 8), RSP);
            BinaryPrimitives.WriteUInt64LittleEndian(Buf.Slice(0xF8, 8), RIP);
            _emulator.WriteMemory(ContextAddress, Buf);

            return ContextAddress;
        }

        internal ulong BuildInitialContext32(ulong Eip, ulong Esp, ulong Eax, ulong Ebx)
        {
            const uint ContextI386ControlIntegerSegments = 0x00010000 | 0x1 | 0x2 | 0x4;
            const ulong ContextSize = 0x2CC;
            ulong ContextAddress = MapUniqueAddress(ContextSize, MemoryProtection.ReadWrite);

            Span<byte> Buf = stackalloc byte[(int)ContextSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x00, 4), ContextI386ControlIntegerSegments);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x8C, 4), ReadRegister32(Registers.UC_X86_REG_GS));
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x90, 4), ReadRegister32(Registers.UC_X86_REG_FS));
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x94, 4), ReadRegister32(Registers.UC_X86_REG_ES));
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0x98, 4), ReadRegister32(Registers.UC_X86_REG_DS));
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xA4, 4), (uint)Ebx);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xB0, 4), (uint)Eax);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xB8, 4), (uint)Eip);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xBC, 4), ReadRegister32(Registers.UC_X86_REG_CS));
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xC0, 4), 0x202u);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xC4, 4), (uint)Esp);
            BinaryPrimitives.WriteUInt32LittleEndian(Buf.Slice(0xC8, 4), ReadRegister32(Registers.UC_X86_REG_SS));
            _emulator.WriteMemory(ContextAddress, Buf);

            return ContextAddress;
        }

        public EmulatedThread CreateEmulatedThread(ulong StartAddress, string Name = null!, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8)
        {
            return Guest.CreateEmulatedThread(this, StartAddress, Name, Parameter, StackSizeOverride, BasePriority);
        }

        private int[] GetGprBatchRegs()
        {
            int[] Regs = _gprBatchRegs;
            if (Regs == null)
            {
                Regs = IsX86Guest
                    ? new int[GprBatchCount32]
                    {
                        (int)Registers.UC_X86_REG_EAX, (int)Registers.UC_X86_REG_EBX,
                        (int)Registers.UC_X86_REG_ECX, (int)Registers.UC_X86_REG_EDX,
                        (int)Registers.UC_X86_REG_ESI, (int)Registers.UC_X86_REG_EDI,
                        (int)Registers.UC_X86_REG_EBP, (int)Registers.UC_X86_REG_ESP,
                        IPRegister,                    (int)Registers.UC_X86_REG_EFLAGS
                    }
                    : new int[GprBatchCount]
                    {
                        (int)Registers.UC_X86_REG_RAX, (int)Registers.UC_X86_REG_RBX,
                        (int)Registers.UC_X86_REG_RCX, (int)Registers.UC_X86_REG_RDX,
                        (int)Registers.UC_X86_REG_RSI, (int)Registers.UC_X86_REG_RDI,
                        (int)Registers.UC_X86_REG_RBP, (int)Registers.UC_X86_REG_RSP,
                        (int)Registers.UC_X86_REG_R8,  (int)Registers.UC_X86_REG_R9,
                        (int)Registers.UC_X86_REG_R10, (int)Registers.UC_X86_REG_R11,
                        (int)Registers.UC_X86_REG_R12, (int)Registers.UC_X86_REG_R13,
                        (int)Registers.UC_X86_REG_R14, (int)Registers.UC_X86_REG_R15,
                        IPRegister,                    (int)Registers.UC_X86_REG_EFLAGS
                    };
                _gprBatchRegs = Regs;
            }
            return Regs;
        }

        public void SaveContext(EmulatedThread t)
        {
            if (t == null || t.Context == null) return;
            ReadGprBatch(t.Context);
            if (_emulator.IsThreadResident(t.ThreadId))
                return;
            _emulator.ReadXmmRegisters(t.Context.Xmm);
            t.Context.MXCSR = ReadRegister(Registers.UC_X86_REG_MXCSR);
            t.Context.FPCW = ReadRegister(Registers.UC_X86_REG_FPCW);
        }

        public bool ReadGprBatch(CpuContext c)
        {
            if (c == null) return false;
            int[] Regs = GetGprBatchRegs();
            ulong[] Vals = _gprBatchScratch ??= new ulong[GprBatchCount];
            if (!_emulator.ReadRegisterBatch(Regs, Vals, Regs.Length))
                return false;
            c.RAX = Vals[0]; c.RBX = Vals[1]; c.RCX = Vals[2]; c.RDX = Vals[3];
            c.RSI = Vals[4]; c.RDI = Vals[5]; c.RBP = Vals[6]; c.RSP = Vals[7];
            if (Regs.Length == GprBatchCount32)
            {
                c.RIP = Vals[8]; c.RFLAGS = Vals[9];
                return true;
            }
            c.R8 = Vals[8]; c.R9 = Vals[9]; c.R10 = Vals[10]; c.R11 = Vals[11];
            c.R12 = Vals[12]; c.R13 = Vals[13]; c.R14 = Vals[14]; c.R15 = Vals[15];
            c.RIP = Vals[16]; c.RFLAGS = Vals[17];
            return true;
        }

        public void WriteGprBatch(CpuContext c)
        {
            if (c == null) return;
            int[] Regs = GetGprBatchRegs();
            ulong[] Vals = _gprBatchScratch ??= new ulong[GprBatchCount];
            Vals[0] = c.RAX; Vals[1] = c.RBX; Vals[2] = c.RCX; Vals[3] = c.RDX;
            Vals[4] = c.RSI; Vals[5] = c.RDI; Vals[6] = c.RBP; Vals[7] = c.RSP;
            if (Regs.Length == GprBatchCount32)
            {
                Vals[8] = c.RIP; Vals[9] = c.RFLAGS;
            }
            else
            {
                Vals[8] = c.R8; Vals[9] = c.R9; Vals[10] = c.R10; Vals[11] = c.R11;
                Vals[12] = c.R12; Vals[13] = c.R13; Vals[14] = c.R14; Vals[15] = c.R15;
                Vals[16] = c.RIP; Vals[17] = c.RFLAGS;
            }
            _emulator.WriteRegisterBatch(Regs, Vals, Regs.Length);
        }

        public void LoadContext(EmulatedThread t)
        {
            if (t == null) return;
            LoadContext(t, !_emulator.IsThreadResident(t.ThreadId));
        }

        // A resident thread keeps its vector state in its own processor, so only a first load or a
        // shared processor takes the saved copy.
        private void LoadContext(EmulatedThread t, bool LoadVectorState)
        {
            if (t == null || t.Context == null) return;

            if (t.SwitchingContext)
            {
                if (!IsX86Guest)
                    t.Context.RIP = t.Context.RIP - 2;
                t.SwitchingContext = false;
            }

            WriteGprBatch(t.Context);
            if (LoadVectorState)
            {
                _emulator.WriteXmmRegisters(t.Context.Xmm);
                WriteRegister(Registers.UC_X86_REG_MXCSR, t.Context.MXCSR);
                WriteRegister(Registers.UC_X86_REG_FPCW, t.Context.FPCW);
            }
            Guest.OnThreadContextLoaded(this, t);
        }

        private void SwitchToThread(int ThreadId)
        {
            if (!Threads.TryGetValue((uint)ThreadId, out EmulatedThread next))
                return;
            EmulatedThread cur = _currentThreadCache;
            if (cur != null)
            {
                SaveContext(cur);
                if (cur.State == EmulatedThreadState.Terminated)
                    ReleaseThreadProcessor(cur);
            }
            CurrentThreadId = ThreadId;
            _currentThreadCache = next;
            bool FirstResidentLoad = !_emulator.IsThreadResident(next.ThreadId) && BindThreadProcessor(next);
            _emulator.SelectThread(next.ThreadId);
            LoadContext(next, FirstResidentLoad || !_emulator.IsThreadResident(next.ThreadId));
        }

        private bool _threadProcessorsExhausted;

        private bool BindThreadProcessor(EmulatedThread Thread)
        {
            if (!_emulator.SupportsThreadResidency || _threadProcessorsExhausted || Thread.State == EmulatedThreadState.Terminated)
                return false;

            if (_emulator.TryBindThread(Thread.ThreadId))
                return true;

            foreach (EmulatedThread Other in Threads.Values)
                if (Other.State == EmulatedThreadState.Terminated)
                    _emulator.UnbindThread(Other.ThreadId);

            if (_emulator.TryBindThread(Thread.ThreadId))
                return true;

            _threadProcessorsExhausted = true;
            return false;
        }

        private void ReleaseThreadProcessor(EmulatedThread Thread)
        {
            if (!_emulator.IsThreadResident(Thread.ThreadId))
                return;
            _emulator.UnbindThread(Thread.ThreadId);
            _threadProcessorsExhausted = false;
        }

        /// <summary>
        /// Returns a stable snapshot of the currently known emulated threads.
        /// </summary>
        public List<EmulatedThread> GetThreadsSnapshot()
        {
            List<EmulatedThread> Snapshot = new List<EmulatedThread>(Threads.Count);
            foreach (var Thread in Threads.Values)
                Snapshot.Add(Thread);

            Snapshot.Sort((a, b) => a.ThreadId.CompareTo(b.ThreadId));
            return Snapshot;
        }

        /// <summary>
        /// Tries to get an emulated thread by guest thread id.
        /// </summary>
        public bool TryGetThread(uint ThreadId, out EmulatedThread Thread)
        {
            return Threads.TryGetValue(ThreadId, out Thread);
        }

        /// <summary>
        /// Switches the live Unicorn context to an existing emulated thread.
        /// </summary>
        public bool TrySwitchToThread(uint ThreadId)
        {
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.Context == null)
                return false;

            if (Thread.State == EmulatedThreadState.Terminated)
                return false;

            SwitchToThread((int)ThreadId);
            return CurrentThreadId == (int)ThreadId;
        }

        /// <summary>
        /// Suspends an emulated thread and returns its previous suspend count.
        /// </summary>
        public bool TrySuspendThread(uint ThreadId, out int PreviousSuspendCount)
        {
            PreviousSuspendCount = 0;
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                return false;

            SuspendThread(Thread, out PreviousSuspendCount, false);
            SchedulerRefreshRequested = true;
            return true;
        }

        /// <summary>
        /// Releases the threads held back by <see cref="BinaryEmulatorSettings.StartSuspended"/>, which is what
        /// the creator asking to resume the initial thread means for a process spawned suspended.
        /// </summary>
        public void ResumeSuspendedStart()
        {
            if (StartSuspendedReleased)
                return;

            // The resume can arrive before the scheduler ever held the threads, so record it either way.
            StartSuspendedReleased = true;

            if (!StartSuspendedApplied)
                return;

            StartSuspendedApplied = false;

            foreach (EmulatedThread Thread in Threads.Values)
                ResumeThread(Thread, out _);

            SchedulerRefreshRequested = true;
        }

        /// <summary>
        /// Resumes an emulated thread and returns its previous suspend count.
        /// </summary>
        public bool TryResumeThread(uint ThreadId, out int PreviousSuspendCount)
        {
            PreviousSuspendCount = 0;
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                return false;

            ResumeThread(Thread, out PreviousSuspendCount);
            SchedulerRefreshRequested = true;
            return true;
        }

        /// <summary>
        /// Marks an emulated thread as terminated.
        /// </summary>
        public bool TryTerminateThread(uint ThreadId, int ExitCode = 0)
        {
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                return false;

            if (CurrentThreadId == (int)ThreadId && Thread.Context != null)
                SaveContext(Thread);

            Thread.ExitCode = ExitCode;
            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitDeadline = -1;
            Thread.State = EmulatedThreadState.Terminated;
            SchedulerRefreshRequested = true;
            return true;
        }

        private static int ClampInt(int Value, int Min, int Max)
        {
            if (Value < Min) return Min;
            if (Value > Max) return Max;
            return Value;
        }

        internal void SuspendThread(EmulatedThread Thread, out int PreviousSuspendCount, bool StopIfCurrentThread)
        {
            PreviousSuspendCount = 0;

            if (Thread == null)
                return;

            PreviousSuspendCount = Thread.SuspendCount;
            Thread.SuspendCount = PreviousSuspendCount + 1;

            if (Thread.SuspendCount > 0)
            {
                if (Thread.State == EmulatedThreadState.Ready || Thread.State == EmulatedThreadState.Running || Thread.State == EmulatedThreadState.Exception)
                    Thread.State = EmulatedThreadState.Suspended;
            }

            if (StopIfCurrentThread)
            {
                if (!IsX86Guest)
                    _emulator.WriteRegister(IPRegister, _emulator.ReadRegister(IPRegister) + 2);
                _emulator.StopEmulation();
            }
        }

        internal void ResumeThread(EmulatedThread Thread, out int PreviousSuspendCount)
        {
            PreviousSuspendCount = 0;

            if (Thread == null)
                return;

            PreviousSuspendCount = Thread.SuspendCount;

            if (Thread.SuspendCount > 0)
                Thread.SuspendCount--;

            if (Thread.SuspendCount == 0 && Thread.State == EmulatedThreadState.Suspended)
            {
                Thread.State = EmulatedThreadState.Ready;
                WakeSignal.Bump();
            }
        }

        private static int GetMlfqLevelForPriority(int Priority, int Levels)
        {
            if (Levels <= 1)
                return 0;

            Priority = ClampInt(Priority, 0, 31);

            // Level 0 is highest priority, Level (Levels - 1) is lowest priority.
            int Level = ((31 - Priority) * Levels) / 32;

            if (Level < 0) return 0;
            if (Level >= Levels) return Levels - 1;
            return Level;
        }

        private static void BuildMlfqQuanta(uint BaseQuantumInstructions, int Levels, uint[] Quanta)
        {
            if (Levels < 1 || Quanta == null || Quanta.Length == 0)
                return;

            Quanta[0] = BaseQuantumInstructions == 0 ? 1U : BaseQuantumInstructions;

            for (int i = 1; i < Levels && i < Quanta.Length; i++)
            {
                uint Prev = Quanta[i - 1];
                if (Prev > uint.MaxValue / 2)
                    Quanta[i] = uint.MaxValue;
                else
                    Quanta[i] = Prev * 2;
            }
        }

        private bool IsMlfqRunnableThread(EmulatedThread Thread)
        {
            if (Thread == null)
                return false;

            if (Thread.State == EmulatedThreadState.Terminated)
                return false;

            if (Thread.SuspendCount > 0 || Thread.State == EmulatedThreadState.Suspended)
                return false;

            if (Guest.HasPendingGuestWork(this, Thread))
                return true;

            return Thread.State == EmulatedThreadState.Ready ||
                   Thread.State == EmulatedThreadState.Running ||
                   Thread.State == EmulatedThreadState.Exception;
        }

        private void CompleteThreadWait(EmulatedThread Thread)
        {
            if (Debug && Thread != null)
            {
                if (Debug)
                    TriggerDebugMessage($"scheduler: wait satisfied tid={Thread.ThreadId} index={Thread.WaitSatisfiedIndex} timedOut={Thread.WaitTimedOut}");
            }

            Guest.OnThreadWaitSatisfied(this, Thread);

            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitDeadline = -1;
            Thread.WaitAll = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            Thread.State = EmulatedThreadState.Ready;
        }

        private bool UpdateMlfqThreadWakeup(EmulatedThread Thread, Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick, ref long EarliestDeadline)
        {
            bool Changed = false;

            if (Thread == null)
                return false;

            if (Thread.State == EmulatedThreadState.Suspended && Thread.SuspendCount == 0)
            {
                if (Debug)
                    TriggerDebugMessage($"scheduler: resumed suspended tid={Thread.ThreadId}");

                Thread.State = EmulatedThreadState.Ready;
                Changed = true;
            }
            else if (Thread.State == EmulatedThreadState.Waiting && Thread.WaitActive && TrySatisfyThreadWait(Thread))
            {
                CompleteThreadWait(Thread);
                Changed = true;
            }

            if (Thread.State == EmulatedThreadState.Waiting && Thread.WaitActive && Thread.WaitDeadline != -1 && Thread.WaitDeadline < EarliestDeadline)
                EarliestDeadline = Thread.WaitDeadline;

            EnqueueMlfqThread(Thread, ReadyQueues, InQueue, Levels, SchedulerTick);
            return Changed;
        }

        private bool UpdateMlfqWakeups(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick, bool ScanAllThreads = false)
        {
            bool Changed = RefreshWindowsTimersAndWakeWaiters();
            long EarliestDeadline = long.MaxValue;

            if (ScanAllThreads)
            {
                foreach (var kvp in Threads)
                    Changed |= UpdateMlfqThreadWakeup(kvp.Value, ReadyQueues, InQueue, Levels, SchedulerTick, ref EarliestDeadline);
            }
            else
            {
                foreach (EmulatedThread Thread in LiveThreads)
                    Changed |= UpdateMlfqThreadWakeup(Thread, ReadyQueues, InQueue, Levels, SchedulerTick, ref EarliestDeadline);

                if (Debug)
                {
                    int LiveInMap = 0;
                    foreach (var kvp in Threads)
                    {
                        if (kvp.Value != null && kvp.Value.State != EmulatedThreadState.Terminated)
                            LiveInMap++;
                    }

                    int LiveInOrder = 0;
                    foreach (EmulatedThread Thread in LiveThreads)
                    {
                        if (Thread.State != EmulatedThreadState.Terminated)
                            LiveInOrder++;
                    }

                    if (LiveInMap != LiveInOrder)
                        TriggerDebugMessage($"scheduler: thread order mismatch map={LiveInMap} order={LiveInOrder}");
                }
            }

            EarliestWaitDeadline = EarliestDeadline;
            LastScannedWakeEpoch = WakeSignal.Current;
            LastFullWakeupScanTick = EmulatedTickCount64;
            SlicesSinceFullWakeupScan = 0;

            return Changed;
        }

        private bool TryGetNextWaitSleepMs(out int SleepMs, int MaxSleepMs = 10)
        {
            SleepMs = 0;

            long Now = EmulatedTickCount64;
            long BestDelta = long.MaxValue;

            foreach (EmulatedThread Thread in LiveThreads)
            {
                if (Thread.State != EmulatedThreadState.Waiting || !Thread.WaitActive || Thread.WaitDeadline == -1)
                    continue;

                long Delta = Thread.WaitDeadline - Now;

                if (Delta <= 0)
                    return true;

                if (Delta < BestDelta)
                    BestDelta = Delta;
            }

            if (TryGetNextWindowsTimerSleepMs(out int TimerSleepMs, MaxSleepMs))
            {
                if (BestDelta == long.MaxValue || TimerSleepMs < BestDelta)
                {
                    SleepMs = TimerSleepMs;
                    return true;
                }
            }

            if (BestDelta == long.MaxValue)
                return false;

            long Clamped = BestDelta > MaxSleepMs ? MaxSleepMs : BestDelta;
            SleepMs = (int)Clamped;
            if (SleepMs < 1)
                SleepMs = 1;

            return true;
        }

        private void TrimDeadThreadsFromOrder()
        {
            for (int i = ThreadOrder.Count - 1; i >= 0; i--)
            {
                int Tid = ThreadOrder[i];
                if (!Threads.TryGetValue((uint)Tid, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                    ThreadOrder.RemoveAt(i);
            }
        }

        private void EnqueueMlfqThread(EmulatedThread t, Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick)
        {
            if (t == null)
                return;

            if (!IsMlfqRunnableThread(t))
                return;

            int Tid = (int)t.ThreadId;
            if (!InQueue.Add(Tid))
                return;

            int Level = GetMlfqLevelForPriority(t.EffectivePriority, Levels);
            t.QueueLevel = Level;
            t.LastReadyTick = SchedulerTick;

            ReadyQueues[Level].Enqueue(Tid);
        }

        private void EnsureMlfqRunnableThreadsEnqueued(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick)
        {
            for (int i = 0; i < ThreadOrder.Count; i++)
            {
                int Tid = ThreadOrder[i];
                if (InQueue.Contains(Tid))
                    continue;

                if (!Threads.TryGetValue((uint)Tid, out EmulatedThread t))
                    continue;

                if (IsMlfqRunnableThread(t))
                    EnqueueMlfqThread(t, ReadyQueues, InQueue, Levels, SchedulerTick);
            }
        }

        private bool TryDequeueMlfqThread(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, out EmulatedThread Thread, out int SelectedLevel)
        {
            Thread = null;
            SelectedLevel = -1;

            for (int Attempt = 0; Attempt < Levels; Attempt++)
            {
                int Level = PickMlfqLevel(ReadyQueues, Levels);
                if (Level < 0)
                    return false;

                while (ReadyQueues[Level].Count > 0)
                {
                    int Tid = ReadyQueues[Level].Dequeue();
                    InQueue.Remove(Tid);

                    if (!Threads.TryGetValue((uint)Tid, out EmulatedThread Candidate))
                        continue;

                    if (!IsMlfqRunnableThread(Candidate))
                        continue;

                    ChargeMlfqLevelSkips(ReadyQueues, Levels, Level);

                    Thread = Candidate;
                    SelectedLevel = Level;
                    return true;
                }
            }

            return false;
        }

        // Guest wait deadlines run on host wall time, so emulator overhead keeps short sleepers permanently
        // expired: they re-enter the boosted queues on every dispatch and strict priority order then never
        // reaches a lower queue at all. Bounding how often a level may be skipped turns that livelock into a
        // share of the dispatches.
        private const int MlfqStarvationSkipLimit = 24;

        private int PickMlfqLevel(Queue<int>[] ReadyQueues, int Levels)
        {
            int Best = -1;

            for (int Level = 0; Level < Levels; Level++)
            {
                if (ReadyQueues[Level].Count == 0)
                    continue;

                if (Best < 0)
                    Best = Level;

                if (MlfqLevelSkips[Level] >= MlfqStarvationSkipLimit)
                    return Level;
            }

            return Best;
        }

        private void ChargeMlfqLevelSkips(Queue<int>[] ReadyQueues, int Levels, int SelectedLevel)
        {
            MlfqLevelSkips[SelectedLevel] = 0;

            for (int Level = SelectedLevel + 1; Level < Levels; Level++)
            {
                if (ReadyQueues[Level].Count > 0 && MlfqLevelSkips[Level] < int.MaxValue)
                    MlfqLevelSkips[Level]++;
            }
        }

        private bool HasLiveMlfqThread()
        {
            for (int i = 0; i < ThreadOrder.Count; i++)
            {
                int Tid = ThreadOrder[i];
                if (Threads.TryGetValue((uint)Tid, out EmulatedThread Thread) && Thread != null && Thread.State != EmulatedThreadState.Terminated)
                    return true;
            }

            return false;
        }

        private void RebuildMlfqReadyQueues(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick, long AgingThresholdBudget, int AgingBoost)
        {
            for (int i = 0; i < Levels && i < ReadyQueues.Length; i++)
                ReadyQueues[i]?.Clear();

            InQueue.Clear();
            TrimDeadThreadsFromOrder();

            for (int i = 0; i < ThreadOrder.Count; i++)
            {
                int Tid = ThreadOrder[i];
                if (!Threads.TryGetValue((uint)Tid, out EmulatedThread t))
                    continue;

                if (!IsMlfqRunnableThread(t))
                    continue;

                // if a thread hasn't run for a while, gently boost it upward.
                if (AgingThresholdBudget > 0 && SchedulerTick - t.LastRunTick >= AgingThresholdBudget)
                    t.DynamicBoost = ClampInt(t.DynamicBoost + AgingBoost, -16, 16);

                EnqueueMlfqThread(t, ReadyQueues, InQueue, Levels, SchedulerTick);
            }

            if (Debug)
                TriggerDebugMessage($"scheduler: rebuilt queues live={ThreadOrder.Count} queued={InQueue.Count} tick={SchedulerTick}");
        }

        public bool RunMlfqScheduler(uint BaseQuantumInstructions = 200000, int Levels = 4, ulong MaxTotalInstructions = 0, uint MaxSlices = 0, long AgingThresholdSlices = 50)
        {
            _emulator.RestoreCodeCache();
            PublishTimestampCounterSource();
            TrimDeadThreadsFromOrder();
            if (ThreadOrder.Count == 0)
            {
                TriggerDebugMessage("scheduler: no threads to run");
                return false;
            }

            if (Levels < 1)
                Levels = 1;
            if (Levels > 32)
                Levels = 32;

            BuildMlfqQuanta(BaseQuantumInstructions, Levels, MlfqQuanta);
            MlfqLevels = Levels;

            Queue<int>[] ReadyQueues = MlfqReadyQueues;
            for (int i = 0; i < Levels; i++)
            {
                if (ReadyQueues[i] == null)
                    ReadyQueues[i] = new Queue<int>();
                else
                    ReadyQueues[i].Clear();

                MlfqLevelSkips[i] = 0;
            }

            HashSet<int> InQueue = MlfqQueuedThreads;
            InQueue.Clear();

            ulong Total = 0;
            uint Slices = 0;
            long SchedulerTick = 0;
            ulong PendingSchedulerInstructions = 0;
            const ulong SchedulerRescanInstructions = 1_000_000;
            const long FullWakeupScanIntervalMs = 1;
            const uint FullWakeupScanSliceLimit = 1024;
            long AgingThresholdBudget = AgingThresholdSlices <= 0 ? 0 : AgingThresholdSlices;
            int KnownThreadOrderCount = ThreadOrder.Count;
            bool WakeupScanRequired = true;

            if (Debug)
                TriggerDebugMessage($"scheduler: start threads={ThreadOrder.Count} levels={Levels} baseQuantum={BaseQuantumInstructions} maxInstructions={MaxTotalInstructions} maxSlices={MaxSlices}");

            if (Settings.StartSuspended && !StartSuspendedApplied && !StartSuspendedReleased)
            {
                StartSuspendedApplied = true;

                foreach (EmulatedThread Thread in Threads.Values)
                    SuspendThread(Thread, out _, false);
            }

            RebuildMlfqReadyQueues(ReadyQueues, InQueue, Levels, SchedulerTick, AgingThresholdBudget, 1);
            SchedulerRefreshRequested = false;

            while (true)
            {
                SchedulerTick++;
                MlfqSchedulerTick = SchedulerTick;

                if ((SchedulerTick & 0x7) == 0)
                    _emulator.ResolveCodeCache();

                if (WinHelper != null)
                    OS.Windows.RemoteProcessRequests.Drain(this);

                if (Interlocked.Exchange(ref TerminationRequested, 0) != 0)
                    StopEmulation();

                bool ThreadOrderChanged = ThreadOrder.Count != KnownThreadOrderCount;
                bool AgingDue = AgingThresholdSlices > 0 && SchedulerTick % AgingThresholdSlices == 0;
                if (AgingDue)
                {
                    RebuildMlfqReadyQueues(ReadyQueues, InQueue, Levels, SchedulerTick, AgingThresholdBudget, 1);
                    KnownThreadOrderCount = ThreadOrder.Count;
                    WakeupScanRequired = false;
                }
                else
                {
                    if (ThreadOrderChanged)
                    {
                        if (Debug)
                            TriggerDebugMessage($"scheduler: thread list changed old={KnownThreadOrderCount} new={ThreadOrder.Count}");
                        EnsureMlfqRunnableThreadsEnqueued(ReadyQueues, InQueue, Levels, SchedulerTick);
                        KnownThreadOrderCount = ThreadOrder.Count;
                    }

                    // Comparing against the epoch the last scan observed, rather than a per-slice difference
                    if (WakeupScanRequired || SchedulerRefreshRequested || WakeSignal.Current != LastScannedWakeEpoch)
                    {
                        if (Debug)
                            TriggerDebugMessage($"scheduler: wakeup scan required={WakeupScanRequired} refresh={SchedulerRefreshRequested} tick={SchedulerTick}");

                        UpdateMlfqWakeups(ReadyQueues, InQueue, Levels, SchedulerTick);
                        KnownThreadOrderCount = ThreadOrder.Count;
                        SchedulerRefreshRequested = false;
                        WakeupScanRequired = false;
                    }
                }

                if (!TryDequeueMlfqThread(ReadyQueues, InQueue, Levels, out EmulatedThread ImmaBeEmulatedOOO, out int SelectedLevel))
                {
                    UpdateMlfqWakeups(ReadyQueues, InQueue, Levels, SchedulerTick, true);
                    KnownThreadOrderCount = ThreadOrder.Count;
                    SchedulerRefreshRequested = false;
                    WakeupScanRequired = false;

                    if (!TryDequeueMlfqThread(ReadyQueues, InQueue, Levels, out ImmaBeEmulatedOOO, out SelectedLevel))
                    {
                        TrimDeadThreadsFromOrder();
                        KnownThreadOrderCount = ThreadOrder.Count;

                        // A process created suspended has no runnable thread by design, and it still has to serve
                        // session requests until its creator resumes it.
                        if (StartSuspendedApplied && !StartSuspendedReleased)
                        {
                            Thread.Sleep(IdleWaitSliceMs);
                            WakeupScanRequired = true;
                            continue;
                        }

                        if (!HasLiveMlfqThread())
                        {
                            if (Debug)
                                TriggerDebugMessage($"scheduler: finished no live threads total={Total} slices={Slices}");
                            return true;
                        }

                        if (TryGetNextWaitSleepMs(out int SleepMs, int.MaxValue))
                        {
                            if (Debug)
                                TriggerDebugMessage($"scheduler: no runnable thread, waiting up to {SleepMs}ms");
                            Thread.Sleep(Math.Min(SleepMs, IdleWaitSliceMs));
                            WinHelper?.KuserSharedData?.RefreshIfUnhooked();
                            WakeupScanRequired = true;
                            continue;
                        }

                        if (HasActiveGetMessageWait())
                        {
                            Thread.Sleep(IdleWaitSliceMs);
                            WinHelper?.KuserSharedData?.RefreshIfUnhooked();
                            WakeupScanRequired = true;
                            continue;
                        }

                        if (Debug)
                            TriggerDebugMessage($"scheduler: no runnable thread and no pending wakeup total={Total} slices={Slices}");
                        return true;
                    }
                }

                if (CurrentThreadId != (int)ImmaBeEmulatedOOO.ThreadId)
                {
                    if ((Settings.Flags & LogFlags.General) != 0)
                        TriggerEventMessage($"[!] Switching to thread with ID {ImmaBeEmulatedOOO.ThreadId}", LogFlags.General);
                    if (Debug)
                        TriggerDebugMessage($"scheduler: switch {CurrentThreadId} -> {ImmaBeEmulatedOOO.ThreadId} queue={SelectedLevel} state={ImmaBeEmulatedOOO.State} rip=0x{ImmaBeEmulatedOOO.Context?.RIP ?? 0:X}");
                }

                SwitchToThread((int)ImmaBeEmulatedOOO.ThreadId);
                EmulatedThreadState StateBeforeSlice = ImmaBeEmulatedOOO.State;
                ulong RipBeforeSlice = ImmaBeEmulatedOOO.Context?.RIP ?? 0;
                ImmaBeEmulatedOOO.State = EmulatedThreadState.Running;

                uint QuantumInstructions = MlfqQuanta[Math.Max(0, SelectedLevel)];

                if (Debug && (Slices < 64 || (Slices & 0xFF) == 0))
                {
                    TriggerDebugMessage($"scheduler: run tid={ImmaBeEmulatedOOO.ThreadId} queue={SelectedLevel} quantum={QuantumInstructions} priority={ImmaBeEmulatedOOO.EffectivePriority} boost={ImmaBeEmulatedOOO.DynamicBoost} rip=0x{RipBeforeSlice:X}");
                }
                bool State = false;
                bool SliceRequestedRefresh = false;

                SchedulerRefreshRequested = false;
                try
                {
                    Guest.ExecuteThreadSlice(this, ImmaBeEmulatedOOO, QuantumInstructions, out State);
                }
                catch (Exception ex)
                {
                    if (Debug)
                        TriggerDebugMessage($"scheduler: slice exception tid={ImmaBeEmulatedOOO.ThreadId} {ex.GetType().Name}: {ex.Message}");

                    Utils.LogError($"[Scheduler] Thread {ImmaBeEmulatedOOO.ThreadId} terminated by an unhandled {ex.GetType().Name}: {ex.Message}");

                    if (ImmaBeEmulatedOOO.State != EmulatedThreadState.Terminated)
                        ImmaBeEmulatedOOO.ExitCode = unchecked((int)(uint)ImmaBeEmulatedOOO.Context.RAX);

                    ImmaBeEmulatedOOO.State = EmulatedThreadState.Terminated;
                    SchedulerRefreshRequested = true;
                }
                finally
                {
                    SliceRequestedRefresh = SchedulerRefreshRequested;
                    SchedulerRefreshRequested = false;
                }

                if (!ImmaBeEmulatedOOO.SwitchingContext)
                    SaveContext(ImmaBeEmulatedOOO);

                if (EscapeScheduler)
                {
                    if (Debug)
                        TriggerDebugMessage($"scheduler: escape requested after slice tid={ImmaBeEmulatedOOO.ThreadId}");

                    EscapeScheduler = false;
                    return true;
                }

                uint SchedulerSliceWork = 1;

                if (State && ImmaBeEmulatedOOO.State != EmulatedThreadState.Terminated)
                {
                    bool StoppedBeforeQuantum = ImmaBeEmulatedOOO.State != EmulatedThreadState.Running || ImmaBeEmulatedOOO.Context == null || ImmaBeEmulatedOOO.Context.RIP == 0;

                    if (!StoppedBeforeQuantum)
                        SchedulerSliceWork = Math.Max(1U, QuantumInstructions);
                }

                ImmaBeEmulatedOOO.InstructionsExecuted += SchedulerSliceWork;
                Total += SchedulerSliceWork;

                bool TimedWaitRescanDue = false;
                if (SchedulerSliceWork > 1)
                {
                    PendingSchedulerInstructions += SchedulerSliceWork;
                    if (PendingSchedulerInstructions >= SchedulerRescanInstructions)
                    {
                        PendingSchedulerInstructions = 0;
                        TimedWaitRescanDue = true;
                    }
                }

                // A guest whose threads all block early never accumulates instructions, so the fallback sweep is
                // bounded by wall time. The slice count is only a belt against a clock that stops moving.
                SlicesSinceFullWakeupScan++;
                if (!TimedWaitRescanDue)
                {
                    long NowTick = EmulatedTickCount64;
                    if (SlicesSinceFullWakeupScan >= FullWakeupScanSliceLimit
                        || (NowTick - LastFullWakeupScanTick >= FullWakeupScanIntervalMs && NowTick >= EarliestWaitDeadline))
                        TimedWaitRescanDue = true;
                }

                Slices++;
                WinHelper?.KuserSharedData?.RefreshIfUnhooked();
                ImmaBeEmulatedOOO.LastRunTick = SchedulerTick;

                if (ImmaBeEmulatedOOO.Context?.RIP == 0)
                {
                    if (ImmaBeEmulatedOOO.State != EmulatedThreadState.Terminated)
                    {
                        ImmaBeEmulatedOOO.ExitCode = unchecked((int)(uint)ImmaBeEmulatedOOO.Context?.RAX);

                        if (WinHelper != null)
                        {
                            TriggerEventMessage($"[-] Thread {ImmaBeEmulatedOOO.ThreadId} jumped to a NULL address from 0x{RipBeforeSlice:X}.", LogFlags.Issues);
                            TraceStackModuleFrames("[-] NULL call");
                        }
                    }

                    ImmaBeEmulatedOOO.State = EmulatedThreadState.Terminated;
                }
                else if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Running)
                {
                    ImmaBeEmulatedOOO.State = EmulatedThreadState.Ready;
                }

                // Feedback: threads that block quickly get boosted, CPU-bound threads get demoted.
                if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Waiting)
                    ImmaBeEmulatedOOO.DynamicBoost = ClampInt(ImmaBeEmulatedOOO.DynamicBoost + 2, -16, 16);
                else if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Exception)
                    ImmaBeEmulatedOOO.DynamicBoost = ClampInt(ImmaBeEmulatedOOO.DynamicBoost - 1, -16, 16);
                else if (ImmaBeEmulatedOOO.State != EmulatedThreadState.Terminated)
                    ImmaBeEmulatedOOO.DynamicBoost = ClampInt(ImmaBeEmulatedOOO.DynamicBoost - 1, -16, 16);

                if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Ready || ImmaBeEmulatedOOO.State == EmulatedThreadState.Exception)
                    EnqueueMlfqThread(ImmaBeEmulatedOOO, ReadyQueues, InQueue, Levels, SchedulerTick);
                else if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Terminated)
                {
                    TrimDeadThreadsFromOrder();
                    KnownThreadOrderCount = ThreadOrder.Count;
                }

                if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Waiting && ImmaBeEmulatedOOO.WaitActive
                    && ImmaBeEmulatedOOO.WaitDeadline != -1 && ImmaBeEmulatedOOO.WaitDeadline < EarliestWaitDeadline)
                    EarliestWaitDeadline = ImmaBeEmulatedOOO.WaitDeadline;

                WakeupScanRequired = SliceRequestedRefresh || TimedWaitRescanDue || ThreadOrder.Count != KnownThreadOrderCount;

                if (Debug && (Slices <= 64 || (Slices & 0xFF) == 0 || ImmaBeEmulatedOOO.State != StateBeforeSlice || SliceRequestedRefresh || TimedWaitRescanDue))
                {
                    TriggerDebugMessage($"scheduler: slice tid={ImmaBeEmulatedOOO.ThreadId} {StateBeforeSlice}->{ImmaBeEmulatedOOO.State} work={SchedulerSliceWork} total={Total} rip=0x{RipBeforeSlice:X}->0x{ImmaBeEmulatedOOO.Context?.RIP ?? 0:X} refresh={SliceRequestedRefresh} rescanDue={TimedWaitRescanDue} boost={ImmaBeEmulatedOOO.DynamicBoost}");
                }

                if (MaxTotalInstructions != 0 && Total >= MaxTotalInstructions)
                {
                    if (Debug)
                        TriggerDebugMessage($"scheduler: max instruction budget reached total={Total} slices={Slices}");
                    return true;
                }
                if (MaxSlices != 0 && Slices >= MaxSlices)
                {
                    if (Debug)
                        TriggerDebugMessage($"scheduler: max slice budget reached total={Total} slices={Slices}");
                    return true;
                }
            }
        }

        /// <summary>
        /// Gets the action name associated with a Unicorn memory access type.
        /// </summary>
        /// <param name="Type">Memory type.</param>
        /// <returns>returns the string that represents the memory action.</returns>
        private string GetAction(BackendMemoryAccessType Type)
        {
            return Type switch
            {
                BackendMemoryAccessType.ReadUnmapped => "read",
                BackendMemoryAccessType.WriteUnmapped => "write",
                BackendMemoryAccessType.FetchUnmapped => "fetch",
                BackendMemoryAccessType.ReadProtected => "read (protected)",
                BackendMemoryAccessType.WriteProtected => "write (protected)",
                BackendMemoryAccessType.FetchProtected => "fetch (protected)",
                _ => "action (unknown)"
            };
        }

        /// <summary>
        /// Handles invalid memory operations and pass the exception to user-mode.
        /// </summary>
        private bool InvalidMemoryHandler(BackendMemoryAccessType Type, ulong Address, uint Size, ulong value)
        {
            if (Type == BackendMemoryAccessType.FetchUnmapped && Address == 0)
            {
                return false;
            }

            if (TryHandleGuardPageViolation(Type, Address, out bool ResumeAfterGuard))
            {
                SchedulerRefreshRequested = true;

                if (ResumeAfterGuard)
                    _emulator.StopEmulation();

                return false;
            }

            ulong Rip = ReadRegister(IPRegister);
            if ((Settings.Flags & LogFlags.Issues) != 0)
            {
                string RegionInfo = TryFindMemoryRegion(Address, out MemoryRegion FaultRegion)
                    ? $" [region 0x{FaultRegion.BaseAddress:X}+0x{FaultRegion.Size:X} prot={FaultRegion.Protections} win=0x{FaultRegion.Protect:X} special={FaultRegion.SpecialProtections} reserved={FaultRegion.IsReserved} committed={FaultRegion.IsCommitted}]"
                    : " [no region]";
                TriggerEventMessage($"[-] Invalid memory {GetAction(Type)} related to the address 0x{Address:X} at {(WinHelper != null ? DescribeAddress(Rip) : $"0x{Rip:X}")}.{RegionInfo}", LogFlags.Issues);
                if (WinHelper != null)
                    TraceStackModuleFrames("[-] Invalid memory");
            }

            bool Continue = false;
            if (Settings.InvalidOperationsCallback != null)
                Continue = Settings.InvalidOperationsCallback.Invoke(Type, Address, Size, value);

            if (Continue)
                return true;

            SchedulerRefreshRequested = true;
            return Guest.HandleInvalidMemory(this, Type, Address, Size, value);
        }

        /// <summary>
        /// Initialize the emulation environment with necessary memory mappings and setup.
        /// </summary>
        /// <param name="Settings">Emulation settings.</param>
        private void InitializeEmulationEnvironment(BinaryEmulatorSettings Settings)
        {
            if (Settings.HandleInvalidOperations)
            {
                InvalidMemory = InvalidMemoryHandler;
                if (_emulator.AddMemoryHook(1, 0, BackendHookType.MemoryUnmapped | BackendHookType.MemoryProtected, InvalidMemory) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the invalid-memory hook: {_emulator.GetLastError()}.");
            }

            Interrupt = InterruptHandler;
            if (_emulator.AddInterruptHook(Interrupt) == IntPtr.Zero)
                Utils.LogError($"Couldn't add the interrupt hook: {_emulator.GetLastError()}.");

            if (BackendArch == Arch.X86)
            {
                Syscall = SyscallInstructionHandler;
                if (_emulator.AddInstructionHook(BackendInstructionHook.Syscall, Syscall) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the syscall hook: {_emulator.GetLastError()}.");

                CPUID = CPUID_Handler;
                if (_emulator.AddInstructionBoolHook(BackendInstructionHook.CpuId, CPUID) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the CPUID hook: {_emulator.GetLastError()}.");

                RDTSC = RDTSC_Handler;
                if (_emulator.AddInstructionBoolHook(BackendInstructionHook.Rdtsc, RDTSC) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the RDTSC hook: {_emulator.GetLastError()}.");

                RDTSCP = RDTSCP_Handler;
                if (_emulator.AddInstructionBoolHook(BackendInstructionHook.Rdtscp, RDTSCP) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the RDTSCP hook: {_emulator.GetLastError()}.");

                Privileged = PrivilegedInstructionHandler;
                if (_emulator.AddInstructionHook(BackendInstructionHook.In, Privileged) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the IN instruction hook: {_emulator.GetLastError()}.");
                if (_emulator.AddInstructionHook(BackendInstructionHook.Out, Privileged) == IntPtr.Zero)
                    Utils.LogError($"Couldn't add the OUT instruction hook: {_emulator.GetLastError()}.");
            }

            InvalidInstruction = InvalidInstructionHandler;
            if (_emulator.AddInstructionHook(BackendInstructionHook.Invalid, InvalidInstruction) == IntPtr.Zero)
                Utils.LogError($"Couldn't add the invalid-instruction hook: {_emulator.GetLastError()}.");

            Guest.Initialize(this, _binary);
            if (IsArchX86Guest)
            {
                if (IsX64Guest)
                {
                    _emulator.WriteRegister(Registers.UC_X86_REG_RFLAGS, 0x202);
                }
                else
                {
                    _emulator.WriteRegister(Registers.UC_X86_REG_EFLAGS, 0x202);
                }
            }
        }

        private void SyscallInstructionHandler()
        {
            if (Debug)
                TriggerDebugMessage($"cpu: syscall instruction at 0x{ReadRegister(IPRegister):X}");
            try
            {
                Guest.TryHandleSyscall(this);
            }
            catch (Exception ex)
            {
                // A handler that threw got partway through whatever it was doing, so its bumps cannot be
                // trusted to be complete.
                SchedulerRefreshRequested = true;
                Utils.LogError($"[GuestSyscall] Error: {ex.Message}");
            }
        }

        public void Start()
        {
            Guest.Start(this);

            // The guest has stopped here. Dispose() is not a reliable hook: the menu's
            // "exit" command calls Environment.Exit.
            _emulator.PersistCodeCache();
        }

        /// <summary>
        /// Align size to 4KB page boundary.
        /// </summary>
        /// <param name="Size">Size to align.</param>
        /// <returns>Aligned size.</returns>
        public ulong AlignToPageSize(ulong Size)
        {
            return (Size + 0xFFF) & ~0xFFFUL;
        }

        public bool IsAlignedToPageSize(ulong value)
        {
            return (value & 0xFFFUL) == 0;
        }

        /// <summary>
        /// Convert PE section characteristics to Unicorn memory protection.
        /// </summary>
        /// <param name="Characteristics">PE section characteristics.</param>
        /// <returns>Unicorn memory protection flags.</returns>
        public MemoryProtection GetMemoryProtection(SectionCharacteristics Characteristics)
        {
            MemoryProtection Protection = MemoryProtection.None;

            if (Characteristics.HasFlag(SectionCharacteristics.MemRead))
                Protection |= MemoryProtection.Read;

            if (Characteristics.HasFlag(SectionCharacteristics.MemWrite))
                Protection |= MemoryProtection.Write;

            if (Characteristics.HasFlag(SectionCharacteristics.MemExecute))
                Protection |= MemoryProtection.Execute;

            return Protection != MemoryProtection.None ? Protection : MemoryProtection.All;
        }

        /// <summary>
        /// Convert ELF section characteristics to Unicorn memory protection.
        /// </summary>
        /// <param name="Characteristics">ELF section characteristics.</param>
        /// <returns>Unicorn memory protection flags.</returns>
        public MemoryProtection GetMemoryProtection(ElfSectionCharacteristics Characteristics)
        {
            MemoryProtection Protection = MemoryProtection.None;

            if (Characteristics.HasFlag(ElfSectionCharacteristics.Alloc))
                Protection |= MemoryProtection.Read;

            if (Characteristics.HasFlag(ElfSectionCharacteristics.Write))
                Protection |= MemoryProtection.Write;

            if (Characteristics.HasFlag(ElfSectionCharacteristics.ExecInstr))
                Protection |= MemoryProtection.Execute;

            return Protection != MemoryProtection.None ? Protection : MemoryProtection.All;
        }

        /// <summary>
        /// Get the last unicorn error.
        /// </summary>
        public BackendError GetLastError() => _emulator.GetLastError();

        /// <summary>
        /// Write a value to a register.
        /// </summary>
        /// <param name="Register">Register to write to.</param>
        /// <param name="Value">Value to write.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool WriteRegister(Registers Register, ulong Value) => _emulator.WriteRegister(Register, Value);

        public bool WriteRegister(int Register, ulong Value) => _emulator.WriteRegister(Register, Value);

        /// <summary>
        /// Write a value to a register.
        /// </summary>
        /// <param name="Register">Register to write to.</param>
        /// <param name="Value">Value to write.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool WriteRegister32(Registers Register, uint Value) => _emulator.WriteRegister32(Register, Value);

        public bool WriteRegister32(int Register, uint Value) => _emulator.WriteRegister32(Register, Value);

        /// <summary>
        /// Write a value to a register.
        /// </summary>
        /// <param name="Register">Register to write to.</param>
        /// <param name="Value">Value to write.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool WriteRegisterByte(Registers Register, byte Value) => _emulator.WriteRegisterByte(Register, Value);

        public bool WriteRegisterByte(int Register, byte Value) => _emulator.WriteRegisterByte(Register, Value);

        /// <summary>
        /// Write a value to a register.
        /// </summary>
        /// <param name="Register">Register to write to.</param>
        /// <param name="Value">Value to write.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool WriteRegisterByte(Registers Register, byte[] Value) => _emulator.WriteRegisterByte(Register, Value);

        /// <summary>
        /// Read a value from a register.
        /// </summary>
        /// <param name="Register">Register to read from.</param>
        /// <returns>Value of the register.</returns>
        public ulong ReadRegister(Registers Register) => _emulator.ReadRegister(Register);

        public ulong ReadRegister(int Register) => _emulator.ReadRegister(Register);

        /// <summary>
        /// Read a value from a register.
        /// </summary>
        /// <param name="Register">Register to read from.</param>
        /// <returns>Value of the register.</returns>
        public uint ReadRegister32(Registers Register) => _emulator.ReadRegister32(Register);

        public uint ReadRegister32(int Register) => _emulator.ReadRegister32(Register);

        /// <summary>
        /// Read a value from a register.
        /// </summary>
        /// <param name="Register">Register to read from.</param>
        /// <returns>Value of the register.</returns>
        public byte ReadRegisterByte(Registers Register) => _emulator.ReadRegisterByte(Register);

        public byte ReadRegisterByte(int Register) => _emulator.ReadRegisterByte(Register);

        /// <summary>
        /// Write data to emulated memory.
        /// </summary>
        /// <param name="Address">Address to write to.</param>
        /// <param name="Data">Data to write.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool WriteMemory(ulong Address, byte[] Data) => _emulator.WriteMemory(Address, Data);

        /// <summary>
        /// Write data to emulated memory without allocating a temporary byte array.
        /// </summary>
        /// <param name="Address">Address to write to.</param>
        /// <param name="Data">Data to write.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool WriteMemory(ulong Address, ReadOnlySpan<byte> Data) => _emulator.WriteMemory(Address, Data);

        /// <summary>
        /// Read data from emulated memory into an existing buffer.
        /// </summary>
        /// <param name="Address">Address to read from.</param>
        /// <param name="Data">Destination buffer.</param>
        /// <param name="Size">Number of bytes to read, or zero to read the full span.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool ReadMemory(ulong Address, Span<byte> Data, uint Size = 0) => _emulator.ReadMemory(Address, Data, Size);

        /// <summary>
        /// Read data from emulated memory.
        /// </summary>
        /// <param name="Address">Address to read from.</param>
        /// <param name="Size">Number of bytes to read.</param>
        /// <returns>Byte array containing the read data.</returns>
        public byte[] ReadMemory(ulong Address, uint Size) => _emulator.ReadMemory(Address, Size);

        /// <summary>
        /// Read data from emulated memory.
        /// </summary>
        /// <param name="Address">Address to read from.</param>
        /// <param name="Size">Number of bytes to read.</param>
        /// <returns>Byte array containing the read data.</returns>
        public ulong ReadMemoryULong(ulong Address) => _emulator.ReadMemoryULong(Address);

        /// <summary>
        /// Read data from emulated memory.
        /// </summary>
        /// <param name="Address">Address to read from.</param>
        /// <param name="Size">Number of bytes to read.</param>
        /// <returns>Byte array containing the read data.</returns>
        public uint ReadMemoryUInt(ulong Address) => _emulator.ReadMemoryUInt(Address);

        /// <summary>
        /// Start emulation.
        /// </summary>
        /// <param name="StartAddress">Beginning of emulation.</param>
        /// <param name="EndAddress">End of emulation.</param>
        /// <param name="Timeout">Timeout in milliseconds. A value of 0 disables the timeout.</param>
        /// <param name="Count">Instruction count limit. A value of 0 disables the instruction limit.</param>
        /// <returns>returns true if the emulation completed without problems, otherwise false.</returns>
        public bool StartEmulation(ulong StartAddress, ulong EndAddress, uint Timeout = 0, uint Count = 0, bool LogErrors = true)
        {
            if (Disposed)
                return false;

            _emulator.RestoreCodeCache();
            if (Debug)
                TriggerDebugMessage($"emu: start 0x{StartAddress:X}->0x{EndAddress:X} timeout={Timeout} count={Count}");
            bool Result = _emulator.Emulate(StartAddress, EndAddress, Timeout, Count);
            if (!Result && LogErrors)
            {
                Utils.LogError($"[BinaryEmulator] Emulation failed: {GetLastError()}");
            }
            if (Debug)
                TriggerDebugMessage($"emu: stop result={Result} ip=0x{ReadRegister(IPRegister):X} error={GetLastError()}");
            return Result;
        }

        public void RequestTermination()
        {
            Interlocked.Exchange(ref TerminationRequested, 1);
        }

        /// <summary>
        /// Stops the emulation completely.
        /// </summary>
        /// <returns>returns true if the emulation was successfully stopped, otherwise false.</returns>
        public bool StopEmulation()
        {
            SchedulerRefreshRequested = true;
            TriggerDebugMessage(() => $"emu: stop requested threads={Threads.Count}");
            foreach (EmulatedThread EmuThread in Threads.Values)
            {
                EmuThread.State = EmulatedThreadState.Terminated;
            }
            return _emulator.StopEmulation();
        }

        private static readonly Registers[] EssentialRegistersX64 =
        {
            Registers.UC_X86_REG_RAX, Registers.UC_X86_REG_RBX, Registers.UC_X86_REG_RCX,
            Registers.UC_X86_REG_RDX, Registers.UC_X86_REG_RSI, Registers.UC_X86_REG_RDI,
            Registers.UC_X86_REG_RBP, Registers.UC_X86_REG_RSP, Registers.UC_X86_REG_R8,
            Registers.UC_X86_REG_R9,  Registers.UC_X86_REG_R10, Registers.UC_X86_REG_R11,
            Registers.UC_X86_REG_R12, Registers.UC_X86_REG_R13, Registers.UC_X86_REG_R14,
            Registers.UC_X86_REG_R15, Registers.UC_X86_REG_RIP, Registers.UC_X86_REG_EFLAGS
        };

        private static readonly Registers[] EssentialRegistersX86 =
        {
            Registers.UC_X86_REG_EAX, Registers.UC_X86_REG_EBX, Registers.UC_X86_REG_ECX,
            Registers.UC_X86_REG_EDX, Registers.UC_X86_REG_ESI, Registers.UC_X86_REG_EDI,
            Registers.UC_X86_REG_EBP, Registers.UC_X86_REG_ESP, Registers.UC_X86_REG_EIP,
            Registers.UC_X86_REG_EFLAGS
        };

        /// <summary>
        /// Take a snapshot of the current emulator state.
        /// </summary>
        /// <param name="SaveRegions">Specifies whether to save the regions with their bytes or not. stack is always saved.</param>
        /// <returns>return the <see cref="EmulatorSnapshot"/> class which contains the full information about the emulator's state.</returns>
        public EmulatorSnapshot TakeSnapshot()
        {
            if (Disposed || !IsX86Guest)
                return null;

            EmulatorSnapshot Snapshot = new EmulatorSnapshot
            {
                Registers = new Dictionary<Registers, ulong>(),
                MemoryRegions = new Dictionary<ulong, byte[]>(),
                OriginalRegionAddresses = new HashSet<ulong>()
            };

            Registers[] Essential = _binary.Architecture == BinaryArchitecture.x64 ? EssentialRegistersX64 : EssentialRegistersX86;

            foreach (Registers Reg in Essential)
            {
                try { Snapshot.Registers[Reg] = ReadRegister(Reg); }
                catch { continue; }
            }

            foreach (MemoryRegion Region in _memory)
            {
                byte[] Data = _emulator.ReadMemory(Region.BaseAddress, Region.Size);
                Snapshot.MemoryRegions[Region.BaseAddress] = Data;
                Snapshot.OriginalRegionAddresses.Add(Region.BaseAddress);
            }

            return Snapshot;
        }

        /// <summary>
        /// Restore a snapshot from the <see cref="EmulatorSnapshot"/> class.
        /// </summary>
        /// <param name="Snapshot">Snapshot to set the current state to.</param>
        public void RestoreSnapshot(EmulatorSnapshot Snapshot)
        {
            if (Snapshot == null || _emulator.Disposed || Disposed)
                return;

            List<MemoryRegion> RegionsToDelete = new List<MemoryRegion>();

            foreach (MemoryRegion Region in _memory)
            {
                if (!Snapshot.OriginalRegionAddresses.Contains(Region.BaseAddress))
                    RegionsToDelete.Add(Region);
            }

            for (int i = 0; i < RegionsToDelete.Count; i++)
            {
                UnmapMemoryRegion(RegionsToDelete[i].BaseAddress);
            }

            if (Snapshot.Registers != null && Snapshot.Registers.Count > 0)
            {
                foreach (var kvp in Snapshot.Registers)
                {
                    try { WriteRegister(kvp.Key, kvp.Value); }
                    catch { continue; }
                }
            }

            if (Snapshot.MemoryRegions != null && Snapshot.MemoryRegions.Count > 0)
            {
                foreach (var kvp in Snapshot.MemoryRegions)
                {
                    if (kvp.Value != null)
                        _emulator.WriteMemory(kvp.Key, kvp.Value);
                }
            }
        }

        private Dictionary<ulong, byte[]> RegionSnapshots = new Dictionary<ulong, byte[]>();

        private bool SnapMemoryMonitor(BackendMemoryAccessType Type, ulong Address, uint Size, ulong value)
        {
            try
            {
                MemoryRegion Region = new MemoryRegion();
                TryFindMemoryRegion(Address, out Region);

                if (Region.BaseAddress != 0 && !RegionSnapshots.TryGetValue(Region.BaseAddress, out _))
                {
                    RegionSnapshots[Region.BaseAddress] = _emulator.ReadMemory(Region.BaseAddress, Region.Size);
                }
            }
            catch
            {

            }
            return true;
        }

        /// <summary>
        /// Take a lazy snapshot of the current emulator state in which all registers are saved but only parts of the memory that are written will be restored.
        /// </summary>
        /// <returns>return the <see cref="EmulatorSnapshot"/> class which contains the full information about the emulator's state.</returns>
        public EmulatorSnapshot TakeLazySnapshot()
        {
            if (Disposed || !IsX86Guest)
                return null;

            EmulatorSnapshot Snapshot = new EmulatorSnapshot
            {
                Registers = new Dictionary<Registers, ulong>(),
                OriginalRegionAddresses = new HashSet<ulong>(),
                IsLazy = true
            };

            Registers[] Essential = _binary.Architecture == BinaryArchitecture.x64 ? EssentialRegistersX64 : EssentialRegistersX86;

            foreach (Registers Reg in Essential)
            {
                try { Snapshot.Registers[Reg] = ReadRegister(Reg); }
                catch { continue; }
            }

            foreach (MemoryRegion Region in _memory)
            {
                Snapshot.OriginalRegionAddresses.Add(Region.BaseAddress);
            }

            if (SnapMonitor == null)
                SnapMonitor = SnapMemoryMonitor;
            RegionSnapshots.Clear();
            _emulator.AddMemoryHook(0, 0, BackendHookType.MemoryWrite, SnapMonitor);
            return Snapshot;
        }

        /// <summary>
        /// Restore a snapshot from the <see cref="EmulatorSnapshot"/> class.
        /// </summary>
        /// <param name="Snapshot">Snapshot to set the current state to.</param>
        public void RestoreLazySnapshot(EmulatorSnapshot Snapshot)
        {
            if (Snapshot == null || _emulator.Disposed || Disposed || !Snapshot.IsLazy)
                return;


            List<MemoryRegion> RegionsToDelete = new List<MemoryRegion>();

            foreach (MemoryRegion Region in _memory)
            {
                if (!Snapshot.OriginalRegionAddresses.Contains(Region.BaseAddress))
                    RegionsToDelete.Add(Region);
            }

            for (int i = 0; i < RegionsToDelete.Count; i++)
            {
                UnmapMemoryRegion(RegionsToDelete[i].BaseAddress);
            }

            if (Snapshot.Registers != null && Snapshot.Registers.Count > 0)
            {
                foreach (var kvp in Snapshot.Registers)
                {
                    try { WriteRegister(kvp.Key, kvp.Value); }
                    catch { continue; }
                }
            }

            if (RegionSnapshots.Count > 0)
            {
                foreach (var kvp in RegionSnapshots)
                {
                    try
                    {
                        _emulator.WriteMemory(kvp.Key, kvp.Value);
                    }
                    catch
                    {

                    }
                }
            }
        }

        /// <summary>
        /// Emulate a specific function in the binary.
        /// </summary>
        /// <param name="FunctionName">Name of the function to emulate.</param>
        /// <param name="Arguments">Arguments to pass to the function.</param>
        /// <param name="Timeout">Timeout in milliseconds. A value of 0 disables the timeout.</param>
        /// <param name="Count">Instruction count limit. A value of 0 disables the instruction limit.</param>
        /// <param name="Snapshot">Snapshot to return to it's state after emulation.</param>
        /// <returns>returns true if emulation succeeded, false otherwise.</returns>
        public bool EmulateFunction(string FunctionName, ulong[] Arguments = null!, uint Timeout = 0, uint Count = 0, EmulatorSnapshot Snapshot = null, bool LogErrors = true)
        {
            if (Disposed)
                return false;

            // Find the function in the binary
            BinaryFunction Function = Array.Find(_binary.Functions, f => f.FunctionName == FunctionName);
            if (Function.FunctionName == null)
            {
                Utils.LogError($"Function '{FunctionName}' not found in the binary.");
                return false;
            }

            // Set up function arguments according to calling convention
            if (Arguments != null && Arguments.Length > 0)
            {
                if (_binary.Architecture == BinaryArchitecture.x64)
                {
                    if (_binary.FileFormat == BinaryFormat.PE)
                    {
                        // Windows x64 calling convention
                        if (Arguments.Length > 0) _emulator.WriteRegister(Registers.UC_X86_REG_RCX, Arguments[0]);
                        if (Arguments.Length > 1) _emulator.WriteRegister(Registers.UC_X86_REG_RDX, Arguments[1]);
                        if (Arguments.Length > 2) _emulator.WriteRegister(Registers.UC_X86_REG_R8, Arguments[2]);
                        if (Arguments.Length > 3) _emulator.WriteRegister(Registers.UC_X86_REG_R9, Arguments[3]);

                        // Reserve 32 bytes shadow space on stack before pushing additional args
                        ulong RSP = _emulator.ReadRegister(Registers.UC_X86_REG_RSP);
                        RSP -= 32;

                        // Push remaining args left to right
                        for (int i = 4; i < Arguments.Length; i++)
                        {
                            RSP -= 8;
                            _emulator.WriteMemory(RSP, Arguments[i], 8);
                        }
                        RSP -= 8;
                        _emulator.WriteRegister(Registers.UC_X86_REG_RSP, RSP);
                    }
                    else if (_binary.FileFormat == BinaryFormat.ELF)
                    {
                        // System V AMD64 calling convention (Unix/Linux)
                        if (Arguments.Length > 0) _emulator.WriteRegister(Registers.UC_X86_REG_RDI, Arguments[0]);
                        if (Arguments.Length > 1) _emulator.WriteRegister(Registers.UC_X86_REG_RSI, Arguments[1]);
                        if (Arguments.Length > 2) _emulator.WriteRegister(Registers.UC_X86_REG_RDX, Arguments[2]);
                        if (Arguments.Length > 3) _emulator.WriteRegister(Registers.UC_X86_REG_RCX, Arguments[3]);
                        if (Arguments.Length > 4) _emulator.WriteRegister(Registers.UC_X86_REG_R8, Arguments[4]);
                        if (Arguments.Length > 5) _emulator.WriteRegister(Registers.UC_X86_REG_R9, Arguments[5]);

                        ulong RSP = _emulator.ReadRegister(Registers.UC_X86_REG_RSP);

                        // Push remaining args left to right
                        for (int i = 4; i < Arguments.Length; i++)
                        {
                            RSP -= 8;
                            _emulator.WriteMemory(RSP, Arguments[i], 8);
                        }
                        _emulator.WriteRegister(Registers.UC_X86_REG_RSP, RSP);
                    }
                }
                else
                {
                    // Cdecl calling convention (args pushed on stack in reverse order)
                    ulong ESP = _emulator.ReadRegister(Registers.UC_X86_REG_ESP);
                    for (int i = Arguments.Length - 1; i >= 0; i--)
                    {
                        ESP -= 4;
                        _emulator.WriteMemory(ESP, (uint)Arguments[i], 4);
                    }
                    ESP -= 4;
                    _emulator.WriteRegister(Registers.UC_X86_REG_ESP, ESP);
                }
            }

            bool Result = StartEmulation(Function.Address, Function.EndAddress, Timeout, Count, LogErrors);
            if (Snapshot != null)
            {
                if (Snapshot.IsLazy)
                    RestoreLazySnapshot(Snapshot);
                else
                    RestoreSnapshot(Snapshot);
            }
            return Result;
        }

        /// <summary>
        /// Emulate a specific function in the binary.
        /// </summary>
        /// <param name="Function">Function to emulate.</param>
        /// <param name="Arguments">Arguments to pass to the function.</param>
        /// <param name="Timeout">Timeout in milliseconds. A value of 0 disables the timeout.</param>
        /// <param name="Count">Instruction count limit. A value of 0 disables the instruction limit.</param>
        /// <param name="Snapshot">Snapshot to return to it's state after emulation.</param>
        /// <returns>returns true if emulation succeeded, false otherwise.</returns>
        public bool EmulateFunction(BinaryFunction Function, ulong[] Arguments = null!, uint Timeout = 0, uint Count = 0, EmulatorSnapshot Snapshot = null, bool LogErrors = true)
        {
            if (Disposed)
                return false;

            // Set up function arguments according to calling convention
            if (Arguments != null && Arguments.Length > 0)
            {
                if (_binary.Architecture == BinaryArchitecture.x64)
                {
                    if (_binary.FileFormat == BinaryFormat.PE)
                    {
                        // Windows x64 calling convention
                        if (Arguments.Length > 0) _emulator.WriteRegister(Registers.UC_X86_REG_RCX, Arguments[0]);
                        if (Arguments.Length > 1) _emulator.WriteRegister(Registers.UC_X86_REG_RDX, Arguments[1]);
                        if (Arguments.Length > 2) _emulator.WriteRegister(Registers.UC_X86_REG_R8, Arguments[2]);
                        if (Arguments.Length > 3) _emulator.WriteRegister(Registers.UC_X86_REG_R9, Arguments[3]);

                        // Reserve 32 bytes shadow space on stack before pushing additional args
                        ulong RSP = _emulator.ReadRegister(Registers.UC_X86_REG_RSP);
                        RSP -= 32;

                        // Push remaining args left to right
                        for (int i = 4; i < Arguments.Length; i++)
                        {
                            RSP -= 8;
                            _emulator.WriteMemory(RSP, Arguments[i], 8);
                        }
                        RSP -= 8;
                        _emulator.WriteRegister(Registers.UC_X86_REG_RSP, RSP);
                    }
                    else if (_binary.FileFormat == BinaryFormat.ELF)
                    {
                        // System V AMD64 calling convention (Unix/Linux)
                        if (Arguments.Length > 0) _emulator.WriteRegister(Registers.UC_X86_REG_RDI, Arguments[0]);
                        if (Arguments.Length > 1) _emulator.WriteRegister(Registers.UC_X86_REG_RSI, Arguments[1]);
                        if (Arguments.Length > 2) _emulator.WriteRegister(Registers.UC_X86_REG_RDX, Arguments[2]);
                        if (Arguments.Length > 3) _emulator.WriteRegister(Registers.UC_X86_REG_RCX, Arguments[3]);
                        if (Arguments.Length > 4) _emulator.WriteRegister(Registers.UC_X86_REG_R8, Arguments[4]);
                        if (Arguments.Length > 5) _emulator.WriteRegister(Registers.UC_X86_REG_R9, Arguments[5]);

                        ulong RSP = _emulator.ReadRegister(Registers.UC_X86_REG_RSP);

                        // Push remaining args left to right
                        for (int i = 4; i < Arguments.Length; i++)
                        {
                            RSP -= 8;
                            _emulator.WriteMemory(RSP, Arguments[i], 8);
                        }
                        _emulator.WriteRegister(Registers.UC_X86_REG_RSP, RSP);
                    }
                }
                else
                {
                    // Cdecl calling convention (args pushed on stack in reverse order)
                    ulong ESP = _emulator.ReadRegister(Registers.UC_X86_REG_ESP);
                    for (int i = Arguments.Length - 1; i >= 0; i--)
                    {
                        ESP -= 4;
                        _emulator.WriteMemory(ESP, (uint)Arguments[i], 4);
                    }
                    ESP -= 4;
                    _emulator.WriteRegister(Registers.UC_X86_REG_ESP, ESP);
                }
            }

            bool Result = StartEmulation(Function.Address, Function.EndAddress, Timeout, Count, LogErrors);
            if (Snapshot != null)
            {
                RestoreSnapshot(Snapshot);
            }
            return Result;
        }

        /// <summary>
        /// Code address allocated by <see cref="ExecuteCode(byte[], bool)"/> which is used to write code to it then execute.
        /// </summary>
        public ulong CodeAddress = 0;

        /// <summary>
        /// Execute assembly code.
        /// </summary>
        /// <param name="Code">Code to be executed</param>
        /// <param name="StartEmulation">Indicates whether to run the code immediately or install it as the current instruction pointer. When false, a return address is pushed so execution resumes at the original instruction pointer.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        /// <remarks>
        /// this method is mainly used to test for some bugs.
        /// </remarks>
        public bool ExecuteCode(byte[] Code, bool StartEmulation)
        {
            if (Disposed)
                return false;
            if (Code == null || Code.Length == 0)
                throw new NullReferenceException(nameof(Code));

            // Reserve a reusable 2 MB code region for injected test snippets.
            ulong Size = 2 * 1024 * 1024;
            if (CodeAddress == 0)
                CodeAddress = MapUniqueAddress(Size, MemoryProtection.All);

            bool Status;
            if (StartEmulation)
            {
                _emulator.WriteMemory(CodeAddress, Code);
                Status = this.StartEmulation(CodeAddress, CodeAddress + (ulong)Code.Length, 0, 0);
            }
            else
            {
                // Append a RET instruction so execution returns to the saved instruction pointer.
                byte[] NewCode = new byte[Code.Length + 1];
                Buffer.BlockCopy(Code, 0, NewCode, 0, Code.Length);
                NewCode[NewCode.Length - 1] = 0xC3;

                // Push the current instruction pointer as the return address.
                if (_binary.Architecture == BinaryArchitecture.x64)
                {
                    ulong RSP = ReadRegister(Registers.UC_X86_REG_RSP);
                    ulong RIP = ReadRegister(Registers.UC_X86_REG_RIP);
                    RSP -= 8;
                    Status = _emulator.WriteMemory(RSP, RIP);
                }
                else
                {
                    uint ESP = ReadRegister32(Registers.UC_X86_REG_ESP);
                    uint EIP = ReadRegister32(Registers.UC_X86_REG_EIP);
                    ESP -= 4;
                    Status = _emulator.WriteMemory(ESP, EIP);
                }

                if (!Status)
                    return false;

                // Write the generated code into the reusable code region.
                if (!WriteMemory(CodeAddress, NewCode))
                    return false;

                // Transfer execution to the generated code.
                Status = _binary.Architecture == BinaryArchitecture.x64 ? WriteRegister(Registers.UC_X86_REG_RIP, CodeAddress) : WriteRegister(Registers.UC_X86_REG_EIP, CodeAddress);
            }
            return Status;
        }

        /// <summary>
        /// Dispose of resources used by the emulator.
        /// </summary>
        public void Dispose()
        {
            if (!Disposed)
            {
                if (_emulator != null)
                {
                    _emulator.StopEmulation();
                    _emulator.PersistCodeCache();
                    _emulator.Dispose();
                }

                _memory.Clear();
                _freedmemory.Clear();
                _emulator = null;
                _binary = null;
                _memory = null;
                _freedmemory = null;
                Disposed = true;
                GC.SuppressFinalize(this);
            }
        }

        //~BinaryEmulator() => Dispose();
    }
}
