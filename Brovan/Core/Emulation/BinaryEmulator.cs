using System.Runtime.CompilerServices;
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
    [Flags]
    public enum LogFlags
    {
        General = 1 << 0,

        Issues = 1 << 1,

        Syscall = 1 << 2,

        CPUID = 1 << 3,

        RDTSC = 1 << 4,

        RDTSCP = 1 << 5,

        Suspicious = 1 << 6,

        Important = 1 << 7,

        All = General | Issues | Syscall | CPUID | RDTSC | RDTSCP | Suspicious | Important,
    }

    public enum GuestConsoleOutputMode
    {
        Suppressed,

        /// <summary>
        /// Allow safe virtual terminal styling and cursor control, and drop every other escape sequence.
        /// </summary>
        LightEscaped,

        Escaped,

        Raw
    }

    public enum NetworkAccessMode
    {
        None,

        Loopback,

        Full
    }

    public sealed class NetworkAccessPolicy
    {
        private readonly HashSet<IPAddress> AllowedAddresses = new HashSet<IPAddress>();

        public NetworkAccessMode Mode { get; set; }

        /// <summary>
        /// Addresses allowed in addition to the base mode.
        /// </summary>
        public IReadOnlyCollection<IPAddress> Allowed => AllowedAddresses;

        public NetworkAccessPolicy(NetworkAccessMode Mode = NetworkAccessMode.None)
        {
            this.Mode = Mode;
        }

        public static NetworkAccessPolicy Full()
        {
            return new NetworkAccessPolicy(NetworkAccessMode.Full);
        }

        public static NetworkAccessPolicy None()
        {
            return new NetworkAccessPolicy(NetworkAccessMode.None);
        }

        public void AddAllowedAddress(IPAddress Address)
        {
            if (Address == null)
                return;

            AllowedAddresses.Add(NormalizeAddress(Address));
        }

        public bool HasAnyAccess()
        {
            return Mode != NetworkAccessMode.None || AllowedAddresses.Count != 0;
        }

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
        public bool EmulateNetworking;

        /// <summary>
        /// When null, <see cref="EmulateNetworking"/> is used for compatibility.
        /// </summary>
        public NetworkAccessPolicy NetworkPolicy;

        /// <summary>
        /// Causes unimplemented syscalls to return STATUS_SUCCESS instead of STATUS_NOT_SUPPORTED.
        /// </summary>
        public bool FakeUnimplementedSyscalls;

        public LogFlags Flags;

        /// <summary>
        /// Holds every guest thread suspended until another session member resumes the process.
        /// </summary>
        public bool StartSuspended;

        public bool SplitStack;

        public bool HandleInvalidOperations;

        /// <summary>
        /// Specifies a callback used to decide whether invalid memory operations should stop emulation.
        /// </summary>
        public InvalidOperationHandler InvalidOperationsCallback;

        /// <summary>
        /// When set, the syscall handler does not emit its own event messages.
        /// </summary>
        public SyscallNotificationDelegate SyscallNotificationCallback;

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

        public GuestConsoleOutputMode ConsoleOutputMode;

        public bool Debug;

        /// <summary>
        /// Tells the binding to add only instruction hooks, such as syscalls, and the hooks for invalid memory,
        /// invalid instructions and interrupts.
        /// </summary>
        public bool NoHooks;

        public EmulationBackendKind BackendKind;

        /// <summary>Runs guest threads on several host threads at once. Hypervisor backends only.</summary>
        public bool Smp;

        /// <summary>Host threads that run guest code at once. Zero picks a count from the host.</summary>
        public int SmpWorkers;

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
            Smp = true;
#pragma warning restore
        }

        public NetworkAccessPolicy GetNetworkPolicy()
        {
            if (NetworkPolicy != null)
                return NetworkPolicy;

            return EmulateNetworking ? NetworkAccessPolicy.Full() : NetworkAccessPolicy.None();
        }
    }

    public partial class BinaryEmulator : IDisposable, IGuestMemory
    {
        internal BinaryFile _binary;

        internal IEmulationBackend _emulator;

        internal List<MemoryRegion> _memory = new();
        // Sorted and coalesced. Change it only through AddFreedRegion and ConsumeFreedMemoryRange.
        internal List<FreedRange> _freedmemory = new();
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

        private List<EmulatedThread> WakeScanList = new();
        private List<EmulatedThread> WakeScanMerged = new();
        private List<EmulatedThread> WakeScanWoken = new();
        private List<EmulatedThread> WakeScanRound = new();
        private bool WakeScanIterating;
        private int IndexedThreadOrderCount;
        private long NextThreadOrderKey;
        private bool ThreadOrderHasDead;
        private const int MaxWakeScanRounds = 8;
        private static readonly Comparer<EmulatedThread> _orderKeyComparer = Comparer<EmulatedThread>.Create((A, B) => A.OrderKey.CompareTo(B.OrderKey));

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
        public readonly ulong BaseAddress = 0x10000000UL;

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

        // MaxAddress is inclusive on x64 and exclusive on x86.
        public ulong UserAddressEnd => AlignUp(MaxAddress, PageSize);
        private const int IdleWaitSliceMs = 5;

        // Held by every host thread that touches emulator state. A hypervisor backend releases it only for
        // the time a processor spends in the guest, see IEmulationBackend.UseRunLock.
        internal readonly object KernelLock = new();

        private bool SmpEnabled;
        private volatile bool SchedulerExiting;
        private int IdleWorkers;
        private int ParkWaiters;
        private int DispatchedThreads;
        private int SmpWorkerCount;
        private ulong _schedulerTotal;
        private uint _schedulerSlices;
        private ulong _schedulerPendingInstructions;

        private const int IdleWaitBackstopMs = 50;
        private const int SweepIntervalMs = 1;
        private const int SchedulerThreadStackSize = 4 * 1024 * 1024;

        private bool IdleWaitSkipped;

        private long ParkedEpoch;
        private readonly ManualResetEventSlim SweepKick = new(false);

        // An idle worker sleeps until a producer or the sweeper pulses it. The timeout is only a backstop
        // against a lost pulse.
        private void IdleWait(int Milliseconds, long PassEpoch, long PassHostEpoch)
        {
            if (!SmpEnabled)
            {
                // A bump from the pass itself ends one wait, never two in a row. A host bump always ends it.
                IdleWaitSkipped = IdleWaitSkipped
                    ? !WakeSignal.WaitPastHost(PassHostEpoch, Milliseconds)
                    : !WakeSignal.WaitPast(PassEpoch, Milliseconds);
                return;
            }

            IdleWorkers++;
            if (IdleWorkers == SmpWorkerCount)
            {
                ParkedEpoch = PassEpoch;
                SweepKick.Set();
            }

            Monitor.Wait(KernelLock, IdleWaitBackstopMs);
            IdleWorkers--;
        }

        // A dispatched thread is invisible to every scan, so a worker leaving its slice by any route, an
        // escaping exception included, has to give it back.
        private void ReleaseDispatch(SchedulerWorker Worker)
        {
            EmulatedThread Dispatched = Worker.DispatchedThread;
            if (Dispatched == null)
                return;

            Worker.DispatchedThread = null;
            Dispatched.HostWorker = -1;
            DispatchedThreads--;
            if (ParkWaiters != 0)
                Monitor.PulseAll(KernelLock);
        }

        private void WakeIdleWorker()
        {
            if (ParkWaiters != 0)
                Monitor.PulseAll(KernelLock);
            else
                Monitor.Pulse(KernelLock);
        }

        // Timed wakes have no producer, so one thread wakes an idle worker every SweepIntervalMs. While every
        // worker is parked, a bump wakes one at once. A running worker serves its own bumps.
        private void SweepLoop()
        {
            bool Pulse = true;
            while (!SchedulerExiting)
            {
                bool AllIdle;
                long Observed;
                SweepKick.Reset();
                lock (KernelLock)
                {
                    if (Pulse && IdleWorkers != 0)
                    {
                        WakeIdleWorker();
                        ParkedEpoch = WakeSignal.Current;
                    }

                    AllIdle = IdleWorkers == SmpWorkerCount;
                    Observed = ParkedEpoch;
                }

                if (AllIdle)
                {
                    WakeSignal.WaitPast(Observed, SweepIntervalMs);
                    Pulse = true;
                }
                else
                {
                    Pulse = !SweepKick.Wait(SweepIntervalMs);
                }
            }
        }

        private void SignalSchedulerExit()
        {
            SchedulerExiting = true;
            _emulator.StopAllProcessors();
            Monitor.PulseAll(KernelLock);
        }

        private static Thread StartSchedulerThread(string Name, ThreadStart Body)
        {
            Thread Started = new Thread(Body, SchedulerThreadStackSize)
            {
                IsBackground = true,
                Name = Name
            };
            Started.Start();
            return Started;
        }

        private int ResolveSmpWorkerCount()
        {
            int Requested = Settings.SmpWorkers > 0 ? Settings.SmpWorkers : Math.Max(1, Environment.ProcessorCount - 1);

            // One processor stays free, so a thread past the limit can always evict a parked one.
            int Limit = _emulator.ProcessorLimit - 1;
            return Math.Max(1, Math.Min(Requested, Limit));
        }

        // NT answers a context request on a running thread only once it reaches a safe point. False means it
        // never reached one, so the saved context is not the one it runs on.
        internal bool WaitUntilParked(EmulatedThread Thread)
        {
            if (!SmpEnabled || Thread == null || Thread.HostWorker == -1 || ReferenceEquals(Thread, CurrentThread))
                return true;

            _emulator.StopThread(Thread.ThreadId);

            EmulatedThread Self = CurrentThread;
            if (Self != null)
            {
                Self.ParkTarget = Thread;
                Self.ParkWaiting = true;
            }
            ParkWaiters++;
            try
            {
                long Deadline = System.Diagnostics.Stopwatch.GetTimestamp() + System.Diagnostics.Stopwatch.Frequency / 4;
                while (Thread.HostWorker != -1 && !SchedulerExiting)
                {
                    // Two threads inspecting each other are both inside a handler, so neither parks.
                    if (Self != null && Thread.ParkWaiting && ReferenceEquals(Thread.ParkTarget, Self))
                        return false;
                    if (System.Diagnostics.Stopwatch.GetTimestamp() >= Deadline)
                        return false;

                    Monitor.Wait(KernelLock, 1);
                }

                return Thread.HostWorker == -1;
            }
            finally
            {
                ParkWaiters--;
                if (Self != null)
                {
                    Self.ParkWaiting = false;
                    Self.ParkTarget = null;
                }
            }
        }

        // The console thread's view of the guest follows the thread it last ran once the workers are gone.
        private void ReselectCurrentThread()
        {
            SchedulerWorker Main = _mainWorker;
            if (Main.CurrentThreadId == -1 && Main.LastThreadId != -1)
                Main.CurrentThreadId = Main.LastThreadId;

            EmulatedThread Current = CurrentThread;
            if (Current == null || Current.Context == null)
                return;

            if (!_emulator.IsThreadResident(Current.ThreadId) && Current.State != EmulatedThreadState.Terminated && BindThreadProcessor(Current))
            {
                _emulator.SelectThread(Current.ThreadId);
                LoadContext(Current, true);
                CurrentContextSaved = true;
                return;
            }

            _emulator.SelectThread(Current.ThreadId);
        }

        // A producer completes the waiters it woke before its own slice resumes. The thread it runs on is
        // dispatched, so the scan skips it and its worker checks it after the slice.
        private void ScanWakeupsAfterCallback(long EpochBeforeCallback)
        {
            if (!SmpEnabled || MlfqLevels == 0 || WakeSignal.Current == EpochBeforeCallback
                || WakeSignal.Current == LastScannedWakeEpoch)
                return;

            UpdateMlfqWakeups(MlfqReadyQueues, MlfqQueuedThreads, MlfqLevels, MlfqSchedulerTick);
        }

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

        internal long GetEmulatedSystemTimeFileTimeUtc()
        {
            if (EmulatedTickCount64 > (long.MaxValue - EmulatedSystemTimeBaseFileTimeUtc) / 10000)
                return long.MaxValue;

            return EmulatedSystemTimeBaseFileTimeUtc + (EmulatedTickCount64 * 10000);
        }

        internal long CreateEmulatedDeadlineMilliseconds(long Milliseconds)
        {
            if (Milliseconds <= 0)
                return EmulatedTickCount64;

            if (Milliseconds == long.MaxValue || EmulatedTickCount64 > long.MaxValue - Milliseconds)
                return long.MaxValue;

            return EmulatedTickCount64 + Milliseconds;
        }

        internal bool IsEmulatedDeadlineExpired(long Deadline)
        {
            return Deadline != -1 && Deadline != long.MaxValue && EmulatedTickCount64 >= Deadline;
        }

        internal static bool IsDeadlineExpired(long Deadline, long Now)
        {
            return Deadline != -1 && Deadline != long.MaxValue && Now >= Deadline;
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
                : HostTicks / HostFrequency * QpcFrequency + HostTicks % HostFrequency * QpcFrequency / HostFrequency;

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

        public event MessageHandler OnMessage;

        internal readonly Dictionary<uint, EmulatedThread> Threads = new();

        private bool StartSuspendedApplied;

        private bool StartSuspendedReleased;
        internal readonly List<int> ThreadOrder = new();
        internal int NextThreadId = 1;
        internal volatile bool EscapeScheduler;
        private int TerminationRequested;

        internal int CurrentThreadId { get => Worker.CurrentThreadId; set => Worker.CurrentThreadId = value; }
        private bool SchedulerRefreshRequested { get => Worker.RefreshRequested; set => Worker.RefreshRequested = value; }

        // Threads keeps a terminated entry while something still refers to it, so a thread-id lookup made
        // with a handle open stays valid. ThreadOrder is the live set.
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

        // Never lowered. Windows releases the request when the process exits.
        private static bool _hostTimerPeriodRaised;

        private sealed class SchedulerWorker
        {
            public readonly BinaryEmulator Owner;
            public readonly int Index;
            public int CurrentThreadId = -1;
            public int LastThreadId = -1;
            public EmulatedThread CurrentThreadCache;
            public bool ContextSaved;
            public bool RefreshRequested;
            public bool SuppressStatusWrite;
            public bool WakeupScanRequired;
            public EmulatedThread DispatchedThread;
            public ulong[] GprScratch;

            public SchedulerWorker(BinaryEmulator Owner, int Index)
            {
                this.Owner = Owner;
                this.Index = Index;
            }
        }

        [ThreadStatic]
        private static SchedulerWorker t_worker;
        private SchedulerWorker _mainWorker;

        private SchedulerWorker Worker
        {
            get
            {
                SchedulerWorker Bound = t_worker;
                return Bound != null && ReferenceEquals(Bound.Owner, this) ? Bound : _mainWorker;
            }
        }

        private void BindMainWorker()
        {
            _mainWorker = new SchedulerWorker(this, 0);
            t_worker = _mainWorker;
        }

        private EmulatedThread CurrentThreadCache { get => Worker.CurrentThreadCache; set => Worker.CurrentThreadCache = value; }

        private bool CurrentContextSaved { get => Worker.ContextSaved; set => Worker.ContextSaved = value; }

        internal EmulatedThread CurrentThread
        {
            get
            {
                SchedulerWorker W = Worker;
                int tid = W.CurrentThreadId;
                if (tid == -1) return null;
                EmulatedThread Cached = W.CurrentThreadCache;
                if (Cached != null && (int)Cached.ThreadId == tid)
                    return Cached;
                if (Threads.TryGetValue((uint)tid, out EmulatedThread t))
                { W.CurrentThreadCache = t; return t; }
                W.CurrentThreadCache = null;
                return null;
            }
        }

        internal TGuest GetGuest<TGuest>() where TGuest : class, IGuestEnvironment
        {
            return Guest as TGuest;
        }

        public BinaryEmulator(BinaryFile Binary, BinaryEmulatorSettings Settings)
        {
            if (Binary == null || Binary.Location == null)
                throw new NullReferenceException("The binary cannot be null.");

            if (Binary.FileFormat == BinaryFormat.Unknown)
                throw new BadImageFormatException("Unknown file format used.");

            if (Binary.Architecture == BinaryArchitecture.Unknown)
                throw new BadImageFormatException("Unsupported binary architecture.");

            BindMainWorker();
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

        public BinaryEmulator(IGuestEnvironment Guest, BinaryEmulatorSettings Settings, Mode mode, Arch arch, BinaryFile Binary)
        {
            if (Binary == null)
                throw new NullReferenceException(nameof(Binary));

            BindMainWorker();
            _binary = Binary;
            BackendArch = arch;
            BackendMode = mode;
            GeneralHelper.IO.Wow64FileRedirect = Binary.FileFormat == BinaryFormat.PE && Binary.Architecture == BinaryArchitecture.x86;
            GuestImagePath = ResolveGuestImagePath(_binary, Guest);
            _emulator = BackendFactory.Create(Settings.BackendKind, arch, mode, Settings.NoHooks, GuestImagePath, _binary.Location);
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

        internal void TriggerDebugMessage(string Message)
        {
            if (Debug && (Settings.Flags & LogFlags.General) != 0)
                TriggerEventMessage($"[DBG] {Message}", LogFlags.General);
        }

        private const ulong PageSize = 0x1000;

        public static ulong AlignUp(ulong Value, ulong Align)
        {
            return (Value + Align - 1) & ~(Align - 1);
        }

        private static bool RegionsOverlap(ulong ABase, ulong ASize, ulong BBase, ulong BSize)
        {
            ulong AEnd = GetRangeEnd(ABase, ASize);
            ulong BEnd = GetRangeEnd(BBase, BSize);
            return ABase < BEnd && AEnd > BBase;
        }

        private void ConsumeFreedMemoryRange(ulong Address, ulong Size)
        {
            if (Size == 0 || _freedmemory.Count == 0)
                return;

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
                FreedRange Freed = _freedmemory[i];
                ulong FreedEnd = GetRangeEnd(Freed.BaseAddress, Freed.Size);

                if (Freed.BaseAddress >= End)
                    break;

                if (!RegionsOverlap(Address, Size, Freed.BaseAddress, Freed.Size))
                    continue;

                bool KeepLeft = Address > Freed.BaseAddress;
                bool KeepRight = End < FreedEnd;

                if (KeepLeft)
                    _freedmemory[i] = new FreedRange(Freed.BaseAddress, Address - Freed.BaseAddress);

                if (KeepRight)
                {
                    FreedRange Right = new FreedRange(End, FreedEnd - End);
                    if (KeepLeft)
                        _freedmemory.Insert(++i, Right);
                    else
                        _freedmemory[i] = Right;
                }

                if (!KeepLeft && !KeepRight)
                    _freedmemory.RemoveAt(i--);
            }
        }

        internal void AddMemoryRegion(MemoryRegion Region)
        {
            int idx = _memory.BinarySearch(Region, _memoryRegionBaseComparer);
            if (idx < 0) idx = ~idx;
            _memory.Insert(idx, Region);
        }

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

        internal void RemoveMemoryRegionAt(int Index)
        {
            _memory.RemoveAt(Index);
        }

        internal int RemoveMemoryRegions(Predicate<MemoryRegion> Match)
        {
            return _memory.RemoveAll(Match);
        }

        internal void SetMemoryRegion(int Index, MemoryRegion Region)
        {
            if (Index < 0 || Index >= _memory.Count)
                return;

            ulong OldBase = _memory[Index].BaseAddress;
            _memory[Index] = Region;

            if (Region.BaseAddress != OldBase)
                _memory.Sort(_memoryRegionBaseComparer);
        }

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

        internal bool TryFindMemoryRegionIndex(ulong Address, out int Index)
        {
            Index = -1;

            Span<MemoryRegion> Regions = CollectionsMarshal.AsSpan(_memory);

            int Left = 0;
            int Right = Regions.Length - 1;
            int Candidate = -1;

            while (Left <= Right)
            {
                int Middle = Left + ((Right - Left) >> 1);

                if (Regions[Middle].BaseAddress <= Address)
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

            ref MemoryRegion Found = ref Regions[Candidate];
            ulong End = GetRangeEnd(Found.BaseAddress, Found.Size);
            if (Address >= Found.BaseAddress && Address < End)
            {
                Index = Candidate;
                return true;
            }

            return false;
        }

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

        internal IEnumerable<MemoryRegion> EnumerateMemoryRegionsByBase()
        {
            for (int i = 0; i < _memory.Count; i++)
                yield return _memory[i];
        }

        // NT splits these: a reserved-only region counts towards the virtual size and not the committed size.
        internal void SumGuestMemoryUsage(out ulong VirtualSize, out ulong CommittedSize)
        {
            ulong Reserved = 0;
            ulong Committed = 0;

            for (int i = 0; i < _memory.Count; i++)
            {
                MemoryRegion Region = _memory[i];
                Reserved += Region.Size;

                if (Region.IsCommitted)
                    Committed += Region.Size;
            }

            VirtualSize = Reserved;
            CommittedSize = Committed;
        }

        internal int FindFirstRegionStartingBefore(ulong Address)
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
        /// True when any region overlaps the range. Reserved-only regions count, so this is not a commit check.
        /// </summary>
        public bool IsRegionInUse(ulong Address, ulong Size)
        {
            return TryFindOverlappingMemoryRegion(Address, Size, out _);
        }

        internal bool TryFindFreeBaseAddress(ulong Size, ulong Alignment, ulong MinAddress, ulong MaxAddress, out ulong Result)
        {
            Result = 0;
            if (Size == 0 || Alignment == 0 || Size > MaxAddress)
                return false;

            ulong Limit = MaxAddress - Size;
            ulong Candidate = AlignUp(MinAddress, Alignment);
            if (Candidate < MinAddress || Candidate > Limit)
                return false;

            ReadOnlySpan<MemoryRegion> Regions = CollectionsMarshal.AsSpan(_memory);
            int First = Math.Max(FindFirstRegionStartingBefore(Candidate), 0);

            // A window of up to two alignment units never gallops, so it gets a loop without the gallop branch.
            ulong GallopBelow = Size >> 1;
            if (GallopBelow <= Alignment)
            {
                for (int i = First; i < Regions.Length; i++)
                {
                    ref readonly MemoryRegion Region = ref Regions[i];

                    ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);
                    if (RegionEnd <= Candidate)
                        continue;

                    if (Region.BaseAddress > Candidate && Region.BaseAddress - Candidate >= Size)
                        break;

                    ulong Next = AlignUp(RegionEnd, Alignment);
                    if (Next < RegionEnd || Next > Limit)
                        return false;

                    Candidate = Next;
                }
            }
            else
            {
                for (int i = First; i < Regions.Length; i++)
                {
                    ref readonly MemoryRegion Region = ref Regions[i];

                    ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);
                    if (RegionEnd <= Candidate)
                        continue;

                    if (Region.BaseAddress > Candidate && Region.BaseAddress - Candidate >= Size)
                        break;

                    ulong Next = AlignUp(RegionEnd, Alignment);
                    if (Next - Candidate < GallopBelow)
                    {
                        i = GallopLastRegionStartingBefore(Regions, i, Candidate + Size, out RegionEnd);
                        Next = AlignUp(RegionEnd, Alignment);
                    }

                    if (Next < RegionEnd || Next > Limit)
                        return false;

                    Candidate = Next;
                }
            }

            Result = Candidate;
            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GallopLastRegionStartingBefore(ReadOnlySpan<MemoryRegion> Regions, int First, ulong Address, out ulong LastEnd)
        {
            int Last = First;
            int Step = 1;
            while (Step < Regions.Length - Last && Regions[Last + Step].BaseAddress < Address)
            {
                Last += Step;
                LastEnd = GetRangeEnd(Regions[Last].BaseAddress, Regions[Last].Size);
                if (LastEnd >= Address)
                    return Last;

                Step = Last - First;
            }

            for (Step >>= 1; Step > 0; Step >>= 1)
            {
                if (Step < Regions.Length - Last && Regions[Last + Step].BaseAddress < Address)
                    Last += Step;
            }

            LastEnd = GetRangeEnd(Regions[Last].BaseAddress, Regions[Last].Size);
            return Last;
        }

        public bool IsRegionCommitted(ulong Address, ulong Size)
        {
            if (Size == 0)
                return true;

            ulong End = GetRangeEnd(Address, Size);
            ulong Current = Address;

            while (Current < End)
            {
                if (!TryFindMemoryRegion(Current, out MemoryRegion Region) || (Region.IsReserved && !Region.IsCommitted))
                    return false;

                ulong RegionEnd = GetRangeEnd(Region.BaseAddress, Region.Size);
                if (RegionEnd <= Current)
                    return false;

                Current = RegionEnd;
            }

            return true;
        }

        /// <param name="Address">Address to map memory at, or 0 for auto-allocation.</param>
        /// <returns>The page-aligned base of the mapping, or 0 on failure.</returns>
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
                    if (Debug)
                        TriggerDebugMessage($"memory: mapped base=0x{AlignedAddress:X} size=0x{Size:X} aligned=0x{AlignedSize:X} prot={Protection}");
                    return AlignedAddress;
                }

                if (Debug)
                    TriggerDebugMessage($"memory: map failed base=0x{AlignedAddress:X} size=0x{AlignedSize:X} prot={Protection} error={GetLastError()}");
                return 0;
            }
            else
            {
                return MapUniqueAddress(Size, Protection);
            }
        }

        public ulong MapUniqueAddress(ulong Size, MemoryProtection Protection)
        {
            ulong AlignedSize = AlignToPageSize(Size);
            ulong SearchFrom = BaseAddress;
            while (TryFindFreeBaseAddress(AlignedSize, PageSize, SearchFrom, MaxAddress, out ulong CurrentAddress))
            {
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
                    if (Debug)
                        TriggerDebugMessage($"memory: mapped unique base=0x{CurrentAddress:X} size=0x{Size:X} aligned=0x{AlignedSize:X} prot={Protection}");
                    return CurrentAddress;
                }

                SearchFrom = CurrentAddress + AlignedSize;
            }

            if (Debug)
                TriggerDebugMessage($"memory: unique map failed size=0x{AlignedSize:X} prot={Protection}");
            return 0;
        }

        /// <summary>
        /// True when any byte of the range is in a region. It does not prove that the whole range is mapped.
        /// </summary>
        public bool IsRegionMapped(ulong Address, ulong Size)
        {
            return TryFindOverlappingMemoryRegion(Address, Size, out _);
        }

        public IntPtr GetHostPointer(ulong Address, ulong Size)
        {
            return _emulator.GetHostPointer(Address, Size);
        }

        /// <param name="WholeMemory">True matches an address inside a freed range, false only the start of one.</param>
        public bool IsRegionFreed(ulong BaseAddress, bool WholeMemory)
        {
            if (_freedmemory.Count == 0)
                return false;

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
                FreedRange r = _freedmemory[cand];
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

        public bool UnmapMemoryRegion(ulong Address, bool UnmapImage = false)
        {
            if (Address == 0)
                return false;

            if (!TryFindMemoryRegion(Address, out MemoryRegion Region) || Region.BaseAddress != Address)
            {
                if (Debug)
                    TriggerDebugMessage($"memory: unmap failed, base not found 0x{Address:X}");
                return false;
            }

            if (!UnmapImage && Region.Flags.HasFlag(AllocationType.Image))
            {
                if (Debug)
                    TriggerDebugMessage($"memory: unmap denied image base=0x{Address:X} size=0x{Region.Size:X}");
                return false;
            }

            bool HostBacked = Region.IsCommitted || !Region.IsReserved;
            if (HostBacked && !_emulator.UnmapMemory(Address, AlignToPageSize(Region.Size)))
            {
                if (Debug)
                    TriggerDebugMessage($"memory: unmap failed base=0x{Address:X} size=0x{Region.Size:X} error={GetLastError()}");
                return false;
            }

            RemoveMemoryRegion(Region);
            AddFreedRegion(Region.BaseAddress, Region.Size);
            if (Debug)
                TriggerDebugMessage($"memory: unmapped base=0x{Address:X} size=0x{Region.Size:X}");
            return true;
        }

        public void AddFreedRegion(ulong BaseAddress, ulong Size)
        {
            if (BaseAddress == 0 || Size == 0)
                return;

            ulong Start = BaseAddress;
            ulong End = BaseAddress + Size;

            int lo = 0, hi = _freedmemory.Count - 1, firstTouch = _freedmemory.Count;
            while (lo <= hi)
            {
                int mid = lo + ((hi - lo) >> 1);
                ulong midEnd = _freedmemory[mid].BaseAddress + _freedmemory[mid].Size;
                if (midEnd >= Start)
                {
                    firstTouch = mid;
                    hi = mid - 1;
                }
                else
                {
                    lo = mid + 1;
                }
            }

            int lastTouch = firstTouch;
            for (; lastTouch < _freedmemory.Count && _freedmemory[lastTouch].BaseAddress <= End; lastTouch++)
            {
                FreedRange Region = _freedmemory[lastTouch];
                Start = Math.Min(Start, Region.BaseAddress);
                End = Math.Max(End, Region.BaseAddress + Region.Size);
            }

            FreedRange Merged = new FreedRange(Start, End - Start);
            if (lastTouch == firstTouch)
            {
                _freedmemory.Insert(firstTouch, Merged);
                return;
            }

            _freedmemory[firstTouch] = Merged;
            if (lastTouch - firstTouch > 1)
                _freedmemory.RemoveRange(firstTouch + 1, lastTouch - firstTouch - 1);
        }

        public ulong GetSuitableBaseAddress(ulong Size, ulong Alignment)
        {
            ulong AlignedSize = AlignToPageSize(Size);
            ulong SearchFrom = BaseAddress;

            while (TryFindFreeBaseAddress(AlignedSize, Alignment, SearchFrom, MaxAddress, out ulong Candidate))
            {
                if (!IsRegionFreed(Candidate, WholeMemory: false))
                    return Candidate;

                SearchFrom = Candidate + Alignment;
            }

            return 0;
        }

        private void PrivilegedInstructionHandler()
        {
            SchedulerRefreshRequested = true;
            if (Debug)
                TriggerDebugMessage($"cpu: privileged instruction at 0x{ReadRegister(IPRegister):X}");
            Guest.HandlePrivilegedInstruction(this);
        }

        private void InvalidInstructionHandler()
        {
            SchedulerRefreshRequested = true;
            if (Debug)
                TriggerDebugMessage($"cpu: invalid instruction at 0x{ReadRegister(IPRegister):X}");
            Guest.HandleInvalidInstruction(this);
        }

        private void InterruptHandler(uint interrupt_number)
        {
            if (Debug)
                TriggerDebugMessage($"cpu: interrupt 0x{interrupt_number:X} at 0x{ReadRegister(IPRegister):X}");
            long EpochBeforeCallback = WakeSignal.Current;
            try
            {
                // An unhandled vector leaves IP on the faulting instruction, which re-faults forever.
                if (!Guest.TryHandleInterrupt(this, interrupt_number) && (Settings.Flags & LogFlags.Issues) != 0)
                    TriggerEventMessage($"[-] Unhandled CPU interrupt 0x{interrupt_number:X} at 0x{ReadRegister(IPRegister):X}.", LogFlags.Issues);
            }
            catch (Exception ex)
            {
                SchedulerRefreshRequested = true;
                Utils.LogError($"[GuestInterrupt] Error: {ex.Message}");
            }

            ScanWakeupsAfterCallback(EpochBeforeCallback);
        }

        /// <summary>
        /// Makes a thread that the running thread woke runnable. Real hardware runs the woken thread on another
        /// core at once. A waker whose slice can be capped keeps running, because it usually wakes more threads
        /// or blocks soon. Otherwise its slice ends here, so the woken thread does not wait for the full quantum.
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
            if (Debug)
                TriggerDebugMessage($"cpu: synthetic instruction stop nextIp=0x{NextIp:X}");
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

        // A backend with a real TSC answers from it, so a thread's clock never steps into another domain.
        private ulong ReadGuestTimestampCounter()
        {
            if (!_emulator.TimestampCounterIsEmulated && _emulator.TryReadTimestampCounter(out ulong Counter) && Counter != 0)
                return Counter;

            return GetEmulatedTimestampCounter();
        }

        private bool RDTSC_Handler()
        {
            ulong IP = ReadRegister(IPRegister);
            ulong ticks = ReadGuestTimestampCounter();

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
            ulong ticks = ReadGuestTimestampCounter();

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
            SaveFloatingPointState(t.Context);
        }

        private void SaveFloatingPointState(CpuContext c)
        {
            _emulator.ReadVectorState(c.Xmm, c.YmmHigh);
            _emulator.ReadX87State(c.X87, ref c.FPSW, ref c.FPTAG);
            c.MXCSR = ReadRegister(Registers.UC_X86_REG_MXCSR);
            c.FPCW = ReadRegister(Registers.UC_X86_REG_FPCW);
        }

        private void LoadFloatingPointState(CpuContext c)
        {
            _emulator.WriteVectorState(c.Xmm, c.YmmHigh);
            _emulator.WriteX87State(c.X87, c.FPSW, c.FPTAG);
            WriteRegister(Registers.UC_X86_REG_MXCSR, c.MXCSR);
            WriteRegister(Registers.UC_X86_REG_FPCW, c.FPCW);
        }

        public bool ReadThreadVectorState(EmulatedThread t, ulong[] xmm, ulong[] ymmHigh)
        {
            if (t == null || t.Context == null) return false;
            EmulatedThread current = CurrentThread;
            if (ReferenceEquals(t, current))
                return _emulator.ReadVectorState(xmm, ymmHigh);

            if (_emulator.IsThreadResident(t.ThreadId))
            {
                _emulator.SelectThread(t.ThreadId);
                bool read = _emulator.ReadVectorState(xmm, ymmHigh);
                if (current != null) _emulator.SelectThread(current.ThreadId);
                return read;
            }

            Array.Copy(t.Context.Xmm, xmm, t.Context.Xmm.Length);
            Array.Copy(t.Context.YmmHigh, ymmHigh, t.Context.YmmHigh.Length);
            return true;
        }

        // SaveContext does not copy MXCSR and FPCW out of a resident thread's processor.
        public void RefreshThreadFpControl(EmulatedThread t)
        {
            EmulatedThread current = CurrentThread;
            if (t == null || t.Context == null || ReferenceEquals(t, current) || !_emulator.IsThreadResident(t.ThreadId))
                return;

            _emulator.SelectThread(t.ThreadId);
            t.Context.MXCSR = ReadRegister(Registers.UC_X86_REG_MXCSR);
            t.Context.FPCW = ReadRegister(Registers.UC_X86_REG_FPCW);
            if (current != null) _emulator.SelectThread(current.ThreadId);
        }

        public void StoreThreadFpControl(EmulatedThread t)
        {
            EmulatedThread current = CurrentThread;
            if (t == null || t.Context == null || ReferenceEquals(t, current) || !_emulator.IsThreadResident(t.ThreadId))
                return;

            _emulator.SelectThread(t.ThreadId);
            WriteRegister(Registers.UC_X86_REG_MXCSR, t.Context.MXCSR);
            WriteRegister(Registers.UC_X86_REG_FPCW, t.Context.FPCW);
            if (current != null) _emulator.SelectThread(current.ThreadId);
        }

        public bool WriteThreadVectorState(EmulatedThread t, ulong[] xmm, ulong[] ymmHigh)
        {
            if (t == null || t.Context == null) return false;
            Array.Copy(xmm, t.Context.Xmm, t.Context.Xmm.Length);
            Array.Copy(ymmHigh, t.Context.YmmHigh, t.Context.YmmHigh.Length);

            EmulatedThread current = CurrentThread;
            if (ReferenceEquals(t, current))
                return _emulator.WriteVectorState(xmm, ymmHigh);

            if (!_emulator.IsThreadResident(t.ThreadId))
                return true;

            _emulator.SelectThread(t.ThreadId);
            bool written = _emulator.WriteVectorState(xmm, ymmHigh);
            if (current != null) _emulator.SelectThread(current.ThreadId);
            return written;
        }

        public bool ReadGprBatch(CpuContext c)
        {
            if (c == null) return false;
            int[] Regs = GetGprBatchRegs();
            ulong[] Vals = Worker.GprScratch ??= new ulong[GprBatchCount];
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
            ulong[] Vals = Worker.GprScratch ??= new ulong[GprBatchCount];
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
                LoadFloatingPointState(t.Context);
            Guest.OnThreadContextLoaded(this, t);
        }

        private void SwitchToThread(int ThreadId, bool BoundThisSwitch = false)
        {
            if (!Threads.TryGetValue((uint)ThreadId, out EmulatedThread next))
                return;
            EmulatedThread cur = CurrentThreadCache;
            if (!SmpEnabled && cur != null && !CurrentContextSaved && cur.State != EmulatedThreadState.Terminated)
                SaveContext(cur);
            CurrentContextSaved = false;
            CurrentThreadId = ThreadId;
            CurrentThreadCache = next;
            bool FirstResidentLoad = BoundThisSwitch || (!_emulator.IsThreadResident(next.ThreadId) && BindThreadProcessor(next));
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
                if (Other.State == EmulatedThreadState.Terminated && Other.HostWorker == -1)
                    _emulator.UnbindThread(Other.ThreadId);

            if (_emulator.TryBindThread(Thread.ThreadId))
                return true;

            if (EvictLeastRecentlyRunProcessor(Thread) && _emulator.TryBindThread(Thread.ThreadId))
                return true;

            _threadProcessorsExhausted = true;
            return false;
        }

        // A resident thread's saved context has no vector state, so read the victim's before eviction.
        private bool EvictLeastRecentlyRunProcessor(EmulatedThread Thread)
        {
            EmulatedThread Victim = null;
            for (int i = 0; i < ThreadOrder.Count; i++)
            {
                if (!Threads.TryGetValue((uint)ThreadOrder[i], out EmulatedThread Candidate))
                    continue;
                if (ReferenceEquals(Candidate, Thread) || Candidate.HostWorker != -1 || Candidate.Context == null || !_emulator.IsThreadResident(Candidate.ThreadId))
                    continue;
                if (Victim == null || Candidate.LastRunTick < Victim.LastRunTick)
                    Victim = Candidate;
            }

            if (Victim == null)
                return false;

            _emulator.SelectThread(Victim.ThreadId);
            SaveFloatingPointState(Victim.Context);
            _emulator.UnbindThread(Victim.ThreadId);
            return true;
        }

        internal void ReleaseThreadProcessor(EmulatedThread Thread)
        {
            if (!_emulator.IsThreadResident(Thread.ThreadId))
                return;
            _emulator.UnbindThread(Thread.ThreadId);
            _threadProcessorsExhausted = false;
        }

        public List<EmulatedThread> GetThreadsSnapshot()
        {
            List<EmulatedThread> Snapshot = new List<EmulatedThread>(Threads.Count);
            foreach (var Thread in Threads.Values)
                Snapshot.Add(Thread);

            Snapshot.Sort((a, b) => a.ThreadId.CompareTo(b.ThreadId));
            return Snapshot;
        }

        public bool TryGetThread(uint ThreadId, out EmulatedThread Thread)
        {
            return Threads.TryGetValue(ThreadId, out Thread);
        }

        public bool TrySwitchToThread(uint ThreadId)
        {
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.Context == null)
                return false;

            if (Thread.State == EmulatedThreadState.Terminated || Thread.HostWorker != -1)
                return false;

            CurrentContextSaved = false;
            SwitchToThread((int)ThreadId);
            return CurrentThreadId == (int)ThreadId;
        }

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
        /// Releases the threads that <see cref="BinaryEmulatorSettings.StartSuspended"/> holds. For a process
        /// created suspended, this is what a resume of its initial thread means.
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

        public bool TryResumeThread(uint ThreadId, out int PreviousSuspendCount)
        {
            PreviousSuspendCount = 0;
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                return false;

            ResumeThread(Thread, out PreviousSuspendCount);
            SchedulerRefreshRequested = true;
            return true;
        }

        public bool TryTerminateThread(uint ThreadId, int ExitCode = 0)
        {
            if (!Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                return false;

            if (CurrentThreadId == (int)ThreadId && Thread.Context != null)
                SaveContext(Thread);
            else
                WaitUntilParked(Thread);

            UnfileWait(Thread);
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
            else
            {
                _emulator.StopThread(Thread.ThreadId);
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
                UnfileWait(Thread);
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
            if (Thread == null || Thread.HostWorker != -1)
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

            UnfileWait(Thread);
            Guest.OnThreadWaitSatisfied(this, Thread);

            Thread.WaitActive = false;
            Thread.WaitHandles = null;
            Thread.WaitDeadline = -1;
            Thread.WaitAll = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;
            Thread.State = EmulatedThreadState.Ready;
        }

        private bool UpdateMlfqThreadWakeup(EmulatedThread Thread, Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick, long Now, long ScanEpoch, ref long EarliestDeadline)
        {
            bool Changed = false;

            if (Thread == null || Thread.HostWorker != -1)
                return false;

            if (Thread.State == EmulatedThreadState.Suspended && Thread.SuspendCount == 0)
            {
                if (Debug)
                    TriggerDebugMessage($"scheduler: resumed suspended tid={Thread.ThreadId}");

                Thread.State = EmulatedThreadState.Ready;
                Changed = true;
            }
            else if (Thread.State == EmulatedThreadState.Waiting && Thread.WaitActive)
            {
                bool Check = !CanSkipWaitCheck(Thread, Now);
                if (Check && TrySatisfyThreadWait(Thread, Now))
                {
                    CompleteThreadWait(Thread);
                    Changed = true;
                }
                else
                {
                    if (Check)
                        NoteWaitCheckFailed(Thread, ScanEpoch);

                    if (TryFileWait(Thread, Now))
                        return false;
                }
            }

            if (Thread.State == EmulatedThreadState.Waiting && Thread.WaitActive && Thread.WaitDeadline != -1 && Thread.WaitDeadline < EarliestDeadline)
                EarliestDeadline = Thread.WaitDeadline;

            EnqueueMlfqThread(Thread, ReadyQueues, InQueue, Levels, SchedulerTick);
            return Changed;
        }

        private bool UpdateMlfqWakeups(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick)
        {
            // Read before the timer refresh, so a timer that signals inside this scan counts as later.
            long ScanEpoch = WakeSignal.Current;
            bool Changed = RefreshWindowsTimersAndWakeWaiters();
            long EarliestDeadline = long.MaxValue;
            long Now = EmulatedTickCount64;

            IndexNewThreads();

            WakeScanIterating = true;
            UnfileWokenWaits(Now);
            if (Now - LastFiledWaitSweepTick >= FiledWaitSweepIntervalMs)
                SweepFiledWaits(Now);

            (WakeScanWoken, WakeScanRound) = (WakeScanRound, WakeScanWoken);
            WakeScanRound.Sort(_orderKeyComparer);

            List<EmulatedThread> Merged = WakeScanMerged;
            int Listed = 0;
            int Woken = 0;
            while (Listed < WakeScanList.Count || Woken < WakeScanRound.Count)
            {
                EmulatedThread Thread = Woken >= WakeScanRound.Count || (Listed < WakeScanList.Count && WakeScanList[Listed].OrderKey < WakeScanRound[Woken].OrderKey)
                    ? WakeScanList[Listed++]
                    : WakeScanRound[Woken++];

                Changed |= VisitWakeScanThread(Thread, ReadyQueues, InQueue, Levels, SchedulerTick, Now, ScanEpoch, ref EarliestDeadline, out bool Keep);
                if (Keep)
                    Merged.Add(Thread);
            }

            WakeScanMerged = WakeScanList;
            WakeScanMerged.Clear();
            WakeScanList = Merged;
            WakeScanRound.Clear();

            // A visit can signal objects with filed waiters.
            long Served;
            int Rounds = 0;
            while (true)
            {
                Served = WakeSignal.Current;
                UnfileWokenWaits(Now);
                if (WakeScanWoken.Count == 0)
                    break;

                (WakeScanWoken, WakeScanRound) = (WakeScanRound, WakeScanWoken);
                if (++Rounds > MaxWakeScanRounds)
                {
                    for (int i = 0; i < WakeScanRound.Count; i++)
                        InsertByOrderKey(WakeScanList, WakeScanRound[i]);
                    WakeScanRound.Clear();
                    Served = ScanEpoch;
                    break;
                }

                WakeScanRound.Sort(_orderKeyComparer);
                for (int i = 0; i < WakeScanRound.Count; i++)
                {
                    EmulatedThread Thread = WakeScanRound[i];
                    Changed |= VisitWakeScanThread(Thread, ReadyQueues, InQueue, Levels, SchedulerTick, Now, ScanEpoch, ref EarliestDeadline, out bool Keep);
                    if (Keep)
                        InsertByOrderKey(WakeScanList, Thread);
                }

                WakeScanRound.Clear();
            }

            WakeScanIterating = false;

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

            EarliestWaitDeadline = Math.Min(EarliestFiledDeadline, EarliestDeadline);
            LastScannedWakeEpoch = Served;
            LastFullWakeupScanTick = EmulatedTickCount64;
            SlicesSinceFullWakeupScan = 0;

            return Changed;
        }

        private bool VisitWakeScanThread(EmulatedThread Thread, Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick, long Now, long ScanEpoch, ref long EarliestDeadline, out bool Keep)
        {
            bool Changed = false;
            if (Thread.State == EmulatedThreadState.Terminated && Thread.HostWorker == -1)
                ThreadOrderHasDead = true;
            else if (!IsWaitFiled(Thread))
                Changed = UpdateMlfqThreadWakeup(Thread, ReadyQueues, InQueue, Levels, SchedulerTick, Now, ScanEpoch, ref EarliestDeadline);

            Keep = Thread.State != EmulatedThreadState.Terminated && !IsWaitFiled(Thread);
            if (!Keep)
                Thread.InWakeScanList = false;

            return Changed;
        }

        internal void AddToWakeScan(EmulatedThread Thread)
        {
            if (Thread == null || Thread.InWakeScanList)
                return;

            if (Thread.State == EmulatedThreadState.Terminated)
            {
                ThreadOrderHasDead = true;
                return;
            }

            if (Thread.OrderKey == 0)
                Thread.OrderKey = ++NextThreadOrderKey;

            Thread.InWakeScanList = true;
            if (WakeScanIterating)
                WakeScanWoken.Add(Thread);
            else
                InsertByOrderKey(WakeScanList, Thread);
        }

        private static void InsertByOrderKey(List<EmulatedThread> List, EmulatedThread Thread)
        {
            int Count = List.Count;
            if (Count == 0 || List[Count - 1].OrderKey < Thread.OrderKey)
            {
                List.Add(Thread);
                return;
            }

            int Index = List.BinarySearch(Thread, _orderKeyComparer);
            List.Insert(Index < 0 ? ~Index : Index, Thread);
        }

        private static void SortByOrderKeyDistinct(List<EmulatedThread> List)
        {
            List.Sort(_orderKeyComparer);

            int Kept = 0;
            for (int i = 0; i < List.Count; i++)
            {
                if (Kept != 0 && ReferenceEquals(List[Kept - 1], List[i]))
                    continue;

                List[Kept++] = List[i];
            }

            List.RemoveRange(Kept, List.Count - Kept);
        }

        // While the scheduler runs, ThreadOrder only grows at its end and only TrimDeadThreadsFromOrder removes
        // from it. Returns the WakeScanList index of the first added thread.
        private int IndexNewThreads()
        {
            if (IndexedThreadOrderCount > ThreadOrder.Count)
            {
                RebuildWakeScan();
                return 0;
            }

            int First = WakeScanList.Count;
            for (int i = IndexedThreadOrderCount; i < ThreadOrder.Count; i++)
            {
                if (Threads.TryGetValue((uint)ThreadOrder[i], out EmulatedThread Thread) && Thread != null && !Thread.InWakeScanList)
                {
                    Thread.OrderKey = ++NextThreadOrderKey;
                    AddToWakeScan(Thread);
                }
            }

            IndexedThreadOrderCount = ThreadOrder.Count;
            return First;
        }

        // The debugger can rewrite ThreadOrder while the scheduler is stopped.
        private void RebuildWakeScan()
        {
            UnfileAllWaits();

            for (int i = 0; i < WakeScanList.Count; i++)
                WakeScanList[i].InWakeScanList = false;

            foreach (EmulatedThread Thread in Threads.Values)
            {
                if (Thread == null)
                    continue;

                Thread.InWakeScanList = false;
                Thread.OrderKey = 0;
            }

            WakeScanList.Clear();
            WakeScanWoken.Clear();
            NextThreadOrderKey = 0;
            IndexedThreadOrderCount = 0;
            IndexNewThreads();
        }

        private bool TryGetNextWaitSleepMs(out int SleepMs, int MaxSleepMs = 10)
        {
            SleepMs = 0;

            long Now = EmulatedTickCount64;
            long BestDelta = FiledDeadlineCount != 0 ? EarliestFiledDeadline - Now : long.MaxValue;
            if (BestDelta <= 0)
                return true;

            for (int i = 0; i < WakeScanList.Count; i++)
            {
                EmulatedThread Thread = WakeScanList[i];
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
            ThreadOrderHasDead = false;
            for (int i = ThreadOrder.Count - 1; i >= 0; i--)
            {
                int Tid = ThreadOrder[i];
                if (!Threads.TryGetValue((uint)Tid, out EmulatedThread Thread) || Thread == null || Thread.State == EmulatedThreadState.Terminated)
                {
                    ThreadOrder.RemoveAt(i);
                    if (i < IndexedThreadOrderCount)
                        IndexedThreadOrderCount--;
                }
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

            // Any worker still awake reaches the queue within a slice, and a pulse for the same thread costs
            // more in lock contention than the wait it saves. Only a fully parked guest has nobody to reach it.
            if (IdleWorkers != 0 && IdleWorkers == SmpWorkerCount)
                WakeIdleWorker();
        }

        private void EnsureMlfqRunnableThreadsEnqueued(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, long SchedulerTick)
        {
            for (int i = IndexNewThreads(); i < WakeScanList.Count; i++)
                EnqueueMlfqThread(WakeScanList[i], ReadyQueues, InQueue, Levels, SchedulerTick);
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

        // Guest wait deadlines run on host wall time. Emulator overhead keeps short sleepers always expired, so
        // they enter the boosted queues again on every dispatch and strict priority order never reaches a lower
        // queue. A limit on how often a level is skipped gives the lower queues a share of the dispatches.
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
            if (ThreadOrderHasDead)
                TrimDeadThreadsFromOrder();
            IndexNewThreads();

            for (int i = 0; i < WakeScanList.Count; i++)
            {
                EmulatedThread t = WakeScanList[i];
                if (!IsMlfqRunnableThread(t))
                    continue;

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
            RebuildWakeScan();
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

            long AgingThresholdBudget = AgingThresholdSlices <= 0 ? 0 : AgingThresholdSlices;
            int KnownThreadOrderCount = ThreadOrder.Count;

            if (Debug)
                TriggerDebugMessage($"scheduler: start threads={ThreadOrder.Count} levels={Levels} baseQuantum={BaseQuantumInstructions} maxInstructions={MaxTotalInstructions} maxSlices={MaxSlices}");

            if (Settings.StartSuspended && !StartSuspendedApplied && !StartSuspendedReleased)
            {
                StartSuspendedApplied = true;

                foreach (EmulatedThread Thread in Threads.Values)
                    SuspendThread(Thread, out _, false);
            }

            RebuildMlfqReadyQueues(ReadyQueues, InQueue, Levels, 0, AgingThresholdBudget, 1);
            SchedulerRefreshRequested = false;

            // A register written from outside the loop is only captured by a fresh save.
            CurrentContextSaved = false;

            if (!_hostTimerPeriodRaised)
                _hostTimerPeriodRaised = GeneralHelper.BeginHostTimerPeriod();

            _schedulerTotal = 0;
            _schedulerSlices = 0;
            _schedulerPendingInstructions = 0;
            MlfqSchedulerTick = 0;

            SchedulerExiting = false;
            IdleWorkers = 0;
            ParkWaiters = 0;
            DispatchedThreads = 0;
            foreach (EmulatedThread Dispatched in Threads.Values)
                Dispatched.HostWorker = -1;

            SmpEnabled = Settings.Smp && _emulator.SupportsThreadResidency;
            if (!SmpEnabled)
            {
                WakeSignal.BeginServing();
                try
                {
                    return RunSchedulerLoop(ReadyQueues, InQueue, Levels, MaxTotalInstructions, MaxSlices, AgingThresholdSlices, AgingThresholdBudget, KnownThreadOrderCount);
                }
                finally
                {
                    WakeSignal.EndServing();
                    ReleaseDispatch(_mainWorker);
                }
            }

            // Another worker may dispatch the thread before this one switches again, so the context loaded
            // before the run is captured here.
            EmulatedThread Loaded = CurrentThread;
            if (Loaded != null && !CurrentContextSaved && Loaded.State != EmulatedThreadState.Terminated)
                SaveContext(Loaded);
            CurrentContextSaved = true;

            _emulator.UseRunLock(KernelLock);

            int WorkerCount = ResolveSmpWorkerCount();
            SmpWorkerCount = WorkerCount;
            Thread[] Helpers = new Thread[WorkerCount];
            Helpers[0] = StartSchedulerThread("BrovanSchedulerSweep", SweepLoop);
            for (int i = 1; i < WorkerCount; i++)
            {
                SchedulerWorker Extra = new SchedulerWorker(this, i);
                Helpers[i] = StartSchedulerThread($"BrovanScheduler-{i}",
                    () => RunSchedulerWorker(Extra, ReadyQueues, InQueue, Levels, MaxTotalInstructions, MaxSlices, AgingThresholdSlices, AgingThresholdBudget));
            }

            try
            {
                return RunSchedulerWorker(_mainWorker, ReadyQueues, InQueue, Levels, MaxTotalInstructions, MaxSlices, AgingThresholdSlices, AgingThresholdBudget);
            }
            finally
            {
                for (int i = 0; i < Helpers.Length; i++)
                    Helpers[i].Join();
                SmpEnabled = false;
                ReselectCurrentThread();
            }
        }

        private bool RunSchedulerWorker(SchedulerWorker Worker, Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, ulong MaxTotalInstructions, uint MaxSlices, long AgingThresholdSlices, long AgingThresholdBudget)
        {
            t_worker = Worker;
            WakeSignal.BeginServing();
            lock (KernelLock)
            {
                try
                {
                    return RunSchedulerLoop(ReadyQueues, InQueue, Levels, MaxTotalInstructions, MaxSlices, AgingThresholdSlices, AgingThresholdBudget, ThreadOrder.Count);
                }
                catch (Exception ex) when (Worker.Index != 0)
                {
                    Utils.LogError($"[Scheduler] Worker {Worker.Index} stopped on an unhandled {ex.GetType().Name}: {ex.Message}");
                    return false;
                }
                finally
                {
                    ReleaseDispatch(Worker);

                    // Any worker leaving ends the run for all of them.
                    SignalSchedulerExit();
                    WakeSignal.EndServing();
                }
            }
        }

        private bool RunSchedulerLoop(Queue<int>[] ReadyQueues, HashSet<int> InQueue, int Levels, ulong MaxTotalInstructions, uint MaxSlices, long AgingThresholdSlices, long AgingThresholdBudget, int KnownThreadOrderCount)
        {
            const ulong SchedulerRescanInstructions = 1_000_000;
            const long FullWakeupScanIntervalMs = 1;
            const uint FullWakeupScanSliceLimit = 1024;
            SchedulerWorker Self = Worker;
            Self.WakeupScanRequired = true;

            while (true)
            {
                if (SchedulerExiting)
                    return true;

                long SchedulerTick = ++MlfqSchedulerTick;
                long PassEpoch = WakeSignal.Current;
                long PassHostEpoch = WakeSignal.HostCurrent;

                if ((SchedulerTick & 0x7) == 0)
                    _emulator.ResolveCodeCache();

                if (WinHelper != null)
                {
                    OS.Windows.RemoteProcessRequests.Drain(this);

                    if (WinHelper.PipeRequests.Count != 0)
                        WinHelper.PipeRequests.Poll(this);

                    if (WinHelper.AfdRequests.HasWork)
                        WinHelper.AfdRequests.Service(this);
                }

                if (Volatile.Read(ref TerminationRequested) != 0 && Interlocked.Exchange(ref TerminationRequested, 0) != 0)
                {
                    if (WinHelper != null)
                        OS.Windows.NtTerminateJobObject.CloseJobsOfExitingProcess(this);

                    WinHelper?.HideDesktopWindow();
                    StopEmulation();
                }

                bool ThreadOrderChanged = ThreadOrder.Count != KnownThreadOrderCount;
                bool AgingDue = AgingThresholdSlices > 0 && SchedulerTick % AgingThresholdSlices == 0;
                if (AgingDue)
                {
                    RebuildMlfqReadyQueues(ReadyQueues, InQueue, Levels, SchedulerTick, AgingThresholdBudget, 1);
                    KnownThreadOrderCount = ThreadOrder.Count;
                    Self.WakeupScanRequired = false;
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

                    if (Self.WakeupScanRequired || SchedulerRefreshRequested || WakeSignal.Current != LastScannedWakeEpoch || HasFinishedHostIo())
                    {
                        if (Debug)
                            TriggerDebugMessage($"scheduler: wakeup scan required={Self.WakeupScanRequired} refresh={SchedulerRefreshRequested} tick={SchedulerTick}");

                        UpdateMlfqWakeups(ReadyQueues, InQueue, Levels, SchedulerTick);
                        KnownThreadOrderCount = ThreadOrder.Count;
                        SchedulerRefreshRequested = false;
                        Self.WakeupScanRequired = false;
                    }
                }

                if (!TryDequeueMlfqThread(ReadyQueues, InQueue, Levels, out EmulatedThread ImmaBeEmulatedOOO, out int SelectedLevel))
                {
                    UpdateMlfqWakeups(ReadyQueues, InQueue, Levels, SchedulerTick);
                    KnownThreadOrderCount = ThreadOrder.Count;
                    SchedulerRefreshRequested = false;
                    Self.WakeupScanRequired = false;

                    if (!TryDequeueMlfqThread(ReadyQueues, InQueue, Levels, out ImmaBeEmulatedOOO, out SelectedLevel))
                    {
                        if (ThreadOrderHasDead)
                            TrimDeadThreadsFromOrder();
                        KnownThreadOrderCount = ThreadOrder.Count;

                        // A process created suspended has no runnable thread by design, and it still has to serve
                        // session requests until its creator resumes it.
                        if (StartSuspendedApplied && !StartSuspendedReleased)
                        {
                            IdleWait(IdleWaitSliceMs, PassEpoch, PassHostEpoch);
                            Self.WakeupScanRequired = true;
                            continue;
                        }

                        // A slice on another worker can still make threads runnable.
                        if (DispatchedThreads != 0)
                        {
                            IdleWait(IdleWaitSliceMs, PassEpoch, PassHostEpoch);
                            Self.WakeupScanRequired = true;
                            continue;
                        }

                        if (!HasLiveMlfqThread())
                        {
                            if (Debug)
                                TriggerDebugMessage($"scheduler: finished no live threads total={_schedulerTotal} slices={_schedulerSlices}");
                            return true;
                        }

                        if (TryGetNextWaitSleepMs(out int SleepMs, int.MaxValue))
                        {
                            if (Debug)
                                TriggerDebugMessage($"scheduler: no runnable thread, waiting up to {SleepMs}ms");
                            IdleWait(Math.Min(SleepMs, IdleWaitSliceMs), PassEpoch, PassHostEpoch);
                            WinHelper?.KuserSharedData?.RefreshIfUnhooked();
                            Self.WakeupScanRequired = true;
                            continue;
                        }

                        if (HasActiveGetMessageWait() || HasPendingHostIo())
                        {
                            IdleWait(IdleWaitSliceMs, PassEpoch, PassHostEpoch);
                            WinHelper?.KuserSharedData?.RefreshIfUnhooked();
                            Self.WakeupScanRequired = true;
                            continue;
                        }

                        if (Debug)
                            TriggerDebugMessage($"scheduler: no runnable thread and no pending wakeup total={_schedulerTotal} slices={_schedulerSlices}");
                        return true;
                    }
                }

                // Without a processor of its own the thread waits for one rather than sharing processor 0.
                bool BoundThisSwitch = false;
                if (SmpEnabled && !_emulator.IsThreadResident(ImmaBeEmulatedOOO.ThreadId))
                {
                    if (!BindThreadProcessor(ImmaBeEmulatedOOO))
                    {
                        EnqueueMlfqThread(ImmaBeEmulatedOOO, ReadyQueues, InQueue, Levels, SchedulerTick);
                        IdleWait(IdleWaitSliceMs, PassEpoch, PassHostEpoch);
                        Self.WakeupScanRequired = true;
                        continue;
                    }

                    BoundThisSwitch = true;
                }

                UnfileWait(ImmaBeEmulatedOOO);
                AddToWakeScan(ImmaBeEmulatedOOO);

                ImmaBeEmulatedOOO.HostWorker = Self.Index;
                Self.DispatchedThread = ImmaBeEmulatedOOO;
                DispatchedThreads++;

                if (CurrentThreadId != (int)ImmaBeEmulatedOOO.ThreadId)
                {
                    if ((Settings.Flags & LogFlags.General) != 0)
                        TriggerEventMessage($"[!] Switching to thread with ID {ImmaBeEmulatedOOO.ThreadId}", LogFlags.General);
                    if (Debug)
                        TriggerDebugMessage($"scheduler: switch {CurrentThreadId} -> {ImmaBeEmulatedOOO.ThreadId} queue={SelectedLevel} state={ImmaBeEmulatedOOO.State} rip=0x{ImmaBeEmulatedOOO.Context?.RIP ?? 0:X}");
                }

                SwitchToThread((int)ImmaBeEmulatedOOO.ThreadId, BoundThisSwitch);

                EmulatedThreadState StateBeforeSlice = ImmaBeEmulatedOOO.State;
                ulong RipBeforeSlice = ImmaBeEmulatedOOO.Context?.RIP ?? 0;
                ImmaBeEmulatedOOO.State = EmulatedThreadState.Running;

                uint QuantumInstructions = MlfqQuanta[Math.Max(0, SelectedLevel)];

                if (Debug && (_schedulerSlices < 64 || (_schedulerSlices & 0xFF) == 0))
                {
                    TriggerDebugMessage($"scheduler: run tid={ImmaBeEmulatedOOO.ThreadId} queue={SelectedLevel} quantum={QuantumInstructions} priority={ImmaBeEmulatedOOO.EffectivePriority} boost={ImmaBeEmulatedOOO.DynamicBoost} rip=0x{RipBeforeSlice:X}");
                }
                bool State = false;
                bool SliceRequestedRefresh = false;

                SchedulerRefreshRequested = false;
                long SliceStart = _wallClock.ElapsedTicks;
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

                ImmaBeEmulatedOOO.RunTicks += _wallClock.ElapsedTicks - SliceStart;
                SaveContext(ImmaBeEmulatedOOO);
                CurrentContextSaved = true;

                ReleaseDispatch(Self);

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
                _schedulerTotal += SchedulerSliceWork;

                bool TimedWaitRescanDue = false;
                if (SchedulerSliceWork > 1)
                {
                    _schedulerPendingInstructions += SchedulerSliceWork;
                    if (_schedulerPendingInstructions >= SchedulerRescanInstructions)
                    {
                        _schedulerPendingInstructions = 0;
                        TimedWaitRescanDue = true;
                    }
                }

                // A guest whose threads all block early never accumulates instructions, so the fallback sweep is
                // bounded by wall time. The slice count is a second bound that does not depend on the clock.
                SlicesSinceFullWakeupScan++;
                if (!TimedWaitRescanDue)
                {
                    long NowTick = EmulatedTickCount64;
                    if (SlicesSinceFullWakeupScan >= FullWakeupScanSliceLimit
                        || (NowTick - LastFullWakeupScanTick >= FullWakeupScanIntervalMs && NowTick >= EarliestWaitDeadline))
                        TimedWaitRescanDue = true;
                }

                _schedulerSlices++;
                WinHelper?.KuserSharedData?.RefreshIfUnhooked();
                ImmaBeEmulatedOOO.LastRunTick = SchedulerTick;

                if (ImmaBeEmulatedOOO.Context?.RIP == 0)
                {
                    if (ImmaBeEmulatedOOO.State != EmulatedThreadState.Terminated)
                    {
                        ImmaBeEmulatedOOO.ExitCode = unchecked((int)(uint)ImmaBeEmulatedOOO.Context!.RAX);

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

                if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Waiting)
                    ImmaBeEmulatedOOO.DynamicBoost = ClampInt(ImmaBeEmulatedOOO.DynamicBoost + 2, -16, 16);
                else if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Exception)
                    ImmaBeEmulatedOOO.DynamicBoost = ClampInt(ImmaBeEmulatedOOO.DynamicBoost - 1, -16, 16);
                else if (ImmaBeEmulatedOOO.State != EmulatedThreadState.Terminated)
                    ImmaBeEmulatedOOO.DynamicBoost = ClampInt(ImmaBeEmulatedOOO.DynamicBoost - 1, -16, 16);

                // Scans skipped the thread while it was dispatched, so its own wait is checked here.
                if (SmpEnabled && ImmaBeEmulatedOOO.State == EmulatedThreadState.Waiting && ImmaBeEmulatedOOO.WaitActive)
                {
                    long EarliestDeadline = EarliestWaitDeadline;
                    UpdateMlfqThreadWakeup(ImmaBeEmulatedOOO, ReadyQueues, InQueue, Levels, SchedulerTick, EmulatedTickCount64, WakeSignal.Current, ref EarliestDeadline);
                    EarliestWaitDeadline = EarliestDeadline;
                }

                if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Ready || ImmaBeEmulatedOOO.State == EmulatedThreadState.Exception)
                    EnqueueMlfqThread(ImmaBeEmulatedOOO, ReadyQueues, InQueue, Levels, SchedulerTick);
                else if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Terminated)
                {
                    // The thread is off its worker now, so a release the terminating side skipped runs here.
                    Guest.OnThreadTerminated(this, ImmaBeEmulatedOOO);
                    ReleaseThreadProcessor(ImmaBeEmulatedOOO);
                    // A thread that ended its own slice stays in the table until the slice is fully over.
                    if (ImmaBeEmulatedOOO.Unreferenced)
                        Threads.Remove(ImmaBeEmulatedOOO.ThreadId);
                    TrimDeadThreadsFromOrder();
                    KnownThreadOrderCount = ThreadOrder.Count;
                }

                if (ImmaBeEmulatedOOO.State == EmulatedThreadState.Waiting && ImmaBeEmulatedOOO.WaitActive
                    && ImmaBeEmulatedOOO.WaitDeadline != -1 && ImmaBeEmulatedOOO.WaitDeadline < EarliestWaitDeadline)
                    EarliestWaitDeadline = ImmaBeEmulatedOOO.WaitDeadline;

                Self.WakeupScanRequired = SliceRequestedRefresh || TimedWaitRescanDue || ThreadOrder.Count != KnownThreadOrderCount;

                if (Debug && (_schedulerSlices <= 64 || (_schedulerSlices & 0xFF) == 0 || ImmaBeEmulatedOOO.State != StateBeforeSlice || SliceRequestedRefresh || TimedWaitRescanDue))
                {
                    TriggerDebugMessage($"scheduler: slice tid={ImmaBeEmulatedOOO.ThreadId} {StateBeforeSlice}->{ImmaBeEmulatedOOO.State} work={SchedulerSliceWork} total={_schedulerTotal} rip=0x{RipBeforeSlice:X}->0x{ImmaBeEmulatedOOO.Context?.RIP ?? 0:X} refresh={SliceRequestedRefresh} rescanDue={TimedWaitRescanDue} boost={ImmaBeEmulatedOOO.DynamicBoost}");
                }

                // Between slices a worker runs no thread, so nothing may treat the parked one as current.
                if (SmpEnabled)
                {
                    Self.LastThreadId = Self.CurrentThreadId;
                    Self.CurrentThreadId = -1;
                    Self.CurrentThreadCache = null;
                }

                if (MaxTotalInstructions != 0 && _schedulerTotal >= MaxTotalInstructions)
                {
                    if (Debug)
                        TriggerDebugMessage($"scheduler: max instruction budget reached total={_schedulerTotal} slices={_schedulerSlices}");
                    return true;
                }
                if (MaxSlices != 0 && _schedulerSlices >= MaxSlices)
                {
                    if (Debug)
                        TriggerDebugMessage($"scheduler: max slice budget reached total={_schedulerTotal} slices={_schedulerSlices}");
                    return true;
                }
            }
        }

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
            long EpochBeforeCallback = WakeSignal.Current;
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

            ScanWakeupsAfterCallback(EpochBeforeCallback);
        }

        public void Start()
        {
            Guest.Start(this);

            // The guest has stopped here. Dispose() is not a reliable hook: the menu's
            // "exit" command calls Environment.Exit.
            _emulator.PersistCodeCache();
        }

        public ulong AlignToPageSize(ulong Size)
        {
            return (Size + 0xFFF) & ~0xFFFUL;
        }

        public bool IsAlignedToPageSize(ulong value)
        {
            return (value & 0xFFFUL) == 0;
        }

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

        public BackendError GetLastError() => _emulator.GetLastError();

        public bool WriteRegister(Registers Register, ulong Value) => _emulator.WriteRegister(Register, Value);

        public bool WriteRegister(int Register, ulong Value) => _emulator.WriteRegister(Register, Value);

        public bool WriteRegister32(Registers Register, uint Value) => _emulator.WriteRegister32(Register, Value);

        public bool WriteRegister32(int Register, uint Value) => _emulator.WriteRegister32(Register, Value);

        public bool WriteRegisterByte(Registers Register, byte Value) => _emulator.WriteRegisterByte(Register, Value);

        public bool WriteRegisterByte(int Register, byte Value) => _emulator.WriteRegisterByte(Register, Value);

        public bool WriteRegisterByte(Registers Register, byte[] Value) => _emulator.WriteRegisterByte(Register, Value);

        public ulong ReadRegister(Registers Register) => _emulator.ReadRegister(Register);

        public ulong ReadRegister(int Register) => _emulator.ReadRegister(Register);

        public uint ReadRegister32(Registers Register) => _emulator.ReadRegister32(Register);

        public uint ReadRegister32(int Register) => _emulator.ReadRegister32(Register);

        public byte ReadRegisterByte(Registers Register) => _emulator.ReadRegisterByte(Register);

        public byte ReadRegisterByte(int Register) => _emulator.ReadRegisterByte(Register);

        public bool WriteMemory(ulong Address, byte[] Data) => _emulator.WriteMemory(Address, Data);

        public bool WriteMemory(ulong Address, ReadOnlySpan<byte> Data) => _emulator.WriteMemory(Address, Data);

        /// <param name="Size">Number of bytes to read, or zero to read the full span.</param>
        public bool ReadMemory(ulong Address, Span<byte> Data, uint Size = 0) => _emulator.ReadMemory(Address, Data, Size);

        public byte[] ReadMemory(ulong Address, uint Size) => _emulator.ReadMemory(Address, Size);

        public ulong ReadMemoryULong(ulong Address) => _emulator.ReadMemoryULong(Address);

        public uint ReadMemoryUInt(ulong Address) => _emulator.ReadMemoryUInt(Address);

        /// <param name="Timeout">Timeout in microseconds, or 0 for none. Only the Unicorn backend applies it.</param>
        /// <param name="Count">Instruction count limit, or 0 for none.</param>
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

        public bool StopEmulation()
        {
            SchedulerRefreshRequested = true;
            if (Debug)
                TriggerDebugMessage($"emu: stop requested threads={Threads.Count}");
            foreach (EmulatedThread EmuThread in Threads.Values)
            {
                EmuThread.State = EmulatedThreadState.Terminated;
            }
            _emulator.StopAllProcessors();
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
        /// Saves the general registers and flags. Each memory region is copied on its first write after this call.
        /// </summary>
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

        /// <param name="Timeout">Timeout in microseconds, or 0 for none. Only the Unicorn backend applies it.</param>
        /// <param name="Count">Instruction count limit, or 0 for none.</param>
        /// <param name="Snapshot">State restored after the run.</param>
        public bool EmulateFunction(string FunctionName, ulong[] Arguments = null!, uint Timeout = 0, uint Count = 0, EmulatorSnapshot Snapshot = null, bool LogErrors = true)
        {
            if (Disposed)
                return false;

            BinaryFunction Function = Array.Find(_binary.Functions, f => f.FunctionName == FunctionName);
            if (Function.FunctionName == null)
            {
                Utils.LogError($"Function '{FunctionName}' not found in the binary.");
                return false;
            }

            SetupCallArguments(Arguments);

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

        /// <param name="Timeout">Timeout in microseconds, or 0 for none. Only the Unicorn backend applies it.</param>
        /// <param name="Count">Instruction count limit, or 0 for none.</param>
        /// <param name="Snapshot">State restored after the run.</param>
        public bool EmulateFunction(BinaryFunction Function, ulong[] Arguments = null!, uint Timeout = 0, uint Count = 0, EmulatorSnapshot Snapshot = null, bool LogErrors = true)
        {
            if (Disposed)
                return false;

            SetupCallArguments(Arguments);

            bool Result = StartEmulation(Function.Address, Function.EndAddress, Timeout, Count, LogErrors);
            if (Snapshot != null)
            {
                RestoreSnapshot(Snapshot);
            }
            return Result;
        }

        private static readonly Registers[] Win64ArgumentRegisters =
        {
            Registers.UC_X86_REG_RCX, Registers.UC_X86_REG_RDX, Registers.UC_X86_REG_R8, Registers.UC_X86_REG_R9
        };

        private static readonly Registers[] SysVArgumentRegisters =
        {
            Registers.UC_X86_REG_RDI, Registers.UC_X86_REG_RSI, Registers.UC_X86_REG_RDX,
            Registers.UC_X86_REG_RCX, Registers.UC_X86_REG_R8, Registers.UC_X86_REG_R9
        };

        private void SetupCallArguments(ulong[] Arguments)
        {
            if (Arguments == null || Arguments.Length == 0)
                return;

            if (_binary.Architecture == BinaryArchitecture.x64)
            {
                Registers[] ArgumentRegisters;
                ulong ShadowSpace;
                if (_binary.FileFormat == BinaryFormat.PE)
                {
                    ArgumentRegisters = Win64ArgumentRegisters;
                    ShadowSpace = 32;
                }
                else if (_binary.FileFormat == BinaryFormat.ELF)
                {
                    ArgumentRegisters = SysVArgumentRegisters;
                    ShadowSpace = 0;
                }
                else
                    return;

                int RegisterCount = Math.Min(Arguments.Length, ArgumentRegisters.Length);
                for (int i = 0; i < RegisterCount; i++)
                    _emulator.WriteRegister(ArgumentRegisters[i], Arguments[i]);

                ulong StackArgumentsSize = (ulong)(Arguments.Length - RegisterCount) * 8;
                ulong CallSiteRsp = (_emulator.ReadRegister(Registers.UC_X86_REG_RSP) - ShadowSpace - StackArgumentsSize) & ~0xFUL;
                ulong StackArguments = CallSiteRsp + ShadowSpace;
                for (int i = RegisterCount; i < Arguments.Length; i++)
                    _emulator.WriteMemory(StackArguments + (ulong)(i - RegisterCount) * 8, Arguments[i], 8);

                _emulator.WriteRegister(Registers.UC_X86_REG_RSP, CallSiteRsp - 8);
            }
            else
            {
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

        /// <summary>
        /// Code region that <see cref="ExecuteCode(byte[], bool)"/> maps on first use and reuses.
        /// </summary>
        public ulong CodeAddress = 0;

        /// <param name="StartEmulation">True runs the code now. False makes it the next instruction and pushes a return address to the current instruction pointer.</param>
        public bool ExecuteCode(byte[] Code, bool StartEmulation)
        {
            if (Disposed)
                return false;
            if (Code == null || Code.Length == 0)
                throw new NullReferenceException(nameof(Code));

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
                byte[] NewCode = new byte[Code.Length + 1];
                Buffer.BlockCopy(Code, 0, NewCode, 0, Code.Length);
                NewCode[NewCode.Length - 1] = 0xC3;

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

                if (!WriteMemory(CodeAddress, NewCode))
                    return false;

                Status = _binary.Architecture == BinaryArchitecture.x64 ? WriteRegister(Registers.UC_X86_REG_RIP, CodeAddress) : WriteRegister(Registers.UC_X86_REG_EIP, CodeAddress);
            }
            return Status;
        }

        public void Dispose()
        {
            if (!Disposed)
            {
                WinHelper?.AfdRequests.Dispose();

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
    }
}
