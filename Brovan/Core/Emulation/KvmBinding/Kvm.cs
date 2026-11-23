using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Buffers;
using Brovan.Core.Emulation;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation
{
    public class KvmException : SystemException
    {
        public int LastError { get; }

        public KvmException(string message) : base(message) { }

        public KvmException(string message, int errno) : base($"{message}: errno={errno}")
        {
            LastError = errno;
        }

        public KvmException() : base("KVM backend exception occurred.") { }
    }

    public sealed class Kvm : IDisposable, IGuestKernelBackend, IGuestPagingBackend, IGuestEntryBackend
    {
        private int _systemFd = -1;
        private int _partitionFd = -1;
        private int _runMmapSize;
        private readonly int _pid;
        private ulong _timestampCounterFrequency;
        private byte[] _cpuidTable;

        private const int DefaultMemslotCount = 32;
        private const int MaxVirtualProcessors = 1024;
        private int _maxMemslots;
        private bool _supportsXsave;
        private bool _supportsVcpuAttributes;
        private bool _supportsPreFault;
        private bool _supportsXcrs;
        private bool _supportsXsave2;
        private int _xsaveSize = 4096;
        private bool _avxEnabled;
        private ulong _cr4Protection;
        private int _ymmHighOffset = 576;
        private bool _populateUnavailable;
        private const ulong PopulateLimitBytes = 32UL * 1024 * 1024;
        private const ulong PopulateMinBytes = 64UL * 1024;
        private const int ResidencyQueryPages = 4096;
        private bool _tscOffsetKnown;
        private ulong _tscOffset;
        private int _nextSlotId;
        private readonly List<int> _freeSlotIds = new();
        private readonly Dictionary<ulong, InstalledSlot> _activeSlots = new();

        private readonly GuestPageMap _mappedPages = new(InternalPages.PageLimit(KvmConstants.InternalPageTableBase));
        private readonly BackingTable<BackingAllocation> _backings = new();
        private readonly BackingFrees<BackingAllocation> _frees;

        // Slots KVM refused to delete. Their host memory is freed only with the partition.
        private readonly List<InstalledSlot> _stillMappedBacking = new();
        private ulong _backingBytes;
        // A page watched for writes only keeps a read-only memslot, so its reads run natively.
        private readonly Dictionary<ulong, bool> _trappedPages = new();

        private bool _mappingsDirty;
        private readonly GuestPaging _paging;
        private readonly Dictionary<ulong, InstalledSlot> _desiredSlots = new();
        private readonly List<ulong> _staleSlotKeys = new();
        private readonly List<DirtyRange> _deletedSlotRanges = new();
        private readonly List<ulong> _activeSlotStarts = new();
        private readonly HashSet<ulong> _keptSlotStarts = new();
        private const int SlotHeadroom = 64;
        private bool HasSlotHeadroom => _activeSlots.Count + _kernelViewSlots.Count + SlotHeadroom < _maxMemslots;
        private bool _fullRebuildRequired = true;
        private readonly List<DirtyRange> _dirtyRanges = new();
        private const int MaxDirtyRanges = 16;
        private ulong _nextInternalGpa = KvmConstants.InternalPageTableBase;

        private IntPtr _internalPoolPtr = IntPtr.Zero;
        private const ulong InternalPoolSize = 16 * 1024 * 1024;
        private ulong _internalPoolOffset;

        private readonly List<(IntPtr Ptr, ulong Size)> _internalPoolFallbacks = new();

        private ulong _syscallTrapPageGpa;
        private GuestKernelHost _guestKernel;
        private readonly Dictionary<ulong, int> _kernelViewSlots = new();
        private ulong _exceptionStubPageGpa;
        private ulong _exceptionIdtPageGpa;
        private ulong _gdtPageGpa;
        private const ulong ExceptionStackPages = 2;

        private readonly record struct UserReturnState(ulong Rip, ulong Rsp, ulong Rflags, LinuxKvmSegment Cs, LinuxKvmSegment Ss);

        private sealed class VirtualProcessor : GuestProcessor
        {
            public Kvm Owner;
            public int Index;
            public int Fd = -1;
            public IntPtr RunPtr;
            public readonly object RegisterLock = new();
            public byte[] XsaveImage;
            public uint ThreadId;
            public ulong GdtPageGpa;
            public ulong TssPageGpa;
            public ulong SyscallStubGpa;
            public IntPtr SyscallSpill;

            // Parked in the trap page with kernel CS/SS, so no segment write reaches the vCPU.
            public bool InSyscallStub;
            public bool SyscallScratchWritten;

            // An MMIO exit stopped a kernel call, which ends after KVM finishes the access.
            public bool KernelCallStopped;
            public ulong KernelCallRip;
            public ulong KernelCallRflags;

            public bool InIretStub;
            public UserReturnState IretReturn;

            public ulong InterruptFrameGpa;
            public IntPtr InterruptFrameHost;

            public ulong DebugFrameGpa;
            public IntPtr DebugFrameHost;

            public bool MmioCompletionPending;
            public bool FaultRegistersSaved;
            public LinuxKvmRegisters FaultRegisters;

            public uint InterruptErrorCode;

            public readonly CachedDebugRegisters DebugRegisterCache = new();

            public volatile bool StopRequested;
            public volatile bool Running;
            public bool TlbFlushOnSyscallReturn;
            public int HostThreadId;
            public int HostTid;
            public bool SingleStepRequested;
            public long SliceDeadlineTimestamp;

            // Bumped when the vCPU leaves a guest thread. A selection made before the bump is stale.
            public long Binding;
        }

        // Trap page: sysretq at 8, CR3 reload and sysretq at 16, hlt at 32 for CSTAR. LSTAR goes to each processor's own
        // syscall stub.
        private const ulong SyscallReturnOffset = 8;
        private const ulong FlushingSyscallReturnOffset = 16;

        private const ulong IretStubOffset = KvmConstants.ExceptionVectorCount * KvmConstants.ExceptionStubStride;

        // The stubs run in 64-bit mode for a 32-bit guest too.
        private static readonly LinuxKvmSegment StubCodeSegment = MakeSegment(KvmConstants.KernelCodeSelector, true, false, code64: true);
        private static readonly LinuxKvmSegment StubStackSegment = MakeSegment(KvmConstants.KernelDataSelector, false, false, code64: false);

        // mov r10, cr3 / mov cr3, r10 / xor r10d, r10d / sysretq. NT returns from a syscall with R10 zero.
        private static readonly byte[] FlushingSyscallReturn =
            { 0x41, 0x0F, 0x20, 0xDA, 0x41, 0x0F, 0x22, 0xDA, 0x45, 0x31, 0xD2, 0x48, 0x0F, 0x07 };
        private const ulong FlushingSysretOffset = FlushingSyscallReturnOffset + 11;

        private readonly bool _guest64;
        private readonly ushort _userCodeSelector;

        // One vCPU per guest thread. A thread that cannot get one waits.
        private readonly List<VirtualProcessor> _processors = new();
        private VirtualProcessor[] _processorSnapshot = Array.Empty<VirtualProcessor>();
        private readonly Stack<VirtualProcessor> _idleProcessors = new();
        private readonly Dictionary<uint, VirtualProcessor> _threadProcessors = new();
        private int _processorLimit;

        [ThreadStatic]
        private static VirtualProcessor t_vp;
        [ThreadStatic]
        private static long t_vpBinding;

        private VirtualProcessor CurrentVp
        {
            get
            {
                VirtualProcessor vp = t_vp;
                return vp != null && ReferenceEquals(vp.Owner, this) && vp.Binding == t_vpBinding
                    ? vp
                    : Volatile.Read(ref _processorSnapshot)[0];
            }
        }

        private static void SelectProcessor(VirtualProcessor vp)
        {
            t_vp = vp;
            t_vpBinding = vp.Binding;
        }

        private readonly GuestEntryGate _gate;

        // KVM cannot end a run after a set instruction count, so a slice is bounded by wall clock.
        private const int BoundedSliceMilliseconds = 10;
        private Thread _maintenanceThread;

        // A vCPU in guest mode leaves only for a signal.
        private static int _kickSignal;
        private static PosixSignalRegistration _kickRegistration;

        private readonly List<MemoryHookEntry> _memoryHooks = new();
        private readonly List<MmioRegion> _mmioRegions = new();
        private InstructionHookEntry _syscallHook;
        private readonly List<InstructionHookEntry> _instructionHooks = new();
        private readonly List<InterruptHookEntry> _interruptHooks = new();
        private readonly List<IntPtr> _liveHookHandles = new();

        private bool _hasCpuIdHook;
        private bool _hasInvalidHook;
        private bool _scanPreRunInstructions;

        private static readonly long MmioRefreshIntervalTicks = Stopwatch.Frequency / 4000;
        private long _lastMmioRefreshTimestamp;

        // A leaf lock. Take it inside the mapping lock, never around it.
        private readonly object _mmioLock = new();

        private int _disposed;
        private int _disposing;

        public bool NoHooks;
        public static bool ThrowDisposed = true;
        public bool Disposed => Volatile.Read(ref _disposed) == 1;

        public bool SupportsXsave => _supportsXsave;
        private bool Disposing => Volatile.Read(ref _disposing) == 1;

        [ThreadStatic]
        private static KvmErrors _error;

        private sealed class BackingAllocation : BackingBlock
        {
            public bool HugePages;
            public ulong GuestBase;
        }

        private struct InstalledSlot
        {
            public int Id;
            public ulong Size;
            public IntPtr Host;
            public uint Flags;
        }

        private struct DirtyRange
        {
            public ulong Start;
            public ulong End;
        }

        private sealed class MemoryHookEntry
        {
            public ulong Begin;
            public ulong End;
            public BackendHookType Type;
            public MemoryHookCallback Callback;
        }

        private sealed class MmioRegion
        {
            public ulong Address;
            public ulong Size;
            public MmioReadCallback ReadCallback;
            public MmioWriteCallback WriteCallback;
        }

        private sealed class InstructionHookEntry
        {
            public BackendInstructionHook Type;
            public InstructionHookCallback Callback;
            public InstructionBoolHookCallback BoolCallback;
        }

        private sealed class InterruptHookEntry
        {
            public InterruptHookCallback Callback;
        }

        private enum GpRegisterName
        {
            Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp, Rip,
            R8, R9, R10, R11, R12, R13, R14, R15, Rflags
        }

        private struct GpRegisterAccess
        {
            public GpRegisterName Name;
            public byte Offset;
            public byte Width;
            public bool ZeroExtend32;

            public readonly bool IsValid => Width != 0;
        }

        public Kvm(Arch arch, Mode mode)
        {
            if (arch != Arch.X86 || (mode != Mode.MODE_64 && mode != Mode.MODE_32))
                throw new KvmException("KVM backend only supports x86 32-bit and x86-64 guests.");

            _gate = new GuestEntryGate(this);
            _paging = new GuestPaging(this, _gate, _mappedPages, KvmConstants.InternalPageTableBase);
            _frees = new BackingFrees<BackingAllocation>(_backings, new FreeSite(this));
            _guest64 = mode == Mode.MODE_64;
            _userCodeSelector = _guest64 ? KvmConstants.UserCodeSelector : KvmConstants.UserCodeSelector32;

            EnsurePlatformSupport();
            _pid = KvmNative.getpid();
            AllocateInternalPool();
            ConfigurePartition();
            InitializeLongModePageTables();
            InitializeGdt();
            InitializeSyscallTrapPage();
            InitializeExceptionHandling();
            SelectProcessor(CreateProcessor(0));
            _timestampCounterFrequency = QueryTimestampCounterFrequency();
            RebuildMappings();
        }

        public KvmErrors GetLastError() => _error;

        public ulong TimestampCounterFrequency => _timestampCounterFrequency;

        private ulong QueryTimestampCounterFrequency()
        {
            if (KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapGetTscKhz) <= 0)
                return 0;
            int khz = KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoGetTscKhz, IntPtr.Zero);
            return khz <= 0 ? 0 : (ulong)khz * 1000;
        }

        public bool TryReadTimestampCounter(out ulong value)
        {
            value = 0;
            if (DisposedCheck())
                return false;

            try
            {
                value = GetMsr(CurrentVp, KvmConstants.MsrTsc);
                return true;
            }
            catch (KvmException)
            {
                return false;
            }
        }

        private static bool IsGuestRange(ulong address, ulong size)
            => InternalPages.IsGuestRange(address, size, KvmConstants.InternalPageTableBase);

        private static bool IsGuestPageRange(ulong address, ulong size)
            => (address & KvmConstants.PageMask) == 0 && (size & KvmConstants.PageMask) == 0 && IsGuestRange(address, size);

        public bool MapMemoryShared(ulong address, ulong size, MemoryProtection protection, IntPtr hostPointer)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck() || hostPointer == IntPtr.Zero) return false;

            if (!IsGuestPageRange(address, size))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            GuestPagePermission perm = TranslateProtection(protection);
            long backingAddr = hostPointer.ToInt64();
            IntPtr backing = IntPtr.Zero;
            BackingAllocation allocation = null;
            bool accessRemoved = false;

            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                IntPtr hostPage = new IntPtr(backingAddr + (long)off);

                if (allocation == null || (ulong)(hostPage.ToInt64() - backing.ToInt64()) >= allocation.Size)
                {
                    backing = _backings.Find(hostPage);
                    if (backing == IntPtr.Zero || !_backings.TryGet(backing, out allocation))
                    {
                        backing = IntPtr.Zero;
                        allocation = null;
                    }
                }

                // Referenced before the replaced page is released, so the last reference cannot drop mid-loop.
                if (allocation != null)
                    allocation.AliasPages++;

                if (_mappedPages.TryGetValue(guest, out GuestPage previous))
                    ReleaseBacking(previous);

                SetGuestPage(guest, new GuestPage
                {
                    HostPage = hostPage,
                    OwnedBacking = backing,
                    IsAlias = true,
                    Permissions = perm,
                });
                accessRemoved |= _paging.SetLeaf(guest, perm);
            }

            if (accessRemoved)
                _gate.ShootDownGuestTlbs();
            RebuildMappings();
            FreeReleasedBackings();
            _error = KvmErrors.Ok;
            return true;
        }

        public IntPtr AllocateSharedStorage(ulong size)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return IntPtr.Zero;

            if (size == 0 || (size & KvmConstants.PageMask) != 0)
            {
                _error = KvmErrors.InvalidArgument;
                return IntPtr.Zero;
            }

            // Section offset 0 lands on a 2 MiB boundary.
            if (!TryAllocateGuestBacking(0, size, out IntPtr backing, out _))
            {
                _error = KvmErrors.NoMemory;
                return IntPtr.Zero;
            }

            _backings.Add(backing, new BackingAllocation { Size = size, Held = true });
            _error = KvmErrors.Ok;
            return backing;
        }

        public IntPtr AdoptSharedStorage(IntPtr hostPointer, ulong size, IDisposable owner)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return IntPtr.Zero;

            if (hostPointer == IntPtr.Zero || owner == null || size == 0 || (size & KvmConstants.PageMask) != 0
                || ((ulong)hostPointer.ToInt64() & KvmConstants.PageMask) != 0 || _backings.Find(hostPointer) != IntPtr.Zero)
            {
                _error = KvmErrors.InvalidArgument;
                return IntPtr.Zero;
            }

            _backings.Add(hostPointer, new BackingAllocation { Size = size, Held = true, Owner = owner });
            _error = KvmErrors.Ok;
            return hostPointer;
        }

        public void ReleaseSharedStorage(IntPtr storage)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return;
            BackingAllocation allocation = _backings.TakeHold(storage);
            if (allocation == null)
                return;

            _frees.FreeIfUnreferenced(storage, allocation);
            _frees.Settle();
        }

        public bool MapMemory(ulong address, ulong size, MemoryProtection protection)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return false;

            if (!IsGuestPageRange(address, size))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            GuestPagePermission perm = TranslateProtection(protection);

            bool canBatch = true;
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                if (_mappedPages.TryGetValue(address + off, out GuestPage existing) && existing.HostPage != IntPtr.Zero)
                {
                    canBatch = false;
                    break;
                }
            }

            if (canBatch && size > 0)
            {
                if (!TryAllocateGuestBacking(address, size, out IntPtr backing, out bool hugePages))
                {
                    _error = KvmErrors.NoMemory;
                    return false;
                }

                long backingAddr = backing.ToInt64();
                _backings.Add(backing, new BackingAllocation
                {
                    Size = size,
                    LivePages = (int)(size / KvmConstants.PageSize),
                    HugePages = hugePages,
                    GuestBase = address,
                });

                for (ulong off = 0; off < size; off += KvmConstants.PageSize)
                {
                    ulong guest = address + off;
                    GuestPage page = new GuestPage
                    {
                        HostPage = new IntPtr(backingAddr + (long)off),
                        OwnedBacking = backing,
                        Permissions = perm,
                    };
                    SetGuestPage(guest, page);
                    _paging.SetLeaf(guest, perm);
                }

                RebuildMappings();
                if (perm != GuestPagePermission.None)
                    PopulateRange(address, size, backing);
                _error = KvmErrors.Ok;
                return true;
            }

            bool accessRemoved = false;
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                _mappedPages.TryGetValue(guest, out GuestPage current);
                IntPtr host = current?.HostPage ?? IntPtr.Zero;
                IntPtr owned = current?.OwnedBacking ?? IntPtr.Zero;
                if (host == IntPtr.Zero)
                {
                    if (!TryAllocateBackingMemory(KvmConstants.PageSize, out IntPtr backing))
                    {
                        if (accessRemoved)
                            _gate.ShootDownGuestTlbs();
                        RebuildMappings();
                        _error = KvmErrors.NoMemory;
                        return false;
                    }

                    _backings.Add(backing, new BackingAllocation
                    {
                        Size = KvmConstants.PageSize,
                        LivePages = 1,
                    });
                    host = backing;
                    owned = backing;
                }

                GuestPage page = new GuestPage
                {
                    HostPage = host,
                    OwnedBacking = owned,
                    IsAlias = current?.IsAlias ?? false,
                    Permissions = perm,
                    WriteRetained = false,
                    WriteWatched = current?.WriteWatched ?? false,
                    Written = current?.Written ?? false,
                    Untouched = current?.Untouched ?? false,
                };
                if (current == null)
                    SetGuestPage(guest, page);
                else
                    _paging.ReplacePage(guest, page);
                MarkSpanDirty(guest, KvmConstants.PageSize);
                accessRemoved |= _paging.SetLeaf(guest, perm);
            }

            if (accessRemoved)
                _gate.ShootDownGuestTlbs();
            RebuildMappings();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool UnmapMemory(ulong address, ulong size)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return false;

            if (!IsGuestPageRange(address, size))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            bool accessRemoved = false;
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                if (_mappedPages.ContainsKey(guest))
                    accessRemoved |= _paging.SetLeaf(guest, GuestPagePermission.None);
            }

            // Shoot down before the backing is freed.
            if (accessRemoved)
                _gate.ShootDownGuestTlbs();

            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                if (_mappedPages.TryGetValue(guest, out GuestPage page))
                {
                    ReleaseBacking(page);
                    RemoveGuestPage(guest);
                }
            }

            lock (_mmioLock)
            {
                for (int i = _mmioRegions.Count - 1; i >= 0; i--)
                {
                    MmioRegion region = _mmioRegions[i];
                    if (region.Address >= address && region.Address < address + size)
                        _mmioRegions.RemoveAt(i);
                }
            }

            RebuildMappings();
            FreeReleasedBackings();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool MapMmio(ulong address, ulong size, MmioReadCallback read, MmioWriteCallback write)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return false;

            if (read == null || write == null ||
                size == 0 || !IsGuestPageRange(address, size))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            if (!MapMemory(address, size, MemoryProtection.Read))
                return false;

            MmioRegion region = new MmioRegion
            {
                Address = address,
                Size = size,
                ReadCallback = read,
                WriteCallback = write,
            };

            lock (_mmioLock)
            {
                _mmioRegions.RemoveAll(r => r.Address == address);
                _mmioRegions.Add(region);
                RefreshMmioRegion(region);
            }

            _error = KvmErrors.Ok;
            return true;
        }

        public bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return false;
            if (!IsGuestRange(address, size))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            GuestPagePermission perm = TranslateProtection(protection);
            bool writable = (perm & GuestPagePermission.Write) != 0;
            bool accessRemoved = false;
            bool writeAdded = false;

            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                if (!_mappedPages.TryGetValue(guest, out GuestPage page) || page.Permissions == perm)
                    continue;

                GuestPagePermission old = page.Permissions;
                bool wasWritable = (old & GuestPagePermission.Write) != 0;

                if (old == GuestPagePermission.None || perm == GuestPagePermission.None || (writable && !MapsWritable(page)))
                    MarkSpanDirty(guest, KvmConstants.PageSize);

                _paging.ReplacePage(guest, page.WithPermissions(perm, page.WriteRetained || wasWritable));

                if (wasWritable == writable && (old == GuestPagePermission.None) == (perm == GuestPagePermission.None))
                    continue;

                accessRemoved |= _paging.SetLeaf(guest, perm);
                writeAdded |= old != GuestPagePermission.None && writable;
            }

            if (accessRemoved)
                _gate.ShootDownGuestTlbs();
            RebuildMappings();

            // Granting write needs no shootdown. A stale read-only entry costs one retried fault.
            if (!accessRemoved && writeAdded)
                CurrentVp.TlbFlushOnSyscallReturn = true;

            _error = KvmErrors.Ok;
            return true;
        }

        // A memslot stays writable once write is granted and the guest PTE holds the current write bit.
        // Removing write then needs no slot split, which deletes and refaults the slot.
        private static bool MapsWritable(GuestPage page)
            => (page.Permissions & GuestPagePermission.Write) != 0 || page.WriteRetained;

        private static uint SlotFlags(GuestPage page)
            => MapsWritable(page) ? 0 : KvmConstants.MemSlotReadOnly;

        public bool WatchWrites(ulong address, ulong size)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            return !DisposedCheck() && SetWatchStatus(_paging.WatchWrites(address, size));
        }

        public bool QueryWrites(ulong address, ulong pageCount, Span<ulong> written)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            return !DisposedCheck() && SetWatchStatus(_paging.QueryWrites(address, pageCount, written));
        }

        public bool ResetWrites(ulong address, ulong pageCount, ReadOnlySpan<ulong> pages)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            return !DisposedCheck() && SetWatchStatus(_paging.ResetWrites(address, pageCount, pages));
        }

        private bool SetWatchStatus(WriteWatchStatus status)
        {
            _error = status switch
            {
                WriteWatchStatus.Ok => KvmErrors.Ok,
                WriteWatchStatus.InvalidArgument => KvmErrors.InvalidArgument,
                _ => KvmErrors.MemoryWriteUnmapped,
            };
            return status == WriteWatchStatus.Ok;
        }

        public void EvictProcessors()
        {
            if (!DisposedCheck())
                _gate.EvictProcessors();
        }

        public ProcessorHold HoldProcessorsOutOfGuest() => DisposedCheck() ? ProcessorHold.None : _gate.HoldProcessorsOutOfGuest();

        GuestProcessor[] IGuestEntryBackend.Processors => Volatile.Read(ref _processorSnapshot);

        void IGuestEntryBackend.Kick(GuestProcessor processor)
        {
            EnsureKickSignal();
            KickProcessor((VirtualProcessor)processor);
        }

        // KVM flushes the guest TLB on a CR4.PGE change, not on an unchanged CR3 write. No page is global.
        private static void FlushGuestTlbOnEntry(ref LinuxKvmRun run)
        {
            run.Sregs.Cr4 ^= ControlRegister4.Pge;
            run.DirtyRegs |= KvmConstants.SyncSpecialRegisters;
        }

        public bool WriteMemory(ulong address, byte[] value, uint length = 0)
        {
            if (DisposedCheck()) return false;
            if (value == null) return false;
            return WriteMemory(address, (ReadOnlySpan<byte>)value, length);
        }

        public unsafe bool WriteMemory(ulong address, byte[] value, int offset, int length)
        {
            if (DisposedCheck()) return false;
            if (value == null) return false;
            if ((uint)offset > (uint)value.Length) return false;
            if (length < 0) return false;

            int remaining = value.Length - offset;
            if (length > remaining) length = remaining;
            if (length == 0) { _error = KvmErrors.Ok; return true; }

            if (TryGetHostPointer(address, length, true, out byte* dst, out long dstOffset))
            {
                _error = KvmErrors.Ok;
                fixed (byte* src = value)
                    Unsafe.CopyBlockUnaligned(dst + dstOffset, src + offset, (uint)length);
                return true;
            }

            if (TryWriteMemoryInternal(address, new ReadOnlySpan<byte>(value, offset, length)))
            {
                _error = KvmErrors.Ok;
                return true;
            }

            _error = KvmErrors.MemoryWriteUnmapped;
            return false;
        }

        public unsafe bool WriteMemory(ulong address, ReadOnlySpan<byte> value, uint length = 0)
        {
            if (DisposedCheck()) return false;
            uint writeLen = ClampLength(length, value.Length);
            if (writeLen == 0) return false;

            if (TryGetHostPointer(address, (int)writeLen, true, out byte* dst, out long offset))
            {
                _error = KvmErrors.Ok;
                fixed (byte* src = value)
                    Unsafe.CopyBlockUnaligned(dst + offset, src, writeLen);
                return true;
            }

            if (TryWriteMemoryInternal(address, value.Slice(0, (int)writeLen)))
            {
                _error = KvmErrors.Ok;
                return true;
            }

            _error = KvmErrors.MemoryWriteUnmapped;
            return false;
        }

        public bool WriteMemory(ulong address, ulong value, uint length = 0)
        {
            Span<byte> buffer = stackalloc byte[sizeof(ulong)];
            BitConverter.TryWriteBytes(buffer, value);
            return WriteMemory(address, buffer, length);
        }

        public bool WriteMemory(ulong address, string value, Encoding encoding)
        {
            if (DisposedCheck()) return false;
            byte[] bytes = encoding.GetBytes(value);
            return WriteMemory(address, bytes);
        }

        public bool WriteMemory(ulong address, uint value, uint length = 0)
        {
            Span<byte> buffer = stackalloc byte[sizeof(uint)];
            BitConverter.TryWriteBytes(buffer, value);
            return WriteMemory(address, buffer, length);
        }

        public bool WriteMemoryByte(ulong address, byte value, uint length = 0)
        {
            if (DisposedCheck()) return false;
            if (length == 0) return false;

            if (length <= 16)
            {
                Span<byte> tiny = stackalloc byte[(int)length];
                tiny.Fill(value);
                return WriteMemory(address, tiny);
            }

            Span<byte> slab = stackalloc byte[256];
            slab.Fill(value);

            ulong current = address;
            uint remaining = length;
            while (remaining != 0)
            {
                int count = (int)Math.Min((uint)slab.Length, remaining);
                if (!WriteMemory(current, slab.Slice(0, count)))
                    return false;
                current += (ulong)count;
                remaining -= (uint)count;
            }

            return true;
        }

        public bool WriteMemory(ulong address, int value, uint length = 0)
        {
            Span<byte> buffer = stackalloc byte[sizeof(int)];
            BitConverter.TryWriteBytes(buffer, value);
            return WriteMemory(address, buffer, length);
        }

        public bool WriteMemory(ulong address, ushort value, uint length = 0)
        {
            Span<byte> buffer = stackalloc byte[sizeof(ushort)];
            BitConverter.TryWriteBytes(buffer, value);
            return WriteMemory(address, buffer, length);
        }

        public byte[] ReadMemory(ulong address, ulong length)
        {
            if (DisposedCheck()) return Array.Empty<byte>();
            if (length > int.MaxValue) return null;
            return ReadMemory(address, (uint)length);
        }

        public unsafe byte[] ReadMemory(ulong address, uint length)
        {
            if (DisposedCheck()) return Array.Empty<byte>();
            if (length > int.MaxValue) return null;
            byte[] value = new byte[length];
            if (length == 0)
            {
                _error = KvmErrors.Ok;
                return value;
            }

            if (TryGetHostPointer(address, (int)length, false, out byte* src, out long offset))
            {
                _error = KvmErrors.Ok;
                Unsafe.CopyBlockUnaligned(ref value[0], ref Unsafe.AsRef<byte>(src + offset), length);
            }
            else if (TryReadMemoryInternal(address, value))
            {
                _error = KvmErrors.Ok;
            }
            else
            {
                _error = KvmErrors.MemoryReadUnmapped;
            }
            return value;
        }

        public unsafe bool ReadMemory(ulong address, Span<byte> value, uint length = 0)
        {
            if (DisposedCheck()) return false;
            uint readLen = ClampLength(length, value.Length);
            if (readLen == 0) return false;

            if (TryGetHostPointer(address, (int)readLen, false, out byte* src, out long offset))
            {
                _error = KvmErrors.Ok;
                fixed (byte* dst = value)
                    Unsafe.CopyBlockUnaligned(dst, src + offset, readLen);
                return true;
            }

            if (TryReadMemoryInternal(address, value.Slice(0, (int)readLen)))
            {
                _error = KvmErrors.Ok;
                return true;
            }

            _error = KvmErrors.MemoryReadUnmapped;
            return false;
        }

        private static uint ClampLength(uint requested, int available)
        {
            if (available <= 0) return 0;
            if (requested == 0 || requested > (uint)available) return (uint)available;
            return requested;
        }

        public unsafe ulong ReadMemoryULong(ulong address)
        {
            if (DisposedCheck()) return 0;
            if (TryGetHostPointer(address, sizeof(ulong), false, out byte* ptr, out long offset))
            {
                _error = KvmErrors.Ok;
                return *(ulong*)(ptr + offset);
            }
            Span<byte> buffer = stackalloc byte[sizeof(ulong)];
            if (TryReadMemoryInternal(address, buffer))
            {
                _error = KvmErrors.Ok;
                return BitConverter.ToUInt64(buffer);
            }
            _error = KvmErrors.MemoryReadUnmapped;
            return 0;
        }

        public unsafe uint ReadMemoryUInt(ulong address)
        {
            if (DisposedCheck()) return 0;
            if (TryGetHostPointer(address, sizeof(uint), false, out byte* ptr, out long offset))
            {
                _error = KvmErrors.Ok;
                return *(uint*)(ptr + offset);
            }
            Span<byte> buffer = stackalloc byte[sizeof(uint)];
            if (TryReadMemoryInternal(address, buffer))
            {
                _error = KvmErrors.Ok;
                return BitConverter.ToUInt32(buffer);
            }
            _error = KvmErrors.MemoryReadUnmapped;
            return 0;
        }

        public unsafe ushort ReadMemoryUShort(ulong address)
        {
            if (DisposedCheck()) return 0;
            if (TryGetHostPointer(address, sizeof(ushort), false, out byte* ptr, out long offset))
            {
                _error = KvmErrors.Ok;
                return *(ushort*)(ptr + offset);
            }
            Span<byte> buffer = stackalloc byte[sizeof(ushort)];
            if (TryReadMemoryInternal(address, buffer))
            {
                _error = KvmErrors.Ok;
                return BitConverter.ToUInt16(buffer);
            }
            _error = KvmErrors.MemoryReadUnmapped;
            return 0;
        }

        public unsafe string ReadMemoryString(ulong address, int length, Encoding encoding)
        {
            if (DisposedCheck()) return null;
            if (address == 0 || length <= 0) return string.Empty;

            byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                if (TryGetHostPointer(address, length, false, out byte* src, out long offset))
                {
                    _error = KvmErrors.Ok;
                    Unsafe.CopyBlockUnaligned(ref buffer[0], ref Unsafe.AsRef<byte>(src + offset), (uint)length);
                }
                else if (TryReadMemoryInternal(address, buffer.AsSpan(0, length)))
                {
                    _error = KvmErrors.Ok;
                }
                else
                {
                    _error = KvmErrors.MemoryReadUnmapped;
                    return string.Empty;
                }

                int bytesRead;
                if (encoding == Encoding.Unicode || encoding == Encoding.BigEndianUnicode)
                {
                    ReadOnlySpan<char> units = MemoryMarshal.Cast<byte, char>(buffer.AsSpan(0, length & ~1));
                    int terminator = units.IndexOf('\0');
                    bytesRead = (terminator >= 0 ? terminator : units.Length) * 2;
                    if (bytesRead == 0) return string.Empty;
                }
                else
                {
                    int terminatorIndex = buffer.AsSpan(0, length).IndexOf((byte)0);
                    bytesRead = terminatorIndex >= 0 ? terminatorIndex : length;
                    if (bytesRead == 0) return string.Empty;
                }

                return encoding.GetString(buffer, 0, bytesRead);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public bool WriteRegister(Registers register, ulong value)
        {
            if (DisposedCheck()) return false;

            if (TryWriteSpecialRegister(register, value))
            {
                _error = KvmErrors.Ok;
                return true;
            }

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid)
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            ref ulong target = ref GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            ulong updated = WriteGpRegisterField(target, access, value);
            NoteSyscallScratchWrite(access.Name, target, updated);
            target = updated;
            MarkRegistersDirty();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool WriteRegister(int register, ulong value) => WriteRegister((Registers)register, value);

        public void SetSyscallReturnRegisters(ulong ReturnRip)
        {
            if (DisposedCheck()) return;

            ref LinuxKvmRegisters regs = ref GetRegistersRef();
            NoteSyscallScratchWrite(GpRegisterName.Rcx, regs.Rcx, ReturnRip);
            NoteSyscallScratchWrite(GpRegisterName.R11, regs.R11, regs.Rflags);
            regs.Rcx = ReturnRip;
            regs.R11 = regs.Rflags;
            SetSyscallReturnVolatiles(ref regs);
            MarkRegistersDirty();
        }

        private static void SetSyscallReturnVolatiles(ref LinuxKvmRegisters regs)
        {
            regs.Rdx = 0;
            regs.R8 = regs.Rsp;
            regs.R9 = 0;
            regs.R10 = 0;
        }

        public bool WriteRegisterBatch(int[] registers, ulong[] values, int count)
        {
            if (DisposedCheck()) return false;
            if (!RegisterBatch.IsValid(registers, values, count))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            if (IsGpBatch(registers, count))
            {
                ref LinuxKvmRegisters regs = ref GetRegistersRef();
                for (int i = 0; i < count; i++)
                {
                    GpRegisterAccess access = ClassifyGpRegister((Registers)registers[i]);
                    ref ulong target = ref GetGpRegisterPointer(ref regs, access.Name);
                    ulong updated = WriteGpRegisterField(target, access, values[i]);
                    NoteSyscallScratchWrite(access.Name, target, updated);
                    target = updated;
                }
                MarkRegistersDirty();
                _error = KvmErrors.Ok;
                return true;
            }

            if (DebugRegisters.IsDebugBatch(registers, count))
            {
                WriteDebugRegisters(registers.AsSpan(0, count), values.AsSpan(0, count));
                _error = KvmErrors.Ok;
                return true;
            }

            if (IsFpControlBatch(registers, count))
            {
                bool transferred = TransferFpControl(registers.AsSpan(0, count), values.AsSpan(0, count), true);
                _error = transferred ? KvmErrors.Ok : KvmErrors.InvalidArgument;
                return transferred;
            }

            bool written = true;
            for (int i = 0; i < count; i++)
                written &= WriteRegister((Registers)registers[i], values[i]);
            return written;
        }

        public bool ReadRegisterBatch(int[] registers, ulong[] values, int count)
        {
            if (DisposedCheck()) return false;
            if (!RegisterBatch.IsValid(registers, values, count))
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            if (IsGpBatch(registers, count))
            {
                ref LinuxKvmRegisters regs = ref GetRegistersRef();
                for (int i = 0; i < count; i++)
                {
                    GpRegisterAccess access = ClassifyGpRegister((Registers)registers[i]);
                    values[i] = ReadGpRegisterField(GetGpRegisterPointer(ref regs, access.Name), access);
                }
                _error = KvmErrors.Ok;
                return true;
            }

            if (DebugRegisters.IsDebugBatch(registers, count))
            {
                LinuxKvmDebugRegisters dr = GetDebugRegisters();
                for (int i = 0; i < count; i++)
                    values[i] = DebugRegisterValue(dr, DebugRegisters.Index((Registers)registers[i]));
                _error = KvmErrors.Ok;
                return true;
            }

            if (IsFpControlBatch(registers, count))
            {
                bool transferred = TransferFpControl(registers.AsSpan(0, count), values.AsSpan(0, count), false);
                _error = transferred ? KvmErrors.Ok : KvmErrors.InvalidArgument;
                return transferred;
            }

            for (int i = 0; i < count; i++)
                values[i] = ReadRegister((Registers)registers[i]);
            return true;
        }

        private static bool IsFpControlBatch(int[] registers, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (!IsFpControlRegister((Registers)registers[i]))
                    return false;
            }
            return true;
        }

        private static bool IsGpBatch(int[] registers, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (!ClassifyGpRegister((Registers)registers[i]).IsValid)
                    return false;
            }
            return true;
        }

        public bool WriteRegister32(Registers register, uint value)
        {
            if (DisposedCheck()) return false;

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid) { _error = KvmErrors.InvalidArgument; return false; }

            ref ulong target = ref GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            ulong updated = access.ZeroExtend32 ? value : WriteGpRegisterField(target, access, value);
            NoteSyscallScratchWrite(access.Name, target, updated);
            target = updated;
            MarkRegistersDirty();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool WriteRegister32(int register, uint value) => WriteRegister32((Registers)register, value);

        public bool WriteRegisterByte(Registers register, byte value)
        {
            if (DisposedCheck()) return false;

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid) { _error = KvmErrors.InvalidArgument; return false; }

            ref ulong target = ref GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            int shift = access.Offset * 8;
            ulong updated = (target & ~(0xFFUL << shift)) | ((ulong)value << shift);
            NoteSyscallScratchWrite(access.Name, target, updated);
            target = updated;
            MarkRegistersDirty();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool WriteRegisterByte(int register, byte value) => WriteRegisterByte((Registers)register, value);

        public bool WriteRegisterByte(Registers register, byte[] value)
        {
            if (value == null || value.Length == 0) return false;
            return WriteRegisterByte(register, value[0]);
        }

        private static ulong WriteGpRegisterField(ulong current, GpRegisterAccess access, ulong value)
        {
            if (access.ZeroExtend32) return (uint)value;
            if (access.Width >= sizeof(ulong)) return value;
            int shift = access.Offset * 8;
            ulong mask = ((1UL << (access.Width * 8)) - 1) << shift;
            return (current & ~mask) | ((value << shift) & mask);
        }

        public ulong ReadRegister(Registers register)
        {
            if (DisposedCheck()) return 0;

            if (TryReadSpecialRegister(register, out ulong specialValue))
            {
                _error = KvmErrors.Ok;
                return specialValue;
            }

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid) { _error = KvmErrors.InvalidArgument; return 0; }

            ulong value = GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            _error = KvmErrors.Ok;
            return ReadGpRegisterField(value, access);
        }

        private static ulong ReadGpRegisterField(ulong current, GpRegisterAccess access)
        {
            int shiftBits = access.Offset * 8;
            int widthBits = access.Width * 8;
            if (widthBits >= sizeof(ulong) * 8) return current >> shiftBits;
            return (current >> shiftBits) & ((1UL << widthBits) - 1);
        }

        public ulong ReadRegister(int register) => ReadRegister((Registers)register);
        public uint ReadRegister32(Registers register) => (uint)ReadRegister(register);
        public uint ReadRegister32(int register) => (uint)ReadRegister((Registers)register);
        public byte ReadRegisterByte(Registers register) => (byte)ReadRegister(register);
        public byte ReadRegisterByte(int register) => (byte)ReadRegister((Registers)register);

        public CPUFlags GetCPUFlags() => (CPUFlags)ReadRegister(Registers.UC_X86_REG_RFLAGS);
        public bool SetCPUFlags(CPUFlags flags) => WriteRegister(Registers.UC_X86_REG_RFLAGS, (ulong)flags);

        public bool Emulate(ulong start, ulong end, uint timeout = 0, uint count = 0)
        {
            if (DisposedCheck()) return false;

            if (_mappingsDirty) RebuildMappings();

            _guestKernel?.Seal();
            VirtualProcessor vp = CurrentVp;
            ref LinuxKvmRun run = ref GetRunRef(vp);

            run.Regs.Rip = start;
            MarkRegistersDirty();

            vp.StopRequested = false;
            vp.MmioCompletionPending = false;
            vp.FaultRegistersSaved = false;
            vp.KernelCallStopped = false;
            vp.SingleStepRequested = count == 1;
            run.ImmediateExit = 0;

            if (vp.HostThreadId != Environment.CurrentManagedThreadId)
            {
                vp.HostThreadId = Environment.CurrentManagedThreadId;
                Volatile.Write(ref vp.HostTid, KvmNative.gettid());
            }

            bool bounded = count != 0;
            if (bounded)
            {
                EnsureMaintenanceThread();
                Volatile.Write(ref vp.SliceDeadlineTimestamp,
                    Stopwatch.GetTimestamp() + (Stopwatch.Frequency * BoundedSliceMilliseconds) / 1000);
            }

            if (vp.SingleStepRequested)
            {
                run.Regs.Rflags |= 0x100UL;
                MarkRegistersDirty();
            }

            bool releaseRunLock = _gate.HoldsRunLock;

            try
            {
                while (true)
                {
                    // Zero means the deadline was consumed, by the timer or by a kick.
                    bool sliceOver = vp.StopRequested || (bounded && Volatile.Read(ref vp.SliceDeadlineTimestamp) == 0);
                    if (sliceOver && !vp.MmioCompletionPending)
                        break;

                    // RIP can only become non-canonical through a register write, which marks it dirty.
                    if ((run.DirtyRegs & KvmConstants.SyncGeneralRegisters) != 0 && !LongModeAddress.IsCanonical(run.Regs.Rip))
                    {
                        if (RaiseNonCanonicalFetch(vp)) continue;
                        return false;
                    }

                    if (HandlePreRunInstruction()) continue;

                    RefreshMmioBackedRegions();

                    bool flushTlb = _gate.NeedsTlbFlush(vp, out long tlbGeneration);

                    if ((run.DirtyRegs & KvmConstants.SyncGeneralRegisters) != 0)
                        run.Regs.Rflags = UserModeFlags.Clamp(run.Regs.Rflags);
                    if (vp.InSyscallStub) PrepareSyscallReturn(vp, ref run, flushTlb || vp.TlbFlushOnSyscallReturn);
                    vp.TlbFlushOnSyscallReturn = false;
                    if (!vp.InSyscallStub && !vp.MmioCompletionPending && (run.DirtyRegs & KvmConstants.SyncGeneralRegisters) != 0
                        && (run.Regs.Rflags & 0x100UL) != 0)
                        PrepareIretReturn(vp, ref run);

                    if (flushTlb)
                    {
                        if (!vp.InSyscallStub) FlushGuestTlbOnEntry(ref run);
                        GuestEntryGate.TlbFlushed(vp, tlbGeneration);
                    }

                    int rc = RunProcessor(vp, releaseRunLock, out int errno);

                    if (vp.InIretStub) CompleteIretReturn(vp, ref run);
                    if (vp.InSyscallStub) CompleteSyscallReturn(vp, ref run, flushTlb);

                    if (vp.MmioCompletionPending)
                    {
                        vp.MmioCompletionPending = false;
                        if (vp.FaultRegistersSaved && (rc < 0 || run.ExitReason != KvmConstants.ExitMmio))
                        {
                            vp.FaultRegistersSaved = false;
                            SetRegisters(vp.FaultRegisters);
                        }
                    }

                    uint exitReason = run.ExitReason;
                    if (rc < 0)
                    {
                        // A host file that shrank under a kernel view leaves pages KVM cannot fault in.
                        if (errno == KvmNative.ErrnoEfault && TryFinishInterruptedKernelCall(vp, ref run, out bool faulted))
                        {
                            if (faulted) continue;
                            return _error == KvmErrors.Ok;
                        }

                        if (errno != KvmNative.ErrnoEintr)
                        {
                            _error = KvmErrors.InternalError;
                            throw new KvmException("KVM_RUN failed", errno);
                        }

                        exitReason = KvmConstants.ExitIntr;
                    }

                    switch (exitReason)
                    {
                        case KvmConstants.ExitHlt:
                            if (HandleHltExit(vp)) continue;
                            return _error == KvmErrors.Ok;
                        case KvmConstants.ExitMmio:
                            if (TryDeferKernelCallExit(vp, ref run))
                                continue;
                            if (!HandleMmioExit(vp, ref run))
                                StopEmulation();
                            continue;
                        case KvmConstants.ExitException:
                            {
                                uint excVector = run.Exit.Exception.Exception;
                                uint excErrorCode = run.Exit.Exception.ErrorCode;
                                bool handled = HandleException(excVector, excErrorCode);
                                ClearPendingExceptionState();
                                if (handled) continue;
                                _error = KvmErrors.Exception;
                                return false;
                            }
                        case KvmConstants.ExitDebug:
                            if (HandleDebugExit(ref run))
                                continue;
                            _error = KvmErrors.Ok;
                            return true;
                        case KvmConstants.ExitIntr:
                            ClearImmediateExit(vp, ref run, bounded);
                            if (TryFinishInterruptedKernelCall(vp, ref run, out bool kickResumed))
                            {
                                if (kickResumed) continue;
                                return _error == KvmErrors.Ok;
                            }
                            if (TryTakeStubEntryAsHalt())
                                goto case KvmConstants.ExitHlt;
                            continue;
                        case KvmConstants.ExitShutdown:
                            _error = KvmErrors.Exception;
                            throw new KvmException($"KVM guest triple-faulted (SHUTDOWN) at RIP 0x{ReadRegister(Registers.UC_X86_REG_RIP):X}");
                        case KvmConstants.ExitFailEntry:
                            _error = KvmErrors.InternalError;
                            throw new KvmException($"KVM vCPU failed to enter guest mode (reason=0x{run.Exit.FailEntry.HardwareEntryFailureReason:X}, cpu={run.Exit.FailEntry.Cpu})");
                        case KvmConstants.ExitInternalError:
                            _error = KvmErrors.InternalError;
                            throw new KvmException($"KVM internal error (suberror={run.Exit.InternalError.Suberror})");
                        default:
                            _error = KvmErrors.InternalError;
                            throw new KvmException($"Unhandled KVM exit reason: {run.ExitReason}");
                    }
                }

                _error = KvmErrors.Ok;
                return true;
            }
            finally
            {
                Volatile.Write(ref vp.SliceDeadlineTimestamp, 0);

                if (vp.SingleStepRequested)
                {
                    vp.SingleStepRequested = false;
                    ClearTrapFlag();
                }
            }
        }

        private int RunProcessor(VirtualProcessor vp, bool releaseRunLock, out int errno)
        {
            int rc;
            vp.Running = true;
            // A run that may not enter goes through KVM_RUN with immediate_exit, so KVM takes the dirty registers and
            // the loop sees an interrupted run, the same as a kick before entry.
            bool entered = _gate.TryEnterGuest(vp, releaseRunLock);
            if (!entered)
                Volatile.Write(ref GetRunRef(vp).ImmediateExit, 1);
            try
            {
                rc = KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoRun, IntPtr.Zero);
                errno = rc < 0 ? Marshal.GetLastWin32Error() : 0;
            }
            finally
            {
                if (entered)
                    _gate.LeaveGuest(vp, releaseRunLock);
                vp.Running = false;
            }
            return rc;
        }

        // KVM never clears immediate_exit, and leaving it set makes every later KVM_RUN return -EINTR.
        private static void ClearImmediateExit(VirtualProcessor vp, ref LinuxKvmRun run, bool bounded)
        {
            if (vp.StopRequested) return;
            if (bounded && Volatile.Read(ref vp.SliceDeadlineTimestamp) == 0) return;

            run.ImmediateExit = 0;
            Interlocked.MemoryBarrier();
            if (bounded && Volatile.Read(ref vp.SliceDeadlineTimestamp) == 0)
                run.ImmediateExit = 1;
        }

        public bool StopEmulation()
        {
            if (DisposedCheck()) return false;

            VirtualProcessor vp = CurrentVp;
            vp.StopRequested = true;
            if (Environment.CurrentManagedThreadId == vp.HostThreadId)
                GetRunRef(vp).ImmediateExit = 1;
            else
                KickProcessor(vp);

            _error = KvmErrors.Ok;
            return true;
        }

        public void UseHost(IBackendHost host)
        {
            _gate.UseHost(host);
            _paging.UseHost(host);
            _frees.UseHost(host);
        }

        public void StopThread(uint threadId)
        {
            if (Disposed || Disposing) return;
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (!_threadProcessors.TryGetValue(threadId, out VirtualProcessor vp)) return;

            vp.StopRequested = true;
            if (vp.Running)
                KickProcessor(vp);
        }

        public void StopAllProcessors()
        {
            if (Disposed || Disposing) return;

            VirtualProcessor[] processors = Volatile.Read(ref _processorSnapshot);
            for (int i = 0; i < processors.Length; i++)
            {
                VirtualProcessor vp = processors[i];
                vp.StopRequested = true;
                if (vp.Running)
                    KickProcessor(vp);
            }
        }

        private void EnsureMaintenanceThread()
        {
            if (Volatile.Read(ref _maintenanceThread) != null)
                return;

            EnsureKickSignal();
            Thread maintenance = new Thread(MaintenanceLoop)
            {
                IsBackground = true,
                Name = "KvmMaintenance"
            };
            if (Interlocked.CompareExchange(ref _maintenanceThread, maintenance, null) == null)
                maintenance.Start();
        }

        private void MaintenanceLoop()
        {
            while (!Disposed && !Disposing)
            {
                EnforceSliceDeadlines();
                Thread.Sleep(1);
            }
        }

        public bool TryLimitSlice(int microseconds)
        {
            VirtualProcessor vp = CurrentVp;
            long limit = Stopwatch.GetTimestamp() + (Stopwatch.Frequency * microseconds) / 1_000_000;
            while (true)
            {
                long deadline = Volatile.Read(ref vp.SliceDeadlineTimestamp);
                if (deadline == 0)
                    return false;
                if (limit >= deadline)
                    return true;
                if (Interlocked.CompareExchange(ref vp.SliceDeadlineTimestamp, limit, deadline) == deadline)
                    return true;
            }
        }

        private void EnforceSliceDeadlines()
        {
            if (Disposed || Disposing)
                return;

            VirtualProcessor[] processors = Volatile.Read(ref _processorSnapshot);
            long now = Stopwatch.GetTimestamp();
            for (int i = 0; i < processors.Length; i++)
            {
                VirtualProcessor vp = processors[i];
                long deadline = Volatile.Read(ref vp.SliceDeadlineTimestamp);
                if (deadline == 0 || now < deadline)
                    continue;

                if (Interlocked.CompareExchange(ref vp.SliceDeadlineTimestamp, 0, deadline) != deadline)
                    continue;

                KickProcessor(vp);
            }
        }

        // immediate_exit stops a run that has not entered the guest yet, the signal stops one that has.
        private void KickProcessor(VirtualProcessor vp)
        {
            Volatile.Write(ref GetRunRef(vp).ImmediateExit, 1);
            Interlocked.MemoryBarrier();

            int tid = Volatile.Read(ref vp.HostTid);
            if (tid != 0)
                KvmNative.tgkill(_pid, tid, _kickSignal);
        }

        private static void EnsureKickSignal()
        {
            if (_kickRegistration != null)
                return;

            lock (typeof(Kvm))
            {
                if (_kickRegistration != null)
                    return;

                // The runtime takes the first real-time signal for itself.
                _kickSignal = KvmNative.__libc_current_sigrtmin() + 1;
                _kickRegistration = PosixSignalRegistration.Create((PosixSignal)_kickSignal, context => context.Cancel = true);
            }
        }

        private const BackendHookType FaultMemoryHookTypes =
            BackendHookType.MemoryUnmapped | BackendHookType.MemoryProtected;

        private const BackendHookType TrappedMemoryHookTypes =
            BackendHookType.MemoryRead | BackendHookType.MemoryWrite | BackendHookType.MemoryReadAfter;

        private const BackendHookType SupportedMemoryHookTypes =
            FaultMemoryHookTypes | TrappedMemoryHookTypes;

        private static bool IsUnboundedRange(ulong begin, ulong end) => end == 0 || end < begin;

        // Hooks change only while no worker runs a slice, so the exits read the hook lists without a lock.
        public IntPtr AddMemoryHook(ulong begin, ulong end, BackendHookType hookType, MemoryHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;
            if (NoHooks && (hookType & FaultMemoryHookTypes) == 0)
            {
                _error = KvmErrors.Ok;
                return IntPtr.Zero;
            }

            if ((hookType & ~SupportedMemoryHookTypes) != 0)
            {
                _error = KvmErrors.HookError;
                return IntPtr.Zero;
            }

            if ((hookType & TrappedMemoryHookTypes) != 0 && IsUnboundedRange(begin, end))
            {
                _error = KvmErrors.HookError;
                return IntPtr.Zero;
            }

            MemoryHookEntry entry = new MemoryHookEntry
            {
                Begin = begin,
                End = end,
                Type = hookType,
                Callback = callback
            };
            _memoryHooks.Add(entry);

            if ((hookType & TrappedMemoryHookTypes) != 0)
                RefreshTrappedPages();

            return PinHookEntry(entry);
        }

        private void RefreshTrappedPages()
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            _trappedPages.Clear();

            for (int i = 0; i < _memoryHooks.Count; i++)
            {
                MemoryHookEntry entry = _memoryHooks[i];
                if ((entry.Type & TrappedMemoryHookTypes) == 0) continue;
                if (IsUnboundedRange(entry.Begin, entry.End)) continue;

                bool writeOnly = (entry.Type & TrappedMemoryHookTypes) == BackendHookType.MemoryWrite;
                ulong first = entry.Begin & ~KvmConstants.PageMask;
                ulong last = entry.End & ~KvmConstants.PageMask;
                for (ulong page = first; page <= last; page += KvmConstants.PageSize)
                    _trappedPages[page] = writeOnly && (!_trappedPages.TryGetValue(page, out bool existing) || existing);
            }

            RequireFullRebuild();
            RebuildMappings();
        }

        public IntPtr AddCodeHook(ulong begin, ulong end, CodeHookCallback callback)
        {
            if (DisposedCheck()) return IntPtr.Zero;
            if (NoHooks) { _error = KvmErrors.Ok; return IntPtr.Zero; }

            _error = KvmErrors.HookError;
            return IntPtr.Zero;
        }

        public IntPtr AddInterruptHook(InterruptHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;

            InterruptHookEntry entry = new InterruptHookEntry { Callback = callback };
            _interruptHooks.Add(entry);
            return PinHookEntry(entry);
        }

        public IntPtr AddInstructionHook(BackendInstructionHook instruction, InstructionHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;

            InstructionHookEntry entry = new InstructionHookEntry { Type = instruction, Callback = callback };
            if (instruction == BackendInstructionHook.Syscall)
            {
                if (_syscallHook != null) UnpinHookEntry(_syscallHook);
                _syscallHook = entry;
            }
            else
            {
                _instructionHooks.Add(entry);
                RefreshInstructionHookFlags();
            }
            return PinHookEntry(entry);
        }

        public IntPtr AddInstructionBoolHook(BackendInstructionHook instruction, InstructionBoolHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;

            InstructionHookEntry entry = new InstructionHookEntry { Type = instruction, BoolCallback = callback };
            _instructionHooks.Add(entry);
            RefreshInstructionHookFlags();
            return PinHookEntry(entry);
        }

        public bool RemoveHook(IntPtr hook)
        {
            for (int i = 0; i < _liveHookHandles.Count; i++)
            {
                if (_liveHookHandles[i] != hook) continue;

                GCHandle handle = GCHandle.FromIntPtr(hook);
                object target = handle.Target;
                handle.Free();
                _liveHookHandles.RemoveAt(i);

                switch (target)
                {
                    case MemoryHookEntry mem:
                        _memoryHooks.Remove(mem);
                        if ((mem.Type & TrappedMemoryHookTypes) != 0) RefreshTrappedPages();
                        break;
                    case InterruptHookEntry intr: _interruptHooks.Remove(intr); break;
                    case InstructionHookEntry ins:
                        _instructionHooks.Remove(ins);
                        if (ReferenceEquals(_syscallHook, ins)) _syscallHook = null;
                        RefreshInstructionHookFlags();
                        break;
                }

                _error = KvmErrors.Ok;
                return true;
            }

            _error = KvmErrors.HookError;
            return false;
        }

        public bool RemoveHooks()
        {
            foreach (IntPtr ptr in _liveHookHandles)
                GCHandle.FromIntPtr(ptr).Free();
            _liveHookHandles.Clear();
            _memoryHooks.Clear();
            _instructionHooks.Clear();
            _interruptHooks.Clear();
            _syscallHook = null;
            RefreshInstructionHookFlags();

            if (_trappedPages.Count > 0 && !Disposing)
                RefreshTrappedPages();

            _error = KvmErrors.Ok;
            return true;
        }

        public unsafe IntPtr GetHostPointer(ulong address, ulong size)
        {
            if (size == 0 || size > int.MaxValue) return IntPtr.Zero;
            if (Volatile.Read(ref _disposing) != 0 || Volatile.Read(ref _disposed) != 0) return IntPtr.Zero;
            if (!TryGetHostPointer(address, (int)size, false, out byte* ptr, out long offset)) return IntPtr.Zero;
            return (IntPtr)(ptr + offset);
        }

        public bool IsRangeMapped(ulong address, ulong size)
        {
            if (size == 0) return true;
            if (Volatile.Read(ref _disposing) != 0 || Volatile.Read(ref _disposed) != 0) return false;
            return _paging.IsRangeMapped(address, size);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposing, 1) == 1) return;

            try
            {
                RemoveHooks();

                // The maintenance thread reads run pages and fds of every processor, so it has to be gone
                // before they are released.
                Thread Maintenance = _maintenanceThread;
                _maintenanceThread = null;
                Maintenance?.Join();

                for (int i = 0; i < _processors.Count; i++)
                {
                    VirtualProcessor vp = _processors[i];
                    if (vp.RunPtr != IntPtr.Zero)
                    {
                        KvmNative.munmap(vp.RunPtr, (UIntPtr)_runMmapSize);
                        vp.RunPtr = IntPtr.Zero;
                    }
                    if (vp.Fd >= 0)
                    {
                        KvmNative.close(vp.Fd);
                        vp.Fd = -1;
                    }
                }
                _processors.Clear();
                _idleProcessors.Clear();
                _threadProcessors.Clear();

                using (_paging.LockMappings())
                    _frees.CompletePassed(true);
                foreach (KeyValuePair<IntPtr, BackingAllocation> kv in _backings)
                    FreeAllocation(kv.Key, kv.Value);
                _backings.Clear();
                _paging.Clear();
                _gate.Dispose();

                if (_internalPoolPtr != IntPtr.Zero)
                {
                    FreeBackingMemory(_internalPoolPtr, InternalPoolSize);
                    _internalPoolPtr = IntPtr.Zero;
                }
                foreach (var fb in _internalPoolFallbacks)
                    FreeBackingMemory(fb.Ptr, fb.Size);
                _internalPoolFallbacks.Clear();

                if (_partitionFd >= 0) { KvmNative.close(_partitionFd); _partitionFd = -1; }
                if (_systemFd >= 0) { KvmNative.close(_systemFd); _systemFd = -1; }
            }
            finally
            {
                Volatile.Write(ref _disposed, 1);
                GC.SuppressFinalize(this);
            }
        }

        ~Kvm() { Dispose(); }

        private static GuestPagePermission TranslateProtection(MemoryProtection protection)
        {
            GuestPagePermission perm = GuestPagePermission.None;
            if ((protection & MemoryProtection.Read) != 0) perm |= GuestPagePermission.Read;
            if ((protection & MemoryProtection.Write) != 0) perm |= GuestPagePermission.Write;
            if ((protection & MemoryProtection.Execute) != 0) perm |= GuestPagePermission.Execute;
            return perm;
        }

        private static bool ExceptionHasErrorCode(uint vector)
        {
            switch (vector)
            {
                case 8:
                case 10:
                case 11:
                case 12:
                case 13:
                case 14:
                case 17:
                case 21:
                    return true;
                default:
                    return false;
            }
        }

        private LinuxKvmSegment MakeSegment(ushort selector, bool isCode, bool isUser)
            => MakeSegment(selector, isCode, isUser, _guest64 && isCode);

        private static LinuxKvmSegment MakeSegment(ushort selector, bool isCode, bool isUser, bool code64)
        {
            // KVM takes the limit in bytes and applies G itself.
            return new LinuxKvmSegment
            {
                Base = 0,
                Limit = 0xFFFFFFFF,
                Selector = selector,
                Type = isCode ? (byte)0xB : (byte)0x3,
                Present = 1,
                Dpl = isUser ? (byte)3 : (byte)0,
                Db = code64 ? (byte)0 : (byte)1,
                S = 1,
                L = code64 ? (byte)1 : (byte)0,
                G = 1,
                Avl = 0,
                Unusable = 0,
            };
        }

        private void ClearTrapFlag()
        {
            ref LinuxKvmRegisters regs = ref GetRegistersRef();
            if ((regs.Rflags & 0x100UL) == 0) return;
            regs.Rflags &= ~0x100UL;
            MarkRegistersDirty();
        }

        private unsafe bool TryAllocateBackingMemory(ulong size, out IntPtr pointer)
        {
            pointer = KvmNative.mmap(IntPtr.Zero, (UIntPtr)size,
                KvmNative.PROT_READ | KvmNative.PROT_WRITE,
                KvmNative.MAP_PRIVATE | KvmNative.MAP_ANONYMOUS, -1, 0);

            if (pointer == KvmNative.MAP_FAILED)
            {
                pointer = IntPtr.Zero;
                Utils.LogError($"[Kvm] Host backing mapping of 0x{size:X} bytes failed with {Marshal.GetLastWin32Error()}. Live backing 0x{_backingBytes:X} bytes in {_backings.Count} allocations.");
                return false;
            }

            _backingBytes += size;
            return true;
        }

        private unsafe IntPtr AllocateBackingMemory(ulong size)
        {
            if (!TryAllocateBackingMemory(size, out IntPtr ptr))
                throw new KvmException("mmap failed", Marshal.GetLastWin32Error());
            return ptr;
        }

        // A 2 MiB second level entry needs host and guest addresses to agree modulo 2 MiB.
        private bool TryAllocateGuestBacking(ulong guestAddress, ulong size, out IntPtr pointer, out bool hugePages)
        {
            hugePages = false;
            ulong huge = KvmConstants.HugePageSize;
            ulong firstBlock = (guestAddress + huge - 1) & ~(huge - 1);
            if (firstBlock + huge > guestAddress + size)
                return TryAllocateBackingMemory(size, out pointer);

            if (!TryAllocateBackingMemory(size + huge, out IntPtr mapped))
            {
                pointer = IntPtr.Zero;
                return false;
            }

            ulong head = (guestAddress - (ulong)mapped) & (huge - 1);
            pointer = (IntPtr)((ulong)mapped + head);
            if (head != 0)
                KvmNative.munmap(mapped, (UIntPtr)head);
            KvmNative.munmap((IntPtr)((ulong)pointer + size), (UIntPtr)(huge - head));
            _backingBytes -= huge;

            hugePages = KvmNative.madvise(pointer, (UIntPtr)size, KvmNative.MADV_HUGEPAGE) == 0;
            return true;
        }

        // Second level entries are otherwise built one exit per page at first touch.
        // An oversized range is skipped, not clipped, because a clipped tail still faults page by page.
        private void PopulateRange(ulong address, ulong size, IntPtr backing)
        {
            if (_populateUnavailable || !_supportsPreFault) return;
            if (size < PopulateMinBytes || size > PopulateLimitBytes) return;

            // A read populate would map the zero page read only and fault again on the first write.
            if (KvmNative.madvise(backing, (UIntPtr)size, KvmNative.MADV_POPULATE_WRITE) != 0)
            {
                _populateUnavailable = true;
                return;
            }

            // The ioctl takes the vCPU mutex, which KVM_RUN holds.
            VirtualProcessor vp = CurrentVp;
            if (vp.Running) return;

            PreFaultSpan(vp, address, size);
        }

        // A slot deleted and made again loses its second level entries for the whole range. Pre-faulting
        // a page the host never touched maps the zero page, and the first guest write pays for the copy,
        // so only resident pages get an entry built ahead of time.
        private unsafe void PopulateResidentRange(ulong address, ulong size, IntPtr backing)
        {
            if (_populateUnavailable || !_supportsPreFault) return;
            if (backing == IntPtr.Zero || size < PopulateMinBytes || size > PopulateLimitBytes) return;

            VirtualProcessor vp = CurrentVp;
            if (vp.Running) return;

            ulong pageCount = size / KvmConstants.PageSize;
            int chunkPages = (int)Math.Min(pageCount, (ulong)ResidencyQueryPages);
            long backingBase = backing.ToInt64();

            byte[] buffer = ArrayPool<byte>.Shared.Rent(chunkPages);
            try
            {
                ulong spanStart = 0;
                ulong spanPages = 0;

                fixed (byte* vec = buffer)
                {
                    for (ulong page = 0; page < pageCount; page += (ulong)chunkPages)
                    {
                        ulong count = Math.Min((ulong)chunkPages, pageCount - page);
                        IntPtr chunk = new IntPtr(backingBase + (long)(page * KvmConstants.PageSize));
                        if (KvmNative.mincore(chunk, (UIntPtr)(count * KvmConstants.PageSize), vec) != 0)
                            break;

                        for (ulong i = 0; i < count; i++)
                        {
                            if ((vec[i] & 1) != 0)
                            {
                                if (spanPages == 0) spanStart = page + i;
                                spanPages++;
                                continue;
                            }

                            if (spanPages != 0)
                            {
                                PreFaultResidentSpan(vp, address, spanStart, spanPages);
                                spanPages = 0;
                            }
                        }
                    }
                }

                if (spanPages != 0)
                    PreFaultResidentSpan(vp, address, spanStart, spanPages);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void PreFaultResidentSpan(VirtualProcessor vp, ulong address, ulong firstPage, ulong pageCount)
        {
            ulong size = pageCount * KvmConstants.PageSize;
            if (size < PopulateMinBytes) return;

            PreFaultSpan(vp, address + firstPage * KvmConstants.PageSize, size);
        }

        private void PreFaultSpan(VirtualProcessor vp, ulong address, ulong size)
        {
            LinuxKvmPreFaultMemory range = new LinuxKvmPreFaultMemory { Gpa = address, Size = size };
            while (range.Size != 0)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoPreFaultMemory, ref range) < 0)
                    break;
            }
        }

        private unsafe void FreeBackingMemory(IntPtr ptr, ulong size)
        {
            KvmNative.munmap(ptr, (UIntPtr)size);
            _backingBytes -= size;
        }

        private void ReleaseBacking(GuestPage page)
        {
            if (page.OwnedBacking == IntPtr.Zero) return;
            if (!_backings.TryGet(page.OwnedBacking, out BackingAllocation allocation)) return;

            if (page.IsAlias)
                allocation.AliasPages--;
            else
                allocation.LivePages--;

            if (!allocation.IsReferenced)
                _frees.Released(page.OwnedBacking);
            else if (!page.IsAlias && allocation.IsDiscardable)
                _frees.Discards.Add(page.OwnedBacking, page.HostPage, KvmConstants.PageSize);
        }

        // Only after the rebuild deletes the slots. Until then other processors can reach the backing.
        private void FreeReleasedBackings()
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            _frees.Flush();
        }

        public bool HasDeferredFrees => _frees.HasDeferred;

        public bool CompleteDeferredFrees(bool all)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            return _frees.CompletePassed(all);
        }

        private sealed class FreeSite : IBackingFreeSite<BackingAllocation>
        {
            private readonly Kvm _owner;

            public FreeSite(Kvm owner) => _owner = owner;

            public bool IsBackingStillMapped(IntPtr start, ulong size) => _owner.IsBackingStillMapped(start, size);

            public void ForgetBlock(IntPtr backing, BackingAllocation allocation) => _owner._paging.AssertMappingsHeld(nameof(ForgetBlock));

            public void FreeBlock(IntPtr backing, BackingAllocation allocation)
            {
                _owner._paging.AssertMappingsHeld(nameof(FreeBlock));
                _owner.FreeAllocation(backing, allocation);
            }

            public void DiscardRun(HostDiscardRuns.Run run, BackingAllocation allocation)
            {
                if (allocation.HugePages)
                    _owner.DiscardFreeSpans(run, allocation);
                else
                    HostDiscard.Release(run.Start, run.Size);
            }
        }

        // Linux keeps a partly discarded huge page until reclaim.
        private void DiscardFreeSpans(HostDiscardRuns.Run run, BackingAllocation allocation)
        {
            ulong huge = KvmConstants.HugePageSize;
            ulong blockStart = (ulong)run.Key.ToInt64();
            ulong blockEnd = blockStart + allocation.Size;
            ulong cursor = (ulong)run.Start.ToInt64();
            ulong end = cursor + run.Size;

            while (cursor < end)
            {
                ulong spanStart = cursor & ~(huge - 1);
                ulong spanEnd = spanStart + huge;
                ulong pieceEnd = Math.Min(end, spanEnd);

                if (spanStart < blockStart || spanEnd > blockEnd)
                    HostDiscard.Release(new IntPtr((long)cursor), pieceEnd - cursor);
                else if (!HasLivePage(run.Key, allocation, spanStart - blockStart) && !IsBackingStillMapped(new IntPtr((long)spanStart), huge))
                    HostDiscard.Release(new IntPtr((long)spanStart), huge);

                cursor = pieceEnd;
            }
        }

        private bool HasLivePage(IntPtr backing, BackingAllocation allocation, ulong spanOffset)
        {
            ulong guest = allocation.GuestBase + spanOffset;
            for (ulong off = 0; off < KvmConstants.HugePageSize; off += KvmConstants.PageSize)
            {
                if (_mappedPages.TryGetValue(guest + off, out GuestPage page) && page.OwnedBacking == backing && !page.IsAlias)
                    return true;
            }

            return false;
        }

        public IntPtr PinBacking(IntPtr hostPointer, ulong size)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck()) return IntPtr.Zero;

            IntPtr backing = _backings.FindRange(hostPointer, size, out BackingAllocation allocation);
            if (backing == IntPtr.Zero)
                return IntPtr.Zero;

            allocation.Pins++;
            return backing;
        }

        public void UnpinBacking(IntPtr pin)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck() || !_backings.TryGet(pin, out BackingAllocation allocation) || allocation.Pins == 0)
                return;

            allocation.Pins--;
            _frees.FreeIfUnreferenced(pin, allocation);
            _frees.Settle();
        }

        private bool IsBackingStillMapped(IntPtr backing, ulong size)
        {
            long start = backing.ToInt64();
            for (int i = 0; i < _stillMappedBacking.Count; i++)
            {
                long slotStart = _stillMappedBacking[i].Host.ToInt64();
                if (slotStart < start + (long)size && start < slotStart + (long)_stillMappedBacking[i].Size)
                    return true;
            }
            return false;
        }

        private void FreeAllocation(IntPtr backing, BackingAllocation allocation)
        {
            if (allocation.Owner != null)
                allocation.Owner.Dispose();
            else
                FreeBackingMemory(backing, allocation.Size);
        }

        private unsafe ref LinuxKvmRun GetRunRef()
            => ref Unsafe.AsRef<LinuxKvmRun>((void*)CurrentVp.RunPtr);

        private static unsafe ref LinuxKvmRun GetRunRef(VirtualProcessor vp)
            => ref Unsafe.AsRef<LinuxKvmRun>((void*)vp.RunPtr);

        private IntPtr PinHookEntry(object entry)
        {
            GCHandle handle = GCHandle.Alloc(entry, GCHandleType.Normal);
            IntPtr ptr = (IntPtr)GCHandle.ToIntPtr(handle);
            _liveHookHandles.Add(ptr);
            return ptr;
        }

        private void UnpinHookEntry(object entry)
        {
            for (int i = 0; i < _liveHookHandles.Count; i++)
            {
                GCHandle h = GCHandle.FromIntPtr(_liveHookHandles[i]);
                if (ReferenceEquals(h.Target, entry))
                {
                    h.Free();
                    _liveHookHandles.RemoveAt(i);
                    return;
                }
            }
        }

        private void EnsurePlatformSupport()
        {
            _systemFd = KvmNative.open("/dev/kvm", KvmNative.O_RDWR | KvmNative.O_CLOEXEC, 0);
            if (_systemFd < 0)
            {
                int Errno = Marshal.GetLastWin32Error();

                if (Errno == KvmNative.ErrnoAccess)
                    throw new KvmException("open(/dev/kvm) failed, this user may not open it. Add the user to the kvm group with \"sudo usermod -aG kvm $USER\" and log in again", Errno);

                if (Errno == KvmNative.ErrnoNoEntry)
                    throw new KvmException("open(/dev/kvm) failed, it does not exist. Load the kvm_intel or kvm_amd module and turn virtualisation on in the firmware", Errno);

                throw new KvmException("open(/dev/kvm) failed", Errno);
            }

            int apiVersion = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoGetApiVersion, IntPtr.Zero);
            if (apiVersion < 0)
                throw new KvmException("KVM_GET_API_VERSION failed", Marshal.GetLastWin32Error());
            if (apiVersion != KvmConstants.ExpectedApiVersion)
                throw new KvmException($"Unexpected KVM API version {apiVersion}");

            _maxMemslots = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapNrMemslots);
            if (_maxMemslots <= 0)
                _maxMemslots = DefaultMemslotCount;

            _supportsXsave = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapXsave) > 0;
            _supportsVcpuAttributes = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapVcpuAttributes) > 0;
            _supportsPreFault = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapPreFaultMemory) > 0;
            _supportsXcrs = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapXcrs) > 0;
            int xsaveSize = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapXsave2);
            _supportsXsave2 = xsaveSize > 0;
            if (xsaveSize > _xsaveSize) _xsaveSize = xsaveSize;

            const ulong requiredSync = KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;
            int syncRegs = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapSyncRegs);
            if (syncRegs < 0 || ((ulong)syncRegs & requiredSync) != requiredSync)
                throw new KvmException("KVM_CAP_SYNC_REGS with register and segment sync is required (Linux 4.18 or later).");

            int maxVcpus = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapMaxVcpus);
            _processorLimit = maxVcpus <= 0 ? 1 : Math.Min(maxVcpus, MaxVirtualProcessors);
            _processorLimit = Math.Max(1, Math.Min(_processorLimit, ReserveFileDescriptors()));

            _runMmapSize = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoGetVcpuMmapSize, IntPtr.Zero);
            if (_runMmapSize <= 0)
                throw new KvmException("KVM_GET_VCPU_MMAP_SIZE failed", Marshal.GetLastWin32Error());
        }

        // Every vCPU is a file descriptor. Half of the raised limit is left to the guest's files.
        private static int ReserveFileDescriptors()
        {
            LinuxRlimit limit = default;
            if (KvmNative.getrlimit(KvmNative.RLIMIT_NOFILE, ref limit) != 0)
                return MaxVirtualProcessors;

            ulong wanted = Math.Min(limit.Maximum, 1UL << 16);
            if (limit.Current < wanted)
            {
                LinuxRlimit raised = new LinuxRlimit { Current = wanted, Maximum = limit.Maximum };
                if (KvmNative.setrlimit(KvmNative.RLIMIT_NOFILE, ref raised) == 0)
                    limit.Current = wanted;
            }

            return (int)Math.Min(limit.Current / 2, (ulong)MaxVirtualProcessors);
        }

        private void ConfigurePartition()
        {
            _partitionFd = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCreateVm, IntPtr.Zero);
            if (_partitionFd < 0)
                throw new KvmException("KVM_CREATE_VM failed", Marshal.GetLastWin32Error());
            KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoSetTssAddress, unchecked((IntPtr)0xfffbd000));
            KeepMappingsOnSlotDelete();
        }

        // With the quirk on, deleting one memslot drops every second level entry of the partition.
        private void KeepMappingsOnSlotDelete()
        {
            int quirks = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapDisableQuirks2);
            if (quirks <= 0 || ((ulong)quirks & KvmConstants.QuirkSlotZapAll) == 0) return;

            LinuxKvmEnableCap cap = new LinuxKvmEnableCap
            {
                Cap = (uint)KvmConstants.CapDisableQuirks2,
                Arg0 = KvmConstants.QuirkSlotZapAll,
            };
            KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoEnableCap, ref cap);
        }

        private VirtualProcessor CreateProcessor(int index)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            int fd = KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoCreateVcpu, index);
            if (fd < 0)
                throw new KvmException("KVM_CREATE_VCPU failed", Marshal.GetLastWin32Error());

            IntPtr runPtr = KvmNative.mmap(IntPtr.Zero, (UIntPtr)_runMmapSize,
                KvmNative.PROT_READ | KvmNative.PROT_WRITE, KvmNative.MAP_SHARED, fd, 0);
            if (runPtr == KvmNative.MAP_FAILED)
            {
                int errno = Marshal.GetLastWin32Error();
                KvmNative.close(fd);
                throw new KvmException("mmap(KVM_RUN) failed", errno);
            }

            VirtualProcessor vp = new VirtualProcessor { Owner = this, Index = index, Fd = fd, RunPtr = runPtr };

            try
            {
                AllocateProcessorTables(vp);
                InitializeCpuid(vp);
                InitializeVirtualProcessorState(vp);
                AlignTimestampCounter(vp);
            }
            catch
            {
                KvmNative.munmap(runPtr, (UIntPtr)_runMmapSize);
                KvmNative.close(fd);
                throw;
            }

            _processors.Add(vp);
            Volatile.Write(ref _processorSnapshot, _processors.ToArray());
            return vp;
        }

        private unsafe void AllocateProcessorTables(VirtualProcessor vp)
        {
            vp.GdtPageGpa = AllocateInternalPage(GuestPagePermission.Read);
            vp.TssPageGpa = AllocateInternalPage();
            ulong stackSize = ExceptionStackPages * KvmConstants.PageSize;
            ulong stackBase = AllocateInternalRange(stackSize, GuestPagePermission.ReadWrite, out IntPtr stackHost);
            ulong stackTop = stackBase + stackSize;
            vp.InterruptFrameGpa = GuestInterruptGates.InterruptFrame(stackTop);
            vp.InterruptFrameHost = stackHost + (nint)(vp.InterruptFrameGpa - stackBase);
            vp.DebugFrameGpa = GuestInterruptGates.DebugFrame(stackTop);
            vp.DebugFrameHost = stackHost + (nint)(vp.DebugFrameGpa - stackBase);

            if (!_mappedPages.TryGetValue(_gdtPageGpa, out GuestPage template)
                || !_mappedPages.TryGetValue(vp.GdtPageGpa, out GuestPage gdtPage)
                || !_mappedPages.TryGetValue(vp.TssPageGpa, out GuestPage tssPage))
                throw new KvmException("Failed to allocate the processor tables.");

            byte* gdt = (byte*)gdtPage.HostPage;
            Unsafe.CopyBlockUnaligned(gdt, (byte*)template.HostPage, (uint)KvmConstants.PageSize);
            WriteTssDescriptor(gdt, vp.TssPageGpa);

            GuestInterruptGates.WriteTss((byte*)tssPage.HostPage, stackTop);
        }

        private static unsafe void WriteTssDescriptor(byte* gdt, ulong tssBase)
        {
            int tssIndex = KvmConstants.TssSelector >> 3;
            uint tssLimit = 0x67;
            gdt[tssIndex * 8 + 0] = (byte)(tssLimit & 0xFF);
            gdt[tssIndex * 8 + 1] = (byte)((tssLimit >> 8) & 0xFF);
            gdt[tssIndex * 8 + 2] = (byte)(tssBase & 0xFF);
            gdt[tssIndex * 8 + 3] = (byte)((tssBase >> 8) & 0xFF);
            gdt[tssIndex * 8 + 4] = (byte)((tssBase >> 16) & 0xFF);
            gdt[tssIndex * 8 + 5] = (byte)(0x89 | 0x80);
            gdt[tssIndex * 8 + 6] = (byte)(((tssLimit >> 16) & 0xF) | 0x00);
            gdt[tssIndex * 8 + 7] = (byte)((tssBase >> 24) & 0xFF);
            gdt[tssIndex * 8 + 8] = (byte)((tssBase >> 32) & 0xFF);
            gdt[tssIndex * 8 + 9] = (byte)((tssBase >> 40) & 0xFF);
            gdt[tssIndex * 8 + 10] = (byte)((tssBase >> 48) & 0xFF);
            gdt[tssIndex * 8 + 11] = (byte)((tssBase >> 56) & 0xFF);
            gdt[tssIndex * 8 + 12] = 0;
            gdt[tssIndex * 8 + 13] = 0;
            gdt[tssIndex * 8 + 14] = 0;
            gdt[tssIndex * 8 + 15] = 0;
        }

        private unsafe void InitializeCpuid(VirtualProcessor vp)
        {
            if (_cpuidTable == null)
            {
                const int cpuidEntries = 256;
                byte[] table = new byte[sizeof(LinuxKvmCpuid2) + (cpuidEntries - 1) * sizeof(LinuxKvmCpuidEntry2)];
                fixed (byte* buffer = table)
                {
                    Unsafe.AsRef<LinuxKvmCpuid2>(buffer).Nent = cpuidEntries;
                    if (KvmNative.ioctl(_systemFd, KvmConstants.KvmIoGetSupportedCpuid, (IntPtr)buffer) < 0)
                        throw new KvmException("KVM_GET_SUPPORTED_CPUID failed", Marshal.GetLastWin32Error());
                    ApplyHostHypervisorLeaves(ref Unsafe.AsRef<LinuxKvmCpuid2>(buffer), cpuidEntries);
                }
                _cpuidTable = table;
                ConfigureExtendedState();
            }

            fixed (byte* buffer = _cpuidTable)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoSetCpuid2, (IntPtr)buffer) < 0)
                    throw new KvmException("KVM_SET_CPUID2 failed", Marshal.GetLastWin32Error());
            }
        }

        private static unsafe void ApplyHostHypervisorLeaves(ref LinuxKvmCpuid2 table, uint capacity)
        {
            LinuxKvmCpuidEntry2* entries = (LinuxKvmCpuidEntry2*)Unsafe.AsPointer(ref table.FirstEntry);
            uint kept = 0;
            for (uint i = 0; i < table.Nent; i++)
            {
                ref LinuxKvmCpuidEntry2 entry = ref entries[i];
                if (entry.Function >= HostHypervisorLeaves.First && entry.Function <= HostHypervisorLeaves.ReservedLast)
                    continue;
                if (entry.Function == HostHypervisorLeaves.FeatureLeaf)
                    entry.Ecx = HostHypervisorLeaves.HostHasHypervisor ? entry.Ecx | HostHypervisorLeaves.PresentBit : entry.Ecx & ~HostHypervisorLeaves.PresentBit;
                entries[kept++] = entry;
            }

            (uint Eax, uint Ebx, uint Ecx, uint Edx)[] leaves = HostHypervisorLeaves.Leaves;
            uint count = Math.Min((uint)leaves.Length, capacity - kept);
            for (uint i = 0; i < count; i++)
            {
                entries[kept++] = new LinuxKvmCpuidEntry2
                {
                    Function = HostHypervisorLeaves.First + i,
                    Eax = leaves[i].Eax,
                    Ebx = leaves[i].Ebx,
                    Ecx = leaves[i].Ecx,
                    Edx = leaves[i].Edx,
                };
            }
            table.Nent = kept;
        }

        // Guest XCR0 stops at x87, SSE and AVX, which is the state the thread contexts carry.
        private unsafe void ConfigureExtendedState()
        {
            ulong supportedXcr0 = 0;
            bool cpuidXsave = false;
            fixed (byte* buffer = _cpuidTable)
            {
                ref LinuxKvmCpuid2 table = ref Unsafe.AsRef<LinuxKvmCpuid2>(buffer);
                LinuxKvmCpuidEntry2* entries = (LinuxKvmCpuidEntry2*)Unsafe.AsPointer(ref table.FirstEntry);
                for (uint i = 0; i < table.Nent; i++)
                {
                    ref LinuxKvmCpuidEntry2 entry = ref entries[i];
                    if (entry.Function == 1 && entry.Index == 0)
                        cpuidXsave = (entry.Ecx & (1u << 26)) != 0;
                    if (entry.Function == 7 && entry.Index == 0)
                    {
                        if ((entry.Ecx & (1u << 2)) != 0) _cr4Protection |= ControlRegister4.Umip;
                        if ((entry.Ebx & (1u << 7)) != 0) _cr4Protection |= ControlRegister4.Smep;
                        if ((entry.Ebx & (1u << 20)) != 0) _cr4Protection |= ControlRegister4.Smap;
                    }
                    if (entry.Function != 0xD) continue;
                    if (entry.Index == 0)
                        supportedXcr0 = entry.Eax | ((ulong)entry.Edx << 32);
                    else if (entry.Index == 2 && entry.Eax >= XmmRegisterCount * 16 && entry.Ebx + entry.Eax <= (uint)_xsaveSize)
                        _ymmHighOffset = (int)entry.Ebx;
                }
            }

            _avxEnabled = _supportsXsave && _supportsXcrs && cpuidXsave
                && (supportedXcr0 & KvmConstants.XcrAvxFeatures) == KvmConstants.XcrAvxFeatures;
        }

        private void InitializeVirtualProcessorState(VirtualProcessor vp)
        {
            ref LinuxKvmRun run = ref GetRunRef(vp);

            lock (vp.RegisterLock)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoGetRegisters, ref run.Regs) < 0)
                    throw new KvmException("KVM_GET_REGS failed", Marshal.GetLastWin32Error());
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoGetSpecialRegisters, ref run.Sregs) < 0)
                    throw new KvmException("KVM_GET_SREGS failed", Marshal.GetLastWin32Error());
            }

            ref LinuxKvmSpecialRegisters sregs = ref run.Sregs;
            sregs.Cs = MakeSegment(_userCodeSelector, true, true);
            sregs.Ss = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Ds = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Es = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Fs = MakeSegment(KvmConstants.UserFsSelector32, false, true);
            sregs.Gs = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Cr0 = 0x80010033UL;
            sregs.Cr4 = 0x620UL | (_avxEnabled ? ControlRegister4.Osxsave : 0) | _cr4Protection;
            sregs.Cr3 = _paging.Root;
            sregs.Efer = (1UL << 8) | (1UL << 10) | (1UL << 11) | (_guest64 ? 1UL << 0 : 0);
            sregs.Gdt.Base = vp.GdtPageGpa;
            sregs.Gdt.Limit = KvmConstants.GdtLimit;
            sregs.Idt.Base = _exceptionIdtPageGpa;
            sregs.Idt.Limit = (ushort)(KvmConstants.ExceptionVectorCount * 16 - 1);
            sregs.Tr.Selector = KvmConstants.TssSelector;
            sregs.Tr.Base = vp.TssPageGpa;
            sregs.Tr.Limit = 0x67;
            sregs.Tr.Type = 11;
            sregs.Tr.S = 0;
            sregs.Tr.Present = 1;
            sregs.Tr.Dpl = 0;
            sregs.Tr.Db = 0;
            sregs.Tr.L = 0;
            sregs.Tr.G = 0;
            sregs.Tr.Avl = 0;
            sregs.Tr.Unusable = 0;

            run.Regs = default;
            run.Regs.Rflags = 0x2UL;

            run.ValidRegs = KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;
            run.DirtyRegs = KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;

            unsafe
            {
                LinuxKvmFpu fpu = new LinuxKvmFpu
                {
                    Fcw = 0x037F,
                    Fsw = 0,
                    Ftwx = 0xFF,
                    LastOpcode = 0,
                    LastIp = 0,
                    LastDp = 0,
                    Mxcsr = 0x1F80,
                };
                SetFpu(vp, ref fpu);
            }

            if (_avxEnabled)
                SetXcr0(vp);

            if (_guest64)
            {
                AllocateSyscallStub(vp);
                SetMsr(vp, KvmConstants.MsrStar, (0x23UL << 48) | (0x08UL << 32));
                SetMsr(vp, KvmConstants.MsrSyscallMask, UserModeFlags.SyscallEntryMask);
                SetMsr(vp, KvmConstants.MsrLstar, vp.SyscallStubGpa);
                SetMsr(vp, KvmConstants.MsrCstar, _syscallTrapPageGpa + SyscallTrapPage.CompatSyscallOffset);
            }
        }

        public bool SupportsThreadResidency => _processorLimit > 1;

        public int ProcessorLimit => _processorLimit;

        public bool IsThreadResident(uint threadId)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            return _threadProcessors.ContainsKey(threadId);
        }

        public bool TryBindThread(uint threadId)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (DisposedCheck() || threadId == 0)
                return false;

            if (_threadProcessors.ContainsKey(threadId))
                return true;

            VirtualProcessor vp;
            if (_idleProcessors.Count != 0)
            {
                vp = _idleProcessors.Pop();
            }
            else
            {
                if (_processors.Count >= _processorLimit)
                    return false;

                try
                {
                    vp = CreateProcessor(_processors.Count);
                }
                catch (KvmException)
                {
                    _processorLimit = _processors.Count;
                    return false;
                }
            }

            if (vp.ThreadId != threadId)
                LeaveSyscallStub(vp);
            vp.ThreadId = threadId;
            _threadProcessors[threadId] = vp;
            return true;
        }

        public void UnbindThread(uint threadId)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (!_threadProcessors.Remove(threadId, out VirtualProcessor vp))
                return;

            vp.ThreadId = 0;
            vp.Binding++;
            _idleProcessors.Push(vp);
        }

        public void SelectThread(uint threadId)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            VirtualProcessor vp = _threadProcessors.TryGetValue(threadId, out VirtualProcessor bound) ? bound : _processors[0];
            if (vp.ThreadId != threadId)
            {
                LeaveSyscallStub(vp);
                vp.ThreadId = threadId;
            }
            SelectProcessor(vp);
        }

        private void InitializeSyscallTrapPage()
        {
            if (!_guest64) return;

            _syscallTrapPageGpa = AllocateInternalPage(GuestPagePermission.ReadExecute);
            unsafe
            {
                if (_mappedPages.TryGetValue(_syscallTrapPageGpa, out GuestPage page))
                {
                    byte* code = (byte*)page.HostPage;
                    code[SyscallReturnOffset] = 0x48;
                    code[SyscallReturnOffset + 1] = 0x0F;
                    code[SyscallReturnOffset + 2] = 0x07;
                    for (int i = 0; i < FlushingSyscallReturn.Length; i++)
                        code[(int)FlushingSyscallReturnOffset + i] = FlushingSyscallReturn[i];
                    code[SyscallTrapPage.CompatSyscallOffset] = 0xF4;
                }
            }
        }

        // The syscall registers reach the host through the run page, so the stub spills them only for kernel calls.
        private void AllocateSyscallStub(VirtualProcessor vp)
        {
            vp.SyscallStubGpa = AllocateInternalRange(KvmConstants.PageSize, GuestPagePermission.ReadExecute, out IntPtr code);
            ulong spillGpa = AllocateInternalRange(KvmConstants.PageSize, GuestPagePermission.ReadWrite, out vp.SyscallSpill);
            _guestKernel ??= new GuestKernelHost(this, _gate, KvmConstants.InternalPageTableBase, KvmConstants.UserCodeSelector,
                KvmConstants.UserDataSelector, smap: (_cr4Protection & ControlRegister4.Smap) != 0, alwaysSpill: false);
            _guestKernel.AddProcessor(vp.SyscallStubGpa, code, spillGpa, vp.SyscallSpill);
        }

        public IGuestKernel GuestKernel => Disposed ? null : _guestKernel;

        bool IGuestKernelBackend.DisposedCheck() => DisposedCheck();

        bool IGuestKernelBackend.TryAllocateKernelRange(ulong size, bool writable, out ulong address, out IntPtr host)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            try
            {
                address = AllocateInternalRange(size, writable ? GuestPagePermission.ReadWrite : GuestPagePermission.Read, out host);
                RebuildMappings();
                return true;
            }
            catch (KvmException ex)
            {
                Utils.LogError($"[Kvm] No guest kernel memory of 0x{size:X} bytes: {ex.Message}");
                address = 0;
                host = IntPtr.Zero;
                return false;
            }
        }

        bool IGuestKernelBackend.MapKernelView(IntPtr host, ulong address, ulong size)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (!HasSlotHeadroom)
                return false;

            int slot = -1;
            try
            {
                slot = AllocateSlotId();
                SetMemslot(slot, address, size, host, KvmConstants.MemSlotReadOnly);
            }
            catch (KvmException ex)
            {
                if (slot >= 0)
                    _freeSlotIds.Add(slot);
                Utils.LogError($"[Kvm] No memory slot for a kernel view at 0x{address:X}: {ex.Message}");
                return false;
            }

            _kernelViewSlots[address] = slot;
            return true;
        }

        bool IGuestKernelBackend.UnmapKernelView(ulong address, ulong size)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (!_kernelViewSlots.TryGetValue(address, out int slot))
                return true;

            if (!DeleteMemslot(slot))
                return false;

            _kernelViewSlots.Remove(address);
            return true;
        }

        // A new table page enters the memslots before the entry that points through it.
        bool IGuestKernelBackend.MapKernelLargePage(ulong address)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            try
            {
                _paging.EnsureDirectoryTable(address);
                if (_mappingsDirty)
                    RebuildMappings();
                return _paging.SetKernelLargePage(address);
            }
            catch (KvmException ex)
            {
                Utils.LogError($"[Kvm] No page table for a kernel view at 0x{address:X}: {ex.Message}");
                return false;
            }
        }


        ulong IGuestPagingBackend.AllocateTablePage() => AllocateInternalPage(mapIntoGuest: false);

        private void InitializeGdt()
        {
            _gdtPageGpa = AllocateInternalPage(GuestPagePermission.Read);
            if (!_mappedPages.TryGetValue(_gdtPageGpa, out GuestPage gdtPage) || gdtPage.HostPage == IntPtr.Zero)
                throw new KvmException("Failed to allocate GDT page.");

            unsafe
            {
                byte* gdt = (byte*)gdtPage.HostPage;
                Unsafe.InitBlockUnaligned(gdt, 0, (uint)KvmConstants.PageSize);

                gdt[0x08] = 0xFF; gdt[0x09] = 0xFF; gdt[0x0A] = 0x00; gdt[0x0B] = 0x00;
                gdt[0x0C] = 0x00; gdt[0x0D] = 0x9B; gdt[0x0E] = 0xAF; gdt[0x0F] = 0x00;

                gdt[0x10] = 0xFF; gdt[0x11] = 0xFF; gdt[0x12] = 0x00; gdt[0x13] = 0x00;
                gdt[0x14] = 0x00; gdt[0x15] = 0x93; gdt[0x16] = 0xCF; gdt[0x17] = 0x00;

                gdt[0x20] = 0xFF; gdt[0x21] = 0xFF; gdt[0x22] = 0x00; gdt[0x23] = 0x00;
                gdt[0x24] = 0x00; gdt[0x25] = 0xFB; gdt[0x26] = 0xCF; gdt[0x27] = 0x00;

                gdt[0x28] = 0xFF; gdt[0x29] = 0xFF; gdt[0x2A] = 0x00; gdt[0x2B] = 0x00;
                gdt[0x2C] = 0x00; gdt[0x2D] = 0xF3; gdt[0x2E] = 0xCF; gdt[0x2F] = 0x00;

                gdt[0x30] = 0xFF; gdt[0x31] = 0xFF; gdt[0x32] = 0x00; gdt[0x33] = 0x00;
                gdt[0x34] = 0x00; gdt[0x35] = 0xFB; gdt[0x36] = 0xAF; gdt[0x37] = 0x00;

                // RtlGetCurrentProcessorNumber reads this descriptor limit with lsl and shifts it right by 14
                gdt[0x50] = 0xFF; gdt[0x51] = 0x0F; gdt[0x52] = 0x00; gdt[0x53] = 0x00;
                gdt[0x54] = 0x00; gdt[0x55] = 0xF3; gdt[0x56] = 0x40; gdt[0x57] = 0x00;
            }
        }

        private void InitializeExceptionHandling()
        {
            _exceptionStubPageGpa = AllocateInternalPage(GuestPagePermission.ReadExecute);
            _exceptionIdtPageGpa = AllocateInternalPage(GuestPagePermission.Read);

            unsafe
            {
                if (_mappedPages.TryGetValue(_exceptionStubPageGpa, out GuestPage stubPage))
                {
                    byte* stubs = (byte*)stubPage.HostPage;
                    for (uint vector = 0; vector < KvmConstants.ExceptionVectorCount; vector++)
                        stubs[vector * (int)KvmConstants.ExceptionStubStride] = 0xF4;
                    stubs[IretStubOffset] = 0x48;
                    stubs[IretStubOffset + 1] = 0xCF;
                }

                if (_mappedPages.TryGetValue(_exceptionIdtPageGpa, out GuestPage idtPage))
                {
                    byte* idt = (byte*)idtPage.HostPage;
                    for (uint vector = 0; vector < KvmConstants.ExceptionVectorCount; vector++)
                    {
                        GuestInterruptGates.WriteIdtGate(idt, vector, _exceptionStubPageGpa + vector * KvmConstants.ExceptionStubStride,
                            KvmConstants.KernelCodeSelector);
                    }
                }
            }
        }

        public unsafe void SetUserInterruptGates(Func<uint, bool> raisableFromUserMode)
        {
            if (_mappedPages.TryGetValue(_exceptionIdtPageGpa, out GuestPage idtPage) && idtPage.HostPage != IntPtr.Zero)
                GuestInterruptGates.SetUserGates((byte*)idtPage.HostPage, KvmConstants.ExceptionVectorCount, raisableFromUserMode);
        }

        private void InitializeLongModePageTables() => _paging.CreateRoot();

        private void AllocateInternalPool()
        {
            _internalPoolPtr = AllocateBackingMemory(InternalPoolSize);
            _internalPoolOffset = 0;
        }

        private ulong AllocateInternalPage(GuestPagePermission permissions = GuestPagePermission.ReadWrite, bool mapIntoGuest = true)
            => AllocateInternalRange(KvmConstants.PageSize, permissions, mapIntoGuest);

        private ulong AllocateInternalRange(ulong size, GuestPagePermission permissions, bool mapIntoGuest = true)
            => AllocateInternalRange(size, permissions, out _, mapIntoGuest);

        private ulong AllocateInternalRange(ulong size, GuestPagePermission permissions, out IntPtr host, bool mapIntoGuest = true)
        {
            if ((size & KvmConstants.PageMask) != 0)
                size = (size + KvmConstants.PageMask) & ~KvmConstants.PageMask;
            if (size > InternalPages.PageLimit(KvmConstants.InternalPageTableBase) - _nextInternalGpa)
                throw new KvmException($"No internal guest address space for 0x{size:X} bytes");

            IntPtr backing;
            if (_internalPoolPtr != IntPtr.Zero &&
                _internalPoolOffset + size <= InternalPoolSize)
            {
                backing = new IntPtr(_internalPoolPtr.ToInt64() + (long)_internalPoolOffset);
                _internalPoolOffset += size;
            }
            else
            {
                backing = AllocateBackingMemory(size);
                _internalPoolFallbacks.Add((backing, size));
            }

            ulong baseGpa = _nextInternalGpa;
            _nextInternalGpa += size;
            host = backing;

            long backingBase = backing.ToInt64();
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong pageGpa = baseGpa + off;
                GuestPage page = new GuestPage
                {
                    HostPage = new IntPtr(backingBase + (long)off),
                    OwnedBacking = IntPtr.Zero,
                    Permissions = permissions,
                    // The PTE protects an internal page. Its memslot keeps the flags of the pages around it.
                    WriteRetained = true,
                };
                SetGuestPage(pageGpa, page);

                if (mapIntoGuest)
                    _paging.SetLeaf(pageGpa, permissions);
            }

            return baseGpa;
        }

        private void SetGuestPage(ulong guestAddress, GuestPage page)
        {
            _paging.SetPage(guestAddress, page);
            _mappingsDirty = true;
            MarkSpanDirty(guestAddress, KvmConstants.PageSize);
        }

        private void RemoveGuestPage(ulong guestAddress)
        {
            if (!_paging.RemovePage(guestAddress)) return;
            _mappingsDirty = true;
            MarkSpanDirty(guestAddress, KvmConstants.PageSize);
        }

        private void RebuildMappings()
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            _mappingsDirty = false;

            if (!_fullRebuildRequired)
            {
                if (HasSlotHeadroom)
                {
                    RebuildDirtyRanges();
                }
                else
                {
                    for (int i = 0; i < _dirtyRanges.Count; i++)
                        RebuildMappingsIncremental(_dirtyRanges[i].Start, _dirtyRanges[i].End);
                }
                _dirtyRanges.Clear();
                return;
            }

            RebuildMappingsFull();
            _fullRebuildRequired = false;
            _dirtyRanges.Clear();
        }

        private void MarkSpanDirty(ulong address, ulong size)
        {
            if (_fullRebuildRequired) return;

            ulong start = address & ~KvmConstants.PageMask;
            ulong end = address + size;
            end = end < address ? ulong.MaxValue & ~KvmConstants.PageMask : (end + KvmConstants.PageMask) & ~KvmConstants.PageMask;
            if (end <= start) return;

            for (int i = _dirtyRanges.Count - 1; i >= 0; i--)
            {
                DirtyRange range = _dirtyRanges[i];
                if (start > range.End || range.Start > end) continue;

                if (range.Start < start) start = range.Start;
                if (range.End > end) end = range.End;
                _dirtyRanges.RemoveAt(i);
            }

            if (_dirtyRanges.Count >= MaxDirtyRanges)
            {
                RequireFullRebuild();
                return;
            }

            _dirtyRanges.Add(new DirtyRange { Start = start, End = end });
        }

        private void RequireFullRebuild()
        {
            _fullRebuildRequired = true;
            _dirtyRanges.Clear();
        }

        private void AddActiveSlot(ulong start, InstalledSlot slot)
        {
            _activeSlots[start] = slot;
            int index = _activeSlotStarts.BinarySearch(start);
            if (index < 0) _activeSlotStarts.Insert(~index, start);
        }

        private void RemoveActiveSlot(ulong start)
        {
            if (!_activeSlots.Remove(start)) return;
            int index = _activeSlotStarts.BinarySearch(start);
            if (index >= 0) _activeSlotStarts.RemoveAt(index);
        }

        private int FirstActiveSlotIndexAtOrBefore(ulong address)
        {
            int index = _activeSlotStarts.BinarySearch(address);
            if (index >= 0) return index;

            index = ~index;
            return index > 0 ? index - 1 : 0;
        }

        // A slot whose pages still map as installed stays as it is. Replacing it unmaps it for a moment, and
        // a processor delivering an exception in that moment cannot recover. Slots merge only when they run out.
        private void MarkIntactSlots(ulong spanStart, ulong spanEnd)
        {
            _keptSlotStarts.Clear();
            if (!HasSlotHeadroom) return;

            int firstIndex = FirstActiveSlotIndexAtOrBefore(spanStart);
            for (int i = firstIndex; i < _activeSlotStarts.Count; i++)
            {
                ulong start = _activeSlotStarts[i];
                if (start >= spanEnd) break;

                InstalledSlot active = _activeSlots[start];
                if (start + active.Size <= spanStart) continue;
                if (!IsSlotIntact(start, active)) continue;

                _keptSlotStarts.Add(start);
                _desiredSlots[start] = active;
            }
        }

        private bool IsSlotIntact(ulong start, InstalledSlot slot) => IsSlotIntact(start, slot, start, start + slot.Size);

        private bool IsSlotIntact(ulong start, InstalledSlot slot, ulong from, ulong to)
        {
            bool anyTrapped = _trappedPages.Count != 0;
            for (ulong address = from; address < to; address += KvmConstants.PageSize)
            {
                ulong off = address - start;
                if (!_mappedPages.TryGetValue(address, out GuestPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == GuestPagePermission.None)
                    return false;
                if (page.HostPage.ToInt64() != slot.Host.ToInt64() + (long)off) return false;

                uint flags;
                if (anyTrapped && _trappedPages.TryGetValue(address, out bool writeOnly))
                {
                    if (!writeOnly || slot.Size != KvmConstants.PageSize) return false;
                    flags = KvmConstants.MemSlotReadOnly;
                }
                else
                {
                    flags = SlotFlags(page);
                }
                if (flags != slot.Flags) return false;
            }
            return true;
        }

        private bool TryGetKeptSlotEnd(ulong address, out ulong end)
        {
            end = 0;
            if (_keptSlotStarts.Count == 0 || _activeSlotStarts.Count == 0) return false;

            ulong start = _activeSlotStarts[FirstActiveSlotIndexAtOrBefore(address)];
            if (start > address || !_keptSlotStarts.Contains(start)) return false;

            InstalledSlot slot = _activeSlots[start];
            if (address - start >= slot.Size) return false;
            end = start + slot.Size;
            return true;
        }

        private void RebuildMappingsFull()
        {
            bool anyTrapped = _trappedPages.Count != 0;

            _desiredSlots.Clear();
            MarkIntactSlots(0, ulong.MaxValue);
            bool anyKept = _keptSlotStarts.Count != 0;

            ulong cursor = 0;
            while (_mappedPages.TryGetNext(cursor, out ulong runAddress, out GuestPage page))
            {
                if (TryGetKeptSlotEnd(runAddress, out ulong keptEnd))
                {
                    cursor = keptEnd;
                    continue;
                }

                cursor = runAddress + KvmConstants.PageSize;
                if (page.HostPage == IntPtr.Zero || page.Permissions == GuestPagePermission.None)
                    continue;

                if (anyTrapped && _trappedPages.TryGetValue(runAddress, out bool writeOnly))
                {
                    if (writeOnly)
                        _desiredSlots[runAddress] = MakeWriteWatchSlot(page);
                    continue;
                }

                long runHostBaseLong = page.HostPage.ToInt64();
                uint runFlags = SlotFlags(page);
                ulong runSize = KvmConstants.PageSize;

                while (true)
                {
                    ulong nextAddress = runAddress + runSize;
                    if (anyKept && _keptSlotStarts.Contains(nextAddress)) break;
                    if (!_mappedPages.TryGetValue(nextAddress, out GuestPage next)) break;
                    if (next.Permissions == GuestPagePermission.None || SlotFlags(next) != runFlags) break;
                    if (anyTrapped && _trappedPages.ContainsKey(nextAddress)) break;
                    if (next.HostPage.ToInt64() != runHostBaseLong + (long)runSize) break;
                    runSize += KvmConstants.PageSize;
                }

                _desiredSlots[runAddress] = new InstalledSlot
                {
                    Size = runSize,
                    Host = new IntPtr(runHostBaseLong),
                    Flags = runFlags,
                };
                cursor = runAddress + runSize;
            }

            _staleSlotKeys.Clear();
            _deletedSlotRanges.Clear();
            foreach (KeyValuePair<ulong, InstalledSlot> kv in _activeSlots)
            {
                if (!_desiredSlots.TryGetValue(kv.Key, out InstalledSlot want)
                    || want.Size != kv.Value.Size
                    || want.Host != kv.Value.Host
                    || want.Flags != kv.Value.Flags)
                {
                    if (!DeleteMemslot(kv.Value.Id))
                        _stillMappedBacking.Add(kv.Value);
                    _staleSlotKeys.Add(kv.Key);
                    _deletedSlotRanges.Add(new DirtyRange { Start = kv.Key, End = kv.Key + kv.Value.Size });
                }
                else
                {
                    _desiredSlots.Remove(kv.Key);
                }
            }
            for (int i = 0; i < _staleSlotKeys.Count; i++)
                _activeSlots.Remove(_staleSlotKeys[i]);

            foreach (KeyValuePair<ulong, InstalledSlot> kv in _desiredSlots)
                _activeSlots[kv.Key] = InstallSlot(kv.Key, kv.Value, WasSlotLive(kv.Key));

            _activeSlotStarts.Clear();
            foreach (KeyValuePair<ulong, InstalledSlot> kv in _activeSlots)
                _activeSlotStarts.Add(kv.Key);
            _activeSlotStarts.Sort();
        }

        private void RebuildMappingsIncremental(ulong spanStart, ulong spanEnd)
        {
            int firstIndex = FirstActiveSlotIndexAtOrBefore(spanStart);
            for (int i = firstIndex; i < _activeSlotStarts.Count; i++)
            {
                ulong start = _activeSlotStarts[i];
                if (start >= spanEnd) break;

                InstalledSlot active = _activeSlots[start];
                ulong end = start + active.Size;
                if (end <= spanStart) continue;

                if (start < spanStart) spanStart = start;
                if (end > spanEnd) spanEnd = end;
            }

            _desiredSlots.Clear();
            MarkIntactSlots(spanStart, spanEnd);
            BuildDesiredSlotsForSpan(spanStart, spanEnd);

            _staleSlotKeys.Clear();
            _deletedSlotRanges.Clear();
            firstIndex = FirstActiveSlotIndexAtOrBefore(spanStart);
            for (int i = firstIndex; i < _activeSlotStarts.Count; i++)
            {
                ulong start = _activeSlotStarts[i];
                if (start >= spanEnd) break;

                InstalledSlot active = _activeSlots[start];
                if (start + active.Size <= spanStart) continue;

                if (!_desiredSlots.TryGetValue(start, out InstalledSlot want)
                    || want.Size != active.Size
                    || want.Host != active.Host
                    || want.Flags != active.Flags)
                {
                    if (!DeleteMemslot(active.Id))
                        _stillMappedBacking.Add(active);
                    _staleSlotKeys.Add(start);
                    _deletedSlotRanges.Add(new DirtyRange { Start = start, End = start + active.Size });
                }
                else
                {
                    _desiredSlots.Remove(start);
                }
            }

            for (int i = 0; i < _staleSlotKeys.Count; i++)
                RemoveActiveSlot(_staleSlotKeys[i]);

            foreach (KeyValuePair<ulong, InstalledSlot> kv in _desiredSlots)
                AddActiveSlot(kv.Key, InstallSlot(kv.Key, kv.Value, WasSlotLive(kv.Key)));
        }

        // KVM cannot delete part of a slot. A changed slot is deleted and its clean parts are installed again.
        private void RebuildDirtyRanges()
        {
            _desiredSlots.Clear();
            _keptSlotStarts.Clear();
            _staleSlotKeys.Clear();
            _deletedSlotRanges.Clear();

            for (int r = 0; r < _dirtyRanges.Count; r++)
            {
                DirtyRange range = _dirtyRanges[r];
                for (int i = FirstActiveSlotIndexAtOrBefore(range.Start); i < _activeSlotStarts.Count; i++)
                {
                    ulong start = _activeSlotStarts[i];
                    if (start >= range.End) break;

                    InstalledSlot active = _activeSlots[start];
                    ulong end = start + active.Size;
                    if (end <= range.Start || OverlapsDirtyRangeBefore(r, start, end)) continue;

                    if (IsSlotIntactInDirtyRanges(start, active))
                    {
                        _keptSlotStarts.Add(start);
                        continue;
                    }

                    _staleSlotKeys.Add(start);
                    AddCleanSlotParts(start, active);
                }
            }

            for (int r = 0; r < _dirtyRanges.Count; r++)
                BuildDesiredSlotsForSpan(_dirtyRanges[r].Start, _dirtyRanges[r].End);

            for (int i = 0; i < _staleSlotKeys.Count; i++)
            {
                ulong start = _staleSlotKeys[i];
                InstalledSlot stale = _activeSlots[start];
                if (!DeleteMemslot(stale.Id))
                    _stillMappedBacking.Add(stale);
                _deletedSlotRanges.Add(new DirtyRange { Start = start, End = start + stale.Size });
                RemoveActiveSlot(start);
            }

            foreach (KeyValuePair<ulong, InstalledSlot> kv in _desiredSlots)
                AddActiveSlot(kv.Key, InstallSlot(kv.Key, kv.Value, WasSlotLive(kv.Key)));
        }

        private bool OverlapsDirtyRangeBefore(int index, ulong start, ulong end)
        {
            for (int r = 0; r < index; r++)
            {
                if (_dirtyRanges[r].Start < end && start < _dirtyRanges[r].End)
                    return true;
            }
            return false;
        }

        private bool IsSlotIntactInDirtyRanges(ulong start, InstalledSlot slot)
        {
            ulong end = start + slot.Size;
            for (int r = 0; r < _dirtyRanges.Count; r++)
            {
                ulong from = Math.Max(start, _dirtyRanges[r].Start);
                ulong to = Math.Min(end, _dirtyRanges[r].End);
                if (from < to && !IsSlotIntact(start, slot, from, to))
                    return false;
            }
            return true;
        }

        private void AddCleanSlotParts(ulong start, InstalledSlot slot)
        {
            ulong end = start + slot.Size;
            for (ulong cursor = start; cursor < end;)
            {
                ulong partEnd = end;
                ulong resume = end;
                for (int r = 0; r < _dirtyRanges.Count; r++)
                {
                    DirtyRange range = _dirtyRanges[r];
                    if (range.End <= cursor || range.Start >= partEnd) continue;
                    partEnd = Math.Max(range.Start, cursor);
                    resume = range.End;
                }

                if (partEnd > cursor)
                {
                    _desiredSlots[cursor] = new InstalledSlot
                    {
                        Size = partEnd - cursor,
                        Host = new IntPtr(slot.Host.ToInt64() + (long)(cursor - start)),
                        Flags = slot.Flags,
                    };
                }
                cursor = resume;
            }
        }

        private void BuildDesiredSlotsForSpan(ulong spanStart, ulong spanEnd)
        {
            bool anyTrapped = _trappedPages.Count != 0;
            bool anyKept = _keptSlotStarts.Count != 0;

            for (ulong address = spanStart; address < spanEnd;)
            {
                if (TryGetKeptSlotEnd(address, out ulong keptEnd))
                {
                    address = keptEnd;
                    continue;
                }

                if (!_mappedPages.TryGetValue(address, out GuestPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == GuestPagePermission.None)
                {
                    address += KvmConstants.PageSize;
                    continue;
                }

                if (anyTrapped && _trappedPages.TryGetValue(address, out bool writeOnly))
                {
                    if (writeOnly)
                        _desiredSlots[address] = MakeWriteWatchSlot(page);
                    address += KvmConstants.PageSize;
                    continue;
                }

                long runHostBaseLong = page.HostPage.ToInt64();
                uint runFlags = SlotFlags(page);
                ulong runSize = KvmConstants.PageSize;

                while (address + runSize < spanEnd)
                {
                    if (anyKept && _keptSlotStarts.Contains(address + runSize)) break;
                    if (!_mappedPages.TryGetValue(address + runSize, out GuestPage next) || next == null) break;
                    if (next.Permissions == GuestPagePermission.None || SlotFlags(next) != runFlags) break;
                    if (next.HostPage == IntPtr.Zero) break;
                    if (anyTrapped && _trappedPages.ContainsKey(address + runSize)) break;
                    if (next.HostPage.ToInt64() != runHostBaseLong + (long)runSize) break;
                    runSize += KvmConstants.PageSize;
                }

                _desiredSlots[address] = new InstalledSlot
                {
                    Size = runSize,
                    Host = new IntPtr(runHostBaseLong),
                    Flags = runFlags,
                };
                address += runSize;
            }
        }

        private static InstalledSlot MakeWriteWatchSlot(GuestPage page) => new InstalledSlot
        {
            Size = KvmConstants.PageSize,
            Host = page.HostPage,
            Flags = KvmConstants.MemSlotReadOnly,
        };

        private bool WasSlotLive(ulong start)
        {
            for (int i = 0; i < _deletedSlotRanges.Count; i++)
            {
                if (start >= _deletedSlotRanges[i].Start && start < _deletedSlotRanges[i].End)
                    return true;
            }
            return false;
        }

        private InstalledSlot InstallSlot(ulong guestAddress, InstalledSlot want, bool overLiveRange = false)
        {
            int slot = AllocateSlotId();
            SetMemslot(slot, guestAddress, want.Size, want.Host, want.Flags);
            if (overLiveRange)
                PopulateResidentRange(guestAddress, want.Size, want.Host);
            return new InstalledSlot
            {
                Id = slot,
                Size = want.Size,
                Host = want.Host,
                Flags = want.Flags,
            };
        }

        private int AllocateSlotId()
        {
            if (_freeSlotIds.Count > 0)
            {
                int slot = _freeSlotIds[_freeSlotIds.Count - 1];
                _freeSlotIds.RemoveAt(_freeSlotIds.Count - 1);
                return slot;
            }
            if (_nextSlotId >= _maxMemslots)
                throw new KvmException("Exhausted KVM memory slots");
            return _nextSlotId++;
        }

        private void SetMemslot(int slot, ulong guestAddress, ulong size, IntPtr hostBase, uint flags)
        {
            _paging.AssertMappingsHeld(nameof(SetMemslot));
            LinuxKvmUserspaceMemoryRegion region = new LinuxKvmUserspaceMemoryRegion
            {
                Slot = (uint)slot,
                Flags = flags,
                GuestPhysAddr = guestAddress,
                MemorySize = size,
                UserspaceAddr = (ulong)hostBase,
            };
            if (KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoSetUserMemoryRegion, ref region) < 0)
                throw new KvmException("KVM_SET_USER_MEMORY_REGION failed", Marshal.GetLastWin32Error());
        }

        // A slot KVM did not delete still maps its host memory, so its id is never reused.
        private bool DeleteMemslot(int slot)
        {
            _paging.AssertMappingsHeld(nameof(DeleteMemslot));
            LinuxKvmUserspaceMemoryRegion region = new LinuxKvmUserspaceMemoryRegion
            {
                Slot = (uint)slot,
                MemorySize = 0,
            };
            if (KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoSetUserMemoryRegion, ref region) < 0)
            {
                Utils.LogError($"[Kvm] Memory slot {slot} stays mapped: KVM_SET_USER_MEMORY_REGION failed with errno {Marshal.GetLastWin32Error()}.");
                return false;
            }

            _freeSlotIds.Add(slot);
            return true;
        }

        private void RefreshMmioBackedRegions()
        {
            if (_mmioRegions.Count == 0) return;

            long now = Stopwatch.GetTimestamp();
            if (now - Volatile.Read(ref _lastMmioRefreshTimestamp) < MmioRefreshIntervalTicks) return;

            using RankedLock.Scope mappingHold = _paging.LockMappings();
            lock (_mmioLock)
            {
                if (now - _lastMmioRefreshTimestamp < MmioRefreshIntervalTicks) return;
                Volatile.Write(ref _lastMmioRefreshTimestamp, now);

                for (int i = 0; i < _mmioRegions.Count; i++)
                    RefreshMmioRegion(_mmioRegions[i]);
            }
        }

        private unsafe void RefreshMmioRegion(MmioRegion region)
        {
            for (ulong offset = 0; offset < region.Size; offset += KvmConstants.PageSize)
            {
                if (!_mappedPages.TryGetValue(region.Address + offset, out GuestPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero)
                    continue;

                int chunk = (int)Math.Min(KvmConstants.PageSize, region.Size - offset);
                region.ReadCallback(offset, new Span<byte>((void*)page.HostPage, chunk));
            }
        }

        private bool HandlePreRunInstruction()
        {
            if (!_scanPreRunInstructions) return false;

            ulong rip = ReadRegister(Registers.UC_X86_REG_RIP);
            Span<byte> opcode = stackalloc byte[3];
            using (_paging.LockMappings())
            {
                if (!TryReadMemoryInternal(rip, opcode)) return false;
            }

            if (opcode[0] != 0x0F) return false;

            // rdtsc and rdtscp run on the processor, so they never reach here.
            if (_hasCpuIdHook && opcode[1] == 0xA2)
                return HandleInstructionHook(BackendInstructionHook.CpuId, 2);
            if (_hasInvalidHook && opcode[1] == 0x0B)
                return HandleInvalidInstructionHook();
            return false;
        }

        private void RefreshInstructionHookFlags()
        {
            _hasCpuIdHook = false;
            _hasInvalidHook = false;

            for (int i = 0; i < _instructionHooks.Count; i++)
            {
                switch (_instructionHooks[i].Type)
                {
                    case BackendInstructionHook.CpuId: _hasCpuIdHook = true; break;
                    case BackendInstructionHook.Invalid: _hasInvalidHook = true; break;
                }
            }

            _scanPreRunInstructions = _hasCpuIdHook || _hasInvalidHook;
        }

        private bool TryReadMemoryInternal(ulong address, Span<byte> buffer)
            => IsGuestRange(address, (ulong)buffer.Length) && TryReadPages(address, buffer);

        private bool TryReadPages(ulong address, Span<byte> buffer) => _paging.TryReadPages(address, buffer);

        private bool TryWriteMemoryInternal(ulong address, ReadOnlySpan<byte> buffer) => _paging.TryWritePages(address, buffer);

        private bool HandleInstructionHook(BackendInstructionHook type, ulong instructionSize)
        {
            ulong rip = ReadRegister(Registers.UC_X86_REG_RIP);
            bool handled = false;
            bool skip = false;

            for (int i = 0; i < _instructionHooks.Count; i++)
            {
                InstructionHookEntry entry = _instructionHooks[i];
                if (entry.Type != type) continue;

                handled = true;
                if (entry.Callback != null)
                {
                    entry.Callback();
                    skip = true;
                }
                else if (entry.BoolCallback != null)
                {
                    if (entry.BoolCallback()) skip = true;
                }
            }

            if (handled && skip)
            {
                if (ReadRegister(Registers.UC_X86_REG_RIP) == rip)
                    AdvanceRip(instructionSize);
                return true;
            }
            return false;
        }

        private bool HandleInvalidInstructionHook()
        {
            bool consumed = false;

            for (int i = 0; i < _instructionHooks.Count; i++)
            {
                InstructionHookEntry entry = _instructionHooks[i];
                if (entry.Type != BackendInstructionHook.Invalid) continue;

                if (entry.Callback != null) { entry.Callback(); consumed = true; }
                else if (entry.BoolCallback != null) { if (entry.BoolCallback()) consumed = true; }
            }

            return consumed;
        }

        private bool HandleHltExit(VirtualProcessor vp)
        {
            ulong rip = ReadRegister(Registers.UC_X86_REG_RIP);

            if (_guest64 && _syscallHook != null && rip == vp.SyscallStubGpa + _guestKernel.Layout.ResumeOffset)
            {
                if (HandleSyscallTrap()) return true;
                _error = KvmErrors.Ok;
                return false;
            }

            if (_guest64 && rip == _syscallTrapPageGpa + SyscallTrapPage.CompatSyscallOffset + 1)
                return HandleCompatSyscall();

            ulong stubEnd = _exceptionStubPageGpa +
                KvmConstants.ExceptionVectorCount * KvmConstants.ExceptionStubStride;
            if (rip > _exceptionStubPageGpa && rip <= stubEnd)
            {
                if (vp.SingleStepRequested &&
                    (uint)((rip - 1 - _exceptionStubPageGpa) / KvmConstants.ExceptionStubStride) == 1)
                {
                    vp.SingleStepRequested = false;
                    RestoreExceptionFrame(rip);
                    ClearTrapFlag();
                    _error = KvmErrors.Ok;
                    return false;
                }

                return HandleExceptionTrap(rip);
            }

            _error = KvmErrors.Ok;
            return false;
        }

        // A kick can exit with RIP on a stub's hlt before the hlt runs, or in the register stores before the syscall
        // stub's hlt. Count it as that hlt only in ring 0, because ring 3 can jump there too.
        private bool TryTakeStubEntryAsHalt()
        {
            VirtualProcessor vp = CurrentVp;
            ref LinuxKvmRegisters regs = ref GetRegistersRef();
            bool atExceptionStub = GuestInterruptGates.IsStubEntry(_exceptionStubPageGpa, KvmConstants.ExceptionVectorCount,
                KvmConstants.ExceptionStubStride, regs.Rip, out _);
            bool inSyscallStores = _guest64 && regs.Rip >= vp.SyscallStubGpa
                && regs.Rip <= vp.SyscallStubGpa + _guestKernel.Layout.HaltOffset;
            bool atCompatEntry = _guest64 && regs.Rip == _syscallTrapPageGpa + SyscallTrapPage.CompatSyscallOffset;
            if (!atExceptionStub && !inSyscallStores && !atCompatEntry)
                return false;
            if (GetSpecialRegistersRef().Cs.Dpl != 0)
                return false;

            regs.Rip = inSyscallStores ? vp.SyscallStubGpa + _guestKernel.Layout.ResumeOffset : regs.Rip + 1;
            MarkRegistersDirty();
            return true;
        }

        private unsafe bool HandleMmioExit(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            ref LinuxKvmMmioExit mmio = ref run.Exit.Mmio;
            ulong physAddr = mmio.PhysAddr;
            uint len = mmio.Len;
            byte isWrite = mmio.IsWrite;

            // A later fragment of the faulted instruction.
            if (vp.FaultRegistersSaved)
            {
                vp.MmioCompletionPending = true;
                return true;
            }

            lock (_mmioLock)
            {
                foreach (MmioRegion region in _mmioRegions)
                {
                    if (physAddr < region.Address || physAddr >= region.Address + region.Size) continue;
                    if (isWrite == 0) break;

                    ulong data = mmio.Data;
                    region.WriteCallback(physAddr - region.Address,
                        new ReadOnlySpan<byte>(&data, (int)Math.Min(len, sizeof(ulong))));
                    return true;
                }
            }

            ulong faultPage = physAddr & ~KvmConstants.PageMask;
            bool mapped;
            bool trapped;
            using (_paging.LockMappings())
            {
                mapped = _mappedPages.TryGetValue(faultPage, out GuestPage faulted)
                         && faulted != null
                         && faulted.HostPage != IntPtr.Zero;
                trapped = mapped && _trappedPages.ContainsKey(faultPage);

                // KVM reports a wide access one fragment at a time. A fragment on a page that is accessible now
                // is not a new fault.
                if (!trapped && mapped && IsPageAccessible(faultPage, isWrite != 0))
                {
                    if (_mappingsDirty) RebuildMappings();
                    CompleteMmioAccess(ref mmio);
                    return true;
                }
            }

            if (trapped)
                return HandleTrappedAccess(ref mmio, physAddr, len, isWrite != 0);

            BackendHookType required = mapped ? BackendHookType.MemoryProtected : BackendHookType.MemoryUnmapped;
            BackendMemoryAccessType type = mapped
                ? (isWrite != 0 ? BackendMemoryAccessType.WriteProtected : BackendMemoryAccessType.ReadProtected)
                : (isWrite != 0 ? BackendMemoryAccessType.WriteUnmapped : BackendMemoryAccessType.ReadUnmapped);

            bool hookRan = false;
            bool handled = false;
            for (int i = 0; i < _memoryHooks.Count; i++)
            {
                MemoryHookEntry entry = _memoryHooks[i];
                if ((entry.Type & required) == 0) continue;
                if (entry.End == 0 || entry.End < entry.Begin || (entry.Begin <= physAddr && entry.End >= physAddr))
                {
                    hookRan = true;
                    if (entry.Callback(type, physAddr, len, isWrite != 0 ? mmio.Data : 0))
                    {
                        handled = true;
                        break;
                    }
                }
            }

            // A guard page hook makes the page accessible and returns false. KVM does not retry, so the
            // access is applied here.
            if (!handled && hookRan && IsPageAccessible(faultPage, isWrite != 0))
            {
                if (_mappingsDirty) RebuildMappings();
                handled = true;
            }

            if (!handled)
            {
                // The completion writes back RIP and the loaded register. The fault-time registers go back
                // after it. KVM retires a write at the exit, so RIP is the next instruction. Only a stale TLB
                // entry gets here.
                vp.FaultRegisters = GetRegisters();
                vp.FaultRegistersSaved = true;
                vp.MmioCompletionPending = true;
                return false;
            }

            CompleteMmioAccess(ref mmio);
            return true;
        }

        private bool IsPageAccessible(ulong pageAddress, bool write)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (!TryGetBackedPage(pageAddress, out GuestPage page))
                return false;

            GuestPagePermission perm = page.Permissions;
            return GuestPageEntries.Allows((perm & GuestPagePermission.Read) != 0, (perm & GuestPagePermission.Write) != 0,
                (perm & GuestPagePermission.Execute) != 0, write ? GuestAccess.Write : GuestAccess.Read);
        }

        private bool TryGetBackedPage(ulong pageAddress, out GuestPage page)
        {
            page = null;
            return IsGuestRange(pageAddress, KvmConstants.PageSize) && !_trappedPages.ContainsKey(pageAddress)
                && _mappedPages.TryGetValue(pageAddress, out page) && page != null && page.HostPage != IntPtr.Zero;
        }

        private unsafe bool HandleTrappedAccess(ref LinuxKvmMmioExit mmio, ulong physAddr, uint len, bool isWrite)
        {
            BackendHookType required = isWrite ? BackendHookType.MemoryWrite : BackendHookType.MemoryRead;
            BackendMemoryAccessType type = isWrite ? BackendMemoryAccessType.Write : BackendMemoryAccessType.Read;

            for (int i = 0; i < _memoryHooks.Count; i++)
            {
                MemoryHookEntry entry = _memoryHooks[i];
                if ((entry.Type & required) == 0) continue;
                if (entry.Begin > physAddr || entry.End < physAddr) continue;
                entry.Callback(type, physAddr, len, isWrite ? mmio.Data : 0);
            }

            CompleteMmioAccess(ref mmio);

            if (!isWrite)
            {
                for (int i = 0; i < _memoryHooks.Count; i++)
                {
                    MemoryHookEntry entry = _memoryHooks[i];
                    if ((entry.Type & BackendHookType.MemoryReadAfter) == 0) continue;
                    if (entry.Begin > physAddr || entry.End < physAddr) continue;
                    entry.Callback(BackendMemoryAccessType.ReadAfter, physAddr, len, mmio.Data);
                }
            }

            return true;
        }

        private unsafe void CompleteMmioAccess(ref LinuxKvmMmioExit mmio)
        {
            // KVM retires the instruction on its next entry, before it reads immediate_exit.
            CurrentVp.MmioCompletionPending = true;

            uint len = mmio.Len;
            if (len == 0 || len > sizeof(ulong)) return;

            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (mmio.IsWrite != 0)
            {
                ulong data = mmio.Data;
                TryWriteMemoryInternal(mmio.PhysAddr, new ReadOnlySpan<byte>(&data, (int)len));
                return;
            }

            ulong value = 0;
            if (TryReadMemoryInternal(mmio.PhysAddr, new Span<byte>(&value, (int)len)))
                mmio.Data = value;
        }

        private bool HandleException(uint exception, uint errorCode)
        {
            if (exception == 6 && HandleInvalidInstructionHook()) return true;

            if (exception == 14)
            {
                ulong faultAddress = ReadRegister(Registers.UC_X86_REG_CR2);
                ulong faultPage = faultAddress & ~KvmConstants.PageMask;

                bool write = (errorCode & GuestPageEntries.FaultWrite) != 0;
                bool fetch = (errorCode & GuestPageEntries.FaultFetch) != 0;

                // No-access pages are not present, so the present bit cannot tell mapped from unmapped.
                bool mapped;
                using (_paging.LockMappings())
                {
                    mapped = _mappedPages.TryGetValue(faultPage, out GuestPage faulted)
                             && faulted != null
                             && faulted.HostPage != IntPtr.Zero;
                }

                BackendMemoryAccessType type;
                if (fetch)
                    type = mapped ? BackendMemoryAccessType.FetchProtected : BackendMemoryAccessType.FetchUnmapped;
                else if (write)
                    type = mapped ? BackendMemoryAccessType.WriteProtected : BackendMemoryAccessType.WriteUnmapped;
                else
                    type = mapped ? BackendMemoryAccessType.ReadProtected : BackendMemoryAccessType.ReadUnmapped;

                bool hookRan = false;
                for (int i = 0; i < _memoryHooks.Count; i++)
                {
                    MemoryHookEntry entry = _memoryHooks[i];
                    if ((entry.Type & (BackendHookType.MemoryUnmapped | BackendHookType.MemoryProtected)) == 0) continue;
                    if (entry.End == 0 || entry.End < entry.Begin || (entry.Begin <= faultAddress && entry.End >= faultAddress))
                    {
                        hookRan = true;
                        if (entry.Callback(type, faultAddress, 1, 0)) return true;
                    }
                }

                // A guard page hook makes the page accessible and returns false. Retry the access.
                if (hookRan && IsPageAccessible(faultPage, write))
                {
                    if (_mappingsDirty) RebuildMappings();
                    return true;
                }

                return false;
            }

            CurrentVp.InterruptErrorCode = errorCode;
            bool handled = false;
            for (int i = 0; i < _interruptHooks.Count; i++)
                handled |= _interruptHooks[i].Callback(exception);

            return handled || (_interruptHooks.Count != 0 && exception >= KvmConstants.FirstSoftwareInterruptVector);
        }

        public uint InterruptErrorCode => CurrentVp.InterruptErrorCode;

        private void RestoreExceptionFrame(ulong stubRip)
            => ReadExceptionFrame(stubRip, out _, out _);

        private bool HandleExceptionTrap(ulong stubRip)
        {
            bool fromUserMode = ReadExceptionFrame(stubRip, out uint vector, out ulong errorCode);
            if (!fromUserMode)
            {
                ref LinuxKvmRun run = ref GetRunRef();
                if (TryFinishKernelCall(CurrentVp, ref run, run.Regs.Rip, run.Regs.Rflags, out bool resumed))
                    return resumed;
                return HandleKernelFault(vector);
            }
            if (vector == 14 && (_paging.TryTouchWatchedPage(errorCode, ReadRegister(Registers.UC_X86_REG_CR2)) || IsStaleFault(errorCode)))
                return true;
            if (HandleException(vector, (uint)errorCode))
                return true;
            _error = KvmErrors.Exception;
            return false;
        }

        // A mov ss before a syscall or a user gate delays a data breakpoint #DB into ring 0. Any other fault in ring 0
        // comes from the backend itself.
        private unsafe bool HandleKernelFault(uint vector)
        {
            ulong rip = GetRegistersRef().Rip;
            if (_guest64 && vector == 1 && rip == CurrentVp.SyscallStubGpa && HandleSyscallTrap())
                return true;

            bool atUserGate = false;
            if (vector == 1)
            {
                using RankedLock.Scope mappingHold = _paging.LockMappings();
                atUserGate = _mappedPages.TryGetValue(_exceptionIdtPageGpa, out GuestPage idtPage)
                    && GuestInterruptGates.IsUserGateEntry((byte*)idtPage.HostPage, _exceptionStubPageGpa, KvmConstants.ExceptionVectorCount,
                        KvmConstants.ExceptionStubStride, rip);
            }
            if (atUserGate)
                return HandleExceptionTrap(rip + 1);

            Utils.LogError($"[Kvm] Vector 0x{vector:X} faulted in ring 0 at 0x{rip:X}.");
            _error = KvmErrors.InternalError;
            return false;
        }

        // A VM entry at a non-canonical RIP fails, so give the guest the #GP(0) the processor would raise.
        private bool RaiseNonCanonicalFetch(VirtualProcessor vp)
        {
            if (HandleException(13, 0) && (vp.StopRequested || LongModeAddress.IsCanonical(GetRegistersRef().Rip)))
                return true;
            _error = KvmErrors.Exception;
            return false;
        }

        // AMD enters CSTAR on a syscall from compatibility mode, but Intel raises #UD, so the guest gets #UD.
        private bool HandleCompatSyscall()
        {
            ref LinuxKvmRun run = ref GetRunRef();
            run.Regs.Rip = (uint)run.Regs.Rcx - 2u;
            run.Regs.Rflags = run.Regs.R11;
            run.Sregs.Cs = MakeSegment(KvmConstants.UserCodeSelector32, true, true, code64: false);
            run.Sregs.Ss = MakeSegment(KvmConstants.UserDataSelector, false, true);
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;

            if (HandleException(6, 0))
                return true;
            _error = KvmErrors.Exception;
            return false;
        }

        // A stale TLB entry, or a fault that raced a grant on another processor. The #PF already dropped the entry.
        private bool IsStaleFault(ulong errorCode)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            ulong page = ReadRegister(Registers.UC_X86_REG_CR2) & ~KvmConstants.PageMask;
            if (!TryGetBackedPage(page, out GuestPage mapped))
                return false;

            GuestPagePermission perm = mapped.Permissions;
            if (!GuestPageEntries.IsStaleFault(errorCode, (perm & GuestPagePermission.Read) != 0,
                    (perm & GuestPagePermission.Write) != 0, (perm & GuestPagePermission.Execute) != 0))
                return false;

            _paging.SetLeaf(page, perm);
            return true;
        }

        /// <returns>False when the frame was taken in ring 0.</returns>
        private unsafe bool ReadExceptionFrame(ulong stubRip, out uint vector, out ulong errorCode)
        {
            vector = (uint)((stubRip - 1 - _exceptionStubPageGpa) / KvmConstants.ExceptionStubStride);
            errorCode = 0;

            VirtualProcessor vp = CurrentVp;
            ref LinuxKvmRun run = ref GetRunRef(vp);
            bool hasErrorCode = ExceptionHasErrorCode(vector);
            ulong frameAddress = run.Regs.Rsp + (hasErrorCode ? sizeof(ulong) : 0UL);

            Span<ulong> frame = stackalloc ulong[5];
            IntPtr frameHost = frameAddress == vp.InterruptFrameGpa ? vp.InterruptFrameHost
                : frameAddress == vp.DebugFrameGpa ? vp.DebugFrameHost
                : IntPtr.Zero;
            if (frameHost != IntPtr.Zero)
            {
                ulong* pushed = (ulong*)frameHost;
                if (hasErrorCode)
                    errorCode = pushed[-1];
                new ReadOnlySpan<ulong>(pushed, frame.Length).CopyTo(frame);
            }
            else
            {
                using RankedLock.Scope mappingHold = _paging.LockMappings();
                if (hasErrorCode)
                {
                    Span<byte> ecBytes = stackalloc byte[sizeof(ulong)];
                    ecBytes.Clear();
                    TryReadPages(run.Regs.Rsp, ecBytes);
                    errorCode = BitConverter.ToUInt64(ecBytes);
                }

                frame.Clear();
                TryReadPages(frameAddress, MemoryMarshal.AsBytes(frame));
            }

            ulong frameRip = frame[0];
            ulong frameCs = frame[1];
            ulong frameRflags = frame[2];
            ulong frameRsp = frame[3];
            ulong frameSs = frame[4];

            // A fault on either sysretq of the trap page belongs to the user address it was returning to.
            if (_guest64 && (frameRip == _syscallTrapPageGpa + SyscallReturnOffset
                             || frameRip == _syscallTrapPageGpa + FlushingSysretOffset))
            {
                frameRip = run.Regs.Rcx;
                frameRflags = run.Regs.R11;
                frameCs = KvmConstants.UserCodeSelector;
                frameSs = KvmConstants.UserDataSelector;
            }

            // A fault on the iretq stub belongs to the ring 3 state it was returning to.
            if (frameRip == _exceptionStubPageGpa + IretStubOffset && (frameCs & 3) == 0)
            {
                RestoreIretReturn(vp, ref run);
                return true;
            }

            run.Regs.Rip = frameRip;
            run.Regs.Rsp = frameRsp;
            run.Regs.Rflags = UserModeFlags.Clamp(frameRflags);
            run.Sregs.Cs = MakeSegment((ushort)(frameCs | 3), true, true);
            run.Sregs.Ss = MakeSegment((ushort)(frameSs | 3), false, true);
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;
            return (frameCs & 3) == 3;
        }

        private void ClearPendingExceptionState()
        {
            lock (CurrentVp.RegisterLock)
            {
                LinuxKvmVcpuEvents events = new LinuxKvmVcpuEvents();
                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoGetVcpuEvents, ref events) < 0)
                    return;

                events.Exception.Injected = 0;
                events.Exception.Pending = 0;
                events.Exception.HasErrorCode = 0;
                events.Exception.ErrorCode = 0;
                events.ExceptionHasPayload = 0;
                events.ExceptionPayload = 0;
                events.Interrupt.Injected = 0;
                events.Interrupt.Shadow = 0;
                events.Nmi.Injected = 0;
                events.Nmi.Pending = 0;

                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoSetVcpuEvents, ref events) < 0)
                    return;
            }
        }

        private bool HandleDebugExit(ref LinuxKvmRun run)
        {
            uint exception = run.Exit.Debug.Exception;
            CurrentVp.InterruptErrorCode = 0;
            for (int i = 0; i < _interruptHooks.Count; i++)
                _interruptHooks[i].Callback(exception);

            return _interruptHooks.Count != 0;
        }

        private bool HandleSyscallTrap()
        {
            if (_syscallHook == null) return false;

            ref LinuxKvmRegisters regs = ref GetRegistersRef();

            ulong postSyscallRcx = regs.Rcx;
            ulong postSyscallR10 = regs.R10;
            ulong savedRflags = regs.R11;
            ulong preSyscallRip = postSyscallRcx - 2;

            regs.Rip = preSyscallRip;
            regs.Rcx = postSyscallR10;
            regs.Rflags = savedRflags;
            MarkRegistersDirty();
            ReturnThroughSyscallTrapPage(CurrentVp);

            if (_syscallHook.Callback != null) _syscallHook.Callback();
            else if (_syscallHook.BoolCallback != null) _syscallHook.BoolCallback();

            regs = ref GetRegistersRef();
            if (regs.Rip == preSyscallRip)
                regs.Rip = postSyscallRcx;
            else
                regs.Rip += 2;
            MarkRegistersDirty();
            return true;
        }

        private bool InSyscallStubPage(VirtualProcessor vp, ulong rip)
            => _guest64 && rip >= vp.SyscallStubGpa && rip < vp.SyscallStubGpa + KvmConstants.PageSize;

        // A kernel call never resumes after an exit, because its views can be unmapped during the wait for the lock.
        private unsafe bool TryFinishKernelCall(VirtualProcessor vp, ref LinuxKvmRun run, ulong rip, ulong rflags, out bool resumed)
        {
            resumed = false;
            if (!InSyscallStubPage(vp, rip))
                return false;

            GuestKernelCallState state = _guestKernel.Settle(vp.SyscallSpill, rip - vp.SyscallStubGpa, rflags);
            if (state == GuestKernelCallState.None)
                return false;

            // A stop on a deferred mapping would repeat until the mappings are rebuilt.
            if (_mappingsDirty)
                RebuildMappings();

            ref LinuxKvmRegisters regs = ref run.Regs;
            new ReadOnlySpan<ulong>((void*)vp.SyscallSpill, GuestSyscallStub.RegisterSlots)
                .CopyTo(MemoryMarshal.CreateSpan(ref regs.Rax, GuestSyscallStub.RegisterSlots));
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters;
            if (state == GuestKernelCallState.Committed)
            {
                regs.Rip = regs.Rcx;
                regs.Rflags = regs.R11;
                regs.Rax = 0;
                SetSyscallReturnVolatiles(ref regs);
                ReturnThroughSyscallTrapPage(vp);
                resumed = true;
                return true;
            }

            resumed = HandleSyscallTrap();
            if (!resumed)
                _error = KvmErrors.Ok;
            return true;
        }

        private bool TryFinishInterruptedKernelCall(VirtualProcessor vp, ref LinuxKvmRun run, out bool resumed)
        {
            if (vp.KernelCallStopped)
            {
                vp.KernelCallStopped = false;
                return TryFinishKernelCall(vp, ref run, vp.KernelCallRip, vp.KernelCallRflags, out resumed);
            }

            resumed = false;
            return run.Sregs.Cs.Dpl == 0 && TryFinishKernelCall(vp, ref run, run.Regs.Rip, run.Regs.Rflags, out resumed);
        }

        // KVM finishes the access on the next entry, and immediate_exit ends that entry before more guest code runs.
        private bool TryDeferKernelCallExit(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            if (!vp.KernelCallStopped)
            {
                if (run.Sregs.Cs.Dpl != 0 || !InSyscallStubPage(vp, run.Regs.Rip)
                    || _guestKernel.Layout.Classify(run.Regs.Rip - vp.SyscallStubGpa, run.Regs.Rflags, out _) == GuestKernelCallState.None)
                    return false;

                vp.KernelCallStopped = true;
                vp.KernelCallRip = run.Regs.Rip;
                vp.KernelCallRflags = run.Regs.Rflags;
            }

            vp.MmioCompletionPending = true;
            run.ImmediateExit = 1;
            return true;
        }

        private void ReturnThroughSyscallTrapPage(VirtualProcessor vp)
        {
            ShowUserCodeAndStackSegments();
            vp.InSyscallStub = true;
            vp.SyscallScratchWritten = false;
        }

        // sysretq loads the user segments, so the register page write is not marked dirty.
        private void ShowUserCodeAndStackSegments()
        {
            ref LinuxKvmSpecialRegisters sregs = ref GetSpecialRegistersRef();
            sregs.Cs = MakeSegment(KvmConstants.UserCodeSelector, true, true);
            sregs.Ss = MakeSegment(KvmConstants.UserDataSelector, false, true);
        }

        private void NoteSyscallScratchWrite(GpRegisterName name, ulong before, ulong after)
        {
            if (before != after && (name == GpRegisterName.Rcx || name == GpRegisterName.R11))
                CurrentVp.SyscallScratchWritten = true;
        }

        private static void LeaveSyscallStub(VirtualProcessor vp)
        {
            if (!vp.InSyscallStub) return;
            vp.InSyscallStub = false;
            GetRunRef(vp).DirtyRegs |= KvmConstants.SyncSpecialRegisters;
        }

        // sysretq takes RIP from RCX and RFLAGS from R11, which is what NT leaves in them.
        private void PrepareSyscallReturn(VirtualProcessor vp, ref LinuxKvmRun run, bool flushTlb)
        {
            // sysretq traps as soon as it restores TF, so a return with TF set goes through iretq instead.
            if (vp.SingleStepRequested || (run.Regs.Rflags & 0x100UL) != 0)
                run.DirtyRegs |= KvmConstants.SyncSpecialRegisters;

            // A value written to RCX or R11 survives sysretq only when it is the one sysretq loads there.
            if (vp.SyscallScratchWritten && (run.Regs.Rcx != run.Regs.Rip || run.Regs.R11 != run.Regs.Rflags))
                run.DirtyRegs |= KvmConstants.SyncSpecialRegisters;
            vp.SyscallScratchWritten = false;

            if ((run.DirtyRegs & KvmConstants.SyncSpecialRegisters) != 0)
            {
                vp.InSyscallStub = false;
                return;
            }

            ref LinuxKvmRegisters regs = ref run.Regs;
            regs.Rcx = regs.Rip;
            regs.R11 = regs.Rflags;
            regs.Rflags = 0x2;
            regs.Rip = _syscallTrapPageGpa + (flushTlb ? FlushingSyscallReturnOffset : SyscallReturnOffset);
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters;
        }

        // A run that ended before guest entry leaves RIP in the stub. Before the CR3 reload, the flush is still owed.
        private void CompleteSyscallReturn(VirtualProcessor vp, ref LinuxKvmRun run, bool flushRequired)
        {
            ref LinuxKvmRegisters regs = ref run.Regs;
            ulong flushingStub = _syscallTrapPageGpa + FlushingSyscallReturnOffset;
            bool inFlushingStub = regs.Rip >= flushingStub && regs.Rip <= _syscallTrapPageGpa + FlushingSysretOffset;
            if (regs.Rip != _syscallTrapPageGpa + SyscallReturnOffset && !inFlushingStub)
            {
                vp.InSyscallStub = false;
                return;
            }

            if (inFlushingStub)
            {
                if (regs.Rip < flushingStub + 8)
                {
                    if (flushRequired)
                        vp.TlbFlushPending = true;
                    else
                        vp.TlbFlushOnSyscallReturn = true;
                }
                regs.R10 = 0;
            }

            regs.Rip = regs.Rcx;
            regs.Rflags = regs.R11;
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters;
            ShowUserCodeAndStackSegments();
        }

        // On KVM a VM entry with TF set traps before the first instruction runs. iretq lets one instruction run
        // first, as NT and Linux do. The frame goes on the IST stack, which is unused while the guest is in ring 3.
        private unsafe void PrepareIretReturn(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            if (run.Sregs.Cs.Dpl != 3 || vp.InterruptFrameHost == IntPtr.Zero)
                return;

            ulong* slots = (ulong*)vp.InterruptFrameHost;
            slots[0] = run.Regs.Rip;
            slots[1] = run.Sregs.Cs.Selector;
            slots[2] = run.Regs.Rflags;
            slots[3] = run.Regs.Rsp;
            slots[4] = run.Sregs.Ss.Selector;

            vp.InIretStub = true;
            vp.IretReturn = new UserReturnState(run.Regs.Rip, run.Regs.Rsp, run.Regs.Rflags, run.Sregs.Cs, run.Sregs.Ss);

            run.Regs.Rip = _exceptionStubPageGpa + IretStubOffset;
            run.Regs.Rsp = vp.InterruptFrameGpa;
            run.Regs.Rflags = 0x2;
            run.Sregs.Cs = StubCodeSegment;
            run.Sregs.Ss = StubStackSegment;
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;
        }

        // If the run ended before the iretq executed, put the ring 3 state back.
        private void CompleteIretReturn(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            vp.InIretStub = false;
            if (run.Regs.Rip == _exceptionStubPageGpa + IretStubOffset)
                RestoreIretReturn(vp, ref run);
        }

        private static void RestoreIretReturn(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            UserReturnState state = vp.IretReturn;
            run.Regs.Rip = state.Rip;
            run.Regs.Rsp = state.Rsp;
            run.Regs.Rflags = state.Rflags;
            run.Sregs.Cs = state.Cs;
            run.Sregs.Ss = state.Ss;
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters | KvmConstants.SyncSpecialRegisters;
        }

        private void AdvanceRip(ulong amount)
        {
            GetRegistersRef().Rip += amount;
            MarkRegistersDirty();
        }

        // KVM starts every new vCPU TSC at zero, while the guest and the shared QPC page take one TSC for the
        // whole partition. Later vCPUs get the offset of the first.
        private unsafe void AlignTimestampCounter(VirtualProcessor vp)
        {
            if (!_supportsVcpuAttributes)
                return;

            ulong value = 0;
            LinuxKvmDeviceAttr attr = new LinuxKvmDeviceAttr
            {
                Group = KvmConstants.VcpuTscCtrl,
                Attr = KvmConstants.VcpuTscOffset,
                Addr = (ulong)&value,
            };

            if (!_tscOffsetKnown)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoGetDeviceAttr, ref attr) < 0)
                    return;
                _tscOffset = value;
                _tscOffsetKnown = true;
                return;
            }

            value = _tscOffset;
            KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoSetDeviceAttr, ref attr);
        }

        private ulong GetMsr(VirtualProcessor vp, uint msr)
        {
            lock (vp.RegisterLock)
            {
                LinuxKvmMsrs msrs = new LinuxKvmMsrs
                {
                    Count = 1,
                    FirstEntry = new LinuxKvmMsrEntry { Index = msr },
                };
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoGetMsrs, ref msrs) != 1)
                    throw new KvmException("KVM_GET_MSRS failed", Marshal.GetLastWin32Error());
                return msrs.FirstEntry.Data;
            }
        }

        private void SetMsr(VirtualProcessor vp, uint msr, ulong value)
        {
            lock (vp.RegisterLock)
            {
                LinuxKvmMsrs msrs = new LinuxKvmMsrs
                {
                    Count = 1,
                    FirstEntry = new LinuxKvmMsrEntry { Index = msr, Data = value },
                };
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoSetMsrs, ref msrs) != 1)
                    throw new KvmException("KVM_SET_MSRS failed", Marshal.GetLastWin32Error());
            }
        }

        private ref LinuxKvmRegisters GetRegistersRef() => ref GetRunRef().Regs;

        private LinuxKvmRegisters GetRegisters() => GetRegistersRef();

        private void SetRegisters(in LinuxKvmRegisters regs)
        {
            ref LinuxKvmRegisters current = ref GetRegistersRef();
            if (regs.Rcx != current.Rcx || regs.R11 != current.R11)
                LeaveSyscallStub(CurrentVp);
            current = regs;
            MarkRegistersDirty();
        }

        private void MarkRegistersDirty() => GetRunRef().DirtyRegs |= KvmConstants.SyncGeneralRegisters;

        private ref LinuxKvmSpecialRegisters GetSpecialRegistersRef() => ref GetRunRef().Sregs;

        private void MarkSpecialRegistersDirty() => GetRunRef().DirtyRegs |= KvmConstants.SyncSpecialRegisters;

        internal const int XmmRegisterCount = 16;

        public bool SupportsAvx => _avxEnabled;

        public bool UmipEnabled => (_cr4Protection & ControlRegister4.Umip) != 0;

        private void SetXcr0(VirtualProcessor vp)
        {
            LinuxKvmXcrs xcrs = new LinuxKvmXcrs { Count = 1, Value = KvmConstants.XcrAvxFeatures };
            lock (vp.RegisterLock)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoSetXcrs, ref xcrs) < 0)
                    throw new KvmException("KVM_SET_XCRS failed", Marshal.GetLastWin32Error());
            }
        }

        // A write starts from the current image so the x87 and MXCSR state stay as they are.
        public unsafe bool TransferVectorState(ulong[] Xmm, ulong[] YmmHigh, bool Write)
        {
            if (!_avxEnabled)
            {
                if (!Write && YmmHigh != null) Array.Clear(YmmHigh);
                return TransferXmmRegisters(Xmm, Write);
            }
            if (Xmm == null || Xmm.Length < XmmRegisterCount * 2 || YmmHigh == null || YmmHigh.Length < XmmRegisterCount * 2)
                return false;

            VirtualProcessor vp = CurrentVp;
            vp.XsaveImage ??= new byte[_xsaveSize];
            int fd = vp.Fd;
            uint getRequest = _supportsXsave2 ? KvmConstants.KvmIoGetXsave2 : KvmConstants.KvmIoGetXsave;

            lock (vp.RegisterLock)
            {
                fixed (byte* image = vp.XsaveImage)
                {
                    if (KvmNative.ioctl(fd, getRequest, (IntPtr)image) < 0)
                        return false;

                    ulong* xmm = (ulong*)(image + KvmConstants.XsaveXmmOffset);
                    ulong* ymmHigh = (ulong*)(image + _ymmHighOffset);
                    ulong* stateMask = (ulong*)(image + KvmConstants.XsaveHeaderOffset);

                    if (!Write)
                    {
                        bool avxLive = (*stateMask & KvmConstants.XcrAvx) != 0;
                        for (int i = 0; i < XmmRegisterCount * 2; i++)
                        {
                            Xmm[i] = xmm[i];
                            YmmHigh[i] = avxLive ? ymmHigh[i] : 0;
                        }
                        return true;
                    }

                    for (int i = 0; i < XmmRegisterCount * 2; i++)
                    {
                        xmm[i] = Xmm[i];
                        ymmHigh[i] = YmmHigh[i];
                    }
                    *stateMask |= KvmConstants.XcrSse | KvmConstants.XcrAvx;
                    stateMask[1] = 0;
                    return KvmNative.ioctl(fd, KvmConstants.KvmIoSetXsave, (IntPtr)image) >= 0;
                }
            }
        }

        /// <summary>
        /// Transfers XMM0-15 as 32 qwords, low half of each register first.
        /// </summary>
        public unsafe bool TransferXmmRegisters(ulong[] Values, bool Write)
        {
            if (Values == null || Values.Length < XmmRegisterCount * 2)
                return false;

            LinuxKvmFpu Fpu = default;

            lock (CurrentVp.RegisterLock)
            {
                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoGetFpu, (IntPtr)(&Fpu)) < 0)
                    return false;

                if (Write)
                {
                    for (int i = 0; i < XmmRegisterCount * 2; i++)
                        ((ulong*)Fpu.Xmm)[i] = Values[i];

                    if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoSetFpu, (IntPtr)(&Fpu)) < 0)
                        return false;
                }
                else
                {
                    for (int i = 0; i < XmmRegisterCount * 2; i++)
                        Values[i] = ((ulong*)Fpu.Xmm)[i];
                }
            }

            return true;
        }

        private unsafe void SetFpu(VirtualProcessor vp, ref LinuxKvmFpu fpu)
        {
            lock (vp.RegisterLock)
            {
                fixed (LinuxKvmFpu* p = &fpu)
                {
                    if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoSetFpu, (IntPtr)p) < 0)
                        throw new KvmException("KVM_SET_FPU failed", Marshal.GetLastWin32Error());
                }
            }
        }

        private void SetVcpuEvents(LinuxKvmVcpuEvents events)
        {
            lock (CurrentVp.RegisterLock)
            {
                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoSetVcpuEvents, ref events) < 0)
                    throw new KvmException("KVM_SET_VCPU_EVENTS failed", Marshal.GetLastWin32Error());
            }
        }

        private LinuxKvmDebugRegisters GetDebugRegisters()
        {
            lock (CurrentVp.RegisterLock)
            {
                LinuxKvmDebugRegisters dr = new LinuxKvmDebugRegisters();
                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoGetDebugRegisters, ref dr) < 0)
                    throw new KvmException("KVM_GET_DEBUGREGS failed", Marshal.GetLastWin32Error());
                return dr;
            }
        }

        private void SetDebugRegisters(LinuxKvmDebugRegisters dr)
        {
            lock (CurrentVp.RegisterLock)
            {
                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoSetDebugRegisters, ref dr) < 0)
                    throw new KvmException("KVM_SET_DEBUGREGS failed", Marshal.GetLastWin32Error());
            }
        }

        private static ref ulong GetGpRegisterPointer(ref LinuxKvmRegisters regs, GpRegisterName name)
        {
            switch (name)
            {
                case GpRegisterName.Rax: return ref regs.Rax;
                case GpRegisterName.Rbx: return ref regs.Rbx;
                case GpRegisterName.Rcx: return ref regs.Rcx;
                case GpRegisterName.Rdx: return ref regs.Rdx;
                case GpRegisterName.Rsi: return ref regs.Rsi;
                case GpRegisterName.Rdi: return ref regs.Rdi;
                case GpRegisterName.Rbp: return ref regs.Rbp;
                case GpRegisterName.Rsp: return ref regs.Rsp;
                case GpRegisterName.Rip: return ref regs.Rip;
                case GpRegisterName.R8: return ref regs.R8;
                case GpRegisterName.R9: return ref regs.R9;
                case GpRegisterName.R10: return ref regs.R10;
                case GpRegisterName.R11: return ref regs.R11;
                case GpRegisterName.R12: return ref regs.R12;
                case GpRegisterName.R13: return ref regs.R13;
                case GpRegisterName.R14: return ref regs.R14;
                case GpRegisterName.R15: return ref regs.R15;
                case GpRegisterName.Rflags: return ref regs.Rflags;
                default: throw new KvmException("Unsupported KVM GP register");
            }
        }

        private bool TryWriteSpecialRegister(Registers register, ulong value)
        {
            if (DebugRegisters.IsDebugRegister(register))
            {
                WriteDebugRegister(register, value);
                return true;
            }

            if (IsFpControlRegister(register))
                return TransferFpControl(register, ref value, true);

            if (!IsSregRegister(register)) return false;

            // The page holds the current value, so an unchanged write needs no entry-time update.
            ref LinuxKvmSpecialRegisters sregs = ref GetSpecialRegistersRef();
            if (TryApplySregRead(ref sregs, register, out ulong current) && current == value) return true;

            if (!TryApplySregWrite(ref sregs, register, value)) return false;
            if (!_guest64 && register == Registers.UC_X86_REG_FS_BASE)
                SyncGdtDescriptorBase(value);
            MarkSpecialRegistersDirty();
            return true;
        }

        // A compatibility-mode segment load takes the base from the descriptor, not from the MSR.
        private unsafe void SyncGdtDescriptorBase(ulong segmentBase)
        {
            using RankedLock.Scope mappingHold = _paging.LockMappings();
            if (!_mappedPages.TryGetValue(CurrentVp.GdtPageGpa, out GuestPage gdtPage) || gdtPage.HostPage == IntPtr.Zero)
                return;

            byte* descriptor = (byte*)gdtPage.HostPage + (KvmConstants.UserFsSelector32 >> 3) * 8;
            descriptor[2] = (byte)segmentBase;
            descriptor[3] = (byte)(segmentBase >> 8);
            descriptor[4] = (byte)(segmentBase >> 16);
            descriptor[7] = (byte)(segmentBase >> 24);
        }

        private bool TryReadSpecialRegister(Registers register, out ulong value)
        {
            if (DebugRegisters.IsDebugRegister(register))
            {
                value = ReadDebugRegister(register);
                return true;
            }

            value = 0;

            if (IsFpControlRegister(register))
                return TransferFpControl(register, ref value, false);

            if (!IsSregRegister(register))
                return false;

            return TryApplySregRead(ref GetSpecialRegistersRef(), register, out value);
        }

        private bool TransferFpControl(Registers register, ref ulong value, bool Write)
        {
            ReadOnlySpan<int> name = stackalloc int[] { (int)register };
            Span<ulong> data = stackalloc ulong[] { value };
            bool transferred = TransferFpControl(name, data, Write);
            value = data[0];
            return transferred;
        }

        private unsafe bool TransferFpControl(ReadOnlySpan<int> registers, Span<ulong> values, bool Write)
        {
            LinuxKvmFpu Fpu = default;

            lock (CurrentVp.RegisterLock)
            {
                if (KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoGetFpu, (IntPtr)(&Fpu)) < 0)
                    return false;

                for (int i = 0; i < registers.Length; i++)
                {
                    switch ((Registers)registers[i])
                    {
                        case Registers.UC_X86_REG_FPCW:
                            if (Write) Fpu.Fcw = (ushort)values[i]; else values[i] = Fpu.Fcw;
                            break;
                        case Registers.UC_X86_REG_FPSW:
                            if (Write) Fpu.Fsw = (ushort)values[i]; else values[i] = Fpu.Fsw;
                            break;
                        case Registers.UC_X86_REG_MXCSR:
                            if (Write) Fpu.Mxcsr = (uint)values[i]; else values[i] = Fpu.Mxcsr;
                            break;
                        default:
                            return false;
                    }
                }

                return !Write || KvmNative.ioctl(CurrentVp.Fd, KvmConstants.KvmIoSetFpu, (IntPtr)(&Fpu)) >= 0;
            }
        }

        private static bool IsSregRegister(Registers register) => register switch
        {
            Registers.UC_X86_REG_FS_BASE => true,
            Registers.UC_X86_REG_GS_BASE => true,
            Registers.UC_X86_REG_CS => true,
            Registers.UC_X86_REG_SS => true,
            Registers.UC_X86_REG_DS => true,
            Registers.UC_X86_REG_ES => true,
            Registers.UC_X86_REG_FS => true,
            Registers.UC_X86_REG_GS => true,
            Registers.UC_X86_REG_CR0 => true,
            Registers.UC_X86_REG_CR2 => true,
            Registers.UC_X86_REG_CR3 => true,
            Registers.UC_X86_REG_CR4 => true,
            Registers.UC_X86_REG_CR8 => true,
            Registers.UC_X86_REG_MSR => true,
            _ => false,
        };

        private static bool TryApplySregWrite(ref LinuxKvmSpecialRegisters s, Registers register, ulong value)
        {
            switch (register)
            {
                case Registers.UC_X86_REG_FS_BASE: s.Fs.Base = value; return true;
                case Registers.UC_X86_REG_GS_BASE: s.Gs.Base = value; return true;
                case Registers.UC_X86_REG_CS: s.Cs.Selector = (ushort)value; return true;
                case Registers.UC_X86_REG_SS: s.Ss.Selector = (ushort)value; return true;
                case Registers.UC_X86_REG_DS: s.Ds.Selector = (ushort)value; return true;
                case Registers.UC_X86_REG_ES: s.Es.Selector = (ushort)value; return true;
                case Registers.UC_X86_REG_FS: s.Fs.Selector = (ushort)value; return true;
                case Registers.UC_X86_REG_GS: s.Gs.Selector = (ushort)value; return true;
                case Registers.UC_X86_REG_CR0: s.Cr0 = value; return true;
                case Registers.UC_X86_REG_CR2: s.Cr2 = value; return true;
                case Registers.UC_X86_REG_CR3: s.Cr3 = value; return true;
                case Registers.UC_X86_REG_CR4: s.Cr4 = value; return true;
                case Registers.UC_X86_REG_CR8: s.Cr8 = value; return true;
                case Registers.UC_X86_REG_MSR: s.Efer = value; return true;
                default: return false;
            }
        }

        private static bool TryApplySregRead(ref LinuxKvmSpecialRegisters s, Registers register, out ulong value)
        {
            value = 0;
            switch (register)
            {
                case Registers.UC_X86_REG_FS_BASE: value = s.Fs.Base; return true;
                case Registers.UC_X86_REG_GS_BASE: value = s.Gs.Base; return true;
                case Registers.UC_X86_REG_CS: value = s.Cs.Selector; return true;
                case Registers.UC_X86_REG_SS: value = s.Ss.Selector; return true;
                case Registers.UC_X86_REG_DS: value = s.Ds.Selector; return true;
                case Registers.UC_X86_REG_ES: value = s.Es.Selector; return true;
                case Registers.UC_X86_REG_FS: value = s.Fs.Selector; return true;
                case Registers.UC_X86_REG_GS: value = s.Gs.Selector; return true;
                case Registers.UC_X86_REG_CR0: value = s.Cr0; return true;
                case Registers.UC_X86_REG_CR2: value = s.Cr2; return true;
                case Registers.UC_X86_REG_CR3: value = s.Cr3; return true;
                case Registers.UC_X86_REG_CR4: value = s.Cr4; return true;
                case Registers.UC_X86_REG_CR8: value = s.Cr8; return true;
                case Registers.UC_X86_REG_MSR: value = s.Efer; return true;
                default: return false;
            }
        }

        private static bool IsFpControlRegister(Registers register)
            => register is Registers.UC_X86_REG_FPCW or Registers.UC_X86_REG_FPSW or Registers.UC_X86_REG_MXCSR;

        private void WriteDebugRegister(Registers register, ulong value)
        {
            ReadOnlySpan<int> name = stackalloc int[] { (int)register };
            ReadOnlySpan<ulong> data = stackalloc ulong[] { value };
            WriteDebugRegisters(name, data);
        }

        private void WriteDebugRegisters(ReadOnlySpan<int> registers, ReadOnlySpan<ulong> values)
        {
            VirtualProcessor vp = CurrentVp;
            if (vp.DebugRegisterCache.IsUnchanged(registers, values))
                return;

            int covered = 0;
            for (int i = 0; i < registers.Length; i++)
                covered |= 1 << DebugRegisters.Index((Registers)registers[i]);

            LinuxKvmDebugRegisters dr = covered == AllDebugRegisterBits ? default : GetDebugRegisters();
            for (int i = 0; i < registers.Length; i++)
                SetDebugRegisterValue(ref dr, DebugRegisters.Index((Registers)registers[i]), values[i]);
            SetDebugRegisters(dr);
            vp.DebugRegisterCache.Note(registers, values);
        }

        private const int AllDebugRegisterBits = (1 << DebugRegisters.Count) - 1;

        private ulong ReadDebugRegister(Registers register) => DebugRegisterValue(GetDebugRegisters(), DebugRegisters.Index(register));

        private static unsafe ulong DebugRegisterValue(LinuxKvmDebugRegisters dr, int index) => index switch
        {
            0 or 1 or 2 or 3 => dr.Db[index],
            4 => dr.Dr7,
            5 => dr.Dr6,
            _ => 0,
        };

        private static unsafe void SetDebugRegisterValue(ref LinuxKvmDebugRegisters dr, int index, ulong value)
        {
            switch (index)
            {
                case 0 or 1 or 2 or 3: dr.Db[index] = value; break;
                case 4: dr.Dr7 = value; break;
                case 5: dr.Dr6 = value; break;
            }
        }

        private static GpRegisterAccess ClassifyGpRegister(Registers register)
        {
            switch (register)
            {
                case Registers.UC_X86_REG_AL: return new GpRegisterAccess { Name = GpRegisterName.Rax, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_AH: return new GpRegisterAccess { Name = GpRegisterName.Rax, Offset = 1, Width = sizeof(byte) };
                case Registers.UC_X86_REG_AX: return new GpRegisterAccess { Name = GpRegisterName.Rax, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_EAX: return new GpRegisterAccess { Name = GpRegisterName.Rax, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RAX: return new GpRegisterAccess { Name = GpRegisterName.Rax, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_BL: return new GpRegisterAccess { Name = GpRegisterName.Rbx, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_BH: return new GpRegisterAccess { Name = GpRegisterName.Rbx, Offset = 1, Width = sizeof(byte) };
                case Registers.UC_X86_REG_BX: return new GpRegisterAccess { Name = GpRegisterName.Rbx, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_EBX: return new GpRegisterAccess { Name = GpRegisterName.Rbx, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RBX: return new GpRegisterAccess { Name = GpRegisterName.Rbx, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_CL: return new GpRegisterAccess { Name = GpRegisterName.Rcx, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_CH: return new GpRegisterAccess { Name = GpRegisterName.Rcx, Offset = 1, Width = sizeof(byte) };
                case Registers.UC_X86_REG_CX: return new GpRegisterAccess { Name = GpRegisterName.Rcx, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_ECX: return new GpRegisterAccess { Name = GpRegisterName.Rcx, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RCX: return new GpRegisterAccess { Name = GpRegisterName.Rcx, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_DL: return new GpRegisterAccess { Name = GpRegisterName.Rdx, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_DH: return new GpRegisterAccess { Name = GpRegisterName.Rdx, Offset = 1, Width = sizeof(byte) };
                case Registers.UC_X86_REG_DX: return new GpRegisterAccess { Name = GpRegisterName.Rdx, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_EDX: return new GpRegisterAccess { Name = GpRegisterName.Rdx, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RDX: return new GpRegisterAccess { Name = GpRegisterName.Rdx, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_SIL: return new GpRegisterAccess { Name = GpRegisterName.Rsi, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_SI: return new GpRegisterAccess { Name = GpRegisterName.Rsi, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_ESI: return new GpRegisterAccess { Name = GpRegisterName.Rsi, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RSI: return new GpRegisterAccess { Name = GpRegisterName.Rsi, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_DIL: return new GpRegisterAccess { Name = GpRegisterName.Rdi, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_DI: return new GpRegisterAccess { Name = GpRegisterName.Rdi, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_EDI: return new GpRegisterAccess { Name = GpRegisterName.Rdi, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RDI: return new GpRegisterAccess { Name = GpRegisterName.Rdi, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_BPL: return new GpRegisterAccess { Name = GpRegisterName.Rbp, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_BP: return new GpRegisterAccess { Name = GpRegisterName.Rbp, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_EBP: return new GpRegisterAccess { Name = GpRegisterName.Rbp, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RBP: return new GpRegisterAccess { Name = GpRegisterName.Rbp, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_SPL: return new GpRegisterAccess { Name = GpRegisterName.Rsp, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_SP: return new GpRegisterAccess { Name = GpRegisterName.Rsp, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_ESP: return new GpRegisterAccess { Name = GpRegisterName.Rsp, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RSP: return new GpRegisterAccess { Name = GpRegisterName.Rsp, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_IP: return new GpRegisterAccess { Name = GpRegisterName.Rip, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_EIP: return new GpRegisterAccess { Name = GpRegisterName.Rip, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_RIP: return new GpRegisterAccess { Name = GpRegisterName.Rip, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R8B: return new GpRegisterAccess { Name = GpRegisterName.R8, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R8W: return new GpRegisterAccess { Name = GpRegisterName.R8, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R8D: return new GpRegisterAccess { Name = GpRegisterName.R8, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R8: return new GpRegisterAccess { Name = GpRegisterName.R8, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R9B: return new GpRegisterAccess { Name = GpRegisterName.R9, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R9W: return new GpRegisterAccess { Name = GpRegisterName.R9, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R9D: return new GpRegisterAccess { Name = GpRegisterName.R9, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R9: return new GpRegisterAccess { Name = GpRegisterName.R9, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R10B: return new GpRegisterAccess { Name = GpRegisterName.R10, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R10W: return new GpRegisterAccess { Name = GpRegisterName.R10, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R10D: return new GpRegisterAccess { Name = GpRegisterName.R10, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R10: return new GpRegisterAccess { Name = GpRegisterName.R10, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R11B: return new GpRegisterAccess { Name = GpRegisterName.R11, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R11W: return new GpRegisterAccess { Name = GpRegisterName.R11, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R11D: return new GpRegisterAccess { Name = GpRegisterName.R11, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R11: return new GpRegisterAccess { Name = GpRegisterName.R11, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R12B: return new GpRegisterAccess { Name = GpRegisterName.R12, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R12W: return new GpRegisterAccess { Name = GpRegisterName.R12, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R12D: return new GpRegisterAccess { Name = GpRegisterName.R12, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R12: return new GpRegisterAccess { Name = GpRegisterName.R12, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R13B: return new GpRegisterAccess { Name = GpRegisterName.R13, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R13W: return new GpRegisterAccess { Name = GpRegisterName.R13, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R13D: return new GpRegisterAccess { Name = GpRegisterName.R13, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R13: return new GpRegisterAccess { Name = GpRegisterName.R13, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R14B: return new GpRegisterAccess { Name = GpRegisterName.R14, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R14W: return new GpRegisterAccess { Name = GpRegisterName.R14, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R14D: return new GpRegisterAccess { Name = GpRegisterName.R14, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R14: return new GpRegisterAccess { Name = GpRegisterName.R14, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_R15B: return new GpRegisterAccess { Name = GpRegisterName.R15, Offset = 0, Width = sizeof(byte) };
                case Registers.UC_X86_REG_R15W: return new GpRegisterAccess { Name = GpRegisterName.R15, Offset = 0, Width = sizeof(ushort) };
                case Registers.UC_X86_REG_R15D: return new GpRegisterAccess { Name = GpRegisterName.R15, Offset = 0, Width = sizeof(uint), ZeroExtend32 = true };
                case Registers.UC_X86_REG_R15: return new GpRegisterAccess { Name = GpRegisterName.R15, Offset = 0, Width = sizeof(ulong) };
                case Registers.UC_X86_REG_FLAGS:
                case Registers.UC_X86_REG_EFLAGS:
                case Registers.UC_X86_REG_RFLAGS: return new GpRegisterAccess { Name = GpRegisterName.Rflags, Offset = 0, Width = sizeof(ulong) };
                default: return default;
            }
        }

        private unsafe bool TryGetHostPointer(ulong address, int accessSize, bool write, out byte* ptr, out long offset)
            => _paging.TryGetHostPointer(address, accessSize, write, out ptr, out offset);

        private bool DisposedCheck()
        {
            if (Disposed || Disposing)
            {
                if (ThrowDisposed) throw new ObjectDisposedException(nameof(Kvm));
                return true;
            }
            return false;
        }
    }
}
