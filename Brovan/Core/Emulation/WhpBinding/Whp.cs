using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Buffers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation
{
    public class WhpException : SystemException
    {
        public int LastError { get; }

        public WhpException(string message) : base(message) { }

        public WhpException(string message, int hr) : base($"{message}: hr=0x{hr:X8}")
        {
            LastError = hr;
        }

        public WhpException() : base("WHP backend exception occurred.") { }
    }

    public sealed class Whp : IDisposable
    {
        private IntPtr _partition = IntPtr.Zero;
        private const uint SharedVpIndex = 0;
        private const uint MaxVirtualProcessors = 240;
        private const ulong ExceptionStackPages = 2;

        private readonly Dictionary<ulong, MappedPage> _mappedPages = new();
        private readonly Dictionary<IntPtr, BackingAllocation> _backingAllocations = new();
        private ulong _backingBytes;
        private readonly Dictionary<ulong, bool> _trappedPages = new();
        private readonly Dictionary<ulong, IntPtr> _pageTableViews = new();

        private ulong[] _sortedPageKeys = Array.Empty<ulong>();
        private bool _sortedPageKeysDirty = true;
        private bool _mappingsDirty;
        private ulong _lastLookupPageBase = ulong.MaxValue;
        private MappedPage _lastLookupPage;

        private readonly Dictionary<ulong, InstalledMap> _activeMaps = new();
        private readonly Dictionary<ulong, InstalledMap> _desiredMaps = new();
        private readonly List<ulong> _staleMapKeys = new();

        private readonly List<ulong> _activeMapStarts = new();
        private readonly HashSet<ulong> _keptMapStarts = new();

        // Kept maps never merge, so past this count the next rebuild merges everything and starts over.
        private const int MaxGpaRanges = 8192;
        private const int MapHeadroom = 64;
        private bool _fullRebuildRequired = true;
        private readonly List<DirtyRange> _dirtyRanges = new();
        private const int MaxDirtyRanges = 16;

        private readonly bool _guest64;
        private ulong _pml4Gpa;
        private ulong _nextInternalGpa = WhpConstants.InternalPageTableBase;

        private IntPtr _internalPoolPtr = IntPtr.Zero;
        private const ulong InternalPoolSize = 16 * 1024 * 1024;
        private ulong _internalPoolOffset;
        private readonly List<(IntPtr Ptr, ulong Size)> _internalPoolFallbacks = new();

        private ulong _syscallTrapPageGpa;
        private ulong _exceptionStubPageGpa;
        private ulong _exceptionIdtPageGpa;
        private ulong _gdtPageGpa;

        private readonly object _vcpuLock = new();

        private sealed class VirtualProcessor
        {
            public Whp Owner;
            public uint Index;
            public uint ThreadId;
            public IntPtr ExitContextPtr;
            public ulong GdtPageGpa;
            public ulong TssPageGpa;
            public WhpRegisters Regs;
            public bool RegsValid;
            public bool RegsDirty;
            public readonly WhvRegisterValue[] Xmm = new WhvRegisterValue[VectorRegisterCount];
            public bool XmmValid;
            public bool XmmDirty;
            public WhvRegisterValue PendingCs;
            public WhvRegisterValue PendingSs;
            public bool SegmentsDirty;
            public ulong FsBase = ulong.MaxValue;
            public ulong GsBase = ulong.MaxValue;

            public bool CompletionActive;
            public ulong CompletionPageGpa;
            public ulong CompletionAccessGpa;
            public uint CompletionLen;
            public bool CompletionIsWrite;

            public volatile bool StopRequested;
            public volatile bool Running;
            public int HostThreadId;
            public bool SingleStepRequested;
            public long SliceDeadlineTimestamp;
            public long SliceGeneration;
            public long SliceExpiredGeneration;

            // Bumped when the VP leaves a guest thread. A selection made before the bump is stale.
            public long Binding;
        }

        // One VP per guest thread, so a thread switch moves no register state. A thread that cannot get one waits.
        private readonly List<VirtualProcessor> _processors = new();
        private VirtualProcessor[] _processorSnapshot = Array.Empty<VirtualProcessor>();
        private readonly Stack<VirtualProcessor> _idleProcessors = new();
        private readonly Dictionary<uint, VirtualProcessor> _threadProcessors = new();
        private uint _processorLimit;

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
                    : _processors[(int)SharedVpIndex];
            }
        }

        private static void SelectProcessor(VirtualProcessor vp)
        {
            t_vp = vp;
            t_vpBinding = vp.Binding;
        }

        private object _runLock;

        private readonly WhvRegisterValue _userCodeSegment;
        private readonly WhvRegisterValue _userDataSegment;

        private readonly List<MemoryHookEntry> _memoryHooks = new();
        private readonly List<MmioRegion> _mmioRegions = new();
        private InstructionHookEntry _syscallHook;
        private readonly List<InstructionHookEntry> _instructionHooks = new();
        private readonly List<InterruptHookEntry> _interruptHooks = new();
        private readonly List<IntPtr> _liveHookHandles = new();

        private readonly object _mmioLock = new();
        private readonly object _partitionLock = new();
        private Thread _maintenanceThread;

        // WHP cannot end a run after a set number of instructions, so a slice that makes no VM exit is
        // bounded by wall clock instead. Without it one guest loop never returns to the scheduler.
        private const int BoundedSliceMilliseconds = 10;

        // The next slice clears the trap flag, so an armed completion cannot carry over.
        private const int CompletionGraceMilliseconds = 10;

        private int _disposed;
        private int _disposing;

        public bool NoHooks;
        public static bool ThrowDisposed = true;
        public bool Disposed => Volatile.Read(ref _disposed) == 1;
        private bool Disposing => Volatile.Read(ref _disposing) == 1;

        [ThreadStatic]
        private static WhpErrors _error;

        private sealed class MappedPage
        {
            public IntPtr HostPage;
            public IntPtr OwnedBacking;
            public bool IsAlias;
            public WhpMemoryPermission Permissions;
        }

        private sealed class BackingAllocation
        {
            public ulong Size;
            public int LivePages;
            public int AliasPages;
        }

        private struct InstalledMap
        {
            public ulong Size;
            public IntPtr Host;
            public WhvMapGpaRangeFlags Flags;
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
            public IntPtr[] HostPages;
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

        private struct WhpRegisters
        {
            public ulong Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rsp, Rbp;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public ulong Rip, Rflags;
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

        private static readonly uint[] GpRegNames =
        {
            (uint)WhvRegisterName.Rax, (uint)WhvRegisterName.Rbx, (uint)WhvRegisterName.Rcx, (uint)WhvRegisterName.Rdx,
            (uint)WhvRegisterName.Rsi, (uint)WhvRegisterName.Rdi, (uint)WhvRegisterName.Rsp, (uint)WhvRegisterName.Rbp,
            (uint)WhvRegisterName.R8, (uint)WhvRegisterName.R9, (uint)WhvRegisterName.R10, (uint)WhvRegisterName.R11,
            (uint)WhvRegisterName.R12, (uint)WhvRegisterName.R13, (uint)WhvRegisterName.R14, (uint)WhvRegisterName.R15,
            (uint)WhvRegisterName.Rip, (uint)WhvRegisterName.Rflags,
        };

        private static readonly uint[] GpRegNamesWithSegments =
        {
            (uint)WhvRegisterName.Rax, (uint)WhvRegisterName.Rbx, (uint)WhvRegisterName.Rcx, (uint)WhvRegisterName.Rdx,
            (uint)WhvRegisterName.Rsi, (uint)WhvRegisterName.Rdi, (uint)WhvRegisterName.Rsp, (uint)WhvRegisterName.Rbp,
            (uint)WhvRegisterName.R8, (uint)WhvRegisterName.R9, (uint)WhvRegisterName.R10, (uint)WhvRegisterName.R11,
            (uint)WhvRegisterName.R12, (uint)WhvRegisterName.R13, (uint)WhvRegisterName.R14, (uint)WhvRegisterName.R15,
            (uint)WhvRegisterName.Rip, (uint)WhvRegisterName.Rflags,
            (uint)WhvRegisterName.Cs, (uint)WhvRegisterName.Ss,
        };

        public Whp(Arch arch, Mode mode)
        {
            if (arch != Arch.X86 || (mode != Mode.MODE_64 && mode != Mode.MODE_32))
                throw new WhpException("WHP backend only supports x86 32-bit and x86-64 guests.");

            _guest64 = mode == Mode.MODE_64;
            _userCodeSegment = MakeSegment(_guest64 ? WhpConstants.UserCodeSelector : WhpConstants.UserCodeSelector32, true, true);
            _userDataSegment = MakeSegment(_guest64 ? WhpConstants.UserDataSelector : WhpConstants.UserDataSelector32, false, true);

            EnsurePlatformSupport();
            _timestampCounterFrequency = QueryTimestampCounterFrequency();
            ConfigurePartition();
            AllocateInternalPool();
            InitializeLongModePageTables();
            InitializeGdt();
            InitializeSyscallTrapPage();
            InitializeExceptionHandling();
            SelectProcessor(CreateProcessor(SharedVpIndex));
            RebuildMappings();
        }

        public WhpErrors GetLastError() => _error;

        private readonly ulong _timestampCounterFrequency;

        public ulong TimestampCounterFrequency => _timestampCounterFrequency;

        private static unsafe ulong QueryTimestampCounterFrequency()
        {
            ulong frequency = 0;
            uint written = 0;
            int hr = WhpNative.WHvGetCapability(WhvCapabilityCode.ProcessorClockFrequency, &frequency, sizeof(ulong), &written);
            return WhpNative.Failed(hr) || written < sizeof(ulong) ? 0 : frequency;
        }

        public bool TryReadTimestampCounter(out ulong value)
        {
            value = 0;
            if (DisposedCheck())
                return false;

            try
            {
                value = GetSingleRegister(WhvRegisterName.Tsc).Low;
                return true;
            }
            catch (WhpException)
            {
                return false;
            }
        }

        public bool MapMemoryShared(ulong address, ulong size, MemoryProtection protection, IntPtr hostPointer)
        {
            if (DisposedCheck() || hostPointer == IntPtr.Zero) return false;

            if ((address & WhpConstants.PageMask) != 0 || (size & WhpConstants.PageMask) != 0)
            {
                _error = WhpErrors.InvalidArgument;
                return false;
            }

            WhpMemoryPermission perm = TranslateProtection(protection);
            long backingAddr = hostPointer.ToInt64();
            IntPtr backing = FindBackingAllocation(hostPointer);

            for (ulong off = 0; off < size; off += WhpConstants.PageSize)
            {
                ulong guest = address + off;

                // Referenced before the replaced page is released, so the last reference cannot drop mid-loop.
                if (backing != IntPtr.Zero && _backingAllocations.TryGetValue(backing, out BackingAllocation allocation))
                    allocation.AliasPages++;

                if (_mappedPages.TryGetValue(guest, out MappedPage previous))
                    ReleaseBacking(previous);

                SetMappedPage(guest, new MappedPage
                {
                    HostPage = new IntPtr(backingAddr + (long)off),
                    OwnedBacking = backing,
                    IsAlias = true,
                    Permissions = perm,
                });
                EnsureVirtualMapping(guest);
            }

            RebuildMappings();
            _error = WhpErrors.Ok;
            return true;
        }

        public bool MapMemory(ulong address, ulong size, MemoryProtection protection)
        {
            if (DisposedCheck()) return false;

            if ((address & WhpConstants.PageMask) != 0 || (size & WhpConstants.PageMask) != 0)
            {
                _error = WhpErrors.InvalidArgument;
                return false;
            }

            WhpMemoryPermission perm = TranslateProtection(protection);

            bool canBatch = true;
            for (ulong off = 0; off < size; off += WhpConstants.PageSize)
            {
                if (_mappedPages.TryGetValue(address + off, out MappedPage existing) && existing.HostPage != IntPtr.Zero)
                {
                    canBatch = false;
                    break;
                }
            }

            if (canBatch && size > 0)
            {
                if (!TryAllocateBackingMemory(size, out IntPtr backing))
                {
                    _error = WhpErrors.NoMemory;
                    return false;
                }

                long backingAddr = backing.ToInt64();
                _backingAllocations[backing] = new BackingAllocation
                {
                    Size = size,
                    LivePages = (int)(size / WhpConstants.PageSize),
                };

                for (ulong off = 0; off < size; off += WhpConstants.PageSize)
                {
                    ulong guest = address + off;
                    MappedPage page = new MappedPage
                    {
                        HostPage = new IntPtr(backingAddr + (long)off),
                        OwnedBacking = backing,
                        Permissions = perm,
                    };
                    SetMappedPage(guest, page);
                    EnsureVirtualMapping(guest);
                }

                _error = WhpErrors.Ok;
                return true;
            }

            for (ulong off = 0; off < size; off += WhpConstants.PageSize)
            {
                ulong guest = address + off;
                if (!_mappedPages.TryGetValue(guest, out MappedPage page))
                {
                    page = new MappedPage();
                    SetMappedPage(guest, page);
                }

                if (page.HostPage == IntPtr.Zero)
                {
                    if (!TryAllocateBackingMemory(WhpConstants.PageSize, out IntPtr backing))
                    {
                        RebuildMappings();
                        _error = WhpErrors.NoMemory;
                        return false;
                    }

                    _backingAllocations[backing] = new BackingAllocation
                    {
                        Size = WhpConstants.PageSize,
                        LivePages = 1,
                    };
                    page.HostPage = backing;
                    page.OwnedBacking = backing;
                }

                page.Permissions = perm;
                MarkSpanDirty(guest, WhpConstants.PageSize);
                EnsureVirtualMapping(guest);
            }

            _error = WhpErrors.Ok;
            return true;
        }

        public bool UnmapMemory(ulong address, ulong size)
        {
            if (DisposedCheck()) return false;

            if ((address & WhpConstants.PageMask) != 0 || (size & WhpConstants.PageMask) != 0)
            {
                _error = WhpErrors.InvalidArgument;
                return false;
            }

            int removedRegions;
            lock (_mmioLock)
            {
                removedRegions = _mmioRegions.RemoveAll(r => r.Address >= address && r.Address < address + size);
            }

            for (ulong off = 0; off < size; off += WhpConstants.PageSize)
            {
                ulong guest = address + off;
                if (_mappedPages.TryGetValue(guest, out MappedPage page))
                {
                    ReleaseBacking(page);
                    RemoveMappedPage(guest);
                }
            }

            if (removedRegions != 0)
                RefreshTrappedPages();
            else
                RebuildMappings();
            _error = WhpErrors.Ok;
            return true;
        }

        public bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection)
        {
            if (DisposedCheck()) return false;

            WhpMemoryPermission perm = TranslateProtection(protection);
            for (ulong off = 0; off < size; off += WhpConstants.PageSize)
            {
                if (_mappedPages.TryGetValue(address + off, out MappedPage page))
                {
                    page.Permissions = perm;
                    MarkSpanDirty(address + off, WhpConstants.PageSize);
                }
            }

            RebuildMappings();
            _error = WhpErrors.Ok;
            return true;
        }

        public bool MapMmio(ulong address, ulong size, MmioReadCallback read, MmioWriteCallback write)
        {
            if (DisposedCheck()) return false;

            if (read == null || write == null ||
                (address & WhpConstants.PageMask) != 0 || (size & WhpConstants.PageMask) != 0 || size == 0)
            {
                _error = WhpErrors.InvalidArgument;
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
                HostPages = new IntPtr[size / WhpConstants.PageSize],
            };

            for (ulong offset = 0; offset < size; offset += WhpConstants.PageSize)
            {
                if (_mappedPages.TryGetValue(address + offset, out MappedPage page) && page != null)
                    region.HostPages[offset / WhpConstants.PageSize] = page.HostPage;
            }

            lock (_mmioLock)
            {
                _mmioRegions.RemoveAll(r => r.Address == address);
                _mmioRegions.Add(region);
                RefreshMmioRegion(region);
            }

            RefreshTrappedPages();
            EnsureMaintenanceThread();
            _error = WhpErrors.Ok;
            return true;
        }

        private void RefreshMmioBackedRegions()
        {
            if (_mmioRegions.Count == 0) return;

            lock (_mmioLock)
            {
                for (int i = 0; i < _mmioRegions.Count; i++)
                    RefreshMmioRegion(_mmioRegions[i]);
            }
        }

        private unsafe void RefreshMmioRegion(MmioRegion region)
        {
            for (int i = 0; i < region.HostPages.Length; i++)
            {
                IntPtr hostPage = region.HostPages[i];
                if (hostPage == IntPtr.Zero)
                    continue;

                ulong offset = (ulong)i * WhpConstants.PageSize;
                int chunk = (int)Math.Min(WhpConstants.PageSize, region.Size - offset);
                region.ReadCallback(offset, new Span<byte>((void*)hostPage, chunk));
            }
        }

        // Slice deadlines are enforced from a 1 ms sleep loop, which the default 15.6 ms system timer
        // would stretch to 16 ms; the request is per process and released with the partition.
        private const uint MaintenanceTimerPeriodMs = 1;

        private void EnsureMaintenanceThread()
        {
            if (_maintenanceThread != null)
                return;

            WhpNative.timeBeginPeriod(MaintenanceTimerPeriodMs);
            _maintenanceThread = new Thread(MaintenanceLoop)
            {
                IsBackground = true,
                Name = "WhpMaintenance"
            };
            _maintenanceThread.Start();
        }

        private void MaintenanceLoop()
        {
            while (!Disposed && !Disposing)
            {
                lock (_mmioLock)
                {
                    for (int i = 0; i < _mmioRegions.Count; i++)
                        RefreshMmioRegion(_mmioRegions[i]);
                }

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

                // Emulate arms the generation first, so reading it second keeps the pair consistent.
                long deadline = Volatile.Read(ref vp.SliceDeadlineTimestamp);
                long generation = Volatile.Read(ref vp.SliceGeneration);
                if (deadline == 0 || now < deadline)
                    continue;

                if (Interlocked.CompareExchange(ref vp.SliceDeadlineTimestamp, 0, deadline) != deadline)
                    continue;

                // Naming the slice that ran out keeps a late cancel from ending the one that replaced it.
                Volatile.Write(ref vp.SliceExpiredGeneration, generation);
                CancelRun(vp);
            }
        }

        private void CancelRun(VirtualProcessor vp)
        {
            lock (_partitionLock)
            {
                if (_partition != IntPtr.Zero)
                    WhpNative.WHvCancelRunVirtualProcessor(_partition, vp.Index, 0);
            }
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
            if (length == 0) { _error = WhpErrors.Ok; return true; }

            if (TryGetHostPointer(address, length, out byte* dst, out long dstOffset))
            {
                _error = WhpErrors.Ok;
                fixed (byte* src = value)
                    Unsafe.CopyBlockUnaligned(dst + dstOffset, src + offset, (uint)length);
                return true;
            }

            if (TryWriteMemoryInternal(address, new ReadOnlySpan<byte>(value, offset, length)))
            {
                _error = WhpErrors.Ok;
                return true;
            }

            _error = WhpErrors.MemoryWriteUnmapped;
            return false;
        }

        public unsafe bool WriteMemory(ulong address, ReadOnlySpan<byte> value, uint length = 0)
        {
            if (DisposedCheck()) return false;
            uint writeLen = ClampLength(length, value.Length);
            if (writeLen == 0) return false;

            if (TryGetHostPointer(address, (int)writeLen, out byte* dst, out long offset))
            {
                _error = WhpErrors.Ok;
                fixed (byte* src = value)
                    Unsafe.CopyBlockUnaligned(dst + offset, src, writeLen);
                return true;
            }

            if (TryWriteMemoryInternal(address, value.Slice(0, (int)writeLen)))
            {
                _error = WhpErrors.Ok;
                return true;
            }

            _error = WhpErrors.MemoryWriteUnmapped;
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
                _error = WhpErrors.Ok;
                return value;
            }

            if (TryGetHostPointer(address, (int)length, out byte* src, out long offset))
            {
                _error = WhpErrors.Ok;
                Unsafe.CopyBlockUnaligned(ref value[0], ref Unsafe.AsRef<byte>(src + offset), length);
            }
            else if (TryReadMemoryInternal(address, value))
            {
                _error = WhpErrors.Ok;
            }
            else
            {
                _error = WhpErrors.MemoryReadUnmapped;
            }
            return value;
        }

        public unsafe bool ReadMemory(ulong address, Span<byte> value, uint length = 0)
        {
            if (DisposedCheck()) return false;
            uint readLen = ClampLength(length, value.Length);
            if (readLen == 0) return false;

            if (TryGetHostPointer(address, (int)readLen, out byte* src, out long offset))
            {
                _error = WhpErrors.Ok;
                fixed (byte* dst = value)
                    Unsafe.CopyBlockUnaligned(dst, src + offset, readLen);
                return true;
            }

            if (TryReadMemoryInternal(address, value.Slice(0, (int)readLen)))
            {
                _error = WhpErrors.Ok;
                return true;
            }

            _error = WhpErrors.MemoryReadUnmapped;
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
            if (TryGetHostPointer(address, sizeof(ulong), out byte* ptr, out long offset))
            {
                _error = WhpErrors.Ok;
                return *(ulong*)(ptr + offset);
            }
            Span<byte> buffer = stackalloc byte[sizeof(ulong)];
            if (TryReadMemoryInternal(address, buffer))
            {
                _error = WhpErrors.Ok;
                return BitConverter.ToUInt64(buffer);
            }
            _error = WhpErrors.MemoryReadUnmapped;
            return 0;
        }

        public unsafe uint ReadMemoryUInt(ulong address)
        {
            if (DisposedCheck()) return 0;
            if (TryGetHostPointer(address, sizeof(uint), out byte* ptr, out long offset))
            {
                _error = WhpErrors.Ok;
                return *(uint*)(ptr + offset);
            }
            Span<byte> buffer = stackalloc byte[sizeof(uint)];
            if (TryReadMemoryInternal(address, buffer))
            {
                _error = WhpErrors.Ok;
                return BitConverter.ToUInt32(buffer);
            }
            _error = WhpErrors.MemoryReadUnmapped;
            return 0;
        }

        public unsafe ushort ReadMemoryUShort(ulong address)
        {
            if (DisposedCheck()) return 0;
            if (TryGetHostPointer(address, sizeof(ushort), out byte* ptr, out long offset))
            {
                _error = WhpErrors.Ok;
                return *(ushort*)(ptr + offset);
            }
            Span<byte> buffer = stackalloc byte[sizeof(ushort)];
            if (TryReadMemoryInternal(address, buffer))
            {
                _error = WhpErrors.Ok;
                return BitConverter.ToUInt16(buffer);
            }
            _error = WhpErrors.MemoryReadUnmapped;
            return 0;
        }

        public unsafe string ReadMemoryString(ulong address, int length, Encoding encoding)
        {
            if (DisposedCheck()) return null;
            if (address == 0 || length <= 0) return string.Empty;

            byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                if (TryGetHostPointer(address, length, out byte* src, out long offset))
                {
                    _error = WhpErrors.Ok;
                    Unsafe.CopyBlockUnaligned(ref buffer[0], ref Unsafe.AsRef<byte>(src + offset), (uint)length);
                }
                else if (TryReadMemoryInternal(address, buffer.AsSpan(0, length)))
                {
                    _error = WhpErrors.Ok;
                }
                else
                {
                    _error = WhpErrors.MemoryReadUnmapped;
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
                _error = WhpErrors.Ok;
                return true;
            }

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid)
            {
                _error = WhpErrors.InvalidArgument;
                return false;
            }

            ref ulong target = ref GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            target = WriteGpRegisterField(target, access, value);
            CurrentVp.RegsDirty = true;
            _error = WhpErrors.Ok;
            return true;
        }

        public bool WriteRegister(int register, ulong value) => WriteRegister((Registers)register, value);

        public bool WriteRegister32(Registers register, uint value)
        {
            if (DisposedCheck()) return false;

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid) { _error = WhpErrors.InvalidArgument; return false; }

            ref ulong target = ref GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            target = access.ZeroExtend32 ? value : WriteGpRegisterField(target, access, value);
            CurrentVp.RegsDirty = true;
            _error = WhpErrors.Ok;
            return true;
        }

        public bool WriteRegister32(int register, uint value) => WriteRegister32((Registers)register, value);

        public bool WriteRegisterByte(Registers register, byte value)
        {
            if (DisposedCheck()) return false;

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid) { _error = WhpErrors.InvalidArgument; return false; }

            ref ulong target = ref GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            int shift = access.Offset * 8;
            target = (target & ~(0xFFUL << shift)) | ((ulong)value << shift);
            CurrentVp.RegsDirty = true;
            _error = WhpErrors.Ok;
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
                _error = WhpErrors.Ok;
                return specialValue;
            }

            GpRegisterAccess access = ClassifyGpRegister(register);
            if (!access.IsValid) { _error = WhpErrors.InvalidArgument; return 0; }

            ulong value = GetGpRegisterPointer(ref GetRegistersRef(), access.Name);
            _error = WhpErrors.Ok;
            int shiftBits = access.Offset * 8;
            int widthBits = access.Width * 8;
            if (widthBits >= sizeof(ulong) * 8) return value >> shiftBits;
            return (value >> shiftBits) & ((1UL << widthBits) - 1);
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

            VirtualProcessor vp = CurrentVp;
            ClearTrapFlag(vp);

            GetRegistersRef(vp).Rip = start;
            vp.RegsDirty = true;

            FlushRegisterCache(vp);
            vp.StopRequested = false;
            vp.HostThreadId = Environment.CurrentManagedThreadId;
            vp.SingleStepRequested = count == 1;

            long SliceGeneration = Interlocked.Increment(ref vp.SliceGeneration);

            if (count != 0)
            {
                EnsureMaintenanceThread();
                Volatile.Write(ref vp.SliceDeadlineTimestamp,
                    Stopwatch.GetTimestamp() + (Stopwatch.Frequency * BoundedSliceMilliseconds) / 1000);
            }

            if (vp.SingleStepRequested)
            {
                GetRegistersRef(vp).Rflags |= 0x100UL;
                vp.RegsDirty = true;
                FlushRegisterCache(vp);
            }

            bool releaseRunLock = _runLock != null && Monitor.IsEntered(_runLock);

            try
            {
                // A stepped completion still owes a #DB, and its page stays writable until that arrives.
                long CompletionGraceEnd = 0;

                while (true)
                {
                    if (vp.StopRequested || Volatile.Read(ref vp.SliceExpiredGeneration) == SliceGeneration)
                    {
                        if (!vp.CompletionActive)
                        {
                            break;
                        }

                        long Now = Stopwatch.GetTimestamp();
                        if (CompletionGraceEnd == 0)
                            CompletionGraceEnd = Now + (Stopwatch.Frequency * CompletionGraceMilliseconds) / 1000;
                        else if (Now >= CompletionGraceEnd)
                        {
                            AbandonSteppedCompletion(vp);
                            break;
                        }
                    }

                    RefreshMmioBackedRegions();

                    FlushRegisterCache(vp);

                    ref WhvRunVpExitContext exit = ref RunVirtualProcessor(vp, releaseRunLock);
                    InvalidateRegisterCache(vp);

                    switch (exit.ExitReason)
                    {
                        case WhvRunVpExitReason.X64Halt:
                            if (HandleHltExit(vp)) continue;
                            return _error == WhpErrors.Ok;
                        case WhvRunVpExitReason.MemoryAccess:
                            if (HandleMemoryAccess(vp, ref exit)) continue;
                            _error = WhpErrors.Ok;
                            return true;
                        case WhvRunVpExitReason.Canceled:
                            if (Volatile.Read(ref vp.SliceExpiredGeneration) == SliceGeneration && !vp.CompletionActive)
                            {
                                _error = WhpErrors.Ok;
                                return true;
                            }
                            continue;
                        case WhvRunVpExitReason.X64InterruptWindow:
                            continue;
                        case WhvRunVpExitReason.UnrecoverableException:
                            _error = WhpErrors.Exception;
                            throw new WhpException($"WHP guest hit an unrecoverable exception at RIP 0x{ReadRegister(Registers.UC_X86_REG_RIP):X}");
                        case WhvRunVpExitReason.InvalidVpRegisterValue:
                            _error = WhpErrors.InternalError;
                            throw new WhpException("WHP reported an invalid virtual processor register value.");
                        case WhvRunVpExitReason.UnsupportedFeature:
                            _error = WhpErrors.InternalError;
                            throw new WhpException("WHP reported an unsupported feature during guest execution.");
                        default:
                            _error = WhpErrors.InternalError;
                            throw new WhpException($"Unhandled WHP exit reason: {exit.ExitReason}");
                    }
                }

                _error = WhpErrors.Ok;
                return true;
            }
            finally
            {
                Volatile.Write(ref vp.SliceDeadlineTimestamp, 0);

                if (vp.SingleStepRequested)
                {
                    vp.SingleStepRequested = false;
                    ClearTrapFlag(vp);
                }
                FlushRegisterCache(vp);
            }
        }

        public bool StopEmulation()
        {
            if (DisposedCheck()) return false;

            RequestStop(CurrentVp);

            _error = WhpErrors.Ok;
            return true;
        }

        public void UseRunLock(object runLock) => _runLock = runLock;

        public void StopThread(uint threadId)
        {
            if (Disposed || Disposing) return;
            if (!_threadProcessors.TryGetValue(threadId, out VirtualProcessor vp)) return;

            vp.StopRequested = true;
            if (vp.Running)
                CancelRun(vp);
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
                    CancelRun(vp);
            }
        }

        // A cancel is only for a run in progress on another thread. Issued from the VP's own thread between
        // runs, WHP keeps it pending and the next run returns Canceled at once.
        private void RequestStop(VirtualProcessor vp)
        {
            vp.StopRequested = true;
            if (Environment.CurrentManagedThreadId == vp.HostThreadId)
                return;
            CancelRun(vp);
        }

        private unsafe ref WhvRunVpExitContext RunVirtualProcessor(VirtualProcessor vp, bool releaseRunLock)
        {
            int hr;
            vp.Running = true;
            if (releaseRunLock) Monitor.Exit(_runLock);
            try
            {
                hr = WhpNative.WHvRunVirtualProcessor(_partition, vp.Index, (void*)vp.ExitContextPtr,
                    (uint)sizeof(WhvRunVpExitContext));
            }
            finally
            {
                if (releaseRunLock) Monitor.Enter(_runLock);
                vp.Running = false;
            }

            if (WhpNative.Failed(hr))
            {
                _error = WhpErrors.InternalError;
                throw new WhpException("WHvRunVirtualProcessor failed", hr);
            }
            return ref Unsafe.AsRef<WhvRunVpExitContext>((void*)vp.ExitContextPtr);
        }

        private const BackendHookType FaultMemoryHookTypes =
            BackendHookType.MemoryUnmapped | BackendHookType.MemoryProtected;

        private const BackendHookType TrappedMemoryHookTypes =
            BackendHookType.MemoryRead | BackendHookType.MemoryWrite | BackendHookType.MemoryReadAfter;

        private const BackendHookType SupportedMemoryHookTypes =
            FaultMemoryHookTypes | TrappedMemoryHookTypes;

        private static bool IsUnboundedRange(ulong begin, ulong end) => end == 0 || end < begin;

        public IntPtr AddMemoryHook(ulong begin, ulong end, BackendHookType hookType, MemoryHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;
            if (NoHooks && (hookType & FaultMemoryHookTypes) == 0)
            {
                _error = WhpErrors.Ok;
                return IntPtr.Zero;
            }

            if ((hookType & ~SupportedMemoryHookTypes) != 0)
            {
                _error = WhpErrors.HookError;
                return IntPtr.Zero;
            }

            if ((hookType & TrappedMemoryHookTypes) != 0 && IsUnboundedRange(begin, end))
            {
                _error = WhpErrors.HookError;
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

        private const BackendHookType ReadingMemoryHookTypes =
            BackendHookType.MemoryRead | BackendHookType.MemoryReadAfter;

        private void RefreshTrappedPages()
        {
            _trappedPages.Clear();

            for (int i = 0; i < _memoryHooks.Count; i++)
            {
                MemoryHookEntry entry = _memoryHooks[i];
                if ((entry.Type & TrappedMemoryHookTypes) == 0) continue;
                if (IsUnboundedRange(entry.Begin, entry.End)) continue;

                bool hookReads = (entry.Type & ReadingMemoryHookTypes) != 0;
                ulong first = entry.Begin & ~WhpConstants.PageMask;
                ulong last = entry.End & ~WhpConstants.PageMask;
                for (ulong page = first; page <= last; page += WhpConstants.PageSize)
                {
                    if (_trappedPages.TryGetValue(page, out bool writeOnly))
                        _trappedPages[page] = writeOnly && !hookReads;
                    else
                        _trappedPages[page] = !hookReads;
                }
            }

            for (int i = 0; i < _mmioRegions.Count; i++)
            {
                MmioRegion region = _mmioRegions[i];
                for (ulong page = region.Address; page < region.Address + region.Size; page += WhpConstants.PageSize)
                {
                    if (!_trappedPages.ContainsKey(page))
                        _trappedPages[page] = true;
                }
            }

            RequireFullRebuild();
            RebuildMappings();
        }

        public IntPtr AddCodeHook(ulong begin, ulong end, CodeHookCallback callback)
        {
            if (DisposedCheck()) return IntPtr.Zero;
            if (NoHooks) { _error = WhpErrors.Ok; return IntPtr.Zero; }

            _error = WhpErrors.HookError;
            return IntPtr.Zero;
        }

        public IntPtr AddInterruptHook(InterruptHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;
            if (NoHooks) { _error = WhpErrors.Ok; return IntPtr.Zero; }

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
            }
            return PinHookEntry(entry);
        }

        public IntPtr AddInstructionBoolHook(BackendInstructionHook instruction, InstructionBoolHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            if (DisposedCheck()) return IntPtr.Zero;

            InstructionHookEntry entry = new InstructionHookEntry { Type = instruction, BoolCallback = callback };
            _instructionHooks.Add(entry);
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
                        break;
                }

                _error = WhpErrors.Ok;
                return true;
            }

            _error = WhpErrors.HookError;
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

            if (_trappedPages.Count > 0 && !Disposing)
                RefreshTrappedPages();

            _error = WhpErrors.Ok;
            return true;
        }

        public unsafe IntPtr GetHostPointer(ulong address, ulong size)
        {
            if (size == 0 || size > int.MaxValue) return IntPtr.Zero;
            if (Volatile.Read(ref _disposing) != 0 || Volatile.Read(ref _disposed) != 0) return IntPtr.Zero;
            if (!TryGetHostPointer(address, (int)size, out byte* ptr, out long offset)) return IntPtr.Zero;
            return (IntPtr)(ptr + offset);
        }

        public bool IsRangeMapped(ulong address, ulong size)
        {
            if (size == 0) return true;
            if (Volatile.Read(ref _disposing) != 0 || Volatile.Read(ref _disposed) != 0) return false;

            ulong current = address;
            ulong remaining = size;
            while (remaining > 0)
            {
                ulong pageBase = current & ~WhpConstants.PageMask;
                if (!TryLookupPage(pageBase, out MappedPage page))
                    return false;
                ulong runEnd = TryGetIntactBackingEnd(page, pageBase, out ulong backingEnd)
                    ? backingEnd
                    : pageBase + WhpConstants.PageSize;
                ulong chunk = runEnd - current;
                if (chunk > remaining) chunk = remaining;
                current += chunk;
                remaining -= chunk;
            }
            return true;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposing, 1) == 1) return;

            lock (_mmioLock)
            {
                _mmioRegions.Clear();
            }

            try
            {
                RemoveHooks();

                if (_maintenanceThread != null)
                    WhpNative.timeEndPeriod(MaintenanceTimerPeriodMs);

                lock (_partitionLock)
                {
                    if (_partition != IntPtr.Zero)
                    {
                        for (int i = 0; i < _processors.Count; i++)
                            WhpNative.WHvDeleteVirtualProcessor(_partition, _processors[i].Index);
                        WhpNative.WHvDeletePartition(_partition);
                        _partition = IntPtr.Zero;
                    }
                }

                for (int i = 0; i < _processors.Count; i++)
                {
                    VirtualProcessor vp = _processors[i];
                    if (vp.ExitContextPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(vp.ExitContextPtr);
                        vp.ExitContextPtr = IntPtr.Zero;
                    }
                }

                foreach (KeyValuePair<IntPtr, BackingAllocation> kv in _backingAllocations)
                    FreeBackingMemory(kv.Key, kv.Value.Size);
                _backingAllocations.Clear();
                _mappedPages.Clear();
                _lastLookupPageBase = ulong.MaxValue;
                _lastLookupPage = null;

                if (_internalPoolPtr != IntPtr.Zero)
                {
                    FreeBackingMemory(_internalPoolPtr, InternalPoolSize);
                    _internalPoolPtr = IntPtr.Zero;
                }
                foreach (var fb in _internalPoolFallbacks)
                    FreeBackingMemory(fb.Ptr, fb.Size);
                _internalPoolFallbacks.Clear();
            }
            finally
            {
                Volatile.Write(ref _disposed, 1);
                GC.SuppressFinalize(this);
            }
        }

        ~Whp() { Dispose(); }

        private static WhpMemoryPermission TranslateProtection(MemoryProtection protection)
        {
            WhpMemoryPermission perm = WhpMemoryPermission.None;
            if ((protection & MemoryProtection.Read) != 0) perm |= WhpMemoryPermission.Read;
            if ((protection & MemoryProtection.Write) != 0) perm |= WhpMemoryPermission.Write;
            if ((protection & MemoryProtection.Execute) != 0) perm |= WhpMemoryPermission.Execute;
            return perm;
        }

        private static WhvMapGpaRangeFlags ToWhpMapFlags(WhpMemoryPermission permissions)
        {
            WhvMapGpaRangeFlags flags = WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Execute;
            if ((permissions & WhpMemoryPermission.Write) != 0)
                flags |= WhvMapGpaRangeFlags.Write;
            return flags;
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

        private ushort SegmentAttributes(bool isCode, bool isUser)
        {
            int type = isCode ? 0xB : 0x3;
            int dpl = isUser ? 3 : 0;
            bool code64 = _guest64 && isCode;
            int db = code64 ? 0 : 1;
            int l = code64 ? 1 : 0;
            return (ushort)(type | (1 << 4) | (dpl << 5) | (1 << 7) | (l << 13) | (db << 14) | (1 << 15));
        }

        private WhvRegisterValue MakeSegment(ushort selector, bool isCode, bool isUser)
            => WhvRegisterValue.FromSegment(0, 0xFFFFFFFF, selector, SegmentAttributes(isCode, isUser));

        private static void QueueCsSs(VirtualProcessor vp, WhvRegisterValue cs, WhvRegisterValue ss)
        {
            vp.PendingCs = cs;
            vp.PendingSs = ss;
            vp.SegmentsDirty = true;
        }

        private void ClearTrapFlag(VirtualProcessor vp)
        {
            ref WhpRegisters regs = ref GetRegistersRef(vp);
            if ((regs.Rflags & 0x100UL) == 0) return;
            regs.Rflags &= ~0x100UL;
            vp.RegsDirty = true;
            FlushRegisterCache(vp);
        }

        private bool TryAllocateBackingMemory(ulong size, out IntPtr pointer)
        {
            pointer = WhpNative.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WhpNative.MEM_COMMIT | WhpNative.MEM_RESERVE, WhpNative.PAGE_READWRITE);

            if (pointer == IntPtr.Zero)
            {
                Utils.LogError($"[Whp] Host backing commit of 0x{size:X} bytes failed with {Marshal.GetLastWin32Error()}. Live backing 0x{_backingBytes:X} bytes in {_backingAllocations.Count} allocations.");
                return false;
            }

            _backingBytes += size;
            return true;
        }

        private IntPtr AllocateBackingMemory(ulong size)
        {
            if (!TryAllocateBackingMemory(size, out IntPtr ptr))
                throw new WhpException("VirtualAlloc failed", Marshal.GetLastWin32Error());
            return ptr;
        }

        private void FreeBackingMemory(IntPtr ptr, ulong size)
        {
            WhpNative.VirtualFree(ptr, UIntPtr.Zero, WhpNative.MEM_RELEASE);
            _backingBytes -= size;
        }

        private void ReleaseBacking(MappedPage page)
        {
            if (page.OwnedBacking == IntPtr.Zero) return;
            if (!_backingAllocations.TryGetValue(page.OwnedBacking, out BackingAllocation allocation)) return;

            if (page.IsAlias)
                allocation.AliasPages--;
            else
                allocation.LivePages--;

            if (allocation.LivePages > 0 || allocation.AliasPages > 0) return;

            FreeBackingMemory(page.OwnedBacking, allocation.Size);
            _backingAllocations.Remove(page.OwnedBacking);
        }

        private IntPtr FindBackingAllocation(IntPtr hostPointer)
        {
            long target = hostPointer.ToInt64();

            foreach (KeyValuePair<IntPtr, BackingAllocation> entry in _backingAllocations)
            {
                long start = entry.Key.ToInt64();
                if (target >= start && (ulong)(target - start) < entry.Value.Size)
                    return entry.Key;
            }

            return IntPtr.Zero;
        }

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

        private unsafe void EnsurePlatformSupport()
        {
            int present = 0;
            uint written = 0;
            int hr = WhpNative.WHvGetCapability(WhvCapabilityCode.HypervisorPresent, &present,
                sizeof(int), &written);
            if (WhpNative.Failed(hr))
                throw new WhpException("WHvGetCapability(HypervisorPresent) failed. The Windows Hypervisor Platform feature must be enabled.", hr);
            if (written < sizeof(int) || present == 0)
                throw new WhpException("Windows Hypervisor Platform is not present. Enable the 'Windows Hypervisor Platform' optional feature and ensure virtualization is available.");
        }

        private unsafe void ConfigurePartition()
        {
            int hr = WhpNative.WHvCreatePartition(out _partition);
            if (WhpNative.Failed(hr))
                throw new WhpException("WHvCreatePartition failed", hr);

            if (!TrySetupPartition(MaxVirtualProcessors, out hr))
            {
                WhpNative.WHvDeletePartition(_partition);
                hr = WhpNative.WHvCreatePartition(out _partition);
                if (WhpNative.Failed(hr))
                    throw new WhpException("WHvCreatePartition failed", hr);
                if (!TrySetupPartition(1, out hr))
                    throw new WhpException("WHvSetupPartition failed", hr);
            }

        }

        private unsafe bool TrySetupPartition(uint processorCount, out int hr)
        {
            hr = WhpNative.WHvSetPartitionProperty(_partition, WhvPartitionPropertyCode.ProcessorCount,
                &processorCount, sizeof(uint));
            if (WhpNative.Failed(hr))
                return false;

            hr = WhpNative.WHvSetupPartition(_partition);
            if (WhpNative.Failed(hr))
                return false;

            _processorLimit = processorCount;
            return true;
        }

        private unsafe VirtualProcessor CreateProcessor(uint index)
        {
            int hr = WhpNative.WHvCreateVirtualProcessor(_partition, index, 0);
            if (WhpNative.Failed(hr))
                throw new WhpException("WHvCreateVirtualProcessor failed", hr);

            VirtualProcessor vp = new VirtualProcessor
            {
                Owner = this,
                Index = index,
                ExitContextPtr = Marshal.AllocHGlobal(sizeof(WhvRunVpExitContext)),
            };

            try
            {
                AllocateProcessorTables(vp);
                InitializeVirtualProcessorState(vp);
            }
            catch
            {
                Marshal.FreeHGlobal(vp.ExitContextPtr);
                vp.ExitContextPtr = IntPtr.Zero;
                WhpNative.WHvDeleteVirtualProcessor(_partition, index);
                throw;
            }

            _processors.Add(vp);
            Volatile.Write(ref _processorSnapshot, _processors.ToArray());
            return vp;
        }

        private unsafe void AllocateProcessorTables(VirtualProcessor vp)
        {
            vp.GdtPageGpa = AllocateInternalPage(false);
            vp.TssPageGpa = AllocateInternalPage(false);
            ulong stackSize = ExceptionStackPages * WhpConstants.PageSize;
            ulong stackTop = AllocateInternalRange(stackSize, WhpMemoryPermission.ReadWrite) + stackSize;

            if (!_mappedPages.TryGetValue(_gdtPageGpa, out MappedPage template)
                || !_mappedPages.TryGetValue(vp.GdtPageGpa, out MappedPage gdtPage)
                || !_mappedPages.TryGetValue(vp.TssPageGpa, out MappedPage tssPage))
                throw new WhpException("Failed to allocate the processor tables.");

            byte* gdt = (byte*)gdtPage.HostPage;
            Unsafe.CopyBlockUnaligned(gdt, (byte*)template.HostPage, (uint)WhpConstants.PageSize);
            int tssIndex = WhpConstants.TssSelector >> 3;
            WriteDescriptor(gdt, tssIndex, vp.TssPageGpa & 0xFFFFFFFF, 0x67, 0x89, 0x0);
            Unsafe.WriteUnaligned(gdt + (tssIndex + 1) * 8, vp.TssPageGpa >> 32);

            byte* tss = (byte*)tssPage.HostPage;
            Unsafe.WriteUnaligned(tss + 0x04, stackTop);
            Unsafe.WriteUnaligned(tss + 0x24, stackTop);
            Unsafe.WriteUnaligned(tss + 0x66, (ushort)0x68);
        }

        private static void ResetProcessorCache(VirtualProcessor vp)
        {
            vp.RegsValid = false;
            vp.RegsDirty = false;
            vp.XmmValid = false;
            vp.XmmDirty = false;
            vp.SegmentsDirty = false;
            vp.FsBase = ulong.MaxValue;
            vp.GsBase = ulong.MaxValue;
        }

        public bool SupportsThreadResidency => _processorLimit > 1;

        public int ProcessorLimit => (int)_processorLimit;

        public bool IsThreadResident(uint threadId) => _threadProcessors.ContainsKey(threadId);

        public bool TryBindThread(uint threadId)
        {
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
                if ((uint)_processors.Count >= _processorLimit)
                    return false;

                try
                {
                    vp = CreateProcessor((uint)_processors.Count);
                }
                catch (WhpException)
                {
                    _processorLimit = (uint)_processors.Count;
                    return false;
                }
            }

            vp.ThreadId = threadId;
            ResetProcessorCache(vp);
            _threadProcessors[threadId] = vp;
            return true;
        }

        public void UnbindThread(uint threadId)
        {
            if (!_threadProcessors.Remove(threadId, out VirtualProcessor vp))
                return;

            // A completion the next thread on this processor would finish against the wrong page.
            AbandonSteppedCompletion(vp);
            vp.StopRequested = false;
            vp.SingleStepRequested = false;
            vp.ThreadId = 0;
            vp.Binding++;
            _idleProcessors.Push(vp);
        }

        public void SelectThread(uint threadId)
        {
            SelectProcessor(_threadProcessors.TryGetValue(threadId, out VirtualProcessor vp) ? vp : _processors[(int)SharedVpIndex]);
        }

        private unsafe void InitializeVirtualProcessorState(VirtualProcessor vp)
        {
            const int maxCount = 16;
            Span<uint> names = stackalloc uint[maxCount];
            Span<WhvRegisterValue> values = stackalloc WhvRegisterValue[maxCount];

            names[0] = (uint)WhvRegisterName.Cs; values[0] = _userCodeSegment;
            names[1] = (uint)WhvRegisterName.Ss; values[1] = _userDataSegment;
            names[2] = (uint)WhvRegisterName.Ds; values[2] = _userDataSegment;
            names[3] = (uint)WhvRegisterName.Es; values[3] = _userDataSegment;
            names[4] = (uint)WhvRegisterName.Fs;
            values[4] = MakeSegment(WhpConstants.UserFsSelector32, false, true);
            names[5] = (uint)WhvRegisterName.Gs;
            values[5] = _guest64 ? _userDataSegment : MakeSegment(WhpConstants.UserGsSelector32, false, true);
            names[6] = (uint)WhvRegisterName.Tr;
            values[6] = WhvRegisterValue.FromSegment(vp.TssPageGpa, 0x67, WhpConstants.TssSelector, 0x8B);
            names[7] = (uint)WhvRegisterName.Gdtr;
            values[7] = WhvRegisterValue.FromTable(vp.GdtPageGpa, WhpConstants.GdtLimit);
            names[8] = (uint)WhvRegisterName.Idtr;
            values[8] = WhvRegisterValue.FromTable(_exceptionIdtPageGpa, (ushort)(WhpConstants.ExceptionVectorCount * 16 - 1));
            names[9] = (uint)WhvRegisterName.Cr0; values[9] = WhvRegisterValue.FromReg64(0x80000033UL);
            names[10] = (uint)WhvRegisterName.Cr3; values[10] = WhvRegisterValue.FromReg64(_pml4Gpa);
            names[11] = (uint)WhvRegisterName.Cr4; values[11] = WhvRegisterValue.FromReg64(0x620UL);
            names[12] = (uint)WhvRegisterName.Efer;
            values[12] = WhvRegisterValue.FromReg64((1UL << 8) | (1UL << 10) | (1UL << 11) | (_guest64 ? 1UL << 0 : 0));

            int count = 13;
            if (_guest64)
            {
                names[13] = (uint)WhvRegisterName.Star; values[13] = WhvRegisterValue.FromReg64((0x23UL << 48) | (0x08UL << 32));
                names[14] = (uint)WhvRegisterName.Lstar; values[14] = WhvRegisterValue.FromReg64(_syscallTrapPageGpa);
                names[15] = (uint)WhvRegisterName.Sfmask; values[15] = WhvRegisterValue.FromReg64(0);
                count = maxCount;
            }

            lock (_vcpuLock)
            {
                fixed (uint* n = names)
                fixed (WhvRegisterValue* v = values)
                {
                    int hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, vp.Index, n, (uint)count, v);
                    if (WhpNative.Failed(hr))
                        throw new WhpException("WHvSetVirtualProcessorRegisters(initial state) failed", hr);
                }
            }
        }

        private unsafe void InitializeSyscallTrapPage()
        {
            if (!_guest64) return;

            _syscallTrapPageGpa = AllocateInternalPage(true);
            if (_mappedPages.TryGetValue(_syscallTrapPageGpa, out MappedPage page))
            {
                byte* code = (byte*)page.HostPage;
                code[0] = 0xF4;
            }
        }

        private static unsafe void WriteDescriptor(byte* gdt, int index, ulong segmentBase, uint limit, byte access, byte flags)
        {
            ulong descriptor = (limit & 0xFFFFUL)
                             | ((segmentBase & 0xFFFFFFUL) << 16)
                             | ((ulong)access << 40)
                             | ((ulong)((limit >> 16) & 0xF) << 48)
                             | ((ulong)(flags & 0xF) << 52)
                             | (((segmentBase >> 24) & 0xFFUL) << 56);
            Unsafe.WriteUnaligned(gdt + index * 8, descriptor);
        }

        private void InitializeGdt()
        {
            _gdtPageGpa = AllocateInternalPage(false);
            if (!_mappedPages.TryGetValue(_gdtPageGpa, out MappedPage gdtPage) || gdtPage.HostPage == IntPtr.Zero)
                throw new WhpException("Failed to allocate GDT page.");

            unsafe
            {
                byte* gdt = (byte*)gdtPage.HostPage;
                Unsafe.InitBlockUnaligned(gdt, 0, (uint)WhpConstants.PageSize);

                WriteDescriptor(gdt, WhpConstants.KernelCodeSelector >> 3, 0, 0xFFFFF, 0x9B, 0xA);
                WriteDescriptor(gdt, WhpConstants.KernelDataSelector >> 3, 0, 0xFFFFF, 0x93, 0xC);
                WriteDescriptor(gdt, WhpConstants.UserCodeSelector32 >> 3, 0, 0xFFFFF, 0xFB, 0xC);
                WriteDescriptor(gdt, WhpConstants.UserDataSelector >> 3, 0, 0xFFFFF, 0xF3, 0xC);
                WriteDescriptor(gdt, WhpConstants.UserCodeSelector >> 3, 0, 0xFFFFF, 0xFB, 0xA);
                // RtlGetCurrentProcessorNumber reads this descriptor limit with lsl and shifts it right by 14
                WriteDescriptor(gdt, WhpConstants.UserFsSelector32 >> 3, 0, 0x0FFF, 0xF3, 0x4);
            }
        }

        private static unsafe void WriteIdtGate(byte* idt, uint vector, ulong handler)
        {
            ulong low = (handler & 0xFFFF)
                      | ((ulong)WhpConstants.KernelCodeSelector << 16)
                      | ((ulong)(WhpConstants.ExceptionIstIndex & 0x7) << 32)
                      | ((ulong)WhpConstants.ExceptionGateAttributes << 40)
                      | (((handler >> 16) & 0xFFFF) << 48);
            Unsafe.WriteUnaligned(idt + vector * 16, low);
            Unsafe.WriteUnaligned(idt + vector * 16 + 8, (uint)((handler >> 32) & 0xFFFFFFFF));
        }

        private void InitializeExceptionHandling()
        {
            _exceptionStubPageGpa = AllocateInternalPage(true);
            _exceptionIdtPageGpa = AllocateInternalPage(false);

            unsafe
            {
                if (_mappedPages.TryGetValue(_exceptionStubPageGpa, out MappedPage stubPage))
                {
                    byte* stubs = (byte*)stubPage.HostPage;
                    for (uint vector = 0; vector < WhpConstants.ExceptionVectorCount; vector++)
                        stubs[vector * (int)WhpConstants.ExceptionStubStride] = 0xF4;
                }

                if (_mappedPages.TryGetValue(_exceptionIdtPageGpa, out MappedPage idtPage))
                {
                    byte* idt = (byte*)idtPage.HostPage;
                    for (uint vector = 0; vector < WhpConstants.ExceptionVectorCount; vector++)
                        WriteIdtGate(idt, vector, _exceptionStubPageGpa + vector * WhpConstants.ExceptionStubStride);
                }
            }
        }

        private void InitializeLongModePageTables()
        {
            _pml4Gpa = AllocateInternalPage(false, false);
        }

        private void AllocateInternalPool()
        {
            _internalPoolPtr = AllocateBackingMemory(InternalPoolSize);
            _internalPoolOffset = 0;
        }

        private ulong AllocateInternalPage(bool executable = false, bool mapIntoGuest = true)
            => AllocateInternalRange(WhpConstants.PageSize,
                executable ? WhpMemoryPermission.All : WhpMemoryPermission.ReadWrite, mapIntoGuest);

        private ulong AllocateInternalRange(ulong size, WhpMemoryPermission permissions, bool mapIntoGuest = true)
        {
            if ((size & WhpConstants.PageMask) != 0)
                size = (size + WhpConstants.PageMask) & ~WhpConstants.PageMask;

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

            long backingBase = backing.ToInt64();
            for (ulong off = 0; off < size; off += WhpConstants.PageSize)
            {
                ulong pageGpa = baseGpa + off;
                MappedPage page = new MappedPage
                {
                    HostPage = new IntPtr(backingBase + (long)off),
                    OwnedBacking = IntPtr.Zero,
                    Permissions = permissions,
                };
                SetMappedPage(pageGpa, page);
                _pageTableViews[pageGpa] = page.HostPage;

                if (mapIntoGuest)
                    EnsureVirtualMapping(pageGpa);
            }

            return baseGpa;
        }

        private const ulong PageTableEntryDefaultFlags =
            WhpConstants.PageTableEntryPresent | WhpConstants.PageTableEntryWritable | WhpConstants.PageTableEntryUser;

        private void EnsureVirtualMapping(ulong guestAddress)
        {
            ulong pageBase = guestAddress & ~WhpConstants.PageMask;
            int pml4Index = (int)((pageBase >> 39) & 0x1FF);
            int pdptIndex = (int)((pageBase >> 30) & 0x1FF);
            int pdIndex = (int)((pageBase >> 21) & 0x1FF);
            int ptIndex = (int)((pageBase >> 12) & 0x1FF);

            ulong pdptGpa = EnsureChildTable(_pml4Gpa, pml4Index);
            ulong pdGpa = EnsureChildTable(pdptGpa, pdptIndex);
            ulong ptGpa = EnsureChildTable(pdGpa, pdIndex);

            if (!_pageTableViews.TryGetValue(ptGpa, out IntPtr ptPtr) || ptPtr == IntPtr.Zero) return;
            unsafe
            {
                ulong* pt = (ulong*)ptPtr;
                pt[ptIndex] = pageBase | PageTableEntryDefaultFlags;
            }
        }

        private ulong EnsureChildTable(ulong tableGpa, int index)
        {
            if (!_pageTableViews.TryGetValue(tableGpa, out IntPtr tablePtr) || tablePtr == IntPtr.Zero)
                return 0;
            unsafe
            {
                ulong* entries = (ulong*)tablePtr;
                ulong entry = entries[index];
                if ((entry & WhpConstants.PageTableEntryPresent) == 0)
                {
                    ulong childGpa = AllocateInternalPage(false, false);
                    entries[index] = childGpa | PageTableEntryDefaultFlags;
                    return childGpa;
                }
                return entry & WhpConstants.PageTableEntryAddressMask;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private bool TryLookupPage(ulong pageBase, out MappedPage page)
        {
            if (pageBase == _lastLookupPageBase)
            {
                page = _lastLookupPage;
                return true;
            }

            if (_mappedPages.TryGetValue(pageBase, out page) && page != null && page.HostPage != IntPtr.Zero)
            {
                _lastLookupPageBase = pageBase;
                _lastLookupPage = page;
                return true;
            }

            page = null;
            return false;
        }

        private void SetMappedPage(ulong guestAddress, MappedPage page)
        {
            _mappedPages[guestAddress] = page;
            _sortedPageKeysDirty = true;
            _mappingsDirty = true;
            MarkSpanDirty(guestAddress, WhpConstants.PageSize);
            _lastLookupPageBase = ulong.MaxValue;
            _lastLookupPage = null;
        }

        private void RemoveMappedPage(ulong guestAddress)
        {
            if (!_mappedPages.Remove(guestAddress)) return;
            _sortedPageKeysDirty = true;
            _mappingsDirty = true;
            MarkSpanDirty(guestAddress, WhpConstants.PageSize);
            _lastLookupPageBase = ulong.MaxValue;
            _lastLookupPage = null;
        }

        private void MarkSpanDirty(ulong address, ulong size)
        {
            if (_fullRebuildRequired) return;

            ulong start = address & ~WhpConstants.PageMask;
            ulong end = GetRangeEndAligned(address, size);
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

        private static ulong GetRangeEndAligned(ulong address, ulong size)
        {
            ulong end = address + size;
            if (end < address) return ulong.MaxValue & ~WhpConstants.PageMask;
            return (end + WhpConstants.PageMask) & ~WhpConstants.PageMask;
        }

        private void RequireFullRebuild()
        {
            _fullRebuildRequired = true;
            _dirtyRanges.Clear();
        }

        private void AddActiveMap(ulong start, InstalledMap map)
        {
            _activeMaps[start] = map;
            int index = _activeMapStarts.BinarySearch(start);
            if (index < 0) _activeMapStarts.Insert(~index, start);
        }

        private void RemoveActiveMap(ulong start)
        {
            if (!_activeMaps.Remove(start)) return;
            int index = _activeMapStarts.BinarySearch(start);
            if (index >= 0) _activeMapStarts.RemoveAt(index);
        }

        private ulong[] GetSortedPageKeys()
        {
            if (!_sortedPageKeysDirty) return _sortedPageKeys;

            int count = _mappedPages.Count;
            if (_sortedPageKeys.Length < count)
                _sortedPageKeys = new ulong[Math.Max(count, _sortedPageKeys.Length * 2)];

            _mappedPages.Keys.CopyTo(_sortedPageKeys, 0);
            Array.Sort(_sortedPageKeys, 0, count);
            _sortedPageKeysDirty = false;
            return _sortedPageKeys;
        }

        private void RebuildMappings()
        {
            _mappingsDirty = false;

            if (!_fullRebuildRequired)
            {
                for (int i = 0; i < _dirtyRanges.Count; i++)
                    RebuildMappingsIncremental(_dirtyRanges[i].Start, _dirtyRanges[i].End);

                _dirtyRanges.Clear();
                return;
            }

            RebuildMappingsFull();
            _fullRebuildRequired = false;
            _dirtyRanges.Clear();
        }

        private void RebuildMappingsFull()
        {
            ulong[] sortedKeys = GetSortedPageKeys();
            int keyCount = _mappedPages.Count;
            bool anyTrapped = _trappedPages.Count != 0;

            _desiredMaps.Clear();
            MarkIntactMaps(0, ulong.MaxValue);
            bool anyKept = _keptMapStarts.Count != 0;

            for (int i = 0; i < keyCount;)
            {
                ulong runAddress = sortedKeys[i];
                if (TryGetKeptMapEnd(runAddress, out ulong keptEnd))
                {
                    while (i < keyCount && sortedKeys[i] < keptEnd) i++;
                    continue;
                }

                if (!_mappedPages.TryGetValue(runAddress, out MappedPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == WhpMemoryPermission.None)
                {
                    i++;
                    continue;
                }

                if (anyTrapped && _trappedPages.TryGetValue(runAddress, out bool writeOnly))
                {
                    if (writeOnly)
                    {
                        _desiredMaps[runAddress] = new InstalledMap
                        {
                            Size = WhpConstants.PageSize,
                            Host = page.HostPage,
                            Flags = WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Execute,
                        };
                    }
                    i++;
                    continue;
                }

                long runHostBaseLong = page.HostPage.ToInt64();
                WhvMapGpaRangeFlags runFlags = ToWhpMapFlags(page.Permissions);
                ulong runSize = WhpConstants.PageSize;

                int j = i + 1;
                while (j < keyCount)
                {
                    if (sortedKeys[j] != runAddress + runSize) break;
                    if (anyKept && _keptMapStarts.Contains(sortedKeys[j])) break;
                    if (!_mappedPages.TryGetValue(sortedKeys[j], out MappedPage next) || next == null) break;
                    if (next.Permissions != page.Permissions) break;
                    if (anyTrapped && _trappedPages.ContainsKey(sortedKeys[j])) break;
                    if (next.HostPage.ToInt64() != runHostBaseLong + (long)runSize) break;
                    runSize += WhpConstants.PageSize;
                    j++;
                }

                _desiredMaps[runAddress] = new InstalledMap
                {
                    Size = runSize,
                    Host = new IntPtr(runHostBaseLong),
                    Flags = runFlags,
                };
                i = j;
            }

            _staleMapKeys.Clear();
            foreach (KeyValuePair<ulong, InstalledMap> kv in _activeMaps)
            {
                if (!_desiredMaps.TryGetValue(kv.Key, out InstalledMap want)
                    || want.Size != kv.Value.Size
                    || want.Host != kv.Value.Host
                    || want.Flags != kv.Value.Flags)
                {
                    UnmapGpaRange(kv.Key, kv.Value.Size);
                    _staleMapKeys.Add(kv.Key);
                }
                else
                {
                    _desiredMaps.Remove(kv.Key);
                }
            }
            for (int i = 0; i < _staleMapKeys.Count; i++)
                _activeMaps.Remove(_staleMapKeys[i]);

            foreach (KeyValuePair<ulong, InstalledMap> kv in _desiredMaps)
            {
                MapGpaRange(kv.Key, kv.Value.Size, kv.Value.Host, kv.Value.Flags);
                _activeMaps[kv.Key] = kv.Value;
            }

            _activeMapStarts.Clear();
            foreach (KeyValuePair<ulong, InstalledMap> kv in _activeMaps)
                _activeMapStarts.Add(kv.Key);
            _activeMapStarts.Sort();
        }

        private int FirstActiveMapIndexAtOrBefore(ulong address)
        {
            int index = _activeMapStarts.BinarySearch(address);
            if (index >= 0) return index;

            index = ~index;
            return index > 0 ? index - 1 : 0;
        }

        // A map whose pages still map as installed stays as it is. Replacing it unmaps it for a moment from
        // processors that are using it. Maps merge only when they run out.
        private void MarkIntactMaps(ulong spanStart, ulong spanEnd)
        {
            _keptMapStarts.Clear();
            if (_activeMaps.Count + MapHeadroom >= MaxGpaRanges) return;

            int firstIndex = FirstActiveMapIndexAtOrBefore(spanStart);
            for (int i = firstIndex; i < _activeMapStarts.Count; i++)
            {
                ulong start = _activeMapStarts[i];
                if (start >= spanEnd) break;

                InstalledMap active = _activeMaps[start];
                if (start + active.Size <= spanStart) continue;
                if (!IsMapIntact(start, active)) continue;

                _keptMapStarts.Add(start);
                _desiredMaps[start] = active;
            }
        }

        private bool IsMapIntact(ulong start, InstalledMap map)
        {
            bool anyTrapped = _trappedPages.Count != 0;
            for (ulong off = 0; off < map.Size; off += WhpConstants.PageSize)
            {
                ulong address = start + off;
                if (!_mappedPages.TryGetValue(address, out MappedPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == WhpMemoryPermission.None)
                    return false;
                if (page.HostPage.ToInt64() != map.Host.ToInt64() + (long)off) return false;

                WhvMapGpaRangeFlags flags;
                if (anyTrapped && _trappedPages.TryGetValue(address, out bool writeOnly))
                {
                    if (!writeOnly || map.Size != WhpConstants.PageSize) return false;
                    flags = WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Execute;
                }
                else
                {
                    flags = ToWhpMapFlags(page.Permissions);
                }
                if (flags != map.Flags) return false;
            }
            return true;
        }

        private bool TryGetKeptMapEnd(ulong address, out ulong end)
        {
            end = 0;
            if (_keptMapStarts.Count == 0 || _activeMapStarts.Count == 0) return false;

            ulong start = _activeMapStarts[FirstActiveMapIndexAtOrBefore(address)];
            if (start > address || !_keptMapStarts.Contains(start)) return false;

            InstalledMap map = _activeMaps[start];
            if (address - start >= map.Size) return false;
            end = start + map.Size;
            return true;
        }

        // A fault raised while another processor was replacing the mapping is retried once it is back.
        private bool IsAccessInstalled(ulong gpa, bool isWrite)
        {
            if (_activeMapStarts.Count == 0) return false;

            ulong start = _activeMapStarts[FirstActiveMapIndexAtOrBefore(gpa)];
            if (start > gpa || !_activeMaps.TryGetValue(start, out InstalledMap map) || gpa - start >= map.Size)
                return false;

            return !isWrite || (map.Flags & WhvMapGpaRangeFlags.Write) != 0;
        }

        private void RebuildMappingsIncremental(ulong spanStart, ulong spanEnd)
        {
            int firstIndex = FirstActiveMapIndexAtOrBefore(spanStart);
            for (int i = firstIndex; i < _activeMapStarts.Count; i++)
            {
                ulong start = _activeMapStarts[i];
                if (start >= spanEnd) break;

                InstalledMap active = _activeMaps[start];
                ulong end = start + active.Size;
                if (end <= spanStart) continue;

                if (start < spanStart) spanStart = start;
                if (end > spanEnd) spanEnd = end;
            }

            _desiredMaps.Clear();
            MarkIntactMaps(spanStart, spanEnd);
            BuildDesiredMapsForSpan(spanStart, spanEnd);

            _staleMapKeys.Clear();
            firstIndex = FirstActiveMapIndexAtOrBefore(spanStart);
            for (int i = firstIndex; i < _activeMapStarts.Count; i++)
            {
                ulong start = _activeMapStarts[i];
                if (start >= spanEnd) break;

                InstalledMap active = _activeMaps[start];
                if (start + active.Size <= spanStart) continue;

                if (!_desiredMaps.TryGetValue(start, out InstalledMap want)
                    || want.Size != active.Size
                    || want.Host != active.Host
                    || want.Flags != active.Flags)
                {
                    UnmapGpaRange(start, active.Size);
                    _staleMapKeys.Add(start);
                }
                else
                {
                    _desiredMaps.Remove(start);
                }
            }

            for (int i = 0; i < _staleMapKeys.Count; i++)
                RemoveActiveMap(_staleMapKeys[i]);

            foreach (KeyValuePair<ulong, InstalledMap> kv in _desiredMaps)
            {
                MapGpaRange(kv.Key, kv.Value.Size, kv.Value.Host, kv.Value.Flags);
                AddActiveMap(kv.Key, kv.Value);
            }
        }

        private void BuildDesiredMapsForSpan(ulong spanStart, ulong spanEnd)
        {
            bool anyTrapped = _trappedPages.Count != 0;
            bool anyKept = _keptMapStarts.Count != 0;

            for (ulong address = spanStart; address < spanEnd;)
            {
                if (TryGetKeptMapEnd(address, out ulong keptEnd))
                {
                    address = keptEnd;
                    continue;
                }

                if (!_mappedPages.TryGetValue(address, out MappedPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == WhpMemoryPermission.None)
                {
                    address += WhpConstants.PageSize;
                    continue;
                }

                if (anyTrapped && _trappedPages.TryGetValue(address, out bool writeOnly))
                {
                    if (writeOnly)
                    {
                        _desiredMaps[address] = new InstalledMap
                        {
                            Size = WhpConstants.PageSize,
                            Host = page.HostPage,
                            Flags = WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Execute,
                        };
                    }
                    address += WhpConstants.PageSize;
                    continue;
                }

                long runHostBaseLong = page.HostPage.ToInt64();
                WhvMapGpaRangeFlags runFlags = ToWhpMapFlags(page.Permissions);
                ulong runSize = WhpConstants.PageSize;

                while (address + runSize < spanEnd)
                {
                    if (anyKept && _keptMapStarts.Contains(address + runSize)) break;
                    if (!_mappedPages.TryGetValue(address + runSize, out MappedPage next) || next == null) break;
                    if (next.Permissions != page.Permissions) break;
                    if (next.HostPage == IntPtr.Zero) break;
                    if (anyTrapped && _trappedPages.ContainsKey(address + runSize)) break;
                    if (next.HostPage.ToInt64() != runHostBaseLong + (long)runSize) break;
                    runSize += WhpConstants.PageSize;
                }

                _desiredMaps[address] = new InstalledMap
                {
                    Size = runSize,
                    Host = new IntPtr(runHostBaseLong),
                    Flags = runFlags,
                };
                address += runSize;
            }
        }

        private unsafe void MapGpaRange(ulong gpa, ulong size, IntPtr host, WhvMapGpaRangeFlags flags)
        {
            int hr = WhpNative.WHvMapGpaRange(_partition, (void*)host, gpa, size, flags);
            if (WhpNative.Failed(hr))
                throw new WhpException($"WHvMapGpaRange failed (gpa=0x{gpa:X}, size=0x{size:X})", hr);
        }

        private void UnmapGpaRange(ulong gpa, ulong size)
            => WhpNative.WHvUnmapGpaRange(_partition, gpa, size);

        private unsafe bool TryReadMemoryInternal(ulong address, Span<byte> buffer)
        {
            ulong current = address;
            int offset = 0;
            int remaining = buffer.Length;

            while (remaining > 0)
            {
                ulong pageBase = current & ~WhpConstants.PageMask;
                if (!TryLookupPage(pageBase, out MappedPage page))
                    return false;

                ulong pageOffset = current - pageBase;
                int chunk = (int)Math.Min((ulong)remaining, WhpConstants.PageSize - pageOffset);
                Unsafe.CopyBlockUnaligned(
                    ref Unsafe.AsRef<byte>(ref buffer[offset]),
                    ref Unsafe.AsRef<byte>((void*)(page.HostPage + (int)pageOffset)),
                    (uint)chunk);

                current += (ulong)chunk;
                offset += chunk;
                remaining -= chunk;
            }
            return true;
        }

        private unsafe bool TryWriteMemoryInternal(ulong address, ReadOnlySpan<byte> buffer)
        {
            ulong current = address;
            int offset = 0;
            int remaining = buffer.Length;

            while (remaining > 0)
            {
                ulong pageBase = current & ~WhpConstants.PageMask;
                if (!TryLookupPage(pageBase, out MappedPage page))
                    return false;

                ulong pageOffset = current - pageBase;
                int chunk = (int)Math.Min((ulong)remaining, WhpConstants.PageSize - pageOffset);
                Unsafe.CopyBlockUnaligned(
                    ref Unsafe.AsRef<byte>((void*)(page.HostPage + (int)pageOffset)),
                    ref Unsafe.AsRef<byte>(in buffer[offset]),
                    (uint)chunk);

                current += (ulong)chunk;
                offset += chunk;
                remaining -= chunk;
            }
            return true;
        }

        private bool HandleInvalidInstructionHook()
        {
            bool consumed = false;
            ulong rip = ReadRegister(Registers.UC_X86_REG_RIP);

            for (int i = 0; i < _instructionHooks.Count; i++)
            {
                InstructionHookEntry entry = _instructionHooks[i];
                if (entry.Type != BackendInstructionHook.Invalid) continue;

                if (entry.Callback != null) { entry.Callback(); consumed = true; }
                else if (entry.BoolCallback != null) { if (entry.BoolCallback()) consumed = true; }
            }

            if (consumed && ReadRegister(Registers.UC_X86_REG_RIP) == rip)
                AdvanceRip(2);
            return consumed;
        }

        private bool HandleHltExit(VirtualProcessor vp)
        {
            ulong rip = GetRegistersRef(vp).Rip;

            if (_guest64 && _syscallHook != null && rip == (_syscallTrapPageGpa + 1))
            {
                if (HandleSyscallTrap(vp)) return true;
                _error = WhpErrors.Ok;
                return false;
            }

            ulong stubEnd = _exceptionStubPageGpa +
                WhpConstants.ExceptionVectorCount * WhpConstants.ExceptionStubStride;
            if (rip > _exceptionStubPageGpa && rip <= stubEnd)
            {
                uint vector = (uint)((rip - 1 - _exceptionStubPageGpa) / WhpConstants.ExceptionStubStride);

                if (vp.CompletionActive && vector == 1)
                {
                    CompleteSteppedAccess(vp, rip);
                    return true;
                }

                if (vp.SingleStepRequested && vector == 1)
                {
                    vp.SingleStepRequested = false;
                    ReadExceptionFrame(vp, rip, out _, out _);
                    ClearTrapFlag(vp);
                    _error = WhpErrors.Ok;
                    return false;
                }

                ReadExceptionFrame(vp, rip, out uint faultVector, out ulong errorCode);
                if (HandleException(faultVector, (uint)errorCode))
                    return true;
                _error = WhpErrors.Exception;
                return false;
            }

            _error = WhpErrors.Ok;
            return false;
        }

        private bool HandleMemoryAccess(VirtualProcessor vp, ref WhvRunVpExitContext exit)
        {
            ulong gpa = exit.MemGpa;
            uint info = exit.MemAccessInfo;
            WhvMemoryAccessType accessType = (WhvMemoryAccessType)(info & 0x3);
            bool isWrite = accessType == WhvMemoryAccessType.Write;
            bool isFetch = accessType == WhvMemoryAccessType.Execute;
            const uint len = 1;

            ulong faultPage = gpa & ~WhpConstants.PageMask;
            bool mapped = TryLookupPage(faultPage, out _);

            if (vp.CompletionActive)
            {
                // Another processor re-trapped the page mid-step, so the step is armed again. A fault
                // elsewhere belongs to the stepped instruction itself and ends the step.
                if (faultPage == vp.CompletionPageGpa)
                {
                    ArmSteppedCompletion(vp, faultPage);
                    return true;
                }

                AbandonSteppedCompletion(vp);
            }

            if (mapped && _trappedPages.ContainsKey(faultPage))
            {
                BeginSteppedCompletion(vp, faultPage, gpa, len, isWrite);
                return true;
            }

            if (mapped && IsAccessInstalled(gpa, isWrite))
                return true;

            // Mapping installs are deferred, so a processor can reach a recorded page before its range is
            // installed. Install it and retry the access instead of reporting a fault.
            if (_mappingsDirty)
            {
                RebuildMappings();
                if (mapped && IsAccessInstalled(gpa, isWrite))
                    return true;
            }

            BackendHookType required = mapped ? BackendHookType.MemoryProtected : BackendHookType.MemoryUnmapped;
            BackendMemoryAccessType type = mapped
                ? (isFetch ? BackendMemoryAccessType.FetchProtected
                    : isWrite ? BackendMemoryAccessType.WriteProtected : BackendMemoryAccessType.ReadProtected)
                : (isFetch ? BackendMemoryAccessType.FetchUnmapped
                    : isWrite ? BackendMemoryAccessType.WriteUnmapped : BackendMemoryAccessType.ReadUnmapped);

            for (int i = 0; i < _memoryHooks.Count; i++)
            {
                MemoryHookEntry entry = _memoryHooks[i];
                if ((entry.Type & required) == 0) continue;
                if (entry.End == 0 || entry.End < entry.Begin || (entry.Begin <= gpa && entry.End >= gpa))
                {
                    if (entry.Callback(type, gpa, len, 0))
                        return true;
                }
            }
            return false;
        }

        private void BeginSteppedCompletion(VirtualProcessor vp, ulong pageGpa, ulong gpa, uint len, bool isWrite)
        {
            if (!_mappedPages.TryGetValue(pageGpa, out MappedPage page) || page.HostPage == IntPtr.Zero)
                return;

            vp.CompletionActive = true;
            vp.CompletionPageGpa = pageGpa;
            vp.CompletionAccessGpa = gpa;
            vp.CompletionLen = len;
            vp.CompletionIsWrite = isWrite;
            ArmSteppedCompletion(vp, pageGpa);
        }

        private void ArmSteppedCompletion(VirtualProcessor vp, ulong pageGpa)
        {
            if (!_mappedPages.TryGetValue(pageGpa, out MappedPage page) || page.HostPage == IntPtr.Zero)
                return;

            UnmapGpaRange(pageGpa, WhpConstants.PageSize);
            MapGpaRange(pageGpa, WhpConstants.PageSize, page.HostPage,
                WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Write | WhvMapGpaRangeFlags.Execute);

            ref WhpRegisters regs = ref GetRegistersRef(vp);
            regs.Rflags |= 0x100UL;
            vp.RegsDirty = true;
            FlushRegisterCache(vp);
        }

        private void CompleteSteppedAccess(VirtualProcessor vp, ulong stubRip)
        {
            ReadExceptionFrame(vp, stubRip, out _, out _);

            ulong pageGpa = vp.CompletionPageGpa;
            ulong gpa = vp.CompletionAccessGpa;
            uint len = vp.CompletionLen;
            bool isWrite = vp.CompletionIsWrite;
            vp.CompletionActive = false;

            ulong value = ReadMemoryULong(gpa);
            BackendHookType required = isWrite ? BackendHookType.MemoryWrite : BackendHookType.MemoryRead;
            BackendMemoryAccessType type = isWrite ? BackendMemoryAccessType.Write : BackendMemoryAccessType.Read;
            for (int i = 0; i < _memoryHooks.Count; i++)
            {
                MemoryHookEntry entry = _memoryHooks[i];
                if ((entry.Type & required) == 0) continue;
                if (entry.Begin > gpa || entry.End < gpa) continue;
                entry.Callback(type, gpa, len, value);
            }
            if (!isWrite)
            {
                for (int i = 0; i < _memoryHooks.Count; i++)
                {
                    MemoryHookEntry entry = _memoryHooks[i];
                    if ((entry.Type & BackendHookType.MemoryReadAfter) == 0) continue;
                    if (entry.Begin > gpa || entry.End < gpa) continue;
                    entry.Callback(BackendMemoryAccessType.ReadAfter, gpa, len, value);
                }
            }

            ReTrapPage(pageGpa);

            if (!vp.SingleStepRequested)
                ClearTrapFlag(vp);
            FlushRegisterCache(vp);
        }

        /// <summary>
        /// Gives up a stepped access whose #DB never arrived. The guest faults on the page again.
        /// </summary>
        private void AbandonSteppedCompletion(VirtualProcessor vp)
        {
            if (!vp.CompletionActive)
                return;

            ulong pageGpa = vp.CompletionPageGpa;
            vp.CompletionActive = false;
            vp.CompletionPageGpa = 0;
            vp.CompletionAccessGpa = 0;
            vp.CompletionLen = 0;
            vp.CompletionIsWrite = false;

            ReTrapPage(pageGpa);
            ClearTrapFlag(vp);
            FlushRegisterCache(vp);
        }

        private void ReTrapPage(ulong pageGpa)
        {
            UnmapGpaRange(pageGpa, WhpConstants.PageSize);

            if (_activeMapStarts.Count != 0)
            {
                ulong start = _activeMapStarts[FirstActiveMapIndexAtOrBefore(pageGpa)];
                if (start <= pageGpa && _activeMaps.TryGetValue(start, out InstalledMap map) && pageGpa - start < map.Size)
                {
                    MapGpaRange(pageGpa, WhpConstants.PageSize, new IntPtr(map.Host.ToInt64() + (long)(pageGpa - start)), map.Flags);
                    return;
                }
            }

            if (!_mappedPages.TryGetValue(pageGpa, out MappedPage page) || page == null
                || page.HostPage == IntPtr.Zero || page.Permissions == WhpMemoryPermission.None)
                return;

            WhvMapGpaRangeFlags flags = _trappedPages.TryGetValue(pageGpa, out bool writeOnly) && writeOnly
                ? WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Execute
                : ToWhpMapFlags(page.Permissions);
            MapGpaRange(pageGpa, WhpConstants.PageSize, page.HostPage, flags);
        }

        private void ReadExceptionFrame(VirtualProcessor vp, ulong stubRip, out uint vector, out ulong errorCode)
        {
            vector = (uint)((stubRip - 1 - _exceptionStubPageGpa) / WhpConstants.ExceptionStubStride);
            errorCode = 0;

            ref WhpRegisters regs = ref GetRegistersRef(vp);
            ulong frameAddress = regs.Rsp;

            if (ExceptionHasErrorCode(vector))
            {
                Span<byte> ecBytes = stackalloc byte[sizeof(ulong)];
                ecBytes.Clear();
                TryReadMemoryInternal(frameAddress, ecBytes);
                errorCode = BitConverter.ToUInt64(ecBytes);
                frameAddress += sizeof(ulong);
            }

            Span<byte> frameBytes = stackalloc byte[40];
            frameBytes.Clear();
            TryReadMemoryInternal(frameAddress, frameBytes);

            ulong frameRip = BitConverter.ToUInt64(frameBytes);
            ulong frameCs = BitConverter.ToUInt64(frameBytes.Slice(8));
            ulong frameRflags = BitConverter.ToUInt64(frameBytes.Slice(16));
            ulong frameRsp = BitConverter.ToUInt64(frameBytes.Slice(24));
            ulong frameSs = BitConverter.ToUInt64(frameBytes.Slice(32));

            regs.Rip = frameRip;
            if (vector == 3) regs.Rip -= 1;
            regs.Rsp = frameRsp;
            regs.Rflags = frameRflags;
            vp.RegsDirty = true;

            QueueCsSs(vp, MakeSegment((ushort)frameCs, true, (frameCs & 3) == 3),
                MakeSegment((ushort)frameSs, false, (frameSs & 3) == 3));
        }

        private bool HandleSyscallTrap(VirtualProcessor vp)
        {
            if (_syscallHook == null) return false;

            ref WhpRegisters regs = ref GetRegistersRef(vp);

            ulong postSyscallRcx = regs.Rcx;
            ulong postSyscallR10 = regs.R10;
            ulong savedRflags = regs.R11;
            ulong preSyscallRip = postSyscallRcx - 2;

            regs.Rip = preSyscallRip;
            regs.Rcx = postSyscallR10;
            regs.Rflags = savedRflags;
            vp.RegsDirty = true;

            if (_syscallHook.Callback != null) _syscallHook.Callback();
            else if (_syscallHook.BoolCallback != null) _syscallHook.BoolCallback();

            ref WhpRegisters after = ref GetRegistersRef(vp);
            if (after.Rip == preSyscallRip)
                after.Rip = postSyscallRcx;
            else
                after.Rip += 2;
            vp.RegsDirty = true;

            QueueCsSs(vp, _userCodeSegment, _userDataSegment);
            return true;
        }

        private bool HandleException(uint exception, uint errorCode)
        {
            if (exception == 6 && HandleInvalidInstructionHook()) return true;

            if (exception == 14)
            {
                ulong faultAddress = ReadRegister(Registers.UC_X86_REG_CR2);

                bool present = (errorCode & 0x1) != 0;
                bool write = (errorCode & 0x2) != 0;
                bool fetch = (errorCode & 0x10) != 0;

                BackendMemoryAccessType type;
                if (fetch)
                    type = present ? BackendMemoryAccessType.FetchProtected : BackendMemoryAccessType.FetchUnmapped;
                else if (write)
                    type = present ? BackendMemoryAccessType.WriteProtected : BackendMemoryAccessType.WriteUnmapped;
                else
                    type = present ? BackendMemoryAccessType.ReadProtected : BackendMemoryAccessType.ReadUnmapped;

                for (int i = 0; i < _memoryHooks.Count; i++)
                {
                    MemoryHookEntry entry = _memoryHooks[i];
                    if ((entry.Type & (BackendHookType.MemoryUnmapped | BackendHookType.MemoryProtected)) == 0) continue;
                    if (entry.End == 0 || entry.End < entry.Begin || (entry.Begin <= faultAddress && entry.End >= faultAddress))
                    {
                        if (entry.Callback(type, faultAddress, 1, 0)) return true;
                    }
                }

                return false;
            }

            for (int i = 0; i < _interruptHooks.Count; i++)
                _interruptHooks[i].Callback(exception);

            return _interruptHooks.Count != 0 && exception >= WhpConstants.FirstSoftwareInterruptVector;
        }

        private void AdvanceRip(ulong amount)
        {
            VirtualProcessor vp = CurrentVp;
            GetRegistersRef(vp).Rip += amount;
            vp.RegsDirty = true;
        }

        private ref WhpRegisters GetRegistersRef() => ref GetRegistersRef(CurrentVp);

        private ref WhpRegisters GetRegistersRef(VirtualProcessor vp)
        {
            if (!vp.RegsValid)
            {
                LoadRegisters(vp);
                vp.RegsValid = true;
            }
            return ref vp.Regs;
        }

        internal const int XmmRegisterCount = 16;

        private const int FpControlSlot = XmmRegisterCount;
        private const int XmmControlSlot = XmmRegisterCount + 1;
        private const int VectorRegisterCount = XmmRegisterCount + 2;

        private static readonly uint[] VectorRegNames = BuildVectorRegNames();

        private static uint[] BuildVectorRegNames()
        {
            uint[] Names = new uint[VectorRegisterCount];
            for (int i = 0; i < XmmRegisterCount; i++)
                Names[i] = (uint)WhvRegisterName.Xmm0 + (uint)i;
            Names[FpControlSlot] = (uint)WhvRegisterName.FpControlStatus;
            Names[XmmControlSlot] = (uint)WhvRegisterName.XmmControlStatus;
            return Names;
        }

        private static readonly uint[] GpXmmRegNames = ConcatRegNames(GpRegNames, VectorRegNames);
        private static readonly uint[] GpSegXmmRegNames = ConcatRegNames(GpRegNamesWithSegments, VectorRegNames);

        private static uint[] ConcatRegNames(uint[] head, uint[] tail)
        {
            uint[] Names = new uint[head.Length + tail.Length];
            Array.Copy(head, Names, head.Length);
            Array.Copy(tail, 0, Names, head.Length, tail.Length);
            return Names;
        }

        /// <summary>
        /// Transfers XMM0-15 as 32 qwords, low half of each register first.
        /// </summary>
        public unsafe bool TransferXmmRegisters(ulong[] Values, bool Write)
        {
            if (Values == null || Values.Length < XmmRegisterCount * 2)
                return false;

            VirtualProcessor vp = CurrentVp;
            if (Write)
            {
                // The cache also carries the two control registers, which this call does not supply.
                if (!vp.XmmValid && !LoadXmmRegisters(vp))
                    return false;

                for (int i = 0; i < XmmRegisterCount; i++)
                {
                    vp.Xmm[i].Low = Values[i * 2];
                    vp.Xmm[i].High = Values[i * 2 + 1];
                }

                vp.XmmDirty = true;
                return true;
            }

            if (!vp.XmmValid && !LoadXmmRegisters(vp))
                return false;

            for (int i = 0; i < XmmRegisterCount; i++)
            {
                Values[i * 2] = vp.Xmm[i].Low;
                Values[i * 2 + 1] = vp.Xmm[i].High;
            }

            return true;
        }

        private unsafe bool LoadXmmRegisters(VirtualProcessor vp)
        {
            lock (_vcpuLock)
            {
                fixed (uint* Names = VectorRegNames)
                fixed (WhvRegisterValue* Vals = vp.Xmm)
                {
                    int Hr = WhpNative.WHvGetVirtualProcessorRegisters(_partition, vp.Index, Names, VectorRegisterCount, Vals);
                    if (WhpNative.Failed(Hr))
                        return false;
                }
            }

            vp.XmmValid = true;
            return true;
        }

        private unsafe void StoreXmmRegisters(VirtualProcessor vp)
        {
            lock (_vcpuLock)
            {
                fixed (uint* Names = VectorRegNames)
                fixed (WhvRegisterValue* Vals = vp.Xmm)
                {
                    int Hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, vp.Index, Names, VectorRegisterCount, Vals);
                    if (WhpNative.Failed(Hr))
                        throw new WhpException("WHvSetVirtualProcessorRegisters(XMM) failed", Hr);
                }
            }

            vp.XmmDirty = false;
        }

        // XMM is deliberately not folded into this call. Reading XMM makes WHP extract the full FP
        // state, which costs far more than the call it would save: a GP load runs on every VM exit,
        // an XMM read only on a context switch. Merging the two here measured 1.7s -> 16.8s.
        private unsafe void LoadRegisters(VirtualProcessor vp)
        {
            Span<WhvRegisterValue> values = stackalloc WhvRegisterValue[GpRegNames.Length];
            lock (_vcpuLock)
            {
                fixed (uint* names = GpRegNames)
                fixed (WhvRegisterValue* vals = values)
                {
                    int hr = WhpNative.WHvGetVirtualProcessorRegisters(_partition, vp.Index, names,
                        (uint)GpRegNames.Length, vals);
                    if (WhpNative.Failed(hr))
                        throw new WhpException("WHvGetVirtualProcessorRegisters(GP) failed", hr);
                }
            }

            vp.Regs.Rax = values[0].Low;
            vp.Regs.Rbx = values[1].Low;
            vp.Regs.Rcx = values[2].Low;
            vp.Regs.Rdx = values[3].Low;
            vp.Regs.Rsi = values[4].Low;
            vp.Regs.Rdi = values[5].Low;
            vp.Regs.Rsp = values[6].Low;
            vp.Regs.Rbp = values[7].Low;
            vp.Regs.R8 = values[8].Low;
            vp.Regs.R9 = values[9].Low;
            vp.Regs.R10 = values[10].Low;
            vp.Regs.R11 = values[11].Low;
            vp.Regs.R12 = values[12].Low;
            vp.Regs.R13 = values[13].Low;
            vp.Regs.R14 = values[14].Low;
            vp.Regs.R15 = values[15].Low;
            vp.Regs.Rip = values[16].Low;
            vp.Regs.Rflags = values[17].Low;
        }

        private unsafe void StoreRegisters(VirtualProcessor vp)
        {
            bool withSegments = vp.SegmentsDirty;
            bool withXmm = vp.XmmDirty;
            uint[] names = withSegments
                ? (withXmm ? GpSegXmmRegNames : GpRegNamesWithSegments)
                : (withXmm ? GpXmmRegNames : GpRegNames);
            Span<WhvRegisterValue> values = stackalloc WhvRegisterValue[GpSegXmmRegNames.Length];
            values[0] = WhvRegisterValue.FromReg64(vp.Regs.Rax);
            values[1] = WhvRegisterValue.FromReg64(vp.Regs.Rbx);
            values[2] = WhvRegisterValue.FromReg64(vp.Regs.Rcx);
            values[3] = WhvRegisterValue.FromReg64(vp.Regs.Rdx);
            values[4] = WhvRegisterValue.FromReg64(vp.Regs.Rsi);
            values[5] = WhvRegisterValue.FromReg64(vp.Regs.Rdi);
            values[6] = WhvRegisterValue.FromReg64(vp.Regs.Rsp);
            values[7] = WhvRegisterValue.FromReg64(vp.Regs.Rbp);
            values[8] = WhvRegisterValue.FromReg64(vp.Regs.R8);
            values[9] = WhvRegisterValue.FromReg64(vp.Regs.R9);
            values[10] = WhvRegisterValue.FromReg64(vp.Regs.R10);
            values[11] = WhvRegisterValue.FromReg64(vp.Regs.R11);
            values[12] = WhvRegisterValue.FromReg64(vp.Regs.R12);
            values[13] = WhvRegisterValue.FromReg64(vp.Regs.R13);
            values[14] = WhvRegisterValue.FromReg64(vp.Regs.R14);
            values[15] = WhvRegisterValue.FromReg64(vp.Regs.R15);
            values[16] = WhvRegisterValue.FromReg64(vp.Regs.Rip);
            values[17] = WhvRegisterValue.FromReg64(vp.Regs.Rflags | 0x2UL);

            if (withSegments)
            {
                values[18] = vp.PendingCs;
                values[19] = vp.PendingSs;
                vp.SegmentsDirty = false;
            }

            if (withXmm)
            {
                int xmmBase = withSegments ? GpRegNamesWithSegments.Length : GpRegNames.Length;
                for (int i = 0; i < VectorRegisterCount; i++)
                    values[xmmBase + i] = vp.Xmm[i];
                vp.XmmDirty = false;
            }

            lock (_vcpuLock)
            {
                fixed (uint* n = names)
                fixed (WhvRegisterValue* vals = values)
                {
                    int hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, vp.Index, n,
                        (uint)names.Length, vals);
                    if (WhpNative.Failed(hr))
                        throw new WhpException("WHvSetVirtualProcessorRegisters(GP) failed", hr);
                }
            }
        }

        private void FlushRegisterCache(VirtualProcessor vp)
        {
            if (vp.RegsDirty || vp.SegmentsDirty)
            {
                vp.RegsDirty = false;
                StoreRegisters(vp);
                return;
            }

            // vp.Regs is only known live once something has dirtied it, so a lone XMM write must not ride
            // along a GP store that would push a stale cache into the processor.
            if (vp.XmmDirty)
                StoreXmmRegisters(vp);
        }

        private static void InvalidateRegisterCache(VirtualProcessor vp)
        {
            vp.RegsValid = false;
            vp.XmmValid = false;
        }

        private unsafe void SetSingleRegister(WhvRegisterName name, WhvRegisterValue value)
        {
            uint n = (uint)name;
            lock (_vcpuLock)
            {
                int hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, CurrentVp.Index, &n, 1, &value);
                if (WhpNative.Failed(hr))
                    throw new WhpException($"WHvSetVirtualProcessorRegisters({name}) failed", hr);
            }
        }

        private unsafe WhvRegisterValue GetSingleRegister(WhvRegisterName name)
        {
            VirtualProcessor vp = CurrentVp;
            if (vp.SegmentsDirty && (name == WhvRegisterName.Cs || name == WhvRegisterName.Ss))
                FlushRegisterCache(vp);

            uint n = (uint)name;
            WhvRegisterValue value;
            lock (_vcpuLock)
            {
                int hr = WhpNative.WHvGetVirtualProcessorRegisters(_partition, vp.Index, &n, 1, &value);
                if (WhpNative.Failed(hr))
                    throw new WhpException($"WHvGetVirtualProcessorRegisters({name}) failed", hr);
            }
            return value;
        }

        private static ref ulong GetGpRegisterPointer(ref WhpRegisters regs, GpRegisterName name)
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
                default: throw new WhpException("Unsupported WHP GP register");
            }
        }

        private bool TryWriteSpecialRegister(Registers register, ulong value)
        {
            if (IsDebugRegister(register))
            {
                WriteDebugRegister(register, value);
                return true;
            }

            switch (register)
            {
                case Registers.UC_X86_REG_FS_BASE: WriteSegmentBase(WhvRegisterName.Fs, value); return true;
                case Registers.UC_X86_REG_GS_BASE: WriteSegmentBase(WhvRegisterName.Gs, value); return true;
                case Registers.UC_X86_REG_CS: WriteSegmentSelector(WhvRegisterName.Cs, value); return true;
                case Registers.UC_X86_REG_SS: WriteSegmentSelector(WhvRegisterName.Ss, value); return true;
                case Registers.UC_X86_REG_DS: WriteSegmentSelector(WhvRegisterName.Ds, value); return true;
                case Registers.UC_X86_REG_ES: WriteSegmentSelector(WhvRegisterName.Es, value); return true;
                case Registers.UC_X86_REG_FS: WriteSegmentSelector(WhvRegisterName.Fs, value); return true;
                case Registers.UC_X86_REG_GS: WriteSegmentSelector(WhvRegisterName.Gs, value); return true;
                case Registers.UC_X86_REG_CR0: SetSingleRegister(WhvRegisterName.Cr0, WhvRegisterValue.FromReg64(value)); return true;
                case Registers.UC_X86_REG_CR2: SetSingleRegister(WhvRegisterName.Cr2, WhvRegisterValue.FromReg64(value)); return true;
                case Registers.UC_X86_REG_CR3: SetSingleRegister(WhvRegisterName.Cr3, WhvRegisterValue.FromReg64(value)); return true;
                case Registers.UC_X86_REG_CR4: SetSingleRegister(WhvRegisterName.Cr4, WhvRegisterValue.FromReg64(value)); return true;
                case Registers.UC_X86_REG_CR8: SetSingleRegister(WhvRegisterName.Cr8, WhvRegisterValue.FromReg64(value)); return true;
                case Registers.UC_X86_REG_MSR: SetSingleRegister(WhvRegisterName.Efer, WhvRegisterValue.FromReg64(value)); return true;
                case Registers.UC_X86_REG_FPCW:
                case Registers.UC_X86_REG_MXCSR: return WriteFpControl(register, value);
                default: return false;
            }
        }

        private bool TryReadSpecialRegister(Registers register, out ulong value)
        {
            if (IsDebugRegister(register))
            {
                value = ReadDebugRegister(register);
                return true;
            }

            switch (register)
            {
                case Registers.UC_X86_REG_FS_BASE: value = CurrentVp.FsBase != ulong.MaxValue ? CurrentVp.FsBase : GetSingleRegister(WhvRegisterName.Fs).Low; return true;
                case Registers.UC_X86_REG_GS_BASE: value = CurrentVp.GsBase != ulong.MaxValue ? CurrentVp.GsBase : GetSingleRegister(WhvRegisterName.Gs).Low; return true;
                case Registers.UC_X86_REG_CS: value = SegmentSelector(WhvRegisterName.Cs); return true;
                case Registers.UC_X86_REG_SS: value = SegmentSelector(WhvRegisterName.Ss); return true;
                case Registers.UC_X86_REG_DS: value = SegmentSelector(WhvRegisterName.Ds); return true;
                case Registers.UC_X86_REG_ES: value = SegmentSelector(WhvRegisterName.Es); return true;
                case Registers.UC_X86_REG_FS: value = SegmentSelector(WhvRegisterName.Fs); return true;
                case Registers.UC_X86_REG_GS: value = SegmentSelector(WhvRegisterName.Gs); return true;
                case Registers.UC_X86_REG_CR0: value = GetSingleRegister(WhvRegisterName.Cr0).Low; return true;
                case Registers.UC_X86_REG_CR2: value = GetSingleRegister(WhvRegisterName.Cr2).Low; return true;
                case Registers.UC_X86_REG_CR3: value = GetSingleRegister(WhvRegisterName.Cr3).Low; return true;
                case Registers.UC_X86_REG_CR4: value = GetSingleRegister(WhvRegisterName.Cr4).Low; return true;
                case Registers.UC_X86_REG_CR8: value = GetSingleRegister(WhvRegisterName.Cr8).Low; return true;
                case Registers.UC_X86_REG_MSR: value = GetSingleRegister(WhvRegisterName.Efer).Low; return true;
                case Registers.UC_X86_REG_FPCW:
                case Registers.UC_X86_REG_MXCSR: return ReadFpControl(register, out value);
                default: value = 0; return false;
            }
        }

        // Both registers carry unrelated state in the rest of their 128 bits (FpStatus/FpTag/LastFpOp/LastFpRip,
        // LastFpRdp/XmmStatusControlMask), so a write is a read-modify-write of the cached value.
        private bool WriteFpControl(Registers register, ulong value)
        {
            VirtualProcessor vp = CurrentVp;
            if (!vp.XmmValid && !LoadXmmRegisters(vp))
                return false;

            if (register == Registers.UC_X86_REG_FPCW)
                vp.Xmm[FpControlSlot].Low = (vp.Xmm[FpControlSlot].Low & ~0xFFFFUL) | (ushort)value;
            else
                vp.Xmm[XmmControlSlot].High = (vp.Xmm[XmmControlSlot].High & ~0xFFFFFFFFUL) | (uint)value;

            vp.XmmDirty = true;
            return true;
        }

        private bool ReadFpControl(Registers register, out ulong value)
        {
            value = 0;
            VirtualProcessor vp = CurrentVp;
            if (!vp.XmmValid && !LoadXmmRegisters(vp))
                return false;

            value = register == Registers.UC_X86_REG_FPCW
                ? (ushort)vp.Xmm[FpControlSlot].Low
                : (uint)vp.Xmm[XmmControlSlot].High;
            return true;
        }

        private ushort SegmentSelector(WhvRegisterName name) => (ushort)(GetSingleRegister(name).High >> 32);

        private void WriteSegmentSelector(WhvRegisterName name, ulong selector)
        {
            WhvRegisterValue v = GetSingleRegister(name);
            v.High = (v.High & ~(0xFFFFUL << 32)) | ((ulong)(ushort)selector << 32);
            SetSingleRegister(name, v);
        }

        private void WriteSegmentBase(WhvRegisterName name, ulong baseAddress)
        {
            VirtualProcessor vp = CurrentVp;
            ref ulong cached = ref (name == WhvRegisterName.Gs ? ref vp.GsBase : ref vp.FsBase);
            if (_guest64 && cached == baseAddress)
                return;

            WhvRegisterValue v = GetSingleRegister(name);
            v.Low = baseAddress;
            SetSingleRegister(name, v);
            cached = baseAddress;

            if (!_guest64)
                SyncGdtDescriptorBase((ushort)(v.High >> 32), baseAddress);
        }

        private unsafe void SyncGdtDescriptorBase(ushort selector, ulong segmentBase)
        {
            int index = selector >> 3;
            if (index != WhpConstants.UserFsSelector32 >> 3) return;
            if (!_mappedPages.TryGetValue(CurrentVp.GdtPageGpa, out MappedPage gdtPage) || gdtPage.HostPage == IntPtr.Zero) return;

            byte* descriptor = (byte*)gdtPage.HostPage + index * 8;
            descriptor[2] = (byte)segmentBase;
            descriptor[3] = (byte)(segmentBase >> 8);
            descriptor[4] = (byte)(segmentBase >> 16);
            descriptor[7] = (byte)(segmentBase >> 24);
        }

        private static bool IsDebugRegister(Registers register) => register switch
        {
            Registers.UC_X86_REG_DR0 => true,
            Registers.UC_X86_REG_DR1 => true,
            Registers.UC_X86_REG_DR2 => true,
            Registers.UC_X86_REG_DR3 => true,
            Registers.UC_X86_REG_DR6 => true,
            Registers.UC_X86_REG_DR7 => true,
            _ => false,
        };

        private void WriteDebugRegister(Registers register, ulong value)
        {
            WhvRegisterName name = register switch
            {
                Registers.UC_X86_REG_DR0 => WhvRegisterName.Dr0,
                Registers.UC_X86_REG_DR1 => WhvRegisterName.Dr1,
                Registers.UC_X86_REG_DR2 => WhvRegisterName.Dr2,
                Registers.UC_X86_REG_DR3 => WhvRegisterName.Dr3,
                Registers.UC_X86_REG_DR6 => WhvRegisterName.Dr6,
                Registers.UC_X86_REG_DR7 => WhvRegisterName.Dr7,
                _ => throw new WhpException("Unsupported WHP debug register"),
            };
            SetSingleRegister(name, WhvRegisterValue.FromReg64(value));
        }

        private ulong ReadDebugRegister(Registers register)
        {
            WhvRegisterName name = register switch
            {
                Registers.UC_X86_REG_DR0 => WhvRegisterName.Dr0,
                Registers.UC_X86_REG_DR1 => WhvRegisterName.Dr1,
                Registers.UC_X86_REG_DR2 => WhvRegisterName.Dr2,
                Registers.UC_X86_REG_DR3 => WhvRegisterName.Dr3,
                Registers.UC_X86_REG_DR6 => WhvRegisterName.Dr6,
                Registers.UC_X86_REG_DR7 => WhvRegisterName.Dr7,
                _ => throw new WhpException("Unsupported WHP debug register"),
            };
            return GetSingleRegister(name).Low;
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

        private unsafe bool TryGetHostPointer(ulong address, int accessSize, out byte* ptr, out long offset)
        {
            ptr = null;
            offset = 0;
            if (accessSize <= 0) return false;

            ulong pageBase = address & ~WhpConstants.PageMask;
            if (!TryLookupPage(pageBase, out MappedPage page))
                return false;

            ulong accessEnd = address + (ulong)accessSize;
            ulong firstPageEnd = pageBase + WhpConstants.PageSize;
            if (accessEnd <= firstPageEnd)
            {
                ptr = (byte*)page.HostPage;
                offset = (long)(address - pageBase);
                return true;
            }

            if (TryGetIntactBackingEnd(page, pageBase, out ulong backingEnd) && accessEnd <= backingEnd)
            {
                ptr = (byte*)page.HostPage;
                offset = (long)(address - pageBase);
                return true;
            }

            ulong cursor = pageBase + WhpConstants.PageSize;
            while (cursor < accessEnd)
            {
                if (!_mappedPages.TryGetValue(cursor, out MappedPage next) || next == null || next.HostPage == IntPtr.Zero)
                    return false;
                long expectedHost = page.HostPage.ToInt64() + (long)(cursor - pageBase);
                long actualHost = next.HostPage.ToInt64();
                if (expectedHost != actualHost) return false;
                cursor += WhpConstants.PageSize;
            }

            ptr = (byte*)page.HostPage;
            offset = (long)(address - pageBase);
            return true;
        }

        private bool TryGetIntactBackingEnd(MappedPage page, ulong pageBase, out ulong backingEnd)
        {
            backingEnd = 0;
            if (page.OwnedBacking == IntPtr.Zero || page.IsAlias) return false;
            if (!_backingAllocations.TryGetValue(page.OwnedBacking, out BackingAllocation allocation)) return false;
            if (allocation.LivePages != (int)(allocation.Size / WhpConstants.PageSize)) return false;

            ulong hostOffset = (ulong)(page.HostPage.ToInt64() - page.OwnedBacking.ToInt64());
            if (hostOffset > pageBase || hostOffset >= allocation.Size) return false;

            backingEnd = pageBase - hostOffset + allocation.Size;
            return true;
        }

        private bool DisposedCheck()
        {
            if (Disposed || Disposing)
            {
                if (ThrowDisposed) throw new ObjectDisposedException(nameof(Whp));
                return true;
            }
            return false;
        }
    }
}
