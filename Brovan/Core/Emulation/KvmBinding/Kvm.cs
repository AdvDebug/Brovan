using System;
using System.Collections.Generic;
using System.Diagnostics;
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

    public sealed class Kvm : IDisposable
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
        private int _nextSlotId;
        private readonly List<int> _freeSlotIds = new();
        private readonly Dictionary<ulong, InstalledSlot> _activeSlots = new();

        private readonly Dictionary<ulong, MappedPage> _mappedPages = new();
        private readonly Dictionary<IntPtr, BackingAllocation> _backingAllocations = new();
        private ulong _backingBytes;
        // A page watched for writes only keeps a read-only memslot, so its reads run natively.
        private readonly Dictionary<ulong, bool> _trappedPages = new();
        private readonly Dictionary<ulong, IntPtr> _pageTableViews = new();

        private ulong[] _sortedPageKeys = Array.Empty<ulong>();
        private bool _sortedPageKeysDirty = true;
        private bool _mappingsDirty;
        private ulong _lastLookupPageBase = ulong.MaxValue;
        private MappedPage _lastLookupPage;
        private readonly Dictionary<ulong, InstalledSlot> _desiredSlots = new();
        private readonly List<ulong> _staleSlotKeys = new();
        private readonly List<ulong> _activeSlotStarts = new();
        private bool _fullRebuildRequired = true;
        private readonly List<DirtyRange> _dirtyRanges = new();
        private const int MaxDirtyRanges = 16;
        private ulong _pml4Gpa;
        private ulong _nextInternalGpa = KvmConstants.InternalPageTableBase;

        private IntPtr _internalPoolPtr = IntPtr.Zero;
        private const ulong InternalPoolSize = 16 * 1024 * 1024;
        private ulong _internalPoolOffset;

        private readonly List<(IntPtr Ptr, ulong Size)> _internalPoolFallbacks = new();

        private ulong _syscallTrapPageGpa;
        private ulong _exceptionStubPageGpa;
        private ulong _exceptionIdtPageGpa;
        private ulong _exceptionTssPageGpa;
        private ulong _exceptionStackPageGpa;
        private ulong _gdtPageGpa;

        private readonly object _vcpuLock = new();

        private sealed class VirtualProcessor
        {
            public int Index;
            public int Fd = -1;
            public IntPtr RunPtr;
            public uint ThreadId;

            // Parked in the trap page with kernel CS/SS, so no segment write reaches the vCPU.
            public bool InSyscallStub;
        }

        // The trap page holds hlt at 0 and sysretq at 8.
        private const ulong SyscallReturnOffset = 8;

        // One vCPU per guest thread. Threads past the limit share vCPU 0 and swap state each slice.
        private VirtualProcessor _vp;
        private readonly List<VirtualProcessor> _processors = new();
        private readonly Stack<VirtualProcessor> _idleProcessors = new();
        private readonly Dictionary<uint, VirtualProcessor> _threadProcessors = new();
        private int _processorLimit;
        private VirtualProcessor _runningProcessor;
        private int _emulateManagedThreadId;
        private int _emulateTid;

        // KVM cannot end a run after a set instruction count, so a slice is bounded by wall clock.
        private const int BoundedSliceMilliseconds = 10;
        private Thread _maintenanceThread;
        private long _sliceDeadlineTimestamp;

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
        private bool _hasRdtscHook;
        private bool _hasRdtscpHook;
        private bool _hasInvalidHook;
        private bool _scanPreRunInstructions;

        private static readonly long MmioRefreshIntervalTicks = Stopwatch.Frequency / 4000;
        private long _lastMmioRefreshTimestamp;

        private int _disposed;
        private int _disposing;
        private volatile bool _stopRequested;
        private bool _mmioCompletionPending;
        private bool _faultRegistersSaved;
        private LinuxKvmRegisters _faultRegisters;
        private bool _singleStepRequested;

        public bool NoHooks;
        public static bool ThrowDisposed = true;
        public bool Disposed => Volatile.Read(ref _disposed) == 1;

        public bool SupportsXsave => _supportsXsave;
        private bool Disposing => Volatile.Read(ref _disposing) == 1;

        private KvmErrors _error;

        private sealed class MappedPage
        {
            public IntPtr HostPage;
            public IntPtr OwnedBacking;
            public bool IsAlias;
            public KvmMemoryPermission Permissions;
        }

        private sealed class BackingAllocation
        {
            public ulong Size;
            public int LivePages;
            public int AliasPages;
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
            if (arch != Arch.X86 || mode != Mode.MODE_64)
                throw new KvmException("KVM backend only supports x86-64 long mode.");

            EnsurePlatformSupport();
            _pid = KvmNative.getpid();
            AllocateInternalPool();
            ConfigurePartition();
            InitializeLongModePageTables();
            InitializeGdt();
            InitializeSyscallTrapPage();
            InitializeExceptionHandling();
            _vp = CreateProcessor(0);
            _timestampCounterFrequency = QueryTimestampCounterFrequency();
            RebuildMappings();
        }

        public KvmErrors GetLastError() => _error;

        public ulong TimestampCounterFrequency => _timestampCounterFrequency;

        private ulong QueryTimestampCounterFrequency()
        {
            if (KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapGetTscKhz) <= 0)
                return 0;
            int khz = KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoGetTscKhz, IntPtr.Zero);
            return khz <= 0 ? 0 : (ulong)khz * 1000;
        }

        public bool TryReadTimestampCounter(out ulong value)
        {
            value = 0;
            if (DisposedCheck())
                return false;

            try
            {
                value = GetMsr(_vp, KvmConstants.MsrTsc);
                return true;
            }
            catch (KvmException)
            {
                return false;
            }
        }

        public bool MapMemoryShared(ulong address, ulong size, MemoryProtection protection, IntPtr hostPointer)
        {
            if (DisposedCheck() || hostPointer == IntPtr.Zero) return false;

            if ((address & KvmConstants.PageMask) != 0 || (size & KvmConstants.PageMask) != 0)
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            KvmMemoryPermission perm = TranslateProtection(protection);
            long backingAddr = hostPointer.ToInt64();
            IntPtr backing = FindBackingAllocation(hostPointer);

            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
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
            _error = KvmErrors.Ok;
            return true;
        }

        public bool MapMemory(ulong address, ulong size, MemoryProtection protection)
        {
            if (DisposedCheck()) return false;

            if ((address & KvmConstants.PageMask) != 0 || (size & KvmConstants.PageMask) != 0)
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            KvmMemoryPermission perm = TranslateProtection(protection);

            bool canBatch = true;
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
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
                    _error = KvmErrors.NoMemory;
                    return false;
                }

                long backingAddr = backing.ToInt64();
                _backingAllocations[backing] = new BackingAllocation
                {
                    Size = size,
                    LivePages = (int)(size / KvmConstants.PageSize),
                };

                for (ulong off = 0; off < size; off += KvmConstants.PageSize)
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

                RebuildMappings();
                _error = KvmErrors.Ok;
                return true;
            }

            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                if (!_mappedPages.TryGetValue(guest, out MappedPage page))
                {
                    page = new MappedPage();
                    SetMappedPage(guest, page);
                }

                if (page.HostPage == IntPtr.Zero)
                {
                    if (!TryAllocateBackingMemory(KvmConstants.PageSize, out IntPtr backing))
                    {
                        RebuildMappings();
                        _error = KvmErrors.NoMemory;
                        return false;
                    }

                    _backingAllocations[backing] = new BackingAllocation
                    {
                        Size = KvmConstants.PageSize,
                        LivePages = 1,
                    };
                    page.HostPage = backing;
                    page.OwnedBacking = backing;
                }

                page.Permissions = perm;
                MarkSpanDirty(guest, KvmConstants.PageSize);
                EnsureVirtualMapping(guest);
            }

            RebuildMappings();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool UnmapMemory(ulong address, ulong size)
        {
            if (DisposedCheck()) return false;

            if ((address & KvmConstants.PageMask) != 0 || (size & KvmConstants.PageMask) != 0)
            {
                _error = KvmErrors.InvalidArgument;
                return false;
            }

            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                ulong guest = address + off;
                if (_mappedPages.TryGetValue(guest, out MappedPage page))
                {
                    ReleaseBacking(page);
                    RemoveMappedPage(guest);
                }
            }

            for (int i = _mmioRegions.Count - 1; i >= 0; i--)
            {
                MmioRegion region = _mmioRegions[i];
                if (region.Address >= address && region.Address < address + size)
                    _mmioRegions.RemoveAt(i);
            }

            RebuildMappings();
            _error = KvmErrors.Ok;
            return true;
        }

        public bool MapMmio(ulong address, ulong size, MmioReadCallback read, MmioWriteCallback write)
        {
            if (DisposedCheck()) return false;

            if (read == null || write == null ||
                (address & KvmConstants.PageMask) != 0 || (size & KvmConstants.PageMask) != 0 || size == 0)
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

            _mmioRegions.RemoveAll(r => r.Address == address);
            _mmioRegions.Add(region);

            RefreshMmioRegion(region);
            _error = KvmErrors.Ok;
            return true;
        }

        public bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection)
        {
            if (DisposedCheck()) return false;

            KvmMemoryPermission perm = TranslateProtection(protection);
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
            {
                if (_mappedPages.TryGetValue(address + off, out MappedPage page))
                {
                    page.Permissions = perm;
                    MarkSpanDirty(address + off, KvmConstants.PageSize);
                }
            }

            RebuildMappings();
            _error = KvmErrors.Ok;
            return true;
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

            if (TryGetHostPointer(address, length, out byte* dst, out long dstOffset))
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

            if (TryGetHostPointer(address, (int)writeLen, out byte* dst, out long offset))
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

            if (TryGetHostPointer(address, (int)length, out byte* src, out long offset))
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

            if (TryGetHostPointer(address, (int)readLen, out byte* src, out long offset))
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
            if (TryGetHostPointer(address, sizeof(ulong), out byte* ptr, out long offset))
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
            if (TryGetHostPointer(address, sizeof(uint), out byte* ptr, out long offset))
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
            if (TryGetHostPointer(address, sizeof(ushort), out byte* ptr, out long offset))
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
                if (TryGetHostPointer(address, length, out byte* src, out long offset))
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

            VirtualProcessor vp = _vp;
            ref LinuxKvmRun run = ref GetRunRef(vp);

            ClearTrapFlag();

            run.Regs.Rip = start;
            MarkRegistersDirty();

            _stopRequested = false;
            _mmioCompletionPending = false;
            _faultRegistersSaved = false;
            _singleStepRequested = count == 1;
            run.ImmediateExit = 0;

            if (_emulateManagedThreadId != Environment.CurrentManagedThreadId)
            {
                _emulateManagedThreadId = Environment.CurrentManagedThreadId;
                Volatile.Write(ref _emulateTid, KvmNative.gettid());
            }
            Volatile.Write(ref _runningProcessor, vp);

            bool bounded = count != 0;
            if (bounded)
            {
                EnsureMaintenanceThread();
                Volatile.Write(ref _sliceDeadlineTimestamp,
                    Stopwatch.GetTimestamp() + (Stopwatch.Frequency * BoundedSliceMilliseconds) / 1000);
            }

            if (_singleStepRequested)
            {
                run.Regs.Rflags |= 0x100UL;
                MarkRegistersDirty();
            }

            try
            {
                while (true)
                {
                    // Zero means the deadline was consumed, by the timer or by a kick.
                    bool sliceOver = _stopRequested || (bounded && Volatile.Read(ref _sliceDeadlineTimestamp) == 0);
                    if (sliceOver && !_mmioCompletionPending)
                        break;

                    if (HandlePreRunInstruction()) continue;

                    RefreshMmioBackedRegions();

                    if (vp.InSyscallStub) PrepareSyscallReturn(vp, ref run);

                    int rc;
                    lock (_vcpuLock)
                    {
                        rc = KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoRun, IntPtr.Zero);
                    }

                    if (vp.InSyscallStub) CompleteSyscallReturn(vp, ref run);

                    if (_mmioCompletionPending)
                    {
                        _mmioCompletionPending = false;
                        if (_faultRegistersSaved && (rc < 0 || run.ExitReason != KvmConstants.ExitMmio))
                        {
                            _faultRegistersSaved = false;
                            SetRegisters(_faultRegisters);
                        }
                    }

                    if (rc < 0)
                    {
                        int errno = Marshal.GetLastWin32Error();
                        if (errno == KvmNative.ErrnoEintr)
                        {
                            ClearImmediateExit(ref run, bounded);
                            continue;
                        }

                        _error = KvmErrors.InternalError;
                        throw new KvmException("KVM_RUN failed", errno);
                    }

                    switch (run.ExitReason)
                    {
                        case KvmConstants.ExitHlt:
                            if (HandleHltExit()) continue;
                            return _error == KvmErrors.Ok;
                        case KvmConstants.ExitMmio:
                            if (!HandleMmioExit(ref run))
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
                            ClearImmediateExit(ref run, bounded);
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
                Volatile.Write(ref _sliceDeadlineTimestamp, 0);
                Volatile.Write(ref _runningProcessor, null);

                if (_singleStepRequested)
                {
                    _singleStepRequested = false;
                    ClearTrapFlag();
                }
            }
        }

        // KVM never clears immediate_exit, and leaving it set makes every later KVM_RUN return -EINTR.
        private void ClearImmediateExit(ref LinuxKvmRun run, bool bounded)
        {
            if (_stopRequested) return;
            if (bounded && Volatile.Read(ref _sliceDeadlineTimestamp) == 0) return;

            run.ImmediateExit = 0;
            Interlocked.MemoryBarrier();
            if (bounded && Volatile.Read(ref _sliceDeadlineTimestamp) == 0)
                run.ImmediateExit = 1;
        }

        public bool StopEmulation()
        {
            if (DisposedCheck()) return false;

            _stopRequested = true;
            if (Environment.CurrentManagedThreadId == _emulateManagedThreadId)
                GetRunRef().ImmediateExit = 1;
            else
                KickRunningProcessor();

            _error = KvmErrors.Ok;
            return true;
        }

        private void EnsureMaintenanceThread()
        {
            if (_maintenanceThread != null)
                return;

            EnsureKickSignal();
            _maintenanceThread = new Thread(MaintenanceLoop)
            {
                IsBackground = true,
                Name = "KvmMaintenance"
            };
            _maintenanceThread.Start();
        }

        private void MaintenanceLoop()
        {
            while (!Disposed && !Disposing)
            {
                EnforceSliceDeadline();
                Thread.Sleep(1);
            }
        }

        public bool TryLimitSlice(int microseconds)
        {
            long limit = Stopwatch.GetTimestamp() + (Stopwatch.Frequency * microseconds) / 1_000_000;
            while (true)
            {
                long deadline = Volatile.Read(ref _sliceDeadlineTimestamp);
                if (deadline == 0)
                    return false;
                if (limit >= deadline)
                    return true;
                if (Interlocked.CompareExchange(ref _sliceDeadlineTimestamp, limit, deadline) == deadline)
                    return true;
            }
        }

        private void EnforceSliceDeadline()
        {
            long deadline = Volatile.Read(ref _sliceDeadlineTimestamp);
            if (deadline == 0 || Stopwatch.GetTimestamp() < deadline)
                return;

            if (Disposed || Disposing)
                return;

            if (Interlocked.CompareExchange(ref _sliceDeadlineTimestamp, 0, deadline) != deadline)
                return;

            KickRunningProcessor();
        }

        // immediate_exit stops a run that has not entered the guest yet, the signal stops one that has.
        private void KickRunningProcessor()
        {
            VirtualProcessor vp = Volatile.Read(ref _runningProcessor);
            if (vp == null)
                return;

            Volatile.Write(ref GetRunRef(vp).ImmediateExit, 1);
            Interlocked.MemoryBarrier();

            int tid = Volatile.Read(ref _emulateTid);
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
            if (NoHooks) { _error = KvmErrors.Ok; return IntPtr.Zero; }

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
                ulong pageBase = current & ~KvmConstants.PageMask;
                if (!TryLookupPage(pageBase, out MappedPage page))
                    return false;
                ulong runEnd = TryGetIntactBackingEnd(page, pageBase, out ulong backingEnd)
                    ? backingEnd
                    : pageBase + KvmConstants.PageSize;
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

            try
            {
                RemoveHooks();

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

        private static KvmMemoryPermission TranslateProtection(MemoryProtection protection)
        {
            KvmMemoryPermission perm = KvmMemoryPermission.None;
            if ((protection & MemoryProtection.Read) != 0) perm |= KvmMemoryPermission.Read;
            if ((protection & MemoryProtection.Write) != 0) perm |= KvmMemoryPermission.Write;
            if ((protection & MemoryProtection.Execute) != 0) perm |= KvmMemoryPermission.Execute;
            return perm;
        }

        private static uint ToKvmMapFlags(KvmMemoryPermission permissions)
        {
            if (permissions == KvmMemoryPermission.None) return 0;
            uint flags = 0;
            if ((permissions & KvmMemoryPermission.Write) == 0)
                flags |= KvmConstants.MemSlotReadOnly;
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

        private static LinuxKvmSegment MakeSegment(ushort selector, bool isCode, bool isUser)
        {
            return new LinuxKvmSegment
            {
                Base = 0,
                Limit = 0xFFFFF,
                Selector = selector,
                Type = isCode ? (byte)0xB : (byte)0x3,
                Present = 1,
                Dpl = isUser ? (byte)3 : (byte)0,
                Db = isCode ? (byte)0 : (byte)1,
                S = 1,
                L = isCode ? (byte)1 : (byte)0,
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
                Utils.LogError($"[Kvm] Host backing mapping of 0x{size:X} bytes failed with {Marshal.GetLastWin32Error()}. Live backing 0x{_backingBytes:X} bytes in {_backingAllocations.Count} allocations.");
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

        private unsafe void FreeBackingMemory(IntPtr ptr, ulong size)
        {
            KvmNative.munmap(ptr, (UIntPtr)size);
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

        private unsafe ref LinuxKvmRun GetRunRef()
            => ref Unsafe.AsRef<LinuxKvmRun>((void*)_vp.RunPtr);

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
                throw new KvmException("open(/dev/kvm) failed", Marshal.GetLastWin32Error());

            int apiVersion = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoGetApiVersion, IntPtr.Zero);
            if (apiVersion < 0)
                throw new KvmException("KVM_GET_API_VERSION failed", Marshal.GetLastWin32Error());
            if (apiVersion != KvmConstants.ExpectedApiVersion)
                throw new KvmException($"Unexpected KVM API version {apiVersion}");

            _maxMemslots = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapNrMemslots);
            if (_maxMemslots <= 0)
                _maxMemslots = DefaultMemslotCount;

            _supportsXsave = KvmNative.ioctl(_systemFd, KvmConstants.KvmIoCheckExtension, KvmConstants.CapXsave) > 0;

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
            KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoSetTssAddress, (IntPtr)0xfffbd000);
        }

        private VirtualProcessor CreateProcessor(int index)
        {
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

            VirtualProcessor vp = new VirtualProcessor { Index = index, Fd = fd, RunPtr = runPtr };
            _processors.Add(vp);
            InitializeCpuid(vp);
            InitializeVirtualProcessorState(vp);
            return vp;
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
                }
                _cpuidTable = table;
            }

            fixed (byte* buffer = _cpuidTable)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoSetCpuid2, (IntPtr)buffer) < 0)
                    throw new KvmException("KVM_SET_CPUID2 failed", Marshal.GetLastWin32Error());
            }
        }

        private void InitializeVirtualProcessorState(VirtualProcessor vp)
        {
            ref LinuxKvmRun run = ref GetRunRef(vp);

            lock (_vcpuLock)
            {
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoGetRegisters, ref run.Regs) < 0)
                    throw new KvmException("KVM_GET_REGS failed", Marshal.GetLastWin32Error());
                if (KvmNative.ioctl(vp.Fd, KvmConstants.KvmIoGetSpecialRegisters, ref run.Sregs) < 0)
                    throw new KvmException("KVM_GET_SREGS failed", Marshal.GetLastWin32Error());
            }

            ref LinuxKvmSpecialRegisters sregs = ref run.Sregs;
            sregs.Cs = MakeSegment(KvmConstants.UserCodeSelector, true, true);
            sregs.Ss = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Ds = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Es = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Fs = MakeSegment(0x53, false, true);
            sregs.Gs = MakeSegment(KvmConstants.UserDataSelector, false, true);
            sregs.Cr0 = 0x80000033UL;
            sregs.Cr4 = 0x620UL;
            sregs.Cr3 = _pml4Gpa;
            sregs.Efer = (1UL << 0) | (1UL << 8) | (1UL << 10) | (1UL << 11);
            sregs.Gdt.Base = _gdtPageGpa;
            sregs.Gdt.Limit = 0x48;
            sregs.Idt.Base = _exceptionIdtPageGpa;
            sregs.Idt.Limit = (ushort)(KvmConstants.ExceptionVectorCount * 16 - 1);
            sregs.Tr.Selector = KvmConstants.TssSelector;
            sregs.Tr.Base = _exceptionTssPageGpa;
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

            SetMsr(vp, KvmConstants.MsrStar, (0x23UL << 48) | (0x08UL << 32));
            SetMsr(vp, KvmConstants.MsrSyscallMask, 0);
            SetMsr(vp, KvmConstants.MsrLstar, _syscallTrapPageGpa);
        }

        public bool SupportsThreadResidency => _processorLimit > 1;

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
            if (!_threadProcessors.Remove(threadId, out VirtualProcessor vp))
                return;

            vp.ThreadId = 0;
            _idleProcessors.Push(vp);
            if (ReferenceEquals(_vp, vp))
                _vp = _processors[0];
        }

        public void SelectThread(uint threadId)
        {
            VirtualProcessor vp = _threadProcessors.TryGetValue(threadId, out VirtualProcessor bound) ? bound : _processors[0];
            if (vp.ThreadId != threadId)
            {
                LeaveSyscallStub(vp);
                vp.ThreadId = threadId;
            }
            _vp = vp;
        }

        private void InitializeSyscallTrapPage()
        {
            _syscallTrapPageGpa = AllocateInternalPage(true);
            unsafe
            {
                if (_mappedPages.TryGetValue(_syscallTrapPageGpa, out MappedPage page))
                {
                    byte* code = (byte*)page.HostPage;
                    code[0] = 0xF4;
                    code[SyscallReturnOffset] = 0x48;
                    code[SyscallReturnOffset + 1] = 0x0F;
                    code[SyscallReturnOffset + 2] = 0x07;
                }
            }
        }

        private void InitializeGdt()
        {
            _gdtPageGpa = AllocateInternalPage(false);
            if (!_mappedPages.TryGetValue(_gdtPageGpa, out MappedPage gdtPage) || gdtPage.HostPage == IntPtr.Zero)
                throw new KvmException("Failed to allocate GDT page.");

            unsafe
            {
                byte* gdt = (byte*)gdtPage.HostPage;
                Unsafe.InitBlockUnaligned(gdt, 0, (uint)KvmConstants.PageSize);

                gdt[0x08] = 0xFF; gdt[0x09] = 0xFF; gdt[0x0A] = 0x00; gdt[0x0B] = 0x00;
                gdt[0x0C] = 0x00; gdt[0x0D] = 0x9B; gdt[0x0E] = 0xAF; gdt[0x0F] = 0x00;

                gdt[0x10] = 0xFF; gdt[0x11] = 0xFF; gdt[0x12] = 0x00; gdt[0x13] = 0x00;
                gdt[0x14] = 0x00; gdt[0x15] = 0x93; gdt[0x16] = 0xCF; gdt[0x17] = 0x00;

                gdt[0x28] = 0xFF; gdt[0x29] = 0xFF; gdt[0x2A] = 0x00; gdt[0x2B] = 0x00;
                gdt[0x2C] = 0x00; gdt[0x2D] = 0xF3; gdt[0x2E] = 0xCF; gdt[0x2F] = 0x00;

                gdt[0x30] = 0xFF; gdt[0x31] = 0xFF; gdt[0x32] = 0x00; gdt[0x33] = 0x00;
                gdt[0x34] = 0x00; gdt[0x35] = 0xFB; gdt[0x36] = 0xAF; gdt[0x37] = 0x00;
            }
        }

        private void InitializeExceptionHandling()
        {
            _exceptionStubPageGpa = AllocateInternalPage(true);
            _exceptionIdtPageGpa = AllocateInternalPage(false);
            _exceptionTssPageGpa = AllocateInternalPage(false);

            ulong exceptionStackSize = 16 * KvmConstants.PageSize;
            _exceptionStackPageGpa = AllocateInternalRange(exceptionStackSize, KvmMemoryPermission.ReadWrite);

            unsafe
            {
                if (_mappedPages.TryGetValue(_exceptionStubPageGpa, out MappedPage stubPage))
                {
                    byte* stubs = (byte*)stubPage.HostPage;
                    for (uint vector = 0; vector < KvmConstants.ExceptionVectorCount; vector++)
                        stubs[vector * (int)KvmConstants.ExceptionStubStride] = 0xF4;
                }

                if (_mappedPages.TryGetValue(_exceptionIdtPageGpa, out MappedPage idtPage))
                {
                    byte* idt = (byte*)idtPage.HostPage;
                    for (uint vector = 0; vector < KvmConstants.ExceptionVectorCount; vector++)
                    {
                        ulong handler = _exceptionStubPageGpa + vector * KvmConstants.ExceptionStubStride;

                        ulong low = (handler & 0xFFFF)
                                  | ((ulong)KvmConstants.KernelCodeSelector << 16)
                                  | ((ulong)(KvmConstants.ExceptionIstIndex & 0x7) << 32)
                                  | ((ulong)KvmConstants.ExceptionGateAttributes << 40)
                                  | (((handler >> 16) & 0xFFFF) << 48);
                        ulong high = (handler >> 32) & 0xFFFFFFFF;
                        Unsafe.WriteUnaligned(idt + vector * 16, low);
                        Unsafe.WriteUnaligned(idt + vector * 16 + 8, (uint)high);
                    }
                }

                if (_mappedPages.TryGetValue(_exceptionTssPageGpa, out MappedPage tssPage))
                {
                    byte* tss = (byte*)tssPage.HostPage;
                    ulong stackTop = _exceptionStackPageGpa + exceptionStackSize;
                    Unsafe.WriteUnaligned(tss + 0x04, stackTop);
                    Unsafe.WriteUnaligned(tss + 0x24, stackTop);
                    ushort ioMapBase = 0x68;
                    Unsafe.WriteUnaligned(tss + 0x66, ioMapBase);
                }
            }

            if (_gdtPageGpa != 0 && _mappedPages.TryGetValue(_gdtPageGpa, out MappedPage gdtMapped) && gdtMapped.HostPage != IntPtr.Zero)
            {
                unsafe
                {
                    byte* gdt = (byte*)gdtMapped.HostPage;
                    int tssIndex = KvmConstants.TssSelector >> 3;
                    ulong tssBase = _exceptionTssPageGpa;
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
            => AllocateInternalRange(KvmConstants.PageSize,
                executable ? KvmMemoryPermission.All : KvmMemoryPermission.ReadWrite, mapIntoGuest);

        private ulong AllocateInternalRange(ulong size, KvmMemoryPermission permissions, bool mapIntoGuest = true)
        {
            if ((size & KvmConstants.PageMask) != 0)
                size = (size + KvmConstants.PageMask) & ~KvmConstants.PageMask;

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
            for (ulong off = 0; off < size; off += KvmConstants.PageSize)
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

        private void EnsureVirtualMapping(ulong guestAddress)
        {
            ulong pageBase = guestAddress & ~KvmConstants.PageMask;
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
                pt[ptIndex] = pageBase
                    | KvmConstants.PageTableEntryPresent
                    | KvmConstants.PageTableEntryWritable
                    | KvmConstants.PageTableEntryUser;
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
                if ((entry & KvmConstants.PageTableEntryPresent) == 0)
                {
                    ulong childGpa = AllocateInternalPage(false, false);
                    entries[index] = childGpa
                        | KvmConstants.PageTableEntryPresent
                        | KvmConstants.PageTableEntryWritable
                        | KvmConstants.PageTableEntryUser;
                    return childGpa;
                }
                return entry & KvmConstants.PageTableEntryAddressMask;
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
            MarkSpanDirty(guestAddress, KvmConstants.PageSize);
            _lastLookupPageBase = ulong.MaxValue;
            _lastLookupPage = null;
        }

        private void RemoveMappedPage(ulong guestAddress)
        {
            if (!_mappedPages.Remove(guestAddress)) return;
            _sortedPageKeysDirty = true;
            _mappingsDirty = true;
            MarkSpanDirty(guestAddress, KvmConstants.PageSize);
            _lastLookupPageBase = ulong.MaxValue;
            _lastLookupPage = null;
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

        private void RebuildMappingsFull()
        {
            ulong[] sortedKeys = GetSortedPageKeys();
            int keyCount = _mappedPages.Count;
            bool anyTrapped = _trappedPages.Count != 0;

            _desiredSlots.Clear();

            for (int i = 0; i < keyCount;)
            {
                ulong runAddress = sortedKeys[i];
                if (!_mappedPages.TryGetValue(runAddress, out MappedPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == KvmMemoryPermission.None)
                {
                    i++;
                    continue;
                }

                if (anyTrapped && _trappedPages.TryGetValue(runAddress, out bool writeOnly))
                {
                    if (writeOnly)
                        _desiredSlots[runAddress] = MakeWriteWatchSlot(page);
                    i++;
                    continue;
                }

                long runHostBaseLong = page.HostPage.ToInt64();
                uint runFlags = ToKvmMapFlags(page.Permissions);
                ulong runSize = KvmConstants.PageSize;

                int j = i + 1;
                while (j < keyCount)
                {
                    if (sortedKeys[j] != runAddress + runSize) break;
                    if (!_mappedPages.TryGetValue(sortedKeys[j], out MappedPage next) || next == null) break;
                    if (next.Permissions != page.Permissions) break;
                    if (anyTrapped && _trappedPages.ContainsKey(sortedKeys[j])) break;
                    if (next.HostPage.ToInt64() != runHostBaseLong + (long)runSize) break;
                    runSize += KvmConstants.PageSize;
                    j++;
                }

                _desiredSlots[runAddress] = new InstalledSlot
                {
                    Size = runSize,
                    Host = new IntPtr(runHostBaseLong),
                    Flags = runFlags,
                };
                i = j;
            }

            _staleSlotKeys.Clear();
            foreach (KeyValuePair<ulong, InstalledSlot> kv in _activeSlots)
            {
                if (!_desiredSlots.TryGetValue(kv.Key, out InstalledSlot want)
                    || want.Size != kv.Value.Size
                    || want.Host != kv.Value.Host
                    || want.Flags != kv.Value.Flags)
                {
                    DeleteMemslot(kv.Value.Id);
                    _staleSlotKeys.Add(kv.Key);
                }
                else
                {
                    _desiredSlots.Remove(kv.Key);
                }
            }
            for (int i = 0; i < _staleSlotKeys.Count; i++)
                _activeSlots.Remove(_staleSlotKeys[i]);

            foreach (KeyValuePair<ulong, InstalledSlot> kv in _desiredSlots)
                _activeSlots[kv.Key] = InstallSlot(kv.Key, kv.Value);

            _activeSlotStarts.Clear();
            foreach (KeyValuePair<ulong, InstalledSlot> kv in _activeSlots)
                _activeSlotStarts.Add(kv.Key);
            _activeSlotStarts.Sort();
        }

        // One page either side of the change, so a neighbouring slot can absorb it.
        private void RebuildMappingsIncremental(ulong spanStart, ulong spanEnd)
        {
            if (spanStart >= KvmConstants.PageSize) spanStart -= KvmConstants.PageSize;
            if (spanEnd <= ulong.MaxValue - KvmConstants.PageSize) spanEnd += KvmConstants.PageSize;

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
            BuildDesiredSlotsForSpan(spanStart, spanEnd);

            _staleSlotKeys.Clear();
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
                    DeleteMemslot(active.Id);
                    _staleSlotKeys.Add(start);
                }
                else
                {
                    _desiredSlots.Remove(start);
                }
            }

            for (int i = 0; i < _staleSlotKeys.Count; i++)
                RemoveActiveSlot(_staleSlotKeys[i]);

            foreach (KeyValuePair<ulong, InstalledSlot> kv in _desiredSlots)
                AddActiveSlot(kv.Key, InstallSlot(kv.Key, kv.Value));
        }

        private void BuildDesiredSlotsForSpan(ulong spanStart, ulong spanEnd)
        {
            bool anyTrapped = _trappedPages.Count != 0;

            for (ulong address = spanStart; address < spanEnd;)
            {
                if (!_mappedPages.TryGetValue(address, out MappedPage page)
                    || page == null
                    || page.HostPage == IntPtr.Zero
                    || page.Permissions == KvmMemoryPermission.None)
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
                uint runFlags = ToKvmMapFlags(page.Permissions);
                ulong runSize = KvmConstants.PageSize;

                while (address + runSize < spanEnd)
                {
                    if (!_mappedPages.TryGetValue(address + runSize, out MappedPage next) || next == null) break;
                    if (next.Permissions != page.Permissions) break;
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

        private static InstalledSlot MakeWriteWatchSlot(MappedPage page) => new InstalledSlot
        {
            Size = KvmConstants.PageSize,
            Host = page.HostPage,
            Flags = KvmConstants.MemSlotReadOnly,
        };

        private InstalledSlot InstallSlot(ulong guestAddress, InstalledSlot want)
        {
            int slot = AllocateSlotId();
            SetMemslot(slot, guestAddress, want.Size, want.Host, want.Flags);
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

        private void DeleteMemslot(int slot)
        {
            LinuxKvmUserspaceMemoryRegion region = new LinuxKvmUserspaceMemoryRegion
            {
                Slot = (uint)slot,
                MemorySize = 0,
            };
            KvmNative.ioctl(_partitionFd, KvmConstants.KvmIoSetUserMemoryRegion, ref region);
            _freeSlotIds.Add(slot);
        }

        private void RefreshMmioBackedRegions()
        {
            if (_mmioRegions.Count == 0) return;

            long now = Stopwatch.GetTimestamp();
            if (now - _lastMmioRefreshTimestamp < MmioRefreshIntervalTicks) return;
            _lastMmioRefreshTimestamp = now;

            for (int i = 0; i < _mmioRegions.Count; i++)
                RefreshMmioRegion(_mmioRegions[i]);
        }

        private unsafe void RefreshMmioRegion(MmioRegion region)
        {
            for (ulong offset = 0; offset < region.Size; offset += KvmConstants.PageSize)
            {
                if (!_mappedPages.TryGetValue(region.Address + offset, out MappedPage page)
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
            if (!TryReadMemoryInternal(rip, opcode)) return false;

            if (opcode[0] != 0x0F) return false;

            if (_hasCpuIdHook && opcode[1] == 0xA2)
                return HandleInstructionHook(BackendInstructionHook.CpuId, 2);
            if (_hasRdtscHook && opcode[1] == 0x31)
                return HandleInstructionHook(BackendInstructionHook.Rdtsc, 2);
            if (_hasRdtscpHook && opcode[1] == 0x01 && opcode[2] == 0xF9)
                return HandleInstructionHook(BackendInstructionHook.Rdtscp, 3);
            if (_hasInvalidHook && opcode[1] == 0x0B)
                return HandleInvalidInstructionHook();
            return false;
        }

        private void RefreshInstructionHookFlags()
        {
            _hasCpuIdHook = false;
            _hasRdtscHook = false;
            _hasRdtscpHook = false;
            _hasInvalidHook = false;

            for (int i = 0; i < _instructionHooks.Count; i++)
            {
                switch (_instructionHooks[i].Type)
                {
                    case BackendInstructionHook.CpuId: _hasCpuIdHook = true; break;
                    case BackendInstructionHook.Rdtsc: _hasRdtscHook = true; break;
                    case BackendInstructionHook.Rdtscp: _hasRdtscpHook = true; break;
                    case BackendInstructionHook.Invalid: _hasInvalidHook = true; break;
                }
            }

            _scanPreRunInstructions = _hasCpuIdHook || _hasRdtscHook || _hasRdtscpHook || _hasInvalidHook;
        }

        private unsafe bool TryReadMemoryInternal(ulong address, Span<byte> buffer)
        {
            ulong current = address;
            int offset = 0;
            int remaining = buffer.Length;

            while (remaining > 0)
            {
                ulong pageBase = current & ~KvmConstants.PageMask;
                if (!TryLookupPage(pageBase, out MappedPage page))
                    return false;

                ulong pageOffset = current - pageBase;
                int chunk = (int)Math.Min((ulong)remaining, KvmConstants.PageSize - pageOffset);
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
                ulong pageBase = current & ~KvmConstants.PageMask;
                if (!TryLookupPage(pageBase, out MappedPage page))
                    return false;

                ulong pageOffset = current - pageBase;
                int chunk = (int)Math.Min((ulong)remaining, KvmConstants.PageSize - pageOffset);
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

        private bool HandleHltExit()
        {
            ulong rip = ReadRegister(Registers.UC_X86_REG_RIP);

            if (_syscallHook != null && rip == (_syscallTrapPageGpa + 1))
            {
                if (HandleSyscallTrap()) return true;
                _error = KvmErrors.Ok;
                return false;
            }

            ulong stubEnd = _exceptionStubPageGpa +
                KvmConstants.ExceptionVectorCount * KvmConstants.ExceptionStubStride;
            if (rip > _exceptionStubPageGpa && rip <= stubEnd)
            {
                if (_singleStepRequested &&
                    (uint)((rip - 1 - _exceptionStubPageGpa) / KvmConstants.ExceptionStubStride) == 1)
                {
                    _singleStepRequested = false;
                    RestoreExceptionFrame(rip);
                    ClearTrapFlag();
                    _error = KvmErrors.Ok;
                    return false;
                }

                bool handled = HandleExceptionTrap(rip);
                ClearPendingExceptionState();
                if (handled) return true;
                _error = KvmErrors.Exception;
                return false;
            }

            _error = KvmErrors.Ok;
            return false;
        }

        private unsafe bool HandleMmioExit(ref LinuxKvmRun run)
        {
            ref LinuxKvmMmioExit mmio = ref run.Exit.Mmio;
            ulong physAddr = mmio.PhysAddr;
            uint len = mmio.Len;
            byte isWrite = mmio.IsWrite;

            // A later fragment of the faulted instruction.
            if (_faultRegistersSaved)
            {
                _mmioCompletionPending = true;
                return true;
            }

            foreach (MmioRegion region in _mmioRegions)
            {
                if (physAddr < region.Address || physAddr >= region.Address + region.Size) continue;
                if (isWrite == 0) break;

                ulong data = mmio.Data;
                region.WriteCallback(physAddr - region.Address,
                    new ReadOnlySpan<byte>(&data, (int)Math.Min(len, sizeof(ulong))));
                return true;
            }

            ulong faultPage = physAddr & ~KvmConstants.PageMask;
            bool mapped = _mappedPages.TryGetValue(faultPage, out MappedPage faulted)
                          && faulted != null
                          && faulted.HostPage != IntPtr.Zero;

            if (mapped && _trappedPages.ContainsKey(faultPage))
                return HandleTrappedAccess(ref mmio, physAddr, len, isWrite != 0);

            // KVM reports a wide access one fragment at a time. A fragment on a page that is accessible now
            // is not a new fault.
            if (mapped && IsPageAccessible(faultPage, isWrite != 0))
            {
                if (_mappingsDirty) RebuildMappings();
                CompleteMmioAccess(ref mmio);
                return true;
            }

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
                // after it.
                _faultRegisters = GetRegisters();
                _faultRegistersSaved = true;
                _mmioCompletionPending = true;
                return false;
            }

            CompleteMmioAccess(ref mmio);
            return true;
        }

        private bool IsPageAccessible(ulong pageAddress, bool write)
        {
            if (_trappedPages.ContainsKey(pageAddress)) return false;
            if (!_mappedPages.TryGetValue(pageAddress, out MappedPage page) || page == null || page.HostPage == IntPtr.Zero)
                return false;

            KvmMemoryPermission needed = write ? KvmMemoryPermission.Write : KvmMemoryPermission.Read;
            return (page.Permissions & needed) != 0;
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
            _mmioCompletionPending = true;

            uint len = mmio.Len;
            if (len == 0 || len > sizeof(ulong)) return;

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

            return false;
        }

        private void RestoreExceptionFrame(ulong stubRip)
            => ReadExceptionFrame(stubRip, restoreSregs: true, out _, out _);

        private bool HandleExceptionTrap(ulong stubRip)
        {
            ReadExceptionFrame(stubRip, restoreSregs: true, out uint vector, out ulong errorCode);
            return HandleException(vector, (uint)errorCode);
        }

        private void ReadExceptionFrame(ulong stubRip, bool restoreSregs, out uint vector, out ulong errorCode)
        {
            vector = (uint)((stubRip - 1 - _exceptionStubPageGpa) / KvmConstants.ExceptionStubStride);
            errorCode = 0;

            LinuxKvmRegisters regs = GetRegisters();
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

            // A fault on the trap page's sysretq belongs to the user address it was returning to.
            if (frameRip == _syscallTrapPageGpa + SyscallReturnOffset)
            {
                frameRip = regs.Rcx;
                frameRflags = regs.R11;
                frameCs = KvmConstants.UserCodeSelector;
                frameSs = KvmConstants.UserDataSelector;
            }

            regs.Rip = frameRip;
            if (vector == 3) regs.Rip -= 1;
            regs.Rsp = frameRsp;
            regs.Rflags = frameRflags;
            SetRegisters(regs);

            if (restoreSregs)
            {
                LinuxKvmSpecialRegisters sregs = GetSpecialRegisters();
                sregs.Cs = MakeSegment((ushort)frameCs, true, (frameCs & 3) == 3);
                sregs.Ss = MakeSegment((ushort)frameSs, false, (frameSs & 3) == 3);
                SetSpecialRegisters(sregs);
            }
        }

        private void ClearPendingExceptionState()
        {
            lock (_vcpuLock)
            {
                LinuxKvmVcpuEvents events = new LinuxKvmVcpuEvents();
                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoGetVcpuEvents, ref events) < 0)
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

                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoSetVcpuEvents, ref events) < 0)
                    return;
            }
        }

        private bool HandleDebugExit(ref LinuxKvmRun run)
        {
            for (int i = 0; i < _interruptHooks.Count; i++)
            {
                _interruptHooks[i].Callback(1);
                return true;
            }
            return false;
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
            ShowUserCodeAndStackSegments();
            _vp.InSyscallStub = true;

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

        // sysretq loads the user segments, so the register page write is not marked dirty.
        private void ShowUserCodeAndStackSegments()
        {
            ref LinuxKvmSpecialRegisters sregs = ref GetSpecialRegistersRef();
            sregs.Cs = MakeSegment(KvmConstants.UserCodeSelector, true, true);
            sregs.Ss = MakeSegment(KvmConstants.UserDataSelector, false, true);
        }

        // Only valid while RCX and R11 hold what the syscall left.
        private void NoteSyscallScratchWrite(GpRegisterName name, ulong before, ulong after)
        {
            if (before != after && (name == GpRegisterName.Rcx || name == GpRegisterName.R11))
                LeaveSyscallStub(_vp);
        }

        private static void LeaveSyscallStub(VirtualProcessor vp)
        {
            if (!vp.InSyscallStub) return;
            vp.InSyscallStub = false;
            GetRunRef(vp).DirtyRegs |= KvmConstants.SyncSpecialRegisters;
        }

        // sysretq takes RIP from RCX and RFLAGS from R11, which is what NT leaves in them.
        private void PrepareSyscallReturn(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            if (_singleStepRequested)
                run.DirtyRegs |= KvmConstants.SyncSpecialRegisters;

            if ((run.DirtyRegs & KvmConstants.SyncSpecialRegisters) != 0)
            {
                vp.InSyscallStub = false;
                return;
            }

            ref LinuxKvmRegisters regs = ref run.Regs;
            regs.Rcx = regs.Rip;
            regs.R11 = regs.Rflags;
            regs.Rip = _syscallTrapPageGpa + SyscallReturnOffset;
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters;
        }

        // A run that ended before guest entry leaves RIP on the sysretq.
        private void CompleteSyscallReturn(VirtualProcessor vp, ref LinuxKvmRun run)
        {
            ref LinuxKvmRegisters regs = ref run.Regs;
            if (regs.Rip != _syscallTrapPageGpa + SyscallReturnOffset)
            {
                vp.InSyscallStub = false;
                return;
            }

            regs.Rip = regs.Rcx;
            regs.Rflags = regs.R11;
            run.DirtyRegs |= KvmConstants.SyncGeneralRegisters;
            ShowUserCodeAndStackSegments();
        }

        private void AdvanceRip(ulong amount)
        {
            GetRegistersRef().Rip += amount;
            MarkRegistersDirty();
        }

        private ulong GetMsr(VirtualProcessor vp, uint msr)
        {
            lock (_vcpuLock)
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
            lock (_vcpuLock)
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
                LeaveSyscallStub(_vp);
            current = regs;
            MarkRegistersDirty();
        }

        private void MarkRegistersDirty() => GetRunRef().DirtyRegs |= KvmConstants.SyncGeneralRegisters;

        private ref LinuxKvmSpecialRegisters GetSpecialRegistersRef() => ref GetRunRef().Sregs;

        private LinuxKvmSpecialRegisters GetSpecialRegisters() => GetSpecialRegistersRef();

        private void SetSpecialRegisters(in LinuxKvmSpecialRegisters sregs)
        {
            GetSpecialRegistersRef() = sregs;
            MarkSpecialRegistersDirty();
        }

        private void MarkSpecialRegistersDirty() => GetRunRef().DirtyRegs |= KvmConstants.SyncSpecialRegisters;

        internal const int XmmRegisterCount = 16;

        /// <summary>
        /// Transfers XMM0-15 as 32 qwords, low half of each register first.
        /// </summary>
        public unsafe bool TransferXmmRegisters(ulong[] Values, bool Write)
        {
            if (Values == null || Values.Length < XmmRegisterCount * 2)
                return false;

            LinuxKvmFpu Fpu = default;

            lock (_vcpuLock)
            {
                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoGetFpu, (IntPtr)(&Fpu)) < 0)
                    return false;

                if (Write)
                {
                    for (int i = 0; i < XmmRegisterCount * 2; i++)
                        ((ulong*)Fpu.Xmm)[i] = Values[i];

                    if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoSetFpu, (IntPtr)(&Fpu)) < 0)
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
            lock (_vcpuLock)
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
            lock (_vcpuLock)
            {
                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoSetVcpuEvents, ref events) < 0)
                    throw new KvmException("KVM_SET_VCPU_EVENTS failed", Marshal.GetLastWin32Error());
            }
        }

        private LinuxKvmDebugRegisters GetDebugRegisters()
        {
            lock (_vcpuLock)
            {
                LinuxKvmDebugRegisters dr = new LinuxKvmDebugRegisters();
                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoGetDebugRegisters, ref dr) < 0)
                    throw new KvmException("KVM_GET_DEBUGREGS failed", Marshal.GetLastWin32Error());
                return dr;
            }
        }

        private void SetDebugRegisters(LinuxKvmDebugRegisters dr)
        {
            lock (_vcpuLock)
            {
                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoSetDebugRegisters, ref dr) < 0)
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
            if (IsDebugRegister(register))
            {
                WriteDebugRegister(register, value);
                return true;
            }

            if (register == Registers.UC_X86_REG_FPCW || register == Registers.UC_X86_REG_MXCSR)
                return TransferFpControl(register, ref value, true);

            if (!IsSregRegister(register)) return false;

            // The page holds the current value, so an unchanged write needs no entry-time update.
            ref LinuxKvmSpecialRegisters sregs = ref GetSpecialRegistersRef();
            if (TryApplySregRead(ref sregs, register, out ulong current) && current == value) return true;

            if (!TryApplySregWrite(ref sregs, register, value)) return false;
            MarkSpecialRegistersDirty();
            return true;
        }

        private bool TryReadSpecialRegister(Registers register, out ulong value)
        {
            if (IsDebugRegister(register))
            {
                value = ReadDebugRegister(register);
                return true;
            }

            value = 0;

            if (register == Registers.UC_X86_REG_FPCW || register == Registers.UC_X86_REG_MXCSR)
                return TransferFpControl(register, ref value, false);

            if (!IsSregRegister(register))
                return false;

            return TryApplySregRead(ref GetSpecialRegistersRef(), register, out value);
        }

        private unsafe bool TransferFpControl(Registers register, ref ulong value, bool Write)
        {
            LinuxKvmFpu Fpu = default;

            lock (_vcpuLock)
            {
                if (KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoGetFpu, (IntPtr)(&Fpu)) < 0)
                    return false;

                if (!Write)
                {
                    value = register == Registers.UC_X86_REG_FPCW ? Fpu.Fcw : Fpu.Mxcsr;
                    return true;
                }

                if (register == Registers.UC_X86_REG_FPCW)
                    Fpu.Fcw = (ushort)value;
                else
                    Fpu.Mxcsr = (uint)value;

                return KvmNative.ioctl(_vp.Fd, KvmConstants.KvmIoSetFpu, (IntPtr)(&Fpu)) >= 0;
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

        private unsafe void WriteDebugRegister(Registers register, ulong value)
        {
            LinuxKvmDebugRegisters dr = GetDebugRegisters();
            switch (register)
            {
                case Registers.UC_X86_REG_DR0: dr.Db[0] = value; break;
                case Registers.UC_X86_REG_DR1: dr.Db[1] = value; break;
                case Registers.UC_X86_REG_DR2: dr.Db[2] = value; break;
                case Registers.UC_X86_REG_DR3: dr.Db[3] = value; break;
                case Registers.UC_X86_REG_DR6: dr.Dr6 = value; break;
                case Registers.UC_X86_REG_DR7: dr.Dr7 = value; break;
            }
            SetDebugRegisters(dr);
        }

        private unsafe ulong ReadDebugRegister(Registers register)
        {
            LinuxKvmDebugRegisters dr = GetDebugRegisters();
            return register switch
            {
                Registers.UC_X86_REG_DR0 => dr.Db[0],
                Registers.UC_X86_REG_DR1 => dr.Db[1],
                Registers.UC_X86_REG_DR2 => dr.Db[2],
                Registers.UC_X86_REG_DR3 => dr.Db[3],
                Registers.UC_X86_REG_DR6 => dr.Dr6,
                Registers.UC_X86_REG_DR7 => dr.Dr7,
                _ => 0,
            };
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

            ulong pageBase = address & ~KvmConstants.PageMask;
            if (!TryLookupPage(pageBase, out MappedPage page))
                return false;

            ulong accessEnd = address + (ulong)accessSize;
            ulong firstPageEnd = pageBase + KvmConstants.PageSize;
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

            ulong cursor = pageBase + KvmConstants.PageSize;
            while (cursor < accessEnd)
            {
                if (!_mappedPages.TryGetValue(cursor, out MappedPage next) || next == null || next.HostPage == IntPtr.Zero)
                    return false;
                long expectedHost = page.HostPage.ToInt64() + (long)(cursor - pageBase);
                long actualHost = next.HostPage.ToInt64();
                if (expectedHost != actualHost) return false;
                cursor += KvmConstants.PageSize;
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
            if (allocation.LivePages != (int)(allocation.Size / KvmConstants.PageSize)) return false;

            ulong hostOffset = (ulong)(page.HostPage.ToInt64() - page.OwnedBacking.ToInt64());
            if (hostOffset > pageBase || hostOffset >= allocation.Size) return false;

            backingEnd = pageBase - hostOffset + allocation.Size;
            return true;
        }

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
