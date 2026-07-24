using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Buffers;

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
        private const uint VpIndex = 0;
        private IntPtr _exitContextPtr = IntPtr.Zero;

        private readonly Dictionary<ulong, MappedPage> _mappedPages = new();
        private readonly Dictionary<IntPtr, BackingAllocation> _backingAllocations = new();
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
        private ulong _exceptionTssPageGpa;
        private ulong _exceptionStackPageGpa;
        private ulong _gdtPageGpa;

        private readonly object _vcpuLock = new();

        private WhpRegisters _regsCache;
        private bool _regsValid;
        private bool _regsDirty;
        private WhvRegisterValue _pendingCs;
        private WhvRegisterValue _pendingSs;
        private bool _segmentsDirty;

        private readonly WhvRegisterValue _userCodeSegment;
        private readonly WhvRegisterValue _userDataSegment;

        private readonly List<MemoryHookEntry> _memoryHooks = new();
        private readonly List<MmioRegion> _mmioRegions = new();
        private InstructionHookEntry _syscallHook;
        private readonly List<InstructionHookEntry> _instructionHooks = new();
        private readonly List<InterruptHookEntry> _interruptHooks = new();
        private readonly List<IntPtr> _liveHookHandles = new();

        private readonly object _mmioLock = new();
        private Thread _mmioRefreshThread;

        private bool _completionActive;
        private ulong _completionPageGpa;
        private ulong _completionAccessGpa;
        private uint _completionLen;
        private bool _completionIsWrite;

        private int _disposed;
        private int _disposing;
        private volatile bool _stopRequested;
        private bool _singleStepRequested;

        public bool NoHooks;
        public static bool ThrowDisposed = true;
        public bool Disposed => Volatile.Read(ref _disposed) == 1;
        private bool Disposing => Volatile.Read(ref _disposing) == 1;

        private WhpErrors _error;

        private sealed class MappedPage
        {
            public IntPtr HostPage;
            public IntPtr OwnedBacking;
            public WhpMemoryPermission Permissions;
        }

        private sealed class BackingAllocation
        {
            public ulong Size;
            public int LivePages;
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
            ConfigurePartition();
            AllocateInternalPool();
            InitializeLongModePageTables();
            InitializeGdt();
            InitializeSyscallTrapPage();
            InitializeExceptionHandling();
            RebuildMappings();
            InitializeVirtualProcessorState();
        }

        public WhpErrors GetLastError() => _error;

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
                IntPtr backing = AllocateBackingMemory(size);
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

                RebuildMappings();
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
                    IntPtr backing = AllocateBackingMemory(WhpConstants.PageSize);
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

            RebuildMappings();
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
            EnsureMmioRefreshThread();
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

        private void EnsureMmioRefreshThread()
        {
            if (_mmioRefreshThread != null)
                return;

            _mmioRefreshThread = new Thread(MmioRefreshLoop)
            {
                IsBackground = true,
                Name = "WhpMmioRefresh"
            };
            _mmioRefreshThread.Start();
        }

        private void MmioRefreshLoop()
        {
            while (!Disposed && !Disposing)
            {
                lock (_mmioLock)
                {
                    for (int i = 0; i < _mmioRegions.Count; i++)
                        RefreshMmioRegion(_mmioRegions[i]);
                }

                Thread.Sleep(1);
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
            _regsDirty = true;
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
            _regsDirty = true;
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
            _regsDirty = true;
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

            ClearTrapFlag();

            GetRegistersRef().Rip = start;
            _regsDirty = true;

            FlushRegisterCache();
            _stopRequested = false;
            _singleStepRequested = count == 1;

            if (_singleStepRequested)
            {
                GetRegistersRef().Rflags |= 0x100UL;
                _regsDirty = true;
                FlushRegisterCache();
            }

            try
            {
                while (!_stopRequested)
                {
                    RefreshMmioBackedRegions();

                    FlushRegisterCache();

                    ref WhvRunVpExitContext exit = ref RunVirtualProcessor();
                    InvalidateRegisterCache();

                    switch (exit.ExitReason)
                    {
                        case WhvRunVpExitReason.X64Halt:
                            if (HandleHltExit()) continue;
                            return _error == WhpErrors.Ok;
                        case WhvRunVpExitReason.MemoryAccess:
                            if (HandleMemoryAccess(ref exit)) continue;
                            _error = WhpErrors.Ok;
                            return true;
                        case WhvRunVpExitReason.Canceled:
                            if (_stopRequested) { _error = WhpErrors.Ok; return true; }
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
                if (_singleStepRequested)
                {
                    _singleStepRequested = false;
                    ClearTrapFlag();
                }
                FlushRegisterCache();
            }
        }

        public bool StopEmulation()
        {
            if (DisposedCheck()) return false;

            _stopRequested = true;
            if (_partition != IntPtr.Zero)
                WhpNative.WHvCancelRunVirtualProcessor(_partition, VpIndex, 0);

            _error = WhpErrors.Ok;
            return true;
        }

        private unsafe ref WhvRunVpExitContext RunVirtualProcessor()
        {
            int hr = WhpNative.WHvRunVirtualProcessor(_partition, VpIndex, (void*)_exitContextPtr,
                (uint)sizeof(WhvRunVpExitContext));
            if (WhpNative.Failed(hr))
            {
                _error = WhpErrors.InternalError;
                throw new WhpException("WHvRunVirtualProcessor failed", hr);
            }
            return ref Unsafe.AsRef<WhvRunVpExitContext>((void*)_exitContextPtr);
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
                if (!TryLookupPage(pageBase, out _))
                    return false;
                ulong pageEnd = pageBase + WhpConstants.PageSize;
                ulong chunk = pageEnd - current;
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

                if (_partition != IntPtr.Zero)
                {
                    WhpNative.WHvDeleteVirtualProcessor(_partition, VpIndex);
                    WhpNative.WHvDeletePartition(_partition);
                    _partition = IntPtr.Zero;
                }

                if (_exitContextPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_exitContextPtr);
                    _exitContextPtr = IntPtr.Zero;
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

        private void QueueCsSs(WhvRegisterValue cs, WhvRegisterValue ss)
        {
            _pendingCs = cs;
            _pendingSs = ss;
            _segmentsDirty = true;
        }

        private void ClearTrapFlag()
        {
            ref WhpRegisters regs = ref GetRegistersRef();
            if ((regs.Rflags & 0x100UL) == 0) return;
            regs.Rflags &= ~0x100UL;
            _regsDirty = true;
            FlushRegisterCache();
        }

        private IntPtr AllocateBackingMemory(ulong size)
        {
            IntPtr ptr = WhpNative.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WhpNative.MEM_COMMIT | WhpNative.MEM_RESERVE, WhpNative.PAGE_READWRITE);
            if (ptr == IntPtr.Zero)
                throw new WhpException("VirtualAlloc failed", Marshal.GetLastWin32Error());
            return ptr;
        }

        private static void FreeBackingMemory(IntPtr ptr, ulong size)
            => WhpNative.VirtualFree(ptr, UIntPtr.Zero, WhpNative.MEM_RELEASE);

        private void ReleaseBacking(MappedPage page)
        {
            if (page.OwnedBacking == IntPtr.Zero) return;
            if (!_backingAllocations.TryGetValue(page.OwnedBacking, out BackingAllocation allocation)) return;

            if (--allocation.LivePages > 0) return;

            FreeBackingMemory(page.OwnedBacking, allocation.Size);
            _backingAllocations.Remove(page.OwnedBacking);
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

            uint processorCount = 1;
            hr = WhpNative.WHvSetPartitionProperty(_partition, WhvPartitionPropertyCode.ProcessorCount,
                &processorCount, sizeof(uint));
            if (WhpNative.Failed(hr))
                throw new WhpException("WHvSetPartitionProperty(ProcessorCount) failed", hr);

            hr = WhpNative.WHvSetupPartition(_partition);
            if (WhpNative.Failed(hr))
                throw new WhpException("WHvSetupPartition failed", hr);

            hr = WhpNative.WHvCreateVirtualProcessor(_partition, VpIndex, 0);
            if (WhpNative.Failed(hr))
                throw new WhpException("WHvCreateVirtualProcessor failed", hr);

            _exitContextPtr = Marshal.AllocHGlobal(sizeof(WhvRunVpExitContext));
        }

        private unsafe void InitializeVirtualProcessorState()
        {
            const int maxCount = 16;
            Span<uint> names = stackalloc uint[maxCount];
            Span<WhvRegisterValue> values = stackalloc WhvRegisterValue[maxCount];

            names[0] = (uint)WhvRegisterName.Cs; values[0] = _userCodeSegment;
            names[1] = (uint)WhvRegisterName.Ss; values[1] = _userDataSegment;
            names[2] = (uint)WhvRegisterName.Ds; values[2] = _userDataSegment;
            names[3] = (uint)WhvRegisterName.Es; values[3] = _userDataSegment;
            names[4] = (uint)WhvRegisterName.Fs;
            values[4] = _guest64 ? MakeSegment(0x53, false, true) : MakeSegment(WhpConstants.UserFsSelector32, false, true);
            names[5] = (uint)WhvRegisterName.Gs;
            values[5] = _guest64 ? _userDataSegment : MakeSegment(WhpConstants.UserGsSelector32, false, true);
            names[6] = (uint)WhvRegisterName.Tr;
            values[6] = WhvRegisterValue.FromSegment(_exceptionTssPageGpa, 0x67, WhpConstants.TssSelector, 0x8B);
            names[7] = (uint)WhvRegisterName.Gdtr;
            values[7] = WhvRegisterValue.FromTable(_gdtPageGpa, WhpConstants.GdtLimit);
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
                    int hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, VpIndex, n, (uint)count, v);
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
                WriteDescriptor(gdt, WhpConstants.UserDataSelector32 >> 3, 0, 0xFFFFF, 0xF3, 0xC);
                WriteDescriptor(gdt, WhpConstants.UserDataSelector >> 3, 0, 0xFFFFF, 0xF3, 0xC);
                WriteDescriptor(gdt, WhpConstants.UserCodeSelector >> 3, 0, 0xFFFFF, 0xFB, 0xA);
                WriteDescriptor(gdt, WhpConstants.UserFsSelector32 >> 3, 0, 0xFFFFF, 0xF3, 0xC);
                WriteDescriptor(gdt, WhpConstants.UserGsSelector32 >> 3, 0, 0xFFFFF, 0xF3, 0xC);
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
            _exceptionTssPageGpa = AllocateInternalPage(false);

            ulong exceptionStackSize = 16 * WhpConstants.PageSize;
            _exceptionStackPageGpa = AllocateInternalRange(exceptionStackSize, WhpMemoryPermission.ReadWrite);

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
                    ulong tssBase = _exceptionTssPageGpa;
                    int tssIndex = WhpConstants.TssSelector >> 3;
                    WriteDescriptor(gdt, tssIndex, tssBase & 0xFFFFFFFF, 0x67, 0x89, 0x0);
                    Unsafe.WriteUnaligned(gdt + (tssIndex + 1) * 8, tssBase >> 32);
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

            for (int i = 0; i < keyCount;)
            {
                ulong runAddress = sortedKeys[i];
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

            for (ulong address = spanStart; address < spanEnd;)
            {
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

        private bool HandleHltExit()
        {
            ulong rip = ReadRegister(Registers.UC_X86_REG_RIP);

            if (_guest64 && _syscallHook != null && rip == (_syscallTrapPageGpa + 1))
            {
                if (HandleSyscallTrap()) return true;
                _error = WhpErrors.Ok;
                return false;
            }

            ulong stubEnd = _exceptionStubPageGpa +
                WhpConstants.ExceptionVectorCount * WhpConstants.ExceptionStubStride;
            if (rip > _exceptionStubPageGpa && rip <= stubEnd)
            {
                uint vector = (uint)((rip - 1 - _exceptionStubPageGpa) / WhpConstants.ExceptionStubStride);

                if (_completionActive && vector == 1)
                {
                    CompleteSteppedAccess(rip);
                    return true;
                }

                if (_singleStepRequested && vector == 1)
                {
                    _singleStepRequested = false;
                    RestoreExceptionFrame(rip);
                    ClearTrapFlag();
                    _error = WhpErrors.Ok;
                    return false;
                }

                if (HandleExceptionTrap(rip))
                    return true;
                _error = WhpErrors.Exception;
                return false;
            }

            _error = WhpErrors.Ok;
            return false;
        }

        private bool HandleMemoryAccess(ref WhvRunVpExitContext exit)
        {
            if (_completionActive) return false;

            ulong gpa = exit.MemGpa;
            uint info = exit.MemAccessInfo;
            WhvMemoryAccessType accessType = (WhvMemoryAccessType)(info & 0x3);
            bool isWrite = accessType == WhvMemoryAccessType.Write;
            bool isFetch = accessType == WhvMemoryAccessType.Execute;
            const uint len = 1;

            ulong faultPage = gpa & ~WhpConstants.PageMask;
            bool mapped = TryLookupPage(faultPage, out _);

            if (mapped && _trappedPages.ContainsKey(faultPage))
            {
                BeginSteppedCompletion(faultPage, gpa, len, isWrite);
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

        private unsafe void BeginSteppedCompletion(ulong pageGpa, ulong gpa, uint len, bool isWrite)
        {
            if (!_mappedPages.TryGetValue(pageGpa, out MappedPage page) || page.HostPage == IntPtr.Zero)
                return;

            UnmapGpaRange(pageGpa, WhpConstants.PageSize);
            MapGpaRange(pageGpa, WhpConstants.PageSize, page.HostPage,
                WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Write | WhvMapGpaRangeFlags.Execute);

            _completionActive = true;
            _completionPageGpa = pageGpa;
            _completionAccessGpa = gpa;
            _completionLen = len;
            _completionIsWrite = isWrite;

            ref WhpRegisters regs = ref GetRegistersRef();
            regs.Rflags |= 0x100UL;
            _regsDirty = true;
            FlushRegisterCache();
        }

        private void CompleteSteppedAccess(ulong stubRip)
        {
            RestoreExceptionFrame(stubRip);

            ulong pageGpa = _completionPageGpa;
            ulong gpa = _completionAccessGpa;
            uint len = _completionLen;
            bool isWrite = _completionIsWrite;
            _completionActive = false;

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

            if (!_singleStepRequested)
                ClearTrapFlag();
            FlushRegisterCache();
        }

        private void ReTrapPage(ulong pageGpa)
        {
            UnmapGpaRange(pageGpa, WhpConstants.PageSize);
            if (_trappedPages.TryGetValue(pageGpa, out bool writeOnly) && writeOnly
                && _mappedPages.TryGetValue(pageGpa, out MappedPage page) && page.HostPage != IntPtr.Zero)
            {
                MapGpaRange(pageGpa, WhpConstants.PageSize, page.HostPage,
                    WhvMapGpaRangeFlags.Read | WhvMapGpaRangeFlags.Execute);
            }
        }

        private void RestoreExceptionFrame(ulong stubRip)
            => ReadExceptionFrame(stubRip, out _, out _);

        private bool HandleExceptionTrap(ulong stubRip)
        {
            ReadExceptionFrame(stubRip, out uint vector, out ulong errorCode);
            return HandleException(vector, (uint)errorCode);
        }

        private void ReadExceptionFrame(ulong stubRip, out uint vector, out ulong errorCode)
        {
            vector = (uint)((stubRip - 1 - _exceptionStubPageGpa) / WhpConstants.ExceptionStubStride);
            errorCode = 0;

            ref WhpRegisters regs = ref GetRegistersRef();
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
            _regsDirty = true;

            QueueCsSs(MakeSegment((ushort)frameCs, true, (frameCs & 3) == 3),
                MakeSegment((ushort)frameSs, false, (frameSs & 3) == 3));
        }

        private bool HandleSyscallTrap()
        {
            if (_syscallHook == null) return false;

            ref WhpRegisters regs = ref GetRegistersRef();

            ulong postSyscallRcx = regs.Rcx;
            ulong postSyscallR10 = regs.R10;
            ulong savedRflags = regs.R11;
            ulong preSyscallRip = postSyscallRcx - 2;

            regs.Rip = preSyscallRip;
            regs.Rcx = postSyscallR10;
            regs.Rflags = savedRflags;
            _regsDirty = true;

            if (_syscallHook.Callback != null) _syscallHook.Callback();
            else if (_syscallHook.BoolCallback != null) _syscallHook.BoolCallback();

            ref WhpRegisters after = ref GetRegistersRef();
            if (after.Rip == preSyscallRip)
                after.Rip = postSyscallRcx;
            else
                after.Rip += 2;
            _regsDirty = true;

            QueueCsSs(_userCodeSegment, _userDataSegment);
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
            GetRegistersRef().Rip += amount;
            _regsDirty = true;
        }

        private unsafe ref WhpRegisters GetRegistersRef()
        {
            if (!_regsValid)
            {
                LoadRegisters();
                _regsValid = true;
            }
            return ref _regsCache;
        }

        private unsafe void LoadRegisters()
        {
            Span<WhvRegisterValue> values = stackalloc WhvRegisterValue[GpRegNames.Length];
            lock (_vcpuLock)
            {
                fixed (uint* names = GpRegNames)
                fixed (WhvRegisterValue* vals = values)
                {
                    int hr = WhpNative.WHvGetVirtualProcessorRegisters(_partition, VpIndex, names,
                        (uint)GpRegNames.Length, vals);
                    if (WhpNative.Failed(hr))
                        throw new WhpException("WHvGetVirtualProcessorRegisters(GP) failed", hr);
                }
            }

            _regsCache.Rax = values[0].Low;
            _regsCache.Rbx = values[1].Low;
            _regsCache.Rcx = values[2].Low;
            _regsCache.Rdx = values[3].Low;
            _regsCache.Rsi = values[4].Low;
            _regsCache.Rdi = values[5].Low;
            _regsCache.Rsp = values[6].Low;
            _regsCache.Rbp = values[7].Low;
            _regsCache.R8 = values[8].Low;
            _regsCache.R9 = values[9].Low;
            _regsCache.R10 = values[10].Low;
            _regsCache.R11 = values[11].Low;
            _regsCache.R12 = values[12].Low;
            _regsCache.R13 = values[13].Low;
            _regsCache.R14 = values[14].Low;
            _regsCache.R15 = values[15].Low;
            _regsCache.Rip = values[16].Low;
            _regsCache.Rflags = values[17].Low;
        }

        private unsafe void StoreRegisters()
        {
            bool withSegments = _segmentsDirty;
            uint[] names = withSegments ? GpRegNamesWithSegments : GpRegNames;
            Span<WhvRegisterValue> values = stackalloc WhvRegisterValue[GpRegNamesWithSegments.Length];
            values[0] = WhvRegisterValue.FromReg64(_regsCache.Rax);
            values[1] = WhvRegisterValue.FromReg64(_regsCache.Rbx);
            values[2] = WhvRegisterValue.FromReg64(_regsCache.Rcx);
            values[3] = WhvRegisterValue.FromReg64(_regsCache.Rdx);
            values[4] = WhvRegisterValue.FromReg64(_regsCache.Rsi);
            values[5] = WhvRegisterValue.FromReg64(_regsCache.Rdi);
            values[6] = WhvRegisterValue.FromReg64(_regsCache.Rsp);
            values[7] = WhvRegisterValue.FromReg64(_regsCache.Rbp);
            values[8] = WhvRegisterValue.FromReg64(_regsCache.R8);
            values[9] = WhvRegisterValue.FromReg64(_regsCache.R9);
            values[10] = WhvRegisterValue.FromReg64(_regsCache.R10);
            values[11] = WhvRegisterValue.FromReg64(_regsCache.R11);
            values[12] = WhvRegisterValue.FromReg64(_regsCache.R12);
            values[13] = WhvRegisterValue.FromReg64(_regsCache.R13);
            values[14] = WhvRegisterValue.FromReg64(_regsCache.R14);
            values[15] = WhvRegisterValue.FromReg64(_regsCache.R15);
            values[16] = WhvRegisterValue.FromReg64(_regsCache.Rip);
            values[17] = WhvRegisterValue.FromReg64(_regsCache.Rflags | 0x2UL);

            if (withSegments)
            {
                values[18] = _pendingCs;
                values[19] = _pendingSs;
                _segmentsDirty = false;
            }

            lock (_vcpuLock)
            {
                fixed (uint* n = names)
                fixed (WhvRegisterValue* vals = values)
                {
                    int hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, VpIndex, n,
                        (uint)names.Length, vals);
                    if (WhpNative.Failed(hr))
                        throw new WhpException("WHvSetVirtualProcessorRegisters(GP) failed", hr);
                }
            }
        }

        private void FlushRegisterCache()
        {
            if (_regsDirty || _segmentsDirty)
            {
                _regsDirty = false;
                StoreRegisters();
            }
        }

        private void InvalidateRegisterCache() => _regsValid = false;

        private unsafe void SetSingleRegister(WhvRegisterName name, WhvRegisterValue value)
        {
            uint n = (uint)name;
            lock (_vcpuLock)
            {
                int hr = WhpNative.WHvSetVirtualProcessorRegisters(_partition, VpIndex, &n, 1, &value);
                if (WhpNative.Failed(hr))
                    throw new WhpException($"WHvSetVirtualProcessorRegisters({name}) failed", hr);
            }
        }

        private unsafe WhvRegisterValue GetSingleRegister(WhvRegisterName name)
        {
            if (_segmentsDirty && (name == WhvRegisterName.Cs || name == WhvRegisterName.Ss))
                FlushRegisterCache();

            uint n = (uint)name;
            WhvRegisterValue value;
            lock (_vcpuLock)
            {
                int hr = WhpNative.WHvGetVirtualProcessorRegisters(_partition, VpIndex, &n, 1, &value);
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
                case Registers.UC_X86_REG_FS_BASE: value = GetSingleRegister(WhvRegisterName.Fs).Low; return true;
                case Registers.UC_X86_REG_GS_BASE: value = GetSingleRegister(WhvRegisterName.Gs).Low; return true;
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
                default: value = 0; return false;
            }
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
            WhvRegisterValue v = GetSingleRegister(name);
            v.Low = baseAddress;
            SetSingleRegister(name, v);

            if (!_guest64)
                SyncGdtDescriptorBase((ushort)(v.High >> 32), baseAddress);
        }

        private unsafe void SyncGdtDescriptorBase(ushort selector, ulong segmentBase)
        {
            int index = selector >> 3;
            if (index != WhpConstants.UserFsSelector32 >> 3 && index != WhpConstants.UserGsSelector32 >> 3) return;
            if (!_mappedPages.TryGetValue(_gdtPageGpa, out MappedPage gdtPage) || gdtPage.HostPage == IntPtr.Zero) return;

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
