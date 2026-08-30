using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Emulation.Native;
using Brovan.Core.Emulation;
using Brovan.Core.Helpers;
using System.Buffers;

namespace Brovan.Core.Emulation
{
    /// <summary>
    /// Unicorn exception class.
    /// </summary>
    public class UnicornException : SystemException
    {
        public UnicornException(string message) : base(message)
        {

        }

        public UnicornException() : base("Unicorn Emulation Engine exception occured.")
        {

        }
    }

    /// <summary>
    /// Unicorn emulator class which provides a semi high-level binding to interact with the unicorn library.
    /// </summary>
    public class Unicorn : IDisposable
    {
        private IntPtr _uc;
        private Mode mode;
        private UCErrors _error;
        private readonly List<MappedRegion> _mappedRegions = new List<MappedRegion>();
        private readonly List<IntPtr> _pendingFrees = new List<IntPtr>();
        private readonly Dictionary<IntPtr, nuint> _bufferSizes = new Dictionary<IntPtr, nuint>();
        private ulong _pendingFreeBytes;
        private readonly List<MappedRegion> _unmapSurvivors = new List<MappedRegion>();
        private readonly List<IntPtr> _unmapReleasedBuffers = new List<IntPtr>();
        private List<IntPtr> HooksList = new List<IntPtr>();

        private sealed class MappedRegion
        {
            public ulong Address;
            public ulong Size;
            public IntPtr Ptr;
            public IntPtr BufferBase;
        }

        private readonly object _memoryLock = new object();
        private readonly object _registerLock = new object();
        private readonly object _hooksLock = new object();
        private readonly object _mapsLock = new object();
        private readonly ReaderWriterLockSlim _emuLock = new ReaderWriterLockSlim();
        private int _disposed;
        private int _disposing;
        private readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();
        public bool NoHooks;

        public bool Disposed => Volatile.Read(ref _disposed) == 1;
        private bool Disposing => Volatile.Read(ref _disposing) == 1;

        /// <summary>
        /// Indicates whether disposed-object access should throw instead of returning failure.
        /// </summary>
        public static bool ThrowDisposed = true;

        /// <summary>
        /// Check if Control Flow Guard is enabled in the process.
        /// </summary>
        /// <returns>True if CFG is enabled; otherwise, false.</returns>
        public static bool IsCFGEnabled()
        {
            if (!GeneralHelper.IsWindows)
                return false;

            IntPtr CurrentProcess = new IntPtr(-1);
            uint CFGFlag = 7;
            uint Flags = 0;
            UIntPtr BufferSize = new UIntPtr(sizeof(uint));
            if (NativeWinImports.GetProcessMitigationPolicy(CurrentProcess, CFGFlag, out Flags, BufferSize))
            {
                if ((Flags & 0x1) != 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Initialize the unicorn emulator.
        /// </summary>
        /// <param name="arch">Architecture to be used.</param>
        /// <param name="mode">Mode to be used.</param>
        /// <exception cref="UnicornException"></exception>
        public Unicorn(Arch arch, Mode mode)
        {
            _error = uc_open(arch, mode, out _uc);

            // some heavily  samples can generate an unusually large number of translation blocks and stress Unicorn's TCG code buffer
            // causing a crash. this is a hack to mitigate it.
            SetTcgBufferSize(uint.MaxValue);

            if (_error != UCErrors.UC_ERR_OK)
                throw new UnicornException($"Couldn't open a unicorn instance (error {_error})");

            if (IsCFGEnabled())
            {
                _error = UCErrors.UC_ERR_CFG;
                throw new UnicornException("Unicorn doesn't support CFG Mitigation which is currently enabled in the process. if this is a custom/fork build, please use a PE editor to set the CFG flag to 0. if this is an official release build, please open a github issue.");
            }

            this.mode = mode;
        }

        /// <summary>
        /// Initialize the unicorn emulator with an already available instance.
        /// </summary>
        /// <param name="instance">Instance to be used.</param>
        /// <exception cref="UnicornException"></exception>
        public Unicorn(IntPtr instance)
        {
            if (instance == IntPtr.Zero)
                throw new UnicornException("Invalid unicorn instance.");

            if (IsCFGEnabled())
            {
                _error = UCErrors.UC_ERR_CFG;
                throw new UnicornException("Unicorn doesn't support CFG Mitigation which is currently enabled in the process. if this is a custom/fork build, please use a PE editor to set the CFG flag to 0.");
            }

            _uc = instance;
        }

        /// <summary>
        /// Get the emulator's last error.
        /// </summary>
        /// <returns>returns the emulator's last error.</returns>
        public UCErrors GetLastError()
        {
            return _error;
        }

        public bool MapMemoryShared(ulong address, ulong size, MemoryProtection protection, IntPtr hostPointer)
        {
            if (hostPointer == IntPtr.Zero)
                return false;

            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                IntPtr OwnerBuffer = FindBufferBase(hostPointer);

                _error = uc_mem_map_ptr(_uc, address, new UIntPtr(size), protection, hostPointer);
                if (_error != UCErrors.UC_ERR_OK)
                    return false;

                InsertMappedRegion(new MappedRegion { Address = address, Size = size, Ptr = hostPointer, BufferBase = OwnerBuffer });
                return true;
            }
        }

        private const ulong PendingFreeSliceLimit = 64UL * 1024 * 1024;

        private static unsafe byte* AllocateBacking(nuint size)
        {
            if (GeneralHelper.IsWindows)
                return (byte*)VirtualAlloc(IntPtr.Zero, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            IntPtr Mapped = Mmap(IntPtr.Zero, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            return Mapped == IntPtr.Zero || Mapped == new IntPtr(-1) ? null : (byte*)Mapped;
        }

        private static unsafe void FreeBacking(byte* pointer, nuint size)
        {
            if (GeneralHelper.IsWindows)
                VirtualFree((IntPtr)pointer, UIntPtr.Zero, MEM_RELEASE);
            else
                Munmap((IntPtr)pointer, size);
        }

        private unsafe void ReleaseBacking(IntPtr buffer)
        {
            if (!_bufferSizes.TryGetValue(buffer, out nuint Size))
                return;

            _bufferSizes.Remove(buffer);
            FreeBacking((byte*)buffer, Size);
        }

        public unsafe bool MapMemory(ulong address, ulong size, MemoryProtection protection)
        {
            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                nuint nativeSize = (nuint)size;
                byte* ptr = AllocateBacking(nativeSize);
                if (ptr != null)
                {
                    _error = uc_mem_map_ptr(_uc, address, new UIntPtr(size), protection, (IntPtr)ptr);
                    if (_error == UCErrors.UC_ERR_OK)
                    {
                        _bufferSizes[(IntPtr)ptr] = nativeSize;
                        InsertMappedRegion(new MappedRegion { Address = address, Size = size, Ptr = (IntPtr)ptr, BufferBase = (IntPtr)ptr });
                        return true;
                    }
                    FreeBacking(ptr, nativeSize);
                }

                _error = uc_mem_map(_uc, address, new UIntPtr(size), protection);
                if (_error == UCErrors.UC_ERR_OK)
                {
                    InsertMappedRegion(new MappedRegion { Address = address, Size = size, Ptr = IntPtr.Zero, BufferBase = IntPtr.Zero });
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Unmap an emulated memory.
        /// </summary>
        /// <param name="address">Address of the mapped memory.</param>
        /// <param name="size">Size of the mapped memory.</param>
        /// <returns>returns true if successfully unmapped, otherwise false.</returns>
        public unsafe bool UnmapMemory(ulong address, ulong size)
        {
            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                _error = uc_mem_unmap(_uc, address, new UIntPtr(size));
                if (_error == UCErrors.UC_ERR_OK)
                {
                    FlushTlb();
                    TrimMappedRegions(address, size);
                    return true;
                }
            }
            return false;
        }

        private unsafe IntPtr FindBufferBase(IntPtr hostPointer)
        {
            byte* Target = (byte*)hostPointer;

            for (int i = 0; i < _mappedRegions.Count; i++)
            {
                MappedRegion Region = _mappedRegions[i];
                if (Region.Ptr == IntPtr.Zero || Region.BufferBase == IntPtr.Zero)
                    continue;

                byte* Start = (byte*)Region.Ptr;
                if (Target >= Start && Target < Start + Region.Size)
                    return Region.BufferBase;
            }

            return IntPtr.Zero;
        }

        private unsafe void TrimMappedRegions(ulong address, ulong size)
        {
            ulong end = address + size;
            bool changed = false;

            _unmapSurvivors.Clear();
            _unmapReleasedBuffers.Clear();

            for (int i = _mappedRegions.Count - 1; i >= 0; i--)
            {
                MappedRegion Region = _mappedRegions[i];
                ulong RegionEnd = Region.Address + Region.Size;
                if (RegionEnd <= address || end <= Region.Address)
                    continue;

                ulong OverlapStart = Region.Address > address ? Region.Address : address;
                ulong OverlapEnd = RegionEnd < end ? RegionEnd : end;

                _mappedRegions.RemoveAt(i);
                changed = true;

                if (OverlapStart > Region.Address)
                {
                    _unmapSurvivors.Add(new MappedRegion
                    {
                        Address = Region.Address,
                        Size = OverlapStart - Region.Address,
                        Ptr = Region.Ptr,
                        BufferBase = Region.BufferBase
                    });
                }

                if (RegionEnd > OverlapEnd)
                {
                    IntPtr TailPtr = Region.Ptr == IntPtr.Zero
                        ? IntPtr.Zero
                        : (IntPtr)((byte*)Region.Ptr + (OverlapEnd - Region.Address));

                    _unmapSurvivors.Add(new MappedRegion
                    {
                        Address = OverlapEnd,
                        Size = RegionEnd - OverlapEnd,
                        Ptr = TailPtr,
                        BufferBase = Region.BufferBase
                    });
                }

                if (Region.BufferBase != IntPtr.Zero && !_unmapReleasedBuffers.Contains(Region.BufferBase))
                    _unmapReleasedBuffers.Add(Region.BufferBase);
            }

            if (!changed)
                return;

            for (int i = 0; i < _unmapSurvivors.Count; i++)
                InsertMappedRegion(_unmapSurvivors[i]);

            for (int i = 0; i < _unmapReleasedBuffers.Count; i++)
            {
                IntPtr Buffer = _unmapReleasedBuffers[i];
                bool StillAliased = false;

                for (int j = 0; j < _mappedRegions.Count; j++)
                {
                    if (_mappedRegions[j].BufferBase == Buffer)
                    {
                        StillAliased = true;
                        break;
                    }
                }

                if (!StillAliased)
                {
                    _pendingFrees.Add(Buffer);
                    if (_bufferSizes.TryGetValue(Buffer, out nuint Bytes))
                        _pendingFreeBytes += Bytes;
                }
            }

            // Buffers are released at the end of the slice, so a guest that commits and decommits large
            // blocks inside one slice keeps every dead buffer resident. Cut the slice short instead.
            if (_pendingFreeBytes >= PendingFreeSliceLimit && _uc != IntPtr.Zero)
                uc_emu_stop(_uc);
        }

        /// <summary>
        /// Write to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Value to write to the emulated memory address.</param>
        /// <param name="length">Number of bytes to write. A value of 0 writes the full byte array.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public unsafe bool WriteMemory(ulong address, byte[] value, uint length = 0)
        {
            if (value == null)
                return false;

            uint writeLen = length == 0 ? (uint)value.Length : length;
            if (writeLen == 0 || writeLen > (uint)value.Length)
                writeLen = (uint)value.Length;

            if (writeLen == 0)
                return false;

            if (TryGetHostPointer(address, (int)writeLen, out byte* dst, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                fixed (byte* src = value)
                    Unsafe.CopyBlockUnaligned(dst + offset, src, writeLen);
                return true;
            }

            if (DisposedCheck())
                return false;

            _lock.EnterReadLock();
            try
            {
                lock (_memoryLock)
                {
                    if (DisposedCheck())
                        return false;

                    if (_uc == IntPtr.Zero)
                        return false;

                    GCHandle handle = default;
                    try
                    {
                        handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                        IntPtr ptr = handle.AddrOfPinnedObject();
                        _error = uc_mem_write_ptr(_uc, address, ptr, new UIntPtr(writeLen));
                        return _error == UCErrors.UC_ERR_OK;
                    }
                    finally
                    {
                        if (handle.IsAllocated)
                            handle.Free();
                    }
                }
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public unsafe bool WriteMemory(ulong Address, byte[] Value, int Offset, int Length)
        {
            if (Value == null)
                return false;

            if ((uint)Offset > (uint)Value.Length)
                return false;

            if (Length < 0)
                return false;

            int Remaining = Value.Length - Offset;
            if (Length > Remaining)
                Length = Remaining;

            if (Length == 0)
                return true;

            if (TryGetHostPointer(Address, Length, out byte* dst, out long dstOffset))
            {
                _error = UCErrors.UC_ERR_OK;
                fixed (byte* src = Value)
                    Unsafe.CopyBlockUnaligned(dst + dstOffset, src + Offset, (uint)Length);
                return true;
            }

            if (DisposedCheck())
                return false;

            _lock.EnterReadLock();
            try
            {
                lock (_memoryLock)
                {
                    if (_uc == IntPtr.Zero || DisposedCheck())
                        return false;

                    GCHandle Handle = default;
                    try
                    {
                        Handle = GCHandle.Alloc(Value, GCHandleType.Pinned);

                        IntPtr BasePtr = Handle.AddrOfPinnedObject();
                        IntPtr Ptr = IntPtr.Add(BasePtr, Offset);

                        _error = uc_mem_write_ptr(_uc, Address, Ptr, new UIntPtr((uint)Length));
                        return _error == UCErrors.UC_ERR_OK;
                    }
                    finally
                    {
                        if (Handle.IsAllocated)
                            Handle.Free();
                    }
                }
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public unsafe bool WriteMemory(ulong address, ReadOnlySpan<byte> value, uint length = 0)
        {
            uint writeLen = length == 0 ? (uint)value.Length : length;
            if (writeLen == 0 || writeLen > (uint)value.Length)
                writeLen = (uint)value.Length;

            if (writeLen == 0)
                return false;

            if (TryGetHostPointer(address, (int)writeLen, out byte* dst, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                fixed (byte* src = value)
                    Unsafe.CopyBlockUnaligned(dst + offset, src, writeLen);
                return true;
            }

            if (DisposedCheck())
                return false;

            _lock.EnterReadLock();
            try
            {
                lock (_memoryLock)
                {
                    if (DisposedCheck())
                        return false;

                    if (_uc == IntPtr.Zero)
                        return false;

                    fixed (byte* ptr = value)
                    {
                        _error = uc_mem_write_ptr(_uc, address, (IntPtr)ptr, new UIntPtr(writeLen));
                        return _error == UCErrors.UC_ERR_OK;
                    }
                }
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        /// <summary>
        /// Write to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Value to write to the emulated memory address.</param>
        /// <param name="length">Number of bytes to write. A value of 0 writes the full value.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public bool WriteMemory(ulong address, ulong value, uint length = 0)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(ulong)];
            BitConverter.TryWriteBytes(Buffer, value);
            return WriteMemory(address, Buffer, length);
        }

        /// <summary>
        /// Write a string to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Value to write to the emulated memory address.</param>
        /// <param name="length">Unused for this overload.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public bool WriteMemory(ulong address, string value, Encoding EncodingType)
        {
            if (DisposedCheck())
                return false;
            byte[] StringValue = EncodingType.GetBytes(value);
            return WriteMemory(address, StringValue);
        }

        /// <summary>
        /// Write to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Value to write to the emulated memory address.</param>
        /// <param name="length">Number of bytes to write. A value of 0 writes the full value.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public bool WriteMemory(ulong address, uint value, uint length = 0)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(uint)];
            BitConverter.TryWriteBytes(Buffer, value);
            return WriteMemory(address, Buffer, length);
        }

        /// <summary>
        /// Write to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Byte value to repeat across the target memory range.</param>
        /// <param name="length">Number of bytes to write.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public bool WriteMemoryByte(ulong address, byte value, uint length = 0)
        {
            if (DisposedCheck())
                return false;

            if (length == 0)
                return false;

            Span<byte> StackBuffer = stackalloc byte[256];
            StackBuffer.Fill(value);

            ulong Current = address;
            uint Remaining = length;
            while (Remaining != 0)
            {
                int Count = (int)Math.Min((uint)StackBuffer.Length, Remaining);
                if (!WriteMemory(Current, StackBuffer.Slice(0, Count)))
                    return false;

                Current += (ulong)Count;
                Remaining -= (uint)Count;
            }

            return true;
        }

        /// <summary>
        /// Write to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Value to write to the emulated memory address.</param>
        /// <param name="length">Number of bytes to write. A value of 0 writes the full value.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public bool WriteMemory(ulong address, int value, uint length = 0)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(int)];
            BitConverter.TryWriteBytes(Buffer, value);
            return WriteMemory(address, Buffer, length);
        }

        /// <summary>
        /// Write to an emulated memory address.
        /// </summary>
        /// <param name="address">Address in the emulated memory.</param>
        /// <param name="value">Value to write to the emulated memory address.</param>
        /// <param name="length">Number of bytes to write. A value of 0 writes the full value.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        public bool WriteMemory(ulong address, ushort value, uint length = 0)
        {
            Span<byte> Buffer = stackalloc byte[sizeof(ushort)];
            BitConverter.TryWriteBytes(Buffer, value);
            return WriteMemory(address, Buffer, length);
        }

        /// <summary>
        /// Read a byte array from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <param name="length">Length of the data to read.</param>
        /// <returns>returns a byte array containing the data.</returns>
        public unsafe byte[] ReadMemory(ulong address, ulong length)
        {
            if (DisposedCheck())
                return Array.Empty<byte>();
            if (length > int.MaxValue)
                return null;
            byte[] value = new byte[length];
            if (TryGetHostPointer(address, (int)length, out byte* src, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                if (length > 0)
                    Unsafe.CopyBlockUnaligned(ref value[0], ref Unsafe.AsRef<byte>(src + offset), (uint)length);
                return value;
            }
            _error = uc_mem_read(_uc, address, value, new UIntPtr(length));
            return value;
        }

        /// <summary>
        /// Read a byte array from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <param name="length">Length of the data to read.</param>
        /// <returns>returns a byte array containing the data.</returns>
        public unsafe byte[] ReadMemory(ulong address, uint length)
        {
            if (DisposedCheck())
                return Array.Empty<byte>();
            if (length > int.MaxValue)
                return null;
            byte[] value = new byte[length];
            if (TryGetHostPointer(address, (int)length, out byte* src, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                if (length > 0)
                    Unsafe.CopyBlockUnaligned(ref value[0], ref Unsafe.AsRef<byte>(src + offset), length);
                return value;
            }
            _error = uc_mem_read(_uc, address, value, length);
            return value;
        }

        public unsafe bool ReadMemory(ulong address, Span<byte> value, uint length = 0)
        {
            uint ReadLen = length == 0 ? (uint)value.Length : length;
            if (ReadLen == 0 || ReadLen > (uint)value.Length)
                ReadLen = (uint)value.Length;

            if (ReadLen == 0)
                return false;

            if (TryGetHostPointer(address, (int)ReadLen, out byte* src, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                fixed (byte* dst = value)
                    Unsafe.CopyBlockUnaligned(dst, src + offset, ReadLen);
                return true;
            }

            if (DisposedCheck())
                return false;

            _lock.EnterReadLock();
            try
            {
                lock (_memoryLock)
                {
                    if (DisposedCheck())
                        return false;

                    if (_uc == IntPtr.Zero)
                        return false;

                    fixed (byte* Ptr = value)
                    {
                        _error = uc_mem_read_ptr(_uc, address, (IntPtr)Ptr, new UIntPtr(ReadLen));
                        return _error == UCErrors.UC_ERR_OK;
                    }
                }
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        /// <summary>
        /// Read a ulong from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <returns>returns a ulong of the data.</returns>
        public unsafe ulong ReadMemoryULong(ulong address)
        {
            if (TryGetHostPointer(address, sizeof(ulong), out byte* ptr, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                return *(ulong*)(ptr + offset);
            }
            if (DisposedCheck())
                return 0;
            ulong value = 0;
            _error = uc_mem_read(_uc, address, out value, sizeof(ulong));
            return value;
        }

        /// <summary>
        /// Read a uint from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <returns>returns a ulong of the data.</returns>
        public unsafe uint ReadMemoryUInt(ulong address)
        {
            if (TryGetHostPointer(address, sizeof(uint), out byte* ptr, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                return *(uint*)(ptr + offset);
            }
            if (DisposedCheck())
                return 0;
            uint value = 0;
            _error = uc_mem_read(_uc, address, out value, sizeof(uint));
            return value;
        }

        /// <summary>
        /// Read a ushort from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <returns>returns a ushort of the data.</returns>
        public unsafe ushort ReadMemoryUShort(ulong address)
        {
            if (TryGetHostPointer(address, sizeof(ushort), out byte* ptr, out long offset))
            {
                _error = UCErrors.UC_ERR_OK;
                return *(ushort*)(ptr + offset);
            }
            if (DisposedCheck())
                return 0;
            ushort value = 0;
            _error = uc_mem_read(_uc, address, out value, sizeof(ushort));
            return value;
        }

        /// <summary>
        /// Reads a string from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <param name="length">Maximum length of the string to read.</param>
        /// <param name="encoding">Encoding type.</param>
        /// <returns>Returns a string of the data, or <see cref="string.Empty"/> if reading failed.</returns>
        public unsafe string ReadMemoryString(ulong address, int length, Encoding encoding)
        {
            if (DisposedCheck())
                return null;

            if (address == 0 || length <= 0)
                return string.Empty;

            byte[] Buffer = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                if (TryGetHostPointer(address, length, out byte* src, out long offset))
                {
                    _error = UCErrors.UC_ERR_OK;
                    Unsafe.CopyBlockUnaligned(ref Buffer[0], ref Unsafe.AsRef<byte>(src + offset), (uint)length);
                }
                else
                {
                    _error = uc_mem_read(_uc, address, Buffer, (uint)length);
                    if (_error != UCErrors.UC_ERR_OK)
                        return string.Empty;
                }

                int BytesRead;
                if (encoding == Encoding.Unicode || encoding == Encoding.BigEndianUnicode)
                {
                    int NulIdx = SimdStringHelpers.IndexOfUtf16Nul(Buffer.AsSpan(0, length));
                    if (NulIdx < 0)
                    {
                        BytesRead = length;
                        if ((BytesRead & 1) != 0)
                            BytesRead--;
                    }
                    else
                    {
                        BytesRead = NulIdx;
                    }

                    if (BytesRead == 0)
                        return string.Empty;
                }
                else
                {
                    int TerminatorIndex = Array.IndexOf(Buffer, (byte)0, 0, length);
                    BytesRead = TerminatorIndex >= 0 ? TerminatorIndex : length;

                    if (BytesRead == 0)
                        return string.Empty;
                }

                return encoding.GetString(Buffer, 0, BytesRead);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(Buffer);
            }
        }

        /// <summary>
        /// Write to a register.
        /// </summary>
        /// <param name="register">Register to write to.</param>
        /// <param name="value">value to write to the register.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool WriteRegister(Registers register, ulong value)
        {
            return WriteRegister((int)register, value);
        }

        public unsafe bool WriteRegister(int Register, ulong Value)
        {
            if (DisposedCheck())
                return false;

            lock (_registerLock)
            {
                ulong* Slot = DirectRegister(Register, DirectWritable);
                if (Slot != null)
                {
                    *Slot = Value;
                    _error = UCErrors.UC_ERR_OK;
                    return true;
                }

                _error = uc_reg_write_raw(_uc, Register, ref Value);
                return _error == UCErrors.UC_ERR_OK;
            }
        }

        public bool WriteGdtr(ulong Base, uint Limit)
        {
            if (DisposedCheck())
                return false;

            uc_x86_mmr Value = new uc_x86_mmr { selector = 0, Base = Base, limit = Limit, flags = 0 };
            lock (_registerLock)
            {
                _error = uc_reg_write_mmr(_uc, Registers.UC_X86_REG_GDTR, ref Value);
                return _error == UCErrors.UC_ERR_OK;
            }
        }

        /// <summary>
        /// Write to a register.
        /// </summary>
        /// <param name="register">Register to write to.</param>
        /// <param name="value">value to write to the register.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool WriteRegister32(Registers register, uint value)
        {
            if (DisposedCheck())
                return false;
            _error = uc_reg_write(_uc, register, ref value);
            return _error == UCErrors.UC_ERR_OK;
        }

        public bool WriteRegister32(int Register, uint Value)
        {
            if (DisposedCheck())
                return false;
            _error = uc_reg_write_raw(_uc, Register, ref Value);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Write to a register.
        /// </summary>
        /// <param name="register">Register to write to.</param>
        /// <param name="value">value to write to the register.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool WriteRegisterByte(Registers register, byte value)
        {
            if (DisposedCheck())
                return false;
            _error = uc_reg_write(_uc, register, ref value);
            return _error == UCErrors.UC_ERR_OK;
        }

        public bool WriteRegisterByte(int Register, byte Value)
        {
            if (DisposedCheck())
                return false;
            _error = uc_reg_write_raw(_uc, Register, ref Value);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Write to a register.
        /// </summary>
        /// <param name="register">Register to write to.</param>
        /// <param name="value">value to write to the register.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool WriteRegisterByte(Registers register, byte[] value)
        {
            if (DisposedCheck())
                return false;
            _error = uc_reg_write(_uc, register, value);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Read from a register.
        /// </summary>
        /// <param name="register">Register to read from.</param>
        /// <returns>returns the value of the register.</returns>
        public ulong ReadRegister(Registers register)
        {
            return ReadRegister((int)register);
        }

        /// <summary>
        /// Read raw register.
        /// </summary>
        /// <param name="Register">Register to read.</param>
        /// <returns>returns the value of the register.</returns>
        public unsafe ulong ReadRegister(int Register)
        {
            if (DisposedCheck())
                return 0;

            if (_uc == IntPtr.Zero)
                throw new InvalidOperationException("Unicorn engine is not initialized.");

            ulong* Slot = DirectRegister(Register, DirectReadable);
            if (Slot != null)
            {
                _error = UCErrors.UC_ERR_OK;
                return *Slot;
            }

            ulong Value = 0;
            _error = uc_reg_read_raw(_uc, Register, out Value);
            return Value;
        }

        /// <summary>
        /// Read from a register.
        /// </summary>
        /// <param name="register">Register to read from.</param>
        /// <returns>returns the value of the register.</returns>
        public uint ReadRegister32(Registers register)
        {
            if (DisposedCheck())
                return 0;

            uint value = 0;
            _error = uc_reg_read(_uc, register, out value);
            return value;
        }

        /// <summary>
        /// Read raw register.
        /// </summary>
        /// <param name="Register">Register to read.</param>
        /// <returns>returns the value of the register.</returns>
        public uint ReadRegister32(int Register)
        {
            if (DisposedCheck())
                return 0;

            uint Value = 0;
            _error = uc_reg_read_raw(_uc, Register, out Value);
            return Value;
        }

        /// <summary>
        /// Read from a register.
        /// </summary>
        /// <param name="register">Register to read from.</param>
        /// <returns>returns the value of the register.</returns>
        public byte ReadRegisterByte(Registers register)
        {
            if (DisposedCheck())
                return 0;

            byte value = 0;
            _error = uc_reg_read(_uc, register, out value);
            return value;
        }

        public byte ReadRegisterByte(int Register)
        {
            if (DisposedCheck())
                return 0;

            byte Value = 0;
            _error = uc_reg_read_raw(_uc, Register, out Value);
            return Value;
        }

        /// <summary>
        /// Reads several registers in a single native call.
        /// </summary>
        public unsafe bool ReadRegisterBatch(int[] Registers, ulong[] Values, int Count)
        {
            if (DisposedCheck())
                return false;

            if (Registers == null || Values == null || Count <= 0 || Count > Registers.Length || Count > Values.Length)
                return false;

            lock (_registerLock)
            {
                if (_uc == IntPtr.Zero)
                    return false;

                fixed (int* RegsPtr = Registers)
                fixed (ulong* ValsPtr = Values)
                {
                    void** PtrArray = stackalloc void*[Count];
                    for (int i = 0; i < Count; i++)
                        PtrArray[i] = &ValsPtr[i];

                    _error = uc_reg_read_batch(_uc, RegsPtr, PtrArray, Count);
                    return _error == UCErrors.UC_ERR_OK;
                }
            }
        }

        /// <summary>
        /// Writes several registers in a single native call.
        /// </summary>
        public unsafe bool WriteRegisterBatch(int[] Registers, ulong[] Values, int Count)
        {
            if (DisposedCheck())
                return false;

            if (Registers == null || Values == null || Count <= 0 || Count > Registers.Length || Count > Values.Length)
                return false;

            lock (_registerLock)
            {
                if (_uc == IntPtr.Zero)
                    return false;

                fixed (int* RegsPtr = Registers)
                fixed (ulong* ValsPtr = Values)
                {
                    void** PtrArray = stackalloc void*[Count];
                    for (int i = 0; i < Count; i++)
                        PtrArray[i] = &ValsPtr[i];

                    _error = uc_reg_write_batch(_uc, RegsPtr, PtrArray, Count);
                    return _error == UCErrors.UC_ERR_OK;
                }
            }
        }

        internal const int XmmRegisterCount = 16;

        private static int[] _xmmBatchRegs;

        private static int[] GetXmmBatchRegs()
        {
            int[] Regs = _xmmBatchRegs;
            if (Regs == null)
            {
                Regs = new int[XmmRegisterCount];
                for (int i = 0; i < XmmRegisterCount; i++)
                    Regs[i] = (int)Registers.UC_X86_REG_XMM0 + i;
                _xmmBatchRegs = Regs;
            }
            return Regs;
        }

        /// <summary>
        /// Transfers XMM0-15 as 32 qwords, low half of each register first.
        /// </summary>
        public unsafe bool TransferXmmRegisters(ulong[] Values, bool Write)
        {
            if (DisposedCheck() || Values == null || Values.Length < XmmRegisterCount * 2)
                return false;

            lock (_registerLock)
            {
                if (_uc == IntPtr.Zero)
                    return false;

                int[] Regs = GetXmmBatchRegs();

                fixed (int* RegsPtr = Regs)
                fixed (ulong* ValsPtr = Values)
                {
                    void** PtrArray = stackalloc void*[XmmRegisterCount];
                    for (int i = 0; i < XmmRegisterCount; i++)
                        PtrArray[i] = &ValsPtr[i * 2];

                    _error = Write
                        ? uc_reg_write_batch(_uc, RegsPtr, PtrArray, XmmRegisterCount)
                        : uc_reg_read_batch(_uc, RegsPtr, PtrArray, XmmRegisterCount);
                    return _error == UCErrors.UC_ERR_OK;
                }
            }
        }

        /// <summary>
        /// Get the CPU Flags.
        /// </summary>
        /// <returns>returns the CPU Flags.</returns>
        public CPUFlags GetCPUFlags()
        {
            if (mode == Mode.MODE_64)
            {
                return (CPUFlags)ReadRegister(Registers.UC_X86_REG_RFLAGS);
            }
            else
            {
                return (CPUFlags)ReadRegister(Registers.UC_X86_REG_EFLAGS);
            }
        }

        /// <summary>
        /// Set the CPU Flags.
        /// </summary>
        /// <param name="Flags">Flags to set.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool SetCPUFlags(CPUFlags Flags)
        {
            if (mode == Mode.MODE_64)
            {
                return WriteRegister(Registers.UC_X86_REG_RFLAGS, (ulong)Flags);
            }
            else
            {
                return WriteRegister(Registers.UC_X86_REG_EFLAGS, (ulong)Flags);
            }
        }

        /// <summary>
        /// Set a new memory protection for an already mapped memory.
        /// </summary>
        /// <param name="Address">Address of the mapped memory.</param>
        /// <param name="Size">Size of the mapped memory.</param>
        /// <param name="Protection">New protection(s) for the mapped memory.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool SetMemoryProtection(ulong Address, ulong Size, MemoryProtection Protection)
        {
            if (DisposedCheck())
                return false;

            _error = uc_mem_protect(_uc, Address, Size, Protection);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Start Emulation.
        /// </summary>
        /// <param name="start">Beginning of emulation.</param>
        /// <param name="end">End of emulation.</param>
        /// <param name="timeout">Timeout in milliseconds. A value of 0 disables the timeout.</param>
        /// <param name="count">Instruction count limit. A value of 0 disables the instruction limit.</param>
        /// <returns>True if emulation completed without errors; otherwise, false.</returns>
        public bool Emulate(ulong start, ulong end, uint timeout = 0, uint count = 0)
        {
            if (DisposedCheck())
                return false;

            _emuLock.EnterWriteLock();
            try
            {
                _error = uc_emu_start(_uc, start, end, new UIntPtr(timeout), new UIntPtr(count));
                return _error == UCErrors.UC_ERR_OK;
            }
            finally
            {
                _emuLock.ExitWriteLock();
                FlushPendingFrees();
            }
        }

        private unsafe void FlushPendingFrees()
        {
            lock (_mapsLock)
            {
                if (_pendingFrees.Count == 0)
                    return;

                for (int i = 0; i < _pendingFrees.Count; i++)
                    ReleaseBacking(_pendingFrees[i]);

                _pendingFrees.Clear();
                _pendingFreeBytes = 0;
            }
        }

        /// <summary>
        /// Stop emulation.
        /// </summary>
        /// <returns>returns true if successfully stopped emulation, otherwise false.</returns>
        public bool StopEmulation()
        {
            if (DisposedCheck())
                return false;

            _error = uc_emu_stop(_uc);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Add an instruction hook.
        /// </summary>
        /// <param name="Instruction">Instruction to hook.</param>
        /// <param name="ReturnHook">The hook to return to.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool AddHook(INSTHooks Instruction, IntPtr ReturnHook)
        {
            if (DisposedCheck())
                return false;

            IntPtr Hook = IntPtr.Zero;
            _error = uc_hook_add(_uc, out Hook, (int)Emulation.Hooks.UC_HOOK_INSN, ReturnHook, IntPtr.Zero, 1, 0, Instruction);
            if (_error == UCErrors.UC_ERR_OK)
            {
                HooksList.Add(Hook);
                return true;
            }
            return false;
        }

        private const Hooks RequiredHookTypes =
            Hooks.UC_HOOK_MEM_READ_UNMAPPED | Hooks.UC_HOOK_MEM_WRITE_UNMAPPED | Hooks.UC_HOOK_MEM_FETCH_UNMAPPED |
            Hooks.UC_HOOK_MEM_READ_PROT | Hooks.UC_HOOK_MEM_WRITE_PROT | Hooks.UC_HOOK_MEM_FETCH_PROT |
            Hooks.UC_HOOK_INSN_INVALID | Hooks.UC_HOOK_INTR;

        /// <summary>
        /// Make sure that the hook is a whitelisted hook when <see cref="NoHooks"/> are enabled.
        /// </summary>
        /// <returns>returns true if the hook is whitelisted, otherwise false.</returns>
        private static bool IsWhitelistedHookType(Hooks hook)
        {
            return (hook & RequiredHookTypes) != 0;
        }

        /// <summary>
        /// Adds a hook.
        /// </summary>
        /// <param name="Begin">The beginning of the address to hook.</param>
        /// <param name="End">The end of the address to hook (if less than the Begin parameter, then it's applied to all addresses).</param>
        /// <param name="ReturnHook">The hook to return to.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool AddHook(ulong Begin, ulong End, Hooks HookType, IntPtr ReturnHook)
        {
            if (NoHooks && !IsWhitelistedHookType(HookType)) return true;
            if (DisposedCheck())
                return false;

            IntPtr Hook = IntPtr.Zero;
            _error = uc_hook_add(_uc, out Hook, HookType, ReturnHook, IntPtr.Zero, Begin, End);
            if (_error == UCErrors.UC_ERR_OK)
            {
                HooksList.Add(Hook);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Adds a hook and returns the hook handle.
        /// </summary>
        /// <param name="Begin">The beginning of the address to hook.</param>
        /// <param name="End">The end of the address to hook (if less than the Begin parameter, then it's applied to all addresses).</param>
        /// <param name="HookType">Hook type.</param>
        /// <param name="ReturnHook">Hook callback pointer.</param>
        /// <returns>Hook handle or <see cref="IntPtr.Zero"/> on failure.</returns>
        public IntPtr AddHookWithHandle(ulong Begin, ulong End, Hooks HookType, IntPtr ReturnHook)
        {
            if (NoHooks && !IsWhitelistedHookType(HookType)) return IntPtr.Zero;
            if (DisposedCheck())
                return IntPtr.Zero;

            IntPtr Hook = IntPtr.Zero;
            _error = uc_hook_add(_uc, out Hook, HookType, ReturnHook, IntPtr.Zero, Begin, End);
            if (_error == UCErrors.UC_ERR_OK)
            {
                HooksList.Add(Hook);
                return Hook;
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Remove a hook.
        /// </summary>
        /// <param name="Hook">The hook to remove.</param>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool RemoveHook(IntPtr Hook)
        {
            if (DisposedCheck())
                return false;

            _error = uc_hook_del(_uc, Hook);
            if (_error == UCErrors.UC_ERR_OK)
            {
                HooksList.Remove(Hook);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Remove all registered hooks.
        /// </summary>
        /// <returns>returns true if **ALL** registered hooks was successfully removed, otherwise false.</returns>
        public bool RemoveHooks()
        {
            if (DisposedCheck())
                return false;

            bool SuccessAll = true;
            IntPtr[] snapshot;
            lock (_hooksLock)
            {
                snapshot = HooksList.ToArray();
            }

            foreach (IntPtr Hook in snapshot)
            {
                if (uc_hook_del(_uc, Hook) == UCErrors.UC_ERR_OK)
                {
                    lock (_hooksLock) { HooksList.Remove(Hook); }
                }
                else
                {
                    SuccessAll = false;
                }
            }

            return SuccessAll;
        }

        public bool FlushTlb()
        {
            const int UC_CTL_TLB_FLUSH = 11;
            const int UC_CTL_IO_WRITE = 1;

            int control = UC_CTL_TLB_FLUSH | (0 << 26) | (UC_CTL_IO_WRITE << 30);

            _error = uc_ctl0(_uc, control);

            return _error == UCErrors.UC_ERR_OK;
        }

        // TCG keys block invalidation on ram_addr, so two mappings of the same host pages do not
        // invalidate each other.
        public bool InvalidateCodeRange(ulong address, ulong size)
        {
            if (size == 0)
                return true;

            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                const int UC_CTL_TB_REMOVE_CACHE = 9;
                const int UC_CTL_IO_WRITE = 1;

                int control = UC_CTL_TB_REMOVE_CACHE | (2 << 26) | (UC_CTL_IO_WRITE << 30);

                _error = uc_ctl2_ulong(_uc, control, address, address + size);
                return _error == UCErrors.UC_ERR_OK;
            }
        }

        public bool SetTlbMode(UcTlbType mode)
        {
            const int UC_CTL_TLB_TYPE = 12;
            const int UC_CTL_IO_WRITE = 1;

            int control = UC_CTL_TLB_TYPE | (1 << 26) | (UC_CTL_IO_WRITE << 30);

            _error = uc_ctl1(_uc, control, (int)mode);

            return _error == UCErrors.UC_ERR_OK;
        }

        public bool SetTcgBufferSize(uint Size)
        {
            if (DisposedCheck())
                return false;

            const int UC_CTL_TCG_BUFFER_SIZE = 13;
            const int UC_CTL_IO_WRITE = 1;

            int Control = UC_CTL_TCG_BUFFER_SIZE | (1 << 26) | (UC_CTL_IO_WRITE << 30);

            _error = uc_ctl1_uint(_uc, Control, Size);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Reserve the address range that the TCG code buffer, the slot table and the
        /// uc struct live in. Must be called before any <see cref="Unicorn"/> instance
        /// is created: the reservation is what makes a saved code cache reloadable.
        /// </summary>
        /// <param name="ReserveBase">Base recorded by a previous run, or 0 to let the OS choose.</param>
        /// <param name="ReserveSize">Total bytes to reserve, including the header region.</param>
        /// <param name="EnableCache">Whether saving and loading are wanted this run.</param>
        /// <param name="StrictAudit">Also flag pointers into the interior of tracked objects.</param>
        public static bool ConfigureCodeCache(ulong ReserveBase, ulong ReserveSize, bool EnableCache, bool StrictAudit = false)
        {
            BrovConfig Config = new BrovConfig
            {
                StructSize = (uint)Marshal.SizeOf<BrovConfig>(),
                Flags = (EnableCache ? BROV_CFG_ENABLE_CACHE : 0u) | (StrictAudit ? BROV_CFG_STRICT_AUDIT : 0u),
                ReserveBase = ReserveBase,
                ReserveSize = ReserveSize,
                SlotCount = 0,
                Reserved = 0,
            };

            return brov_configure(ref Config) == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Get the base and size of the address reservation actually obtained.
        /// </summary>
        public static bool GetCodeCacheReservation(out ulong ReservationBase, out ulong ReservationSize)
        {
            return brov_reservation_info(out ReservationBase, out ReservationSize) == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Read the reservation a saved blob needs, so it can be requested before uc_open.
        /// </summary>
        public static bool GetBlobReservation(byte[] Blob, out ulong ReservationBase, out ulong ReservationSize)
        {
            ReservationBase = 0;
            ReservationSize = 0;

            if (Blob == null || Blob.Length == 0)
                return false;

            return brov_blob_reservation(Blob, (UIntPtr)Blob.Length, out ReservationBase, out ReservationSize) == UCErrors.UC_ERR_OK;
        }

        internal bool GetCodeCacheInfo(out BrovCacheInfo Info)
        {
            Info = new BrovCacheInfo { StructSize = (uint)Marshal.SizeOf<BrovCacheInfo>() };

            if (DisposedCheck())
                return false;

            _error = brov_cc_info(_uc, ref Info);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Run the relocation audit without saving. Reports any host pointer baked into
        /// generated code that a reload could not repoint.
        /// </summary>
        internal bool ValidateCodeCache(out BrovAuditResult Result)
        {
            Result = new BrovAuditResult { StructSize = (uint)Marshal.SizeOf<BrovAuditResult>() };

            if (DisposedCheck())
                return false;

            _error = brov_cc_validate(_uc, ref Result);
            return _error == UCErrors.UC_ERR_OK && Result.HitCount == 0;
        }

        /// <summary>
        /// Serialize the TCG code cache. Returns null when the cache cannot be saved;
        /// <see cref="GetCodeCacheReason"/> says why.
        /// </summary>
        public byte[] SaveCodeCache()
        {
            if (DisposedCheck())
                return null;

            _error = brov_cc_save(_uc, out IntPtr Blob, out UIntPtr Length);
            if (_error != UCErrors.UC_ERR_OK || Blob == IntPtr.Zero)
                return null;

            try
            {
                byte[] Managed = new byte[(int)Length];
                Marshal.Copy(Blob, Managed, 0, Managed.Length);
                return Managed;
            }
            finally
            {
                brov_cc_free(Blob);
            }
        }

        /// <summary>
        /// Restore a previously saved TCG code cache. The guest image must already be
        /// mapped: every restored block is verified against the guest bytes it was
        /// translated from.
        /// </summary>
        public bool LoadCodeCache(byte[] Blob)
        {
            if (DisposedCheck() || Blob == null || Blob.Length == 0)
                return false;

            _error = brov_cc_load(_uc, Blob, (UIntPtr)Blob.Length);
            return _error == UCErrors.UC_ERR_OK;
        }

        /// <summary>
        /// Register restored blocks whose guest pages were not mapped yet when the cache
        /// was loaded. Returns false once nothing is left to resolve.
        /// </summary>
        public bool ResolveCodeCache(out uint Resolved, out uint Remaining)
        {
            Resolved = 0;
            Remaining = 0;

            if (DisposedCheck())
                return false;

            _error = brov_cc_resolve(_uc, out Resolved, out Remaining);
            return _error == UCErrors.UC_ERR_OK && Remaining != 0;
        }

        public uint GetCodeCacheReason()
        {
            if (DisposedCheck())
                return 0;

            return brov_last_reason(_uc, out uint Reason) == UCErrors.UC_ERR_OK ? Reason : 0;
        }

        /// <summary>
        /// Host pointers to register storage inside the guest CPU state, so the common
        /// 64-bit reads and writes become a load or a store instead of a native call.
        /// </summary>
        /// <remarks>
        /// Only registers Unicorn stores verbatim get an entry, and only those it would
        /// have written with a plain store get <see cref="DirectWritable"/>. EFLAGS is
        /// absent because its condition codes are computed lazily, the program counter is
        /// read-only here because writing it also raises quit_request and flushes
        /// translated blocks, and nothing is exposed in 16- or 32-bit mode where the same
        /// storage is reached under different truncation rules.
        /// </remarks>
        private const int DirectRegisterCount = 512;
        private const byte DirectProbed = 0x1;
        private const byte DirectReadable = 0x2;
        private const byte DirectWritable = 0x4;

        private IntPtr[] _directRegisters;
        private byte[] _directRegisterState;

        private byte ProbeDirectRegister(int Register)
        {
            IntPtr[] Pointers = _directRegisters;
            byte[] State = _directRegisterState;

            if (Pointers == null || State == null)
            {
                Interlocked.CompareExchange(ref _directRegisters, new IntPtr[DirectRegisterCount], null);
                Interlocked.CompareExchange(ref _directRegisterState, new byte[DirectRegisterCount], null);
                Pointers = _directRegisters;
                State = _directRegisterState;
            }

            byte Known = Volatile.Read(ref State[Register]);
            if (Known != 0)
                return Known;

            byte Result = DirectProbed;
            if (brov_reg_ptr(_uc, Register, out IntPtr Pointer, out UIntPtr Bytes, out uint Flags) == UCErrors.UC_ERR_OK
                && Pointer != IntPtr.Zero && (ulong)Bytes == sizeof(ulong))
            {
                Pointers[Register] = Pointer;

                if ((Flags & BROV_REG_READABLE) != 0)
                    Result |= DirectReadable;
                if ((Flags & BROV_REG_WRITABLE) != 0)
                    Result |= DirectWritable;
            }

            Volatile.Write(ref State[Register], Result);
            return Result;
        }

        private unsafe ulong* DirectRegister(int Register, byte Access)
        {
            if ((uint)Register >= DirectRegisterCount)
                return null;

            byte[] State = _directRegisterState;
            byte Known = State != null ? Volatile.Read(ref State[Register]) : (byte)0;

            if (Known == 0)
                Known = ProbeDirectRegister(Register);

            return (Known & Access) != 0 ? (ulong*)_directRegisters[Register] : null;
        }

        /// <summary>
        /// Get the current emulator context.
        /// </summary>
        /// <returns>returns a pointer to the context, if it failed it will return <see cref="IntPtr.Zero"/>.</returns>
        public IntPtr GetCurrentContext()
        {
            if (DisposedCheck())
                return IntPtr.Zero;

            IntPtr Context = IntPtr.Zero;
            _error = uc_context_save(_uc, out Context);
            if (_error != UCErrors.UC_ERR_OK)
                return IntPtr.Zero;
            return Context;
        }

        /// <summary>
        /// Set the current emulator context.
        /// </summary>
        /// <returns>returns true if successful, otherwise false.</returns>
        public bool SetCurrentContext(IntPtr Context)
        {
            if (DisposedCheck())
                return false;

            _error = uc_context_restore(_uc, Context);
            return _error == UCErrors.UC_ERR_OK;
        }

        private bool DisposedCheck()
        {
            if (Disposed || Disposing || _uc == IntPtr.Zero)
            {
                if (ThrowDisposed) throw new ObjectDisposedException(nameof(Unicorn));
                return true;
            }
            return false;
        }

        public bool IsRangeMapped(ulong address, ulong size)
        {
            if (size == 0)
                return true;

            if (Volatile.Read(ref _disposing) != 0 || Volatile.Read(ref _disposed) != 0)
                return false;

            ulong remaining = size;
            ulong current = address;

            while (remaining > 0)
            {
                if (!TryFindMappedRegion(current, out MappedRegion found))
                    return false;

                ulong regionEnd = found.Address + found.Size;
                if (regionEnd <= current)
                    return false;

                ulong chunk = regionEnd - current;
                if (chunk > remaining)
                    chunk = remaining;

                current += chunk;
                remaining -= chunk;
            }

            return true;
        }

        public unsafe IntPtr GetHostPointer(ulong address, ulong size)
        {
            if (size == 0 || size > int.MaxValue) return IntPtr.Zero;
            if (!TryGetHostPointer(address, (int)size, out byte* ptr, out long offset)) return IntPtr.Zero;
            return (IntPtr)(ptr + offset);
        }

        private unsafe bool TryGetHostPointer(ulong address, int accessSize, out byte* ptr, out long offset)
        {
            if (!TryFindMappedRegion(address, out MappedRegion found))
            {
                ptr = null;
                offset = 0;
                return false;
            }

            if (found.Ptr == IntPtr.Zero)
            {
                ptr = null;
                offset = 0;
                return false;
            }

            if (!IsRangeInRegion(address, (ulong)accessSize, found.Address, found.Size))
            {
                ptr = null;
                offset = 0;
                return false;
            }

            ptr = (byte*)found.Ptr;
            offset = (long)(address - found.Address);
            return true;
        }

        private bool TryFindMappedRegion(ulong address, out MappedRegion found)
        {
            found = null;

            if (Volatile.Read(ref _disposing) != 0 || Volatile.Read(ref _disposed) != 0)
                return false;

            if (_mappedRegions.Count == 0)
                return false;

            int left = 0;
            int right = _mappedRegions.Count - 1;
            int candidate = -1;

            while (left <= right)
            {
                int mid = left + ((right - left) >> 1);
                MappedRegion r = _mappedRegions[mid];
                if (r.Address <= address)
                {
                    candidate = mid;
                    left = mid + 1;
                }
                else
                {
                    right = mid - 1;
                }
            }

            if (candidate < 0)
                return false;

            found = _mappedRegions[candidate];

            if (address < found.Address || address >= found.Address + found.Size)
            {
                found = null;
                return false;
            }

            return true;
        }

        private static bool IsRangeInRegion(ulong address, ulong size, ulong regionBase, ulong regionSize)
        {
            if (size == 0)
                return true;

            ulong regionEnd = regionBase + regionSize;
            if (regionEnd < regionBase)
                return false;

            if (address < regionBase || address >= regionEnd)
                return false;

            ulong remaining = regionEnd - address;
            return size <= remaining;
        }

        private void InsertMappedRegion(MappedRegion Region)
        {
            int Left = 0;
            int Right = _mappedRegions.Count - 1;

            while (Left <= Right)
            {
                int Middle = Left + ((Right - Left) >> 1);
                if (_mappedRegions[Middle].Address < Region.Address)
                    Left = Middle + 1;
                else
                    Right = Middle - 1;
            }

            _mappedRegions.Insert(Left, Region);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposing, 1) == 1)
                return;

            try
            {
                try
                {
                    if (_uc != IntPtr.Zero)
                        uc_emu_stop(_uc);
                }
                catch { }

                _lock.EnterWriteLock();
                try
                {
                    if (_uc != IntPtr.Zero)
                    {
                        List<MappedRegion> mapsSnapshot;
                        lock (_mapsLock)
                        {
                            mapsSnapshot = _mappedRegions.ToList();
                        }

                        foreach (var region in mapsSnapshot)
                        {
                            try { uc_mem_unmap(_uc, region.Address, new UIntPtr(region.Size)); } catch { }
                        }

                        List<IntPtr> hooksSnapshot;
                        lock (_hooksLock)
                        {
                            hooksSnapshot = HooksList.ToList();
                        }

                        foreach (var hook in hooksSnapshot)
                        {
                            try { uc_hook_del(_uc, hook); } catch { }
                            lock (_hooksLock) { HooksList.Remove(hook); }
                        }

                        try { uc_close(_uc); } catch { }
                        _uc = IntPtr.Zero;

                        lock (_mapsLock)
                        {
                            unsafe
                            {
                                _unmapReleasedBuffers.Clear();
                                foreach (var region in _mappedRegions)
                                {
                                    if (region.BufferBase != IntPtr.Zero && !_unmapReleasedBuffers.Contains(region.BufferBase))
                                        _unmapReleasedBuffers.Add(region.BufferBase);
                                }
                                foreach (IntPtr buffer in _unmapReleasedBuffers)
                                    ReleaseBacking(buffer);
                                _unmapReleasedBuffers.Clear();
                                _unmapSurvivors.Clear();
                                _mappedRegions.Clear();

                                foreach (IntPtr ptr in _pendingFrees)
                                    ReleaseBacking(ptr);
                            }
                            _pendingFrees.Clear();
                            _pendingFreeBytes = 0;
                            _bufferSizes.Clear();
                        }
                        lock (_hooksLock) { HooksList.Clear(); }
                    }
                }
                finally
                {
                    _lock.ExitWriteLock();
                }
            }
            finally
            {
                Volatile.Write(ref _disposed, 1);
                GC.SuppressFinalize(this);
            }
        }
    }
}