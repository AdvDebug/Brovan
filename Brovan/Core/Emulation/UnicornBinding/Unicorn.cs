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
        private readonly List<int> _regionIndex = new List<int>();
        private bool _regionIndexDirty = true;
        private readonly List<IntPtr> _pendingFrees = new List<IntPtr>();
        private List<IntPtr> HooksList = new List<IntPtr>();

        private sealed class MappedRegion
        {
            public ulong Address;
            public ulong Size;
            public IntPtr Ptr;
        }

        private readonly struct RegionAddressComparer : IComparer<int>
        {
            private readonly List<MappedRegion> _regions;
            public RegionAddressComparer(List<MappedRegion> regions) => _regions = regions;

            public int Compare(int a, int b)
            {
                ulong aBase = _regions[a].Address;
                ulong bBase = _regions[b].Address;
                return aBase.CompareTo(bBase);
            }
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

        /// <summary>
        /// Map an emulated memory.
        /// </summary>
        /// <param name="address">Address for the mapped memory.</param>
        /// <param name="size">Size of the mapped memory.</param>
        /// <param name="protection">Protection(s) for the mapped memory.</param>
        /// <returns>returns true if successfully mapped, otherwise false.</returns>
        public unsafe bool MapMemory(ulong address, ulong size, MemoryProtection protection)
        {
            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                nuint nativeSize = (nuint)size;
                byte* ptr = (byte*)NativeMemory.AlignedAlloc(nativeSize, 0x1000);
                if (ptr != null)
                {
                    NativeMemory.Clear(ptr, nativeSize);
                    _error = uc_mem_map_ptr(_uc, address, new UIntPtr(size), protection, (IntPtr)ptr);
                    if (_error == UCErrors.UC_ERR_OK)
                    {
                        _mappedRegions.Add(new MappedRegion { Address = address, Size = size, Ptr = (IntPtr)ptr });
                        _regionIndexDirty = true;
                        return true;
                    }
                    NativeMemory.AlignedFree(ptr);
                }

                _error = uc_mem_map(_uc, address, new UIntPtr(size), protection);
                if (_error == UCErrors.UC_ERR_OK)
                {
                    _mappedRegions.Add(new MappedRegion { Address = address, Size = size, Ptr = IntPtr.Zero });
                    _regionIndexDirty = true;
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

                    for (int i = 0; i < _mappedRegions.Count; i++)
                    {
                        if (_mappedRegions[i].Address == address && _mappedRegions[i].Size == size)
                        {
                            if (_mappedRegions[i].Ptr != IntPtr.Zero)
                                _pendingFrees.Add(_mappedRegions[i].Ptr);
                            _mappedRegions.RemoveAt(i);
                            _regionIndexDirty = true;
                            break;
                        }
                    }
                    return true;
                }
            }
            return false;
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
                    BytesRead = 0;
                    for (int i = 0; i + 1 < length; i += 2)
                    {
                        if (Buffer[i] == 0x00 && Buffer[i + 1] == 0x00)
                            break;

                        BytesRead += 2;
                    }

                    if (BytesRead == 0)
                        return string.Empty;

                    if ((BytesRead & 1) != 0)
                        BytesRead--;
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
            if (DisposedCheck())
                return false;

            lock (_registerLock)
            {
                _error = uc_reg_write(_uc, register, ref value);
                return _error == UCErrors.UC_ERR_OK;
            }
        }

        public bool WriteRegister(int Register, ulong Value)
        {
            if (DisposedCheck())
                return false;

            lock (_registerLock)
            {
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
            if (DisposedCheck())
                return 0;

            if (_uc == IntPtr.Zero)
                throw new InvalidOperationException("Unicorn engine is not initialized.");

            ulong value = 0;
            _error = uc_reg_read(_uc, register, out value);
            return value;
        }

        /// <summary>
        /// Read raw register.
        /// </summary>
        /// <param name="Register">Register to read.</param>
        /// <returns>returns the value of the register.</returns>
        public ulong ReadRegister(int Register)
        {
            if (DisposedCheck())
                return 0;

            if (_uc == IntPtr.Zero)
                throw new InvalidOperationException("Unicorn engine is not initialized.");

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
            IntPtr[] toFree;
            lock (_mapsLock)
            {
                if (_pendingFrees.Count == 0)
                    return;
                toFree = _pendingFrees.ToArray();
                _pendingFrees.Clear();
            }
            foreach (IntPtr ptr in toFree)
                NativeMemory.AlignedFree((void*)ptr);
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

        /// <summary>
        /// Make sure that the hook is a whitelisted hook when <see cref="NoHooks"/> are enabled.
        /// </summary>
        /// <returns>returns true if the hook is whitelisted, otherwise false.</returns>
        private static bool IsWhitelistedHookType(Hooks hook)
        {
            switch (hook)
            {
                case Hooks.UC_HOOK_MEM_FETCH_PROT:
                case Hooks.UC_HOOK_MEM_FETCH_UNMAPPED:
                case Hooks.UC_HOOK_MEM_READ_PROT:
                case Hooks.UC_HOOK_MEM_READ_UNMAPPED:
                case Hooks.UC_HOOK_MEM_WRITE_PROT:
                case Hooks.UC_HOOK_MEM_WRITE_UNMAPPED:
                case Hooks.UC_HOOK_INSN_INVALID:
                    return true;

                default:
                    return false;
            }
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

            EnsureRegionIndex();

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

            EnsureRegionIndex();

            if (_regionIndex.Count == 0)
                return false;

            int left = 0;
            int right = _regionIndex.Count - 1;
            int candidate = -1;

            while (left <= right)
            {
                int mid = left + ((right - left) >> 1);
                MappedRegion r = _mappedRegions[_regionIndex[mid]];
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

            found = _mappedRegions[_regionIndex[candidate]];

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

        private void EnsureRegionIndex()
        {
            if (!_regionIndexDirty && _regionIndex.Count == _mappedRegions.Count)
                return;

            _regionIndex.Clear();
            for (int i = 0; i < _mappedRegions.Count; i++)
                _regionIndex.Add(i);

            CollectionsMarshal.AsSpan(_regionIndex).Sort(new RegionAddressComparer(_mappedRegions));
            _regionIndexDirty = false;
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
                                foreach (var region in _mappedRegions)
                                {
                                    if (region.Ptr != IntPtr.Zero)
                                        NativeMemory.AlignedFree((void*)region.Ptr);
                                }
                                _mappedRegions.Clear();
                                _regionIndex.Clear();
                                _regionIndexDirty = true;

                                foreach (IntPtr ptr in _pendingFrees)
                                    NativeMemory.AlignedFree((void*)ptr);
                            }
                            _pendingFrees.Clear();
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
