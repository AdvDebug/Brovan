using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
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
        // local variables used by the class
        private IntPtr _uc;
        private Mode mode;
        private UCErrors _error;
        private List<(ulong, ulong)> Maps = new List<(ulong, ulong)>();
        private List<IntPtr> Hooks = new List<IntPtr>();
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
        public bool MapMemory(ulong address, ulong size, MemoryProtection protection)
        {
            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                _error = uc_mem_map(_uc, address, new UIntPtr(size), protection);
                if (_error == UCErrors.UC_ERR_OK)
                {
                    Maps.Add((address, size));
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
        public bool UnmapMemory(ulong address, ulong size)
        {
            lock (_mapsLock)
            {
                if (DisposedCheck())
                    return false;

                _error = uc_mem_unmap(_uc, address, new UIntPtr(size));
                if (_error == UCErrors.UC_ERR_OK)
                {
                    Maps.Remove((address, size));
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
        public bool WriteMemory(ulong address, byte[] value, uint length = 0)
        {
            if (DisposedCheck())
                return false;

            _lock.EnterReadLock();
            try
            {
                lock (_memoryLock)
                {
                    if (value == null)
                        return false;

                    if (DisposedCheck())
                        return false;

                    if (_uc == IntPtr.Zero)
                        return false;

                    uint writeLen = length == 0 ? (uint)value.Length : length;
                    if (writeLen == 0 || writeLen > (uint)value.Length)
                    {
                        writeLen = (uint)value.Length;
                    }

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

        public bool WriteMemory(ulong Address, byte[] Value, int Offset, int Length)
        {
            if (DisposedCheck())
                return false;

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

                    uint writeLen = length == 0 ? (uint)value.Length : length;
                    if (writeLen == 0 || writeLen > (uint)value.Length)
                        writeLen = (uint)value.Length;

                    if (writeLen == 0)
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
        public byte[] ReadMemory(ulong address, ulong length)
        {
            if (DisposedCheck())
                return Array.Empty<byte>();
            byte[] value = new byte[length];
            _error = uc_mem_read(_uc, address, value, new UIntPtr(length));
            return value;
        }

        /// <summary>
        /// Read a byte array from an emulated memory address.
        /// </summary>
        /// <param name="address">Address to read from.</param>
        /// <param name="length">Length of the data to read.</param>
        /// <returns>returns a byte array containing the data.</returns>
        public byte[] ReadMemory(ulong address, uint length)
        {
            if (DisposedCheck())
                return Array.Empty<byte>();
            if (length > int.MaxValue)
                return null;
            byte[] value = new byte[length];
            _error = uc_mem_read(_uc, address, value, length);
            return value;
        }

        public unsafe bool ReadMemory(ulong address, Span<byte> value, uint length = 0)
        {
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

                    uint ReadLen = length == 0 ? (uint)value.Length : length;
                    if (ReadLen == 0 || ReadLen > (uint)value.Length)
                        ReadLen = (uint)value.Length;

                    if (ReadLen == 0)
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
        public ulong ReadMemoryULong(ulong address)
        {
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
        public uint ReadMemoryUInt(ulong address)
        {
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
        public ushort ReadMemoryUShort(ulong address)
        {
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
        public string ReadMemoryString(ulong address, int length, Encoding encoding)
        {
            if (DisposedCheck())
                return null;

            if (address == 0 || length <= 0)
                return string.Empty;

            byte[] Buffer = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                _error = uc_mem_read(_uc, address, Buffer, (uint)length);
                if (_error != UCErrors.UC_ERR_OK)
                    return string.Empty;

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
            if (!Enum.IsDefined(typeof(Registers), register))
                return 0;

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
                Hooks.Add(Hook);
                return true;
            }
            return false;
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
            if (NoHooks) return true;
            if (DisposedCheck())
                return false;

            IntPtr Hook = IntPtr.Zero;
            _error = uc_hook_add(_uc, out Hook, HookType, ReturnHook, IntPtr.Zero, Begin, End);
            if (_error == UCErrors.UC_ERR_OK)
            {
                Hooks.Add(Hook);
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
            if (NoHooks) return IntPtr.Zero;
            if (DisposedCheck())
                return IntPtr.Zero;

            IntPtr Hook = IntPtr.Zero;
            _error = uc_hook_add(_uc, out Hook, HookType, ReturnHook, IntPtr.Zero, Begin, End);
            if (_error == UCErrors.UC_ERR_OK)
            {
                Hooks.Add(Hook);
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
                Hooks.Remove(Hook);
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
            foreach (IntPtr Hook in Hooks)
            {
                if (uc_hook_del(_uc, Hook) == UCErrors.UC_ERR_OK)
                {
                    Hooks.Remove(Hook);
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
                        List<(ulong Start, ulong Size)> mapsSnapshot;
                        lock (_mapsLock)
                        {
                            mapsSnapshot = Maps.ToList();
                        }

                        foreach (var (Start, Size) in mapsSnapshot)
                        {
                            try { uc_mem_unmap(_uc, Start, new UIntPtr(Size)); } catch { }
                            lock (_mapsLock) { Maps.Remove((Start, Size)); }
                        }

                        List<IntPtr> hooksSnapshot;
                        lock (_hooksLock)
                        {
                            hooksSnapshot = Hooks.ToList();
                        }

                        foreach (var hook in hooksSnapshot)
                        {
                            try { uc_hook_del(_uc, hook); } catch { }
                            lock (_hooksLock) { Hooks.Remove(hook); }
                        }

                        try { uc_close(_uc); } catch { }
                        _uc = IntPtr.Zero;

                        lock (_mapsLock) { Maps.Clear(); }
                        lock (_hooksLock) { Hooks.Clear(); }
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