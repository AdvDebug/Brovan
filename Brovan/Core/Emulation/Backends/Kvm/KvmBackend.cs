using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Brovan.Core.Emulation
{
    public sealed class KvmBackend : IEmulationBackend
    {
        public Kvm Inner { get; }

        public KvmBackend(Arch arch, Mode mode)
        {
            Inner = new Kvm(arch, mode);
            Arch = arch;
            Mode = mode;
        }

        public Arch Arch { get; }
        public Mode Mode { get; }
        public bool Disposed => Inner.Disposed;
        public bool NoHooks { get => Inner.NoHooks; set => Inner.NoHooks = value; }

        public BackendError GetLastError() => TranslateError(Inner.GetLastError());

        public bool MapMemory(ulong address, ulong size, MemoryProtection protection)
            => Inner.MapMemory(address, size, protection);

        public bool UnmapMemory(ulong address, ulong size)
            => Inner.UnmapMemory(address, size);

        public bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection)
            => Inner.SetMemoryProtection(address, size, protection);

        public bool MapMmio(ulong address, ulong size, MmioReadCallback read, MmioWriteCallback write)
            => Inner.MapMmio(address, size, read, write);

        public bool WriteMemory(ulong address, byte[] value, uint length = 0)
            => Inner.WriteMemory(address, value, length);

        public bool WriteMemory(ulong address, byte[] value, int offset, int length)
            => Inner.WriteMemory(address, value, offset, length);

        public bool WriteMemory(ulong address, ReadOnlySpan<byte> value, uint length = 0)
            => Inner.WriteMemory(address, value, length);

        public bool WriteMemory(ulong address, ulong value, uint length = 0)
            => Inner.WriteMemory(address, value, length);

        public bool WriteMemory(ulong address, uint value, uint length = 0)
            => Inner.WriteMemory(address, value, length);

        public bool WriteMemory(ulong address, int value, uint length = 0)
            => Inner.WriteMemory(address, value, length);
        public bool WriteMemory(ulong address, ushort value, uint length = 0)
            => Inner.WriteMemory(address, value, length);
        public bool WriteMemory(ulong address, string value, Encoding encoding)
            => Inner.WriteMemory(address, value, encoding);
        public bool WriteMemoryByte(ulong address, byte value, uint length = 0)
            => Inner.WriteMemoryByte(address, value, length);

        public byte[] ReadMemory(ulong address, ulong length)
            => Inner.ReadMemory(address, length);
        public byte[] ReadMemory(ulong address, uint length)
            => Inner.ReadMemory(address, length);
        public bool ReadMemory(ulong address, Span<byte> value, uint length = 0)
            => Inner.ReadMemory(address, value, length);
        public ulong ReadMemoryULong(ulong address)
            => Inner.ReadMemoryULong(address);
        public uint ReadMemoryUInt(ulong address)
            => Inner.ReadMemoryUInt(address);
        public ushort ReadMemoryUShort(ulong address)
            => Inner.ReadMemoryUShort(address);
        public string ReadMemoryString(ulong address, int length, Encoding encoding)
            => Inner.ReadMemoryString(address, length, encoding);

        public bool WriteRegister(Registers register, ulong value)
            => Inner.WriteRegister(register, value);
        public bool WriteRegister(int register, ulong value)
            => Inner.WriteRegister(register, value);
        public bool WriteRegister32(Registers register, uint value)
            => Inner.WriteRegister32(register, value);
        public bool WriteRegister32(int register, uint value)
            => Inner.WriteRegister32(register, value);
        public bool WriteGdtr(ulong Base, uint Limit)
            => false;
        public bool WriteRegisterByte(Registers register, byte value)
            => Inner.WriteRegisterByte(register, value);
        public bool WriteRegisterByte(int register, byte value)
            => Inner.WriteRegisterByte(register, value);
        public bool WriteRegisterByte(Registers register, byte[] value)
            => Inner.WriteRegisterByte(register, value);

        public ulong ReadRegister(Registers register)
            => Inner.ReadRegister(register);
        public ulong ReadRegister(int register)
            => Inner.ReadRegister(register);
        public uint ReadRegister32(Registers register)
            => Inner.ReadRegister32(register);
        public uint ReadRegister32(int register)
            => Inner.ReadRegister32(register);
        public byte ReadRegisterByte(Registers register)
            => Inner.ReadRegisterByte(register);
        public byte ReadRegisterByte(int register)
            => Inner.ReadRegisterByte(register);

        public CPUFlags GetCPUFlags() => Inner.GetCPUFlags();
        public bool SetCPUFlags(CPUFlags flags) => Inner.SetCPUFlags(flags);

        public bool Emulate(ulong start, ulong end, uint timeout = 0, uint count = 0)
            => Inner.Emulate(start, end, timeout, count);
        public bool StopEmulation() => Inner.StopEmulation();

        public IntPtr AddMemoryHook(ulong begin, ulong end, BackendHookType hookType, MemoryHookCallback callback)
            => Inner.AddMemoryHook(begin, end, hookType, callback);

        public IntPtr AddCodeHook(ulong begin, ulong end, CodeHookCallback callback)
            => Inner.AddCodeHook(begin, end, callback);

        public IntPtr AddInterruptHook(InterruptHookCallback callback)
            => Inner.AddInterruptHook(callback);

        public IntPtr AddInstructionHook(BackendInstructionHook instruction, InstructionHookCallback callback)
            => Inner.AddInstructionHook(instruction, callback);

        public IntPtr AddInstructionBoolHook(BackendInstructionHook instruction, InstructionBoolHookCallback callback)
            => Inner.AddInstructionBoolHook(instruction, callback);

        public bool RemoveHook(IntPtr hook)
            => Inner.RemoveHook(hook);

        public bool RemoveHooks()
            => Inner.RemoveHooks();

        public IntPtr GetHostPointer(ulong address, ulong size)
            => Inner.GetHostPointer(address, size);

        public bool IsRangeMapped(ulong address, ulong size)
            => Inner.IsRangeMapped(address, size);

        public void Dispose()
        {
            Inner?.Dispose();
        }

        private static BackendError TranslateError(KvmErrors e) => e switch
        {
            KvmErrors.Ok => BackendError.None,
            KvmErrors.NoMemory => BackendError.OutOfMemory,
            KvmErrors.InvalidArchitecture => BackendError.InvalidArchitecture,
            KvmErrors.InvalidMode => BackendError.InvalidMode,
            KvmErrors.InvalidArgument => BackendError.InvalidArgument,
            KvmErrors.MemoryReadUnmapped => BackendError.MemoryReadUnmapped,
            KvmErrors.MemoryWriteUnmapped => BackendError.MemoryWriteUnmapped,
            KvmErrors.MemoryFetchUnmapped => BackendError.MemoryFetchUnmapped,
            KvmErrors.MemoryReadProtected => BackendError.MemoryReadProtected,
            KvmErrors.MemoryWriteProtected => BackendError.MemoryWriteProtected,
            KvmErrors.MemoryFetchProtected => BackendError.MemoryFetchProtected,
            KvmErrors.InvalidInstruction => BackendError.InvalidInstruction,
            KvmErrors.HookError => BackendError.HookError,
            KvmErrors.ResourceError => BackendError.ResourceError,
            KvmErrors.Exception => BackendError.Exception,
            _ => BackendError.InternalError,
        };
    }
}
