using System.Text;

namespace Brovan.Core.Emulation
{
    public enum EmulationBackendKind
    {
        Unicorn = 0,
        Kvm = 1,
        Whp = 2,
    }

    public enum BackendError
    {
        None = 0,
        InvalidArgument,
        InvalidArchitecture,
        InvalidMode,
        OutOfMemory,
        MemoryReadUnmapped,
        MemoryWriteUnmapped,
        MemoryFetchUnmapped,
        MemoryReadProtected,
        MemoryWriteProtected,
        MemoryFetchProtected,
        InvalidInstruction,
        HookError,
        ResourceError,
        Exception,
        InternalError,
    }

    [Flags]
    public enum BackendHookType : uint
    {
        MemoryReadUnmapped = 1 << 4,
        MemoryWriteUnmapped = 1 << 5,
        MemoryFetchUnmapped = 1 << 6,
        MemoryReadProtected = 1 << 7,
        MemoryWriteProtected = 1 << 8,
        MemoryFetchProtected = 1 << 9,
        MemoryRead = 1 << 10,
        MemoryWrite = 1 << 11,
        MemoryFetch = 1 << 12,
        MemoryReadAfter = 1 << 13,
        MemoryUnmapped = MemoryReadUnmapped | MemoryWriteUnmapped | MemoryFetchUnmapped,
        MemoryProtected = MemoryReadProtected | MemoryWriteProtected | MemoryFetchProtected,
    }

    public enum BackendMemoryAccessType
    {
        Read = 0,
        Write,
        Fetch,
        ReadUnmapped,
        WriteUnmapped,
        FetchUnmapped,
        WriteProtected,
        ReadProtected,
        FetchProtected,
        ReadAfter,
    }

    public enum BackendInstructionHook
    {
        CpuId,
        In,
        Out,
        Rdtsc,
        Rdtscp,
        Syscall,
        Sysenter,
        Hlt,
        Invalid,
    }

    public delegate bool MemoryHookCallback(BackendMemoryAccessType type, ulong address, uint size, ulong value);
    public delegate void MmioReadCallback(ulong offset, Span<byte> destination);
    public delegate void MmioWriteCallback(ulong offset, ReadOnlySpan<byte> data);
    public delegate void CodeHookCallback(ulong address, uint size);
    public delegate void InterruptHookCallback(uint interruptNumber);
    public delegate void InstructionHookCallback();
    public delegate bool InstructionBoolHookCallback();

    public interface IEmulationBackend : IDisposable
    {
        Arch Arch { get; }
        Mode Mode { get; }
        bool Disposed { get; }
        bool NoHooks { get; set; }

        BackendError GetLastError();

        bool MapMemory(ulong address, ulong size, MemoryProtection protection);
        bool UnmapMemory(ulong address, ulong size);
        bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection);

        bool MapMmio(ulong address, ulong size, MmioReadCallback read, MmioWriteCallback write) => false;

        IntPtr GetHostPointer(ulong address, ulong size) => IntPtr.Zero;
        bool WriteMemory(ulong address, byte[] value, uint length = 0);
        bool WriteMemory(ulong address, byte[] value, int offset, int length);
        bool WriteMemory(ulong address, ReadOnlySpan<byte> value, uint length = 0);
        bool WriteMemory(ulong address, ulong value, uint length = 0);
        bool WriteMemory(ulong address, uint value, uint length = 0);
        bool WriteMemory(ulong address, int value, uint length = 0);
        bool WriteMemory(ulong address, ushort value, uint length = 0);
        bool WriteMemory(ulong address, string value, Encoding encoding);
        bool WriteMemoryByte(ulong address, byte value, uint length = 0);

        byte[] ReadMemory(ulong address, ulong length);
        byte[] ReadMemory(ulong address, uint length);
        bool ReadMemory(ulong address, Span<byte> value, uint length = 0);
        ulong ReadMemoryULong(ulong address);
        uint ReadMemoryUInt(ulong address);
        ushort ReadMemoryUShort(ulong address);
        string ReadMemoryString(ulong address, int length, Encoding encoding);

        bool WriteRegister(Registers register, ulong value);
        bool WriteRegister(int register, ulong value);
        bool WriteRegister32(Registers register, uint value);
        bool WriteRegister32(int register, uint value);

        bool WriteGdtr(ulong Base, uint Limit);
        bool WriteRegisterByte(Registers register, byte value);
        bool WriteRegisterByte(int register, byte value);
        bool WriteRegisterByte(Registers register, byte[] value);

        ulong ReadRegister(Registers register);
        ulong ReadRegister(int register);
        uint ReadRegister32(Registers register);
        uint ReadRegister32(int register);
        byte ReadRegisterByte(Registers register);
        byte ReadRegisterByte(int register);

        bool ReadRegisterBatch(int[] registers, ulong[] values, int count)
        {
            if (registers == null || values == null || count <= 0 || count > registers.Length || count > values.Length)
                return false;

            for (int i = 0; i < count; i++)
                values[i] = ReadRegister(registers[i]);
            return true;
        }

        bool WriteRegisterBatch(int[] registers, ulong[] values, int count)
        {
            if (registers == null || values == null || count <= 0 || count > registers.Length || count > values.Length)
                return false;

            for (int i = 0; i < count; i++)
                WriteRegister(registers[i], values[i]);
            return true;
        }

        CPUFlags GetCPUFlags();
        bool SetCPUFlags(CPUFlags flags);

        bool Emulate(ulong start, ulong end, uint timeout = 0, uint count = 0);
        bool StopEmulation();

        IntPtr AddMemoryHook(ulong begin, ulong end, BackendHookType hookType, MemoryHookCallback callback);
        IntPtr AddCodeHook(ulong begin, ulong end, CodeHookCallback callback);
        IntPtr AddInterruptHook(InterruptHookCallback callback);
        IntPtr AddInstructionHook(BackendInstructionHook instruction, InstructionHookCallback callback);
        IntPtr AddInstructionBoolHook(BackendInstructionHook instruction, InstructionBoolHookCallback callback);
        bool RemoveHook(IntPtr hook);
        bool RemoveHooks();

        bool IsRangeMapped(ulong address, ulong size);
    }
}
