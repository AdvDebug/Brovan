using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

namespace Brovan.Core.Emulation
{
    public sealed class UnicornBackend : IEmulationBackend
    {
        public Unicorn Inner { get; }

        public UnicornBackend(Arch arch, Mode mode, string guestImagePath = null, string hostImagePath = null)
        {
            // Has to precede uc_open. the code cache reserves the address range that the
            // translation buffer and the uc struct are then carved out of.
            UnicornCodeCache.Configure(guestImagePath, hostImagePath);

            Inner = new Unicorn(arch, mode);
            Arch = arch;
            Mode = mode;
        }

        public Arch Arch { get; }
        public Mode Mode { get; }
        public bool Disposed => Inner.Disposed;
        public bool NoHooks { get => Inner.NoHooks; set => Inner.NoHooks = value; }

        public BackendError GetLastError() => TranslateError(Inner.GetLastError());

        public ulong MaxMappableAddress => ulong.MaxValue;

        public bool TimestampCounterIsEmulated => true;

        public bool MapMemory(ulong address, ulong size, MemoryProtection protection)
            => Inner.MapMemory(address, size, protection);

        public bool MapMemoryShared(ulong address, ulong size, MemoryProtection protection, System.IntPtr hostPointer)
            => Inner.MapMemoryShared(address, size, protection, hostPointer);
        public bool UnmapMemory(ulong address, ulong size)
            => Inner.UnmapMemory(address, size);
        public bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection)
            => Inner.SetMemoryProtection(address, size, protection);
        public bool InvalidateCodeRange(ulong address, ulong size)
            => Inner.InvalidateCodeRange(address, size);

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
            => Inner.WriteGdtr(Base, Limit);
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

        public bool ReadRegisterBatch(int[] registers, ulong[] values, int count)
            => Inner.ReadRegisterBatch(registers, values, count);
        public bool WriteRegisterBatch(int[] registers, ulong[] values, int count)
            => Inner.WriteRegisterBatch(registers, values, count);
        public bool ReadXmmRegisters(ulong[] values)
            => Inner.TransferXmmRegisters(values, false);
        public bool WriteXmmRegisters(ulong[] values)
            => Inner.TransferXmmRegisters(values, true);

        public CPUFlags GetCPUFlags() => Inner.GetCPUFlags();
        public bool SetCPUFlags(CPUFlags flags) => Inner.SetCPUFlags(flags);

        public bool ConfigureEmulatedTimestampCounter(long hostStart, long hostFrequency, long qpcFrequency, ulong tscPerQpc, long skewCounts)
            => Inner.ConfigureTimestampCounter(hostStart, hostFrequency, qpcFrequency, tscPerQpc, skewCounts);

        public bool Emulate(ulong start, ulong end, uint timeout = 0, uint count = 0)
        {
            _armedBudget = count;
            _sliceLimit = count;
            _sliceStart = Stopwatch.GetTimestamp();
            bool Result = Inner.Emulate(start, end, timeout, count);
            UpdateInstructionRate();
            return Result;
        }

        private uint _armedBudget;
        private uint _sliceLimit;
        private long _sliceStart;
        private double _instructionsPerMicrosecond = 200;
        private const int MinimumLimitInstructions = 4000;
        private const long RateSampleInstructions = 20_000;
        private const double RateSampleMicroseconds = 100;

        // A short slice is mostly slice cost and syscall time, so only long ones feed the rate. Pause
        // charges count against the budget, so a short slice can also read as a very high rate.
        private unsafe void UpdateInstructionRate()
        {
            int* Budget = Inner.BudgetPointer;
            if (_armedBudget == 0 || Budget == null)
                return;

            int Remaining = *Budget;
            long Consumed = Remaining < 0 ? _sliceLimit : (long)_sliceLimit - Remaining;
            double Microseconds = (Stopwatch.GetTimestamp() - _sliceStart) * 1_000_000.0 / Stopwatch.Frequency;
            if (Consumed < RateSampleInstructions || Microseconds < RateSampleMicroseconds)
                return;

            _instructionsPerMicrosecond = _instructionsPerMicrosecond * 0.9 + (Consumed / Microseconds) * 0.1;
        }

        // The budget only counts in a hook-free run.
        public unsafe bool TryLimitSlice(int microseconds)
        {
            int* Budget = Inner.BudgetPointer;
            if (!NoHooks || _armedBudget == 0 || Budget == null)
                return false;

            double Wanted = microseconds * _instructionsPerMicrosecond;
            int Limit = Wanted >= int.MaxValue / 2 ? int.MaxValue / 2 : Math.Max(MinimumLimitInstructions, (int)Wanted);
            if (*Budget > Limit)
            {
                *Budget = Limit;
                _sliceLimit = (uint)Limit;
            }
            return true;
        }

        public bool StopEmulation() => Inner.StopEmulation();

        public IntPtr AddMemoryHook(ulong begin, ulong end, BackendHookType hookType, MemoryHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            var thunk = new MemoryThunk(callback);
            IntPtr handle = Inner.AddHookWithHandle(begin, end, TranslateHookType(hookType), thunk.NativePtr);
            if (handle == IntPtr.Zero) return IntPtr.Zero;
            _liveThunks[handle] = thunk;
            return handle;
        }

        public IntPtr AddCodeHook(ulong begin, ulong end, CodeHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            var thunk = new CodeThunk(callback);
            IntPtr handle = Inner.AddHookWithHandle(begin, end, Hooks.UC_HOOK_CODE, thunk.NativePtr);
            if (handle == IntPtr.Zero) return IntPtr.Zero;
            _liveThunks[handle] = thunk;
            return handle;
        }

        public IntPtr AddInterruptHook(InterruptHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            var thunk = new InterruptThunk(callback);
            IntPtr handle = Inner.AddHookWithHandle(1, 0, Hooks.UC_HOOK_INTR, thunk.NativePtr);
            if (handle == IntPtr.Zero) return IntPtr.Zero;
            _liveThunks[handle] = thunk;
            return handle;
        }

        public IntPtr AddInstructionHook(BackendInstructionHook instruction, InstructionHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            var thunk = new InstructionThunk(callback);
            if (instruction == BackendInstructionHook.Invalid)
            {
                IntPtr handle = Inner.AddHookWithHandle(0, 1, Hooks.UC_HOOK_INSN_INVALID, thunk.NativePtr);
                if (handle == IntPtr.Zero) return IntPtr.Zero;
                _liveThunks[handle] = thunk;
                return handle;
            }
            if (!Inner.AddHook(TranslateInstructionHook(instruction), thunk.NativePtr))
                return IntPtr.Zero;
            IntPtr key = thunk.NativePtr;
            _liveThunks[key] = thunk;
            return key;
        }

        public IntPtr AddInstructionBoolHook(BackendInstructionHook instruction, InstructionBoolHookCallback callback)
        {
            if (callback == null) return IntPtr.Zero;
            var thunk = new InstructionBoolThunk(callback);
            if (!Inner.AddHook(TranslateInstructionHook(instruction), thunk.NativePtr))
                return IntPtr.Zero;
            IntPtr key = thunk.NativePtr;
            _liveThunks[key] = thunk;
            return key;
        }

        public bool RemoveHook(IntPtr hook)
        {
            if (_liveThunks.TryGetValue(hook, out var thunk))
            {
                _liveThunks.Remove(hook);
                thunk.Dispose();
            }
            return Inner.RemoveHook(hook);
        }

        public bool RemoveHooks()
        {
            foreach (var thunk in _liveThunks.Values)
                thunk.Dispose();
            _liveThunks.Clear();
            return Inner.RemoveHooks();
        }

        public bool IsRangeMapped(ulong address, ulong size)
            => Inner.IsRangeMapped(address, size);

        public IntPtr GetHostPointer(ulong address, ulong size)
            => Inner.GetHostPointer(address, size);

        public void Dispose()
        {
            foreach (var thunk in _liveThunks.Values)
                thunk.Dispose();
            _liveThunks.Clear();
            Inner?.Dispose();
        }

        public static bool IsCFGEnabled() => Unicorn.IsCFGEnabled();

        private static BackendError TranslateError(UCErrors e) => e switch
        {
            UCErrors.UC_ERR_OK => BackendError.None,
            UCErrors.UC_ERR_NOMEM => BackendError.OutOfMemory,
            UCErrors.UC_ERR_ARCH => BackendError.InvalidArchitecture,
            UCErrors.UC_ERR_MODE => BackendError.InvalidMode,
            UCErrors.UC_ERR_ARG => BackendError.InvalidArgument,
            UCErrors.UC_ERR_READ_UNMAPPED => BackendError.MemoryReadUnmapped,
            UCErrors.UC_ERR_WRITE_UNMAPPED => BackendError.MemoryWriteUnmapped,
            UCErrors.UC_ERR_FETCH_UNMAPPED => BackendError.MemoryFetchUnmapped,
            UCErrors.UC_ERR_READ_PROT => BackendError.MemoryReadProtected,
            UCErrors.UC_ERR_WRITE_PROT => BackendError.MemoryWriteProtected,
            UCErrors.UC_ERR_FETCH_PROT => BackendError.MemoryFetchProtected,
            UCErrors.UC_ERR_INSN_INVALID => BackendError.InvalidInstruction,
            UCErrors.UC_ERR_HOOK => BackendError.HookError,
            UCErrors.UC_ERR_RESOURCE => BackendError.ResourceError,
            UCErrors.UC_ERR_EXCEPTION => BackendError.Exception,
            _ => BackendError.InternalError,
        };

        private static Hooks TranslateHookType(BackendHookType t)
        {
            Hooks h = 0;
            if ((t & BackendHookType.MemoryReadUnmapped) != 0) h |= Hooks.UC_HOOK_MEM_READ_UNMAPPED;
            if ((t & BackendHookType.MemoryWriteUnmapped) != 0) h |= Hooks.UC_HOOK_MEM_WRITE_UNMAPPED;
            if ((t & BackendHookType.MemoryFetchUnmapped) != 0) h |= Hooks.UC_HOOK_MEM_FETCH_UNMAPPED;
            if ((t & BackendHookType.MemoryReadProtected) != 0) h |= Hooks.UC_HOOK_MEM_READ_PROT;
            if ((t & BackendHookType.MemoryWriteProtected) != 0) h |= Hooks.UC_HOOK_MEM_WRITE_PROT;
            if ((t & BackendHookType.MemoryFetchProtected) != 0) h |= Hooks.UC_HOOK_MEM_FETCH_PROT;
            if ((t & BackendHookType.MemoryRead) != 0) h |= Hooks.UC_HOOK_MEM_READ;
            if ((t & BackendHookType.MemoryWrite) != 0) h |= Hooks.UC_HOOK_MEM_WRITE;
            if ((t & BackendHookType.MemoryFetch) != 0) h |= Hooks.UC_HOOK_MEM_FETCH;
            if ((t & BackendHookType.MemoryReadAfter) != 0) h |= Hooks.UC_HOOK_MEM_READ_AFTER;
            return h;
        }

        private static INSTHooks TranslateInstructionHook(BackendInstructionHook i) => i switch
        {
            BackendInstructionHook.CpuId => INSTHooks.UC_X86_INS_CPUID,
            BackendInstructionHook.In => INSTHooks.UC_X86_INS_IN,
            BackendInstructionHook.Out => INSTHooks.UC_X86_INS_OUT,
            BackendInstructionHook.Rdtsc => INSTHooks.UC_X86_INS_RDTSC,
            BackendInstructionHook.Rdtscp => INSTHooks.UC_X86_INS_RDTSCP,
            BackendInstructionHook.Syscall => INSTHooks.UC_X86_INS_SYSCALL,
            BackendInstructionHook.Sysenter => INSTHooks.UC_X86_INS_SYSENTER,
            BackendInstructionHook.Hlt => INSTHooks.UC_X86_INS_HLT,
            _ => throw new ArgumentOutOfRangeException(nameof(i), i, null),
        };

        private static BackendMemoryAccessType TranslateMemoryType(MemoryType t) => t switch
        {
            MemoryType.UC_MEM_READ => BackendMemoryAccessType.Read,
            MemoryType.UC_MEM_WRITE => BackendMemoryAccessType.Write,
            MemoryType.UC_MEM_FETCH => BackendMemoryAccessType.Fetch,
            MemoryType.UC_MEM_READ_UNMAPPED => BackendMemoryAccessType.ReadUnmapped,
            MemoryType.UC_MEM_WRITE_UNMAPPED => BackendMemoryAccessType.WriteUnmapped,
            MemoryType.UC_MEM_FETCH_UNMAPPED => BackendMemoryAccessType.FetchUnmapped,
            MemoryType.UC_MEM_WRITE_PROT => BackendMemoryAccessType.WriteProtected,
            MemoryType.UC_MEM_READ_PROT => BackendMemoryAccessType.ReadProtected,
            MemoryType.UC_MEM_FETCH_PROT => BackendMemoryAccessType.FetchProtected,
            MemoryType.UC_MEM_READ_AFTER => BackendMemoryAccessType.ReadAfter,
            _ => BackendMemoryAccessType.Read,
        };

        private interface IHookThunk : IDisposable
        {
            IntPtr NativePtr { get; }
        }

        private delegate bool NativeMemoryDelegate(IntPtr uc, MemoryType type, ulong address, uint size, ulong value, IntPtr userData);
        private delegate void NativeCodeDelegate(IntPtr uc, ulong address, uint size, IntPtr userData);
        private delegate void NativeInterruptDelegate(IntPtr uc, uint interruptNumber);
        private delegate void NativeInstructionDelegate(IntPtr uc, IntPtr userData);
        private delegate bool NativeInstructionBoolDelegate(IntPtr uc, IntPtr userData);

        private sealed class MemoryThunk : IHookThunk
        {
            private readonly MemoryHookCallback _user;
            private readonly NativeMemoryDelegate _thunk;
            private GCHandle _selfPin;
            public IntPtr NativePtr { get; }

            public MemoryThunk(MemoryHookCallback user)
            {
                _user = user;
                _thunk = (_, type, address, size, value, _) => _user(TranslateMemoryType(type), address, size, value);
                _selfPin = GCHandle.Alloc(this);
                NativePtr = Marshal.GetFunctionPointerForDelegate(_thunk);
            }
            public void Dispose() { if (_selfPin.IsAllocated) _selfPin.Free(); }
        }

        private sealed class CodeThunk : IHookThunk
        {
            private readonly CodeHookCallback _user;
            private readonly NativeCodeDelegate _thunk;
            private GCHandle _selfPin;
            public IntPtr NativePtr { get; }

            public CodeThunk(CodeHookCallback user)
            {
                _user = user;
                _thunk = (_, address, size, _) => _user(address, size);
                _selfPin = GCHandle.Alloc(this);
                NativePtr = Marshal.GetFunctionPointerForDelegate(_thunk);
            }
            public void Dispose() { if (_selfPin.IsAllocated) _selfPin.Free(); }
        }

        private sealed class InterruptThunk : IHookThunk
        {
            private readonly InterruptHookCallback _user;
            private readonly NativeInterruptDelegate _thunk;
            private GCHandle _selfPin;
            public IntPtr NativePtr { get; }

            public InterruptThunk(InterruptHookCallback user)
            {
                _user = user;
                _thunk = (_, intno) => _user(intno);
                _selfPin = GCHandle.Alloc(this);
                NativePtr = Marshal.GetFunctionPointerForDelegate(_thunk);
            }
            public void Dispose() { if (_selfPin.IsAllocated) _selfPin.Free(); }
        }

        private sealed class InstructionThunk : IHookThunk
        {
            private readonly InstructionHookCallback _user;
            private readonly NativeInstructionDelegate _thunk;
            private GCHandle _selfPin;
            public IntPtr NativePtr { get; }

            public InstructionThunk(InstructionHookCallback user)
            {
                _user = user;
                _thunk = (_, _) => _user();
                _selfPin = GCHandle.Alloc(this);
                NativePtr = Marshal.GetFunctionPointerForDelegate(_thunk);
            }
            public void Dispose() { if (_selfPin.IsAllocated) _selfPin.Free(); }
        }

        private sealed class InstructionBoolThunk : IHookThunk
        {
            private readonly InstructionBoolHookCallback _user;
            private readonly NativeInstructionBoolDelegate _thunk;
            private GCHandle _selfPin;
            public IntPtr NativePtr { get; }

            public InstructionBoolThunk(InstructionBoolHookCallback user)
            {
                _user = user;
                _thunk = (_, _) => _user();
                _selfPin = GCHandle.Alloc(this);
                NativePtr = Marshal.GetFunctionPointerForDelegate(_thunk);
            }
            public void Dispose() { if (_selfPin.IsAllocated) _selfPin.Free(); }
        }

        private readonly Dictionary<IntPtr, IHookThunk> _liveThunks = new();

        public void RestoreCodeCache() => UnicornCodeCache.TryLoad(Inner);

        public void ResolveCodeCache() => UnicornCodeCache.ResolvePending(Inner);

        public void PersistCodeCache() => UnicornCodeCache.TrySave(Inner);
    }
}
