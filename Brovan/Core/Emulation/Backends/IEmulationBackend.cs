using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using Brovan.Core.Helpers;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

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
    public delegate bool InterruptHookCallback(uint interruptNumber);
    public delegate void InstructionHookCallback();
    public delegate bool InstructionBoolHookCallback();

    public static class ControlRegister4
    {
        public const ulong Pge = 1UL << 7;
        public const ulong Umip = 1UL << 11;
        public const ulong Osxsave = 1UL << 18;
        public const ulong Smep = 1UL << 20;
        public const ulong Smap = 1UL << 21;
    }

    public static class UserModeFlags
    {
        // Ring 3 never gets IOPL, VM, VIF, VIP or reserved bits, and some of them would fail the VM entry.
        public const ulong ClampKeep = 0x254FD5;
        public const ulong ClampSet = 0x202;

        public static ulong Clamp(ulong rflags) => (rflags & ClampKeep) | ClampSet;

        // syscall clears TF, IF, DF, NT and AC on its way into ring 0 (SFMASK).
        public const ulong SyscallEntryMask = 0x44700;
    }

    public static class GuestInterruptGates
    {
        public const byte KernelGateAttributes = 0x8E;
        public const byte UserGateAttributes = 0xEE;

        private const int GateSize = 16;
        private const int GateAttributesOffset = 5;
        private const byte ExceptionIst = 1;
        private const byte DebugIst = 2;
        private const ulong DebugStackOffset = 0x1000;

        public static unsafe void WriteIdtGate(byte* idt, uint vector, ulong handler, ushort selector)
        {
            ulong low = (handler & 0xFFFF)
                      | ((ulong)selector << 16)
                      | ((ulong)IstFor(vector) << 32)
                      | ((ulong)KernelGateAttributes << 40)
                      | (((handler >> 16) & 0xFFFF) << 48);
            Unsafe.WriteUnaligned(idt + vector * GateSize, low);
            Unsafe.WriteUnaligned(idt + vector * GateSize + 8, (uint)(handler >> 32));
        }

        public static unsafe void SetUserGates(byte* idt, uint vectorCount, Func<uint, bool> raisableFromUserMode)
        {
            for (uint vector = 0; vector < vectorCount; vector++)
                idt[vector * GateSize + GateAttributesOffset] = raisableFromUserMode(vector) ? UserGateAttributes : KernelGateAttributes;
        }

        // #DB has its own stack, so one that hits the first instruction of another gate leaves that gate's frame intact.
        private static byte IstFor(uint vector) => vector == 1 ? DebugIst : ExceptionIst;

        private static int TssIstOffset(byte ist) => 0x1C + ist * 8;

        public static ulong DebugStackTop(ulong stackTop) => stackTop - DebugStackOffset;

        public static unsafe void WriteTss(byte* tss, ulong stackTop)
        {
            Unsafe.WriteUnaligned(tss + 0x04, stackTop);
            Unsafe.WriteUnaligned(tss + TssIstOffset(ExceptionIst), stackTop);
            Unsafe.WriteUnaligned(tss + TssIstOffset(DebugIst), DebugStackTop(stackTop));
            Unsafe.WriteUnaligned(tss + 0x66, (ushort)0x68);
        }

        public static bool IsStubEntry(ulong stubPage, uint vectorCount, ulong stride, ulong rip, out uint vector)
        {
            vector = 0;
            ulong offset = rip - stubPage;
            if (rip < stubPage || offset >= vectorCount * stride || offset % stride != 0)
                return false;

            vector = (uint)(offset / stride);
            return true;
        }

        // NT drops a #DB that a mov ss delays onto the first instruction of a user gate (KiDebugTrapOrFault).
        public static unsafe bool IsUserGateEntry(byte* idt, ulong stubPage, uint vectorCount, ulong stride, ulong rip)
            => IsStubEntry(stubPage, vectorCount, stride, rip, out uint vector)
               && idt[vector * GateSize + GateAttributesOffset] == UserGateAttributes;
    }

    // The guest sees the host's own hypervisor leaves, because CPUID always exits under VT-x and its latency gives
    // away a guest that claims bare metal.
    public static class HostHypervisorLeaves
    {
        public const uint FeatureLeaf = 1;
        public const uint PresentBit = 1u << 31;
        public const uint First = 0x40000000;
        public const uint ReservedLast = 0x4FFFFFFF;

        public static readonly bool HostHasHypervisor = X86Base.IsSupported && ((uint)X86Base.CpuId((int)FeatureLeaf, 0).Ecx & PresentBit) != 0;

        public static readonly (uint Eax, uint Ebx, uint Ecx, uint Edx)[] Leaves = ReadLeaves();

        private static (uint Eax, uint Ebx, uint Ecx, uint Edx)[] ReadLeaves()
        {
            if (!HostHasHypervisor)
                return Array.Empty<(uint, uint, uint, uint)>();

            (int a, int b, int c, int d) = X86Base.CpuId(unchecked((int)First), 0);
            uint last = (uint)a;
            if (last < First)
                return Array.Empty<(uint, uint, uint, uint)>();

            var leaves = new (uint Eax, uint Ebx, uint Ecx, uint Edx)[Math.Min(last - First + 1, 0x100u)];
            for (int i = 0; i < leaves.Length; i++)
            {
                if (i != 0)
                    (a, b, c, d) = X86Base.CpuId(unchecked((int)First) + i, 0);
                leaves[i] = ((uint)a, (uint)b, (uint)c, (uint)d);
            }
            return leaves;
        }
    }

    public static class DebugStatus
    {
        public const ulong BreakpointHits = 0xF;
        public const ulong SingleStep = 1UL << 14;
        public const ulong ReservedOnes = 0xFFFF0FF0;
    }

    // Keep DR6 last. Backends cache only the first CachedDebugRegisters.Count registers.
    public static class DebugRegisters
    {
        public const int Count = 6;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int Index(Registers register) => register switch
        {
            Registers.UC_X86_REG_DR0 => 0,
            Registers.UC_X86_REG_DR1 => 1,
            Registers.UC_X86_REG_DR2 => 2,
            Registers.UC_X86_REG_DR3 => 3,
            Registers.UC_X86_REG_DR7 => 4,
            Registers.UC_X86_REG_DR6 => 5,
            _ => -1,
        };

        public static bool IsDebugRegister(Registers register) => Index(register) >= 0;

        public static bool IsDebugBatch(int[] registers, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (Index((Registers)registers[i]) < 0)
                    return false;
            }
            return true;
        }
    }

    public sealed class CachedDebugRegisters
    {
        public const int Count = 5;

        private readonly ulong[] _values = new ulong[Count];

        public bool IsUnchanged(int index, ulong value) => (uint)index < Count && _values[index] == value;

        public bool IsUnchanged(ReadOnlySpan<int> registers, ReadOnlySpan<ulong> values)
        {
            for (int i = 0; i < registers.Length; i++)
            {
                if (!IsUnchanged(DebugRegisters.Index((Registers)registers[i]), values[i]))
                    return false;
            }
            return true;
        }

        public void Note(ReadOnlySpan<int> registers, ReadOnlySpan<ulong> values)
        {
            for (int i = 0; i < registers.Length; i++)
            {
                int index = DebugRegisters.Index((Registers)registers[i]);
                if ((uint)index < Count)
                    _values[index] = values[i];
            }
        }
    }

    public static class RegisterBatch
    {
        public static bool IsValid(int[] registers, ulong[] values, int count)
            => registers != null && values != null && count > 0 && count <= registers.Length && count <= values.Length;
    }

    public static class LongModeAddress
    {
        public static ulong Canonicalize(ulong address) => (ulong)((long)(address << 16) >> 16);

        public static bool IsCanonical(ulong address) => Canonicalize(address) == address;
    }

    public static class InternalPages
    {
        public static bool IsGuestRange(ulong address, ulong size, ulong internalBase)
            => address < internalBase && size <= internalBase - address;
    }

    public static class SyscallTrapPage
    {
        public const ulong CompatSyscallOffset = 32;
    }

    public delegate void GuestKernelFinish(ReadOnlySpan<ulong> saved);

    public interface IGuestKernel
    {
        /// <summary>Registration closes when the guest first runs.</summary>
        bool RegisterSyscall(uint number, string name, Action<GuestKernelCallBuilder> emit, GuestKernelFinish finish);

        bool TryAllocateMemory(ulong size, out ulong address, out IntPtr host);

        /// <summary>The caller keeps the host memory alive until UnmapViews reports the view unmapped.</summary>
        bool TryMapView(IntPtr host, ulong size, out ulong address);

        /// <summary>
        /// Returns only after every processor has left the guest. A false entry in <paramref name="unmapped"/> is a view
        /// the guest can still read, so its host memory must stay alive.
        /// </summary>
        void UnmapViews(ReadOnlySpan<ulong> addresses, Span<bool> unmapped);

        bool Enabled { get; set; }

        IReadOnlyList<GuestKernelCallStats> Stats { get; }
    }

    public readonly record struct GuestKernelCallStats(string Name, ulong Served, ulong Aborted);

    internal sealed class GuestKernelCall
    {
        public uint Number;
        public string Name;
        public Action<GuestKernelCallBuilder> Emit;
        public GuestKernelFinish Finish;
    }

    internal enum GuestKernelCallState
    {
        None,
        Aborted,
        Committed,
        Finishing,
    }

    // A kernel call starts with every register saved and only RCX and R11 changed. It must not change RSP.
    public sealed class GuestKernelCallBuilder
    {
        private readonly ulong _spillAddress;
        private readonly bool _smap;

        internal GuestKernelCallBuilder(Assembler asm, Label abort, ulong spillAddress, ulong userEnd, bool smap)
        {
            Asm = asm;
            Abort = abort;
            _spillAddress = spillAddress;
            UserEnd = userEnd;
            _smap = smap;
        }

        public Assembler Asm { get; }

        public Label Abort { get; }

        public ulong UserEnd { get; }

        internal Label? CommitLabel { get; private set; }

        public void LoadAddress(AssemblerRegister64 target, ulong address) => GuestSyscallStub.Lea(Asm, target, address);

        public void Save(int index, AssemblerRegister64 value)
        {
            if ((uint)index >= GuestSyscallStub.SavedSlots)
                throw new InvalidOperationException("A kernel call saves at most " + GuestSyscallStub.SavedSlots + " values.");

            GuestSyscallStub.Store(Asm, _spillAddress, GuestSyscallStub.SavedSlot + index, value);
        }

        public void BeginUserAccess()
        {
            if (_smap)
                Asm.stac();
        }

        public void EndUserAccess()
        {
            if (_smap)
                Asm.clac();
        }

        // Code before the swap must be safe to run again, because an abort hands the whole call to the host. If the code
        // after it is stopped, the host runs the call's finish.
        public void Commit(AssemblerMemoryOperand target, AssemblerRegister64 newValue, Label lost)
        {
            if (CommitLabel != null)
                throw new InvalidOperationException("A kernel call commits once.");

            Asm.@lock.cmpxchg(target, newValue);
            Label commit = Asm.CreateLabel();
            Asm.Label(ref commit);
            Asm.jnz(lost);
            CommitLabel = commit;
        }
    }

    internal sealed class GuestSyscallStub
    {
        public const int RegisterSlots = 16;
        public const int FrameSlot = RegisterSlots;
        public const int MaxCalls = 64;
        public const uint MaxNumber = 0x2000;

        private const int RaxSlot = 0;
        private const int RcxSlot = 2;
        private const int RdxSlot = 3;
        private const int RspSlot = 6;
        private const int R8Slot = 8;
        private const int R9Slot = 9;
        private const int R10Slot = 10;
        private const int R11Slot = 11;
        private const int FrameRflagsSlot = FrameSlot + 2;
        private const int FrameRspSlot = FrameSlot + 3;
        private const int FrameSlots = 5;
        public const int SavedSlot = FrameSlot + FrameSlots;
        public const int SavedSlots = 3;
        private const int CounterSlot = SavedSlot + SavedSlots;

        private const int FastReturnSlots = 1 << RaxSlot | 1 << RcxSlot | 1 << RdxSlot | 1 << RspSlot | 1 << R8Slot | 1 << R9Slot
            | 1 << R10Slot | 1 << R11Slot;

        private const ulong ZeroFlag = 1UL << 6;
        private const ulong TrapFlag = 1UL << 8;

        // Same order as the WHV and KVM general register blocks.
        private static readonly AssemblerRegister64[] SlotRegisters =
            { rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15 };

        private readonly record struct CallLayout(ulong Body, ulong Commit, ulong Served, ulong Abort, ulong End);

        public ulong HaltOffset { get; private set; }
        public ulong ResumeOffset { get; private set; }
        public ulong ReturnOffset { get; private set; }

        private ulong _dispatchOffset;
        private ulong _fastReturnOffset;
        private ulong _commonAbortOffset;
        private CallLayout[] _calls = Array.Empty<CallLayout>();

        public static int ServedSlot(int call) => CounterSlot + call * 2;

        public static int AbortedSlot(int call) => CounterSlot + call * 2 + 1;

        public static unsafe void CountOutcome(IntPtr spill, int call, GuestKernelCallState state)
            => ((ulong*)spill)[state == GuestKernelCallState.Committed ? ServedSlot(call) : AbortedSlot(call)]++;

        public ushort EntryOffset(int call) => (ushort)_calls[call].Body;

        public static GuestSyscallStub Build(ulong codeAddress, ulong spillAddress, ulong tableAddress,
            IReadOnlyList<GuestKernelCall> calls, ulong userEnd, bool smap, bool alwaysSpill, out ArraySegment<byte> code)
        {
            Assembler a = new Assembler(64);
            Label start = a.CreateLabel();
            Label dispatch = a.CreateLabel();
            Label reload = a.CreateLabel();
            Label halt = a.CreateLabel();
            Label resume = a.CreateLabel();
            Label iret = a.CreateLabel();
            Label fastReturn = a.CreateLabel();
            Label commonAbort = a.CreateLabel();
            Label callsEnd = a.CreateLabel();

            if (alwaysSpill || calls.Count != 0)
            {
                a.Label(ref start);
                for (int slot = 0; slot < RegisterSlots; slot++)
                    Store(a, spillAddress, slot, SlotRegisters[slot]);
            }

            if (calls.Count != 0)
            {
                // A set TF goes to the host, because NT raises the single step before the next user instruction.
                a.Label(ref dispatch);
                a.test(r11d, (int)TrapFlag);
                a.jnz(halt);
                a.mov(r11d, eax);
                a.cmp(r11d, (int)MaxNumber);
                a.jae(reload);
                Lea(a, rcx, tableAddress);
                a.movzx(r11d, __word_ptr[rcx + r11 * 2]);
                a.test(r11d, r11d);
                a.jz(reload);
                a.lea(rcx, __[start]);
                a.add(r11, rcx);
                a.jmp(r11);

                a.Label(ref reload);
                Load(a, spillAddress, RcxSlot, rcx);
                Load(a, spillAddress, R11Slot, r11);
            }

            a.Label(ref halt);
            a.hlt();

            a.Label(ref resume);
            Lea(a, rsp, SlotAddress(spillAddress, FrameSlot));
            LoadSlotsExcept(a, spillAddress, 1 << RspSlot);
            a.Label(ref iret);
            a.iretq();

            Label[] served = new Label[calls.Count];
            Label[] aborts = new Label[calls.Count];
            Label[] bodies = new Label[calls.Count];
            Label[] commits = new Label[calls.Count];
            if (calls.Count != 0)
            {
                a.Label(ref fastReturn);
                Load(a, spillAddress, RcxSlot, rcx);
                Store(a, spillAddress, FrameSlot, rcx);
                Load(a, spillAddress, R11Slot, r11);
                a.mov(rax, r11);
                a.and(rax, (int)UserModeFlags.ClampKeep);
                a.or(rax, (int)UserModeFlags.ClampSet);
                Store(a, spillAddress, FrameRflagsSlot, rax);
                a.mov(r8, rsp);
                Store(a, spillAddress, FrameRspSlot, r8);
                Lea(a, rsp, SlotAddress(spillAddress, FrameSlot));
                LoadSlotsExcept(a, spillAddress, FastReturnSlots);
                a.xor(edx, edx);
                a.xor(r9d, r9d);
                a.xor(r10d, r10d);
                a.xor(eax, eax);
                a.iretq();

                a.Label(ref commonAbort);
                if (smap)
                    a.clac();
                LoadSlotsExcept(a, spillAddress, 1 << RspSlot);
                a.jmp(halt);

                for (int i = 0; i < calls.Count; i++)
                {
                    served[i] = a.CreateLabel();
                    aborts[i] = a.CreateLabel();
                    bodies[i] = a.CreateLabel();

                    a.Label(ref bodies[i]);
                    GuestKernelCallBuilder builder = new GuestKernelCallBuilder(a, aborts[i], spillAddress, userEnd, smap);
                    calls[i].Emit(builder);
                    commits[i] = builder.CommitLabel ?? throw new InvalidOperationException($"Kernel call {calls[i].Name} never commits.");

                    a.Label(ref served[i]);
                    Increment(a, spillAddress, ServedSlot(i));
                    a.jmp(fastReturn);
                    a.Label(ref aborts[i]);
                    Increment(a, spillAddress, AbortedSlot(i));
                    a.jmp(commonAbort);
                }

                a.Label(ref callsEnd);
                a.int3();
            }

            MemoryStream stream = new MemoryStream();
            AssemblerResult result = a.Assemble(new StreamCodeWriter(stream), codeAddress, BlockEncoderOptions.ReturnNewInstructionOffsets);
            code = new ArraySegment<byte>(stream.GetBuffer(), 0, (int)stream.Length);

            GuestSyscallStub stub = new GuestSyscallStub
            {
                HaltOffset = result.GetLabelRIP(halt) - codeAddress,
                ResumeOffset = result.GetLabelRIP(resume) - codeAddress,
                ReturnOffset = result.GetLabelRIP(iret) - codeAddress,
            };

            if (calls.Count == 0)
                return stub;

            stub._dispatchOffset = result.GetLabelRIP(dispatch) - codeAddress;
            stub._fastReturnOffset = result.GetLabelRIP(fastReturn) - codeAddress;
            stub._commonAbortOffset = result.GetLabelRIP(commonAbort) - codeAddress;
            stub._calls = new CallLayout[calls.Count];
            for (int i = 0; i < calls.Count; i++)
            {
                stub._calls[i] = new CallLayout(
                    Body: result.GetLabelRIP(bodies[i]) - codeAddress,
                    Commit: result.GetLabelRIP(commits[i]) - codeAddress,
                    Served: result.GetLabelRIP(served[i]) - codeAddress,
                    Abort: result.GetLabelRIP(aborts[i]) - codeAddress,
                    End: (i + 1 < calls.Count ? result.GetLabelRIP(bodies[i + 1]) : result.GetLabelRIP(callsEnd)) - codeAddress);
            }

            return stub;
        }

        // The call index comes back only while the stub has not counted the outcome itself.
        public GuestKernelCallState Classify(ulong offset, ulong rflags, out int call)
        {
            call = -1;
            if (_calls.Length == 0)
                return GuestKernelCallState.None;

            if (offset >= _dispatchOffset && offset < HaltOffset)
                return GuestKernelCallState.Aborted;

            if (offset >= _fastReturnOffset && offset < _commonAbortOffset)
                return GuestKernelCallState.Committed;

            if (offset >= _commonAbortOffset && offset < _calls[0].Body)
                return GuestKernelCallState.Aborted;

            for (int i = 0; i < _calls.Length; i++)
            {
                ref readonly CallLayout layout = ref _calls[i];
                if (offset < layout.Body || offset >= layout.End)
                    continue;

                if (offset >= layout.Abort)
                {
                    call = offset == layout.Abort ? i : -1;
                    return GuestKernelCallState.Aborted;
                }
                if (offset >= layout.Served)
                {
                    call = offset == layout.Served ? i : -1;
                    return GuestKernelCallState.Committed;
                }

                call = i;

                // A stop between the cmpxchg and its jnz has the result of the swap only in ZF.
                if (offset == layout.Commit)
                    return (rflags & ZeroFlag) != 0 ? GuestKernelCallState.Finishing : GuestKernelCallState.Aborted;

                return offset > layout.Commit ? GuestKernelCallState.Finishing : GuestKernelCallState.Aborted;
            }

            return GuestKernelCallState.None;
        }

        private static MemoryOperand At(ulong address) => new MemoryOperand(Register.RIP, (long)address, 8);

        private static ulong SlotAddress(ulong spillAddress, int slot) => spillAddress + (ulong)slot * 8;

        internal static void Lea(Assembler a, AssemblerRegister64 register, ulong address)
            => a.AddInstruction(Instruction.Create(Code.Lea_r64_m, register.Value, At(address)));

        private static void Load(Assembler a, ulong spillAddress, int slot, AssemblerRegister64 register)
            => a.AddInstruction(Instruction.Create(Code.Mov_r64_rm64, register.Value, At(SlotAddress(spillAddress, slot))));

        internal static void Store(Assembler a, ulong spillAddress, int slot, AssemblerRegister64 register)
            => a.AddInstruction(Instruction.Create(Code.Mov_rm64_r64, At(SlotAddress(spillAddress, slot)), register.Value));

        private static void Increment(Assembler a, ulong spillAddress, int slot)
            => a.AddInstruction(Instruction.Create(Code.Inc_rm64, At(SlotAddress(spillAddress, slot))));

        private static void LoadSlotsExcept(Assembler a, ulong spillAddress, int skippedSlots)
        {
            for (int slot = 0; slot < RegisterSlots; slot++)
            {
                if ((skippedSlots & (1 << slot)) == 0)
                    Load(a, spillAddress, slot, SlotRegisters[slot]);
            }
        }
    }

    internal interface IGuestKernelBackend
    {
        bool DisposedCheck();

        ulong AllocateKernelRange(ulong size, bool writable, out IntPtr host);

        bool MapKernelView(IntPtr host, ulong address, ulong size);

        bool UnmapKernelView(ulong address, ulong size);

        IntPtr EnsureKernelPageDirectory(ulong address);

        void EvictProcessors();
    }

    internal sealed class GuestKernelHost : IGuestKernel
    {
        private const ulong PageSize = 0x1000;
        private const ulong PageMask = PageSize - 1;
        private const ulong Present = 1UL << 0;
        private const ulong LargePage = 1UL << 7;
        private const ulong NoExecute = 1UL << 63;
        private const ulong ViewWindowOffset = 0x4_0000_0000UL;
        private const ulong ViewChunk = 2UL << 20;

        // 32 GB covers the largest MemoryBudget view budget and ends below the 512 GB of a 39-bit physical address.
        private const int ViewChunks = 16384;

        private readonly record struct StubPages(ulong Code, IntPtr CodeHost, ulong Spill, IntPtr SpillHost);

        private readonly IGuestKernelBackend _backend;
        private readonly ulong _internalBase;
        private readonly ushort _userCodeSelector;
        private readonly ushort _userDataSelector;
        private readonly bool _smap;
        private readonly bool _alwaysSpill;
        private readonly List<GuestKernelCall> _calls = new();
        private bool[] _viewChunksUsed;
        private readonly Dictionary<ulong, ulong> _views = new();
        private StubPages[] _stubs = Array.Empty<StubPages>();
        private ulong _tableAddress;
        private IntPtr _tableHost;
        private bool _sealed;
        private bool _enabled = true;

        public GuestKernelHost(IGuestKernelBackend backend, ulong internalBase, ushort userCodeSelector, ushort userDataSelector,
            bool smap, bool alwaysSpill)
        {
            _backend = backend;
            _internalBase = internalBase;
            _userCodeSelector = userCodeSelector;
            _userDataSelector = userDataSelector;
            _smap = smap;
            _alwaysSpill = alwaysSpill;
        }

        public GuestSyscallStub Layout { get; private set; }

        public void AddProcessor(ulong code, IntPtr codeHost, ulong spill, IntPtr spillHost)
        {
            StubPages stub = new StubPages(code, codeHost, spill, spillHost);
            WriteStub(stub);
            Volatile.Write(ref _stubs, [.. _stubs, stub]);
        }

        // Every guest run calls this, so the flag is written only once to keep its cache line shared.
        public void Seal()
        {
            if (!_sealed)
                _sealed = true;
        }

        public bool RegisterSyscall(uint number, string name, Action<GuestKernelCallBuilder> emit, GuestKernelFinish finish)
        {
            if (_backend.DisposedCheck() || _sealed || emit == null || number >= GuestSyscallStub.MaxNumber
                || _calls.Count >= GuestSyscallStub.MaxCalls || IsCallNumber(number))
                return false;

            if (_tableAddress == 0)
                _tableAddress = _backend.AllocateKernelRange(GuestSyscallStub.MaxNumber * sizeof(ushort), false, out _tableHost);

            _calls.Add(new GuestKernelCall { Number = number, Name = name, Emit = emit, Finish = finish });
            try
            {
                foreach (StubPages stub in _stubs)
                    WriteStub(stub);
            }
            catch (InvalidOperationException ex)
            {
                _calls.RemoveAt(_calls.Count - 1);
                Utils.LogError($"[GuestKernel] Kernel call {name} does not fit the syscall stub: {ex.Message}");
                return false;
            }

            WriteTable();
            return true;
        }

        private bool IsCallNumber(uint number)
        {
            for (int i = 0; i < _calls.Count; i++)
            {
                if (_calls[i].Number == number)
                    return true;
            }

            return false;
        }

        // Aborted means the host runs the syscall from the spilled registers, Committed that it only returns to user mode.
        public unsafe GuestKernelCallState Settle(IntPtr spill, ulong offset, ulong rflags)
        {
            GuestKernelCallState state = Layout.Classify(offset, rflags, out int call);
            if (state == GuestKernelCallState.Finishing)
            {
                _calls[call].Finish?.Invoke(new ReadOnlySpan<ulong>((ulong*)spill + GuestSyscallStub.SavedSlot, GuestSyscallStub.SavedSlots));
                state = GuestKernelCallState.Committed;
            }

            if (call >= 0)
                GuestSyscallStub.CountOutcome(spill, call, state);
            return state;
        }

        // Every processor's stub has the same layout, so the last build serves all of them.
        private unsafe void WriteStub(StubPages stub)
        {
            GuestSyscallStub layout = GuestSyscallStub.Build(stub.Code, stub.Spill, _tableAddress, _calls, _internalBase, _smap,
                _alwaysSpill, out ArraySegment<byte> code);
            if ((ulong)code.Count > PageSize)
                throw new InvalidOperationException("The syscall stub does not fit in its page.");

            code.AsSpan().CopyTo(new Span<byte>((void*)stub.CodeHost, code.Count));
            Layout = layout;

            // Only a stub that spills returns through this frame, so other spill pages stay demand-zero.
            if (_alwaysSpill || _calls.Count != 0)
            {
                ulong* frame = (ulong*)stub.SpillHost + GuestSyscallStub.FrameSlot;
                frame[1] = _userCodeSelector;
                frame[4] = _userDataSelector;
            }
        }

        public bool Enabled
        {
            get => _enabled;
            set
            {
                if (_enabled == value)
                    return;

                _enabled = value;
                WriteTable();
            }
        }

        private unsafe void WriteTable()
        {
            ushort* table = (ushort*)_tableHost;
            for (int i = 0; i < _calls.Count; i++)
                table[_calls[i].Number] = _enabled ? Layout.EntryOffset(i) : (ushort)0;
        }

        public bool TryAllocateMemory(ulong size, out ulong address, out IntPtr host)
        {
            address = 0;
            host = IntPtr.Zero;
            if (_backend.DisposedCheck() || size == 0)
                return false;

            address = _backend.AllocateKernelRange(size, true, out host);
            return true;
        }

        public bool TryMapView(IntPtr host, ulong size, out ulong address)
        {
            address = 0;
            if (_backend.DisposedCheck() || host == IntPtr.Zero || size == 0 || ((ulong)host.ToInt64() & PageMask) != 0)
                return false;

            ulong mapSize = (size + PageMask) & ~PageMask;
            int chunks = ChunkCount(mapSize);
            if (chunks > ViewChunks || !TryReserveChunks(chunks, out int first))
                return false;

            // The host memory is mapped last, so no failure here leaves it mapped.
            ulong view = _internalBase + ViewWindowOffset + (ulong)first * ViewChunk;
            int mapped = 0;
            while (mapped < chunks && TryMapChunk(view + (ulong)mapped * ViewChunk))
                mapped++;

            if (mapped == chunks && _backend.MapKernelView(host, view, mapSize))
            {
                _views[view] = mapSize;
                address = view;
                return true;
            }

            Array.Clear(_viewChunksUsed, first, chunks);
            return false;
        }

        public void UnmapViews(ReadOnlySpan<ulong> addresses, Span<bool> unmapped)
        {
            unmapped.Fill(true);
            if (_backend.DisposedCheck() || addresses.IsEmpty)
                return;

            _backend.EvictProcessors();
            for (int i = 0; i < addresses.Length; i++)
            {
                if (!_views.TryGetValue(addresses[i], out ulong mapSize))
                    continue;

                if (!_backend.UnmapKernelView(addresses[i], mapSize))
                {
                    unmapped[i] = false;
                    continue;
                }

                _views.Remove(addresses[i]);
                Array.Clear(_viewChunksUsed, ChunkIndex(addresses[i]), ChunkCount(mapSize));
            }
        }

        public unsafe IReadOnlyList<GuestKernelCallStats> Stats
        {
            get
            {
                StubPages[] stubs = Volatile.Read(ref _stubs);
                GuestKernelCallStats[] stats = new GuestKernelCallStats[_calls.Count];
                for (int call = 0; call < stats.Length; call++)
                {
                    ulong served = 0, aborted = 0;
                    for (int i = 0; i < stubs.Length; i++)
                    {
                        ulong* spill = (ulong*)stubs[i].SpillHost;
                        served += Volatile.Read(ref spill[GuestSyscallStub.ServedSlot(call)]);
                        aborted += Volatile.Read(ref spill[GuestSyscallStub.AbortedSlot(call)]);
                    }

                    stats[call] = new GuestKernelCallStats(_calls[call].Name, served, aborted);
                }

                return stats;
            }
        }

        private static int ChunkCount(ulong mapSize) => (int)((mapSize + ViewChunk - 1) / ViewChunk);

        private int ChunkIndex(ulong view) => (int)((view - _internalBase - ViewWindowOffset) / ViewChunk);

        private bool TryReserveChunks(int count, out int first)
        {
            bool[] used = _viewChunksUsed ??= new bool[ViewChunks];
            int run = 0;
            for (int i = 0; i < ViewChunks; i++)
            {
                if (used[i])
                {
                    run = 0;
                    continue;
                }

                if (++run < count)
                    continue;

                first = i - count + 1;
                Array.Fill(used, true, first, count);
                return true;
            }

            first = 0;
            return false;
        }

        // The view can end inside the 2 MB page, and kernel calls never read past its length.
        private unsafe bool TryMapChunk(ulong address)
        {
            ulong* directory = (ulong*)_backend.EnsureKernelPageDirectory(address);
            if (directory == null)
                return false;

            Volatile.Write(ref directory[(address >> 21) & 0x1FF], address | Present | LargePage | NoExecute);
            return true;
        }
    }

    public interface IEmulationBackend : IDisposable
    {
        Arch Arch { get; }
        Mode Mode { get; }
        bool Disposed { get; }
        bool NoHooks { get; set; }

        BackendError GetLastError();

        /// <summary>
        /// Highest guest address the backend can map. Hypervisor backends are bound by the partition's
        /// guest physical address space, which is narrower than the guest's own address space.
        /// </summary>
        ulong MaxMappableAddress { get; }

        /// <summary>
        /// True when RDTSC reads the emulator's clock, through the instruction hook or a counter the backend
        /// computes from that clock. A backend that runs the instruction on the real CPU returns the host TSC.
        /// </summary>
        bool TimestampCounterIsEmulated { get; }

        /// <summary>
        /// Rate of the counter RDTSC reads when the backend runs it on the real CPU, or zero when the
        /// counter is emulated or the rate is unknown.
        /// </summary>
        ulong TimestampCounterFrequency => 0;

        bool TryReadTimestampCounter(out ulong value)
        {
            value = 0;
            return false;
        }

        bool MapMemory(ulong address, ulong size, MemoryProtection protection);

        /// <summary>
        /// Maps memory that is already backed by <paramref name="hostPointer"/>, so the same host pages are
        /// visible at more than one guest address.
        /// </summary>
        bool MapMemoryShared(ulong address, ulong size, MemoryProtection protection, IntPtr hostPointer);

        /// <summary>
        /// The storage lives until <see cref="ReleaseSharedStorage"/> is called and the last mapping is gone.
        /// </summary>
        IntPtr AllocateSharedStorage(ulong size);

        /// <summary>
        /// Uses host memory the caller mapped as shared storage. The backend disposes <paramref name="owner"/>
        /// where it would free the memory. On failure the caller keeps the memory.
        /// </summary>
        IntPtr AdoptSharedStorage(IntPtr hostPointer, ulong size, IDisposable owner);

        void ReleaseSharedStorage(IntPtr storage);

        bool UnmapMemory(ulong address, ulong size);
        bool SetMemoryProtection(ulong address, ulong size, MemoryProtection protection);

        /// <summary>
        /// Records guest and host writes to the mapped pages of the range. The first access of a new page counts
        /// as a write when its protection allows writes. Watching a page again keeps its record, unmapping ends it.
        /// </summary>
        bool WatchWrites(ulong address, ulong size, MemoryProtection protection) => false;

        /// <summary>
        /// Sets bit i of <paramref name="written"/> when page i is watched and written since its watch or reset,
        /// and clears the other bits.
        /// </summary>
        bool QueryWrites(ulong address, ulong pageCount, Span<ulong> written) => false;

        /// <summary>
        /// Marks the pages whose bit is set in <paramref name="pages"/> as not written. Later writes on any
        /// processor are recorded.
        /// </summary>
        bool ResetWrites(ulong address, ulong pageCount, ReadOnlySpan<ulong> pages) => false;

        /// <summary>
        /// Discards any cached translation of the range. Only a translating backend has work to do here.
        /// </summary>
        bool InvalidateCodeRange(ulong address, ulong size) => true;

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
            if (!RegisterBatch.IsValid(registers, values, count))
                return false;

            for (int i = 0; i < count; i++)
                values[i] = ReadRegister(registers[i]);
            return true;
        }

        bool ReadXmmRegisters(ulong[] values) => false;

        bool WriteXmmRegisters(ulong[] values) => false;

        bool SupportsAvx => false;

        bool ReadVectorState(ulong[] xmm, ulong[] ymmHigh)
        {
            if (ymmHigh != null) System.Array.Clear(ymmHigh);
            return ReadXmmRegisters(xmm);
        }

        bool WriteVectorState(ulong[] xmm, ulong[] ymmHigh) => WriteXmmRegisters(xmm);

        bool ReadX87State(ulong[] registers, ref ulong statusWord, ref ulong tagWord) => false;

        bool WriteX87State(ulong[] registers, ulong statusWord, ulong tagWord) => false;

        /// <summary>
        /// True when the backend can keep a guest thread's register file resident in its own processor,
        /// so switching to that thread transfers no state.
        /// </summary>
        bool SupportsThreadResidency => false;

        int ProcessorLimit => 1;

        bool TryBindThread(uint threadId) => false;

        void UnbindThread(uint threadId)
        {
        }

        bool IsThreadResident(uint threadId) => false;

        void SelectThread(uint threadId)
        {
        }

        /// <summary>
        /// Shortens the running slice so it ends within <paramref name="microseconds"/>. False when the
        /// backend has no bounded slice to shorten, in which case the caller has to stop the slice itself.
        /// </summary>
        bool TryLimitSlice(int microseconds) => false;

        /// <summary>
        /// The lock the caller holds around <see cref="Emulate"/>. A backend releases it only for the time
        /// the guest runs.
        /// </summary>
        void UseRunLock(object runLock)
        {
        }

        /// <summary>Ends the slice of the thread's processor, not the thread.</summary>
        void StopThread(uint threadId)
        {
        }

        void StopAllProcessors()
        {
        }

        /// <summary>No processor is in the guest on return, until the caller releases the run lock.</summary>
        void HoldProcessorsOutOfGuest()
        {
        }

        IGuestKernel GuestKernel => null;

        /// <summary>
        /// Answers RDTSC inside the backend from the emulator's clock. False when the backend has no such path.
        /// </summary>
        bool ConfigureEmulatedTimestampCounter(long hostStart, long hostFrequency, long qpcFrequency, ulong tscPerQpc, long skewCounts) => false;

        bool WriteRegisterBatch(int[] registers, ulong[] values, int count)
        {
            if (!RegisterBatch.IsValid(registers, values, count))
                return false;

            for (int i = 0; i < count; i++)
                WriteRegister(registers[i], values[i]);
            return true;
        }

        void SetSyscallReturnRegisters(ulong ReturnRip)
        {
            WriteRegister(Registers.UC_X86_REG_RCX, ReturnRip);
            WriteRegister(Registers.UC_X86_REG_R11, ReadRegister(Registers.UC_X86_REG_RFLAGS));
            WriteRegister(Registers.UC_X86_REG_R8, ReadRegister(Registers.UC_X86_REG_RSP));
            WriteRegister(Registers.UC_X86_REG_RDX, 0UL);
            WriteRegister(Registers.UC_X86_REG_R9, 0UL);
            WriteRegister(Registers.UC_X86_REG_R10, 0UL);
        }

        CPUFlags GetCPUFlags();
        bool SetCPUFlags(CPUFlags flags);

        bool Emulate(ulong start, ulong end, uint timeout = 0, uint count = 0);
        bool StopEmulation();

        IntPtr AddMemoryHook(ulong begin, ulong end, BackendHookType hookType, MemoryHookCallback callback);
        IntPtr AddCodeHook(ulong begin, ulong end, CodeHookCallback callback);
        IntPtr AddInterruptHook(InterruptHookCallback callback);

        uint InterruptErrorCode => 0;

        bool UmipEnabled => false;

        /// <summary>All gates start closed, and int n through a closed gate raises #GP.</summary>
        void SetUserInterruptGates(Func<uint, bool> raisableFromUserMode)
        {
        }

        IntPtr AddInstructionHook(BackendInstructionHook instruction, InstructionHookCallback callback);
        IntPtr AddInstructionBoolHook(BackendInstructionHook instruction, InstructionBoolHookCallback callback);
        bool RemoveHook(IntPtr hook);
        bool RemoveHooks();

        bool IsRangeMapped(ulong address, ulong size);

        /// <summary>
        /// Reuse translated guest code from a previous run. Called once execution is about
        /// to begin, because a backend that verifies restored code against guest memory
        /// needs the image mapped first. Backends that do not translate do nothing.
        /// </summary>
        void RestoreCodeCache();

        /// <summary>
        /// Cheap periodic follow-up to <see cref="RestoreCodeCache"/>, called from the
        /// scheduler while the guest runs. Returns once there is nothing left to do.
        /// </summary>
        void ResolveCodeCache();

        /// <summary>
        /// Persist translated guest code. Called with the guest stopped.
        /// </summary>
        void PersistCodeCache();
    }
}
