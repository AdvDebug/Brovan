using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtGetContextThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong ContextPtr = Instance.WinHelper.GetArg(1);

            EmulatedThread Thread = WindowsThreadContext64.ResolveThread(Instance, ThreadHandle);
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!WindowsThreadContext64.HasThreadAccess(Instance, ThreadHandle, AccessMask.ThreadGetContext))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            NTSTATUS Status = WindowsThreadContext64.TryReadContextFlags(Instance, ContextPtr, out uint Flags);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WaitUntilParked(Thread))
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadContext64.WriteContext(Instance, Thread, ContextPtr, Flags, ContextSource.SyscallReturn);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal enum ContextSource
    {
        Processor,
        SavedContext,
        // NT reports a thread in a system call at its return address.
        SyscallReturn,
    }

    /// <summary>
    /// Shared x64 and x86 CONTEXT helpers for native thread-context syscalls.
    /// </summary>
    internal static class WindowsThreadContext64
    {
        internal const uint CONTEXT_AMD64 = 0x00100000;
        internal const uint CONTEXT_CONTROL = 0x00000001;
        internal const uint CONTEXT_INTEGER = 0x00000002;
        internal const uint CONTEXT_SEGMENTS = 0x00000004;
        internal const uint CONTEXT_FLOATING_POINT = 0x00000008;
        internal const uint CONTEXT_DEBUG_REGISTERS = 0x00000010;
        internal const uint CONTEXT_XSTATE = 0x00000040;
        internal const uint CONTEXT_EXTENDED_REGISTERS = 0x00000020;

        internal const uint CONTEXT_I386 = 0x00010000;

        internal const ulong ContextFlagsOffset = 0x30;
        internal const ulong MinimumContextSize = 0x100;
        internal const ulong MinimumContextSize32 = 0x2CC;

        // NT reports fixed user selectors here, not the ones the thread holds (KeContextFromKframes).
        // FS is the 32-bit TEB selector even on x64.
        private const ulong UserSegmentSelectors = WindowsGuest.NtUserDataSelector | WindowsGuest.NtUserDataSelector << 16
            | WindowsGuest.NtUserTebSelector32 << 32 | WindowsGuest.NtUserDataSelector << 48;

        // A selector below ring 3 belongs to the backend, so NT's user selector is reported instead.
        private static ulong UserSelector(ulong Selector, ulong NtSelector) => (Selector & 3) == 3 ? Selector : NtSelector;

        private const ulong FltSaveOffset = 0x100;
        private const int FltSaveSize = 0x200;
        private const ulong FloatSaveOffset32 = 0x1C;
        private const int FloatSaveSize32 = 0x70;
        private const ulong ExtendedRegistersOffset32 = 0xCC;
        // The 32-bit FXSAVE image ends after XMM7.
        private const int ExtendedRegistersSize32 = 0x120;
        internal const ulong ContextExOffset = 0x4D0;
        internal const int ContextExSize = 0x20;
        private const int XStateHeaderSize = 64;
        // XSAVE header plus YMM_Hi128. x87 and SSE state stay in FltSave.
        internal const int XStateAreaSize = XStateHeaderSize + 256;
        private const ulong XcrAvx = 0x4;
        private const ulong XcrAvxFeatures = 0x7;
        private const int VectorQwords = 32;
        private const int VectorQwords32 = 16;

        [ThreadStatic] private static ulong[] _xmmScratch;
        [ThreadStatic] private static ulong[] _ymmScratch;
        [ThreadStatic] private static CpuContext _liveScratch;
        private static ulong[] XmmScratch => _xmmScratch ??= new ulong[VectorQwords];
        private static ulong[] YmmScratch => _ymmScratch ??= new ulong[VectorQwords];
        private static readonly CpuContext NoContext = new();

        internal static bool XStateEnabled(BinaryEmulator Instance)
            => Instance.WinHelper.PointerSize == 8 && Instance._emulator.SupportsAvx;

        private static bool IsCurrent(BinaryEmulator Instance, EmulatedThread Thread)
            => Thread != null && Instance.CurrentThread is EmulatedThread Current && Thread.ThreadId == Current.ThreadId;

        // The x87 stack is reported empty, and the area is already zeroed.
        private static void FillFltSave(Span<byte> Area, ulong[] Xmm, int XmmQwords, ulong MxCsr, ulong Fpcw, ulong Fpsw)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Area.Slice(0x00, 2), (ushort)Fpcw);
            BinaryPrimitives.WriteUInt16LittleEndian(Area.Slice(0x02, 2), (ushort)Fpsw);
            BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x18, 4), (uint)MxCsr);
            BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x1C, 4), 0xFFFF);
            for (int i = 0; i < XmmQwords; i++)
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xA0 + i * 8, 8), Xmm[i]);
        }

        // The CONTEXT_EX ntdll builds (InitializeContext2).
        private static void WriteContextEx(Span<byte> Context, ulong XStateAreaOffset)
        {
            Span<byte> Ex = Context.Slice((int)ContextExOffset, ContextExSize);
            BinaryPrimitives.WriteInt32LittleEndian(Ex.Slice(0x00, 4), -(int)ContextExOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Ex.Slice(0x04, 4), (uint)(XStateAreaOffset + (ulong)XStateAreaSize));
            BinaryPrimitives.WriteInt32LittleEndian(Ex.Slice(0x08, 4), -(int)ContextExOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Ex.Slice(0x0C, 4), (uint)ContextExOffset);
            BinaryPrimitives.WriteInt32LittleEndian(Ex.Slice(0x10, 4), (int)(XStateAreaOffset - ContextExOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(Ex.Slice(0x14, 4), (uint)XStateAreaSize);
        }

        private static Span<byte> FrameSlice(Span<byte> Frame, ulong ContextPtr, ulong Address, int Length)
        {
            ulong Offset = Address - ContextPtr;
            return !Frame.IsEmpty && Address >= ContextPtr && Offset + (ulong)Length <= (ulong)Frame.Length
                ? Frame.Slice((int)Offset, Length)
                : Span<byte>.Empty;
        }

        // ntdll sets the header mask to the features the CONTEXT asks for (InitializeContext2).
        private static void WriteXStateHeader(BinaryEmulator Instance, ulong ContextPtr, ulong Area, Span<byte> Frame)
        {
            Span<byte> InPlace = FrameSlice(Frame, ContextPtr, Area, XStateHeaderSize);
            bool InFrame = !InPlace.IsEmpty;
            Span<byte> Header = InFrame ? InPlace : stackalloc byte[XStateHeaderSize];
            BinaryPrimitives.WriteUInt64LittleEndian(Header, XcrAvxFeatures);
            if (!InFrame)
                Instance.WriteMemory(Area, Header);
        }

        // CONTEXT_EX chunk offsets count from the CONTEXT_EX itself, the way ntdll reads them.
        internal static bool TryLocateXStateArea(BinaryEmulator Instance, ulong ContextPtr, out ulong Area)
        {
            Area = 0;
            ulong ContextEx = ContextPtr + ContextExOffset;
            if (!Instance.IsRegionMapped(ContextEx, (ulong)ContextExSize))
                return false;

            int AllOffset = (int)Instance.ReadMemoryUInt(ContextEx + 0x00);
            uint AllLength = Instance.ReadMemoryUInt(ContextEx + 0x04);
            int XStateOffset = (int)Instance.ReadMemoryUInt(ContextEx + 0x10);
            uint XStateLength = Instance.ReadMemoryUInt(ContextEx + 0x14);
            if (XStateOffset < AllOffset || (long)AllOffset + AllLength < (long)XStateOffset + XStateLength)
                return false;
            if (XStateLength < (uint)XStateAreaSize)
                return false;

            Area = (ulong)((long)ContextEx + XStateOffset);
            return Instance.IsRegionMapped(Area, (ulong)XStateAreaSize);
        }

        // A clear AVX bit in XSTATE_BV is the init state, so the upper halves read as zero.
        internal static void ReadXStateArea(BinaryEmulator Instance, ulong Area, ulong[] YmmHigh)
        {
            if ((Instance.ReadMemoryULong(Area) & XcrAvx) == 0)
            {
                Array.Clear(YmmHigh);
                return;
            }

            Span<byte> Bytes = stackalloc byte[VectorQwords * 8];
            Instance._emulator.ReadMemory(Area + (ulong)XStateHeaderSize, Bytes, (uint)Bytes.Length);
            for (int i = 0; i < VectorQwords; i++)
                YmmHigh[i] = BinaryPrimitives.ReadUInt64LittleEndian(Bytes.Slice(i * 8, 8));
        }

        // XSTATE_BV reports the features present, and the upper halves count as present only when one
        // of them is nonzero. XCOMP_BV stays zero for the standard layout.
        private static void WriteXStateArea(BinaryEmulator Instance, ulong ContextPtr, ulong Area, ulong[] YmmHigh, ulong Mask, Span<byte> Frame)
        {
            Span<byte> InPlace = FrameSlice(Frame, ContextPtr, Area, XStateAreaSize);
            bool InFrame = !InPlace.IsEmpty;
            Span<byte> Bytes = InFrame ? InPlace : stackalloc byte[XStateAreaSize];

            bool AvxLive = false;
            for (int i = 0; i < VectorQwords && !AvxLive; i++)
                AvxLive = YmmHigh[i] != 0;

            ulong StateMask = Mask & 0x3;
            if ((Mask & XcrAvx) != 0 && AvxLive)
                StateMask |= XcrAvx;
            BinaryPrimitives.WriteUInt64LittleEndian(Bytes.Slice(0, 8), StateMask);

            if ((Mask & XcrAvx) != 0)
            {
                for (int i = 0; i < VectorQwords; i++)
                    BinaryPrimitives.WriteUInt64LittleEndian(Bytes.Slice(XStateHeaderSize + i * 8, 8), YmmHigh[i]);
            }

            if (!InFrame)
                Instance.WriteMemory(Area, Bytes);
        }

        private static void WriteContextVectorState(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags,
            ulong Fpcw, ulong Fpsw, ulong MxCsr, ulong XStateArea, bool FromSavedContext, Span<byte> Frame)
        {
            bool WantXmm = (Flags & CONTEXT_FLOATING_POINT) != 0;
            bool WantYmm = (Flags & CONTEXT_XSTATE) != 0 && XStateEnabled(Instance);
            if (!WantXmm && !WantYmm)
                return;

            ulong[] Xmm = XmmScratch;
            ulong[] YmmHigh = WantYmm ? YmmScratch : null;
            if (!Instance.ReadThreadVectorState(Thread, Xmm, YmmHigh, FromSavedContext))
            {
                if (WantYmm && XStateArea != 0)
                    WriteXStateHeader(Instance, ContextPtr, XStateArea, Frame);
                return;
            }

            Span<byte> FltSaveInFrame = FrameSlice(Frame, ContextPtr, ContextPtr + FltSaveOffset, FltSaveSize);
            if (WantXmm && (!FltSaveInFrame.IsEmpty || Instance.IsRegionMapped(ContextPtr + FltSaveOffset, (ulong)FltSaveSize)))
            {
                Span<byte> Area = FltSaveInFrame.IsEmpty ? stackalloc byte[FltSaveSize] : FltSaveInFrame;
                FillFltSave(Area, Xmm, VectorQwords, MxCsr, Fpcw, Fpsw);
                if (FltSaveInFrame.IsEmpty)
                    Instance.WriteMemory(ContextPtr + FltSaveOffset, Area);
            }

            if (!WantYmm)
                return;

            if (XStateArea != 0)
                WriteXStateArea(Instance, ContextPtr, XStateArea, YmmHigh, XcrAvxFeatures, Frame);
            else if (TryLocateXStateArea(Instance, ContextPtr, out ulong Located))
                WriteXStateArea(Instance, ContextPtr, Located, YmmHigh, Instance.ReadMemoryULong(Located), Frame);
        }

        /// <returns>True when FPCW, FPSW and MXCSR were applied with the FltSave.</returns>
        private static bool ApplyVectorState(BinaryEmulator Instance, EmulatedThread Thread, bool IsCurrentThread, ulong ContextPtr, ReadOnlySpan<byte> Header,
            uint Flags)
        {
            bool HaveXmm = (Flags & CONTEXT_FLOATING_POINT) != 0 && Instance.IsRegionMapped(ContextPtr + FltSaveOffset, (ulong)FltSaveSize);
            ulong XStateArea = 0;
            bool HaveYmm = (Flags & CONTEXT_XSTATE) != 0 && XStateEnabled(Instance) && TryLocateXStateArea(Instance, ContextPtr, out XStateArea);
            if (!HaveXmm && !HaveYmm)
                return false;

            ulong[] Xmm = XmmScratch;
            ulong[] YmmHigh = YmmScratch;
            if (!(HaveXmm && HaveYmm) && !Instance.ReadThreadVectorState(Thread, Xmm, YmmHigh))
                return false;

            if (HaveXmm)
            {
                Span<byte> Area = stackalloc byte[FltSaveSize];
                Instance._emulator.ReadMemory(ContextPtr + FltSaveOffset, Area, (uint)FltSaveSize);
                for (int i = 0; i < VectorQwords; i++)
                    Xmm[i] = BinaryPrimitives.ReadUInt64LittleEndian(Area.Slice(0xA0 + i * 8, 8));

                ulong Fpcw = BinaryPrimitives.ReadUInt16LittleEndian(Area.Slice(0x00, 2));
                ulong Fpsw = BinaryPrimitives.ReadUInt16LittleEndian(Area.Slice(0x02, 2));
                ulong MxCsr = SanitizeMxCsr(BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x34)));
                Thread.Context.FPCW = Fpcw;
                Thread.Context.FPSW = Fpsw;
                Thread.Context.MXCSR = MxCsr;
                if (IsCurrentThread)
                    Instance.WriteFpControl(Fpcw, Fpsw, MxCsr);
            }

            if (HaveYmm)
                ReadXStateArea(Instance, XStateArea, YmmHigh);

            Instance.WriteThreadVectorState(Thread, Xmm, YmmHigh);
            return HaveXmm;
        }

        // FLOATING_SAVE_AREA gets only the control and status words, with an empty x87 stack.
        private static void WriteContextVectorState32(BinaryEmulator Instance, EmulatedThread Thread, bool IsCurrentThread, bool FromSavedContext,
            ulong ContextPtr, uint Flags, Span<byte> Frame)
        {
            bool WantFloat = (Flags & CONTEXT_FLOATING_POINT) != 0;
            bool WantExtended = (Flags & CONTEXT_EXTENDED_REGISTERS) != 0;
            if (Thread == null || (!WantFloat && !WantExtended))
                return;

            ReadFpControl(Instance, Thread.Context, IsCurrentThread, out ulong Fpcw, out ulong Fpsw, out ulong MxCsr);

            if (WantFloat)
            {
                Span<byte> InPlace = FrameSlice(Frame, ContextPtr, ContextPtr + FloatSaveOffset32, FloatSaveSize32);
                Span<byte> Area = InPlace.IsEmpty ? stackalloc byte[FloatSaveSize32] : InPlace;
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x00, 4), (ushort)Fpcw);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x04, 4), (ushort)Fpsw);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x08, 4), 0xFFFF);
                if (InPlace.IsEmpty)
                    Instance.WriteMemory(ContextPtr + FloatSaveOffset32, Area);
            }

            if (WantExtended && Instance.ReadThreadVectorState(Thread, XmmScratch, null, FromSavedContext))
            {
                Span<byte> InPlace = FrameSlice(Frame, ContextPtr, ContextPtr + ExtendedRegistersOffset32, ExtendedRegistersSize32);
                Span<byte> Area = InPlace.IsEmpty ? stackalloc byte[ExtendedRegistersSize32] : InPlace;
                FillFltSave(Area, XmmScratch, VectorQwords32, MxCsr, Fpcw, Fpsw);
                if (InPlace.IsEmpty)
                    Instance.WriteMemory(ContextPtr + ExtendedRegistersOffset32, Area);
            }
        }

        // ExtendedRegisters wins over FLOATING_SAVE_AREA when both are set.
        private static void ApplyVectorState32(BinaryEmulator Instance, EmulatedThread Thread, bool IsCurrentThread, ulong ContextPtr, ReadOnlySpan<byte> Header, uint Flags)
        {
            CpuContext Context = Thread.Context;

            if ((Flags & CONTEXT_EXTENDED_REGISTERS) == 0 || !Instance.ReadThreadVectorState(Thread, XmmScratch, YmmScratch))
            {
                if ((Flags & CONTEXT_FLOATING_POINT) != 0)
                {
                    Context.FPCW = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice((int)FloatSaveOffset32));
                    Context.FPSW = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice((int)FloatSaveOffset32 + 4));
                    if (IsCurrentThread)
                        Instance.WriteFpControl(Context.FPCW, Context.FPSW, null);
                }
                return;
            }

            Span<byte> Area = stackalloc byte[ExtendedRegistersSize32];
            Instance._emulator.ReadMemory(ContextPtr + ExtendedRegistersOffset32, Area, (uint)Area.Length);
            for (int i = 0; i < VectorQwords32; i++)
                XmmScratch[i] = BinaryPrimitives.ReadUInt64LittleEndian(Area.Slice(0xA0 + i * 8, 8));

            Context.FPCW = BinaryPrimitives.ReadUInt16LittleEndian(Area.Slice(0x00, 2));
            Context.FPSW = BinaryPrimitives.ReadUInt16LittleEndian(Area.Slice(0x02, 2));
            Context.MXCSR = SanitizeMxCsr(BinaryPrimitives.ReadUInt32LittleEndian(Area.Slice(0x18, 4)));
            if (IsCurrentThread)
                Instance.WriteFpControl(Context.FPCW, Context.FPSW, Context.MXCSR);
            Instance.WriteThreadVectorState(Thread, XmmScratch, YmmScratch);
        }

        // The WOW64 CPU area also keeps AC. The NT flag is dropped because it faults natively.
        private static ulong SanitizeEFlags(ulong EFlags, bool InCpuArea) => (EFlags & (InCpuArea ? 0x250DD5UL : 0x210DD5UL)) | 0x202;

        // Bits above MXCSR_MASK fault when loaded.
        private static ulong SanitizeMxCsr(ulong MxCsr) => MxCsr & 0xFFFF;

        private static ulong SanitizeRip(ulong Rip) => LongModeAddress.Canonicalize(Rip);

        // NT zeroes a breakpoint address above the user range.
        private static ulong SanitizeDebugAddress(ulong Address)
            => Address <= NtWow64GetNativeSystemInformation.NativeMaximumUserModeAddress ? Address : 0;

        private const ulong Dr7LocalEnables = 0x55;
        private const ulong Dr7LocalExact = 0x100;
        private const ulong Dr7GlobalExact = 0x200;
        private const ulong Dr7Enables = Dr7LocalEnables | Dr7LocalExact | Dr7GlobalExact;
        private const ulong Dr7ReservedOne = 0x400;
        private const ulong Dr7Conditions = 0xFFFF0000;

        private static ulong SanitizeDr7(ulong Dr7) => Dr7 & (Dr7Conditions | Dr7Enables);

        private const int DebugRegisterCount = 6;

        // Values come in CONTEXT order. When DR7 has no enable bit set, NT reports all six as 0 (KeContextFromKframes).
        private static void ReadDebugRegisters(BinaryEmulator Instance, EmulatedThread Thread, CpuContext Context, bool IsCurrentThread, Span<ulong> Values)
        {
            bool Held = WinEmulatedThread.TryGetState(Thread)?.DebugRegistersFromContext == true;
            if (IsCurrentThread && !Held)
            {
                Instance.ReadLiveDebugRegisters(Context, Values);
            }
            else if (Context != null)
            {
                Values[0] = Context.DR0; Values[1] = Context.DR1; Values[2] = Context.DR2;
                Values[3] = Context.DR3; Values[4] = Context.DR6; Values[5] = Context.DR7;
            }
            else
            {
                Values.Clear();
            }

            if ((Values[5] & Dr7Enables) == 0)
            {
                Values.Clear();
                return;
            }

            // The processor reads DR7 bit 10 and the DR6 reserved bits as 1, but KVM and Unicorn return the value as written.
            if (!Held)
            {
                Values[5] |= Dr7ReservedOne;
                Values[4] |= DebugStatus.ReservedOnes;
            }
        }

        // NT sets DR6 to 0 whatever the CONTEXT holds (KxContextToKframes).
        private static void ApplyDebugRegisters(BinaryEmulator Instance, EmulatedThread Thread, ReadOnlySpan<byte> Header, uint Flags)
        {
            if ((Flags & CONTEXT_DEBUG_REGISTERS) == 0)
                return;

            bool Wow64 = Instance.WinHelper.PointerSize == 4;
            CpuContext Context = Thread.Context ??= new CpuContext();
            ulong Dr0 = ReadDebugRegister(Header, Wow64, 0), Dr1 = ReadDebugRegister(Header, Wow64, 1);
            ulong Dr2 = ReadDebugRegister(Header, Wow64, 2), Dr3 = ReadDebugRegister(Header, Wow64, 3);
            ulong Dr7 = ReadDebugRegister(Header, Wow64, 5);
            // WOW64 sets LE for an address with no local enable (RtlpWow64CtxToAmd64).
            if (Wow64 && (Dr7 & Dr7LocalEnables) == 0 && (Dr0 | Dr1 | Dr2 | Dr3) != 0)
                Dr7 |= Dr7LocalExact;

            Dr7 = SanitizeDr7(Dr7);
            // If no breakpoint is enabled before or after, no CONTEXT can see the debug registers, so the processor
            // keeps its own.
            bool Observable = ((Context.DR7 | Dr7) & Dr7Enables) != 0;
            Context.DR0 = SanitizeDebugAddress(Dr0);
            Context.DR1 = SanitizeDebugAddress(Dr1);
            Context.DR2 = SanitizeDebugAddress(Dr2);
            Context.DR3 = SanitizeDebugAddress(Dr3);
            Context.DR6 = 0;
            Context.DR7 = Dr7;
            if (Observable)
                Instance.WriteThreadDebugRegisters(Thread);
        }

        // NT holds the context in the trap frame until the thread runs.
        private static void HoldUntilRun(EmulatedThread Thread, uint Flags)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            State.EFlagsFromContext |= (Flags & CONTEXT_CONTROL) != 0;
            State.DebugRegistersFromContext |= (Flags & CONTEXT_DEBUG_REGISTERS) != 0;
        }

        // The trap frame stores EFLAGS without bit 1, which the processor sets again when the thread runs.
        private static ulong ReportedEFlags(EmulatedThread Thread, ulong EFlags)
            => WinEmulatedThread.TryGetState(Thread)?.EFlagsFromContext == true ? EFlags & ~2UL : EFlags;

        private static bool InWow64Gate(BinaryEmulator Instance, ulong Eip)
        {
            ulong Gate = Instance.WindowsGuest?.WowSyscallGate ?? 0;
            return Gate != 0 && Eip - Gate <= WinSysHelper.IntInstructionLength;
        }

        // Indexed in CONTEXT order, where DR6 comes before DR7.
        private static ulong ReadDebugRegister(ReadOnlySpan<byte> Header, bool Wow64, int Index) => Wow64
            ? BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x04 + Index * 4))
            : BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0x48 + Index * 8));

        private static void KeepInCpuArea(EmulatedThread Thread, ReadOnlySpan<byte> Header, uint Flags)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if ((Flags & CONTEXT_CONTROL) != 0)
                State.Wow64EFlags = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xC0));

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                ulong[] Values = State.Wow64DebugRegisters ??= new ulong[DebugRegisterCount];
                for (int i = 0; i < DebugRegisterCount; i++)
                    Values[i] = ReadDebugRegister(Header, Wow64: true, i);
                State.Wow64DebugRegistersHeld = true;
            }
        }

        private static readonly ContextPart[] AppliedParts64 =
        {
            new(Start: 0x34, End: 0x38, Flag: CONTEXT_FLOATING_POINT),
            new(Start: 0x38, End: 0x100, Flag: CONTEXT_CONTROL),
            new(Start: 0x48, End: 0x78, Flag: CONTEXT_DEBUG_REGISTERS),
            new(Start: 0x78, End: 0xF8, Flag: CONTEXT_INTEGER),
        };

        private static readonly ContextPart[] AppliedParts32 =
        {
            new(Start: 0x04, End: 0x1C, Flag: CONTEXT_DEBUG_REGISTERS),
            new(Start: 0x1C, End: 0x24, Flag: CONTEXT_FLOATING_POINT),
            new(Start: 0x9C, End: 0xB4, Flag: CONTEXT_INTEGER),
            new(Start: 0xB4, End: 0xC8, Flag: CONTEXT_CONTROL),
        };

        private static ReadOnlySpan<byte> CaptureContextHeader(BinaryEmulator Instance, ulong ContextPtr, uint Flags, Span<byte> Buffer)
        {
            bool Wow64 = Instance.WinHelper.PointerSize == 4;
            int Start = int.MaxValue;
            int End = 0;
            foreach (ContextPart Part in Wow64 ? AppliedParts32 : AppliedParts64)
            {
                if ((Flags & Part.Flag) == 0)
                    continue;
                Start = Math.Min(Start, Part.Start);
                End = Math.Max(End, Part.End);
            }

            Span<byte> Header = Buffer.Slice(0, Wow64 ? (int)ExtendedRegistersOffset32 : (int)MinimumContextSize);
            if (End > Start)
                Instance.ReadMemory(ContextPtr + (ulong)Start, Header[Start..End]);
            return Header;
        }

        /// <summary>
        /// Resolves a Windows thread handle, including the current-thread pseudo handle.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="ThreadHandle">The guest thread handle value.</param>
        /// <returns>The emulated thread object, or null when the handle is invalid.</returns>
        internal static EmulatedThread ResolveThread(BinaryEmulator Instance, ulong ThreadHandle)
        {
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle) || ThreadHandle == 0xFFFFFFFEu)
                return Instance.CurrentThread;

            return Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
        }

        /// <summary>
        /// Checks whether a thread handle has the requested native thread access.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="ThreadHandle">The guest thread handle value.</param>
        /// <param name="RequiredAccess">The required access mask.</param>
        /// <returns>True when access should be allowed.</returns>
        internal static bool HasThreadAccess(BinaryEmulator Instance, ulong ThreadHandle, AccessMask RequiredAccess)
        {
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle) || ThreadHandle == 0xFFFFFFFEu)
                return true;

            AccessMask GrantedAccess = Instance.WinHelper.HandleManager.GetPermissionsByHandle(ThreadHandle);
            if (GrantedAccess == AccessMask.GiveTemp)
                return true;

            if ((GrantedAccess & AccessMask.GenericAll) != 0)
                return true;

            if ((RequiredAccess & AccessMask.ThreadGetContext) != 0 && (GrantedAccess & AccessMask.GenericRead) != 0)
                return true;

            if ((RequiredAccess & AccessMask.ThreadSetContext) != 0 && (GrantedAccess & AccessMask.GenericWrite) != 0)
                return true;

            if ((GrantedAccess & AccessMask.ThreadAllAccess) == AccessMask.ThreadAllAccess)
                return true;

            // NT grants the limited query right along with the full one (PspThreadOpen, PspThreadMapping).
            const AccessMask QueryLimitedGrants = AccessMask.ThreadQueryInformation | AccessMask.GenericRead | AccessMask.GenericExecute | AccessMask.MaximumAllowed;
            if (RequiredAccess == AccessMask.ThreadQueryLimitedInformation && (GrantedAccess & QueryLimitedGrants) != 0)
                return true;

            return (GrantedAccess & RequiredAccess) == RequiredAccess;
        }

        /// <summary>
        /// Validates the user supplied CONTEXT pointer and returns the requested context flags.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="ContextPtr">The guest CONTEXT pointer.</param>
        /// <param name="Flags">The requested CONTEXT flags.</param>
        /// <param name="ProbeSize64">The bytes of an x64 CONTEXT that must be mapped.</param>
        /// <returns>An NTSTATUS value indicating whether the CONTEXT pointer is usable.</returns>
        internal static NTSTATUS TryReadContextFlags(BinaryEmulator Instance, ulong ContextPtr, out uint Flags, ulong ProbeSize64 = MinimumContextSize)
        {
            Flags = 0;
            if (ContextPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool Is64 = Instance.WinHelper.PointerSize == 8;

            if (!Instance.IsRegionMapped(ContextPtr, Is64 ? ProbeSize64 : MinimumContextSize32))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Flags = Instance.ReadMemoryUInt(ContextPtr + (Is64 ? ContextFlagsOffset : 0));
            if ((Flags & (Is64 ? CONTEXT_AMD64 : CONTEXT_I386)) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // A part with flag 0 is always written.
        private readonly record struct ContextPart(int Start, int End, uint Flag);

        // Sorted by offset. FltSave and the extended state are written separately.
        private static readonly ContextPart[] ContextParts64 =
        {
            new(Start: 0x30, End: 0x34, Flag: 0),
            new(Start: 0x34, End: 0x38, Flag: CONTEXT_FLOATING_POINT),
            new(Start: 0x38, End: 0x3A, Flag: CONTEXT_CONTROL),
            new(Start: 0x3A, End: 0x42, Flag: CONTEXT_SEGMENTS),
            new(Start: 0x42, End: 0x48, Flag: CONTEXT_CONTROL),
            new(Start: 0x48, End: 0x78, Flag: CONTEXT_DEBUG_REGISTERS),
            new(Start: 0x78, End: 0x98, Flag: CONTEXT_INTEGER),
            new(Start: 0x98, End: 0xA0, Flag: CONTEXT_CONTROL),
            new(Start: 0xA0, End: 0xF8, Flag: CONTEXT_INTEGER),
            new(Start: 0xF8, End: 0x100, Flag: CONTEXT_CONTROL),
        };

        // Sorted by offset. FloatSave is written separately.
        private static readonly ContextPart[] ContextParts32 =
        {
            new(Start: 0x00, End: 0x04, Flag: 0),
            new(Start: 0x04, End: 0x1C, Flag: CONTEXT_DEBUG_REGISTERS),
            new(Start: 0x8C, End: 0x9C, Flag: CONTEXT_SEGMENTS),
            new(Start: 0x9C, End: 0xB4, Flag: CONTEXT_INTEGER),
            new(Start: 0xB4, End: 0xCC, Flag: CONTEXT_CONTROL),
        };

        // Parts the flags do not ask for keep whatever the guest wrote there.
        private static void WriteRequestedParts(BinaryEmulator Instance, ulong ContextPtr, ReadOnlySpan<byte> Area, ContextPart[] Parts, uint Flags,
            Span<byte> Frame)
        {
            int RunStart = 0;
            int RunEnd = 0;
            foreach (ContextPart Part in Parts)
            {
                if (Part.Flag != 0 && (Flags & Part.Flag) == 0)
                    continue;

                if (Part.Start != RunEnd)
                {
                    WritePartRun(Instance, ContextPtr, Area, RunStart, RunEnd, Frame);
                    RunStart = Part.Start;
                }
                RunEnd = Part.End;
            }

            WritePartRun(Instance, ContextPtr, Area, RunStart, RunEnd, Frame);
        }

        private static void WritePartRun(BinaryEmulator Instance, ulong ContextPtr, ReadOnlySpan<byte> Area, int RunStart, int RunEnd, Span<byte> Frame)
        {
            if (RunEnd <= RunStart)
                return;

            if (Frame.IsEmpty)
                Instance.WriteMemory(ContextPtr + (ulong)RunStart, Area[RunStart..RunEnd]);
            else
                Area[RunStart..RunEnd].CopyTo(Frame.Slice(RunStart));
        }

        private static CpuContext CaptureLiveRegisters(BinaryEmulator Instance, uint Flags, bool Wow64)
        {
            CpuContext Live = _liveScratch ??= new CpuContext();
            if ((Flags & (CONTEXT_CONTROL | CONTEXT_INTEGER)) != 0)
                Instance.ReadGprBatch(Live);
            if ((Flags & CONTEXT_CONTROL) != 0 || (Wow64 && (Flags & CONTEXT_SEGMENTS) != 0))
                Instance.ReadLiveSelectors(Live);
            return Live;
        }

        // The WOW64 gate returns through the address its caller pushed.
        private static void MoveToSyscallReturn(BinaryEmulator Instance, CpuContext Live)
        {
            if (Instance.WinHelper.PointerSize == 8)
            {
                Live.RIP += 2;
                return;
            }

            ulong Gate = Instance.WindowsGuest?.WowSyscallGate ?? 0;
            if (Gate == 0 || (uint)Live.RIP != Gate + WinSysHelper.IntInstructionLength)
                return;

            uint Esp = (uint)Live.RSP;
            Live.RIP = Instance.ReadMemoryUInt(Esp);
            Live.RSP = Esp + 4;
        }

        /// <param name="XStateAreaOffset">When nonzero, the XSAVE area sits at this offset and the CONTEXT gets CONTEXT_XSTATE
        /// and a CONTEXT_EX that points at it. When 0, the guest's own CONTEXT_EX locates the area.</param>
        /// <param name="Frame">A zeroed frame that a dispatcher builds at <paramref name="ContextPtr"/> and writes itself.
        /// Parts that fall past its end go straight to guest memory.</param>
        internal static void WriteContext(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags,
            ContextSource Source = ContextSource.Processor, ulong XStateAreaOffset = 0, Span<byte> Frame = default)
        {
            bool FromSavedContext = Source == ContextSource.SavedContext;
            bool IsCurrentThread = !FromSavedContext && IsCurrent(Instance, Thread);
            bool Wow64 = Instance.WinHelper.PointerSize == 4;
            CpuContext Context = Thread?.Context;
            CpuContext Cpu = IsCurrentThread ? CaptureLiveRegisters(Instance, Flags, Wow64) : Context ?? NoContext;
            if (IsCurrentThread && Source == ContextSource.SyscallReturn && (Flags & CONTEXT_CONTROL) != 0)
                MoveToSyscallReturn(Instance, Cpu);
            if ((Flags & (CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS)) != 0)
                Instance.RefreshThreadFpControl(Thread);

            if (Wow64)
            {
                WriteContext32(Instance, Thread, Context, Cpu, IsCurrentThread, ContextPtr, Flags, Frame);
                WriteContextVectorState32(Instance, Thread, IsCurrentThread, FromSavedContext, ContextPtr, Flags, Frame);
                return;
            }

            if (XStateAreaOffset != 0)
            {
                Flags |= CONTEXT_XSTATE;
                WriteContextEx(Frame, XStateAreaOffset);
            }

            Span<byte> Area = stackalloc byte[(int)MinimumContextSize];
            BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x30), Flags);

            ulong Fpcw = 0, Fpsw = 0, MxCsr = 0;
            if ((Flags & CONTEXT_FLOATING_POINT) != 0)
            {
                ReadFpControl(Instance, Context, IsCurrentThread, out Fpcw, out Fpsw, out MxCsr);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x34), (uint)MxCsr);
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(Area.Slice(0x38), (ushort)UserSelector(Cpu.CS, WindowsGuest.NtUserCodeSelector));
                BinaryPrimitives.WriteUInt16LittleEndian(Area.Slice(0x42), (ushort)UserSelector(Cpu.SS, WindowsGuest.NtUserDataSelector));
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x44), (uint)ReportedEFlags(Thread, Cpu.RFLAGS));
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x98), Cpu.RSP);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xF8), Cpu.RIP);
            }

            if ((Flags & CONTEXT_SEGMENTS) != 0)
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x3A), UserSegmentSelectors);

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                Span<ulong> Debug = stackalloc ulong[DebugRegisterCount];
                ReadDebugRegisters(Instance, Thread, Context, IsCurrentThread, Debug);
                for (int i = 0; i < DebugRegisterCount; i++)
                    BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x48 + i * 8), Debug[i]);
            }

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x78), Cpu.RAX);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x80), Cpu.RCX);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x88), Cpu.RDX);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0x90), Cpu.RBX);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xA0), Cpu.RBP);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xA8), Cpu.RSI);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xB0), Cpu.RDI);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xB8), Cpu.R8);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xC0), Cpu.R9);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xC8), Cpu.R10);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xD0), Cpu.R11);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xD8), Cpu.R12);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xE0), Cpu.R13);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xE8), Cpu.R14);
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xF0), Cpu.R15);
            }

            WriteRequestedParts(Instance, ContextPtr, Area, ContextParts64, Flags, Frame);
            ulong XStateArea = XStateAreaOffset != 0 ? ContextPtr + XStateAreaOffset : 0;
            WriteContextVectorState(Instance, Thread, ContextPtr, Flags, Fpcw, Fpsw, MxCsr, XStateArea, FromSavedContext, Frame);
        }

        internal static void ApplyContext(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags)
        {
            CpuContext Context = Thread.Context ??= new CpuContext();
            bool IsCurrentThread = IsCurrent(Instance, Thread);
            Span<byte> HeaderBuffer = stackalloc byte[(int)MinimumContextSize];
            ReadOnlySpan<byte> Header = CaptureContextHeader(Instance, ContextPtr, Flags, HeaderBuffer);
            if ((Flags & (CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS)) != 0)
                Instance.RefreshThreadFpControl(Thread);
            ApplyDebugRegisters(Instance, Thread, Header, Flags);

            bool LiveRegisters = IsCurrentThread && (Flags & (CONTEXT_CONTROL | CONTEXT_INTEGER)) != 0;
            if (Instance.WinHelper.PointerSize == 4)
            {
                bool InCpuArea = IsCurrentThread || WinEmulatedThread.GetState(Thread).LoaderThunkPending || InWow64Gate(Instance, Context.RIP);
                if (LiveRegisters)
                    Instance.ReadGprBatch(Context);
                ApplyContext32(Context, Header, Flags, InCpuArea);
                if (LiveRegisters)
                    Instance.WriteGprBatch(Context);
                ApplyVectorState32(Instance, Thread, IsCurrentThread, ContextPtr, Header, Flags);
                if ((Flags & (CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS)) != 0)
                    Instance.StoreThreadFpControl(Thread);

                if (!IsCurrentThread && InCpuArea)
                    KeepInCpuArea(Thread, Header, Flags);
                else if (!IsCurrentThread)
                    HoldUntilRun(Thread, Flags);
                return;
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                Context.CS = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x38));
                Context.SS = BinaryPrimitives.ReadUInt16LittleEndian(Header.Slice(0x42));
            }

            if (LiveRegisters)
                Instance.ReadGprBatch(Context);
            ApplyIntegerAndControl64(Context, Header, Flags);
            if (LiveRegisters)
            {
                // The syscall return adds 2 to RIP, so write it 2 bytes early.
                ulong Rip = Context.RIP;
                if ((Flags & CONTEXT_CONTROL) != 0)
                    Context.RIP = Rip - 2;
                Instance.WriteGprBatch(Context);
                Context.RIP = Rip;
            }

            if (!ApplyVectorState(Instance, Thread, IsCurrentThread, ContextPtr, Header, Flags) && (Flags & CONTEXT_FLOATING_POINT) != 0)
            {
                Context.MXCSR = SanitizeMxCsr(BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x34)));
                if (IsCurrentThread)
                    Instance.WriteRegister(Registers.UC_X86_REG_MXCSR, Context.MXCSR);
            }
            if ((Flags & CONTEXT_FLOATING_POINT) != 0)
                Instance.StoreThreadFpControl(Thread);

            if (!IsCurrentThread)
                HoldUntilRun(Thread, Flags);
        }

        private static void ApplyIntegerAndControl64(CpuContext Context, ReadOnlySpan<byte> Header, uint Flags)
        {
            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                Context.RFLAGS = SanitizeEFlags(BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x44)), InCpuArea: false);
                Context.RSP = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0x98));
                Context.RIP = SanitizeRip(BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xF8)));
            }

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Context.RAX = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0x78));
                Context.RCX = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0x80));
                Context.RDX = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0x88));
                Context.RBX = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0x90));
                Context.RBP = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xA0));
                Context.RSI = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xA8));
                Context.RDI = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xB0));
                Context.R8 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xB8));
                Context.R9 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xC0));
                Context.R10 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xC8));
                Context.R11 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xD0));
                Context.R12 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xD8));
                Context.R13 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xE0));
                Context.R14 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xE8));
                Context.R15 = BinaryPrimitives.ReadUInt64LittleEndian(Header.Slice(0xF0));
            }
        }

        // NT suspends a thread only on its way back to user mode, so the new context always takes effect.
        internal static void ResumeAtNewContext(BinaryEmulator Instance, EmulatedThread Thread)
        {
            Thread.SwitchingContext = true;
            Instance.SuppressSyscallStatusWrite = true;
            Instance._emulator.StopEmulation();
        }

        internal static void ApplyResumeContext(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags)
        {
            CpuContext Context = Thread.Context ??= new CpuContext();
            Span<byte> HeaderBuffer = stackalloc byte[(int)MinimumContextSize];
            ReadOnlySpan<byte> Header = CaptureContextHeader(Instance, ContextPtr, Flags, HeaderBuffer);
            bool AppliesRegisters = (Flags & (CONTEXT_CONTROL | CONTEXT_INTEGER)) != 0;
            Instance.ReadGprBatch(Context);

            if (Instance.WinHelper.PointerSize == 4)
            {
                ApplyContext32(Context, Header, Flags, InCpuArea: true);
                if (AppliesRegisters)
                    Instance.WriteGprBatch(Context);
                ApplyVectorState32(Instance, Thread, IsCurrentThread: true, ContextPtr, Header, Flags);
                ApplyDebugRegisters(Instance, Thread, Header, Flags);
                return;
            }

            ApplyIntegerAndControl64(Context, Header, Flags);
            if (AppliesRegisters)
                Instance.WriteGprBatch(Context);
            ApplyVectorState(Instance, Thread, IsCurrentThread: true, ContextPtr, Header, Flags);
            ApplyDebugRegisters(Instance, Thread, Header, Flags);
            HoldUntilRun(Thread, Flags);
        }

        private static void WriteContext32(BinaryEmulator Instance, EmulatedThread Thread, CpuContext Context, CpuContext Cpu, bool IsCurrentThread,
            ulong ContextPtr, uint Flags, Span<byte> Frame)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Thread);
            Span<byte> Area = stackalloc byte[(int)ExtendedRegistersOffset32];
            BinaryPrimitives.WriteUInt32LittleEndian(Area, Flags);

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                Span<ulong> Debug = stackalloc ulong[DebugRegisterCount];
                if (State is { Wow64DebugRegistersHeld: true, Wow64DebugRegisters: ulong[] Written })
                {
                    Written.CopyTo(Debug);
                }
                else
                {
                    ReadDebugRegisters(Instance, Thread, Context, IsCurrentThread, Debug);
                    // WOW64 drops GE and bit 10 from DR7 (RtlpWow64CtxFromAmd64).
                    Debug[5] &= Dr7Conditions | Dr7LocalEnables | Dr7LocalExact;
                }

                for (int i = 0; i < DebugRegisterCount; i++)
                    BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x04 + i * 4), (uint)Debug[i]);
            }

            if ((Flags & CONTEXT_SEGMENTS) != 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x8C), (uint)UserSelector(Cpu.GS, WindowsGuest.NtUserDataSelector));
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x90), (uint)UserSelector(Cpu.FS, WindowsGuest.NtUserTebSelector32));
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x94), (uint)UserSelector(Cpu.ES, WindowsGuest.NtUserDataSelector));
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x98), (uint)UserSelector(Cpu.DS, WindowsGuest.NtUserDataSelector));
            }

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x9C), (uint)Cpu.RDI);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xA0), (uint)Cpu.RSI);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xA4), (uint)Cpu.RBX);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xA8), (uint)Cpu.RDX);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xAC), (uint)Cpu.RCX);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xB0), (uint)Cpu.RAX);
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                ulong EFlags = State?.Wow64EFlags ?? ReportedEFlags(Thread, Cpu.RFLAGS);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xB4), (uint)Cpu.RBP);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xB8), (uint)Cpu.RIP);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xBC), (uint)UserSelector(Cpu.CS, WindowsGuest.NtUserCodeSelector32));
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xC0), (uint)EFlags);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xC4), (uint)Cpu.RSP);
                BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0xC8), (uint)UserSelector(Cpu.SS, WindowsGuest.NtUserDataSelector));
            }

            WriteRequestedParts(Instance, ContextPtr, Area, ContextParts32, Flags, Frame);
        }

        private static void ApplyContext32(CpuContext Context, ReadOnlySpan<byte> Header, uint Flags, bool InCpuArea)
        {
            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Context.RDI = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0x9C));
                Context.RSI = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xA0));
                Context.RBX = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xA4));
                Context.RDX = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xA8));
                Context.RCX = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xAC));
                Context.RAX = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xB0));
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                Context.RBP = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xB4));
                Context.RIP = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xB8));
                Context.RFLAGS = SanitizeEFlags(BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xC0)), InCpuArea);
                Context.RSP = BinaryPrimitives.ReadUInt32LittleEndian(Header.Slice(0xC4));
            }
        }

        private static void ReadFpControl(BinaryEmulator Instance, CpuContext Context, bool IsCurrentThread, out ulong Fpcw, out ulong Fpsw, out ulong MxCsr)
        {
            if (IsCurrentThread)
            {
                Instance.ReadFpControl(out Fpcw, out Fpsw, out MxCsr);
                return;
            }

            Fpcw = Context?.FPCW ?? 0;
            Fpsw = Context?.FPSW ?? 0;
            MxCsr = Context?.MXCSR ?? 0;
        }
    }
}
