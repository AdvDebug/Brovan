using System.Buffers.Binary;
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

            WindowsThreadContext64.WriteContext(Instance, Thread, ContextPtr, Flags);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    /// <summary>
    /// Shared x64 CONTEXT helpers for native thread-context syscalls.
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

        internal const uint CONTEXT_I386 = 0x00010000;

        internal const ulong ContextFlagsOffset = 0x30;
        internal const ulong MinimumContextSize = 0x100;
        internal const ulong MinimumContextSize32 = 0x2CC;

        internal const ulong FltSaveOffset = 0x100;
        internal const int FltSaveSize = 0x200;
        internal const ulong ContextExOffset = 0x4D0;
        internal const int ContextExSize = 0x20;
        internal const int XStateHeaderSize = 64;
        // XSAVE header plus YMM_Hi128. x87 and SSE state stay in FltSave.
        internal const int XStateAreaSize = XStateHeaderSize + 256;
        internal const ulong XcrAvx = 0x4;
        internal const ulong XcrAvxFeatures = 0x7;
        private const int VectorQwords = 32;

        [ThreadStatic] private static ulong[] _xmmScratch;
        [ThreadStatic] private static ulong[] _ymmScratch;
        internal static ulong[] XmmScratch => _xmmScratch ??= new ulong[VectorQwords];
        internal static ulong[] YmmScratch => _ymmScratch ??= new ulong[VectorQwords];

        internal static bool XStateEnabled(BinaryEmulator Instance)
            => Instance.WinHelper.PointerSize == 8 && Instance._emulator.SupportsAvx;

        // No x87 register stack is kept, so FltSave carries the control words, MXCSR and XMM0-15.
        internal static void FillFltSave(Span<byte> Area, ulong[] Xmm, ulong MxCsr, ulong Fpcw)
        {
            Area.Slice(0, FltSaveSize).Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(Area.Slice(0x00, 2), (ushort)Fpcw);
            BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x18, 4), (uint)MxCsr);
            BinaryPrimitives.WriteUInt32LittleEndian(Area.Slice(0x1C, 4), 0xFFFF);
            for (int i = 0; i < VectorQwords; i++)
                BinaryPrimitives.WriteUInt64LittleEndian(Area.Slice(0xA0 + i * 8, 8), Xmm[i]);
        }

        internal static void WriteContextEx(Span<byte> Context, ulong XStateAreaOffset)
        {
            Span<byte> Ex = Context.Slice((int)ContextExOffset, ContextExSize);
            Ex.Clear();
            BinaryPrimitives.WriteInt32LittleEndian(Ex.Slice(0x00, 4), -(int)ContextExOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Ex.Slice(0x04, 4), (uint)(XStateAreaOffset + (ulong)XStateAreaSize));
            BinaryPrimitives.WriteInt32LittleEndian(Ex.Slice(0x08, 4), -(int)ContextExOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(Ex.Slice(0x0C, 4), (uint)ContextExOffset);
            BinaryPrimitives.WriteInt32LittleEndian(Ex.Slice(0x10, 4), (int)(XStateAreaOffset - ContextExOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(Ex.Slice(0x14, 4), (uint)XStateAreaSize);
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
        internal static void WriteXStateArea(BinaryEmulator Instance, ulong Area, ulong[] YmmHigh, ulong Mask)
        {
            Span<byte> Bytes = stackalloc byte[XStateAreaSize];
            Bytes.Clear();

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

            Instance.WriteMemory(Area, Bytes);
        }

        internal static void WriteContextVectorState(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags)
        {
            bool WantXmm = (Flags & CONTEXT_FLOATING_POINT) != 0;
            bool WantYmm = (Flags & CONTEXT_XSTATE) != 0 && XStateEnabled(Instance);
            if (!WantXmm && !WantYmm)
                return;

            ulong[] Xmm = XmmScratch;
            ulong[] YmmHigh = YmmScratch;
            if (!Instance.ReadThreadVectorState(Thread, Xmm, YmmHigh))
                return;

            bool IsCurrentThread = Instance.CurrentThread != null && Thread.ThreadId == Instance.CurrentThread.ThreadId;
            if (WantXmm && Instance.IsRegionMapped(ContextPtr + FltSaveOffset, (ulong)FltSaveSize))
            {
                Span<byte> Area = stackalloc byte[FltSaveSize];
                FillFltSave(Area, Xmm,
                    ReadSavedOrLive(Instance, Thread.Context, IsCurrentThread, Registers.UC_X86_REG_MXCSR, Ctx => Ctx.MXCSR),
                    ReadSavedOrLive(Instance, Thread.Context, IsCurrentThread, Registers.UC_X86_REG_FPCW, Ctx => Ctx.FPCW));
                Instance.WriteMemory(ContextPtr + FltSaveOffset, Area);
            }

            if (WantYmm && TryLocateXStateArea(Instance, ContextPtr, out ulong XStateArea))
                WriteXStateArea(Instance, XStateArea, YmmHigh, Instance.ReadMemoryULong(XStateArea));
        }

        internal static void ApplyVectorState(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags)
        {
            if (Thread == null || Instance.WinHelper.PointerSize != 8)
                return;

            bool HaveXmm = (Flags & CONTEXT_FLOATING_POINT) != 0 && Instance.IsRegionMapped(ContextPtr + FltSaveOffset, (ulong)FltSaveSize);
            ulong XStateArea = 0;
            bool HaveYmm = (Flags & CONTEXT_XSTATE) != 0 && XStateEnabled(Instance) && TryLocateXStateArea(Instance, ContextPtr, out XStateArea);
            if (!HaveXmm && !HaveYmm)
                return;

            ulong[] Xmm = XmmScratch;
            ulong[] YmmHigh = YmmScratch;
            if (!Instance.ReadThreadVectorState(Thread, Xmm, YmmHigh))
                return;

            if (HaveXmm)
            {
                Span<byte> Area = stackalloc byte[FltSaveSize];
                Instance._emulator.ReadMemory(ContextPtr + FltSaveOffset, Area, (uint)FltSaveSize);
                for (int i = 0; i < VectorQwords; i++)
                    Xmm[i] = BinaryPrimitives.ReadUInt64LittleEndian(Area.Slice(0xA0 + i * 8, 8));

                bool IsCurrentThread = Instance.CurrentThread != null && Thread.ThreadId == Instance.CurrentThread.ThreadId;
                ulong Fpcw = BinaryPrimitives.ReadUInt16LittleEndian(Area.Slice(0x00, 2));
                ulong MxCsr = Instance.ReadMemoryUInt(ContextPtr + 0x34);
                Thread.Context.FPCW = Fpcw;
                Thread.Context.MXCSR = MxCsr;
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_FPCW, Fpcw);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_MXCSR, MxCsr);
            }

            if (HaveYmm)
                ReadXStateArea(Instance, XStateArea, YmmHigh);

            Instance.WriteThreadVectorState(Thread, Xmm, YmmHigh);
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

            return (GrantedAccess & RequiredAccess) == RequiredAccess;
        }

        /// <summary>
        /// Validates the user supplied CONTEXT pointer and returns the requested context flags.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="ContextPtr">The guest CONTEXT pointer.</param>
        /// <param name="Flags">The requested CONTEXT flags.</param>
        /// <returns>An NTSTATUS value indicating whether the CONTEXT pointer is usable.</returns>
        internal static NTSTATUS TryReadContextFlags(BinaryEmulator Instance, ulong ContextPtr, out uint Flags)
        {
            Flags = 0;
            if (ContextPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool Is64 = Instance.WinHelper.PointerSize == 8;

            if (!Instance.IsRegionMapped(ContextPtr, Is64 ? MinimumContextSize : MinimumContextSize32))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Flags = Instance.ReadMemoryUInt(ContextPtr + (Is64 ? ContextFlagsOffset : 0));
            if ((Flags & (Is64 ? CONTEXT_AMD64 : CONTEXT_I386)) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }

        /// <summary>
        /// Writes the selected portions of an x64 CONTEXT record from an emulated thread.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Thread">The source thread.</param>
        /// <param name="ContextPtr">The destination CONTEXT pointer.</param>
        /// <param name="Flags">The selected CONTEXT flags.</param>
        internal static void WriteContext(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags)
        {
            bool IsCurrentThread = Thread != null && Instance.CurrentThread != null && Thread.ThreadId == Instance.CurrentThread.ThreadId;
            CpuContext Context = Thread?.Context;

            if (Instance.WinHelper.PointerSize == 4)
            {
                WriteContext32(Instance, Context, IsCurrentThread, ContextPtr, Flags);
                return;
            }

            Instance._emulator.WriteMemory(ContextPtr + 0x30, Flags, 4);

            if ((Flags & CONTEXT_FLOATING_POINT) != 0)
                Instance._emulator.WriteMemory(ContextPtr + 0x34, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_MXCSR, Ctx => Ctx.MXCSR), 4);

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x38, (ushort)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_CS, Ctx => Ctx.CS));
                Instance._emulator.WriteMemory(ContextPtr + 0x42, (ushort)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_SS, Ctx => Ctx.SS));
                Instance._emulator.WriteMemory(ContextPtr + 0x44, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EFLAGS, Ctx => Ctx.RFLAGS), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x98, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RSP, Ctx => Ctx.RSP), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xF8, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RIP, Ctx => Ctx.RIP), 8);
            }

            if ((Flags & CONTEXT_SEGMENTS) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x3A, (ushort)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DS, Ctx => Ctx.DS));
                Instance._emulator.WriteMemory(ContextPtr + 0x3C, (ushort)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_ES, Ctx => Ctx.ES));
                Instance._emulator.WriteMemory(ContextPtr + 0x3E, (ushort)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_FS, Ctx => Ctx.FS));
                Instance._emulator.WriteMemory(ContextPtr + 0x40, (ushort)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_GS, Ctx => Ctx.GS));
            }

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x48, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR0, Ctx => Ctx.DR0), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x50, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR1, Ctx => Ctx.DR1), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x58, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR2, Ctx => Ctx.DR2), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x60, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR3, Ctx => Ctx.DR3), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x68, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR6, Ctx => Ctx.DR6), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x70, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR7, Ctx => Ctx.DR7), 8);
            }

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x78, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RAX, Ctx => Ctx.RAX), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x80, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RCX, Ctx => Ctx.RCX), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x88, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RDX, Ctx => Ctx.RDX), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0x90, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RBX, Ctx => Ctx.RBX), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xA0, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RBP, Ctx => Ctx.RBP), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xA8, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RSI, Ctx => Ctx.RSI), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xB0, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_RDI, Ctx => Ctx.RDI), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xB8, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R8, Ctx => Ctx.R8), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xC0, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R9, Ctx => Ctx.R9), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xC8, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R10, Ctx => Ctx.R10), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xD0, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R11, Ctx => Ctx.R11), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xD8, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R12, Ctx => Ctx.R12), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xE0, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R13, Ctx => Ctx.R13), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xE8, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R14, Ctx => Ctx.R14), 8);
                Instance._emulator.WriteMemory(ContextPtr + 0xF0, ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_R15, Ctx => Ctx.R15), 8);
            }

            WriteContextVectorState(Instance, Thread, ContextPtr, Flags);
        }

        /// <summary>
        /// Applies the selected portions of an x64 CONTEXT record to an emulated thread.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Thread">The destination thread.</param>
        /// <param name="ContextPtr">The source CONTEXT pointer.</param>
        /// <param name="Flags">The selected CONTEXT flags.</param>
        internal static void ApplyContext(BinaryEmulator Instance, EmulatedThread Thread, ulong ContextPtr, uint Flags)
        {
            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            bool IsCurrentThread = Instance.CurrentThread != null && Thread.ThreadId == Instance.CurrentThread.ThreadId;
            CpuContext Context = Thread.Context;

            if (Instance.WinHelper.PointerSize == 4)
            {
                ApplyContext32(Instance, Context, IsCurrentThread, ContextPtr, Flags);
                return;
            }

            if ((Flags & CONTEXT_FLOATING_POINT) != 0)
            {
                ulong MxCsr = Instance.ReadMemoryUInt(ContextPtr + 0x34);
                Context.MXCSR = MxCsr;
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_MXCSR, MxCsr);
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                ulong EFlags = Instance.ReadMemoryUInt(ContextPtr + 0x44);
                ulong Rsp = Instance.ReadMemoryULong(ContextPtr + 0x98);
                ulong Rip = Instance.ReadMemoryULong(ContextPtr + 0xF8);

                Context.CS = Instance._emulator.ReadMemoryUShort(ContextPtr + 0x38);
                Context.SS = Instance._emulator.ReadMemoryUShort(ContextPtr + 0x42);
                Context.RFLAGS = EFlags;
                Context.RSP = Rsp;
                Context.RIP = Rip;

                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EFLAGS, EFlags);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RSP, Rsp);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RIP, Rip);
            }

            if ((Flags & CONTEXT_SEGMENTS) != 0)
            {
                Context.DS = Instance._emulator.ReadMemoryUShort(ContextPtr + 0x3A);
                Context.ES = Instance._emulator.ReadMemoryUShort(ContextPtr + 0x3C);
                Context.FS = Instance._emulator.ReadMemoryUShort(ContextPtr + 0x3E);
                Context.GS = Instance._emulator.ReadMemoryUShort(ContextPtr + 0x40);
            }

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                Context.DR0 = Instance.ReadMemoryULong(ContextPtr + 0x48);
                Context.DR1 = Instance.ReadMemoryULong(ContextPtr + 0x50);
                Context.DR2 = Instance.ReadMemoryULong(ContextPtr + 0x58);
                Context.DR3 = Instance.ReadMemoryULong(ContextPtr + 0x60);
                Context.DR6 = Instance.ReadMemoryULong(ContextPtr + 0x68);
                Context.DR7 = Instance.ReadMemoryULong(ContextPtr + 0x70);

                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_DR0, Context.DR0);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_DR1, Context.DR1);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_DR2, Context.DR2);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_DR3, Context.DR3);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_DR6, Context.DR6);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_DR7, Context.DR7);
            }

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Context.RAX = Instance.ReadMemoryULong(ContextPtr + 0x78);
                Context.RCX = Instance.ReadMemoryULong(ContextPtr + 0x80);
                Context.RDX = Instance.ReadMemoryULong(ContextPtr + 0x88);
                Context.RBX = Instance.ReadMemoryULong(ContextPtr + 0x90);
                Context.RBP = Instance.ReadMemoryULong(ContextPtr + 0xA0);
                Context.RSI = Instance.ReadMemoryULong(ContextPtr + 0xA8);
                Context.RDI = Instance.ReadMemoryULong(ContextPtr + 0xB0);
                Context.R8 = Instance.ReadMemoryULong(ContextPtr + 0xB8);
                Context.R9 = Instance.ReadMemoryULong(ContextPtr + 0xC0);
                Context.R10 = Instance.ReadMemoryULong(ContextPtr + 0xC8);
                Context.R11 = Instance.ReadMemoryULong(ContextPtr + 0xD0);
                Context.R12 = Instance.ReadMemoryULong(ContextPtr + 0xD8);
                Context.R13 = Instance.ReadMemoryULong(ContextPtr + 0xE0);
                Context.R14 = Instance.ReadMemoryULong(ContextPtr + 0xE8);
                Context.R15 = Instance.ReadMemoryULong(ContextPtr + 0xF0);

                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RAX, Context.RAX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RCX, Context.RCX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RDX, Context.RDX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RBX, Context.RBX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RBP, Context.RBP);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RSI, Context.RSI);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_RDI, Context.RDI);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R8, Context.R8);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R9, Context.R9);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R10, Context.R10);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R11, Context.R11);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R12, Context.R12);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R13, Context.R13);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R14, Context.R14);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_R15, Context.R15);
            }

            ApplyVectorState(Instance, Thread, ContextPtr, Flags);
        }

        private static void WriteContext32(BinaryEmulator Instance, CpuContext Context, bool IsCurrentThread, ulong ContextPtr, uint Flags)
        {
            Instance._emulator.WriteMemory(ContextPtr + 0x00, Flags, 4);

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x04, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR0, Ctx => Ctx.DR0), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x08, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR1, Ctx => Ctx.DR1), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x0C, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR2, Ctx => Ctx.DR2), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x10, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR3, Ctx => Ctx.DR3), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x14, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR6, Ctx => Ctx.DR6), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x18, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DR7, Ctx => Ctx.DR7), 4);
            }

            if ((Flags & CONTEXT_SEGMENTS) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x8C, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_GS, Ctx => Ctx.GS), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x90, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_FS, Ctx => Ctx.FS), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x94, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_ES, Ctx => Ctx.ES), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0x98, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_DS, Ctx => Ctx.DS), 4);
            }

            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0x9C, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EDI, Ctx => Ctx.RDI), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xA0, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_ESI, Ctx => Ctx.RSI), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xA4, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EBX, Ctx => Ctx.RBX), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xA8, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EDX, Ctx => Ctx.RDX), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xAC, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_ECX, Ctx => Ctx.RCX), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xB0, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EAX, Ctx => Ctx.RAX), 4);
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                Instance._emulator.WriteMemory(ContextPtr + 0xB4, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EBP, Ctx => Ctx.RBP), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xB8, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EIP, Ctx => Ctx.RIP), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xBC, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_CS, Ctx => Ctx.CS), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xC0, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_EFLAGS, Ctx => Ctx.RFLAGS), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xC4, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_ESP, Ctx => Ctx.RSP), 4);
                Instance._emulator.WriteMemory(ContextPtr + 0xC8, (uint)ReadSavedOrLive(Instance, Context, IsCurrentThread, Registers.UC_X86_REG_SS, Ctx => Ctx.SS), 4);
            }
        }

        private static void ApplyContext32(BinaryEmulator Instance, CpuContext Context, bool IsCurrentThread, ulong ContextPtr, uint Flags)
        {
            if ((Flags & CONTEXT_INTEGER) != 0)
            {
                Context.RDI = Instance.ReadMemoryUInt(ContextPtr + 0x9C);
                Context.RSI = Instance.ReadMemoryUInt(ContextPtr + 0xA0);
                Context.RBX = Instance.ReadMemoryUInt(ContextPtr + 0xA4);
                Context.RDX = Instance.ReadMemoryUInt(ContextPtr + 0xA8);
                Context.RCX = Instance.ReadMemoryUInt(ContextPtr + 0xAC);
                Context.RAX = Instance.ReadMemoryUInt(ContextPtr + 0xB0);

                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EDI, Context.RDI);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_ESI, Context.RSI);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EBX, Context.RBX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EDX, Context.RDX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_ECX, Context.RCX);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EAX, Context.RAX);
            }

            if ((Flags & CONTEXT_CONTROL) != 0)
            {
                Context.RBP = Instance.ReadMemoryUInt(ContextPtr + 0xB4);
                Context.RIP = Instance.ReadMemoryUInt(ContextPtr + 0xB8);
                Context.RFLAGS = Instance.ReadMemoryUInt(ContextPtr + 0xC0);
                Context.RSP = Instance.ReadMemoryUInt(ContextPtr + 0xC4);

                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EBP, Context.RBP);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EIP, Context.RIP);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_EFLAGS, Context.RFLAGS);
                WriteLiveRegister(Instance, IsCurrentThread, Registers.UC_X86_REG_ESP, Context.RSP);
            }

            if ((Flags & CONTEXT_DEBUG_REGISTERS) != 0)
            {
                Context.DR0 = Instance.ReadMemoryUInt(ContextPtr + 0x04);
                Context.DR1 = Instance.ReadMemoryUInt(ContextPtr + 0x08);
                Context.DR2 = Instance.ReadMemoryUInt(ContextPtr + 0x0C);
                Context.DR3 = Instance.ReadMemoryUInt(ContextPtr + 0x10);
                Context.DR6 = Instance.ReadMemoryUInt(ContextPtr + 0x14);
                Context.DR7 = Instance.ReadMemoryUInt(ContextPtr + 0x18);
            }
        }

        private static ulong ReadSavedOrLive(BinaryEmulator Instance, CpuContext Context, bool IsCurrentThread, Registers Register, Func<CpuContext, ulong> ReadSaved)
        {
            if (IsCurrentThread)
                return Instance.ReadRegister(Register);

            if (Context == null)
                return 0;

            return ReadSaved(Context);
        }

        private static void WriteLiveRegister(BinaryEmulator Instance, bool IsCurrentThread, Registers Register, ulong Value)
        {
            if (IsCurrentThread)
                Instance.WriteRegister(Register, Value);
        }
    }
}
