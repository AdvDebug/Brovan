using System;
using System.Runtime.InteropServices;
using Brovan.Core.Emulation.Guests;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class KernelFileInformation
    {
        private const int ArgumentCount = 5;
        private const int ClassArg = 4;
        private const int FilePositionInformation = 14;
        private const int PositionSize = 8;
        private const int IoStatusBlockSize = 16;
        private const int PositionCallsBeforeCell = 4;
        private const int StandardQueriesBeforeLease = 32;
        private const int StandardQueriesAfterFailure = 256;
        private const int StandardSize = 24;

        private const int SavedIoStatusBlock = 0;
        private const int SavedBuffer = 1;
        private const int SavedLength = 2;
        private const int SavedData = 3;

        private readonly BinaryEmulator Emulator;
        private readonly KernelFileTable Table;
        private bool QueryRegistered;

        private KernelFileInformation(BinaryEmulator Emulator, KernelFileTable Table)
        {
            this.Emulator = Emulator;
            this.Table = Table;
        }

        internal static KernelFileInformation TryCreate(BinaryEmulator Instance, WindowsGuest Guest, KernelFileTable Table)
        {
            if (Table == null)
                return null;

            KernelFileInformation Information = new KernelFileInformation(Instance, Table);
            bool Query = Guest.TryGetSyscallNumber(nameof(NtQueryInformationFile), out uint QueryNumber)
                && Table.Kernel.RegisterSyscall(QueryNumber, nameof(NtQueryInformationFile), Information.EmitQuery, Information.FinishQuery);
            bool Set = Guest.TryGetSyscallNumber(nameof(NtSetInformationFile), out uint SetNumber)
                && Table.Kernel.RegisterSyscall(SetNumber, nameof(NtSetInformationFile), Information.EmitSet, Information.FinishSet);
            Information.QueryRegistered = Query;
            return Query || Set ? Information : null;
        }

        // Leaves the class in EAX.
        private static void EmitLoadClass(GuestKernelCallBuilder Builder)
        {
            Builder.CheckStackArguments(ArgumentCount, rax);
            Builder.BeginUserAccess();
            Builder.LoadStackArgument(eax, ClassArg);
            Builder.EndUserAccess();
        }

        // Takes the class's size in R15D, and leaves the buffer end in R11 and the cell in RBX.
        private void EmitBufferChecks(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            a.mov(r9d, r9d);
            a.cmp(r9d, r15d);
            a.jb(Builder.Abort);
            a.test(r8b, sizeof(long) - 1);
            a.jnz(Builder.Abort);
            Builder.CheckUserRange(rdx, IoStatusBlockSize, rax);
            Builder.CheckUserRange(r8, r9, r11, rax);
            Table.EmitLookup(Builder, 0);
        }

        private void EmitQuery(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            Label PositionClass = a.CreateLabel();
            Label Checks = a.CreateLabel();
            Label Position = a.CreateLabel();
            Label Captured = a.CreateLabel();
            Label OutputDone = a.CreateLabel();
            EmitLoadClass(Builder);
            a.cmp(eax, FilePositionInformation);
            a.je(PositionClass);
            a.cmp(eax, (int)FILE_INFORMATION_CLASS.FileStandardInformation);
            a.jne(Builder.Decline);
            a.mov(r15d, StandardSize);
            a.jmp(Checks);
            a.Label(ref PositionClass);
            a.mov(r15d, PositionSize);
            a.Label(ref Checks);
            a.cmp(r9d, NtReadFile.IoChunkBytes);
            a.ja(Builder.Abort);
            EmitBufferChecks(Builder);
            Builder.BeginUserAccess();
            Builder.ProbeForWrite(rdx, IoStatusBlockSize);
            Builder.ProbeForWrite(r8, r11, rax, rcx);
            Builder.EndUserAccess();
            a.mov(rbp, rdx);

            a.cmp(r15d, PositionSize);
            a.je(Position);
            a.mov(r11, __qword_ptr[rbx + KernelCellData.MetadataGuardField]);
            a.test(r11, r11);
            a.jz(Builder.Abort);
            a.mov(r12, __qword_ptr[rbx + KernelCellData.MetadataAllocationField]);
            a.mov(r13, __qword_ptr[rbx + KernelCellData.MetadataEndField]);
            a.mov(r14d, 1);
            a.cmp(__dword_ptr[r11], 1);
            a.jne(Builder.Abort);
            a.mov(rcx, __qword_ptr[rbx + KernelCellData.MetadataDeadlineField]);
            a.test(rcx, rcx);
            a.jz(Captured);
            a.lfence();
            a.rdtsc();
            a.shl(rdx, 32);
            a.or(rax, rdx);
            a.cmp(rax, rcx);
            a.jae(Builder.Abort);
            a.jmp(Captured);
            a.Label(ref Position);
            KernelFileTable.EmitLoadOffset(Builder);
            a.mov(r12, rax);
            a.xor(r13d, r13d);
            a.xor(r14d, r14d);
            a.Label(ref Captured);
            Builder.Save(SavedIoStatusBlock, rbp);
            Builder.Save(SavedBuffer, r8);
            Builder.Save(SavedLength, r15);
            Builder.Save(SavedData, r12);
            Builder.Save(SavedData + 1, r13);
            Builder.Save(SavedData + 2, r14);
            Builder.CommitReadOnly();

            Builder.BeginUserAccess();
            a.mov(__qword_ptr[r8], r12);
            a.cmp(r15d, PositionSize);
            a.je(OutputDone);
            a.mov(__qword_ptr[r8 + 8], r13);
            a.mov(__qword_ptr[r8 + 16], r14);
            a.Label(ref OutputDone);
            a.mov(__qword_ptr[rbp], 0);
            a.mov(__qword_ptr[rbp + 8], r15);
            Builder.EndUserAccess();
        }

        private void FinishQuery(ReadOnlySpan<ulong> Saved)
        {
            int Length = (int)Saved[SavedLength];
            Emulator._emulator.WriteMemory(Saved[SavedBuffer], MemoryMarshal.AsBytes(Saved.Slice(SavedData, Length / sizeof(ulong))));
            Emulator.WinHelper.WriteIoStatusBlock(Emulator, Saved[SavedIoStatusBlock], NTSTATUS.STATUS_SUCCESS, (ulong)Length);
        }

        internal void NoteStandard(ulong Handle, WinFile File)
        {
            if (!QueryRegistered || !Table.Enabled || Handle > uint.MaxValue || !KernelFileTable.CanHoldCell(File)
                || File.AllowsWrite(File.GrantedAccess) || Emulator.WinHelper.IsFileDeletePending(File))
                return;

            if (File.KernelCell is not { HasMetadata: true }
                && ++File.KernelNotes.StandardQueries < StandardQueriesBeforeLease)
                return;
            if (Table.TryPublishMetadata(File, out KernelFileCell? Cell))
                Table.SetSlot(Handle, Cell, 0);
            else
                File.KernelNotes.StandardQueries = StandardQueriesBeforeLease - StandardQueriesAfterFailure;
        }

        private void EmitSet(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;

            EmitLoadClass(Builder);
            a.cmp(eax, FilePositionInformation);
            a.jne(Builder.Decline);
            a.mov(r15d, PositionSize);
            EmitBufferChecks(Builder);
            Builder.BeginUserAccess();
            Builder.ProbeForWrite(rdx, IoStatusBlockSize);
            a.mov(rcx, __qword_ptr[r8]);
            Builder.EndUserAccess();
            a.test(rcx, rcx);
            a.js(Builder.Abort);
            Builder.Save(SavedIoStatusBlock, rdx);

            Label Retry = KernelFileTable.EmitLoadOffset(Builder);
            KernelFileTable.EmitCommitOffset(Builder, rcx, Retry);

            Builder.BeginUserAccess();
            a.mov(__qword_ptr[rdx], 0);
            a.mov(__qword_ptr[rdx + 8], 0);
            Builder.EndUserAccess();
        }

        private void FinishSet(ReadOnlySpan<ulong> Saved)
            => Emulator.WinHelper.WriteIoStatusBlock(Emulator, Saved[SavedIoStatusBlock], NTSTATUS.STATUS_SUCCESS, 0);

        internal void NotePosition(ulong Handle, WinFile File)
        {
            if (Handle > uint.MaxValue)
                return;

            if (File.KernelCell is KernelFileCell Cell)
            {
                Table.SetSlot(Handle, Cell, 0);
                return;
            }

            if (!Table.Enabled || KernelFileReads.IsReadEligible(File) || !KernelFileTable.CanHoldCell(File)
                || ++File.KernelNotes.PositionCalls < PositionCallsBeforeCell || !Table.TryCreateCell(File, out Cell))
                return;

            Table.SetSlot(Handle, Cell, 0);
        }
    }
}
