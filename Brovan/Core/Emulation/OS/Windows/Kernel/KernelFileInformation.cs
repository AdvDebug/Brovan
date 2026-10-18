using System;
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

        private const int SavedIoStatusBlock = 0;
        private const int SavedBuffer = 1;
        private const int SavedPosition = 2;

        private readonly BinaryEmulator Emulator;
        private readonly KernelFileTable Table;

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
            return Query || Set ? Information : null;
        }

        private void EmitPositionChecks(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            Builder.CheckStackArguments(ArgumentCount, rax);
            Builder.BeginUserAccess();
            Builder.LoadStackArgument(eax, ClassArg);
            Builder.EndUserAccess();
            a.cmp(eax, FilePositionInformation);
            a.jne(Builder.Decline);

            a.mov(r9d, r9d);
            a.cmp(r9d, PositionSize);
            a.jb(Builder.Abort);
            a.test(r8b, PositionSize - 1);
            a.jnz(Builder.Abort);
            Builder.CheckUserRange(rdx, IoStatusBlockSize, rax);
            Builder.CheckUserRange(r8, r9, r11, rax);
            Table.EmitLookup(Builder, 0);
        }

        private void EmitQuery(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;

            EmitPositionChecks(Builder);
            Builder.BeginUserAccess();
            Builder.ProbeForWrite(rdx, IoStatusBlockSize);
            Builder.ProbeForWrite(r8, r11, rax, rcx);
            Builder.EndUserAccess();
            Builder.Save(SavedIoStatusBlock, rdx);
            Builder.Save(SavedBuffer, r8);

            // A query moves nothing, but the commit still marks the point after which a stop finishes the call.
            Label Retry = KernelFileTable.EmitLoadOffset(Builder);
            Builder.Save(SavedPosition, rax);
            a.mov(rcx, rax);
            KernelFileTable.EmitCommitOffset(Builder, rcx, Retry);

            Builder.BeginUserAccess();
            a.mov(__qword_ptr[r8], rax);
            a.mov(__qword_ptr[rdx], 0);
            a.mov(__qword_ptr[rdx + 8], PositionSize);
            Builder.EndUserAccess();
        }

        private void FinishQuery(ReadOnlySpan<ulong> Saved)
        {
            Emulator._emulator.WriteMemory(Saved[SavedBuffer], Saved[SavedPosition], PositionSize);
            Emulator.WinHelper.WriteIoStatusBlock(Emulator, Saved[SavedIoStatusBlock], NTSTATUS.STATUS_SUCCESS, PositionSize);
        }

        private void EmitSet(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;

            EmitPositionChecks(Builder);
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

        // NT needs no access right for a position call, so the slot carries none. A file that reads can map gets its
        // cell from reads, because a cell without a view would keep the view out.
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
