using System;
using System.IO;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Settings;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class KernelFileReads
    {
        private const int ReadsBeforeView = 4;
        private const int ReadsAfterFailure = 256;
        private const int MaxReadBytes = 1 << 20;

        private const int ArgumentCount = 9;
        private const int IoStatusBlockArg = 4;
        private const int BufferArg = 5;
        private const int LengthArg = 6;
        private const int ByteOffsetArg = 7;
        private const int KeyArg = 8;
        private const int StackArgsStart = 0x28;
        private const int StackArgsEnd = 0x50;

        private const int IoStatusBlockSize = 16;

        private const int SavedIoStatusBlock = 0;
        private const int SavedLength = 1;

        private readonly BinaryEmulator Emulator;
        private readonly KernelFileTable Table;

        private KernelFileReads(BinaryEmulator Emulator, KernelFileTable Table)
        {
            this.Emulator = Emulator;
            this.Table = Table;
        }

        internal static KernelFileReads TryCreate(BinaryEmulator Instance, WindowsGuest Guest, KernelFileTable Table)
        {
            if (Table == null || !Guest.TryGetSyscallNumber(nameof(NtReadFile), out uint Number))
                return null;

            KernelFileReads Reads = new KernelFileReads(Instance, Table);
            return Table.Kernel.RegisterSyscall(Number, nameof(NtReadFile), Reads.EmitRead, Reads.FinishRead) ? Reads : null;
        }

        private void EmitRead(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            Label Abort = Builder.Abort;
            Label BufferClear = a.CreateLabel();
            Label StatusClear = a.CreateLabel();

            a.test(rdx, rdx);
            a.jnz(Abort);
            a.test(r8, r8);
            a.jnz(Abort);

            Builder.CheckStackArguments(ArgumentCount, rax);
            Builder.BeginUserAccess();
            Builder.LoadStackArgument(rdx, IoStatusBlockArg);
            Builder.LoadStackArgument(r11, BufferArg);
            Builder.LoadStackArgument(r9d, LengthArg);
            Builder.LoadStackArgument(rsi, ByteOffsetArg);
            Builder.LoadStackArgument(rcx, KeyArg);
            Builder.EndUserAccess();
            a.or(rsi, rcx);
            a.jnz(Abort);
            a.test(r9d, r9d);
            a.jz(Abort);
            a.cmp(r9d, MaxReadBytes);
            a.ja(Abort);

            Table.EmitLookup(Builder, KernelFileTable.ReadRight);
            Builder.CheckUserRange(r11, r9, r8, rax);
            Builder.CheckUserRange(rdx, IoStatusBlockSize, rax);

            // An abort makes the host read arguments 5 to 9 again, so no output may overlap them.
            a.lea(rax, __[rsp + StackArgsEnd]);
            a.lea(rcx, __[rsp + StackArgsStart]);
            a.cmp(r11, rax);
            a.jae(BufferClear);
            a.cmp(r8, rcx);
            a.ja(Abort);
            a.Label(ref BufferClear);
            a.cmp(rdx, rax);
            a.jae(StatusClear);
            a.lea(rsi, __[rdx + IoStatusBlockSize]);
            a.cmp(rsi, rcx);
            a.ja(Abort);
            a.Label(ref StatusClear);

            Builder.BeginUserAccess();
            Builder.ProbeForWrite(rdx, IoStatusBlockSize);
            Builder.ProbeForWrite(r11, r8, rax, rcx);
            Builder.EndUserAccess();
            Builder.Save(SavedIoStatusBlock, rdx);
            Builder.Save(SavedLength, r9);

            Label Retry = KernelFileTable.EmitLoadOffset(Builder);
            a.lea(r8, __[rax + r9]);
            a.cmp(r8, __qword_ptr[rbx + KernelCellData.ViewLengthField]);
            a.ja(Abort);

            a.mov(rdi, r11);
            a.mov(rcx, r9);
            a.mov(rsi, __qword_ptr[rbx + KernelCellData.ViewAddressField]);
            a.add(rsi, rax);
            Builder.BeginUserAccess();
            a.rep.movsb();
            Builder.EndUserAccess();
            KernelFileTable.EmitCommitOffset(Builder, r8, Retry);

            Builder.BeginUserAccess();
            a.mov(__qword_ptr[rdx], 0);
            a.mov(__qword_ptr[rdx + 8], r9);
            Builder.EndUserAccess();
        }

        // A served read stopped after its commit still owes the status block.
        private void FinishRead(ReadOnlySpan<ulong> Saved)
            => Emulator.WinHelper.WriteIoStatusBlock(Emulator, Saved[SavedIoStatusBlock], NTSTATUS.STATUS_SUCCESS, Saved[SavedLength]);

        internal void NoteRead(ulong Handle, WinFile File, ulong EventHandle, ulong ApcRoutine, ulong ByteOffsetPtr, ulong KeyPtr, uint Length)
        {
            if (Handle > uint.MaxValue || (EventHandle | ApcRoutine | ByteOffsetPtr | KeyPtr) != 0 || Length == 0
                || Length > MaxReadBytes)
                return;

            if (File.KernelCell is not { HasView: true })
            {
                // A view pays for itself only when as many reads of this size remain as it took to qualify.
                if (!IsReadEligible(File) || !Table.Enabled || ++File.KernelNotes.Reads < ReadsBeforeView
                    || !TryCreateViewCell(File, File.Position + (long)Length * ReadsBeforeView))
                    return;
            }

            Table.SetSlot(Handle, File.KernelCell, KernelFileTable.ReadRight);
        }

        internal static bool IsReadEligible(WinFile File)
            => KernelFileTable.CanHoldCell(File) && !File.AllowsWrite(File.GrantedAccess)
               && (File.ShareAccess & WinSysHelper.FILE_SHARE_WRITE) == 0 && File.Locks.Count == 0;

        // A file too short for the view is looked at again after more reads. Any other failure backs off longer.
        private bool TryCreateViewCell(WinFile File, long MinLength)
        {
            File.KernelNotes.Reads = ReadsBeforeView - ReadsAfterFailure;
            WindowsFileStream Stream = File.GetFileStream();
            if (Stream == null)
                return false;

            WinImageLayoutCache.View View = null;
            try
            {
                View = Stream.TryMapReadView(MemoryBudget.KernelReadViewBytes, MinLength, out long Length);
                if (View == null)
                {
                    if (Length != 0)
                        File.KernelNotes.Reads = 0;
                    return false;
                }

                if (!Table.TryCreateViewCell(File, View, (ulong)Length))
                    return false;

                View = null;
                return true;
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException || Ex is ArgumentException)
            {
                Table.LogMapFailure(File, Ex.Message);
                return false;
            }
            finally
            {
                View?.Dispose();
            }
        }

        // A read that ends inside the view means the host file shrank under it.
        internal void NoteEnd(WinFile File, long End)
        {
            if (File.KernelCell is KernelFileCell Cell && Cell.HasView && (ulong)End < Cell.ViewLength)
                Table.ReleaseCell(Cell);
        }
    }
}
