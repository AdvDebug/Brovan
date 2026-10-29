using System.Buffers.Binary;
using Brovan.Core.Emulation.Guests;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class KernelFileVolumeInformation
    {
        private const int EntryBytes = sizeof(ulong) + NtQueryVolumeInformationFile.MaximumInformationBytes;
        private const int EntryCount = NtQueryVolumeInformationFile.MaximumInformationClass + 1;
        private const int IoStatusBlockSize = 16;
        private const int SavedIoStatusBlock = 0;
        private const int SavedBuffer = 1;
        private const int SavedClass = 2;

        private readonly BinaryEmulator Emulator;
        private readonly KernelFileTable Table;
        private readonly ulong DataAddress;
        private readonly byte[] Data;

        private KernelFileVolumeInformation(BinaryEmulator Emulator, KernelFileTable Table, ulong DataAddress, byte[] Data)
        {
            this.Emulator = Emulator;
            this.Table = Table;
            this.DataAddress = DataAddress;
            this.Data = Data;
        }

        internal static unsafe KernelFileVolumeInformation? TryCreate(BinaryEmulator Instance, WindowsGuest Guest, KernelFileTable? Table)
        {
            if (Table == null || !Guest.TryGetSyscallNumber(nameof(NtQueryVolumeInformationFile), out uint Number))
                return null;

            byte[] Data = new byte[EntryCount * EntryBytes];
            for (uint Class = 0; Class < EntryCount; Class++)
            {
                Span<byte> Entry = Data.AsSpan((int)Class * EntryBytes, EntryBytes);
                int Length = NtQueryVolumeInformationFile.BuildInformation(Instance, null, Class, Entry.Slice(sizeof(ulong)));
                BinaryPrimitives.WriteUInt64LittleEndian(Entry, (ulong)Length);
            }

            if (!Table.Kernel.TryAllocateMemory((ulong)Data.Length, out ulong Address, out IntPtr Host))
                return null;
            Data.AsSpan().CopyTo(new Span<byte>((void*)Host, Data.Length));

            KernelFileVolumeInformation Information = new KernelFileVolumeInformation(Instance, Table, Address, Data);
            return Table.Kernel.RegisterSyscall(Number, nameof(NtQueryVolumeInformationFile), Information.EmitQuery, Information.FinishQuery) ? Information : null;
        }

        private void EmitQuery(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            Builder.CheckStackArguments(5, rax);
            Builder.BeginUserAccess();
            Builder.LoadStackArgument(r12d, 4);
            Builder.EndUserAccess();
            a.cmp(r12d, EntryCount);
            a.jae(Builder.Decline);
            a.imul(r14, r12, EntryBytes);
            Builder.LoadAddress(rax, DataAddress);
            a.add(r14, rax);
            a.mov(r13, __qword_ptr[r14]);
            a.test(r13, r13);
            a.jz(Builder.Decline);
            a.add(r14, sizeof(ulong));
            a.mov(r9d, r9d);
            a.cmp(r9, r13);
            a.jb(Builder.Abort);
            a.cmp(r9d, NtReadFile.IoChunkBytes);
            a.ja(Builder.Abort);
            a.test(r8b, 7);
            a.jnz(Builder.Abort);
            Builder.CheckUserRange(rdx, IoStatusBlockSize, rax);
            Builder.CheckUserRange(r8, r9, r11, rax);
            Table.EmitLookup(Builder, 0);

            Builder.BeginUserAccess();
            Builder.ProbeForWrite(rdx, IoStatusBlockSize);
            Builder.ProbeForWrite(r8, r11, rax, rcx);
            Builder.EndUserAccess();
            Builder.Save(SavedIoStatusBlock, rdx);
            Builder.Save(SavedBuffer, r8);
            Builder.Save(SavedClass, r12);

            Label Retry = KernelFileTable.EmitLoadOffset(Builder);
            a.mov(rcx, rax);
            KernelFileTable.EmitCommitOffset(Builder, rcx, Retry);

            a.mov(rdi, r8);
            a.mov(rsi, r14);
            a.mov(rcx, r13);
            Builder.BeginUserAccess();
            a.rep.movsb();
            a.mov(__qword_ptr[rdx], 0);
            a.mov(__qword_ptr[rdx + 8], r13);
            Builder.EndUserAccess();
        }

        private void FinishQuery(ReadOnlySpan<ulong> Saved)
        {
            ReadOnlySpan<byte> Entry = Data.AsSpan((int)Saved[SavedClass] * EntryBytes, EntryBytes);
            int Length = (int)BinaryPrimitives.ReadUInt64LittleEndian(Entry);
            Emulator.WriteMemory(Saved[SavedBuffer], Entry.Slice(sizeof(ulong), Length));
            Emulator.WinHelper.WriteIoStatusBlock(Emulator, Saved[SavedIoStatusBlock], NTSTATUS.STATUS_SUCCESS, (ulong)Length);
        }

        internal void NoteQuery(ulong Handle, WinFile File)
        {
            if (Handle > uint.MaxValue || !Table.Enabled)
                return;

            if (File.KernelCell is not KernelFileCell Cell)
            {
                if (KernelFileReads.IsReadEligible(File) || File.Locks.Count != 0
                    || !KernelFileTable.CanHoldCell(File) || !Table.TryCreateCell(File, out Cell))
                    return;
            }

            Table.SetSlot(Handle, Cell, 0);
        }
    }
}
