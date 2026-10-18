using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.Core.Emulation.OS.Windows
{
    // One cache line per cell, so swaps of different files do not contend.
    [StructLayout(LayoutKind.Explicit, Size = KernelFileReads.CellSize)]
    internal struct KernelCellData
    {
        internal const int OffsetField = 0;
        internal const int ViewAddressField = 8;
        internal const int ViewLengthField = 16;

        [FieldOffset(OffsetField)] internal long Offset;
        [FieldOffset(ViewAddressField)] internal ulong ViewAddress;
        [FieldOffset(ViewLengthField)] internal ulong ViewLength;
    }

    // While bit 63 of the offset is set, the host owns it and guest ring 0 sends every read of the file to the host.
    internal sealed unsafe class KernelFileCell
    {
        internal const long HostOwned = long.MinValue;

        internal KernelFileReads Owner;
        internal int Index;
        internal long Sequence;
        internal KernelCellData* Data;
        internal WinFile File;
        internal WinImageLayoutCache.View View;

        // Guest ring 0 can write Data, so the host keeps its own copy of the view it mapped.
        internal ulong ViewAddress;
        internal ulong ViewLength;

        internal bool IsLive => File.KernelCell == this;

        internal long Offset
        {
            get => Volatile.Read(ref Data->Offset) & long.MaxValue;
            set => Volatile.Write(ref Data->Offset, value);
        }

        internal long Claim()
        {
            long Value;
            do
            {
                Value = Volatile.Read(ref Data->Offset);
                if (Value < 0)
                    return Value & long.MaxValue;
            }
            while (Interlocked.CompareExchange(ref Data->Offset, Value | HostOwned, Value) != Value);

            return Value;
        }

        // Guest ring 0 cannot swap a claimed offset, so a plain store releases it.
        internal void Release()
        {
            long Value = Volatile.Read(ref Data->Offset);
            if (Value < 0)
                Volatile.Write(ref Data->Offset, Value & long.MaxValue);
        }
    }

    internal sealed unsafe class KernelFileReads : IDisposable
    {
        // A slot packs the handle in its low half and its cell's byte offset in the high half, so one load reads both.
        private const int SlotCount = 256;
        private const int SlotSize = 8;
        private const int SlotsBytes = SlotCount * SlotSize;

        internal const int CellSize = 64;

        private const int ReadsBeforeView = 4;
        private const int ReadsAfterFailure = 256;
        private const int MaxReadBytes = 1 << 20;
        private const int RetiredLimit = 8;

        private const int IoStatusBlockArg = 0x28;
        private const int BufferArg = 0x30;
        private const int LengthArg = 0x38;
        private const int ByteOffsetArg = 0x40;
        private const int KeyArg = 0x48;
        private const int StackArgsStart = IoStatusBlockArg;
        private const int StackArgsEnd = 0x50;

        private const int IoStatusBlockSize = 16;
        private const int GuestPageMask = 0xFFF;

        private const int SavedIoStatusBlock = 0;
        private const int SavedLength = 1;

        private readonly BinaryEmulator Emulator;
        private readonly IGuestKernel Kernel;
        private readonly ulong SlotsAddress;
        private readonly ulong* Slots;
        private readonly KernelCellData* Cells;
        private readonly KernelFileCell[] CellObjects;
        private readonly Stack<int> FreeCells;
        private readonly List<KernelFileCell> Retired = new List<KernelFileCell>(RetiredLimit);
        private readonly int OwnerThreadId = Environment.CurrentManagedThreadId;
        private long NextSequence;
        private bool MapFailureLogged;
        private bool Disposed;

        private KernelFileReads(BinaryEmulator Emulator, IGuestKernel Kernel, ulong Address, IntPtr Host, int CellCount)
        {
            this.Emulator = Emulator;
            this.Kernel = Kernel;
            SlotsAddress = Address;
            Slots = (ulong*)Host;
            Cells = (KernelCellData*)((byte*)Host + SlotsBytes);
            CellObjects = new KernelFileCell[CellCount];
            FreeCells = new Stack<int>(CellCount);
            for (int i = CellCount - 1; i >= 0; i--)
                FreeCells.Push(i);
        }

        internal static KernelFileReads TryCreate(BinaryEmulator Instance, WindowsGuest Guest)
        {
            int CellCount = MemoryBudget.KernelReadFiles;
            if (Instance.GuestKernel is not IGuestKernel Kernel || !Guest.TryGetSyscallNumber(nameof(NtReadFile), out uint Number)
                || !Kernel.TryAllocateMemory((ulong)(SlotsBytes + CellCount * CellSize), out ulong Address, out IntPtr Host))
                return null;

            KernelFileReads Reads = new KernelFileReads(Instance, Kernel, Address, Host, CellCount);
            if (!Kernel.RegisterSyscall(Number, nameof(NtReadFile), Reads.EmitRead, Reads.FinishRead))
                return null;

            WindowsFileStream.HostFileChanging += Reads.OnHostFileChanging;
            Instance.RefreshGuestKernel();
            return Reads;
        }

        private void EmitRead(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            Label Abort = Builder.Abort;
            Label BufferClear = a.CreateLabel();
            Label StatusClear = a.CreateLabel();
            Label Probe = a.CreateLabel();
            Label Retry = a.CreateLabel();

            a.test(r10, r10);
            a.jz(Abort);
            a.test(rdx, rdx);
            a.jnz(Abort);
            a.test(r8, r8);
            a.jnz(Abort);

            a.mov(rax, (long)(Builder.UserEnd - StackArgsEnd));
            a.cmp(rsp, rax);
            a.ja(Abort);
            Builder.BeginUserAccess();
            a.mov(rdx, __qword_ptr[rsp + IoStatusBlockArg]);
            a.mov(r11, __qword_ptr[rsp + BufferArg]);
            a.mov(r9d, __dword_ptr[rsp + LengthArg]);
            a.mov(rsi, __qword_ptr[rsp + ByteOffsetArg]);
            a.or(rsi, __qword_ptr[rsp + KeyArg]);
            Builder.EndUserAccess();
            a.jnz(Abort);
            a.test(r9d, r9d);
            a.jz(Abort);
            a.cmp(r9d, MaxReadBytes);
            a.ja(Abort);

            // The two tag bits make the masked handle four times its slot index.
            a.mov(eax, r10d);
            a.and(eax, (SlotCount - 1) << 2);
            Builder.LoadAddress(rbx, SlotsAddress);
            a.mov(rax, __qword_ptr[rbx + rax * (SlotSize / 4)]);
            a.mov(ecx, eax);
            a.cmp(rcx, r10);
            a.jne(Abort);
            a.shr(rax, 32);
            a.lea(rbx, __[rbx + rax + SlotsBytes]);

            a.mov(rax, (long)Builder.UserEnd);
            a.mov(r8, r11);
            a.add(r8, r9);
            a.jc(Abort);
            a.cmp(r8, rax);
            a.ja(Abort);
            a.sub(rax, IoStatusBlockSize);
            a.cmp(rdx, rax);
            a.ja(Abort);

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

            // A locked or of zero write-probes the status block and each buffer page first, as the host path does.
            a.lea(rcx, __[r8 - 1]);
            a.mov(rax, r11);
            Builder.BeginUserAccess();
            a.@lock.or(__byte_ptr[rdx], 0);
            a.@lock.or(__byte_ptr[rdx + IoStatusBlockSize - 1], 0);
            a.Label(ref Probe);
            a.@lock.or(__byte_ptr[rax], 0);
            a.or(rax, GuestPageMask);
            a.add(rax, 1);
            a.cmp(rax, rcx);
            a.jbe(Probe);
            Builder.EndUserAccess();
            Builder.Save(SavedIoStatusBlock, rdx);
            Builder.Save(SavedLength, r9);

            a.mov(rax, __qword_ptr[rbx + KernelCellData.OffsetField]);
            a.Label(ref Retry);
            a.test(rax, rax);
            a.js(Abort);
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
            Builder.Commit(__qword_ptr[rbx + KernelCellData.OffsetField], r8, Retry);

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
            if (Disposed || Handle > uint.MaxValue || (EventHandle | ApcRoutine | ByteOffsetPtr | KeyPtr) != 0 || Length == 0
                || Length > MaxReadBytes)
                return;

            if (File.KernelCell == null)
            {
                // A view pays for itself only when as many reads of this size remain as it took to qualify.
                if (!IsEligible(File) || !Kernel.Enabled || ++File.SlowReads < ReadsBeforeView
                    || !TryCreateCell(File, File.Position + (long)Length * ReadsBeforeView))
                    return;
            }

            ulong* Slot = SlotOf(Handle);
            ulong Packed = (ulong)(uint)(File.KernelCell.Index * CellSize) << 32 | Handle;
            if (*Slot != Packed)
                Volatile.Write(ref *Slot, Packed);
        }

        private static bool IsEligible(WinFile File)
            => !File.AllowsWrite(File.GrantedAccess) && (File.ShareAccess & WinSysHelper.FILE_SHARE_WRITE) == 0
               && File.Synchronous && !File.NoIntermediateBuffering && !File.Device && !File.Directory && !File.IsNamedPipe
               && File.ConsoleKind == ConsoleObjectKind.None && File.SharedPosition == null && File.CompletionHandle == 0
               && File.Locks.Count == 0;

        private ulong* SlotOf(ulong Handle) => Slots + ((Handle >> 2) & (SlotCount - 1));

        // A file too short for the view is looked at again after more reads. Any other failure backs off longer.
        private bool TryCreateCell(WinFile File, long MinLength)
        {
            File.SlowReads = ReadsBeforeView - ReadsAfterFailure;
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
                        File.SlowReads = 0;
                    return false;
                }

                if (!TryMakeRoom())
                    return false;

                if (!Kernel.TryMapView(View.Pointer, (ulong)Length, out ulong ViewAddress))
                {
                    LogMapFailure(File, "no kernel view could be mapped");
                    return false;
                }

                int Index = FreeCells.Pop();
                KernelCellData* Data = Cells + Index;
                Data->Offset = File.Position;
                Data->ViewAddress = ViewAddress;
                Data->ViewLength = (ulong)Length;

                KernelFileCell Cell = new KernelFileCell
                {
                    Owner = this,
                    Index = Index,
                    Sequence = NextSequence++,
                    Data = Data,
                    File = File,
                    View = View,
                    ViewAddress = ViewAddress,
                    ViewLength = (ulong)Length,
                };

                File.KernelCell = Cell;
                CellObjects[Index] = Cell;
                View = null;
                return true;
            }
            catch (Exception Ex) when (Ex is IOException || Ex is UnauthorizedAccessException || Ex is ArgumentException)
            {
                LogMapFailure(File, Ex.Message);
                return false;
            }
            finally
            {
                View?.Dispose();
            }
        }

        private void LogMapFailure(WinFile File, string Reason)
        {
            if (MapFailureLogged)
                return;

            MapFailureLogged = true;
            Utils.LogError($"[KernelFileReads] {File.Path}: {Reason}. Its reads stay on the host path.");
        }

        private bool TryMakeRoom()
        {
            if (FreeCells.Count != 0)
                return true;

            if (Retired.Count == 0)
            {
                KernelFileCell Oldest = null;
                for (int i = 0; i < CellObjects.Length; i++)
                {
                    KernelFileCell Cell = CellObjects[i];
                    if (Cell != null && Cell.IsLive && (Oldest == null || Cell.Sequence < Oldest.Sequence))
                        Oldest = Cell;
                }

                if (Oldest != null)
                    Retire(Oldest);
            }

            Flush();
            return FreeCells.Count != 0;
        }

        // NT ignores the two low tag bits of a handle, so any variant of it releases the slot.
        internal void ReleaseHandle(ulong Handle)
        {
            if (Disposed || Handle > uint.MaxValue)
                return;

            ulong* Slot = SlotOf(Handle);
            ulong Value = *Slot;
            if (Value != 0 && ((uint)Value & ~3u) == ((uint)Handle & ~3u))
                Volatile.Write(ref *Slot, 0);
        }

        // The view keeps the host file mapped, which on a Windows host stops any other process from truncating it.
        internal void ReleaseFile(WinFile File)
        {
            if (File.KernelCell is not KernelFileCell Cell)
                return;

            Retire(Cell);
            Flush();
        }

        // A read that ends inside the view means the host file shrank under it.
        internal void NoteEnd(WinFile File, long End)
        {
            if (File.KernelCell is not KernelFileCell Cell || (ulong)End >= Cell.ViewLength)
                return;

            Retire(Cell);
            Flush();
        }

        private bool HasCells => FreeCells.Count != CellObjects.Length;

        // A lock changes no byte, so the views can wait for a later flush.
        internal void ReleaseLockedPath(string GuestPath)
        {
            if (!HasCells)
                return;

            RetireMatching(GuestPath, null);
            if (Retired.Count >= RetiredLimit)
                Flush();
        }

        // Every view of the path is unmapped on return, so the host file can then change.
        internal void ReleasePath(string GuestPath, string ChildPrefix)
        {
            if (!HasCells)
                return;

            if (RetireMatching(GuestPath, ChildPrefix))
                Flush();
        }

        private bool RetireMatching(string GuestPath, string ChildPrefix)
        {
            bool Any = false;
            for (int i = 0; i < CellObjects.Length; i++)
            {
                KernelFileCell Cell = CellObjects[i];
                if (Cell == null || !WinSysHelper.MatchesGuestPath(Cell.File.Path, GuestPath, ChildPrefix))
                    continue;

                if (Cell.IsLive)
                    Retire(Cell);
                Any = true;
            }

            return Any;
        }

        // The event is process-wide, so a change from another emulator here counts as one from another process. Without
        // SMP no thread takes KernelLock, and only the thread that built this runs the guest.
        private void OnHostFileChanging(string GuestPath)
        {
            if (Monitor.IsEntered(Emulator.KernelLock) || (!Emulator.SmpEnabled && Environment.CurrentManagedThreadId == OwnerThreadId))
                ReleasePath(GuestPath, null);
        }

        // Runs before the backend is disposed, because the unmap goes through it.
        public void Dispose()
        {
            WindowsFileStream.HostFileChanging -= OnHostFileChanging;
            if (Disposed)
                return;

            Disposed = true;
            for (int i = 0; i < CellObjects.Length; i++)
            {
                if (CellObjects[i] is KernelFileCell Cell && Cell.IsLive)
                    Retire(Cell);
            }

            Flush();
        }

        private void Retire(KernelFileCell Cell)
        {
            long Offset = Cell.Claim();
            uint CellOffset = (uint)(Cell.Index * CellSize);
            for (int i = 0; i < SlotCount; i++)
            {
                ulong Value = Slots[i];
                if (Value != 0 && (uint)(Value >> 32) == CellOffset)
                    Volatile.Write(ref Slots[i], 0);
            }

            Cell.File.KernelCell = null;
            Cell.File.SlowReads = 0;
            Cell.File.Position = Offset;
            Retired.Add(Cell);
        }

        private void Flush()
        {
            if (Retired.Count == 0)
                return;

            Span<ulong> Addresses = stackalloc ulong[Retired.Count];
            for (int i = 0; i < Retired.Count; i++)
                Addresses[i] = Retired[i].ViewAddress;
            Kernel.UnmapViews(Addresses);

            for (int i = 0; i < Retired.Count; i++)
            {
                KernelFileCell Cell = Retired[i];
                Cell.View.Dispose();
                CellObjects[Cell.Index] = null;
                FreeCells.Push(Cell.Index);
            }

            Retired.Clear();
        }
    }
}
