using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace Brovan.Core.Emulation.OS.Windows
{
    // One cache line per cell, so swaps of different files do not contend.
    [StructLayout(LayoutKind.Explicit, Size = KernelFileTable.CellSize)]
    internal struct KernelCellData
    {
        internal const int OffsetField = 0;
        internal const int ViewAddressField = 8;
        internal const int ViewLengthField = 16;
        internal const int UsedField = 24;

        [FieldOffset(OffsetField)] internal long Offset;
        [FieldOffset(ViewAddressField)] internal ulong ViewAddress;
        [FieldOffset(ViewLengthField)] internal ulong ViewLength;
        [FieldOffset(UsedField)] internal byte Used;
    }

    internal struct KernelFileNotes
    {
        internal int Reads;
        internal int PositionCalls;
    }

    // While bit 63 of the offset is set, the host owns it and guest ring 0 sends every call on the file to the host.
    // Nothing may leave KernelLock between Claim and Release, because a second claim does not own the offset.
    internal sealed unsafe class KernelFileCell
    {
        internal const long HostOwned = long.MinValue;

        internal KernelFileTable Owner;
        internal int Index;
        internal KernelCellData* Data;
        internal WinFile File;
        internal WinImageLayoutCache.View View;

        // Guest ring 0 can write Data, so the host keeps its own copy of the view it mapped.
        internal ulong ViewAddress;
        internal ulong ViewLength;

        internal bool IsLive => File.KernelCell == this;

        internal bool HasView => View != null;

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

    internal sealed unsafe class KernelFileTable : IDisposable
    {
        // A slot packs the handle in bits 0-31, its cell's byte offset in bits 32-47 and the rights the handle passed in
        // bits 48-63, so one load reads all three.
        private const int SlotCount = 256;
        private const int SlotSize = 8;
        private const int SlotsBytes = SlotCount * SlotSize;
        private const int CellShift = 32;
        private const int RightsShift = 48;
        private const ulong CellOffsetMask = 0xFFFF;

        internal const int CellSize = 64;
        private const int MaxCells = (int)(CellOffsetMask + 1) / CellSize;

        internal const ulong ReadRight = 1;

        private const int RetiredViewLimit = 8;

        private readonly BinaryEmulator Emulator;
        private readonly ulong SlotsAddress;
        private readonly ulong* Slots;
        private readonly KernelCellData* Cells;
        private readonly KernelFileCell[] CellObjects;
        private readonly Stack<int> FreeCells;
        private readonly List<KernelFileCell> Retired = new List<KernelFileCell>();

        // The guest can still read these views, so their host memory stays mapped while this object lives.
        private readonly List<WinImageLayoutCache.View> StillMapped = new List<WinImageLayoutCache.View>();
        private readonly int OwnerThreadId = Environment.CurrentManagedThreadId;
        private int ClockHand;
        private int LiveViews;
        private int RetiredViews;
        private bool MapFailureLogged;
        private bool Disposed;

        private KernelFileTable(BinaryEmulator Emulator, IGuestKernel Kernel, ulong Address, IntPtr Host, int CellCount)
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

        internal IGuestKernel Kernel { get; }

        internal bool Enabled => !Disposed && Kernel.Enabled;

        internal static KernelFileTable TryCreate(BinaryEmulator Instance)
        {
            int CellCount = Math.Clamp(MemoryBudget.KernelFileCells, 1, MaxCells);
            if (Instance.GuestKernel is not IGuestKernel Kernel
                || !Kernel.TryAllocateMemory((ulong)(SlotsBytes + CellCount * CellSize), out ulong Address, out IntPtr Host))
                return null;

            KernelFileTable Table = new KernelFileTable(Instance, Kernel, Address, Host, CellCount);
            WindowsFileStream.HostFileChanging += Table.OnHostFileChanging;
            return Table;
        }

        internal static bool CanHoldCell(WinFile File)
            => File.Synchronous && !File.NoIntermediateBuffering && !File.Device && !File.Directory && !File.IsNamedPipe
               && File.ConsoleKind == ConsoleObjectKind.None && File.SharedPosition == null && File.CompletionHandle == 0;

        // Takes the handle in R10, leaves its cell in RBX marked used, and changes RAX and RCX.
        internal void EmitLookup(GuestKernelCallBuilder Builder, ulong Rights)
        {
            Assembler a = Builder.Asm;
            a.test(r10, r10);
            a.jz(Builder.Abort);

            // The two tag bits make the masked handle four times its slot index.
            a.mov(eax, r10d);
            a.and(eax, (SlotCount - 1) << 2);
            Builder.LoadAddress(rbx, SlotsAddress);
            a.mov(rax, __qword_ptr[rbx + rax * (SlotSize / 4)]);
            a.mov(ecx, eax);
            a.cmp(rcx, r10);
            a.jne(Builder.Abort);

            if (Rights != 0)
            {
                a.mov(rcx, rax);
                a.shr(rcx, RightsShift);
                a.and(ecx, (int)Rights);
                a.cmp(ecx, (int)Rights);
                a.jne(Builder.Abort);
            }

            a.shr(rax, CellShift);
            a.movzx(eax, ax);
            a.lea(rbx, __[rbx + rax + SlotsBytes]);
            a.mov(__byte_ptr[rbx + KernelCellData.UsedField], 1);
        }

        // Takes the cell in RBX and leaves its offset in RAX. A lost commit goes back to the returned label.
        internal static Label EmitLoadOffset(GuestKernelCallBuilder Builder)
        {
            Assembler a = Builder.Asm;
            Label Retry = a.CreateLabel();
            a.mov(rax, __qword_ptr[rbx + KernelCellData.OffsetField]);
            a.Label(ref Retry);
            a.test(rax, rax);
            a.js(Builder.Abort);
            return Retry;
        }

        internal static void EmitCommitOffset(GuestKernelCallBuilder Builder, AssemblerRegister64 NewOffset, Label Retry)
            => Builder.Commit(__qword_ptr[rbx + KernelCellData.OffsetField], NewOffset, Retry);

        private static ulong PackSlot(ulong Handle, int CellIndex, ulong Rights)
            => Handle | (ulong)(uint)(CellIndex * CellSize) << CellShift | Rights << RightsShift;

        private static int SlotCellOffset(ulong Slot) => (int)((Slot >> CellShift) & CellOffsetMask);

        private static ulong SlotRights(ulong Slot) => Slot >> RightsShift;

        private ulong* SlotOf(ulong Handle) => Slots + ((Handle >> 2) & (SlotCount - 1));

        // Another handle in the slot is replaced and goes back to the host path.
        internal void SetSlot(ulong Handle, KernelFileCell Cell, ulong Rights)
        {
            if (Disposed || Handle > uint.MaxValue || !Cell.IsLive)
                return;

            ulong* Slot = SlotOf(Handle);
            ulong Old = *Slot;
            if (Old != 0 && (uint)Old == (uint)Handle && SlotCellOffset(Old) == Cell.Index * CellSize)
                Rights |= SlotRights(Old);

            ulong Packed = PackSlot(Handle, Cell.Index, Rights);
            if (Old != Packed)
                Volatile.Write(ref *Slot, Packed);
            Volatile.Write(ref Cell.Data->Used, 1);
        }

        internal bool TryCreateCell(WinFile File, out KernelFileCell Cell)
        {
            Cell = null;
            if (Disposed || File.KernelCell != null || !CanHoldCell(File) || !TryTakeIndex(false, out int Index))
                return false;

            Cell = Install(File, Index, null, 0, 0);
            return true;
        }

        // Maps the view and takes it over on success. On failure the caller still owns it.
        internal bool TryCreateViewCell(WinFile File, WinImageLayoutCache.View View, ulong Length)
        {
            if (Disposed || File.KernelCell != null || !CanHoldCell(File) || !TryTakeIndex(true, out int Index))
                return false;

            if (!Kernel.TryMapView(View.Pointer, Length, out ulong ViewAddress))
            {
                FreeCells.Push(Index);
                LogMapFailure(File, "no kernel view could be mapped");
                return false;
            }

            Install(File, Index, View, ViewAddress, Length);
            LiveViews++;
            return true;
        }

        private KernelFileCell Install(WinFile File, int Index, WinImageLayoutCache.View View, ulong ViewAddress, ulong ViewLength)
        {
            KernelCellData* Data = Cells + Index;
            Data->Offset = File.Position;
            Data->ViewAddress = ViewAddress;
            Data->ViewLength = ViewLength;
            Data->Used = 1;

            KernelFileCell Cell = new KernelFileCell
            {
                Owner = this,
                Index = Index,
                Data = Data,
                File = File,
                View = View,
                ViewAddress = ViewAddress,
                ViewLength = ViewLength,
            };

            File.KernelCell = Cell;
            CellObjects[Index] = Cell;
            return Cell;
        }

        internal void LogMapFailure(WinFile File, string Reason)
        {
            if (MapFailureLogged)
                return;

            MapFailureLogged = true;
            Utils.LogError($"[KernelFileTable] {File.Path}: {Reason}. The file stays on the host path.");
        }

        private bool TryTakeIndex(bool View, out int Index)
        {
            if (View && LiveViews >= MemoryBudget.KernelReadFiles)
            {
                RetireUnused(true);
                Flush();
            }

            if (FreeCells.Count == 0 && Retired.Count == 0)
                RetireUnused(false);

            if (FreeCells.Count == 0)
                Flush();

            return FreeCells.TryPop(out Index);
        }

        // A cell that a call used since the hand last passed it gets a second chance.
        private void RetireUnused(bool ViewsOnly)
        {
            for (int Step = 0; Step < CellObjects.Length * 2; Step++)
            {
                KernelFileCell Cell = CellObjects[ClockHand];
                ClockHand = (ClockHand + 1) % CellObjects.Length;
                if (Cell == null || !Cell.IsLive || (ViewsOnly && !Cell.HasView))
                    continue;

                if (Volatile.Read(ref Cell.Data->Used) != 0)
                {
                    Volatile.Write(ref Cell.Data->Used, 0);
                    continue;
                }

                Retire(Cell);
                return;
            }
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

        // A view keeps the host file mapped, which on a Windows host stops any other process from truncating it.
        internal void ReleaseFile(WinFile File)
        {
            if (File.KernelCell is not KernelFileCell Cell)
                return;

            Retire(Cell);
            if (Cell.HasView)
                Flush();
        }

        internal void ReleaseCell(KernelFileCell Cell)
        {
            if (!Cell.IsLive)
                return;

            Retire(Cell);
            Flush();
        }

        private bool HasViews => LiveViews != 0;

        // A lock changes no byte, so the views can wait for a later flush.
        internal void ReleaseLockedPath(string GuestPath)
        {
            if (!HasViews)
                return;

            RetireViewsOf(GuestPath, null);
            if (RetiredViews >= RetiredViewLimit)
                Flush();
        }

        // Every view of the path is unmapped on return, so the host file can then change. A cell without a view stays.
        internal void ReleasePath(string GuestPath, string ChildPrefix)
        {
            if (!HasViews && RetiredViews == 0)
                return;

            if (RetireViewsOf(GuestPath, ChildPrefix))
                Flush();
        }

        private bool RetireViewsOf(string GuestPath, string ChildPrefix)
        {
            bool Any = false;
            for (int i = 0; i < CellObjects.Length; i++)
            {
                KernelFileCell Cell = CellObjects[i];
                if (Cell == null || !Cell.HasView || !WinSysHelper.MatchesGuestPath(Cell.File.Path, GuestPath, ChildPrefix))
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

            for (int i = 0; i < CellObjects.Length; i++)
            {
                if (CellObjects[i] is KernelFileCell Cell && Cell.IsLive)
                    Retire(Cell);
            }

            Flush();
            Disposed = true;
        }

        private void Retire(KernelFileCell Cell)
        {
            long Offset = Cell.Claim();
            int CellOffset = Cell.Index * CellSize;
            for (int i = 0; i < SlotCount; i++)
            {
                ulong Value = Slots[i];
                if (Value != 0 && SlotCellOffset(Value) == CellOffset)
                    Volatile.Write(ref Slots[i], 0);
            }

            Cell.File.KernelCell = null;
            Cell.File.KernelNotes = default;
            Cell.File.Position = Offset;
            if (Cell.HasView)
            {
                LiveViews--;
                RetiredViews++;
            }

            Retired.Add(Cell);
        }

        // A call that loaded a slot before it was cleared can still hold its cell, so every processor leaves the guest
        // before a retired cell is used again.
        private void Flush()
        {
            if (Retired.Count == 0)
                return;

            int Views = 0;
            for (int i = 0; i < Retired.Count; i++)
            {
                if (Retired[i].HasView)
                    Views++;
            }

            Span<ulong> Addresses = stackalloc ulong[Views];
            Span<bool> Unmapped = stackalloc bool[Views];
            int Next = 0;
            for (int i = 0; i < Retired.Count; i++)
            {
                if (Retired[i].HasView)
                    Addresses[Next++] = Retired[i].ViewAddress;
            }

            if (Views == 0)
                Kernel.EvictProcessors();
            else
                Kernel.UnmapViews(Addresses, Unmapped);

            Next = 0;
            for (int i = 0; i < Retired.Count; i++)
            {
                KernelFileCell Cell = Retired[i];
                if (Cell.HasView)
                {
                    if (Unmapped[Next++])
                        Cell.View.Dispose();
                    else
                        StillMapped.Add(Cell.View);
                }

                CellObjects[Cell.Index] = null;
                FreeCells.Push(Cell.Index);
            }

            Retired.Clear();
            RetiredViews = 0;
        }
    }
}
