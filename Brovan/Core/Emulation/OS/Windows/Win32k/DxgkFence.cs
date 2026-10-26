using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // The guest may write the page slot, so Value is the one that counts and the slot only mirrors it.
    internal sealed class DxgkFence : DxgkDeviceObject
    {
        internal DxgkFencePage Page;
        internal int Slot;
        internal ulong Value;
        internal ulong QueuedValue;
        internal bool OwnedByPagingQueue;
        internal bool NtSecuritySharing;
        internal bool Released;

        internal readonly List<DxgkFenceWaiter> Waiters = new();

        internal ulong CpuAddress => Page.Base + (ulong)Slot * DxgkFencePages.SlotSize;

        internal static NTSTATUS TryCreate(BinaryEmulator Instance, DxgkProcess Process, DxgkDevice Device, ulong InitialValue, out DxgkFence Fence)
        {
            Fence = null;
            if (!Process.FencePages.TryAllocate(Instance, out DxgkFencePage Page, out int Slot))
                return NTSTATUS.STATUS_NO_MEMORY;

            DxgkFence Created = new() { Device = Device, Page = Page, Slot = Slot, Value = InitialValue, QueuedValue = InitialValue };
            if (!Process.TryAdd(Created, out _))
            {
                Process.FencePages.Free(Instance, Page, Slot);
                return NTSTATUS.STATUS_NO_MEMORY;
            }

            Page.Write(Slot, InitialValue);
            Device.Fences.Add(Created);
            Fence = Created;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static bool TryReadValues(BinaryEmulator Instance, ulong ArrayPtr, Span<ulong> Values)
            => Instance.ReadMemory(ArrayPtr, MemoryMarshal.AsBytes(Values));

        internal static NTSTATUS TryReadGpuArguments(BinaryEmulator Instance, DxgkProcess Process, DxgkDevice Device, ulong HandlesPtr,
            ulong ValuesPtr, uint Count, out DxgkFence[] Fences, out ulong[] Values)
        {
            Fences = new DxgkFence[Count];
            Values = null;
            NTSTATUS Status = Process.TryResolve(Instance, Device, HandlesPtr, Fences.AsSpan());
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Values = new ulong[Count];
            return TryReadValues(Instance, ValuesPtr, Values) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // NT returns STATUS_NO_MEMORY when it cannot allocate the arrays of one call.
        internal static bool IsCountBounded(uint Count) => Count <= (uint)MemoryBudget.DxgkFenceReferences;

        // NT: a monitored fence never moves back.
        internal static bool IsForward(ReadOnlySpan<DxgkFence> Fences, ReadOnlySpan<ulong> Values, bool CountQueued)
        {
            for (int Index = 0; Index < Fences.Length; Index++)
            {
                if (Values[Index] < (CountQueued ? Fences[Index].QueuedValue : Fences[Index].Value))
                    return false;
            }

            return true;
        }

        internal static void RaiseQueuedValues(ReadOnlySpan<DxgkFence> Fences, ReadOnlySpan<ulong> Values)
        {
            for (int Index = 0; Index < Fences.Length; Index++)
            {
                if (Values[Index] > Fences[Index].QueuedValue)
                    Fences[Index].QueuedValue = Values[Index];
            }
        }

        internal void ForgetDeadWaiters(DxgkProcess Process)
        {
            for (int Index = Waiters.Count - 1; Index >= 0; Index--)
            {
                if (Index < Waiters.Count && Waiters[Index].IsDead)
                    Waiters[Index].Forget(Process);
            }
        }

        internal void Signal(BinaryEmulator Instance, ulong NewValue)
        {
            if (!Released && NewValue > Value)
                SetValue(Instance, NewValue);
        }

        internal void SetValue(BinaryEmulator Instance, ulong NewValue)
        {
            Value = NewValue;
            Page.Write(Slot, NewValue);

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            for (int Index = Waiters.Count - 1; Index >= 0; Index--)
            {
                if (Index >= Waiters.Count)
                    continue;

                DxgkFenceWaiter Waiter = Waiters[Index];
                if (Waiter.IsDead)
                    Waiter.Forget(Process);
                else if (Waiter.IsSatisfied)
                    Waiter.Complete(Instance, Process);
            }

            WakeBlockedContexts(Instance, Process);
        }

        private static void WakeBlockedContexts(BinaryEmulator Instance, DxgkProcess Process)
        {
            if (Process.Gpu.HasFenceWaits)
                Instance.WakeSignal.Bump();
        }

        // NT: a destroyed fence sets the events still waiting on it.
        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            Released = true;
            Device.Fences.Remove(this);
            while (Waiters.Count != 0)
                Waiters[^1].Complete(Instance, Process);

            Process.FencePages.Free(Instance, Page, Slot);
            WakeBlockedContexts(Instance, Process);
        }
    }

    internal sealed class DxgkFencePage
    {
        internal ulong Base;
        internal IntPtr Storage;
        internal int Handed;
        internal int Live;

        // NT: the slot freed last is the one handed out next.
        internal readonly Stack<int> FreeSlots = new();

        internal unsafe void Write(int Slot, ulong Value)
        {
            Volatile.Write(ref *(ulong*)((byte*)Storage + Slot * DxgkFencePages.SlotSize), Value);
        }
    }

    // NT: all devices of a process share its fence pages.
    internal sealed class DxgkFencePages
    {
        internal const int SlotSize = 64;
        private const ulong PageSize = DxgkProcess.StoragePageSize;
        private const int SlotsPerPage = (int)PageSize / SlotSize;

        private readonly List<DxgkFencePage> Pages = new();

        internal bool TryAllocate(BinaryEmulator Instance, out DxgkFencePage Page, out int Slot)
        {
            foreach (DxgkFencePage Candidate in Pages)
            {
                if (Candidate.Live == SlotsPerPage)
                    continue;

                Page = Candidate;
                Slot = Candidate.FreeSlots.Count != 0 ? Candidate.FreeSlots.Pop() : Candidate.Handed++;
                Candidate.Live++;
                return true;
            }

            Page = null;
            Slot = 0;
            IntPtr Storage = Instance._emulator.AllocateSharedStorage(PageSize);
            if (Storage == IntPtr.Zero)
                return false;

            // NT lets the guest unmap this view. Here the unmap fails, because later fences take free slots on the page.
            if (!Instance.WinHelper.TryMapSystemView(Storage, PageSize, GuestUnmaps: false, NoChange: false, out ulong Base))
            {
                Instance._emulator.ReleaseSharedStorage(Storage);
                return false;
            }

            Page = new DxgkFencePage { Base = Base, Storage = Storage, Handed = 1, Live = 1 };
            Pages.Add(Page);
            return true;
        }

        internal void Free(BinaryEmulator Instance, DxgkFencePage Page, int Slot)
        {
            if (--Page.Live == 0)
            {
                Pages.Remove(Page);
                Release(Instance, Page);
                return;
            }

            Page.Write(Slot, 0);
            Page.FreeSlots.Push(Slot);
        }

        private static void Release(BinaryEmulator Instance, DxgkFencePage Page)
        {
            Instance.WinHelper.UnmapSystemView(Page.Base, Page.Storage);
            Instance._emulator.ReleaseSharedStorage(Page.Storage);
        }
    }

    internal sealed class DxgkFenceWaiter
    {
        internal DxgkFence[] Fences;
        internal ulong[] Values;
        internal bool WaitAny;
        internal WinEvent Event;
        internal DxgkFenceWait Request;

        internal bool IsDead => Request != null && !Request.IsLive;

        internal bool IsSatisfied => AreSatisfied(Fences, Values, WaitAny);

        // NT: a destroyed fence ends the wait.
        internal static bool AreSatisfied(ReadOnlySpan<DxgkFence> Fences, ReadOnlySpan<ulong> Values, bool WaitAny)
        {
            for (int Index = 0; Index < Fences.Length; Index++)
            {
                bool Reached = Fences[Index].Released || Fences[Index].Value >= Values[Index];
                if (Reached == WaitAny)
                    return WaitAny;
            }

            return !WaitAny;
        }

        internal bool TryRegister(DxgkProcess Process)
        {
            foreach (DxgkFence Fence in Fences)
                Fence.ForgetDeadWaiters(Process);

            if (!Process.TryReserveFenceReferences(Fences.Length))
                return false;

            foreach (DxgkFence Fence in Fences)
            {
                if (Fence.Waiters.Count == 0 || Fence.Waiters[^1] != this)
                    Fence.Waiters.Add(this);
            }

            return true;
        }

        internal void Complete(BinaryEmulator Instance, DxgkProcess Process)
        {
            Forget(Process);
            if (Event != null)
                Event.Signaled = true;
            else if (Request.IsLive)
                Request.Complete(Instance, NTSTATUS.STATUS_SUCCESS);
        }

        internal void Forget(DxgkProcess Process)
        {
            foreach (DxgkFence Fence in Fences)
            {
                int Index = Fence.Waiters.LastIndexOf(this);
                if (Index >= 0)
                    Fence.Waiters.RemoveAt(Index);
            }

            Process.ReleaseFenceReferences(Fences.Length);
        }
    }

    // NT: the wait has no timeout, and an alert does not end it.
    internal sealed class DxgkFenceWait : ParkedIoRequest
    {
        internal override WinFile File => null;

        internal override string WaitLabel => "dxgk-fence";
    }
}
