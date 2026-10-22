using System.Collections.Generic;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal abstract class DxgkPacket
    {
        internal virtual int FenceReferences => 0;

        internal abstract bool TryRun(BinaryEmulator Instance);

        internal virtual void Retire(BinaryEmulator Instance)
        {
        }
    }

    // NT sets Start when the work begins, and a WARP thread in the guest sets Finish when it ends (WARPGPUCMDSYNC).
    internal sealed class DxgkSubmitPacket : DxgkPacket
    {
        internal WinEvent Start;
        internal WinEvent Finish;
        private bool Started;

        internal override bool TryRun(BinaryEmulator Instance)
        {
            if (!Started)
            {
                Started = true;
                if (Start != null)
                    Start.Signaled = true;
            }

            return Finish == null || Instance.TryAcquireWaitObject(Finish, null, out _) == true;
        }
    }

    internal sealed class DxgkSignalPacket : DxgkPacket
    {
        internal DxgkFence[] Fences;
        internal ulong[] Values;

        internal override int FenceReferences => Fences.Length;

        internal override bool TryRun(BinaryEmulator Instance)
        {
            Apply(Instance);
            return true;
        }

        internal override void Retire(BinaryEmulator Instance) => Apply(Instance);

        private void Apply(BinaryEmulator Instance)
        {
            for (int Index = 0; Index < Fences.Length; Index++)
                Fences[Index].Signal(Instance, Values[Index]);
        }
    }

    // The wake scan runs blocked contexts, because any guest path can set a finish event.
    internal sealed class DxgkGpu
    {
        private readonly DxgkProcess Process;
        private readonly List<DxgkContext> Blocked = new();
        private int QueuedPackets;

        internal DxgkGpu(DxgkProcess Owner)
        {
            Process = Owner;
        }

        internal bool HasBlocked => Blocked.Count != 0;

        internal bool TryEnqueue(BinaryEmulator Instance, DxgkContext Context, DxgkPacket Packet)
        {
            if (QueuedPackets >= MemoryBudget.DxgkQueuedPackets || !Process.TryReserveFenceReferences(Packet.FenceReferences))
                return false;

            Context.Packets.Enqueue(Packet);
            QueuedPackets++;
            Advance(Instance, Context);
            return true;
        }

        internal void Run(BinaryEmulator Instance)
        {
            for (int Index = Blocked.Count - 1; Index >= 0; Index--)
            {
                if (Index < Blocked.Count)
                    Advance(Instance, Blocked[Index]);
            }
        }

        // NT: queued work finishes when its context goes, without waiting for finish events.
        internal void Finish(BinaryEmulator Instance, DxgkContext Context)
        {
            while (Context.Packets.Count != 0)
                Remove(Context).Retire(Instance);

            Unblock(Context);
        }

        internal void Discard(DxgkContext Context)
        {
            while (Context.Packets.Count != 0)
                Remove(Context);

            Unblock(Context);
        }

        private void Advance(BinaryEmulator Instance, DxgkContext Context)
        {
            while (Context.Packets.TryPeek(out DxgkPacket Packet))
            {
                if (!Packet.TryRun(Instance))
                {
                    if (!Context.IsBlocked)
                    {
                        Context.IsBlocked = true;
                        Blocked.Add(Context);
                    }

                    return;
                }

                Remove(Context);
            }

            Unblock(Context);
        }

        private void Unblock(DxgkContext Context)
        {
            if (Context.IsBlocked)
            {
                Context.IsBlocked = false;
                Blocked.Remove(Context);
            }
        }

        private DxgkPacket Remove(DxgkContext Context)
        {
            DxgkPacket Packet = Context.Packets.Dequeue();
            QueuedPackets--;
            Process.ReleaseFenceReferences(Packet.FenceReferences);
            return Packet;
        }
    }
}
