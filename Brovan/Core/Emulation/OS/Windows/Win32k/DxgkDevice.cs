using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal sealed class DxgkDevice : DxgkObject
    {
        internal DxgkAdapter Adapter;

        internal readonly List<DxgkContext> Contexts = new();
        internal readonly List<DxgkPagingQueue> PagingQueues = new();
        internal readonly HashSet<DxgkResource> Resources = new();
        internal readonly HashSet<DxgkAllocation> Allocations = new();
        internal readonly HashSet<DxgkFence> Fences = new();

        // NT: signals on a faulted device succeed without effect.
        internal bool Faulted;

        internal void Fault(BinaryEmulator Instance, DxgkProcess Process)
        {
            Faulted = true;
            foreach (DxgkContext Context in Contexts)
                Process.Gpu.Discard(Context);

            foreach (DxgkFence Fence in Fences)
                Fence.SetValue(Instance, ulong.MaxValue);
        }

        // Contexts go first, so their queued signals reach the fences.
        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            foreach (DxgkContext Context in Contexts.ToArray())
                Process.Destroy(Instance, Context);

            foreach (DxgkPagingQueue Queue in PagingQueues.ToArray())
                Process.Destroy(Instance, Queue);

            // Each release removes the object from its HashSet, which the enumeration allows.
            foreach (DxgkResource Resource in Resources)
                Process.Destroy(Instance, Resource);

            foreach (DxgkAllocation Allocation in Allocations)
                Process.Destroy(Instance, Allocation);

            foreach (DxgkFence Fence in Fences)
                Process.Destroy(Instance, Fence);
        }
    }

    internal sealed class DxgkContext : DxgkDeviceObject
    {
        internal const uint DmaBufferPrivateDataSize = 304;
        internal const uint DmaBufferSize = 0x1000;

        internal ulong CommandBuffer;
        internal bool DmaBufferReady;
        internal bool IsBlocked;
        internal uint InProcessPriority;
        internal readonly Queue<DxgkPacket> Packets = new();

        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            Process.Gpu.Finish(Instance, this);
            Device.Contexts.Remove(this);

            // NT: the buffer is freed by its address and size, whatever the guest put there since.
            if (CommandBuffer != 0)
            {
                ulong Base = CommandBuffer;
                ulong Size = DmaBufferSize;
                NtFreeVirtualMemory.Free(Instance, ref Base, ref Size, NtFreeVirtualMemory.MemRelease);
                CommandBuffer = 0;
            }
        }
    }

    internal sealed class DxgkPagingQueue : DxgkDeviceObject
    {
        // NT
        internal const ulong InitialFenceValue = 7000;

        internal DxgkFence Fence;

        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            Device.PagingQueues.Remove(this);
            Process.Destroy(Instance, Fence);
        }
    }

    internal sealed class DxgkResource : DxgkDeviceObject
    {
        internal bool Shared;
        internal bool NtSecuritySharing;
        internal readonly List<DxgkAllocation> Allocations = new();

        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            Device.Resources.Remove(this);
            foreach (DxgkAllocation Allocation in Allocations)
            {
                Allocation.Resource = null;
                Process.Destroy(Instance, Allocation);
            }

            Allocations.Clear();
        }
    }

    internal sealed class DxgkAllocation : DxgkDeviceObject
    {
        internal DxgkStorage Storage;
        internal DxgkResource Resource;
        internal bool SwapChainBackBuffer;

        // NT: the first Lock maps the allocation, and the view stays until the allocation goes.
        internal ulong View;
        internal uint LockCount;

        internal override void Release(BinaryEmulator Instance, DxgkProcess Process)
        {
            Device.Allocations.Remove(this);
            Resource?.Allocations.Remove(this);
            DxgkProcess.UnmapStorage(Instance, View, Storage.Memory);
            Storage.Release(Instance, Process);
        }
    }
}
