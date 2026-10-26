using System;
using System.Collections.Generic;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // The application side of a DirectComposition channel, which win32kbase keeps as CApplicationChannel.
    internal sealed class CompositionChannel
    {
        private readonly CompositionProcess Process;

        internal uint Id;

        // The batch page is a view of host storage that the channel keeps until it ends.
        internal uint Size;
        internal ulong Base;
        internal IntPtr Storage;

        internal readonly ulong[] ConnectionIds = new ulong[2];

        // NT indexes the resource table by ID - 1, grows it to the highest ID created and never shrinks it.
        private readonly List<CompositionResource> Resources = new();

        // A reference cycle never reaches count 0, so the end of the channel releases what every live resource holds.
        private readonly HashSet<CompositionResource> Live = new();

        private readonly Stack<CompositionResource> PendingReleases = new();
        private bool Draining;
        private bool Ending;

        internal CompositionChannel(CompositionProcess Process)
        {
            this.Process = Process;
        }

        internal CompositionTableSet Tables => Process.Tables;

        internal CompositionResource Lookup(uint Id) => Id != 0 && Id <= Resources.Count ? Resources[(int)Id - 1] : null;

        // NT creates the resource (CreatePrivateMarshaler) before it applies the ID rules of CreateResource.
        internal NTSTATUS TryCreateResource(uint Id, uint Type)
        {
            CompositionResource Resource = CompositionResource.Create(Type, this);
            if (Resource == null)
                return CompositionResource.Unserved;

            if (Process.LiveResources >= MemoryBudget.CompositionResources)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (Id == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Id > Resources.Count)
            {
                long Growth = Id - Resources.Count;
                if (Growth > MemoryBudget.CompositionResources - Process.ResourceSlots)
                    return NTSTATUS.STATUS_NO_MEMORY;

                Process.ResourceSlots += (int)Growth;
                Resources.EnsureCapacity((int)Id);
                while (Resources.Count < Id)
                    Resources.Add(null);
            }
            else if (Resources[(int)Id - 1] != null)
            {
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            Resources[(int)Id - 1] = Resource;
            Live.Add(Resource);
            Process.LiveResources++;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // The resource lives on while something references it.
        internal void RemoveId(uint Id)
        {
            if (Id != 0 && Id <= Resources.Count)
                Resources[(int)Id - 1] = null;
        }

        // A resource at count 0 releases what it references through a stack, so a long reference chain never recurses
        // (CApplicationChannel::ReleaseResource).
        internal void ReleaseResource(CompositionResource Resource)
        {
            Resource.References--;
            if (Ending || Resource.References != 0)
                return;

            Live.Remove(Resource);
            Process.LiveResources--;
            PendingReleases.Push(Resource);
            if (Draining)
                return;

            Draining = true;
            while (PendingReleases.TryPop(out CompositionResource Next))
                Next.ReleaseReferences();

            Draining = false;
        }

        internal void Release(BinaryEmulator Instance)
        {
            if (Storage != IntPtr.Zero)
            {
                Instance.WinHelper.UnmapSystemView(Base, Storage);
                Instance._emulator.ReleaseSharedStorage(Storage);
                Process.AllocatedBytes -= Size;
                Storage = IntPtr.Zero;
            }

            Ending = true;
            foreach (CompositionResource Resource in Live)
                Resource.ReleaseReferences();

            Process.LiveResources -= Live.Count;
            Live.Clear();
            Process.ResourceSlots -= Resources.Count;
            Resources.Clear();
        }
    }

    // The DirectComposition state of a process, which win32kbase keeps as CProcessData.
    internal sealed class CompositionProcess
    {
        private const uint PageSize = 0x1000;

        // A channel ID is its slot index plus one. NT fills a free slot next-fit from a cursor and moves the cursor
        // past it, and appends without moving the cursor (CLinearObjectTableBase::InsertObject).
        private readonly List<CompositionChannel> Slots = new();
        private int Live;
        private int Cursor;

        internal ulong AllocatedBytes;

        internal int LiveResources;
        internal int ResourceSlots;

        // Null when no table set covers the guest's win32kbase.sys, and then no batch is handled.
        internal CompositionTableSet Tables { get; private set; }
        private bool TablesResolved;

        private void ResolveTables(BinaryEmulator Instance)
        {
            TablesResolved = true;
            bool Issues = (Instance.Settings.Flags & LogFlags.Issues) != 0;
            if (!Instance.WinHelper.TryGetSystemFileVersion(CompositionTableSet.KeyFile, out ushort Build, out ushort Revision))
            {
                if (Issues)
                    Instance.TriggerEventMessage($"[!] DirectComposition: {CompositionTableSet.KeyFile} is not in the system files, import the Windows image again", LogFlags.Issues);

                return;
            }

            Tables = CompositionTableSet.Find(Build, Revision);
            if (Tables == null && Issues)
                Instance.TriggerEventMessage($"[!] DirectComposition: {CompositionTableSet.KeyFile} {Build}.{Revision} is not a version the tables cover", LogFlags.Issues);
        }

        internal NTSTATUS TryCreateChannel(BinaryEmulator Instance, uint RequestedSize, out CompositionChannel Channel)
        {
            Channel = null;
            if (!TablesResolved)
                ResolveTables(Instance);

            uint Size = unchecked(RequestedSize + PageSize - 1) & ~(PageSize - 1);
            if (RequestedSize != 0 && Size == 0)
                return NTSTATUS.STATUS_NO_MEMORY;

            if (Live >= MemoryBudget.CompositionChannels)
                return NTSTATUS.STATUS_NO_MEMORY;

            CompositionChannel Created = new CompositionChannel(this) { Size = Size };
            if (Size != 0)
            {
                if (Size > MemoryBudget.CompositionBatchBytes || Size > MemoryBudget.CompositionBatchTotalBytes - AllocatedBytes)
                    return NTSTATUS.STATUS_COMMITMENT_LIMIT;

                IntPtr Storage = Instance._emulator.AllocateSharedStorage(Size);
                if (Storage == IntPtr.Zero)
                    return NTSTATUS.STATUS_COMMITMENT_LIMIT;

                if (!Instance.WinHelper.TryMapSystemView(Storage, Size, GuestUnmaps: true, NoChange: true, out ulong Base))
                {
                    Instance._emulator.ReleaseSharedStorage(Storage);
                    return NTSTATUS.STATUS_NO_MEMORY;
                }

                Created.Base = Base;
                Created.Storage = Storage;
                AllocatedBytes += Size;
            }

            int Index;
            if (Live < Slots.Count)
            {
                Index = Cursor;
                while (Slots[Index] != null)
                    Index = (Index + 1) % Slots.Count;

                Cursor = (Index + 1) % Slots.Count;
                Slots[Index] = Created;
            }
            else
            {
                Index = Slots.Count;
                Slots.Add(Created);
            }

            Live++;
            Created.Id = (uint)Index + 1;
            Channel = Created;
            return NTSTATUS.STATUS_SUCCESS;
        }

        // Every channel here is an application channel (CApplicationChannel::ReferenceHandleAndLock).
        internal NTSTATUS Reference(uint Id, out CompositionChannel Channel)
        {
            Channel = Id != 0 && Id <= Slots.Count ? Slots[(int)Id - 1] : null;
            return Channel != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_DENIED;
        }

        internal NTSTATUS DestroyChannel(BinaryEmulator Instance, uint Id)
        {
            NTSTATUS Status = Reference(Id, out CompositionChannel Channel);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Slots[(int)Id - 1] = null;
            Live--;
            Channel.Release(Instance);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal void ReleaseAll(BinaryEmulator Instance)
        {
            foreach (CompositionChannel Channel in Slots)
                Channel?.Release(Instance);

            Slots.Clear();
            Live = 0;
            Cursor = 0;
        }
    }
}
