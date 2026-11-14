using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // The application side of a DirectComposition channel, which win32kbase keeps as CApplicationChannel.
    internal sealed class CompositionChannel
    {
        private const AccessMask OpenAccess = (AccessMask)1;

        internal readonly CompositionProcess Process;

        internal uint Id;

        // The batch page is a view of host storage that the channel keeps until it ends.
        internal uint Size;
        internal ulong Base;
        internal IntPtr Storage;

        internal readonly ulong[] ConnectionIds = new ulong[2];

        // Opening a channel posts its own first batch, so Committed starts at 1.
        private uint Ordinal = 1;
        internal uint Committed { get; private set; } = 1;
        internal uint Processed { get; private set; }
        internal uint Confirmed { get; private set; }

        // NT builds a batch only at the first commit, after a change or a Synchronize, or when flag 1 asks for one.
        private bool BatchDue = true;
        private bool FragmentSynchronized;

        private WinEvent CompletionEvent;
        private bool CompletionSerialized;

        // NT indexes the resource table by ID - 1, grows it to the highest ID created and never shrinks it.
        private readonly List<CompositionResource> Resources = new();

        // A reference cycle never reaches count 0, so the end of the channel releases what every live resource holds.
        private readonly HashSet<CompositionResource> Live = new();

        private readonly Stack<CompositionResource> PendingReleases = new();
        private bool Draining;
        private bool Ending;

        // Changes stay in order, except that a later value of a property replaces the earlier one in place.
        private readonly List<CompositionChange> Pending = new();
        private readonly Dictionary<(CompositionResource Resource, CompositionChangeKind Kind, byte Key), int> PendingValues = new();

        private readonly HashSet<CompositionResource> GateWatch = new();
        private readonly List<ulong> PendingSynchronizations = new();
        private int CapturedReleases;
        internal int PendingCreates { get; private set; }

        internal readonly Dictionary<CompositionResource, CompositorResource> CommittedResources = new();

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
            return Resource == null ? CompositionResource.Unserved : TryAdd(Id, Resource);
        }

        private NTSTATUS TryAdd(uint Id, CompositionResource Resource)
        {
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

        // NT opens a shared visual as a visual target while no other target of it lives (OpenExternalSharedReadResource).
        internal NTSTATUS OpenSharedResource(BinaryEmulator Instance, uint Id, ulong Handle, uint Type, out CompositionResource Opened)
        {
            Opened = null;
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(Handle, OpenAccess, out CompositionObject Object);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Object is not CompositionSharedVisual Shared)
                return NTSTATUS.STATUS_OBJECT_TYPE_MISMATCH;

            if (!CompositionResource.IsDerived(Tables, Shared.ResourceType, Type))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Type != Shared.ResourceType)
                return CompositionResource.Unserved;

            if (Shared.Opened)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Shared.Opened = true;
            CompositionVisualTarget Target = new(Tables.TypeOf(CompositionClass.VisualTarget), this, Shared);
            Status = TryAdd(Id, Target);
            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Target.ReleaseReferences(Instance);
                return Status;
            }

            Opened = Target;
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
        internal void ReleaseResource(BinaryEmulator Instance, CompositionResource Resource)
        {
            Resource.References--;
            if (Ending || Resource.References != 0)
                return;

            Live.Remove(Resource);
            Process.LiveResources--;
            CaptureRelease(Resource);
            PendingReleases.Push(Resource);
            if (Draining)
                return;

            Draining = true;
            while (PendingReleases.TryPop(out CompositionResource Next))
                Next.ReleaseReferences(Instance);

            Draining = false;
        }

        // Only changes count, because the releases a record causes are bounded by the live resources.
        internal bool CanCapture => Process.PendingChanges < MemoryBudget.CompositionPendingChanges;

        internal int PendingCount => Pending.Count;

        internal ReadOnlySpan<CompositionChange> PendingChanges => CollectionsMarshal.AsSpan(Pending);

        internal void MarkChanged() => BatchDue = true;

        internal void MarkChanged(BinaryEmulator Instance, in CompositionChange Change, bool Due = true)
        {
            BatchDue |= Due;
            if (Due && Change.Resource != null)
                Change.Resource.DueOrdinal = Ordinal + 1;

            bool Coalesces = Change.Kind is CompositionChangeKind.Value or CompositionChangeKind.Object;
            if (Coalesces && PendingValues.TryGetValue((Change.Resource, Change.Kind, Change.Key), out int Index))
            {
                ref CompositionChange Held = ref CollectionsMarshal.AsSpan(Pending)[Index];
                ReferencedNtObject Replaced = Held.Object;
                Held.Value = Change.Value;
                Held.Object = Change.Object;
                Replaced?.Unreference(Instance);
                return;
            }

            if (Coalesces)
                PendingValues[(Change.Resource, Change.Kind, Change.Key)] = Pending.Count;
            else if (Change.Kind is CompositionChangeKind.Create or CompositionChangeKind.Open)
                PendingCreates++;

            if (Change.Kind == CompositionChangeKind.None)
                return;

            Pending.Add(Change);
            Process.PendingChanges++;
        }

        private void CaptureRelease(CompositionResource Resource)
        {
            GateWatch.Remove(Resource);
            Pending.Add(new CompositionChange { Kind = CompositionChangeKind.Release, Resource = Resource });
            CapturedReleases++;
            Process.CapturedReleases++;
        }

        internal void ClearPending(BinaryEmulator Instance, bool Applied)
        {
            if (!Applied)
            {
                foreach (CompositionChange Change in Pending)
                    Change.Object?.Unreference(Instance);
            }

            Process.PendingChanges -= Pending.Count - CapturedReleases;
            Process.CapturedReleases -= CapturedReleases;
            Pending.Clear();
            PendingValues.Clear();
            PendingCreates = 0;
            CapturedReleases = 0;
        }

        internal NTSTATUS Commit(BinaryEmulator Instance, bool Forced, out uint BatchId)
        {
            BatchId = 0;
            if (!Process.Compositor.TryApply(Instance, this))
                return NTSTATUS.STATUS_NO_MEMORY;

            Ordinal++;
            bool Built = BatchDue || Forced;
            if (Built)
            {
                if (GateWatch.Count != 0)
                    GateWatch.RemoveWhere(EmitsGate);

                Process.CommitSynchronizations(PendingSynchronizations);
                Committed = Ordinal;
                Processed = Committed;
                BatchDue = false;
                FragmentSynchronized = false;
                Process.ScheduleConfirmation(Instance);
            }

            // NT sets a serialized event at every commit, and the other kind only when a built batch returns.
            if (CompletionEvent != null && (Built || CompletionSerialized))
                CompletionEvent.Signaled = true;

            BatchId = Committed;
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal bool HasCompletionEvent => CompletionEvent != null;

        internal void SetCompletionEvent(WinEvent Event, bool Serialized)
        {
            CompletionEvent = Event;
            CompletionSerialized = Serialized;
        }

        internal NTSTATUS Synchronize(out ulong SynchronizationId)
        {
            SynchronizationId = 0;
            if (FragmentSynchronized)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            FragmentSynchronized = true;
            BatchDue = true;
            SynchronizationId = SessionIds.Next(SessionIdKind.CompositionSynchronization);
            PendingSynchronizations.Add(SynchronizationId);
            Process.AddSynchronization(SynchronizationId);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal void WatchGate(CompositionResource Resource) => GateWatch.Add(Resource);

        private bool EmitsGate(CompositionResource Watched)
        {
            if (Watched.DueOrdinal != Ordinal)
                return false;

            Watched.GateCommitted = Watched.GateHeld;
            return true;
        }

        // A commit returns its own batch, so only the channel's first batch returns here.
        internal void ReturnBatches()
        {
            if (Processed == Committed)
                return;

            Processed = Committed;
            if (CompletionEvent != null && !CompletionSerialized)
                CompletionEvent.Signaled = true;
        }

        internal void Confirm(uint Batch) => Confirmed = Math.Max(Confirmed, Math.Min(Batch, Processed));

        // The table keeps its size, so the IDs can be created again (CApplicationChannel::ReleaseAllResources).
        internal void ReleaseAllResources(BinaryEmulator Instance)
        {
            if (Live.Count == 0)
                return;

            for (int Index = 0; Index < Resources.Count; Index++)
            {
                CompositionResource Resource = Resources[Index];
                if (Resource == null)
                    continue;

                Resources[Index] = null;
                ReleaseResource(Instance, Resource);
            }

            if (Live.Count != 0)
            {
                CompositionResource[] Cycles = new CompositionResource[Live.Count];
                Live.CopyTo(Cycles);
                foreach (CompositionResource Resource in Cycles)
                    Resource.ReleaseReferences(Instance);

                foreach (CompositionResource Resource in Cycles)
                {
                    if (!Live.Remove(Resource))
                        continue;

                    Process.LiveResources--;
                    CaptureRelease(Resource);
                }
            }

            MarkChanged();
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

            CompletionEvent = null;
            Ending = true;
            foreach (CompositionResource Resource in Live)
                Resource.ReleaseReferences(Instance);

            Process.LiveResources -= Live.Count;
            Live.Clear();
            Process.ResourceSlots -= Resources.Count;
            Resources.Clear();
            GateWatch.Clear();
            Process.ForgetSynchronizations(Instance, PendingSynchronizations);
            ClearPending(Instance, Applied: false);
            Process.Compositor.ForgetChannel(Instance, this);
        }
    }

    // The DirectComposition state of a process, which win32kbase keeps as CProcessData.
    internal sealed class CompositionProcess
    {
        private const uint PageSize = 0x1000;

        internal const NTSTATUS WindowAlreadyComposed = (NTSTATUS)0x803E0006;

        private const AccessMask TargetAccess = (AccessMask)1;

        // A channel ID is its slot index plus one. NT fills a free slot next-fit from a cursor and moves the cursor
        // past it, and appends without moving the cursor (CLinearObjectTableBase::InsertObject).
        private readonly List<CompositionChannel> Slots = new();
        private int Live;
        private int Cursor;

        internal ulong AllocatedBytes;

        internal int LiveResources;
        internal int ResourceSlots;
        internal int PendingChanges;

        internal int CapturedReleases;

        private sealed class Synchronization
        {
            internal int Outstanding;
            internal bool Committed;
        }

        private readonly Dictionary<ulong, Synchronization> Synchronizations = new();

        internal readonly List<DxgkCompositionToken> CompletedTokens = new();
        private bool TokensChanged;
        private int LiveTokens;
        private int LiveTokenRects;

        internal readonly Compositor Compositor;

        private readonly HashSet<CompositionObject> Objects = new();

        private bool Scheduled;

        internal bool NeedsService => Scheduled || Compositor.HasWork || TokensChanged || Compositor.HasForgottenSurfaces;

        // Null when no table set covers the guest's win32kbase.sys, and then no batch is handled.
        internal CompositionTableSet Tables { get; private set; }
        private bool TablesResolved;

        private readonly Dictionary<(CompositionClass, CompositionSlots, uint), CompositionName> Names = new();
        private readonly HashSet<CompositionName> ResolvedNames = new();

        internal CompositionProcess()
        {
            Compositor = new Compositor(this);
        }

        private void EnsureTables(BinaryEmulator Instance)
        {
            if (TablesResolved)
                return;

            TablesResolved = true;
            bool Issues = (Instance.Settings.Flags & LogFlags.Issues) != 0;
            if (!Instance.WinHelper.TryGetSystemFileVersion(CompositionTableSet.KeyFile, out ushort Build, out ushort Revision))
            {
                if (Issues)
                    Instance.TriggerEventMessage($"[!] DirectComposition: {CompositionTableSet.KeyFile} is not in the system files, import the Windows image again", LogFlags.Issues);

                return;
            }

            Tables = CompositionTableSet.Find(Build, Revision);
            if (Tables == null)
            {
                if (Issues)
                    Instance.TriggerEventMessage($"[!] DirectComposition: {CompositionTableSet.KeyFile} {Build}.{Revision} is not a version the tables cover", LogFlags.Issues);

                return;
            }

            ResolveNames(Instance, Issues);
        }

        // Names join only where the tables accept their ID, size and compare kind, so mismatched files draw less, not wrong.
        private void ResolveNames(BinaryEmulator Instance, bool Issues)
        {
            CompositionNameSet Set = Instance.WinHelper.TryGetSystemFileVersion(CompositionNameSet.KeyFile, out ushort Build, out ushort Revision)
                ? CompositionNameSet.Find(Build, Revision)
                : null;
            if (Set == null)
            {
                if (Issues)
                    Instance.TriggerEventMessage($"[!] DirectComposition: {CompositionNameSet.KeyFile} {Build}.{Revision} is not a version the names cover, nothing is drawn", LogFlags.Issues);

                return;
            }

            foreach ((CompositionName Name, CompositionClass Class, CompositionSlots Setter, uint Id, int Bytes, CompositionCompare? Compare) in Set.Names)
            {
                if (Tables.TryGetRule(Class, Setter, Id, out CompositionRule Rule) && (Setter != CompositionSlots.Buffer || Rule.Bytes == Bytes) &&
                    (Compare == null || Rule.Compare == Compare))
                {
                    Names[(Class, Setter, Id)] = Name;
                    ResolvedNames.Add(Name);
                }
                else if (Issues)
                    Instance.TriggerEventMessage($"[!] DirectComposition: {Name} is not property 0x{Id:X} of the {Class} in {CompositionTableSet.KeyFile}, it is not drawn", LogFlags.Issues);
            }
        }

        internal bool TryGetName(CompositionClass Class, CompositionSlots Setter, uint Property, out CompositionName Name)
            => Names.TryGetValue((Class, Setter, Property), out Name);

        internal bool HasName(CompositionName Name) => ResolvedNames.Contains(Name);

        internal NTSTATUS TryCreateChannel(BinaryEmulator Instance, uint RequestedSize, out CompositionChannel Channel)
        {
            Channel = null;
            EnsureTables(Instance);

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
            ScheduleConfirmation(Instance);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal void ScheduleConfirmation(BinaryEmulator Instance)
        {
            if (Scheduled)
                return;

            Scheduled = true;
            Instance.WakeSignal.Bump();
        }

        internal void Service(BinaryEmulator Instance)
        {
            Scheduled = false;
            foreach (CompositionChannel Channel in Slots)
                Channel?.ReturnBatches();

            Compositor.Service(Instance);
        }

        internal void SnapshotBatches(List<(CompositionChannel Channel, uint Processed)> Batches)
        {
            Batches.Clear();
            foreach (CompositionChannel Channel in Slots)
            {
                if (Channel != null)
                    Batches.Add((Channel, Channel.Processed));
            }
        }

        internal void Confirm(List<(CompositionChannel Channel, uint Processed)> Batches)
        {
            foreach ((CompositionChannel Channel, uint Processed) in Batches)
                Channel.Confirm(Processed);
        }

        internal void ConfirmAll()
        {
            foreach (CompositionChannel Channel in Slots)
                Channel?.Confirm(Channel.Processed);
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

        internal NTSTATUS TryCreateTarget(BinaryEmulator Instance, ulong Hwnd, uint Slot, ulong HandlePtr)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || Window.Destroyed)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (IsTargetlessWindow(Window))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Compositor.HasTarget(Hwnd, Slot))
                return WindowAlreadyComposed;

            EnsureTables(Instance);
            CompositionSharedVisual Visual = new(Tables != null ? Tables.TypeOf(CompositionClass.Visual) : 0);
            Compositor.AttachTarget(Instance, Hwnd, Slot, Visual);
            NTSTATUS Status = Visual.Insert(Instance, TargetAccess, HandlePtr);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                Compositor.DetachTarget(Instance, Hwnd, Slot);

            return Status;
        }

        internal NTSTATUS DestroyTarget(BinaryEmulator Instance, ulong Hwnd, uint Slot)
        {
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || Window.Destroyed || IsTargetlessWindow(Window))
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return Compositor.DetachTarget(Instance, Hwnd, Slot) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NOT_FOUND;
        }

        private static bool IsTargetlessWindow(WinWindow Window)
            => Win32kHelper.MaskFunctionId(Window.Fnid) is Win32kHelper.FnidDesktop or Win32kHelper.FnidMessageWnd;

        internal void AddObject(CompositionObject Object) => Objects.Add(Object);

        internal void ForgetObject(CompositionObject Object) => Objects.Remove(Object);

        internal void AddSynchronization(ulong Id) => Synchronizations[Id] = new Synchronization();

        internal void CommitSynchronizations(List<ulong> Ids)
        {
            foreach (ulong Id in Ids)
            {
                if (Synchronizations.TryGetValue(Id, out Synchronization Record))
                {
                    Record.Committed = true;
                    TokensChanged = true;
                    DropSettled(Id, Record);
                }
            }

            Ids.Clear();
        }

        internal void ForgetSynchronizations(BinaryEmulator Instance, List<ulong> Ids)
        {
            foreach (ulong Id in Ids)
                Synchronizations.Remove(Id);

            if (Ids.Count != 0)
                LetTokensEnter(Instance);

            Ids.Clear();
        }

        private void LetTokensEnter(BinaryEmulator Instance)
        {
            TokensChanged = true;
            if (CompletedTokens.Count != 0)
                Instance.WakeSignal.Bump();
        }

        internal void NotifyPendingPresent(ulong SynchronizationId)
        {
            if (Synchronizations.TryGetValue(SynchronizationId, out Synchronization Record))
                Record.Outstanding++;
        }

        internal void NotifyCompletedPresent(BinaryEmulator Instance, ulong SynchronizationId)
        {
            if (Synchronizations.TryGetValue(SynchronizationId, out Synchronization Record) && Record.Outstanding != 0)
            {
                Record.Outstanding--;
                if (Record.Outstanding == 0)
                    LetTokensEnter(Instance);

                DropSettled(SynchronizationId, Record);
            }
        }

        private void DropSettled(ulong Id, Synchronization Record)
        {
            if (Record.Committed && Record.Outstanding == 0)
                Synchronizations.Remove(Id);
        }

        internal bool TryAddToken(int Rects)
        {
            if (LiveTokens >= MemoryBudget.CompositionTokens || Rects > MemoryBudget.CompositionTokenUpdates - LiveTokenRects)
                return false;

            LiveTokens++;
            LiveTokenRects += Rects;
            return true;
        }

        internal void RemoveToken(int Rects)
        {
            LiveTokens--;
            LiveTokenRects -= Rects;
        }

        internal bool ShouldDeferToken(DxgkCompositionToken Token)
            => Synchronizations.TryGetValue(Token.SynchronizationId, out Synchronization Record) && (Record.Outstanding != 0 || !Record.Committed);

        internal void TokenCompleted(BinaryEmulator Instance, DxgkCompositionToken Token)
        {
            Token.Reference();
            CompletedTokens.Add(Token);
            TokensChanged = true;
            Instance.WakeSignal.Bump();
        }

        internal bool TakeTokensChanged()
        {
            bool Changed = TokensChanged;
            TokensChanged = false;
            return Changed;
        }

        internal void ReleaseAll(BinaryEmulator Instance)
        {
            foreach (CompositionChannel Channel in Slots)
                Channel?.Release(Instance);

            Slots.Clear();
            Live = 0;
            Cursor = 0;
            Scheduled = false;
            foreach (DxgkCompositionToken Token in CompletedTokens)
                Token.Unreference(Instance);

            CompletedTokens.Clear();
            TokensChanged = false;
            Synchronizations.Clear();
            Compositor.ReleaseAll(Instance);

            CompositionObject[] Left = new CompositionObject[Objects.Count];
            Objects.CopyTo(Left);
            foreach (CompositionObject Object in Left)
                Object.Release(Instance);
        }
    }
}
