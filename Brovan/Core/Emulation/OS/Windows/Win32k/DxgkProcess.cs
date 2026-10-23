using System.Buffers.Binary;
using System.Collections.Generic;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal abstract class DxgkObject
    {
        internal uint Handle;

        internal abstract void Release(BinaryEmulator Instance, DxgkProcess Process);
    }

    internal abstract class DxgkDeviceObject : DxgkObject
    {
        internal DxgkDevice Device;
    }

    internal abstract class DxgkNtObject : IHandleObject
    {
        internal string Name;

        public string ObjectId => Name;

        public abstract HandleType ObjectType { get; }

        internal abstract string TypeName { get; }

        internal abstract void Release(BinaryEmulator Instance, DxgkProcess Process);
    }

    // DXGPROCESS in dxgkrnl. A handle of the wrong type fails as an unknown handle.
    internal sealed class DxgkProcess
    {
        private const int IndexShift = 6;
        private const uint IndexMask = 0xFFFFFF;
        private const int InstanceShift = 30;

        // NT reuses the oldest freed index once more than this many are free, and cycles instances 1, 2, 3 (HMGRTABLE).
        private const int MinFreeEntries = 128;

        internal const ulong StoragePageSize = 0x1000;

        internal const int PreferredAdapterSize = 16;

        private readonly List<object> Values = new();
        private readonly List<byte> Instances = new();
        private readonly Queue<int> FreeIndices = new();
        private readonly HashSet<DxgkNtObject> NtObjects = new();
        private readonly HashSet<DxgkCompositionBuffer> PendingBuffers = new();

        internal readonly DxgkFencePages FencePages = new();
        internal readonly DxgkGpu Gpu;

        internal ulong AllocatedBytes;
        private int FenceReferences;
        internal uint PreferredNodeCounter;
        internal readonly byte[] DefaultHighPerformanceAdapter = new byte[PreferredAdapterSize];
        internal bool DefaultHighPerformanceAdapterSet;
        internal uint HybridQueryState1;
        internal uint HybridQueryState2;

        internal DxgkProcess()
        {
            Gpu = new DxgkGpu(this);
        }

        internal bool TryAdd(object Value, out uint Handle)
        {
            int Index;
            if (FreeIndices.Count > MinFreeEntries || (FreeIndices.Count != 0 && Values.Count >= MemoryBudget.DxgkHandles))
            {
                Index = FreeIndices.Dequeue();
                Values[Index] = Value;
            }
            else if (Values.Count < MemoryBudget.DxgkHandles)
            {
                Index = Values.Count;
                Values.Add(Value);
                Instances.Add(1);
            }
            else
            {
                Handle = 0;
                return false;
            }

            Handle = (uint)Instances[Index] << InstanceShift | (uint)Index << IndexShift;
            if (Value is DxgkObject Object)
                Object.Handle = Handle;
            return true;
        }

        internal bool TryGet<T>(uint Handle, out T Value) where T : class
        {
            Value = TryGetIndex(Handle, out int Index) ? Values[Index] as T : null;
            return Value != null;
        }

        internal bool TryGet<T>(uint Handle, DxgkDevice Device, out T Object) where T : DxgkDeviceObject
        {
            if (TryGet(Handle, out Object) && Object.Device == Device)
                return true;

            Object = null;
            return false;
        }

        internal NTSTATUS TryResolve<T>(BinaryEmulator Instance, DxgkDevice Device, ulong ArrayPtr, Span<T> Objects) where T : DxgkDeviceObject
        {
            Span<byte> Handles = Instance.WinHelper.ReadMemorySpan(ArrayPtr, (uint)Objects.Length * sizeof(uint));
            if (Handles.IsEmpty)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            for (int Index = 0; Index < Objects.Length; Index++)
            {
                if (!TryGet(BinaryPrimitives.ReadUInt32LittleEndian(Handles.Slice(Index * sizeof(uint))), Device, out T Object))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                Objects[Index] = Object;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // An object that owns something goes through Destroy, which releases it.
        internal bool TryRemove<T>(uint Handle) where T : class
        {
            if (!TryGetIndex(Handle, out int Index) || Values[Index] is not T Value || Value is DxgkObject)
                return false;

            Free(Index);
            return true;
        }

        internal void Destroy(BinaryEmulator Instance, DxgkObject Object)
        {
            if (!TryGetIndex(Object.Handle, out int Index) || !ReferenceEquals(Values[Index], Object))
                return;

            Free(Index);
            Object.Release(Instance, this);
        }

        // Handles are not closed at dispose, so the NT objects still open are released here.
        internal void ReleaseAll(BinaryEmulator Instance)
        {
            for (int Index = 0; Index < Values.Count; Index++)
            {
                if (Values[Index] is DxgkObject Object)
                    Destroy(Instance, Object);
            }

            foreach (DxgkNtObject Object in NtObjects)
                Object.Release(Instance, this);

            NtObjects.Clear();
        }

        // On failure the handle close releases the object.
        internal NTSTATUS InsertNtObject(BinaryEmulator Instance, DxgkNtObject Object, AccessMask DesiredAccess, ulong HandlePtr)
        {
            Object.Name = $"{Object.TypeName}_{Instance.WinHelper.GenerateAnonymousObjectId()}";
            NtObjects.Add(Object);
            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Object, DesiredAccess);
            if (Instance.WinHelper.WritePointer(HandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_SUCCESS;

            Instance.WinHelper.CloseHandle(Handle.Handle);
            return NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        internal bool NeedsService => PendingBuffers.Count != 0 || Gpu.HasBlocked;

        // Buffers retire first, because a retire can free room for a present that holds up its context.
        // A HashSet allows Remove while it is enumerated.
        internal void Service(BinaryEmulator Instance)
        {
            foreach (DxgkCompositionBuffer Buffer in PendingBuffers)
            {
                Buffer.RetireConsumed(Instance);
                if (Buffer.Pending.Count == 0)
                    PendingBuffers.Remove(Buffer);
            }

            if (Gpu.HasBlocked)
                Gpu.Run(Instance);
        }

        internal void AddPendingBuffer(DxgkCompositionBuffer Buffer) => PendingBuffers.Add(Buffer);

        internal void RemovePendingBuffer(DxgkCompositionBuffer Buffer) => PendingBuffers.Remove(Buffer);

        internal void ReleaseNtObject(BinaryEmulator Instance, DxgkNtObject Object)
        {
            if (NtObjects.Remove(Object))
                Object.Release(Instance, this);
        }

        // A wait whose thread gave up keeps its references until a fence changes, so a full budget forgets those first.
        internal bool TryReserveFenceReferences(int Count)
        {
            if (Count > MemoryBudget.DxgkFenceReferences - FenceReferences)
            {
                for (int Index = 0; Index < Values.Count; Index++)
                    (Values[Index] as DxgkFence)?.ForgetDeadWaiters(this);

                if (Count > MemoryBudget.DxgkFenceReferences - FenceReferences)
                    return false;
            }

            FenceReferences += Count;
            return true;
        }

        internal void ReleaseFenceReferences(int Count) => FenceReferences -= Count;

        internal static bool TryMapStorage(BinaryEmulator Instance, IntPtr Storage, ulong Size, out ulong Base)
            => Instance.TryFindFreeBaseAddress(Size, WinSysHelper.AllocationGranularity, Instance.BaseAddress, Instance.MaxAddress, out Base)
                && Instance.MapSharedMemoryRegion(Base, Size, MemoryProtection.ReadWrite, Storage, WinSysHelper.PAGE_READWRITE, Base);

        // A guest that freed the view may have put its own memory at the address.
        internal static void UnmapStorage(BinaryEmulator Instance, ulong Base, IntPtr Storage)
        {
            if (Base != 0 && Instance.GetHostPointer(Base, StoragePageSize) == Storage)
                Instance.UnmapMemoryRegion(Base);
        }

        private void Free(int Index)
        {
            Values[Index] = null;
            Instances[Index] = (byte)(Instances[Index] == 3 ? 1 : Instances[Index] + 1);
            FreeIndices.Enqueue(Index);
        }

        private bool TryGetIndex(uint Handle, out int Index)
        {
            Index = (int)((Handle >> IndexShift) & IndexMask);
            return Index < Values.Count && Values[Index] != null && Instances[Index] == Handle >> InstanceShift;
        }
    }
}
