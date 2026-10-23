using System.Buffers.Binary;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDdDDIShareObjects : IWinSyscall
    {
        // The checks follow DxgkShareObjectsInternal, CreateSharedResourceNtObject and CreateSharedSyncNtObject.
        private const uint MaxObjects = 3;
        private const uint KeyedMutexObjects = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Count = (uint)Instance.WinHelper.GetArg(0);
            ulong ObjectsPtr = Instance.WinHelper.GetArg(1);
            ulong AttributesPtr = Instance.WinHelper.GetArg(2);
            AccessMask DesiredAccess = (AccessMask)(uint)Instance.WinHelper.GetArg(3);
            ulong SharedHandlePtr = Instance.WinHelper.GetArg(4);

            if (Count - 1 >= MaxObjects)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Span<byte> Handles = stackalloc byte[(int)MaxObjects * sizeof(uint)];
            Handles = Handles.Slice(0, (int)Count * sizeof(uint));
            if (!Instance.ReadMemory(ObjectsPtr, Handles))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint First = BinaryPrimitives.ReadUInt32LittleEndian(Handles);
            if (AttributesPtr == 0 || First == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS NameStatus = Instance.WinHelper.ReadCreateObjectName(AttributesPtr, out string Name, out _);
            if (NameStatus != NTSTATUS.STATUS_SUCCESS)
                return NameStatus;

            if (Name != null)
                return Instance.WinUnimplemented;

            DxgkProcess Process = Instance.WinHelper.DxgkProcess;
            DxgkNtObject Shared;
            if (Process.TryGet(First, out DxgkResource Resource))
            {
                if (Count == KeyedMutexObjects)
                    return Instance.WinUnimplemented;

                if (Count != 1 || !Resource.Shared || !Resource.NtSecuritySharing)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                DxgkStorage[] Storage = new DxgkStorage[Resource.Allocations.Count];
                for (int Index = 0; Index < Storage.Length; Index++)
                    Storage[Index] = Resource.Allocations[Index].Storage;

                DxgkStorage.AddReferences(Storage);
                Shared = new DxgkSharedResource { Storage = Storage };
            }
            else if (Process.TryGet(First, out DxgkFence Fence) && Count == 1 && Fence.NtSecuritySharing)
            {
                Shared = new DxgkSharedSyncObject { Fence = Fence };
            }
            else
            {
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            return Process.InsertNtObject(Instance, Shared, DesiredAccess, SharedHandlePtr);
        }
    }
}
