using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateMutant : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong MutantHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            bool InitialOwner = (byte)Instance.WinHelper.GetArg(3) != 0;

            return HandleCreateMutant(Instance, MutantHandlePtr, DesiredAccess, ObjectAttributesPtr, InitialOwner);
        }

        private static NTSTATUS HandleCreateMutant(BinaryEmulator Instance, ulong MutantHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, bool InitialOwner)
        {
            if (MutantHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(MutantHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinMutex? Existing, out Status))
                return Status;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle;
            if (Existing != null)
            {
                Handle = Instance.WinHelper.OpenObjectHandle(Existing, Permissions);
            }
            else
            {
                Handle = Instance.WinHelper.CreateMutexHandle(Name, Permissions);
                if (InitialOwner)
                    TakeInitialOwnership(Instance, Handle.Handle);
            }

            if (!Instance.WinHelper.WritePointer(MutantHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }

        private static void TakeInitialOwnership(BinaryEmulator Instance, ulong Handle)
        {
            WinMutex Mutex = Instance.WinHelper.HandleManager.GetObjectByHandle<WinMutex>(Handle);
            if (Mutex == null || Instance.CurrentThread == null)
                return;

            Mutex.Signaled = false;
            Mutex.Abandoned = false;
            Mutex.OwnerThreadId = Instance.CurrentThread.ThreadId;
            Mutex.RecursionCount = 1;
        }
    }
}
