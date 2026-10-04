using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateSemaphore : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SemaphoreHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            int InitialCount = (int)Instance.WinHelper.GetArg(3);
            int MaximumCount = (int)Instance.WinHelper.GetArg(4);

            return HandleCreateSemaphore(Instance, SemaphoreHandlePtr, DesiredAccess, ObjectAttributesPtr, InitialCount, MaximumCount);
        }

        private static NTSTATUS HandleCreateSemaphore(BinaryEmulator Instance, ulong SemaphoreHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, int InitialCount, int MaximumCount)
        {
            if (SemaphoreHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SemaphoreHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (MaximumCount <= 0 || InitialCount < 0 || InitialCount > MaximumCount)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            NTSTATUS Status = Instance.WinHelper.ReadCreateObjectName(ObjectAttributesPtr, out string Name, out uint Attributes);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.TryLookupNameForCreate(Name, Attributes, out WinSemaphore? Existing, out Status))
                return Status;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Existing != null
                ? Instance.WinHelper.OpenObjectHandle(Existing, Permissions)
                : Instance.WinHelper.CreateSemaphoreHandle(Name, InitialCount, MaximumCount, Permissions);

            if (!Instance.WinHelper.WritePointer(SemaphoreHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Status;
        }
    }
}
