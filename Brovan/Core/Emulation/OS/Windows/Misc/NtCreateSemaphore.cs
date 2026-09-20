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

            string Name = string.Empty;
            if (ObjectAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                    return ObjectNameStatus;

                Name = FullName;
            }

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.CreateSemaphoreHandle(Name, InitialCount, MaximumCount, Permissions);
            if (!Instance.WinHelper.WritePointer(SemaphoreHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
