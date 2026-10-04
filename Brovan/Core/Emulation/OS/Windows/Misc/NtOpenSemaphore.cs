using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSemaphore : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong SemaphoreHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

            return HandleOpenSemaphore(Instance, SemaphoreHandlePtr, DesiredAccess, ObjectAttributesPtr);
        }

        private static NTSTATUS HandleOpenSemaphore(BinaryEmulator Instance, ulong SemaphoreHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr)
        {
            if (SemaphoreHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SemaphoreHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            uint Attributes = Instance.WinHelper.ReadObjectAttributesFlags(ObjectAttributesPtr);
            if (!Instance.WinHelper.TryLookupNameForOpen(FullName, Attributes, out WinSemaphore? Semaphore, out NTSTATUS Status))
                return Status;

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Semaphore, (AccessMask)(uint)DesiredAccess);

            if (!Instance.WinHelper.WritePointer(SemaphoreHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
