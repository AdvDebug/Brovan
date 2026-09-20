using System;
using System.Linq;
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

            WinSemaphore Semaphore = Instance.WinHelper.WinSemaphores.FirstOrDefault(s => s.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Semaphore == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Semaphore, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WinHelper.WritePointer(SemaphoreHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
