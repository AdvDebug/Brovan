using System;
using System.Linq;
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
            bool InitialOwner = (uint)Instance.WinHelper.GetArg(3) != 0;

            return HandleCreateMutant(Instance, MutantHandlePtr, DesiredAccess, ObjectAttributesPtr, InitialOwner);
        }

        private static NTSTATUS HandleCreateMutant(BinaryEmulator Instance, ulong MutantHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, bool InitialOwner)
        {
            if (MutantHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(MutantHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string Name = string.Empty;
            if (ObjectAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                    return ObjectNameStatus;

                Name = FullName;
            }

            bool CreatedNew = string.IsNullOrEmpty(Name) || Instance.WinHelper.WinMutexes.FirstOrDefault(m => m.Name.Equals(Name, StringComparison.OrdinalIgnoreCase)) == null;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.CreateMutexHandle(Name, Permissions);

            if (CreatedNew && InitialOwner)
                TakeInitialOwnership(Instance, Handle.Handle);

            if (!Instance.WinHelper.WritePointer(MutantHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
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
