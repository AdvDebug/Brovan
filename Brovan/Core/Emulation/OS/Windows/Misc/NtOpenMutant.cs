using System;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenMutant : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                ulong MutantHandlePtr = Instance.WinHelper.GetArg(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);

                return HandleOpenMutant64(Instance, MutantHandlePtr, DesiredAccess, ObjectAttributesPtr);
            }


            uint MutantHandlePtr32 = (uint)Instance.WinHelper.GetArg(0);
            uint DesiredAccess32 = (uint)Instance.WinHelper.GetArg(1);
            uint ObjectAttributesPtr32 = (uint)Instance.WinHelper.GetArg(2);

            return HandleOpenMutant32(Instance, MutantHandlePtr32, DesiredAccess32, ObjectAttributesPtr32);
        }

        private static NTSTATUS HandleOpenMutant64(BinaryEmulator Instance, ulong MutantHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr)
        {
            if (MutantHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(MutantHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            WinMutex Mutex = Instance.WinHelper.WinMutexes.FirstOrDefault(m => m.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Mutex == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Mutex, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance._emulator.WriteMemory(MutantHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleOpenMutant32(BinaryEmulator Instance, uint MutantHandlePtr, uint DesiredAccess, uint ObjectAttributesPtr)
        {
            if (MutantHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(MutantHandlePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName32(ObjectAttributesPtr, out _, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            WinMutex Mutex = Instance.WinHelper.WinMutexes.FirstOrDefault(m => m.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Mutex == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Mutex, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance._emulator.WriteMemory(MutantHandlePtr, (uint)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
