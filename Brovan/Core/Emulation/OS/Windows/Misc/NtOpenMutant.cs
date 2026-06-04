using System;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenMutant : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong MutantHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

                return HandleOpenMutant64(Instance, MutantHandlePtr, DesiredAccess, ObjectAttributesPtr);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint MutantHandlePtr32 = Instance.ReadMemoryUInt(SP + 4);
            uint DesiredAccess32 = Instance.ReadMemoryUInt(SP + 8);
            uint ObjectAttributesPtr32 = Instance.ReadMemoryUInt(SP + 12);

            return HandleOpenMutant32(Instance, MutantHandlePtr32, DesiredAccess32, ObjectAttributesPtr32);
        }

        private static NTSTATUS HandleOpenMutant64(BinaryEmulator Instance, ulong MutantHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr)
        {
            if (MutantHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(MutantHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            WinMutex Mutex = Instance.WinHelper.WinMutexes.FirstOrDefault(m => m.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Mutex == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Mutex, Permissions);
            Instance.WinHelper.WinHandles.Add(Handle);

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
            Instance.WinHelper.WinHandles.Add(Handle);

            if (!Instance._emulator.WriteMemory(MutantHandlePtr, (uint)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
