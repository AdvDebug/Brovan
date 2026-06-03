using System;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSemaphore : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong SemaphoreHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

                return HandleOpenSemaphore64(Instance, SemaphoreHandlePtr, DesiredAccess, ObjectAttributesPtr);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint SemaphoreHandlePtr32 = Instance.ReadMemoryUInt(SP + 4);
            uint DesiredAccess32 = Instance.ReadMemoryUInt(SP + 8);
            uint ObjectAttributesPtr32 = Instance.ReadMemoryUInt(SP + 12);

            return HandleOpenSemaphore32(Instance, SemaphoreHandlePtr32, DesiredAccess32, ObjectAttributesPtr32);
        }

        private static NTSTATUS HandleOpenSemaphore64(BinaryEmulator Instance, ulong SemaphoreHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr)
        {
            if (SemaphoreHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SemaphoreHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            WinSemaphore Semaphore = Instance.WinHelper.WinSemaphores.FirstOrDefault(s => s.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Semaphore == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Semaphore, Permissions);
            Instance.WinHelper.WinHandles.Add(Handle);

            if (!Instance._emulator.WriteMemory(SemaphoreHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleOpenSemaphore32(BinaryEmulator Instance, uint SemaphoreHandlePtr, uint DesiredAccess, uint ObjectAttributesPtr)
        {
            if (SemaphoreHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SemaphoreHandlePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName32(ObjectAttributesPtr, out _, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            WinSemaphore Semaphore = Instance.WinHelper.WinSemaphores.FirstOrDefault(s => s.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Semaphore == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Semaphore, Permissions);
            Instance.WinHelper.WinHandles.Add(Handle);

            if (!Instance._emulator.WriteMemory(SemaphoreHandlePtr, (uint)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
