using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateSemaphore : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong SemaphoreHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
                int InitialCount = (int)Instance.WinHelper.GetArg64(3, true);
                int MaximumCount = (int)Instance.WinHelper.GetArg64(4, true);

                return HandleCreateSemaphore64(Instance, SemaphoreHandlePtr, DesiredAccess, ObjectAttributesPtr, InitialCount, MaximumCount);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint SemaphoreHandlePtr32 = Instance.ReadMemoryUInt(SP + 4);
            uint DesiredAccess32 = Instance.ReadMemoryUInt(SP + 8);
            uint ObjectAttributesPtr32 = Instance.ReadMemoryUInt(SP + 12);
            int InitialCount32 = (int)Instance.ReadMemoryUInt(SP + 16);
            int MaximumCount32 = (int)Instance.ReadMemoryUInt(SP + 20);

            return HandleCreateSemaphore32(Instance, SemaphoreHandlePtr32, DesiredAccess32, ObjectAttributesPtr32, InitialCount32, MaximumCount32);
        }

        private static NTSTATUS HandleCreateSemaphore64(BinaryEmulator Instance, ulong SemaphoreHandlePtr, ulong DesiredAccess, ulong ObjectAttributesPtr, int InitialCount, int MaximumCount)
        {
            if (SemaphoreHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SemaphoreHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (MaximumCount <= 0 || InitialCount < 0 || InitialCount > MaximumCount)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            string Name = string.Empty;
            if (ObjectAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                    return ObjectNameStatus;

                Name = FullName;
            }

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.CreateSemaphoreHandle(Name, InitialCount, MaximumCount, Permissions);
            if (!Instance._emulator.WriteMemory(SemaphoreHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleCreateSemaphore32(BinaryEmulator Instance, uint SemaphoreHandlePtr, uint DesiredAccess, uint ObjectAttributesPtr, int InitialCount, int MaximumCount)
        {
            if (SemaphoreHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SemaphoreHandlePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (MaximumCount <= 0 || InitialCount < 0 || InitialCount > MaximumCount)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            string Name = string.Empty;
            if (ObjectAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName32(ObjectAttributesPtr, out _, out _, out _, out string FullName, out NTSTATUS ObjectNameStatus))
                    return ObjectNameStatus;

                Name = FullName;
            }

            AccessMask Permissions = (AccessMask)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.CreateSemaphoreHandle(Name, InitialCount, MaximumCount, Permissions);
            if (!Instance._emulator.WriteMemory(SemaphoreHandlePtr, (uint)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
