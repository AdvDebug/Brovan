using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySemaphore : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong SemaphoreHandle = Instance.WinHelper.GetArg64(0);
                SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass = (SEMAPHORE_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg64(1, true);
                ulong SemaphoreInformation = Instance.WinHelper.GetArg64(2);
                uint SemaphoreInformationLength = (uint)Instance.WinHelper.GetArg64(3, true);
                ulong ReturnLength = Instance.WinHelper.GetArg64(4);

                return HandleQuerySemaphore(Instance, SemaphoreHandle, SemaphoreInformationClass, SemaphoreInformation, SemaphoreInformationLength, ReturnLength);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint SemaphoreHandle32 = Instance.ReadMemoryUInt(SP + 4);
            SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass32 = (SEMAPHORE_INFORMATION_CLASS)Instance.ReadMemoryUInt(SP + 8);
            uint SemaphoreInformation32 = Instance.ReadMemoryUInt(SP + 12);
            uint SemaphoreInformationLength32 = Instance.ReadMemoryUInt(SP + 16);
            uint ReturnLength32 = Instance.ReadMemoryUInt(SP + 20);

            return HandleQuerySemaphore(Instance, SemaphoreHandle32, SemaphoreInformationClass32, SemaphoreInformation32, SemaphoreInformationLength32, ReturnLength32);
        }

        private static NTSTATUS HandleQuerySemaphore(BinaryEmulator Instance, ulong SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, ulong SemaphoreInformation, uint SemaphoreInformationLength, ulong ReturnLength)
        {
            if (ReturnLength != 0 && !Instance.IsRegionMapped(ReturnLength, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (SemaphoreInformationClass != SEMAPHORE_INFORMATION_CLASS.SemaphoreBasicInformation)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            uint RequiredSize = (uint)Marshal.SizeOf<SEMAPHORE_BASIC_INFORMATION>();
            if (ReturnLength != 0 && !Instance._emulator.WriteMemory(ReturnLength, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (SemaphoreInformationLength < RequiredSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (SemaphoreInformation == 0 || !Instance.IsRegionMapped(SemaphoreInformation, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinSemaphore Semaphore = Instance.WinHelper.GetSemaphoreByHandle(SemaphoreHandle, AccessMask.SemaphoreQueryState);
            if (Semaphore == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            SEMAPHORE_BASIC_INFORMATION Information = new SEMAPHORE_BASIC_INFORMATION
            {
                CurrentCount = Semaphore.CurrentCount,
                MaximumCount = Semaphore.MaximumCount
            };

            if (!StructSerializer.WriteStruct(Instance, SemaphoreInformation, Information).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
