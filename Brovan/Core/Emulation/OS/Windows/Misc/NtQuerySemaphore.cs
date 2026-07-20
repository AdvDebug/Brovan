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
                ulong SemaphoreHandle = Instance.WinHelper.GetArg(0);
                SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass = (SEMAPHORE_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg(1);
                ulong SemaphoreInformation = Instance.WinHelper.GetArg(2);
                uint SemaphoreInformationLength = (uint)Instance.WinHelper.GetArg(3);
                ulong ReturnLength = Instance.WinHelper.GetArg(4);

                return HandleQuerySemaphore(Instance, SemaphoreHandle, SemaphoreInformationClass, SemaphoreInformation, SemaphoreInformationLength, ReturnLength);
            }


            uint SemaphoreHandle32 = (uint)Instance.WinHelper.GetArg(0);
            SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass32 = (SEMAPHORE_INFORMATION_CLASS)Instance.WinHelper.GetArg(1);
            uint SemaphoreInformation32 = (uint)Instance.WinHelper.GetArg(2);
            uint SemaphoreInformationLength32 = (uint)Instance.WinHelper.GetArg(3);
            uint ReturnLength32 = (uint)Instance.WinHelper.GetArg(4);

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
