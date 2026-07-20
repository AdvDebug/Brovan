using System.Runtime.InteropServices;
using Brovan.Core.Emulation.OS;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryMutant : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong MutantHandle = Instance.WinHelper.GetArg(0);
                MUTANT_INFORMATION_CLASS MutantInformationClass = (MUTANT_INFORMATION_CLASS)(uint)Instance.WinHelper.GetArg(1);
                ulong MutantInformation = Instance.WinHelper.GetArg(2);
                uint MutantInformationLength = (uint)Instance.WinHelper.GetArg(3);
                ulong ReturnLength = Instance.WinHelper.GetArg(4);

                return HandleQueryMutant(Instance, MutantHandle, MutantInformationClass, MutantInformation, MutantInformationLength, ReturnLength, true);
            }


            uint MutantHandle32 = (uint)Instance.WinHelper.GetArg(0);
            MUTANT_INFORMATION_CLASS MutantInformationClass32 = (MUTANT_INFORMATION_CLASS)Instance.WinHelper.GetArg(1);
            uint MutantInformation32 = (uint)Instance.WinHelper.GetArg(2);
            uint MutantInformationLength32 = (uint)Instance.WinHelper.GetArg(3);
            uint ReturnLength32 = (uint)Instance.WinHelper.GetArg(4);

            return HandleQueryMutant(Instance, MutantHandle32, MutantInformationClass32, MutantInformation32, MutantInformationLength32, ReturnLength32, false);
        }

        private static NTSTATUS HandleQueryMutant(BinaryEmulator Instance, ulong MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, ulong MutantInformation, uint MutantInformationLength, ulong ReturnLength, bool Is64Bit)
        {
            if (ReturnLength != 0 && !Instance.IsRegionMapped(ReturnLength, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinMutex Mutex = Instance.WinHelper.GetMutexByHandle(MutantHandle, AccessMask.MutantQueryState);
            if (Mutex == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (MutantInformationClass == MUTANT_INFORMATION_CLASS.MutantBasicInformation)
                return WriteBasicInformation(Instance, Mutex, MutantInformation, MutantInformationLength, ReturnLength);

            if (MutantInformationClass == MUTANT_INFORMATION_CLASS.MutantOwnerInformation)
                return WriteOwnerInformation(Instance, Mutex, MutantInformation, MutantInformationLength, ReturnLength, Is64Bit);

            return NTSTATUS.STATUS_INVALID_INFO_CLASS;
        }

        private static NTSTATUS WriteBasicInformation(BinaryEmulator Instance, WinMutex Mutex, ulong MutantInformation, uint MutantInformationLength, ulong ReturnLength)
        {
            uint RequiredSize = (uint)Marshal.SizeOf<MUTANT_BASIC_INFORMATION>();
            if (ReturnLength != 0 && !Instance._emulator.WriteMemory(ReturnLength, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (MutantInformationLength < RequiredSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (MutantInformation == 0 || !Instance.IsRegionMapped(MutantInformation, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            MUTANT_BASIC_INFORMATION Information = new MUTANT_BASIC_INFORMATION
            {
                CurrentCount = Mutex.SignalState,
                OwnedByCaller = Instance.CurrentThread != null && Mutex.OwnerThreadId == Instance.CurrentThread.ThreadId ? (byte)1 : (byte)0,
                AbandonedState = Mutex.Abandoned ? (byte)1 : (byte)0
            };

            if (!StructSerializer.WriteStruct(Instance, MutantInformation, Information).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS WriteOwnerInformation(BinaryEmulator Instance, WinMutex Mutex, ulong MutantInformation, uint MutantInformationLength, ulong ReturnLength, bool Is64Bit)
        {
            uint RequiredSize = Is64Bit ? 16u : 8u;
            if (ReturnLength != 0 && !Instance._emulator.WriteMemory(ReturnLength, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (MutantInformationLength < RequiredSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (MutantInformation == 0 || !Instance.IsRegionMapped(MutantInformation, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Is64Bit)
            {
                if (!Instance._emulator.WriteMemory(MutantInformation, (ulong)(Mutex.OwnerThreadId != 0 ? Instance.WinHelper.PID : 0)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance._emulator.WriteMemory(MutantInformation + 8, (ulong)Mutex.OwnerThreadId))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            else
            {
                if (!Instance._emulator.WriteMemory(MutantInformation, (uint)(Mutex.OwnerThreadId != 0 ? Instance.WinHelper.PID : 0)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance._emulator.WriteMemory(MutantInformation + 4, Mutex.OwnerThreadId))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
