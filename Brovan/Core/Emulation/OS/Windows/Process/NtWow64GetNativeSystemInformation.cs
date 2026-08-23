using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64GetNativeSystemInformation : IWinSyscall
    {
        private const uint NativeBasicInformationSize = 0x40;
        private const uint Wow64BasicInformationSize = 0x2C;
        private const uint Wow64NativeMaximumUserModeAddress = 0xFFFEFFFF;
        private const ulong NativeMaximumUserModeAddress = 0x7FFFFFFEFFFFUL;
        private const ulong NativeMinimumUserModeAddress = 0x10000UL;
        private const ushort NativeProcessorArchitectureAmd64 = 9;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            SYSTEM_INFORMATION_CLASS SystemInformationClass = (SYSTEM_INFORMATION_CLASS)Instance.WinHelper.GetArg(0);
            ulong SystemInformationPtr = Instance.WinHelper.GetArg(1);
            ulong SystemInformationLength = Instance.WinHelper.GetArg(2);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg(3);

            if (SystemInformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (SystemInformationClass == SYSTEM_INFORMATION_CLASS.SystemProcessorInformation)
            {
                const uint ProcessorInformationSize = 0x0C;

                if (ReturnLengthPtr != 0)
                {
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Instance.WinHelper.WriteUInt32(ReturnLengthPtr, ProcessorInformationSize);
                }

                if (SystemInformationLength < ProcessorInformationSize)
                    return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                if (!Instance.IsRegionMapped(SystemInformationPtr, ProcessorInformationSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                int CpuCount = Environment.ProcessorCount;
                if (CpuCount < 1)
                    CpuCount = 1;
                if (CpuCount > ushort.MaxValue)
                    CpuCount = ushort.MaxValue;

                Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, ProcessorInformationSize);
                Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, NativeProcessorArchitectureAmd64);
                Instance._emulator.WriteMemory(SystemInformationPtr + 0x02, (ushort)6);
                Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, (ushort)0x0100);
                Instance._emulator.WriteMemory(SystemInformationPtr + 0x06, (ushort)CpuCount);
                Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, 0u);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (SystemInformationClass != SYSTEM_INFORMATION_CLASS.SystemBasicInformation &&
                SystemInformationClass != SYSTEM_INFORMATION_CLASS.SystemEmulationBasicInformation)
                return Instance.WinUnimplemented;

            // The wow64 layer hands the caller the 32-bit struct shape holding the native values.
            bool Wide = Instance.WinHelper.PointerSize == 8;
            uint BasicInformationSize = Wide ? NativeBasicInformationSize : Wow64BasicInformationSize;

            if (ReturnLengthPtr != 0)
            {
                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance.WinHelper.WriteUInt32(ReturnLengthPtr, BasicInformationSize);
            }

            if (SystemInformationLength != BasicInformationSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(SystemInformationPtr, BasicInformationSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint NumberOfPhysicalPages = 0x200000;
            uint LowestPhysicalPageNumber = 0x00000001;
            uint HighestPhysicalPageNumber = LowestPhysicalPageNumber + NumberOfPhysicalPages - 1;
            const ulong AffinityMask = 0x1;

            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, BasicInformationSize);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x00, 0u);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x04, 156250u);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x08, 0x1000u);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x0C, NumberOfPhysicalPages);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x10, LowestPhysicalPageNumber);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x14, HighestPhysicalPageNumber);
            Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x18, 0x10000u);

            if (Wide)
            {
                Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x1C, 0u);
                Instance.WinHelper.WriteUInt64(SystemInformationPtr + 0x20, NativeMinimumUserModeAddress);
                Instance.WinHelper.WriteUInt64(SystemInformationPtr + 0x28, NativeMaximumUserModeAddress);
                Instance.WinHelper.WriteUInt64(SystemInformationPtr + 0x30, AffinityMask);
                Instance.WinHelper.WriteByte(SystemInformationPtr + 0x38, (byte)Environment.ProcessorCount);
            }
            else
            {
                Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x1C, (uint)NativeMinimumUserModeAddress);
                Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x20, Wow64NativeMaximumUserModeAddress);
                Instance.WinHelper.WriteUInt32(SystemInformationPtr + 0x24, (uint)AffinityMask);
                Instance.WinHelper.WriteByte(SystemInformationPtr + 0x28, (byte)Environment.ProcessorCount);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
