using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFlushVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private static NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg64(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(3);

            if (BaseAddressPtr == 0 || RegionSizePtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, 8) || !Instance.IsRegionMapped(RegionSizePtr, 8) || !Instance.IsRegionMapped(IoStatusBlockPtr, 0x10))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            ulong BaseAddress = Instance.ReadMemoryULong(BaseAddressPtr);
            ulong RegionSize = Instance.ReadMemoryULong(RegionSizePtr);

            NTSTATUS Status = FlushRange(Instance, BaseAddress, RegionSize, out ulong FlushedSize);
            if (Status == NTSTATUS.STATUS_SUCCESS)
            {
                Instance._emulator.WriteMemory(BaseAddressPtr, BaseAddress, 8);
                Instance._emulator.WriteMemory(RegionSizePtr, FlushedSize, 8);
            }

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, Status, FlushedSize);
            return Status;
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint ProcessHandle = Instance.WinHelper.GetArg32(0);
            uint BaseAddressPtr = Instance.WinHelper.GetArg32(1);
            uint RegionSizePtr = Instance.WinHelper.GetArg32(2);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(3);

            if (BaseAddressPtr == 0 || RegionSizePtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, 4) || !Instance.IsRegionMapped(RegionSizePtr, 4) || !Instance.IsRegionMapped(IoStatusBlockPtr, 0x08))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
            {
                Instance.WinHelper.WriteIoStatusBlock32(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            ulong BaseAddress = Instance.ReadMemoryUInt(BaseAddressPtr);
            ulong RegionSize = Instance.ReadMemoryUInt(RegionSizePtr);

            NTSTATUS Status = FlushRange(Instance, BaseAddress, RegionSize, out ulong FlushedSize);
            if (Status == NTSTATUS.STATUS_SUCCESS)
            {
                Instance._emulator.WriteMemory(BaseAddressPtr, (uint)BaseAddress);
                Instance._emulator.WriteMemory(RegionSizePtr, (uint)FlushedSize);
            }

            Instance.WinHelper.WriteIoStatusBlock32(Instance, IoStatusBlockPtr, Status, (uint)Math.Min(FlushedSize, uint.MaxValue));
            return Status;
        }

        private static NTSTATUS FlushRange(BinaryEmulator Instance, ulong BaseAddress, ulong RegionSize, out ulong FlushedSize)
        {
            FlushedSize = 0;

            if (BaseAddress == 0 || !Instance.IsRegionMapped(BaseAddress, 1))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            WinSection Section = FindSectionByAddress(Instance, BaseAddress);
            if (Section == null)
                return NTSTATUS.STATUS_SUCCESS;

            ulong SectionOffset = BaseAddress - Section.BackingAddress;
            ulong Available = Section.Size > SectionOffset ? Section.Size - SectionOffset : 0;
            if (Available == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            FlushedSize = RegionSize == 0 || RegionSize > Available ? Available : RegionSize;
            if (FlushedSize == 0)
                return NTSTATUS.STATUS_SUCCESS;

            if (string.IsNullOrEmpty(Section.Path) || Section.IsImage)
                return NTSTATUS.STATUS_SUCCESS;

            if (FlushedSize > int.MaxValue || SectionOffset > int.MaxValue || FlushedSize > (ulong)int.MaxValue - SectionOffset)
                return NTSTATUS.STATUS_NO_MEMORY;

            byte[] FlushedBytes = Instance.ReadMemory(BaseAddress, (uint)FlushedSize);
            if (FlushedBytes == null || (ulong)FlushedBytes.Length < FlushedSize)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WindowsFileStream Stream = Section.GetFileStream(true);
            if (Stream == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            try
            {
                Stream.WriteAt((long)SectionOffset, FlushedBytes, 0, (int)FlushedSize);
            }
            catch
            {
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            Instance.TriggerEventMessage($"[+] NtFlushVirtualMemory: Base=0x{BaseAddress:X}, Size=0x{FlushedSize:X}, File=\"{Section.Path}\".", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static WinSection FindSectionByAddress(BinaryEmulator Instance, ulong Address)
        {
            foreach (WinSection Section in Instance.WinHelper.WinSections)
            {
                if (Section == null || Section.BackingAddress == 0 || Section.Size == 0)
                    continue;

                if (Address >= Section.BackingAddress && Address - Section.BackingAddress < Section.Size)
                    return Section;
            }

            return null;
        }

    }
}
