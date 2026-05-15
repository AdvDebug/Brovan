using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtUnlockFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong FileHandle = Instance.WinHelper.GetArg64(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(1);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg64(2);
            ulong LengthPtr = Instance.WinHelper.GetArg64(3);
            uint Key = (uint)Instance.WinHelper.GetArg64(4, true);

            if (IoStatusBlockPtr == 0 || ByteOffsetPtr == 0 || LengthPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, 0x10) || !Instance.IsRegionMapped(ByteOffsetPtr, 8) || !Instance.IsRegionMapped(LengthPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (FileObj.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (!Instance.WinHelper.TryReadFileLockRange(ByteOffsetPtr, LengthPtr, out ulong Offset, out ulong Length, out NTSTATUS RangeStatus))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, RangeStatus, 0);
                return RangeStatus;
            }

            if (!FileObj.RemoveLock(Offset, Length, Key))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_RANGE_NOT_LOCKED, 0);
                return NTSTATUS.STATUS_RANGE_NOT_LOCKED;
            }

            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
            Instance.TriggerEventMessage($"[+] NtUnlockFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Length=0x{Length:X}, Key=0x{Key:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

    }
}
