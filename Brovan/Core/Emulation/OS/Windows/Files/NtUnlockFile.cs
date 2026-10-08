using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtUnlockFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(1);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg(2);
            ulong LengthPtr = Instance.WinHelper.GetArg(3);
            uint Key = (uint)Instance.WinHelper.GetArg(4);

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            NTSTATUS CaptureStatus = Instance.WinHelper.ReadFileLockRange(ByteOffsetPtr, LengthPtr, out long Offset, out ulong Length);
            if (CaptureStatus != NTSTATUS.STATUS_SUCCESS)
                return CaptureStatus;

            if (FileObj.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (!Instance.WinHelper.IsValidFileLockRange(Offset, Length))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_LOCK_RANGE, 0);
                return NTSTATUS.STATUS_INVALID_LOCK_RANGE;
            }

            if (!FileObj.RemoveLock((ulong)Offset, Length, Key))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_RANGE_NOT_LOCKED, 0);
                return NTSTATUS.STATUS_RANGE_NOT_LOCKED;
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtUnlockFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Length=0x{Length:X}, Key=0x{Key:X}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

    }
}
