using System;
using System.Threading;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtLockFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong FileHandle = Instance.WinHelper.GetArg64(0);
            ulong EventHandle = Instance.WinHelper.GetArg64(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg64(2);
            ulong ApcContext = Instance.WinHelper.GetArg64(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(4);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg64(5);
            ulong LengthPtr = Instance.WinHelper.GetArg64(6);
            uint Key = (uint)Instance.WinHelper.GetArg64(7, true);
            bool FailImmediately = (Instance.WinHelper.GetArg64(8) & 0xFF) != 0;
            bool ExclusiveLock = (Instance.WinHelper.GetArg64(9) & 0xFF) != 0;

            if (IoStatusBlockPtr == 0 || ByteOffsetPtr == 0 || LengthPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, 0x10) || !Instance.IsRegionMapped(ByteOffsetPtr, 8) || !Instance.IsRegionMapped(LengthPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                SignalEvent(Instance, EventHandle, NTSTATUS.STATUS_INVALID_HANDLE);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (FileObj.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                SignalEvent(Instance, EventHandle, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                SignalEvent(Instance, EventHandle, NTSTATUS.STATUS_INVALID_PARAMETER);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (!Instance.WinHelper.TryReadFileLockRange(ByteOffsetPtr, LengthPtr, out ulong Offset, out ulong Length, out NTSTATUS RangeStatus))
            {
                Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, RangeStatus, 0);
                SignalEvent(Instance, EventHandle, RangeStatus);
                return RangeStatus;
            }

            while (true)
            {
                WinFile.WinLockFile Conflict = FileObj.GetConflictingLock(Offset, Length, Key, ExclusiveLock);
                if (Conflict == null)
                    break;

                if (FailImmediately)
                {
                    Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_LOCK_NOT_GRANTED, 0);
                    SignalEvent(Instance, EventHandle, NTSTATUS.STATUS_LOCK_NOT_GRANTED);
                    return NTSTATUS.STATUS_LOCK_NOT_GRANTED;
                }

                Thread.Sleep(1);
            }

            FileObj.AddLock(Offset, Length, Key, ExclusiveLock);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
            SignalEvent(Instance, EventHandle, NTSTATUS.STATUS_SUCCESS);

            Instance.TriggerEventMessage($"[+] NtLockFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Length=0x{Length:X}, Key=0x{Key:X}, Exclusive={ExclusiveLock}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }


        private static void SignalEvent(BinaryEmulator Instance, ulong EventHandle, NTSTATUS Status)
        {
            if (EventHandle == 0 || Status == NTSTATUS.STATUS_PENDING)
                return;

            WinEvent Ev = Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.GiveTemp);
            if (Ev != null)
                Ev.Signaled = true;
        }
    }
}
