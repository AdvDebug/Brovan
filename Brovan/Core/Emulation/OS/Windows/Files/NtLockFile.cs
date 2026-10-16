using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtLockFile : IWinSyscall
    {
        private const int LockRetrySliceMilliseconds = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(4);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg(5);
            ulong LengthPtr = Instance.WinHelper.GetArg(6);
            uint Key = (uint)Instance.WinHelper.GetArg(7);
            bool FailImmediately = (Instance.WinHelper.GetArg(8) & 0xFF) != 0;
            bool ExclusiveLock = (Instance.WinHelper.GetArg(9) & 0xFF) != 0;

            NTSTATUS Status = CheckRequest(Instance, FileHandle, IoStatusBlockPtr, ByteOffsetPtr, LengthPtr, out WinFile FileObj, out long Offset, out ulong Length);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (FileObj.RefusesApcRoutine(ApcRoutine))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance.WinHelper.ResetIoEvent(EventHandle);

            if (FileObj.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                Instance.WinHelper.SignalIoEvent(EventHandle, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_PARAMETER, 0);
                Instance.WinHelper.SignalIoEvent(EventHandle, NTSTATUS.STATUS_INVALID_PARAMETER);
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (!Instance.WinHelper.IsValidFileLockRange(Offset, Length))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_LOCK_RANGE, 0);
                Instance.WinHelper.SignalIoEvent(EventHandle, NTSTATUS.STATUS_INVALID_LOCK_RANGE);
                return NTSTATUS.STATUS_INVALID_LOCK_RANGE;
            }

            if (FileObj.GetConflictingLock((ulong)Offset, Length, Key, ExclusiveLock) != null)
            {
                WinPendingIo? SyncIo = FileObj.Synchronous ? Instance.WinHelper.SynchronousIo(FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr) : null;
                if (!FailImmediately && Instance.WinHelper.TryRetrySyscallAfterSlice(LockRetrySliceMilliseconds, SyncIo))
                    return NTSTATUS.STATUS_PENDING;

                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_LOCK_NOT_GRANTED, 0);
                Instance.WinHelper.SignalIoEvent(EventHandle, NTSTATUS.STATUS_LOCK_NOT_GRANTED);
                PostFastLockPacket(Instance, FileObj, ApcContext, NTSTATUS.STATUS_LOCK_NOT_GRANTED);
                return NTSTATUS.STATUS_LOCK_NOT_GRANTED;
            }

            FileObj.AddLock((ulong)Offset, Length, Key, ExclusiveLock);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
            Instance.WinHelper.SignalIoEvent(EventHandle, NTSTATUS.STATUS_SUCCESS);
            PostFastLockPacket(Instance, FileObj, ApcContext, NTSTATUS.STATUS_SUCCESS);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtLockFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Length=0x{Length:X}, Key=0x{Key:X}, Exclusive={ExclusiveLock}.", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT checks in this order and writes no IO_STATUS_BLOCK for a failure here.
        internal static NTSTATUS CheckRequest(BinaryEmulator Instance, ulong FileHandle, ulong IoStatusBlockPtr, ulong ByteOffsetPtr, ulong LengthPtr, out WinFile FileObj, out long Offset, out ulong Length)
        {
            Offset = 0;
            Length = 0;
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out FileObj, out AccessMask Granted);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if ((Granted & (WinFile.ReadDataAccess | WinFile.WriteDataAccess)) == 0)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (!Instance.WinHelper.ProbeIoStatusBlock(IoStatusBlockPtr))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return Instance.WinHelper.ReadFileLockRange(ByteOffsetPtr, LengthPtr, out Offset, out Length);
        }

        // NT: the fast lock path posts a failure too, and queues no APC.
        private static void PostFastLockPacket(BinaryEmulator Instance, WinFile File, ulong ApcContext, NTSTATUS Status)
        {
            if ((File.CompletionNotificationModes & WinSysHelper.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) == 0)
                Instance.WinHelper.QueueFileCompletion(Instance, File, ApcContext, Status, 0);
        }
    }
}
