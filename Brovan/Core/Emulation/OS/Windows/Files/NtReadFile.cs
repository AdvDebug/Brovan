using System;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtReadFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong Event = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(4);
            ulong BufferPtr = Instance.WinHelper.GetArg(5);
            uint Length = (uint)Instance.WinHelper.GetArg(6);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg(7);
            ulong Key = Instance.WinHelper.GetArg(8);

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (FileHandle == (ulong)Instance.WinHelper.STD_IN.Handle)
                return HandleStdIn(Instance, IoStatusBlockPtr, BufferPtr, Length);

            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(BufferPtr, Length))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0);
                return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (FileObj.Device)
            {
                if (NullDevice.IsNullDevicePath(FileObj.Path))
                {
                    if (!HasReadAccess(Instance, FileHandle))
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                        return NTSTATUS.STATUS_ACCESS_DENIED;
                    }

                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_IS_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;
            }

            if (!HasReadAccess(Instance, FileHandle))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            WindowsFileStream Stream = FileObj.GetFileStream();
            if (Stream == null || !Stream.ExistsAsFile)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            long Offset = Instance.WinHelper.GetEffectiveFileOffset(ByteOffsetPtr, FileObj.Position);
            if (Offset < 0)
                Offset = 0;

            long FileLength = Stream.Length;
            if (Offset >= FileLength)
            {
                if (ByteOffsetPtr == 0)
                    FileObj.Position = Offset;

                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Available = checked((int)Math.Min(int.MaxValue, FileLength - Offset));
            int Requested = Length > int.MaxValue ? int.MaxValue : (int)Length;
            int ToRead = Math.Min(Requested, Available);

            if (ToRead != 0 && FileObj.HasConflictingIoLock((ulong)Offset, (ulong)ToRead, false))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_LOCK_CONFLICT, 0);
                return NTSTATUS.STATUS_FILE_LOCK_CONFLICT;
            }

            Span<byte> Slice = Instance.WinHelper.Shared.GetSpan((uint)ToRead);
            try
            {
                ToRead = Stream.ReadAt(Offset, Slice.Slice(0, ToRead));
            }
            catch
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            Instance._emulator.WriteMemory(BufferPtr, Slice.Slice(0, ToRead));

            if (ByteOffsetPtr == 0)
                FileObj.Position = Offset + ToRead;

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)ToRead);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtReadFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Read=0x{ToRead:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleStdIn(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.IsRegionMapped(BufferPtr, Length))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            string Line = Console.ReadLine() ?? string.Empty;
            Line += "\r\n";

            int CharCount = (int)Math.Min((uint)Line.Length, Length);
            Span<byte> Data = Instance.WinHelper.Shared.GetSpan((uint)CharCount);
            int ToWrite = Encoding.ASCII.GetBytes(Line.AsSpan(0, CharCount), Data);

            Instance._emulator.WriteMemory(BufferPtr, Data.Slice(0, ToWrite));

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)ToWrite);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtReadFile: STDIN read {ToWrite} bytes", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }


        private static bool HasReadAccess(BinaryEmulator Instance, ulong FileHandle)
        {
            AccessMask Granted = Instance.WinHelper.HandleManager.GetPermissionsByHandle(FileHandle);

            if ((Granted & AccessMask.GenericAll) == AccessMask.GenericAll)
                return true;

            if ((Granted & AccessMask.GenericRead) == AccessMask.GenericRead)
                return true;

            if ((Granted & AccessMask.FileAllAccess) == AccessMask.FileAllAccess)
                return true;

            if ((Granted & AccessMask.FileReadData) == AccessMask.FileReadData)
                return true;

            return false;
        }
    }
}
