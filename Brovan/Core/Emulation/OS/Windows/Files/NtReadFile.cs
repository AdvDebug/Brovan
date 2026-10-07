using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtReadFile : IWinSyscall
    {
        internal const int IoChunkBytes = 4 << 20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Event = Instance.WinHelper.GetArg(1);
            NTSTATUS Status = Read(Instance, out bool EventDone);
            if (!EventDone)
                Instance.WinHelper.SignalIoEvent(Event, Status);
            return Status;
        }

        private static NTSTATUS Read(BinaryEmulator Instance, out bool EventDone)
        {
            EventDone = false;

            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
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

            WinFile PipeFile = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            EventDone = PipeFile != null && (PipeFile.Pipe != null || PipeFile.HostStream == HostStreamKind.Input);
            if (PipeFile?.Pipe != null)
                return ReadPipe(Instance, FileHandle, PipeFile, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

            if (PipeFile?.ConsoleKind == ConsoleObjectKind.Input)
            {
                WinPendingIo Io = Instance.WinHelper.SynchronousIo(PipeFile, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);
                return ConsoleServer.ReadFile(Instance, in Io, BufferPtr, Length);
            }

            if (PipeFile?.HostStream == HostStreamKind.Input)
                return ReadHostStream(Instance, FileHandle, PipeFile, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

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

            Instance.WinHelper.ResetIoEvent(EventHandle);

            if (FileObj.Device)
            {
                if (NullDevice.IsNullDevicePath(FileObj.Path))
                {
                    if (!HasReadAccess(Instance, FileHandle))
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                        return NTSTATUS.STATUS_ACCESS_DENIED;
                    }

                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                    return NTSTATUS.STATUS_END_OF_FILE;
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
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                return NTSTATUS.STATUS_END_OF_FILE;
            }

            int Available = checked((int)Math.Min(int.MaxValue, FileLength - Offset));
            int Requested = Length > int.MaxValue ? int.MaxValue : (int)Length;
            int ToRead = Math.Min(Requested, Available);

            if (ToRead != 0 && FileObj.HasConflictingIoLock((ulong)Offset, (ulong)ToRead, false))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_LOCK_CONFLICT, 0);
                return NTSTATUS.STATUS_FILE_LOCK_CONFLICT;
            }

            // Bounded chunks keep a guest-sized read from growing the shared scratch buffer to the file size.
            int Done = 0;
            try
            {
                while (Done < ToRead)
                {
                    int ChunkSize = Math.Min(IoChunkBytes, ToRead - Done);
                    Span<byte> Slice = Instance.WinHelper.Shared.GetSpan((uint)ChunkSize);
                    int Got = Stream.ReadAt(Offset + Done, Slice.Slice(0, ChunkSize));
                    if (Got <= 0)
                        break;

                    Instance._emulator.WriteMemory(BufferPtr + (ulong)Done, Slice.Slice(0, Got));
                    Done += Got;
                }
            }
            catch
            {
                if (Done == 0)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                    return NTSTATUS.STATUS_ACCESS_DENIED;
                }
            }

            if (ByteOffsetPtr == 0)
                FileObj.Position = Offset + Done;

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Done);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtReadFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Read=0x{Done:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: access and buffer failures leave the event and the IO_STATUS_BLOCK alone.
        private static NTSTATUS ReadPipe(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
            if (!HasReadAccess(Instance, FileHandle))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Length != 0 && !Instance.IsMemoryRangeMapped(BufferPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.WinHelper.ResetIoEvent(EventHandle);

            PipeRequest Request = Instance.WinHelper.PipeRequests.Create(Instance, PipeRequestKind.Read, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);
            Request.Buffer = BufferPtr;
            Request.Length = (int)Math.Min(Length, (uint)GuestNamedPipe.MaxMessageBytes);
            return Instance.WinHelper.PipeRequests.Submit(Instance, Request);
        }

        // NT: a zero-byte read still waits for data. A failure leaves the IO_STATUS_BLOCK alone and the event reset.
        private static NTSTATUS ReadHostStream(BinaryEmulator Instance, ulong FileHandle, WinFile File, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
            if (!HasReadAccess(Instance, FileHandle))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Length != 0 && !Instance.IsMemoryRangeMapped(BufferPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.WinHelper.ResetIoEvent(EventHandle);

            Task NextChange = GeneralHelper.HostStreamInput.NextChange;
            int Capacity = (int)Math.Min(Length, (uint)Brovan.Core.Settings.MemoryBudget.HostStreamInputBytes);
            Span<byte> Data = Capacity == 0 ? Span<byte>.Empty : Instance.WinHelper.Shared.GetSpan((uint)Capacity).Slice(0, Capacity);

            int Copied = GeneralHelper.HostStreamInput.Peek(Data, out int Available, out bool Ended);
            if (Ended)
                return NTSTATUS.STATUS_PIPE_BROKEN;

            if (Available == 0)
            {
                GeneralHelper.HostStreamInput.Request(Instance.WakeSignal);
                WinPendingIo Io = Instance.WinHelper.SynchronousIo(File, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);
                return Instance.WinHelper.TryRetrySyscallWhenDone(NextChange, Io) ? NTSTATUS.STATUS_PENDING : NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            if (Copied != 0)
            {
                if (!Instance._emulator.WriteMemory(BufferPtr, Data.Slice(0, Copied)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                GeneralHelper.HostStreamInput.Skip(Copied);
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Copied);
            Instance.WinHelper.SignalIoEvent(EventHandle, NTSTATUS.STATUS_SUCCESS);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtReadFile: STDIN read {Copied} bytes", LogFlags.Syscall);

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
