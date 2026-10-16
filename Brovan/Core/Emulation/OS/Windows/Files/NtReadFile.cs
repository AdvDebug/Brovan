using System;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtReadFile : IWinSyscall
    {
        internal const int IoChunkBytes = 4 << 20;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(4);
            ulong BufferPtr = Instance.WinHelper.GetArg(5);
            uint Length = (uint)Instance.WinHelper.GetArg(6);
            ulong ByteOffsetPtr = Instance.WinHelper.GetArg(7);

            NTSTATUS Status = BeginRequest(Instance, FileHandle, EventHandle, IoStatusBlockPtr, BufferPtr, Length, ApcRoutine, ByteOffsetPtr, Write: false, out WinFile FileObj, out long Offset);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (FileObj.Pipe != null)
                return ReadPipe(Instance, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

            if (FileObj.HostStream == HostStreamKind.Input)
                return ReadHostStream(Instance, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

            Status = Read(Instance, FileHandle, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length, Offset);
            Instance.WinHelper.SignalIoEvent(EventHandle, Status);
            return Status;
        }

        private static NTSTATUS Read(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length, long Offset)
        {
            if (FileObj.ConsoleKind == ConsoleObjectKind.Input)
            {
                WinPendingIo Io = Instance.WinHelper.SynchronousIo(FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);
                return ConsoleServer.ReadFile(Instance, in Io, BufferPtr, Length);
            }

            // NT: the null device answers EOF to a zero-length read too.
            if (FileObj.IsNullDevice)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                return NTSTATUS.STATUS_END_OF_FILE;
            }

            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                Instance.WinHelper.QueueImmediateCompletion(FileObj, ApcRoutine, ApcContext, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (FileObj.Device)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_DEVICE_REQUEST, 0);
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;
            }

            if (FileObj.Directory)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_IS_A_DIRECTORY, 0);
                return NTSTATUS.STATUS_FILE_IS_A_DIRECTORY;
            }

            WindowsFileStream Stream = FileObj.GetFileStream();
            if (Stream == null || !Stream.ExistsAsFile)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND, 0);
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
            }

            int ToRead = Length > int.MaxValue ? int.MaxValue : (int)Length;

            // A read that runs past the end comes back short, so only the lock check needs the length first.
            if (FileObj.Locks.Count != 0)
            {
                long FileLength = Stream.Length;
                if (Offset >= FileLength)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                    return NTSTATUS.STATUS_END_OF_FILE;
                }

                ToRead = (int)Math.Min(ToRead, FileLength - Offset);
                if (FileObj.HasConflictingIoLock((ulong)Offset, (ulong)ToRead, false))
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_LOCK_CONFLICT, 0);
                    return NTSTATUS.STATUS_FILE_LOCK_CONFLICT;
                }
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

                    if (!Instance._emulator.WriteMemory(BufferPtr + (ulong)Done, Slice.Slice(0, Got)))
                    {
                        if (Done == 0)
                        {
                            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        }

                        break;
                    }

                    Done += Got;
                    if (Got < ChunkSize)
                        break;
                }
            }
            catch (FileNotFoundException)
            {
                // A file that went away under the stream reads as ended.
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[NtReadFile] {FileObj.Path}: {Ex.Message}");
                if (Done == 0)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                    return NTSTATUS.STATUS_ACCESS_DENIED;
                }
            }

            if (Done == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                return NTSTATUS.STATUS_END_OF_FILE;
            }

            if (FileObj.Synchronous)
                FileObj.Position = Offset + Done;

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Done);
            Instance.WinHelper.QueueImmediateCompletion(FileObj, ApcRoutine, ApcContext, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Done);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtReadFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Read=0x{Done:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ReadPipe(BinaryEmulator Instance, WinFile FileObj, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
            PipeRequest Request = Instance.WinHelper.PipeRequests.Create(Instance, PipeRequestKind.Read, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);
            Request.Buffer = BufferPtr;
            Request.Length = (int)Math.Min(Length, (uint)GuestNamedPipe.MaxMessageBytes);
            return Instance.WinHelper.PipeRequests.Submit(Instance, Request);
        }

        // NT: a zero-byte read still waits for data. A failure leaves the IO_STATUS_BLOCK alone and the event reset.
        private static NTSTATUS ReadHostStream(BinaryEmulator Instance, WinFile File, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
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
            Instance.WinHelper.QueueImmediateCompletion(File, ApcRoutine, ApcContext, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Copied);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtReadFile: STDIN read {Copied} bytes", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // The order follows IopReadFile and IopValidateAndGetWriteParameters, and no failure writes the IO_STATUS_BLOCK.
        internal static NTSTATUS BeginRequest(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length, ulong ApcRoutine, ulong ByteOffsetPtr, bool Write, out WinFile FileObj, out long Offset)
        {
            Offset = 0;
            NTSTATUS Status = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out FileObj, out AccessMask Granted);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!(Write ? FileObj.AllowsWrite(Granted) : WinFile.AllowsRead(Granted)))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (!Instance.WinHelper.ProbeIoStatusBlock(IoStatusBlockPtr))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT: a read buffer is probed for write page by page, a write buffer for read by range only.
            if (Length != 0 && !(Write ? NtWow64GetNativeSystemInformation.IsUserRange(BufferPtr, Length) : Instance.IsAccessible(BufferPtr, Length, true)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (FileObj.RefusesApcRoutine(ApcRoutine))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Status = Instance.WinHelper.ReadFileByteOffset(ByteOffsetPtr, out long Requested);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = Instance.WinHelper.ReferenceIoEvent(EventHandle);

            if (Status != NTSTATUS.STATUS_SUCCESS || !HasFileOffset(FileObj))
                return Status;

            return ResolveFileOffset(FileObj, ByteOffsetPtr != 0 ? Requested : null, Write, Write && WinFile.IsAppendOnly(Granted), out Offset);
        }

        internal const long FileWriteToEndOfFile = -1;
        private const long FileUseFilePointerPosition = -2;

        // Console and volume objects carry no open mode, so a device other than a pipe skips the offset rules.
        private static bool HasFileOffset(WinFile FileObj) => !FileObj.Device || FileObj.IsNamedPipe;

        private static NTSTATUS ResolveFileOffset(WinFile FileObj, long? Requested, bool Write, bool AppendOnly, out long Offset)
        {
            Offset = 0;
            if (Requested == null && !FileObj.Synchronous)
                return FileObj.IsNamedPipe ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;

            Offset = AppendOnly ? FileWriteToEndOfFile : Requested ?? FileUseFilePointerPosition;
            if (Offset == FileUseFilePointerPosition && FileObj.Synchronous)
                Offset = FileObj.Position;

            return Offset >= 0 || (Write && Offset == FileWriteToEndOfFile) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
