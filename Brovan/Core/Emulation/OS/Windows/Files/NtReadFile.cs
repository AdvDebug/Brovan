using System;
using Brovan.Core.Emulation.Guests;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtReadFile : IWinSyscall
    {
        internal const int IoChunkBytes = 4 << 20;

        public WinSyscallDomain Domain => WinSyscallDomain.Resolved;

        public WinSyscallDomain ResolveDomain(BinaryEmulator Instance) => ResolveRequest(Instance, Write: false);

        // A read or write of a regular file runs without KernelLock when its buffer passes the page probe and, for a write,
        // the file admits a change without KernelLock.
        internal static WinSyscallDomain ResolveRequest(BinaryEmulator Instance, bool Write)
        {
            WinSysHelper Helper = Instance.WinHelper;
            ulong FileHandle = Helper.GetArg(0);
            ulong EventHandle = Helper.GetArg(1);
            ulong IoStatusBlockPtr = Helper.GetArg(4);
            ulong BufferPtr = Helper.GetArg(5);
            uint Length = (uint)Helper.GetArg(6);

            if (!Helper.TryResolveFileRequest(FileHandle, EventHandle, IoStatusBlockPtr, out WinFile File, out AccessMask Granted, out WinEvent? Event))
                return WinSyscallDomain.KernelLock;

            if (!(Write ? File.AllowsWrite(Granted) : WinFile.AllowsRead(Granted)) || !Helper.IsAccessibleUserRange(BufferPtr, Length, !Write))
            {
                WindowsGuest.SyscallDomainStats.FileFellBack(WindowsGuest.SyscallDomainStats.FileReason.Check);
                return WinSyscallDomain.KernelLock;
            }

            if (Write && !File.Fcb.TryBeginUnlockedChange())
            {
                WindowsGuest.SyscallDomainStats.FileFellBack(WindowsGuest.SyscallDomainStats.FileReason.Change);
                return WinSyscallDomain.KernelLock;
            }

            Helper.SetFileRequest(FileHandle, File, Granted, EventHandle, Event, AdmittedChange: Write);
            return WinSyscallDomain.Self;
        }

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
            ulong KeyPtr = Instance.WinHelper.GetArg(8);

            NTSTATUS Status = BeginRequest(Instance, FileHandle, EventHandle, IoStatusBlockPtr, BufferPtr, Length, ApcRoutine, ByteOffsetPtr, KeyPtr, Write: false, out WinFile FileObj, out long Offset, out uint Key, out WinEvent? Event);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (FileObj.Pipe != null)
                return ReadPipe(Instance, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

            if (FileObj.HostStream == HostStreamKind.Input)
                return ReadHostStream(Instance, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

            KernelFileReads? Reads = Instance.WinHelper.KernelFileReads;
            long EndedAt = -1;
            bool TableWork = false;
            RankedLock.Scope Reopen = default;
            try
            {
                using (EnterFileForStream(Instance, FileObj, ref Reopen))
                {
                    if (FileObj.CleanedUp)
                        return Instance.WinHelper.CompleteOnCleanedUpFile(IoStatusBlockPtr, Event);

                    if (Offset == FileUseFilePointerPosition)
                        Offset = FileObj.ClaimPosition();

                    try
                    {
                        Status = Read(Instance, FileHandle, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length, Offset, Key, ref EndedAt);
                    }
                    finally
                    {
                        FileObj.ReleasePosition();
                    }

                    TableWork = Status == NTSTATUS.STATUS_SUCCESS && Reads != null
                        && Reads.CountRead(FileHandle, FileObj, EventHandle, ApcRoutine, ByteOffsetPtr, KeyPtr, Length);
                }

                bool EndsView = EndedAt >= 0 && FileObj.KernelCell is { HasView: true };
                if (Reads != null && (TableWork || EndsView))
                {
                    using (Instance.EnterKernelLockScope())
                    {
                        if (EndsView)
                            Reads.NoteEnd(FileObj, EndedAt);
                        if (TableWork)
                            Reads.NoteRead(FileHandle, FileObj, Length);
                    }
                }

                WinSysHelper.SignalIoEvent(Event, Status);
                return Status;
            }
            finally
            {
                Reopen.Dispose();
            }
        }

        // NT: a handle keeps its file across a rename. A reopen waits under KernelLock for a rename's release, move and
        // path change.
        internal static RankedLock.Scope EnterFileForStream(BinaryEmulator Instance, WinFile File, ref RankedLock.Scope Reopen)
        {
            RankedLock.Scope FileScope = File.ObjectLock.EnterScope();
            if (Instance.KernelLockCovered || !File.StreamNeedsReopen)
                return FileScope;

            FileScope.Dispose();
            WindowsGuest.SyscallDomainStats.FellBack(WindowsGuest.SyscallDomainStats.Reason.StreamReopen);
            Reopen = Instance.EnterKernelLockScope();
            return File.ObjectLock.EnterScope();
        }

        private static NTSTATUS Read(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length, long Offset, uint Key, ref long EndedAt)
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
            if (FileObj.Fcb.LockCount != 0)
            {
                long FileLength = Stream.Length;
                if (Offset >= FileLength)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_END_OF_FILE, 0);
                    return NTSTATUS.STATUS_END_OF_FILE;
                }

                ToRead = (int)Math.Min(ToRead, FileLength - Offset);
                if (FileObj.Fcb.HasConflictingIo(FileObj, (ulong)Offset, (ulong)ToRead, Key, false))
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_LOCK_CONFLICT, 0);
                    return NTSTATUS.STATUS_FILE_LOCK_CONFLICT;
                }
            }

            // Bounded chunks keep a guest-sized read from growing the shared scratch buffer to the file size.
            int Done = 0;
            bool StreamEnded = false;
            try
            {
                while (Done < ToRead)
                {
                    int ChunkSize = Math.Min(IoChunkBytes, ToRead - Done);
                    Span<byte> Slice = Instance.WinHelper.Shared.GetSpan((uint)ChunkSize);
                    int Got = Stream.ReadAt(Offset + Done, Slice.Slice(0, ChunkSize));
                    if (Got <= 0)
                    {
                        StreamEnded = true;
                        break;
                    }

                    // NT: the file system faults on the user buffer while it copies, and the request fails.
                    if (!Instance._emulator.WriteMemory(BufferPtr + (ulong)Done, Slice.Slice(0, Got)))
                    {
                        Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_USER_BUFFER, 0);
                        return NTSTATUS.STATUS_INVALID_USER_BUFFER;
                    }

                    Done += Got;
                    if (Got < ChunkSize)
                    {
                        StreamEnded = true;
                        break;
                    }
                }
            }
            catch (FileNotFoundException)
            {
                // A file that went away under the stream reads as ended.
                StreamEnded = true;
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

            if (StreamEnded)
                EndedAt = Offset + Done;

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

        // The order follows IopReadFile and IopValidateAndGetWriteParameters. No failure writes the IO_STATUS_BLOCK.
        internal static NTSTATUS BeginRequest(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length, ulong ApcRoutine, ulong ByteOffsetPtr, ulong KeyPtr, bool Write, out WinFile FileObj, out long Offset, out uint Key, out WinEvent? Event)
        {
            Offset = 0;
            Key = 0;
            Event = null;
            NTSTATUS Status = NTSTATUS.STATUS_SUCCESS;
            bool Resolved = Instance.WinHelper.TakeFileRequest(FileHandle, EventHandle, out FileObj, out AccessMask Granted, out WinEvent? ResolvedEvent);
            if (!Resolved)
            {
                ResolvedEvent = null;
                Status = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out FileObj, out Granted);
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            if (!(Write ? FileObj.AllowsWrite(Granted) : WinFile.AllowsRead(Granted)))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (!Resolved && !Instance.WinHelper.TryProbeIoStatusBlock(IoStatusBlockPtr, out NTSTATUS ProbeStatus))
                return ProbeStatus;

            // NT: a read buffer is probed for write page by page, a write buffer for read by range only.
            if (!Resolved && Length != 0)
            {
                Status = !Write ? Instance.WinHelper.ProbeForWrite(BufferPtr, Length)
                    : NtWow64GetNativeSystemInformation.IsUserRange(BufferPtr, Length) ? NTSTATUS.STATUS_SUCCESS
                    : NTSTATUS.STATUS_ACCESS_VIOLATION;
                if (Status != NTSTATUS.STATUS_SUCCESS)
                    return Status;
            }

            if (FileObj.RefusesApcRoutine(ApcRoutine))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Status = Instance.WinHelper.ReadFileByteOffset(ByteOffsetPtr, out long? Requested);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = Instance.WinHelper.ReadFileKey(KeyPtr, out Key);
            if (Status == NTSTATUS.STATUS_SUCCESS && FileObj.NoIntermediateBuffering && !FileObj.Device)
                Status = CheckSectorAlignment(FileObj, BufferPtr, Length, Requested, Write);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = Instance.WinHelper.ReferenceIoEvent(EventHandle, ResolvedEvent, out Event);

            if (Status != NTSTATUS.STATUS_SUCCESS || !HasFileOffset(FileObj))
                return Status;

            return ResolveFileOffset(FileObj, Requested, Write, Write && WinFile.IsAppendOnly(Granted), out Offset);
        }

        internal const long FileWriteToEndOfFile = -1;
        internal const long FileUseFilePointerPosition = -2;

        // The offset checks follow IopReadFile and IopValidateAndGetWriteParameters.
        private static NTSTATUS CheckSectorAlignment(WinFile FileObj, ulong BufferPtr, uint Length, long? Offset, bool Write)
        {
            const ulong SectorMask = WindowsStorageDeviceSupport.BytesPerSector - 1;
            if ((Length & SectorMask) != 0 || (BufferPtr & FileObj.AlignmentRequirement) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Offset is not long Value
                || (Write && (Value == FileWriteToEndOfFile || (Value == FileUseFilePointerPosition && FileObj.Synchronous))))
                return NTSTATUS.STATUS_SUCCESS;

            return ((ulong)Value & SectorMask) == 0 ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }

        // Console and volume objects carry no open mode, so a device other than a pipe skips the offset rules.
        private static bool HasFileOffset(WinFile FileObj) => !FileObj.Device || FileObj.IsNamedPipe;

        private static NTSTATUS ResolveFileOffset(WinFile FileObj, long? Requested, bool Write, bool AppendOnly, out long Offset)
        {
            Offset = 0;
            if (Requested == null && !FileObj.Synchronous)
                return FileObj.IsNamedPipe ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;

            // A synchronous file's pointer is claimed by the caller, under the file object lock.
            Offset = AppendOnly ? FileWriteToEndOfFile : Requested ?? FileUseFilePointerPosition;
            if (Offset == FileUseFilePointerPosition && FileObj.Synchronous)
                return NTSTATUS.STATUS_SUCCESS;

            return Offset >= 0 || (Write && Offset == FileWriteToEndOfFile) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PARAMETER;
        }
    }
}
