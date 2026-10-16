using System;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtWriteFile : IWinSyscall
    {
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

            NTSTATUS Status = NtReadFile.BeginRequest(Instance, FileHandle, EventHandle, IoStatusBlockPtr, BufferPtr, Length, ApcRoutine, ByteOffsetPtr, Write: true, out WinFile FileObj, out long Offset);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (FileObj.Pipe != null)
                return WritePipe(Instance, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length);

            if (FileObj.ConsoleKind == ConsoleObjectKind.Output || FileObj.HostStream is HostStreamKind.Output or HostStreamKind.Error)
            {
                // NT: a pipe copies the buffer at once, so a fault leaves the IO_STATUS_BLOCK alone.
                if (Length != 0 && !Instance.IsAccessible(BufferPtr, Length, false))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Status = HandleStdOut(Instance, IoStatusBlockPtr, BufferPtr, Length, FileObj.HostStream == HostStreamKind.Error);
                Instance.WinHelper.QueueImmediateCompletion(FileObj, ApcRoutine, ApcContext, IoStatusBlockPtr, Status, Length);
            }
            else
            {
                Status = Write(Instance, FileHandle, FileObj, ApcRoutine, ApcContext, IoStatusBlockPtr, BufferPtr, Length, Offset);
            }

            Instance.WinHelper.SignalIoEvent(EventHandle, Status);
            return Status;
        }

        private static NTSTATUS Write(BinaryEmulator Instance, ulong FileHandle, WinFile FileObj, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length, long Offset)
        {
            if (FileObj.Device)
            {
                if (FileObj.IsNullDevice)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Length);
                    Instance.WinHelper.QueueImmediateCompletion(FileObj, ApcRoutine, ApcContext, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Length);
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

            if ((Instance.Settings.Flags & LogFlags.Suspicious) != 0 && WarnWrite(FileObj.Path, out string WarnData))
                Instance.TriggerEventMessage($"[!] The emulated program tried to write to {WarnData}", LogFlags.Suspicious);

            WindowsFileStream Stream = FileObj.GetFileStream(true);
            if (Stream == null)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            if (Offset == NtReadFile.FileWriteToEndOfFile)
                Offset = Stream.Length;

            int ToWrite = Length > int.MaxValue ? int.MaxValue : (int)Length;
            if (ToWrite != 0 && FileObj.HasConflictingIoLock((ulong)Offset, (ulong)ToWrite, true))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_FILE_LOCK_CONFLICT, 0);
                return NTSTATUS.STATUS_FILE_LOCK_CONFLICT;
            }

            // NT: the file system faults on the user buffer after the probe passed, and writes none of it.
            if (ToWrite != 0 && !Instance.IsAccessible(BufferPtr, (ulong)ToWrite, false))
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_USER_BUFFER, 0);
                return NTSTATUS.STATUS_INVALID_USER_BUFFER;
            }

            // Bounded chunks keep a guest-sized write from growing the shared scratch buffer to the data size.
            int Done = 0;
            try
            {
                while (Done < ToWrite)
                {
                    int ChunkSize = Math.Min(NtReadFile.IoChunkBytes, ToWrite - Done);
                    Span<byte> Incoming = Instance.WinHelper.ReadMemorySpan(BufferPtr + (ulong)Done, (uint)ChunkSize);
                    if (Incoming.Length == 0)
                        break;

                    Stream.WriteAt(Offset + Done, Incoming);
                    Done += Incoming.Length;
                }
            }
            catch (Exception Ex)
            {
                Utils.LogError($"[NtWriteFile] {FileObj.Path}: {Ex.Message}");
                if (Done == 0)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0);
                    return NTSTATUS.STATUS_ACCESS_DENIED;
                }
            }

            FileObj.Real = true;
            if (FileObj.Synchronous && ToWrite != 0)
                FileObj.Position = Offset + Done;

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Done);
            Instance.WinHelper.QueueImmediateCompletion(FileObj, ApcRoutine, ApcContext, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, (ulong)Done);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtWriteFile: File=0x{FileHandle:X}, Offset=0x{Offset:X}, Wrote=0x{Done:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: no failure writes the IO_STATUS_BLOCK.
        private static NTSTATUS WritePipe(BinaryEmulator Instance, WinFile FileObj, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length)
        {
            bool MessagePipe = FileObj.Pipe.PipeType == GuestNamedPipe.FILE_PIPE_MESSAGE_MODE;
            if (Length > (MessagePipe ? (uint)GuestNamedPipe.MaxMessageBytes : int.MaxValue))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            PipeRequest Request = Instance.WinHelper.PipeRequests.Create(Instance, PipeRequestKind.Write, FileObj, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);
            bool Readable = MessagePipe
                ? PipeRequestQueue.TryTakeData(Instance, Request, BufferPtr, (int)Length)
                : Length == 0 || Instance.IsMemoryRangeMapped(BufferPtr, Length);

            if (!Readable)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!MessagePipe)
            {
                Request.Buffer = BufferPtr;
                Request.DataLength = (int)Length;
            }

            return Instance.WinHelper.PipeRequests.Submit(Instance, Request);
        }

        private static NTSTATUS HandleStdOut(BinaryEmulator Instance, ulong IoStatusBlockPtr, ulong BufferPtr, uint Length, bool StandardError)
        {
            if (Length == 0)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, 0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (uint Done = 0; Done < Length;)
            {
                uint Step = Math.Min(Length - Done, (uint)NtReadFile.IoChunkBytes);
                Span<byte> Data = Instance.WinHelper.ReadMemorySpan(BufferPtr + Done, Step);
                if (Data.Length == 0)
                {
                    Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                Instance.WinHelper.ConsoleState.TrackOutput(Data);
                GeneralHelper.ConsoleWrite(Data, Instance.Settings.ConsoleOutputMode, StandardError);
                Done += Step;
            }

            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, Length);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool WarnWrite(string Path, out string Data)
        {
            Data = string.Empty;

            if (string.IsNullOrWhiteSpace(Path))
                return false;

            Path = Path.Replace('/', '\\').TrimEnd('\\');

            if (Path.Equals(@"\\.\PhysicalDrive0", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive0 (raw disk / possible MBR)";
                return true;
            }

            if (Path.Equals(@"\\.\PhysicalDrive1", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive1 (raw disk)";
                return true;
            }

            if (Path.Equals(@"\\.\PhysicalDrive2", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive2 (raw disk)";
                return true;
            }

            if (Path.Equals(@"\\.\PhysicalDrive3", StringComparison.OrdinalIgnoreCase))
            {
                Data = "PhysicalDrive3 (raw disk)";
                return true;
            }

            if (Path.Equals(@"\\.\C:", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A raw volume device";
                return true;
            }

            if (Path.Equals(@"C:\Boot\BCD", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The Boot Configuration Data";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SAM", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SAM database";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SECURITY", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SECURITY hive";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SYSTEM hive";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\SOFTWARE", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The SOFTWARE hive";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\config\DEFAULT", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The DEFAULT hive";
                return true;
            }

            if (Path.StartsWith(@"\\.\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A raw volume device";
                return true;
            }

            if (Path.StartsWith(@"\\?\GLOBALROOT\Device\Harddisk", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith(@"\Device\Harddisk", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A low-level disk device";
                return true;
            }

            if (Path.StartsWith(@"C:\Windows\System32\drivers\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The drivers folder";
                return true;
            }

            if (Path.Equals(@"C:\Windows\System32\Tasks", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith(@"C:\Windows\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The tasks folder directly";
                return true;
            }

            if (Path.StartsWith(@"C:\EFI\", StringComparison.OrdinalIgnoreCase) ||
                Path.StartsWith(@"C:\Windows\Boot\EFI\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "EFI boot files";
                return true;
            }

            if (Path.StartsWith(@"C:\Windows\System32\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A core Windows system32 directory";
                return true;
            }

            if (Path.StartsWith(@"C:\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "A core Windows WOW64 system directory";
                return true;
            }

            if (Path.StartsWith(@"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase))
            {
                Data = "The all-users Startup folder";
                return true;
            }

            return false;
        }
    }
}