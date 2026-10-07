using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFsControlFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private static NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg64(0);
            ulong EventHandle = Instance.WinHelper.GetArg64(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg64(2);
            ulong ApcContext = Instance.WinHelper.GetArg64(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(4);
            uint FsControlCode = (uint)Instance.WinHelper.GetArg64(5, true);
            ulong InputBufferPtr = Instance.WinHelper.GetArg64(6);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg64(7, true);
            ulong OutputBufferPtr = Instance.WinHelper.GetArg64(8);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg64(9, true);

            return ControlFile(Instance, FileHandle, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, Is64Bit: true);
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint FileHandle = Instance.WinHelper.GetArg32(0);
            uint EventHandle = Instance.WinHelper.GetArg32(1);
            uint ApcRoutine = Instance.WinHelper.GetArg32(2);
            uint ApcContext = Instance.WinHelper.GetArg32(3);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(4);
            uint FsControlCode = Instance.WinHelper.GetArg32(5);
            uint InputBufferPtr = Instance.WinHelper.GetArg32(6);
            uint InputBufferLength = Instance.WinHelper.GetArg32(7);
            uint OutputBufferPtr = Instance.WinHelper.GetArg32(8);
            uint OutputBufferLength = Instance.WinHelper.GetArg32(9);

            return ControlFile(Instance, FileHandle, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, Is64Bit: false);
        }

        private static NTSTATUS QueuePipeControl(BinaryEmulator Instance, WinFile File, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, uint FsControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength, bool Is64Bit)
        {
            GuestNamedPipe Pipe = File.Pipe;
            bool Listen = FsControlCode == GuestNamedPipe.FSCTL_PIPE_LISTEN;

            // NT: a listen that fails at once leaves the IO_STATUS_BLOCK and the event alone.
            if (Listen && Pipe.IsServer && Pipe.Channel.Connected)
                return Pipe.Channel.PeerClosed ? NTSTATUS.STATUS_PIPE_CLOSING : NTSTATUS.STATUS_PIPE_CONNECTED;

            PipeRequest Request = Instance.WinHelper.PipeRequests.Create(Instance, Listen ? PipeRequestKind.Listen : PipeRequestKind.Transceive, File, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);

            if (!Listen)
            {
                if (InputBufferLength > GuestNamedPipe.MaxMessageBytes)
                    return FailTransceive(Instance, Request, NTSTATUS.STATUS_INVALID_PARAMETER);

                if (!PipeRequestQueue.TryTakeData(Instance, Request, InputBufferPtr, (int)InputBufferLength))
                    return FailTransceive(Instance, Request, NTSTATUS.STATUS_ACCESS_VIOLATION);

                Request.Buffer = OutputBufferPtr;
                Request.Length = (int)Math.Min(OutputBufferLength, (uint)GuestNamedPipe.MaxMessageBytes);
            }

            return Instance.WinHelper.PipeRequests.Submit(Instance, Request);
        }

        // NT: a failed transceive still writes the IO_STATUS_BLOCK and the event.
        private static NTSTATUS FailTransceive(BinaryEmulator Instance, PipeRequest Request, NTSTATUS Status)
        {
            Instance.WinHelper.CompletePendingIo(in Request.Io, Status, 0, false, false);
            return Status;
        }

        private static NTSTATUS ControlFile(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, uint FsControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength, bool Is64Bit)
        {
            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, Is64Bit ? 0x10UL : 0x08UL))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // NT: these fail before the event or the IO_STATUS_BLOCK is touched.
            WinFile File = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (File == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (InputBufferPtr != 0 && InputBufferLength != 0 && !Instance.IsRegionMapped(InputBufferPtr, InputBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (OutputBufferPtr != 0 && OutputBufferLength != 0 && !Instance.IsRegionMapped(OutputBufferPtr, OutputBufferLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!HasControlAccess(Instance, FileHandle, FsControlCode))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Instance.WinHelper.ResetIoEvent(EventHandle);

            if (File.Pipe != null && !File.Pipe.IsRoot &&
                (FsControlCode == GuestNamedPipe.FSCTL_PIPE_LISTEN || FsControlCode == GuestNamedPipe.FSCTL_PIPE_TRANSCEIVE))
                return QueuePipeControl(Instance, File, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, Is64Bit);

            DeviceData Data = new DeviceData();

            if (InputBufferPtr != 0 && InputBufferLength != 0)
            {
                Data.InputBuffer = Instance.ReadMemory(InputBufferPtr, InputBufferLength);
                Data.InputLength = InputBufferLength;
            }

            if (OutputBufferPtr != 0 && OutputBufferLength != 0)
            {
                Data.OutputBuffer = Instance.ReadMemory(OutputBufferPtr, OutputBufferLength);
                Data.OutputLength = OutputBufferLength;
            }

            Data.File = File;
            Data.FileHandle = FileHandle;
            Data.EventHandle = EventHandle;
            Data.ApcRoutine = ApcRoutine;
            Data.ApcContext = ApcContext;
            Data.IoStatusBlock = IoStatusBlockPtr;

            NTSTATUS Status;
            try
            {
                // FSCTL and IOCTL are separate namespaces, and a device handler answers the IOCTL one.
                if (File.Pipe != null)
                    Status = File.Pipe.HandleControl(FsControlCode, ref Data, Instance);
                else if (File.HostStream == HostStreamKind.Input && FsControlCode == GuestNamedPipe.FSCTL_PIPE_PEEK)
                    Status = GuestNamedPipe.PeekHostStream(ref Data, Instance);
                else
                    Status = WindowsStorageDeviceSupport.HandleFsControl(FsControlCode, ref Data, File);
            }
            catch
            {
                Status = NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            if (File.HostStream != HostStreamKind.None && Status == NTSTATUS.STATUS_PENDING)
                return Status;

            // Only FSCTL_PIPE_WAIT returns pending here.
            if (File.Pipe != null && Status == NTSTATUS.STATUS_PENDING)
            {
                int TimeoutMilliseconds = GuestNamedPipe.ReadWaitTimeoutMilliseconds(Data.InputBuffer, Data.InputLength);
                WinPendingIo? SyncIo = File.Synchronous ? Instance.WinHelper.SynchronousIo(File, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr) : null;
                if (Instance.WinHelper.TryContinuePipeWait(FileHandle, TimeoutMilliseconds, GuestNamedPipe.PollSliceMilliseconds, SyncIo))
                    return NTSTATUS.STATUS_PENDING;

                Status = NTSTATUS.STATUS_IO_TIMEOUT;
            }
            else if (File.Pipe != null)
            {
                Instance.WinHelper.ClearPipeWait();
            }

            ulong Information = Data.Information;

            if (((uint)Status >> 30) != 3 && OutputBufferPtr != 0 && OutputBufferLength != 0 && Data.OutputBuffer != null)
            {
                uint ToWrite = (uint)Math.Min(Information, Math.Min(OutputBufferLength, (uint)Data.OutputBuffer.Length));
                if (ToWrite != 0)
                    Instance.WriteMemory(OutputBufferPtr, Data.OutputBuffer.AsSpan(0, (int)ToWrite));
            }

            WriteIoStatus(Instance, IoStatusBlockPtr, Status, Information, Is64Bit);

            if (EventHandle != 0 && Status != NTSTATUS.STATUS_PENDING)
            {
                WinEvent Ev = Instance.WinHelper.GetEventByHandle(EventHandle, AccessMask.GiveTemp);
                if (Ev != null)
                    Ev.Signaled = true;
            }

            return Status;
        }

        private static bool HasControlAccess(BinaryEmulator Instance, ulong FileHandle, uint ControlCode)
        {
            uint RequiredAccess = (ControlCode >> 14) & 0x3;
            if (RequiredAccess == 0)
                return true;

            if ((RequiredAccess & 0x1) != 0 &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.GenericRead) &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.FileReadData))
            {
                return false;
            }

            if ((RequiredAccess & 0x2) != 0 &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.GenericWrite) &&
                !Instance.WinHelper.HandleManager.CheckAccess(FileHandle, AccessMask.FileWriteData))
            {
                return false;
            }

            return true;
        }

        private static NTSTATUS WriteIoStatus(BinaryEmulator Instance, ulong IoStatusBlockPtr, NTSTATUS Status, ulong Information, bool Is64Bit)
        {
            if (Is64Bit)
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);
            else
                Instance.WinHelper.WriteIoStatusBlock(Instance, (uint)IoStatusBlockPtr, Status, (uint)Information);

            return Status;
        }
    }
}
