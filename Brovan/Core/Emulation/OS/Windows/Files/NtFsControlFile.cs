using System;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFsControlFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong EventHandle = Instance.WinHelper.GetArg(1);
            ulong ApcRoutine = Instance.WinHelper.GetArg(2);
            ulong ApcContext = Instance.WinHelper.GetArg(3);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(4);
            uint FsControlCode = (uint)Instance.WinHelper.GetArg(5);
            ulong InputBufferPtr = Instance.WinHelper.GetArg(6);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg(7);
            ulong OutputBufferPtr = Instance.WinHelper.GetArg(8);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg(9);

            return ControlFile(Instance, FileHandle, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength);
        }

        private static NTSTATUS QueuePipeControl(BinaryEmulator Instance, WinFile File, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, uint FsControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength)
        {
            GuestNamedPipe Pipe = File.Pipe;
            bool Listen = FsControlCode == GuestNamedPipe.FSCTL_PIPE_LISTEN;

            // NT: a listen that fails at once leaves the IO_STATUS_BLOCK alone and the event reset.
            if (Listen && Pipe.IsServer && Pipe.Channel.Connected)
                return Pipe.Channel.PeerClosed ? NTSTATUS.STATUS_PIPE_CLOSING : NTSTATUS.STATUS_PIPE_CONNECTED;

            PipeRequest Request = Instance.WinHelper.PipeRequests.Create(Instance, Listen ? PipeRequestKind.Listen : PipeRequestKind.Transceive, File, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr);

            if (!Listen)
            {
                // NT: NPFS probes the reply buffer first.
                if (OutputBufferLength != 0 && !Instance.IsMemoryRangeMapped(OutputBufferPtr, OutputBufferLength))
                    return FailTransceive(Instance, Request, NTSTATUS.STATUS_ACCESS_VIOLATION);

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

        private static NTSTATUS ControlFile(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong ApcRoutine, ulong ApcContext, ulong IoStatusBlockPtr, uint FsControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength)
        {
            NTSTATUS Status = NtDeviceIoControlFile.CheckRequest(Instance, FileHandle, IoStatusBlockPtr, ApcRoutine, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, out WinFile File);
            if (Status == NTSTATUS.STATUS_SUCCESS)
                Status = Instance.WinHelper.ReferenceIoEvent(EventHandle);

            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.ClearPipeWait();
                return Status;
            }

            if (File.Pipe != null && !File.Pipe.IsDirectory &&
                (FsControlCode == GuestNamedPipe.FSCTL_PIPE_LISTEN || FsControlCode == GuestNamedPipe.FSCTL_PIPE_TRANSCEIVE))
                return QueuePipeControl(Instance, File, EventHandle, ApcRoutine, ApcContext, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength);

            Status = NtDeviceIoControlFile.CheckControlBuffers(Instance, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            DeviceData Data = new DeviceData();
            Data.File = File;
            Data.FileHandle = FileHandle;
            Data.EventHandle = EventHandle;
            Data.ApcRoutine = ApcRoutine;
            Data.ApcContext = ApcContext;
            Data.IoStatusBlock = IoStatusBlockPtr;

            byte[] RentedInput = null;
            byte[] RentedOutput = null;
            try
            {
                Status = NtDeviceIoControlFile.CaptureControlBuffers(Instance, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, ref Data, out RentedInput, out RentedOutput);
                if (Data.OutputBuffer != null)
                    Data.OutputLength = OutputBufferLength;

                if (Status == NTSTATUS.STATUS_SUCCESS)
                {
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
                    catch (Exception Ex)
                    {
                        Utils.LogError($"[NtFsControlFile] 0x{FsControlCode:X} on {File.Path}: {Ex.Message}");
                        Status = NTSTATUS.STATUS_UNSUCCESSFUL;
                    }
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

                if (!NtDeviceIoControlFile.WriteBackControlOutput(Instance, Status, OutputBufferPtr, OutputBufferLength, in Data))
                    Status = NTSTATUS.STATUS_ACCESS_VIOLATION;
            }
            finally
            {
                NtDeviceIoControlFile.ReleaseControlBuffers(RentedInput, RentedOutput);
            }

            ulong Information = Data.Information;
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, Information);
            Instance.WinHelper.SignalIoEvent(EventHandle, Status);
            Instance.WinHelper.QueueImmediateCompletion(File, ApcRoutine, ApcContext, IoStatusBlockPtr, Status, Information);
            return Status;
        }
    }
}
