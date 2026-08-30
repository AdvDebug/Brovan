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
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(4);
            uint FsControlCode = (uint)Instance.WinHelper.GetArg64(5, true);
            ulong InputBufferPtr = Instance.WinHelper.GetArg64(6);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg64(7, true);
            ulong OutputBufferPtr = Instance.WinHelper.GetArg64(8);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg64(9, true);

            return ControlFile(Instance, FileHandle, EventHandle, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, Is64Bit: true);
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint FileHandle = Instance.WinHelper.GetArg32(0);
            uint EventHandle = Instance.WinHelper.GetArg32(1);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(4);
            uint FsControlCode = Instance.WinHelper.GetArg32(5);
            uint InputBufferPtr = Instance.WinHelper.GetArg32(6);
            uint InputBufferLength = Instance.WinHelper.GetArg32(7);
            uint OutputBufferPtr = Instance.WinHelper.GetArg32(8);
            uint OutputBufferLength = Instance.WinHelper.GetArg32(9);

            return ControlFile(Instance, FileHandle, EventHandle, IoStatusBlockPtr, FsControlCode, InputBufferPtr, InputBufferLength, OutputBufferPtr, OutputBufferLength, Is64Bit: false);
        }

        private static NTSTATUS ControlFile(BinaryEmulator Instance, ulong FileHandle, ulong EventHandle, ulong IoStatusBlockPtr, uint FsControlCode, ulong InputBufferPtr, uint InputBufferLength, ulong OutputBufferPtr, uint OutputBufferLength, bool Is64Bit)
        {
            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, Is64Bit ? 0x10UL : 0x08UL))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinFile File = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (File == null)
                return WriteIoStatus(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_INVALID_HANDLE, 0, Is64Bit);

            if (InputBufferPtr != 0 && InputBufferLength != 0 && !Instance.IsRegionMapped(InputBufferPtr, InputBufferLength))
                return WriteIoStatus(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0, Is64Bit);

            if (OutputBufferPtr != 0 && OutputBufferLength != 0 && !Instance.IsRegionMapped(OutputBufferPtr, OutputBufferLength))
                return WriteIoStatus(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_VIOLATION, 0, Is64Bit);

            if (!HasControlAccess(Instance, FileHandle, FsControlCode))
                return WriteIoStatus(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_ACCESS_DENIED, 0, Is64Bit);

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

            NTSTATUS Status;
            try
            {
                // FSCTL and IOCTL are separate namespaces, and a device handler answers the IOCTL one.
                Status = File.Pipe != null
                    ? File.Pipe.HandleControl(FsControlCode, ref Data, Instance)
                    : WindowsStorageDeviceSupport.HandleFsControl(FsControlCode, ref Data, File);
            }
            catch
            {
                Status = NTSTATUS.STATUS_UNSUCCESSFUL;
            }

            if (File.Pipe != null && Status == NTSTATUS.STATUS_PENDING)
            {
                int TimeoutMilliseconds = FsControlCode == GuestNamedPipe.FSCTL_PIPE_WAIT
                    ? GuestNamedPipe.ReadWaitTimeoutMilliseconds(Data.InputBuffer, Data.InputLength)
                    : GuestNamedPipe.BlockingIoMilliseconds;

                if (Instance.WinHelper.TryContinuePipeWait(FileHandle, TimeoutMilliseconds, GuestNamedPipe.PollSliceMilliseconds))
                    return NTSTATUS.STATUS_PENDING;

                Status = FsControlCode switch
                {
                    GuestNamedPipe.FSCTL_PIPE_WAIT => NTSTATUS.STATUS_IO_TIMEOUT,
                    GuestNamedPipe.FSCTL_PIPE_TRANSCEIVE => NTSTATUS.STATUS_PIPE_EMPTY,
                    _ => NTSTATUS.STATUS_PIPE_LISTENING,
                };
            }
            else if (File.Pipe != null)
            {
                Instance.WinHelper.ClearPipeWait();
            }

            ulong Information = Data.Information;

            if (OutputBufferPtr != 0 && OutputBufferLength != 0 && Data.OutputBuffer != null)
            {
                uint ToWrite = Math.Min(OutputBufferLength, (uint)Data.OutputBuffer.Length);
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
