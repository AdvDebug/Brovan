using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFlushBuffersFile : IWinSyscall
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
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(1);

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, 0x10))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = FlushHandle(Instance, FileHandle);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, Status, 0);
            return Status;
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint FileHandle = Instance.WinHelper.GetArg32(0);
            uint IoStatusBlockPtr = Instance.WinHelper.GetArg32(1);

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, 0x08))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = FlushHandle(Instance, FileHandle);
            Instance.WinHelper.WriteIoStatusBlock32(Instance, IoStatusBlockPtr, Status, 0);
            return Status;
        }

        private static NTSTATUS FlushHandle(BinaryEmulator Instance, ulong FileHandle)
        {
            if (Instance.WinHelper.STD_OUT != null && FileHandle == (ulong)Instance.WinHelper.STD_OUT.Handle)
            {
                Console.Out.Flush();
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinFile FileObj = Instance.WinHelper.GetFileByHandle(FileHandle, AccessMask.GiveTemp);
            if (FileObj == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (FileObj.Device)
                return NTSTATUS.STATUS_SUCCESS;

            if (FileObj.Directory)
                return NTSTATUS.STATUS_INVALID_DEVICE_REQUEST;

            WindowsFileStream Stream = FileObj.GetFileStream();
            if (Stream == null || !Stream.ExistsAsFile)
                return NTSTATUS.STATUS_SUCCESS;

            try
            {
                Stream.Flush();
                return NTSTATUS.STATUS_SUCCESS;
            }
            catch
            {
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }
        }
    }
}
