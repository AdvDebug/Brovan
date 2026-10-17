using System;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtFlushBuffersFile : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandle = Instance.WinHelper.GetArg(0);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(1);

            NTSTATUS Reference = Instance.WinHelper.ReferenceObjectByHandle(FileHandle, AccessMask.GiveTemp, out WinFile FileObj, out AccessMask Granted);
            if (Reference != NTSTATUS.STATUS_SUCCESS)
                return Reference;

            if (IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.TryProbeIoStatusBlock(IoStatusBlockPtr, out NTSTATUS ProbeStatus))
                return ProbeStatus;

            if (!FileObj.AllowsWrite(Granted))
                return NTSTATUS.STATUS_ACCESS_DENIED;

            NTSTATUS Status = Flush(FileObj);
            Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
            return Status;
        }

        private static NTSTATUS Flush(WinFile FileObj)
        {
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
            catch (Exception Ex)
            {
                Utils.LogError($"[NtFlushBuffersFile] {FileObj.Path}: {Ex.Message}");
                return NTSTATUS.STATUS_ACCESS_DENIED;
            }
        }
    }
}
