using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtCreateNamedPipeFile : IWinSyscall
    {
        private const uint FILE_CREATE = 2;
        private const uint FILE_OPEN_IF = 3;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong FileHandlePtr = Instance.WinHelper.GetArg(0);
            ulong DesiredAccess = Instance.WinHelper.GetArg(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg(3);
            uint CreateDisposition = (uint)Instance.WinHelper.GetArg(5);
            uint NamedPipeType = (uint)Instance.WinHelper.GetArg(7);
            uint ReadMode = (uint)Instance.WinHelper.GetArg(8);
            uint CompletionMode = (uint)Instance.WinHelper.GetArg(9);
            uint MaximumInstances = (uint)Instance.WinHelper.GetArg(10);
            uint InboundQuota = (uint)Instance.WinHelper.GetArg(11);
            uint OutboundQuota = (uint)Instance.WinHelper.GetArg(12);

            if (FileHandlePtr == 0 || ObjectAttributesPtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(IoStatusBlockPtr, (uint)(Instance.WinHelper.PointerSize * 2)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (CreateDisposition != FILE_CREATE && CreateDisposition != FILE_OPEN_IF)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string GuestPath = WinSysHelper.NormalizePipePath(FullName);
            if (!GuestNamedPipe.IsPipePath(GuestPath) || GuestPath.Length <= GuestNamedPipe.DeviceName.Length)
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            NTSTATUS Status = GuestNamedPipe.TryCreateServer(GuestPath, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, out GuestNamedPipe Pipe);
            if (Status != NTSTATUS.STATUS_SUCCESS)
            {
                Instance.WinHelper.WriteIoStatusBlock(Instance, IoStatusBlockPtr, Status, 0);
                return Status;
            }

            return NtCreateFile.CreateDeviceHandle(Instance, FileHandlePtr, IoStatusBlockPtr, (AccessMask)(uint)DesiredAccess, GuestPath, Pipe.HandleControl, Pipe);
        }
    }
}
