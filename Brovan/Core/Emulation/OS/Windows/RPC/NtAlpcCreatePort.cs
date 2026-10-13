using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcCreatePort : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandlePtr = Instance.WinHelper.GetArg(0);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg(1);

            if (PortHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(PortHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string PortName = string.Empty;
            if (ObjectAttributesPtr != 0)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName(ObjectAttributesPtr, out _, out _, out string FullName, out NTSTATUS Status))
                    return Status;

                PortName = FullName ?? string.Empty;
            }

            if (PortName.Length != 0 && NtConnectPort.FindPortByName(Instance, PortName) != null)
                return NTSTATUS.STATUS_OBJECT_NAME_COLLISION;

            WinPort Created = AlpcMessaging.CreateConnectionPort(PortName);
            if (PortName.Length != 0)
                Instance.WinHelper.WinPorts.Add(Created);

            WinHandle Handle = Instance.WinHelper.OpenObjectHandle(Created, AccessMask.StandardRightsAll);

            if (!Instance.WinHelper.WritePointer(PortHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
