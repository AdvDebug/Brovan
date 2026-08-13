using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcConnectPortEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandlePtr = Instance.WinHelper.GetArg(0);
            ulong ConnectionPortObjectAttributes = Instance.WinHelper.GetArg(1);

            if (PortHandlePtr == 0 || ConnectionPortObjectAttributes == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(PortHandlePtr, (uint)Instance.WinHelper.PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName(ConnectionPortObjectAttributes, out _, out _, out string PortName, out NTSTATUS Status))
                return Status;

            if (string.IsNullOrEmpty(PortName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (!Instance.WinHelper.WinPorts.Any(Port => string.Equals(Port.Name, PortName, StringComparison.OrdinalIgnoreCase)))
            {
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[!] NtAlpcConnectPortEx: no port \"{PortName}\".", LogFlags.Syscall);

                return NTSTATUS.STATUS_ACCESS_DENIED;
            }

            return NtAlpcConnectPort.Connect(Instance, PortHandlePtr, PortName);
        }
    }
}
