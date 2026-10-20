namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlpcAcceptConnectPort : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandlePtr = Instance.WinHelper.GetArg(0);
            ulong ConnectionPortHandle = Instance.WinHelper.GetArg(1);
            ulong PortAttributesPtr = Instance.WinHelper.GetArg(4);
            ulong PortContext = Instance.WinHelper.GetArg(5);
            ulong ConnectionRequestPtr = Instance.WinHelper.GetArg(6);
            bool AcceptConnection = (byte)Instance.WinHelper.GetArg(8) != 0;

            WinPort ConnectionPort = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(ConnectionPortHandle);
            if (ConnectionPort == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!ConnectionPort.IsServer)
                return NTSTATUS.STATUS_INVALID_PORT_HANDLE;

            return AlpcMessaging.Accept(Instance, ConnectionPort, PortHandlePtr, PortAttributesPtr, PortContext, ConnectionRequestPtr, AcceptConnection);
        }
    }
}
