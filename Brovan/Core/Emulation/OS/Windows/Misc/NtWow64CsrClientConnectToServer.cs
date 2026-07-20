namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64CsrClientConnectToServer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ConnectionInfo = Instance.WinHelper.GetArg(2);
            uint ConnectionInfoSize = (uint)Instance.WinHelper.GetArg(3);
            ulong ServerToServerCallPtr = Instance.WinHelper.GetArg(4);

            if (ConnectionInfo != 0 && ConnectionInfoSize != 0 && !Instance.IsRegionMapped(ConnectionInfo, ConnectionInfoSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ServerToServerCallPtr != 0)
            {
                if (!Instance.IsRegionMapped(ServerToServerCallPtr, 1))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WinHelper.WriteByte(ServerToServerCallPtr, 0))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
