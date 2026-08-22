using System;
using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64UserConnectToServer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ConnectionInfo = Instance.WinHelper.GetArg(1);
            uint ConnectionInfoSize = (uint)Instance.WinHelper.GetArg(2);
            ulong ServerToServerCallPtr = Instance.WinHelper.GetArg(3);

            Span<byte> Data = stackalloc byte[CsrssPortHandler.UserConnectTotalSize];
            if (!CsrssPortHandler.TryBuildUserConnect(Instance, ConnectionInfo, ConnectionInfoSize, Data))
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            uint WriteLength = Math.Min(ConnectionInfoSize, (uint)Data.Length);
            if (WriteLength == 0 || !Instance.IsRegionMapped(ConnectionInfo, WriteLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WriteMemory(ConnectionInfo, Data.Slice(0, (int)WriteLength)))
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
