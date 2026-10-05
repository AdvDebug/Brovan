using Brovan.Core.Emulation.OS.Windows.RPC.Ports;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class Wow64BasepNlsGetUserInfo : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong CachePtr = Instance.WinHelper.GetArg(0);
            uint CacheSize = (uint)Instance.WinHelper.GetArg(1);

            BaseSrvNlsUserInfo Server = Instance.WinHelper.NlsUserInfo;
            if (Server == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            NTSTATUS Status = Server.GetUserInfo(Instance, CacheSize);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return Instance.WriteMemory(CachePtr, Server.UserInfo) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }

    internal class Wow64BasepNlsUpdateCacheCount : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.WinHelper.NlsUserInfo?.UpdateCacheCount(Instance);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
