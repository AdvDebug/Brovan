using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // Nothing reaches a server port, so any delivery setting holds. A connection port answers synchronously.
    internal class NtAlpcSetInformation : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PortHandle = Instance.WinHelper.GetArg(0);
            ulong InformationPtr = Instance.WinHelper.GetArg(2);
            uint Length = (uint)Instance.WinHelper.GetArg(3);

            WinPort Port = Instance.WinHelper.HandleManager.GetObjectByHandle<WinPort>(PortHandle);
            if (Port == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (!Port.IsServer)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            if (InformationPtr != 0 && Length != 0 && !Instance.IsRegionMapped(InformationPtr, Length))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
