using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtSetSecurityObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Wide = Instance._binary.Architecture == BinaryArchitecture.x64;
            ulong Handle = Wide ? Instance.WinHelper.GetArg(0) : Instance.WinHelper.GetArg32(0);
            ulong SecurityDescriptorPtr = Wide ? Instance.WinHelper.GetArg(2) : Instance.WinHelper.GetArg32(2);

            if (SecurityDescriptorPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.HandleManager.TryGetHandle(Handle, out _))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            // One user owns everything here, so the descriptor never changes.
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
