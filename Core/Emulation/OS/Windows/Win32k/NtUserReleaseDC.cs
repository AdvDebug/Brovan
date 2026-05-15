using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserReleaseDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hdc = Instance.WinHelper.GetArg64(0);
            bool Released = Win32kHelper.ReleaseDeviceContext(Instance, Hdc);
            Instance.SetRawSyscallReturn(Released ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
