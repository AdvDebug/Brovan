using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetCharSet : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);

            Instance.SetRawSyscallReturn(Win32kHelper.GetDcCharSet(Instance, Hdc));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
