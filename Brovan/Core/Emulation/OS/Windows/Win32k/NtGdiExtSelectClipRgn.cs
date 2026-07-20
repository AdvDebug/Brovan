using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtSelectClipRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.GetArg(0);
            ulong Hrgn = Instance.WinHelper.GetArg(1);
            int Mode = unchecked((int)Instance.WinHelper.GetArg(2));

            if (Hrgn == 0 && Mode == 5)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Hrgn == 0)
            {
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
