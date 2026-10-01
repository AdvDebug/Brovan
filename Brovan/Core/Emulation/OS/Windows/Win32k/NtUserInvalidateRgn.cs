using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserInvalidateRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Erase = Instance.WinHelper.GetArg32(2) != 0;
            return Win32kHelper.RedrawFromRegion(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1),
                Win32kHelper.RDW_INVALIDATE | (Erase ? Win32kHelper.RDW_ERASE : 0));
        }
    }
}
