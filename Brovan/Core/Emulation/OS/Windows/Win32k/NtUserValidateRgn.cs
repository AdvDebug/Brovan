using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserValidateRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Win32kHelper.RedrawFromRegion(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1),
                Win32kHelper.RDW_VALIDATE);
        }
    }
}
