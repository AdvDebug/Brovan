using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetKeyState : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            byte Vk = (byte)Instance.WinHelper.GetArg(0);

            Instance.SetRawSyscallReturn(Win32kHelper.GetKeyState(Instance, Vk));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
