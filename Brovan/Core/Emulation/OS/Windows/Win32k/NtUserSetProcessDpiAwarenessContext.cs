using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetProcessDpiAwarenessContext : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Context = (uint)Instance.WinHelper.GetArg(0);

            Instance.SetBooleanSyscallReturn(Win32kDpi.TrySetProcessContext(Instance, Context));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
