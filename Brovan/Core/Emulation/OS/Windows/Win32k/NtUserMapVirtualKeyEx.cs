using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMapVirtualKeyEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Code = Instance.WinHelper.GetArg32(0);
            uint MapType = Instance.WinHelper.GetArg32(1);

            Instance.SetRawSyscallReturn(Win32kHelper.MapVirtualKey(Code, MapType));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
