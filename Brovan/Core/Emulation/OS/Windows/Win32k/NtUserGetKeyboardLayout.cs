using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetKeyboardLayout : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            IReadOnlyList<uint> Layouts = Win32kHelper.GetKeyboardLayouts(Instance);
            Instance.SetRawSyscallReturn(Layouts.Count != 0 ? Layouts[0] : 0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
