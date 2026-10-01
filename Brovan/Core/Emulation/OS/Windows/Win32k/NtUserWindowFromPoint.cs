using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserWindowFromPoint : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // x64 passes the POINT by value in one register, x86 as two stack slots.
            ulong First = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)(uint)First);
            int Y = Instance.WinHelper.PointerSize == 8
                ? unchecked((int)(uint)(First >> 32))
                : unchecked((int)(uint)Instance.WinHelper.GetArg(1));

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.WindowFromPoint(Instance, X, Y));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
