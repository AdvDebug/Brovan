using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtUnlockVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return NtLockVirtualMemory.Change(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1), Instance.WinHelper.GetArg(2), (uint)Instance.WinHelper.GetArg(3), false);
        }
    }
}
