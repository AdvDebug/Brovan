using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetRawInputBuffer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DataPtr = Instance.WinHelper.GetArg(0);
            ulong SizePtr = Instance.WinHelper.GetArg(1);
            uint HeaderSize = (uint)Instance.WinHelper.GetArg(2);

            Instance.SetRawSyscallReturn(Win32kRawInput.ReadBuffer(Instance, DataPtr, SizePtr, HeaderSize));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
