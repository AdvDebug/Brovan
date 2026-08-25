using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetRawInputData : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong RawInputHandle = Instance.WinHelper.GetArg(0);
            uint Command = (uint)Instance.WinHelper.GetArg(1);
            ulong DataPtr = Instance.WinHelper.GetArg(2);
            ulong SizePtr = Instance.WinHelper.GetArg(3);
            uint HeaderSize = (uint)Instance.WinHelper.GetArg(4);

            uint Result = Win32kRawInput.ReadData(Instance, RawInputHandle, Command, DataPtr, SizePtr, HeaderSize);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
