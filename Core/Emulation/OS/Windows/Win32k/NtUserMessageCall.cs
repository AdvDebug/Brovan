using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMessageCall : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            uint Message = (uint)Instance.WinHelper.GetArg64(1, true);
            ulong WParam = Instance.WinHelper.GetArg64(2);
            ulong LParam = Instance.WinHelper.GetArg64(3);
            ulong XParam = Instance.WinHelper.GetArg64(4);
            ulong Flags = Instance.WinHelper.GetArg64(6);
            bool Ansi = (XParam & 1) != 0 || (Flags & 1) != 0;

            if ((Message & 0xFFFE0000u) != 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Result = Win32kHelper.HandleMessageCall(Instance, Hwnd, Message, WParam, LParam, Ansi);
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
