using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserPostMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            uint Message = (uint)Instance.WinHelper.GetArg64(1, true);
            ulong WParam = Instance.WinHelper.GetArg64(2);
            ulong LParam = Instance.WinHelper.GetArg64(3);

            if ((Message & 0xFFFE0000u) != 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Success = Win32kHelper.PostMessage(Instance, Hwnd, Message, WParam, LParam);
            Instance.SetLastWinError(Success ? 0u : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Success);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
