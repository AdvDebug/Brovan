using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserTranslateMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong MessagePtr = Instance.WinHelper.GetArg64(0);

            if (MessagePtr == 0 || !Win32kHelper.TryReadMessage(Instance, MessagePtr, out Win32kMessage Message))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint CharMessage;
            switch (Message.Message)
            {
                case Win32kHelper.WM_KEYDOWN:
                    CharMessage = Win32kHelper.WM_CHAR;
                    break;
                case Win32kHelper.WM_SYSKEYDOWN:
                    CharMessage = Win32kHelper.WM_SYSCHAR;
                    break;
                default:
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            uint VirtualKey = (uint)Message.WParam;
            uint ScanCode = (uint)((Message.LParam >> 16) & 0xFF);

            if (!Instance.WinHelper.TranslateVirtualKey(VirtualKey, ScanCode, out char Character) || Character == '\0')
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.PostMessage(Instance, Message.Hwnd, CharMessage, Character, Message.LParam);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
