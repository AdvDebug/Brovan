using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserTranslateMessage : IWinSyscall
    {
        private const uint TranslateFailWithoutCharacter = 0x2;
        private const uint MoreCharactersFollow = 0x02000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong MessagePtr = Instance.WinHelper.GetArg(0);
            uint Flags = Instance.WinHelper.GetArg32(1);

            if (MessagePtr == 0 || !Win32kHelper.TryReadMessage(Instance, MessagePtr, out Win32kMessage Message)
                || Instance.WinHelper.GetWindow(Message.Hwnd) == null)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint CharMessage;
            uint DeadCharMessage;
            switch (Message.Message)
            {
                case Win32kHelper.WM_KEYDOWN:
                case Win32kHelper.WM_KEYUP:
                case Win32kHelper.WM_SYSKEYUP:
                    CharMessage = Win32kHelper.WM_CHAR;
                    DeadCharMessage = Win32kHelper.WM_DEADCHAR;
                    break;
                case Win32kHelper.WM_SYSKEYDOWN:
                    CharMessage = Win32kHelper.WM_SYSCHAR;
                    DeadCharMessage = Win32kHelper.WM_SYSDEADCHAR;
                    break;
                default:
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> KeyState = stackalloc byte[Win32kHelper.KeyStateSize];
            Win32kHelper.CopyKeyboardState(Instance, KeyState);

            Span<char> Characters = stackalloc char[Win32kHelper.MaxKeyCharacters];
            uint LParam = (uint)Message.LParam;
            int Count = Win32kHelper.TranslateKey(Instance, (ushort)Message.WParam, LParam >> 16, KeyState, Characters);
            if (Count == 0)
            {
                Instance.SetRawSyscallReturn((Flags & TranslateFailWithoutCharacter) != 0 ? 0UL : 1UL);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Posted = CharMessage;
            if (Count < 0)
            {
                Posted = DeadCharMessage;
                Count = -Count;
            }

            for (int Index = 0; Index < Count; Index++)
            {
                uint Bits = Index < Count - 1 ? LParam | MoreCharactersFollow : LParam;
                Win32kHelper.PostMessage(Instance, Message.Hwnd, Posted, Characters[Index], Bits);
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
