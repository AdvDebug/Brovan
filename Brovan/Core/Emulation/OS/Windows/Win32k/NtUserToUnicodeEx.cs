using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserToUnicodeEx : IWinSyscall
    {
        private const int KeyStateSize = 256;
        private const byte KeyDownMask = 0x80;
        private const byte KeyToggledMask = 0x01;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint VirtualKey = Instance.WinHelper.GetArg32(0);
            ulong KeyStatePtr = Instance.WinHelper.GetArg(2);
            ulong BufferPtr = Instance.WinHelper.GetArg(3);
            int BufferCharacters = unchecked((int)Instance.WinHelper.GetArg32(4));

            if (BufferPtr == 0 || BufferCharacters < 1 || !Instance.IsRegionMapped(BufferPtr, sizeof(char)))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Shift = false;
            bool CapsLock = false;
            bool Control = false;
            bool Menu = false;

            if (KeyStatePtr != 0 && Instance.IsRegionMapped(KeyStatePtr, KeyStateSize))
            {
                Span<byte> KeyState = Instance.WinHelper.Shared.GetSpan(KeyStateSize);
                if (Instance.ReadMemory(KeyStatePtr, KeyState, KeyStateSize))
                {
                    Shift = (KeyState[Win32kHelper.VkShift] & KeyDownMask) != 0;
                    CapsLock = (KeyState[Win32kHelper.VkCapital] & KeyToggledMask) != 0;
                    Control = (KeyState[Win32kHelper.VkControl] & KeyDownMask) != 0;
                    Menu = (KeyState[Win32kHelper.VkMenu] & KeyDownMask) != 0;
                }
            }

            if ((Menu && !Control) || !Win32kHelper.TryTranslateKey(VirtualKey, Shift, CapsLock, Control, out char Character))
            {
                Instance._emulator.WriteMemory(BufferPtr, (ushort)0, sizeof(char));
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance._emulator.WriteMemory(BufferPtr, (ushort)Character, sizeof(char));
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
