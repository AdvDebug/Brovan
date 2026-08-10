using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetKeyboardState : IWinSyscall
    {
        private const int KeyStateSize = 256;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong KeyStatePtr = Instance.WinHelper.GetArg(0);

            if (KeyStatePtr == 0 || !Instance.IsRegionMapped(KeyStatePtr, KeyStateSize))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Span<byte> KeyState = Instance.WinHelper.Shared.GetSpan(KeyStateSize);
            KeyState.Slice(0, KeyStateSize).Clear();

            Instance.SetRawSyscallReturn(Instance.WriteMemory(KeyStatePtr, KeyState.Slice(0, KeyStateSize)) ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
