using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserPeekMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong MessagePtr = Instance.WinHelper.GetArg(0);
            ulong HwndFilter = Instance.WinHelper.GetArg(1);
            uint MinMessage = (uint)Instance.WinHelper.GetArg(2);
            uint MaxMessage = (uint)Instance.WinHelper.GetArg(3);
            uint Flags = (uint)Instance.WinHelper.GetArg(4);

            if (!Win32kHelper.IsKnownWindow(Instance, HwndFilter))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryGetMessage(Instance, HwndFilter, MinMessage, MaxMessage, Win32kHelper.RemoveFlagSet(Flags), out Win32kMessage Message))
            {
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (MessagePtr == 0 || !Win32kHelper.WriteMessage(Instance, MessagePtr, Message))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
