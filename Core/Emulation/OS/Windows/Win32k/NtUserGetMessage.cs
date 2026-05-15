using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetMessage : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong MessagePtr = Instance.WinHelper.GetArg64(0);
            ulong HwndFilter = Instance.WinHelper.GetArg64(1);
            uint MinMessage = (uint)Instance.WinHelper.GetArg64(2, true);
            uint MaxMessage = (uint)Instance.WinHelper.GetArg64(3, true);

            if (MessagePtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Win32kHelper.IsKnownWindow(Instance, HwndFilter))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryGetMessage(Instance, HwndFilter, MinMessage, MaxMessage, true, out Win32kMessage Message))
            {
                Message = new Win32kMessage(0, Win32kHelper.WM_QUIT, 0, 0, unchecked((uint)Instance.EmulatedTickCount64), 0, 0);
            }

            if (!Win32kHelper.WriteMessage(Instance, MessagePtr, Message))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Message.Message == Win32kHelper.WM_QUIT ? 0ul : 1ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
