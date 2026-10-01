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
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            Win32kHelper.DrainHostEvents(Instance);

            uint WakeMask = Win32kHelper.WakeMaskFromPeekFlags(Flags);
            if ((WakeMask & Win32kHelper.QS_SENDMESSAGE) != 0
                && Win32kHelper.ReceiveNotification(Instance, Instance.WinHelper.GetSyscallRip(Instance.CurrentThread, false)))
            {
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Win32kHelper.TryGetMessage(Instance, HwndFilter, MinMessage, MaxMessage, WakeMask, Win32kHelper.RemoveFlagSet(Flags), Instance.CurrentThread?.ThreadId ?? 0, out Win32kMessage Message))
            {
                Instance.SetLastWinError(0);
                if (Win32kHelper.TryDeliverWindowPosChanged(Instance, 0))
                    return NTSTATUS.STATUS_SUCCESS;

                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WindowsThreadState Reader = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            if (MessagePtr == 0 || !Win32kHelper.WriteMessage(Instance, MessagePtr, Message, Reader))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Instance.SetLastWinError(0);
            if (Win32kHelper.TryDeliverWindowPosChanged(Instance, 1))
                return NTSTATUS.STATUS_SUCCESS;

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
